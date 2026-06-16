// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package serve holds the small TLS-serving and trust-anchor helpers the
// harness peer mains share: loading a leaf cert+key issued by the local CA,
// building a TLS http.Server, and building an http.Client that trusts the CA.
//
// It exists so each peer main (filestore, control-plane, exchange, edge) serves
// TLS the same way against the same CA, with the guest told only the edge's CA
// PEM. Nothing here is part of the guest binary.
package serve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// maxJWKSBytes bounds a fetched JWKS document so a misbehaving peer cannot
// exhaust memory.
const maxJWKSBytes = 1 << 20

// readAllClose reads a bounded response body and closes it.
func readAllClose(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
}

// LoadServerTLS builds a *tls.Config serving the leaf cert+key at the given PEM
// paths. The leaf must chain to the local CA so a client trusting the CA PEM
// completes the handshake.
func LoadServerTLS(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("serve: load leaf %q/%q: %w", certPath, keyPath, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// CAClient builds an *http.Client whose root trust is exactly the CA PEM at
// caPath, so a peer dialing another peer over TLS trusts the local CA and
// nothing else.
func CAClient(caPath string) (*http.Client, error) {
	pem, err := os.ReadFile(caPath) //nolint:gosec // G304: caPath is the harness CA path on the shared volume
	if err != nil {
		return nil, fmt.Errorf("serve: read CA %q: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("serve: CA PEM %q contained no certificate", caPath)
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// Run serves handler over TLS on addr until the process is signalled. It blocks;
// a serve error other than the clean shutdown sentinel is returned.
func Run(addr string, tlsConf *tls.Config, handler http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 30 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		// The cert+key are already in TLSConfig, so the empty path args are unused.
		errCh <- srv.ListenAndServeTLS("", "")
	}()
	if err := <-errCh; err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve %q: %w", addr, err)
	}
	return nil
}

// FetchJWKS GETs a JWKS document from url using client and returns the raw
// bytes, retrying until the peer is up or the deadline elapses. Peers come up
// concurrently, so a dependent peer polls for its upstream's JWKS at startup.
func FetchJWKS(ctx context.Context, client *http.Client, url string, within time.Duration) ([]byte, error) {
	deadline := time.Now().Add(within)
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("serve: build JWKS request: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			body, readErr := readAllClose(resp)
			if readErr == nil {
				return body, nil
			}
			lastErr = readErr
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("serve: JWKS %q returned status %d", url, resp.StatusCode)
			_ = resp.Body.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("serve: JWKS %q never reachable within %s: %w", url, within, lastErr)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
