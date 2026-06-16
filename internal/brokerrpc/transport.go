// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

// httpsTransport builds the outbound HTTPS/2 transport the client uses to reach
// the broker's REST service_url. Every connection is plain outbound TCP to the
// service host (no unix dialer) wrapped in TLS whose only trust anchor is the
// inspecting edge's CA, supplied as caCertPEM at construction. The pool is
// deliberately small (a handful of reused connections) because a single mount
// fans many FUSE operations through one Client.
//
// caCertPEM must contain at least one usable certificate: an empty PEM or a PEM
// that AppendCertsFromPEM rejects leaves no trust anchor, so the constructor
// errors rather than silently falling back to the system roots (which the guest
// must never trust for this path).
func httpsTransport(caCertPEM []byte) (*http.Transport, error) {
	if len(caCertPEM) == 0 {
		return nil, fmt.Errorf("brokerrpc: ca_cert_pem must not be empty")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("brokerrpc: ca_cert_pem contains no usable certificate")
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}, nil
}
