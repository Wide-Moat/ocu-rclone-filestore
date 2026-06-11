// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc

import (
	"context"
	"net"
	"net/http"
	"time"
)

// unixTransport returns an *http.Transport whose DialContext is bound
// exclusively to the per-session AF_UNIX socket at socketPath. Every
// connection the transport opens goes through that single socket — there is
// no TLS, no proxy, no fallback, and no shared-socket constant. The socket
// path is supplied at construction from the guest mount config so that two
// clients built from different configs dial two different sockets (D2).
func unixTransport(socketPath string) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// The network and address parameters from the HTTP layer are
			// ignored; the connection always goes to the per-session unix socket.
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   0, // no TLS on the unix socket path
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}
}
