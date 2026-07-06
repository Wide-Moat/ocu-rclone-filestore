// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package edgeglue is the minimal egress-edge glue that drives the per-session
// token exchange and caches its result keyed on filesystem_id.
//
// The edge proxy validates the weak session JWT itself and strips it; this glue
// supplies the credential the edge injects in its place. Given a validated
// filesystem_id and the weak session JWT it stands in for, the Exchanger POSTs
// the RFC-8693 token-exchange form to the exchange peer, parses the issued real
// credential, and returns it. A Cache keyed on filesystem_id ensures one
// exchange per session: the same scope resolves from cache on subsequent calls,
// and a failed exchange caches nothing.
//
// The glue holds no signing key and mints nothing of its own. It exchanges a
// token it cannot have forged (the edge already proved the JWT valid) for a
// credential issued by the exchange peer, and never sees or stores any backend
// secret beyond that issued, session-scoped credential.
package edgeglue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Token-exchange request constants, fixed by RFC 8693.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: the fixed RFC-8693 grant_type URN, not a credential
	subjectTokenTypeJWT    = "urn:ietf:params:oauth:token-type:jwt"            //nolint:gosec // G101: the fixed RFC-8693 token-type URN, not a credential
)

// maxResponseBytes bounds the exchange response body read so a misbehaving or
// hostile peer cannot exhaust memory.
const maxResponseBytes = 1 << 20

// tokenResponse is the RFC-8693 success body the exchange peer returns.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

// scopeClaims is the slice of the weak session JWT payload the glue needs to
// cross-check the requested scope against the token's own claim. It mirrors the
// control-plane claim name and is decoded WITHOUT signature verification: the
// exchange peer is the authority that verifies the signature and only issues a
// credential bound to the token's true scope. The glue's own check exists purely
// to refuse caching that credential under a mismatched cache key (WR-01).
type scopeClaims struct {
	FilesystemID string `json:"filesystem_id"`
}

// Exchanger performs the RFC-8693 exchange against the exchange peer and caches
// the issued credential per filesystem_id. It is safe for concurrent use.
type Exchanger struct {
	// exchangeURL is the absolute URL of the exchange peer's token endpoint
	// (its base URL joined with exchange.ExchangePath).
	exchangeURL string
	// client is the HTTP client used to reach the exchange peer. Injectable so a
	// test can count or intercept the round trips.
	client *http.Client

	mu    sync.Mutex
	cache map[string]string
	// inflight serialises concurrent first-resolvers for the same filesystem_id
	// so a session triggers exactly one exchange even under a stampede. Each
	// entry is created under mu and closed when its exchange settles.
	inflight map[string]*flight
}

// flight tracks one in-progress exchange for a filesystem_id. Waiters block on
// done and then read the result.
type flight struct {
	done chan struct{}
	cred string
	err  error
}

// Options carries Exchanger construction parameters.
type Options struct {
	// ExchangeURL is the absolute URL of the exchange peer's token endpoint.
	ExchangeURL string
	// Client, when set, is used for the exchange round trip; otherwise
	// http.DefaultClient is used.
	Client *http.Client
}

// New constructs an Exchanger. It returns an error on an empty exchange URL: an
// exchanger with no peer to call is a wiring bug, not a usable object.
func New(opts Options) (*Exchanger, error) {
	if strings.TrimSpace(opts.ExchangeURL) == "" {
		return nil, fmt.Errorf("edgeglue.New: an exchange URL is required")
	}
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	return &Exchanger{
		exchangeURL: opts.ExchangeURL,
		client:      client,
		cache:       make(map[string]string),
		inflight:    make(map[string]*flight),
	}, nil
}

// Resolve returns the real filestore credential for the given filesystem_id,
// performing the exchange once and serving the cached result thereafter. The
// weak JWT is the subject token presented to the exchange peer; the peer
// re-validates it, so a credential is only ever issued for a token the edge has
// already proved valid. A failed exchange returns a non-nil error and caches
// nothing.
func (e *Exchanger) Resolve(ctx context.Context, filesystemID, weakJWT string) (string, error) {
	if filesystemID == "" {
		return "", fmt.Errorf("edgeglue: a filesystem_id is required")
	}

	// WR-01: the credential the exchange issues is bound to the scope the JWT
	// itself claims, not to the caller-supplied filesystemID. Caching the result
	// under filesystemID without first confirming the two agree would let a token
	// scoped to fs-B seed an fs-B credential under cache key fs-A, so a later
	// fs-A request would be answered with an fs-B credential. Cross-check the
	// token's own filesystem_id claim against the requested scope before touching
	// the cache or the peer, and refuse on a mismatch. The claim is read from the
	// unverified payload only to compare it; the exchange peer remains the
	// authority that verifies the signature.
	claimedFSID, err := filesystemIDClaim(weakJWT)
	if err != nil {
		return "", fmt.Errorf("edgeglue: cannot read subject token scope: %w", err)
	}
	if claimedFSID != filesystemID {
		return "", fmt.Errorf("edgeglue: subject token is scoped to %q, not the requested %q", claimedFSID, filesystemID)
	}

	e.mu.Lock()
	if cred, ok := e.cache[filesystemID]; ok {
		e.mu.Unlock()
		return cred, nil
	}
	// If an exchange for this scope is already in flight, wait for it rather than
	// launching a second one: one exchange per session even under a stampede.
	// Respect context cancellation while waiting so a caller that gives up (or a
	// cancelled request) is not pinned to the leader's whole round trip.
	if fl, ok := e.inflight[filesystemID]; ok {
		e.mu.Unlock()
		select {
		case <-fl.done:
			return fl.cred, fl.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	// This goroutine owns the exchange for this scope.
	fl := &flight{done: make(chan struct{})}
	e.inflight[filesystemID] = fl
	e.mu.Unlock()

	cred, err := e.exchange(ctx, weakJWT)

	e.mu.Lock()
	fl.cred, fl.err = cred, err
	if err == nil {
		e.cache[filesystemID] = cred
	}
	delete(e.inflight, filesystemID)
	e.mu.Unlock()
	close(fl.done)

	return cred, err
}

// Cached reports the cached credential for a filesystem_id, if any. It exists so
// a caller (or a test) can observe the cache without forcing an exchange.
func (e *Exchanger) Cached(filesystemID string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cred, ok := e.cache[filesystemID]
	return cred, ok
}

// exchange performs one RFC-8693 token exchange and returns the issued
// credential. Every non-2xx outcome, transport failure, or empty/garbled body
// surfaces as an error so nothing is cached on failure.
func (e *Exchanger) exchange(ctx context.Context, weakJWT string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", weakJWT)
	form.Set("subject_token_type", subjectTokenTypeJWT)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.exchangeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("edgeglue: build exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("edgeglue: exchange round trip: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("edgeglue: exchange returned status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("edgeglue: read exchange body: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", fmt.Errorf("edgeglue: decode exchange body: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("edgeglue: exchange returned no access_token")
	}
	return tr.AccessToken, nil
}

// filesystemIDClaim extracts the filesystem_id claim from a compact JWS payload
// segment without verifying the signature. It is used solely to cross-check the
// requested scope against the token's own claim (WR-01); signature, issuer,
// audience, and expiry remain the exchange peer's responsibility. A token that
// is not a three-segment compact JWS, whose payload is not base64url, or whose
// payload is not JSON is rejected, as is one carrying no filesystem_id.
func filesystemIDClaim(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a compact JWS")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload is not base64url: %w", err)
	}
	var sc scopeClaims
	if err := json.Unmarshal(payloadJSON, &sc); err != nil {
		return "", fmt.Errorf("payload is not JSON: %w", err)
	}
	if sc.FilesystemID == "" {
		return "", fmt.Errorf("subject token carries no filesystem_id")
	}
	return sc.FilesystemID, nil
}
