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
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
)

// Token-exchange request constants, fixed by RFC 8693.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: the fixed RFC-8693 grant_type URN, not a credential
	subjectTokenTypeJWT    = "urn:ietf:params:oauth:token-type:jwt"            //nolint:gosec // G101: the fixed RFC-8693 token-type URN, not a credential
)

// maxResponseBytes bounds the exchange response body read so a misbehaving or
// hostile peer cannot exhaust memory.
const maxResponseBytes = 1 << 20

// defaultRenewSkew is how far before an exchanged credential's own expiry the
// cache treats its entry as stale and re-exchanges. It is small so the edge
// re-exchanges just BEFORE the filestore would reject the credential rather than
// serving one that dies mid-flight — the same renew-before posture the cert and
// weak-JWT guards use. A credential with no readable expiry (an opaque, non-JWT
// credential) is never TTL-expired; only a JWT credential gains this bound.
const defaultRenewSkew = 30 * time.Second

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
	Intent       string `json:"intent"`
}

// Exchanger performs the RFC-8693 exchange against the exchange peer and caches
// the issued credential per {filesystem_id, intent} (ADR-0029 amends ADR-0019:
// a session's two mounts share one filesystem_id but carry distinct intent
// claims, so a per-fsID cache would answer the outputs mount's exchange with the
// uploads mount's credential and flatten the intent). It is safe for concurrent
// use.
//
// Each cache entry is bound to the exchanged credential's OWN lifetime: a JWT
// credential carries an exp, and the entry is treated as a miss once the clock is
// within renewSkew of that exp, so the edge re-exchanges rather than injecting a
// credential the filestore would reject as expired. An opaque (non-JWT)
// credential has no readable exp and caches indefinitely, as before. This bounds
// the cache to the credential it holds; a stand up longer than the credential
// lifetime no longer keeps injecting a stale credential until an edge restart.
//
// A downstream-401 evict path (re-exchange when the filestore itself rejects the
// injected credential) is a possible future belt-and-braces but is deliberately
// NOT implemented here: the TTL bound already closes the described failure, and
// evict-on-401 adds a false-evict axis (a scope/authz 401 is not a credential
// expiry) that needs its own design. The TTL is the complete fix for the
// credential-outliving-its-entry defect.
type Exchanger struct {
	// exchangeURL is the absolute URL of the exchange peer's token endpoint
	// (its base URL joined with exchange.ExchangePath).
	exchangeURL string
	// client is the HTTP client used to reach the exchange peer. Injectable so a
	// test can count or intercept the round trips.
	client *http.Client

	// now is the clock, seamed for tests; defaults to time.Now.
	now func() time.Time
	// renewSkew evicts a cached credential this far before its own expiry.
	renewSkew time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
	// inflight serialises concurrent first-resolvers for the same
	// {filesystem_id, intent} key so a session triggers exactly one exchange per
	// mount even under a stampede. Each entry is created under mu and closed when
	// its exchange settles.
	inflight map[string]*flight
}

// cacheEntry is a cached exchanged credential plus the instant it stops being
// usable. A zero notAfter means "no lifetime known" (an opaque, non-JWT
// credential whose exp cannot be read) and is never TTL-expired.
type cacheEntry struct {
	cred     string
	notAfter time.Time
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
	// Now, when set, fixes the clock for deterministic tests; otherwise time.Now.
	Now func() time.Time
	// RenewSkew, when positive, overrides how far before a credential's own exp
	// the cache re-exchanges; otherwise defaultRenewSkew.
	RenewSkew time.Duration
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
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	renewSkew := opts.RenewSkew
	if renewSkew <= 0 {
		renewSkew = defaultRenewSkew
	}
	return &Exchanger{
		exchangeURL: opts.ExchangeURL,
		client:      client,
		now:         now,
		renewSkew:   renewSkew,
		cache:       make(map[string]cacheEntry),
		inflight:    make(map[string]*flight),
	}, nil
}

// Resolve returns the real filestore credential for the given filesystem_id,
// performing the exchange once and serving the cached result thereafter. The
// weak JWT is the subject token presented to the exchange peer; the peer
// re-validates it, so a credential is only ever issued for a token the edge has
// already proved valid. A failed exchange returns a non-nil error and caches
// nothing.
func (e *Exchanger) Resolve(ctx context.Context, filesystemID, intent, weakJWT string) (string, error) {
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

	// The cache and inflight keys are {filesystem_id, intent}: a session's two
	// mounts share the filesystem_id but not the intent, so keying on the pair
	// keeps the outputs (write) mount's exchange a miss against the uploads
	// (read) mount's entry (ADR-0029). The NUL separator cannot appear in either
	// value.
	key := filesystemID + "\x00" + intent

	// The stale-check, the eviction of a stale entry, and the inflight lookup +
	// flight registration all sit under ONE lock acquisition: releasing between
	// the stale-delete and the inflight check would let two goroutines both see the
	// miss and both register a flight across a TTL eviction, defeating the
	// single-flight guarantee.
	e.mu.Lock()
	if entry, ok := e.cache[key]; ok {
		if e.isLive(entry) {
			e.mu.Unlock()
			return entry.cred, nil
		}
		// A known-lifetime entry within renewSkew of its own expiry is stale: evict
		// it and fall through to a fresh exchange under the same lock.
		delete(e.cache, key)
	}
	// If an exchange for this scope is already in flight, wait for it rather than
	// launching a second one: one exchange per session even under a stampede.
	// Respect context cancellation while waiting so a caller that gives up (or a
	// cancelled request) is not pinned to the leader's whole round trip.
	if fl, ok := e.inflight[key]; ok {
		e.mu.Unlock()
		select {
		case <-fl.done:
			return fl.cred, fl.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	// This goroutine owns the exchange for this {scope, intent}.
	fl := &flight{done: make(chan struct{})}
	e.inflight[key] = fl
	e.mu.Unlock()

	cred, err := e.exchange(ctx, weakJWT)

	e.mu.Lock()
	fl.cred, fl.err = cred, err
	if err == nil {
		e.cache[key] = cacheEntry{cred: cred, notAfter: credentialNotAfter(cred)}
	}
	delete(e.inflight, key)
	e.mu.Unlock()
	close(fl.done)

	return cred, err
}

// isLive reports whether a cache entry is still usable as of now(). An entry with
// no known lifetime (zero notAfter — an opaque, non-JWT credential) is always
// live; an entry with a known lifetime is live only while now()+renewSkew is
// still before its notAfter. The IsZero guard is load-bearing: without it a zero
// notAfter would compare as always-expired and evict an opaque entry on every
// hit.
func (e *Exchanger) isLive(entry cacheEntry) bool {
	return entry.notAfter.IsZero() || e.now().Add(e.renewSkew).Before(entry.notAfter)
}

// credentialNotAfter reads the exp of an issued credential to bound its cache
// lifetime. A JWT credential carries an exp and returns its instant; an opaque
// (non-JWT) credential — no dots, so not a compact JWS — returns the zero time,
// meaning "no lifetime known, never TTL-expire". A parse error never fails the
// exchange: the credential is already issued and returned to the caller; only the
// cache bookkeeping degrades to cache-forever.
func credentialNotAfter(cred string) time.Time {
	exp, err := jwtmint.ExpiryUnverified(cred)
	if err != nil || exp == 0 {
		return time.Time{}
	}
	return time.Unix(exp, 0)
}

// Cached reports the cached credential for a {filesystem_id, intent}, if a still
// LIVE entry exists. It exists so a caller (or a test) can observe the cache
// without forcing an exchange. It applies the same liveness predicate as Resolve
// — an entry within renewSkew of its own expiry is reported as absent — but stays
// a pure observer: it never evicts, so a stale entry it hides is still cleaned up
// by the next Resolve.
func (e *Exchanger) Cached(filesystemID, intent string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.cache[filesystemID+"\x00"+intent]
	if !ok || !e.isLive(entry) {
		return "", false
	}
	return entry.cred, true
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
