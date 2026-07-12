// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Command harness-init is the bringup keystone for the network e2e graph. It
// runs ONCE before the peers start and produces, into a shared volume, every
// artifact the peers and the guest mount need but cannot know ahead of time:
//
//   - a single local CA (cert + key) and one leaf serving cert+key per service
//     name (filestore, control-plane, exchange, edge), all chaining to that CA;
//   - the control-plane ES256 signing key, so the control-plane serves a stable
//     JWKS and the init step can mint the per-scope weak session JWTs the guest
//     fixture carries;
//   - the rendered guest-config.json, with service_url pointed at the edge, the
//     real per-mount weak JWTs as auth_token, and the CA PEM as ca_cert_pem.
//
// Keeping all key material generation in one place means the CA PEM the guest is
// told about is the exact anchor the edge's leaf chains to, and the weak JWTs in
// the fixture are signed by the same key the control-plane serves in its JWKS.
// The peers then read their leaf/key/JWKS files; none generates its own random
// cert, so the trust graph is coherent across separate processes.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/fixture"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/jwtmint"
	"github.com/Wide-Moat/ocu-rclone-filestore/test/harness/internal/localca"
)

// serviceNames are the DNS names leaf certs are issued for. Each is the compose
// service name a peer is reachable as on the docker network; the edge leaf SAN
// is the host the guest dials in its service_url.
var serviceNames = []string{"filestore", "control-plane", "exchange", "edge"}

// weakJWTScopes are the filesystem_ids the guest mounts; the init step mints one
// weak session JWT per scope for the fixture's per-mount auth_token. fsrw is
// used by two mount entries (the cold-read second mount), fsthrottle by the SC2
// throttle mount, fsro by the read-only mount. fs-fleet is the deployment scope
// the fleet guest-config template pins for both its outputs and uploads mounts;
// the render keys the token map on the filesystem_id, so one entry covers both.
var weakJWTScopes = []struct {
	fsid   string
	intent string
}{
	{"fsrw", "write"},
	{"fsthrottle", "write"},
	{"fsro", "read"},
	{"fsconf", "write"},
	{"fs-fleet", "write"},
}

const (
	cpIssuer   = "https://control-plane.test"
	cpAudience = "filestore-edge"
	cpKid      = "kid-cp"
)

func main() {
	if err := mainWith(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "harness-init: %v\n", err)
		os.Exit(1)
	}
}

// mainWith parses args with a local FlagSet and runs the keystone, so it is
// callable from a test without racing the package flag set.
func mainWith(args []string) error {
	fs := flag.NewFlagSet("harness-init", flag.ContinueOnError)
	out := fs.String("out", "/shared", "directory to write CA, leaf certs, keys, JWKS, and the rendered guest config into")
	edgeHost := fs.String("edge-host", "edge", "the host the guest dials in service_url (must match the edge leaf SAN)")
	edgePort := fs.Int("edge-port", 8450, "the port the guest dials the edge on")
	fixtureTemplate := fs.String("fixture-template", "/fixtures/guest-config.json", "the single-shape guest config to render service_url/auth_token/ca_cert_pem into")
	certTTL := fs.Duration("cert-ttl", localca.DefaultCertTTL, "validity window stamped on the harness CA and leaves; raise it for a long-lived CI or demo stand so the PKI does not expire mid-run")
	renewBefore := fs.Duration("cert-renew-before", 2*time.Hour, "re-issue the whole artifact set when the existing leaf expires within this window (0 disables the expiry check, restoring pure stat-idempotency)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return run(*out, *edgeHost, *edgePort, *fixtureTemplate, *certTTL, *renewBefore)
}

func run(out, edgeHost string, edgePort int, fixtureTemplate string, certTTL, renewBefore time.Duration) error {
	if err := os.MkdirAll(out, 0o750); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	// Idempotency guard, now expiry-aware. This step gates every long-running
	// peer, but compose re-runs a service_completed_successfully dependency on
	// every `compose run`. Re-generating the CA would rotate the trust anchor out
	// from under an already-running edge/filestore (which loaded their leaves at
	// startup), breaking the next dialer — so when the rendered set exists AND is
	// still valid, leave it untouched.
	//
	// But the test PKI carries a short TTL (DefaultCertTTL); on a stand left up
	// past that window every leaf expires and the shared volume outlives a plain
	// restart, so pure stat-idempotency serves a dead trust graph forever (only
	// `down -v` cures it). When the existing leaf is within renewBefore of expiry
	// (or already expired), re-issue the whole set. This is safe on a clean `up`:
	// harness-init is a one-shot that completes BEFORE edge/filestore start (a
	// service_completed_successfully dependency), so no consumer has read a leaf
	// yet. On an already-dead stand the peers hold expired leaves regardless, so a
	// re-issue cannot make the graph worse — it is the only cure short of down -v.
	marker := filepath.Join(out, "guest-config.json")
	reissue, why, err := needsReissue(out, renewBefore, time.Now())
	if err != nil {
		return err
	}
	if !reissue {
		_, _ = fmt.Fprintf(os.Stdout, "harness-init: artifacts already present in %s and valid; leaving them in place (idempotent)\n", out)
		return nil
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		_, _ = fmt.Fprintf(os.Stdout, "harness-init: re-issuing artifacts in %s (%s)\n", out, why)
	}

	// 1. The CA.
	ca, err := localca.NewWithTTL(certTTL)
	if err != nil {
		return err
	}
	caPEM := ca.CertPEM()
	if err := os.WriteFile(filepath.Join(out, "ca.pem"), caPEM, 0o644); err != nil { //nolint:gosec // G306: harness trust anchor on an ephemeral volume, world-readable by design
		return fmt.Errorf("write ca.pem: %w", err)
	}

	// 2. A leaf cert+key per service. Each leaf SANs its service name plus
	// localhost/127.0.0.1 so an in-process smoke can reach it too.
	for _, name := range serviceNames {
		leafCert, leafKey, certErr := issueLeafPEM(ca, name)
		if certErr != nil {
			return certErr
		}
		if wErr := os.WriteFile(filepath.Join(out, name+".cert.pem"), leafCert, 0o644); wErr != nil { //nolint:gosec // G306: harness leaf cert on an ephemeral volume
			return fmt.Errorf("write %s cert: %w", name, wErr)
		}
		if wErr := os.WriteFile(filepath.Join(out, name+".key.pem"), leafKey, 0o600); wErr != nil {
			return fmt.Errorf("write %s key: %w", name, wErr)
		}
	}

	// 3. The control-plane signing key, so the control-plane serves a stable
	// JWKS and this step mints weak JWTs the guest fixture carries.
	cpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("control-plane key: %w", err)
	}
	cpKeyPEM, err := marshalECKeyPEM(cpKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "control-plane.signing.key.pem"), cpKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write control-plane signing key: %w", err)
	}

	// 3b. The exchange credential signing key, written once so the exchange
	// serves a STABLE credential JWKS across restarts. Without a persisted key
	// the exchange mints a fresh one on every boot, desyncing any edge that
	// cached an exchanged credential or any filestore that cached the JWKS — an
	// otherwise-valid token then fails with a hard 401 after an independent
	// restart. This mirrors the control-plane signing key above.
	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("exchange credential key: %w", err)
	}
	credKeyPEM, err := marshalECKeyPEM(credKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "exchange.credential.key.pem"), credKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write exchange credential signing key: %w", err)
	}

	// 4. Mint one weak session JWT per scope, signed by the control-plane key.
	// The token lifetime is derived from certTTL, not a hard-coded window, so the
	// weak-JWT axis and the cert axis stay coupled: raising -cert-ttl for a long
	// demo extends the tokens too, and the two cannot silently diverge (a fresh
	// cert outliving already-dead tokens). The reissue guard checks both axes.
	tokenTTL := weakTokenTTL(certTTL)
	tokens := map[string]string{}
	now := time.Now()
	for _, sc := range weakJWTScopes {
		claims := jwtmint.Claims{
			Issuer:       cpIssuer,
			Audience:     cpAudience,
			Subject:      sc.fsid,
			IssuedAt:     now.Unix(),
			Expiry:       now.Add(tokenTTL).Unix(),
			FilesystemID: sc.fsid,
			Intent:       sc.intent,
		}
		tok, signErr := jwtmint.Sign(cpKey, cpKid, claims)
		if signErr != nil {
			return fmt.Errorf("mint weak JWT for %s: %w", sc.fsid, signErr)
		}
		tokens[sc.fsid] = tok
	}
	tokensJSON, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("marshal tokens: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, "weak-tokens.json"), tokensJSON, 0o644); err != nil { //nolint:gosec // G306: harness weak session tokens on an ephemeral volume
		return fmt.Errorf("write weak tokens: %w", err)
	}

	// 5. Render the guest config: service_url -> edge, auth_token -> per-scope
	// weak JWT, ca_cert_pem -> the CA PEM.
	serviceURL := fmt.Sprintf("https://%s:%d", edgeHost, edgePort)
	if err := fixture.RenderFile(fixtureTemplate, filepath.Join(out, "guest-config.json"), serviceURL, string(caPEM), tokens); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stdout, "harness-init: wrote CA, %d leaf certs, weak tokens, and guest-config.json to %s\n", len(serviceNames), out)
	return nil
}

// needsReissue decides whether the artifact set in out must be produced. It
// returns true (with a human-readable reason) when there is no rendered set yet,
// or when the set exists but either axis is expiring: the representative leaf is
// missing, unparseable, or within renewBefore of expiry, OR any minted weak JWT
// is missing, unparseable, or within renewBefore of expiry. It returns false
// only when the set exists and BOTH axes are comfortably valid — the idempotent
// leave-in-place path.
//
// The token axis is checked because the weak JWTs are a separate artifact from
// the cert with their own lifetime: a stand restarted after the tokens die but
// while the cert is still valid would otherwise self-heal nothing (the guard
// would leave the dead tokens in place, and the edge would 401 every request).
// Reading the tokens back from weak-tokens.json and checking their exp with the
// same renewBefore window couples the two axes, so a re-issue fires the moment
// either artifact nears expiry.
//
// A non-positive renewBefore disables BOTH expiry checks: an existing marker is
// then always left in place, restoring the original pure stat-idempotency (the
// documented opt-out for a caller that manages cert lifetime itself).
//
// The representative leaf is the first service leaf; every leaf is issued in the
// same run with the same TTL, so one leaf's remaining validity speaks for the
// set. Likewise every weak JWT is minted in the same run with the same TTL.
//
// A present marker but an absent or unparseable weak-tokens.json is treated as a
// torn/partial set (re-issue), which also self-heals a set produced by an older
// harness-init that predates the token axis — re-issue is always the safe
// direction here (harness-init is a one-shot completing before any peer starts).
func needsReissue(out string, renewBefore time.Duration, now time.Time) (bool, string, error) {
	marker := filepath.Join(out, "guest-config.json")
	if _, statErr := os.Stat(marker); statErr != nil {
		if os.IsNotExist(statErr) {
			return true, "no rendered set present", nil
		}
		return false, "", fmt.Errorf("stat guest-config marker: %w", statErr)
	}
	if renewBefore <= 0 {
		// Expiry check disabled: honour the pre-existing set unconditionally.
		return false, "", nil
	}

	leafPath := filepath.Join(out, serviceNames[0]+".cert.pem")
	notAfter, err := leafNotAfter(leafPath)
	if err != nil {
		// A present marker but an unreadable/unparseable leaf is a torn or partial
		// set; re-issue rather than serve a broken trust graph.
		return true, fmt.Sprintf("leaf %s unreadable (%v)", filepath.Base(leafPath), err), nil
	}
	if remaining := notAfter.Sub(now); remaining < renewBefore {
		return true, fmt.Sprintf("leaf expires in %s (< renew-before %s)", remaining.Round(time.Second), renewBefore), nil
	}

	// Token axis: the weak JWTs are their own artifact with their own lifetime.
	// A torn, absent, or unparseable token set is not a fatal error here — it is
	// exactly the state that must trigger a reissue, and `why` already carries the
	// human-readable cause, so returning (true, why, nil) is deliberate.
	tokenNotAfter, why, err := weakTokensNotAfter(out)
	if err != nil {
		return true, why, nil //nolint:nilerr // a bad token set means "reissue", not a fatal error
	}
	if remaining := tokenNotAfter.Sub(now); remaining < renewBefore {
		return true, fmt.Sprintf("weak JWT expires in %s (< renew-before %s)", remaining.Round(time.Second), renewBefore), nil
	}
	return false, "", nil
}

// weakTokenTTL derives the weak session JWT lifetime from the cert TTL so the two
// artifact axes stay coupled. It floors the token TTL at 12h only if certTTL is
// somehow shorter, so a raised -cert-ttl always extends the tokens and the
// default 24h cert simply lends the tokens 24h.
func weakTokenTTL(certTTL time.Duration) time.Duration {
	const floor = 12 * time.Hour
	if certTTL < floor {
		return floor
	}
	return certTTL
}

// weakTokensNotAfter reads weak-tokens.json and returns the earliest exp across
// every minted token, so the soonest-dying token governs the axis. It returns an
// error (with a re-issue reason) when the file is missing, unreadable, not JSON,
// empty, or carries a token that is not a compact JWS, whose payload is
// unparseable, or whose exp is absent/zero (treated as expired-unsafe, mirroring
// Verify's rejection of an exp-less token).
func weakTokensNotAfter(out string) (time.Time, string, error) {
	path := filepath.Join(out, "weak-tokens.json")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: harness-controlled path under the shared volume
	if err != nil {
		return time.Time{}, fmt.Sprintf("weak-tokens.json unreadable (%v)", err), err
	}
	var tokens map[string]string
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return time.Time{}, fmt.Sprintf("weak-tokens.json is not JSON (%v)", err), err
	}
	if len(tokens) == 0 {
		return time.Time{}, "weak-tokens.json carries no tokens", fmt.Errorf("no weak tokens")
	}
	earliest := time.Time{}
	for fsid, tok := range tokens {
		exp, perr := jwtmint.ExpiryUnverified(tok)
		if perr != nil {
			return time.Time{}, fmt.Sprintf("weak JWT for %s unparseable (%v)", fsid, perr), perr
		}
		if exp == 0 {
			// An exp-less token would never expire; treat it as expired-unsafe so the
			// set is re-issued (consistent with Verify rejecting an exp-less token).
			return time.Time{}, fmt.Sprintf("weak JWT for %s carries no expiry", fsid), fmt.Errorf("no expiry")
		}
		notAfter := time.Unix(exp, 0)
		if earliest.IsZero() || notAfter.Before(earliest) {
			earliest = notAfter
		}
	}
	return earliest, "", nil
}

// leafNotAfter reads a PEM leaf certificate file and returns its NotAfter. It
// errors on a missing file, a file with no CERTIFICATE block, or an unparseable
// certificate — each a reason the caller treats as "re-issue".
func leafNotAfter(path string) (time.Time, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: harness-controlled path under the shared volume
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, fmt.Errorf("no CERTIFICATE PEM block in %s", filepath.Base(path))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return cert.NotAfter, nil
}

// issueLeafPEM issues a leaf for the service name (plus localhost) and returns
// the cert and key in PEM form.
func issueLeafPEM(ca *localca.CA, name string) (certPEM, keyPEM []byte, err error) {
	leaf, err := ca.IssueLeaf(
		[]string{name, "localhost"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("issue %s leaf: %w", name, err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	key, ok := leaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("issue %s leaf: unexpected key type", name)
	}
	keyPEM, err = marshalECKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// marshalECKeyPEM serializes an EC private key to PKCS#8 PEM.
func marshalECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal EC key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
