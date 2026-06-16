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
// throttle mount, fsro by the read-only mount.
var weakJWTScopes = []struct {
	fsid   string
	intent string
}{
	{"fsrw", "write"},
	{"fsthrottle", "write"},
	{"fsro", "read"},
	{"fsconf", "write"},
}

const (
	cpIssuer   = "https://control-plane.test"
	cpAudience = "filestore-edge"
	cpKid      = "kid-cp"
)

func main() {
	out := flag.String("out", "/shared", "directory to write CA, leaf certs, keys, JWKS, and the rendered guest config into")
	edgeHost := flag.String("edge-host", "edge", "the host the guest dials in service_url (must match the edge leaf SAN)")
	edgePort := flag.Int("edge-port", 8450, "the port the guest dials the edge on")
	fixtureTemplate := flag.String("fixture-template", "/fixtures/guest-config.json", "the single-shape guest config to render service_url/auth_token/ca_cert_pem into")
	flag.Parse()

	if err := run(*out, *edgeHost, *edgePort, *fixtureTemplate); err != nil {
		fmt.Fprintf(os.Stderr, "harness-init: %v\n", err)
		os.Exit(1)
	}
}

func run(out, edgeHost string, edgePort int, fixtureTemplate string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	// 1. The CA.
	ca, err := localca.New()
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

	// 4. Mint one weak session JWT per scope, signed by the control-plane key.
	tokens := map[string]string{}
	now := time.Now()
	for _, sc := range weakJWTScopes {
		claims := jwtmint.Claims{
			Issuer:       cpIssuer,
			Audience:     cpAudience,
			Subject:      sc.fsid,
			IssuedAt:     now.Unix(),
			Expiry:       now.Add(12 * time.Hour).Unix(),
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

	fmt.Fprintf(os.Stdout, "harness-init: wrote CA, %d leaf certs, weak tokens, and guest-config.json to %s\n", len(serviceNames), out)
	return nil
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
