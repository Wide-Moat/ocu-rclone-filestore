// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package signingkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// writePKCS8EC writes a fresh P-256 key as a PKCS#8 PEM into dir and returns its
// path.
func writePKCS8EC(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// writePKCS8RSA writes a fresh RSA key as a PKCS#8 PEM into dir and returns its
// path, so the non-EC error arm can be driven with a valid-but-wrong key type.
func writePKCS8RSA(t *testing.T, dir string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}
	path := filepath.Join(dir, "rsa.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write rsa key: %v", err)
	}
	return path
}

// TestLoadRoundTrip loads a valid PKCS#8 EC key and gets a usable private key
// back.
func TestLoadRoundTrip(t *testing.T) {
	path := writePKCS8EC(t, t.TempDir())
	key, err := Load(path, "signing key", false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if key == nil {
		t.Fatal("Load returned a nil key for a valid PEM")
	}
}

// TestLoadEmptyPathPolicy pins the two empty-path arms: with allowEmptyPath the
// empty path is a nil-key fallback; without it, the empty path is an error.
func TestLoadEmptyPathPolicy(t *testing.T) {
	key, err := Load("", "credential signing key", true)
	if err != nil {
		t.Fatalf("Load(\"\", allow=true): %v", err)
	}
	if key != nil {
		t.Fatal("Load(\"\", allow=true) returned a non-nil key; want the ephemeral fallback")
	}

	if _, err := Load("", "signing key", false); err == nil {
		t.Fatal("Load(\"\", allow=false) returned nil error; want a read error")
	}
}

// TestLoadRejectsMalformed covers the missing-file, non-PEM, non-PKCS#8, and
// non-EC error arms.
func TestLoadRejectsMalformed(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	if _, err := Load(filepath.Join(dir, "absent.pem"), "signing key", false); err == nil {
		t.Fatal("Load of a missing file returned nil error")
	}

	// Present but not PEM.
	notPEM := filepath.Join(dir, "notpem")
	if err := os.WriteFile(notPEM, []byte("not a pem block"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(notPEM, "signing key", false); err == nil {
		t.Fatal("Load of a non-PEM file returned nil error")
	}

	// PEM whose bytes are not a PKCS#8 key.
	badKey := filepath.Join(dir, "badkey.pem")
	if err := os.WriteFile(badKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(badKey, "signing key", false); err == nil {
		t.Fatal("Load of a non-PKCS#8 PEM returned nil error")
	}

	// A valid PKCS#8 key that is RSA, not EC.
	rsaPath := writePKCS8RSA(t, dir)
	if _, err := Load(rsaPath, "signing key", false); err == nil {
		t.Fatal("Load of a non-EC key returned nil error")
	}
}
