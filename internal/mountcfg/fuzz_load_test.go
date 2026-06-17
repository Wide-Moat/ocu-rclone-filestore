// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// White-box fuzz target for the host-supplied mount config loader.
//
// Load is the guest's defense against a malformed/hostile config document. The
// core security invariant is reject-not-accept: for ANY input bytes, Load
// either returns a *Config every field of which satisfies every rule, OR
// returns a typed error — it must never accept a config that violates a rule
// and must never panic. The target lives in package mountcfg so it can re-run
// the unexported validators against whatever Load accepted.

package mountcfg

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad writes the fuzz bytes to a temp file and feeds them to Load, then
// asserts that any accepted Config independently re-satisfies every validation
// rule (accept-implies-valid).
func FuzzLoad(f *testing.F) {
	valid := `{
  "schema_version": "v1alpha1",
  "service_url": "https://broker.example",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  "mounts": [{
    "destination": "/mnt/a",
    "auth_token": "tok.rw",
    "filesystem_id": "fs-1",
    "readonly": false,
    "vfs_cache_mode": "full",
    "cache_duration_s": 30,
    "vfs_cache_max_size": "512M",
    "dir_perms": "0755",
    "file_perms": "0644"
  }, {
    "destination": "/mnt/ro",
    "auth_token": "tok.ro",
    "memory_store_id": "mem-1",
    "readonly": true,
    "vfs_cache_mode": "off",
    "cache_duration_s": 0,
    "vfs_cache_max_size": "0",
    "dir_perms": "0700",
    "file_perms": "0600"
  }]
}`

	f.Add([]byte(valid))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":"v1alpha1","service_url":"https://b","ca_cert_pem":"-----BEGIN CERTIFICATE-----","mounts":[]}`))
	// A config holding auth_token + ca_cert_pem is now VALID (the guest holds
	// the credential); these seeds exercise the held-credential accept path.
	f.Add([]byte(`{"schema_version":"v1alpha1","service_url":"https://b","ca_cert_pem":"-----BEGIN CERTIFICATE-----","mounts":[{"destination":"/m","auth_token":"x","filesystem_id":"f","readonly":true,"vfs_cache_mode":"off","cache_duration_s":0,"vfs_cache_max_size":"1M","dir_perms":"0755","file_perms":"0644"}]}`))
	f.Add([]byte(`{"schema_version":"v1alpha1","service_url":"https://b","ca_cert_pem":"x","backend_cache_ttl":60,"mounts":[]}`))
	// Adversarial scalars / structure.
	f.Add([]byte(`{"service_url":"http://insecure","mounts":[]}`))
	f.Add([]byte(`{"schema_version":"v1alpha1","service_url":"https://b","ca_cert_pem":"x","mounts":[{"destination":"relative","auth_token":"x","filesystem_id":"f","memory_store_id":"m","readonly":true,"vfs_cache_mode":"off","cache_duration_s":-1,"vfs_cache_max_size":"bad","dir_perms":"999","file_perms":"0644"}]}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"unknown_field":1}`))

	dir := f.TempDir()

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			// Rejection is always acceptable; the only requirement on the error
			// path is "did not panic".
			return
		}

		// Accept path: the returned Config MUST satisfy every rule. Re-running
		// validate is the strongest possible accept-implies-valid oracle: if
		// validate now reports an error on something Load accepted, Load let a
		// rule-violating config through.
		if cfg == nil {
			t.Fatal("Load returned nil Config and nil error")
		}
		if vErr := validate(cfg); vErr != nil {
			t.Fatalf("Load accepted a config that fails validate: %v", vErr)
		}

		// Belt-and-suspenders: spot-check the load-bearing rules directly rather
		// than trusting validate alone.
		if cfg.Mounts == nil {
			t.Fatal("accepted a config whose required mounts key is absent")
		}
		if cfg.CACertPEM == "" {
			t.Fatal("accepted a config whose required ca_cert_pem is absent")
		}
		if len(cfg.ServiceURL) < len("https://") || cfg.ServiceURL[:len("https://")] != "https://" {
			t.Fatalf("accepted a non-https service_url: %q", cfg.ServiceURL)
		}
		for _, m := range cfg.Mounts {
			assertMountValid(t, m)
		}
	})
}

// assertMountValid re-checks the per-mount invariants the loader promises on
// the accept path, independent of validateMount's own messaging.
func assertMountValid(t *testing.T, m Mount) {
	t.Helper()
	if !destinationRe.MatchString(m.Destination) {
		t.Fatalf("accepted mount with non-absolute destination %q", m.Destination)
	}
	if m.AuthToken == "" {
		t.Fatal("accepted mount with empty auth_token")
	}
	hasFS := m.FilesystemID != nil
	hasMem := m.MemoryStoreID != nil
	if hasFS == hasMem {
		t.Fatalf("accepted mount violating scope XOR (hasFS=%v hasMem=%v)", hasFS, hasMem)
	}
	if hasFS && *m.FilesystemID == "" {
		t.Fatal("accepted mount with present-but-empty filesystem_id")
	}
	if hasMem && *m.MemoryStoreID == "" {
		t.Fatal("accepted mount with present-but-empty memory_store_id")
	}
	if m.Readonly == nil {
		t.Fatal("accepted mount with absent readonly flag")
	}
	if m.CacheDurationS == nil || *m.CacheDurationS < 0 {
		t.Fatalf("accepted mount with bad cache_duration_s (%v)", m.CacheDurationS)
	}
	if !octalRe.MatchString(m.DirPerms) {
		t.Fatalf("accepted mount with bad dir_perms %q", m.DirPerms)
	}
	if !octalRe.MatchString(m.FilePerms) {
		t.Fatalf("accepted mount with bad file_perms %q", m.FilePerms)
	}
	if !byteSizeRe.MatchString(m.VfsCacheMaxSize) {
		t.Fatalf("accepted mount with bad vfs_cache_max_size %q", m.VfsCacheMaxSize)
	}
	if _, ok := cacheModes[m.VfsCacheMode]; !ok {
		t.Fatalf("accepted mount with bad vfs_cache_mode %q", m.VfsCacheMode)
	}
}
