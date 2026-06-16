// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package fixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const template = `{
  "schema_version": "v1alpha",
  "service_url": "https://placeholder",
  "ca_cert_pem": "placeholder",
  "mounts": [
    {"destination": "/mnt/user-data/outputs/", "auth_token": "x", "filesystem_id": "fsrw", "readonly": false}
  ]
}`

func TestRenderFillsValuesAndKeepsMounts(t *testing.T) {
	out, err := Render([]byte(template), "https://edge:8450", "CA-PEM", map[string]string{"fsrw": "tok"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("rendered output is not JSON: %v", err)
	}
	if cfg["service_url"] != "https://edge:8450" {
		t.Fatalf("service_url not filled: %v", cfg["service_url"])
	}
	if cfg["ca_cert_pem"] != "CA-PEM" {
		t.Fatalf("ca_cert_pem not filled: %v", cfg["ca_cert_pem"])
	}
	m := cfg["mounts"].([]any)[0].(map[string]any)
	if m["auth_token"] != "tok" {
		t.Fatalf("auth_token not filled: %v", m["auth_token"])
	}
	if m["destination"] != "/mnt/user-data/outputs/" {
		t.Fatalf("destination drifted: %v", m["destination"])
	}
}

func TestRenderErrors(t *testing.T) {
	if _, err := Render([]byte("not json"), "u", "c", nil); err == nil {
		t.Fatal("Render accepted non-JSON template")
	}
	if _, err := Render([]byte(`{"service_url":"x"}`), "u", "c", nil); err == nil {
		t.Fatal("Render accepted a template with no mounts array")
	}
	noToken := `{"mounts":[{"filesystem_id":"fsrw"}]}`
	if _, err := Render([]byte(noToken), "u", "c", map[string]string{}); err == nil {
		t.Fatal("Render accepted a mount with no minted token")
	}
	noFSID := `{"mounts":[{"destination":"/x/"}]}`
	if _, err := Render([]byte(noFSID), "u", "c", map[string]string{}); err == nil {
		t.Fatal("Render accepted a mount with no filesystem_id")
	}
}

func TestRenderFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if err := RenderFile(in, out, "https://edge:8450", "CA", map[string]string{"fsrw": "tok"}); err != nil {
		t.Fatalf("RenderFile: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("RenderFile did not write the output: %v", err)
	}
	if err := RenderFile(filepath.Join(dir, "missing.json"), out, "u", "c", nil); err == nil {
		t.Fatal("RenderFile accepted a missing template path")
	}
}
