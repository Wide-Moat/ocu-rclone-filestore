// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mountcfg loads and strictly validates the guest mount config.
//
// The guest config is host-supplied input. The loader refuses anything that is
// not the single mount-config shape: unknown fields are rejected by strict
// decoding, and every structural rule is enforced with a distinct typed error.
// The config carries the per-mount session token (auth_token) and the top-level
// trust anchor (ca_cert_pem); the loader holds them rather than refusing them.
package mountcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
)

// Mount is one provisioned mount entry. Pointer fields distinguish absence from
// a zero value so the loader can enforce presence rules.
type Mount struct {
	Destination     string  `json:"destination"`
	AuthToken       string  `json:"auth_token"`
	FilesystemID    *string `json:"filesystem_id,omitempty"`
	MemoryStoreID   *string `json:"memory_store_id,omitempty"`
	Readonly        *bool   `json:"readonly,omitempty"`
	VfsCacheMode    string  `json:"vfs_cache_mode"`
	CacheDurationS  *int    `json:"cache_duration_s,omitempty"`
	VfsCacheMaxSize string  `json:"vfs_cache_max_size"`
	DirPerms        string  `json:"dir_perms"`
	FilePerms       string  `json:"file_perms"`
}

// Config is the guest mount config. It carries the top-level trust anchor
// (ca_cert_pem) and a single mounts array; RW/RO is the per-mount readonly key.
type Config struct {
	SchemaVersion string  `json:"schema_version"`
	ServiceURL    string  `json:"service_url"`
	CACertPEM     string  `json:"ca_cert_pem"`
	Mounts        []Mount `json:"mounts"`
	// BackendCacheTTL is accepted but not consumed by the guest. The single
	// shape allows it as an optional top-level field; the loader decodes it so
	// strict decoding does not reject a config that carries it (and so the
	// loader and the frozen schema reach the same accept verdict).
	BackendCacheTTL *int `json:"backend_cache_ttl,omitempty"`
}

var (
	schemaVersionRe = regexp.MustCompile(`^v[0-9]+(alpha|beta)?[0-9]*$`)
	destinationRe   = regexp.MustCompile(`^/.+`)
	octalRe         = regexp.MustCompile(`^0[0-7]{3}$`)
	byteSizeRe      = regexp.MustCompile(`^[0-9]+(B|K|M|G|T)?$`)
)

var cacheModes = map[string]struct{}{
	"off":     {},
	"minimal": {},
	"writes":  {},
	"full":    {},
}

// Load reads and strictly validates a guest mount config from path.
//
// The config is decoded with unknown-field rejection, then every rule is
// validated. A failure returns a distinct typed error from this package naming
// the failing field (and mount index where applicable).
func Load(path string) (*Config, error) {
	// The path is the host-supplied --config provisioning input, the trusted
	// entry point of this binary's contract — not attacker-controlled. Reading
	// it by variable path is the intended behaviour.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: trusted host-provisioned config path
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, &ErrDecode{Err: err}
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validate(cfg *Config) error {
	if !schemaVersionRe.MatchString(cfg.SchemaVersion) {
		return &ErrSchemaVersion{Value: cfg.SchemaVersion}
	}
	if err := validateServiceURL(cfg.ServiceURL); err != nil {
		return err
	}
	// ca_cert_pem is a schema-required top-level field: the guest holds the
	// trust anchor for the egress hop, so its presence is a load-time rule.
	if cfg.CACertPEM == "" {
		return &ErrMissingField{Field: "ca_cert_pem"}
	}
	// The schema lists mounts as required: the key must be present. An
	// empty-but-present array is legal (the schema permits []); absence is not.
	// A nil slice means the key was absent or null — both are rejected.
	if cfg.Mounts == nil {
		return &ErrMissingField{Field: "mounts"}
	}
	return validateMounts(cfg.Mounts)
}

func validateServiceURL(raw string) error {
	if len(raw) < len("https://") || raw[:len("https://")] != "https://" {
		return &ErrServiceURL{Value: raw, Reason: "must begin https://"}
	}
	if _, err := url.ParseRequestURI(raw); err != nil {
		return &ErrServiceURL{Value: raw, Reason: "is not a parseable URI"}
	}
	return nil
}

func validateMounts(mounts []Mount) error {
	for i, m := range mounts {
		if err := validateMount(i, m); err != nil {
			return err
		}
	}
	return nil
}

func validateMount(i int, m Mount) error {
	if !destinationRe.MatchString(m.Destination) {
		return &ErrDestination{Index: i, Value: m.Destination}
	}

	if m.AuthToken == "" {
		return &ErrAuthToken{Index: i}
	}

	// The scope XOR keys on presence of the field, exactly as the schema's
	// oneOf does: an explicit empty string is present and still trips the
	// both-set error. A present-but-empty id is separately invalid (the schema
	// requires minLength 1).
	hasFS := m.FilesystemID != nil
	hasMem := m.MemoryStoreID != nil
	if hasFS == hasMem { // both present or neither present
		return &ErrMountScope{Index: i, HasFilesystem: hasFS, HasMemory: hasMem}
	}
	if hasFS && *m.FilesystemID == "" {
		return &ErrScopeID{Index: i, Field: "filesystem_id"}
	}
	if hasMem && *m.MemoryStoreID == "" {
		return &ErrScopeID{Index: i, Field: "memory_store_id"}
	}

	// readonly is schema-required per mount and carries the RW/RO posture.
	// The pointer distinguishes an absent field from an explicit false; both
	// true and false are legal, only absence is rejected.
	if m.Readonly == nil {
		return &ErrReadonlyMissing{Index: i}
	}

	// cache_duration_s is schema-required with minimum 0. The pointer
	// distinguishes an absent field from an explicit 0 (0 is legal; absence is
	// not).
	if m.CacheDurationS == nil {
		return &ErrCacheDuration{Index: i, Missing: true}
	}
	if *m.CacheDurationS < 0 {
		return &ErrCacheDuration{Index: i, Value: *m.CacheDurationS}
	}

	if !octalRe.MatchString(m.DirPerms) {
		return &ErrPerms{Index: i, Field: "dir_perms", Value: m.DirPerms}
	}
	if !octalRe.MatchString(m.FilePerms) {
		return &ErrPerms{Index: i, Field: "file_perms", Value: m.FilePerms}
	}
	if !byteSizeRe.MatchString(m.VfsCacheMaxSize) {
		return &ErrByteSize{Index: i, Value: m.VfsCacheMaxSize}
	}
	if _, ok := cacheModes[m.VfsCacheMode]; !ok {
		return &ErrCacheMode{Index: i, Value: m.VfsCacheMode}
	}
	return nil
}
