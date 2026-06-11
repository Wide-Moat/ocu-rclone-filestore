// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mountcfg loads and strictly validates the guest mount config.
//
// The guest config is host-supplied input. The loader refuses anything that is
// not a strict GuestMountConfig: unknown fields are rejected by strict decoding,
// every structural rule is enforced with a distinct typed error, and any
// provision-side credential marker is refused outright. The guest binary holds
// no backend credential by construction.
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
	FilesystemID    *string `json:"filesystem_id,omitempty"`
	MemoryStoreID   *string `json:"memory_store_id,omitempty"`
	Writes          *bool   `json:"writes,omitempty"`
	VfsCacheMode    string  `json:"vfs_cache_mode"`
	CacheDurationS  int     `json:"cache_duration_s"`
	VfsCacheMaxSize string  `json:"vfs_cache_max_size"`
	DirPerms        string  `json:"dir_perms"`
	FilePerms       string  `json:"file_perms"`
}

// Config is the guest-facing mount config. It carries no credential field; the
// bearer is injected at the egress edge and never seen in the guest.
type Config struct {
	SchemaVersion  string  `json:"schema_version"`
	ServiceURL     string  `json:"service_url"`
	Mounts         []Mount `json:"mounts"`
	ReadonlyMounts []Mount `json:"readonly_mounts,omitempty"`
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

// provisionMarkers are the provision-side credential fields the guest config
// must never carry. They are checked explicitly so the refusal is legible and
// independently testable, in addition to strict decoding rejecting them as
// unknown fields.
var provisionMarkers = []string{"auth_token", "ca_cert_pem"}

// Load reads and strictly validates a guest mount config from path.
//
// The config is decoded with unknown-field rejection into the guest variant,
// then every rule is validated. A failure returns a distinct typed error from
// this package naming the failing field (and mount index where applicable).
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	// Permissive pre-scan: refuse provision-side credential markers with a
	// clearly-messaged error before the generic unknown-field path can fire,
	// so the refusal is legible and independently asserted.
	if err := scanProvisionMarkers(raw); err != nil {
		return nil, err
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

// scanProvisionMarkers checks the top-level object and every mount entry for a
// provision-side credential marker and returns ErrProvisionMarker on the first
// hit, naming the marker and its location.
func scanProvisionMarkers(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		// Not an object, or malformed; the strict decoder reports the real error.
		return nil
	}
	for _, marker := range provisionMarkers {
		if _, ok := top[marker]; ok {
			return &ErrProvisionMarker{Marker: marker, Location: "top level"}
		}
	}
	for _, arr := range []string{"mounts", "readonly_mounts"} {
		rawArr, ok := top[arr]
		if !ok {
			continue
		}
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(rawArr, &entries); err != nil {
			continue
		}
		for i, entry := range entries {
			for _, marker := range provisionMarkers {
				if _, ok := entry[marker]; ok {
					return &ErrProvisionMarker{
						Marker:   marker,
						Location: fmt.Sprintf("%s[%d]", arr, i),
					}
				}
			}
		}
	}
	return nil
}

func validate(cfg *Config) error {
	if !schemaVersionRe.MatchString(cfg.SchemaVersion) {
		return &ErrSchemaVersion{Value: cfg.SchemaVersion}
	}
	if err := validateServiceURL(cfg.ServiceURL); err != nil {
		return err
	}
	// The schema lists mounts as required for GuestMountConfig: the key must be
	// present. An empty-but-present array is legal (the schema permits []);
	// absence is not. A nil slice means the key was absent or null — both are
	// rejected (null fails the schema's array type the same way).
	if cfg.Mounts == nil {
		return &ErrMissingField{Field: "mounts"}
	}
	if err := validateMounts(arrayMounts, cfg.Mounts, true); err != nil {
		return err
	}
	if err := validateMounts(arrayReadonlyMounts, cfg.ReadonlyMounts, false); err != nil {
		return err
	}
	return nil
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

func validateMounts(arr mountArray, mounts []Mount, wantWrites bool) error {
	for i, m := range mounts {
		if err := validateMount(arr, i, m, wantWrites); err != nil {
			return err
		}
	}
	return nil
}

func validateMount(arr mountArray, i int, m Mount, wantWrites bool) error {
	if !destinationRe.MatchString(m.Destination) {
		return &ErrDestination{Array: arr, Index: i, Value: m.Destination}
	}

	hasFS := m.FilesystemID != nil && *m.FilesystemID != ""
	hasMem := m.MemoryStoreID != nil && *m.MemoryStoreID != ""
	if hasFS == hasMem { // both set or neither set
		return &ErrMountScope{Array: arr, Index: i, HasFilesystem: hasFS, HasMemory: hasMem}
	}

	if m.Writes == nil {
		return &ErrWritesPosture{Array: arr, Index: i, Expected: wantWrites, Missing: true}
	}
	if *m.Writes != wantWrites {
		return &ErrWritesPosture{Array: arr, Index: i, Expected: wantWrites}
	}

	if !octalRe.MatchString(m.DirPerms) {
		return &ErrPerms{Array: arr, Index: i, Field: "dir_perms", Value: m.DirPerms}
	}
	if !octalRe.MatchString(m.FilePerms) {
		return &ErrPerms{Array: arr, Index: i, Field: "file_perms", Value: m.FilePerms}
	}
	if !byteSizeRe.MatchString(m.VfsCacheMaxSize) {
		return &ErrByteSize{Array: arr, Index: i, Value: m.VfsCacheMaxSize}
	}
	if _, ok := cacheModes[m.VfsCacheMode]; !ok {
		return &ErrCacheMode{Array: arr, Index: i, Value: m.VfsCacheMode}
	}
	return nil
}
