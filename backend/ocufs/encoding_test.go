// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocufs

import (
	"context"
	"testing"
)

// TestNewFsDefaultsEncodingWithoutRegistryLayer pins the production-seam
// encoding default (F-33): the mounter seam calls NewFs directly with a bare
// configmap, bypassing the registry-defaults layer that fs.NewFs applies, so
// NewFs itself must fall back to defaultEncoding when the map carries no
// "encoding" key. Without the fallback the production mount runs the identity
// path encoder while every fs.NewFs-constructed test runs the real one — a
// prod/test divergence on the wire path.
func TestNewFsDefaultsEncodingWithoutRegistryLayer(t *testing.T) {
	fb := startFakeBroker(t)

	// The bare key set, exactly what the mounter's buildOcufsConfigmap emits.
	m := newConfigMapForFake(fb, "fs-enc-default", false)
	fsAny, err := NewFs(context.Background(), "ocufs-enc", "", m)
	if err != nil {
		t.Fatalf("NewFs: %v", err)
	}
	f, ok := fsAny.(*Fs)
	if !ok {
		t.Fatalf("NewFs returned %T, want *Fs", fsAny)
	}
	if f.enc != defaultEncoding {
		t.Fatalf("NewFs without an encoding key left enc = %d, want defaultEncoding (%d): the production seam would run the identity path encoder", f.enc, defaultEncoding)
	}

	// An explicit "encoding" key still wins over the fallback.
	m2 := newConfigMapForFake(fb, "fs-enc-explicit", false)
	m2.Set("encoding", "None")
	fs2, err := NewFs(context.Background(), "ocufs-enc-explicit", "", m2)
	if err != nil {
		t.Fatalf("NewFs with explicit encoding: %v", err)
	}
	if got := fs2.(*Fs).enc; got == defaultEncoding {
		t.Fatalf("explicit encoding None was overridden by the fallback (enc=%d)", got)
	}
}
