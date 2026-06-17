// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocufs tests — client.go production adapter forwarding.
//
// These tests construct a REAL brokerClientAdapter over the in-process fake
// broker served from an httptest TLS server (fakebroker_test.go) and drive every
// adapter method end-to-end. Each adapter method is a single forwarding call
// into *brokerrpc.Client; exercising it against the fake confirms the method
// reaches the wire, builds the right route, and decodes the canned response —
// not just that the line was touched.
package ocufs

import (
	"bytes"
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
	"github.com/rclone/rclone/fs/config/configmap"
)

// newConfigMapForFake builds the configmap NewFs consumes for a fake-broker
// mount: the broker's HTTPS service_url, the session-scoped filesystem_id, the
// static session credential, the TLS trust anchor, and the read-only flag.
func newConfigMapForFake(fb fakeBroker, fsID string, readOnly bool) configmap.Simple {
	m := configmap.Simple{
		"service_url":   fb.url,
		"filesystem_id": fsID,
		"auth_token":    fakeBrokerAuthToken,
		"ca_cert_pem":   string(fb.certPEM),
	}
	if readOnly {
		m["read_only"] = "true"
	}
	return m
}

// newAdapterOverFakeBroker constructs a production brokerClientAdapter wired to
// a real *brokerrpc.Client bound to the fake broker's HTTPS endpoint over TLS.
// The returned brokerClient is the exact production seam NewFs installs.
func newAdapterOverFakeBroker(t *testing.T) brokerClient {
	t.Helper()
	fb := startFakeBroker(t)
	c, err := brokerrpc.New(fb.url, "fs-adapter-test", fakeBrokerAuthToken, fb.certPEM)
	if err != nil {
		t.Fatalf("brokerrpc.New(%q): %v", fb.url, err)
	}
	return newBrokerClientAdapter(c)
}

// TestAdapterListDirectoryAllForwards confirms ListDirectoryAll forwards to the
// broker and decodes the pinned union page (one file arm + one directory arm).
func TestAdapterListDirectoryAllForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	entries, err := a.ListDirectoryAll(context.Background(), "/testdir")
	if err != nil {
		t.Fatalf("ListDirectoryAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("ListDirectoryAll returned %d entries, want 2 (file arm + dir arm)", len(entries))
	}
	if entries[0].File == nil {
		t.Errorf("entries[0].File is nil, want the file arm")
	}
	if entries[1].Directory == nil {
		t.Errorf("entries[1].Directory is nil, want the directory arm")
	}
}

// TestAdapterReadMetadataForwards confirms ReadMetadata forwards to the broker
// and decodes the canned file-arm response carrying the requested path.
func TestAdapterReadMetadataForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	const path = "/meta/file.txt"
	resp, err := a.ReadMetadata(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if resp == nil {
		t.Fatal("ReadMetadata returned nil response")
	}
	if resp.File.Path != path {
		t.Errorf("ReadMetadata File.Path = %q, want %q", resp.File.Path, path)
	}
	if resp.File.UUID == "" {
		t.Error("ReadMetadata File.UUID is empty, want the canned uuid")
	}
}

// TestAdapterDownloadForwards confirms Download forwards to the broker's
// fileDownload stream and returns the canned content bytes.
func TestAdapterDownloadForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	data, err := a.Download(context.Background(), "uuid-download")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(data, fakeBrokerContentBytes) {
		t.Errorf("Download returned %q, want %q", data, fakeBrokerContentBytes)
	}
}

// TestAdapterDownloadRangeForwards confirms DownloadRange forwards to the
// broker and that the returned slice is clamped to the requested length.
func TestAdapterDownloadRangeForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	const length = int64(5)
	data, err := a.DownloadRange(context.Background(), "uuid-range", 0, length)
	if err != nil {
		t.Fatalf("DownloadRange: %v", err)
	}
	// The fake serves the full canned bytes; DownloadRange's defensive clamp
	// trims to the requested length.
	if int64(len(data)) != length {
		t.Errorf("DownloadRange returned %d bytes, want %d (clamped to requested length)", len(data), length)
	}
	if !bytes.Equal(data, fakeBrokerContentBytes[:length]) {
		t.Errorf("DownloadRange returned %q, want %q", data, fakeBrokerContentBytes[:length])
	}
}

// TestAdapterUploadForwards confirms Upload forwards the client-streaming
// fileUpload op and succeeds against the canned end-stream trailer.
func TestAdapterUploadForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	content := []byte("adapter upload payload")
	err := a.Upload(context.Background(), "/up/file.bin", bytes.NewReader(content), int64(len(content)), false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
}

// newCapturingAdapterOverFakeBroker constructs a production brokerClientAdapter
// wired to a capturing fake broker, returning the adapter and the capture handle
// so a test can assert which path reached which wire slot for the two-path ops.
func newCapturingAdapterOverFakeBroker(t *testing.T) (brokerClient, *capturingBroker) {
	t.Helper()
	fb, cap := startCapturingFakeBroker(t)
	c, err := brokerrpc.New(fb.url, "fs-adapter-cap-test", fakeBrokerAuthToken, fb.certPEM)
	if err != nil {
		t.Fatalf("brokerrpc.New(%q): %v", fb.url, err)
	}
	return newBrokerClientAdapter(c), cap
}

// TestAdapterCopyFileForwards confirms CopyFile forwards, decodes the ack, AND
// that the distinct source and destination land in their correct wire slots —
// source in `source`, destination in `destination`, not transposed. The
// capturing broker decodes the request body the client marshalled so a slot
// swap in the client-to-wire mapping is caught, not silently passed.
func TestAdapterCopyFileForwards(t *testing.T) {
	a, cap := newCapturingAdapterOverFakeBroker(t)
	const (
		src = "/copy/source.txt"
		dst = "/copy/destination.txt"
	)
	ack, err := a.CopyFile(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("CopyFile: %v", err)
	}
	if ack == nil {
		t.Fatal("CopyFile returned nil ack")
	}
	if n := cap.callCount("copyFile"); n != 1 {
		t.Fatalf("copyFile reached the broker %d times, want exactly 1", n)
	}
	body, ok := cap.lastTwoPath("copyFile")
	if !ok {
		t.Fatal("copyFile never reached the broker; want one captured request")
	}
	if body.Source != src {
		t.Errorf("copyFile wire source = %q, want %q (source must land in the source slot)", body.Source, src)
	}
	if body.Destination != dst {
		t.Errorf("copyFile wire destination = %q, want %q (destination must land in the destination slot, not transposed with source)", body.Destination, dst)
	}
}

// TestAdapterMoveFileForwards confirms MoveFile forwards, decodes the ack, and
// that source and destination reach the correct wire slots without transposition.
func TestAdapterMoveFileForwards(t *testing.T) {
	a, cap := newCapturingAdapterOverFakeBroker(t)
	const (
		src = "/move/source.txt"
		dst = "/move/destination.txt"
	)
	ack, err := a.MoveFile(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	if ack == nil {
		t.Fatal("MoveFile returned nil ack")
	}
	if n := cap.callCount("moveFile"); n != 1 {
		t.Fatalf("moveFile reached the broker %d times, want exactly 1", n)
	}
	body, ok := cap.lastTwoPath("moveFile")
	if !ok {
		t.Fatal("moveFile never reached the broker; want one captured request")
	}
	if body.Source != src {
		t.Errorf("moveFile wire source = %q, want %q (source must land in the source slot)", body.Source, src)
	}
	if body.Destination != dst {
		t.Errorf("moveFile wire destination = %q, want %q (destination must land in the destination slot, not transposed with source)", body.Destination, dst)
	}
}

// TestAdapterRemoveFileForwards confirms RemoveFile forwards and decodes the ack.
func TestAdapterRemoveFileForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	ack, err := a.RemoveFile(context.Background(), "/gone.txt")
	if err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if ack == nil {
		t.Fatal("RemoveFile returned nil ack")
	}
}

// TestAdapterMakeDirectoryForwards confirms MakeDirectory forwards and decodes
// the ack.
func TestAdapterMakeDirectoryForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	ack, err := a.MakeDirectory(context.Background(), "/newdir")
	if err != nil {
		t.Fatalf("MakeDirectory: %v", err)
	}
	if ack == nil {
		t.Fatal("MakeDirectory returned nil ack")
	}
}

// TestAdapterRemoveDirectoryForwards confirms RemoveDirectory forwards and
// decodes the ack.
func TestAdapterRemoveDirectoryForwards(t *testing.T) {
	a := newAdapterOverFakeBroker(t)
	ack, err := a.RemoveDirectory(context.Background(), "/olddir")
	if err != nil {
		t.Fatalf("RemoveDirectory: %v", err)
	}
	if ack == nil {
		t.Fatal("RemoveDirectory returned nil ack")
	}
}

// TestAdapterMoveDirectoryForwards confirms MoveDirectory forwards, decodes the
// ack, and that the distinct source and destination directories reach the
// correct wire slots without transposition.
func TestAdapterMoveDirectoryForwards(t *testing.T) {
	a, cap := newCapturingAdapterOverFakeBroker(t)
	const (
		src = "/dirs/source"
		dst = "/dirs/destination"
	)
	ack, err := a.MoveDirectory(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("MoveDirectory: %v", err)
	}
	if ack == nil {
		t.Fatal("MoveDirectory returned nil ack")
	}
	if n := cap.callCount("moveDirectory"); n != 1 {
		t.Fatalf("moveDirectory reached the broker %d times, want exactly 1", n)
	}
	body, ok := cap.lastTwoPath("moveDirectory")
	if !ok {
		t.Fatal("moveDirectory never reached the broker; want one captured request")
	}
	if body.Source != src {
		t.Errorf("moveDirectory wire source = %q, want %q (source must land in the source slot)", body.Source, src)
	}
	if body.Destination != dst {
		t.Errorf("moveDirectory wire destination = %q, want %q (destination must land in the destination slot, not transposed with source)", body.Destination, dst)
	}
}

// TestNewFsParseOptionsError verifies that NewFs surfaces a configstruct parse
// error: a non-boolean read_only value cannot be parsed into the bool field, so
// option parsing fails before any socket validation or broker dial.
func TestNewFsParseOptionsError(t *testing.T) {
	m := configmap.Simple{
		"service_url":   "https://broker",
		"filesystem_id": "fs-01",
		"auth_token":    "t",
		"ca_cert_pem":   "pem",
		"read_only":     "not-a-bool", // unparseable as bool → configstruct.Set error
	}
	_, err := NewFs(context.Background(), "test", "/", m)
	if err == nil {
		t.Fatal("NewFs with an unparseable read_only returned nil error, want a parse error")
	}
}

// TestNewFsReadOnlyMountWired exercises the read-only NewFs path: a read_only
// mount produces an Fs whose readOnly flag is set, constructed over TLS.
func TestNewFsReadOnlyMountWired(t *testing.T) {
	fb := startFakeBroker(t)
	m := newConfigMapForFake(fb, "fs-ro-test", true)

	fsAny, err := NewFs(context.Background(), "ocufs-ro", "/", m)
	if err != nil {
		t.Fatalf("NewFs (read-only): %v", err)
	}
	f, ok := fsAny.(*Fs)
	if !ok {
		t.Fatalf("NewFs returned %T, want *Fs", fsAny)
	}
	if !f.readOnly {
		t.Error("readOnly = false, want true for a read-only mount")
	}
}

// TestNewFsConstructsAdapterOverService exercises the NewFs success path end to
// end: a real config map (service_url + filesystem_id + auth_token + ca_cert_pem)
// drives NewFs through brokerrpc.New and installs the production
// brokerClientAdapter. A subsequent List proves the constructed Fs actually
// reaches the fake broker over TLS (NewFs does not dial synchronously; the first
// RPC does).
func TestNewFsConstructsAdapterOverService(t *testing.T) {
	fb := startFakeBroker(t)
	m := newConfigMapForFake(fb, "fs-newfs-test", false)

	fsAny, err := NewFs(context.Background(), "ocufs-newfs", "/", m)
	if err != nil {
		t.Fatalf("NewFs: %v", err)
	}
	f, ok := fsAny.(*Fs)
	if !ok {
		t.Fatalf("NewFs returned %T, want *Fs", fsAny)
	}
	if f.Name() != "ocufs-newfs" {
		t.Errorf("Name() = %q, want %q", f.Name(), "ocufs-newfs")
	}
	if f.readOnly {
		t.Error("readOnly = true, want false for a writable mount")
	}

	// Drive a real RPC through the installed adapter to prove the socket wiring.
	entries, err := f.List(context.Background(), "testdir")
	if err != nil {
		t.Fatalf("List over constructed Fs: %v", err)
	}
	if len(entries) == 0 {
		t.Error("List over constructed Fs returned no entries, want the canned page")
	}
}
