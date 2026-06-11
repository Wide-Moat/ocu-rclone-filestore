// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package brokerrpc_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/brokerrpc"
)

// readOps lists the ops whose correct intent is "read".
var readOps = []brokerrpc.Op{
	brokerrpc.OpListDirectory,
	brokerrpc.OpReadFile,
	brokerrpc.OpReadMetadata,
	brokerrpc.OpGetFileMetadata,
	brokerrpc.OpListFiles,
	brokerrpc.OpFileDownload,
}

// writeOps lists the ops whose correct intent is "write".
var writeOps = []brokerrpc.Op{
	brokerrpc.OpMakeDirectory,
	brokerrpc.OpMoveDirectory,
	brokerrpc.OpRemoveDirectory,
	brokerrpc.OpCreateFile,
	brokerrpc.OpCopyFile,
	brokerrpc.OpMoveFile,
	brokerrpc.OpRemoveFile,
	brokerrpc.OpFileUpload,
	brokerrpc.OpImportFiles,
	brokerrpc.OpImportZip,
	brokerrpc.OpMigrateFilesystem,
	brokerrpc.OpRemoveFilesystem,
}

// allOps is the canonical set of 18 ops. Used to verify coverage.
var allOps = append(readOps, writeOps...)

// TestIntentTableCoversAll18Ops verifies that the intent table resolves every
// one of the 18 op constants to a non-empty intent string, with no op missing.
func TestIntentTableCoversAll18Ops(t *testing.T) {
	if len(allOps) != 18 {
		t.Fatalf("allOps has %d entries; want 18", len(allOps))
	}

	for _, op := range allOps {
		intent, err := brokerrpc.IntentFor(op)
		if err != nil {
			t.Errorf("IntentFor(%v) returned error: %v", op, err)
			continue
		}
		if intent == "" {
			t.Errorf("IntentFor(%v) returned empty intent", op)
		}
	}
}

// TestReadOpsHaveReadIntent verifies that every read-class op resolves to the
// "read" intent string.
func TestReadOpsHaveReadIntent(t *testing.T) {
	for _, op := range readOps {
		intent, err := brokerrpc.IntentFor(op)
		if err != nil {
			t.Errorf("IntentFor(%v): %v", op, err)
			continue
		}
		if intent != "read" {
			t.Errorf("IntentFor(%v) = %q; want \"read\"", op, intent)
		}
	}
}

// TestWriteOpsHaveWriteIntent verifies that every write/mutate-class op
// resolves to the "write" intent string.
func TestWriteOpsHaveWriteIntent(t *testing.T) {
	for _, op := range writeOps {
		intent, err := brokerrpc.IntentFor(op)
		if err != nil {
			t.Errorf("IntentFor(%v): %v", op, err)
			continue
		}
		if intent != "write" {
			t.Errorf("IntentFor(%v) = %q; want \"write\"", op, intent)
		}
	}
}

// TestNoOpResolvesToPreviewIntent verifies that the preview intent is not
// assigned to any op. The mount never requests preview access.
func TestNoOpResolvesToPreviewIntent(t *testing.T) {
	for _, op := range allOps {
		intent, err := brokerrpc.IntentFor(op)
		if err != nil {
			t.Errorf("IntentFor(%v): %v", op, err)
			continue
		}
		if intent == "preview" {
			t.Errorf("IntentFor(%v) returned preview intent; the mount must never request preview", op)
		}
	}
}

// TestStampHelperDownloadableAlwaysFalse verifies that the stamp helper returns
// AuthorizationMetadata with downloadable hardcoded to false for every op.
func TestStampHelperDownloadableAlwaysFalse(t *testing.T) {
	for _, op := range allOps {
		am, err := brokerrpc.StampAuthMeta(op)
		if err != nil {
			t.Errorf("StampAuthMeta(%v): %v", op, err)
			continue
		}
		if am.Downloadable {
			t.Errorf("StampAuthMeta(%v).Downloadable = true; must always be false (SEC-73)", op)
		}
	}
}

// TestStampHelperIntentMatchesTable verifies that the stamp helper returns the
// same intent as IntentFor.
func TestStampHelperIntentMatchesTable(t *testing.T) {
	for _, op := range allOps {
		expected, err := brokerrpc.IntentFor(op)
		if err != nil {
			t.Errorf("IntentFor(%v): %v", op, err)
			continue
		}
		am, err := brokerrpc.StampAuthMeta(op)
		if err != nil {
			t.Errorf("StampAuthMeta(%v): %v", op, err)
			continue
		}
		if am.Intent != expected {
			t.Errorf("StampAuthMeta(%v).Intent = %q; want %q", op, am.Intent, expected)
		}
	}
}
