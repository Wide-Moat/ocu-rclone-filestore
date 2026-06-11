// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package buildgraph holds a mechanical guard over the binary's dependency
// graph. The guest mount talks to exactly one south face — the broker — and
// holds no backend credential and no object-store client. This test proves
// that invariant structurally: no foreign object-store backend or SDK may
// enter the linked dependency graph. rclone is the one allowed external
// backend root the binary openly builds on; everything else listed below is
// an object-store client that must never be linked.
package buildgraph

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenRoots are import-path prefixes for foreign object-store
// clients/SDKs that must never appear in the linked dependency graph. The
// guest binary reaches storage only through the broker RPC; a direct
// object-store client would be a second transport, bypassing the broker.
//
// The set is expressed generically as the public import roots of the major
// object-store client families. It deliberately does not name any particular
// deployment or product — it names the client libraries themselves.
var forbiddenRoots = []string{
	// Amazon S3 SDKs (v1 and v2) and the standalone S3-compatible client.
	"github.com/aws/aws-sdk-go",
	"github.com/aws/aws-sdk-go-v2",
	"github.com/minio/minio-go",
	// Google Cloud Storage client and the CDK blob abstraction.
	"cloud.google.com/go/storage",
	"gocloud.dev/blob",
	// Azure Blob storage SDKs (track 1 and track 2).
	"github.com/Azure/azure-storage-blob-go",
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob",
	// Other widely used object-store client families.
	"github.com/Backblaze/blazer",
	"github.com/ncw/swift",
	"github.com/oracle/oci-go-sdk",
	"github.com/tencentyun/cos-go-sdk-v5",
	"github.com/aliyun/aliyun-oss-go-sdk",
	"github.com/baidubce/bce-sdk-go",
}

func TestNoForeignObjectStore(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./... failed: %v\n%s", err, out)
	}

	var violations []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "" {
			continue
		}
		for _, root := range forbiddenRoots {
			if dep == root || strings.HasPrefix(dep, root+"/") {
				violations = append(violations, dep+" (matched forbidden root "+root+")")
			}
		}
	}

	if len(violations) > 0 {
		t.Fatalf("forbidden object-store client(s) linked into the dependency graph:\n  %s\n"+
			"the guest binary must reach storage only through the broker RPC; no foreign object-store client may be linked",
			strings.Join(violations, "\n  "))
	}
}

// repoRoot returns the module root by walking up from the test's working
// directory until a go.mod is found, so `go list` runs against the whole
// module regardless of where the test binary is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolving module root failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}
