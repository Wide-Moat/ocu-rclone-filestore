// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestMountScaffoldStaysEmpty guards the safety precondition of the unconditional
// AllowNonEmpty=true pinned in internal/mounter/options.go: the FUSE mount is
// allowed over the non-empty /mnt/user-data scaffold ONLY because that scaffold
// holds zero files, so the mount shadows nothing.
//
// This test enforces that invariant at the source: the Dockerfile bakes the
// scaffold with `mkdir -p` (empty directories) and MUST NOT COPY or ADD any file
// into /mnt/user-data. If a future change stages real content there, the mount
// would silently shadow it — and AllowNonEmpty would become a data-loss hazard
// rather than a safe default. This test reds on that change, forcing a reviewer
// to either drop the baked content or make AllowNonEmpty conditional on an empty
// mountpoint. It is the invariant pin behind the flag pin.
func TestMountScaffoldStaysEmpty(t *testing.T) {
	f, err := os.Open("Dockerfile")
	if err != nil {
		t.Fatalf("open Dockerfile: %v", err)
	}
	defer f.Close()

	// A COPY or ADD whose destination lands anywhere under the mount root. The
	// scaffold is created only by mkdir; any COPY/ADD into it stages a file and
	// breaks the empty-scaffold invariant.
	copyIntoMount := regexp.MustCompile(`(?i)^\s*(COPY|ADD)\b.*\b/(staging/)?mnt/user-data\b`)

	var sawScaffoldMkdir bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "mkdir") && strings.Contains(line, "mnt/user-data") {
			sawScaffoldMkdir = true
		}
		if copyIntoMount.MatchString(line) {
			t.Errorf("Dockerfile stages content into the /mnt/user-data mount scaffold:\n  %s\n"+
				"The mounter pins AllowNonEmpty=true unconditionally, which is only safe while the "+
				"scaffold is empty (the FUSE mount would silently shadow any baked file). Either drop "+
				"the baked content, or make AllowNonEmpty conditional on an empty mountpoint before "+
				"mounting.", strings.TrimSpace(line))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan Dockerfile: %v", err)
	}
	// Guard against the guard silently going vacuous if the scaffold line is ever
	// renamed away: the mount root must still be created somewhere, or this test is
	// checking nothing.
	if !sawScaffoldMkdir {
		t.Fatal("no `mkdir ... mnt/user-data` found in Dockerfile — the scaffold-empty invariant this test guards may have moved; re-point the test at the new scaffold source")
	}
}
