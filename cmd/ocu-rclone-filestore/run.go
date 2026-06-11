// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mountcfg"
	"github.com/Wide-Moat/ocu-rclone-filestore/internal/mounter"
)

// run parses args, loads the guest mount config from the --config path, and
// drives the mounter seam. It returns a non-nil error on every failure path —
// a missing flag, a config that fails to load or validate, or the seam's
// not-implemented sentinel — and nil only on a clean shutdown. It never calls
// os.Exit; main maps the returned error to the process exit code.
//
// run takes its own FlagSet rather than the global one so it can be called
// repeatedly (the table test relies on this).
func run(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("ocu-rclone-filestore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the guest mount config file")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if *configPath == "" {
		return errors.New("missing required --config flag: pass the path to the guest mount config")
	}

	cfg, err := mountcfg.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return mounter.New().Mount(cfg)
}
