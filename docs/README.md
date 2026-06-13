<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Documentation

This is the documentation for `ocu-rclone-filestore`, the guest-side mount
binary. Pick the door that matches what you came for.

## Start here, by what you need

| You want to… | Go to |
| --- | --- |
| Build it and see one mount work in five minutes | the [Quickstart](../README.md#quickstart) in the root README |
| Understand what it is and where it sits in the system | [`architecture.md`](./architecture.md) — trust boundaries, the host-side credential seam, the data path of one file operation |
| Read one package in depth | [`components/`](./components/README.md) — one document per package, in call-chain order, plus the deep wire reference |
| Run it locally against real brokers | [`e2e-local.md`](./e2e-local.md) — the Lima + docker-compose end-to-end harness |
| Know why this is a wrapper, not a fork of rclone | [`fork-shape.md`](./fork-shape.md) |
| Know the rules it must satisfy | [`requirements.md`](./requirements.md) — the invariants and defaults, distilled from the architecture canon |
| Know why the live e2e gate needs a real kernel | [`ci-fuse-decision.md`](./ci-fuse-decision.md) |

## A suggested first pass

1. Skim the root [README](../README.md) and run the **Quickstart**.
2. Read [`architecture.md`](./architecture.md) for the whole-system picture.
3. Dive into a package under [`components/`](./components/README.md) when you need
   to change one.

The **source of truth** for the system design is the architecture canon in
[`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use);
the documents here restate, in this project's own words, the parts that bear on
this binary.
