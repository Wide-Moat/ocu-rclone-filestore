<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Security Policy

This repository is the guest-side mount binary of Open Computer Use. It runs
inside an untrusted guest and is, by design, a security boundary: it holds no
backend credential and no object-store client, and every file operation crosses
the broker, which custodies the one credential and resolves authorization per
request. Because of that posture, security reports are handled with priority.

## Supported versions

Until the first tagged release the supported version is the `main` branch.
Once releases are tagged, this section will enumerate the supported release
line(s); fixes land on `main` first and are backported to supported lines.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
issue for a security report.

- Use GitHub's private vulnerability reporting on this repository
  (**Security → Report a vulnerability**). This is the preferred channel and
  keeps the report and its discussion private until a fix is released.

When reporting, include as much of the following as you can:

- the affected version, commit, or container image digest;
- a description of the issue and its impact, with the trust boundary it
  crosses (guest ↔ broker, or within the guest);
- reproduction steps or a proof of concept;
- any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- **Triage and an initial assessment** within 10 business days, including a
  severity judgement and whether the report is in scope.
- **Coordinated disclosure**: we agree a disclosure timeline with the reporter
  and credit reporters who wish to be named once a fix is available.

## Scope

In scope: anything that lets the guest bypass the broker boundary — a direct
network path to a backend, a second transport, credential or secret material
reaching the guest, an authorization decision the guest makes that the broker
should own, or a path that loses or corrupts data the broker acknowledged.

Out of scope: vulnerabilities in upstream dependencies (report those upstream;
we track and update dependencies), and issues that require an attacker who
already controls the broker or the host (those are outside this binary's trust
model — the broker is trusted by construction).

## Hardening already in place

- The guest holds no backend credential, no object-store client, and opens no
  second transport; the broker unix socket is the sole external channel.
- Release artifacts are built reproducibly (static, trimmed) and accompanied by
  checksums and an SBOM.
- CI blocks on secret scanning, SAST, and dependency CVE scanning before any
  change merges.
