<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

## Summary

<!-- What changed and why. Keep it to the point a reviewer needs. -->

## Linked issue

<!-- e.g. Closes #123, Fixes #456. If there is no issue, say why. -->

## Type of change

<!-- Tick all that apply; the box maps to the conventional-commit type in the PR title. -->

- [ ] `fix` — bug fix
- [ ] `feat` — new feature
- [ ] `docs` — documentation only
- [ ] `refactor` — code change that neither fixes a bug nor adds a feature
- [ ] `test` — adding or correcting tests
- [ ] `ci` — CI configuration and pipelines
- [ ] `build` — build system, dependencies, or release tooling
- [ ] `chore` — anything else that does not affect runtime behaviour

## Checklist

- [ ] PR title is a conventional commit (`type(scope): summary`); the commit-lint gate enforces it.
- [ ] Tests added or updated for the change, and they pass. Bug fixes include a regression test that failed before the fix.
- [ ] `go test ./... -cover` is green and coverage did not drop (the ratchet never goes down).
- [ ] `go vet ./...` is clean.
- [ ] `gofmt -l .` prints nothing.
- [ ] `golangci-lint run` is clean (config: `.golangci.yml`).
- [ ] Every authored source file carries the FSL SPDX header; files derived from upstream rclone keep their upstream MIT header untouched.
- [ ] English only in code, comments, commit messages, and docs.
- [ ] No security boundary crossed: the guest holds no backend credential, no object-store client, and opens no second transport; every file operation still crosses the broker, and no authorization decision the broker should own moved into the guest.
- [ ] All CI gates are green: build (linux amd64 + arm64), vet, gofmt, golangci-lint, unit + conformance tests, the coverage ratchet, secret scanning, SAST, dependency CVE scanning, the lexicon job, the doc-slop gate, and conventional-commits.

## Security / boundary note

<!--
Describe any trust-boundary effect of this change, even if you believe there is
none ("no boundary effect" is a valid answer). Call out anything touching the
HTTPS/REST transport client, mount options, credential handling, or the network surface.
If this change has a security impact that should not be public, stop and follow
SECURITY.md (private vulnerability reporting) instead of describing it here.
-->

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the contribution workflow and [`SECURITY.md`](../SECURITY.md) for reporting vulnerabilities privately.
