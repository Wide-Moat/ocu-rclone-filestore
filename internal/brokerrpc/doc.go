// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc is the guest-side client for the broker's file-operations
// service under the ocu.filestore.v1alpha namespace.
//
// Design invariants (non-negotiable):
//
//   - One broker endpoint. The only egress path is the per-session AF_UNIX
//     socket whose path arrives from the guest mount config at construction
//     time. No second transport, no fallback, no shared-socket constant.
//
//   - One scope handle: filesystem_id. The guest holds no backend credential,
//     no object-store client, no upstream secret. filesystem_id is the sole
//     scope handle, supplied at construction from the provisioned config.
//
//   - Three-axis authorization metadata on every request: intent (derived
//     centrally from the op via the package-level table), downloadable (always
//     false — the perimeter-exit decision is broker-resolved, never
//     guest-requested), and filesystem_id at the request top level.
//
//   - Connect-JSON unary transport: every unary request is POST
//     application/json to /ocu.filestore.v1alpha.FilesystemService/<Op> with
//     the Connect-Protocol-Version: 1 header on every request. Streaming ops
//     (fileUpload, fileDownload) are defined as types here; their transport
//     is completed in a later phase.
//
// This package contains no Authorization header construction, no credential
// header handling, and no code path that sets downloadable to true.
package brokerrpc
