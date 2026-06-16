// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package brokerrpc is the guest-side client for the broker's file-operations
// service.
//
// Design invariants (non-negotiable):
//
//   - One broker endpoint. The only egress path is the HTTPS service_url that
//     arrives from the guest mount config at construction time. The transport
//     dials that host over TLS whose sole trust anchor is the inspecting edge's
//     CA (ca_cert_pem); there is no second transport, no fallback, no
//     system-root trust on this path.
//
//   - One scope handle: filesystem_id. filesystem_id is the sole scope handle,
//     supplied at construction from the provisioned config. The guest holds no
//     backend credential and no object-store client.
//
//   - One static session credential. Every request carries a static
//     Authorization: Bearer <session JWT> header. The credential is read once at
//     construction and never refreshed: a token that expires yields a clean,
//     non-retryable permission error (the guest does not loop and does not
//     re-mint).
//
//   - REST-JSON transport over HTTP/2. Every unary request is a POST of a
//     protojson-compatible JSON body to <service_url>/v1/filestore/fs/<op>.
//     fileUpload is a multipart/form-data POST (a "params" JSON field plus a
//     streamed file part); fileDownload returns a chunked octet-stream body.
//     Errors are HTTP statuses mapped to typed sentinels with a fixed retry
//     posture (429/503 retryable; everything else permanent; 401 and 403 both
//     collapse to permission-denied).
//
//   - Three-axis authorization metadata on every request: intent (derived
//     centrally from the op via the package-level table), downloadable (always
//     false — the perimeter-exit decision is broker-resolved, never
//     guest-requested), and filesystem_id at the request top level.
//
// This package has no code path that sets downloadable to true and no
// credential-refresh path.
package brokerrpc
