<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# `internal/brokerrpc` — the broker file-operations client

This is the one package in the mount that opens an outbound connection. Every
other guest component reaches the broker through a `Client`, and a `Client`
reaches nothing else. It is bound at construction to the broker's HTTPS
`service_url`, a single `filesystem_id`, a static session JWT, and the PEM trust
anchor for the inspecting edge (`ca_cert_pem`). Those four values are its entire
view of the world: no backend credential, no object-store client, no second
transport, no fallback host (SEC-25). `New` rejects an empty or non-`https://`
`service_url`, an empty `filesystem_id`, an empty `authToken`, or an empty
`caCertPEM` rather than dialing a shared default.

The package owns the call path (unary REST-JSON, plus the multipart upload and
chunked download transports), the op→intent stamp applied to every request, and
the HTTP-status error mapper that hands callers a typed Go error with a correct
retry posture. The exhaustive wire-level map — every request and response body,
the multipart and chunk shapes, field-level divergences — lives in the
[wire reference](./07-wire-reference.md); this document stays at the level a
caller needs to use the client and reason about its guarantees.

## The single outbound connection

`httpsTransport` builds an `*http.Transport` whose TLS config trusts only the
edge CA parsed from `ca_cert_pem` — never the system roots. There is no second
transport and no fallback host. Two clients built from two configs reach two
different `service_url`s; nothing in the package reaches a shared constant. Unary
requests POST `application/json` to `<service_url>/v1/filestore/fs/<op>` with a
static `Authorization: Bearer <session JWT>` header. The JWT is read once at
construction and never refreshed: an expired token yields a clean, non-retryable
permission error, with no re-mint and no loop.

## Op → intent

There are 18 operations, each an `Op` constant whose value is the final path
segment of the REST route. `opIntentTable` is the single authoritative map from
op to its authorization intent: the six read-class ops (`listDirectory`,
`readFile`, `readMetadata`, `getFileMetadata`, `listFiles`, `fileDownload`)
resolve to `read`; the twelve mutate-class ops resolve to `write`. `IntentFor`
reads that table and treats an op missing from it as an implementation error,
not a silent default.

Every request carries an `AuthorizationMetadata` value produced by
`StampAuthMeta`: the op-derived intent plus `downloadable` hardcoded to
`false`. The mount never sets `downloadable` true and never requests the
`preview` intent that exists in the service vocabulary — the perimeter-exit
decision is the broker's to resolve, never the guest's to ask for (SEC-73).
`filesystem_id` rides at the request top level, not inside the metadata. The
UUID-addressed ops (`getFileMetadata`, `listFiles`, `fileDownload`) carry a
broker-minted handle, and the guest never derives scope from it.

The unary methods on `Client` are thin: each stamps its op, fills the
op-specific request fields, and runs the shared `call` helper. `call` marshals
the request, POSTs it over HTTPS with the static Bearer header, and on a 2xx
decodes the response; response structs decode tolerantly so a future broker
field does not break an existing decoder.

Code: `client.go` (`New`, `call`, `stamp`, `setAuthHeader`), `transport.go` (`httpsTransport`), `intent.go` (`opIntentTable`, `IntentFor`, `StampAuthMeta`).

## Deny → error, and the retry posture

A non-2xx response is mapped by `MapHTTPStatus`, which keys **on the HTTP
status** and turns it into one of the package's typed sentinels, which callers
match with `errors.Is`:

| HTTP status | Sentinel | Retry |
| --- | --- | --- |
| `401` (token expiry), `403` (foreign scope) | `ErrPermissionDenied` | no |
| `400`, `422` | `ErrInvalidArgument` | no |
| `404` | `ErrNotFound` | no |
| `409` | `ErrAlreadyExists` | no |
| `429` (too many requests) | retryable (rclone retry error) | yes, with backoff |
| `503` (unavailable) | retryable (rclone retry error) | yes, with backoff |
| any other non-2xx status | `ErrPermanentOther` | no |

The default arm is deliberately permanent. Any status outside the mapped set
falls through to no-retry, because a wrong retryable default could loop a write
forever. Only `429` and `503` are retryable — the two backpressure-class
statuses (SEC-46) — and the mount must tolerate that throttling rather than treat
it as a hard failure.

The `401`/`403` collapse is one-way: a token that simply expires yields the same
clean, non-retryable EACCES as a foreign-scope denial, with no `401→unauth` /
`403→permission` split. The response body is carried into the wrapped error
message for diagnostics only; it never drives the mapping. A `429` reply may
carry a `Retry-After` header: when present and within a sane bound it becomes a
retry-after deadline the upstream pacer can honour; a non-positive, non-finite,
or absurd value is dropped so a malformed header degrades to "retryable, no
deadline" rather than a garbage sleep.

Code: `errors.go` (`MapHTTPStatus`, `maxRetryAfterSeconds`).

## Upload, download, and pagination

**`Upload` (`fileUpload`).** The op is a `multipart/form-data` POST. The first
form field, `params`, is the JSON params object (destination path,
`declared_size_bytes` = the total source size, optional `overwrite_existing`, and
the auth stamp); the file part streams the source bytes in ceiling-bounded reads
so a single write stays under the message ceiling (default 256 KiB). The
multipart body is built over a pipe so the writer and the HTTP sender run
concurrently and the full payload is never buffered. Because the body is rebuilt
from the same source on each attempt, a `429` retry replays byte-identical
content (the SC2 invariant).

Success or failure is the **HTTP status**. The result handling carries the
subtlety. When the broker ends the request early — a throttle, a permission
failure — it replies without draining the request body, the pipe closes, and the
writer goroutine fails with a pipe-closure error. That local error must **not**
mask the retryable backpressure verdict the status carries; `Upload` prefers the
non-2xx status first, and surfaces a genuine write fault only on a 2xx where the
write error is not a pipe closure. The `overwrite` argument selects whether an
existing destination is replaced; both backend write paths pass `true` —
Update for the atomic in-place replace, Put because rclone re-drives it after
an ambiguous first attempt and it must be idempotent at the destination path.

**`Download` / `DownloadRange` (`fileDownload`).** The request is a JSON POST
addressing the object by UUID; on a 2xx the broker streams the object bytes as a
chunked `application/octet-stream` body, read to completion. The read is bounded
by a download cap (16 GiB) so a runaway stream cannot OOM the least-provisioned
party in the system: a body over the cap is a hard error, never a truncated
success. `Download` returns the full object. `DownloadRange` sends an
`{offset, length}` window so the broker streams only those bytes; it rejects a
negative offset or length up front, answers a length-0 window with an empty
reader and no wire call, and bounds the stream strictly to `length` — the wire
carries no range echo, so over-delivery is the one verifiable signature of a
dishonoured range, and it fails as an error rather than being trimmed into
wrong-but-plausible bytes. A non-2xx maps through `MapHTTPStatus`.

**Cursor pagination.** Listing is paged. `ListDirectory` and `ListFiles` each
return one page plus a continuation token (`Cursor` and `AfterUUID`
respectively); the token is exposed so a caller can tell a first page from a
complete listing instead of mistaking page 1 for the whole result.
`ListDirectoryAll` and `ListFilesAll` follow the token to completion. The token
is an `OpaqueCursor` — echoed back verbatim, never parsed or mutated, because it
may carry broker-internal scope and inspecting it could leak an enumeration path.
Both loops carry a progress guard: a token that repeats at any distance (a
pagination cycle, caught by a fixed-size digest set) or a listing that runs
past the hard page ceiling aborts with an error rather than spinning forever
with unbounded memory growth inside the mount.

Code: `upload.go` (`Upload`, `isPipeClosure`, `sourceChunkSize`), `download.go` (`Download`, `DownloadRange`, `doDownload`), `cursor.go` (`ListDirectoryAll`, `ListFilesAll`, `OpaqueCursor`).

## See also

- [`07-wire-reference.md`](./07-wire-reference.md) — the authoritative
  message-by-message and field-by-field map: every request/response body, the
  multipart and chunk shapes, and the full status-to-error mapping.
- [`05-ocufs-backend.md`](./05-ocufs-backend.md) — the rclone backend that calls
  this client; where the read-only gate and path canonicalization live.
