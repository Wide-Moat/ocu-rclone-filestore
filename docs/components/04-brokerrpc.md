<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# `internal/brokerrpc` — the broker file-operations client

This is the one package in the mount that opens a socket. Every other guest
component reaches the broker through a `Client`, and a `Client` reaches nothing
else. It is bound at construction to a single per-session AF_UNIX socket path
and a single `filesystem_id`, and those two values are its entire view of the
world: no backend credential, no object-store client, no second transport, no
fallback host (SEC-25). `New` rejects an empty socket path or empty
`filesystem_id` rather than dialing a shared default.

The package owns the call path (unary Connect-JSON, plus the two streaming
transports), the op→intent stamp applied to every request, and the closed-code
error mapper that hands callers a typed Go error with a correct retry posture.
The exhaustive wire-level map — every request and response body, the frame
arithmetic, field-level divergences — lives in the
[wire reference](./07-wire-reference.md); this document stays at the level a
caller needs to use the client and reason about its guarantees.

## The single socket

`unixTransport` builds an `*http.Transport` whose `DialContext` ignores the
network and address the HTTP layer hands it and always dials the per-session
socket. There is no TLS on this path and compression is disabled. Two clients
built from two configs dial two different sockets; nothing in the package
reaches a shared constant. Unary requests POST to
`/ocu.filestore.v1alpha.FilesystemService/<op>` with a placeholder
`http://broker` host (the transport discards it) and the
`Connect-Protocol-Version: 1` header.

## Op → intent

There are 18 operations, each an `Op` constant whose value is the camelCase
method name in the route path. `opIntentTable` is the single authoritative
map from op to its authorization intent: the six read-class ops (`listDirectory`,
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
the request, POSTs it, and on a 2xx decodes the response; response structs
decode tolerantly so a future broker field does not break an existing decoder.

Code: `client.go` (`New`, `call`, `stamp`), `dialer.go` (`unixTransport`), `intent.go` (`opIntentTable`, `IntentFor`, `StampAuthMeta`).

## Deny → error, and the retry posture

A non-2xx unary body or an error trailer on a stream is a `ConnectError`
(a closed code plus a message). `MapConnectError` keys **on the Connect code**
and turns it into one of the package's typed sentinels, which callers match with
`errors.Is`:

| Connect code | Sentinel | Retry |
| --- | --- | --- |
| `permission_denied`, `unauthenticated` | `ErrPermissionDenied` | no |
| `invalid_argument` | `ErrInvalidArgument` | no |
| `not_found` | `ErrNotFound` | no |
| `already_exists` | `ErrAlreadyExists` | no |
| `resource_exhausted` | retryable (rclone retry error) | yes, with backoff |
| `unavailable` | retryable (rclone retry error) | yes, with backoff |
| `aborted` and any code not listed | `ErrPermanentOther` | no |

The default arm is deliberately permanent. `aborted` and any code outside the
closed set fall through to no-retry, because a wrong retryable default could
loop a write forever. Only `resource_exhausted` and `unavailable` are
retryable — the two backpressure-class codes (SEC-46) — and the mount must
tolerate that throttling rather than treat it as a hard failure.

The `x-deny-reason` response header (`scope_mismatch`, `intent_denied`,
`not_downloadable`, `lease_expired`) is informational only; it never drives the
mapping. The code decides the posture, the header explains it. A
`resource_exhausted` reply may carry a `Retry-After` header: when present and
within a sane bound it becomes a retry-after deadline the upstream pacer can
honour; a non-positive, non-finite, or absurd value is dropped so a malformed
header degrades to "retryable, no deadline" rather than a garbage sleep.

Code: `errors.go` (`MapConnectError`, `maxRetryAfterSeconds`), `stream.go` (`ConnectError`).

## Streaming and pagination

Two ops are not unary, and one read shape spans multiple responses. All three
share one rule worth stating up front: for a streaming op the **HTTP status is
always 200**, and success or failure lives only in the `EndStreamResponse`
trailer (frame flag `0x02`). A caller that trusts the status code instead of
reading the trailer is reading the wrong signal. Frames are a 5-byte prefix
(flag byte plus a big-endian length) followed by a JSON payload; `readFrame`
caps the length it will allocate so a corrupt or desynced length field cannot
turn 4 wire bytes into a multi-gigabyte allocation on the least-provisioned
party in the system.

**`Upload` (client-streaming `fileUpload`).** The first frame is the params
(destination path, `declared_size_bytes` = the total source size, the auth
stamp); the following data frames each carry one base64 chunk sized so the
*encoded* frame stays strictly under the message ceiling (default 256 KiB) —
sizing by raw bytes would push every frame to ~4/3 of the ceiling and draw
`resource_exhausted`. An explicit end-stream frame, not a bare body half-close,
tells the broker the upload is complete; without it the broker keeps waiting and
then aborts the already-assembled object as malformed. The frame writer and the
HTTP sender run concurrently over a pipe so the full payload is never buffered.

The result handling here carries the subtlety. When the broker ends the stream
early — a throttle, a frame over the ceiling, a permission failure — it replies
without draining the request body, the pipe closes, and the writer goroutine
fails with a pipe-closure error. That local error must **not** mask a parseable
error trailer, or the retryable backpressure posture is lost; `Upload` reads and
prefers the trailer verdict first, and only surfaces a genuine write fault when
there is no authoritative trailer. The `overwrite` argument distinguishes a
create-new write (the common path, which serialises no overwrite key at all)
from an overwrite-in-place write.

**`Download` / `DownloadRange` (server-streaming `fileDownload`).** The request
is a single params frame addressing the object by UUID; the response is a run of
content frames (each `{data: <base64>}`) terminated by the trailer. `Download`
concatenates every frame into the full object. `DownloadRange` sends an
`{offset, length}` window so the broker streams only those bytes, then clamps
the result to `length` as a defensive trim against a broker that over-delivers.
A frame that fails to decode is a **hard** error: on a FUSE-backed mount,
silently dropping a frame would surface as file corruption, so truncated content
is never returned as success. A stream that ends before the trailer is likewise
an error, not an empty success.

**Cursor pagination.** Listing is paged. `ListDirectory` and `ListFiles` each
return one page plus a continuation token (`Cursor` and `AfterUUID`
respectively); the token is exposed so a caller can tell a first page from a
complete listing instead of mistaking page 1 for the whole result.
`ListDirectoryAll` and `ListFilesAll` follow the token to completion. The token
is an `OpaqueCursor` — echoed back verbatim, never parsed or mutated, because it
may carry broker-internal scope and inspecting it could leak an enumeration path.
Both loops guard against a token that repeats unchanged: a non-advancing cursor
aborts rather than spinning forever with unbounded memory growth inside the
mount.

Code: `stream.go` (`readFrame`, `endStreamFlag`, `maxInboundFrame`), `upload.go` (`Upload`, `sourceChunkSize`), `download.go` (`Download`, `DownloadRange`), `cursor.go` (`ListDirectoryAll`, `ListFilesAll`, `OpaqueCursor`).

## See also

- [`07-wire-reference.md`](./07-wire-reference.md) — the authoritative
  message-by-message and field-by-field map: every request/response body, the
  frame envelope arithmetic, and the full code-to-error mapping.
- [`05-ocufs-backend.md`](./05-ocufs-backend.md) — the rclone backend that calls
  this client; where the read-only gate and path canonicalization live.
