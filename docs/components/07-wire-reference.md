<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Wire reference — `internal/brokerrpc`

This is the exhaustive map of the wire `brokerrpc` speaks: the only egress path
the guest mount has to the broker's file-operations service. Everything the guest
sends, everything it must tolerate receiving, and the arithmetic and rules that
hold it together live here. Read the package README first for what the client is
for; this document is the byte-level contract.

Two invariants frame the whole surface and are stated once, here, rather than
repeated per op:

- **One egress, one scope handle.** Every request is an outbound HTTPS POST to
  the `service_url` that arrives in the mount config at construction, over TLS
  trusting only the edge CA (`ca_cert_pem`). No proxy, no fallback host, no
  shared-`service_url` constant. The guest holds no backend credential and no
  object-store client; the lone scope handle is `filesystem_id`, also supplied at
  construction, and the lone credential is a static session JWT presented as
  `Authorization: Bearer` — an edge-only assertion the egress edge exchanges for
  the real storage credential.
- **`downloadable` is never `true`.** The perimeter-exit decision is
  broker-resolved (SEC-73). No code path in this package sets the flag true,
  and `StampAuthMeta` hardcodes it false.

## Transport

Unary requests are REST-JSON: an HTTPS `POST` to
`<service_url>/v1/filestore/fs/<Op>` with a JSON body. Two headers are set on
every request — `Content-Type: application/json` and
`Authorization: Bearer <session JWT>`. The JWT is read once at construction and
never refreshed; an expired token draws a clean, non-retryable permission error
(no re-mint, no loop).

`fileUpload` is a `multipart/form-data` POST (a JSON `params` field plus a
streamed file part). `fileDownload` is a JSON POST whose 2xx response body is a
chunked `application/octet-stream`. For every op success or failure is the
**HTTP status** — there is no streaming trailer and no per-frame envelope.

A `Client` is bound at construction by `New` (or `NewWithOptions`) to its
`service_url`, `filesystem_id`, static `auth_token`, and `ca_cert_pem`; each must
be non-empty and the `service_url` must be `https://` or construction fails. The
one tunable is `MessageCeiling`, the per-write byte budget for the upload file
part, defaulting to 256 KiB.

Code: `transport.go` (`httpsTransport`), `client.go` (`opURL`, `restBase`, `call`, `setAuthHeader`, `New`, `NewWithOptions`).

## The 18 operations

Every request carries `filesystem_id` at the top level and an
`authorization_metadata` block. Path-scoped ops address by `path`; three ops
(`getFileMetadata`, `listFiles`, `fileDownload`) address by broker-minted
`uuid` handle — the guest never derives scope from a UUID. Rename/copy ops use
the bare field names `source` and `destination` (not `*_path`).

Intent is derived centrally from the op via one authoritative table; it is
never set by the caller. The `preview` intent exists in the service vocabulary
but the mount never requests it.

| # | Op (route segment) | Intent | Address | Transport | Request fields (beyond `filesystem_id` + `authorization_metadata`) | Response |
|---|---|---|---|---|---|---|
| 1 | `listDirectory` | read | path | unary | `path`; `cursor` on page 2+ | `ListDirectoryResponse` |
| 2 | `readFile` | read | path | unary | `path`, `range{offset,length}` | `ReadFileResponse` (metadata-only; see below) |
| 3 | `readMetadata` | read | path | unary | `path` | `ReadMetadataResponse` |
| 4 | `getFileMetadata` | read | uuid | unary | `uuid` | `GetFileMetadataResponse` |
| 5 | `listFiles` | read | uuid | unary | `uuid`; `after_uuid` on page 2+ | `ListFilesResponse` |
| 6 | `fileDownload` | read | uuid | chunked download | `uuid`, optional `range{offset,length}` | chunked octet-stream body |
| 7 | `makeDirectory` | write | path | unary | `path` | ack `{}` |
| 8 | `moveDirectory` | write | path | unary | `source`, `destination` | ack `{}` |
| 9 | `removeDirectory` | write | path | unary | `path` | ack `{}` |
| 10 | `createFile` | write | path | unary | `path` | `CreateFileResponse` |
| 11 | `copyFile` | write | path | unary | `source`, `destination`, `overwrite_existing` | ack `{}` |
| 12 | `moveFile` | write | path | unary | `source`, `destination`, `overwrite_existing` | ack `{}` |
| 13 | `removeFile` | write | path | unary | `path` | ack `{}` |
| 14 | `fileUpload` | write | path | multipart upload | `params` field + streamed file part | optional `FileUploadResponse` |
| 15 | `importFiles` | write | path | unary | `path` | ack `{}` |
| 16 | `importZip` | write | path | unary | `path` | ack `{}` |
| 17 | `migrateFilesystem` | write | — | unary | (none) | ack `{}` |
| 18 | `removeFilesystem` | write | — | unary | (none) | ack `{}` |

Ack responses decode to the empty `AckResponse` struct and tolerate any future
fields the broker adds. The unary `copyFile`/`moveFile` methods send
`overwrite_existing: true` — the operations layer has already decided the
mutation should proceed by the time it reaches the backend.

`readFile` is **metadata-only as shipped**: its response carries a `File` with
no content body, because the content field is contract-TBD and is not invented
here. The request `range` therefore selects within a body that is currently
absent. Bulk content arrives over `fileDownload`, not this op. A broker that
returns a content field has it silently dropped by the tolerant decoder until
the field is pinned.

Code: `intent.go` (the 18 `Op` constants, `opIntentTable`), `client.go` (per-op methods), `messages.go` (request/response types).

## Authorization metadata — three axes

`authorization_metadata` rides on every request body and carries two of the
three axes; the third sits at the request top level. The guest supplies all
three, but they are hints — host-attested attribution and the perimeter-exit
decision are authoritative broker-side (SEC-43, SEC-73).

| Axis | Where it lives | Value the guest sends | Set by |
|---|---|---|---|
| `intent` | inside `authorization_metadata` | `read` or `write`, op-derived | `StampAuthMeta` via `opIntentTable` |
| `downloadable` | inside `authorization_metadata` | always `false` | hardcoded in `StampAuthMeta` |
| `filesystem_id` | request top level (NOT inside the block) | the bound scope handle | `Client.stamp` |

`filesystem_id` living at the top level rather than inside the metadata block
is a deliberate divergence (D3); the two are intentionally not merged.
`StampAuthMeta` rejects any op absent from the intent table — an unknown op is
an implementation error, not a silent default.

Code: `messages.go` (`AuthorizationMetadata`), `intent.go` (`IntentFor`, `StampAuthMeta`), `client.go` (`stamp`).

## fileUpload — multipart, chunked file part

The upload is a `multipart/form-data` POST built over a pipe: a writer goroutine
emits the body while the HTTP client sends it, so the full payload is never
buffered. The body is two form fields:

1. **`params` field** — the JSON params object: `filesystem_id`, `path`,
   `declared_size_bytes` (the exact total source size), `authorization_metadata`,
   and an optional `overwrite_existing`.
2. **`file` part** — the source bytes, streamed in ceiling-bounded reads so a
   single `Write` stays under `MessageCeiling`; the part as a whole carries the
   exact source bytes.

The broker replies with an HTTP status. A 2xx is success and may carry an
optional `FileUploadResponse` JSON body with the assembled object's metadata; the
decoder tolerates its presence or absence. A non-2xx maps through `MapHTTPStatus`.

**`overwrite_existing` semantics.** A create-new write (Put) sends the field
`false`, and because it is `omitempty` the create-new path — the common case —
serialises no key at all, so a broker build predating the knob accepts it
unchanged. An overwrite-in-place write (Update) sends `true` so the broker
replaces the object atomically rather than forcing the guest into a non-atomic
remove-then-upload.

**Status-precedence rule.** When the broker ends the request early (a SEC-46
`429` throttle or a permission failure) it replies without draining the request
body; the transport closes the pipe and the writer goroutine fails with
`io.ErrClosedPipe`. `Upload` prefers the non-2xx status *before* considering the
writer error, and treats a pipe closure as the expected symptom of early
termination — not a local fault (`isPipeClosure`). On a 2xx it surfaces a write
error only when that error is not a pipe closure. A retryable backpressure
verdict must never be masked, or the SEC-46 posture (D4) is destroyed.

Because the multipart body is rebuilt from the same source on each attempt, a
`429` retry replays byte-identical content (the SC2 invariant).

### Chunk arithmetic

`sourceChunkSize` answers: how many raw source bytes per read keep a single
`Write` comfortably under the ceiling? The file part now streams raw bytes (no
per-chunk base64 envelope), so the budget is `ceiling − jsonEnvelopeOverhead`
and the read size is `3 × (budget / 4)`, floored at 3 so progress is guaranteed
even under a tiny ceiling. The conservative factor keeps each write well clear of
the ceiling.

The broker assembles the object only when the streamed total equals
`declared_size_bytes`; any over- or under-send draws `400`/`422`, which maps to a
permanent no-retry error.

Code: `upload.go` (`Upload`, `writeUploadMultipart`, `isPipeClosure`, `sourceChunkSize`, `jsonEnvelopeOverhead`, `uploadParamsFrame`), `messages.go` (`FileUploadResponse`).

## fileDownload — chunked octet-stream, ranged, UUID-addressed

The request is a JSON POST carrying `filesystem_id`, `uuid`, optional `range`,
and `authorization_metadata`. On a 2xx the broker streams the object bytes as a
chunked `application/octet-stream` body, read to completion. There is no per-chunk
JSON envelope; the body is the raw object bytes. A non-2xx maps through
`MapHTTPStatus` (the error body is read bounded for diagnostics).

The read is bounded by a download cap (16 GiB). The body is read through an
`io.LimitReader` of `cap+1`; a body over the cap is a **hard error**, never a
truncated success — for a FUSE-backed mount, silent truncation would surface as
file corruption, and the guest is the least-provisioned party that must never be
driven to OOM by a runaway stream.

Two entry points consume the same op:

- `Download(uuid)` — `range` omitted; the broker streams the whole object. The
  `*Range` field is a pointer with `omitempty`, so a full download serialises no
  `range` key and its request body is byte-identical to the no-range form.
- `DownloadRange(uuid, offset, length)` — sends the window so the broker streams
  only those bytes; a ranged read transfers just the requested window, not the
  whole object. Negative offset or length is rejected locally. After the read the
  result is defensively clamped to `length`: a broker that honoured the range
  returns exactly the window and the clamp is a no-op; a broker that over-delivers
  is trimmed so the caller never sees more than the contract. Offset is not
  re-applied locally — the broker already seeked to it.

Neither helper is the unary `readFile` op; they are the chunked ranged-read path
(D5).

Code: `download.go` (`Download`, `DownloadRange`, `doDownload`, `maxDownloadBytes`), `messages.go` (`FileDownloadRequest`, `Range`).

## Cursor pagination

Two listing ops page. `listDirectory` returns a `cursor`; `listFiles` returns an
`after_uuid`. Both are `OpaqueCursor` — transmitted as strings, echoed back
verbatim on the next request, never parsed or mutated. The opacity is a security
requirement: a cursor may carry broker-internal scope information, and inspecting
or rewriting it could break broker invariants or open an enumeration path
(D7 / D8).

The single-page methods (`ListDirectory`, `ListFiles`) expose the cursor so a
caller can tell page 1 from a complete listing — silent truncation is
detectable rather than disguised as the whole result. The aggregating methods
(`ListDirectoryAll`, `ListFilesAll`) follow the cursor across pages and return
the accumulated slice. Each carries a **progress guard**: if the broker echoes
the same cursor it was just handed, the loop aborts with an error rather than
spinning forever with unbounded memory growth inside the mount.

`listDirectory` entries are a pinned union, `ListDirEntry`: each entry is either
a `file` (a full `FilesystemFile`) XOR a `directory`, discriminated by which key
is present; exactly one arm is non-nil after decoding.

Code: `cursor.go` (`OpaqueCursor`, `ListDirectoryAll`, `ListFilesAll`, the page request/response types), `messages.go` (`ListDirEntry`, `ListDirectoryResponse`, `ListFilesResponse`).

## Error mapping

The broker reports errors as HTTP status codes, carried on a non-2xx response.
`MapHTTPStatus` keys on the **status first** and produces a typed filesystem
error that call sites match with `errors.Is`. The response body is appended to
the wrapped error message for diagnostics only and **never drives the mapping**.

| HTTP status | Sentinel / outcome | Retry posture | Notes |
|---|---|---|---|
| `401` | `ErrPermissionDenied` | permanent | token expiry; the credential is read once and never re-minted |
| `403` | `ErrPermissionDenied` | permanent | foreign scope; collapses to the same sentinel as `401` |
| `400`, `422` | `ErrInvalidArgument` | permanent | covers size-policy failures and malformed requests |
| `404` | `ErrNotFound` | permanent | includes the cross-scope-UUID anti-enumeration degrade (D8) |
| `409` | `ErrAlreadyExists` | permanent | the `overwrite_existing=false`-on-present-path conflict |
| `429` | retryable | retry with backoff | per-session throttle (SEC-46); honours `Retry-After` |
| `503` | retryable | retry with backoff | transient unavailability; no `Retry-After` honoured on this status |
| any other non-2xx | `ErrPermanentOther` | permanent | explicit no-retry default — a wrong retryable fallthrough could loop a write forever (D4, T-02-09) |

The `401`/`403` collapse is one-way: there is no `401→unauthenticated` /
`403→permission` split. Both yield the same clean, non-retryable EACCES.

`Retry-After` is honoured for `429` only. The header is parsed as decimal seconds
and bounded: a non-positive, non-finite (`inf`), or absurdly large value
(≥ 3600 s) is rejected as no usable hint, and the error stays retryable but
without a deadline. This bounded parse is the deliberate defense against a
malformed back-off header turning into a garbage `time.Duration`. A valid hint is
wrapped as a retry-after error so the upstream pacer can honour the broker's
deadline.

Code: `errors.go` (`MapHTTPStatus`, the four `Err*` sentinels, `ErrPermanentOther`, `maxRetryAfterSeconds`).

## Decoding discipline and TBD fields

All response types decode tolerantly — no `DisallowUnknownFields` — so a future
broker field pin (D6) cannot break an existing decoder. `File` and
`FilesystemFile` carry the same fields today but are kept as distinct wire
messages on purpose: a later pin may add a field to only one, and aliasing them
would silently couple the two. The `File` tags (`uuid`, `size`, `mtime`,
`mode`, `sha`, `mime`, `path`) are opaque, non-authorizing carriers.

Contract-**TBD** items, not invented here:

- The `readFile` response **content body** — TBD per D6. The type is
  metadata-only until the field is pinned.
- Any `FilesystemFile`-bearing metadata for a `fileDownload` is fetched via the
  metadata ops per D6; the download 2xx delivers raw object bytes, never a
  `{"file": …}` body.

No request carries a `metadata_retention_days` field (D6 reject).

Code: `messages.go` (`File`, `FilesystemFile`, `Directory`, `ReadFileResponse`, the response-type comments).
