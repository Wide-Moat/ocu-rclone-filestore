<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Wire reference — `internal/brokerrpc`

This is the exhaustive map of the wire `brokerrpc` speaks: the only egress path
the guest mount has to the broker's file-operations service under the
`ocu.filestore.v1alpha` namespace. Everything the guest sends, everything it
must tolerate receiving, and the arithmetic and rules that hold it together
live here. Read the package README first for what the client is for; this
document is the byte-level contract.

Two invariants frame the whole surface and are stated once, here, rather than
repeated per op:

- **One egress, one scope handle.** Every connection dials a single
  per-session AF_UNIX socket whose path arrives in the mount config at
  construction. No TLS, no proxy, no fallback, no shared-socket constant. The
  guest holds no credential and no object-store client; the lone scope handle
  is `filesystem_id`, also supplied at construction.
- **`downloadable` is never `true`.** The perimeter-exit decision is
  broker-resolved (SEC-73). No code path in this package sets the flag true,
  and `StampAuthMeta` hardcodes it false.

## Transport

Unary requests are Connect-JSON: an HTTP/1.1 `POST` to
`/ocu.filestore.v1alpha.FilesystemService/<Op>` with a JSON body. Two headers
are mandatory on every request — `Content-Type: application/json` and
`Connect-Protocol-Version: 1`. The URL host is the placeholder `http://broker`;
the transport's `DialContext` ignores host and network entirely and always
dials the bound socket, so the host string only exists to satisfy the standard
library's request builder.

Streaming ops (`fileUpload`, `fileDownload`) use the same route scheme but
`Content-Type: application/connect+json`, and their bodies are framed (see the
frame envelope below). A streaming response **always returns HTTP 200** — the
status line never carries the verdict. Success or failure lives exclusively in
the `EndStreamResponse` trailer frame, which the caller must read.

A `Client` is bound at construction by `New` (or `NewWithOptions`) to its
socket path and `filesystem_id`; both must be non-empty or construction fails.
The one tunable is `MessageCeiling`, the per-encoded-chunk-frame byte budget,
defaulting to 256 KiB.

Code: `dialer.go` (`unixTransport`), `client.go` (`serviceBase`, `call`, `New`, `NewWithOptions`), `stream.go` (`streamingURL`).

## The 18 operations

Every request carries `filesystem_id` at the top level and an
`authorization_metadata` block. Path-scoped ops address by `path`; three ops
(`getFileMetadata`, `listFiles`, `fileDownload`) address by broker-minted
`uuid` handle — the guest never derives scope from a UUID. Rename/copy ops use
the bare field names `source` and `destination` (not `*_path`).

Intent is derived centrally from the op via one authoritative table; it is
never set by the caller. The `preview` intent exists in the service vocabulary
but the mount never requests it.

| # | Op (route method) | Intent | Address | Transport | Request fields (beyond `filesystem_id` + `authorization_metadata`) | Response |
|---|---|---|---|---|---|---|
| 1 | `listDirectory` | read | path | unary | `path`; `cursor` on page 2+ | `ListDirectoryResponse` |
| 2 | `readFile` | read | path | unary | `path`, `range{offset,length}` | `ReadFileResponse` (metadata-only; see below) |
| 3 | `readMetadata` | read | path | unary | `path` | `ReadMetadataResponse` |
| 4 | `getFileMetadata` | read | uuid | unary | `uuid` | `GetFileMetadataResponse` |
| 5 | `listFiles` | read | uuid | unary | `uuid`; `after_uuid` on page 2+ | `ListFilesResponse` |
| 6 | `fileDownload` | read | uuid | server-stream | `uuid`, optional `range{offset,length}` | content frames + trailer |
| 7 | `makeDirectory` | write | path | unary | `path` | ack `{}` |
| 8 | `moveDirectory` | write | path | unary | `source`, `destination` | ack `{}` |
| 9 | `removeDirectory` | write | path | unary | `path` | ack `{}` |
| 10 | `createFile` | write | path | unary | `path` | `CreateFileResponse` |
| 11 | `copyFile` | write | path | unary | `source`, `destination`, `overwrite_existing` | ack `{}` |
| 12 | `moveFile` | write | path | unary | `source`, `destination`, `overwrite_existing` | ack `{}` |
| 13 | `removeFile` | write | path | unary | `path` | ack `{}` |
| 14 | `fileUpload` | write | path | client-stream | params frame + chunk frames | trailer (optional `FileUploadResponse`) |
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
three, but they are hints — host-derived attribution and the perimeter-exit
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

## Streaming frame envelope

Both streaming ops share one frame format: a fixed 5-byte prefix then a
JSON payload.

| Bytes | Field | Meaning |
|---|---|---|
| 0 | flag | `0x00` data frame, `0x02` end-stream frame |
| 1–4 | length | payload length, big-endian `uint32` |
| 5+ | payload | JSON-encoded message |

The end-stream frame (`0x02`) is the trailer. Its payload is an
`EndStreamResponse`: `{}` on success, or `{"error":{code,message,details?}}` on
failure. The `ConnectError` shape inside it is the same one a unary non-2xx body
carries, so one error mapper serves both paths.

`readFrame` refuses any inbound frame whose declared length exceeds 4 MiB. The
guest is the least-provisioned party here; a corrupted or desynced 4-byte
length field must never be allowed to size a multi-gigabyte allocation. The cap
sits well above the 256 KiB message ceiling so legitimate trailer or metadata
frames pass.

Code: `stream.go` (`writeFrame`, `readFrame`, `endStreamFlag`, `frameHeaderLen`, `maxInboundFrame`, `ConnectError`, `EndStreamResponse`).

## fileUpload — client-streaming, chunked

The upload is a pipe: a writer goroutine emits frames while the HTTP client
sends them, so the full payload is never buffered. The frame sequence is:

1. **Params frame** (`0x00`) — `filesystem_id`, `path`, `declared_size_bytes`
   (the exact total source size), `authorization_metadata`, and an optional
   `overwrite_existing`.
2. **Chunk frames** (`0x00`) — each `{"chunk": <base64 bytes>}`, sized so the
   encoded payload stays strictly below `MessageCeiling`.
3. **End-stream frame** (`0x02`) carrying `{}` — the explicit completion
   signal. A bare body half-close is *not* completion: without this frame the
   broker keeps waiting, then aborts the already-assembled stream as malformed,
   and a retry collides with the now-present object.

The broker replies HTTP 200 with an optional response message frame followed by
the trailer. `readUploadResult` tolerates the message frame's presence or
absence; the trailer is the authoritative verdict.

**`overwrite_existing` semantics.** A create-new write (Put) sends the field
`false`, and because it is `omitempty` the create-new path — the common case —
serialises no key at all, so a broker build predating the knob accepts it
unchanged. An overwrite-in-place write (Update) sends `true` so the broker
replaces the object atomically rather than forcing the guest into a non-atomic
remove-then-upload.

**Trailer-precedence rule.** When the broker ends the stream early (a SEC-46
`resource_exhausted` throttle, a frame over the ceiling, or a permission
failure) it replies without draining the request body; the transport closes the
pipe and the writer goroutine fails with `io.ErrClosedPipe`. The code reads and
prefers the trailer verdict *before* considering the writer error, and treats a
pipe closure as the expected symptom of early termination — not a local fault.
A parseable error trailer must never be masked, or the retryable backpressure
posture (D4 / SEC-46) is destroyed.

### Chunk arithmetic

`sourceChunkSize` answers: how many raw source bytes per read keep the *encoded*
frame payload under the ceiling? Base64 turns N source bytes into 4·N/3
characters with no padding when N is a multiple of 3. Wrapped in the
`{"chunk":""}` envelope (whose byte cost plus one safety byte is
`jsonEnvelopeOverhead`), the frame payload is `jsonEnvelopeOverhead + 4·N/3`.
Solving `4·N/3 < ceiling − jsonEnvelopeOverhead` and rounding N down to a
multiple of 3 gives the chunk size, floored at 3 so progress is guaranteed even
under a tiny ceiling. Sizing the read by *raw* bytes instead would push every
full frame to roughly 4/3 of the ceiling and deterministically draw
`resource_exhausted` (D4).

The broker assembles the object only when the streamed total equals
`declared_size_bytes`; any over- or under-send draws `invalid_argument`, which
maps to a permanent no-retry error.

Code: `upload.go` (`Upload`, `writeUploadFrames`, `sourceChunkSize`, `jsonEnvelopeOverhead`, `uploadParamsFrame`, `uploadChunkFrame`), `stream.go` (`readUploadResult`), `messages.go` (`FileUploadResponse`).

## fileDownload — server-streaming, ranged, UUID-addressed

The request is a single params frame (`0x00`) carrying `filesystem_id`, `uuid`,
optional `range`, and `authorization_metadata`. The broker replies HTTP 200 and
streams content frames (`0x00`) each shaped `{"data": <base64 bytes>}`, then the
trailer (`0x02`).

`reassembleDownloadStream` concatenates the `data` payloads frame by frame. A
malformed data frame is a **hard error** — never partial content returned as
success — because for a FUSE-backed mount a silently dropped frame surfaces as
silent file corruption. A stream that ends before the trailer is likewise an
error: `readFrame` wraps EOF with `%w`, so the check uses `errors.Is` against
`io.EOF` / `io.ErrUnexpectedEOF`. A zero-length data frame is harmless.

Two entry points consume the same stream:

- `Download(uuid)` — `range` omitted; the broker streams the whole object. The
  `*Range` field is a pointer with `omitempty`, so a full download serialises no
  `range` key and its request body is byte-identical to the no-range form.
- `DownloadRange(uuid, offset, length)` — sends the window so the broker streams
  only those bytes; a ranged read transfers just the requested window, not the
  whole object. Negative offset or length is rejected locally. After reassembly
  the result is defensively clamped to `length`: a broker that honoured the
  range returns exactly the window and the clamp is a no-op; a broker that
  over-delivers is trimmed so the caller never sees more than the contract.
  Offset is not re-applied locally — the broker already seeked to it.

Neither helper is the unary `readFile` op; they are the streaming ranged-read
path (D5).

Code: `download.go` (`Download`, `DownloadRange`, `doDownloadRequest`, `reassembleDownloadStream`, `downloadContentFrame`), `messages.go` (`FileDownloadRequest`, `Range`).

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

The broker reports errors via the closed Connect-code set, carried in a unary
non-2xx JSON body or a streaming error trailer — the same `ConnectError` shape
either way. `MapConnectError` keys on the **code first** and produces a typed
filesystem error that call sites match with `errors.Is`. The `x-deny-reason`
response header is a secondary informational hint, present only on the authz
verdicts, and **never drives the mapping**.

| Connect code | Sentinel / outcome | Retry posture | Notes |
|---|---|---|---|
| `permission_denied` | `ErrPermissionDenied` | permanent | authz verdict; carries `x-deny-reason` |
| `unauthenticated` | `ErrPermissionDenied` | permanent | authz verdict; same sentinel as above |
| `invalid_argument` | `ErrInvalidArgument` | permanent | covers policy `size_exceeded` and malformed requests |
| `not_found` | `ErrNotFound` | permanent | includes the cross-scope-UUID anti-enumeration degrade (D8), which sends no deny-reason header |
| `already_exists` | `ErrAlreadyExists` | permanent | the `overwrite_existing=false`-on-present-path conflict |
| `resource_exhausted` | retryable | retry with backoff | per-session throttle or a frame over the ceiling (SEC-46, D4); honours `Retry-After` |
| `unavailable` | retryable | retry with backoff | no `Retry-After` on this code per the locked contract |
| `aborted` + any unlisted code | `ErrPermanentOther` | permanent | explicit no-retry default — a wrong retryable fallthrough could loop a write forever (D4, T-02-09) |

The `x-deny-reason` header values that may accompany the authz codes —
`scope_mismatch`, `intent_denied`, `not_downloadable`, `lease_expired` — are
informational only and leave the sentinel unchanged.

`Retry-After` is honoured for `resource_exhausted` only. The header is parsed as
decimal seconds and bounded: a non-positive, non-finite (`inf`), or absurdly
large value (≥ 3600 s) is rejected as no usable hint, and the error stays
retryable but without a deadline. This bounded parse is the deliberate defense
against a malformed back-off header turning into a garbage `time.Duration`. A
valid hint is wrapped as a retry-after error so the upstream pacer can honour
the broker's deadline.

Code: `errors.go` (`MapConnectError`, the four `Err*` sentinels, `ErrPermanentOther`, `maxRetryAfterSeconds`), `stream.go` (`ConnectError`).

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
- Any `FilesystemFile`-bearing metadata on a `fileDownload` stream rides the
  trailer/metadata per D6; there is no separate per-frame download response
  type, and content frames carry `{"data": …}`, never a `{"file": …}` body.

No request carries a `metadata_retention_days` field (D6 reject).

Code: `messages.go` (`File`, `FilesystemFile`, `Directory`, `ReadFileResponse`, the response-type comments).
