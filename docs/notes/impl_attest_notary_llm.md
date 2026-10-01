# Implementation notes: pkg/attest, pkg/notary, pkg/llm

Running log of design decisions, ambiguities, and problems found while
implementing the three packages. Environment: Go 1.27.1, darwin/arm64
(Apple M3). Standard library only.

## 1. pkg/attest

### 1.1 Decisions where the contract was silent

| Topic | Decision | Reason |
|---|---|---|
| Empty transcript (0 leaves) | Rejected by Build, Present, Validate, Verify (`ErrMalformed`) | RFC 6962 defines the empty tree hash as SHA-256(""), but a transcript without fields is meaningless, and accepting `leaf_count: 0` adds an edge case to consensus code for no benefit. |
| Leaf names | 1..256 bytes of printable non-space ASCII (0x21..0x7e) | `encoding/json` silently replaces invalid UTF-8 in strings by U+FFFD. A name with invalid UTF-8 would therefore change during Encode/Decode and the root would no longer match. Restricting the alphabet makes the encoding lossless. HTTP header names (tokens) are a subset. |
| `server_name` | 1..255 bytes of the same alphabet | Same reason, and `SigningBytes` has a u16 length prefix. |
| `server_spki` | exactly 32 bytes | It is a SHA-256 digest by definition. |
| `SigningBytes` on an invalid header (field > 65535 bytes, root != 32 bytes) | returns `nil` | The signature is frozen (no error result). Build and Verify validate the header first, so `nil` is never signed or verified; Verify treats `nil` as bad signature. |
| `Present` with names in `disclose` that are not in the transcript | ignored | One fixed policy map (`x-api-key`, `authorization`, `req.body`) must be applicable to transcripts that do not have all of those headers. |
| `Present` consistency | recomputes the root from the secret and compares with the attestation (`ErrRootMismatch`), does not check the signature | Catches mixing up secrets/attestations on the contributor side, before a transaction is built. |
| Structural validation | exported as `(*Presentation).Validate`; called by `Encode`, `DecodePresentation` and `Verify` | Mempool-level code can reject garbage after decoding without doing any hashing. |
| Size limit | `MaxPresentationBytes = 1 MiB` in Encode/Decode | Equals `types.MaxBodyBytes`; duplicated as a constant to keep the package free of dependencies. |
| Transcript aliasing | Verify copies everything; the Transcript does not alias the presentation or `known` | Validators cache verification results; aliasing bugs there would be consensus bugs. |
| `trusted` entries of wrong length | ignored | Never matched against a 32-byte key; also avoids the panic of `ed25519.Verify` on a wrong key length (the header key length is checked structurally first). |

### 1.2 Hardening beyond the contract: `known` vs. Revealed leaves

The contract says `known` supplies values for leaves with `Disclosure ==
Known`. A presenter chooses the disclosure mode, so a presenter may present
`req.body` as **Revealed** with some value, and a caller that passed
`known["req.body"]` and then forgets to compare `Fields["req.body"]` would
accept a different body. Verify therefore ALSO requires, for a Revealed
leaf whose name is in `known`, that the revealed value equals the supplied
one (`ErrRootMismatch` otherwise). Guarantee: for every name in `known`, if
`Fields` has it, its value is the one the caller supplied. (pkg/app checks
the body again as defence in depth; both are fine.)

### 1.3 Inherent property found while defining the fuzz oracle: "hide more"

First formulation of the fuzz property was "if a mutated presentation
verifies, the Transcript equals the original one". This is NOT achievable
by any selective-disclosure scheme of this shape: whoever knows value and
salt of a leaf (the contributor does) can present it as Hidden with the
correct commitment. The presentation verifies and the transcript has the
field in `HiddenNames` instead of `Fields`.

Consequences:

* The property actually tested (`checkNoNewContent`): identical header
  fields, identical `Names`, every entry of `Fields` equals the original
  value of that name, and `Fields`/`HiddenNames` partition `Names`. I.e. a
  mutation can never make the verifier see DIFFERENT content, only LESS.
* Callers must treat absence from `Fields` as failure for every field they
  need, and must decide which fields may be hidden at all. pkg/app does
  this (`hideableReqHeaders`, "field must not be hidden").
  `TestPresenterMayHideMore` documents the behaviour.

### 1.4 JSON malleability

Accepted and harmless (nothing is derived from the encoded bytes; the
signature covers `SigningBytes`, the root covers decoded names/values):
whitespace, key order, `\uXXXX` escapes, key case-insensitivity and
duplicate keys of `encoding/json`. Consequence for other packages: **the
hash of the encoded presentation (or of a transaction containing it) is
not a unique identifier of the receipt** - the same attestation has many
encodings. Replay protection must key on content (e.g. attestation root +
signature, or the review nonce), not on the transaction bytes.

Also note ed25519 itself: Go rejects non-canonical `S`, but the scheme is
not strongly unforgeable in every corner; again irrelevant as long as
nothing keys on signature bytes.

### 1.5 Tests

* Round trip for all-revealed, DOSR policy, all-hidden, all-known, mixed;
  leaf counts 1, 2, 3, 5, 8, 9, 256; empty values.
* `TestFlipEveryByte`: 2499 single-byte tamperings (3 bit patterns for
  every byte of notary key, SPKI, root, signature, every revealed value,
  salt, hidden commit, and the known value), all rejected with the expected
  sentinel.
* `TestTamperCases`: 84 named cases (header fields, key/signature lengths,
  leaf count incl. u32 wrap, > MaxLeaves, drop/append/duplicate/reorder
  leaves, renames, name/commit and salt/value boundary shifts, per-mode
  field presence, known missing/wrong/under wrong name, ...), each also
  after an encode/decode cycle. Cases marked `resign` re-sign the header
  with the trusted key to reach the checks behind the signature check
  (models a faulty notary).
* `TestDomainSeparation`: interior node offered as leaf, same root claimed
  with another leaf count (3 leaves vs. 2 leaves `[H(a,b), c]` have the
  same root bytes; distinguished by the signed LeafCount and the leaf
  domain), leaf hash as value commitment, index binding, length-prefix
  framing.
* Merkle root checked against an independent recursive RFC 6962
  implementation for n = 1..300.
* Hiding: the API key, the salt of the hidden leaf and the Known body do
  not occur in the encoded presentation in raw, hex or any base64
  alignment.

No bug in the verification code was found by the tests or the fuzzers. The
problems found were in the tests/tooling (below).

### 1.6 Fuzzing

Targets: `FuzzDecodePresentation`, `FuzzVerify` (byte-level mutation of
encoded presentations) and additionally `FuzzVerifyMutate` (STRUCTURED
mutation program applied to the decoded honest presentation: flips in any
field, disclosure changes, swaps/drops/duplicates of leaves, header
changes, legitimate re-opening in another mode, mutation of the known
value). The structured target exists because byte-level mutation of
JSON+base64 text almost never yields a well-formed presentation with an
interesting field change.

**Problem: Go fuzzing engine stalls.** First runs (`-fuzztime 25s`):
`FuzzDecodePresentation` executed only 36 inputs in 26 s and `FuzzVerify`
froze at 273,433 execs (`0/sec`). Cause: not the code under test but the
engine's input MINIMIZATION (default `-fuzzminimizetime 60s`), which blocks
the workers when a new interesting input is large (our seeds are ~2 KB
JSON). Fix: run with `-fuzzminimizetime 1s`.

Results (30 s each, 8 workers, `-fuzzminimizetime 1s`), no failures, no
crashers written to `testdata/`:

| Target | execs | new interesting |
|---|---|---|
| FuzzDecodePresentation | 2,937,480 | 231 |
| FuzzVerify | 1,207,056 | 431 |
| FuzzVerifyMutate | 1,385,810 | 10 (corpus 183) |

Command: `go test -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s -fuzzminimizetime 1s ./pkg/attest/`

### 1.7 Benchmarks (13-field transcript, DOSR disclosure policy)

| Operation | 1 KB | 10 KB | 100 KB |
|---|---|---|---|
| Build (commit + sign) | 101 us | 112 us | 277 us |
| Present | 13 us | 16 us | 104 us |
| Verify | 46 us | 69 us | 177 us |
| Decode + Verify (validator path) | 85 us | 154 us | 1008 us |
| Encode | 13 us | 22 us | 241 us |

Observations: Verify is dominated by the ed25519 verification (~40 us)
for small responses and by SHA-256 of the response for large ones. For
100 KB the JSON/base64 decoding costs ~5x the cryptographic verification -
if validator CPU ever matters, the encoding is the thing to replace, not
the proof system. Build uses a deterministic test RNG in the benchmark
(slower than crypto/rand), so the Build numbers are upper bounds.

## 2. pkg/notary

### 2.1 Trust model

Stated prominently in the package documentation: the notary is a trusted
proxy that sees all plaintext including the API key, can forge
attestations, and its clock is trusted. Only the verifier-facing object
has the TLSNotary shape.

### 2.2 The transcript (normative description in `doc.go`)

* The notary does not use `net/http`'s client. It writes the HTTP/1.1
  request by hand on its own `tls.Conn` and parses the response with
  `http.ReadResponse`. Reason: `http.Transport` adds headers on its own
  (`User-Agent`, `Accept-Encoding: gzip`), transparently decompresses,
  may negotiate HTTP/2 and follows redirects; with it, "what was sent"
  would not be well-defined. With the hand-written request the transcript
  lists EXACTLY the header lines on the wire
  (`TestWireRequestMatchesTranscript` records the raw bytes on a TLS
  listener and rebuilds them from the transcript).
* Request headers: caller's headers + `host`, `accept-encoding: identity`,
  `connection: close`, `content-length`. A caller may repeat one of these
  with the identical value, but not change it. Hop-by-hop/framing headers
  and `expect`, `proxy-*` are refused. Names unique after lower-casing.
  Values without control characters (CR/LF header injection is tested).
* Response headers: multi-valued headers joined with ", " in order
  received (not injective, documented; response headers carry no authority
  in DOSR). Dropped: hop-by-hop headers, headers named by `Connection`,
  and `content-length` (so that chunked and non-chunked responses attest
  alike). `date` is kept. Trailers ignored.
* `content-encoding` other than identity: rejected (502). Interim 1xx
  responses skipped (max 8), 101 rejected.
* Redirects: never followed; a 3xx is attested as-is. The verifier must
  require `resp.status == "200"`.

### 2.3 AMBIGUITY in the contracts: host, port, ServerName

`attest.Header.ServerName` is "TLS SNI / verified certificate name" (no
port), while `types.Policy.ProviderHost` may carry a port (`hostRe`), and
the mock provider necessarily runs on a non-443 port. Resolution, matching
what pkg/app's `checkTranscript` does:

* `ServerName` = host name without port.
* The port is bound by the attested `req.header.host`, which is the
  canonical authority: lower case, `:443` omitted (`CanonicalHost`).
* So a policy must write `provider_host` in canonical form:
  `api.anthropic.com` (NOT `api.anthropic.com:443`), `127.0.0.1:8443`.
  A policy with an explicit `:443` would never match. Suggest that
  `Policy.Validate` rejects `:443` or that pkg/app canonicalises.

IPv6 literals are not supported (neither by `hostRe`).

### 2.4 SSRF hardening

https only; canonical host:port must be on the allow-list (exact match, no
wildcards); userinfo (`https://allowed@evil/`), fragments, bad ports
(`:0443`), trailing dots rejected before any connection; no redirects;
certificate validated for the host name under the configured roots;
bounded response size (body AND raw bytes incl. headers/chunk framing) and
bounded total time; concurrency limit (`busy`, 503).

Not covered: DNS rebinding of an allow-listed name to an internal address
is only stopped by the certificate check (the internal service would need
a certificate for that name from a trusted root).

Test `TestUntrustedUpstreamCertificate` asserts that NO request (which
would carry the API key) reaches a server whose certificate fails
validation (other CA, empty pool, self-signed, wrong name, name not in
SAN).

### 2.5 Single-use review nonces (anti approval-grinding)

Design as requested; rationale is in `nonce.go`. Summary:

* Nonce taken ONLY from the header block of `messages[0].content` (lines
  between the magic line `DOSR-REVIEW-REQUEST v2` and the first blank
  line). Exactly one `nonce: ` line, lower-case hex, even length, <= 128
  hex digits. `-` is refused (`nonce_missing`, 400). v1 texts are refused.
* Reserved BEFORE the upstream call (append + fsync to the log file under
  a mutex), so of N concurrent requests with one nonce exactly one reaches
  the provider (`TestConcurrentDuplicateNonce`: 3 nonces x 16 concurrent
  requests -> provider call counter == 3, under `-race`).
* Never released: not on "reject", not on upstream failure (attested 500,
  timeout, caller disconnect - all tested). Releasing on failure would
  re-open the grinding channel because the notary cannot distinguish
  genuine from provoked failures and, after a timeout, does not know
  whether a verdict was produced. Cost: liveness only (a new ReviewIntent
  is needed after a provider outage).
* Requests refused before the upstream call (bad request, host not
  allowed, busy) do not consume the nonce.
* Persistence: append-only text log, one nonce per line, mode 0600. On
  start the log is replayed; a torn last line (crash during append) is
  truncated away - safe, because `Reserve` had not returned and no call
  was made; corruption anywhere else makes the notary refuse to start
  rather than forget nonces. `Reserve` after `Close` fails (it does not
  silently degrade to memory).
* Cost: one fsync per attestation: **3.9 ms** on this machine
  (`BenchmarkNonceReserve`; macOS `F_FULLFSYNC`), negligible against
  seconds of LLM latency but larger than the whole cryptographic part.

Limitations (documented in code):

1. The check parses JSON with `encoding/json`. A body with duplicate
   `messages` keys or other parser differentials could show the notary a
   different nonce than the provider sees. This is harmless because
   validators recompute the canonical body and require byte equality with
   the attested `req.body`; a non-canonical body yields a worthless
   receipt.
2. The rule binds ONE notary. If a policy trusts k notaries with separate
   logs, a contributor gets k attempts per nonce. Either one notary per
   policy, or a shared log, or the chain must bound this otherwise.
3. No file locking: a log must not be shared by two notary processes.
4. The log grows without bound (one line per review). Pruning would need a
   notion of nonce expiry that the notary does not have.

### 2.6 Problems found by tests

* **Upstream cancellation test failed** ("upstream connections were not
  closed"). Not a notary bug: Go's HTTP server only notices a closed
  client connection (and cancels `r.Context()`) once the handler has
  consumed the request body. The test handler did not read the body. Fixed
  in the test.
* `context.AfterFunc(ctx, conn.Close)` plus `SetDeadline` is what makes
  both the timeout and the caller's cancellation abort a blocked
  read/handshake; verified by `TestUpstreamTimeout` (slow header and slow
  body), `TestUpstreamHangingHandshakeAndUnreachable`,
  `TestCallerCancellationAbortsUpstream`.

### 2.7 Attestation overhead (BenchmarkAttest, provider latency zero)

| Response | wall | upstream (connect+TLS+HTTP) | commit+sign | notary overhead as seen by client |
|---|---|---|---|---|
| 1 KB | 7.3 ms | 5.1 ms | 0.35 ms | 2.2 ms |
| 10 KB | 7.5 ms | 5.2 ms | 0.19 ms | 2.3 ms |
| 100 KB | 11.9 ms | 7.1 ms | 0.42 ms | 4.8 ms |

"Overhead" includes the client<->notary HTTP hop with JSON/base64 encoding
of request, attestation and secret. The upstream part is dominated by a
fresh TLS handshake per call (no connection reuse, by design:
`connection: close`). Everything is on localhost, so network latency is
not represented.

### 2.8 Prototype simplifications

* The notary's own API is plain HTTP unless `Config.TLS` is set; only
  acceptable on localhost (requests carry the API key, responses the
  secret).
* No authentication of notary clients, no rate limiting beyond the
  concurrency limit.
* Key file: hex seed, 0600, refused if group/other-accessible; no
  encryption at rest, no HSM.

## 3. pkg/llm (mock provider)

### 3.1 Protocol changes during development

1. `temperature` removed from the canonical request: the mock accepts a
   body without it and tolerates the key only with value 1.
2. Forced tool use is rejected by current models: `tool_choice`
   `{"type":"auto"}` (or absent) is the normal case; `tool`/`any` get 400
   `invalid_request_error` with the message
   `tool_choice: type "tool" and "any" are not supported for this model.`
   unless `RejectForcedToolChoice: llm.Bool(false)`.
3. `fallbacks` is rejected with 400 (a fallback model could answer instead
   of the requested one).
4. Thinking is always on: responses start with
   `{"type":"thinking","thinking":"","signature":"<base64>"}` unless
   `EmitThinking: llm.Bool(false)`.
5. New faults `PNoToolCall` (plain text, `end_turn`; `PRefusal` kept as a
   deprecated alias, probabilities added) and `PSafetyRefusal` (HTTP 200,
   `stop_reason: "refusal"`, `content: []`, `stop_details`
   `{type, category, explanation}`). `stop_details` is always present in
   responses and `null` except for refusals.
6. Review text magic is `DOSR-REVIEW-REQUEST v2`; v1 is rejected by the
   mock and by the notary's nonce parser.

**Go-specific issue with "default TRUE" booleans.** A `bool` field of a
config struct defaults to false. `RejectForcedToolChoice` and
`EmitThinking` are therefore `*bool` (nil = true) with the helper
`llm.Bool(v)`.

### 3.2 Decisions

* The mock has its own parser of the review text (does not import
  pkg/review), following the contract. It is checked against the real
  format through `llm.GoldenRequestBody`, a copy of pkg/review's golden
  test vector (must be re-copied when the protocol changes; done for v2),
  and through the tagged integration test (3.4).
* With `tool_choice: auto` the mock calls `submit_review` if it is among
  the tools, else the first tool.
* Unknown top-level request keys are rejected with 400 like the real API;
  known-and-ignored keys: `thinking`, `output_config`, `service_tier`,
  `metadata`, `stop_sequences`, `stream:false`.
* Natural truncation: if the estimated output tokens exceed `max_tokens`
  the response is truncated (`stop_reason: "max_tokens"`, tool input
  `{}`), like a fault-injected truncation. NOTE for policies: the default
  answer is ~55 estimated tokens (incl. thinking signature), so
  `max_tokens` below that ALWAYS yields truncation with the mock.
* Billing: only HTTP 200 responses are billed (incl. truncated and
  no-tool-call responses); safety refusals bill input tokens only
  (assumption); 4xx/5xx/529 and cancelled calls are not billed.
* Cost is computed from integer token counters at read time (no
  accumulated floating point error).
* Model names/prices are neutral placeholders (`mock-reviewer-*`), so
  that no figure can be mistaken for a statement about a real model.

### 3.3 ASSUMED parameters (not measurements)

* Tokens = ceil(bytes / 4).
* `LatencyFast`: median TTFT 150 ms (sigma 0.25), 2000 tok/s, 2 us/input
  token.
* `LatencyRealistic`: median TTFT 1.2 s (sigma 0.4), 60 output tok/s,
  50 us/input token; ~6.7 s for 300 output / 10k input tokens. Capped at
  60 s.
* Default prices (USD/MTok): large 15/75, medium 3/15, small 1/5.

### 3.4 Problems found by tests

* **`json.Number` accepts quoted numbers.** `"max_tokens":"1024"` and
  `"temperature":"1"` were accepted (encoding/json unmarshals a JSON
  string containing a number into `json.Number`). Fixed by decoding into
  `json.RawMessage` and parsing by hand.
* **Empty 200 on aborted calls.** When the simulated latency was
  interrupted by server shutdown the handler returned without writing;
  net/http then sends `200 OK` with an empty body - a client would have
  seen a "successful" empty response. Now answered with 503 `api_error`
  (nothing can be sent if the client itself is gone).
* **Float rounding in the latency model.** `exp(ln(0.3 s))` gave
  299,999,999 ns. The lognormal is now computed as
  `median * exp(sigma * z)` and rounded, so sigma = 0 gives the median
  exactly.

### 3.5 Cross-package tests

* `pkg/notary/integration_test.go` (build tag `dosr_integration`, so that
  the default test run of the package does not depend on packages under
  concurrent development): real `review.BuildRequestBody` -> notary with
  nonce enforcement -> mock provider -> presentation -> `ProxyVerifier`
  -> `review.ParseResponse`; approve and reject (marker) cases; second
  attempt per nonce refused; truncated / no-tool-call / safety-refusal
  responses are rejected by `review.ParseResponse`. Passes.
* The integrator's `go test ./pkg/app/ -run TestRealReceiptPipeline`
  passes.

## 4. Open points for the integrator

1. `provider_host` must be in canonical form (2.3).
2. Replay protection must not key on transaction/presentation bytes (1.4).
3. Several notaries in one policy multiply grinding attempts (2.5).
4. `authorization` is Hidden by `notary.BuildPresentation`, but pkg/app's
   `allowedReqHeaders` does not allow that header at all; a request using
   it is attested by the notary and rejected on chain. Consistent, but
   worth knowing.
5. Notary default `MaxResponseBytes` is 512 KiB so that the base64-encoded
   presentation fits into a 1 MiB transaction body.
