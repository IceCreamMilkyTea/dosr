# Design log (integrator)

Chronological record of design decisions and problems found while building the
DOSR state machine. Newest entries at the bottom.

## D1. Git objects must commit atomically with consensus state
**Problem.** First design wrote accepted Git objects into a bare Git directory
(loose objects) and the consensus state into a KV database. `VerifyClosure`
consults the local store for objects a bundle omits, so the store is an *input*
of transaction verification. A crash between the object write and the state
commit leaves objects of a block whose state was never committed. On restart
CometBFT replays the block; transaction #3 of the block may now find objects
written by transaction #5 during the first attempt, verify successfully here
and fail on every other replica -> app-hash divergence.
**Decision.** Objects, history and state go into ONE atomic DB batch at
`Commit`. Git directories are a derived view rebuilt from the DB.

## D2. Speculative execution must never write objects
CheckTx / PrepareProposal / ProcessProposal run on copy-on-write layers
(`objLayer`). Nothing reaches the DB except through `Commit` of a decided block.
Otherwise a proposal that was never decided would leave objects behind and the
store would stop being a deterministic function of the chain.

## D3. Evidence cache poisoning (found during design review)
**Problem.** Verifying an AcceptCommit is expensive (bundle closure, diff,
request rendering, signature, Merkle root) and happens up to 3x per node, so we
cache successes. But a success computed in the mempool's speculative state can
depend on objects of *another pending transaction* (same repo, other branch).
A Byzantine client can exploit this: send victim node a transaction A (branch
b2, introduces object x) and T (branch b1, bundle deliberately omits x). The
victim verifies T successfully against its speculative store and caches it. If
T is later decided in a block before/without A, the victim would apply T from
cache while every other replica rejects it (incomplete bundle) -> the victim
forks off.
**Decision.** `objLayer` counts lookups answered by uncommitted objects;
evidence is cached only if verification touched committed objects exclusively.
Successes are monotone in the (append-only) committed store, failures are never
cached.

## D4. ProcessProposal strictness
CometBFT's spec recommends that ProcessProposal accept blocks and let
FinalizeBlock mark bad transactions as failed. We make this a switch
(`StrictProposals`). Strict mode rejects any proposal containing a transaction
that does not execute successfully in order; this keeps replayed / garbage
transactions (each up to megabytes of bundle) out of the chain when the proposer
is Byzantine, at the price of one lost round. Both choices are deterministic.

## D5. `temperature: 0` removed from the canonical request
Literature review found current Anthropic models reject any temperature other
than the default. The canonical request omits the key. Consequence: review
verdicts are inherently non-deterministic -> approval grinding is possible ->
motivates ReviewIntent + single-use nonces enforced by the notary.

## D6. Rate limits need an identity that costs something
`MaxAttempts` is counted per (submitter key, branch, base head). Keys are free
in a permissionless setting, so without fees/stake this bounds honest-but-eager
clients, not Sybils. Candidate hashes cannot be used as the key either: a
contributor can change the commit message to get a fresh hash for the same diff.
Documented as a limitation; a fee per intent is future work.

## D7. The cache-poisoning attack is real (verified by mutation)
`TestCachePoisoning` builds the D3 scenario. With the defence removed (mutant
M14: cache evidence regardless of what it depended on) the victim replica
accepts a transaction with an incomplete bundle and the test reports
`app hash diverged on replica B`. With the defence the three replicas (cache
64 / cache 0 / cache 1) agree.

## D8. CheckTx needs an injectable clock
First run of the suite: `TestCachePoisoning: A not admitted: 27 (expired)`.
CheckTx has no block time, so it used `time.Now()`; test receipts carry a fixed
attestation time and looked a week old. CheckTx now uses `Config.Now`
(default `time.Now`). The consensus path (Prepare/Process/FinalizeBlock) never
reads a clock: it uses the BFT block time from the request.

## D9. Mutation testing of the state machine
`scripts/mutation_test.py` removes one safety check at a time (27 mutants) and
requires the test-suite to fail. First run: M05 survived. Cause: the mutant
("take the request body from the prover") was ill-defined because honest
presentations never carry the body. Replaced by "do not compare a *revealed*
body with the recomputed one" plus a new negative test; this mutant still
survives, because `attest.ProxyVerifier` already enforces the binding - the
check in `checkTranscript` is redundant defence in depth. Reported as
"redundant", not "killed". Final: 26 killed, 1 redundant, 0 survived.

## D10. The canonical request was not accepted by current models (protocol v2)
Found by the engineer implementing `pkg/review` and confirmed against the
current API reference: (a) forced `tool_choice` (`tool`/`any`) returns HTTP 400
on the current model generation, (b) thinking cannot be disabled, so responses
start with `thinking` blocks, which our strict response parser rejected.
Protocol v1 would have produced receipts only for old models - or none.
**Change.** `tool_choice: auto` + `strict: true` tool + fixed system-prompt
suffix; parser skips `thinking`/`redacted_thinking`/`text` blocks but still
demands exactly one `submit_review` call and `stop_reason == tool_use`.
**Trade-off.** With `auto` the model may answer in prose; the contributor then
has to retry. This affects liveness and cost, not safety.
The mock provider now mirrors the real API's 400s so that the mismatch cannot
creep back in unnoticed.

## D11. Policy hash collisions through invalid UTF-8
`Policy.Canonical` uses `encoding/json`, which silently replaces invalid UTF-8
with U+FFFD. Two different system prompts could therefore hash to the same
policy hash. `Policy.Validate` now rejects invalid UTF-8 and NUL in the system
prompt and non-printable characters in model names and the provider path.

## D12. Cross-package integration held on first contact
`TestRealReceiptPipeline` (real HTTPS mock provider -> notary -> presentation ->
state machine) passed the first time it ran, including host canonicalisation
(`127.0.0.1:port`), the header set recorded by the notary vs. the validators'
allow-list, and SPKI pinning. We attribute this to freezing the three package
contracts (`contract.go`) before any implementation started.

## D13. Wasted reviews caused by the mempool's first-come rule (found by the contention experiment)
The first contention run (4 contributors racing on one head) showed 7.4
reviews per accepted commit, far above the k-1 = 3 wasted reviews per block
that optimistic concurrency implies. Cause: `CheckTx` executes on the *check
state*, which already reflects competing transactions admitted earlier; a
loser's transaction is refused with `stale_head` immediately, while the
chain's head has not moved yet. The client treated this like a chain-level
stale, re-read the (unchanged) head, paid for a new review and was refused
again - a busy loop of paid reviews until the next block.
**Fix.** On a mempool-level `stale_head` the client waits until the head
actually moves before reporting `ErrStale`; a contributor then pays at most
once per head state. The measurement in eval/results shows the effect.
**Lesson.** The mempool admission policy is part of the economic design:
"first come" in the mempool means the losers must be told to wait, not retry.
Measured before the fix (4 changes per contributor, fast LLM): 3.0 / 6.44 /
15.97 reviews per accepted change for k = 2 / 4 / 8; after: 1.75 / 2.44 / 5.12.
