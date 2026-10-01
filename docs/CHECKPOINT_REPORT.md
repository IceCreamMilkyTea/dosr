# DOSR — Checkpoint Report

*ECE/CS 512, Fall 2026 — William Convertino, Jakub Romanczuk, Gage Garcia, Yuhan Wei*
*Status as of 2026-09-29*

## 1. Summary

We built a working prototype of DOSR: a decentralized Git host where a commit
enters the canonical branch only if consensus orders a transaction carrying a
verifiable certificate that an LLM approved *exactly that change on exactly
that head under the repository's current policy*. Validators never call the
LLM; they recompute the review request from the Git objects and check that an
attested transcript commits to it.

What exists and works today:

* **A replicated state machine** (ABCI 2.0 on CometBFT v0.38) with
  `CreateRepo`, `AcceptCommit`, `UpdatePolicy` and `ReviewIntent`
  transactions, compare-and-swap on the branch head, policy-bound receipts,
  intents with chain-derived nonces, atomic storage of state + history + Git
  objects, and Git-compatible mirrors that `git clone` can read.
* **The evidence pipeline**: strict Git object parsing and closure
  verification, a deterministic canonical review request (unified diffs with
  content-hash-derived section boundaries), a TLSNotary-style
  attestation/presentation format with selective disclosure (the API key is
  hidden, the request body is *recomputed* rather than shipped), and a
  transcript policy check (host, key pin, path, header allow-list, model,
  stop reason, verdict binding, freshness against BFT time).
* **The off-chain services**: an attesting proxy (trusted; see §6) with
  single-use review nonces, and a mock LLM provider speaking the Anthropic
  Messages API over HTTPS with latency, verdict and fault models and cost
  accounting.
* **A contributor client and CLI** that work against real Git repositories,
  and a demo launcher.
* **A test and verification stack**: 10 packages of unit tests, differential
  tests against `git`, 11 fuzz targets, a seeded randomized simulation of the
  state machine with an adversarial workload, mutation testing (27 mutants),
  a TLA+ model checked with TLC (including mutants and a grinding witness), a
  4–10 node testnet with emulated links, crash/partition/Byzantine-application
  fault injection and an invariant checker, and whole-stack end-to-end tests.
* **An evaluation** of verification cost, consensus/propagation latency vs
  validators and network, bundle size, end-to-end latency and cost against an
  "every validator reviews" baseline, head contention, faults, and approval
  grinding — with a mock LLM and emulated network, stated as such.

Headline results (details in [EVALUATION.md](EVALUATION.md)):

| | |
|---|---|
| Verifying a certificate on a validator | 0.15 ms (1 KB change) – 11 ms (1 MB) |
| Submission → decided, 4–10 validators, default CometBFT timeouts | ~1.3 s (timeout-dominated), LAN–WAN |
| End-to-end with a ~6.5 s (assumed) LLM call, 4 validators, WAN | DOSR 7.2 s; baseline "each validator reviews" 29.7 s, 5 consensus rounds per block, 4× the LLM calls and cost |
| Reviews wasted under contention (*k* contributors, one branch) | 1.75 / 2.44 / 5.12 reviews per accepted change for *k* = 2 / 4 / 8 |
| Grinding a *p*=0.25 change, 12 tries | 95 % accepted without intents; 65 % with intents (bound 3) + single-use nonces |
| Faults (crash, restart, 3\|1 partition, heal) | progress on the majority side throughout; invariants hold after |

## 2. What changed relative to the proposal

| Proposal | Now | Why |
|---|---|---|
| "Use TLSNotary" | TLSNotary-*style* attestation behind a `Verifier` interface; the prototype attestor is a trusted proxy | TLSNotary is alpha, Rust-only, its notary server was removed upstream, and its MPC cost is dominated by request bytes (our diff); see literature review F1–F2 |
| Consensus "verifies the approval" | Consensus verifies the approval **and recomputes the whole review request** from the Git objects | The obvious design (trust the prompt inside the receipt) lets the contributor choose what the model saw |
| Nothing about repeated attempts | Review intents with chain-derived nonces, single-use enforcement at the attestor, bounded attempts per identity | LLM verdicts are non-deterministic, so "one approval exists" is weak evidence; found no prior work naming the problem |
| Forced tool call, `temperature: 0` | `tool_choice: auto` + strict tool + prompt suffix; no temperature | Current models reject both (verified against the API reference) — protocol v2 |
| Git objects "off-chain" | Bundles travel inside transactions (≤ 4 MiB); on-chain *state* holds only hashes | Availability by construction for the checkpoint; measured cost is small; availability certificates remain future work |

## 3. Correctness: what is checked and how

The primary invariant — *a commit becomes head only if consensus orders a
transaction whose certificate is valid for exactly that commit, that head and
the current policy* — and the supporting invariants (linear history, no stale
accept, replica agreement, policy binding, no receipt reuse, bounded
attempts) are checked at four levels (DESIGN §8):

1. **TLA+ / TLC** (`spec/`): consensus abstracted as a total-order log;
   Byzantine submitters that replay, re-bind and forge; replicas with prefix
   indices and restarts; policy updates; intents with notary single-use.
   38 TLC jobs, all with the expected outcome, reproducible with
   `./run.sh` in ~15 min: 9 "holds" models (up to 25.9 M generated /
   5.1 M distinct states, depth 22), 3 grinding witnesses and 3 other
   deliberately-false properties violated as expected, 21 single-guard
   mutants each caught by the corresponding invariant, 2 mutants proven
   *equivalent* (the removed guard is implied by others — exhaustively
   explored, no violation) plus 2 double mutants showing those guards are
   load-bearing once the masking guard is gone. See `spec/README.md`.
2. **State machine tests** (`pkg/app`): a chain driver runs three replicas
   with different cache configurations through every block and asserts
   identical results and app hashes; a negative matrix of 30+ forged /
   replayed / tampered receipts; a randomized simulation (20 seeds × 150
   blocks, adversarial mix, random restarts, three delivery paths) with a
   certified-history oracle; **mutation testing: 26 of 27 mutants killed, 1
   redundant check, 0 survived** (`scripts/mutation_test.py`).
3. **Component tests**: differential tests of the Git implementation against
   `git` 2.39 (object IDs, `diff-tree`, `fsck --strict`), fuzzing of every
   parser (≈ 20 M executions in total, no crashes), 2,499 single-byte flips
   and 84 named tamper cases on presentations, all rejected.
4. **Network tests** (`pkg/testnet`, `pkg/e2e`): 4-node smoke, crash/restart
   (in-process and `SIGKILL` of a subprocess), 2-of-4 down (no progress, as
   required), 2|2 and 3|1 partitions with heal, Byzantine application
   validator, duplicate/reordered submissions, and whole-stack runs with real
   HTTPS provider + notary + client, adversarial clients and contention; an
   invariant checker compares block/app hashes and walks every history and
   object store after each test.

## 4. Problems found on the way (the interesting part)

Full logs: [notes/design_log.md](notes/design_log.md) and the per-package
notes in `docs/notes/`. The ones worth a paragraph in the final report:

1. **Verification-cache poisoning → fork of one validator** (D3, D7).
   Caching successful evidence verification is necessary (three verifications
   per transaction per node) but a success computed against *uncommitted*
   objects of another pending transaction can be exploited: a client sends a
   victim node a transaction A (adds object X) and T (omits X); the victim
   caches "T verified", and if T is decided without A the victim applies it
   while everyone else rejects it. Removing the defence in the code makes the
   test print `app hash diverged on replica B`. Fix: only cache evidence that
   touched committed objects.
2. **Git objects must be in the same atomic batch as the state** (D1).
   Writing objects to a Git directory and state to a database is not crash
   safe: after a crash between the two, block replay can see objects from a
   later transaction and verify differently. Git directories are now a
   derived view.
3. **The canonical request did not work on current models** (D10). Forced
   `tool_choice` returns HTTP 400 and thinking cannot be disabled; protocol
   v2 fixed both; the mock provider now returns the same 400s so the mismatch
   cannot come back silently.
4. **Wasted reviews caused by mempool admission** (D13). Measured 16 reviews
   per accepted change with 8 contributors; cause was the client re-reviewing
   after a mempool-level `stale_head` while the chain head had not moved.
   Fixed; now 5.1.
5. **Policy hash collisions through invalid UTF-8** (D11) and an attested
   host header that could never match a policy naming `:443` — both caught by
   the other engineers' reviews of the contracts and fixed in validation.
6. **State explosion in TLC.** The first Byzantine-liveness model ran for
   4 h 17 min (522 M states) and died when TLC's disk queue filled the
   volume; a grinding mutant did the same after 2 h. Bounded replacements
   (documented per config, originals kept in `spec/large/`) finish in
   seconds to minutes; two mutants turned out to be *equivalent* (their
   guard is implied by others), which is itself a small result about the
   design — see `docs/notes/tla_spec.md`.
7. CometBFT details that bit: persistent-peer redial backoff after a healed
   partition (1.2–6.8 s passively, ~20 ms with the harness re-dialling),
   block-sync's fixed 3 s peer wait on restart, the transaction index lagging
   the head, mempool `max_tx_bytes` default of 1 MiB, and an orphaned
   subprocess bug in our own `dosrd` (`--exit-with-parent` read the parent
   PID too late) — see `docs/notes/impl_testnet.md`, which also has the
   measured numbers: ~3 one-way delays per block, 386–598 ms lost per
   Byzantine proposer turn in strict mode, 0 Byzantine transactions applied
   in either mode.

## 5. Evaluation in one page

See [EVALUATION.md](EVALUATION.md) §4 and the generated
[eval/results/SUMMARY.md](../eval/results/SUMMARY.md). Three observations we
would build the final report around:

* **The receipt check is free; consensus is cheap; the LLM is the cost.** 0.15–11
  ms to verify, ~1.3 s to decide (dominated by CometBFT's fixed
  `timeout_commit`; with fast timeouts the WAN adds 0.5 s at 10 validators),
  6.5 s for the review.
* **Putting the LLM inside consensus is not just *n*× more expensive, it
  breaks the timing assumptions.** The baseline needed 5 rounds per block
  because a multi-second call in `ProcessProposal` exceeds `timeout_propose`,
  giving 29.7 s instead of 7.2 s end to end.
* **Optimistic concurrency has a price in reviews, not just in latency.** The
  contention curve (1.75 → 5.12 wasted reviews per accepted change from *k*=2
  to 8) is the argument for leases/batching in the next phase; and the
  experiment found a real client bug first.

## 6. Limitations, stated plainly

* The attestor is a trusted proxy that sees plaintext and the API key. The
  integrity trust is of the same *kind* as a TLSNotary notary's (a signature
  by a party the policy trusts), the confidentiality is not.
* The LLM is a mock; its latency model and prices are assumptions.
  Nothing here says AI review is any good — the literature review says the
  opposite is a live concern.
* Grinding is bounded per identity, not prevented; identities are free.
* Linear history only; no merges, tags, force-push; validator set fixed at
  genesis; no fees; queries are not proofs.
* One machine, emulated links, single runs, no confidence intervals.

## 7. Next steps (proposed split)

| Area | Work |
|---|---|
| Attestation | Prototype a TLSNotary prover/verifier sidecar (Rust) for one request; measure MPC cost vs diff size; or a TEE-gateway-style attestor with remote attestation |
| Protocol | Availability certificates (Narwhal-style) so transactions carry digests, not bundles; leases on the head or Bors-style batching to cut wasted reviews; *k*-of-*n* provider certificates as a policy option |
| Verification | Twins-style Byzantine consensus tests; a Porcupine-checked linearizability test of the head as a CAS register; TLC on larger models with symmetry reduction |
| Evaluation | Multi-machine deployment (the harness supports subprocess mode); bandwidth-limited links; real provider calls for a handful of PRs to calibrate the latency model |
| Report | Re-check literature quotations against originals (see LITERATURE_REVIEW §4) |

## 8. Where everything is

See the table in [../README.md](../README.md). Run `go test ./...`,
`python3 scripts/mutation_test.py`, `./bin/dosr-bench -exp all`,
`(cd spec && ./run.sh)`.
