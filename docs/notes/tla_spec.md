# TLA+ / TLC notes

Running log of the problems met while model-checking `spec/DOSR.tla` with
TLC 2.19 (Java 21, 8-core Apple Silicon laptop, 8 GB heap). Newest entries at
the bottom. All state counts are copied from the TLC logs in `spec/out/`
(current run) and `spec/out/prev/` (the previous engineer's runs).

## T1. Consensus is a total-order log, not a protocol
The first decision was to not model CometBFT at all. The state machine only
sees a sequence of transactions; `log` is that sequence and `Submit` appends
to it. Byzantine *validators* therefore do not exist in the model - the
assumption is that BFT consensus delivers a single total order to every
correct replica. Everything the model proves is conditional on that.

## T2. Receipts as a set of genuinely issued records
Cryptography is replaced by set membership: `receipts` contains exactly the
records a notary really signed. The adversary can replay and re-bind
elements of `receipts` and can make up records with `sid = 0`, which are
never in `receipts`. This is where "the notary's signature is unforgeable"
enters the model; it is an assumption, not a result.

## T3. The single-fault reduction of the adversary
With `FullAdversary = TRUE` the Byzantine submitter chooses among every
`AcceptTx(h, c, r)` with `r` any genuine receipt or any forged record, which
is thousands of transactions per step. Observation: five checks of
`AcceptCommit` depend on the transaction alone (`member`, `verdict`, `base`,
`candidate`, `parent`), and a transaction failing two of them is rejected by
every single mutant in every state. So the reduced adversary only submits
transactions that fail at most one static check plus one representative junk
transaction. `SafetyFull.cfg` (full adversary, 2 commits, log 2) passes and
serves as the cross-check of the reduction: 6,043,941 states generated,
2,004,917 distinct, 31 s.

## T4. Session identity and the `UniqueSessions` quotient
Without session ids two LLM calls with the same request and the same verdict
produce the same record and collapse into one element of `receipts`. This is
sound for every safety property that does not talk about *order* (the state
machine cannot distinguish the two receipts), and it keeps the state space
small. `NoGrinding` needs "the rejection came first", so the grinding
witnesses and the `*_NoGrinding` mutants run with `UniqueSessions = TRUE`,
where the k-th call gets `sid = k`.

## T5. First run of the "deep" safety model was killed
`out/prev/Safety.out`: an early version of the deep model (before the
constants were tuned) was at 33,036,951 states generated / 11,650,430
distinct after one minute with 10.8 M states still on the queue and was
killed. The previous engineer then split the safety checks into
`SafetyChain` (5 commits, log 5, small adversary) and `SafetyAdversary`
(3 commits, log 3, large adversary). Neither of the two was ever run to
completion before the hand-over: `results.txt` had no row for them and no
log existed. Re-run in this session: `SafetyChain` completes in 202 s
(21,007,340 generated / 8,143,227 distinct, depth 15), `SafetyAdversary` in
234 s (59,228,780 / 15,809,026, depth 10). Both hold. Both were later
reduced further (T15) because they did not fit the budget on a loaded
machine; the checked larger versions are kept in `spec/large/`.

## T6. Results that existed but were not in the table
`out/prev/results.txt` was written by `./run.sh` invoked with a pattern, so
it only listed the jobs of that invocation. Logs of earlier invocations
showed: `SafetyFull` PASS (`run1.log`), `Replicas` complete with no error
(25,875,873 / 5,092,728, depth 22, 118 s, 8 workers), `Grinding`,
`GrindingHonest`, `GrindingIntents2` refuted as expected. Two mutants,
`NoAuth_PolicyAuthorised` and `NoAttemptCap_BoundedAttempts`, had never been
run at all (no log). All of these are in the table now; the two mutants are
killed (3-state and 7-state traces).

## T7. State explosion and disk-full crash of `LivenessByz`
Config: 3 commits, log 6, receipts 6, 2 rejects, 1 Byzantine call, 2
Byzantine transactions, 1 policy update, liveness property `Progress`.
TLC ran for 4 h 17 min, 521,850,804 states generated / 180,317,599 distinct,
47.8 M states on the queue at depth 16, and then died with
`java.io.IOException: No space left on device` (the disk-backed state queue
filled the 460 GB volume; the log ends in a `FileOutputStream` stack trace
because TLC could not even re-extract its standard modules to `$TMPDIR`).
The periodic liveness checks up to 124 M states found no violation, but that
is not a verdict.

Why so big: every Byzantine call has ~27 requests to choose from, every
Byzantine transaction ~12, they can be interleaved anywhere in a log of 6,
and liveness checking keeps the whole graph (no symmetry, no state
compression). The previous engineer sized the bounds from the worst case
(2 Byzantine txs + 1 policy tx + 2 accepts wasted by a policy change + 1 =
log 6; 2 rejects + 1 Byzantine call + 2 wasted approvals + 1 = receipts 6).

Fix: same arithmetic with 1 reject and 1 Byzantine transaction gives log 5,
receipts 5. That model completes in 228 s (8,221,828 / 2,980,875, depth 16)
and `Progress` holds. On a loaded machine that is still too close to the
budget, so the default model additionally uses `Forest2` (two root commits;
`Progress` only needs the first accept, the child commit `c` of `Forest3`
adds nothing to the property): 2,069,963 / 693,277, depth 16, 32 s. The
Forest3 version is `large/LivenessByz_Forest3.cfg`, the original (crashed)
config is `large/LivenessByz.cfg`. The plain `Liveness` model (299 s, close
to the 5-minute budget) was reduced to 1 reject / receipts 5: 5,601,681 /
1,417,112, depth 26, 164 s idle, 107 s in the final run.

## T8. Mutant `NoNotaryIntent_NoGrinding`: 2 hours, then disk full
Single-worker BFS (for a shortest trace), log 4, receipts 3, 2 Byzantine
calls and transactions, `UniqueSessions = TRUE`. The violating trace is only
7 states long, but with the `notaryIntent` guard removed the Byzantine call
may use *any* nonce in `1..MaxLogLen`, and with unique session ids no two
calls collapse, so the branching at depths 4-6 is enormous: still at depth 7
after 1 h 56 min, 510,498,808 generated / 229,693,151 distinct, 190 M on
the queue, then `No space left on device`.

Fix: the witness needs one intent, one Byzantine rejection under an
unregistered nonce, one honest approval under the registered nonce, one
accept. Constants reduced to log 2, receipts 2, 1 reject, 1 Byzantine call,
1 Byzantine tx: the violation is found in 2 s after 73,155 states.

## T9. Mutant `NoRestartIndex_PrefixConsistency`: 68 minutes for a 10-state trace
Found the violation, but only after 457,243,218 states generated /
97,052,868 distinct (1 h 07 min, single worker). The trace uses only honest
actions plus one crash/restart: two approvals for `a` and `b` at head
`none`, both accepts in the log, replica r1 applies the first, crashes,
restarts with the persisted (empty) state but the old index, applies the
second accept on top of the empty state and ends with history `<<b>>` while
r2 has `<<a>>`. The Byzantine budget (2 calls, 2 txs, 3 receipts) only
multiplied the states at every BFS level before depth 10. Reduced to 2
receipts, 1 reject, 1 call, 1 tx: same 10-state trace in 44 s.

## T10. Two mutants that survived: `NoIntent` and `NoIntentUnused`
Both ran to completion (9,264,359 generated / 2,926,248 distinct, depth 12,
about 8.5 min each with one worker) and TLC found no violation of
`IntentBinding`. Three possible causes were considered.

*Constants too small?* No: the full state space of the model was explored,
and the same bounds (log 4, 3 receipts) are enough for the grinding witness
with intents. Enlarging them cannot create an accept that is not already
representable.

*Property too weak?* `IntentBinding` states exactly what the two guards are
meant to ensure (nonce consumed, intent registered for the same pair, no
nonce consumed twice). A stronger property would not help because the
mutants really do not reach a bad state:

*Equivalent mutants.* With every other guard in place, the two checks are
implied:

- `intent` (AcceptCommit: the nonce belongs to a registered intent for
  `(expectedHead, candidate)`). The notary guard `notaryIntent` only issues a
  receipt whose nonce is registered on chain for the receipt's own
  `(base, candidate)`; `member` forces the transaction's receipt to be
  genuine; `base` and `candidate` force `receipt.base = expectedHead` and
  `receipt.candidate = candidate`. Intents are never removed, so the intent
  the notary saw is still registered when the accept is applied. Hence
  every accept that passes the other guards also passes `intent`.
- `intentUnused` (AcceptCommit: the nonce was not consumed before). A nonce
  can only be consumed twice by accepting two receipts with the same nonce.
  `notaryOnce` makes the receipt with a given nonce unique, and `head`
  prevents accepting the same receipt again because the head never returns
  to `receipt.base` (the history is a chain without duplicates). Hence no
  second consumption is reachable.

This mirrors D9 in the design log, where one code mutant was "redundant"
because `attest.ProxyVerifier` already enforced the binding. The two guards
are defence in depth against a notary that does not check intents (or that
attests a nonce twice) and against a head that could be rolled back. To show
that they are load-bearing on their own, two **double mutants** were added:
`NoIntent_NoNotaryIntent` (notary and state machine both skip the intent
check) is caught by `IntentBinding` after 21,140 states with a 4-state
trace; `NoIntentUnused_NoHead` (replay of a consumed accept) is caught after
15,531 states with an 8-state trace. The two single mutants stay in
`mutants/` marked `EXPECTED: invariant IntentBinding HOLDS (equivalent
mutant)`; `run.sh` now treats such a file as a "holds" job.

## T11. `Intents` needed 395 s
Over the 5-minute budget. `MaxByzCalls` 2 -> 1 (keeping 2 Byzantine
transactions, which are the interesting part for intents: intent spam and
accept replays) brings it to 129 s (7,016,264 / 2,797,553, depth 12).
`MaxByzTxs` 2 -> 1 instead would give 32 s but removes the replay + spam
combination. The equivalent mutants use the same reduction (4,676,457 /
1,708,840 each, 46 s and 57 s with 8 workers). `IntentsNoGrinding` (229 s
with 2 calls / 2 txs) keeps the 2 Byzantine calls, which are what matters
for grinding, and drops to 1 Byzantine transaction: 210,378 / 118,931,
5 s. Together the two intent models cover both sides (2 calls + 1 tx, and
1 call + 2 txs); the 2 + 2 versions are in `large/` with their results.

## T12. Concurrent TLC runs race on `$TMPDIR`
TLC extracts `Naturals.tla`, `Sequences.tla` etc. into `java.io.tmpdir`
before parsing. Two instances started at the same second produced
`Fatal errors while parsing TLA+ spec in file MC ... NullPointerException`
in one of them. `run.sh` now gives every job its own tmpdir.

## T13. What `run.sh` does now
Every java invocation runs under `timeout 600`; the table reports `TIMEOUT`
and `CRASH` (TLC threw an exception, e.g. disk full) as distinct results
instead of a silent `FAIL`. `./run.sh PATTERN` re-runs a subset and keeps
the rows of the other jobs (the old script truncated `results.txt` on every
invocation, which is how the previous table lost the `SafetyFull`,
`Replicas` and `Grinding*` rows, T6). The configs that do not fit the budget
live in `spec/large/` and are not executed. The whole table (38 jobs)
reproduced in 14.5 minutes.

## T14. Spec bugs found by TLC
None in this session, and none recorded by the previous engineer; every
"holds" job holds and every reachable violation is a mutant or a
deliberately false property. Two things TLC *did* tell us that are design
facts rather than bugs: receipts bind the policy hash and not the epoch
(`PolicyEpoch` refuted: a receipt obtained before an update to the same
hash is accepted after it), and with `MaxAttempts = 2` approval grinding is
bounded but not excluded (`GrindingIntents2` refuted after exactly two
attempts).

## T15. The first full run hit a loaded machine
The first complete `./run.sh` was started while another session on the same
laptop ran a Java test grader on 4-5 cores (load average 17-28, 16 GB RAM
fully used, 40-50 % of CPU time in the kernel). Every job was 2-4x slower
than in the isolated measurements: `SafetyChain` 412 s instead of 202 s,
`SafetyFull` 65-136 s instead of 31 s, and `SafetyAdversary` was killed by
the 600 s timeout with 56,467,208 of its 59,228,780 states explored. The
run was aborted and the four models that took more than 150 s in isolation
were reduced once more so that the table is robust to a 2-3x slowdown:
`SafetyChain` 4 -> 3 receipts (4,355,686 / 1,724,168, depth 14; the two
`Witness*` configs were aligned so that they witness the model that is
checked), `SafetyAdversary` 2 -> 1 Byzantine calls (8,292,032 / 2,715,007,
depth 10), `IntentsNoGrinding` 2 -> 1 Byzantine txs, `LivenessByz`
Forest3 -> Forest2. The checked larger versions and their numbers are in
`spec/large/README.md`. The final run (still with the other workload
present) completed all 38 jobs in 14.5 minutes; the slowest job was
`Replicas` at 164 s.
