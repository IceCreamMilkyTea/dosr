# DOSR - TLA+ model and TLC results

`DOSR.tla` is a TLA+ model of the DOSR replicated state machine: one
repository, one branch, whose head only advances through an
`AcceptCommit(expected_head, candidate, receipt)` transaction that carries a
notarised, approving LLM-review receipt for exactly that commit and head under
the current review policy. `MC.tla` adds the concrete commit forests and guard
sets used by the `.cfg` files. `run.sh` runs every job and prints the table
reproduced in section 5.

```
spec/
  DOSR.tla            the model
  MC.tla              commit forests, guard sets (mutants), symmetry set
  *.cfg               models on which the properties must HOLD
  expected/*.cfg      properties that are deliberately false; TLC must refute them
  mutants/*.cfg       one guard removed; TLC must find the violation
  large/*.cfg         original, hours-long models (NOT run by run.sh; see large/README.md)
  run.sh              runs everything; ./run.sh PATTERN runs a subset
  out/<job>.out       TLC log of the last run; out/prev/ has the logs of the previous engineer's runs
  traces/<job>.txt    counterexample of every "violates" job
  tools/tla2tools.jar TLC 2.19
```

Reproduce with `./run.sh` (Java 21, 8 cores, 8 GB heap: about 30 minutes in
total, every job under 5 minutes, each java invocation limited to 10 minutes
by `timeout`).

## 1. What is modelled, and what is abstracted away

| Real system | In the model | Why |
|---|---|---|
| CometBFT consensus, blocks, mempool | `log`, a single global sequence of transactions; `Submit(tx)` appends to it | We assume BFT total-order broadcast is correct. Only the *order* of transactions matters to the state machine, not how it was agreed. Consensus correctness is not proved here. |
| Replicas executing blocks, lagging, crashing | `applied[r]`, `rstate[r]` (volatile) and `pidx[r]`, `pstate[r]` (persisted); `Apply`, `Persist`, `Crash`, `Restart` | Checks that the state is a deterministic function of the applied prefix and that a restart resumes from a consistent (index, state) pair. |
| The notarised LLM call (attestor / proxy / TEE) | `Notarise(b, c, p, n, v)` adds a record to `receipts`, the set of **genuinely issued** receipts. The verdict `v` is chosen nondeterministically (the LLM is an oracle). | Cryptography is abstracted: a record is in `receipts` iff a notary really signed it. Forged records have `sid = 0` and are never in `receipts` (unforgeability). |
| Receipt contents (canonical request *Q*, response) | `[base, candidate, policy, nonce, verdict, sid, epoch]` | Exactly the fields the state-machine checks read. `epoch` is a ghost field used only by the refuted property `PolicyEpoch`. |
| Session identity | `UniqueSessions = TRUE`: the k-th call gets `sid = k`. `FALSE`: every genuine receipt has `sid = 1`, so two calls with the same request and verdict are the same element of `receipts` (a sound quotient: the state machine cannot tell them apart). | The quotient keeps the state space small when the order of calls is irrelevant. `NoGrinding` needs the order, so grinding models use `UniqueSessions = TRUE`. |
| Honest contributors | `HonestCall`, `HonestAccept`, `HonestIntent`: read head and policy from *some* replica (possibly stale), ask for a review of a child of that head, submit the receipt they got | Models optimistic concurrency and stale views. |
| Byzantine contributors | `ByzCall`: any request whatsoever to the notary. `ByzAccept`: replay a receipt, pair it with another head or commit, or submit a forged record. `ByzIntent`: register any intent. | `FullAdversary = TRUE` tries every transaction; `FALSE` uses the single-fault reduction below. |
| Maintainers and policy updates | `HonestPolicy` (threshold signatures), `ByzPolicy` (Byzantine maintainers plus an outsider sign anything, but cannot forge honest signatures) | `UpdatePolicy` with compare-and-swap on the version and a signature threshold. |
| ReviewIntent extension | `IntentsEnabled`: `IntentTx` registers `(base, candidate)` and receives `nonce = position in the log`; the notary refuses unregistered nonces (`notaryIntent`) and a second session per nonce (`notaryOnce`); `AcceptCommit` checks the nonce (`intent`, `intentUnused`); `MaxAttempts` intents per pair (`attemptCap`) | The anti-grinding mechanism of DESIGN §4. |
| Every validity check of the state machine and the notary | wrapped in `G("name")`, `Guards = AllGuards` for the real protocol | A **mutant** is `Guards = AllGuards \ {name}`. |

**Single-fault reduction (`FullAdversary = FALSE`).** Five of the
`AcceptCommit` checks are static, i.e. depend on the transaction alone
(`member`, `verdict`, `base`, `candidate`, `parent`). A transaction that
fails two or more of them is rejected by the real state machine *and by every
single mutant*, in every state, so it is a no-op that only occupies a log
slot; all of them are represented by one `JunkTx`. The reduced adversary
submits `JunkTx` or a transaction that fails at most one static check
(genuine receipt with its own pair; receipt re-bound to the parent of its
candidate; receipt re-bound to a sibling; forged but otherwise perfectly bound
approval). The dynamic checks (`head`, `policy`, `intent`, `intentUnused`) are
not restricted. `SafetyFull.cfg` cross-checks the reduction with
`FullAdversary = TRUE` on a small model.

**Bounds.** The model is made finite by `MaxLogLen`, `MaxReceipts`,
`MaxRejects`, `MaxByzCalls`, `MaxByzTxs`, `MaxPolicyTxs`, `MaxCrashes`.
Safety results are therefore results about all behaviours *within those
bounds*. For liveness the bounds must be chosen so that the adversary and the
policy update cannot exhaust the log or the receipt budget before an honest
accept lands; each liveness config states the arithmetic in its header.

## 2. Properties

`States` is the set of all replica states (volatile and persisted); an
invariant `Xxx` asserts `XxxIn(s)` of every `s ∈ States`. `s.certs` is a
ghost sequence with one entry per accepted commit recording the receipt, the
head before, the policy (version, hash) and the log index of the accept.

### Properties that must hold

| Name | In prose | TLA+ |
|---|---|---|
| `TypeOK` | Type invariant: receipts are well-formed genuine records (`sid ≠ 0`), sessions are unique if `UniqueSessions`, the log respects `MaxLogLen`, counters are within bounds, every replica state has one certificate per history entry. | see `DOSR.tla` |
| `CertifiedHistory` (I1) | Every commit of the history was accepted by a transaction of the log that carried a **genuinely issued, approving** receipt for exactly that (base, candidate), issued under the policy hash that was current when the transaction was applied. | `∀ i ∈ 1..Len(s.history): LET c == s.certs[i], tx == log[c.index] IN c.candidate = s.history[i] ∧ c.headBefore = (IF i = 1 THEN None ELSE s.history[i-1]) ∧ tx = AcceptTx(c.headBefore, c.candidate, c.receipt) ∧ c.receipt ∈ receipts ∧ c.receipt.verdict = Approve ∧ c.receipt.base = c.headBefore ∧ c.receipt.candidate = c.candidate ∧ c.receipt.policy = c.policy.hash` |
| `LinearHistory` (I2) | The history is a parent-linked chain from `None`, has no duplicates, and the head is its last element. | `∀ i: Parent[s.history[i]] = (IF i = 1 THEN None ELSE s.history[i-1]) ∧ NoDuplicates(s.history) ∧ s.head = (IF s.history = ⟨⟩ THEN None ELSE last)` |
| `NoStaleAccept` (I3) | A receipt obtained for base *H* is only ever used while the head is *H*. | `∀ i ∈ 1..Len(s.certs): s.certs[i].receipt.base = s.certs[i].headBefore` |
| `PrefixConsistency` (I4) | The histories of any two replicas are prefixes of one another. | `∀ r1, r2: IsPrefix(rstate[r1].history, rstate[r2].history) ∨ IsPrefix(rstate[r2].history, rstate[r1].history)` |
| `Determinism` (I4/I8) | A replica's volatile state is the replay of the prefix it applied, its persisted state the replay of the persisted prefix, and `pidx ≤ applied ≤ Len(log)`. | `∀ r: pidx[r] ≤ applied[r] ≤ Len(log) ∧ rstate[r] = Replay(applied[r]) ∧ pstate[r] = Replay(pidx[r])` |
| `PolicyBinding` (I5) | Every accept used a receipt issued under the policy hash that was current when the accept was applied. | `∀ i: s.certs[i].receipt.policy = s.certs[i].policy.hash` |
| `PolicyAuthorised` | Every policy update that took effect was signed by at least `Threshold` maintainers for exactly the version it replaced, and versions increase one by one. | `Len(s.pauth) = s.pver - 1 ∧ ∀ i: Cardinality(s.pauth[i].signers ∩ Maintainers) ≥ Threshold ∧ s.pauth[i].version = i ∧ s.pauth[i].expected = i` |
| `NoReceiptReuse` (I6) | No receipt is used for two accepts. | `∀ i ≠ j: s.certs[i].receipt ≠ s.certs[j].receipt` |
| `IntentBinding` (I7) | With intents: every accept consumed its own registered intent for the same (base, candidate), and no two accepts consumed the same nonce. | `IntentsEnabled ⇒ ∀ s: (∀ i: c.receipt.nonce ∈ s.used ∧ ∃ n ∈ IntentsFor(s, c.headBefore, c.candidate): n.nonce = c.receipt.nonce) ∧ (∀ i ≠ j: nonces differ)` |
| `BoundedAttempts` (I7) | With intents: at most `MaxAttempts` LLM calls were ever notarised for a given (base, candidate). | `IntentsEnabled ⇒ ∀ b, c: Cardinality({r ∈ receipts : r.base = b ∧ r.candidate = c}) ≤ MaxAttempts` |
| `Progress` (liveness) | Under weak fairness of honest actions, replica application and restart, eventually every replica is up with a non-empty history, and stays so. | `LiveSpec == Spec ∧ Fairness`, `Progress == ◇□(∀ r: up[r] ∧ rstate[r].head ≠ None)` |

### Properties that are deliberately false (`expected/`)

| Name | In prose | TLA+ | Why it is false |
|---|---|---|---|
| `NoGrinding` | A commit that the LLM rejected (same base, candidate, policy, earlier session) is never accepted. | `∀ i: LET a == s.certs[i].receipt IN ¬∃ r ∈ receipts: r.verdict = Reject ∧ r.base = a.base ∧ r.candidate = a.candidate ∧ r.policy = a.policy ∧ (UniqueSessions ⇒ r.sid < a.sid)` | Without intents anyone can simply ask again (approval grinding, D5). With intents and `MaxAttempts = 2` it is still false (bounded, not excluded). With `MaxAttempts = 1` it holds (`IntentsNoGrinding`). |
| `PolicyEpoch` | A receipt is only accepted in the policy *epoch* (version) in which it was issued. | `∀ i: s.certs[i].receipt.epoch = s.certs[i].policy.ver` | Receipts bind the policy **hash**, not the version: a receipt issued before an update to the same hash, or before a roll-back, is still accepted. Documented behaviour, not a bug. |
| `NeverThreeAccepts`, `NeverAcceptAfterPolicyUpdate` | Non-vacuity witnesses: a history of length 3 / an accept after a policy update is reachable in `SafetyChain`. | `Len(s.history) < 3`; `∀ i: s.certs[i].policy.ver = 1` | They must be refuted so that the safety results are not vacuous. |

## 3. Models and constants

All models share `PolicyHashes = {p1, p2}`, `InitPolicy = p1`, three
maintainers of which `m3` is Byzantine, an outsider key `x`, `Threshold = 2`.
Commit forests (`MC.tla`): `Forest2` (`a`, `b` roots), `Forest3` (`a`, `b`
roots, `c` child of `a`), `Forest5` (`a`, `b` roots; `c`, `d` children of
`a`; `e` child of `c`).

| Config | Forest | Replicas / Honest / Byz | Intents | Full adv. | Unique sid | Log | Receipts | Rejects | Byz calls / txs | Policy txs | Crashes | Checks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `SafetyChain` | 5 | 1 / 1 / 1 | - | - | - | 5 | 3 | 1 | 1 / 1 | 1 | 0 | all safety invariants |
| `SafetyAdversary` | 3 | 1 / 1 / 1 | - | - | - | 3 | 3 | 3 | 1 / 2 | 1 | 0 | all safety invariants |
| `SafetyFull` | 2 | 1 / 0 / 1 | - | **yes** | - | 2 | 1 | 1 | 1 / 2 | 1 | 0 | all safety invariants |
| `Replicas` | 3 | 3 / 1 / 1 | - | - | - | 3 | 2 | 1 | 0 / 1 | 1 | 2 | all safety invariants, symmetry on replicas |
| `Intents` | 3 | 1 / 1 / 1 | MaxAttempts 2 | - | - | 4 | 3 | 3 | 1 / 2 | 0 | 0 | all + `IntentBinding`, `BoundedAttempts` |
| `IntentsNoGrinding` | 3 | 1 / 1 / 1 | MaxAttempts 1 | - | yes | 4 | 3 | 3 | 2 / 1 | 0 | 0 | all + `IntentBinding`, `BoundedAttempts`, `NoGrinding` |
| `Liveness` | 3 | 2 / 2 / 0 | - | - | - | 5 | 5 | 1 | 0 / 0 | 1 | 1 | `TypeOK`, `Progress` |
| `LivenessByz` | 2 | 1 / 1 / 1 | - | - | - | 5 | 5 | 1 | 1 / 1 | 1 | 0 | `TypeOK`, `Progress` |
| `LivenessIntents` | 2 | 1 / 1 / 0 | MaxAttempts 2 | - | - | 5 | 4 | 1 | 0 / 0 | 0 | 0 | `TypeOK`, `Progress` |
| `expected/Grinding` | 3 | 1 / 0 / 1 | - | - | yes | 2 | 3 | 2 | 3 / 2 | 0 | 0 | `NoGrinding` |
| `expected/GrindingHonest` | 3 | 1 / 1 / 0 | - | - | yes | 2 | 3 | 2 | 0 / 0 | 0 | 0 | `NoGrinding` |
| `expected/GrindingIntents2` | 3 | 1 / 1 / 1 | MaxAttempts 2 | - | yes | 4 | 3 | 3 | 2 / 2 | 0 | 0 | `NoGrinding` |
| `expected/PolicyEpoch` | 3 | 1 / 1 / 1 | - | - | - (TrackEpoch) | 3 | 2 | 0 | 1 / 1 | 2 | 0 | `PolicyEpoch` |
| `expected/Witness*` | 5 | as `SafetyChain` | - | - | - | 5 | 3 | 1 | 1 / 1 | 1 | 0 | `NeverThreeAccepts` / `NeverAcceptAfterPolicyUpdate` |
| `mutants/*` (no intents) | 3 | 1 / 1 / 1 (2 replicas, 1 crash for `NoRestartIndex_*`) | - | - | - | 3 | 3 | 3 | 2 / 2 | 1 (3 for `NoVersion`) | 0 | the one invariant named in the file |
| `mutants/*` (intents) | 3 | 1 / 1 / 1 | MaxAttempts 1 | - | yes for `*_NoGrinding` | 4 | 3 | 3 | 2 / 2 | 0 | 0 | the one invariant named in the file |

Mutants with reduced constants (the reason is in section 5.2 and in `docs/notes/tla_spec.md`):
`NoIntent_IntentBinding` and `NoIntentUnused_IntentBinding` use 1 Byzantine
call; `NoNotaryIntent_NoGrinding` uses log 2, receipts 2, rejects 1, 1 / 1;
`NoRestartIndex_PrefixConsistency` uses receipts 2, rejects 1, 1 / 1; the
double mutants `NoIntent_NoNotaryIntent_IntentBinding` and
`NoIntentUnused_NoHead_IntentBinding` use log 3, receipts 2, rejects 1, 1 / 1.
The larger versions of `SafetyChain`, `SafetyAdversary`, `Intents`,
`IntentsNoGrinding` and `LivenessByz` that were checked but do not fit the
time budget are in `large/` together with their results (section 5.3).

## 4. Mutants

Every mutant removes exactly one guard (`Guards = AllGuards \ {g}` in
`MC.tla`) and names the invariant that must catch it. `run.sh` runs the
mutants single-threaded so that TLC's breadth-first search returns a
shortest counterexample; the traces are in `traces/<job>.txt`.

| Guard removed | What the real protocol checks | Mutant job(s) | Caught by | Trace |
|---|---|---|---|---|
| `head` | `AcceptCommit`: `head = expected_head` (compare-and-swap) | `NoHead_LinearHistory`, `NoHead_NoStaleAccept`, `NoHead_NoReceiptReuse` | `LinearHistory`, `NoStaleAccept`, `NoReceiptReuse` | 4 / 4 / 6 states |
| `member` | receipt was really issued by the notary (signature) | `NoMember_CertifiedHistory` | `CertifiedHistory` | 3 |
| `verdict` | receipt says *approve* | `NoVerdict_CertifiedHistory` | `CertifiedHistory` | 4 |
| `base` | `receipt.base = expected_head` | `NoBase_CertifiedHistory`, `NoBase_NoStaleAccept` | `CertifiedHistory`, `NoStaleAccept` | 4 / 4 |
| `candidate` | `receipt.candidate = candidate` | `NoCandidate_CertifiedHistory` | `CertifiedHistory` | 4 |
| `policy` | `receipt.policy = current policy hash` | `NoPolicy_CertifiedHistory`, `NoPolicy_PolicyBinding` | `CertifiedHistory`, `PolicyBinding` | 4 / 4 |
| `parent` | `parent(candidate) = expected_head` | `NoParent_LinearHistory` | `LinearHistory` | 4 |
| `version` | `UpdatePolicy`: `expected_version = current version` | `NoVersion_PolicyAuthorised` | `PolicyAuthorised` (a stale, authorised update is applied twice) | 5 |
| `auth` | `UpdatePolicy`: at least `Threshold` maintainer signatures | `NoAuth_PolicyAuthorised` | `PolicyAuthorised` | 3 |
| `attemptCap` | `ReviewIntent`: fewer than `MaxAttempts` intents for the pair | `NoAttemptCap_BoundedAttempts` | `BoundedAttempts` | 7 |
| `notaryIntent` | notary: the nonce is registered on chain for the same pair | `NoNotaryIntent_BoundedAttempts`, `NoNotaryIntent_NoGrinding` | `BoundedAttempts`, `NoGrinding` | 3 / 7 |
| `notaryOnce` | notary: at most one session per nonce | `NoNotaryOnce_BoundedAttempts`, `NoNotaryOnce_NoGrinding` | `BoundedAttempts`, `NoGrinding` | 5 / 7 |
| `restartIndex` | replica restart restores index and state together | `NoRestartIndex_Determinism`, `NoRestartIndex_PrefixConsistency` | `Determinism`, `PrefixConsistency` | 5 / 10 |
| `intent` | `AcceptCommit`: nonce belongs to a registered intent for the pair | `NoIntent_IntentBinding` | **not caught: equivalent mutant** (below) | - |
| `intentUnused` | `AcceptCommit`: that intent was not consumed before | `NoIntentUnused_IntentBinding` | **not caught: equivalent mutant** (below) | - |
| `intent` + `notaryIntent` | double mutant | `NoIntent_NoNotaryIntent_IntentBinding` | `IntentBinding` | 4 |
| `intentUnused` + `head` | double mutant | `NoIntentUnused_NoHead_IntentBinding` | `IntentBinding` | 8 |

### Equivalent mutants

`NoIntent_IntentBinding` and `NoIntentUnused_IntentBinding` were run by the
previous engineer with the expectation "violated" and TLC found no violation
after exploring the complete state space (9,264,359 states, 8.5 min each,
`out/prev/`). This session re-ran them (4,676,457 states each, complete)
with the same outcome and concluded that they are *equivalent mutants*: the
removed check is implied by the remaining ones, so no bounded or unbounded
model can distinguish them from the real protocol.

- `intent`: the notary guard `notaryIntent` only issues a receipt whose
  nonce is registered on chain for the receipt's own `(base, candidate)`;
  `member` forces the transaction's receipt to be genuine; `base` and
  `candidate` force `receipt.base = expected_head` and
  `receipt.candidate = candidate`; intents are never removed. Hence every
  accept that passes the other guards has a registered intent for its pair
  with the receipt's nonce.
- `intentUnused`: consuming a nonce twice needs two accepts of receipts with
  the same nonce. `notaryOnce` makes that receipt unique and `head` prevents
  accepting the same receipt twice, because the head never returns to
  `receipt.base` (the history is a chain without duplicates).

They are defence in depth against a notary that does not enforce intents
(or attests one nonce twice) and against a head that can be rolled back.
The two double mutants above show that with the masking guard also removed
each of them is load-bearing: `IntentBinding` is violated in 4 and 8
states. `run.sh` lists the two single mutants as `equiv IntentBinding`,
which passes iff TLC completes without error. This is the same situation
as mutant M05 in the implementation's mutation testing (design log D9).

## 5. Results

### 5.1 Final table (`./run.sh`, TLC 2.19, Java 21, 8 workers for "holds"/"equiv", 1 worker for "violates")

All 38 jobs passed; total wall-clock time 14.5 minutes (23:48:09 to
00:02:40). Times were measured while another Java workload used 4-5 of the
8 cores, so they are upper bounds (e.g. `Replicas` took 164 s here and 118 s
in the previous engineer's run, `Intents` 128 s here and 129 s idle). "Depth"
is the depth of the complete state graph for a "holds"/"equiv" job and the
length of the counterexample for a "violates" job.

| Job | Expectation | Result | States generated | Distinct | Depth / trace length | Time |
|---|---|---|---|---|---|---|
| `SafetyChain` | holds | **PASS** | 4,355,686 | 1,724,168 | 14 | 28s |
| `SafetyAdversary` | holds | **PASS** | 8,292,032 | 2,715,007 | 10 | 30s |
| `SafetyFull` | holds | **PASS** | 6,043,941 | 2,004,917 | 6 | 29s |
| `Replicas` | holds | **PASS** | 25,875,873 | 5,092,728 | 22 | 164s |
| `Intents` | holds | **PASS** | 7,016,264 | 2,797,553 | 12 | 128s |
| `IntentsNoGrinding` | holds | **PASS** | 210,378 | 118,931 | 12 | 5s |
| `Liveness` | holds | **PASS** | 5,601,681 | 1,417,112 | 26 | 107s |
| `LivenessByz` | holds | **PASS** | 2,069,963 | 693,277 | 16 | 32s |
| `LivenessIntents` | holds | **PASS** | 1,211 | 945 | 14 | 1s |
| `Grinding` | violates NoGrinding | **PASS** | 853,683 | 445,238 | 5 | 4s |
| `GrindingHonest` | violates NoGrinding | **PASS** | 83 | 73 | 5 | 1s |
| `GrindingIntents2` | violates NoGrinding | **PASS** | 1,859,695 | 896,821 | 9 | 84s |
| `PolicyEpoch` | violates PolicyEpoch | **PASS** | 71,403 | 38,276 | 6 | 1s |
| `WitnessAcceptAfterUpdate` | violates NeverAcceptAfterPolicyUpdate | **PASS** | 208,610 | 80,759 | 6 | 2s |
| `WitnessThreeAccepts` | violates NeverThreeAccepts | **PASS** | 3,190,805 | 1,202,143 | 10 | 46s |
| `NoAttemptCap_BoundedAttempts` | violates BoundedAttempts | **PASS** | 243,120 | 128,011 | 7 | 15s |
| `NoAuth_PolicyAuthorised` | violates PolicyAuthorised | **PASS** | 2,608 | 1,263 | 3 | 1s |
| `NoBase_CertifiedHistory` | violates CertifiedHistory | **PASS** | 25,049 | 10,958 | 4 | 0s |
| `NoBase_NoStaleAccept` | violates NoStaleAccept | **PASS** | 25,049 | 10,958 | 4 | 1s |
| `NoCandidate_CertifiedHistory` | violates CertifiedHistory | **PASS** | 5,177 | 2,464 | 4 | 0s |
| `NoHead_LinearHistory` | violates LinearHistory | **PASS** | 22,173 | 9,752 | 4 | 1s |
| `NoHead_NoReceiptReuse` | violates NoReceiptReuse | **PASS** | 808,644 | 276,307 | 6 | 4s |
| `NoHead_NoStaleAccept` | violates NoStaleAccept | **PASS** | 22,173 | 9,752 | 4 | 2s |
| `NoIntentUnused_IntentBinding` | equiv IntentBinding | **PASS** | 4,676,457 | 1,708,840 | 12 | 46s |
| `NoIntentUnused_NoHead_IntentBinding` | violates IntentBinding | **PASS** | 15,531 | 7,135 | 8 | 1s |
| `NoIntent_IntentBinding` | equiv IntentBinding | **PASS** | 4,676,457 | 1,708,840 | 12 | 57s |
| `NoIntent_NoNotaryIntent_IntentBinding` | violates IntentBinding | **PASS** | 21,140 | 10,356 | 4 | 1s |
| `NoMember_CertifiedHistory` | violates CertifiedHistory | **PASS** | 2,386 | 1,213 | 3 | 1s |
| `NoNotaryIntent_BoundedAttempts` | violates BoundedAttempts | **PASS** | 553 | 479 | 3 | 1s |
| `NoNotaryIntent_NoGrinding` | violates NoGrinding | **PASS** | 73,155 | 32,457 | 7 | 1s |
| `NoNotaryOnce_BoundedAttempts` | violates BoundedAttempts | **PASS** | 20,048 | 16,856 | 5 | 1s |
| `NoNotaryOnce_NoGrinding` | violates NoGrinding | **PASS** | 401,257 | 196,602 | 7 | 17s |
| `NoParent_LinearHistory` | violates LinearHistory | **PASS** | 17,632 | 7,883 | 4 | 0s |
| `NoPolicy_CertifiedHistory` | violates CertifiedHistory | **PASS** | 38,666 | 16,269 | 4 | 3s |
| `NoPolicy_PolicyBinding` | violates PolicyBinding | **PASS** | 38,666 | 16,269 | 4 | 1s |
| `NoRestartIndex_Determinism` | violates Determinism | **PASS** | 323,704 | 113,023 | 5 | 3s |
| `NoRestartIndex_PrefixConsistency` | violates PrefixConsistency | **PASS** | 4,763,349 | 1,341,734 | 10 | 41s |
| `NoVerdict_CertifiedHistory` | violates CertifiedHistory | **PASS** | 10,244 | 4,666 | 4 | 0s |
| `NoVersion_PolicyAuthorised` | violates PolicyAuthorised | **PASS** | 382,270 | 133,828 | 5 | 4s |

### 5.2 Status of the jobs that had no result before this session

| Job | Previous status (`out/prev/`) | Now |
|---|---|---|
| `SafetyChain` | no log; an early version (`Safety.out`) was killed after 1 min at 33 M states | 4-receipt model completes in 202 s idle (21,007,340 / 8,143,227, depth 15) but took 412 s under load; default model reduced to 3 receipts (28 s); the 4-receipt config is `large/SafetyChain.cfg` |
| `SafetyAdversary` | no log | 2-call model completes in 234 s idle (59,228,780 / 15,809,026, depth 10) but timed out at 600 s under load; default reduced to 1 Byzantine call (30 s); 2-call config in `large/` |
| `SafetyFull` | PASS in `run1.log` (6,043,941 / 2,004,917, 31 s) | PASS, same numbers |
| `Replicas` | complete, no error in `Replicas.out` (25,875,873 / 5,092,728, depth 22, 118 s) but missing from `results.txt` | PASS, same numbers |
| `LivenessByz` | 4 h 17 min, 521,850,804 / 180,317,599 states, crashed: disk full, no verdict | `Progress` holds on the bounded model (log 5, receipts 5, 1 Byzantine tx, Forest2: 2,069,963 / 693,277, depth 16, 32 s) and on the Forest3 version (8,221,828 / 2,980,875, 228 s idle, `large/LivenessByz_Forest3.cfg`). The original model remains unchecked. |
| `NoIntent_IntentBinding`, `NoIntentUnused_IntentBinding` | complete, no violation | equivalent mutants (section 4); double mutants added and caught |
| `NoNotaryIntent_NoGrinding` | 1 h 56 min, 510,498,808 / 229,693,151 states at depth 7, crashed: disk full | violated in 1 s with the reduced constants (7-state trace) |
| `NoAuth_PolicyAuthorised`, `NoAttemptCap_BoundedAttempts` | never run | violated as expected (3- and 7-state traces) |
| `NoRestartIndex_PrefixConsistency` | violated, but after 457,243,218 states and 1 h 07 min | violated in 41 s with the reduced constants, same 10-state trace |

### 5.3 Largest models that were completed

See `large/README.md`: `SafetyChain` with 4 receipts (21.0 M states),
`SafetyAdversary` with 2 Byzantine calls (59.2 M), `Intents` with 2
Byzantine calls (15.1 M), `IntentsNoGrinding` with 2 Byzantine transactions
(13.3 M), `LivenessByz` on Forest3 (8.2 M). All hold. The only model that
was attempted and never finished is the original `LivenessByz` (log 6,
receipts 6, 2 Byzantine transactions).

## 6. Counterexamples, in prose

Full traces are in `traces/`. `-difftrace` prints only the variables that
changed in each step.

### 6.1 Approval grinding without intents (`expected/GrindingHonest`, 5 states)

1. The honest contributor asks the notary to review `b` on head `none`
   under policy `p1`. The LLM answers **reject** (receipt `sid = 1`).
2. The contributor simply asks again for the same request. The LLM answers
   **approve** (receipt `sid = 2`).
3. The contributor submits `AcceptCommit(none, b, receipt 2)`.
4. The replica applies it: `head = b`, `history = <<b>>`, and the
   certificate holds the approving receipt while a *rejecting* receipt for
   the same `(none, b, p1)` with a smaller session id exists.
   `NoGrinding` is violated.

No Byzantine behaviour is needed. `expected/Grinding` shows the same with a
Byzantine contributor (reject, approve, submit: 5 states), and
`expected/GrindingIntents2` shows that with intents and `MaxAttempts = 2`
it takes exactly two registered intents (one honest, one Byzantine),
a rejection under nonce 1 and an approval under nonce 2 (9 states).
`IntentsNoGrinding` shows that with `MaxAttempts = 1` `NoGrinding` holds
on the whole bounded state space.

### 6.2 Mutant `NoHead` caught by `NoReceiptReuse` (6 states)

1. Honest call: approval for `(none, b, p1)`.
2. Honest `AcceptCommit(none, b, r)` is submitted.
3. The Byzantine contributor submits the *same* transaction again (replay).
4. The replica applies the first: `head = b`.
5. Without the `head = expected_head` check the replay is applied too:
   `history = <<b, b>>`, two certificates with the same receipt.
   `NoReceiptReuse` is violated (and `LinearHistory`: duplicate, and
   `NoStaleAccept`: the second accept used a receipt for base `none` while
   the head was `b`).

### 6.3 Mutant `NoRestartIndex` caught by `PrefixConsistency` (10 states, 2 replicas)

1. Two honest calls: approvals for `(none, b, p1)` and `(none, a, p1)`.
2. Both accepts are submitted: `log = <<Accept(none, b), Accept(none, a)>>`.
3. Replica `r1` applies the first one: `head = b`, `history = <<b>>`.
   `r2` has applied nothing.
4. `r1` crashes and restarts. Its volatile state is replaced by the
   persisted one (empty, `pidx = 0`), but the mutant keeps `applied = 1`.
5. `r1` applies log entry 2 on the *empty* state: `Accept(none, a)` is
   valid there, so `r1.history = <<a>>`.
6. `r2` applies log entry 1: `r2.history = <<b>>`.
   `<<a>>` and `<<b>>` are not prefixes of each other:
   `PrefixConsistency` is violated. (`Determinism` catches the same mutant
   already at the restart: `rstate[r1] ≠ Replay(applied[r1])`.)

### 6.4 Mutant `NoNotaryIntent` caught by `NoGrinding` (7 states)

1. Honest intent for `(none, b)` is submitted; it gets nonce 1.
2. The Byzantine contributor asks for a review of `(none, b, p1)` with the
   **unregistered** nonce 2; the mutant notary attests it: **reject**,
   `sid = 1`.
3. The replica applies the intent.
4. The honest contributor asks with the registered nonce 1: **approve**,
   `sid = 2`.
5. Honest `AcceptCommit(none, b, receipt 2)` is applied. A rejection for
   the same request came first: `NoGrinding` is violated. With the guard
   in place the notary refuses step 2, and `notaryOnce` makes step 4 the
   only session for nonce 1.

### 6.5 Double mutant `NoIntent + NoNotaryIntent` caught by `IntentBinding` (4 states)

The Byzantine contributor obtains an approval for `(none, b, p1)` with
nonce 1 although no intent was ever registered; the honest contributor
sees a current approving receipt and submits it; with the `intent` check
also gone the accept is applied and its certificate carries a nonce for
which `IntentsFor(s, none, b)` is empty.

### 6.6 Mutant `NoPolicy` caught by `PolicyBinding` (4 states)

The Byzantine contributor obtains an approval for `(none, b)` under policy
`p2` while the chain runs `p1`, submits it, and without the policy check it
is applied: the certificate records `receipt.policy = p2`,
`policy.hash = p1`.

## 7. What the spec does not prove

- **LLM semantic correctness.** The verdict is a nondeterministic oracle.
  The model proves that only *notarised approvals* advance the head, not
  that an approval means the code is good. An LLM that approves malicious
  code is outside the model, as is prompt injection through the diff.
- **Consensus correctness.** `log` *is* the total order. Safety and
  liveness of CometBFT (agreement, validity, no forks with fewer than 1/3
  Byzantine validators) are assumed. Byzantine validators are not modelled;
  a fork of the log would break every property.
- **Cryptographic soundness.** Membership in `receipts` stands for "the
  notary signature verifies"; forged records are simply not members. The
  TLS/MPC-TLS/TEE attestation, hash functions, signatures and the binding
  of the canonical request *Q* to the commit objects (bundle closure,
  recomputed diff) are all collapsed into the receipt fields
  `base, candidate, policy, nonce`.
- **Grinding without intents is reachable** (section 6.1): without the
  ReviewIntent extension the protocol only guarantees that *some* notarised
  approval exists, not that the first verdict was respected. With intents
  and `MaxAttempts = k` grinding is bounded to `k` attempts (refuted for
  `k = 2`, holds for `k = 1`), and the bound is per `(base, candidate)` in
  the model; the implementation's per-submitter accounting and its Sybil
  limitation (design log D6) are not modelled.
- **Receipts bind the policy hash, not the epoch** (`PolicyEpoch`
  refuted): a receipt issued before an update that re-installs the same
  hash, or before a roll-back, is accepted after it.
- **Bounded models only.** Every "holds" is a statement about behaviours
  with at most `MaxLogLen` transactions, `MaxReceipts` notarised calls,
  and so on (section 3). No inductive invariant was proved; TLC's
  fingerprint collision probability is reported in each log
  (about 1e-6 or less).
- **Liveness under Byzantine interference** is only checked for 1
  Byzantine call and 1 Byzantine transaction on two root commits; the
  original 2-transaction model on Forest3 could not be completed (state
  explosion, disk full after 4 h). Liveness also depends on the bounds:
  if the adversary and the policy update could exhaust the log or the
  receipt budget, `Progress` would fail for a reason that does not exist in
  the real system (unbounded log); the configs are sized so that this
  cannot happen.
- **Not checked at all:** fees/rate limits per identity, multiple
  branches or repositories, the freshness (block time) check of receipts,
  and the object store / bundle verification (design log D1-D3, D7), which
  are covered by the implementation tests instead.

