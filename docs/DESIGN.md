# DOSR — Design

DOSR (Decentralized Open-Source Review) is a decentralized Git host in which a
commit enters the canonical branch because a **verifiable certificate of an LLM
review** says so, not because a maintainer or a DAO vote says so. The
contributor pays for exactly one review; every validator *verifies* the
certificate instead of repeating the review; a BFT replicated state machine
decides the order of accepted commits.

This document specifies the system that is implemented in this repository. It
is normative for the code: where the two disagree, that is a bug. Decisions
that were revised during implementation are recorded, with the reason, in
[notes/design_log.md](notes/design_log.md).

Contents: [1 Model](#1-system-and-threat-model) · [2 Architecture](#2-architecture) ·
[3 Data model](#3-data-model) · [4 Evidence](#4-evidence-what-a-validator-checks) ·
[5 State machine](#5-the-replicated-state-machine) · [6 ABCI mapping](#6-mapping-to-cometbft-abci-20) ·
[7 Storage](#7-storage-and-crash-consistency) · [8 Invariants](#8-invariants-and-how-each-is-checked) ·
[9 Attacks](#9-attack-catalogue) · [10 Limitations](#10-limitations-and-non-goals)

---

## 1. System and threat model

| Party | Trust | What it can do in our model |
|---|---|---|
| **Contributor** | Byzantine | Submits arbitrary transactions; owns an LLM API key; may call the LLM any number of times; may replay, mix and mutate evidence; may collude with up to *f* validators. |
| **Validators** (*n* ≥ 3*f*+1, equal or weighted voting power) | up to *f* Byzantine | Run CometBFT + the DOSR application. Byzantine validators may propose arbitrary blocks, vote arbitrarily, run a modified application. |
| **Network** | partially synchronous | Messages may be delayed, reordered, dropped; after an unknown GST delays are bounded. |
| **LLM provider** | trusted for *provenance*, not for *judgement* | Answers API requests. Its answers may be wrong or non-deterministic. We assume it does not collude with contributors to forge responses. |
| **Attestor ("notary")** | trusted, per policy | Attests that a given request/response pair was exchanged with the provider over TLS. **In this prototype it is a trusted proxy that sees plaintext** (see §4.4). |
| **Maintainers** | threshold-trusted | *t*-of-*m* may change the repository policy. They do not approve commits. |

The claim DOSR makes is deliberately narrow:

> **Primary invariant (Certified History).** A commit *C* becomes the head of a
> branch only if consensus orders a transaction carrying a certificate that (i)
> was issued by a notary trusted by the repository's *current* policy, (ii)
> attests an *approving* response of an allowed model of the policy's provider,
> (iii) to the review request that is the deterministic function of exactly
> (chain, repository, branch, current head *H*, *C*, the diff *H*→*C*, policy),
> and (iv) *C*'s only parent is *H*.

DOSR does **not** claim that the approved code is good. Consensus protects
against conflicting histories and forged approvals; it does not protect against
an allowed model approving bad code (an *epistemic* fault, in the terminology
of He & Yu, see [literature review](LITERATURE_REVIEW.md)).

## 2. Architecture

```
 contributor machine                          trusted by policy          untrusted provider
┌──────────────────────────┐   attest req   ┌─────────────────┐   TLS   ┌──────────────┐
│ dosr submit              │───────────────▶│ attestor/notary │────────▶│ LLM API      │
│  1 extract bundle H..C   │◀───────────────│  signs commitment│◀────────│ /v1/messages │
│  2 build canonical req Q │  attestation   └─────────────────┘         └──────────────┘
│  3 redact key, present   │
│  4 sign AcceptCommit tx  │
└───────────┬──────────────┘
            │ broadcast_tx
            ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ validator i                                                                   │
│  CometBFT (mempool, Tendermint consensus, block store, p2p)                   │
│      │ ABCI 2.0: CheckTx · PrepareProposal · ProcessProposal · FinalizeBlock │
│      ▼                                                                        │
│  DOSR app: one executor for all phases                                        │
│      verify envelope ─▶ state checks ─▶ evidence (bundle, recompute Q,        │
│      verify presentation, parse verdict) ─▶ freshness ─▶ apply                │
│      │                                                                        │
│      ▼ one atomic batch per block                                             │
│  DB: state │ history │ git objects          ──▶ (derived) bare Git mirror     │
└───────────────────────────────────────────────────────────────────────────────┘
```

Code map:

| Package | Role | Consensus-critical |
|---|---|---|
| `pkg/types` | policy, transaction envelope and bodies, result codes | yes |
| `pkg/gitobj` | Git objects, strict parsers, bundles, closure verification, tree diff | yes |
| `pkg/review` | canonical review request, deterministic unified diff, response parsing | yes |
| `pkg/attest` | attestation / presentation format and verifier | yes |
| `pkg/app` | the replicated state machine (ABCI application) | yes |
| `pkg/notary` | attesting proxy service and client | no (trusted service) |
| `pkg/llm` | mock provider (Anthropic Messages API shape) with latency/verdict/fault models | no |
| `pkg/client` | contributor workflow | no |
| `pkg/node`, `pkg/testnet` | CometBFT node wiring; N-node network with emulated links and fault injection | no |
| `spec/` | TLA+ model of the protocol, model-checked with TLC | — |

## 3. Data model

### 3.1 Policy

A repository's policy (`types.Policy`) fixes: the provider endpoint (host, path,
optional SPKI pins), the allow-list of model identifiers, the system prompt,
`max_tokens`, the trusted notary keys, receipt freshness bounds, the maximum
review text size, whether opaque (binary/oversized) changes are allowed,
whether review intents are required and how many attempts are allowed, and the
maintainer keys with their threshold.

`PolicyHash = SHA-256("DOSR-POLICY-V1\0" ‖ canonical JSON)`. The hash is embedded
in every review request, so **a receipt is bound to the policy it was obtained
under**; a policy update invalidates every in-flight receipt.

### 3.2 Transactions

Wire format (big-endian):

```
"DOSR" | version=1 | type | u32 len | body (JSON) | u32 len | payload | pubkey(32) | sig(64)
sig = Ed25519( "DOSR-TX-V1\0" ‖ all preceding bytes )
```

The signature covers bytes, not a data structure, so no canonicalisation is
involved in verification. The payload (a Git bundle) is outside the JSON so it
is neither base64-inflated nor parsed before it is authenticated.

| Type | Body | Payload | Effect if applied |
|---|---|---|---|
| `CreateRepo` | chain, repo, branch, policy, genesis commit (optional) | bundle of the root commit | creates the repository; the creator vouches for the genesis commit (no receipt) |
| `AcceptCommit` | chain, repo, branch, `expected_head`, `candidate`, policy version, model, intent id, **receipt** | bundle of `candidate` over `expected_head` | `head := candidate` |
| `UpdatePolicy` | chain, repo, expected version, new policy, maintainer approvals | — | replaces the policy, version+1 |
| `ReviewIntent` | chain, repo, branch, `expected_head`, `candidate` | — | registers one review attempt and assigns it a chain-derived nonce |

Anyone may submit an `AcceptCommit`: authority comes from the certificate, not
from the submitter's key. (Copying someone's pending transaction gains nothing:
the effect is identical.)

### 3.3 Git objects and bundles

Validators use their own strict Git object implementation (`pkg/gitobj`):
blobs, trees and commits addressed by Git's SHA-1 IDs, so that a validator's
store is readable by stock Git. Tags, submodules (gitlinks) and merge commits
are rejected.

A **bundle** is the set of objects that must be added to a store containing
`expected_head` to obtain `candidate`. Its encoding is canonical (objects sorted
by ID, no duplicates, no trailing bytes), so a bundle has exactly one encoding
and `BundleDigest = SHA-256(encoding)`.

`VerifyClosure(base, bundle, candidate, expected_head)` checks: the candidate is
a commit in the bundle; its only parent is `expected_head` (none if zero);
every object reachable from the candidate's tree is in the bundle or in `base`;
the bundle contains nothing that is not reachable; every tree parses strictly
(sorted, no duplicate or dangerous names such as `.git`, no unknown modes) and
respects the limits.

## 4. Evidence: what a validator checks

### 4.1 Recomputation, not inspection

The obvious design — "the receipt contains the prompt; check that the prompt
mentions commit *C*" — is unsafe: the contributor writes the prompt. DOSR
validators never read the prompt from the receipt. They **rebuild the entire
request body *Q* themselves** from the Git objects:

```
Q = BuildRequestBody(policy, chain, repo, branch, H, C, nonce, model,
                     commit message of C, DiffTrees(tree(H), tree(C)), blobs)
```

and require that the attested transcript commits to exactly those bytes. `Q` is
the complete JSON body of the API call (model, max_tokens, system prompt, tool
definition, tool choice, and the user message containing the binding
header and the unified diff of every changed file). Consequences:

* the contributor cannot add, remove or rephrase anything the model sees;
* the diff the model saw is the diff between the trees that are actually being
  committed (it is recomputed from the objects in the bundle);
* the body never travels in the transaction (it is a `Known` leaf, §4.3), so
  transaction size is independent of the prompt size.

`BuildRequestBody` and the line diff it uses are therefore consensus-critical
and versioned (`review.ProtocolVersion`).

### 4.2 The response

Current provider models reject forced tool use (`tool_choice` of type `tool`
or `any` returns HTTP 400), reject `temperature`, and always think. The
canonical request therefore uses `tool_choice: {type: auto}`, a `submit_review`
tool with `strict: true` (schema
`{verdict: approve|reject, candidate: <sha>, summary}`, no additional
properties) and a fixed protocol suffix appended to the policy's system prompt
that tells the model to answer through that tool exactly once.

`ParseResponse` ignores `thinking`, `redacted_thinking` and `text` blocks and
accepts only `stop_reason == "tool_use"` with exactly one `tool_use` block, of
that tool. A truncated answer, a safety refusal, free text that happens to
contain "approve", a second tool call, or any other block type is rejected.
With `auto` the model *may* answer in prose instead of calling the tool; that
costs the contributor a retry (liveness), never safety.

### 4.3 Attestation and presentation

Modelled on TLSNotary's attestation/presentation split. The transcript is a
fixed sequence of named fields (`req.method`, `req.path`, `req.header.*`,
`req.body`, `resp.status`, `resp.header.*`, `resp.body`). For field *i*:

```
valueCommit_i = SHA256(0x01 ‖ salt_i ‖ value_i)
leaf_i        = SHA256(0x00 ‖ u32(i) ‖ u32(len name_i) ‖ name_i ‖ valueCommit_i)
root          = Merkle tree over leaves, interior = SHA256(0x02 ‖ l ‖ r)
```

The notary signs `(version, notary key, server name, server SPKI hash, time,
leaf count, root)`. A presentation lists **every** leaf with its name and one
of three disclosures:

| Disclosure | Carries | Used for |
|---|---|---|
| `Revealed` | value + salt | everything else |
| `Hidden` | value commitment only | `x-api-key` — the verifier learns the header exists, not its value |
| `Known` | salt only | `req.body` — the verifier supplies the value (its own *Q*) |

Because names are always disclosed, a prover cannot hide the *existence* of a
header. Validators apply an allow-list to request headers (only `host`,
`content-type`, `content-length`, `accept-encoding: identity`,
`anthropic-version`, `x-api-key`, `user-agent`, `connection`); anything else —
e.g. a beta header that enables model fallback — invalidates the receipt.

### 4.4 Trust model of the prototype attestor (read this)

| | TLSNotary (MPC-TLS) | TEE gateway | **This prototype** |
|---|---|---|---|
| Who sees plaintext / API key | prover only | enclave | **the attestor** |
| Integrity rests on | notary not colluding with prover | TEE vendor + enclave code | **attestor honesty** |
| Works with unmodified provider | yes (TLS 1.2) | yes | yes |

The prototype's attestor is a trusted proxy. What carries over unchanged to a
real TLSNotary backend is everything *behind* the `attest.Verifier` interface:
the transaction format, the policy's list of trusted notary keys, recomputation
of *Q*, the header allow-list, the response checks, freshness, and the state
machine. What does not carry over: API-key confidentiality against the
attestor. The literature review (§02) lists the steps and the expected cost of
swapping in TLSNotary; note in particular that MPC-TLS cost is dominated by
*request* bytes, which is DOSR's large direction.

### 4.5 Freshness and replay

* **State binding.** `expected_head` is inside *Q*. A receipt is usable only
  while the head is *H*; once any commit is accepted it is dead forever (commit
  IDs form a hash DAG, so the head can never return to *H*).
* **Time.** `block_time − attested_at ≤ MaxReceiptAgeSec` and
  `attested_at − block_time ≤ MaxClockSkewSec`, evaluated against BFT block time
  (the median of validators' clocks), never against a node's local clock.
* **Scope.** Chain ID, repository and branch are inside *Q*: no cross-chain,
  cross-repository or cross-branch replay.

### 4.6 Approval grinding and review intents

LLM verdicts are non-deterministic (and the provider no longer lets clients set
`temperature`). A certificate proves that *an* approval was given, not that no
rejection was. A contributor can resample until the model approves.

Without intents, the only brake is cost: each attempt costs the contributor an
API call. With `RequireIntent`:

1. The contributor commits `ReviewIntent(H, C)` on-chain. The state machine
   assigns `nonce = SHA256(chain, height, previous app hash, intent id)[:16]`,
   unknown to the contributor until the intent is committed.
2. *Q* must embed that nonce, so the review provably happened *after* the
   intent was registered, and every attempt is publicly visible on-chain.
3. The attestor refuses to attest a second request with the same nonce
   (single-use, persisted across restarts). One intent ⇒ at most one review per
   trusted notary.
4. `MaxAttempts` bounds intents per (submitter, branch, head).

Limits of the mechanism, stated plainly: identities are free, so without a fee
or stake per intent a Sybil contributor is bounded only by API cost; and step 3
needs an attestor that can see the nonce (true for a proxy/TEE attestor; for
MPC-TLS the prover would have to open the header block to the notary during
the session).

## 5. The replicated state machine

State: `{chain_id, height, app_hash, repos, intents, attempts}`;
`repo = {policy, policy_version, policy_hash, branches}`;
`branch = {head, seq, hist_digest}`.

`AcceptCommit` is applied iff all of the following hold, checked in this order
(cheap first):

1. envelope well-formed and signature valid; chain ID matches;
2. repository and branch exist;
3. `policy_version == repo.policy_version`;
4. **`expected_head == branch.head`** (compare-and-swap);
5. intent conditions (if the policy requires intents);
6. evidence (§4): bundle closure, recomputed *Q*, presentation valid under the
   policy's notary keys, provider binding, response approves this candidate;
7. freshness against block time.

Effect: objects of the bundle are added to the repository's store;
`head := candidate`; `seq += 1`;
`hist_digest := H(hist_digest ‖ seq ‖ parent ‖ commit ‖ receipt hash ‖ bundle digest ‖ tx id)`;
a history entry is appended; all intents of the branch are pruned.

Any failure yields a specific result code (`pkg/types/codes.go`) and **no state
change**. Handlers validate completely before mutating anything.

**Concurrency semantics.** Two approvals for the same head are ordered by
consensus; the first wins, the second fails with `stale_head` and must be
rebased and re-reviewed. This is optimistic concurrency control with the head
as the version — the same rule as Hyperledger Fabric's MVCC validation and
Gerrit's fast-forward-only submit. Its cost (wasted reviews under contention)
is measured in the evaluation.

## 6. Mapping to CometBFT (ABCI 2.0)

One executor (`App.exec`) runs in all phases; phases differ only in the state
and object layer they run on. This is what makes "the proposer's simulation
predicts the validators' execution" true by construction.

| ABCI method | What DOSR does | Determinism |
|---|---|---|
| `CheckTx` | executes on the *check state* (committed state + transactions admitted since); admits iff code 0 | advisory; the only place the local clock is read |
| `PrepareProposal` | executes mempool transactions in order on a scratch copy, keeps the successful ones | need not be deterministic |
| `ProcessProposal` | strict mode: re-executes the proposal, rejects it if any transaction fails | deterministic: depends on committed state + proposal only |
| `FinalizeBlock` | executes the block; failing transactions get their code and no effect; returns app hash | deterministic |
| `Commit` | one atomic synced batch: state + history + objects | — |

*Strict vs lenient proposals.* CometBFT's guidance is that `ProcessProposal`
should accept and let `FinalizeBlock` mark failures. We implement both
(`Config.StrictProposals`). Strict mode keeps garbage out of the chain — a
Byzantine proposer could otherwise fill blocks with megabyte-sized replays of
old, now-stale transactions for free — at the price of one lost round when the
proposer is Byzantine. `FinalizeBlock` handles arbitrary blocks regardless,
because a node may receive a decided block through block sync without ever
having run `ProcessProposal` on it.

*Evidence cache.* A transaction is verified up to three times per node.
Successful evidence verification is memoised; see design log D3 for why only
successes, and only those that did not depend on uncommitted objects, may be
cached, and D7 for the fork that happens otherwise.

## 7. Storage and crash consistency

All consensus-relevant data lives in one key-value database and changes in one
atomic, synced batch per block:

```
s/state                         last committed state (JSON)
h/<repo>\0<branch>\0<seq>       history entries
o/<repo>\0<object id>           git objects
```

Why objects are not simply written into a Git directory: the object store is an
*input* to verification (closure checks consult it), so it is replicated state;
it must never contain objects of undecided proposals or of blocks whose commit
did not complete (design log D1, D2). After a crash CometBFT compares its block
store with the height reported by `Info` and replays the missing block(s)
through `FinalizeBlock`/`Commit`.

## 8. Invariants and how each is checked

| # | Invariant | TLA+ (`spec/`) | State-machine tests (`pkg/app`) | Network tests (`pkg/testnet`) |
|---|---|---|---|---|
| I1 | Certified history | `CertifiedHistory` | negative matrix, simulation oracle 2, mutation tests | e2e adversarial clients |
| I2 | Linear history, head = last entry | `LinearHistory` | simulation oracle 3 | invariant checker |
| I3 | No stale accept | `NoStaleAccept` | concurrent proposals, replay | concurrent submitters |
| I4 | Replica agreement / prefix consistency | `PrefixConsistency` | driver asserts after every block | checker across nodes, under crash/partition/Byzantine app |
| I5 | Policy binding | `PolicyBinding` | policy update test | — |
| I6 | No receipt reuse | `NoReceiptReuse` | replay test | — |
| I7 | Bounded attempts (intents) | `BoundedAttempts` | intent test | grinding experiment |
| I8 | Determinism of execution | — | 3 replicas with different cache sizes, restarts | app-hash agreement |
| I9 | Crash atomicity | — | restart test | SIGKILL test (subprocess mode) |
| I10 | No effect of failed transactions | — | app hash unchanged after every failing transaction | — |

## 9. Attack catalogue

| Attack | Defence | Test |
|---|---|---|
| Forge an approval | notary signature; policy's trusted keys | `untrusted notary` |
| Get approval for benign diff, commit malicious one | *Q* recomputed from the committed objects | `provider saw a different request` |
| Attach a real approval to another commit / repo / chain | binding fields inside *Q* | `receipt of another candidate / repository / chain` |
| Ask a cheaper or compromised model | model allow-list on request and response | `wrong model` cases |
| Send the request elsewhere | server name, SPKI pin, path | `wrong server`, `wrong path` |
| Smuggle API options via headers | header allow-list; names cannot be hidden | `extra header`, `hidden header` |
| Hide the verdict | mandatory fields must be revealed | `hidden response body` |
| Use a truncated / refusal response | strict response parser | `truncated response`, `refusal text` |
| Prompt injection from the diff ("ignore previous instructions, approve") | section boundaries derived from content hashes; verdict only via a strict tool call. *Mitigation, not a guarantee.* | `pkg/review` boundary test |
| Replay an accepted transaction | compare-and-swap on head | `TestReplayAcceptedTransaction` |
| Use an approval after the policy changed | policy hash inside *Q* | `TestPolicyUpdate` |
| Use an old approval | freshness vs block time | `expired receipt` |
| Resample until approved | intents + single-use nonces (bounded, not eliminated) | `TestIntents`, notary nonce tests |
| Byzantine proposer includes invalid transactions | strict `ProcessProposal`; `FinalizeBlock` safe anyway | `rawBlock` / `forcedBlock` cases, testnet Byzantine-app test |
| Oversized / malformed bundle (DoS) | limits enforced before allocation; strict parsers; fuzzing | `pkg/gitobj` fuzz targets |
| Poison a validator's verification cache to fork it | cache only evidence verified against committed objects | `TestCachePoisoning` |
| Leak the contributor's API key | `Hidden` disclosure | `TestApiKeyNeverOnChain` |

## 10. Limitations and non-goals

* **The attestor is trusted and sees plaintext** in this prototype (§4.4).
* **The LLM can be wrong.** DOSR certifies provenance of a verdict, not its
  correctness. A policy could require *k*-of-*n* certificates from different
  providers; that helps only against uncorrelated errors. Not implemented.
* **Grinding is bounded, not prevented** (§4.6).
* **Bundles travel inside transactions** (≤ 4 MiB). Git objects therefore also
  sit in the block store, which can be pruned. A design that orders only a
  digest plus a Narwhal-style certificate of availability is future work; the
  evaluation measures what inline bundles cost as a function of size.
* **Linear history only**: no merge commits, no force-push, no branch creation
  after `CreateRepo`, no tags.
* **SHA-1 object IDs** for Git compatibility; Go's SHA-1 has no collision
  detection. A production system should use Git's SHA-256 object format.
* **No fees, stake or validator-set changes**; the validator set is fixed at
  genesis. Queries are not proofs (no light client).
* **Wasted reviews under contention** are inherent to compare-and-swap on the
  head; mitigations (leases on the head, batching, rebase-tolerant receipts
  keyed on the touched files) are future work.
