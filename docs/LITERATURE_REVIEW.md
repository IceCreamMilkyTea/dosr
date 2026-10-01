# DOSR — Literature Review

This review is in three parts, each a self-contained document with its own
reference list. This page summarises what each part found and what it changed
in DOSR's design.

| Part | Topic | Length |
|---|---|---|
| [01](literature/01_decentralized_git.md) | Decentralized source-code management and repository-state consensus | ~3,700 words, 40 references |
| [02](literature/02_verifiable_llm_calls.md) | Verifiable provenance of TLS/API data and verifiable LLM inference | ~5,500 words, 38 references |
| [03](literature/03_bft_and_ai_review.md) | BFT state machine replication; LLM code review and agent quorums | ~5,900 words, 52 references |

**How to read the citations.** All sources were accessed on 2026-09-29. Every
part ends with a **"Could not verify"** list: claims that we could only find in
search snippets, pages that returned errors, and venues we could not confirm.
Those items are excluded from the argument or explicitly flagged. Many pages
were read through an automated fetch tool that summarises content; quotations
from such pages should be re-checked against the originals before they are
reproduced in the final report. Statements marked **(code)** were read from
source code directly.

---

## 1. Where DOSR sits

Existing decentralized Git systems differ in *where canonical state comes from*
and *who authorises a change to it*:

| System | Canonical state | Who authorises a merge |
|---|---|---|
| Radicle (Heartwood) | each node computes it locally from delegates' signed refs; no global order | a threshold of delegates pushing the same commit |
| Gitopia | application chain; refs, PRs and permissions on-chain, packfiles on IPFS via staked providers | repository admin or DAO proposal |
| GOSH | Git objects as smart contracts | DAO soft-majority vote on protected branches |
| Hammad et al. 2023; Nizamuddin et al. 2019 | permissioned ledger / Ethereum + IPFS | designated authority / approvers |
| gittuf | signed, hash-chained reference state log inside the repository; no ordering layer | a threshold of principals named by policy |
| **DOSR** | BFT replicated state machine | **anyone holding a valid review certificate for exactly (head, commit, policy)** |

In every system we reviewed, authorisation is by *identity* or by *vote*. None
authorises a merge by verifying *evidence that a review took place*. Two prior
systems are close on one axis each:

* **gittuf** has nearly DOSR's data model: its reference-authorisation
  attestation is `(ref, from, to)` — our `(branch, expected_head, candidate)`.
  But it has no ordering layer; its own design document lists log forking and
  freeze attacks as out of scope. BFT ordering is what closes those.
* **Gitopia** has nearly DOSR's ordering rule **(code)**: its merge handler
  rejects when the base branch SHA differs from the SHA in the message. But
  authorisation is by role, and the merge result is reported by a provider.

## 2. Findings that changed the design

| # | Finding | Source | Consequence in DOSR |
|---|---|---|---|
| F1 | TLSNotary is alpha software; its notary server was removed upstream (alpha.13), supports TLS 1.2 with two AES-128-GCM suites only, and its MPC cost is dominated by **request** bytes (order of 10 MB of traffic per KB sent) | Part 02 §2.2 | The prototype uses a trusted attesting proxy behind a `Verifier` interface and says so everywhere. DOSR's request carries the diff — the expensive direction — so an MPC backend needs a hard cap on diff size. `req.body` is never shipped in transactions. |
| F2 | Even real TLSNotary requires trusting that the notary does not collude with the prover ("there is always a signature standing in for a proof") | Part 02 §2.2.5 | The policy carries a *set* of trusted notary keys; we do not claim trustlessness. |
| F3 | Current Anthropic models reject `temperature` values other than the default; "deterministic" LLM settings are not repeatable anyway | Part 02 §2.6.1 | `temperature` was removed from the canonical request. Verdicts are treated as inherently non-deterministic. |
| F4 | We found **no prior work that names or analyses approval grinding** (resampling until the model approves) | Part 02 §2.6.1 | Review intents with chain-derived nonces and single-use enforcement at the attestor (DESIGN §4.6); measured in the evaluation. This part of the design is our own reasoning, not taken from the literature. |
| F5 | API features can change which model answers (beta `fallbacks`), and the response carries the model that actually served the request | Part 02 §2.6.5 | Request headers are allow-listed; the model is checked in the request *and* the response; `stop_reason` is checked; non-streaming, `accept-encoding: identity`. |
| F6 | PBFT §4.6 already prescribes the pattern "one party picks a non-deterministic value, replicas deterministically check it"; Hyperledger Fabric's execute-order-validate validates endorsements and read-set versions after ordering | Part 03 §A.1, §A.3 | DOSR is this pattern with an *external* endorser (the LLM) and the branch head as the MVCC version. Validators never call the LLM: a network call inside the state machine is a listed source of non-determinism. |
| F7 | CometBFT's spec recommends that `ProcessProposal` accept blocks and that invalid transactions be marked failed in `FinalizeBlock` | Part 03 §A.2.3 | Implemented as a switch (`StrictProposals`); both modes are tested and the cost of a Byzantine proposer is measured in both. |
| F8 | Default CometBFT limits: mempool `max_tx_bytes` 1 MiB; `timeout_commit` 1 s; `timeout_propose` 3 s | Part 03 §A.2.4–5 | Node configuration raises the transaction limit for bundles; timeouts are experiment parameters, and the baseline "validators call the LLM during consensus" is expected to collide with `timeout_propose`. |
| F9 | Published baseline: Tendermint 0.33.8 on 16 AWS regions, mean block latency 2.14–2.53 s for 16–128 validators including a 1 s `timeout_commit` (Cason et al., SRDS 2021). No published v0.38 numbers for 4–16 validators over a WAN were found | Part 03 §A.4 | Gives the expected order of magnitude for our emulated-WAN measurements; our small-cluster numbers fill a gap but come from emulation on one machine. |
| F10 | Merge queues and Bors avoid wasted CI by assigning queue position *before* testing; DOSR's rule equals Gerrit's strictest mode (fast-forward only) | Part 01 §1.7 | Wasted reviews under contention are an expected cost; measured in the evaluation; leases/batching listed as future work. |
| F11 | IPFS provides discoverability, not persistence; Narwhal orders certificates of availability instead of data | Part 01 §1.8 | The checkpoint ships bundles inside transactions (availability by construction) and measures what that costs; availability certificates are future work. |
| F12 | AI review comments lead to code changes far less often than human comments (0.9–19.2 % vs ~60 %, Sun et al.); curl ended its bug bounty after AI-generated reports pushed the confirmation rate below 5 % | Part 03 §B.2 | Motivation (maintainer burden) is real; reviewer quality is *not* something DOSR can claim. |
| F13 | He & Yu define *epistemic faults*: protocol-compliant validators endorsing a semantically invalid transition; quorums of correlated models can collapse to a single point of failure | Part 03 §B.3–B.4 | DOSR's security boundary is stated in these terms: consensus gives agreement on history, the certificate gives authenticity of a verdict, neither gives semantic correctness. *k*-of-*n* providers would reduce only uncorrelated errors. |

## 3. Corrections to our own notes

The brainstorming document listed seven papers on agent consensus. All seven
exist and were retrieved; two identifiers in our notes were wrong:

* "Rethinking the Reliability of Multi-agent System: A Perspective from
  Byzantine Fault Tolerance" is arXiv **2511.10400**.
* "AgentRoom" is arXiv **2608.23740** (the OpenReview page could not be
  loaded).

These are preprints; we did not confirm peer review, and their quantitative
claims are the authors' own.

The proposal cites Sun et al. as IEEE TSE and Aðalsteinsson et al. as ESEM
2025. We could retrieve both papers but could **not** confirm either venue from
a primary page; the citations should be double-checked before the final report.

## 4. Open items

* Re-check quotations from the ABCI specification against the original text.
* Full texts of Hammad et al. and Nizamuddin et al. were not accessible (only
  abstracts); no numbers from them are used.
* Several facts about GOSH (costs, lineage) and Gitopia (history of storage
  back-ends, caller authorisation of `MergePullRequest`) are unverified and are
  not relied upon.
