# 03 — BFT State Machine Replication and LLM-Based Code Review: Background for DOSR

*Literature review section for DOSR (Decentralized Open-Source Review), Duke ECE/CS 512. All sources accessed 2026-09-29.*

**Method and sourcing note.** Every factual claim below is tied to a source that was fetched during the preparation of this section; bracketed numbers refer to the reference list. Where a claim could only be confirmed through a search-result snippet, or not at all, it is listed in Section C ("Could not verify") instead of being stated as fact. Statements marked *(our analysis)* are our own reasoning about DOSR, not claims made by the cited sources.

---

## Part A — BFT State Machine Replication

### A.1 Protocol families and what DOSR needs from them

**Fault model.** Dwork, Lynch and Stockmeyer (DLS) introduced partial synchrony: message-delay bounds either exist but are unknown, or are known but hold only after an unknown global stabilization time (GST). Their Table I gives the smallest number of processors for a *t*-resilient consensus protocol; for partially synchronous communication it is 3t+1 for Byzantine faults both with and without authentication, and they remark that "for partially synchronous communication, authentication does not improve resiliency" [1]. All protocols below inherit this n ≥ 3f+1 bound.

**PBFT.** Castro and Liskov present "a new, practical algorithm for state machine replication that tolerates Byzantine faults", which "does not rely on synchrony to provide safety" and therefore "must rely on synchrony to provide liveness". Safety is linearizability of the replicated service. The three phases are pre-prepare, prepare and commit; the first two order requests within a view and the last two ensure ordering across views. The paper's headline result is a BFT NFS service "only 3% slower than a standard unreplicated NFS" [2]. PBFT also already addresses non-determinism (Section 4.6 of the paper): the primary selects the non-deterministic value, and "replicas must be able to decide deterministically whether the value is correct (and what to do if it is not) based only on the service state" [2]. This is precisely the pattern DOSR follows: one party produces a non-deterministic artefact (the LLM review), and replicas only run a deterministic check on it.

**Tendermint.** Buchman, Kwon and Milosevic assume partial synchrony with n > 3f and a *gossip communication* property: "If a correct process p sends some message m at time t, all correct processes will receive m before max{t,GST}+Δ". The properties are Agreement ("No two correct processes decide on different values"), Validity (a decided value satisfies a predefined validity predicate) and Termination. Rounds consist of propose, prevote and precommit; `lockedValue/lockedRound` and `validValue/validRound` carry safety across rounds. Unlike PBFT there is "only a single mode of execution" with no separate view-change sub-protocol, and timeouts grow linearly with the round number: `timeoutX(r) = initTimeoutX + r × timeoutDelta` [3].

**HotStuff.** Yin et al. give "a leader-based Byzantine fault-tolerant replication protocol for the partially synchronous model" with *responsiveness* (progress at actual rather than maximum network delay) and communication complexity "linear in the number of replicas". It uses a three-phase commit rule (a block is committed when it heads a "Three-Chain") [4]. HotStuff's comparison table is the standard reference for complexity:

| Protocol | Correct leader | Leader failure (view change) | f leader failures | Responsive |
|---|---|---|---|---|
| PBFT | O(n²) | O(n³) | O(fn³) | yes |
| Tendermint / Casper | O(n²) | O(n²) | O(fn²) | no |
| HotStuff | O(n) | O(n) | O(fn) | yes |

Source: [4] (authenticator complexity). The paper attributes Tendermint's lack of responsiveness to the fact that "a new leader must obtain the highest One-Chain by waiting the maximal network delay" [4]. A separate analytical and experimental study gives message complexities of O(N²) normal-case for PBFT and Tendermint versus O(N) for HotStuff, and concludes that "the CPU cost of serialization and deserialization of the messages limits the throughput" even with sufficient bandwidth [5].

**DAG-based protocols.** Narwhal separates transaction dissemination from ordering; the authors report that Narwhal-HotStuff achieves "over 130,000 tx/sec at less than 2-sec latency" against 1,800 tx/sec for HotStuff, and that Tusk (asynchronous) reaches 160,000 tx/sec at about 3 s latency [6]. Bullshark adds a fast path for synchronous periods and reports 125,000 tx/sec at 2 s latency with 50 parties [7].

**What matters for DOSR** *(our analysis)*. DOSR's workload is a handful of `AcceptCommit` transactions per repository per hour, not 10⁵ tx/s, so the throughput advantage of DAG protocols and the linear message complexity of HotStuff are irrelevant at our validator counts. What matters is:

1. **Deterministic (instant) finality.** A canonical branch head must never reorganise. Tendermint's Agreement property gives this whenever fewer than one third of voting power is Byzantine: a committed block is final, with no probabilistic confirmation depth.
2. **A mature application interface** with an explicit validity predicate, which maps directly onto receipt verification.
3. **Accountability** for equivocation (A.2.5).

The cost is non-responsiveness: block latency is bounded below by configured timeouts, not only by network delay (A.2.4).

### A.2 CometBFT specifics

#### A.2.1 Versions

The GitHub releases API for `cometbft/cometbft` returned the following at access time [8]:

| Line | Latest tag | Published |
|---|---|---|
| v0.38.x | v0.38.26 | 2026-08-13 |
| v0.39.x | v0.39.4 | 2026-07-28 |
| v0.40.x | v0.40.0 (flagged "latest") | 2026-07-27 |
| v1.0.x | v1.0.1 | 2025-02-03 |
| v0.37.x | v0.37.18 | 2026-01-23 |

This differs from the assumption in our project notes that v0.38.x and v1.0.x are the two current lines. The v1.0 line has had no release since February 2025, while v0.38.x is still receiving releases and is the only line the repository README names under "Currently supported versions" ("CometBFT v0.38 introduces ABCI 2.0, which implements the entirety of ABCI++") [9]. The v0.40.0 changelog shows v0.39/v0.40 adding experimental libp2p networking, BLS12-381 keys, adaptive sync, and the ML-DSA-65 post-quantum key type [10]. **Recommendation** *(our analysis)*: build against v0.38.x.

Differences an application developer would meet when moving between lines:

| Change | Source |
|---|---|
| v0.37 → v0.38: ABCI version `2.0.0`; `BeginBlock`, `DeliverTx`, `EndBlock` replaced by `FinalizeBlock`; `app_hash` moved from `ResponseCommit` to `ResponseFinalizeBlock`; `ExtendVote` and `VerifyVoteExtension` added; priority mempool removed | [11] |
| v0.38 → v1.0: ABCI types renamed (`RequestQuery` → `QueryRequest`); protobuf packages moved from `tendermint.*` to `cometbft.*`; Proposer-Based Timestamps opt-in via `PbtsEnableHeight`; `nop` mempool type; default `max_txs_bytes` lowered from 1 GB to 64 MB; minimum Go version 1.23 | [12], [13] |

#### A.2.2 ABCI 2.0 methods

| Method | When called | Must be deterministic? |
|---|---|---|
| `CheckTx` | Before a transaction is admitted to the mempool (and on recheck) | No |
| `PrepareProposal` | At the proposer, to build the block; may reorder, add or remove transactions within `max_tx_bytes` | No ("MAY be non-deterministic") |
| `ProcessProposal` | At every validator on receiving a proposal, before prevoting | **Yes** |
| `ExtendVote` | When a validator precommits a non-nil block | No |
| `VerifyVoteExtension` | On receiving another validator's precommit | **Yes** |
| `FinalizeBlock` | After a block is decided; executes transactions, returns `tx_results`, `validator_updates`, `consensus_param_updates`, `app_hash` | **Yes** |
| `Commit` | After `FinalizeBlock`; persist state | — |

Source: [14]. The grammar for a height is `consensus-height = *consensus-round finalize-block commit` [15].

#### A.2.3 Determinism requirements

The specification states that "ABCI applications must implement deterministic finite-state machines to be securely replicated by the CometBFT consensus engine", and lists sources of non-determinism: random numbers, time, library version changes, race conditions, floating point, JSON or protobuf serialization, "iterating through hash-tables/maps/dictionaries", and external sources ("Filesystem, Network calls"). The consequence: "If there is some non-determinism in the state machine, consensus will eventually fail as nodes disagree over the correct values for the block header" [16].

The formal requirements most relevant to DOSR [17]:

- **Requirement 3 (coherence):** if a correct proposer's `PrepareProposal` produced a block, every correct validator's `ProcessProposal` accepts it.
- **Requirements 4–5 (ProcessProposal determinism):** "`ProcessProposal` is a (deterministic) function of the current state and the block that is about to be applied", and two correct processes accept the same block if and only if the other does. The methods document adds that the status "MUST **exclusively** depend on the parameters passed in the `ProcessProposalRequest`, and the last committed Application state" [14].
- **Requirements 11–12 (FinalizeBlock determinism):** resulting state and transaction results depend exclusively on prior state and the block.
- **`app_hash`** "MUST be deterministic — it must not be a function of anything that did not come from the parameters of `FinalizeBlockRequest` and the previous committed state"; it is the only `FinalizeBlock` output placed in the next block header, while `events` are not required to be deterministic [14].
- A bug in `PrepareProposal`/`ProcessProposal` "makes all processes that hit the bug byzantine"; with a shared codebase most validators would precommit `nil`, "with the serious consequences on CometBFT's liveness" [17]. The spec also advises that "as a general rule `ProcessProposal` SHOULD always accept the block" [17].

*Implications for DOSR (our analysis).* Receipt verification must be a pure function of (transaction bytes, committed state): signature checks against a notary key set stored in application state, hash comparisons, and the `current_head == expected_head` test. It must not read wall-clock time (use the block time from the request), must not fetch certificate chains or revocation data over the network, and must not iterate Go maps when building the state that is hashed. Two design choices are available for a stale or invalid `AcceptCommit`: reject the whole proposal in `ProcessProposal`, or accept the block and mark the transaction failed in `FinalizeBlock`. Given the spec's guidance that `ProcessProposal` should generally accept, and that a false rejection costs a round, the second is the safer default; it also matches Fabric's approach (A.3).

#### A.2.4 Timeouts and latency

Defaults in the v0.38 configuration [18]:

| Parameter | Default | Meaning |
|---|---|---|
| `timeout_propose` / `_delta` | 3 s / 500 ms | wait for a proposal before prevoting nil; increment per round |
| `timeout_prevote` / `_delta` | 1 s / 500 ms | wait after +2/3 prevotes "for anything" |
| `timeout_precommit` / `_delta` | 1 s / 500 ms | wait after +2/3 precommits "for anything" |
| `timeout_commit` | 1 s | wait after committing before starting the next height |
| `create_empty_blocks` | true | blocks created about every second with defaults |

`timeout_commit` is a fixed floor on block interval in the fault-free case. The v1.x configuration reference says it is not required for liveness and that `"0s"` starts the next height as soon as +2/3 precommits are gathered [19]. The `main` branch specification lists a `next_block_delay` field in the `FinalizeBlock` response [14]; we did not find it in the v1.x methods document, so it should not be relied upon in v0.38.

#### A.2.5 Mempool, size limits, evidence

- **Mempool** [18], [20]: defaults `size = 5000`, `max_tx_bytes = 1048576` (1 MiB), `max_txs_bytes = 1 GB` in v0.38 (64 MB in v1.0 [12]), `cache_size = 10000`. There is "no ordering of transactions other than the order they've arrived"; replay protection is the application's responsibility; uncommitted transactions are rechecked after every block; transactions are flooded to peers.
- **Block size** [17]: `BlockParams.MaxBytes` defaults to 21 MB with a hard ceiling of 100 MB, and the spec recommends lowering the default when large blocks are not needed.
- **Evidence** [21]: `DuplicateVoteEvidence` (two votes by the same validator for the same height, round and type with different block IDs) and `LightClientAttackEvidence`. Verified evidence is gossiped, prioritised in blocks, bounded by `MaxAgeNumBlocks`/`MaxAgeDuration`, and delivered to the application in the `misbehavior` field of `FinalizeBlock`.

*Implication (our analysis).* A TLSNotary-style receipt carrying a full transcript may approach the 1 MiB default `max_tx_bytes`; receipt size must be measured, and `max_tx_bytes` raised consistently on all nodes or the transcript committed by hash. Recheck also means `CheckTx` runs repeatedly on pending transactions, so an expensive verification should be cached by transaction hash.

### A.3 Non-determinism, external data, and execute-order-validate

**Why validators cannot call the LLM inside the state machine.** An LLM call is a network call to an external source, which is explicitly listed among sources of non-determinism [16]; two validators would generally obtain different review texts and possibly different verdicts, producing different `app_hash` values and halting consensus. This is an instance of the oracle problem: the state machine needs a fact about the outside world, but replicas cannot independently observe it identically.

**Vote extensions.** The sanctioned channel in CometBFT is `ExtendVote`, which "allows applications to include non-deterministic data, opaque to the consensus algorithm, to precommit messages" [16]; `ExtendVote` is not required to be deterministic but `VerifyVoteExtension` is [17]. Extensions are enabled through the `VoteExtensionsEnableHeight` consensus parameter and become available to the proposer of the next height [17]. They are not free: in the CometBFT v0.38 QA experiments, 2 kB extensions moved mean latency "from below 5s to nearly 10s", and with 32 kB extensions "round 5 [was] reached frequently" [22]. *(Our analysis)* Vote extensions would correspond to the design DOSR rejects (every validator queries the LLM and the results are aggregated), costing n LLM calls per pull request. DOSR instead treats the review as a client-supplied, externally attested artefact.

**Hyperledger Fabric's execute-order-validate.** Androulaki et al. criticise order-execute architectures because operations executed after consensus "must be deterministic, or the distributed ledger 'forks'", noting that even without obvious non-determinism "a map iterator is not deterministic in Go" [23]. In Fabric:

1. *Execute.* Endorsers simulate the proposal and produce a writeset and "a readset, representing the version dependencies of the proposal simulation (i.e., all keys read during simulation along with their version numbers)". The client collects endorsements until the endorsement policy is satisfied.
2. *Order.* The ordering service "does not maintain any state of the blockchain, and neither validates nor executes transactions".
3. *Validate.* Peers evaluate the endorsement policy (VSCC), then perform a sequential read-write conflict check that "compares the versions of the keys in the readset field to those in the current state of the ledger ... and ensures they are still the same". Invalid transactions remain in the ledger, marked invalid.

The payoff is that a non-deterministic chaincode "can only endanger the liveness of its own operations", whereas in order-execute "non-deterministic operations lead to inconsistencies in the state of the peers" [23].

**Mapping to DOSR** *(our analysis)*:

| Fabric | DOSR |
|---|---|
| Endorser simulates chaincode | LLM provider reviews diff (H → C) under a policy |
| Endorser signature over (readset, writeset) | Notary-attested receipt R bound to (H, C, policy) |
| Readset version of a key | `expected_head = H` |
| Writeset | new head C |
| Endorsement policy (e.g. k-of-n organisations) | accepted providers/models/notaries; optional k-of-n providers |
| Ordering service | CometBFT consensus |
| VSCC | receipt verification |
| MVCC read-write check | `current_head == expected_head` |
| Invalid transaction recorded but not applied | failed `AcceptCommit` with a non-zero result code |

The analogy is close but not exact, in three ways. (i) Fabric endorsers are members of the system, whose keys are in the channel configuration; DOSR's "endorser" is an external API that signs nothing, so authenticity must come from a third-party attestation of a TLS session, adding a notary trust assumption that Fabric lacks. (ii) Fabric's default policy requires several endorsers to produce *identical* read/write sets, which filters non-determinism by agreement; LLM outputs will not be byte-identical, so a k-of-n DOSR policy can only require agreement on a structured verdict. (iii) Fabric's orderer is agnostic to content, while a CometBFT application validates in the same process that orders, so DOSR can drop invalid receipts in `CheckTx` before they consume block space. As in Fabric, two pull requests reviewed against the same head conflict: the first committed wins and the second fails the version check and needs a fresh review against the new head. This abort cost is paid in LLM fees and should be measured in our evaluation.

### A.4 Published performance baselines

| Source | Setup | Result |
|---|---|---|
| Cason et al., SRDS 2021 [24] | Tendermint 0.33.8, default configuration, validators spread over 16 AWS regions, 1 kB transactions, closed-loop clients | Mean block latency 2.14 s (N=16), 2.20 s (32), 2.38 s (64), 2.53 s (128); mean transaction latency 2.72 / 2.83 / 3.07 / 3.45 s; throughput 535 / 520 / 477 / 438 tps |
| same [24] | 128 validators | block latency "include[s] an artificial delay of 1s, the timeout commit"; the remaining ≈1.5 s covers the three communication steps |
| Alqahtani & Demirbas [5] | Re-implementation in PaxiBFT (Go), AWS m5a.large, 4–20 nodes, LAN and 4-region WAN | at N=16 Tendermint "degrades to 150 tx/s in LAN" and "around 90 tx/s in WAN" |
| CometBFT QA, v0.34 baseline [25] | 200-node testnet | 19.5 blocks/min; saturation near 200 tx/s over 2 connections |
| CometBFT QA, v0.38 [22] | 200-node testnet | about 20 blocks/min; saturation at 400 tx/s on 1 connection |
| Fabric [23] | Fabric v1.1 Fabcoin benchmark | >3500 tps, average latency below 550 ms |

Two cautions. The numbers in [5] come from a re-implementation in a common framework, not from the production Tendermint code, so they are useful for relative comparison only. And [24] shows that an 8× increase in validators (16 → 128) raised block latency by only 18%, because the fixed `timeout_commit` dominates.

*Expected order of magnitude for DOSR (our analysis).* With default timeouts, consensus should add roughly 2–3.5 s from submission to finality in a WAN deployment with tens of validators, and about 1 s plus small network delay on a LAN. An LLM review and an MPC-TLS notarisation are likely to take longer than this, so we expect consensus to be a minor term in end-to-end approval latency; our evaluation should report the components separately to confirm or refute that expectation.

### A.5 Testing methodology

| Technique | What it offers | Source | Feasible for the project? |
|---|---|---|---|
| **Jepsen** | Black-box fault injection plus history checking. The Tendermint 0.10.2 analysis (2017) used a CAS register checked with Knossos and a set workload, under clock skew, crashes, partitions, WAL truncation, membership changes and byzantine validators with duplicated keys. It found three durability issues and otherwise that "transactions appear linearizable" below the 1/3 byzantine threshold. | [26] | Partly: a simplified harness with partitions and crash-restart |
| **Linearizability checkers** | Knossos (Clojure; WGL and linear search; may return `:unknown`). Porcupine (Go) takes "a sequential specification as executable Go code, along with a concurrent history" and reports being 1,000×–10,000× faster than Knossos on Jepsen test data. | [27], [28] | Yes: Porcupine is in Go, and a branch head is a compare-and-set register |
| **Deterministic simulation** | FoundationDB runs "a deterministic simulation of an entire FoundationDB cluster within a single-threaded process". TigerBeetle's VOPR reproduces any failure from "a seed number and the Git commit", injecting packet drops, reordering, partitions and disk corruption. Antithesis provides a deterministic environment in which bugs are "perfectly reproducible". | [29], [30], [31] | Application layer only: drive the ABCI app directly with seeded random transaction sequences |
| **Model checking (TLA+)** | The CometBFT repository contains TLA+ specifications of a simplified Tendermint tuned for fork accountability, checked with Apalache on instances of 4 to 5 validators (inductive invariant, agreement with fewer than one third faulty, agreement-or-accountability). Apalache translates TLA+ to SMT and supports bounded model checking and inductiveness checking. | [32], [33] | Yes for a small model of the DOSR state machine, not of consensus |
| **Twins** | Emulates Byzantine behaviour by running two copies of a node with the same identity, covering leader equivocation, double voting and lost internal state; 44M scenarios per day in DiemBFT. | [34] | No: it targets the consensus implementation, which we do not write |

*Proposed plan (our analysis).* (1) A small TLA+ model of the application with invariants "the head changes only via an `AcceptCommit` whose `expected_head` equalled the previous head" and "no receipt is applied twice". (2) Seeded property-based tests of the ABCI application asserting identical `app_hash` across replicas for identical block sequences. (3) A multi-node testnet with injected partitions and crash-restarts, recording client histories of `AcceptCommit` and head reads and checking them with Porcupine against a CAS-register model. (4) A negative test that deliberately introduces non-determinism in one replica to demonstrate the failure mode described in [16]. We rely on CometBFT's own testing for consensus-level Byzantine behaviour.

---

## Part B — LLM-Based Code Review and Quorum Reliability

### B.1 Tools

| Tool | Verified facts | Source |
|---|---|---|
| PR-Agent | MIT licence; described in its README as "a community-maintained legacy project of Qodo", donated to the community; tools `/describe`, `/review`, `/improve`, `/ask`; each tool "uses a single LLM call (~30 seconds, low cost)"; GitHub, GitLab, Bitbucket, Azure DevOps, Gitea; many model providers via LiteLLM; a PR compression strategy for large diffs | [35] |
| Mira | Apache-2.0, self-hosted, bring-your-own-key; GitHub, GitLab, Forgejo; confidence thresholds, deduplication and per-PR comment caps; full-repository indexing. The README self-reports an F1 of 44 and a median of about 77 s per PR on a public benchmark (vendor claim, not independently verified) | [36] |
| CodeRabbit | Commercial; "automated, context-aware code reviews"; GitHub, GitLab, Azure DevOps, Bitbucket; IDE and CLI | [37] |
| GitHub Copilot code review | "By default, Copilot's reviews do not count toward required approvals"; the documentation warns that "Copilot is not guaranteed to spot all problems ... Sometimes it will make mistakes ... Supplement Copilot's feedback with a human review" | [38] |

The single-call design of PR-Agent is what makes a one-session receipt plausible: a whole review fits in one HTTPS request/response pair that can be notarised. Copilot's default, in which an AI review does not count as an approval, is the opposite of DOSR's design, where the certified verdict *is* the merge authorisation.

### B.2 Empirical evidence

- **Aðalsteinsson et al.** (arXiv 2505.16339; listed in the ESEM 2025 industry track) studied LLM-assisted review at WirelessCar Sweden AB with two prototypes, AI-led and on-demand, built on retrieval-augmented generation. AI-led reviews were "overall more preferred", conditional on familiarity with the code base and severity of the pull request. The samples were small (7 participants in the field study, 10 in the experiment). Participants raised false positives and trust as concerns, and the authors conclude that LLMs should augment rather than replace human reviewers [39].
- **Sun et al.** (arXiv 2508.18771) analysed 16 AI code-review GitHub Actions, 22,326 comments and 178 repositories. Rates of comments addressed by a code change were 0.9%–4.2% for file-level tools and 6.5%–19.2% for hunk-level tools, against about 60% for valid human review comments. Concise, manually triggered comments containing code snippets were more likely to lead to changes [40].
- **Jin and Chen** (arXiv 2603.00539) report that LLMs "frequently misclassify correct code implementation as non-compliant or defective", and that prompts requiring explanations and proposed corrections lead to *higher* misjudgment rates [41].

**Maintainer burden.**

- Daniel Stenberg announced on 2026-01-26 that curl's bug bounty would end on 2026-01-31. The programme ran from April 2019, confirmed 87 vulnerabilities and paid over US$100,000. The confirmation rate fell from about 15% before 2025 to below 5% in 2025, which he attributes to "an explosion in AI slop reports" [42]. The Register quotes his stated aim to "remove the incentive for people to submit crap and non-well researched reports to us. AI generated or not" [43].
- In early 2026 GitHub product manager Camilla Moraes opened a community discussion acknowledging that maintainers are "dedicating substantial time to reviewing contributions that do not meet project quality standards". Maintainers quoted in the coverage include one claiming that only "1 out of 10 PRs created with AI is legitimate" (an individual's estimate, not a measurement) and another stating that the "review trust model is broken" [44].
- The Godot Engine's policy of 2026-06-30 observes that "the amount of effort required to make a PR has gone down ... while the amount of work to review PRs and the amount of people available to review has stayed the same", prohibits autonomous agents, and requires disclosure of AI assistance [45].

*Takeaway for DOSR (our analysis).* The evidence supports the motivation (review capacity is the bottleneck, and shifting review cost to the contributor is a reasonable response) but not a claim that one LLM review is a sufficient quality gate. The low addressed rates in [40] and the overcorrection in [41] indicate that both false approvals and false rejections will occur. A contributor who pays per review can also resubmit until approval is obtained, so the policy should bound or record retries.

### B.3 Verification of papers from the brainstorming notes

All seven could be retrieved. Two corrections to our notes: the first paper's identifier is arXiv 2511.10400, and AgentRoom is on arXiv as 2608.23740 (the OpenReview page itself could not be loaded).

| # | Title | Authors | Identifier, date | Summary |
|---|---|---|---|---|
| 1 | Rethinking the Reliability of Multi-agent System: A Perspective from Byzantine Fault Tolerance | Lifan Zheng, Jiawei Chen, Qinghong Yin, Jingyuan Zhang, Xinyi Zeng, Yu Tian | arXiv 2511.10400; 13 Nov 2025 (v2 16 Dec 2025) | Quantifies reliability of LLM-based agents under Byzantine faults and finds they show "stronger skepticism" toward erroneous messages than traditional agents. Proposes CP-WBFT, a confidence-probe-based weighted consensus mechanism, and reports results at an 85.7% fault rate. [46] |
| 2 | The Six Sigma Agent: Achieving Enterprise-Grade Reliability in LLM Systems Through Consensus-Driven Decomposed Execution | Khush Patel, Siva Surendira, Jithin George, Shreyas Kapale | arXiv 2601.22290; 29 Jan 2026 | Decomposes tasks into atomic actions, executes each n times across diverse LLMs and takes a clustered majority vote. Claims system error O(p^⌈n/2⌉) *assuming independent outputs*: 5% per-action error falls to 0.11% with 5 agents. [47] |
| 3 | Hallucination as Context Drift: Synchronization Protocols for Multi-Agent LLM Systems | Carson Rodrigues | arXiv 2606.21666; 19 Jun 2026 | Attributes a class of multi-agent hallucinations to divergent knowledge state and proposes a Context Divergence Score and a Shared State Verification Protocol. Naive full-broadcast synchronisation *increased* hallucination rate (0.658 vs 0.492) in the travel domain, a contamination effect that did not replicate in the software domain. [48] |
| 4 | Byzantine Fault-Tolerant Multi-Agent System for Healthcare: A Gossip Protocol Approach to Secure Medical Message Propagation | Nihir Chadderwala | arXiv 2512.17913; 27 Nov 2025 | Combines gossip dissemination with a BFT protocol (n = 3f+1, 2f+1 votes) and signature validation for LLM agents in healthcare. Addresses message integrity, not semantic correctness of agent output. [49] |
| 5 | The Honest Quorum Problem: Epistemic Byzantine Fault Tolerance for Agentic Infrastructure | Jun He, Deying Yu | arXiv 2607.16109; 17 Jul 2026 | Defines an *epistemic fault*: a protocol-compliant validator that endorses a semantically invalid transition. Adds two budgets to the Byzantine bound f, with conditions q > f + e_δ (semantic validity), 2q − N > f (agreement) and q ≤ N − f − u_ε (liveness). Adding nominally distinct agents helps only if it measurably reduces correlated invalid endorsements. [50] |
| 6 | The Illusion of Independent Quorums: Epistemic Fault Domains and Correlated Cognitive Failures in Agentic Quorums | Jun He, Deying Yu | arXiv 2609.02925; 24 Aug 2026 | Introduces Epistemic Fault Domains and shows that arbitrarily large quorums can collapse to a single point of failure when reviewers share upstream sources. Proposes a Dependency-Aware Quorum Controller, evaluated analytically and in simulation. [51] |
| 7 | AgentRoom: Concurrent Multi-Agent Coding in a CRDT-Backed Shared Workspace | Seonglae Cho, Donghyun Lee | arXiv 2608.23740; 24 Aug 2026 | A collaborative editing protocol for concurrent coding agents exposing claim, status and broadcast as MCP tools over a CRDT-merged filesystem. Concludes that "coordination, not parallelism or CRDT-merge, bears the load". [52] |

These are recent preprints; apart from search-snippet indications (Section C) we did not confirm peer review, and their quantitative claims are the authors' own.

### B.4 Relation to DOSR's security boundary

*(Our analysis, drawing on [47], [50], [51].)*

**What consensus guarantees.** With fewer than one third Byzantine voting power, all correct validators agree on one sequence of `AcceptCommit` transactions, each applied only if its receipt verified and its `expected_head` matched. There are no conflicting histories for a branch.

**What it does not guarantee.** That the approved code is good. A valid receipt proves that a specific provider returned an approving response for (H, C, policy); it says nothing about whether the response was correct. This is exactly the epistemic fault of [50], and it is outside the BFT fault model: every validator is honest and the state machine is deterministic, yet an invalid transition is certified. In DOSR the "quorum" that judges semantics has size one by design.

**Optional k-of-n multi-provider certificates.** The Six Sigma bound [47] explains the appeal: under independence, majority voting reduces error exponentially. But [50] and [51] argue that independence is the wrong default, since models share training data, and in DOSR every reviewer necessarily sees the same diff and the same prompt policy. A prompt injection embedded in the diff is a common-mode input that could defeat all k reviewers at once. We should therefore present k-of-n as a policy knob that reduces *uncorrelated* errors at k times the LLM cost, not as a guarantee. In the terms of [50], the policy threshold must exceed the number of coherent invalid endorsements, a quantity that has to be estimated empirically.

**Layering.** The cleanest statement of DOSR's boundary is a two-level argument. The ordering layer tolerates f < n/3 Byzantine validators and gives agreement and finality. The review layer gives authenticity of a review verdict under the notary and provider trust assumptions, and no semantic guarantee. Branch protection rules, human maintainers' veto, and CI results bound into the policy remain necessary complements.

---

## C. Could not verify

1. **Venue of Sun et al.** as *IEEE Transactions on Software Engineering*. The arXiv abstract page and the HTML of v2 do not state a venue; only a search-result snippet indicated TSE early access. Cite as an arXiv preprint until confirmed against IEEE Xplore.
2. **ICML 2026 workshop status of AgentRoom.** A search result pointed to an icml.cc page, but we did not fetch it, and the OpenReview page (id `0aGLZqKJjt`) returned only a browser-verification page. The arXiv record was verified.
3. **AAAI publication of paper 1.** A search result listed an `ojs.aaai.org` entry with the same title; not fetched.
4. **ESEM 2025 venue of Aðalsteinsson et al.** was seen in search results (a conf.researchr.org industry-track listing and a Chalmers research record) but those pages were not fetched; the arXiv page itself lists no venue.
5. **Status of the CometBFT v1.x line.** We verified that there has been no v1.x release since v1.0.1 (2025-02-03) and that the README lists only v0.38.x as supported, but found no explicit statement that v1.x is discontinued.
6. **`next_block_delay`** appears in the `main` specification but was not found in the v1.x methods document; we did not determine which release introduced it.
7. **Apalache model-checking results** (run times, exact outcomes per configuration) for the Tendermint accountability specifications: the synopsis refers to a separate results report that we did not fetch.
8. **Mira's benchmark figures** are self-reported in its README; the benchmark itself was not examined.
9. **"Only 1 in 10 AI PRs is legitimate"** is one maintainer's statement quoted in press coverage, not a measured statistic. The GitHub community discussion (#185387) was read only via The Register's report.
10. **No published benchmark was found for CometBFT v0.38 with small validator sets (4–16) over a WAN.** The closest data are Tendermint 0.33.8 [24] and the 200-node QA runs [22], [25].
11. Several source documents were read through an automated page-to-text summariser. Direct quotations from the ABCI specification, DLS, PBFT and Cason et al. were checked against extracted text; quotations from other web pages should be re-checked against the originals before appearing in the final report.

---

## References

All URLs accessed 2026-09-29.

1. C. Dwork, N. Lynch, L. Stockmeyer. "Consensus in the Presence of Partial Synchrony." *Journal of the ACM* 35(2), 1988. https://groups.csail.mit.edu/tds/papers/Lynch/jacm88.pdf
2. M. Castro, B. Liskov. "Practical Byzantine Fault Tolerance." OSDI 1999. https://css.csail.mit.edu/6.824/2014/papers/castro-practicalbft.pdf ; https://www.usenix.org/legacy/events/osdi99/full_papers/castro/castro_html/castro.html
3. E. Buchman, J. Kwon, Z. Milosevic. "The latest gossip on BFT consensus." arXiv:1807.04938, 2018 (v3 2019). https://arxiv.org/abs/1807.04938
4. M. Yin, D. Malkhi, M. K. Reiter, G. Golan Gueta, I. Abraham. "HotStuff: BFT Consensus in the Lens of Blockchain." arXiv:1803.05069 (v6 2019). https://arxiv.org/abs/1803.05069
5. S. Alqahtani, M. Demirbas. "Bottlenecks in Blockchain Consensus Protocols." arXiv:2103.04234, 2021. https://arxiv.org/abs/2103.04234
6. G. Danezis, E. Kokoris Kogias, A. Sonnino, A. Spiegelman. "Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus." arXiv:2105.11827. https://arxiv.org/abs/2105.11827
7. A. Spiegelman, N. Giridharan, A. Sonnino, L. Kokoris-Kogias. "Bullshark: DAG BFT Protocols Made Practical." arXiv:2201.05677. https://arxiv.org/abs/2201.05677
8. CometBFT releases (GitHub API). https://api.github.com/repos/cometbft/cometbft/releases ; https://github.com/cometbft/cometbft/releases
9. CometBFT README. https://github.com/cometbft/cometbft
10. CometBFT v0.40.0 CHANGELOG. https://raw.githubusercontent.com/cometbft/cometbft/v0.40.0/CHANGELOG.md
11. CometBFT UPGRADING.md (main). https://raw.githubusercontent.com/cometbft/cometbft/main/UPGRADING.md
12. CometBFT, "Upgrading from v0.38 to v1.0." https://raw.githubusercontent.com/cometbft/cometbft/v1.x/docs/guides/upgrades/v0.38-to-v1.0.md
13. CometBFT UPGRADING.md (v1.x). https://raw.githubusercontent.com/cometbft/cometbft/v1.x/UPGRADING.md
14. CometBFT spec, ABCI++ methods. https://raw.githubusercontent.com/cometbft/cometbft/main/spec/abci/abci%2B%2B_methods.md
15. CometBFT spec, expected behaviour. https://raw.githubusercontent.com/cometbft/cometbft/main/spec/abci/abci%2B%2B_comet_expected_behavior.md
16. CometBFT spec, ABCI basic concepts. https://raw.githubusercontent.com/cometbft/cometbft/main/spec/abci/abci%2B%2B_basic_concepts.md
17. CometBFT spec, application requirements. https://raw.githubusercontent.com/cometbft/cometbft/main/spec/abci/abci%2B%2B_app_requirements.md
18. CometBFT v0.38 configuration. https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/docs/core/configuration.md
19. CometBFT v1.x config.toml reference. https://raw.githubusercontent.com/cometbft/cometbft/v1.x/docs/references/config/config.toml.md
20. CometBFT v0.38 mempool. https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/docs/core/mempool.md
21. CometBFT spec, evidence. https://raw.githubusercontent.com/cometbft/cometbft/main/spec/consensus/evidence.md
22. CometBFT QA results v0.38. https://raw.githubusercontent.com/cometbft/cometbft/main/docs/references/qa/CometBFT-QA-38.md
23. E. Androulaki et al. "Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains." EuroSys 2018. arXiv:1801.10228. https://arxiv.org/abs/1801.10228 (full text read via https://ar5iv.labs.arxiv.org/html/1801.10228)
24. D. Cason, E. Fynn, N. Milosevic, Z. Milosevic, E. Buchman, F. Pedone. "The design, architecture and performance of the Tendermint Blockchain Network." SRDS 2021. https://www.inf.usi.ch/pedone/Paper/2021/srds2021a.pdf
25. Tendermint Core QA results v0.34. https://docs.cosmos.network/cometbft/next/docs/qa/TMCore-QA-34.md
26. K. Kingsbury. "Jepsen: Tendermint 0.10.2." 2017-09-05. https://jepsen.io/analyses/tendermint-0-10-2
27. Knossos. https://github.com/jepsen-io/knossos
28. Porcupine. https://github.com/anishathalye/porcupine
29. FoundationDB, "Simulation and Testing." https://apple.github.io/foundationdb/testing.html
30. TigerBeetle, "VOPR." https://raw.githubusercontent.com/tigerbeetle/tigerbeetle/main/docs/internals/vopr.md
31. Antithesis, "How Antithesis works." https://antithesis.com/docs/introduction/how_antithesis_works/
32. CometBFT, accountability TLA+ specifications. https://github.com/cometbft/cometbft/tree/main/spec/light-client/accountability ; https://raw.githubusercontent.com/cometbft/cometbft/main/spec/light-client/accountability/Synopsis.md
33. Apalache. https://apalache-mc.org/
34. S. Bano, A. Sonnino, A. Chursin, D. Perelman, Z. Li, A. Ching, D. Malkhi. "Twins: BFT Systems Made Robust." arXiv:2004.10617. https://arxiv.org/abs/2004.10617
35. PR-Agent. https://github.com/qodo-ai/pr-agent
36. Mira. https://github.com/miracodeai/mira
37. CodeRabbit documentation. https://docs.coderabbit.ai/
38. GitHub Docs, Copilot code review. https://docs.github.com/en/copilot/concepts/agents/code-review
39. F. S. Aðalsteinsson, B. B. Magnússon, M. Milicevic, A. N. Davidsson, C.-H. Cheng. "Rethinking Code Review Workflows with LLM Assistance: An Empirical Study." arXiv:2505.16339, 2025. https://arxiv.org/abs/2505.16339
40. K. Sun, H. Kuang, S. Baltes, X. Zhou, H. Zhang, X. Ma, G. Rong, D. Shao, C. Treude. "Does AI Code Review Lead to Code Changes? A Case Study of GitHub Actions." arXiv:2508.18771 (v2 25 Apr 2026). https://arxiv.org/abs/2508.18771
41. H. Jin, H. Chen. "Are LLMs Reliable Code Reviewers? Systematic Overcorrection in Requirement Conformance Judgement." arXiv:2603.00539, 2026. https://arxiv.org/abs/2603.00539
42. D. Stenberg. "The end of the curl bug-bounty." 2026-01-26. https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/
43. The Register. "Curl shutters bug bounty program to remove incentive for submitting AI slop." 2026-01-21. https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/
44. The Register. "GitHub ponders kill switch for pull requests to stop AI slop." 2026-02-03. https://www.theregister.com/2026/02/03/github_kill_switch_pull_requests_ai/
45. Godot Engine. "Contribution policy 2026." 2026-06-30. https://godotengine.org/article/contribution-policy-2026/
46. L. Zheng et al. arXiv:2511.10400. https://arxiv.org/abs/2511.10400
47. K. Patel et al. arXiv:2601.22290. https://arxiv.org/abs/2601.22290
48. C. Rodrigues. arXiv:2606.21666. https://arxiv.org/abs/2606.21666
49. N. Chadderwala. arXiv:2512.17913. https://arxiv.org/abs/2512.17913
50. J. He, D. Yu. arXiv:2607.16109. https://arxiv.org/abs/2607.16109
51. J. He, D. Yu. arXiv:2609.02925. https://arxiv.org/abs/2609.02925
52. S. Cho, D. Lee. arXiv:2608.23740. https://arxiv.org/abs/2608.23740
