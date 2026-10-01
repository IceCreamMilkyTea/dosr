# 1. Decentralized Source-Code Management and Repository-State Consensus

*Literature review section for DOSR (Decentralized Open-Source Review), Duke ECE/CS 512. All sources accessed 2026-09-29.*

**Evidence convention.** Every factual claim below is tied to a source fetched during this review, cited as `[n]`. Claims marked **(code)** were read directly from source files; all others come from documentation, blog posts, or paper abstracts. Anything I could not confirm from a fetched source is listed under "Could not verify" rather than asserted.

## 1.1 Problem framing

A Git repository is a Merkle DAG of content-addressed objects plus a small mutable map from ref names to object IDs. The objects are self-verifying; the refs are not. "Decentralizing Git" is therefore mostly the problem of agreeing on, and authorizing updates to, the ref map. The systems below differ on three axes: (i) who is allowed to move a canonical ref, (ii) what mechanism makes all observers agree on the result, and (iii) where object bytes live and who guarantees they can be retrieved. DOSR's position is: (i) anyone holding a valid LLM-review receipt for exactly `(H, C, policy)`, (ii) BFT state-machine replication with a compare-and-swap on `expected_head`, (iii) off-chain content-addressed storage.

## 1.2 Radicle (Heartwood)

**Architecture.** Each repository has an identity document, a JSON document "stored under the `refs/rad/id` reference in Git", holding the delegates' DIDs and "the threshold of delegate signatures required to authorize changes" [1]. The Repository ID is derived from the *initial* identity document via Git's `hash-object` (SHA-1), so the document can evolve while the RID stays fixed [1]. Every node signs the full set of its refs on each change and stores the signature under `refs/rad/sigrefs` [1]. Nodes store per-peer copies of the repository using Git namespaces and communicate via two protocols: a gossip protocol and the Git v2 smart transfer protocol [3]. Gossip has three message types (node, inventory, and reference announcements), each signed and timestamped; replication is an ordinary Git fetch from seeds [1]. Social artifacts (issues, patches, identity changes) are Collaborative Objects (COBs) stored in Git; their commit DAGs are unioned and replayed in topological order, which the documentation describes as a form of CRDT [1].

**Canonical state.** There is no global ordering service. The canonical head is computed *locally* by each node: "if a threshold of two out of three delegates is set ... and two delegates have pushed the same commit to their `master` branches, that commit is recognized as the authoritative, canonical state" [1][2]. Merging a patch is a delegate running `git push rad main`; the patch COB is marked merged when the node detects it [2]. Radicle 1.3.0 generalized this to canonical reference rules (`xyz.radicle.crefs`), each with an allow-list of DIDs and a threshold; the default-branch rule is synthesized from the identity document's `delegates` and `threshold` [4].

**Conflicting delegates.** The quorum code treats divergence as an error rather than resolving it. **(code)** `QuorumError` includes `NoCandidates` ("no object with at least {threshold} vote(s) found (threshold not met)"), `DivergingCommits` ("found diverging commits {longest} and {head}, with base commit {base} and threshold {threshold}"), and `DivergingTags` [5]. The commit quorum uses merge-base computations between candidate commits [5]. So when delegates fork, the canonical ref cannot be determined until humans reconcile.

**Trust and fault model.** Self-certifying repositories with a TUF-inspired verification model [1]; trust roots in the delegate key set. By default a node tracks only delegates plus explicitly followed peers [2]. There is no Byzantine quorum intersection argument: two nodes that have fetched different subsets of delegates' sigrefs can compute different canonical heads. The guarantee is eventual convergence conditional on delegates converging.

**Limitations.** LWN's 2024 review noted immature CI support and "only rudimentary support for code review" [3].

**DOSR differs** in that authority is not a fixed key set. Radicle answers "which commit do the maintainers endorse?"; DOSR answers "which commit is the next totally ordered, policy-satisfying successor of `H`?". Radicle is available under partition and cheap; DOSR has a single agreed head at each height and cannot produce a `DivergingCommits` state, at the price of requiring a validator set.

## 1.3 Gitopia

**Architecture.** Gitopia describes itself as a decentralized code collaboration platform with a native token (LORE), DAOs, and a `git-remote-gitopia` helper using a `gitopia://` transport [6]. The README states it uses "permanent storage through Filecoin, Arweave, and IPFS" [7]. The `gitopiad` daemon is a Go application [7].

**On-chain state.** The protobuf definitions show that repositories, branches, tags, pull requests, issues, comments, DAOs, bounties, releases, and users are all chain state [8]. **(code)** A `Branch` record stores `repositoryId`, `name`, `sha`, `allowForcePush`, and timestamps [9]; a repository carries collaborators with permission levels READ/TRIAGE/WRITE/MAINTAIN/ADMIN and backup records typed IPFS or ARWEAVE [10]. Thus the chain stores the ref map and the entire forge data model, not just a head hash.

**Off-chain storage.** The Gitopia Storage Provider is "a self-hosted server that provides storage for Gitopia repositories, LFS objects, and attachments" integrating IPFS and IPFS Cluster; providers stake LORE and "start receiving challenges after registration" [11]. **(code)** The storage module contains challenge, liveness, stake, jailing and clawback handlers, and a per-repository packfile record keyed by CID [12].

**Authorizing merges.** **(code)** `InvokeMergePullRequest` requires that the caller has ADMIN permission on the base repository, rejects the call if the owning DAO sets `RequirePullRequestProposal`, and checks `baseBranch.Sha != msg.BaseCommitSha` returning "SHA mismatch" [13]. It then only emits an event naming a storage `provider`; it does not change branch state [13]. A separate `InvokeDaoMergePullRequest` exists for the DAO path [8][13]. **(code)** `MergePullRequest` later sets `baseBranch.Sha = msg.MergeCommitSha` after checking that the on-chain packfile CID equals `msg.PackfileCid`, commented in the source as "Optimistic concurrency control" [13]. **(code)** Direct pushes (`SetBranch`, `MultiSetBranch`) check `PushBranchPermission` and a packfile-CID match, then overwrite the branch SHA [14]. DAO creation takes `cosmos.group.v1.MemberRequest` members, a voting period and a percentage [8].

**Consistency.** Gitopia therefore already uses optimistic concurrency, in two forms: a head-SHA check at merge invocation and a packfile-CID check at completion. The merge itself is computed off-chain by a storage provider, and the chain records the resulting SHA.

**DOSR differs** in three ways. (1) Authorization is by role or DAO vote in Gitopia, by verifiable review receipt in DOSR. (2) In Gitopia the merge commit SHA is reported by a provider; in DOSR the candidate `C` is fixed before review and bound into the receipt, so validators never rely on a third party's computation. (3) DOSR's chain state is deliberately minimal (head, history, policy hash, receipt hash).

## 1.4 GOSH

**Architecture.** GOSH puts Git itself on-chain. The documented contracts include `Repository`, `Commit`, `Tree`, `Snapshot`, `Diff`, tag contracts, `Task`, `GoshDao`, `GOSHWallet`, profile contracts, and `SystemContract`/`VersionController` for versioning [15]. The GOSH 2.0 release notes describe a snapshot as the last version of a file stored as its own object, a DIFF instruction added to the VM so diffs are applied as a smart-contract instruction, and state that "ipfs is used for large binary objects only" [16]. Users interact through a Git remote helper with URLs of the form `gosh://SYSTEM_CONTRACT_ADDRESS/DAO_NAME/REPO_NAME` and keys in `~/.gosh/config.json` [17]. Current documentation says GOSH runs on the Acki Nacki protocol and advertises "gasless transactions" [18].

**Governance.** "Every repository on GOSH is managed as a Decentralized Autonomous Organization"; "Branches could be locked to require any changes to them to be voted on by DAO SMV" [19]. Soft Majority Voting: if everyone votes, 50% + 1 is required; if nobody votes against, 10% approving votes suffice; in between the required approval is linear in the opposing share [19]. One token is one vote, bounded by a member's Karma [19].

**Trust and cost.** Correctness rests on the underlying chain plus token-weighted voting. Because every commit, tree and file becomes contract state, on-chain footprint grows with repository size; the 2.0 notes describe parallelization work that reduced push times for large repositories "by several orders of magnitude" [16], which indicates that push latency was a first-order problem.

**DOSR differs** by taking the opposite storage stance (objects off-chain) and by replacing a voting period with a single paid review whose result is checked deterministically.

## 1.5 Academic blockchain VCS work

**Nizamuddin et al. (2019)** propose Ethereum smart contracts governing document version control among developers and approvers, with IPFS for storage; contracts were written in Solidity and tested in Remix [20]. It targets documents, not Git DAGs, and approval is by designated approvers.

**Hammad et al. (2023)** present BDA-SCV: IPFS storage plus a private chain where "the proof of authority (PoA) consensus algorithm will be used to approve the developer communicating modifications"; the authority "will only provide permission and will not be able to add, edit, or delete code files". The abstract states it is implemented on Hyperledger Fabric with a .NET web application [21]. This is a permissioned, crash/authority-trust model in which a human authority gates every change.

**Haque et al. (2025, PLoS One)** combine Ethereum, IPFS, client-side AES-256 encryption and 2-of-3 Shamir secret sharing with a middleware component; they report Sepolia push latency of 2.04-11.47 s for 1-20 MB repositories and about 206,886 gas per transaction, and their prototype lacks branching and merging [22]. They criticize Nizamuddin et al. for latency caused by synchronous Ethereum transactions [22].

**Mango** uses an Ethereum contract per repository with Git data on Swarm/IPFS; the README warns the protocol may change and that past repositories may become inaccessible [23].

**ForgeFed** is an ActivityPub extension for federating forges; implementations listed are Vervis (reference), Forgejo (in progress), and an unmaintained Pagure plugin [24]. Federation distributes *hosting* but each repository still has one authoritative server, so it is not a repository-state consensus mechanism.

None of these works addresses concurrent merges to one branch as an ordering problem, and none ties authorization to a verifiable review artifact.

## 1.6 gittuf, in-toto and Sigstore: verifiable policy without consensus

gittuf is the closest prior art to DOSR's policy layer. It is "a platform-agnostic Git security system", an OpenSSF incubating project, still in beta [25].

**Reference State Log (RSL).** The RSL is a hash chain stored at `refs/gittuf/reference-state-log`, one Git commit per entry, each entry recording `ref`, `targetID`, and `number`, signed with standard Git signing [26]. Annotation entries can mark earlier entries as skipped (revocation) [26].

**Policy.** Root-of-trust metadata declares root keys and a threshold; initial root keys are distributed out-of-band or TOFU. Rule files delegate namespaces to principals with thresholds, e.g. `(2, {Alice, Bob, Carol})` for `refs/heads/main` [26]. Multi-party approval uses signed in-toto attestations under `refs/gittuf/attestations`; a reference authorization carries `TargetRef`, `FromTargetID`, `ToTargetID`, and for branches `ToTargetID` pre-computes the resulting merge tree [26].

**Concurrency.** Because "each entry includes the ID of the previous entry, a local entry that does not incorporate the latest RSL entry on the remote is invalid". Writers fetch, verify, then "perform an atomic Git push" of the RSL and the modified refs; "if the push fails, it is likely because another actor pushed their changes first" and the workflow restarts [26]. This is optimistic concurrency arbitrated by whichever server accepts the push.

**Threat model.** gittuf addresses policy tampering, log tampering, and enforcement bypass. It explicitly does not prevent a privileged attacker from making the RSL branch: a "fork* attack where different actors are presented different versions of the RSL" is detected through out-of-band communication. Freeze attacks are out of scope, and there is no timestamp-role equivalent for freshness [26].

**Relation to DOSR.** The reference-authorization triple `(TargetRef, FromTargetID, ToTargetID)` is structurally the same as DOSR's `(branch, expected_head, candidate_commit)`. DOSR differs in two ways: the attestation signer is not a named human principal but a TLS-attested LLM session, and the log's linearity is enforced by BFT consensus rather than by a single forge, which removes exactly the fork* and freeze weaknesses gittuf leaves out of scope. DOSR inherits gittuf's unsolved root-of-trust bootstrapping problem in the form of the policy hash.

**in-toto** supplies the general pattern: a project owner signs a layout naming steps and authorized functionaries; functionaries sign link metadata; a verifier checks signatures and artifact rules [27]. A DOSR receipt is a link attestation for a "review" step whose functionary is a remote API. **Sigstore gitsign** provides keyless commit signing with Fulcio-issued short-lived certificates logged in Rekor [28]; it authenticates authors, not ref transitions.

## 1.7 Reference-transaction semantics in centralized forges

**Git primitives.** `git update-ref <ref> <new> <old>` updates only if the ref currently holds `<old>`; `--stdin` transactions are all-or-nothing [29]. `git push --force-with-lease=<ref>:<expect>` applies the same check remotely [30]. The `reference-transaction` hook sees `<old-value> <new-value> <ref-name>` lines and can abort in the `preparing`/`prepared` states [31]. DOSR's `AcceptCommit` is this compare-and-swap lifted into a replicated state machine.

**Not Rocket Science Rule / Bors.** The rule, attributed to Graydon Hoare, is to "automatically maintain a repository that never fails its tests" [32]. bors-ng pushes candidates to a `staging` branch, tests batches, bisects on failure, and fast-forwards main so that main "contains the exact contents that were just tested, bit-for-bit" [33]. bors-ng is deprecated in favour of GitHub's merge queue [33].

**GitHub merge queue.** Each queued PR is grouped "with the latest version of the `base_branch` as well as changes from pull requests ahead of it in the queue" on temporary `gh-readonly-queue/{base_branch}` branches; failures eject the PR [34].

**Gerrit.** Submit types define behaviour when the tip has moved. Under Fast Forward Only, a change is submittable only if the target can be fast-forwarded to it; if another change lands first, the change must be rebased [35]. Rebase/Cherry-Pick strategies instead create a *new* commit on the current head [35].

**Cost of stale approvals.** Minsky observes that serial verification costs at least `m * n` minutes for `n` requests of `m` minutes each, which motivated speculation and batching [32]. DOSR has the same structure with a monetary rather than CI cost: a receipt binds to exactly `(H, C, policy)`, so if another `AcceptCommit` moves the head from `H`, every outstanding receipt against `H` is void and its review fee is lost. DOSR's semantics equal Gerrit's Fast Forward Only, the strictest option. Forges avoid waste through a server-side queue that assigns a position *before* testing; DOSR has no such step, so under contention wasted reviews grow with the number of concurrent contributors. Candidate mitigations suggested by this literature are an on-chain reservation/lease on `H` before paying for review, or batching in the style of bors.

## 1.8 Data availability for off-chain objects

A hash on chain proves integrity, not retrievability. IPFS "guarantees that any content on the network is discoverable, it doesn't guarantee that any content is persistently available"; data persists only where pinned [36]. The surveyed systems respond differently: Radicle relies on voluntary seeding [1]; Gitopia adds staked providers subject to challenges [11][12]; GOSH avoids the problem for non-binary content by storing it on-chain [16]; Mango, Nizamuddin et al. and Hammad et al. delegate to IPFS/Swarm [20][21][23].

Two stronger designs exist. In Narwhal, validators acknowledge a block by signing its digest, round and creator; `2f+1` acknowledgements form a certificate of availability, implying at least `f+1` honest validators stored it, and consensus orders certificates instead of payloads [37]. In Celestia, block data is 2D Reed-Solomon encoded into a `2k x 2k` matrix and light nodes sample random shares, obtaining a high-probability availability guarantee [38]; the underlying paper replaces the honest-majority assumption with a minimum number of honest nodes that rebroadcast data [39].

For DOSR this matters because a validator cannot check that `C` descends from `H`, or that the receipt covers the diff `H..C`, without the objects. A Narwhal-style rule fits naturally: a validator prevotes for a block containing `AcceptCommit` only if it holds the objects reachable from `C` and not from `H`.

## 1.9 Comparison table

| System | Consensus / trust mechanism | Who authorizes merges | On-chain vs off-chain | Fault model | Review cost model |
|---|---|---|---|---|---|
| Radicle | None global; each node computes threshold quorum over delegates' signed refs [1][5] | Threshold of delegates pushing the same commit [1] | No chain; all data in Git, replicated by gossip + fetch [1] | Trust in delegate keys; divergence yields an error, not a fork choice [5] | Human review, unpriced |
| Gitopia | Cosmos-SDK application chain (SDK types visible in source) [8][13] | Repo ADMIN or DAO proposal [13] | Refs, PRs, issues, permissions on-chain; packfiles on IPFS via staked providers [9][11] | Chain consensus plus provider challenges [12] | Human review; storage fees **(code)** [12] |
| GOSH | Its own smart-contract chain (Acki Nacki protocol per current docs) [18] | DAO Soft Majority Vote on protected branches [19] | Commits, trees, snapshots, diffs on-chain; IPFS for large binaries [15][16] | Underlying chain plus token-weighted voting | Human voting; docs claim gasless [18] |
| Hammad et al. | Proof of Authority, private chain (Hyperledger Fabric) [21] | Designated authority [21] | File references on ledger; files on IPFS [21] | Permissioned, trusted authority | Human authority |
| Nizamuddin et al. | Ethereum smart contracts [20] | Designated approvers [20] | Contract state on-chain; documents on IPFS [20] | Ethereum's | Human approvers + gas |
| gittuf | None; signed hash-chained RSL arbitrated by the hosting server [26] | Threshold of policy-named principals [26] | No chain; metadata in Git refs [26] | Detects tampering; fork* and freeze not prevented [26] | Human review |
| GitHub merge queue / Bors / Gerrit | Single trusted server [33][34][35] | Reviewers + required CI checks | Centralized | Trusted operator | CI compute per attempt [32] |
| **DOSR** | BFT SMR (CometBFT) + deterministic receipt verification | Any contributor with a valid receipt for `(H, C, policy)` | Head, history, policy hash, receipt hash on-chain; Git objects off-chain | Byzantine validators; attestation notary and LLM provider trusted | One paid LLM review per attempt; lost if `H` goes stale |

## 1.10 Synthesis

Existing systems authorize ref updates by identity (delegates, admins, authorities) or by vote (DAO, SMV). None of the sources reviewed authorizes a merge by verifying evidence that a review occurred. gittuf comes closest in data model but has no ordering layer; Gitopia comes closest in ordering but authorizes by role. DOSR's combination appears novel relative to this literature, and the literature identifies its two main risks: review fees wasted under head contention (Section 1.7) and object availability at validation time (Section 1.8).

## Could not verify

1. **CometBFT's one-third fault threshold**: the fetched README and docs confirm BFT state-machine replication but the fetched text did not state the numeric bound [40]. The `< 1/3` bound is standard but uncited here.
2. **Graydon Hoare's original post** (graydon2.dreamwidth.org/1597.html) returned HTTP 403. The rule is quoted via Minsky's Jane Street article [32].
3. **Hammad et al. full text** (MDPI returned 403). Only the abstract and bibliographic record from Crossref were read [21]; no evaluation numbers are reported here.
4. **Nizamuddin et al. full text**: only the repository abstract page was read [20].
5. **Radicle identity-document threshold**: a search snippet suggested identity updates need a majority of delegates; this was not confirmed from a fetched page and is omitted above. The dedicated canonical-references blog post URL I tried returned 404.
6. **Gitopia whitepaper** (docs.gitopia.com/whitepaper returned 404), and therefore the historical sequence of storage backends. Whether Tendermint/CometBFT and delegated proof-of-stake are used was seen only in search snippets, not in a fetched primary page.
7. **Gitopia `MergePullRequest` caller authorization**: in the handler body I read, the preconditions are PR state and packfile-CID match; I did not find a signer permission check there and did not verify whether one is enforced elsewhere (e.g., message validation).
8. **GOSH costs**, the "Git Open Source Hodler" expansion, the Everscale lineage, and formal-verification claims: seen only in search snippets or not at all. The docs page for git on-chain architecture returned 404.
9. **Narwhal venue**: read from arXiv/ar5iv only; publication venue not confirmed.
10. **git-ssb and Pijul**: not researched from primary sources; omitted.
11. Several sources were read through an automated page summarizer; quotations were reproduced as returned and, except where marked **(code)**, not re-checked against raw HTML.

## References

All accessed 2026-09-29.

1. Radicle Protocol Guide. https://radicle.dev/guides/protocol
2. Radicle User Guide. https://radicle.dev/guides/user
3. L. Wirzenius, LWN article on Radicle, 29 March 2024. https://lwn.net/SubscriberLink/966869/4077c682c91ab5ab/
4. Radicle 1.3.0 release notes, 12 August 2025. https://radicle.dev/2025/08/12/radicle-1.3.0
5. Heartwood source, `canonical.rs`, `canonical/quorum.rs`, `canonical/error.rs`. https://raw.githubusercontent.com/radicle-dev/heartwood/master/crates/radicle/src/git/canonical.rs ; https://raw.githubusercontent.com/radicle-dev/heartwood/master/crates/radicle/src/git/canonical/error.rs
6. Gitopia documentation. https://docs.gitopia.com/
7. Gitopia repository README. https://github.com/gitopia/gitopia
8. Gitopia `tx.proto` and proto directory. https://raw.githubusercontent.com/gitopia/gitopia/master/proto/gitopia/gitopia/gitopia/tx.proto
9. Gitopia `branch.proto`. https://raw.githubusercontent.com/gitopia/gitopia/master/proto/gitopia/gitopia/gitopia/branch.proto
10. Gitopia `repository.proto`. https://raw.githubusercontent.com/gitopia/gitopia/master/proto/gitopia/gitopia/gitopia/repository.proto
11. Gitopia Storage Provider README. https://github.com/gitopia/gitopia-storage
12. Gitopia storage module `msg_server.go`. https://raw.githubusercontent.com/gitopia/gitopia/master/x/storage/keeper/msg_server.go
13. Gitopia `msg_server_pullRequest.go`. https://raw.githubusercontent.com/gitopia/gitopia/master/x/gitopia/keeper/msg_server_pullRequest.go
14. Gitopia `msg_server_branch.go`. https://raw.githubusercontent.com/gitopia/gitopia/master/x/gitopia/keeper/msg_server_branch.go
15. GOSH smart contracts. https://docs.gosh.sh/on-chain-architecture/gosh-smart-contracts/
16. GOSH 2.0 Release, 24 August 2022. https://blog.gosh.sh/p/gosh-20-release
17. GOSH Git Remote Helper. https://docs.gosh.sh/working-with-gosh/git-remote-helper/
18. GOSH documentation overview. https://docs.gosh.sh/
19. GOSH DAO and SMV. https://docs.gosh.sh/on-chain-architecture/organizations-gosh-dao-and-smv/
20. N. Nizamuddin, K. Salah, M. A. Azad, J. Arshad, M. H. Rehman, "Decentralized document version control using ethereum blockchain and IPFS," Computers & Electrical Engineering 76:183-197, 2019. DOI 10.1016/j.compeleceng.2019.03.014. https://repository.uwl.ac.uk/id/eprint/5926/
21. M. Hammad, J. Iqbal, C. A. ul Hassan, S. Hussain, S. S. Ullah, M. Uddin, U. A. Malik, M. Abdelhaq, R. Alsaqour, "Blockchain-Based Decentralized Architecture for Software Version Control," Applied Sciences 13(5):3066, 2023. DOI 10.3390/app13053066. Record and abstract: https://api.crossref.org/works/10.3390/app13053066
22. M. R. Haque, S. I. Munna, S. Ahmed, M. T. Islam, M. M. H. Onik, A. B. M. A. Rahman, "An integrated blockchain and IPFS-based solution for secure and efficient source code repository hosting using middleman approach," PLoS One, 2025. DOI 10.1371/journal.pone.0331131. https://pmc.ncbi.nlm.nih.gov/articles/PMC12407423/
23. Mango README. https://github.com/axic/mango
24. ForgeFed. https://forgefed.org/
25. gittuf website. https://gittuf.dev/
26. gittuf design document. https://raw.githubusercontent.com/gittuf/gittuf/main/docs/design-document.md
27. in-toto specification. https://github.com/in-toto/docs/blob/master/in-toto-spec.md
28. Sigstore gitsign. https://github.com/sigstore/gitsign
29. git-update-ref. https://git-scm.com/docs/git-update-ref
30. git-push. https://git-scm.com/docs/git-push
31. githooks. https://git-scm.com/docs/githooks
32. Y. Minsky, "Making 'never break the build' scale," Jane Street blog, 6 July 2014. https://blog.janestreet.com/making-never-break-the-build-scale/
33. bors-ng README. https://github.com/bors-ng/bors-ng
34. GitHub Docs, Managing a merge queue (Enterprise Server 3.17). https://docs.github.com/en/enterprise-server@3.17/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue
35. Gerrit, project configuration file format (submit types). https://gerrit-review.googlesource.com/Documentation/config-project-config.html
36. IPFS Docs, Persistence. https://docs.ipfs.tech/concepts/persistence/
37. G. Danezis, E. Kokoris Kogias, A. Sonnino, A. Spiegelman, "Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus," arXiv:2105.11827. https://arxiv.org/abs/2105.11827 ; https://ar5iv.labs.arxiv.org/html/2105.11827
38. Celestia Docs, data availability layer. https://docs.celestia.org/learn/how-celestia-works/data-availability-layer
39. "Fraud and Data Availability Proofs," arXiv:1809.09044 (author list not captured in the fetched summary). https://arxiv.org/abs/1809.09044
40. CometBFT README and docs. https://github.com/cometbft/cometbft ; https://docs.cosmos.network/cometbft
