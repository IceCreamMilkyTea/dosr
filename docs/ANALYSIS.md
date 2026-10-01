# DOSR — PR Quality, Cost and Latency Analysis

Three questions the team raised after the checkpoint build, answered point by
point. Each section below gives the short answer and points to the detailed
document; every number is either measured in this repository (and says where)
or an explicitly labelled assumption/hypothesis.

| Part | Document | Status |
|---|---|---|
| A. PR formatting and quality | [analysis/01_pr_quality.md](analysis/01_pr_quality.md) | design + literature + **experiment ready to run with a real API key** (no key available here, so no real approval rates) |
| B. Cost per PR | [analysis/02_cost.md](analysis/02_cost.md) | measured request sizes on 398 real commits; formulas with sensitivity tables where a real model is needed; on-chain reputation counters implemented |
| C. Latency | [analysis/03_latency.md](analysis/03_latency.md) | measured (mock LLM latency is an assumed model) |

**What is NOT measured anywhere in this repository:** how often a real model
approves good changes (`p_good`) or bad ones (`p_bad`). Those two numbers decide
most of Part A and the deterrence question in Part B. The experiment that
measures them is built (`cmd/dosr-prstudy`, corpus of 300 cases) and costs
about $15–60 per model to run (Part A below).

---

## A. PR formatting and quality

**Which PR settings work well, which don't.** The protocol fixes the settings
that matter for *verifiability*: diff-only context, a strict `submit_review`
tool as the only verdict channel, one call per review, section boundaries
derived from content hashes (a diff cannot forge a section marker), no
`temperature` (current models reject it), a model allow-list checked on both
request and response. A policy author chooses the system prompt, the model,
size limits and (future) k-of-n providers. Two measured facts constrain the
settings: 2 % of real CometBFT commits contain a binary or oversized file and
are unreviewable under `allow_opaque=false`; and `max_tokens` must leave room
for the structured verdict plus the model's (billed, hidden) thinking. Which
*prompt* works best is a hypothesis until the real-model study runs.

**Maximising good-accepted and bad-rejected.** Framed as a confusion matrix
over four classes (good / low-effort / subtly harmful / obviously harmful +
injected). The asymmetry that matters: a false accept is final and public, a
false reject costs one review (cents) and a retry. The literature gives little
comfort on precision: AI review comments lead to code changes in 0.9–19 % of
cases (Sun et al.) and Mira self-reports F1 ≈ 44 (see
[LITERATURE_REVIEW](LITERATURE_REVIEW.md)). DOSR cannot make a model better; it
can make sure the model saw exactly the change being committed and that one
approval is not enough when the policy says so.

**Low-effort vs bad actors / jailbreaking.** What the protocol stops: forging
or re-binding a verdict, hiding the verdict, smuggling API options, replay,
forging section markers, unbounded resampling (intents + single-use nonces).
What depends on the model: recognising subtle harm, resisting persuasive
injection inside the diff. He & Yu's "epistemic fault" framing applies —
consensus guarantees agreement, not judgement; k-of-n providers help only
against uncorrelated errors, and every provider sees the same injected text.

**Single pass vs back-and-forth.** Multi-turn review ("let the model fetch
more files") is possible in DOSR only if every turn is deterministic and
recomputable by validators (the fetch tool must answer from the tree at the
expected head) and the attestation covers the whole conversation. Cost grows
roughly quadratically in turns without caching, latency linearly, and the
model can be steered to fetch files that contain injection. Measured on the
corpus: the full content of the changed files is 6.9× (median) / 10× (mean)
the diff text. Recommendation: single pass with a bounded, policy-selected
context budget; the `diff` vs `diff+context(S)` experiment decides it.

**The study, ready to run.** `cmd/dosr-prstudy build` turns 60 real merged
commits into 300 cases (60 good; 60 low-effort; 60 subtly harmful — flipped
comparisons, dropped error checks, 1000× timeouts, hard-coded secrets,
weakened checks; 60 obviously harmful — remote exec, env exfiltration, repo
deletion; 60 prompt-injection variants incl. fake boundaries and fake
transcripts). `run` sends them through the notary to a provider with four
prompt variants and `-repeat K` for variance. Mock run (1,200 calls) proves
the pipeline; its verdicts are coin flips and say nothing. Estimated real
cost for 4 variants × 1 repeat: ≈ $15 (Haiku 4.5) / $30 (Sonnet 5.5) / $59
(Opus 5.5). See [eval/prstudy/README.md](../eval/prstudy/README.md).

## B. Cost per PR

Measured on 398 real CometBFT commits ([eval/results/COST.md](../eval/results/COST.md)):
request size p50 2.6k tokens, p90 8k, p99 26k, max 117k; fixed overhead ≈ 870
tokens; tokens ≈ 0.38 × bytes (tiktoken approximation).

**Cost of one review** (list prices cached 2026-09-25; output 300 + 1,500
billed thinking tokens assumed):

| model | p50 commit | p90 commit | mean |
|---|---|---|---|
| Fable 5.1 | $0.116 | $0.170 | $0.133 |
| Opus 5.5 | $0.046 | $0.068 | $0.053 |
| Sonnet 5.5 | $0.023 | $0.034 | $0.027 |
| Haiku 4.5 | $0.012 | $0.017 | $0.013 |

**Getting one good PR accepted:** `E[cost] = c(size, model) × W_k / p_good`,
with the contention factor `W_k` *measured* (1.0 / 1.75 / 2.44 / 5.12 reviews
per accepted change for k = 1/2/4/8 contributors on one branch) and `p_good`
(the real model's approval rate for good changes) unknown. At p50 size on
Opus 5.5: $0.049 (p_good 0.95) to $0.077 (p_good 0.6) alone; $0.30 with 8
contributors racing. Versus the baseline where each of *n* validators reviews:
*n*× per attempt and ~p_good^n acceptance.

**Retries:** `E[attempts] − 1`; the client-side busy-retry bug found by the
contention experiment (design log D13) multiplied waste by 1.7–3.1× before
it was fixed — retry rules are part of the economics.

**Growth with codebase size:** none — the request carries only the diff.
Adding full changed files would cost ≈ 2.1× on a p90 commit (mean .go file in
CometBFT: 6.3 KB); multi-turn review grows with every file the model asks for.

**Can intelligent reviews avoid ballooning costs?** Tiered policy (docs/tests →
Haiku, code → Sonnet, sensitive paths → Opus) costs 41 % less than flat Opus on
the real commit mix ($12.38 vs $21.14 for 398 commits); prompt caching of the
fixed prefix saves ≤ 8 %; diff splitting makes it worse; leases/batching
recover the contention waste; 2-of-3 providers only on the 25 % of commits
touching sensitive paths costs about the same as flat Opus.

**Getting one bad PR accepted:** attacker's expected cost `= c / p_bad` per
identity:

| model | p_bad 0.001 | 0.01 | 0.05 | 0.2 |
|---|---|---|---|---|
| Fable 5.1 | $116 | $11.6 | $2.3 | $0.58 |
| Opus 5.5 | $46 | $4.6 | $0.93 | $0.23 |
| Haiku 4.5 | $11.6 | $1.2 | $0.23 | $0.06 |

Intents with `MaxAttempts` 3 bound the probability per identity to
1−(1−p_bad)³, but identities are free unless a fee/stake per intent is charged
(not implemented). `p_bad` per class (low-effort / subtle / obvious /
injected) is a hypothesis until the study runs.

**Is it a reasonable deterrent?** Yes against spam and low-effort floods —
cost is linear in attempts (10k attempts ≈ $116 on Haiku, $1,158 on Fable).
No against a funded attacker once p_bad ≥ 1 % (< $12 on the most expensive
model). The deterrent for that attacker is p_bad → 0 (model quality,
uncorrelated k-of-n) plus a cost per identity.

**Proof of work / trust levels:** with intents every attempt is on-chain, so
`accepted / intents` per identity is now computable — the state machine keeps
per-submitter counters (`/reputation` query, in the app hash). A trust-level
policy (new identities: few attempts, expensive model or k-of-n; established:
cheaper model, more attempts; penalty on a later `RevertCommit`) is
described; it is a triage tool, not a security boundary, because identities
are free and farming a good ratio costs about $0.15 on Haiku.

## C. Latency

Measured on one machine with emulated links; LLM latency is the mock's
assumed model (median 1.2 s TTFT + 60 tok/s + 50 µs per input token).

**How long to evaluate a PR:**
`total ≈ T_prep + [T_intent] + T_llm(size) + T_attest + T_admit + T_consensus`.
Measured instance (4 validators, WAN, default timeouts): **7.2 s p50 = 6.5 s
LLM + 1.0 s consensus + ~2 ms of DOSR's own work** (prepare 0.1 ms, attestation
1 ms, CheckTx verification 0.15 ms). With an intent: + one block (~1.3 s
default timeouts, 0.38 s fast). By change size (E8): 7.7 s at 1 KB, 7.9 s at
10 KB, 9.3 s at 100 KB, 21 s at 1 MB — all growth is the LLM's input-token
term; everything else stays ≤ 11 ms. Real PRs (p50 2.6k tokens, p99 26k) sit
at 7–9 s under this assumption.

**How long until an accepted commit is propagated:** once decided it is final
(instant finality, no reorganisation). Spread between the first and the last
validator committing the same block: 9 ms LAN → 67 ms WAN (n=4) → 99 ms WAN
(n=10). Non-validator full nodes — what `git clone` users talk to — commit
within 11–16 ms (p50) of the first validator (E9), because an in-sync full node
follows the consensus votes rather than waiting for block sync. A block costs
≈ 3 one-way network delays (testnet measurement).

**Across network sizes:** with default CometBFT timeouts every configuration
from 4 validators on a LAN to 10 on the WAN decides in ~1.3 s — the fixed 1 s
`timeout_commit` hides the network. With fast timeouts: 0.64 s (4, LAN) →
1.18 s (10, WAN); of that, +0.11 s is CPU contention of 10 in-process nodes and
+0.4 s the WAN. Published Tendermint numbers for 16–128 validators across 16
AWS regions: 2.1–2.5 s block latency.

**Across prompt/conversation sizes:** consensus is flat up to 1 MB bundles
inside the transaction (commit p50 1.18–1.29 s); validator verification 0.15 →
11 ms; the LLM call 6.7 → 20.6 s (assumed model). A T-turn conversation
multiplies LLM latency by T and adds an attestation per turn.

**What would change in a real deployment:** real provider latency and
variance; MPC attestation adding seconds (and tens of MB per KB sent);
bandwidth-limited links making 1 MB bundles visible; more validators; where
the notary sits relative to the contributor and the provider.

---

Reproduce: `go run ./cmd/dosr-cost && python3 eval/cost.py`;
`./bin/dosr-bench -exp e2e_size,propagation && python3 eval/plot.py`;
`go run ./cmd/dosr-prstudy build|run|summarize` (see its README).
