# DOSR — Cost analysis per PR

This document answers eight questions about what a change costs under DOSR,
for the contributor, for the validators and for an attacker. It uses only
three kinds of numbers, and labels each:

* **measured** — from `eval/results/COST.md` (398 real first-parent CometBFT
  commits rendered through the real request builder; tokens = bytes × 0.381,
  a tiktoken approximation of the provider's tokenizer) and from
  `docs/EVALUATION.md` §4 (contention waste, grinding, baseline);
* **list price** — Anthropic first-party prices per million tokens as cached
  in the API reference on 2026-09-25 (input/output: fable-5-1 $10/$50,
  opus-5-5 $4/$20, sonnet-5-5 $2/$10, haiku-4-5 $1/$5; cache reads
  fable-5-1 $0.25, opus-5-5 and sonnet-5-5 $0.20); re-check before quoting;
* **hypothesis** — any probability that needs a real model to measure
  (`p_good`, `p_bad`, the no-receipt rate `r`). These appear only as
  sensitivity tables. The real-model study (`docs/analysis/01_pr_quality.md`,
  in progress) is what would replace them.

Notation. `c(s, M)` is the cost of one review of a request of `s` input
tokens on model `M`:

```
c(s, M) = price_in(M) · s / 1e6  +  price_out(M) · (300 + 1500) / 1e6
```

(300 output tokens for the verdict tool call and 1500 billed thinking tokens
are the assumptions of `eval/cost.py`; the second term is the "fixed part" in
COST.md §2.) Request sizes (measured): p50 2,579 tokens (2 files, +9 lines),
p90 8,040 (8 files, +92 lines), p99 26,467, mean 4,281. Fixed overhead of the
request itself (system prompt + tool definition + header): 872 tokens.

| one review | p50 | p90 | p99 | mean |
|---|---|---|---|---|
| fable-5-1 | $0.116 | $0.170 | $0.355 | $0.133 |
| opus-5-5 | $0.046 | $0.068 | $0.142 | $0.053 |
| sonnet-5-5 | $0.023 | $0.034 | $0.071 | $0.027 |
| haiku-4-5 | $0.012 | $0.017 | $0.036 | $0.013 |

A DOSR validator never calls the model: it verifies the receipt (0.15–11 ms,
EVALUATION §4 E1). Everything below is the *contributor's* bill, except where
the baseline is discussed.

## 1. How much does it cost to get one good PR accepted?

A good change is accepted after `A` review attempts, each costing `c`:

```
E[cost] = c(s, M) · E[A],      E[A] = W_k / ( p_good · (1 − r) )
```

* `p_good` (hypothesis): probability that the model approves a good change
  on one attempt. Verdicts are non-deterministic and the provider no longer
  accepts a temperature, so a good change can be rejected; the contributor
  pays and resubmits.
* `W_k` (measured): reviews per accepted change with `k` contributors racing
  on one branch head: **1.0 / 1.75 / 2.44 / 5.12** for k = 1 / 2 / 4 / 8
  (E5, after the D13 fix). This is optimistic concurrency: at most one
  change lands per block, the losers' receipts are for a stale head and must
  be re-reviewed after a rebase. Measured with the mock reviewer, which
  approves every honest request, so it composes multiplicatively with
  `1/p_good`.
* `r` (hypothesis): fraction of attempts that produce no usable receipt — the
  model answers in prose instead of calling `submit_review`, the answer is
  truncated at `max_tokens`, or the provider returns a 5xx. Each is a specific
  rejection code (`bad_response`, see `TestEvidenceRejections`) and costs a
  retry. A 5xx is not billed by the provider; the other two are, so
  `1/(1−r)` is an upper bound.

**Attempts.** `E[A]` for the ranges considered:

| `p_good` | k=1 | k=2 | k=4 | k=8 |
|---|---|---|---|---|
| 0.95 | 1.05 | 1.84 | 2.57 | 5.39 |
| 0.80 | 1.25 | 2.19 | 3.05 | 6.40 |
| 0.60 | 1.67 | 2.92 | 4.07 | 8.53 |

(r = 0; with r = 0.05 multiply by 1.05.) Contention matters more than
model non-determinism in every cell except the top-left: a branch with 4
active contributors costs each of them 2.4–4 reviews per landed change.

**Dollars, no contention (k=1), by model and commit size** (p50 / p90):

| model | p_good = 0.95 | p_good = 0.80 | p_good = 0.60 |
|---|---|---|---|
| fable-5-1 | $0.122 / $0.179 | $0.145 / $0.213 | $0.193 / $0.284 |
| opus-5-5 | $0.049 / $0.072 | $0.058 / $0.085 | $0.077 / $0.114 |
| sonnet-5-5 | $0.024 / $0.036 | $0.029 / $0.043 | $0.039 / $0.057 |
| haiku-4-5 | $0.012 / $0.018 | $0.014 / $0.021 | $0.019 / $0.028 |

**Dollars with contention** (p50 commit, p_good = 0.80):

| model | k=1 | k=2 | k=4 | k=8 |
|---|---|---|---|---|
| fable-5-1 | $0.145 | $0.253 | $0.353 | $0.741 |
| opus-5-5 | $0.058 | $0.101 | $0.141 | $0.296 |
| sonnet-5-5 | $0.029 | $0.051 | $0.071 | $0.148 |
| haiku-4-5 | $0.014 | $0.025 | $0.035 | $0.074 |

**Comparisons.**

* *Every validator reviews* (the E4 baseline): each of `n` validators calls
  the provider, so the per-attempt cost is `n · c` — measured 4× with n = 4
  ($0.0344 vs $0.0086 at mock prices) and, because a multi-second LLM call
  sits inside `timeout_propose`, 5 consensus rounds instead of 1. There is a
  second, less visible multiplier: in strict mode all `n` independent
  verdicts must approve, so the per-attempt acceptance probability is
  roughly `p_good^n` (0.8⁴ = 0.41 for n = 4) and `E[A]` grows accordingly.
  DOSR's cost does not depend on `n` at all.
* *A human review hour.* We give no number. The comparison that matters is
  not "LLM review is cheaper than a maintainer" (it obviously is per attempt)
  but whether the model's `p_good`/`p_bad` make the cheap review worth
  anything — §5–§7.

## 2. How many retries on average?

Same formula: `E[A] − 1` retries. For a single contributor on a quiet
branch, 0.05–0.67 retries per change depending on `p_good`; with four
contributors on one branch, 1.6–3.1 retries, almost all of them caused by
losing the head race rather than by the model.

**A cautionary example (design log D13).** The first contention run measured
**3.0 / 6.44 / 15.97** reviews per accepted change for k = 2 / 4 / 8, i.e.
1.7–3.1× the final numbers. The cause was not the model and not consensus:
`CheckTx` executes against the node's *check state*, which already contains
competing transactions admitted to the mempool, so a loser was refused with
`stale_head` while the chain head had not moved. The client treated this as a
chain-level stale, re-read the (unchanged) head, paid for a new review and
was refused again — a busy loop of paid reviews until the next block. The
fix was purely client-side (wait until the head actually moves before
reporting `ErrStale`), and it halved to thirded the bill. The lesson for the
cost analysis: **mempool admission policy is part of the economic design**;
a retry rule that is correct for free transactions is wrong when each retry
costs a review.

## 3. How does cost grow with codebase size?

It does not. The canonical request contains the commit message and the
unified diff of the change (3 lines of context per hunk) and nothing else
(`pkg/review/contract.go`), so the input is a function of the *change*:

```
tokens(change) ≈ 872 + 0.381 · diff_bytes          (measured)
c(change, M)   ≈ price_in(M) · tokens / 1e6 + fixed_out(M)
```

The fixed part (prompt overhead + verdict + thinking) dominates below ~2k
tokens, which is where most commits are: the p50 commit adds 9 lines. A
10-file or a 10,000-file repository costs the same to review a 9-line change
in.

Any design that adds context changes this. If the reviewer were given the
full post-change content of every touched file (the natural "let the model
see the function it is editing" extension), or the related files, or a
multi-turn conversation with tool calls, the input becomes

```
tokens ≈ 872 + 0.381 · (diff_bytes + Σ_touched size(file) + Σ_related size(file))
```

and grows with the size of the files in the repository, i.e. with the
codebase. Example, measured file sizes: the 617 non-generated `.go` files in
`reference/cometbft` have mean **6,278 bytes** (median 3,228, p90 15,292,
p99 40,625). The p90 commit touches 8 files; if all 8 were included in full
at the mean size, that is 50 kB ≈ 19,100 extra tokens, taking the request
from 8,040 to ~27,200 tokens — the p99 size — and the cost per review from
$0.068 to $0.145 on opus-5-5 (2.1× on every model, since the fixed part is
proportional to price). With the p90 file size instead of the mean it is
8 × 15 kB ≈ 46,600 extra tokens (5.4× the diff-only request). Multi-turn
review (the model asks to read files) is worse: each turn re-sends the
prefix, so the cost is quadratic in turns unless the prefix is cached.

The policy already bounds the worst case: `MaxDiffBytes` caps the rendered
text, so the maximum cost of one review is
`price_in · 0.381 · MaxDiffBytes / 1e6 + fixed_out`; at 256 kB that is
$1.09 / $0.44 / $0.22 / $0.11 for fable / opus / sonnet / haiku.

## 4. Can intelligent reviews avoid ballooning costs?

Five levers, with what each is worth on the measured corpus.

**Tiered model by change category (measured).** Routing docs/tests to
haiku-4-5, code to sonnet-5-5 and changes touching sensitive paths
(consensus, crypto, p2p, CI, …; 25 % of commits) to opus-5-5 costs **$12.38**
for the 398 commits vs **$21.14** flat opus (−41 %). Flat sonnet is cheaper
still ($10.57), flat fable 2.5× more ($52.86). The trade-off is quality: we
do not know `p_good`/`p_bad` per model, so whether sonnet on code is "as
good" is a hypothesis the real-model study must test. Note that the policy
(not the contributor) decides the tier: the model is in the attested request
and `Policy.Models` is verified, so a contributor cannot downgrade.

**Prompt caching of the fixed prefix (if available).** The first 872 tokens
(model, `max_tokens`, system prompt, tool definition) are byte-identical for
every review under a given policy. Marking the system block with
`cache_control` would bill them at the cache-read price: saving per review
872 × ($10 − $0.25)/1e6 = $0.0085 on fable (7.3 % of a p50 review, 5 % of
p90), $0.0033 on opus (7.2 %), $0.0016 on sonnet (6.8 %). On haiku-4-5 the
prefix is below the model's 4,096-token cacheable minimum and would silently
not cache. Three caveats: (i) the saving is bounded by the share of the
prefix, ≤ 8 %, because the fixed *output* part dominates; (ii) a cache entry
is scoped to the API key/organization, so it helps a contributor's own
retries within the 5-minute TTL (contention, 5xx), not the next contributor;
(iii) `cache_control` would have to be part of the canonical body
(policy-versioned, recomputed by validators), which is a request-format
change — not implemented.

**Context budgets.** Already implemented as `MaxDiffBytes`/`MaxTokens` (§3);
the policy author sets a hard ceiling on the cost of one review, and
`allow_opaque` decides whether binary/oversized files make a change
unreviewable (2 % of commits) rather than expensive.

**Diff splitting.** Splitting a large change into `j` reviews does not save
money: the input is the same and the fixed part is paid `j` times (a p99
commit on opus: $0.142 whole vs $0.250 in four parts). It helps only when a
change exceeds `MaxDiffBytes` and, arguably, for quality (smaller units are
easier to judge) — which is a `p_bad` question, not a cost one.

**Intents and leases against contention waste.** The waste in §1 is paid
for receipts that lose the head race. Intents already make every attempt
visible; a *lease* on the head (an intent that reserves the next slot for a
bounded time, Bors-style batching, or rebase-tolerant receipts for
non-overlapping diffs) would move `W_k` toward 1. Not implemented; the
measured 2.44× at k = 4 is what a lease would recover.

**Risk-adaptive quorum.** If sensitive paths get `k`-of-`n` independent
reviews (different providers or models) and everything else one, the cost on
this corpus is: tiered $12.38 + one extra opus review on the 99 sensitive
commits (99 × $0.0563 = $5.57) = **$17.95 for 2-of-2**, or **$23.53 for
2-of-3** (two extra) — the latter slightly above flat opus, i.e. a quorum on
a quarter of the commits costs about as much as the top model everywhere,
with the benefit in §5: if the reviews were independent, `p_bad` on
sensitive paths would become `p²` (2-of-2) or `3p² − 2p³` (2-of-3). They are
not fully independent (same model family, same diff), so treat that as an
upper bound on the improvement. The protocol would need a receipt per
provider and an `AcceptCommit` carrying several — a transaction-format
change, future work.

## 5. How much does it cost to get one bad PR accepted?

For an attacker who resamples until the model approves, with per-attempt
approval probability `p_bad` for that class of change:

```
E[cost per accepted bad PR] = c(s, M) / p_bad       (+ identity cost, below)
```

`p_bad` is a hypothesis until measured; the table spans four orders of
magnitude (p50 commit size; multiply by 1.47 for p90):

| model | p_bad = 0.001 | 0.01 | 0.05 | 0.2 |
|---|---|---|---|---|
| fable-5-1 | $115.79 | $11.58 | $2.32 | $0.58 |
| opus-5-5 | $46.32 | $4.63 | $0.93 | $0.23 |
| sonnet-5-5 | $23.16 | $2.32 | $0.46 | $0.12 |
| haiku-4-5 | $11.58 | $1.16 | $0.23 | $0.06 |

With `RequireIntent` and `MaxAttempts = m` per (identity, branch, head),
one identity succeeds with probability `P ≤ 1 − (1 − p_bad)^m` (m = 3:
0.003 / 0.030 / 0.143 / 0.488 for the four columns; measured in E7 at
p = 0.25: 13/20 = 0.65 vs 0.58 expected, against 19/20 with no cap and 12
tries). After `m` failures the attacker needs a fresh identity. **Identities
are free** — a keypair — so the expected number of attempts until the first
approval is still geometric with mean `1/p_bad`, and the expected cost is
unchanged: `c / p_bad` plus `(1/p_bad)/m` identities at whatever an identity
costs, which is today zero. The chain charges no fee and no stake per intent
(not implemented; DESIGN §4.6 says so). What intents do buy is visibility
(§8) and the single-use nonce (one receipt per intent per notary), which
closes the "reuse the one approval you got for a different nonce" shortcut.

## 6. How bad is bad: the classes

The real-model study (`docs/analysis/01_pr_quality.md`, `cmd/dosr-prstudy`)
mutates real commits into four classes. Each has its own `p_bad`; the values
below are **hypotheses** ordered by how we expect a reviewer to perform, not
measurements, and the study's job is to replace them.

| class | operators (prstudy) | what the attacker gains | expected `p_bad` (hypothesis) | attacker cost (opus, p50) |
|---|---|---|---|---|
| `low_effort` | `msg_fix`, `whitespace_only`, `drop_assertion` | nothing directly: spam, reputation farming (§8) | high — 0.2 or above; a whitespace-only change is often legitimately approvable | ≤ $0.23 per landed change |
| `subtly_harmful` | `flip_comparison`, `drop_err_check`, `timeout_1000x`, `hardcoded_secret`, `weaken_check` | a latent bug or a weakened check in a sensitive path | the dangerous middle — 0.01 to 0.2 is plausible; a flipped `<=` in a diff of 92 lines is exactly what reviewers miss | $0.23–$4.63 |
| `obviously_harmful` | `remote_exec`, `env_exfil`, `rm_repo` | immediate compromise | low — 0.001 or below if the model is competent at all | ≥ $46 |
| `injected` | `inj_comment_direct`, `inj_commit_message`, `inj_markdown`, `inj_fake_boundary`, `inj_comment_rule`, `inj_fake_transcript`, `inj_plus_drop_err`, `inj_plus_remote_exec` | turns any of the above into an approval by instructing the reviewer | unknown; this is the class the boundary scheme and `SystemSuffix` are designed against, and the one where a single model is weakest | whatever the carried payload's row says, divided by the injection's success rate |

Two observations follow from the formula alone. First, the attacker's cost
is set by the *cheapest model the policy allows*, not the most expensive, so
a tiered policy must route anything an attacker could aim at (sensitive
paths) to the strong tier — which the path-based tiering does — and must
treat the category assignment itself as attack surface (a `.md` change that
also touches a `.go` file is "sensitive", not "docs"). Second, `low_effort`
is essentially free to land and must be handled by something other than the
review fee: the point of the counters in §8.

## 7. Is this a reasonable deterrent?

Against what, and for whom:

* **Spam and low-effort floods: yes.** Every attempt costs the submitter at
  least a cent (haiku p50 $0.012; the policy's cheapest allowed model
  decides) and the cost is linear in attempts with no amortisation — a
  receipt is bound to one candidate on one head under one policy and cannot
  be reused. A flood of 10,000 median-size attempts costs $116 on haiku
  and $1,158 on fable, which is a real deterrent for nuisance and none for
  a budget.
* **A funded attacker: no, not by cost.** The value of landing a backdoor in
  a widely used repository is unbounded relative to the numbers in §5. Even
  the best cell of the table — fable-5-1, `p_bad` = 0.001, p90 commit, $170
  per accepted bad PR — is a rounding error against that value, and
  `p_bad` = 0.001 is itself an optimistic hypothesis for `subtly_harmful`.
  At `p_bad` ≥ 1 % the attacker pays under $12 on the most expensive model.
  Review fees deter nobody who is paid to attack.
* **The maintainer's side.** The relevant comparison is the maintainer's
  cost to catch what the model does not: human review time on `n` PRs, at
  whatever an hour costs that project. DOSR reduces the number of PRs a
  human must look at from everything to what the model approved, and makes
  *who tried what, how often* public (§8). It does not make the human
  unnecessary for anything in the `subtly_harmful` row.

Honest conclusion: the deterrent for the funded attacker has to come from
`p_bad → 0` — model quality, independent `k`-of-`n` providers on sensitive
paths (§4), prompt-injection hardening — multiplied by a non-zero identity
cost (§8). The fee is a rate limiter, not a security boundary, and the
design should say so where it currently says "bounded only by API cost".

## 8. Proof of work via accepted/attempted ratio? Trust levels?

**What is observable.** With `RequireIntent`, every review attempt is a
committed `ReviewIntent`, and every success an `AcceptCommit` from the same
key. The state machine now keeps lifetime counters per submitter public key
(`State.Reputation`, never pruned, part of the app hash, served by
`/reputation` and `/reputation/<hex pubkey>`):

```
Reputation{ Intents, Accepted, FirstHeight }
```

`Accepted/Intents` is the identity's acceptance ratio over its whole
history, replicated and identical on every validator (the driver asserts
app-hash equality after every block; `TestReputation`). Three limits:

1. *Rejections are visible only through intents.* A rejected review never
   reaches the chain; the only trace is an intent that was never followed
   by an accept. Under a policy without `RequireIntent` the chain sees
   successes only and the ratio is undefined. Also, an intent that was
   abandoned for a non-review reason (lost the head race, 5xx) counts as a
   miss, so the ratio is a lower bound on the model's acceptance rate for
   that identity.
2. *The genesis commit counts as accepted for the creator* (it needs no
   review), so a repository creator starts at 1/0; a policy should subtract
   it or simply require `Accepted ≥ A` with `A ≥ 2`.
3. *The counters say nothing about whether an accepted change was good.*

**A trust-level policy** (not implemented; the counters are the input):

| level | condition | what the policy grants |
|---|---|---|
| new | `Intents < I0` | `MaxAttempts = m0` (e.g. 2); strongest model or `k`-of-`n` mandatory; perhaps a lease-free queue position |
| established | `Accepted ≥ A` and `Accepted/Intents ≥ r` (e.g. A = 10, r = 0.5) | cheaper tier for non-sensitive paths; `MaxAttempts = m1 > m0`; eligible to hold a head lease |
| penalised | a later `RevertCommit` names one of its accepted commits | back to *new*, or `MaxAttempts = 0` for a period of heights |

The penalty needs an out-of-band signal: the chain cannot know a merged
change was bad. The natural mechanism is a `RevertCommit` transaction —
signed by the maintainer threshold like `UpdatePolicy`, naming a history
entry — whose effect is to decrement nothing (history is append-only) but to
record a strike against the submitter key and, optionally, against the
notary/model that approved it. **Future work**; it is the piece that turns
the counters from bookkeeping into feedback.

**Sybil resistance, honestly.** Everything above is per key, and keys are
free. Ratio-based trust therefore has exactly the weakness of §5: an attacker
farms `A` accepted `low_effort` changes on a fresh key for `A · c/p_good`
(ten trivial docs changes on haiku: about $0.15), reaches *established*, and
then enjoys the cheaper model and more attempts. The ratio does raise the
cost of the *first* bad PR per identity from `c/p_bad` to
`A·c/p_good + c/p_bad`, which is a few cents, and it makes the farming
visible (a key with ten whitespace-only accepts in a row is a pattern a
maintainer can see). Real resistance needs a cost per identity: a fee or
stake per intent (burned or slashed on a `RevertCommit`), or a binding to an
external identity (an organisation's signing key, a GitHub-style account
with history, a maintainer co-signature for new keys). None of these is in
the protocol today, and the analysis of §5 holds until one is: **the trust
level is a tool for maintainers to triage, not a security boundary**.

## Summary table

| question | answer (measured where possible) |
|---|---|
| one review | $0.012 (haiku) – $0.116 (fable) at the median commit; p90 1.5× |
| one good PR, quiet branch | review cost ÷ `p_good`: 1.05–1.67 reviews |
| one good PR, k contributors | × 1.75 / 2.44 / 5.12 for k = 2 / 4 / 8 (measured) |
| every-validator baseline | × n per attempt (4× measured), × 5 rounds, ≈ `p_good^n` acceptance |
| growth with repo size | none; 872 + 0.381·diff_bytes tokens; full-file context ⇒ ~2× at p90 |
| savings | tiering −41 %; caching ≤ 8 %; splitting negative; leases recover `W_k − 1` |
| one bad PR | `c/p_bad`: $0.06–$170 across the hypothesis range; identities free |
| deterrent | yes for spam (≥ 1 ¢/attempt, linear); no for a funded attacker unless `p_bad → 0` and identities cost something |
| reputation | `Accepted/Intents` per key on-chain now; trust levels need `RevertCommit` + identity cost |
