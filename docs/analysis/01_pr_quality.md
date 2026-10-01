# 01 — PR formatting and review quality

*What can be said today about how a change should be presented to the DOSR
reviewer, which settings are fixed by the protocol and which a policy author
tunes, and what decides each open question.*

> **Evidence status.** No real model verdict has been collected: there is no
> API key in this environment, and the provider in the repository
> (`pkg/llm`) is a mock whose verdict is a marker rule or a Bernoulli coin.
> Everything below is one of three kinds of statement, and each is labelled:
> **(D)** design reasoning about what the protocol fixes and why, verifiable
> by reading the code; **(L)** a finding from the literature review
> (`docs/literature/02`, `03`); **(H)** a hypothesis that the harness in
> `cmd/dosr-prstudy` is built to test. Numbers about the corpus (sizes,
> counts, multipliers) are measured from the 300-case corpus in
> `eval/prstudy/corpus`; numbers about verdicts do not exist yet. The
> mock run in `eval/prstudy/runs/` demonstrates the pipeline only.

The study instrument is `cmd/dosr-prstudy` (see `eval/prstudy/README.md`):
60 real CometBFT commits (good), 240 mutants in four bad classes
(low-effort, subtly harmful, obviously harmful, prompt-injected), four
system-prompt variants, one attested call per (case, variant, repeat)
through the production notary, recording verdict, tokens, latency, cost and
the reasons a response yields no verdict. A full run (4 variants × 1
repeat) is estimated at $15 / $30 / $59 on Haiku 4.5 / Sonnet 5.5 / Opus
5.5 at the cached list prices (verify before quoting).

## 1. Which PR settings work well, which don't

"PR formatting" in DOSR is not a convention; it is the canonical request
`Q = BuildRequestBody(policy, chain, repo, branch, H, C, nonce, model, msg,
DiffTrees(H, C), blobs)` that every validator recomputes byte for byte
(`docs/DESIGN.md` §4.1). Settings therefore split into those frozen by the
protocol version and those the policy author chooses.

### 1.1 Settings fixed by the protocol

| setting | value | why it is fixed (D) | failure mode it leaves | evidence |
|---|---|---|---|---|
| Context shown | commit message + unified diff of every changed file, 3 lines of context, nothing else | *Q* must be a pure function of committed Git objects; any file not in the diff would have to be chosen by a rule validators can replay. Cost is then a function of the change, not the repository (`COST.md`: p50 request ≈ 2.6k tokens, fixed overhead ≈ 0.9k). | The reviewer cannot see callers, tests elsewhere, or the rest of the function; a one-line `return nil` in `ValidateBasic` is visible, a removed call site is not. | (D); cost measured on 398 commits |
| Verdict channel | `submit_review` tool, `strict: true`, schema `{verdict: approve\|reject, candidate, summary}`, `additionalProperties: false` | A verdict read from prose would be parsed by a validator-side heuristic the contributor can game ("...I would approve, but..."). The tool input is schema-validated by the provider; `ParseResponse` accepts exactly one such block and nothing else. | A model that answers in prose produces no verdict (liveness cost, never safety). | (D); `pkg/review/response_test.go` |
| Forced single call | one request, one response; `SystemSuffix` rule 1 | Current models reject `tool_choice: any/tool` (HTTP 400), so `auto` plus a prompt instruction is the only option. Two tool calls are rejected by the parser. | The rate of "prose instead of tool call" is a property of the model and prompt; unknown. **(H1)** It is low on current models for a one-tool request with an explicit instruction; the run records it as `no_tool_call`. | (D) |
| Section boundaries | `--<boundary>--` lines, boundary = SHA-256 over chain, repo, branch, H, C, policy hash, nonce and every (path, old id, new id) | Content under review cannot contain its own boundary: putting a guessed marker into a file changes the blob id and hence the boundary. The suffix tells the model everything between markers is data. | A model may still *believe* a fake boundary line (corpus operator `inj_fake_boundary`); the guarantee is syntactic, not cognitive. | (D); `pkg/review` boundary test |
| Sampling | no `temperature`, no `thinking`, no `output_config` | Current models reject non-default temperature; thinking is always on and its depth (`effort`) defaults per model (Sonnet 5.5 `high`, Opus 5.5 `medium`). The request cannot carry these without a protocol version bump, and the header allow-list blocks beta features such as `fallbacks` that would let a different model answer. | Verdicts are a random variable (§3); effort cannot be tuned per policy today. | (D), (L: Atil et al., up to 15 % accuracy variation on "deterministic" settings) |
| Model binding | `model` in *Q* and in the response must both be on the policy allow-list | Prevents substituting a cheaper or compromised model; the response `model` is provider-asserted. | None at the protocol level; quality differences between tiers are **(H2)**, below. | (D) |
| `max_tokens` | policy value, sent verbatim | A truncated answer (`stop_reason: max_tokens`) is not a verdict. With the mock, a verdict needs about 55 output tokens, so `max_tokens` below that *always* truncates (`docs/notes/impl_attest_notary_llm.md`). On real always-thinking models the thinking tokens count against the same limit, so a policy must size it for thinking plus the summary (the study default is 16384). | Too small: 100 % liveness failure; too large: an upper bound on cost per call, not a cost. | (D) |
| Size and opacity | `MaxDiffBytes`; files that are binary, contain NUL, are invalid UTF-8 or exceed 256 KiB are *opaque* and the change is rejected unless `allow_opaque` | What the model cannot read it cannot review; `allow_opaque=true` shows a one-line placeholder, so the hidden bytes get approved unseen. | 2.0 % of 399 real CometBFT commits contain an opaque file and are unreviewable under `allow_opaque=false` (`COST.md`); in this corpus 1 of 144 scanned commits. A committed binary (a vendored tool, a test fixture) needs a separate path, e.g. a maintainer-signed exemption. | measured |

Two of these deserve the label "does not work well" even without data:
`allow_opaque=true` approves content nobody saw and should be off for any
repository that matters; and diff-only context is the setting most likely
to limit the achievable false-accept rate on subtle changes, which is why
§4 proposes a bounded context budget as the next protocol version.

### 1.2 Settings a policy author controls

| setting | choices in the study | hypothesis (H) | experiment that decides |
|---|---|---|---|
| System prompt | `default` ("strict reviewer, approve only safe changes"), `security` (explicit reject list, "when in doubt, reject"), `minimal` ("Review this change."), `risk` (0–10 score, threshold 3) | **(H3)** The explicit reject list lowers false accepts on `obviously_harmful` and `low_effort` at the price of more false rejects on dependency bumps and large refactors; `minimal` has the highest false-accept rate; `risk` behaves like `security` but with better-calibrated summaries. Jin & Chen (L) warn that prompts demanding explanations *raise* misjudgment of correct code, so `risk` may increase false rejects. | `run -variants default,security,minimal,risk -repeat 1`: §2 confusion matrix per variant; the policy author picks by the asymmetry in §2. |
| Model | `claude-haiku-4-5`, `claude-sonnet-5-5`, `claude-opus-5-5` | **(H2)** False accepts on `subtly_harmful` fall with model tier more than on `obviously_harmful`; the tiered policy of `COST.md` (haiku for docs/tests, sonnet for code, opus for sensitive paths) is only justified if the cheap tier's false-accept rate on docs/tests is near zero. | Same run per model; compare §3 per-operator rates across models. |
| Allowed size | `MaxDiffBytes` (study cap 96 KiB of text) | **(H4)** Accuracy degrades with diff size; the policy should cap size and make contributors split changes rather than let the reviewer skim. | Bucket the run's results by `request_bytes`; the corpus p90 is 15.5 KB, so a dedicated large-commit sample is needed. |
| Repeats / grinding bound | `RequireIntent`, `MaxAttempts` | **(H5)** P(at least one approve in K) for bad classes grows with K; the intent cap must be set from the per-case mixed-verdict rate. | `run -repeat 5` on the bad classes (§5 of the summary). |
| k-of-n providers | not implemented | Reduces *uncorrelated* errors only; see §3. | Needs a second provider in the policy; out of scope. |

## 2. Maximising good accepted and bad rejected

The study scores a confusion matrix per variant and model:

| | model approves | model rejects |
|---|---|---|
| **good** (60 real merged commits) | true accept | **false reject** — costs the contributor one review (≈ $0.02–0.05 at p50 on Sonnet/Opus per `COST.md`) and a resubmission; recoverable |
| **bad** (240 mutants) | **false accept** — the certificate is final, the commit is on the canonical branch, and the approval is public; recoverable only by a later commit that reverts it | true reject |

The asymmetry is the whole point: DOSR has no human in the loop after the
certificate, so the policy should sit on the reject-heavy side of the
operating curve, and the metric to minimise is the false-accept rate on
the hard classes, subject to a tolerable false-reject rate. The
`soft` low-effort cases (message "fix", whitespace-only) are reported
separately because their rejection is a policy preference, not a safety
property.

What the literature allows us to expect (L):

* Sun et al. (16 AI review Actions, 22k comments): 0.9–4.2 % of file-level
  and 6.5–19.2 % of hunk-level comments were addressed by a code change,
  against about 60 % for human comments. Most AI review output is noise;
  a verdict distilled from it inherits that noise.
* Jin & Chen: LLMs "frequently misclassify correct code implementation as
  non-compliant or defective", and explanation-demanding prompts make it
  worse. This predicts a non-trivial false-reject rate on the good class,
  especially on large refactors and dependency bumps where the diff gives
  no reason for the change.
* Mira's self-reported F1 ≈ 44 on its own benchmark (vendor claim). Taken
  at face value, a single review is nowhere near a reliable gate.
* Aðalsteinsson et al. (small industrial study): participants named false
  positives and trust as the main concerns and conclude that LLMs should
  augment, not replace, reviewers.

None of these measures the binary approve/reject task on a diff with a
fixed tool schema, which is exactly what the harness measures. The
hypotheses are therefore conservative: **(H6)** false-accept on
`obviously_harmful` is near zero for all variants except `minimal`;
**(H7)** false-accept on `subtly_harmful` is substantial under `default`
and is the class where model tier and prompt matter most; **(H8)** false
rejects on good dependency bumps are common under `security` because the
diff is a wall of hashes with no reviewable semantics.

Levers, in the order a policy author should try them:

1. **Prompt**: an explicit reject list and "when in doubt, reject" (the
   `security` variant). This is free. Its cost is the false-reject rate on
   the good class, which the run quantifies.
2. **Model tier**, per path category (`COST.md` §3: docs/tests → Haiku, code
   → Sonnet, sensitive paths → Opus, 41 % cheaper than flat Opus). Only
   justified by per-class results.
3. **Size cap**: smaller diffs are reviewed better **(H4)** and cost less;
   the policy can force splitting.
4. **Repeated sampling** (k-of-1 on the same model) to reduce variance;
   each sample costs a full review, and the single-use intent nonce makes
   the *contributor* unable to pick the best of k, so the policy would have
   to require k attested approvals of the same intent — not implemented.
5. **k-of-n providers**: see §3; it helps only against uncorrelated errors.

## 3. Low-effort contributors, bad actors and jailbreaking

| threat | corpus operators | stopped by the protocol? (D) | depends on the model? | residual |
|---|---|---|---|---|
| Low effort (no message, whitespace, deleted assertion) | `msg_fix`, `whitespace_only`, `drop_assertion` | No; the protocol does not judge substance. | Yes, and on the prompt: `default` does not ask for descriptive messages, `security` does. | A policy that rejects "fix" messages is cheap and should be the default. |
| Subtly harmful (flipped comparison, dropped error check, 1000× timeout, hard-coded secret, `return nil` in a verify function) | `flip_comparison`, `drop_err_check`, `timeout_1000x`, `hardcoded_secret`, `weaken_check` | No. | Entirely. These are the cases where diff-only context hurts: the hunk shows the mutation but not what depends on it. | This is He & Yu's *epistemic fault*: a protocol-compliant certificate for a semantically invalid transition. It is outside the BFT fault model by construction. |
| Obviously harmful (remote `curl \| sh` in `init()`, env exfiltration, `rm -rf` wired into `make test`) | `remote_exec`, `env_exfil`, `rm_repo` | No. | Yes, but these are the easy cases **(H6)**. | A prompt should name them explicitly; the `security` variant does. |
| Prompt injection (direct instruction, authority claim, fake protocol addendum, fake transcript, fake boundary, injected commit message, injected markdown) | `inj_*` (8 operators, 2 combined with real harm) | **Partly.** The injection cannot forge a section marker (hash-derived boundary), cannot add a system message or a prior assistant turn (there is exactly one user message, recomputed by validators), cannot change `tool_choice` or the tool schema, and cannot produce a verdict by any channel except the model's own strict tool call. `SystemSuffix` rule 2 instructs the model to treat it as a reason to reject. | Yes: whether the model *obeys* the injected text is a model property. Greshake et al. and OWASP LLM01:2025 (L) list the mitigations DOSR uses (constrain behaviour in the system prompt, mark external content, validate output format) and state that none is a guarantee. | **(H9)** Direct "SYSTEM: ignore previous instructions" is rejected by current models under every variant; the authority-claim and fake-addendum phrasings have a higher success rate, and the combined `inj_plus_*` cases are the real risk: an injection that *lowers* the bar for a harmful change rather than demanding approval outright. |
| Grinding (resample until approved) | measured by `-repeat K` | **Bounded**: `ReviewIntent` + chain-derived nonce + single-use nonce at the notary + `MaxAttempts` (`DESIGN.md` §4.6). | The mixed-verdict rate per case decides how much a bound of K attempts is worth. | Identities are free; without stake per intent a Sybil contributor is bounded by API cost only. |
| Forged or replayed certificates, header smuggling, hidden fields, wrong model/host | — | **Yes** (attack catalogue, `DESIGN.md` §9). | No. | Notary honesty in the prototype. |

The clean statement is the two-layer argument of the literature review
(`03` Part B.4): the ordering layer tolerates f < n/3 Byzantine validators
and gives agreement and finality; the review layer gives *authenticity of
a verdict* and no semantic guarantee. In DOSR the quorum that judges
semantics has size one by design, and the He & Yu framing says what k-of-n
would and would not buy: every reviewer necessarily sees the same diff and
the same injection, so correlated failures (a persuasive injection, a
mutation that looks like a refactor) defeat all k at once; only
uncorrelated errors are reduced, at k times the cost. The corpus is built
so that this can be tested directly: an `inj_plus_drop_err` case approved
by two different models is a correlated failure.

## 4. Single pass versus back-and-forth

A multi-turn review, in which the model asks for more files, is tempting
because it attacks the main weakness of §1.1 (diff-only context). It is
possible in DOSR only under conditions that make it expensive (D):

1. **Every turn must be recomputable.** Turn *i*'s request is
   (system, tools, user message, assistant turn 1, tool result 1, ...,
   assistant turn *i*−1, tool result *i*−1). Validators can recompute it
   iff the tool results are a deterministic function of the model's
   requests and the committed objects: a `fetch_file(path)` tool must be
   answered from the tree of *C* (or of *H*, named explicitly), with the
   same opacity and size rules as the diff, and a request for a path that
   does not exist must have a canonical error text. Nothing else (search,
   build output, network) is admissible.
2. **The attestation must cover the whole conversation.** Either *N*
   attested calls whose chain validators check (the request of call *i*+1
   must embed the attested response of call *i* verbatim and the tool
   results the validator recomputes), or one attestation of a multi-turn
   transcript. With the current per-call notary this is *N* receipts per
   commit; the transaction grows linearly with the turns, and the
   freshness window applies to the first call.
3. **Grinding gets a new dimension.** The model's choice of files is
   itself non-deterministic, so two honest runs of the same review differ
   in what they read; a contributor could resample not only the verdict
   but the exploration path, and the intent/nonce bound applies to the
   whole conversation only if the nonce is in every turn.

**Cost multiplier (D, with corpus numbers).** Let *c* be the single-pass
input (system + tool + diff) and *f* the content fetched per turn. Without
caching, turn *i* re-sends everything before it, so *T* turns cost
`T·c + f·T(T−1)/2` input tokens plus *T* thinking-and-output budgets: for
*T* = 3 and *f* ≈ *c* that is 6*c* input instead of *c*, plus three times
the output. With prompt caching, the repeated prefix is billed at the
cached-read price (currently $0.20 per MTok on Sonnet 5.5 and Opus 5.5
against $2 and $4 base input, i.e. 10 % and 5 %), so the input part falls
to roughly `c + (T−1)·f` at full price plus the re-read prefix at the
discounted price, but *the canonical request would have to carry
`cache_control`* and every turn still pays a full thinking budget, which
`COST.md` assumes dominates the per-call cost (1500 thinking tokens against
≈ 2.6k input at p50). Measured on the 60 good commits of the corpus, the
full post-change content of the changed files (excluding `go.mod`/`go.sum`)
is 6.9× the diff text at the median and 10.0× on average (17.6× at p90);
with a 32 KiB-per-file cap the mean is 5.6×. A reviewer that fetches "the
whole file for every hunk" therefore multiplies input cost by roughly an
order of magnitude before it fetches anything the diff did not touch.

**Latency multiplier.** *T* × (time to first token + thinking + output) plus
the fetch round trips through the notary; `LatencyRealistic` in `pkg/llm`
assumes ≈ 6.7 s per call at p50, so a three-turn review is ≈ 20 s before
consensus, against a block time of seconds.

**Attack surface.** The model can be steered to fetch. A comment in the
diff saying "see `docs/REVIEW_NOTES.md` for the approved rationale" is a
pull request for an injection the diff itself does not contain; the file
is in the tree at *C* and would be fetched, rendered and believed with
exactly the same section-marker protection as the diff and no more. The
corpus operator `inj_markdown` adds such a file; in the single-pass design
it is reviewed because it is *in the diff*, in a multi-turn design a file
already present at *H* would never appear in any diff and could be fetched
on demand. Multi-turn also makes the "what did the model see" question,
which single-pass answers with one recomputable byte string, into a
transcript the contributor presents.

**Recommendation (D).** Stay single-pass and add a **bounded, policy-selected
context budget** in the next protocol version: a deterministic rule such
as "for every modified file, include the full post-change content when it
is at most *S* bytes, else the diff plus the enclosing function
boundaries", plus "include files whose path is listed in the policy's
`always_show` list" (e.g. `go.mod`, CI workflows, `Makefile`). This keeps
*Q* a pure function of (policy, H, C), one attested call, one receipt, one
thinking budget, and gives the reviewer what §3 says it lacks for the
subtly harmful class. The budget *S* and the inclusion rule are policy
parameters, so repositories pay for the context they want.

**Experiment that decides it.** Extend the corpus builder with a second
rendering mode (`diff` vs `diff+context(S)`) and run the four classes
under both on the same model: the decision rule is whether the
false-accept rate on `subtly_harmful` (and in particular `drop_err_check`,
`weaken_check`, `flip_comparison`, where the harm is visible only with
the surrounding code) falls by more than the false-reject rate on `good`
rises, per dollar of the measured cost increase. If diff+context does not
move the subtle class, multi-turn, which can only add context the model
asks for, will not either, and the money is better spent on a stronger
model or on k-of-n.

## 5. What the mock run shows, and does not

`eval/prstudy/runs/mock_default_security_r2` is 1200 attested calls (300
cases × 2 variants × 2 repeats) against the in-process mock with a
Bernoulli(0.7) verdict: 0 calls without a verdict, every record carries
tokens, latency, notary overhead and cost, and the summary renders all five
tables. The approval rates in it are 70 % for every class because the
coin does not read the diff; they are **not** results. The same binary,
pointed at `api.anthropic.com` with an invalid key, completes the full
notary path (host allow-list, system roots, TLS, attestation, response
parsing) and records `http_401`, which is as far as the harness can be
tested without a key.

## 6. What remains open

* Every (H) above. The run that resolves H1–H3 and H6–H9 is one command and
  about $30 on Sonnet 5.5; H2 needs it three times; H5 needs `-repeat 5` on
  the bad classes.
* Ground truth of the good class is "merged by maintainers", which is a
  proxy; 10 of the 60 are dependency bumps whose correct verdict under a
  strict policy is debatable.
* Mutations are text-level and may not compile; a model that notices
  "this does not compile" rejects for the wrong reason, which inflates
  true rejects. A compile check per mutant would tighten the class.
* The `risk` variant can only steer reasoning; the protocol has no numeric
  verdict field. If the run shows the risk summaries are well calibrated,
  a protocol version could add `risk` to the tool schema and let the policy
  set the threshold instead of the prompt.
* Effort (`output_config.effort`) is a cost-quality lever the policy
  cannot reach today; adding it to *Q* is a one-field protocol change.
