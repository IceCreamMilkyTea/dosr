# Notes: cost analysis per PR and on-chain reputation counters

What was done for `docs/analysis/02_cost.md`, in the order it happened.

## 1. On-chain reputation counters (`pkg/app` only)

Goal: make `accepted / attempted` per submitter identity computable from
replicated state, so §8 of the cost analysis (trust levels) has an input
that every validator agrees on.

Changes:

* `pkg/app/state.go` — new `Reputation{Intents, Accepted uint64; FirstHeight
  int64}`; `State.Reputation map[string]*Reputation` keyed by hex submitter
  public key; initialised in `NewState`, deep-copied in `Clone` (the records
  are pointers and are mutated in place, so a shallow copy would leak
  mutations between the check state and the committed state); added as a
  fifth field of `hashView` so `ComputeAppHash` covers it (`hashView` is a
  separate struct, so adding a field to `State` alone would NOT have put it
  in the app hash — this was the "verify" the task asked for). Helper
  `reputationOf(pubKey, height)` creates the record on first use.
* `pkg/app/exec.go` — `Accepted++` for `tx.PubKey` after the commit point of
  `execAcceptCommit` and of `execCreateRepo` when a genesis commit is
  included; `Intents++` after the commit point of `execReviewIntent`. All
  three increments sit below the "no failure is possible below" line, so
  the validate-fully-before-mutating discipline holds and a failed
  transaction never creates a record.
* `pkg/app/app.go` — `New` treats a persisted state with a nil `Reputation`
  map as corrupt, like the other maps. (Consequence: a database written by a
  binary without this field will not open. There is no deployed chain, so
  no migration was written.)
* `pkg/app/query.go` — `/reputation` (all records, sorted by hex key, as
  `[]ReputationEntry{pubkey, intents, accepted, first_height}`) and
  `/reputation/<hex pubkey>` (one record; key lower-cased).
* `pkg/app/app_test.go` — `TestReputation` on the three-replica driver:
  genesis counts for the creator with `FirstHeight = 1`; an accept refused
  for a missing intent and, from a fresh key, a rejected review plus a
  stale intent change nothing and create no record; intents count up to
  `MaxAttempts` and the refused one does not; the accept counts and the
  pruning of the branch's intents leaves the lifetime counters alone; a
  second identity on a repository without intents; survival across
  `reopen`; the app hash changes if the map is cleared; both query paths.
  Replica agreement is asserted by the driver after every block.

Not changed: transaction format, `pkg/types`, any other package. Nothing is
pruned, by design.

## 2. Tests and mutation testing

```
go test ./pkg/app/ -count=1          ok (4.8 s)
go test ./... -count=1               all packages ok (pkg/testnet 255 s)
python3 scripts/mutation_test.py     27 mutants: 26 killed, 1 redundant (M05, as before), 0 survived
```

All mutation patterns still matched; none of the matched lines were edited
(the increments were added on new lines after `c.hist = append(...)`,
`c.st.Intents[...] = in` and inside the `if bundle != nil` block, and M25's
pattern `\tc.st.pruneIntents(b.Repo, b.Branch)\n` is intact). The script
was not modified. `eval/results/mutation.json` was rewritten by the run with
the same outcome.

`go build ./...` fails in `cmd/dosr-prstudy` ("function main is undeclared")
— that package is the parallel PR-quality study, still being written by the
other engineer; everything else builds.

## 3. Numbers for the document

* Review sizes and per-model costs: `eval/results/COST.md` as is (no rerun).
* Mean `.go` file size in `reference/cometbft` (for §3's full-file example):

  ```
  python3 - <<'EOF'
  import pathlib, statistics
  s=sorted(p.stat().st_size for p in pathlib.Path('reference/cometbft').rglob('*.go')
           if 'vendor' not in p.parts and not p.name.endswith('.pb.go'))
  print(len(s), statistics.mean(s), statistics.median(s), s[int(len(s)*.9)], s[int(len(s)*.99)])
  EOF
  # 617 files, mean 6278 B, median 3228, p90 15292, p99 40625
  # (643 files / mean 8008 B if generated .pb.go files are included)
  ```

* Tables in §1, §4, §5: computed from the COST.md prices and token counts
  with the formula stated at the top of the document (one-off Python in the
  session, formula reproducible by hand; e.g. opus p50 = 4 × 2579/1e6 +
  20 × 1800/1e6 = $0.0463).
* Cache-read prices and the per-model minimum cacheable prefix (512 tokens on
  fable/opus/sonnet 5.5, 4096 on haiku 4.5) from the Claude API reference
  skill cache dated 2026-09-25, same source as `eval/cost.py`'s price table.
* The prstudy taxonomy (`low_effort`, `subtly_harmful`, `obviously_harmful`,
  `injected`) and operator names were read from `cmd/dosr-prstudy/mutate.go`
  so that §6 matches `01_pr_quality.md`, which did not exist yet when this
  was written.

## 4. Problems and judgement calls

* `hashView` is a positional struct literal; adding `Reputation` to `State`
  without touching `hashView` would have compiled and silently left the
  counters out of the app hash. The test `TestReputation` guards this by
  checking that clearing the map changes `ComputeAppHash()`.
* The genesis commit of a created repository is counted as an accept for the
  creator (the task asked for it). The document notes that a trust policy
  should discount it.
* Rejections are not observable on-chain except as intents without a
  following accept; the document says so, and that abandoned intents
  (lost race, 5xx) also look like misses.
* Prompt caching is described as "if available" with a request-format
  caveat: `cache_control` is not in the canonical body today, and adding it
  is a policy-versioned format change.
* Everything that needs a real model (`p_good`, `p_bad`, no-receipt rate) is
  presented only as sensitivity tables and labelled hypothesis.
