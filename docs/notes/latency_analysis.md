# Notes: latency analysis pass (`docs/analysis/03_latency.md`)

What was run, what was added, what went wrong, what the numbers cannot say.

## 1. Code added

* `pkg/bench/experiments.go`
  * `EndToEndSize(opts)` — experiment `e2e_size`: DOSR mode, 4 validators,
    `wan` preset, CometBFT default timeouts, `llm.LatencyRealistic`, change
    sizes 1 KB / 10 KB / 100 KB / 1 MB via `e.sequential` (6 submissions per
    size, 3 with `-quick`), one cluster for all sizes (as `BundleSize`).
    Results `e2e_size_<size>k.json` with the usual `timelineSummary` plus
    `admit`, `attest_total`, `present` percentiles, provider stats, block
    interval, app stats of node 0, invariant check.
  * `Propagation(opts)` — experiment `propagation`: 4 validators + {0, 2, 4}
    full nodes (`{0, 2}` with `-quick`), `regional` preset sized
    `4 + k`, fast timeouts (`skip_timeout_commit`), no LLM latency, 10
    submissions (4 with `-quick`). For each decided height
    `(*Env).commitSpread` reads `Cluster.Commits(i)[h].CommittedAtUnixNano`
    of every running honest node and splits by `Cluster.IsValidator(i)`.
    Per-sample `Extra`: `validator_first_ms`, `validator_last_ms`,
    `validator_spread_ms`, `full_first_ms`, `full_last_ms`,
    `full_spread_ms`, `full_after_first_validator_ms` (all relative to
    `SubmittedAt` except the spreads). Summary: percentiles of
    `validator_first`, `validator_last`, `validator_spread`, `full_last`,
    `full_spread`, `full_after_first_validator`, `all_spread`, plus block
    interval. Results `propagation_f<k>.json`.
  * helper `p50(any)` (nil-safe log line), `spread` struct.
* `pkg/bench/bench.go`: `EnvConfig.FullNodes`, passed to
  `testnet.Options.FullNodes`. `Env.propagation` already iterated over all
  nodes (`c.N()` includes full nodes), so `decided_all` in the propagation
  results covers the full nodes too.
* `cmd/dosr-bench/main.go`: `e2e_size` and `propagation` registered and in
  the `all` order after `e2e`.
* `eval/plot.py`: the `e2e_` section now excludes `e2e_size_*`; new sections
  "End-to-end latency vs change size" (table + stacked bar `e2e_size.png`,
  same segment colours/order as `e2e_breakdown.png`; "attestation + admit" is
  one segment because both are < 11 ms) and "Propagation to validators and
  non-validator full nodes" (table + `propagation.png`, p50 with bar to p90).
* `docs/analysis/03_latency.md` (the analysis), this note.

Nothing else in `eval/results/raw` was touched; `SUMMARY.md` was regenerated
and `git diff` shows 25 added lines, no changed ones. `eval/results/bench.log`
was left alone (it is the log of the main run); the log of this run is below.

## 2. What was run

```
go build ./... && go build -o bin/dosr-bench ./cmd/dosr-bench
./bin/dosr-bench -exp propagation -quick -out <scratch>      # smoke test, 10 s
./bin/dosr-bench -exp e2e_size,propagation -out eval/results/raw
python3 eval/plot.py
```

Full-run log (stderr of `dosr-bench`, 2026-10-01 00:02–00:08 local):

```
 0:02  up 1 day, 16:30, 1 user, load averages: 2.45 2.31 2.34
00:02:33 == e2e_size_1k
00:03:18    ok 6/6, request 3410 bytes, llm p50 6662 ms, commit p50 1000 ms, total p50 7745 ms, decided-all p50 7747 ms
00:03:18 == e2e_size_10k
00:04:04    ok 6/6, request 15663 bytes, llm p50 6568 ms, commit p50 960 ms, total p50 7935 ms, decided-all p50 7980 ms
00:04:04 == e2e_size_100k
00:05:00    ok 6/6, request 137336 bytes, llm p50 7613 ms, commit p50 561 ms, total p50 9279 ms, decided-all p50 9304 ms
00:05:00 == e2e_size_1024k
00:07:23    ok 6/6, request 1294612 bytes, llm p50 20583 ms, commit p50 661 ms, total p50 21271 ms, decided-all p50 21305 ms
00:07:23 e2e_size done in 4m55s
00:07:23 == propagation_f0
00:07:32    validator spread p50 11.0 ms, full nodes after first validator p50 NaN ms, decided-all p50 567 ms
00:07:32 == propagation_f2
00:07:42    validator spread p50 10.9 ms, full nodes after first validator p50 10.9 ms, decided-all p50 662 ms
00:07:42 == propagation_f4
00:07:52    validator spread p50 15.0 ms, full nodes after first validator p50 15.8 ms, decided-all p50 753 ms
00:07:52 propagation done in 29s
 0:07  up 1 day, 16:36, 1 user, load averages: 2.65 2.54 2.44
```

`python3 eval/plot.py` → `wrote eval/results/SUMMARY.md and 11 figures`.
All blocks in both experiments were decided in round 0 (`rounds_histogram
{'1': n}`), no notes, no invariant violations.

Per-sample raw values of `e2e_size` (upstream / commit / total, ms):

```
1k:     6837/1340/8178  6049/664/6713  6662/1280/7943  7021/723/7745  5685/1000/6686  6823/1200/8023
10k:    6171/483/6655   6694/1300/7995 6228/960/7190   6579/1483/8063 7273/660/7935   6568/1500/8070
100k:   7445/520/7971   7613/1660/9279 8590/561/9156   8832/480/9318  7493/1880/9380  9340/1320/10667
1024k:  20102/1541/21668 20880/440/21353 20110/905/21040 20583/661/21271 20752/481/21262 33950/1701/35726
```

Per-sample spreads of `propagation` (ms, validator spread / last full node
after first validator):

```
f0: 13.2 23.0 14.0 7.8 13.6 21.7 7.5 7.9 7.9 11.0
f2: 8.7/8.7 10.9/10.9 19.0/27.6 10.5/13.3 14.9/17.9 24.9/21.7 18.4/15.5 10.1/3.1 6.3/9.2 13.9/4.6
f4: 10.9/8.0 6.3/13.0 15.0/17.2 25.1/15.8 28.0/25.1 22.0/18.9 5.0/6.7 15.1/25.0 115.0/115.0 6.0/12.2
```

## 3. Problems and things worth knowing

* **Machine load.** Load average 2.3–2.7 on 8 cores during the run (other
  agents' processes; nothing of ours besides the bench). The earlier main
  run of the evaluation was done at similar load. Expect ±10 % between runs;
  no confidence intervals (one run per configuration, 6 or 10 samples).
* **The sixth sample of every `e2e_size` size is a different change.**
  `e.sequential` names files `f<i%5>.txt`, so submission 5 rewrites the file
  added by submission 0. Its diff carries the old and the new lines, so its
  request is ~2× larger (1 KB: 4 303 vs 3 232 B; 100 KB: 218 KB vs 121 KB;
  1 MB: 2.2 MB vs 1.11 MB) and, under the model, its LLM call is longer
  (33.9 s vs 20.1–20.9 s at 1 MB). The table's "request bytes" column is the
  average over all six, so it is ~17 % above the add-only request. The p90
  column at 1 MB (35.7 s) is this sample. I kept it: it is a real effect
  (modifications cost old + new lines) and the per-sample values match the
  model exactly, which is a useful check that the mock does what
  `pkg/llm/model.go` says.
* **`commit` p50 looks like it shrinks with size (1.00 → 0.56 s).** It does
  not; individual commits range 0.44–1.9 s in every size. With no LLM
  latency the harness submits right after a decision and always waits
  ~a full block (1.3 s); with the random LLM latency the arrival phase is
  random and the median of six draws from a ~[0.45, 1.9] s distribution lands
  anywhere. Six samples are too few for this column; the consensus experiment
  (20 samples) is the right source for commit latency.
* **`propagation` full nodes raise the absolute latency.** Commit p50
  601 → 700 → 784 ms and block interval 303 → 404 ms from 0 to 4 full nodes:
  6–8 in-process nodes plus 15–28 proxies on 8 shared cores. The spreads
  (what the experiment is about) stay at 11–16 ms. One 115 ms outlier in f4
  hit validators and full nodes alike (a late precommit).
* **Full nodes are not "behind" the validators.** I expected a visible lag
  (block sync after the fact); there is none because an in-sync CometBFT
  full node runs the consensus reactor and commits on +2/3 precommits like a
  validator. A full node that starts late or lags uses block sync, whose
  catch-up times are in `impl_testnet.md` §6.3, not here.
* **Intent round trip** was not measured with default timeouts; the only
  measured value is from the grinding run (fast timeouts, no delay, 380 ms
  p50). The analysis uses "≈ one block ≈ 1.3 s" from the consensus table
  for the default-timeout case.
* **The smoke run in `-quick` mode** had a `%!f(<nil>)` in the log line when
  there are no full nodes; fixed with the `p50` helper before the real run
  (hence "NaN" in the f0 line above, which is correct).

## 4. Limitations of the analysis

* Every LLM-dependent number is the `LatencyRealistic` assumption (median
  TTFT 1.2 s, 60 tok/s, 50 µs per input token, bytes/4 tokens, ~300 output
  tokens). The size dependence in particular is entirely the 50 µs term; a
  provider with prompt caching or a different prompt-processing rate would
  give a different curve. The protocol-side numbers (prepare, attest, admit,
  verify, commit, spreads) do not depend on it.
* Attestation is the trusted-proxy backend; MPC-TLS figures are quoted from
  the literature review, not measured.
* Links have delay but unlimited bandwidth; 1 MB transactions are cheap here
  and would not be on a real WAN.
* One machine, one clock: spreads are comparable across nodes, but CPU
  contention inflates everything for *n* ≥ 7 and for the full-node runs.
* No multi-turn review was run; §4's conversation paragraph is arithmetic on
  the model, not a measurement.
* No real-provider run and no run with more than 10 validators; the 16–128
  validator numbers are Cason et al.'s.
