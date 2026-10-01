# Large models (not run by `./run.sh`)

Configurations that do not fit the budget of `run.sh` (every job under 5
minutes on 8 cores, `timeout 600` per job).  `run.sh` skips this directory;
run one by hand with

    java -Xmx8g -cp tools/tla2tools.jar tlc2.TLC -workers 8 -deadlock -config large/<name>.cfg MC.tla

The numbers below are from the TLC logs in `out/prev/` (previous engineer)
and from this session's isolated runs; "idle" means no other heavy process
on the 8-core laptop, "loaded" means another Java workload was using 4-5
cores at the same time (which is what happened during the final run).

| config | difference from the default model | result |
|---|---|---|
| `SafetyChain.cfg` | 4 receipts instead of 3 | **holds**: 21,007,340 states generated / 8,143,227 distinct, depth 15; 202 s idle, 412 s loaded |
| `SafetyAdversary.cfg` | 2 Byzantine LLM calls instead of 1 | **holds**: 59,228,780 / 15,809,026, depth 10; 234 s idle; on the loaded machine it was killed by the 600 s timeout at 56,467,208 generated |
| `Intents.cfg` | 2 Byzantine LLM calls instead of 1 | **holds**: 15,126,878 / 5,261,593, depth 12; 395 s (previous engineer's run, `out/prev/Intents.out`) |
| `IntentsNoGrinding.cfg` | 2 Byzantine transactions instead of 1 | **holds** (incl. `NoGrinding`): 13,285,127 / 6,679,176, depth 12; 229 s (`out/prev/IntentsNoGrinding.out`) |
| `LivenessByz_Forest3.cfg` | Forest3 (a, b, c) instead of Forest2 | **holds** (`Progress`): 8,221,828 / 2,980,875, depth 16; 228 s idle |
| `LivenessByz.cfg` | original: log 6, receipts 6, 2 rejects, 2 Byzantine txs, Forest3 | **no verdict**: 4 h 17 min, 521,850,804 / 180,317,599, 47.8 M states on the queue at depth 16, then `java.io.IOException: No space left on device` (TLC's disk state queue filled the volume). The periodic liveness checks up to 124 M states found no violation. |
| `NoNotaryIntent_NoGrinding.cfg` | mutant with log 4, receipts 3, 2 Byzantine calls and txs (default: log 2, receipts 2, 1 / 1) | **no verdict**: single worker, still at depth 7 after 1 h 56 min, 510,498,808 / 229,693,151, 190 M on the queue, then disk full. The 7-state counterexample is found in 2 s with the default constants. |
| `NoRestartIndex_PrefixConsistency.cfg` | mutant with receipts 3, 3 rejects, 2 Byzantine calls and txs (default: 2, 1, 1 / 1) | **violated as expected**: 457,243,218 / 97,052,868, 1 h 07 min, single worker; the same 10-state trace is found in 44 s with the default constants. |
