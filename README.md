# DOSR — Decentralized Open-Source Review

A decentralized Git host in which a commit enters the canonical branch because
a **verifiable certificate of an LLM review** says so. The contributor pays for
one review; validators running BFT consensus (CometBFT) verify the certificate
instead of repeating the review, and order `AcceptCommit(expected_head,
candidate, receipt)` transactions with compare-and-swap semantics on the branch
head.

ECE/CS 512 (Duke, Fall 2026) project — William Convertino, Jakub Romanczuk,
Gage Garcia, Yuhan Wei.

| Document | What it is |
|---|---|
| [docs/CHECKPOINT_REPORT.md](docs/CHECKPOINT_REPORT.md) | **Start here.** Status, results, problems found, next steps |
| [docs/DESIGN.md](docs/DESIGN.md) | The normative design: model, evidence, state machine, ABCI mapping, invariants, attacks, limitations |
| [docs/LITERATURE_REVIEW.md](docs/LITERATURE_REVIEW.md) | Synthesis of the three-part literature review in `docs/literature/` |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Experiment design, metrics, and discussion of the results |
| [eval/results/SUMMARY.md](eval/results/SUMMARY.md) | Generated tables and figures |
| [docs/notes/](docs/notes/) | Engineering logs: every problem met and how it was resolved (design log, per-package implementation notes, testnet notes, TLA+ notes) |
| [spec/README.md](spec/README.md) | TLA+ model and TLC results |

## Layout

```
pkg/types      policy, transactions, result codes            (consensus-critical)
pkg/gitobj     strict Git object model, bundles, closure, diff (consensus-critical)
pkg/review     canonical LLM request + response parsing       (consensus-critical)
pkg/attest     attestation / presentation format + verifier   (consensus-critical)
pkg/app        the ABCI 2.0 state machine                     (consensus-critical)
pkg/notary     attesting proxy (trusted; sees plaintext)
pkg/llm        mock provider: Anthropic Messages API shape, latency/verdict/fault models
pkg/client     contributor workflow
pkg/node       CometBFT node wiring
pkg/testnet    N-node localhost network, emulated links, fault injection, invariant checker
pkg/dosrtest   in-memory fixtures: repositories, receipts, transactions
pkg/e2e        whole-stack tests
pkg/bench      evaluation experiments
cmd/dosrd      node daemon      cmd/dosr  contributor CLI      cmd/dosr-bench  evaluation
spec/          TLA+ model, configs, mutants, TLC outputs
scripts/       mutation_test.py
reference/     (git-ignored) clones of CometBFT, Gitopia, TLSNotary used as references
```

## Running things

Requirements: Go 1.22+ (developed with 1.27), `git`, Python 3 with matplotlib
for the plots, Java 21 for TLC.

```sh
go test ./...                              # unit, differential, simulation, e2e (a few minutes)
go test ./... -short                       # quicker
python3 scripts/mutation_test.py           # 27 mutants of the state machine
go test ./pkg/gitobj/ -run xxx -fuzz FuzzDecodeBundle -fuzztime 30s   # any Fuzz* target
go build -o bin/dosr-bench ./cmd/dosr-bench && ./bin/dosr-bench -exp all   # ~40 min
python3 eval/plot.py                       # -> eval/results/SUMMARY.md + figures
(cd spec && ./run.sh)                      # TLC jobs
```

A local demo with real Git repositories (one terminal each):

```sh
# 1. a one-validator chain, a mock provider and a notary — see docs/EVALUATION.md "Demo"
# 2. contributor:
go build -o bin/dosr ./cmd/dosr
bin/dosr keygen -out alice.hex
bin/dosr policy -host 127.0.0.1:8443 -model mock-reviewer-medium -notary <notary pubkey> -maintainer $(cat alice.pub) > policy.json
bin/dosr create-repo -key alice.hex -repo demo -policy policy.json -git ./myrepo
DOSR_API_KEY=sk-... bin/dosr submit -key alice.hex -repo demo -git ./myrepo -ref HEAD -notary http://127.0.0.1:7443
bin/dosr log -repo demo
```

## Honest summary of what this prototype is and is not

* The attestor is a **trusted proxy**, not TLSNotary's MPC-TLS notary: it sees
  the request, the response and the contributor's API key. The verifier
  interface, certificate format and every validator-side check are designed so
  that a TLSNotary presentation verifier can replace it; see DESIGN §4.4 and the
  literature review §02 for what that swap costs.
* The LLM is a mock with an *assumed* latency model. Nothing here measures how
  good LLM code review is.
* Consensus protects against conflicting histories and forged approvals; it
  does not protect against an allowed model approving bad code.
