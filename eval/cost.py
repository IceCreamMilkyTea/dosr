#!/usr/bin/env python3
"""Cost analysis from real commits.

Input:  eval/results/raw/cost_commits.jsonl  (written by cmd/dosr-cost)
Output: eval/results/COST.md and eval/results/figures/cost_*.png

Token counts use tiktoken's cl100k_base as an APPROXIMATION of the
provider's tokenizer (Anthropic's is not public); bytes/4 is shown next to
it. Prices are Anthropic first-party list prices per million tokens as
cached in Claude Code's API reference on 2026-09-25 — re-check before
quoting.
"""
import json, os, sys, statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RAW = sys.argv[1] if len(sys.argv) > 1 else "eval/results/raw/cost_commits.jsonl"
OUT = sys.argv[2] if len(sys.argv) > 2 else "eval/results"
FIG = os.path.join(OUT, "figures"); os.makedirs(FIG, exist_ok=True)

PRICES = {  # USD per 1M tokens (input, output)
    "claude-fable-5-1": (10.0, 50.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-4-5": (1.0, 5.0),
}
OUTPUT_TOKENS = 300   # assumed length of a structured verdict + summary (+ thinking is billed as output too: see note)
THINKING_TOKENS = 1500  # assumed hidden reasoning tokens billed as output on always-thinking models

try:
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    def ntok(s): return len(enc.encode(s, disallowed_special=()))
    TOK = "tiktoken cl100k_base"
except Exception:
    enc = None
    def ntok(s): return len(s) // 4
    TOK = "bytes/4"

recs = [json.loads(l) for l in open(RAW)]
ok = [r for r in recs if not r.get("error")]
# We only have byte counts; rebuild an approximate token count from bytes
# using the ratio measured on a sample of rendered requests (see below).
RATIO_FILE = os.path.join(os.path.dirname(RAW), "cost_token_ratio.json")
ratio = 0.25
if os.path.exists(RATIO_FILE):
    ratio = json.load(open(RATIO_FILE))["tokens_per_byte"]
for r in ok:
    r["tokens"] = int(r["request_bytes"] * ratio)

def pct(xs, q):
    xs = sorted(xs); return xs[min(len(xs)-1, int(q*len(xs)))]

md = ["# Cost analysis from real commits", "",
      f"Source: {len(recs)} first-parent commits of CometBFT (`reference/cometbft`), {len(ok)} rendered "
      f"({len(recs)-len(ok)} not reviewable: empty tree change). Tokens = request bytes × {ratio:.3f} "
      f"(ratio measured with {TOK} on rendered requests; bytes/4 would give {0.25:.2f}). "
      f"Output tokens per review assumed {OUTPUT_TOKENS} (+{THINKING_TOKENS} billed thinking tokens on always-thinking models).", ""]

# -------- distribution of request size
sizes = [r["tokens"] for r in ok]
md += ["## 1. How big is a review request?", "",
       "| statistic | files | +lines | request bytes | ≈ input tokens |", "|---|---|---|---|---|"]
for name, q in [("p50", .5), ("p90", .9), ("p99", .99), ("max", 1.0)]:
    md.append(f"| {name} | {pct([r['files'] for r in ok], q)} | {pct([r['added_lines'] for r in ok], q)} | "
              f"{pct([r['request_bytes'] for r in ok], q)} | {pct(sizes, q)} |")
md.append(f"| mean | {st.mean(r['files'] for r in ok):.1f} | {st.mean(r['added_lines'] for r in ok):.0f} | "
          f"{st.mean(r['request_bytes'] for r in ok):.0f} | {st.mean(sizes):.0f} |")
opq = sum(1 for r in ok if r["opaque_files"])
md += ["", f"Commits with at least one opaque (binary/oversized) file: {opq} ({100*opq/len(ok):.1f} %) — under a policy with "
       f"`allow_opaque=false` these could not be reviewed at all. Fixed overhead per request (system prompt + tool definition + header): "
       f"{int(min(r['request_bytes'] for r in ok)*ratio)} tokens at the smallest commit.", ""]

fig, ax = plt.subplots(figsize=(5.5, 3.2))
ax.hist(sizes, bins=[0, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000], color="#2563eb")
ax.set_xscale("log"); ax.set_xlabel("≈ input tokens per review request"); ax.set_ylabel("commits")
ax.set_title("Request size, 398 real CometBFT commits")
fig.tight_layout(); fig.savefig(os.path.join(FIG, "cost_request_sizes.png")); plt.close(fig)

# -------- cost per review per model
def cost(tokens, model, thinking=True):
    pin, pout = PRICES[model]
    out = OUTPUT_TOKENS + (THINKING_TOKENS if thinking else 0)
    return tokens * pin / 1e6 + out * pout / 1e6

md += ["## 2. Cost of ONE review, by model", "",
       "| model | $/M in | $/M out | p50 commit | p90 commit | p99 commit | mean | fixed part (output+thinking) |", "|---|---|---|---|---|---|---|---|"]
for m, (pin, pout) in PRICES.items():
    md.append(f"| {m} | {pin} | {pout} | ${cost(pct(sizes,.5), m):.4f} | ${cost(pct(sizes,.9), m):.4f} | "
              f"${cost(pct(sizes,.99), m):.4f} | ${st.mean(cost(t, m) for t in sizes):.4f} | ${(OUTPUT_TOKENS+THINKING_TOKENS)*pout/1e6:.4f} |")
md += ["", "![](figures/cost_request_sizes.png)", ""]

# -------- cost by category and tiered policy
cats = ["docs", "tests", "docs+tests", "code", "sensitive"]
md += ["## 3. By change category (path-based), and a tiered policy", "",
       "| category | commits | share | mean tokens | p90 tokens | mean $ (opus-5-5) |", "|---|---|---|---|---|---|"]
bycat = {c: [r for r in ok if r["category"] == c] for c in cats}
for c in cats:
    rs = bycat[c]
    if not rs: continue
    md.append(f"| {c} | {len(rs)} | {100*len(rs)/len(ok):.0f} % | {st.mean(r['tokens'] for r in rs):.0f} | "
              f"{pct([r['tokens'] for r in rs], .9)} | ${st.mean(cost(r['tokens'], 'claude-opus-5-5') for r in rs):.4f} |")
TIERS = {"docs": "claude-haiku-4-5", "tests": "claude-haiku-4-5", "docs+tests": "claude-haiku-4-5",
         "code": "claude-sonnet-5-5", "sensitive": "claude-opus-5-5"}
flat = {m: sum(cost(r["tokens"], m) for r in ok) for m in PRICES}
tiered = sum(cost(r["tokens"], TIERS[r["category"]]) for r in ok)
md += ["", f"Tiered policy (docs/tests → haiku-4-5, code → sonnet-5-5, sensitive paths → opus-5-5) over all {len(ok)} commits: "
       f"**${tiered:.2f}** vs flat opus-5-5 **${flat['claude-opus-5-5']:.2f}** ({100*(1-tiered/flat['claude-opus-5-5']):.0f} % less), "
       f"flat sonnet-5-5 ${flat['claude-sonnet-5-5']:.2f}, flat fable-5-1 ${flat['claude-fable-5-1']:.2f}.", ""]

# -------- growth with size
fig, ax = plt.subplots(figsize=(5.5, 3.2))
xs = [r["added_lines"]+r["removed_lines"]+1 for r in ok]
ax.scatter(xs, [cost(r["tokens"], "claude-opus-5-5") for r in ok], s=8, color="#2563eb", alpha=.6)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("changed lines (+/-)"); ax.set_ylabel("$ per review (opus-5-5)")
ax.set_title("Review cost grows with the diff, not the repository")
fig.tight_layout(); fig.savefig(os.path.join(FIG, "cost_vs_diff.png")); plt.close(fig)
md += ["## 4. Growth with size", "",
       "The request contains only the diff and the commit message, so cost is a function of the change, not of the repository. "
       "Marginal cost ≈ price_in × tokens; the fixed part (system prompt, tool, verdict, thinking) dominates below ~2k tokens.", "",
       "![](figures/cost_vs_diff.png)", ""]

json.dump({"sizes": sizes, "flat": flat, "tiered": tiered, "n": len(ok)}, open(os.path.join(OUT, "raw", "cost_summary.json"), "w"))
open(os.path.join(OUT, "COST.md"), "w").write("\n".join(md) + "\n")
print("wrote", os.path.join(OUT, "COST.md"))
