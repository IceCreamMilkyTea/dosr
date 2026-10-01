// Command dosr-prstudy builds a corpus of real and mutated commits and
// runs DOSR's canonical review request over it through the notary, to
// measure how an LLM reviewer behaves on good, low-effort, harmful and
// prompt-injected changes under different policy prompts.
//
//	dosr-prstudy build    -repo reference/cometbft -good 60 -out eval/prstudy/corpus
//	dosr-prstudy estimate -corpus eval/prstudy/corpus -variants 4 -repeat 1
//	dosr-prstudy run      -corpus eval/prstudy/corpus -variants default,security -repeat 2 -out eval/prstudy/runs/mock
//	dosr-prstudy summarize -in eval/prstudy/runs/mock.jsonl
//
// run talks to the real provider when DOSR_PROVIDER_HOST and DOSR_API_KEY
// are set (optionally DOSR_NOTARY_URL for an external notary); otherwise
// it starts the mock provider and a notary in-process. Mock verdicts are
// synthetic and say nothing about model quality. See eval/prstudy/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/dosr/dosr/pkg/review"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "build":
		err = cmdBuild(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "summarize":
		err = cmdSummarize(os.Args[2:])
	case "estimate":
		err = cmdEstimate(os.Args[2:])
	case "variants":
		for _, v := range variantNames() {
			fmt.Printf("== %s ==\n%s\n\n", v, variants[v])
		}
		fmt.Printf("== fixed protocol suffix (review.SystemSuffix, appended to every variant) ==\n%s\n", review.SystemSuffix)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dosr-prstudy:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dosr-prstudy build|estimate|run|summarize|variants [flags]")
	os.Exit(2)
}

// cmdEstimate prints the token totals of the corpus and the cost of a run
// per model, from the corpus' size estimates (no provider involved).
func cmdEstimate(args []string) error {
	fs := flag.NewFlagSet("estimate", flag.ExitOnError)
	corpusDir := fs.String("corpus", "eval/prstudy/corpus", "corpus directory")
	nVariants := fs.Int("variants", 4, "number of prompt variants in the run")
	repeat := fs.Int("repeat", 1, "repeats per (case, variant)")
	outTok := fs.Int("out-tokens", 1800, "assumed billed output tokens per call (300 summary + 1500 thinking, the assumption of eval/results/COST.md)")
	tpb := fs.Float64("tokens-per-byte", tokensPerByteDefault, "assumed tokens per request byte")
	fs.Parse(args)

	corpus, err := OpenCorpus(*corpusDir)
	if err != nil {
		return err
	}
	// Input tokens per variant: the stored request differs between
	// variants only by the system prompt length and the policy hash.
	defLen := len(variants["default"])
	byClass := map[string]int{}
	var sub []string
	bySub := map[string]int{}
	totalIn := 0.0
	for _, cs := range corpus.Cases {
		byClass[cs.Class]++
		if cs.Subclass != "" {
			if bySub[cs.Subclass] == 0 {
				sub = append(sub, cs.Subclass)
			}
			bySub[cs.Subclass]++
		}
		for _, v := range variantNames()[:min(*nVariants, len(variants))] {
			totalIn += float64(cs.RequestBytes-defLen+len(variants[v])) * *tpb
		}
	}
	sort.Strings(sub)
	calls := len(corpus.Cases) * *nVariants * *repeat
	totalIn *= float64(*repeat)
	totalOut := float64(calls * *outTok)
	fmt.Printf("corpus: %d cases\n", len(corpus.Cases))
	for _, c := range classOrder {
		if byClass[c] > 0 {
			fmt.Printf("  %-18s %d\n", c, byClass[c])
		}
	}
	for _, s := range sub {
		fmt.Printf("    %-24s %d\n", s, bySub[s])
	}
	fmt.Printf("run: %d calls (%d cases x %d variants x %d repeats)\n", calls, len(corpus.Cases), *nVariants, *repeat)
	fmt.Printf("estimated input tokens: %.0f (%.0f per call); assumed output tokens: %.0f (%d per call)\n", totalIn, totalIn/float64(calls), totalOut, *outTok)
	fmt.Printf("estimated cost (list prices cached 2026-09-25, verify before quoting):\n")
	var models []string
	for m := range realPrices {
		models = append(models, m)
	}
	sort.Strings(models)
	for _, m := range models {
		p := realPrices[m]
		c := (totalIn*p.InputPerMTok + totalOut*p.OutputPerMTok) / 1e6
		fmt.Printf("  %-20s $%.2f  (in $%.2f + out $%.2f)\n", m, c, totalIn*p.InputPerMTok/1e6, totalOut*p.OutputPerMTok/1e6)
	}
	fmt.Println(strings.TrimSpace(`
Notes: input tokens = request bytes x tokens-per-byte (ratio measured with
tiktoken cl100k_base in eval/results/COST.md; the provider's tokenizer
differs). Output tokens are an assumption: thinking tokens are billed as
output on models that always think, and a review that reasons at length
costs more. No prompt caching is assumed (every request has a different
policy hash / boundary, and the shared prefix is only the system prompt).`))
	return nil
}
