package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type agg struct {
	calls, approve, reject, errs int
	errKinds                     map[string]int
	inTok, outTok                int
	latency, upstream, cost      float64
}

func (a *agg) add(r *CallRecord) {
	if a.errKinds == nil {
		a.errKinds = map[string]int{}
	}
	a.calls++
	switch r.Verdict {
	case "approve":
		a.approve++
	case "reject":
		a.reject++
	default:
		a.errs++
		a.errKinds[r.ErrorKind]++
	}
	a.inTok += r.InputTokens
	a.outTok += r.OutputTokens
	a.latency += r.LatencyMs
	a.upstream += r.UpstreamMs
	a.cost += r.CostUSD
}

func (a *agg) rate() string {
	if a.approve+a.reject == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(a.approve)/float64(a.approve+a.reject))
}

func pct(n, d int) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%% (%d/%d)", 100*float64(n)/float64(d), n, d)
}

// summarize renders the summary tables as Markdown.
func summarize(recs []*CallRecord, providerName, model, mockRule string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PR study run summary\n\n")
	if providerName == "mock" {
		fmt.Fprintf(&b, "**MOCK PROVIDER (verdict rule `%s`). The verdicts below are synthetic (a marker rule or a Bernoulli coin) and say NOTHING about any model's review quality. This run only demonstrates that the pipeline works end to end; token counts are the mock's ceil(bytes/4) estimate, latency is the mock's assumed latency model.**\n\n", mockRule)
	} else {
		fmt.Fprintf(&b, "Provider `%s`, model `%s`. Costs use the price table in cmd/dosr-prstudy/run.go (list prices cached 2026-09-25; verify before quoting).\n\n", providerName, model)
	}
	variants := map[string]bool{}
	classes := map[string]bool{}
	subclasses := map[string]string{}
	for _, r := range recs {
		variants[r.Variant] = true
		classes[r.Class] = true
		if r.Subclass != "" {
			subclasses[r.Subclass] = r.Class
		}
	}
	var vnames []string
	for v := range variants {
		vnames = append(vnames, v)
	}
	sort.Strings(vnames)
	var cnames []string
	for _, c := range classOrder {
		if classes[c] {
			cnames = append(cnames, c)
		}
	}
	for c := range classes {
		found := false
		for _, k := range classOrder {
			if k == c {
				found = true
			}
		}
		if !found {
			cnames = append(cnames, c)
		}
	}

	// 1. Approval rate per class x variant, with tokens/latency/cost.
	fmt.Fprintf(&b, "## 1. Calls, approval rate, cost per class and variant\n\n")
	fmt.Fprintf(&b, "| variant | class | calls | approve | reject | errors | approval rate | mean in tok | mean out tok | mean latency ms | mean upstream ms | mean cost $ | total cost $ |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	byVC := map[string]map[string]*agg{}
	byV := map[string]*agg{}
	for _, r := range recs {
		if byVC[r.Variant] == nil {
			byVC[r.Variant] = map[string]*agg{}
		}
		if byVC[r.Variant][r.Class] == nil {
			byVC[r.Variant][r.Class] = &agg{}
		}
		byVC[r.Variant][r.Class].add(r)
		if byV[r.Variant] == nil {
			byV[r.Variant] = &agg{}
		}
		byV[r.Variant].add(r)
	}
	for _, v := range vnames {
		for _, c := range cnames {
			a := byVC[v][c]
			if a == nil {
				continue
			}
			n := float64(a.calls)
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %s | %.0f | %.0f | %.0f | %.0f | %.4f | %.2f |\n",
				v, c, a.calls, a.approve, a.reject, a.errs, a.rate(), float64(a.inTok)/n, float64(a.outTok)/n, a.latency/n, a.upstream/n, a.cost/n, a.cost)
		}
		a := byV[v]
		n := float64(a.calls)
		fmt.Fprintf(&b, "| %s | **all** | %d | %d | %d | %d | %s | %.0f | %.0f | %.0f | %.0f | %.4f | %.2f |\n",
			v, a.calls, a.approve, a.reject, a.errs, a.rate(), float64(a.inTok)/n, float64(a.outTok)/n, a.latency/n, a.upstream/n, a.cost/n, a.cost)
	}

	// 2. Confusion matrix per variant.
	fmt.Fprintf(&b, "\n## 2. Confusion matrix per variant\n\n")
	fmt.Fprintf(&b, "good = expected approve; bad = expected reject (all other classes). False accept = bad approved (final and public in DOSR); false reject = good rejected (costs one review). \"hard\" excludes the soft-expectation low-effort cases (message \"fix\", whitespace-only) whose rejection depends on the prompt demanding it.\n\n")
	fmt.Fprintf(&b, "| variant | good approved (TP) | good rejected (FN) | bad approved (FP) | bad rejected (TN) | false-accept rate | false-accept rate (hard) | false-reject rate | no-verdict rate |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, v := range vnames {
		var tp, fn, fp, tn, fpHard, tnHard, errs, calls int
		for _, r := range recs {
			if r.Variant != v {
				continue
			}
			calls++
			if r.Verdict == "error" {
				errs++
				continue
			}
			good := r.Expected == "approve"
			switch {
			case good && r.Verdict == "approve":
				tp++
			case good:
				fn++
			case r.Verdict == "approve":
				fp++
				if !r.Soft {
					fpHard++
				}
			default:
				tn++
				if !r.Soft {
					tnHard++
				}
			}
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %s | %s | %s | %s |\n", v, tp, fn, fp, tn, pct(fp, fp+tn), pct(fpHard, fpHard+tnHard), pct(fn, tp+fn), pct(errs, calls))
	}

	// 3. Per subclass (mutation operator): approval rate = false-accept rate for bad classes.
	fmt.Fprintf(&b, "\n## 3. Approval rate per mutation operator and variant\n\n")
	var snames []string
	for s := range subclasses {
		snames = append(snames, s)
	}
	sort.Slice(snames, func(i, j int) bool {
		ci, cj := classIndex(subclasses[snames[i]]), classIndex(subclasses[snames[j]])
		if ci != cj {
			return ci < cj
		}
		return snames[i] < snames[j]
	})
	fmt.Fprintf(&b, "| class | operator | n cases |")
	for _, v := range vnames {
		fmt.Fprintf(&b, " %s |", v)
	}
	fmt.Fprintf(&b, "\n|---|---|---|")
	for range vnames {
		fmt.Fprintf(&b, "---|")
	}
	fmt.Fprintf(&b, "\n")
	for _, s := range snames {
		cases := map[string]bool{}
		for _, r := range recs {
			if r.Subclass == s {
				cases[r.CaseID] = true
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %d |", subclasses[s], s, len(cases))
		for _, v := range vnames {
			a := &agg{}
			for _, r := range recs {
				if r.Subclass == s && r.Variant == v {
					a.add(r)
				}
			}
			fmt.Fprintf(&b, " %s |", a.rate())
		}
		fmt.Fprintf(&b, "\n")
	}

	// 4. Errors by kind.
	fmt.Fprintf(&b, "\n## 4. Calls without a usable verdict, by kind and variant\n\n")
	kinds := map[string]bool{}
	for _, r := range recs {
		if r.ErrorKind != "" {
			kinds[r.ErrorKind] = true
		}
	}
	if len(kinds) == 0 {
		fmt.Fprintf(&b, "none\n")
	} else {
		var knames []string
		for k := range kinds {
			knames = append(knames, k)
		}
		sort.Strings(knames)
		fmt.Fprintf(&b, "| variant |")
		for _, k := range knames {
			fmt.Fprintf(&b, " %s |", k)
		}
		fmt.Fprintf(&b, "\n|---|")
		for range knames {
			fmt.Fprintf(&b, "---|")
		}
		fmt.Fprintf(&b, "\n")
		for _, v := range vnames {
			fmt.Fprintf(&b, "| %s |", v)
			for _, k := range knames {
				fmt.Fprintf(&b, " %d |", byV[v].errKinds[k])
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	// 5. Variance across repeats.
	type key struct{ c, v string }
	groups := map[key][]*CallRecord{}
	maxRep := 0
	for _, r := range recs {
		groups[key{r.CaseID, r.Variant}] = append(groups[key{r.CaseID, r.Variant}], r)
		if r.Repeat+1 > maxRep {
			maxRep = r.Repeat + 1
		}
	}
	if maxRep > 1 {
		fmt.Fprintf(&b, "\n## 5. Verdict variance across %d repeats (same request bytes, same model)\n\n", maxRep)
		fmt.Fprintf(&b, "A (case, variant) pair is *mixed* when its repeats did not all give the same verdict. \"P(any approve)\" over bad cases is the grinding exposure: the chance that a contributor who retries %d times gets at least one certificate.\n\n", maxRep)
		fmt.Fprintf(&b, "| variant | class | pairs | pairs with >=2 verdicts | mixed | P(any approve) | P(all approve) |\n|---|---|---|---|---|---|---|\n")
		for _, v := range vnames {
			for _, c := range cnames {
				pairs, with2, mixed, anyA, allA := 0, 0, 0, 0, 0
				for k, g := range groups {
					if k.v != v || g[0].Class != c {
						continue
					}
					pairs++
					var vs []string
					for _, r := range g {
						if r.Verdict != "error" {
							vs = append(vs, r.Verdict)
						}
					}
					if len(vs) == 0 {
						continue
					}
					na := 0
					for _, x := range vs {
						if x == "approve" {
							na++
						}
					}
					if na > 0 {
						anyA++
					}
					if na == len(vs) {
						allA++
					}
					if len(vs) >= 2 {
						with2++
						if na != 0 && na != len(vs) {
							mixed++
						}
					}
				}
				if pairs == 0 {
					continue
				}
				fmt.Fprintf(&b, "| %s | %s | %d | %d | %s | %s | %s |\n", v, c, pairs, with2, pct(mixed, with2), pct(anyA, pairs), pct(allA, pairs))
			}
		}
	}
	return b.String()
}

func classIndex(c string) int {
	for i, k := range classOrder {
		if k == c {
			return i
		}
	}
	return len(classOrder)
}

// cmdSummarize re-renders the summary of an existing run.
func cmdSummarize(args []string) error {
	fs := flag.NewFlagSet("summarize", flag.ExitOnError)
	in := fs.String("in", "", "run JSONL")
	fs.Parse(args)
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	var recs []*CallRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		r := &CallRecord{}
		if err := json.Unmarshal(sc.Bytes(), r); err != nil {
			return err
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return fmt.Errorf("no records")
	}
	md := summarize(recs, recs[0].Provider, recs[0].Model, "(see run)")
	out := strings.TrimSuffix(*in, ".jsonl") + ".summary.md"
	if err := os.WriteFile(out, []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Print(md)
	return nil
}
