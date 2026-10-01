package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/bench"
	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/llm"
	"github.com/dosr/dosr/pkg/notary"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/types"
)

// CallRecord is one attested review call.
type CallRecord struct {
	CaseID   string `json:"case_id"`
	Class    string `json:"class"`
	Subclass string `json:"subclass,omitempty"`
	Expected string `json:"expected"`
	Soft     bool   `json:"soft_expectation,omitempty"`
	Variant  string `json:"variant"`
	Repeat   int    `json:"repeat"`
	Provider string `json:"provider"` // "mock" or the real host

	Model         string `json:"model"`
	ResponseModel string `json:"response_model,omitempty"`
	// Verdict is "approve", "reject" or "error" (no usable verdict).
	Verdict string `json:"verdict"`
	// ErrorKind classifies a missing verdict: notary_error, http_<status>,
	// truncated, refusal, no_tool_call, parse_error, wrong_candidate,
	// model_mismatch.
	ErrorKind   string `json:"error_kind,omitempty"`
	ErrorDetail string `json:"error_detail,omitempty"`
	// Correct is set when a verdict was obtained: verdict == expected.
	Correct *bool `json:"correct,omitempty"`

	RequestBytes   int     `json:"request_bytes"`
	InputTokens    int     `json:"input_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	LatencyMs      float64 `json:"latency_ms"`         // client wall time of the attested call
	UpstreamMs     float64 `json:"upstream_ms"`        // notary-measured provider time
	NotaryOverhead float64 `json:"notary_overhead_ms"` // notary total - upstream
	CostUSD        float64 `json:"cost_usd"`
	Retries        int     `json:"retries,omitempty"`
	StopReason     string  `json:"stop_reason,omitempty"`
	Summary        string  `json:"summary,omitempty"`
}

// price table, USD per million tokens. List prices as cached 2026-09-25;
// verify before quoting. Thinking tokens are billed as output tokens.
var realPrices = map[string]llm.Price{
	"claude-opus-5-5":   {InputPerMTok: 4, OutputPerMTok: 20},
	"claude-sonnet-5-5": {InputPerMTok: 2, OutputPerMTok: 10},
	"claude-haiku-4-5":  {InputPerMTok: 1, OutputPerMTok: 5},
	"claude-fable-5-1":  {InputPerMTok: 10, OutputPerMTok: 50},
}

func priceFor(model string, override string) (llm.Price, bool) {
	if override != "" {
		parts := strings.Split(override, ",")
		if len(parts) == 2 {
			in, e1 := strconv.ParseFloat(parts[0], 64)
			out, e2 := strconv.ParseFloat(parts[1], 64)
			if e1 == nil && e2 == nil {
				return llm.Price{InputPerMTok: in, OutputPerMTok: out}, true
			}
		}
	}
	if p, ok := realPrices[model]; ok {
		return p, true
	}
	if p, ok := llm.DefaultPrices()[model]; ok {
		return p, true
	}
	return llm.Price{}, false
}

// provider is where the calls go.
type provider struct {
	name    string // "mock" or host
	host    string
	apiKey  string
	notaryC *notary.Client
	close   func()
}

// setupProvider returns the real provider if DOSR_PROVIDER_HOST and
// DOSR_API_KEY are set (with DOSR_NOTARY_URL naming an external notary,
// or an in-process notary that allow-lists the host and uses the system
// roots), otherwise an in-process mock provider plus notary.
func setupProvider(mockVerdict string, mockLatency string, seed int64, parallel int) (*provider, error) {
	host, key := os.Getenv("DOSR_PROVIDER_HOST"), os.Getenv("DOSR_API_KEY")
	if host != "" && key != "" {
		canon, err := notary.CanonicalHost(host)
		if err != nil {
			return nil, err
		}
		p := &provider{name: canon, host: canon, apiKey: key, close: func() {}}
		if u := os.Getenv("DOSR_NOTARY_URL"); u != "" {
			p.notaryC = notary.NewClient(u)
			return p, nil
		}
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		srv, err := notary.NewServer(notary.Config{Key: sk, AllowedHosts: []string{canon}, RootCAs: nil,
			MaxConcurrent: parallel + 2, UpstreamTimeout: 10 * time.Minute, MaxResponseBytes: 8 << 20})
		if err != nil {
			return nil, err
		}
		if err := srv.Start("127.0.0.1:0"); err != nil {
			return nil, err
		}
		p.notaryC = notary.NewClient(srv.URL())
		p.close = func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		}
		return p, nil
	}
	if host != "" || key != "" {
		return nil, errors.New("set both DOSR_PROVIDER_HOST and DOSR_API_KEY for a real provider")
	}
	var verdict llm.VerdictFunc
	switch {
	case mockVerdict == "marker" || mockVerdict == "":
		verdict = llm.MarkerVerdict
	case strings.HasPrefix(mockVerdict, "bernoulli:"):
		pa, err := strconv.ParseFloat(strings.TrimPrefix(mockVerdict, "bernoulli:"), 64)
		if err != nil {
			return nil, fmt.Errorf("bad -mock-verdict: %w", err)
		}
		verdict = llm.BernoulliVerdict(pa, llm.NewRand(seed))
	default:
		return nil, fmt.Errorf("unknown -mock-verdict %q (marker | bernoulli:<p>)", mockVerdict)
	}
	lat := llm.LatencyNone
	switch mockLatency {
	case "fast":
		lat = llm.LatencyFast
	case "realistic":
		lat = llm.LatencyRealistic
	case "none", "":
	default:
		return nil, fmt.Errorf("unknown -mock-latency %q", mockLatency)
	}
	st, err := bench.StartStack(lat, verdict, false)
	if err != nil {
		return nil, err
	}
	return &provider{name: "mock", host: st.Host, apiKey: st.APIKey, notaryC: st.NotaryC, close: st.Close}, nil
}

type job struct {
	cs      *Case
	variant string
	repeat  int
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	corpusDir := fs.String("corpus", "eval/prstudy/corpus", "corpus directory")
	out := fs.String("out", "eval/prstudy/runs/run", "output prefix (<prefix>.jsonl and <prefix>.summary.md)")
	variantsFlag := fs.String("variants", "default,security,minimal,risk", "comma-separated prompt variants")
	repeat := fs.Int("repeat", 1, "calls per (case, variant), to measure verdict variance")
	model := fs.String("model", "", "model id (default: mock-reviewer-medium for the mock; required for a real provider)")
	maxTokens := fs.Int("max-tokens", 16384, "policy max_tokens (thinking tokens count against it on models that always think; a truncated answer is no verdict)")
	maxDiff := fs.Int("max-diff-bytes", 1<<20, "policy max_diff_bytes")
	parallel := fs.Int("parallel", 4, "concurrent calls")
	limit := fs.Int("limit", 0, "only the first N cases (0 = all)")
	classes := fs.String("classes", "", "only these classes (comma-separated; empty = all)")
	priceOverride := fs.String("price", "", "override price as in,out USD per Mtok")
	mockVerdict := fs.String("mock-verdict", "bernoulli:0.7", "mock verdict rule: marker | bernoulli:<p>")
	mockLatency := fs.String("mock-latency", "fast", "mock latency model: none | fast | realistic")
	seed := fs.Int64("seed", 1, "seed of the mock verdict generator")
	fs.Parse(args)

	corpus, err := OpenCorpus(*corpusDir)
	if err != nil {
		return err
	}
	prov, err := setupProvider(*mockVerdict, *mockLatency, *seed, *parallel)
	if err != nil {
		return err
	}
	defer prov.close()
	if *model == "" {
		if prov.name != "mock" {
			return errors.New("-model is required with a real provider (e.g. claude-sonnet-5-5)")
		}
		*model = llm.ModelMedium
	}
	price, priced := priceFor(*model, *priceOverride)
	if !priced {
		fmt.Fprintf(os.Stderr, "warning: no price known for %s; cost will be 0 (use -price in,out)\n", *model)
	}
	if prov.name == "mock" {
		fmt.Fprintf(os.Stderr, "MOCK PROVIDER (verdict rule %q): verdicts are synthetic and say NOTHING about any model's review quality; this run only exercises the pipeline.\n", *mockVerdict)
	} else {
		fmt.Fprintf(os.Stderr, "real provider %s, model %s, price $%g/$%g per Mtok (verify before quoting)\n", prov.name, *model, price.InputPerMTok, price.OutputPerMTok)
	}

	vnames := strings.Split(*variantsFlag, ",")
	pols := map[string]policyBundle{}
	for _, v := range vnames {
		pol, err := policyFor(v, prov.host, *model, *maxTokens, *maxDiff)
		if err != nil {
			return err
		}
		pols[v] = policyBundle{pol: pol, hash: pol.Hash()}
	}
	classFilter := map[string]bool{}
	for _, c := range strings.Split(*classes, ",") {
		if c != "" {
			classFilter[c] = true
		}
	}
	var jobs []job
	n := 0
	for _, cs := range corpus.Cases {
		if len(classFilter) > 0 && !classFilter[cs.Class] {
			continue
		}
		n++
		if *limit > 0 && n > *limit {
			break
		}
		for _, v := range vnames {
			for r := 0; r < *repeat; r++ {
				jobs = append(jobs, job{cs, v, r})
			}
		}
	}
	fmt.Fprintf(os.Stderr, "%d calls (%d cases x %d variants x %d repeats)\n", len(jobs), n-boolInt(*limit > 0 && n > *limit), len(vnames), *repeat)

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	f, err := os.Create(*out + ".jsonl")
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	var mu sync.Mutex
	var recs []*CallRecord
	done := 0
	var wg sync.WaitGroup
	ch := make(chan job)
	for i := 0; i < *parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				rec := runOne(corpus, prov, pols[j.variant], j, *model, price)
				mu.Lock()
				recs = append(recs, rec)
				b, _ := json.Marshal(rec)
				w.Write(b)
				w.WriteByte('\n')
				done++
				if done%25 == 0 || done == len(jobs) {
					w.Flush()
					fmt.Fprintf(os.Stderr, "  %d/%d\n", done, len(jobs))
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].CaseID != recs[j].CaseID {
			return recs[i].CaseID < recs[j].CaseID
		}
		if recs[i].Variant != recs[j].Variant {
			return recs[i].Variant < recs[j].Variant
		}
		return recs[i].Repeat < recs[j].Repeat
	})
	md := summarize(recs, prov.name, *model, *mockVerdict)
	if err := os.WriteFile(*out+".summary.md", []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Print(md)
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type policyBundle struct {
	pol  types.Policy
	hash types.PolicyHash
}

// looseResponse is the part of a Messages API response the study records
// besides what review.ParseResponse checks.
type looseResponse struct {
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// runOne renders the canonical request for (case, variant), sends it
// through the notary exactly as the contributor client does, and records
// the outcome. Transient provider errors (429, 5xx, 529) are retried with
// backoff; everything else is recorded as is.
func runOne(corpus *Corpus, prov *provider, pb policyBundle, j job, model string, price llm.Price) *CallRecord {
	cs := j.cs
	rec := &CallRecord{CaseID: cs.ID, Class: cs.Class, Subclass: cs.Subclass, Expected: cs.Expected, Soft: cs.Soft,
		Variant: j.variant, Repeat: j.repeat, Provider: prov.name, Model: model, Verdict: "error"}
	body, err := review.BuildRequestBody(&pb.pol, review.Params{ChainID: "prstudy", RepoID: "cometbft", Branch: "main",
		Base: cs.Base, Candidate: cs.Candidate, PolicyHash: pb.hash, Model: model}, cs.Message, cs.Changes, corpus.Store)
	if err != nil {
		rec.ErrorKind, rec.ErrorDetail = "render_error", err.Error()
		return rec
	}
	rec.RequestBytes = len(body)
	req := &notary.Request{
		URL: "https://" + prov.host + "/v1/messages", Method: "POST",
		Headers: map[string]string{"content-type": "application/json", "anthropic-version": client.AnthropicVersion, "x-api-key": prov.apiKey},
		Body:    body,
	}
	var ares *notary.Response
	var status, respBody []byte
	backoff := 2 * time.Second
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		t := time.Now()
		ares, err = prov.notaryC.AttestTimed(ctx, req)
		rec.LatencyMs = float64(time.Since(t).Microseconds()) / 1000
		cancel()
		if err != nil {
			var ne *notary.Error
			if errors.As(err, &ne) && (ne.Code == notary.CodeBusy || ne.Code == notary.CodeUpstreamUnreachable || ne.Code == notary.CodeUpstreamTimeout) && attempt < 5 {
				time.Sleep(backoff)
				backoff *= 2
				rec.Retries++
				continue
			}
			rec.ErrorKind, rec.ErrorDetail = "notary_error", err.Error()
			return rec
		}
		status, respBody = nil, nil
		for i, n := range ares.Secret.Names {
			switch n {
			case attest.FieldRespStatus:
				status = ares.Secret.Values[i]
			case attest.FieldRespBody:
				respBody = ares.Secret.Values[i]
			}
		}
		st := string(status)
		if (st == "429" || st == "500" || st == "502" || st == "503" || st == "529") && attempt < 5 {
			time.Sleep(backoff)
			backoff *= 2
			rec.Retries++
			continue
		}
		break
	}
	rec.UpstreamMs = float64(ares.Timing.UpstreamNs) / 1e6
	rec.NotaryOverhead = float64(ares.Timing.TotalNs-ares.Timing.UpstreamNs) / 1e6

	var lr looseResponse
	_ = json.Unmarshal(respBody, &lr)
	rec.ResponseModel, rec.StopReason = lr.Model, lr.StopReason
	rec.InputTokens, rec.OutputTokens = lr.Usage.InputTokens, lr.Usage.OutputTokens
	rec.CostUSD = (float64(rec.InputTokens)*price.InputPerMTok + float64(rec.OutputTokens)*price.OutputPerMTok) / 1e6

	if string(status) != "200" {
		rec.ErrorKind = "http_" + string(status)
		if lr.Error != nil {
			rec.ErrorDetail = lr.Error.Type + ": " + lr.Error.Message
		} else {
			rec.ErrorDetail = truncate(respBody, 200)
		}
		return rec
	}
	v, err := review.ParseResponse(respBody)
	if err != nil {
		switch lr.StopReason {
		case "max_tokens":
			rec.ErrorKind = "truncated"
		case "refusal":
			rec.ErrorKind = "refusal"
		case "end_turn":
			rec.ErrorKind = "no_tool_call"
		default:
			rec.ErrorKind = "parse_error"
		}
		rec.ErrorDetail = err.Error()
		return rec
	}
	rec.Summary = truncate([]byte(v.Summary), 300)
	if v.Candidate != cs.Candidate {
		rec.ErrorKind = "wrong_candidate"
		rec.ErrorDetail = "model echoed " + v.Candidate.String()
		return rec
	}
	if v.Model != model {
		rec.ErrorKind = "model_mismatch"
		rec.ErrorDetail = "response model " + v.Model
		return rec
	}
	if v.Approve {
		rec.Verdict = "approve"
	} else {
		rec.Verdict = "reject"
	}
	c := rec.Verdict == cs.Expected
	rec.Correct = &c
	return rec
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
