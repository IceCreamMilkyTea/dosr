// Package bench contains DOSR's evaluation experiments. Each experiment
// starts the whole stack (testnet, mock provider, notary), drives
// contributors, and writes a Result with raw samples; eval/plot.py turns
// the results into tables and figures.
//
// All latency numbers come from one machine with emulated links; the mock
// provider's latency model is an assumption (see pkg/llm). What the
// experiments measure faithfully is the DOSR protocol's own overhead and
// behaviour, not the absolute speed of a production deployment.
package bench

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/llm"
	"github.com/dosr/dosr/pkg/node"
	"github.com/dosr/dosr/pkg/notary"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/testnet"
	"github.com/dosr/dosr/pkg/types"
)

// Result is the output of one experiment configuration.
type Result struct {
	Experiment string         `json:"experiment"`
	Params     map[string]any `json:"params"`
	StartedAt  time.Time      `json:"started_at"`
	Duration   time.Duration  `json:"duration_ns"`
	Samples    []Sample       `json:"samples"`
	Summary    map[string]any `json:"summary"`
	Notes      []string       `json:"notes,omitempty"`
}

// Sample is one submission.
type Sample struct {
	Index       int             `json:"i"`
	Contributor string          `json:"contributor,omitempty"`
	Outcome     *client.Outcome `json:"outcome,omitempty"`
	Err         string          `json:"err,omitempty"`
	// SubmittedAt is the client's wall clock at the start of Submit.
	SubmittedAt time.Time `json:"submitted_at"`
	// DecidedFirstNs / DecidedAllNs: time from SubmittedAt until the
	// first / the last honest running node committed the deciding
	// block (propagation), from the nodes' commit records.
	DecidedFirstNs int64 `json:"decided_first_ns,omitempty"`
	DecidedAllNs   int64 `json:"decided_all_ns,omitempty"`
	// Rounds the deciding height needed (1 = no failed round).
	Rounds int32 `json:"rounds,omitempty"`
	// Attempts for contention: how many reviews this accepted change cost.
	Attempts int `json:"attempts,omitempty"`
	// Extra per-sample data.
	Extra map[string]any `json:"extra,omitempty"`
}

// Options common to all experiments.
type Options struct {
	OutDir string
	Quick  bool // fewer repetitions
	Log    func(format string, a ...any)
}

func (o Options) logf(format string, a ...any) {
	if o.Log != nil {
		o.Log(format, a...)
	}
}

func (o Options) reps(full, quick int) int {
	if o.Quick {
		return quick
	}
	return full
}

// Save writes a result as JSON.
func (o Options) Save(r *Result, name string) error {
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(o.OutDir, name+".json"), b, 0o644)
}

// ---------------------------------------------------------------- stack

// Stack is the off-chain part: provider, notary, keys.
type Stack struct {
	Provider *llm.Server
	Notary   *notary.Server
	NotaryC  *notary.Client
	Host     string
	SPKI     []byte
	APIKey   string
	NotaryK  ed25519.PrivateKey
	ca       *llm.CA
}

// StartStack starts the provider (with the given latency model) and a
// notary that trusts it.
func StartStack(lat llm.LatencyModel, verdict llm.VerdictFunc, nonces bool) (*Stack, error) {
	ca, cert, err := llm.NewLocalhostTLS()
	if err != nil {
		return nil, err
	}
	s := &Stack{APIKey: "sk-bench", NotaryK: dosrtest.Key("bench-notary"), ca: ca}
	cfg := llm.Config{APIKeys: []string{s.APIKey}, Certificate: &cert, Latency: lat, Seed: 7, TargetOutputTokens: 300}
	if verdict != nil {
		cfg.Verdict = verdict
	}
	if s.Provider, err = llm.NewServer(cfg); err != nil {
		return nil, err
	}
	if err := s.Provider.Start("127.0.0.1:0"); err != nil {
		return nil, err
	}
	if s.Host, err = notary.CanonicalHost(s.Provider.Addr()); err != nil {
		return nil, err
	}
	s.SPKI, _ = llm.SPKIHash(cert)
	s.Notary, err = notary.NewServer(notary.Config{
		Key: s.NotaryK, AllowedHosts: []string{s.Host}, RootCAs: ca.Pool(),
		EnforceSingleUseNonce: nonces, MaxConcurrent: 256,
	})
	if err != nil {
		return nil, err
	}
	if err := s.Notary.Start("127.0.0.1:0"); err != nil {
		return nil, err
	}
	s.NotaryC = notary.NewClient(s.Notary.URL())
	return s, nil
}

// Close stops the stack.
func (s *Stack) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Notary.Shutdown(ctx)
	s.Provider.Shutdown(ctx)
}

// Policy returns a policy trusting the stack.
func (s *Stack) Policy(maintainer ed25519.PrivateKey, intents int) types.Policy {
	w := dosrtest.NewWorld("x")
	w.Maintainers = []ed25519.PrivateKey{maintainer}
	p := w.Policy()
	p.Threshold = 1
	p.ProviderHost = s.Host
	p.ProviderSPKI = [][]byte{s.SPKI}
	p.Models = []string{llm.ModelMedium}
	p.Notaries = [][]byte{dosrtest.Pub(s.NotaryK)}
	p.MaxTokens = 4096
	p.MaxDiffBytes = 4 << 20
	if intents > 0 {
		p.RequireIntent, p.MaxAttempts = true, intents
	}
	return p
}

// BaselineReviewer returns an app.Config.Baseline function that calls the
// provider directly, as a validator of the "every validator reviews"
// baseline would. Each validator uses its own client.
func (s *Stack) BaselineReviewer() func([]byte) (bool, error) {
	hc := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: s.ca.Pool()},
	}}
	url := "https://" + s.Host + llm.MessagesPath
	return func(body []byte) (bool, error) {
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			return false, err
		}
		req.Header.Set("content-type", "application/json")
		req.Header.Set("anthropic-version", app.AnthropicVersion)
		req.Header.Set("x-api-key", s.APIKey)
		res, err := hc.Do(req)
		if err != nil {
			return false, err
		}
		defer res.Body.Close()
		rb, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		if err != nil {
			return false, err
		}
		if res.StatusCode != 200 {
			return false, fmt.Errorf("provider status %d", res.StatusCode)
		}
		v, err := review.ParseResponse(rb)
		if err != nil {
			return false, err
		}
		return v.Approve, nil
	}
}

// ---------------------------------------------------------------- env

// Env is a running experiment environment.
type Env struct {
	Opts    Options
	Cluster *testnet.Cluster
	Stack   *Stack
	Repo    string
	Owner   ed25519.PrivateKey
	Git     *dosrtest.Repo
	Files   dosrtest.Files
	Genesis gitobj.ID
	mu      sync.Mutex
	head    gitobj.ID
}

// EnvConfig configures an environment.
type EnvConfig struct {
	Validators int
	Delays     testnet.Matrix
	Timeouts   *node.Timeouts
	Latency    llm.LatencyModel
	Verdict    llm.VerdictFunc
	Intents    int
	Nonces     bool
	Baseline   bool
	AppFor     func(i int, cfg *app.Config)
	Faults     map[int]*app.Faults
}

// NewEnv starts a cluster, the stack and a repository.
func NewEnv(opts Options, cfg EnvConfig) (*Env, error) {
	st, err := StartStack(cfg.Latency, cfg.Verdict, cfg.Nonces)
	if err != nil {
		return nil, err
	}
	tOpts := testnet.Options{Validators: cfg.Validators, Delays: cfg.Delays, JitterFrac: 0.1, Faults: cfg.Faults, LogLevel: "error"}
	if cfg.Timeouts != nil {
		tOpts.Timeouts = *cfg.Timeouts
	}
	acfg := app.DefaultConfig()
	if cfg.Baseline {
		acfg.Baseline = st.BaselineReviewer()
	}
	tOpts.App = &acfg
	tOpts.AppFor = cfg.AppFor
	c, err := testnet.Start(tOpts)
	if err != nil {
		st.Close()
		return nil, err
	}
	e := &Env{Opts: opts, Cluster: c, Stack: st, Repo: "bench", Owner: dosrtest.Key("bench-owner"), Git: dosrtest.NewRepo()}
	e.Files = dosrtest.Files{"README.md": "# bench\n", "main.go": "package main\n"}
	var bundle *gitobj.Bundle
	e.Genesis, bundle = e.Git.Commit(gitobj.ZeroID, e.Files, "genesis")
	e.head = e.Genesis
	cl := &client.Client{RPC: c.RPC(0), Key: e.Owner, ChainID: c.ChainID()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	code, log, err := cl.CreateRepo(ctx, e.Repo, "main", st.Policy(e.Owner, cfg.Intents), e.Genesis, bundle)
	if err != nil {
		e.Close()
		return nil, err
	}
	if code != types.CodeOK {
		e.Close()
		return nil, fmt.Errorf("create repo: %s", log)
	}
	if err := c.WaitRepo(e.Repo, time.Minute); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

// Close stops everything.
func (e *Env) Close() {
	e.Cluster.Close()
	e.Stack.Close()
}

// Contributor returns a client talking to node i.
func (e *Env) Contributor(i int, label string, baseline bool) *client.Client {
	return &client.Client{
		RPC: e.Cluster.RPC(i), Notary: e.Stack.NotaryC, Key: dosrtest.Key("bench-" + label),
		APIKey: e.Stack.APIKey, ChainID: e.Cluster.ChainID(), NoReceipt: baseline,
	}
}

// Change builds a change on top of base in the shared contributor
// repository: a file named path with `size` bytes of deterministic text.
func (e *Env) Change(base gitobj.ID, path string, size int, seed string) (gitobj.ID, *gitobj.Bundle, dosrtest.Files) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f := dosrtest.Files{}
	for p, c := range e.Files {
		f[p] = c
	}
	for p, c := range chunked(path, size, seed) {
		f[p] = c
	}
	id, b := e.Git.Commit(base, f, "change "+seed)
	return id, b, f
}

// chunked splits a change of `size` bytes into files of at most 200 KiB
// (the review renders files above 256 KiB as opaque).
func chunked(path string, size int, seed string) dosrtest.Files {
	const chunk = 200 << 10
	f := dosrtest.Files{}
	if size <= chunk {
		f[path] = text(size, seed)
		return f
	}
	for i := 0; size > 0; i++ {
		n := min(size, chunk)
		f[fmt.Sprintf("%s.%d", path, i)] = text(n, fmt.Sprintf("%s-%d", seed, i))
		size -= n
	}
	return f
}

// text returns size bytes of line-structured pseudo-random text.
func text(size int, seed string) string {
	var buf bytes.Buffer
	h := sha256.Sum256([]byte(seed))
	i := 0
	for buf.Len() < size {
		h = sha256.Sum256(h[:])
		fmt.Fprintf(&buf, "line %d: %x\n", i, h[:12])
		i++
	}
	s := buf.String()
	if len(s) > size {
		s = s[:size]
		if j := bytes.LastIndexByte([]byte(s), '\n'); j > 0 {
			s = s[:j+1]
		}
	}
	return s
}

// Submit submits one change with the given client and fills propagation
// data from the nodes' commit records.
func (e *Env) Submit(ctx context.Context, cl *client.Client, base, cand gitobj.ID, bundle *gitobj.Bundle) (*Sample, error) {
	smp := &Sample{SubmittedAt: time.Now()}
	out, err := cl.Submit(ctx, client.Change{
		Repo: e.Repo, Branch: "main", Base: base, Candidate: cand, Bundle: bundle, Objects: e.Git.Store,
	})
	smp.Outcome = out
	if err != nil {
		smp.Err = err.Error()
		return smp, err
	}
	e.propagation(smp, out.Height)
	return smp, nil
}

func (e *Env) propagation(smp *Sample, h int64) {
	if h == 0 {
		return
	}
	c := e.Cluster
	// Wait briefly for lagging nodes.
	deadline := time.Now().Add(10 * time.Second)
	var first, last int64
	for {
		first, last = math.MaxInt64, 0
		n := 0
		for i := 0; i < c.N(); i++ {
			if !c.Running(i) || c.Byzantine(i) {
				continue
			}
			if r, ok := c.Commits(i)[h]; ok {
				n++
				if r.CommittedAtUnixNano < first {
					first = r.CommittedAtUnixNano
				}
				if r.CommittedAtUnixNano > last {
					last = r.CommittedAtUnixNano
				}
			}
		}
		if n >= e.honestRunning() || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if first != math.MaxInt64 {
		smp.DecidedFirstNs = first - smp.SubmittedAt.UnixNano()
		smp.DecidedAllNs = last - smp.SubmittedAt.UnixNano()
	}
	if rounds, err := c.Rounds(0, h, h); err == nil {
		smp.Rounds = rounds[h] + 1
	}
}

func (e *Env) honestRunning() int {
	n := 0
	for i := 0; i < e.Cluster.N(); i++ {
		if e.Cluster.Running(i) && !e.Cluster.Byzantine(i) {
			n++
		}
	}
	return n
}

// Head returns the current head as known to node 0.
func (e *Env) Head() gitobj.ID {
	h, _ := e.Cluster.BranchHead(0, e.Repo, "main")
	return h
}

// ---------------------------------------------------------------- stats

// Percentiles summarises durations.
func Percentiles(ns []int64) map[string]any {
	if len(ns) == 0 {
		return map[string]any{"n": 0}
	}
	s := append([]int64(nil), ns...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	p := func(q float64) float64 {
		i := int(math.Ceil(q*float64(len(s)))) - 1
		if i < 0 {
			i = 0
		}
		return float64(s[i]) / 1e6
	}
	var sum float64
	for _, v := range s {
		sum += float64(v)
	}
	return map[string]any{
		"n": len(s), "mean_ms": sum / float64(len(s)) / 1e6,
		"p50_ms": p(0.5), "p90_ms": p(0.9), "p99_ms": p(0.99), "min_ms": float64(s[0]) / 1e6, "max_ms": float64(s[len(s)-1]) / 1e6,
	}
}

// ErrSkipped marks an experiment that could not run.
var ErrSkipped = errors.New("bench: skipped")
