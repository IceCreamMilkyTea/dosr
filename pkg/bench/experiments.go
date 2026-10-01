package bench

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/llm"
	"github.com/dosr/dosr/pkg/node"
	"github.com/dosr/dosr/pkg/testnet"
	"github.com/dosr/dosr/pkg/types"
)

// Network presets by name.
func network(name string, n int) testnet.Matrix {
	switch name {
	case "lan":
		return testnet.LAN(n)
	case "regional":
		return testnet.Regional(n)
	case "wan":
		return testnet.WAN5(n)
	}
	return nil
}

// sequential submits `count` changes one after another from one
// contributor and returns the samples.
func (e *Env) sequential(ctx context.Context, cl *client.Client, count, size int, tag string) ([]Sample, []string) {
	var samples []Sample
	var notes []string
	base := e.Head()
	for i := 0; i < count; i++ {
		cand, bundle, files := e.Change(base, fmt.Sprintf("f%d.txt", i%5), size, fmt.Sprintf("%s-%d", tag, i))
		smp, err := e.Submit(ctx, cl, base, cand, bundle)
		smp.Index = i
		samples = append(samples, *smp)
		if err != nil {
			notes = append(notes, fmt.Sprintf("submission %d: %v", i, err))
			base = e.Head()
			continue
		}
		e.mu.Lock()
		e.Files = files
		e.mu.Unlock()
		base = cand
	}
	return samples, notes
}

func timelineSummary(samples []Sample) map[string]any {
	var commit, total, upstream, attestOH, first, all, prepare []int64
	var txBytes, reqBytes, rcBytes int64
	ok := 0
	rounds := map[int32]int{}
	for _, s := range samples {
		if s.Outcome == nil || s.Err != "" {
			continue
		}
		ok++
		tl := s.Outcome.Timeline
		commit = append(commit, int64(tl.Commit))
		total = append(total, int64(tl.Total))
		upstream = append(upstream, int64(tl.Upstream))
		attestOH = append(attestOH, int64(tl.Attest-tl.Upstream))
		prepare = append(prepare, int64(tl.Prepare+tl.Present))
		if s.DecidedFirstNs > 0 {
			first = append(first, s.DecidedFirstNs)
			all = append(all, s.DecidedAllNs)
		}
		txBytes += int64(s.Outcome.TxBytes)
		reqBytes += int64(s.Outcome.RequestBytes)
		rcBytes += int64(s.Outcome.ReceiptBytes)
		rounds[s.Rounds]++
	}
	out := map[string]any{
		"ok": ok, "failed": len(samples) - ok,
		"commit":            Percentiles(commit),
		"total":             Percentiles(total),
		"llm_upstream":      Percentiles(upstream),
		"attest_overhead":   Percentiles(attestOH),
		"client_prepare":    Percentiles(prepare),
		"decided_first":     Percentiles(first),
		"decided_all":       Percentiles(all),
		"rounds_histogram":  rounds,
		"avg_tx_bytes":      0.0,
		"avg_request_bytes": 0.0,
		"avg_receipt_bytes": 0.0,
	}
	if ok > 0 {
		out["avg_tx_bytes"] = float64(txBytes) / float64(ok)
		out["avg_request_bytes"] = float64(reqBytes) / float64(ok)
		out["avg_receipt_bytes"] = float64(rcBytes) / float64(ok)
	}
	return out
}

// Consensus: commit latency and propagation vs validator count and
// network, small changes, no LLM latency (the mock answers instantly), so
// the measurement isolates DOSR's consensus + verification path.
func Consensus(opts Options) error {
	sizes := []int{4, 7, 10}
	nets := []string{"lan", "regional", "wan"}
	tos := []string{"default", "fast"}
	if opts.Quick {
		sizes, nets, tos = []int{4}, []string{"lan", "wan"}, []string{"fast"}
	}
	count := opts.reps(20, 6)
	for _, n := range sizes {
		for _, nw := range nets {
			for _, tn := range tos {
				name := fmt.Sprintf("consensus_n%d_%s_%s", n, nw, tn)
				opts.logf("== %s", name)
				r := &Result{Experiment: "consensus", StartedAt: time.Now(),
					Params: map[string]any{"validators": n, "network": nw, "count": count, "timeouts": tn, "change_bytes": 512}}
				to := timeouts(tn)
				e, err := NewEnv(opts, EnvConfig{Validators: n, Delays: network(nw, n), Timeouts: &to})
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
				cl := e.Contributor(0, "seq", false)
				r.Samples, r.Notes = e.sequential(ctx, cl, count, 512, name)
				cancel()
				r.Summary = timelineSummary(r.Samples)
				st := e.Cluster.BlockIntervals(0, 2, e.Cluster.MaxHeight())
				r.Summary["block_interval"] = st.String()
				r.Summary["app_stats_node0"] = e.Cluster.App(0).StatsSnapshot()
				if rep := e.Cluster.Check(); !rep.OK() {
					r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
				}
				r.Duration = time.Since(r.StartedAt)
				e.Close()
				if err := opts.Save(r, name); err != nil {
					return err
				}
				opts.logf("   commit p50 %.0f ms, decided-all p50 %.0f ms", r.Summary["commit"].(map[string]any)["p50_ms"], r.Summary["decided_all"].(map[string]any)["p50_ms"])
			}
		}
	}
	return nil
}

// timeouts returns a named consensus timeout preset. "default" is
// CometBFT's; "fast" keeps the same structure with all values divided by
// ~4 and commits as soon as all precommits arrived, which exposes the
// network's contribution to latency instead of the fixed timeout_commit.
func timeouts(name string) node.Timeouts {
	if name == "fast" {
		t := node.FastTimeouts()
		t.SkipTimeoutCommit = true
		return t
	}
	return node.DefaultTimeouts()
}

// BundleSize: commit latency vs change size (the transaction carries the
// bundle), 4 validators, regional network.
func BundleSize(opts Options) error {
	sizes := []int{1 << 10, 10 << 10, 100 << 10, 1 << 20}
	if opts.Quick {
		sizes = []int{1 << 10, 100 << 10}
	}
	count := opts.reps(10, 4)
	to := node.DefaultTimeouts()
	e, err := NewEnv(opts, EnvConfig{Validators: 4, Delays: network("regional", 4), Timeouts: &to})
	if err != nil {
		return err
	}
	defer e.Close()
	for _, size := range sizes {
		name := fmt.Sprintf("bundle_%dk", size/1024)
		opts.logf("== %s", name)
		r := &Result{Experiment: "bundle", StartedAt: time.Now(),
			Params: map[string]any{"validators": 4, "network": "regional", "count": count, "change_bytes": size}}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		r.Samples, r.Notes = e.sequential(ctx, e.Contributor(0, "seq", false), count, size, name)
		cancel()
		r.Summary = timelineSummary(r.Samples)
		r.Summary["app_stats_node0"] = e.Cluster.App(0).StatsSnapshot()
		r.Duration = time.Since(r.StartedAt)
		if err := opts.Save(r, name); err != nil {
			return err
		}
		opts.logf("   tx %.0f bytes, commit p50 %.0f ms", r.Summary["avg_tx_bytes"], r.Summary["commit"].(map[string]any)["p50_ms"])
	}
	if rep := e.Cluster.Check(); !rep.OK() {
		return errors.New(rep.String())
	}
	return nil
}

// EndToEnd: full latency breakdown with the realistic provider latency
// model, DOSR vs the "every validator reviews" baseline, on 4 validators
// over the WAN preset with CometBFT's default timeouts. Also reports the
// provider's accounting (calls, tokens, cost).
func EndToEnd(opts Options) error {
	count := opts.reps(10, 4)
	for _, mode := range []string{"dosr", "baseline"} {
		for _, lat := range []string{"none", "realistic"} {
			if opts.Quick && lat == "none" {
				continue
			}
			name := fmt.Sprintf("e2e_%s_%s", mode, lat)
			opts.logf("== %s", name)
			lm := llm.LatencyNone
			if lat == "realistic" {
				lm = llm.LatencyRealistic
			}
			to := node.DefaultTimeouts()
			r := &Result{Experiment: "e2e", StartedAt: time.Now(),
				Params: map[string]any{"mode": mode, "latency": lat, "validators": 4, "network": "wan", "count": count, "timeouts": "default"}}
			e, err := NewEnv(opts, EnvConfig{Validators: 4, Delays: network("wan", 4), Timeouts: &to, Latency: lm, Baseline: mode == "baseline"})
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			e.Stack.Provider.ResetStats()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			r.Samples, r.Notes = e.sequential(ctx, e.Contributor(0, "seq", mode == "baseline"), count, 2048, name)
			cancel()
			r.Summary = timelineSummary(r.Samples)
			ps := e.Stack.Provider.Stats()
			r.Summary["provider"] = ps
			r.Summary["llm_calls_per_accepted"] = 0.0
			if ok := r.Summary["ok"].(int); ok > 0 {
				r.Summary["llm_calls_per_accepted"] = float64(ps.Calls) / float64(ok)
			}
			var apps []app.StatsSnapshot
			for i := 0; i < e.Cluster.N(); i++ {
				apps = append(apps, e.Cluster.App(i).StatsSnapshot())
			}
			r.Summary["app_stats"] = apps
			r.Summary["block_interval"] = e.Cluster.BlockIntervals(0, 2, e.Cluster.MaxHeight()).String()
			if rep := e.Cluster.Check(); !rep.OK() {
				r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
			}
			r.Duration = time.Since(r.StartedAt)
			e.Close()
			if err := opts.Save(r, name); err != nil {
				return err
			}
			opts.logf("   ok %d/%d, total p50 %.0f ms, provider calls %d, cost $%.4f",
				r.Summary["ok"], count, r.Summary["total"].(map[string]any)["p50_ms"], ps.Calls, ps.CostUSD)
		}
	}
	return nil
}

// EndToEndSize: the full DOSR latency breakdown (client prepare, LLM call
// under the ASSUMED realistic latency model, attestation overhead, admit,
// consensus commit, propagation) as a function of change size, 4
// validators over the WAN preset with CometBFT's default timeouts. The
// provider's per-input-token term makes the LLM call grow with the
// rendered request; everything else should stay flat (bundle experiment).
func EndToEndSize(opts Options) error {
	sizes := []int{1 << 10, 10 << 10, 100 << 10, 1 << 20}
	count := opts.reps(6, 3)
	to := node.DefaultTimeouts()
	e, err := NewEnv(opts, EnvConfig{Validators: 4, Delays: network("wan", 4), Timeouts: &to, Latency: llm.LatencyRealistic})
	if err != nil {
		return err
	}
	defer e.Close()
	for _, size := range sizes {
		name := fmt.Sprintf("e2e_size_%dk", size/1024)
		opts.logf("== %s", name)
		e.Stack.Provider.ResetStats()
		r := &Result{Experiment: "e2e_size", StartedAt: time.Now(),
			Params: map[string]any{"mode": "dosr", "latency": "realistic", "validators": 4, "network": "wan", "count": count, "timeouts": "default", "change_bytes": size}}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		r.Samples, r.Notes = e.sequential(ctx, e.Contributor(0, "seq", false), count, size, name)
		cancel()
		r.Summary = timelineSummary(r.Samples)
		// Admit (broadcast -> CheckTx answered) and the attestor call as a
		// whole are not in timelineSummary; they matter for the decomposition.
		var admit, attest, present []int64
		for _, s := range r.Samples {
			if s.Outcome == nil || s.Err != "" {
				continue
			}
			tl := s.Outcome.Timeline
			admit = append(admit, int64(tl.Admit))
			attest = append(attest, int64(tl.Attest))
			present = append(present, int64(tl.Present))
		}
		r.Summary["admit"] = Percentiles(admit)
		r.Summary["attest_total"] = Percentiles(attest)
		r.Summary["present"] = Percentiles(present)
		ps := e.Stack.Provider.Stats()
		r.Summary["provider"] = ps
		r.Summary["block_interval"] = e.Cluster.BlockIntervals(0, 2, e.Cluster.MaxHeight()).String()
		r.Summary["app_stats_node0"] = e.Cluster.App(0).StatsSnapshot()
		if rep := e.Cluster.Check(); !rep.OK() {
			r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
		}
		r.Duration = time.Since(r.StartedAt)
		if err := opts.Save(r, name); err != nil {
			return err
		}
		opts.logf("   ok %d/%d, request %.0f bytes, llm p50 %.0f ms, commit p50 %.0f ms, total p50 %.0f ms, decided-all p50 %.0f ms",
			r.Summary["ok"], count, r.Summary["avg_request_bytes"], r.Summary["llm_upstream"].(map[string]any)["p50_ms"],
			r.Summary["commit"].(map[string]any)["p50_ms"], r.Summary["total"].(map[string]any)["p50_ms"],
			r.Summary["decided_all"].(map[string]any)["p50_ms"])
	}
	return nil
}

// Propagation: how long after the first validator commits a block do the
// other validators and the non-validator full nodes (which receive blocks
// by gossip / block sync and are what a `git clone` would talk to) have
// it? 4 validators + {0, 2, 4} full nodes on the regional preset with fast
// timeouts and no LLM latency, so the spread is the network's and the
// nodes' own. Per decided height the per-node commit timestamps come from
// the nodes' commit records (one clock, same machine).
func Propagation(opts Options) error {
	fulls := []int{0, 2, 4}
	if opts.Quick {
		fulls = []int{0, 2}
	}
	count := opts.reps(10, 4)
	for _, k := range fulls {
		name := fmt.Sprintf("propagation_f%d", k)
		opts.logf("== %s", name)
		to := timeouts("fast")
		n := 4 + k
		e, err := NewEnv(opts, EnvConfig{Validators: 4, FullNodes: k, Delays: network("regional", n), Timeouts: &to})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		r := &Result{Experiment: "propagation", StartedAt: time.Now(),
			Params: map[string]any{"validators": 4, "full_nodes": k, "network": "regional", "timeouts": "fast", "count": count, "change_bytes": 512}}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		r.Samples, r.Notes = e.sequential(ctx, e.Contributor(0, "seq", false), count, 512, name)
		cancel()
		var vSpread, fSpread, fAfterFirst, allSpread, vFirst, vLast, fLast []int64
		for i := range r.Samples {
			s := &r.Samples[i]
			if s.Outcome == nil || s.Err != "" || s.Outcome.Height == 0 {
				continue
			}
			sp := e.commitSpread(s.Outcome.Height)
			s.Extra = map[string]any{
				"validator_first_ms":  float64(sp.vFirst-s.SubmittedAt.UnixNano()) / 1e6,
				"validator_last_ms":   float64(sp.vLast-s.SubmittedAt.UnixNano()) / 1e6,
				"validator_spread_ms": float64(sp.vLast-sp.vFirst) / 1e6,
				"validators_seen":     sp.vN,
				"full_nodes_seen":     sp.fN,
			}
			vSpread = append(vSpread, sp.vLast-sp.vFirst)
			vFirst = append(vFirst, sp.vFirst-s.SubmittedAt.UnixNano())
			vLast = append(vLast, sp.vLast-s.SubmittedAt.UnixNano())
			if sp.fN > 0 {
				s.Extra["full_first_ms"] = float64(sp.fFirst-s.SubmittedAt.UnixNano()) / 1e6
				s.Extra["full_last_ms"] = float64(sp.fLast-s.SubmittedAt.UnixNano()) / 1e6
				s.Extra["full_spread_ms"] = float64(sp.fLast-sp.fFirst) / 1e6
				s.Extra["full_after_first_validator_ms"] = float64(sp.fLast-sp.vFirst) / 1e6
				fSpread = append(fSpread, sp.fLast-sp.fFirst)
				fAfterFirst = append(fAfterFirst, sp.fLast-sp.vFirst)
				fLast = append(fLast, sp.fLast-s.SubmittedAt.UnixNano())
				allSpread = append(allSpread, max(sp.vLast, sp.fLast)-sp.vFirst)
			} else {
				allSpread = append(allSpread, sp.vLast-sp.vFirst)
			}
		}
		r.Summary = timelineSummary(r.Samples)
		r.Summary["validator_first"] = Percentiles(vFirst)
		r.Summary["validator_last"] = Percentiles(vLast)
		r.Summary["validator_spread"] = Percentiles(vSpread)
		r.Summary["full_last"] = Percentiles(fLast)
		r.Summary["full_spread"] = Percentiles(fSpread)
		r.Summary["full_after_first_validator"] = Percentiles(fAfterFirst)
		r.Summary["all_spread"] = Percentiles(allSpread)
		r.Summary["block_interval"] = e.Cluster.BlockIntervals(0, 2, e.Cluster.MaxHeight()).String()
		if rep := e.Cluster.Check(); !rep.OK() {
			r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
		}
		r.Duration = time.Since(r.StartedAt)
		e.Close()
		if err := opts.Save(r, name); err != nil {
			return err
		}
		opts.logf("   validator spread p50 %.1f ms, full nodes after first validator p50 %.1f ms, decided-all p50 %.0f ms",
			p50(r.Summary["validator_spread"]), p50(r.Summary["full_after_first_validator"]), p50(r.Summary["decided_all"]))
	}
	return nil
}

// p50 returns the p50 of a Percentiles map (NaN if empty).
func p50(v any) float64 {
	if m, ok := v.(map[string]any); ok {
		if f, ok := m["p50_ms"].(float64); ok {
			return f
		}
	}
	return math.NaN()
}

// spread of commit timestamps of one height over validators and full nodes.
type spread struct {
	vFirst, vLast, fFirst, fLast int64
	vN, fN                       int
}

// commitSpread reads the commit records of all running honest nodes for
// height h, waiting briefly for lagging nodes (full nodes may receive the
// block a little after the validators).
func (e *Env) commitSpread(h int64) spread {
	c := e.Cluster
	deadline := time.Now().Add(10 * time.Second)
	var sp spread
	for {
		sp = spread{vFirst: math.MaxInt64, fFirst: math.MaxInt64}
		for i := 0; i < c.N(); i++ {
			if !c.Running(i) || c.Byzantine(i) {
				continue
			}
			rec, ok := c.Commits(i)[h]
			if !ok {
				continue
			}
			t := rec.CommittedAtUnixNano
			if c.IsValidator(i) {
				sp.vN++
				sp.vFirst, sp.vLast = min(sp.vFirst, t), max(sp.vLast, t)
			} else {
				sp.fN++
				sp.fFirst, sp.fLast = min(sp.fFirst, t), max(sp.fLast, t)
			}
		}
		if sp.vN+sp.fN >= e.honestRunning() || time.Now().After(deadline) {
			return sp
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Contention: k contributors each need m changes accepted on the same
// branch; a losing contributor rebases and pays for a new review.
// Measures reviews per accepted change and wall-clock time.
func Contention(opts Options) error {
	ks := []int{1, 2, 4, 8}
	if opts.Quick {
		ks = []int{1, 4}
	}
	m := opts.reps(4, 2)
	for _, k := range ks {
		name := fmt.Sprintf("contention_k%d", k)
		opts.logf("== %s", name)
		to := node.DefaultTimeouts()
		e, err := NewEnv(opts, EnvConfig{Validators: 4, Delays: network("regional", 4), Timeouts: &to, Latency: llm.LatencyFast})
		if err != nil {
			return err
		}
		r := &Result{Experiment: "contention", StartedAt: time.Now(),
			Params: map[string]any{"contributors": k, "changes_each": m, "validators": 4, "network": "regional", "latency": "fast"}}
		var mu sync.Mutex
		var wg sync.WaitGroup
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		start := time.Now()
		for c := 0; c < k; c++ {
			wg.Add(1)
			go func(c int) {
				defer wg.Done()
				cl := e.Contributor(c%e.Cluster.N(), fmt.Sprintf("c%d", c), false)
				label := fmt.Sprintf("c%d", c)
				for j := 0; j < m; j++ {
					attempts := 0
					for {
						attempts++
						base := e.Head()
						cand, bundle, _ := e.Change(base, fmt.Sprintf("%s.txt", label), 1024, fmt.Sprintf("%s-%d-%d", label, j, attempts))
						smp, err := e.Submit(ctx, cl, base, cand, bundle)
						smp.Contributor, smp.Index, smp.Attempts = label, j, attempts
						if err == nil {
							mu.Lock()
							r.Samples = append(r.Samples, *smp)
							mu.Unlock()
							break
						}
						if errors.Is(err, client.ErrStale) {
							continue
						}
						mu.Lock()
						r.Notes = append(r.Notes, fmt.Sprintf("%s: %v", label, err))
						r.Samples = append(r.Samples, *smp)
						mu.Unlock()
						if ctx.Err() != nil {
							return
						}
					}
				}
			}(c)
		}
		wg.Wait()
		cancel()
		elapsed := time.Since(start)
		ps := e.Stack.Provider.Stats()
		accepted := 0
		reviews := 0
		var attemptsHist = map[int]int{}
		for _, s := range r.Samples {
			if s.Err == "" {
				accepted++
				reviews += s.Attempts
				attemptsHist[s.Attempts]++
			}
		}
		r.Summary = timelineSummary(r.Samples)
		r.Summary["accepted"] = accepted
		r.Summary["provider_calls"] = ps.Calls
		r.Summary["reviews_per_accepted"] = float64(ps.Calls) / float64(max(accepted, 1))
		r.Summary["wasted_reviews"] = int(ps.Calls) - accepted
		r.Summary["attempts_histogram"] = attemptsHist
		r.Summary["wall_ms"] = float64(elapsed.Milliseconds())
		r.Summary["throughput_per_min"] = float64(accepted) / elapsed.Minutes()
		r.Summary["cost_usd"] = ps.CostUSD
		if rep := e.Cluster.Check(); !rep.OK() {
			r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
		}
		r.Duration = time.Since(r.StartedAt)
		e.Close()
		if err := opts.Save(r, name); err != nil {
			return err
		}
		opts.logf("   accepted %d, reviews %d (%.2f per accepted), %.1fs", accepted, ps.Calls, r.Summary["reviews_per_accepted"], elapsed.Seconds())
	}
	return nil
}

// Faults: a stream of submissions while a validator crashes and restarts
// and while the network partitions 3|1 and heals. Records per-submission
// latency and the phase it fell into, plus the stale/failed count.
func Faults(opts Options) error {
	name := "faults_timeline"
	opts.logf("== %s", name)
	to := node.DefaultTimeouts()
	e, err := NewEnv(opts, EnvConfig{Validators: 4, Delays: network("regional", 4), Timeouts: &to})
	if err != nil {
		return err
	}
	defer e.Close()
	r := &Result{Experiment: "faults", StartedAt: time.Now(),
		Params: map[string]any{"validators": 4, "network": "regional", "timeouts": "default"}}
	cl := e.Contributor(0, "seq", false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	phases := []struct {
		name   string
		count  int
		before func() error
	}{
		{"healthy", opts.reps(6, 3), nil},
		{"validator3_down", opts.reps(6, 3), func() error { return e.Cluster.Kill(3) }},
		{"validator3_restarted", opts.reps(6, 3), func() error { return e.Cluster.Restart(3) }},
		{"partition_3_1_minority_has_client", 0, func() error { e.Cluster.Partition([]int{1, 2, 3}, []int{0}); return nil }},
		{"partition_3_1_majority", opts.reps(6, 3), func() error {
			cl = e.Contributor(1, "seq", false)
			return nil
		}},
		{"healed", opts.reps(6, 3), func() error { e.Cluster.Heal(); return nil }},
	}
	base := e.Head()
	idx := 0
	for _, ph := range phases {
		if ph.before != nil {
			t := time.Now()
			if err := ph.before(); err != nil {
				r.Notes = append(r.Notes, ph.name+": "+err.Error())
			}
			r.Notes = append(r.Notes, fmt.Sprintf("%s: fault injected at +%.1fs", ph.name, time.Since(r.StartedAt).Seconds()))
			_ = t
		}
		if ph.count == 0 {
			// The client on the isolated node: one attempt with a
			// short deadline to show it cannot make progress.
			cctx, c2 := context.WithTimeout(ctx, 15*time.Second)
			cand, bundle, _ := e.Change(base, "iso.txt", 512, "iso")
			smp, err := e.Submit(cctx, cl, base, cand, bundle)
			c2()
			smp.Index, smp.Extra = idx, map[string]any{"phase": ph.name}
			idx++
			if err != nil {
				smp.Err = err.Error()
			}
			r.Samples = append(r.Samples, *smp)
			continue
		}
		for i := 0; i < ph.count; i++ {
			base = headFrom(e, cl)
			cand, bundle, files := e.Change(base, fmt.Sprintf("f%d.txt", i%3), 512, fmt.Sprintf("%s-%d", ph.name, i))
			cctx, c2 := context.WithTimeout(ctx, 2*time.Minute)
			smp, err := e.Submit(cctx, cl, base, cand, bundle)
			c2()
			smp.Index, smp.Extra = idx, map[string]any{"phase": ph.name, "at_s": time.Since(r.StartedAt).Seconds()}
			idx++
			if err == nil {
				e.mu.Lock()
				e.Files = files
				e.mu.Unlock()
			}
			r.Samples = append(r.Samples, *smp)
		}
	}
	if err := e.Cluster.WaitAllHeight(e.Cluster.MaxHeight(), time.Minute); err != nil {
		r.Notes = append(r.Notes, "catch-up after heal: "+err.Error())
	}
	byPhase := map[string]map[string]any{}
	for _, ph := range phases {
		var ns []int64
		failed := 0
		for _, s := range r.Samples {
			if s.Extra["phase"] != ph.name {
				continue
			}
			if s.Err != "" {
				failed++
				continue
			}
			ns = append(ns, int64(s.Outcome.Timeline.Total))
		}
		p := Percentiles(ns)
		p["failed"] = failed
		byPhase[ph.name] = p
	}
	r.Summary = map[string]any{"by_phase": byPhase}
	if rep := e.Cluster.Check(); !rep.OK() {
		r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
	} else {
		r.Summary["invariants"] = "ok"
	}
	r.Duration = time.Since(r.StartedAt)
	return opts.Save(r, name)
}

func headFrom(e *Env, cl *client.Client) gitobj.ID {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if h, err := cl.Head(ctx, e.Repo, "main"); err == nil {
		return h
	}
	return e.Head()
}

// Grinding: a contributor whose change the reviewer approves only with
// probability p resubmits until accepted. Without intents the only limit
// is money; with intents (MaxAttempts) and single-use nonces at the
// notary the number of reviews per head is bounded. Measures acceptance
// rate and reviews spent over `trials` independent heads.
func Grinding(opts Options) error {
	p := 0.25
	trials := opts.reps(20, 6)
	maxTries := 12
	for _, mode := range []string{"no_intents", "intents_max3"} {
		name := "grinding_" + mode
		opts.logf("== %s", name)
		intents := 0
		if mode == "intents_max3" {
			intents = 3
		}
		rng := llm.NewRand(42)
		e, err := NewEnv(opts, EnvConfig{Validators: 4, Verdict: llm.BernoulliVerdict(p, rng), Intents: intents, Nonces: intents > 0})
		if err != nil {
			return err
		}
		r := &Result{Experiment: "grinding", StartedAt: time.Now(),
			Params: map[string]any{"p_approve": p, "trials": trials, "max_tries": maxTries, "mode": mode, "max_attempts": intents}}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		accepted, reviews, refusedByNotary, refusedByChain := 0, 0, 0, 0
		for t := 0; t < trials; t++ {
			base := e.Head()
			cl := e.Contributor(0, fmt.Sprintf("grinder%d", t), false)
			smp := Sample{Index: t}
			for try := 1; try <= maxTries; try++ {
				// The same diff, a fresh commit each time (a grinder
				// can always change the commit message).
				cand, bundle, _ := e.Change(base, "grind.txt", 256, fmt.Sprintf("g%d-%d", t, try))
				before := e.Stack.Provider.Stats().Calls
				s, err := e.Submit(ctx, cl, base, cand, bundle)
				reviews += int(e.Stack.Provider.Stats().Calls - before)
				smp.Attempts = try
				if err == nil {
					accepted++
					smp.Outcome = s.Outcome
					break
				}
				if errors.Is(err, client.ErrRejected) {
					continue
				}
				smp.Err = err.Error()
				if (s.Outcome != nil && s.Outcome.Code == types.CodeTooManyAttempts) || contains(err.Error(), "too_many_attempts") {
					refusedByChain++
				} else if contains(err.Error(), "nonce") {
					refusedByNotary++
				}
				break
			}
			r.Samples = append(r.Samples, smp)
			// Move the head so the next trial starts from a fresh
			// head state (attempt counters are per head).
			if smp.Outcome == nil {
				cand, bundle, _ := e.Change(base, "honest.txt", 128, fmt.Sprintf("h%d", t))
				e.Stack.Provider.SetVerdict(llm.MarkerVerdict)
				_, _ = e.Submit(ctx, e.Contributor(0, "honest", false), base, cand, bundle)
				e.Stack.Provider.SetVerdict(llm.BernoulliVerdict(p, rng))
			}
		}
		cancel()
		r.Summary = map[string]any{
			"accepted": accepted, "acceptance_rate": float64(accepted) / float64(trials),
			"reviews": reviews, "reviews_per_trial": float64(reviews) / float64(trials),
			"refused_by_chain": refusedByChain, "refused_by_notary": refusedByNotary,
			"expected_rate_unbounded": 1 - pow(1-p, maxTries),
			"expected_rate_bounded":   1 - pow(1-p, intents),
		}
		if rep := e.Cluster.Check(); !rep.OK() {
			r.Notes = append(r.Notes, "INVARIANT VIOLATION: "+rep.String())
		}
		r.Duration = time.Since(r.StartedAt)
		e.Close()
		if err := opts.Save(r, name); err != nil {
			return err
		}
		opts.logf("   accepted %d/%d, reviews %d", accepted, trials, reviews)
	}
	return nil
}

func pow(b float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= b
	}
	return r
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// Verify: cost of verifying one AcceptCommit on a validator as a function
// of change size, in-process (no network): what CheckTx / ProcessProposal
// / FinalizeBlock each pay without the cache.
func Verify(opts Options) error {
	name := "verify_cost"
	opts.logf("== %s", name)
	sizes := []int{1 << 10, 10 << 10, 100 << 10, 1 << 20}
	reps := opts.reps(20, 5)
	r := &Result{Experiment: "verify", StartedAt: time.Now(), Params: map[string]any{"sizes": sizes, "reps": reps}}
	w := dosrtest.NewWorld("verify-bench")
	for _, size := range sizes {
		db := dbm.NewMemDB()
		cfg := app.DefaultConfig()
		cfg.EvidenceCacheSize = 0
		cfg.Now = func() time.Time { return time.Unix(w.Now, 0) }
		a, err := app.New(db, cfg)
		if err != nil {
			return err
		}
		ctx := context.Background()
		if _, err := a.InitChain(ctx, &abci.RequestInitChain{ChainId: w.ChainID, InitialHeight: 1}); err != nil {
			return err
		}
		git := dosrtest.NewRepo()
		files := dosrtest.Files{"README.md": "x\n"}
		g, gb := git.Commit(gitobj.ZeroID, files, "genesis")
		pol := w.Policy()
		pol.MaxDiffBytes = 4 << 20
		ctx2 := ctx
		tx, err := w.CreateRepoTx(dosrtest.Key("o"), "r", "main", pol, g, gb)
		if err != nil {
			return err
		}
		bt := time.Unix(w.Now+1, 0)
		if _, err := a.FinalizeBlock(ctx2, &abci.RequestFinalizeBlock{Txs: [][]byte{tx.Bytes()}, Height: 1, Time: bt}); err != nil {
			return err
		}
		if _, err := a.Commit(ctx2, nil); err != nil {
			return err
		}
		for p, c := range chunked("big.txt", size, fmt.Sprintf("v%d", size)) {
			files[p] = c
		}
		cand, bundle := git.Commit(g, files, "big")
		atx, err := w.AcceptTx(dosrtest.Key("u"), dosrtest.Review{Repo: "r", Branch: "main", Base: g, Candidate: cand, Bundle: bundle, Policy: pol, PolicyVersion: 1}, git.Store)
		if err != nil {
			return err
		}
		var ns []int64
		for i := 0; i < reps; i++ {
			// A fresh app per repetition so nothing is warm.
			a2, err := app.New(db, cfg)
			if err != nil {
				return err
			}
			t := time.Now()
			res, err := a2.CheckTx(ctx, &abci.RequestCheckTx{Tx: atx.Bytes()})
			if err != nil {
				return err
			}
			if res.Code != 0 {
				return fmt.Errorf("verify bench: %s", res.Log)
			}
			ns = append(ns, time.Since(t).Nanoseconds())
		}
		p := Percentiles(ns)
		p["change_bytes"] = size
		p["tx_bytes"] = len(atx.Bytes())
		r.Samples = append(r.Samples, Sample{Index: size, Extra: p})
		opts.logf("   %7d bytes: verify p50 %.2f ms (tx %d bytes)", size, p["p50_ms"], len(atx.Bytes()))
	}
	r.Duration = time.Since(r.StartedAt)
	return opts.Save(r, name)
}
