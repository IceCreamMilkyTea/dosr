package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/types"
)

// AppVersion is reported to CometBFT in Info.
const AppVersion = 1

// Config configures an App.
type Config struct {
	// StrictProposals makes ProcessProposal reject any proposal that
	// contains a transaction which does not execute successfully, in
	// order, on the current state (design log D4). If false, proposals
	// are always accepted and failing transactions are recorded with
	// their failure code.
	StrictProposals bool
	// EvidenceCacheSize is the number of verified evidences to memoise;
	// 0 disables the cache (used by the evaluation to measure its effect).
	EvidenceCacheSize int
	// Verifier verifies receipts. Defaults to attest.ProxyVerifier.
	Verifier attest.Verifier
	// OnCommit, if set, is called after each block has been durably
	// committed, outside the app's locks. It must not block for long.
	OnCommit func(CommitInfo)
	// Faults injects Byzantine application behaviour. Tests only.
	Faults *Faults
	// Now is the clock used by CheckTx (and nothing else). Defaults to
	// time.Now.
	Now func() time.Time
	// Baseline, if set, turns the node into the evaluation's baseline
	// "every validator reviews": receipts are ignored and each validator
	// calls this function with the recomputed review request while
	// forming its vote. Never use outside experiments.
	Baseline func(requestBody []byte) (approve bool, err error)
}

// Faults describes Byzantine behaviour of a validator's application. It
// exists to test that honest validators are safe when up to f validators
// run a malicious application.
type Faults struct {
	// InjectTxs are added to the front of every proposal this node
	// makes, without any validation.
	InjectTxs func(height int64) [][]byte
	// AcceptAllProposals makes ProcessProposal vote for everything.
	AcceptAllProposals bool
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{StrictProposals: true, EvidenceCacheSize: 64}
}

// CommitInfo describes a committed block to the OnCommit hook.
type CommitInfo struct {
	Height    int64
	BlockTime int64
	AppHash   []byte
	Accepted  []*HistoryEntry
	// CommittedAt is the local wall-clock time at which the block became
	// durable on this node (used to measure propagation).
	CommittedAt time.Time
}

// App is the DOSR ABCI application.
//
// Concurrency: CometBFT drives the app through four connections. Consensus
// calls (PrepareProposal .. Commit) are sequential among themselves;
// CheckTx and Query may run concurrently with them. mu protects the
// committed state pointer and the mempool check state; block execution
// works on private copies and only takes mu to publish results.
type App struct {
	abci.BaseApplication

	cfg      Config
	db       dbm.DB
	verifier attest.Verifier
	cache    *evidenceCache
	sigs     *sigCache
	stats    *Stats

	mu        sync.RWMutex
	committed *State // never mutated after publication
	check     *execCtx

	// block in progress: set by FinalizeBlock, consumed by Commit.
	pending *execCtx

	baselineMu       sync.Mutex
	baselineVerdicts map[types.TxID]bool
}

var _ abci.Application = (*App)(nil)

// New opens the application on db, loading the last committed state.
func New(db dbm.DB, cfg Config) (*App, error) {
	if cfg.Verifier == nil {
		cfg.Verifier = attest.ProxyVerifier{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &App{
		cfg:      cfg,
		db:       db,
		verifier: cfg.Verifier,
		cache:    newEvidenceCache(cfg.EvidenceCacheSize),
		sigs:     newSigCache(4096),
		stats:    &Stats{},

		baselineVerdicts: map[types.TxID]bool{},
	}
	raw, err := db.Get(stateKey)
	if err != nil {
		return nil, fmt.Errorf("app: load state: %w", err)
	}
	st := NewState("")
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, st); err != nil {
			return nil, fmt.Errorf("app: decode state: %w", err)
		}
		if st.Repos == nil || st.Intents == nil || st.Attempts == nil || st.Reputation == nil {
			return nil, fmt.Errorf("app: corrupt state")
		}
	}
	a.committed = st
	a.resetCheckLocked()
	return a, nil
}

// resetCheckLocked re-bases the mempool check state on the committed
// state. Caller holds mu (or is the constructor).
func (a *App) resetCheckLocked() {
	a.check = &execCtx{
		mode:      modeCheck,
		st:        a.committed.Clone(),
		objs:      newObjLayer(a.db, nil),
		height:    a.committed.Height + 1,
		blockTime: a.cfg.Now().Unix(), // CheckTx is advisory; see CheckTx
		prevHash:  a.committed.AppHash,
	}
}

// Info reports the last committed height and app hash; CometBFT uses it
// to decide which blocks to replay after a restart.
func (a *App) Info(context.Context, *abci.RequestInfo) (*abci.ResponseInfo, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return &abci.ResponseInfo{
		Data:             "dosr",
		Version:          "0.1.0",
		AppVersion:       AppVersion,
		LastBlockHeight:  a.committed.Height,
		LastBlockAppHash: a.committed.AppHash,
	}, nil
}

// InitChain initialises an empty state for the chain.
func (a *App) InitChain(_ context.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := NewState(req.ChainId)
	st.Height = req.InitialHeight - 1
	if st.Height < 0 {
		st.Height = 0
	}
	st.AppHash = st.ComputeAppHash()
	a.committed = st
	a.resetCheckLocked()
	return &abci.ResponseInitChain{AppHash: st.AppHash}, nil
}

// CheckTx admits a transaction to the mempool iff it executes
// successfully on the check state: the committed state plus the effects
// of the transactions admitted since. CheckTx is advisory - it protects
// the mempool from junk - and is the only place the local clock is used
// (as a stand-in for the time of the block the transaction will be in).
func (a *App) CheckTx(_ context.Context, req *abci.RequestCheckTx) (*abci.ResponseCheckTx, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.check.blockTime = a.cfg.Now().Unix()
	// Execute on a copy so that a failing transaction cannot leave
	// partial effects. (Handlers validate before mutating, but CheckTx
	// faces the most hostile input; the copy makes the argument local.)
	trial := &execCtx{
		mode:      modeCheck,
		st:        a.check.st.Clone(),
		objs:      newObjLayer(a.db, a.check.objs),
		height:    a.check.height,
		blockTime: a.check.blockTime,
		prevHash:  a.check.prevHash,
	}
	r := a.exec(trial, req.Tx)
	if r.code == types.CodeOK {
		a.check.st = trial.st
		a.check.objs = trial.objs
	}
	a.stats.observeCheck(r.code)
	return &abci.ResponseCheckTx{Code: r.code, Log: r.log, Codespace: types.Codespace, GasWanted: 1}, nil
}

// speculate returns a fresh context on top of the committed state for the
// block at the given height and time.
func (a *App) speculate(mode execMode, height int64, t time.Time) *execCtx {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return &execCtx{
		mode:      mode,
		st:        a.committed.Clone(),
		objs:      newObjLayer(a.db, nil),
		height:    height,
		blockTime: t.Unix(),
		prevHash:  a.committed.AppHash,
	}
}

// PrepareProposal builds a block: it executes the mempool's transactions
// in order on a scratch state and keeps those that succeed, so that every
// transaction in an honest proposal is one that will take effect.
func (a *App) PrepareProposal(_ context.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
	var out [][]byte
	var size int64
	if f := a.cfg.Faults; f != nil && f.InjectTxs != nil {
		for _, tx := range f.InjectTxs(req.Height) {
			if size+int64(len(tx)) <= req.MaxTxBytes {
				out = append(out, tx)
				size += int64(len(tx))
			}
		}
		// A Byzantine proposer does not validate what it injects.
		for _, tx := range req.Txs {
			if size+int64(len(tx)) <= req.MaxTxBytes {
				out = append(out, tx)
				size += int64(len(tx))
			}
		}
		return &abci.ResponsePrepareProposal{Txs: out}, nil
	}
	c := a.speculate(modePrepare, req.Height, req.Time)
	for _, tx := range req.Txs {
		if size+int64(len(tx)) > req.MaxTxBytes {
			continue
		}
		// exec leaves c untouched on failure, so no copy is needed
		// between transactions.
		if r := a.exec(c, tx); r.code != types.CodeOK {
			continue
		}
		out = append(out, tx)
		size += int64(len(tx))
	}
	return &abci.ResponsePrepareProposal{Txs: out}, nil
}

// ProcessProposal validates a proposed block. It is deterministic: it
// depends only on the committed state and the proposal.
func (a *App) ProcessProposal(_ context.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	accept := &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}
	if f := a.cfg.Faults; f != nil && f.AcceptAllProposals {
		return accept, nil
	}
	if !a.cfg.StrictProposals && a.cfg.Baseline == nil {
		return accept, nil
	}
	c := a.speculate(modeProcess, req.Height, req.Time)
	for _, tx := range req.Txs {
		if r := a.exec(c, tx); r.code != types.CodeOK {
			a.stats.observeRejectedProposal()
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
		}
	}
	return accept, nil
}

// FinalizeBlock executes a decided block. It must handle ANY block: the
// block may come from block sync or replay without this node ever having
// run ProcessProposal on it, and with up to f Byzantine validators plus a
// lenient configuration it may contain failing transactions. Failing
// transactions get their failure code and have no effect.
func (a *App) FinalizeBlock(_ context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	c := a.speculate(modeFinalize, req.Height, req.Time)
	res := make([]*abci.ExecTxResult, len(req.Txs))
	for i, tx := range req.Txs {
		r := a.exec(c, tx)
		res[i] = &abci.ExecTxResult{Code: r.code, Log: r.log, Events: r.events, Codespace: types.Codespace, GasUsed: 1}
		a.stats.observeFinal(r.code)
	}
	c.st.Height = req.Height
	c.st.AppHash = c.st.ComputeAppHash()
	a.pending = c
	return &abci.ResponseFinalizeBlock{TxResults: res, AppHash: c.st.AppHash}, nil
}

// Commit makes the block executed by FinalizeBlock durable: state,
// history and objects are written in one atomic, synced batch.
func (a *App) Commit(context.Context, *abci.RequestCommit) (*abci.ResponseCommit, error) {
	c := a.pending
	if c == nil {
		panic("app: Commit without FinalizeBlock")
	}
	a.pending = nil

	batch := a.db.NewBatch()
	defer batch.Close()
	stb, err := json.Marshal(c.st)
	must(err)
	must(batch.Set(stateKey, stb))
	for _, e := range c.hist {
		eb, err := json.Marshal(e)
		must(err)
		must(batch.Set(histKey(e.Repo, e.Branch, e.Seq), eb))
	}
	must(c.objs.writeTo(batch))
	// A node that cannot persist a decided block must stop, not continue
	// with a state its disk does not have.
	must(batch.WriteSync())
	committedAt := time.Now()

	a.mu.Lock()
	a.committed = c.st
	a.resetCheckLocked()
	a.mu.Unlock()

	if a.cfg.OnCommit != nil {
		a.cfg.OnCommit(CommitInfo{
			Height: c.st.Height, BlockTime: c.blockTime, AppHash: c.st.AppHash,
			Accepted: c.hist, CommittedAt: committedAt,
		})
	}
	return &abci.ResponseCommit{}, nil
}

func must(err error) {
	if err != nil {
		panic("app: storage failure: " + err.Error())
	}
}

// Committed returns the last committed state. The returned value must be
// treated as read-only.
func (a *App) Committed() *State {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.committed
}

// Stats returns the app's counters.
func (a *App) Stats() *Stats { return a.stats }

// sigCache is a bounded set of transaction IDs whose envelope signature
// has been verified.
type sigCache struct {
	mu  sync.Mutex
	max int
	m   map[types.TxID]struct{}
	q   []types.TxID
}

func newSigCache(max int) *sigCache {
	return &sigCache{max: max, m: map[types.TxID]struct{}{}}
}

func (s *sigCache) seen(id types.TxID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[id]
	return ok
}

func (s *sigCache) add(id types.TxID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; ok {
		return
	}
	s.m[id] = struct{}{}
	s.q = append(s.q, id)
	if len(s.q) > s.max {
		delete(s.m, s.q[0])
		s.q = s.q[1:]
	}
}

// Stats holds counters and timings for the evaluation.
type Stats struct {
	mu                sync.Mutex
	VerifyCount       int
	VerifyOK          int
	VerifyNanos       []int64
	CheckCodes        map[uint32]int
	FinalCodes        map[uint32]int
	RejectedProposals int
	BaselineCalls     int
	BaselineErrors    int
	BaselineNanos     []int64
}

func (s *Stats) observeBaseline(d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BaselineCalls++
	if err != nil {
		s.BaselineErrors++
	}
	if len(s.BaselineNanos) < 1<<16 {
		s.BaselineNanos = append(s.BaselineNanos, d.Nanoseconds())
	}
}

func (s *Stats) observeVerify(d time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VerifyCount++
	if ok {
		s.VerifyOK++
	}
	if len(s.VerifyNanos) < 1<<16 {
		s.VerifyNanos = append(s.VerifyNanos, d.Nanoseconds())
	}
}

func (s *Stats) observeCheck(code uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CheckCodes == nil {
		s.CheckCodes = map[uint32]int{}
	}
	s.CheckCodes[code]++
}

func (s *Stats) observeFinal(code uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FinalCodes == nil {
		s.FinalCodes = map[uint32]int{}
	}
	s.FinalCodes[code]++
}

func (s *Stats) observeRejectedProposal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RejectedProposals++
}

// StatsSnapshot is a copy of the counters.
type StatsSnapshot struct {
	VerifyCount       int            `json:"verify_count"`
	VerifyOK          int            `json:"verify_ok"`
	VerifyNanos       []int64        `json:"verify_nanos"`
	CheckCodes        map[string]int `json:"check_codes"`
	FinalCodes        map[string]int `json:"final_codes"`
	RejectedProposals int            `json:"rejected_proposals"`
	BaselineCalls     int            `json:"baseline_calls"`
	BaselineErrors    int            `json:"baseline_errors"`
	BaselineNanos     []int64        `json:"baseline_nanos"`
	CacheHits         uint64         `json:"cache_hits"`
	CacheMisses       uint64         `json:"cache_misses"`
}

// StatsSnapshot returns a consistent copy of the counters.
func (a *App) StatsSnapshot() StatsSnapshot {
	s := a.stats
	s.mu.Lock()
	out := StatsSnapshot{
		VerifyCount: s.VerifyCount, VerifyOK: s.VerifyOK,
		VerifyNanos:       append([]int64(nil), s.VerifyNanos...),
		CheckCodes:        map[string]int{},
		FinalCodes:        map[string]int{},
		RejectedProposals: s.RejectedProposals,
		BaselineCalls:     s.BaselineCalls,
		BaselineErrors:    s.BaselineErrors,
		BaselineNanos:     append([]int64(nil), s.BaselineNanos...),
	}
	for k, v := range s.CheckCodes {
		out.CheckCodes[types.CodeName(k)] = v
	}
	for k, v := range s.FinalCodes {
		out.FinalCodes[types.CodeName(k)] = v
	}
	s.mu.Unlock()
	a.cache.mu.Lock()
	out.CacheHits, out.CacheMisses = a.cache.hits, a.cache.miss
	a.cache.mu.Unlock()
	return out
}

// sortedKeys returns the keys of m in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
