package testnet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	rpcclient "github.com/cometbft/cometbft/rpc/client"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/node"
)

// Invariant names.
const (
	InvAgreement   = "agreement"   // two nodes disagree about a height
	InvValidity    = "validity"    // a node's certified history is not well-formed
	InvPrefix      = "prefix"      // a node's history is not a prefix of a more advanced node's
	InvDeterminism = "determinism" // one node committed a height twice with different results
)

// Violation is one violated invariant.
type Violation struct {
	Invariant string
	Node      int   // the node on which it was observed
	Other     int   // the node it disagrees with; -1 if not applicable
	Height    int64 // 0 if not applicable
	Repo      string
	Branch    string
	Seq       uint64
	Detail    string
}

func (v Violation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] node %d", v.Invariant, v.Node)
	if v.Other >= 0 {
		fmt.Fprintf(&b, " vs node %d", v.Other)
	}
	if v.Height > 0 {
		fmt.Fprintf(&b, " height %d", v.Height)
	}
	if v.Repo != "" {
		fmt.Fprintf(&b, " %s/%s", v.Repo, v.Branch)
		if v.Seq > 0 {
			fmt.Fprintf(&b, " #%d", v.Seq)
		}
	}
	return b.String() + ": " + v.Detail
}

// NodeSummary describes a node as the checker saw it.
type NodeSummary struct {
	Node     int
	Running  bool
	Honest   bool
	Height   int64 // of the state snapshot that was checked
	AppHash  string
	Branches int
	Commits  int // commit records (heights) known for this node
}

// Report is the result of a check.
type Report struct {
	Violations []Violation
	Nodes      []NodeSummary
	// What was compared, so that "no violations" can be told apart from
	// "nothing checked".
	BlocksCompared  int // (height, pair of nodes) block comparisons
	RecordsCompared int // (height, pair of nodes) commit record comparisons
	StatesCompared  int // of which with full state digests
	EntriesChecked  int // history entries walked
	ObjectsChecked  int // Git objects fetched and re-hashed
	PrefixCompared  int // history entries compared across nodes
	// Notes are things the checker could not check.
	Notes   []string
	Elapsed time.Duration
}

// OK reports whether no invariant is violated.
func (r *Report) OK() bool { return len(r.Violations) == 0 }

// String renders the report for humans.
func (r *Report) String() string {
	var b strings.Builder
	if r.OK() {
		b.WriteString("invariants OK")
	} else {
		fmt.Fprintf(&b, "%d INVARIANT VIOLATION(S)", len(r.Violations))
	}
	fmt.Fprintf(&b, " (compared: %d blocks, %d commit records, %d states; walked %d history entries, %d objects; %d prefix entries; %v)\n",
		r.BlocksCompared, r.RecordsCompared, r.StatesCompared, r.EntriesChecked, r.ObjectsChecked, r.PrefixCompared, r.Elapsed.Round(time.Millisecond))
	for _, n := range r.Nodes {
		role := "honest"
		if !n.Honest {
			role = "BYZANTINE-APP (excluded)"
		}
		state := "running"
		if !n.Running {
			state = "down"
		}
		fmt.Fprintf(&b, "  node %d: %s, %s, height %d, app hash %.16s, %d branches, %d commit records\n",
			n.Node, state, role, n.Height, n.AppHash, n.Branches, n.Commits)
	}
	const maxShown = 40
	for i, v := range r.Violations {
		if i == maxShown {
			fmt.Fprintf(&b, "  ... and %d more\n", len(r.Violations)-maxShown)
			break
		}
		fmt.Fprintf(&b, "  VIOLATION %s\n", v)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return b.String()
}

// ------------------------------------------------------------ recorder

// recorder collects the commit records of one node over all its
// incarnations.
type recorder struct {
	mu        sync.Mutex
	recs      map[int64]node.CommitRecord
	conflicts []string
}

func newRecorder() *recorder { return &recorder{recs: map[int64]node.CommitRecord{}} }

func (r *recorder) add(rec node.CommitRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mergeRecord(r.recs, &r.conflicts, rec)
}

// mergeRecord adds rec. A node may commit a height more than once only
// if it crashed after the application committed and before CometBFT
// recorded that (then the application reports the height in Info and
// the block is NOT re-executed), so in practice a height is committed
// once; whatever happens, the results must be equal.
func mergeRecord(recs map[int64]node.CommitRecord, conflicts *[]string, rec node.CommitRecord) {
	old, ok := recs[rec.Height]
	if ok {
		if !bytes.Equal(old.AppHash, rec.AppHash) {
			*conflicts = append(*conflicts, fmt.Sprintf("height %d committed with app hash %x and again with %x", rec.Height, old.AppHash, rec.AppHash))
		} else if len(old.StateDigest) > 0 && len(rec.StateDigest) > 0 && !bytes.Equal(old.StateDigest, rec.StateDigest) {
			*conflicts = append(*conflicts, fmt.Sprintf("height %d committed with state digest %x and again with %x", rec.Height, old.StateDigest, rec.StateDigest))
		}
		if len(rec.StateDigest) == 0 {
			rec.StateDigest = old.StateDigest
		}
	}
	recs[rec.Height] = rec
}

func (r *recorder) snapshot() (map[int64]node.CommitRecord, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int64]node.CommitRecord, len(r.recs))
	for k, v := range r.recs {
		out[k] = v
	}
	return out, append([]string(nil), r.conflicts...)
}

// commitRecords returns the commit records of node i and the conflicts
// among them.
func (c *Cluster) commitRecords(i int) (map[int64]node.CommitRecord, []string) {
	m := c.members[i]
	if c.opts.Mode != Subprocess {
		return m.rec.snapshot()
	}
	list, err := node.ReadCommitLog(filepath.Join(m.cfg.Home, "commits.jsonl"))
	recs := map[int64]node.CommitRecord{}
	var conflicts []string
	if err != nil {
		return recs, []string{"cannot read commit log: " + err.Error()}
	}
	for _, r := range list {
		mergeRecord(recs, &conflicts, r)
	}
	return recs, conflicts
}

// ---------------------------------------------------------------- views

// Snapshot is the part of a node's committed state the checker walks.
type Snapshot struct {
	Height  int64
	AppHash []byte
	Repos   map[string]*app.Repo
	// StateJSON is the JSON of the complete state (in-process only).
	StateJSON []byte
}

// View is read access to one node.
type View interface {
	RPC() rpcclient.Client
	// Snapshot returns the last committed state.
	Snapshot() (*Snapshot, error)
	// Repo returns one repository of the last committed state, or nil.
	Repo(id string) (*app.Repo, error)
	// History returns the entries from..to of a branch.
	History(repo, branch string, from, to uint64) ([]*app.HistoryEntry, error)
	// Object returns an object of a repository's committed store;
	// gitobj.ErrNotFound if it does not exist.
	Object(repo string, id gitobj.ID) (gitobj.Object, error)
}

// view returns a view of node i, or nil if it is not running.
func (c *Cluster) view(i int) View {
	m := c.members[i]
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch {
	case m.n != nil:
		return localView{m.n}
	case m.rpc != nil:
		return remoteView{ctx: c.ctx, rpc: m.rpc}
	}
	return nil
}

// View returns a view of node i, or nil if it is not running.
func (c *Cluster) View(i int) View { return c.view(i) }

type localView struct{ n *node.Node }

func (v localView) RPC() rpcclient.Client { return v.n.RPC() }

func (v localView) Snapshot() (*Snapshot, error) {
	st := v.n.App().Committed() // immutable
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return &Snapshot{Height: st.Height, AppHash: st.AppHash, Repos: st.Repos, StateJSON: b}, nil
}

func (v localView) Repo(id string) (*app.Repo, error) {
	return v.n.App().Committed().Repos[id], nil
}

func (v localView) History(repo, branch string, from, to uint64) ([]*app.HistoryEntry, error) {
	var out []*app.HistoryEntry
	for s := from; s <= to; s++ {
		e, err := v.n.App().History(repo, branch, s)
		if err != nil {
			return nil, err
		}
		if e == nil {
			break
		}
		out = append(out, e)
	}
	return out, nil
}

func (v localView) Object(repo string, id gitobj.ID) (gitobj.Object, error) {
	return v.n.App().Objects(repo).Get(id)
}

// remoteView reads a node through ABCI queries over RPC.
type remoteView struct {
	ctx context.Context
	rpc rpcclient.Client
}

func (v remoteView) RPC() rpcclient.Client { return v.rpc }

func (v remoteView) query(path string, data []byte) ([]byte, int64, bool, error) {
	ctx, cancel := context.WithTimeout(v.ctx, 30*time.Second)
	defer cancel()
	res, err := v.rpc.ABCIQuery(ctx, path, data)
	if err != nil {
		return nil, 0, false, err
	}
	if res.Response.Code != 0 {
		return nil, res.Response.Height, false, nil
	}
	return res.Response.Value, res.Response.Height, true, nil
}

func (v remoteView) Snapshot() (*Snapshot, error) {
	// One query, answered by the node from one immutable state (see
	// node.StateQueryPath). The application's own queries return one
	// repository per round trip, and a node that keeps committing does
	// not answer a sequence of them from the same state.
	val, _, ok, err := v.query(node.StateQueryPath, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("query " + node.StateQueryPath + " failed")
	}
	st := new(app.State)
	if err := json.Unmarshal(val, st); err != nil {
		return nil, err
	}
	return &Snapshot{Height: st.Height, AppHash: st.AppHash, Repos: st.Repos, StateJSON: val}, nil
}

func (v remoteView) Repo(id string) (*app.Repo, error) {
	val, _, ok, err := v.query("/repo/"+id, nil)
	if err != nil || !ok {
		return nil, err
	}
	r := new(app.Repo)
	if err := json.Unmarshal(val, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (v remoteView) History(repo, branch string, from, to uint64) ([]*app.HistoryEntry, error) {
	var out []*app.HistoryEntry
	for from <= to {
		limit := to - from + 1
		if limit > 1000 {
			limit = 1000
		}
		val, _, ok, err := v.query("/history/"+repo+"/"+branch, []byte(fmt.Sprintf("%d,%d", from, limit)))
		if err != nil {
			return nil, err
		}
		if !ok {
			return out, nil
		}
		var es []*app.HistoryEntry
		if err := json.Unmarshal(val, &es); err != nil {
			return nil, err
		}
		if len(es) == 0 {
			break
		}
		out = append(out, es...)
		from += uint64(len(es))
	}
	return out, nil
}

func (v remoteView) Object(repo string, id gitobj.ID) (gitobj.Object, error) {
	val, _, ok, err := v.query("/object/"+repo+"/"+id.String(), nil)
	if err != nil {
		return gitobj.Object{}, err
	}
	if !ok || len(val) == 0 {
		return gitobj.Object{}, fmt.Errorf("%w: %s", gitobj.ErrNotFound, id)
	}
	return gitobj.Object{Type: gitobj.ObjType(val[0]), Data: val[1:]}, nil
}

// -------------------------------------------------------------- checker

// Checker checks the safety invariants of a cluster.
type Checker struct {
	c *Cluster
	// MaxBlocks bounds the number of most recent heights whose blocks
	// are compared through RPC (0: all heights).
	MaxBlocks int64
	// SkipObjects skips fetching and re-hashing Git objects.
	SkipObjects bool
}

// NewChecker returns a checker for the cluster.
func NewChecker(c *Cluster) *Checker { return &Checker{c: c} }

// Check runs a full check with default settings.
func (c *Cluster) Check() *Report { return NewChecker(c).Check() }

// MustCheck runs a full check and fails the test if an invariant is
// violated. The report is logged in any case.
func (c *Cluster) MustCheck(tb testing.TB) *Report {
	tb.Helper()
	r := c.Check()
	if r.OK() {
		tb.Log(r.String())
	} else {
		tb.Error(r.String())
	}
	return r
}

type blockInfo struct {
	hash, appHash, resultsHash, dataHash []byte
}

type nodeData struct {
	idx     int
	honest  bool
	view    View
	snap    *Snapshot
	recs    map[int64]node.CommitRecord
	blocks  map[int64]blockInfo
	history map[string][]*app.HistoryEntry // "repo\x00branch"
}

// Check checks all invariants on the current state of the cluster. It
// can run while the network is making progress.
func (ck *Checker) Check() *Report {
	start := time.Now()
	c := ck.c
	rep := &Report{}
	add := func(v Violation) { rep.Violations = append(rep.Violations, v) }

	nodes := make([]*nodeData, c.N())
	for i := range nodes {
		nd := &nodeData{idx: i, honest: !c.members[i].byzantine, history: map[string][]*app.HistoryEntry{}}
		nodes[i] = nd
		var conflicts []string
		nd.recs, conflicts = c.commitRecords(i)
		if nd.honest {
			for _, d := range conflicts {
				add(Violation{Invariant: InvDeterminism, Node: i, Other: -1, Detail: d})
			}
		}
		nd.view = c.view(i)
		sum := NodeSummary{Node: i, Honest: nd.honest, Running: nd.view != nil, Commits: len(nd.recs)}
		if nd.view != nil {
			snap, err := nd.view.Snapshot()
			if err != nil {
				rep.Notes = append(rep.Notes, fmt.Sprintf("node %d: no snapshot: %v", i, err))
				nd.view = nil
				sum.Running = false
			} else {
				nd.snap = snap
				sum.Height = snap.Height
				sum.AppHash = hex.EncodeToString(snap.AppHash)
				for _, r := range snap.Repos {
					sum.Branches += len(r.Branches)
				}
			}
		} else {
			for h := range nd.recs {
				if h > sum.Height {
					sum.Height = h
					sum.AppHash = hex.EncodeToString(nd.recs[h].AppHash)
				}
			}
		}
		rep.Nodes = append(rep.Nodes, sum)
	}

	var honest []*nodeData
	for _, nd := range nodes {
		if nd.honest {
			honest = append(honest, nd)
		} else {
			rep.Notes = append(rep.Notes, fmt.Sprintf("node %d has a Byzantine application and is not checked", nd.idx))
		}
	}

	ck.checkBlocks(rep, honest)
	ck.checkRecords(rep, honest)
	ck.checkStates(rep, honest)
	// The walks of different nodes are independent; run them together.
	parts := make([]*Report, len(honest))
	var wg sync.WaitGroup
	for k, nd := range honest {
		if nd.snap == nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("node %d is down: its history and objects were not walked", nd.idx))
			continue
		}
		parts[k] = &Report{}
		wg.Add(1)
		go func(part *Report, nd *nodeData) {
			defer wg.Done()
			ck.checkValidity(part, nd)
		}(parts[k], nd)
	}
	wg.Wait()
	for _, p := range parts {
		if p != nil {
			rep.Violations = append(rep.Violations, p.Violations...)
			rep.Notes = append(rep.Notes, p.Notes...)
			rep.EntriesChecked += p.EntriesChecked
			rep.ObjectsChecked += p.ObjectsChecked
		}
	}
	ck.checkPrefix(rep, honest)

	sort.SliceStable(rep.Violations, func(a, b int) bool {
		x, y := rep.Violations[a], rep.Violations[b]
		if x.Invariant != y.Invariant {
			return x.Invariant < y.Invariant
		}
		return x.Height < y.Height
	})
	rep.Elapsed = time.Since(start)
	return rep
}

// fetchBlocks loads the block metas of heights lo..hi of a node.
func fetchBlocks(ctx context.Context, rpc rpcclient.Client, lo, hi int64) (map[int64]blockInfo, error) {
	out := map[int64]blockInfo{}
	for max := hi; max >= lo; {
		min := max - 19 // the RPC returns at most 20 metas
		if min < lo {
			min = lo
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res, err := rpc.BlockchainInfo(cctx, min, max)
		cancel()
		if err != nil {
			return nil, err
		}
		if len(res.BlockMetas) == 0 {
			return nil, fmt.Errorf("no block metas for %d..%d", min, max)
		}
		for _, bm := range res.BlockMetas {
			out[bm.Header.Height] = blockInfo{
				hash: bm.BlockID.Hash, appHash: bm.Header.AppHash,
				resultsHash: bm.Header.LastResultsHash, dataHash: bm.Header.DataHash,
			}
		}
		max = min - 1
	}
	return out, nil
}

// checkBlocks: agreement on the chain. For every height two nodes have
// in their block stores, the block hashes are equal. (The block hash
// covers the header, which contains the app hash after the previous
// block and the hash of the previous block's results; they are compared
// separately only to make reports more readable.)
func (ck *Checker) checkBlocks(rep *Report, nodes []*nodeData) {
	ctx := ck.c.ctx
	for _, nd := range nodes {
		if nd.view == nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, err := nd.view.RPC().Status(cctx)
		cancel()
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("node %d: status: %v", nd.idx, err))
			continue
		}
		hi := st.SyncInfo.LatestBlockHeight
		lo := st.SyncInfo.EarliestBlockHeight
		if lo < 1 {
			lo = 1
		}
		if ck.MaxBlocks > 0 && hi-lo+1 > ck.MaxBlocks {
			lo = hi - ck.MaxBlocks + 1
		}
		if hi < lo {
			continue
		}
		nd.blocks, err = fetchBlocks(ctx, nd.view.RPC(), lo, hi)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("node %d: blocks %d..%d: %v", nd.idx, lo, hi, err))
		}
	}
	for a := 0; a < len(nodes); a++ {
		for b := a + 1; b < len(nodes); b++ {
			x, y := nodes[a], nodes[b]
			for h, bx := range x.blocks {
				by, ok := y.blocks[h]
				if !ok {
					continue
				}
				rep.BlocksCompared++
				if bytes.Equal(bx.hash, by.hash) {
					continue
				}
				what := "block hashes differ"
				switch {
				case !bytes.Equal(bx.appHash, by.appHash):
					what = fmt.Sprintf("app hashes in header differ (%x vs %x)", bx.appHash, by.appHash)
				case !bytes.Equal(bx.dataHash, by.dataHash):
					what = "blocks contain different transactions"
				case !bytes.Equal(bx.resultsHash, by.resultsHash):
					what = "results of the previous block differ"
				}
				rep.Violations = append(rep.Violations, Violation{
					Invariant: InvAgreement, Node: x.idx, Other: y.idx, Height: h,
					Detail: fmt.Sprintf("%s: block %x vs %x", what, bx.hash, by.hash),
				})
			}
		}
	}
	// Tie the applications to the chain: the app hash a node's
	// application computed for height h is the one in the header of
	// block h+1 (of any node that has it).
	for _, nd := range nodes {
		for h, rec := range nd.recs {
			for _, other := range nodes {
				b, ok := other.blocks[h+1]
				if !ok {
					continue
				}
				if !bytes.Equal(b.appHash, rec.AppHash) {
					rep.Violations = append(rep.Violations, Violation{
						Invariant: InvAgreement, Node: nd.idx, Other: other.idx, Height: h,
						Detail: fmt.Sprintf("application computed app hash %x, header of block %d says %x", rec.AppHash, h+1, b.appHash),
					})
				}
				break
			}
		}
	}
}

// checkRecords: agreement on the application state, for every height
// two nodes committed (including nodes that are down now).
func (ck *Checker) checkRecords(rep *Report, nodes []*nodeData) {
	for a := 0; a < len(nodes); a++ {
		for b := a + 1; b < len(nodes); b++ {
			x, y := nodes[a], nodes[b]
			for h, rx := range x.recs {
				ry, ok := y.recs[h]
				if !ok {
					continue
				}
				rep.RecordsCompared++
				if !bytes.Equal(rx.AppHash, ry.AppHash) {
					rep.Violations = append(rep.Violations, Violation{
						Invariant: InvAgreement, Node: x.idx, Other: y.idx, Height: h,
						Detail: fmt.Sprintf("app hash after the block: %x vs %x", rx.AppHash, ry.AppHash),
					})
					continue
				}
				if len(rx.StateDigest) == 0 || len(ry.StateDigest) == 0 {
					continue
				}
				rep.StatesCompared++
				if !bytes.Equal(rx.StateDigest, ry.StateDigest) {
					rep.Violations = append(rep.Violations, Violation{
						Invariant: InvAgreement, Node: x.idx, Other: y.idx, Height: h,
						Detail: fmt.Sprintf("app hashes are equal but the state JSON differs (digest %x vs %x): the app hash does not cover the whole state", rx.StateDigest, ry.StateDigest),
					})
				}
				if rx.BlockTime != ry.BlockTime {
					rep.Violations = append(rep.Violations, Violation{
						Invariant: InvAgreement, Node: x.idx, Other: y.idx, Height: h,
						Detail: fmt.Sprintf("block time %d vs %d", rx.BlockTime, ry.BlockTime),
					})
				}
			}
		}
	}
}

// checkStates compares the current state snapshots of nodes that happen
// to be at the same height, byte by byte.
func (ck *Checker) checkStates(rep *Report, nodes []*nodeData) {
	for a := 0; a < len(nodes); a++ {
		for b := a + 1; b < len(nodes); b++ {
			x, y := nodes[a], nodes[b]
			if x.snap == nil || y.snap == nil || x.snap.Height != y.snap.Height {
				continue
			}
			if !bytes.Equal(x.snap.AppHash, y.snap.AppHash) {
				rep.Violations = append(rep.Violations, Violation{
					Invariant: InvAgreement, Node: x.idx, Other: y.idx, Height: x.snap.Height,
					Detail: fmt.Sprintf("committed app hash %x vs %x", x.snap.AppHash, y.snap.AppHash),
				})
				continue
			}
			var jx, jy []byte
			if x.snap.StateJSON != nil && y.snap.StateJSON != nil {
				jx, jy = x.snap.StateJSON, y.snap.StateJSON
			} else {
				jx, _ = json.Marshal(x.snap.Repos)
				jy, _ = json.Marshal(y.snap.Repos)
			}
			rep.StatesCompared++
			if !bytes.Equal(jx, jy) {
				rep.Violations = append(rep.Violations, Violation{
					Invariant: InvAgreement, Node: x.idx, Other: y.idx, Height: x.snap.Height,
					Detail: "state JSON differs: " + firstDiff(jx, jy),
				})
			}
		}
	}
}

func firstDiff(a, b []byte) string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	ctx := func(s []byte) string {
		lo, hi := n-40, n+40
		if lo < 0 {
			lo = 0
		}
		if hi > len(s) {
			hi = len(s)
		}
		return string(s[lo:hi])
	}
	return fmt.Sprintf("at byte %d: ...%s... vs ...%s...", n, ctx(a), ctx(b))
}

func branchKey(repo, branch string) string { return repo + "\x00" + branch }

// checkValidity walks the certified history of every branch of a node.
func (ck *Checker) checkValidity(rep *Report, nd *nodeData) {
	repos := make([]string, 0, len(nd.snap.Repos))
	for id := range nd.snap.Repos {
		repos = append(repos, id)
	}
	sort.Strings(repos)
	for _, id := range repos {
		repo := nd.snap.Repos[id]
		bad := func(branch string, seq uint64, h int64, format string, a ...any) {
			rep.Violations = append(rep.Violations, Violation{
				Invariant: InvValidity, Node: nd.idx, Other: -1, Height: h,
				Repo: id, Branch: branch, Seq: seq, Detail: fmt.Sprintf(format, a...),
			})
		}
		if repo.ID != id {
			bad("", 0, 0, "repository is stored under %q but says its ID is %q", id, repo.ID)
		}
		if repo.Policy == nil {
			bad("", 0, 0, "repository has no policy")
		} else {
			if err := repo.Policy.Validate(); err != nil {
				bad("", 0, 0, "invalid policy in state: %v", err)
			}
			if repo.Policy.Hash() != repo.PolicyHash {
				bad("", 0, 0, "policy hash in state does not match the policy")
			}
		}
		walker := &objWalker{view: nd.view, repo: id, seen: map[gitobj.ID]gitobj.ObjType{}}
		branches := make([]string, 0, len(repo.Branches))
		for b := range repo.Branches {
			branches = append(branches, b)
		}
		sort.Strings(branches)
		for _, bname := range branches {
			br := repo.Branches[bname]
			entries, err := nd.view.History(id, bname, 1, br.Seq)
			if err != nil {
				rep.Notes = append(rep.Notes, fmt.Sprintf("node %d: history of %s/%s: %v", nd.idx, id, bname, err))
				continue
			}
			nd.history[branchKey(id, bname)] = entries
			if uint64(len(entries)) != br.Seq {
				bad(bname, 0, 0, "branch has seq %d but %d history entries exist", br.Seq, len(entries))
			}
			var digest gitobj.Digest
			prev := gitobj.ZeroID
			var prevHeight int64
			seen := map[gitobj.ID]uint64{}
			for k, e := range entries {
				seq := uint64(k + 1)
				rep.EntriesChecked++
				if e.Seq != seq {
					bad(bname, seq, e.Height, "entry has seq %d", e.Seq)
				}
				if e.Repo != id || e.Branch != bname {
					bad(bname, seq, e.Height, "entry belongs to %s/%s", e.Repo, e.Branch)
				}
				if e.Parent != prev {
					bad(bname, seq, e.Height, "parent is %s but the previous entry's commit is %s", e.Parent, prev)
				}
				if e.Commit.IsZero() {
					bad(bname, seq, e.Height, "zero commit")
				}
				if first, dup := seen[e.Commit]; dup {
					bad(bname, seq, e.Height, "commit %s was already accepted as #%d", e.Commit, first)
				}
				seen[e.Commit] = seq
				if e.Height < prevHeight || e.Height < 1 || e.Height > nd.snap.Height {
					bad(bname, seq, e.Height, "height %d out of order (previous entry %d, state %d)", e.Height, prevHeight, nd.snap.Height)
				}
				if seq > 1 && e.ReceiptHash == (gitobj.Digest{}) {
					bad(bname, seq, e.Height, "accepted without a receipt")
				}
				prevHeight = e.Height
				digest = app.ChainDigest(digest, e)
				prev = e.Commit

				if !ck.SkipObjects {
					n, err := walker.commit(e.Commit, e.Parent)
					rep.ObjectsChecked += n
					if err != nil {
						bad(bname, seq, e.Height, "commit %s: %v", e.Commit, err)
					}
				}
			}
			if uint64(len(entries)) == br.Seq {
				if digest != br.HistDigest {
					bad(bname, br.Seq, 0, "history digest in state is %s, the entries hash to %s", br.HistDigest, digest)
				}
				if br.Head != prev {
					bad(bname, br.Seq, 0, "branch head is %s, last accepted commit is %s", br.Head, prev)
				}
			}
		}
	}
}

// objWalker checks that everything reachable from a commit exists in a
// node's object store, has the right type and hashes to its ID.
type objWalker struct {
	view View
	repo string
	seen map[gitobj.ID]gitobj.ObjType
}

func (w *objWalker) get(id gitobj.ID, want gitobj.ObjType) (gitobj.Object, bool, error) {
	if t, ok := w.seen[id]; ok {
		if t != want {
			return gitobj.Object{}, true, fmt.Errorf("object %s is a %s, referenced as a %s", id, t, want)
		}
		return gitobj.Object{}, true, nil
	}
	o, err := w.view.Object(w.repo, id)
	if err != nil {
		if errors.Is(err, gitobj.ErrNotFound) {
			return o, false, fmt.Errorf("%s %s is missing from the object store", want, id)
		}
		return o, false, fmt.Errorf("%s %s: %v", want, id, err)
	}
	if got := o.ID(); got != id {
		return o, false, fmt.Errorf("object stored as %s hashes to %s", id, got)
	}
	w.seen[id] = o.Type
	if o.Type != want {
		return o, false, fmt.Errorf("object %s is a %s, referenced as a %s", id, o.Type, want)
	}
	return o, false, nil
}

// commit walks one commit; it returns the number of objects fetched.
func (w *objWalker) commit(id, parent gitobj.ID) (int, error) {
	o, cached, err := w.get(id, gitobj.TypeCommit)
	if err != nil {
		return 0, err
	}
	if cached {
		return 0, nil
	}
	n := 1
	c, err := gitobj.ParseCommit(o.Data)
	if err != nil {
		return n, fmt.Errorf("unparsable: %v", err)
	}
	switch {
	case parent.IsZero() && len(c.Parents) != 0:
		return n, fmt.Errorf("accepted as a root commit but has %d parent(s)", len(c.Parents))
	case !parent.IsZero() && (len(c.Parents) != 1 || c.Parents[0] != parent):
		return n, fmt.Errorf("accepted on top of %s but its parents are %v", parent, c.Parents)
	}
	m, err := w.tree(c.Tree, 0)
	return n + m, err
}

func (w *objWalker) tree(id gitobj.ID, depth int) (int, error) {
	if depth > 256 {
		return 0, fmt.Errorf("tree %s: nesting too deep", id)
	}
	o, cached, err := w.get(id, gitobj.TypeTree)
	if err != nil || cached {
		return 0, err
	}
	n := 1
	entries, err := gitobj.ParseTree(o.Data)
	if err != nil {
		return n, fmt.Errorf("tree %s unparsable: %v", id, err)
	}
	for _, e := range entries {
		if e.Mode == gitobj.ModeDir {
			m, err := w.tree(e.ID, depth+1)
			n += m
			if err != nil {
				return n, err
			}
			continue
		}
		_, cached, err := w.get(e.ID, gitobj.TypeBlob)
		if err != nil {
			return n, fmt.Errorf("%s in tree %s: %v", e.Name, id, err)
		}
		if !cached {
			n++
		}
	}
	return n, nil
}

// checkPrefix: the history of every node is a prefix of the history of
// the most advanced node.
func (ck *Checker) checkPrefix(rep *Report, nodes []*nodeData) {
	var ref *nodeData
	for _, nd := range nodes {
		if nd.snap != nil && (ref == nil || nd.snap.Height > ref.snap.Height) {
			ref = nd
		}
	}
	if ref == nil {
		return
	}
	for _, nd := range nodes {
		if nd == ref || nd.snap == nil {
			continue
		}
		for id, repo := range nd.snap.Repos {
			refRepo, ok := ref.snap.Repos[id]
			if !ok {
				rep.Violations = append(rep.Violations, Violation{
					Invariant: InvPrefix, Node: nd.idx, Other: ref.idx, Height: nd.snap.Height, Repo: id,
					Detail: fmt.Sprintf("repository exists at height %d but not on the more advanced node (height %d)", nd.snap.Height, ref.snap.Height),
				})
				continue
			}
			if !bytes.Equal(repo.Creator, refRepo.Creator) {
				rep.Violations = append(rep.Violations, Violation{
					Invariant: InvPrefix, Node: nd.idx, Other: ref.idx, Repo: id,
					Detail: "repository has different creators",
				})
			}
			if repo.PolicyVersion > refRepo.PolicyVersion {
				rep.Violations = append(rep.Violations, Violation{
					Invariant: InvPrefix, Node: nd.idx, Other: ref.idx, Repo: id,
					Detail: fmt.Sprintf("policy version %d is ahead of the more advanced node's %d", repo.PolicyVersion, refRepo.PolicyVersion),
				})
			}
			for bname, br := range repo.Branches {
				refBr, ok := refRepo.Branches[bname]
				v := Violation{Invariant: InvPrefix, Node: nd.idx, Other: ref.idx, Repo: id, Branch: bname}
				if !ok {
					v.Detail = "branch does not exist on the more advanced node"
					rep.Violations = append(rep.Violations, v)
					continue
				}
				if br.Seq > refBr.Seq {
					v.Detail = fmt.Sprintf("branch has %d entries at height %d, the more advanced node has %d at height %d", br.Seq, nd.snap.Height, refBr.Seq, ref.snap.Height)
					rep.Violations = append(rep.Violations, v)
					continue
				}
				mine := nd.history[branchKey(id, bname)]
				theirs := ref.history[branchKey(id, bname)]
				for k, e := range mine {
					if k >= len(theirs) {
						break
					}
					rep.PrefixCompared++
					a, _ := json.Marshal(e)
					b, _ := json.Marshal(theirs[k])
					if !bytes.Equal(a, b) {
						v := v
						v.Seq = uint64(k + 1)
						v.Height = e.Height
						v.Detail = fmt.Sprintf("entries differ: %s vs %s", a, b)
						rep.Violations = append(rep.Violations, v)
						break
					}
				}
				if br.Seq == refBr.Seq && br != refBr {
					v.Detail = fmt.Sprintf("same length but different branch state: %+v vs %+v", br, refBr)
					rep.Violations = append(rep.Violations, v)
				}
			}
		}
	}
}
