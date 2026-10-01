package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/types"
)

// chain drives a set of replicas the way CometBFT would, minus the
// network: every block is prepared by a proposer, validated by every
// replica, finalized and committed by every replica. After every block it
// asserts that all replicas computed the same results and app hash.
type chain struct {
	t        testing.TB
	w        *dosrtest.World
	replicas []*replica
	height   int64
	now      int64 // block time, unix seconds
}

type replica struct {
	name string
	db   dbm.DB
	app  *App
	cfg  Config
}

const testChain = "dosr-test"

func newChain(t testing.TB, cfgs ...Config) *chain {
	t.Helper()
	if len(cfgs) == 0 {
		cfgs = []Config{DefaultConfig()}
	}
	c := &chain{t: t, w: dosrtest.NewWorld(testChain)}
	c.now = c.w.Now + 5
	for i, cfg := range cfgs {
		cfg.Now = func() time.Time { return time.Unix(c.now, 0) }
		db := dbm.NewMemDB()
		a, err := New(db, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.InitChain(context.Background(), &abci.RequestInitChain{ChainId: testChain, InitialHeight: 1}); err != nil {
			t.Fatal(err)
		}
		c.replicas = append(c.replicas, &replica{name: string(rune('A' + i)), db: db, app: a, cfg: cfg})
	}
	return c
}

// reopen simulates a process restart of replica i: a new App on the same
// database. Anything not committed is lost.
func (c *chain) reopen(i int) {
	c.t.Helper()
	r := c.replicas[i]
	a, err := New(r.db, r.cfg)
	if err != nil {
		c.t.Fatal(err)
	}
	r.app = a
}

// blockResult is what a block did.
type blockResult struct {
	included [][]byte
	codes    []uint32
	logs     []string
	rejected bool // the proposal was rejected by ProcessProposal
}

// block runs one height with replica `proposer` proposing from the given
// mempool content.
func (c *chain) block(proposer int, mempool ...[]byte) blockResult {
	c.t.Helper()
	ctx := context.Background()
	h := c.height + 1
	c.now += 2
	bt := time.Unix(c.now, 0)
	pp, err := c.replicas[proposer].app.PrepareProposal(ctx, &abci.RequestPrepareProposal{
		Txs: mempool, MaxTxBytes: 20 << 20, Height: h, Time: bt,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	return c.decide(h, bt, pp.Txs)
}

// rawBlock forces a block with exactly these transactions through
// ProcessProposal (models a Byzantine proposer).
func (c *chain) rawBlock(txs ...[]byte) blockResult {
	c.t.Helper()
	c.now += 2
	return c.decide(c.height+1, time.Unix(c.now, 0), txs)
}

// forcedBlock finalizes a block WITHOUT asking ProcessProposal: what a
// replica sees during block sync / replay, or when more than 2/3 of the
// voting power accepted the block regardless.
func (c *chain) forcedBlock(txs ...[]byte) blockResult {
	c.t.Helper()
	c.now += 2
	return c.finalize(c.height+1, time.Unix(c.now, 0), txs)
}

func (c *chain) decide(h int64, bt time.Time, txs [][]byte) blockResult {
	c.t.Helper()
	ctx := context.Background()
	var statuses []abci.ResponseProcessProposal_ProposalStatus
	for _, r := range c.replicas {
		res, err := r.app.ProcessProposal(ctx, &abci.RequestProcessProposal{Txs: txs, Height: h, Time: bt})
		if err != nil {
			c.t.Fatal(err)
		}
		statuses = append(statuses, res.Status)
	}
	// ProcessProposal must be deterministic across replicas with the
	// same strictness.
	for i, r := range c.replicas {
		for j, q := range c.replicas {
			if r.cfg.StrictProposals == q.cfg.StrictProposals && statuses[i] != statuses[j] {
				c.t.Fatalf("height %d: replicas %s and %s disagree on the proposal (%v vs %v)", h, r.name, q.name, statuses[i], statuses[j])
			}
		}
	}
	for i, s := range statuses {
		if s == abci.ResponseProcessProposal_REJECT && c.replicas[i].cfg.StrictProposals {
			// The round fails; nothing is decided.
			c.assertAgreement()
			return blockResult{rejected: true}
		}
	}
	return c.finalize(h, bt, txs)
}

func (c *chain) finalize(h int64, bt time.Time, txs [][]byte) blockResult {
	c.t.Helper()
	ctx := context.Background()
	out := blockResult{included: txs}
	var first *abci.ResponseFinalizeBlock
	for _, r := range c.replicas {
		res, err := r.app.FinalizeBlock(ctx, &abci.RequestFinalizeBlock{Txs: txs, Height: h, Time: bt})
		if err != nil {
			c.t.Fatal(err)
		}
		if first == nil {
			first = res
			for _, tr := range res.TxResults {
				out.codes = append(out.codes, tr.Code)
				out.logs = append(out.logs, tr.Log)
			}
		} else {
			if !bytes.Equal(first.AppHash, res.AppHash) {
				c.t.Fatalf("height %d: app hash diverged on replica %s", h, r.name)
			}
			a, _ := json.Marshal(first.TxResults)
			b, _ := json.Marshal(res.TxResults)
			if !bytes.Equal(a, b) {
				c.t.Fatalf("height %d: tx results diverged on replica %s:\n%s\n%s", h, r.name, a, b)
			}
		}
	}
	for _, r := range c.replicas {
		if _, err := r.app.Commit(ctx, &abci.RequestCommit{}); err != nil {
			c.t.Fatal(err)
		}
	}
	c.height = h
	c.assertAgreement()
	return out
}

func (c *chain) assertAgreement() {
	c.t.Helper()
	ref, _ := json.Marshal(c.replicas[0].app.Committed())
	for _, r := range c.replicas[1:] {
		got, _ := json.Marshal(r.app.Committed())
		if !bytes.Equal(ref, got) {
			c.t.Fatalf("state of replica %s differs from %s:\n%s\n%s", r.name, c.replicas[0].name, got, ref)
		}
	}
}

func (c *chain) app() *App { return c.replicas[0].app }

func (c *chain) head(repo, branch string) gitobj.ID {
	r, ok := c.app().Committed().Repos[repo]
	if !ok {
		return gitobj.ZeroID
	}
	return r.Branches[branch].Head
}

func (c *chain) checkTx(i int, tx []byte) uint32 {
	c.t.Helper()
	res, err := c.replicas[i].app.CheckTx(context.Background(), &abci.RequestCheckTx{Tx: tx})
	if err != nil {
		c.t.Fatal(err)
	}
	return res.Code
}

// scenario is a repository on the chain together with the contributor's
// copy of it.
type scenario struct {
	c      *chain
	repo   string
	branch string
	git    *dosrtest.Repo
	pol    types.Policy
	polVer uint64
	user   ed25519.PrivateKey
	files  dosrtest.Files
}

// newScenario creates repository `name` with a genesis commit.
func newScenario(c *chain, name string, mut func(*types.Policy)) *scenario {
	c.t.Helper()
	s := &scenario{c: c, repo: name, branch: "main", git: dosrtest.NewRepo(),
		pol: c.w.Policy(), polVer: 1, user: dosrtest.Key("user-" + name)}
	if mut != nil {
		mut(&s.pol)
	}
	s.files = dosrtest.Files{"README.md": "# " + name + "\n", "src/main.go": "package main\n\nfunc main() {}\n"}
	g, b := s.git.Commit(gitobj.ZeroID, s.files, "initial import")
	tx, err := c.w.CreateRepoTx(s.user, name, s.branch, s.pol, g, b)
	if err != nil {
		c.t.Fatal(err)
	}
	r := c.block(0, tx.Bytes())
	if len(r.codes) != 1 || r.codes[0] != types.CodeOK {
		c.t.Fatalf("create repo: %+v", r)
	}
	if c.head(name, s.branch) != g {
		c.t.Fatal("genesis head not set")
	}
	return s
}

// change makes a new candidate commit on top of base that sets path to
// content.
func (s *scenario) change(base gitobj.ID, path, content, msg string) (gitobj.ID, *gitobj.Bundle) {
	f := dosrtest.Files{}
	for k, v := range s.files {
		f[k] = v
	}
	f[path] = content
	return s.git.Commit(base, f, msg)
}

// adopt records that the contributor's working files now include the
// change (call after a change was accepted).
func (s *scenario) adopt(path, content string) { s.files[path] = content }

// review returns the honest review description for a candidate.
func (s *scenario) review(base, cand gitobj.ID, b *gitobj.Bundle) dosrtest.Review {
	return dosrtest.Review{Repo: s.repo, Branch: s.branch, Base: base, Candidate: cand,
		Bundle: b, Policy: s.pol, PolicyVersion: s.polVer}
}

// tx fabricates the AcceptCommit for a review against the committed
// object store of replica 0.
func (s *scenario) tx(rv dosrtest.Review) []byte {
	s.c.t.Helper()
	tx, err := s.c.w.AcceptTx(s.user, rv, s.git.Store)
	if err != nil {
		s.c.t.Fatalf("fabricate tx: %v", err)
	}
	return tx.Bytes()
}

func finalizeReq(h, unix int64, txs ...[]byte) *abci.RequestFinalizeBlock {
	return &abci.RequestFinalizeBlock{Txs: txs, Height: h, Time: time.Unix(unix, 0)}
}

func timeAt(unix int64) time.Time { return time.Unix(unix, 0) }
