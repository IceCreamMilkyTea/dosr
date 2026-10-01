package testnet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	rpcclient "github.com/cometbft/cometbft/rpc/client"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/node"
	"github.com/dosr/dosr/pkg/types"
)

// fakeView is an in-memory node for testing the checker itself: a
// checker that cannot fail proves nothing.
type fakeView struct {
	snap    *Snapshot
	history map[string][]*app.HistoryEntry
	objects map[gitobj.ID]gitobj.Object
}

func (f *fakeView) RPC() rpcclient.Client             { return nil }
func (f *fakeView) Snapshot() (*Snapshot, error)      { return f.snap, nil }
func (f *fakeView) Repo(id string) (*app.Repo, error) { return f.snap.Repos[id], nil }
func (f *fakeView) History(repo, branch string, from, to uint64) ([]*app.HistoryEntry, error) {
	var out []*app.HistoryEntry
	for _, e := range f.history[branchKey(repo, branch)] {
		if e != nil && e.Seq >= from && e.Seq <= to {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeView) Object(_ string, id gitobj.ID) (gitobj.Object, error) {
	o, ok := f.objects[id]
	if !ok {
		return o, fmt.Errorf("%w: %s", gitobj.ErrNotFound, id)
	}
	return o, nil
}

// fakeNode builds a node with one repository whose branch main has n
// accepted commits.
func fakeNode(idx, n int) *nodeData {
	k := Key{Pub: make([]byte, 32), Priv: nil}
	pol := Policy([]ed25519.PublicKey{k.Pub}, nil)
	f := &fakeView{history: map[string][]*app.HistoryEntry{}, objects: map[gitobj.ID]gitobj.Object{}}
	var digest gitobj.Digest
	parent := gitobj.ZeroID
	var entries []*app.HistoryEntry
	for s := 1; s <= n; s++ {
		files := map[string][]byte{
			"README":       []byte("common"),
			"src/main.go":  []byte(fmt.Sprintf("package main // %d", s)),
			"src/a/b/c.go": []byte("package b"),
		}
		id, bundle := BuildCommit(parent, files, fmt.Sprintf("commit %d", s))
		for _, o := range bundle.Objects {
			f.objects[o.ID()] = o
		}
		e := &app.HistoryEntry{
			Repo: "r", Branch: "main", Seq: uint64(s), Commit: id, Parent: parent,
			Height: int64(s + 1), BlockTime: 1750000000 + int64(s),
			TxID: types.TxID(sha256.Sum256([]byte{byte(s)})), PolicyVersion: 1,
			BundleDigest: gitobj.Digest(sha256.Sum256(bundle.Encode())),
		}
		if s > 1 {
			e.ReceiptHash = gitobj.Digest(sha256.Sum256([]byte{1, byte(s)}))
		}
		digest = app.ChainDigest(digest, e)
		entries = append(entries, e)
		parent = id
	}
	f.history[branchKey("r", "main")] = entries
	f.snap = &Snapshot{
		Height: int64(n + 1),
		Repos: map[string]*app.Repo{"r": {
			ID: "r", Creator: k.Pub, Policy: &pol, PolicyVersion: 1, PolicyHash: pol.Hash(),
			Branches: map[string]app.Branch{"main": {Head: parent, Seq: uint64(n), HistDigest: digest}},
		}},
	}
	return &nodeData{idx: idx, honest: true, view: f, snap: f.snap, history: map[string][]*app.HistoryEntry{},
		recs: map[int64]node.CommitRecord{}}
}

func validity(nd *nodeData) *Report {
	rep := &Report{}
	(&Checker{}).checkValidity(rep, nd)
	return rep
}

func expectViolation(t *testing.T, rep *Report, inv, substr string) {
	t.Helper()
	for _, v := range rep.Violations {
		if v.Invariant == inv && strings.Contains(v.Detail, substr) {
			return
		}
	}
	t.Errorf("expected a %s violation containing %q, got:\n%s", inv, substr, rep)
}

func TestCheckerAcceptsValidHistory(t *testing.T) {
	nd := fakeNode(0, 5)
	rep := validity(nd)
	if !rep.OK() {
		t.Fatal(rep)
	}
	if rep.EntriesChecked != 5 || rep.ObjectsChecked < 5*3 {
		t.Fatalf("walked %d entries, %d objects", rep.EntriesChecked, rep.ObjectsChecked)
	}
}

func TestCheckerDetectsViolations(t *testing.T) {
	hist := func(nd *nodeData) []*app.HistoryEntry {
		return nd.view.(*fakeView).history[branchKey("r", "main")]
	}
	setBranch := func(nd *nodeData, f func(b *app.Branch)) {
		b := nd.snap.Repos["r"].Branches["main"]
		f(&b)
		nd.snap.Repos["r"].Branches["main"] = b
	}
	cases := []struct {
		name   string
		break_ func(nd *nodeData)
		want   string
	}{
		{"parent does not chain", func(nd *nodeData) { hist(nd)[2].Parent = hist(nd)[0].Commit }, "parent is"},
		{"sequence gap", func(nd *nodeData) { hist(nd)[3].Seq = 9 }, "entry has seq"},
		{"missing entry", func(nd *nodeData) {
			f := nd.view.(*fakeView)
			f.history[branchKey("r", "main")] = hist(nd)[:4]
		}, "history entries exist"},
		{"digest", func(nd *nodeData) { hist(nd)[1].BundleDigest[0] ^= 1 }, "history digest"},
		{"head", func(nd *nodeData) { setBranch(nd, func(b *app.Branch) { b.Head = hist(nd)[0].Commit }) }, "branch head is"},
		{"duplicate commit", func(nd *nodeData) { hist(nd)[4].Commit = hist(nd)[1].Commit }, "already accepted"},
		{"missing blob", func(nd *nodeData) {
			f := nd.view.(*fakeView)
			for id, o := range f.objects {
				if o.Type == gitobj.TypeBlob && string(o.Data) == "package b" {
					delete(f.objects, id)
				}
			}
		}, "missing from the object store"},
		{"missing commit", func(nd *nodeData) { delete(nd.view.(*fakeView).objects, hist(nd)[2].Commit) }, "missing from the object store"},
		{"corrupt object", func(nd *nodeData) {
			f := nd.view.(*fakeView)
			for id, o := range f.objects {
				if o.Type == gitobj.TypeBlob && string(o.Data) == "common" {
					f.objects[id] = gitobj.Object{Type: gitobj.TypeBlob, Data: []byte("tampered")}
				}
			}
		}, "hashes to"},
		{"no receipt", func(nd *nodeData) { hist(nd)[3].ReceiptHash = gitobj.Digest{} }, "without a receipt"},
		{"policy hash", func(nd *nodeData) { nd.snap.Repos["r"].PolicyHash[0] ^= 1 }, "policy hash"},
		{"height order", func(nd *nodeData) { hist(nd)[2].Height = 1 }, "out of order"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nd := fakeNode(0, 5)
			tc.break_(nd)
			expectViolation(t, validity(nd), InvValidity, tc.want)
		})
	}
}

func TestCheckerPrefixAndAgreement(t *testing.T) {
	ck := &Checker{}
	prefix := func(a, b *nodeData) *Report {
		rep := &Report{}
		ck.checkValidity(rep, a)
		ck.checkValidity(rep, b)
		if !rep.OK() {
			t.Fatalf("setup: %s", rep)
		}
		ck.checkPrefix(rep, []*nodeData{a, b})
		return rep
	}
	// A lagging node is fine.
	if rep := prefix(fakeNode(0, 3), fakeNode(1, 6)); !rep.OK() || rep.PrefixCompared != 3 {
		t.Fatalf("lagging node: %s", rep)
	}
	// A node with a different (internally consistent) history is not.
	a, b := fakeNode(0, 3), fakeNode(1, 6)
	e := a.view.(*fakeView).history[branchKey("r", "main")]
	e[2].TxID[0] ^= 1
	var d gitobj.Digest
	for _, x := range e {
		d = app.ChainDigest(d, x)
	}
	br := a.snap.Repos["r"].Branches["main"]
	br.HistDigest = d
	a.snap.Repos["r"].Branches["main"] = br
	expectViolation(t, prefix(a, b), InvPrefix, "entries differ")
	// A lagging node that is ahead on a branch.
	a, b = fakeNode(0, 6), fakeNode(1, 3)
	a.snap.Height, b.snap.Height = 4, 10
	rep := &Report{}
	ck.checkPrefix(rep, []*nodeData{a, b})
	expectViolation(t, rep, InvPrefix, "more advanced node has")

	// Commit records.
	a, b = fakeNode(0, 1), fakeNode(1, 1)
	a.recs[5] = node.CommitRecord{Height: 5, AppHash: []byte{1}, StateDigest: []byte{7}}
	b.recs[5] = node.CommitRecord{Height: 5, AppHash: []byte{2}, StateDigest: []byte{7}}
	a.recs[6] = node.CommitRecord{Height: 6, AppHash: []byte{3}, StateDigest: []byte{8}}
	b.recs[6] = node.CommitRecord{Height: 6, AppHash: []byte{3}, StateDigest: []byte{9}}
	rep = &Report{}
	ck.checkRecords(rep, []*nodeData{a, b})
	expectViolation(t, rep, InvAgreement, "app hash after the block")
	expectViolation(t, rep, InvAgreement, "state JSON differs")
	if len(rep.Violations) != 2 {
		t.Fatalf("want 2 violations: %s", rep)
	}

	// Snapshots at the same height.
	a, b = fakeNode(0, 2), fakeNode(1, 2)
	b.snap.Repos["r"].PolicyVersion = 2
	rep = &Report{}
	ck.checkStates(rep, []*nodeData{a, b})
	expectViolation(t, rep, InvAgreement, "state JSON differs")

	// One node committing a height twice with different results.
	r := newRecorder()
	r.add(node.CommitRecord{Height: 3, AppHash: []byte{1}})
	r.add(node.CommitRecord{Height: 3, AppHash: []byte{1}})
	if _, c := r.snapshot(); len(c) != 0 {
		t.Fatal("equal re-commit reported")
	}
	r.add(node.CommitRecord{Height: 3, AppHash: []byte{2}})
	if _, c := r.snapshot(); len(c) != 1 {
		t.Fatal("conflicting re-commit not reported")
	}
}
