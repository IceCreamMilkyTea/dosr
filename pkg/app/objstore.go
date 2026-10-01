package app

import (
	"fmt"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/dosr/dosr/pkg/gitobj"
)

// Key layout of the application database:
//
//	s/state                         JSON State (last committed)
//	h/<repo>\0<branch>\0<seq be64>  JSON HistoryEntry
//	o/<repo>\0<id 20 bytes>         type byte || object data
//
// WHY OBJECTS LIVE IN THE SAME DATABASE AS THE STATE
//
// The result of verifying a bundle depends on which objects the validator
// already has (gitobj.VerifyClosure consults the base store for objects
// the bundle does not carry). The object store is therefore part of the
// replicated state, and it must change atomically with it. If objects
// were written to a separate store (e.g. a Git directory) a crash between
// the two writes could leave objects of a block whose state was not
// committed; when CometBFT replays that block after restart, an earlier
// transaction of the block could then see objects written by a later
// transaction during the first attempt, verify differently than on other
// replicas, and fork the app hash. Writing state, history and objects in
// one atomic batch rules that out. Git directories are maintained as a
// derived, rebuildable view (see Mirror).

var stateKey = []byte("s/state")

func histKey(repo, branch string, seq uint64) []byte {
	k := make([]byte, 0, 2+len(repo)+1+len(branch)+1+8)
	k = append(k, "h/"...)
	k = append(k, repo...)
	k = append(k, 0)
	k = append(k, branch...)
	k = append(k, 0)
	for i := 7; i >= 0; i-- {
		k = append(k, byte(seq>>(8*uint(i))))
	}
	return k
}

func objKey(repo string, id gitobj.ID) []byte {
	k := make([]byte, 0, 2+len(repo)+1+20)
	k = append(k, "o/"...)
	k = append(k, repo...)
	k = append(k, 0)
	return append(k, id[:]...)
}

// objLayer is a copy-on-write layer of pending objects on top of the
// committed database, for all repositories.
//
// Speculative execution (CheckTx, PrepareProposal, ProcessProposal) uses
// throw-away layers; FinalizeBlock uses a layer that Commit writes out.
// Nothing reaches the database except through Commit.
type objLayer struct {
	db      dbm.DB
	parent  *objLayer // optional
	pending map[string]map[gitobj.ID]gitobj.Object
	order   []pendingObj // insertion order, for deterministic writes and mirroring
	// pendingHits counts lookups answered by a pending (uncommitted)
	// object. Evidence verified with pendingHits > 0 depended on
	// speculative objects and must not be cached, see App.evidenceFor.
	pendingHits int
}

type pendingObj struct {
	repo string
	id   gitobj.ID
}

func newObjLayer(db dbm.DB, parent *objLayer) *objLayer {
	return &objLayer{db: db, parent: parent, pending: map[string]map[gitobj.ID]gitobj.Object{}}
}

// repoStore is the gitobj.Store view of one repository in a layer.
type repoStore struct {
	l    *objLayer
	repo string
}

func (l *objLayer) Repo(repo string) gitobj.Store { return repoStore{l, repo} }

func (l *objLayer) lookupPending(repo string, id gitobj.ID) (gitobj.Object, bool) {
	for x := l; x != nil; x = x.parent {
		if o, ok := x.pending[repo][id]; ok {
			return o, true
		}
	}
	return gitobj.Object{}, false
}

func (s repoStore) Has(id gitobj.ID) bool {
	if _, ok := s.l.lookupPending(s.repo, id); ok {
		s.l.pendingHits++
		return true
	}
	ok, err := s.l.db.Has(objKey(s.repo, id))
	if err != nil {
		// A failing local database must not be turned into a
		// (replicated) verification verdict.
		panic(fmt.Sprintf("app: object db: %v", err))
	}
	return ok
}

func (s repoStore) Get(id gitobj.ID) (gitobj.Object, error) {
	if o, ok := s.l.lookupPending(s.repo, id); ok {
		s.l.pendingHits++
		return o, nil
	}
	v, err := s.l.db.Get(objKey(s.repo, id))
	if err != nil {
		panic(fmt.Sprintf("app: object db: %v", err))
	}
	if len(v) == 0 {
		return gitobj.Object{}, fmt.Errorf("%w: %s", gitobj.ErrNotFound, id)
	}
	o := gitobj.Object{Type: gitobj.ObjType(v[0]), Data: v[1:]}
	return o, nil
}

func (s repoStore) Put(o gitobj.Object) (gitobj.ID, error) {
	id := o.ID()
	m := s.l.pending[s.repo]
	if m == nil {
		m = map[gitobj.ID]gitobj.Object{}
		s.l.pending[s.repo] = m
	}
	if _, ok := m[id]; !ok {
		m[id] = o
		s.l.order = append(s.l.order, pendingObj{s.repo, id})
	}
	return id, nil
}

// writeTo adds the layer's objects to a batch.
func (l *objLayer) writeTo(b dbm.Batch) error {
	for _, p := range l.order {
		o := l.pending[p.repo][p.id]
		v := make([]byte, 0, 1+len(o.Data))
		v = append(v, byte(o.Type))
		v = append(v, o.Data...)
		if err := b.Set(objKey(p.repo, p.id), v); err != nil {
			return err
		}
	}
	return nil
}
