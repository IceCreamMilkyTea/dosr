package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/dosr/dosr/pkg/gitobj"
)

// Mirror maintains, for every repository, a bare Git directory that stock
// Git can clone from: <Dir>/<repo>.git. It is a DERIVED VIEW of the
// committed chain state: it is updated after blocks are durable, it is
// never read by the state machine, and it can be deleted and rebuilt at
// any time (Rebuild). See design log D1 for why the state machine cannot
// use Git directories as its store.
type Mirror struct {
	Dir string
	mu  sync.Mutex
}

// Hook returns a function for Config.OnCommit.
func (m *Mirror) Hook(a func() *App) func(CommitInfo) {
	return func(ci CommitInfo) {
		for _, e := range ci.Accepted {
			// Errors only affect the view; the next accepted commit
			// or a Rebuild repairs it.
			_ = m.Sync(a(), e.Repo, e.Branch, e.Commit)
		}
	}
}

// Sync copies the closure of head into the mirror and points the branch
// at it.
func (m *Mirror) Sync(a *App, repo, branch string, head gitobj.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, err := gitobj.NewDiskStore(filepath.Join(m.Dir, repo+".git"))
	if err != nil {
		return err
	}
	src := a.Objects(repo)
	// Depth-first copy. An object already in the mirror has its closure
	// there too, because children are written before their parent.
	var copyObj func(id gitobj.ID, depth int) error
	copyObj = func(id gitobj.ID, depth int) error {
		if id.IsZero() || ds.Has(id) {
			return nil
		}
		if depth > 1<<16 {
			return fmt.Errorf("mirror: history too deep")
		}
		o, err := src.Get(id)
		if err != nil {
			return err
		}
		switch o.Type {
		case gitobj.TypeCommit:
			c, err := gitobj.ParseCommit(o.Data)
			if err != nil {
				return err
			}
			for _, p := range c.Parents {
				if err := copyObj(p, depth+1); err != nil {
					return err
				}
			}
			if err := copyObj(c.Tree, depth+1); err != nil {
				return err
			}
		case gitobj.TypeTree:
			es, err := gitobj.ParseTree(o.Data)
			if err != nil {
				return err
			}
			for _, e := range es {
				if err := copyObj(e.ID, depth+1); err != nil {
					return err
				}
			}
		}
		_, err = ds.Put(o)
		return err
	}
	if err := copyObj(head, 0); err != nil {
		return err
	}
	ref := filepath.Join(ds.Dir(), "refs", "heads", filepath.FromSlash(branch))
	if err := os.MkdirAll(filepath.Dir(ref), 0o755); err != nil {
		return err
	}
	tmp := ref + ".tmp"
	if err := os.WriteFile(tmp, []byte(head.String()+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, ref)
}

// Rebuild brings the mirror in line with the committed state.
func (m *Mirror) Rebuild(a *App) error {
	st := a.Committed()
	for _, id := range sortedKeys(st.Repos) {
		r := st.Repos[id]
		for _, b := range sortedKeys(r.Branches) {
			if h := r.Branches[b].Head; !h.IsZero() {
				if err := m.Sync(a, id, b, h); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
