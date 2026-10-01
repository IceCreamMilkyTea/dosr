package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/dosr/dosr/pkg/gitobj"
)

// edit is one file-level change applied to a tree: Delete removes the
// path, otherwise the path is set to Data with Mode (ModeFile if zero).
type edit struct {
	Data   []byte
	Mode   uint32
	Delete bool
}

// patcher rewrites trees along edited paths. It reads from view (base
// repository plus the source commit's bundle) and writes the new objects
// into out (a MemStore) so that they can be collected into a bundle.
type patcher struct {
	view gitobj.Store
	out  *gitobj.MemStore
	// created records every object id written by this patcher.
	created map[gitobj.ID]bool
}

func newPatcher(view gitobj.Store) *patcher {
	return &patcher{view: view, out: gitobj.NewMemStore(), created: map[gitobj.ID]bool{}}
}

func (p *patcher) put(o gitobj.Object) (gitobj.ID, error) {
	id, err := p.out.Put(o)
	if err != nil {
		return gitobj.ZeroID, err
	}
	p.created[id] = true
	return id, nil
}

// get looks an object up in the new objects first, then in the view.
func (p *patcher) get(id gitobj.ID) (gitobj.Object, error) {
	if o, err := p.out.Get(id); err == nil {
		return o, nil
	}
	return p.view.Get(id)
}

func (p *patcher) tree(id gitobj.ID) ([]gitobj.TreeEntry, error) {
	o, err := p.get(id)
	if err != nil {
		return nil, err
	}
	if o.Type != gitobj.TypeTree {
		return nil, fmt.Errorf("%s is a %s, not a tree", id, o.Type)
	}
	return gitobj.ParseTree(o.Data)
}

// apply returns the id of tree `root` with edits applied. Paths are
// slash-separated. Deleting a path that does not exist is an error, as is
// editing through a file.
func (p *patcher) apply(root gitobj.ID, edits map[string]edit) (gitobj.ID, error) {
	paths := make([]string, 0, len(edits))
	for path := range edits {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	cur := root
	for _, path := range paths {
		var err error
		cur, err = p.applyOne(cur, strings.Split(path, "/"), edits[path])
		if err != nil {
			return gitobj.ZeroID, fmt.Errorf("patch %q: %w", path, err)
		}
	}
	return cur, nil
}

func (p *patcher) applyOne(tree gitobj.ID, parts []string, e edit) (gitobj.ID, error) {
	var entries []gitobj.TreeEntry
	if !tree.IsZero() {
		var err error
		if entries, err = p.tree(tree); err != nil {
			return gitobj.ZeroID, err
		}
	}
	name := parts[0]
	idx := -1
	for i, en := range entries {
		if en.Name == name {
			idx = i
			break
		}
	}
	if len(parts) == 1 {
		if e.Delete {
			if idx < 0 {
				return gitobj.ZeroID, errors.New("delete: no such entry")
			}
			entries = append(entries[:idx], entries[idx+1:]...)
		} else {
			mode := e.Mode
			if mode == 0 {
				mode = gitobj.ModeFile
			}
			id, err := p.put(gitobj.Object{Type: gitobj.TypeBlob, Data: e.Data})
			if err != nil {
				return gitobj.ZeroID, err
			}
			en := gitobj.TreeEntry{Mode: mode, Name: name, ID: id}
			if idx >= 0 {
				if entries[idx].Mode == gitobj.ModeDir {
					return gitobj.ZeroID, errors.New("path is a directory")
				}
				entries[idx] = en
			} else {
				entries = append(entries, en)
			}
		}
	} else {
		var sub gitobj.ID
		if idx >= 0 {
			if entries[idx].Mode != gitobj.ModeDir {
				return gitobj.ZeroID, errors.New("path component is a file")
			}
			sub = entries[idx].ID
		} else if e.Delete {
			return gitobj.ZeroID, errors.New("delete: no such directory")
		}
		newSub, err := p.applyOne(sub, parts[1:], e)
		if err != nil {
			return gitobj.ZeroID, err
		}
		en := gitobj.TreeEntry{Mode: gitobj.ModeDir, Name: name, ID: newSub}
		if idx >= 0 {
			entries[idx] = en
		} else {
			entries = append(entries, en)
		}
	}
	gitobj.SortEntries(entries)
	return p.put(gitobj.Object{Type: gitobj.TypeTree, Data: gitobj.EncodeTree(entries)})
}

// collectBundle returns the objects reachable from commit that are new
// relative to the base repository: every object that is either in
// srcBundle (objects of the source commit on top of base) or was created
// by the patcher. Everything else is, by the closure property of the
// source bundle, already in base. Objects of srcBundle that the walk does
// not reach (the replaced trees and blobs, the old commit) are dropped.
func (p *patcher) collectBundle(commit gitobj.ID, srcBundle *gitobj.Bundle) (*gitobj.Bundle, error) {
	fresh := map[gitobj.ID]gitobj.Object{}
	for _, o := range srcBundle.Objects {
		fresh[o.ID()] = o
	}
	for id := range p.created {
		o, _ := p.out.Get(id)
		fresh[id] = o
	}
	b := &gitobj.Bundle{}
	seen := map[gitobj.ID]bool{}
	var walk func(id gitobj.ID) error
	walk = func(id gitobj.ID) error {
		if seen[id] {
			return nil
		}
		o, ok := fresh[id]
		if !ok {
			return nil // in base
		}
		seen[id] = true
		b.Objects = append(b.Objects, o)
		switch o.Type {
		case gitobj.TypeCommit:
			c, err := gitobj.ParseCommit(o.Data)
			if err != nil {
				return err
			}
			return walk(c.Tree)
		case gitobj.TypeTree:
			entries, err := gitobj.ParseTree(o.Data)
			if err != nil {
				return err
			}
			for _, en := range entries {
				if err := walk(en.ID); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(commit); err != nil {
		return nil, err
	}
	return b, nil
}

// fileAt returns the blob content and mode of path in tree, or ok=false.
func fileAt(s gitobj.Store, tree gitobj.ID, path string) (data []byte, mode uint32, ok bool, err error) {
	cur := tree
	parts := strings.Split(path, "/")
	for i, name := range parts {
		o, err := s.Get(cur)
		if err != nil {
			return nil, 0, false, err
		}
		if o.Type != gitobj.TypeTree {
			return nil, 0, false, nil
		}
		entries, err := gitobj.ParseTree(o.Data)
		if err != nil {
			return nil, 0, false, err
		}
		found := false
		for _, en := range entries {
			if en.Name != name {
				continue
			}
			found = true
			if i == len(parts)-1 {
				if en.Mode == gitobj.ModeDir {
					return nil, 0, false, nil
				}
				bo, err := s.Get(en.ID)
				if err != nil {
					return nil, 0, false, err
				}
				return bo.Data, en.Mode, true, nil
			}
			if en.Mode != gitobj.ModeDir {
				return nil, 0, false, nil
			}
			cur = en.ID
			break
		}
		if !found {
			return nil, 0, false, nil
		}
	}
	return nil, 0, false, nil
}

// listDir returns the file paths directly inside dir (no recursion) of
// tree, with the given suffix; "" lists everything.
func listDir(s gitobj.Store, tree gitobj.ID, dir string) ([]string, error) {
	cur := tree
	if dir != "" {
		for _, name := range strings.Split(dir, "/") {
			o, err := s.Get(cur)
			if err != nil {
				return nil, err
			}
			entries, err := gitobj.ParseTree(o.Data)
			if err != nil {
				return nil, err
			}
			next := gitobj.ZeroID
			for _, en := range entries {
				if en.Name == name && en.Mode == gitobj.ModeDir {
					next = en.ID
					break
				}
			}
			if next.IsZero() {
				return nil, nil
			}
			cur = next
		}
	}
	o, err := s.Get(cur)
	if err != nil {
		return nil, err
	}
	entries, err := gitobj.ParseTree(o.Data)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, en := range entries {
		if en.Mode == gitobj.ModeDir {
			continue
		}
		if dir == "" {
			out = append(out, en.Name)
		} else {
			out = append(out, dir+"/"+en.Name)
		}
	}
	return out, nil
}
