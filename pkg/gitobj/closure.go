package gitobj

import (
	"errors"
	"fmt"
)

// treeInfo summarises a bundle tree so it can be referenced from several
// places (and depths) without being walked again.
type treeInfo struct {
	done bool // false while the tree is being walked (cycle detection)
	// height is the number of directory levels below this tree that are
	// stored in the bundle (0 if it has no bundle subtrees).
	height int
	// maxRel is the length of the longest path below this tree, relative
	// to it, over all entries known from bundle trees.
	maxRel int
}

type closureWalker struct {
	base    Store
	lim     Limits
	index   map[ID]int // bundle object ID -> index in objs
	objs    []Object
	visited []bool
	trees   map[ID]*treeInfo
}

// VerifyClosure checks that bundle b is exactly the set of objects needed
// to add commit candidate on top of expectedParent. See the package
// contract for the five rules.
//
// Resolution order: an ID referenced by the candidate is looked up in the
// bundle FIRST and in base only if the bundle does not contain it. An
// object that is both in the bundle and already in base is therefore
// allowed (and, if it is a tree, walked through the bundle). This is
// required for compatibility with `git rev-list --objects C ^H`, which
// legitimately lists objects that exist somewhere in the older history of
// the validator's store - e.g. a blob that was deleted long ago and is now
// re-added. "Junk" (ErrExtraObjects) means: an object of the bundle that
// the walk from the candidate never reaches.
//
// Determinism: the walk visits tree entries in canonical order and the
// bundle in slice order; maps are used for lookups only. The first
// violation encountered in that order determines the error.
//
// Termination and cost: every bundle tree is parsed at most once
// (memoised), and descent is cut at lim.MaxTreeDepth, so the walk is linear
// in the bundle size even for hostile "tree bombs" in which many entries
// point at the same subtree. Depth and path limits are nevertheless
// enforced for every position at which a memoised tree is referenced.
// Subtrees found only in base are not descended into (Store closure
// invariant); DiffTrees enforces the limits on them if they are reached.
//
// Limits: directory nesting is counted in path components: the root tree
// has depth 0 and an entry "a/b/c" lives in a tree of depth 2. Trees deeper
// than lim.MaxTreeDepth are rejected. lim.MaxPathBytes bounds the length of
// the full slash-separated path of every entry.
func VerifyClosure(base Store, b *Bundle, candidate, expectedParent ID, lim Limits) (*Commit, error) {
	if b == nil || base == nil {
		return nil, fmt.Errorf("%w: nil bundle or store", ErrIncomplete)
	}
	if len(b.Objects) > lim.MaxObjects {
		return nil, fmt.Errorf("%w: bundle has %d objects, limit %d", ErrLimit, len(b.Objects), lim.MaxObjects)
	}
	w := &closureWalker{
		base:    base,
		lim:     lim,
		index:   make(map[ID]int, len(b.Objects)),
		objs:    b.Objects,
		visited: make([]bool, len(b.Objects)),
		trees:   make(map[ID]*treeInfo),
	}
	total := 0
	for i, o := range b.Objects {
		if !o.Type.Valid() {
			return nil, fmt.Errorf("%w: bundle object %d: type %d", ErrUnsupported, i, o.Type)
		}
		if len(o.Data) > lim.MaxObjectBytes {
			return nil, fmt.Errorf("%w: bundle object %d is %d bytes, limit %d", ErrLimit, i, len(o.Data), lim.MaxObjectBytes)
		}
		total += bundleObjHeaderBytes + len(o.Data)
		if total > lim.MaxBundleBytes {
			return nil, fmt.Errorf("%w: bundle exceeds %d bytes", ErrLimit, lim.MaxBundleBytes)
		}
		id := o.ID()
		if _, dup := w.index[id]; dup {
			// A Bundle is a set. DecodeBundle can never produce a
			// duplicate; a hand-built bundle that has one is refused
			// rather than silently collapsed.
			return nil, fmt.Errorf("%w: bundle object %d duplicates %s", ErrNonCanonical, i, id)
		}
		w.index[id] = i
	}

	// Rule 1: the candidate is a commit in the bundle.
	ci, ok := w.index[candidate]
	if !ok {
		return nil, fmt.Errorf("%w: candidate %s is not in the bundle", ErrIncomplete, candidate)
	}
	if t := b.Objects[ci].Type; t != TypeCommit {
		return nil, fmt.Errorf("%w: candidate %s is a %s, not a commit", ErrMalformed, candidate, t)
	}
	commit, err := ParseCommit(b.Objects[ci].Data)
	if err != nil {
		return nil, fmt.Errorf("candidate %s: %w", candidate, err)
	}
	w.visited[ci] = true

	// Rule 2: parent linkage. This is what makes acceptance a
	// compare-and-swap on the branch head: merge commits and commits
	// based on anything but the current head are refused.
	if expectedParent.IsZero() {
		if len(commit.Parents) != 0 {
			return nil, fmt.Errorf("%w: first commit of a branch must have no parents, has %d", ErrParent, len(commit.Parents))
		}
	} else {
		if len(commit.Parents) != 1 {
			return nil, fmt.Errorf("%w: want exactly one parent, have %d", ErrParent, len(commit.Parents))
		}
		if commit.Parents[0] != expectedParent {
			return nil, fmt.Errorf("%w: parent is %s, expected %s", ErrParent, commit.Parents[0], expectedParent)
		}
		// The parent must come from base, not from the bundle: a
		// bundle carrying its own "parent" could smuggle unreviewed
		// history. (A bundle copy of the parent would in any case be
		// rejected below as a second commit.)
		t, err := typeOf(base, expectedParent)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: expected parent %s is not in the store", ErrParent, expectedParent)
			}
			return nil, fmt.Errorf("expected parent %s: %w", expectedParent, err)
		}
		if t != TypeCommit {
			return nil, fmt.Errorf("%w: expected parent %s is a %s, not a commit", ErrParent, expectedParent, t)
		}
	}

	// Rules 3 and 5: walk the tree.
	if _, err := w.ref(commit.Tree, TypeTree, 0, 0, ""); err != nil {
		return nil, err
	}

	// Rule 4: nothing else may be in the bundle. Unreviewed objects must
	// not be stored: they would cost every validator disk space for
	// free and could later be "found in base" by another commit.
	for i := range b.Objects {
		if !w.visited[i] {
			o := b.Objects[i]
			return nil, fmt.Errorf("%w: bundle object %d (%s %s) is not reachable from the candidate",
				ErrExtraObjects, i, o.Type, o.ID())
		}
	}
	return commit, nil
}

// ref resolves one reference to an object expected to be of type want,
// located at directory depth `depth`, whose own path has length pathLen.
// what describes the reference for error messages. It returns the
// treeInfo for bundle trees and nil otherwise.
func (w *closureWalker) ref(id ID, want ObjType, depth, pathLen int, what string) (*treeInfo, error) {
	if want == TypeTree && depth > w.lim.MaxTreeDepth {
		return nil, fmt.Errorf("%w: tree nesting deeper than %d", ErrLimit, w.lim.MaxTreeDepth)
	}
	i, inBundle := w.index[id]
	if !inBundle {
		t, err := typeOf(w.base, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: %s %s%s is neither in the bundle nor in the store", ErrIncomplete, want, id, what)
			}
			return nil, fmt.Errorf("%s %s: %w", want, id, err)
		}
		if t != want {
			// Type confusion against the store: e.g. a directory
			// entry naming an existing blob.
			return nil, fmt.Errorf("%w: %s%s is a %s in the store but referenced as a %s", ErrMalformed, id, what, t, want)
		}
		return nil, nil
	}
	if t := w.objs[i].Type; t != want {
		return nil, fmt.Errorf("%w: %s%s is a %s in the bundle but referenced as a %s", ErrMalformed, id, what, t, want)
	}
	w.visited[i] = true
	if want != TypeTree {
		return nil, nil
	}

	info, seen := w.trees[id]
	if seen {
		if !info.done {
			// Unreachable without a SHA-1 cycle, but termination
			// must not depend on the hash function.
			return nil, fmt.Errorf("%w: tree %s contains itself", ErrMalformed, id)
		}
	} else {
		info = &treeInfo{}
		w.trees[id] = info
		entries, err := ParseTree(w.objs[i].Data)
		if err != nil {
			return nil, fmt.Errorf("tree %s: %w", id, err)
		}
		for _, e := range entries {
			rel := len(e.Name)
			h := 0
			childWant := TypeBlob
			if e.Mode == ModeDir {
				childWant = TypeTree
			}
			// Path of the child: parent path + "/" + name (no
			// separator at the root).
			childLen := pathLen + len(e.Name)
			if pathLen > 0 {
				childLen++
			}
			if childLen > w.lim.MaxPathBytes {
				return nil, fmt.Errorf("%w: path longer than %d bytes", ErrLimit, w.lim.MaxPathBytes)
			}
			child, err := w.ref(e.ID, childWant, depth+1, childLen, "")
			if err != nil {
				return nil, err
			}
			if child != nil {
				h = 1 + child.height
				if child.maxRel > 0 {
					rel += 1 + child.maxRel
				}
			}
			if h > info.height {
				info.height = h
			}
			if rel > info.maxRel {
				info.maxRel = rel
			}
		}
		info.done = true
		return info, nil
	}

	// Memoised tree referenced again, possibly deeper or under a longer
	// path than where it was first walked: re-check the limits from the
	// summary instead of re-walking.
	if depth+info.height > w.lim.MaxTreeDepth {
		return nil, fmt.Errorf("%w: tree nesting deeper than %d", ErrLimit, w.lim.MaxTreeDepth)
	}
	if info.maxRel > 0 {
		n := pathLen + info.maxRel
		if pathLen > 0 {
			n++
		}
		if n > w.lim.MaxPathBytes {
			return nil, fmt.Errorf("%w: path longer than %d bytes", ErrLimit, w.lim.MaxPathBytes)
		}
	}
	return info, nil
}
