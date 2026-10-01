package gitobj

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var baseFiles = []File{
	{"README.md", ModeFile, []byte("# readme\n")},
	{"src/main.go", ModeFile, []byte("package main\n")},
	{"src/lib/util.go", ModeFile, []byte("package lib\n")},
	{"bin/run.sh", ModeExec, []byte("#!/bin/sh\n")},
	{"link", ModeSymlink, []byte("README.md")},
}

// setup returns a store holding a first commit.
func setup(t testing.TB) (*MemStore, ID) {
	t.Helper()
	s := NewMemStore()
	b, c := makeCommit(t, s, ZeroID, "first\n", baseFiles)
	if _, err := VerifyClosure(s, b, c, ZeroID, DefaultLimits); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := ApplyBundle(s, b); err != nil {
		t.Fatal(err)
	}
	return s, c
}

func with(files []File, extra ...File) []File {
	out := append([]File(nil), files...)
	for _, e := range extra {
		found := false
		for i := range out {
			if out[i].Path == e.Path {
				out[i] = e
				found = true
			}
		}
		if !found {
			out = append(out, e)
		}
	}
	return out
}

func TestVerifyClosureAccepts(t *testing.T) {
	s, head := setup(t)
	b, c := makeCommit(t, s, head, "second\n", with(baseFiles, File{"src/lib/util.go", ModeFile, []byte("package lib // v2\n")}))
	// commit + 3 trees (root, src, src/lib) + 1 blob
	if len(b.Objects) != 5 {
		t.Fatalf("bundle has %d objects", len(b.Objects))
	}
	commit, err := VerifyClosure(s, b, c, head, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Message != "second\n" || len(commit.Parents) != 1 || commit.Parents[0] != head {
		t.Fatalf("%+v", commit)
	}
	// Bundle order must not matter to VerifyClosure.
	rev := &Bundle{}
	for i := len(b.Objects) - 1; i >= 0; i-- {
		rev.Objects = append(rev.Objects, b.Objects[i])
	}
	if _, err := VerifyClosure(s, rev, c, head, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	// VerifyClosure must not write.
	if s.Has(c) {
		t.Fatal("VerifyClosure stored the candidate")
	}
	if err := ApplyBundle(s, b); err != nil {
		t.Fatal(err)
	}
	for _, o := range b.Objects {
		if !s.Has(o.ID()) {
			t.Fatal("ApplyBundle missed an object")
		}
	}
	// An empty commit (same tree) is a valid closure of one object.
	b2, c2 := makeCommit(t, s, c, "empty\n", with(baseFiles, File{"src/lib/util.go", ModeFile, []byte("package lib // v2\n")}))
	if len(b2.Objects) != 1 {
		t.Fatalf("empty commit bundle has %d objects", len(b2.Objects))
	}
	if _, err := VerifyClosure(s, b2, c2, c, DefaultLimits); err != nil {
		t.Fatal(err)
	}
}

// A blob that exists in the validator's store (older history) AND is
// shipped in the bundle is allowed: `git rev-list --objects C ^H` lists a
// blob that was deleted long ago and is now re-added.
func TestVerifyClosureReAddedBlob(t *testing.T) {
	s, c1 := setup(t)
	old := File{"old.txt", ModeFile, []byte("content that comes back\n")}
	b2, c2 := makeCommit(t, s, c1, "add\n", with(baseFiles, old))
	if _, err := VerifyClosure(s, b2, c2, c1, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	ApplyBundle(s, b2)
	b3, c3 := makeCommit(t, s, c2, "delete\n", baseFiles)
	if _, err := VerifyClosure(s, b3, c3, c2, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	ApplyBundle(s, b3)

	// Re-add under a new name. The helper omits objects the store has
	// (that bundle must be accepted) ...
	files := with(baseFiles, File{"new/old-again.txt", ModeFile, old.Data})
	b4, c4 := makeCommit(t, s, c3, "re-add\n", files)
	blobID := blob(string(old.Data)).ID()
	for _, o := range b4.Objects {
		if o.ID() == blobID {
			t.Fatal("test setup: blob unexpectedly in bundle")
		}
	}
	if _, err := VerifyClosure(s, b4, c4, c3, DefaultLimits); err != nil {
		t.Fatalf("without the blob: %v", err)
	}
	// ... and so must the bundle git would build, which includes it.
	withBlob := &Bundle{Objects: append(append([]Object(nil), b4.Objects...), blob(string(old.Data)))}
	if !s.Has(blobID) {
		t.Fatal("test setup: blob not in base")
	}
	if _, err := VerifyClosure(s, withBlob, c4, c3, DefaultLimits); err != nil {
		t.Fatalf("with the re-added blob: %v", err)
	}
	// The same holds for a whole tree that is both in base and bundle:
	// it is walked through the bundle, so its children shipped in the
	// bundle count as reachable.
	all, c5 := makeCommit(t, NewMemStore(), c3, "re-add\n", files) // empty base => full closure
	if c5 != c4 {
		t.Fatal("test setup: commit ids differ")
	}
	if _, err := VerifyClosure(s, all, c4, c3, DefaultLimits); err != nil {
		t.Fatalf("full closure on top of a populated base: %v", err)
	}
	// But a base object that the candidate does not reference is junk.
	junk := &Bundle{Objects: append(append([]Object(nil), b4.Objects...), blob("# readme v0\n"))}
	s.Put(blob("# readme v0\n"))
	_, err := VerifyClosure(s, junk, c4, c3, DefaultLimits)
	wantErr(t, err, ErrExtraObjects)
}

func TestVerifyClosureParentRules(t *testing.T) {
	s, head := setup(t)
	files := with(baseFiles, File{"x", ModeFile, []byte("x\n")})
	b, c := makeCommit(t, s, head, "m\n", files)
	other := commitObj(treeObj().ID(), "other\n").ID()

	_, err := VerifyClosure(s, b, c, ZeroID, DefaultLimits)
	wantErr(t, err, ErrParent) // has a parent, none expected
	_, err = VerifyClosure(s, b, c, other, DefaultLimits)
	wantErr(t, err, ErrParent) // wrong parent

	// Root commit where a parent is expected.
	rb, rc := makeCommit(t, s, ZeroID, "root\n", files)
	_, err = VerifyClosure(s, rb, rc, head, DefaultLimits)
	wantErr(t, err, ErrParent)

	// Merge commit (two parents), expected parent first or second.
	r := newRecorder(s)
	tree, _ := WriteTree(r, files)
	s.Put(commitObj(treeObj().ID(), "other\n"))
	for _, parents := range [][]ID{{head, other}, {other, head}} {
		m := commitObj(tree, "merge\n", parents...)
		mb := &Bundle{Objects: append([]Object{m}, r.objs...)}
		_, err = VerifyClosure(s, mb, m.ID(), head, DefaultLimits)
		wantErr(t, err, ErrParent)
	}

	// Parent not in the store.
	empty := NewMemStore()
	full, c2 := makeCommit(t, empty, head, "m\n", files)
	_, err = VerifyClosure(empty, full, c2, head, DefaultLimits)
	wantErr(t, err, ErrParent)

	// Parent shipped in the bundle instead of being in the store.
	parentObj, _ := s.Get(head)
	smuggle := &Bundle{Objects: append([]Object{parentObj}, full.Objects...)}
	_, err = VerifyClosure(empty, smuggle, c2, head, DefaultLimits)
	wantErr(t, err, ErrParent)

	// "Parent" that is a blob in the store (type confusion in base).
	fake := blob("not a commit")
	s.Put(fake)
	fc := commitObj(tree, "m\n", fake.ID())
	fb := &Bundle{Objects: append([]Object{fc}, r.objs...)}
	_, err = VerifyClosure(s, fb, fc.ID(), fake.ID(), DefaultLimits)
	wantErr(t, err, ErrParent)
}

func TestVerifyClosureCandidate(t *testing.T) {
	s, head := setup(t)
	b, c := makeCommit(t, s, head, "m\n", with(baseFiles, File{"x", ModeFile, []byte("x\n")}))

	// Candidate not in the bundle (even if it is in the store).
	_, err := VerifyClosure(s, b, head, ZeroID, DefaultLimits)
	wantErr(t, err, ErrIncomplete)
	_, err = VerifyClosure(s, &Bundle{}, c, head, DefaultLimits)
	wantErr(t, err, ErrIncomplete)
	_, err = VerifyClosure(s, nil, c, head, DefaultLimits)
	wantErr(t, err, ErrIncomplete)

	// Candidate is a tree or a blob.
	for _, o := range b.Objects {
		if o.Type != TypeCommit {
			_, err = VerifyClosure(s, b, o.ID(), head, DefaultLimits)
			wantErr(t, err, ErrMalformed)
		}
	}
	// Candidate is a malformed commit.
	bad := Object{Type: TypeCommit, Data: []byte("tree x\n")}
	_, err = VerifyClosure(s, &Bundle{Objects: []Object{bad}}, bad.ID(), ZeroID, DefaultLimits)
	wantErr(t, err, ErrMalformed)
	// Object of invalid type in a hand-built bundle.
	inv := &Bundle{Objects: append([]Object{{Type: 7, Data: []byte("x")}}, b.Objects...)}
	_, err = VerifyClosure(s, inv, c, head, DefaultLimits)
	wantErr(t, err, ErrUnsupported)
}

func TestVerifyClosureIncompleteAndExtra(t *testing.T) {
	s, head := setup(t)
	b, c := makeCommit(t, s, head, "m\n", with(baseFiles,
		File{"new/deep/file.txt", ModeFile, []byte("new\n")},
		File{"x", ModeFile, []byte("x\n")}))

	// Dropping any non-commit object makes the closure incomplete.
	for i, o := range b.Objects {
		if o.Type == TypeCommit {
			continue
		}
		less := &Bundle{Objects: append(append([]Object(nil), b.Objects[:i]...), b.Objects[i+1:]...)}
		_, err := VerifyClosure(s, less, c, head, DefaultLimits)
		if !errorsIs(err, ErrIncomplete) && !errorsIs(err, ErrExtraObjects) {
			t.Errorf("dropping %s %s: %v", o.Type, o.ID(), err)
		}
		// Dropping a tree orphans its children (extra); dropping a
		// leaf blob is always "incomplete".
		if o.Type == TypeBlob {
			wantErr(t, err, ErrIncomplete)
		}
	}

	// Adding an unreachable blob, tree or commit.
	extras := []Object{
		blob("junk"),
		treeObj(TreeEntry{ModeFile, "j", blob("x\n").ID()}),
		commitObj(treeObj().ID(), "second commit\n"),
	}
	for _, e := range extras {
		more := &Bundle{Objects: append(append([]Object(nil), b.Objects...), e)}
		_, err := VerifyClosure(s, more, c, head, DefaultLimits)
		wantErr(t, err, ErrExtraObjects)
	}
	// The parent commit object itself shipped along.
	parentObj, _ := s.Get(head)
	more := &Bundle{Objects: append(append([]Object(nil), b.Objects...), parentObj)}
	_, err := VerifyClosure(s, more, c, head, DefaultLimits)
	wantErr(t, err, ErrExtraObjects)

	// Duplicate object in a hand-built bundle.
	dup := &Bundle{Objects: append(append([]Object(nil), b.Objects...), b.Objects[0])}
	_, err = VerifyClosure(s, dup, c, head, DefaultLimits)
	wantErr(t, err, ErrNonCanonical)
}

func TestVerifyClosureTypeConfusion(t *testing.T) {
	s, head := setup(t)
	aBlob := blob("i am a blob")
	aTree := treeObj(TreeEntry{ModeFile, "f", aBlob.ID()})

	check := func(name string, inBase bool, root Object, extra ...Object) {
		t.Helper()
		st := NewMemStore()
		ApplyBundle(st, &Bundle{Objects: mustAll(t, s)})
		objs := []Object{root}
		if inBase {
			for _, e := range extra {
				st.Put(e)
			}
		} else {
			objs = append(objs, extra...)
		}
		c := commitObj(root.ID(), "m\n", head)
		objs = append(objs, c)
		_, err := VerifyClosure(st, &Bundle{Objects: objs}, c.ID(), head, DefaultLimits)
		if !errorsIs(err, ErrMalformed) {
			t.Errorf("%s (in base: %v): got %v, want ErrMalformed", name, inBase, err)
		}
	}
	for _, inBase := range []bool{false, true} {
		// A directory entry naming a blob.
		check("blob as tree", inBase, treeObj(TreeEntry{ModeDir, "d", aBlob.ID()}), aBlob)
		// A file entry naming a tree.
		check("tree as blob", inBase, treeObj(TreeEntry{ModeFile, "f", aTree.ID()}), aTree, aBlob)
		// A symlink entry naming a tree.
		check("tree as symlink", inBase, treeObj(TreeEntry{ModeSymlink, "l", aTree.ID()}), aTree, aBlob)
		// A file entry naming a commit.
		cm := commitObj(treeObj().ID(), "c\n")
		check("commit as blob", inBase, treeObj(TreeEntry{ModeFile, "f", cm.ID()}), cm)
		check("commit as tree", inBase, treeObj(TreeEntry{ModeDir, "d", cm.ID()}), cm)
	}

	// The commit's tree header naming a blob / the root tree malformed.
	c := commitObj(aBlob.ID(), "m\n", head)
	_, err := VerifyClosure(s, &Bundle{Objects: []Object{c, aBlob}}, c.ID(), head, DefaultLimits)
	wantErr(t, err, ErrMalformed)
	badTree := Object{Type: TypeTree, Data: []byte("100644 a/b\x00" + strings.Repeat("x", 20))}
	c = commitObj(badTree.ID(), "m\n", head)
	_, err = VerifyClosure(s, &Bundle{Objects: []Object{c, badTree}}, c.ID(), head, DefaultLimits)
	wantErr(t, err, ErrMalformed)
	gitlink := Object{Type: TypeTree, Data: rawEntry("160000", "sub", aBlob.ID())}
	c = commitObj(gitlink.ID(), "m\n", head)
	_, err = VerifyClosure(s, &Bundle{Objects: []Object{c, gitlink}}, c.ID(), head, DefaultLimits)
	wantErr(t, err, ErrUnsupported)
}

func mustAll(t *testing.T, s *MemStore) []Object {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Object
	for _, o := range s.objs {
		out = append(out, o)
	}
	sortObjects(out)
	return out
}

// chain builds n nested directories d/d/d/.../f and returns all objects
// and the root tree.
func chain(n int, name string) ([]Object, Object) {
	leaf := blob("leaf")
	objs := []Object{leaf}
	cur := treeObj(TreeEntry{ModeFile, "f", leaf.ID()})
	objs = append(objs, cur)
	for i := 0; i < n; i++ {
		cur = treeObj(TreeEntry{ModeDir, name, cur.ID()})
		objs = append(objs, cur)
	}
	return objs, cur
}

func TestVerifyClosureLimits(t *testing.T) {
	s := NewMemStore()
	lim := DefaultLimits
	lim.MaxTreeDepth = 8

	try := func(objs []Object, root Object, lim Limits) error {
		c := commitObj(root.ID(), "m\n")
		_, err := VerifyClosure(s, &Bundle{Objects: append([]Object{c}, objs...)}, c.ID(), ZeroID, lim)
		return err
	}
	// Depth: root is depth 0, so 8 nested directories are allowed.
	objs, root := chain(8, "d")
	if err := try(objs, root, lim); err != nil {
		t.Fatalf("depth 8: %v", err)
	}
	objs, root = chain(9, "d")
	wantErr(t, try(objs, root, lim), ErrLimit)
	// Depth bomb far beyond the limit must not recurse deeply.
	objs, root = chain(5000, "d")
	wantErr(t, try(objs, root, DefaultLimits), ErrLimit)

	// Path length: "d/d/d/f" is 7 bytes.
	objs, root = chain(3, "d")
	lim = DefaultLimits
	lim.MaxPathBytes = 7
	if err := try(objs, root, lim); err != nil {
		t.Fatalf("path 7: %v", err)
	}
	lim.MaxPathBytes = 6
	wantErr(t, try(objs, root, lim), ErrLimit)

	// Object count / size limits for hand-built bundles.
	objs, root = chain(3, "d")
	lim = DefaultLimits
	lim.MaxObjects = 5
	wantErr(t, try(objs, root, lim), ErrLimit)
	lim = DefaultLimits
	lim.MaxObjectBytes = 10
	wantErr(t, try(objs, root, lim), ErrLimit)
	lim = DefaultLimits
	lim.MaxBundleBytes = 50
	wantErr(t, try(objs, root, lim), ErrLimit)
}

// A subtree that is first reached at a shallow position and then again at
// a deeper one must have the limits enforced for the deeper position too,
// although it is only walked once.
func TestVerifyClosureMemoisedLimits(t *testing.T) {
	s := NewMemStore()
	objs, sub := chain(3, "d") // height 3, longest relative path "d/d/d/f"
	// root: "a" -> sub (depth 1), "z/z/z" -> sub (depth 3)
	z3 := treeObj(TreeEntry{ModeDir, "z", sub.ID()})
	z2 := treeObj(TreeEntry{ModeDir, "z", z3.ID()})
	root := treeObj(TreeEntry{ModeDir, "a", sub.ID()}, TreeEntry{ModeDir, "z", z2.ID()})
	all := append(append([]Object(nil), objs...), z3, z2, root)
	c := commitObj(root.ID(), "m\n")
	b := &Bundle{Objects: append([]Object{c}, all...)}

	// Deepest tree: z/z/z + d/d/d => depth 6. Longest path:
	// "z/z/z/d/d/d/f" = 13 bytes.
	lim := DefaultLimits
	lim.MaxTreeDepth, lim.MaxPathBytes = 6, 13
	if _, err := VerifyClosure(s, b, c.ID(), ZeroID, lim); err != nil {
		t.Fatalf("exact limits: %v", err)
	}
	lim.MaxTreeDepth = 5
	_, err := VerifyClosure(s, b, c.ID(), ZeroID, lim)
	wantErr(t, err, ErrLimit)
	lim.MaxTreeDepth, lim.MaxPathBytes = 6, 12
	_, err = VerifyClosure(s, b, c.ID(), ZeroID, lim)
	wantErr(t, err, ErrLimit)
}

// A "tree bomb": 60 levels, each tree has 8 entries naming the same
// subtree: 8^60 paths from 61 tiny objects. Must be verified in linear
// time thanks to memoisation.
func TestVerifyClosureTreeBomb(t *testing.T) {
	s := NewMemStore()
	leaf := blob("x")
	cur := treeObj(TreeEntry{ModeFile, "f", leaf.ID()})
	objs := []Object{leaf, cur}
	for i := 0; i < 60; i++ {
		var e []TreeEntry
		for j := 0; j < 8; j++ {
			e = append(e, TreeEntry{ModeDir, fmt.Sprintf("d%d", j), cur.ID()})
		}
		cur = treeObj(e...)
		objs = append(objs, cur)
	}
	c := commitObj(cur.ID(), "bomb\n")
	b := &Bundle{Objects: append([]Object{c}, objs...)}
	start := time.Now()
	if _, err := VerifyClosure(s, b, c.ID(), ZeroID, DefaultLimits); err != nil {
		t.Fatalf("bomb within limits should verify: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("tree bomb took %v", d)
	}
	// ... while DiffTrees, which would have to enumerate the paths,
	// stops at its work limit.
	ApplyBundle(s, b)
	start = time.Now()
	_, err := DiffTrees(s, ZeroID, cur.ID(), DefaultLimits)
	wantErr(t, err, ErrLimit)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("DiffTrees on tree bomb took %v", d)
	}
}

func TestVerifyClosureDeterministicError(t *testing.T) {
	// Several simultaneous violations: the same error must be reported
	// regardless of how often we ask or how the base was populated.
	s, head := setup(t)
	b, c := makeCommit(t, s, head, "m\n", with(baseFiles, File{"x", ModeFile, []byte("x\n")}, File{"y", ModeFile, []byte("y\n")}))
	var objs []Object
	for _, o := range b.Objects {
		if o.Type != TypeBlob {
			objs = append(objs, o)
		}
	}
	objs = append(objs, blob("junk1"), blob("junk2"))
	broken := &Bundle{Objects: objs}
	_, first := VerifyClosure(s, broken, c, head, DefaultLimits)
	if first == nil {
		t.Fatal("accepted")
	}
	for i := 0; i < 50; i++ {
		_, err := VerifyClosure(s, broken, c, head, DefaultLimits)
		if err == nil || err.Error() != first.Error() {
			t.Fatalf("run %d: %v vs %v", i, err, first)
		}
	}
}

// A tree bomb whose leaves are empty trees produces no changes at all, so
// only the bound on loaded trees stops DiffTrees.
func TestDiffTreesEmptyLeafBomb(t *testing.T) {
	s := NewMemStore()
	cur := treeObj()
	objs := []Object{cur}
	for i := 0; i < 60; i++ {
		cur = treeObj(TreeEntry{ModeDir, "a", cur.ID()}, TreeEntry{ModeDir, "b", cur.ID()})
		objs = append(objs, cur)
	}
	c := commitObj(cur.ID(), "bomb\n")
	b := &Bundle{Objects: append([]Object{c}, objs...)}
	if _, err := VerifyClosure(s, b, c.ID(), ZeroID, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	ApplyBundle(s, b)
	start := time.Now()
	_, err := DiffTrees(s, ZeroID, cur.ID(), DefaultLimits)
	wantErr(t, err, ErrLimit)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}
