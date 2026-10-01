package gitobj

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func treeOf(t testing.TB, s Store, files []File) ID {
	t.Helper()
	id, err := WriteTree(s, files)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fmtChanges(cs []Change) []string {
	var out []string
	for _, c := range cs {
		out = append(out, fmt.Sprintf("%06o %06o %s %s %s", c.OldMode, c.NewMode, c.OldID, c.NewID, c.Path))
	}
	return out
}

func TestDiffTrees(t *testing.T) {
	s := NewMemStore()
	id := func(d string) ID { return blob(d).ID() }
	old := []File{
		{"a", ModeFile, []byte("a1")},                // becomes a directory
		{"b/c", ModeFile, []byte("c1")},              // directory becomes a file
		{"b/d/e", ModeFile, []byte("e1")},            //
		{"keep/same", ModeFile, []byte("same")},      // unchanged
		{"mod", ModeFile, []byte("m1")},              // modified
		{"mode", ModeFile, []byte("mode")},           // mode only
		{"gone/x", ModeFile, []byte("x1")},           // deleted dir
		{"sym", ModeSymlink, []byte("target")},       // symlink -> file
		{"a-b", ModeFile, []byte("ab")},              // sorts between "a" and "a/"
		{"ren-old", ModeFile, []byte("renamed")},     // rename
		{"keep/changed", ModeFile, []byte("k1")},     //
		{"\xff\xfe", ModeFile, []byte("binaryname")}, //
	}
	new := []File{
		{"a/x", ModeFile, []byte("a1")},
		{"a/y/z", ModeExec, []byte("z")},
		{"b", ModeFile, []byte("b now file")},
		{"keep/same", ModeFile, []byte("same")},
		{"mod", ModeFile, []byte("m2")},
		{"mode", ModeExec, []byte("mode")},
		{"sym", ModeFile, []byte("target")},
		{"a-b", ModeFile, []byte("ab")},
		{"ren-new", ModeFile, []byte("renamed")},
		{"keep/changed", ModeFile, []byte("k2")},
		{"added", ModeFile, nil},
		{"\xff\xfe", ModeFile, []byte("binaryname")},
	}
	ot, nt := treeOf(t, s, old), treeOf(t, s, new)
	got, err := DiffTrees(s, ot, nt, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{"a", ModeFile, 0, id("a1"), ZeroID},
		{"a/x", 0, ModeFile, ZeroID, id("a1")},
		{"a/y/z", 0, ModeExec, ZeroID, id("z")},
		{"added", 0, ModeFile, ZeroID, id("")},
		{"b", 0, ModeFile, ZeroID, id("b now file")},
		{"b/c", ModeFile, 0, id("c1"), ZeroID},
		{"b/d/e", ModeFile, 0, id("e1"), ZeroID},
		{"gone/x", ModeFile, 0, id("x1"), ZeroID},
		{"keep/changed", ModeFile, ModeFile, id("k1"), id("k2")},
		{"mod", ModeFile, ModeFile, id("m1"), id("m2")},
		{"mode", ModeFile, ModeExec, id("mode"), id("mode")},
		{"ren-new", 0, ModeFile, ZeroID, id("renamed")},
		{"ren-old", ModeFile, 0, id("renamed"), ZeroID},
		{"sym", ModeSymlink, ModeFile, id("target"), id("target")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%q\nwant\n%q", fmtChanges(got), fmtChanges(want))
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Path < got[j].Path }) {
		t.Fatal("not sorted")
	}

	// Identity, all-added, all-deleted.
	if cs, err := DiffTrees(s, ot, ot, DefaultLimits); err != nil || len(cs) != 0 {
		t.Fatal("identity diff", cs, err)
	}
	if cs, err := DiffTrees(s, ZeroID, ZeroID, DefaultLimits); err != nil || len(cs) != 0 {
		t.Fatal("zero diff", cs, err)
	}
	added, err := DiffTrees(s, ZeroID, ot, DefaultLimits)
	if err != nil || len(added) != len(old) {
		t.Fatal("all added", err, len(added))
	}
	deleted, err := DiffTrees(s, ot, ZeroID, DefaultLimits)
	if err != nil || len(deleted) != len(old) {
		t.Fatal("all deleted", err)
	}
	for i := range added {
		a, d := added[i], deleted[i]
		if !a.OldID.IsZero() || a.OldMode != 0 || !d.NewID.IsZero() || d.NewMode != 0 ||
			a.Path != d.Path || a.NewID != d.OldID || a.NewMode != d.OldMode {
			t.Fatalf("asymmetric: %+v %+v", a, d)
		}
	}
	// Reverse diff mirrors the forward diff.
	rev, err := DiffTrees(s, nt, ot, DefaultLimits)
	if err != nil || len(rev) != len(got) {
		t.Fatal(err)
	}
	for i := range rev {
		if rev[i].Path != got[i].Path || rev[i].OldID != got[i].NewID || rev[i].NewMode != got[i].OldMode {
			t.Fatalf("reverse mismatch at %d", i)
		}
	}
}

func TestDiffTreesErrors(t *testing.T) {
	s := NewMemStore()
	b := blob("i am a blob")
	s.Put(b)
	good := treeOf(t, s, []File{{"f", ModeFile, []byte("x")}})

	_, err := DiffTrees(s, ZeroID, treeObj().ID(), DefaultLimits) // empty tree not stored
	wantErr(t, err, ErrNotFound)
	_, err = DiffTrees(s, good, b.ID(), DefaultLimits)
	wantErr(t, err, ErrMalformed)
	_, err = DiffTrees(s, b.ID(), good, DefaultLimits)
	wantErr(t, err, ErrMalformed)

	// Entry typed as directory pointing to a blob.
	conf := treeObj(TreeEntry{ModeDir, "d", b.ID()})
	s.Put(conf)
	_, err = DiffTrees(s, good, conf.ID(), DefaultLimits)
	wantErr(t, err, ErrMalformed)
	// Missing subtree.
	miss := treeObj(TreeEntry{ModeDir, "d", treeObj(TreeEntry{ModeFile, "q", b.ID()}).ID()})
	s.Put(miss)
	_, err = DiffTrees(s, good, miss.ID(), DefaultLimits)
	wantErr(t, err, ErrNotFound)
	// Malformed tree in the store.
	bad := Object{Type: TypeTree, Data: []byte("junk")}
	s.Put(bad)
	_, err = DiffTrees(s, good, bad.ID(), DefaultLimits)
	wantErr(t, err, ErrMalformed)

	// Limits.
	objs, root := chain(9, "d")
	for _, o := range objs {
		s.Put(o)
	}
	lim := DefaultLimits
	lim.MaxTreeDepth = 9
	if cs, err := DiffTrees(s, ZeroID, root.ID(), lim); err != nil || len(cs) != 1 || cs[0].Path != "d/d/d/d/d/d/d/d/d/f" {
		t.Fatal(cs, err)
	}
	lim.MaxTreeDepth = 8
	_, err = DiffTrees(s, ZeroID, root.ID(), lim)
	wantErr(t, err, ErrLimit)
	lim = DefaultLimits
	lim.MaxPathBytes = 18
	_, err = DiffTrees(s, ZeroID, root.ID(), lim)
	wantErr(t, err, ErrLimit)
	lim.MaxPathBytes = 19
	if _, err = DiffTrees(s, ZeroID, root.ID(), lim); err != nil {
		t.Fatal(err)
	}
	lim = DefaultLimits
	lim.MaxObjectBytes = 5
	_, err = DiffTrees(s, ZeroID, root.ID(), lim)
	wantErr(t, err, ErrLimit)

	many := treeOf(t, s, synthFiles(50, 0))
	lim = DefaultLimits
	lim.MaxObjects = 49
	_, err = DiffTrees(s, ZeroID, many, lim)
	wantErr(t, err, ErrLimit)
	lim.MaxObjects = 50
	if cs, err := DiffTrees(s, ZeroID, many, lim); err != nil || len(cs) != 50 {
		t.Fatal(err)
	}
}

// The result must not depend on which Store implementation serves the
// objects or on the order in which they were inserted.
func TestDiffTreesStoreIndependent(t *testing.T) {
	a := NewMemStore()
	ot := treeOf(t, a, synthFiles(30, 0))
	nt := treeOf(t, a, synthFiles(30, 1))
	want, err := DiffTrees(a, ot, nt, DefaultLimits)
	if err != nil || len(want) == 0 {
		t.Fatal(err, len(want))
	}
	objs := mustAll(t, a)
	b := NewMemStore()
	for i := len(objs) - 1; i >= 0; i-- {
		b.Put(objs[i])
	}
	d, err := NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ApplyBundle(d, &Bundle{Objects: objs})
	ov := NewOverlay(NewMemStore(), &Bundle{Objects: objs})
	for _, s := range []Store{b, d, ov} {
		got, err := DiffTrees(s, ot, nt, DefaultLimits)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%T differs: %v", s, err)
		}
	}
}
