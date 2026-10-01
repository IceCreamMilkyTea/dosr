package gitobj

import (
	"errors"
	"fmt"
	"testing"
)

const testIdent = "Alice Example <alice@example.org> 1700000000 +0000"

func mustID(t testing.TB, s string) ID {
	t.Helper()
	id, err := ParseID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func blob(s string) Object { return Object{Type: TypeBlob, Data: []byte(s)} }

func treeObj(entries ...TreeEntry) Object {
	e := append([]TreeEntry(nil), entries...)
	SortEntries(e)
	return Object{Type: TypeTree, Data: EncodeTree(e)}
}

func commitObj(tree ID, msg string, parents ...ID) Object {
	return Object{Type: TypeCommit, Data: EncodeCommit(&Commit{
		Tree: tree, Parents: parents, Author: testIdent, Committer: testIdent, Message: msg,
	})}
}

func wantErr(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}

// recorder is a Store that records every Put, to derive bundles.
type recorder struct {
	*MemStore
	base Store
	objs []Object
	seen map[ID]bool
}

func newRecorder(base Store) *recorder {
	return &recorder{MemStore: NewMemStore(), base: base, seen: map[ID]bool{}}
}

func (r *recorder) Put(o Object) (ID, error) {
	id, err := r.MemStore.Put(o)
	if err == nil && !r.seen[id] && (r.base == nil || !r.base.Has(id)) {
		r.seen[id] = true
		r.objs = append(r.objs, Object{Type: o.Type, Data: append([]byte(nil), o.Data...)})
	}
	return id, err
}

// makeCommit writes files as a commit on top of parent and returns the
// bundle of objects that base does not have.
func makeCommit(t testing.TB, base Store, parent ID, msg string, files []File) (*Bundle, ID) {
	t.Helper()
	r := newRecorder(base)
	tree, err := WriteTree(r, files)
	if err != nil {
		t.Fatal(err)
	}
	var parents []ID
	if !parent.IsZero() {
		parents = []ID{parent}
	}
	cid, err := r.Put(commitObj(tree, msg, parents...))
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{Objects: r.objs}
	sortObjects(b.Objects)
	return b, cid
}

// synthFiles returns n files spread over directories.
func synthFiles(n int, gen int) []File {
	files := make([]File, 0, n)
	for i := 0; i < n; i++ {
		var data []byte
		for l := 0; l < 40; l++ {
			data = fmt.Appendf(data, "file %d line %d generation %d\n", i, l, gen*(l%7/6))
		}
		files = append(files, File{
			Path: fmt.Sprintf("dir%02d/sub%d/file%04d.txt", i%10, i%3, i),
			Mode: ModeFile,
			Data: data,
		})
	}
	return files
}
