package gitobj

import (
	"bytes"
	"strings"
	"testing"
)

func TestObjectIDKnownVectors(t *testing.T) {
	cases := []struct {
		o    Object
		want string
	}{
		{Object{Type: TypeBlob}, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"},
		{Object{Type: TypeTree}, "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		{blob("hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a"},
	}
	for _, c := range cases {
		if got := c.o.ID().String(); got != c.want {
			t.Errorf("%s %q: got %s want %s", c.o.Type, c.o.Data, got, c.want)
		}
	}
	// Same bytes, different type => different ID (type confusion guard).
	if (Object{Type: TypeBlob, Data: []byte("x")}).ID() == (Object{Type: TypeTree, Data: []byte("x")}).ID() {
		t.Fatal("blob and tree with equal data share an ID")
	}
}

func TestParseID(t *testing.T) {
	good := "ce013625030ba8dba906f756967f9e9ca394464a"
	id, err := ParseID(good)
	if err != nil || id.String() != good {
		t.Fatal(err, id)
	}
	for _, bad := range []string{"", good[:39], good + "0", strings.ToUpper(good), "zz013625030ba8dba906f756967f9e9ca394464a"} {
		if _, err := ParseID(bad); err == nil {
			t.Errorf("ParseID(%q) succeeded", bad)
		}
	}
	var j ID
	if err := j.UnmarshalText([]byte(good)); err != nil || j != id {
		t.Fatal("UnmarshalText")
	}
}

func rawEntry(mode, name string, id ID) []byte {
	return append([]byte(mode+" "+name+"\x00"), id[:]...)
}

func TestParseTreeRoundTripAndOrder(t *testing.T) {
	id := blob("x").ID()
	// Git order: "a.c" < "a" (dir => "a/") < "a0"; file "b" < "b-c".
	entries := []TreeEntry{
		{ModeFile, "a.c", id},
		{ModeDir, "a", id},
		{ModeFile, "a0", id},
		{ModeExec, "b", id},
		{ModeSymlink, "b-c", id},
		{ModeFile, "\xff\xfe binary name", id},
	}
	data := EncodeTree(entries)
	got, err := ParseTree(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries", len(got))
	}
	for i := range got {
		if got[i] != entries[i] {
			t.Errorf("entry %d: got %+v want %+v", i, got[i], entries[i])
		}
	}
	if !bytes.Equal(EncodeTree(got), data) {
		t.Fatal("re-encoding differs")
	}
	// SortEntries produces the same order from any permutation.
	perm := []TreeEntry{entries[5], entries[2], entries[0], entries[4], entries[1], entries[3]}
	SortEntries(perm)
	if !bytes.Equal(EncodeTree(perm), data) {
		t.Fatal("SortEntries order differs from canonical order")
	}
	if e, err := ParseTree(nil); err != nil || len(e) != 0 {
		t.Fatal("empty tree must parse")
	}
}

func TestParseTreeRejects(t *testing.T) {
	id := blob("x").ID()
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"gitlink", rawEntry("160000", "sub", id), ErrUnsupported},
		{"group writable", rawEntry("100664", "f", id), ErrUnsupported},
		{"mode 0", rawEntry("0", "f", id), ErrMalformed},
		{"zero padded dir", rawEntry("040000", "d", id), ErrMalformed},
		{"zero padded file", rawEntry("0100644", "f", id), ErrMalformed},
		{"non octal", rawEntry("100648", "f", id), ErrMalformed},
		{"mode too long", rawEntry("10064400", "f", id), ErrMalformed},
		{"empty mode", rawEntry("", "f", id), ErrMalformed},
		{"letters", rawEntry("abc", "f", id), ErrMalformed},
		{"no space", []byte("100644"), ErrMalformed},
		{"empty name", rawEntry("100644", "", id), ErrMalformed},
		{"slash", rawEntry("100644", "a/b", id), ErrMalformed},
		{"dot", rawEntry("40000", ".", id), ErrMalformed},
		{"dotdot", rawEntry("40000", "..", id), ErrMalformed},
		{"dotgit", rawEntry("40000", ".git", id), ErrMalformed},
		{"dotGIT", rawEntry("40000", ".GIT", id), ErrMalformed},
		{"dotGit file", rawEntry("100644", ".Git", id), ErrMalformed},
		{"ntfs short", rawEntry("40000", "GIT~1", id), ErrMalformed},
		{"ntfs trailing dot", rawEntry("40000", ".git.", id), ErrMalformed},
		{"ntfs trailing space", rawEntry("40000", ".git ", id), ErrMalformed},
		{"ntfs stream", rawEntry("40000", ".git::$INDEX_ALLOCATION", id), ErrMalformed},
		{"hfs ignorable", rawEntry("40000", ".g‌it", id), ErrMalformed},
		{"null id", rawEntry("100644", "f", ZeroID), ErrMalformed},
		{"truncated id", rawEntry("100644", "f", id)[:20], ErrMalformed},
		{"unterminated name", []byte("100644 abc"), ErrMalformed},
		{"trailing garbage", cat(rawEntry("100644", "f", id), []byte{'1'}), ErrMalformed},
		{"unsorted", cat(rawEntry("100644", "b", id), rawEntry("100644", "a", id)), ErrMalformed},
		{"duplicate adjacent", cat(rawEntry("100644", "a", id), rawEntry("100644", "a", id)), ErrMalformed},
		{"dir sorted as file", cat(rawEntry("40000", "a", id), rawEntry("100644", "a.c", id)), ErrMalformed},
		// file "a", file "a-b", dir "a": in canonical order, yet "a" twice.
		{"duplicate file and dir", cat(rawEntry("100644", "a", id), rawEntry("100644", "a-b", id), rawEntry("40000", "a", id)), ErrMalformed},
	}
	for _, c := range cases {
		if _, err := ParseTree(c.data); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else {
			wantErrT(t, c.name, err, c.want)
		}
	}
	// Names that merely resemble .git are fine.
	for _, ok := range []string{".gitignore", ".github", "git", ".git2", "git~2", "...", ".gitx.", "x.git"} {
		if _, err := ParseTree(rawEntry("100644", ok, id)); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
}

func wantErrT(t *testing.T, name string, err, target error) {
	t.Helper()
	if !errorsIs(err, target) {
		t.Errorf("%s: got error %v, want %v", name, err, target)
	}
}
