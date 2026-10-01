package gitobj

import (
	"bytes"
	"compress/zlib"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T, s Store) {
	t.Helper()
	o := blob("hello\n")
	id := o.ID()
	if s.Has(id) {
		t.Fatal("Has before Put")
	}
	if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get before Put: %v", err)
	}
	if _, err := typeOf(s, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("typeOf before Put: %v", err)
	}
	data := []byte("hello\n")
	for i := 0; i < 2; i++ { // idempotent
		got, err := s.Put(Object{Type: TypeBlob, Data: data})
		if err != nil || got != id {
			t.Fatalf("Put: %v %s", err, got)
		}
	}
	data[0] = 'X' // the store must hold its own copy
	got, err := s.Get(id)
	if err != nil || got.Type != TypeBlob || string(got.Data) != "hello\n" {
		t.Fatalf("Get: %v %+v", err, got)
	}
	for _, o := range []Object{treeObj(), commitObj(treeObj().ID(), "m\n"), {Type: TypeBlob}} {
		id, err := s.Put(o)
		if err != nil {
			t.Fatal(err)
		}
		g, err := s.Get(id)
		if err != nil || g.Type != o.Type || !bytes.Equal(g.Data, o.Data) {
			t.Fatalf("round trip of %s: %v", o.Type, err)
		}
		if ty, err := typeOf(s, id); err != nil || ty != o.Type {
			t.Fatalf("typeOf: %v %v", ty, err)
		}
	}
	for _, bad := range []ObjType{0, 4, 255} {
		if _, err := s.Put(Object{Type: bad, Data: []byte("x")}); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Put of type %d: %v", bad, err)
		}
	}
}

func TestMemStore(t *testing.T) {
	s := NewMemStore()
	testStore(t, s)
	if s.Len() != 4 {
		t.Fatalf("Len = %d", s.Len())
	}
}

func TestDiskStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo.git")
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
	// Reopen: content persists, HEAD is not rewritten.
	if err := os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Has(blob("hello\n").ID()) {
		t.Fatal("object lost on reopen")
	}
	if h, _ := os.ReadFile(filepath.Join(dir, "HEAD")); string(h) != "ref: refs/heads/other\n" {
		t.Fatal("HEAD overwritten")
	}
	// No temporary files left behind.
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && len(fi.Name()) > 4 && fi.Name()[:4] == "tmp_" {
			t.Errorf("leftover temporary file %s", p)
		}
		return nil
	})
	if _, err := NewDiskStore(""); err == nil {
		t.Fatal("empty dir accepted")
	}
}

func TestDiskStoreCorruption(t *testing.T) {
	s, err := NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(id ID, raw []byte, compress bool) {
		p := s.path(id)
		os.MkdirAll(filepath.Dir(p), 0o755)
		var buf bytes.Buffer
		if compress {
			w := zlib.NewWriter(&buf)
			w.Write(raw)
			w.Close()
		} else {
			buf.Write(raw)
		}
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		raw      string
		compress bool
		want     error
	}{
		{"not zlib", "garbage", false, ErrMalformed},
		{"wrong hash", "blob 3\x00abc", true, ErrMalformed},
		{"short content", "blob 9\x00abc", true, ErrMalformed},
		{"long content", "blob 1\x00abc", true, ErrMalformed},
		{"no header", "blob", true, ErrMalformed},
		{"bad length", "blob x\x00abc", true, ErrMalformed},
		{"padded length", "blob 03\x00abc", true, ErrMalformed},
		{"huge length", "blob 99999999999\x00abc", true, ErrMalformed},
		{"tag", "tag 3\x00abc", true, ErrUnsupported},
		{"long header", "blobbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 3\x00abc", true, ErrMalformed},
	}
	for i, c := range cases {
		id := blob(string(rune('A' + i))).ID()
		write(id, []byte(c.raw), c.compress)
		if !s.Has(id) {
			t.Fatalf("%s: Has is false", c.name)
		}
		_, err := s.Get(id)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		wantErrT(t, c.name, err, c.want)
	}
}

func TestOverlay(t *testing.T) {
	base := NewMemStore()
	inBase := blob("base")
	base.Put(inBase)
	inBundle := blob("bundle")
	ov := NewOverlay(base, &Bundle{Objects: []Object{inBundle, {Type: 9, Data: []byte("bad")}}})
	for _, o := range []Object{inBase, inBundle} {
		if !ov.Has(o.ID()) {
			t.Fatal("Has")
		}
		g, err := ov.Get(o.ID())
		if err != nil || !bytes.Equal(g.Data, o.Data) {
			t.Fatal("Get", err)
		}
		if ty, err := typeOf(ov, o.ID()); err != nil || ty != TypeBlob {
			t.Fatal("typeOf", err)
		}
	}
	missing := blob("missing").ID()
	if ov.Has(missing) {
		t.Fatal("Has(missing)")
	}
	if _, err := ov.Get(missing); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if ov.Has((Object{Type: 9, Data: []byte("bad")}).ID()) {
		t.Fatal("invalid object visible")
	}
	if _, err := ov.Put(blob("new")); !errors.Is(err, ErrReadOnly) {
		t.Fatal("overlay accepted a Put")
	}
	if base.Has(blob("new").ID()) || base.Has(inBundle.ID()) {
		t.Fatal("overlay wrote to base")
	}
	// Nil base and nil bundle.
	if _, err := NewOverlay(nil, nil).Get(missing); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
