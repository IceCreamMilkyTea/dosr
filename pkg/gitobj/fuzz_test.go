package gitobj

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzParseTree(f *testing.F) {
	id := blob("x").ID()
	f.Add([]byte{})
	f.Add(rawEntry("100644", "a", id))
	f.Add(rawEntry("40000", "dir", id))
	f.Add(rawEntry("160000", "sub", id))
	f.Add(rawEntry("040000", ".git", id))
	f.Add(EncodeTree([]TreeEntry{{ModeFile, "a.c", id}, {ModeDir, "a", id}, {ModeExec, "a0", id}, {ModeSymlink, "z", id}}))
	f.Add(append(rawEntry("100644", "a", id), rawEntry("40000", "a", id)...))
	f.Add([]byte("100644 abc"))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ParseTree(data)
		if err != nil {
			if entries != nil {
				t.Fatal("entries returned with error")
			}
			if !errorsIs(err, ErrMalformed) && !errorsIs(err, ErrUnsupported) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		// Canonical: the only encoding of these entries is the input.
		if !bytes.Equal(EncodeTree(entries), data) {
			t.Fatalf("accepted tree does not re-encode to itself: %q", data)
		}
		seen := map[string]bool{}
		for i, e := range entries {
			if seen[e.Name] {
				t.Fatalf("duplicate name %q", e.Name)
			}
			seen[e.Name] = true
			lower := strings.ToLower(e.Name)
			if e.Name == "" || strings.ContainsAny(e.Name, "/\x00") || e.Name == "." || e.Name == ".." || lower == ".git" {
				t.Fatalf("bad name accepted: %q", e.Name)
			}
			if e.Mode != ModeDir && e.Mode != ModeFile && e.Mode != ModeExec && e.Mode != ModeSymlink {
				t.Fatalf("bad mode accepted: %o", e.Mode)
			}
			if i > 0 && compareEntries(entries[i-1], e) >= 0 {
				t.Fatal("order")
			}
		}
		// Sorting is a no-op on accepted trees.
		cp := append([]TreeEntry(nil), entries...)
		SortEntries(cp)
		if !bytes.Equal(EncodeTree(cp), data) {
			t.Fatal("SortEntries changed a canonical tree")
		}
	})
}

func FuzzParseCommit(f *testing.F) {
	tree := strings.Repeat("a", 40)
	hdr := "author " + testIdent + "\ncommitter " + testIdent + "\n"
	f.Add([]byte("tree " + tree + "\n" + hdr + "\nmsg\n"))
	f.Add([]byte("tree " + tree + "\nparent " + strings.Repeat("b", 40) + "\n" + hdr + "\n"))
	f.Add([]byte("tree " + tree + "\nparent " + strings.Repeat("b", 40) + "\nparent " + strings.Repeat("c", 40) + "\n" + hdr + "gpgsig x\n y\n z\n\nmsg"))
	f.Add([]byte("tree " + tree + "\n" + hdr + "encoding latin1\n\n\xff\x00"))
	f.Add([]byte("tree " + tree + "\n" + hdr))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseCommit(data)
		if err != nil {
			if c != nil {
				t.Fatal("commit returned with error")
			}
			if !errorsIs(err, ErrMalformed) && !errorsIs(err, ErrLimit) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		// What we parsed is what the bytes say, line by line.
		s := string(data)
		if !strings.HasPrefix(s, "tree "+c.Tree.String()+"\n") {
			t.Fatal("tree mismatch")
		}
		rest := s[46:]
		for _, p := range c.Parents {
			line := "parent " + p.String() + "\n"
			if !strings.HasPrefix(rest, line) {
				t.Fatal("parent mismatch")
			}
			rest = rest[len(line):]
		}
		line := "author " + c.Author + "\ncommitter " + c.Committer + "\n"
		if !strings.HasPrefix(rest, line) {
			t.Fatal("ident mismatch")
		}
		if strings.ContainsAny(c.Author+c.Committer, "\n\x00") {
			t.Fatal("header injection")
		}
		if !strings.HasSuffix(s, "\n\n"+c.Message) && !strings.HasSuffix(s, "\n"+c.Message) {
			t.Fatal("message mismatch")
		}
		// The header section (everything before the message) has no
		// further tree/parent/author/committer lines.
		head := rest[len(line) : len(rest)-len(c.Message)]
		for _, l := range strings.Split(head, "\n") {
			for _, k := range []string{"tree ", "parent ", "author ", "committer "} {
				if strings.HasPrefix(l, k) {
					t.Fatalf("interpreted header %q repeated", k)
				}
			}
		}
		// EncodeCommit round trip when there are no extra headers.
		if head == "\n" && !bytes.Equal(EncodeCommit(c), data) {
			t.Fatal("EncodeCommit differs")
		}
	})
}

func FuzzDecodeBundle(f *testing.F) {
	f.Add((&Bundle{}).Encode())
	f.Add((&Bundle{Objects: []Object{blob("a"), blob("b"), treeObj(), commitObj(treeObj().ID(), "m\n")}}).Encode())
	f.Add(rawBundle(blob("b"), blob("a"), blob("a")))
	f.Add([]byte("DOSRBNDL\x01\xff\xff\xff\xff"))
	f.Add([]byte("DOSRBNDL\x01\x00\x00\x00\x01\x03\xff\xff\xff\xff"))
	{
		s := NewMemStore()
		b, _ := makeCommit(f, s, ZeroID, "m\n", baseFiles)
		f.Add(b.Encode())
	}
	lim := Limits{MaxBundleBytes: 1 << 16, MaxObjects: 64, MaxObjectBytes: 1 << 12, MaxTreeDepth: 8, MaxPathBytes: 128}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := DecodeBundle(data, lim)
		if err != nil {
			if b != nil {
				t.Fatal("bundle returned with error")
			}
			if !errorsIs(err, ErrMalformed) && !errorsIs(err, ErrNonCanonical) && !errorsIs(err, ErrLimit) && !errorsIs(err, ErrUnsupported) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if !bytes.Equal(b.Encode(), data) {
			t.Fatal("Encode(DecodeBundle(x)) != x")
		}
		if len(data) > lim.MaxBundleBytes || len(b.Objects) > lim.MaxObjects {
			t.Fatal("limit not enforced")
		}
		base := NewMemStore()
		for _, o := range b.Objects {
			if len(o.Data) > lim.MaxObjectBytes || !o.Type.Valid() {
				t.Fatal("limit or type not enforced")
			}
		}
		// Whatever decodes must be safe to verify, diff and walk with
		// any object as the candidate.
		for _, o := range b.Objects {
			c, err := VerifyClosure(base, b, o.ID(), ZeroID, lim)
			if err != nil {
				continue
			}
			ov := NewOverlay(base, b)
			changes, err := DiffTrees(ov, ZeroID, c.Tree, lim)
			if err != nil {
				// Only the diff work limits may trip after a
				// successful closure check.
				if !errorsIs(err, ErrLimit) {
					t.Fatalf("DiffTrees after VerifyClosure: %v", err)
				}
				continue
			}
			for i, ch := range changes {
				if len(ch.Path) > lim.MaxPathBytes || strings.Count(ch.Path, "/") > lim.MaxTreeDepth {
					t.Fatalf("path %q exceeds limits", ch.Path)
				}
				if i > 0 && changes[i-1].Path >= ch.Path {
					t.Fatal("changes not strictly sorted")
				}
				if !ov.Has(ch.NewID) {
					t.Fatal("closure verified but blob missing")
				}
			}
		}
	})
}
