package gitobj

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Differential tests against the real git CLI.

type gitRepo struct {
	t    *testing.T
	dir  string
	tick int
}

// gitEnv makes git reproducible: no user/system config, fixed identity.
// It uses t.Setenv so that ExtractBundle/ResolveRef (which inherit the
// process environment) see the same settings.
func gitEnv(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed; skipping differential test")
	}
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_SYSTEM":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "Alice Example",
		"GIT_AUTHOR_EMAIL":    "alice@example.org",
		"GIT_COMMITTER_NAME":  "Bob Example",
		"GIT_COMMITTER_EMAIL": "bob@example.org",
		"GIT_AUTHOR_DATE":     "1700000000 +0000",
		"GIT_COMMITTER_DATE":  "1700000000 +0000",
		"HOME":                t.TempDir(),
	} {
		t.Setenv(k, v)
	}
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	gitEnv(t)
	r := &gitRepo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("config", "core.autocrlf", "false")
	r.git("config", "core.filemode", "true")
	r.git("config", "core.symlinks", "true")
	r.git("config", "core.quotepath", "true")
	r.git("config", "commit.gpgsign", "false")
	return r
}

func (r *gitRepo) gitIn(stdin []byte, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, errb.String())
	}
	return out.String()
}

func (r *gitRepo) git(args ...string) string { r.t.Helper(); return r.gitIn(nil, args...) }

func (r *gitRepo) write(path string, data string, mode os.FileMode) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	os.Remove(p)
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		r.t.Fatal(err)
	}
}

func (r *gitRepo) symlink(path, target string) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(path))
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.RemoveAll(p)
	if err := os.Symlink(target, p); err != nil {
		r.t.Fatal(err)
	}
}

func (r *gitRepo) remove(path string) {
	r.t.Helper()
	if err := os.RemoveAll(filepath.Join(r.dir, filepath.FromSlash(path))); err != nil {
		r.t.Fatal(err)
	}
}

// commit stages everything and commits with a distinct, fixed date.
func (r *gitRepo) commit(msg string) ID {
	r.t.Helper()
	r.git("add", "-A")
	return r.commitIndex(msg)
}

func (r *gitRepo) commitIndex(msg string) ID {
	r.t.Helper()
	r.tick++
	date := fmt.Sprintf("%d +0100", 1700000000+r.tick*60)
	r.t.Setenv("GIT_AUTHOR_DATE", date)
	r.t.Setenv("GIT_COMMITTER_DATE", date)
	r.git("commit", "-q", "--allow-empty", "-m", msg)
	return mustID(r.t, strings.TrimSpace(r.git("rev-parse", "HEAD")))
}

// gitDiff parses `git diff-tree -r --no-renames --raw -z`.
func (r *gitRepo) gitDiff(base, cand ID) []Change {
	r.t.Helper()
	var out string
	if base.IsZero() {
		out = r.git("diff-tree", "-r", "--no-renames", "--raw", "-z", "--no-commit-id", "--root", "--no-abbrev", cand.String())
	} else {
		out = r.git("diff-tree", "-r", "--no-renames", "--raw", "-z", "--no-abbrev", base.String(), cand.String())
	}
	var cs []Change
	f := strings.Split(out, "\x00")
	for i := 0; i+1 < len(f); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(f[i], ":"))
		if len(meta) != 5 {
			r.t.Fatalf("unexpected diff-tree record %q", f[i])
		}
		var c Change
		fmt.Sscanf(meta[0], "%o", &c.OldMode)
		fmt.Sscanf(meta[1], "%o", &c.NewMode)
		c.OldID = mustID(r.t, meta[2])
		c.NewID = mustID(r.t, meta[3])
		c.Path = f[i+1]
		switch meta[4] {
		case "A", "D", "M", "T":
		default:
			r.t.Fatalf("unexpected status %q", meta[4])
		}
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Path < cs[j].Path })
	return cs
}

// buildHistory creates a history exercising every kind of change and
// returns the commits in order.
func buildHistory(r *gitRepo) []ID {
	var commits []ID
	// 1: initial content.
	r.write("README.md", "# project\n\nhello\n", 0o644)
	r.write("src/main.go", "package main\n\nfunc main() {}\n", 0o644)
	r.write("src/lib/util.go", "package lib\n", 0o644)
	r.write("src/lib/deep/er/x.txt", "deep\n", 0o644)
	r.write("bin/run.sh", "#!/bin/sh\necho hi\n", 0o755)
	r.write("empty", "", 0o644)
	r.write("binary.dat", "\x00\x01\xff\xfe binary \x80\n", 0o644)
	r.write("crlf.txt", "a\r\nb\r\n", 0o644)
	r.write("no-newline", "no newline at end", 0o644)
	r.write("with space/and ünïcode.txt", "x\n", 0o644)
	r.write("conf", "a file that becomes a directory\n", 0o644)
	r.write("tool/a", "a directory that becomes a file\n", 0o644)
	r.write("to-delete.txt", "this content will come back later\n", 0o644)
	r.write("to-rename.txt", "rename me\n", 0o644)
	r.write("chmod-me", "mode only\n", 0o644)
	// names that stress tree ordering: "a" (dir) vs "a-b", "a.c", "a0"
	r.write("a/file", "in a\n", 0o644)
	r.write("a-b", "a-b\n", 0o644)
	r.write("a.c", "a.c\n", 0o644)
	r.write("a0", "a0\n", 0o644)
	r.symlink("link", "README.md")
	r.symlink("link-to-file", "src/main.go")
	commits = append(commits, r.commit("initial commit\n\nwith a body"))

	// 2: modify, delete, rename, mode-only change, add.
	r.write("README.md", "# project\n\nhello world\n", 0o644)
	r.remove("to-delete.txt")
	r.git("mv", "to-rename.txt", "renamed.txt")
	r.write("chmod-me", "mode only\n", 0o755)
	r.write("src/new.go", "package main\n", 0o644)
	r.write("empty", "no longer empty\n", 0o644)
	r.write("binary.dat", "\x00\x02\xff binary v2", 0o644)
	r.symlink("link", "src")
	commits = append(commits, r.commit("second"))

	// 3: type changes.
	r.remove("conf")
	r.write("conf/x", "x\n", 0o644)
	r.write("conf/sub/y", "y\n", 0o644)
	r.remove("tool")
	r.write("tool", "now a file\n", 0o644)
	r.remove("link-to-file")
	r.write("link-to-file", "src/main.go", 0o644) // symlink -> file, same content
	r.remove("a-b")
	r.symlink("a-b", "a0") // file -> symlink
	r.remove("a")
	r.write("a", "a is now a file\n", 0o644)
	commits = append(commits, r.commit("type changes"))

	// 4: empty commit (tree unchanged).
	commits = append(commits, r.commit("empty commit"))

	// 5: re-add content deleted in 2 (blob exists in older history) and
	// make a file empty.
	r.write("restored/again.txt", "this content will come back later\n", 0o644)
	r.write("empty", "", 0o644)
	r.write("src/lib/deep/er/x.txt", "deeper\n", 0o644)
	commits = append(commits, r.commit("re-add an old blob"))

	// 6: paths that cannot exist in (this) file system, staged through
	// the index: non-UTF-8 name, newline, quote, backslash, tab.
	for i, name := range []string{"odd/\xff\xfe-latin", "odd/new\nline", "odd/qu\"ote", "odd/back\\slash", "odd/t\tab", "odd/ sp "} {
		blobID := strings.TrimSpace(r.gitIn([]byte(fmt.Sprintf("content %d\n", i)), "hash-object", "-w", "--stdin"))
		r.git("update-index", "--add", "--cacheinfo", "100644,"+blobID+","+name)
	}
	commits = append(commits, r.commitIndex("odd names"))
	return commits
}

func TestGitDifferential(t *testing.T) {
	r := newGitRepo(t)
	commits := buildHistory(r)

	head, err := ResolveRef(r.dir, "HEAD")
	if err != nil || head != commits[len(commits)-1] {
		t.Fatalf("ResolveRef: %v %s", err, head)
	}
	if id, err := ResolveRef(r.dir, "main~1"); err != nil || id != commits[len(commits)-2] {
		t.Fatalf("ResolveRef main~1: %v", err)
	}
	for _, bad := range []string{"", "-h", "--all", "nonexistent", "a\nb"} {
		if _, err := ResolveRef(r.dir, bad); err == nil {
			t.Errorf("ResolveRef(%q) succeeded", bad)
		}
	}

	dir := filepath.Join(t.TempDir(), "validator.git")
	disk, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	mem := NewMemStore()
	vgit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"--git-dir=" + dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git --git-dir %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	parent := ZeroID
	for n, c := range commits {
		b, err := ExtractBundle(r.dir, parent, c)
		if err != nil {
			t.Fatalf("commit %d: ExtractBundle: %v", n+1, err)
		}
		// Our IDs equal git's: ExtractBundle verifies each object
		// against the ID git reported; check the type via git too.
		for _, o := range b.Objects {
			if ty := strings.TrimSpace(r.git("cat-file", "-t", o.ID().String())); ty != o.Type.String() {
				t.Fatalf("object %s: git says %s, we say %s", o.ID(), ty, o.Type)
			}
		}
		enc := b.Encode()
		dec, err := DecodeBundle(enc, DefaultLimits)
		if err != nil {
			t.Fatalf("commit %d: DecodeBundle: %v", n+1, err)
		}
		if !bytes.Equal(dec.Encode(), enc) {
			t.Fatalf("commit %d: bundle round trip", n+1)
		}

		for _, s := range []Store{disk, mem} {
			commit, err := VerifyClosure(s, dec, c, parent, DefaultLimits)
			if err != nil {
				t.Fatalf("commit %d (%T): VerifyClosure: %v", n+1, s, err)
			}
			// Commit fields agree with git.
			if got := strings.TrimSpace(r.git("rev-parse", c.String()+"^{tree}")); got != commit.Tree.String() {
				t.Fatalf("tree: %s vs %s", got, commit.Tree)
			}
			if got := r.git("log", "-1", "--format=%B", c.String()); strings.TrimRight(got, "\n") != strings.TrimRight(commit.Message, "\n") {
				t.Fatalf("message: %q vs %q", got, commit.Message)
			}

			// DiffTrees over the overlay (nothing written yet).
			var baseTree ID
			if !parent.IsZero() {
				po, err := s.Get(parent)
				if err != nil {
					t.Fatal(err)
				}
				pc, err := ParseCommit(po.Data)
				if err != nil {
					t.Fatal(err)
				}
				baseTree = pc.Tree
			}
			got, err := DiffTrees(NewOverlay(s, dec), baseTree, commit.Tree, DefaultLimits)
			if err != nil {
				t.Fatalf("commit %d: DiffTrees: %v", n+1, err)
			}
			want := r.gitDiff(parent, c)
			if len(got) == 0 && len(want) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("commit %d (%T): diff differs from git\n got: %q\nwant: %q", n+1, s, fmtChanges(got), fmtChanges(want))
			}
		}
		for _, s := range []Store{disk, mem} {
			if err := ApplyBundle(s, dec); err != nil {
				t.Fatal(err)
			}
		}

		// Stock git can read what DiskStore wrote.
		for _, o := range dec.Objects {
			id := o.ID().String()
			if ty := strings.TrimSpace(vgit("cat-file", "-t", id)); ty != o.Type.String() {
				t.Fatalf("validator git: type of %s is %s", id, ty)
			}
			if o.Type == TypeBlob {
				if raw := vgit("cat-file", "blob", id); raw != string(o.Data) {
					t.Fatalf("validator git: blob %s differs", id)
				}
			}
		}
		if got, want := vgit("cat-file", "-p", c.String()), r.git("cat-file", "-p", c.String()); got != want {
			t.Fatalf("cat-file -p differs:\n%s\n%s", got, want)
		}
		if got, want := vgit("ls-tree", "-r", "-t", "-z", c.String()), r.git("ls-tree", "-r", "-t", "-z", c.String()); got != want {
			t.Fatalf("ls-tree differs:\n%q\n%q", got, want)
		}
		// Full connectivity and object check from the new head.
		vgit("fsck", "--strict", "--no-dangling", c.String())
		parent = c
	}
	// The whole history is readable.
	if got, want := vgit("rev-list", "--objects", parent.String()), r.git("rev-list", "--objects", parent.String()); got != want {
		t.Fatal("rev-list --objects differs between the validator store and the source repository")
	}
	if got := strings.Fields(vgit("rev-list", parent.String())); len(got) != len(commits) {
		t.Fatalf("history has %d commits", len(got))
	}
}

// Bundles that skip a commit, or that are based on the wrong parent, are
// rejected; this is what git hands us when the client is not a direct
// child of the head.
func TestGitNonLinear(t *testing.T) {
	r := newGitRepo(t)
	r.write("f", "1\n", 0o644)
	c1 := r.commit("one")
	r.write("f", "2\n", 0o644)
	c2 := r.commit("two")
	r.write("f", "3\n", 0o644)
	c3 := r.commit("three")

	s := NewMemStore()
	b1, err := ExtractBundle(r.dir, ZeroID, c1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyClosure(s, b1, c1, ZeroID, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	ApplyBundle(s, b1)

	// c3 on top of c1: two commits in the bundle.
	b13, err := ExtractBundle(r.dir, c1, c3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyClosure(s, b13, c3, c1, DefaultLimits)
	wantErr(t, err, ErrParent)
	// Root bundle of c2 contains c1 as well.
	b2, err := ExtractBundle(r.dir, ZeroID, c2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyClosure(s, b2, c2, ZeroID, DefaultLimits)
	wantErr(t, err, ErrParent)
	// Correct bundle, stale expected head.
	b12, err := ExtractBundle(r.dir, c1, c2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyClosure(s, b12, c2, c3, DefaultLimits)
	wantErr(t, err, ErrParent)
	if _, err = VerifyClosure(s, b12, c2, c1, DefaultLimits); err != nil {
		t.Fatal(err)
	}

	// A merge commit.
	r.git("checkout", "-q", "-b", "side", c1.String())
	r.write("g", "side\n", 0o644)
	r.commit("side")
	r.git("checkout", "-q", "main")
	r.git("merge", "-q", "--no-ff", "-m", "merge", "side")
	m := mustID(t, strings.TrimSpace(r.git("rev-parse", "HEAD")))
	ApplyBundle(s, b12)
	b23, _ := ExtractBundle(r.dir, c2, c3)
	ApplyBundle(s, b23)
	bm, err := ExtractBundle(r.dir, c3, m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyClosure(s, bm, m, c3, DefaultLimits)
	wantErr(t, err, ErrParent)

	// Errors of the client helpers.
	if _, err := ExtractBundle(r.dir, ZeroID, ZeroID); err == nil {
		t.Error("zero candidate accepted")
	}
	if _, err := ExtractBundle(r.dir, c1, blob("nope").ID()); err == nil {
		t.Error("unknown candidate accepted")
	}
	if _, err := ExtractBundle(t.TempDir(), ZeroID, c1); err == nil {
		t.Error("non-repository accepted")
	}
	if _, err := ExtractBundle(r.dir, c1, c1); err == nil {
		t.Error("empty object list accepted")
	}
}

// Objects git refuses to create through porcelain but that a hostile
// client can hand-craft: check that git fsck agrees with our rejections.
func TestGitAgreesOnRejections(t *testing.T) {
	gitEnv(t)
	id := blob("x").ID()
	trees := map[string][]byte{
		"dotgit":     rawEntry("40000", ".git", id),
		"dotGIT":     rawEntry("40000", ".GIT", id),
		"dotdot":     rawEntry("100644", "..", id),
		"dot":        rawEntry("100644", ".", id),
		"unsorted":   append(rawEntry("100644", "b", id), rawEntry("100644", "a", id)...),
		"duplicate":  append(rawEntry("100644", "a", id), rawEntry("100644", "a", id)...),
		"dup-split":  bytes.Join([][]byte{rawEntry("100644", "a", id), rawEntry("100644", "a-b", id), rawEntry("40000", "a", id)}, nil),
		"zeropadded": rawEntry("0100644", "d", id),
		"slash":      rawEntry("100644", "a/b", id),
		"badmode":    rawEntry("100664", "f", id),
		"nullsha":    rawEntry("100644", "f", ZeroID),
		"truncated":  rawEntry("100644", "f", id)[:25],
	}
	names := make([]string, 0, len(trees))
	for name := range trees {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := trees[name]
		if _, err := ParseTree(data); err == nil {
			t.Errorf("%s: we accept", name)
		}
		r := newGitRepo(t)
		r.gitIn([]byte("x"), "hash-object", "-w", "--stdin")
		r.gitIn(data, "hash-object", "-t", "tree", "-w", "--stdin", "--literally")
		cmd := exec.Command("git", "-C", r.dir, "fsck", "--strict")
		if out, err := cmd.CombinedOutput(); err == nil {
			if name == "badmode" && strings.Contains(string(out), "badFilemode") {
				// git 2.39 only warns about mode 100664 (old
				// repositories contain it); we are stricter.
				continue
			}
			t.Errorf("%s: git fsck --strict accepts what we reject: %s", name, out)
		}
	}
	// And the reverse for commits: what we accept, fsck accepts.
	r := newGitRepo(t)
	tree := strings.TrimSpace(r.gitIn(nil, "hash-object", "-t", "tree", "-w", "/dev/null"))
	good := "tree " + tree + "\nauthor " + testIdent + "\ncommitter " + testIdent + "\n\nmsg\n"
	if _, err := ParseCommit([]byte(good)); err != nil {
		t.Fatal(err)
	}
	cid := strings.TrimSpace(r.gitIn([]byte(good), "hash-object", "-t", "commit", "-w", "--stdin"))
	if cid != (Object{Type: TypeCommit, Data: []byte(good)}).ID().String() {
		t.Fatal("commit id differs from git")
	}
	r.git("fsck", "--strict", cid)
	commits := map[string]string{
		"no author":     "tree " + tree + "\ncommitter " + testIdent + "\n\nmsg\n",
		"no committer":  "tree " + tree + "\nauthor " + testIdent + "\n\nmsg\n",
		"bad date":      "tree " + tree + "\nauthor A <a@b> x +0000\ncommitter " + testIdent + "\n\nmsg\n",
		"no email":      "tree " + tree + "\nauthor A 1 +0000\ncommitter " + testIdent + "\n\nmsg\n",
		"bad tree":      "tree xyz\nauthor " + testIdent + "\ncommitter " + testIdent + "\n\nmsg\n",
		"parent late":   "tree " + tree + "\nauthor " + testIdent + "\nparent " + tree + "\ncommitter " + testIdent + "\n\nmsg\n",
		"nul in header": "tree " + tree + "\nauthor " + testIdent + "\ncommitter " + testIdent + "\nx a\x00b\n\nmsg\n",
	}
	cnames := make([]string, 0, len(commits))
	for name := range commits {
		cnames = append(cnames, name)
	}
	sort.Strings(cnames)
	for _, name := range cnames {
		data := commits[name]
		if _, err := ParseCommit([]byte(data)); err == nil {
			t.Errorf("%s: we accept", name)
		}
		r := newGitRepo(t)
		r.gitIn(nil, "hash-object", "-t", "tree", "-w", "/dev/null")
		r.gitIn([]byte(data), "hash-object", "-t", "commit", "-w", "--stdin", "--literally")
		cmd := exec.Command("git", "-C", r.dir, "fsck", "--strict")
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Logf("%s: note: git fsck --strict accepts a commit we reject (we are stricter): %s", name, out)
		}
	}
}
