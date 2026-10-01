package review

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// applyPatch applies hunks produced by UnifiedDiff to a. It is written
// independently of the diff code (it only knows the unified format) and
// verifies every context and deletion line, the hunk positions and the
// line counts announced in the headers.
func applyPatch(a, patch []byte, maxContext int) ([]byte, error) {
	al := splitKeep(a)
	var out []byte
	pos := 0 // lines of a consumed
	bLines := 0
	lines := strings.SplitAfter(string(patch), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	i := 0
	for i < len(lines) {
		h := lines[i]
		i++
		var aStart, aCount, bStart, bCount int
		if !strings.HasSuffix(h, " @@\n") {
			return nil, fmt.Errorf("bad hunk header %q", h)
		}
		if n, err := fmt.Sscanf(h, "@@ -%d,%d +%d,%d @@\n", &aStart, &aCount, &bStart, &bCount); n != 4 || err != nil {
			return nil, fmt.Errorf("bad hunk header %q", h)
		}
		if want := fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", aStart, aCount, bStart, bCount); want != h {
			return nil, fmt.Errorf("non-canonical hunk header %q", h)
		}
		if aCount == 0 && bCount == 0 {
			return nil, fmt.Errorf("empty hunk")
		}
		first := aStart - 1
		if aCount == 0 {
			first = aStart
		}
		if first < pos || first > len(al) {
			return nil, fmt.Errorf("hunk %q out of order or range (pos %d)", h, pos)
		}
		for pos < first {
			out = append(out, al[pos]...)
			pos++
			bLines++
		}
		wantB := bStart - 1
		if bCount == 0 {
			wantB = bStart
		}
		if wantB != bLines {
			return nil, fmt.Errorf("hunk %q: new start is %d, expected %d", h, wantB, bLines)
		}
		lead, trail, sawChange := 0, 0, false
		lastKind := byte(0)
		for aCount > 0 || bCount > 0 {
			if i >= len(lines) {
				return nil, fmt.Errorf("truncated hunk")
			}
			l := lines[i]
			i++
			if len(l) < 2 || l[len(l)-1] != '\n' {
				return nil, fmt.Errorf("bad line %q", l)
			}
			kind, content := l[0], l[1:]
			if i < len(lines) && lines[i] == noNewline {
				i++
				content = content[:len(content)-1]
			}
			switch kind {
			case ' ', '-':
				if pos >= len(al) || al[pos] != content {
					return nil, fmt.Errorf("line %d of old file does not match %q", pos+1, l)
				}
				pos++
				aCount--
				if kind == ' ' {
					out = append(out, content...)
					bCount--
					bLines++
					if sawChange {
						trail++
					} else {
						lead++
					}
				} else {
					if lastKind == '+' {
						return nil, fmt.Errorf("deletion after insertion in one run")
					}
					sawChange = true
					trail = 0
				}
			case '+':
				out = append(out, content...)
				bCount--
				bLines++
				sawChange = true
				trail = 0
			default:
				return nil, fmt.Errorf("bad line prefix in %q", l)
			}
			lastKind = kind
			if aCount < 0 || bCount < 0 {
				return nil, fmt.Errorf("hunk longer than announced")
			}
		}
		if !sawChange {
			return nil, fmt.Errorf("hunk without change")
		}
		if lead > maxContext || trail > maxContext {
			return nil, fmt.Errorf("too much context: %d/%d", lead, trail)
		}
	}
	for pos < len(al) {
		out = append(out, al[pos]...)
		pos++
	}
	return out, nil
}

func splitKeep(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	l := strings.SplitAfter(string(b), "\n")
	if l[len(l)-1] == "" {
		l = l[:len(l)-1]
	}
	return l
}

func checkDiff(t testing.TB, a, b []byte, context int) []byte {
	t.Helper()
	d := UnifiedDiff(a, b, context)
	if !bytes.Equal(d, UnifiedDiff(a, b, context)) {
		t.Fatal("UnifiedDiff is not deterministic")
	}
	if bytes.Equal(a, b) {
		if len(d) != 0 {
			t.Fatalf("diff of equal inputs: %q", d)
		}
		return d
	}
	if len(d) == 0 {
		t.Fatalf("empty diff of different inputs %q %q", a, b)
	}
	c := context
	if c < 0 {
		c = 0
	}
	got, err := applyPatch(a, d, c)
	if err != nil {
		t.Fatalf("invalid diff: %v\na=%q\nb=%q\ndiff=%q", err, a, b, d)
	}
	if !bytes.Equal(got, b) {
		t.Fatalf("patch does not yield b\na=%q\nb=%q\ndiff=%q\ngot=%q", a, b, d, got)
	}
	return d
}

func TestUnifiedDiffExact(t *testing.T) {
	seq := func(from, to int) string {
		var s strings.Builder
		for i := from; i <= to; i++ {
			s.WriteString(strconv.Itoa(i) + "\n")
		}
		return s.String()
	}
	cases := []struct {
		name, a, b string
		ctx        int
		want       string
	}{
		{"equal", "a\n", "a\n", 3, ""},
		{"both empty", "", "", 3, ""},
		{"add to empty", "", "a\nb\n", 3, "@@ -0,0 +1,2 @@\n+a\n+b\n"},
		{"delete all", "a\nb\n", "", 3, "@@ -1,2 +0,0 @@\n-a\n-b\n"},
		{"add without newline", "", "a", 3, "@@ -0,0 +1,1 @@\n+a\n\\ No newline at end of file\n"},
		{"newline added", "a", "a\n", 3, "@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+a\n"},
		{"newline removed", "x\na\n", "x\na", 3, "@@ -1,2 +1,2 @@\n x\n-a\n+a\n\\ No newline at end of file\n"},
		{"both without newline", "a\nb", "c\nb", 3, "@@ -1,2 +1,2 @@\n-a\n+c\n b\n\\ No newline at end of file\n"},
		{"only newline", "", "\n", 3, "@@ -0,0 +1,1 @@\n+\n"},
		{"crlf is content", "a\r\nb\r\n", "a\nb\r\n", 3, "@@ -1,2 +1,2 @@\n-a\r\n+a\n b\r\n"},
		{"middle change", seq(1, 9), strings.Replace(seq(1, 9), "5\n", "five\n", 1), 3,
			"@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"},
		{"context 0", seq(1, 9), strings.Replace(seq(1, 9), "5\n", "five\n", 1), 0,
			"@@ -5,1 +5,1 @@\n-5\n+five\n"},
		{"context 0 insert", seq(1, 3), "1\n2\nnew\n3\n", 0, "@@ -2,0 +3,1 @@\n+new\n"},
		{"context 0 delete", seq(1, 3), "1\n3\n", 0, "@@ -2,1 +1,0 @@\n-2\n"},
		{"negative context", seq(1, 3), "1\n3\n", -5, "@@ -2,1 +1,0 @@\n-2\n"},
		// gap of 6 equal lines = 2*context: one hunk
		{"merged hunks", seq(1, 10), "1\nX\n" + seq(3, 8) + "Y\n10\n", 3,
			"@@ -1,10 +1,10 @@\n 1\n-2\n+X\n 3\n 4\n 5\n 6\n 7\n 8\n-9\n+Y\n 10\n"},
		// gap of 7: two hunks
		{"split hunks", seq(1, 11), "1\nX\n" + seq(3, 9) + "Y\n11\n", 3,
			"@@ -1,5 +1,5 @@\n 1\n-2\n+X\n 3\n 4\n 5\n@@ -7,5 +7,5 @@\n 7\n 8\n 9\n-10\n+Y\n 11\n"},
		{"line looking like a header", "@@ -1,1 +1,1 @@\n", "\\ No newline at end of file\n", 3,
			"@@ -1,1 +1,1 @@\n-@@ -1,1 +1,1 @@\n+\\ No newline at end of file\n"},
	}
	for _, c := range cases {
		got := string(checkDiff(t, []byte(c.a), []byte(c.b), c.ctx))
		if got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestUnifiedDiffMinimal(t *testing.T) {
	// Classic example from Myers' paper: ABCABBA -> CBABAC, D = 5.
	a := "A\nB\nC\nA\nB\nB\nA\n"
	b := "C\nB\nA\nB\nA\nC\n"
	d := checkDiff(t, []byte(a), []byte(b), 0)
	changes := 0
	for _, l := range strings.Split(string(d), "\n") {
		if strings.HasPrefix(l, "-") || strings.HasPrefix(l, "+") {
			changes++
		}
	}
	if changes != 5 {
		t.Fatalf("edit distance %d, want 5:\n%s", changes, d)
	}
}

func TestUnifiedDiffRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a\n", "b\n", "c\n", "\n", "a\r\n", "long line with text\n", "-x\n", "+y\n", " z\n", "\\\n", "@@\n"}
	gen := func(n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, alphabet[rng.Intn(len(alphabet))]...)
		}
		if rng.Intn(3) == 0 {
			b = append(b, "tail without newline"...)
		}
		return b
	}
	for i := 0; i < 3000; i++ {
		a := gen(rng.Intn(30))
		var b []byte
		if rng.Intn(2) == 0 {
			b = gen(rng.Intn(30))
		} else {
			// Mutate a: closer to real edits.
			lines := splitKeep(a)
			for _, l := range lines {
				switch rng.Intn(8) {
				case 0:
				case 1:
					b = append(b, alphabet[rng.Intn(len(alphabet))]...)
					b = append(b, l...)
				default:
					b = append(b, l...)
				}
			}
		}
		checkDiff(t, a, b, rng.Intn(5))
	}
}

// Inputs beyond the algorithm's bounds use the fallback, which must still
// be a valid diff, and must keep the common prefix and suffix.
func TestUnifiedDiffFallback(t *testing.T) {
	var a, b []byte
	for i := 0; i < 5; i++ {
		a = append(a, "common prefix\n"...)
		b = append(b, "common prefix\n"...)
	}
	for i := 0; i < 3000; i++ {
		a = fmt.Appendf(a, "old %d\n", i)
		b = fmt.Appendf(b, "new %d\n", i)
	}
	for i := 0; i < 5; i++ {
		a = append(a, "common suffix\n"...)
		b = append(b, "common suffix\n"...)
	}
	d := checkDiff(t, a, b, 3)
	if !bytes.HasPrefix(d, []byte("@@ -3,3006 +3,3006 @@\n common prefix\n")) {
		t.Fatalf("unexpected fallback diff start: %q", d[:80])
	}
	if got := bytes.Count(d, []byte("\n-old")); got != 3000 {
		t.Fatalf("%d deletions", got)
	}

	// Exactly at the bound: D = diffMaxD is still solved minimally.
	a, b = nil, nil
	for i := 0; i < diffMaxD/2; i++ {
		a = fmt.Appendf(a, "old %d\nsame %d\n", i, i)
		b = fmt.Appendf(b, "new %d\nsame %d\n", i, i)
	}
	d = checkDiff(t, a, b, 0)
	if got := bytes.Count(d, []byte("@@ -")); got != diffMaxD/2 {
		t.Fatalf("at the bound: %d hunks, want %d (minimal script)", got, diffMaxD/2)
	}
	// One beyond: fallback (a single hunk).
	a = fmt.Appendf(a, "old x\nsame x\n")
	b = fmt.Appendf(b, "new x\nsame x\n")
	d = checkDiff(t, a, b, 0)
	if got := bytes.Count(d, []byte("@@ -")); got != 1 {
		t.Fatalf("beyond the bound: %d hunks, want 1 (fallback)", got)
	}

	// Large similar files: work bound. 200k lines, a few edits.
	a, b = nil, nil
	for i := 0; i < 200000; i++ {
		a = fmt.Appendf(a, "%d\n", i)
		if i%50000 == 7 {
			b = fmt.Appendf(b, "changed %d\n", i)
		} else {
			b = fmt.Appendf(b, "%d\n", i)
		}
	}
	d = checkDiff(t, a, b, 3)
	if got := bytes.Count(d, []byte("@@ -")); got != 4 {
		t.Fatalf("large file: %d hunks", got)
	}
}

// Differential test: git apply accepts our hunks and produces b.
func TestUnifiedDiffGitApply(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cases := [][2]string{
		{"a\nb\nc\n", "a\nB\nc\n"},
		{"a\nb\nc", "a\nb\nc\n"},
		{"a\nb\nc\n", "a\nb\nc"},
		{"x", "y"},
		{"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n", "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n"},
		{"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n", "0\n1\n2\n3\n4\n5\n6\n8\n9\n10\n11\ntwelve\n"},
		{"a\r\nb\r\n", "a\r\nc\r\nb\n"},
		{"-- x\n++ y\n@@ -1 +1 @@\n", "-- x\n@@ -1 +1 @@\n\\ no\n"},
	}
	for i, c := range cases {
		for _, ctx := range []int{0, 1, 3} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "f"), []byte(c[0]), 0o644); err != nil {
				t.Fatal(err)
			}
			patch := append([]byte("--- a/f\n+++ b/f\n"), UnifiedDiff([]byte(c[0]), []byte(c[1]), ctx)...)
			cmd := exec.Command("git", "apply", "--unidiff-zero", "--whitespace=nowarn", "-")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
			cmd.Stdin = bytes.NewReader(patch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("case %d ctx %d: git apply: %v\n%s\npatch:\n%s", i, ctx, err, out, patch)
			}
			got, _ := os.ReadFile(filepath.Join(dir, "f"))
			if string(got) != c[1] {
				t.Fatalf("case %d ctx %d: git apply produced %q, want %q", i, ctx, got, c[1])
			}
		}
	}
}

func FuzzUnifiedDiff(f *testing.F) {
	f.Add([]byte(""), []byte(""), 3)
	f.Add([]byte("a\nb\nc\n"), []byte("a\nc\n"), 3)
	f.Add([]byte("a\nb\nc"), []byte("a\nb\nc\n"), 0)
	f.Add([]byte("a\r\nb"), []byte("b\r\na\n\n\n"), 1)
	f.Add([]byte("\n\n\n\n"), []byte("\n\n"), 2)
	f.Add([]byte("\\ No newline at end of file\n"), []byte("@@ -1,1 +1,1 @@\n-x"), 3)
	f.Add([]byte("\xff\x00\n\x00"), []byte("\x00\n\xff"), 3)
	f.Fuzz(func(t *testing.T, a, b []byte, context int) {
		if context > 10 || context < -1 {
			context %= 10
		}
		checkDiff(t, a, b, context)
	})
}
