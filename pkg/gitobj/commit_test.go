package gitobj

import (
	"errors"
	"strings"
	"testing"
)

func errorsIs(err, target error) bool { return errors.Is(err, target) }

func TestParseCommitAccepts(t *testing.T) {
	tree := strings.Repeat("a", 40)
	p1 := strings.Repeat("b", 40)
	p2 := strings.Repeat("c", 40)
	hdr := "author " + testIdent + "\ncommitter " + testIdent + "\n"

	c, err := ParseCommit([]byte("tree " + tree + "\n" + hdr + "\nhello\n\nbody\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tree.String() != tree || len(c.Parents) != 0 || c.Author != testIdent || c.Committer != testIdent || c.Message != "hello\n\nbody\n" {
		t.Fatalf("bad parse: %+v", c)
	}

	c, err = ParseCommit([]byte("tree " + tree + "\nparent " + p1 + "\nparent " + p2 + "\n" + hdr +
		"encoding ISO-8859-1\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n\nmsg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Parents) != 2 || c.Parents[0].String() != p1 || c.Parents[1].String() != p2 || c.Message != "msg" {
		t.Fatalf("bad parse: %+v", c)
	}

	// Empty message; message with a fake header and NUL.
	if c, err = ParseCommit([]byte("tree " + tree + "\n" + hdr + "\n")); err != nil || c.Message != "" {
		t.Fatal(err)
	}
	if c, err = ParseCommit([]byte("tree " + tree + "\n" + hdr + "\nparent " + p1 + "\n\x00")); err != nil || len(c.Parents) != 0 {
		t.Fatal("a parent line inside the message must not be interpreted", err)
	}
	// Round trip through EncodeCommit.
	c2, err := ParseCommit(EncodeCommit(c))
	if err != nil || c2.Message != c.Message || c2.Tree != c.Tree {
		t.Fatal("EncodeCommit round trip")
	}
}

func TestParseCommitRejects(t *testing.T) {
	tree := "tree " + strings.Repeat("a", 40) + "\n"
	parent := "parent " + strings.Repeat("b", 40) + "\n"
	au := "author " + testIdent + "\n"
	co := "committer " + testIdent + "\n"
	cases := map[string]string{
		"empty":                     "",
		"no tree":                   au + co + "\n",
		"tree not first":            parent + tree + au + co + "\n",
		"two trees":                 tree + tree + au + co + "\n",
		"short tree id":             "tree abc\n" + au + co + "\n",
		"uppercase tree id":         "tree " + strings.Repeat("A", 40) + "\n" + au + co + "\n",
		"null tree id":              "tree " + strings.Repeat("0", 40) + "\n" + au + co + "\n",
		"tree trailing space":       "tree " + strings.Repeat("a", 40) + " \n" + au + co + "\n",
		"tree double space":         "tree  " + strings.Repeat("a", 39) + "\n" + au + co + "\n",
		"crlf":                      "tree " + strings.Repeat("a", 40) + "\r\n" + au + co + "\n",
		"bad parent":                tree + "parent xyz\n" + au + co + "\n",
		"null parent":               tree + "parent " + strings.Repeat("0", 40) + "\n" + au + co + "\n",
		"duplicate parent":          tree + parent + parent + au + co + "\n",
		"parent after author":       tree + au + parent + co + "\n",
		"parent after committer":    tree + au + co + parent + "\n",
		"late tree":                 tree + au + co + tree + "\n",
		"second author":             tree + au + co + au + "\n",
		"second committer":          tree + au + co + co + "\n",
		"missing author":            tree + co + "\n",
		"missing committer":         tree + au + "\n",
		"committer before author":   tree + co + au + "\n",
		"no blank line":             tree + au + co,
		"no blank line, extra":      tree + au + co + "encoding x",
		"unterminated header":       tree + au + "committer " + testIdent,
		"nul in header":             tree + au + co + "x-note a\x00b\n\n",
		"nul in author":             tree + "author A\x00 <a@b> 1 +0000\n" + co + "\n",
		"header without value":      tree + au + co + "encoding\n\n",
		"header with empty key":     tree + au + co + ":x y\n\n",
		"continuation after commit": tree + au + co + " continued\n\n",
		"author no email":           tree + "author Alice 1 +0000\n" + co + "\n",
		"author no name":            tree + "author <a@b> 1 +0000\n" + co + "\n",
		"author no space":           tree + "author Alice<a@b> 1 +0000\n" + co + "\n",
		"author nested <":           tree + "author A <a<b> 1 +0000\n" + co + "\n",
		"author stray >":            tree + "author A> <a@b> 1 +0000\n" + co + "\n",
		"author no date":            tree + "author A <a@b>\n" + co + "\n",
		"author bad date":           tree + "author A <a@b> 12x +0000\n" + co + "\n",
		"author zero padded date":   tree + "author A <a@b> 012 +0000\n" + co + "\n",
		"author date overflow":      tree + "author A <a@b> 99999999999999999999 +0000\n" + co + "\n",
		"author no tz":              tree + "author A <a@b> 12\n" + co + "\n",
		"author bad tz":             tree + "author A <a@b> 12 0000\n" + co + "\n",
		"author long tz":            tree + "author A <a@b> 12 +00000\n" + co + "\n",
		"author trailing":           tree + "author A <a@b> 12 +0000 x\n" + co + "\n",
	}
	for name, data := range cases {
		if _, err := ParseCommit([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error %v does not wrap ErrMalformed", name, err)
		}
	}
	// Parent bomb.
	var b strings.Builder
	b.WriteString(tree)
	for i := 0; i < maxParents+1; i++ {
		b.WriteString("parent " + blob(string(rune('a'+i%26))+strings.Repeat("x", i)).ID().String() + "\n")
	}
	b.WriteString(au + co + "\n")
	if _, err := ParseCommit([]byte(b.String())); !errors.Is(err, ErrLimit) {
		t.Errorf("parent bomb: %v", err)
	}
}
