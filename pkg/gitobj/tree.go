package gitobj

import (
	"fmt"
	"strconv"
	"unicode/utf8"
)

// minTreeEntryBytes is the size of the smallest possible tree entry:
// "40000" SP one-byte-name NUL 20-byte-id.
const minTreeEntryBytes = 5 + 1 + 1 + 1 + 20

// ParseTree strictly parses a tree object.
//
// The parser accepts exactly the byte strings that EncodeTree can produce
// from a valid, canonically sorted entry list. This matters because DOSR
// never re-encodes objects: the ID is always the hash of the original bytes,
// so any leniency here (zero-padded modes, unsorted entries, ...) would let
// two different byte strings - with two different IDs - denote "the same"
// tree, or would admit trees that stock Git refuses to check out.
//
// Rejected with ErrUnsupported: syntactically valid modes that DOSR does
// not accept (gitlinks 160000, group-writable 100664, ...).
// Rejected with ErrMalformed: everything else (truncation, bad mode syntax,
// empty or dangerous names, duplicates, wrong order).
func ParseTree(data []byte) ([]TreeEntry, error) {
	// Capacity is bounded by the input length, so a hostile length can
	// never make us allocate more than ~1/28 entries per input byte.
	entries := make([]TreeEntry, 0, len(data)/minTreeEntryBytes)
	var seen map[string]struct{}
	pos := 0
	for pos < len(data) {
		// Mode: 5 or 6 octal digits, no leading zero, followed by SP.
		start := pos
		for pos < len(data) && pos-start < 7 && data[pos] != ' ' {
			c := data[pos]
			if c < '0' || c > '7' {
				return nil, fmt.Errorf("%w: tree entry %d: bad mode character", ErrMalformed, len(entries))
			}
			pos++
		}
		if pos >= len(data) || data[pos] != ' ' {
			return nil, fmt.Errorf("%w: tree entry %d: unterminated mode", ErrMalformed, len(entries))
		}
		modeStr := data[start:pos]
		if len(modeStr) == 0 || modeStr[0] == '0' {
			// Git writes modes without leading zeros ("40000"). Old
			// tools wrote "040000"; accepting both would make the
			// encoding non-canonical.
			return nil, fmt.Errorf("%w: tree entry %d: empty or zero-padded mode", ErrMalformed, len(entries))
		}
		var mode uint32
		for _, c := range modeStr {
			mode = mode<<3 | uint32(c-'0')
		}
		switch mode {
		case ModeDir, ModeFile, ModeExec, ModeSymlink:
		default:
			return nil, fmt.Errorf("%w: tree entry %d: mode %o", ErrUnsupported, len(entries), mode)
		}
		pos++ // SP

		// Name: up to the next NUL.
		start = pos
		for pos < len(data) && data[pos] != 0 {
			pos++
		}
		if pos >= len(data) {
			return nil, fmt.Errorf("%w: tree entry %d: unterminated name", ErrMalformed, len(entries))
		}
		name := string(data[start:pos])
		pos++ // NUL
		if err := checkName(name); err != nil {
			return nil, fmt.Errorf("%w: tree entry %d: %s", ErrMalformed, len(entries), err)
		}

		if len(data)-pos < len(ID{}) {
			return nil, fmt.Errorf("%w: tree entry %d: truncated id", ErrMalformed, len(entries))
		}
		var id ID
		copy(id[:], data[pos:])
		pos += len(id)
		if id.IsZero() {
			// The all-zero ID means "no object" throughout DOSR (and
			// git fsck reports nullSha1); an entry can never name it.
			return nil, fmt.Errorf("%w: tree entry %d: null id", ErrMalformed, len(entries))
		}

		e := TreeEntry{Mode: mode, Name: name, ID: id}
		if n := len(entries); n > 0 {
			prev := entries[n-1]
			if compareEntries(prev, e) >= 0 {
				return nil, fmt.Errorf("%w: tree entry %d: not in canonical order", ErrMalformed, n)
			}
			// Canonical order alone does not exclude duplicates: the
			// file "a" and the directory "a" sort as "a" and "a/" and
			// may be separated by e.g. "a-b". A set is therefore
			// needed. It is only ever used for membership tests, never
			// iterated, so it cannot introduce non-determinism. It is
			// built lazily: the common single pass needs it only when
			// a file/dir pair could collide, but detecting that is as
			// expensive as the set itself, so we just build it.
			if seen == nil {
				seen = make(map[string]struct{}, cap(entries))
				seen[entries[0].Name] = struct{}{}
			}
			if _, dup := seen[name]; dup {
				return nil, fmt.Errorf("%w: tree entry %d: duplicate name", ErrMalformed, n)
			}
			seen[name] = struct{}{}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// EncodeTree encodes entries, which must already be valid and in canonical
// order. ParseTree(EncodeTree(x)) == x for every x ParseTree can return.
func EncodeTree(entries []TreeEntry) []byte {
	n := 0
	for _, e := range entries {
		n += 6 + 1 + len(e.Name) + 1 + len(e.ID)
	}
	out := make([]byte, 0, n)
	for _, e := range entries {
		out = strconv.AppendUint(out, uint64(e.Mode), 8)
		out = append(out, ' ')
		out = append(out, e.Name...)
		out = append(out, 0)
		out = append(out, e.ID[:]...)
	}
	return out
}

// SortEntries sorts entries in place into Git's canonical tree order. It is
// a convenience for code that builds trees (tests, clients).
func SortEntries(entries []TreeEntry) {
	// Insertion sort would be quadratic; use a simple deterministic
	// merge-free approach via the standard library.
	sortEntries(entries)
}

// compareEntries implements Git's tree order (base_name_compare): names are
// compared bytewise, and a directory compares as if its name had a trailing
// '/'. Thus "a.c" < "a" (dir, compared as "a/") < "a0".
func compareEntries(a, b TreeEntry) int {
	an, bn := a.Name, b.Name
	n := len(an)
	if len(bn) < n {
		n = len(bn)
	}
	for i := 0; i < n; i++ {
		if an[i] != bn[i] {
			if an[i] < bn[i] {
				return -1
			}
			return 1
		}
	}
	// One name is a prefix of the other (or they are equal): compare the
	// byte following the common prefix, substituting '/' after the end of
	// a directory name and NUL after the end of a file name.
	ac, bc := tail(a, n), tail(b, n)
	switch {
	case ac < bc:
		return -1
	case ac > bc:
		return 1
	}
	return 0
}

func tail(e TreeEntry, n int) byte {
	if n < len(e.Name) {
		return e.Name[n]
	}
	if e.Mode == ModeDir {
		return '/'
	}
	return 0
}

// checkName rejects names that are unrepresentable or dangerous in a work
// tree. NUL cannot occur (it terminates the name in the encoding).
func checkName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			return fmt.Errorf("name contains '/'")
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("name %q", name)
	}
	if isDotGit(name) {
		return fmt.Errorf("name is or aliases .git")
	}
	return nil
}

// isDotGit reports whether name is ".git" or a name that some file system
// would map to ".git". A tree containing such an entry lets a commit plant
// files (hooks, config) inside the repository metadata of whoever checks it
// out (CVE-2014-9390 and successors), so stock Git refuses them; we must
// refuse at least as much because reviewers and the LLM only see a diff.
//
// Covered: ASCII case folding (".GIT"), the NTFS 8.3 short name "git~1",
// trailing dots/spaces and alternate data streams which NTFS strips
// (".git.", ".git ", ".git::$INDEX_ALLOCATION"), and the code points HFS+
// ignores when comparing names (".g‌it").
func isDotGit(name string) bool {
	s := stripHFSIgnorable(name)
	if foldEq(s, ".git") {
		return true
	}
	for _, p := range [...]string{".git", "git~1"} {
		if len(name) >= len(p) && foldEq(name[:len(p)], p) {
			rest := name[len(p):]
			if i := indexByte(rest, ':'); i >= 0 {
				rest = rest[:i]
			}
			ok := true
			for j := 0; j < len(rest); j++ {
				if rest[j] != ' ' && rest[j] != '.' {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// foldEq compares a with the lowercase ASCII string b, ignoring ASCII case.
func foldEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != b[i] {
			return false
		}
	}
	return true
}

// stripHFSIgnorable removes the code points that HFS+ ignores in file name
// comparisons (the list used by Git's is_hfs_dotgit).
func stripHFSIgnorable(name string) string {
	ascii := true
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return name
	}
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		ignorable := false
		if !(r == utf8.RuneError && size == 1) {
			switch {
			case r >= 0x200c && r <= 0x200f,
				r >= 0x202a && r <= 0x202e,
				r >= 0x206a && r <= 0x206f,
				r == 0xfeff:
				ignorable = true
			}
		}
		if !ignorable {
			out = append(out, name[i:i+size]...)
		}
		i += size
	}
	return string(out)
}
