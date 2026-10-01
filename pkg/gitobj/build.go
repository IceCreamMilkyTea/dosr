package gitobj

import (
	"fmt"
	"sort"
	"strings"
)

// File describes one blob of a tree to be written with WriteTree.
type File struct {
	Path string // slash-separated
	Mode uint32 // ModeFile, ModeExec or ModeSymlink
	Data []byte
}

// WriteTree stores the blobs and (nested) trees for files in s and returns
// the root tree ID. It is a helper for clients, tests and benchmarks; it
// is not used when validating. The order of files does not matter. An
// empty list yields the empty tree.
func WriteTree(s Store, files []File) (ID, error) {
	fs := append([]File(nil), files...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })
	for i, f := range fs {
		if f.Mode != ModeFile && f.Mode != ModeExec && f.Mode != ModeSymlink {
			return ZeroID, fmt.Errorf("%w: %q has mode %o", ErrUnsupported, f.Path, f.Mode)
		}
		if i > 0 && fs[i-1].Path == f.Path {
			return ZeroID, fmt.Errorf("%w: duplicate path %q", ErrMalformed, f.Path)
		}
		for _, part := range strings.Split(f.Path, "/") {
			if err := checkName(part); err != nil || strings.IndexByte(part, 0) >= 0 {
				return ZeroID, fmt.Errorf("%w: bad path %q", ErrMalformed, f.Path)
			}
		}
	}
	return writeTree(s, fs, 0)
}

// writeTree writes the tree of files, all of which share the first `skip`
// bytes of their path (the directory prefix including its trailing '/').
func writeTree(s Store, files []File, skip int) (ID, error) {
	var entries []TreeEntry
	for i := 0; i < len(files); {
		rest := files[i].Path[skip:]
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			id, err := s.Put(Object{Type: TypeBlob, Data: files[i].Data})
			if err != nil {
				return ZeroID, err
			}
			entries = append(entries, TreeEntry{Mode: files[i].Mode, Name: rest, ID: id})
			i++
			continue
		}
		dir := rest[:slash]
		prefix := files[i].Path[:skip+slash+1]
		j := i
		for j < len(files) && strings.HasPrefix(files[j].Path, prefix) {
			j++
		}
		id, err := writeTree(s, files[i:j], skip+slash+1)
		if err != nil {
			return ZeroID, err
		}
		entries = append(entries, TreeEntry{Mode: ModeDir, Name: dir, ID: id})
		i = j
	}
	SortEntries(entries)
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name == entries[i].Name {
			return ZeroID, fmt.Errorf("%w: %q is both a file and a directory", ErrMalformed, entries[i].Name)
		}
	}
	// A file "a" and a directory "a" need not be adjacent in tree order.
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if _, dup := seen[e.Name]; dup {
			return ZeroID, fmt.Errorf("%w: %q is both a file and a directory", ErrMalformed, e.Name)
		}
		seen[e.Name] = struct{}{}
	}
	return s.Put(Object{Type: TypeTree, Data: EncodeTree(entries)})
}

// EncodeCommit encodes a commit with the four standard headers. It is a
// helper for clients and tests; validators never re-encode commits.
func EncodeCommit(c *Commit) []byte {
	var b strings.Builder
	b.WriteString("tree " + c.Tree.String() + "\n")
	for _, p := range c.Parents {
		b.WriteString("parent " + p.String() + "\n")
	}
	b.WriteString("author " + c.Author + "\n")
	b.WriteString("committer " + c.Committer + "\n")
	b.WriteString("\n")
	b.WriteString(c.Message)
	return []byte(b.String())
}
