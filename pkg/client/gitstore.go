package client

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/dosr/dosr/pkg/gitobj"
)

// GitStore is a read-only gitobj.Store view of a local Git repository,
// implemented with `git cat-file --batch`. It is what a contributor uses
// as Change.Objects.
type GitStore struct {
	Dir string

	mu    sync.Mutex
	cache map[gitobj.ID]gitobj.Object
}

// NewGitStore returns a store for the repository at dir.
func NewGitStore(dir string) *GitStore {
	return &GitStore{Dir: dir, cache: map[gitobj.ID]gitobj.Object{}}
}

func (g *GitStore) Has(id gitobj.ID) bool {
	_, err := g.Get(id)
	return err == nil
}

func (g *GitStore) Get(id gitobj.ID) (gitobj.Object, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if o, ok := g.cache[id]; ok {
		return o, nil
	}
	cmd := exec.Command("git", "-C", g.Dir, "cat-file", "--batch")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(id.String() + "\n")
	out, err := cmd.Output()
	if err != nil {
		return gitobj.Object{}, fmt.Errorf("client: git cat-file: %w", err)
	}
	nl := bytes.IndexByte(out, '\n')
	if nl < 0 {
		return gitobj.Object{}, fmt.Errorf("client: git cat-file: unexpected output")
	}
	f := strings.Fields(string(out[:nl]))
	if len(f) == 2 && f[1] == "missing" {
		return gitobj.Object{}, fmt.Errorf("%w: %s", gitobj.ErrNotFound, id)
	}
	if len(f) != 3 {
		return gitobj.Object{}, fmt.Errorf("client: git cat-file: unexpected header %q", out[:nl])
	}
	var t gitobj.ObjType
	switch f[1] {
	case "commit":
		t = gitobj.TypeCommit
	case "tree":
		t = gitobj.TypeTree
	case "blob":
		t = gitobj.TypeBlob
	default:
		return gitobj.Object{}, fmt.Errorf("%w: %s is a %s", gitobj.ErrUnsupported, id, f[1])
	}
	n, err := strconv.Atoi(f[2])
	if err != nil || nl+1+n > len(out) {
		return gitobj.Object{}, fmt.Errorf("client: git cat-file: bad size")
	}
	o := gitobj.Object{Type: t, Data: append([]byte(nil), out[nl+1:nl+1+n]...)}
	if o.ID() != id {
		return gitobj.Object{}, fmt.Errorf("client: object %s does not hash to its id", id)
	}
	g.cache[id] = o
	return o, nil
}

// Put is not supported.
func (g *GitStore) Put(gitobj.Object) (gitobj.ID, error) {
	return gitobj.ZeroID, fmt.Errorf("client: GitStore is read-only")
}
