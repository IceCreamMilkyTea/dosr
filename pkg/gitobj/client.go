package gitobj

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Client-side helpers. They shell out to the git CLI and are NOT used by
// validators.

// maxClientObjectBytes bounds a single object ExtractBundle will read; it
// protects the client from a surprising repository, the validators enforce
// their own (smaller) limits.
const maxClientObjectBytes = 1 << 30

func gitCmd(repoDir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	// Stable, parseable output regardless of the user's locale.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "GIT_TERMINAL_PROMPT=0")
	return cmd
}

func runGit(repoDir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := gitCmd(repoDir, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitobj: git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// ResolveRef runs `git rev-parse --verify <ref>^{commit}`.
func ResolveRef(repoDir, ref string) (ID, error) {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\n") {
		// A ref starting with '-' would be parsed by git as an option.
		return ZeroID, fmt.Errorf("gitobj: invalid ref %q", ref)
	}
	out, err := runGit(repoDir, nil, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return ZeroID, err
	}
	return ParseID(strings.TrimSpace(string(out)))
}

// ExtractBundle builds the bundle for candidate on top of base from a
// local Git repository using
//
//	git rev-list --objects --no-object-names candidate ^base
//	git cat-file --batch
//
// base may be zero (first commit of a branch). The returned bundle is in
// canonical (ascending ID) order. ExtractBundle does not judge the result:
// if candidate is not a direct child of base the bundle contains several
// commits and validators will reject it (VerifyClosure).
func ExtractBundle(repoDir string, base, candidate ID) (*Bundle, error) {
	if candidate.IsZero() {
		return nil, errors.New("gitobj: extract bundle: zero candidate")
	}
	args := []string{"rev-list", "--objects", "--no-object-names", candidate.String()}
	if !base.IsZero() {
		args = append(args, "^"+base.String())
	}
	list, err := runGit(repoDir, nil, args...)
	if err != nil {
		return nil, err
	}
	var ids []ID
	for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		if line == "" {
			continue
		}
		id, err := ParseID(line)
		if err != nil {
			return nil, fmt.Errorf("gitobj: extract bundle: unexpected rev-list output %q (SHA-256 repositories are not supported): %w", line, err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("gitobj: extract bundle: candidate adds no objects on top of base")
	}

	var in bytes.Buffer
	for _, id := range ids {
		in.WriteString(id.String())
		in.WriteByte('\n')
	}
	out, err := runGit(repoDir, in.Bytes(), "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(bytes.NewReader(out))
	b := &Bundle{Objects: make([]Object, 0, len(ids))}
	for _, id := range ids {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("gitobj: extract bundle: truncated cat-file output for %s", id)
		}
		f := strings.Fields(hdr)
		if len(f) != 3 || f[0] != id.String() {
			return nil, fmt.Errorf("gitobj: extract bundle: unexpected cat-file header %q", strings.TrimSpace(hdr))
		}
		var t ObjType
		switch f[1] {
		case "commit":
			t = TypeCommit
		case "tree":
			t = TypeTree
		case "blob":
			t = TypeBlob
		default:
			return nil, fmt.Errorf("%w: object %s has type %s", ErrUnsupported, id, f[1])
		}
		n, err := strconv.ParseUint(f[2], 10, 63)
		if err != nil || n > maxClientObjectBytes {
			return nil, fmt.Errorf("gitobj: extract bundle: bad size in cat-file header %q", strings.TrimSpace(hdr))
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("gitobj: extract bundle: truncated content of %s", id)
		}
		if c, err := r.ReadByte(); err != nil || c != '\n' {
			return nil, fmt.Errorf("gitobj: extract bundle: missing terminator after %s", id)
		}
		o := Object{Type: t, Data: data}
		if o.ID() != id {
			return nil, fmt.Errorf("gitobj: extract bundle: object %s does not hash to its id", id)
		}
		b.Objects = append(b.Objects, o)
	}
	sortObjects(b.Objects)
	return b, nil
}
