package gitobj

import (
	"bytes"
	"fmt"
)

// maxParents bounds the number of parent lines ParseCommit accepts. Git has
// no limit, but octopus merges beyond a handful of parents do not occur in
// practice and DOSR itself only ever accepts 0 or 1 (see VerifyClosure).
const maxParents = 64

// ParseCommit strictly parses a commit object.
//
// Layout accepted (every line terminated by exactly one '\n'):
//
//	tree <40 lowercase hex>
//	parent <40 lowercase hex>        (zero or more, no duplicates)
//	author <name> <<email>> <unix seconds> <+hhmm|-hhmm>
//	committer <same syntax>
//	<key> <value>                    (zero or more extra headers; value
//	 <continuation>                   may continue on lines starting
//	                                  with a space, as gpgsig does)
//	<empty line>
//	<message, arbitrary bytes>
//
// Why so strict: a lenient parser and stock Git could disagree about what
// a commit's tree or parents are (for instance, if a second "tree" line or
// a "parent" line after "author" were tolerated, or if a header value could
// smuggle a newline). The reviewed tree and the tree Git later checks out
// must be the same, so everything Git would interpret differently, or that
// git fsck reports as an error, is rejected. The header section must not
// contain NUL and must be terminated by an empty line.
func ParseCommit(data []byte) (*Commit, error) {
	c := &Commit{}
	pos := 0

	// nextLine returns the next header line without its '\n'.
	nextLine := func() ([]byte, error) {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			return nil, fmt.Errorf("%w: commit: unterminated header line", ErrMalformed)
		}
		line := data[pos : pos+i]
		pos += i + 1
		if bytes.IndexByte(line, 0) >= 0 {
			return nil, fmt.Errorf("%w: commit: NUL in header", ErrMalformed)
		}
		return line, nil
	}

	line, err := nextLine()
	if err != nil {
		return nil, err
	}
	rest, ok := cutPrefix(line, "tree ")
	if !ok {
		return nil, fmt.Errorf("%w: commit: first line is not a tree header", ErrMalformed)
	}
	if c.Tree, err = parseHeaderID(rest); err != nil {
		return nil, fmt.Errorf("%w: commit: tree: %s", ErrMalformed, err)
	}

	if line, err = nextLine(); err != nil {
		return nil, err
	}
	for {
		rest, ok = cutPrefix(line, "parent ")
		if !ok {
			break
		}
		if len(c.Parents) >= maxParents {
			return nil, fmt.Errorf("%w: commit: more than %d parents", ErrLimit, maxParents)
		}
		id, err := parseHeaderID(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: commit: parent: %s", ErrMalformed, err)
		}
		for _, p := range c.Parents {
			if p == id {
				return nil, fmt.Errorf("%w: commit: duplicate parent", ErrMalformed)
			}
		}
		c.Parents = append(c.Parents, id)
		if line, err = nextLine(); err != nil {
			return nil, err
		}
	}

	rest, ok = cutPrefix(line, "author ")
	if !ok {
		return nil, fmt.Errorf("%w: commit: expected author header", ErrMalformed)
	}
	if err := checkIdent(rest); err != nil {
		return nil, fmt.Errorf("%w: commit: author: %s", ErrMalformed, err)
	}
	c.Author = string(rest)

	if line, err = nextLine(); err != nil {
		return nil, err
	}
	rest, ok = cutPrefix(line, "committer ")
	if !ok {
		return nil, fmt.Errorf("%w: commit: expected committer header", ErrMalformed)
	}
	if err := checkIdent(rest); err != nil {
		return nil, fmt.Errorf("%w: commit: committer: %s", ErrMalformed, err)
	}
	c.Committer = string(rest)

	// Extra headers until the empty line.
	first := true
	for {
		if line, err = nextLine(); err != nil {
			return nil, err
		}
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' {
			// Continuation of the previous extra header. author and
			// committer are single-line, so a continuation directly
			// after committer is malformed.
			if first {
				return nil, fmt.Errorf("%w: commit: continuation line without header", ErrMalformed)
			}
			continue
		}
		first = false
		sp := bytes.IndexByte(line, ' ')
		if sp <= 0 {
			return nil, fmt.Errorf("%w: commit: header line without key or value", ErrMalformed)
		}
		key := line[:sp]
		for _, ch := range key {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return nil, fmt.Errorf("%w: commit: bad header key", ErrMalformed)
			}
		}
		switch string(key) {
		case "tree", "parent", "author", "committer":
			// These are the headers Git interprets positionally. A
			// repeated or late occurrence is exactly the "header
			// injection" ambiguity we must exclude.
			return nil, fmt.Errorf("%w: commit: misplaced or repeated %s header", ErrMalformed, key)
		}
	}
	c.Message = string(data[pos:])
	return c, nil
}

func cutPrefix(line []byte, prefix string) ([]byte, bool) {
	if len(line) >= len(prefix) && string(line[:len(prefix)]) == prefix {
		return line[len(prefix):], true
	}
	return nil, false
}

func parseHeaderID(b []byte) (ID, error) {
	id, err := ParseID(string(b))
	if err != nil {
		return id, err
	}
	if id.IsZero() {
		return id, fmt.Errorf("null id")
	}
	return id, nil
}

// checkIdent validates "name <email> seconds tz" the way git fsck does:
// the name contains no '<' or '>', is followed by " <", the email contains
// no '<' or '>', is followed by "> ", the timestamp is decimal digits
// without leading zero (unless it is "0") and fits in 63 bits, and the
// zone is a sign followed by four digits.
func checkIdent(b []byte) error {
	i := 0
	for i < len(b) && b[i] != '<' && b[i] != '>' {
		i++
	}
	if i >= len(b) || b[i] != '<' {
		return fmt.Errorf("missing email")
	}
	if i == 0 {
		return fmt.Errorf("missing name before email")
	}
	if b[i-1] != ' ' {
		return fmt.Errorf("missing space before email")
	}
	i++
	for i < len(b) && b[i] != '<' && b[i] != '>' {
		i++
	}
	if i >= len(b) || b[i] != '>' {
		return fmt.Errorf("bad email")
	}
	i++
	if i >= len(b) || b[i] != ' ' {
		return fmt.Errorf("missing space before date")
	}
	i++
	start := i
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	digits := b[start:i]
	if len(digits) == 0 || len(digits) > 18 || (len(digits) > 1 && digits[0] == '0') {
		return fmt.Errorf("bad date")
	}
	if i >= len(b) || b[i] != ' ' {
		return fmt.Errorf("missing space before time zone")
	}
	i++
	if len(b)-i != 5 || (b[i] != '+' && b[i] != '-') {
		return fmt.Errorf("bad time zone")
	}
	for _, ch := range b[i+1:] {
		if ch < '0' || ch > '9' {
			return fmt.Errorf("bad time zone")
		}
	}
	return nil
}
