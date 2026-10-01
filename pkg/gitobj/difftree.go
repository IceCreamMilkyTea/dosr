package gitobj

import (
	"fmt"
	"sort"
)

// differ carries the state of one DiffTrees call.
type differ struct {
	s       Store
	lim     Limits
	out     []Change
	loads   int // tree objects loaded
	maxLoad int
	maxOut  int
}

// DiffTrees returns the blob-level changes between two trees, sorted by
// Path (bytewise). oldTree may be zero (everything is an addition); newTree
// may be zero as well (everything is a deletion). A path whose type changes
// between file and directory is reported as the corresponding deletions and
// additions; a change between regular file, executable and symlink at the
// same path is a single Change with both sides set. Mode-only changes are
// reported.
//
// Subtrees with equal IDs are skipped without being loaded, so the cost is
// proportional to the size of the change, not of the repository.
//
// Limits (all yield ErrLimit):
//   - directories nested deeper than lim.MaxTreeDepth and paths longer than
//     lim.MaxPathBytes;
//   - tree objects larger than lim.MaxObjectBytes;
//   - more than lim.MaxObjects changes, or more than 2*lim.MaxObjects tree
//     objects loaded. Limits has no dedicated field for these; without a
//     bound, a tiny bundle whose trees reference one large (or one empty)
//     subtree many times - a "tree bomb" - would make every validator
//     enumerate an exponential number of paths.
//
// Trees are parsed strictly; an ID that is referenced as a tree but stored
// as another type (or vice versa for blobs that are loaded later by the
// renderer) yields ErrMalformed. Blobs are not loaded by DiffTrees.
func DiffTrees(s Store, oldTree, newTree ID, lim Limits) ([]Change, error) {
	d := &differ{s: s, lim: lim, maxOut: lim.MaxObjects, maxLoad: 2 * lim.MaxObjects}
	if lim.MaxObjects > 0 && d.maxLoad < lim.MaxObjects { // overflow
		d.maxLoad = lim.MaxObjects
	}
	if err := d.diff(oldTree, newTree, "", 0); err != nil {
		return nil, err
	}
	// Tree-order traversal already yields bytewise path order in almost
	// all cases; sorting makes the contract unconditional. Paths are
	// unique, so the order is total and the sort deterministic.
	sort.Slice(d.out, func(i, j int) bool { return d.out[i].Path < d.out[j].Path })
	return d.out, nil
}

func (d *differ) load(id ID, depth int) ([]TreeEntry, error) {
	if id.IsZero() {
		return nil, nil
	}
	if depth > d.lim.MaxTreeDepth {
		return nil, fmt.Errorf("%w: tree nesting deeper than %d", ErrLimit, d.lim.MaxTreeDepth)
	}
	d.loads++
	if d.loads > d.maxLoad {
		return nil, fmt.Errorf("%w: diff loads more than %d trees", ErrLimit, d.maxLoad)
	}
	o, err := d.s.Get(id)
	if err != nil {
		return nil, fmt.Errorf("tree %s: %w", id, err)
	}
	if o.Type != TypeTree {
		return nil, fmt.Errorf("%w: %s is a %s but referenced as a tree", ErrMalformed, id, o.Type)
	}
	if len(o.Data) > d.lim.MaxObjectBytes {
		return nil, fmt.Errorf("%w: tree %s is %d bytes, limit %d", ErrLimit, id, len(o.Data), d.lim.MaxObjectBytes)
	}
	entries, err := ParseTree(o.Data)
	if err != nil {
		return nil, fmt.Errorf("tree %s: %w", id, err)
	}
	return entries, nil
}

func (d *differ) emit(c Change) error {
	if len(d.out) >= d.maxOut {
		return fmt.Errorf("%w: more than %d changes", ErrLimit, d.maxOut)
	}
	d.out = append(d.out, c)
	return nil
}

func (d *differ) join(prefix, name string) (string, error) {
	n := len(prefix) + len(name)
	if prefix != "" {
		n++
	}
	if n > d.lim.MaxPathBytes {
		return "", fmt.Errorf("%w: path longer than %d bytes", ErrLimit, d.lim.MaxPathBytes)
	}
	if prefix == "" {
		return name, nil
	}
	return prefix + "/" + name, nil
}

// diff compares the trees oldID and newID (either may be zero = absent)
// located at path prefix / directory depth depth.
func (d *differ) diff(oldID, newID ID, prefix string, depth int) error {
	if oldID == newID {
		return nil
	}
	olds, err := d.load(oldID, depth)
	if err != nil {
		return err
	}
	news, err := d.load(newID, depth)
	if err != nil {
		return err
	}
	// Merge by NAME (plain bytewise), not by tree order: a file "a" and
	// a directory "a" are the same path and must meet in one step.
	// Within one tree names are unique, so sorting by name is total.
	sort.Slice(olds, func(i, j int) bool { return olds[i].Name < olds[j].Name })
	sort.Slice(news, func(i, j int) bool { return news[i].Name < news[j].Name })
	i, j := 0, 0
	for i < len(olds) || j < len(news) {
		var o, n *TreeEntry
		switch {
		case j >= len(news) || (i < len(olds) && olds[i].Name < news[j].Name):
			o = &olds[i]
			i++
		case i >= len(olds) || news[j].Name < olds[i].Name:
			n = &news[j]
			j++
		default:
			o, n = &olds[i], &news[j]
			i++
			j++
		}
		if err := d.entry(o, n, prefix, depth); err != nil {
			return err
		}
	}
	return nil
}

// entry handles one name; o and/or n is non-nil.
func (d *differ) entry(o, n *TreeEntry, prefix string, depth int) error {
	name := ""
	if o != nil {
		name = o.Name
	} else {
		name = n.Name
	}
	path, err := d.join(prefix, name)
	if err != nil {
		return err
	}
	oDir := o != nil && o.Mode == ModeDir
	nDir := n != nil && n.Mode == ModeDir

	if o != nil && n != nil && o.Mode == n.Mode && o.ID == n.ID {
		return nil
	}
	// Blob side(s). When both sides are blobs this is one modification;
	// when the type changed, the blob side is an addition or deletion.
	var c Change
	c.Path = path
	blob := false
	if o != nil && !oDir {
		c.OldMode, c.OldID = o.Mode, o.ID
		blob = true
	}
	if n != nil && !nDir {
		c.NewMode, c.NewID = n.Mode, n.ID
		blob = true
	}
	if blob {
		if err := d.emit(c); err != nil {
			return err
		}
	}
	// Directory side(s).
	if oDir || nDir {
		var oid, nid ID
		if oDir {
			oid = o.ID
		}
		if nDir {
			nid = n.ID
		}
		return d.diff(oid, nid, path, depth+1)
	}
	return nil
}
