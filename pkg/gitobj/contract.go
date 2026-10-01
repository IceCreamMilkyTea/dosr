// Package gitobj is DOSR's validator-side Git object model.
//
// It is a deliberately small, pure-Go, strictly-validating implementation of
// the subset of Git's object format that DOSR needs: blobs, trees and commits
// addressed by Git's SHA-1 object IDs. Everything in this package that runs
// on validators MUST be deterministic: the same inputs must produce the same
// outputs (and the same errors) on every node, because results feed the
// replicated state machine.
//
// This file is the package CONTRACT. Types and signatures here are frozen;
// other packages (review, app) are written against them.
package gitobj

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ID is a Git SHA-1 object ID.
type ID [20]byte

// ZeroID is the all-zero ID. It denotes "no object" (e.g. the expected head
// of an empty branch, or the old side of an added file).
var ZeroID ID

func (id ID) String() string { return hex.EncodeToString(id[:]) }
func (id ID) IsZero() bool   { return id == ZeroID }

// MarshalText/UnmarshalText make ID encode as lowercase hex in JSON.
func (id ID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id *ID) UnmarshalText(b []byte) error {
	p, err := ParseID(string(b))
	if err != nil {
		return err
	}
	*id = p
	return nil
}

// ParseID parses exactly 40 lowercase hex characters.
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 40 {
		return id, fmt.Errorf("gitobj: bad id length %d", len(s))
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return id, errors.New("gitobj: id must be lowercase hex")
		}
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, err
	}
	return id, nil
}

// ObjType is a Git object type. Tags are intentionally unsupported.
type ObjType uint8

const (
	TypeCommit ObjType = 1
	TypeTree   ObjType = 2
	TypeBlob   ObjType = 3
)

func (t ObjType) String() string {
	switch t {
	case TypeCommit:
		return "commit"
	case TypeTree:
		return "tree"
	case TypeBlob:
		return "blob"
	}
	return "invalid"
}

// Object is a Git object: its type and its raw content (WITHOUT the
// "<type> <len>\x00" header Git prepends before hashing).
type Object struct {
	Type ObjType
	Data []byte
}

// File modes DOSR accepts inside trees. Anything else (notably 0160000
// gitlinks/submodules) is rejected by ParseTree.
const (
	ModeDir     uint32 = 0o040000
	ModeFile    uint32 = 0o100644
	ModeExec    uint32 = 0o100755
	ModeSymlink uint32 = 0o120000
)

// TreeEntry is one entry of a tree object.
type TreeEntry struct {
	Mode uint32
	Name string
	ID   ID
}

// Commit is a parsed commit object. Only Tree and Parents are interpreted by
// DOSR; the remaining header lines and the message are preserved verbatim.
type Commit struct {
	Tree      ID
	Parents   []ID
	Author    string // raw value of the "author" header line
	Committer string // raw value of the "committer" header line
	Message   string // everything after the first blank line
}

// Store is a content-addressed object store.
//
// INVARIANT (closure): validators only ever Put objects through
// ApplyBundle after VerifyClosure succeeded, so if a commit or tree is
// present in a validator's Store then everything reachable from it is
// present too. VerifyClosure relies on this to avoid re-walking the base.
type Store interface {
	Has(id ID) bool
	// Get returns ErrNotFound if the object is absent.
	Get(id ID) (Object, error)
	// Put stores the object and returns its ID. Idempotent.
	Put(o Object) (ID, error)
}

// Change is one blob-level difference between two trees.
// Added files have a zero OldID/OldMode, deleted files a zero NewID/NewMode.
type Change struct {
	Path    string // slash-separated, relative to the repository root
	OldMode uint32
	NewMode uint32
	OldID   ID
	NewID   ID
}

// Limits bounds the resources a bundle may consume. All limits are enforced
// deterministically and before any large allocation.
type Limits struct {
	MaxBundleBytes int // encoded bundle size
	MaxObjects     int // number of objects in a bundle
	MaxObjectBytes int // size of any single object
	MaxTreeDepth   int // directory nesting
	MaxPathBytes   int // length of any full path
}

// DefaultLimits are the limits used when a policy does not override them.
var DefaultLimits = Limits{
	MaxBundleBytes: 4 << 20,
	MaxObjects:     20000,
	MaxObjectBytes: 1 << 20,
	MaxTreeDepth:   64,
	MaxPathBytes:   4096,
}

// Digest is a SHA-256 digest (used for bundles; Git object IDs stay SHA-1
// for compatibility with stock Git tooling).
type Digest [32]byte

func (d Digest) String() string { return hex.EncodeToString(d[:]) }
func (d Digest) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}
func (d *Digest) UnmarshalText(b []byte) error {
	if len(b) != 64 {
		return fmt.Errorf("gitobj: bad digest length %d", len(b))
	}
	_, err := hex.Decode(d[:], b)
	return err
}

// SumDigest returns the SHA-256 digest of b.
func SumDigest(b []byte) Digest { return sha256.Sum256(b) }

// Sentinel errors. Implementations wrap these with %w so callers can use
// errors.Is; the app maps them to transaction result codes.
var (
	ErrNotFound     = errors.New("gitobj: object not found")
	ErrMalformed    = errors.New("gitobj: malformed object")
	ErrNonCanonical = errors.New("gitobj: non-canonical bundle encoding")
	ErrLimit        = errors.New("gitobj: limit exceeded")
	ErrParent       = errors.New("gitobj: commit parent mismatch")
	ErrIncomplete   = errors.New("gitobj: bundle closure incomplete")
	ErrExtraObjects = errors.New("gitobj: bundle contains unreachable objects")
	ErrUnsupported  = errors.New("gitobj: unsupported object or mode")
)

/*
The functions below are part of the contract and are implemented in the
other files of this package:

	// ID computes the Git object ID: sha1("<type> <len>\x00" || Data).
	func (o Object) ID() ID

	// ParseTree strictly parses a tree object. It rejects: unknown modes,
	// gitlinks, empty names, names containing '/' or NUL, the names ".",
	// ".." and ".git" (case-insensitively), duplicate names, and entries
	// that are not in Git's canonical tree order.
	func ParseTree(data []byte) ([]TreeEntry, error)
	func EncodeTree(entries []TreeEntry) []byte   // entries must already be sorted

	// ParseCommit strictly parses a commit object: exactly one "tree"
	// line first, then zero or more "parent" lines, then "author" and
	// "committer"; other headers (gpgsig, encoding, ...) are skipped but
	// must be syntactically valid. ParseCommit(x) must succeed only if
	// stock Git would hash the same bytes to the same ID (we never
	// re-encode commits; we always hash the original bytes).
	func ParseCommit(data []byte) (*Commit, error)

	// Stores.
	func NewMemStore() *MemStore
	// NewDiskStore opens (creating if needed) a bare-repository-compatible
	// loose object directory: <dir>/objects/ab/cdef... with zlib-compressed
	// "<type> <len>\x00<data>" files, written atomically (tmp + rename).
	// A DiskStore directory can be read with `git --git-dir=<dir> cat-file`.
	func NewDiskStore(dir string) (*DiskStore, error)
	// NewOverlay returns a read-only view: objects of b shadow base.
	func NewOverlay(base Store, b *Bundle) Store

	// Bundle is a set of objects.
	type Bundle struct{ Objects []Object }
	// Encode returns the canonical encoding:
	//   magic "DOSRBNDL" | version u8 = 1 | count u32be |
	//   count * ( type u8 | len u32be | data )
	// with objects sorted by ascending ID and no duplicates.
	func (b *Bundle) Encode() []byte
	// DecodeBundle strictly decodes: it enforces lim, rejects trailing
	// bytes, unsorted or duplicate objects and unknown types. Therefore
	// DecodeBundle(x) succeeds => Encode(DecodeBundle(x)) == x.
	func DecodeBundle(data []byte, lim Limits) (*Bundle, error)

	// VerifyClosure checks that bundle b is exactly the set of objects
	// needed to add commit `candidate` on top of `expectedParent`:
	//   1. candidate is a commit object present in b;
	//   2. if expectedParent is zero, candidate has no parents; otherwise
	//      candidate has exactly one parent, equal to expectedParent, and
	//      base.Has(expectedParent);
	//   3. every object reachable from candidate's tree is in b or in base
	//      (objects found in base are not descended into - see the Store
	//      closure invariant);
	//   4. every object in b is reachable from candidate without passing
	//      through base (no junk objects), and b contains no commit other
	//      than candidate;
	//   5. all trees parse strictly and respect lim.
	// It returns the parsed candidate commit.
	func VerifyClosure(base Store, b *Bundle, candidate, expectedParent ID, lim Limits) (*Commit, error)

	// ApplyBundle Puts every object of b into dst. Call only after
	// VerifyClosure succeeded.
	func ApplyBundle(dst Store, b *Bundle) error

	// DiffTrees returns the blob-level changes between two trees, sorted
	// by Path (bytewise). oldTree may be zero (everything is an addition).
	// A path whose type changes (file <-> directory) is reported as the
	// corresponding deletions and additions. Mode-only changes are reported.
	func DiffTrees(s Store, oldTree, newTree ID, lim Limits) ([]Change, error)

	// Client-side helpers (NOT used by validators; they shell out to the
	// git CLI and therefore need not be deterministic across machines).
	//
	// ExtractBundle builds the bundle for `candidate` on top of `base`
	// from a local Git repository using
	//   git rev-list --objects --no-object-names candidate ^base
	//   git cat-file --batch
	func ExtractBundle(repoDir string, base, candidate ID) (*Bundle, error)
	// ResolveRef runs `git rev-parse --verify <ref>^{commit}`.
	func ResolveRef(repoDir, ref string) (ID, error)
*/
