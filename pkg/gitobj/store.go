package gitobj

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// typer is an optional Store extension that reports an object's type
// without materialising its content. VerifyClosure uses it to detect type
// confusion against base objects cheaply. All stores in this package
// implement it; foreign stores fall back to Get.
type typer interface {
	TypeOf(id ID) (ObjType, error)
}

// typeOf returns the type of the object id in s (ErrNotFound if absent).
func typeOf(s Store, id ID) (ObjType, error) {
	if t, ok := s.(typer); ok {
		return t.TypeOf(id)
	}
	o, err := s.Get(id)
	if err != nil {
		return 0, err
	}
	return o.Type, nil
}

// ---------------------------------------------------------------- MemStore

// MemStore is an in-memory Store. It is safe for concurrent use.
type MemStore struct {
	mu   sync.RWMutex
	objs map[ID]Object
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{objs: make(map[ID]Object)}
}

// Has reports whether id is stored.
func (m *MemStore) Has(id ID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.objs[id]
	return ok
}

// Get returns the object. The returned Data is shared with the store and
// MUST NOT be modified by the caller.
func (m *MemStore) Get(id ID) (Object, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.objs[id]
	if !ok {
		return Object{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return o, nil
}

// TypeOf returns the type of a stored object.
func (m *MemStore) TypeOf(id ID) (ObjType, error) {
	o, err := m.Get(id)
	return o.Type, err
}

// Put stores a private copy of o (so later mutation of o.Data by the
// caller cannot corrupt the content-addressed store).
func (m *MemStore) Put(o Object) (ID, error) {
	if !o.Type.Valid() {
		return ZeroID, fmt.Errorf("%w: object type %d", ErrUnsupported, o.Type)
	}
	id := o.ID()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objs[id]; !ok {
		m.objs[id] = Object{Type: o.Type, Data: append([]byte(nil), o.Data...)}
	}
	return id, nil
}

// Len returns the number of stored objects.
func (m *MemStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objs)
}

// --------------------------------------------------------------- DiskStore

// maxLooseObjectBytes bounds the declared size of a loose object DiskStore
// is willing to inflate. Objects written through ApplyBundle are bounded by
// Limits.MaxObjectBytes (1 MiB by default); this generous ceiling only
// protects against a corrupted or foreign file declaring an absurd length
// (a zlib bomb on the validator's own disk).
const maxLooseObjectBytes = 256 << 20

// DiskStore is a Store backed by a Git loose-object directory.
type DiskStore struct {
	dir string
}

// NewDiskStore opens (creating if needed) a bare-repository-compatible
// directory.
//
// Layout decision: besides <dir>/objects, NewDiskStore creates the minimal
// skeleton stock Git requires to recognise a directory as a repository:
// <dir>/HEAD (containing "ref: refs/heads/main\n") and <dir>/refs/heads.
// No config file is written; Git then treats the directory as a bare
// repository when addressed with --git-dir. Existing files are never
// overwritten, so NewDiskStore can also be pointed at a directory made by
// `git init --bare`. DOSR itself keeps branch heads in chain state, not in
// refs/; a node that wants `git log main` to work can write the ref file
// itself.
func NewDiskStore(dir string) (*DiskStore, error) {
	if dir == "" {
		return nil, errors.New("gitobj: empty disk store directory")
	}
	for _, d := range []string{dir, filepath.Join(dir, "objects"), filepath.Join(dir, "refs", "heads")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("gitobj: disk store: %w", err)
		}
	}
	head := filepath.Join(dir, "HEAD")
	if _, err := os.Lstat(head); errors.Is(err, fs.ErrNotExist) {
		if err := writeFileAtomic(dir, head, []byte("ref: refs/heads/main\n"), 0o644); err != nil {
			return nil, fmt.Errorf("gitobj: disk store: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("gitobj: disk store: %w", err)
	}
	return &DiskStore{dir: dir}, nil
}

// Dir returns the repository directory (usable as git --git-dir).
func (d *DiskStore) Dir() string { return d.dir }

func (d *DiskStore) path(id ID) string {
	h := id.String()
	return filepath.Join(d.dir, "objects", h[:2], h[2:])
}

// Has reports whether a loose object file for id exists.
func (d *DiskStore) Has(id ID) bool {
	fi, err := os.Stat(d.path(id))
	return err == nil && fi.Mode().IsRegular()
}

// open opens the loose object and parses its header.
func (d *DiskStore) open(id ID) (f *os.File, zr io.ReadCloser, br *bufio.Reader, t ObjType, size int, err error) {
	f, err = os.Open(d.path(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = fmt.Errorf("%w: %s", ErrNotFound, id)
		} else {
			err = fmt.Errorf("gitobj: disk store: %w", err)
		}
		return nil, nil, nil, 0, 0, err
	}
	fail := func(e error) (*os.File, io.ReadCloser, *bufio.Reader, ObjType, int, error) {
		if zr != nil {
			zr.Close()
		}
		f.Close()
		return nil, nil, nil, 0, 0, e
	}
	zr, err = zlib.NewReader(bufio.NewReader(f))
	if err != nil {
		return fail(fmt.Errorf("%w: loose object %s: %v", ErrMalformed, id, err))
	}
	br = bufio.NewReader(zr)
	// Header: "<type> <decimal len>\x00", at most 32 bytes.
	var hdr []byte
	for {
		c, e := br.ReadByte()
		if e != nil {
			return fail(fmt.Errorf("%w: loose object %s: truncated header", ErrMalformed, id))
		}
		if c == 0 {
			break
		}
		if len(hdr) >= 32 {
			return fail(fmt.Errorf("%w: loose object %s: oversized header", ErrMalformed, id))
		}
		hdr = append(hdr, c)
	}
	sp := bytes.IndexByte(hdr, ' ')
	if sp < 0 {
		return fail(fmt.Errorf("%w: loose object %s: bad header", ErrMalformed, id))
	}
	switch string(hdr[:sp]) {
	case "commit":
		t = TypeCommit
	case "tree":
		t = TypeTree
	case "blob":
		t = TypeBlob
	default:
		return fail(fmt.Errorf("%w: loose object %s: type %q", ErrUnsupported, id, hdr[:sp]))
	}
	num := hdr[sp+1:]
	if len(num) == 0 || (len(num) > 1 && num[0] == '0') {
		return fail(fmt.Errorf("%w: loose object %s: bad length", ErrMalformed, id))
	}
	n, e := strconv.ParseUint(string(num), 10, 31)
	if e != nil || n > maxLooseObjectBytes {
		return fail(fmt.Errorf("%w: loose object %s: bad or oversized length", ErrMalformed, id))
	}
	return f, zr, br, t, int(n), nil
}

// TypeOf reads only the object header.
func (d *DiskStore) TypeOf(id ID) (ObjType, error) {
	f, zr, _, t, _, err := d.open(id)
	if err != nil {
		return 0, err
	}
	zr.Close()
	f.Close()
	return t, nil
}

// Get reads and verifies the object: the content must have exactly the
// declared length and must hash to id. The hash check means a validator
// whose disk was corrupted or tampered with fails loudly instead of
// silently diverging from the other replicas.
func (d *DiskStore) Get(id ID) (Object, error) {
	f, zr, br, t, size, err := d.open(id)
	if err != nil {
		return Object{}, err
	}
	defer f.Close()
	defer zr.Close()
	data := make([]byte, size)
	if _, err := io.ReadFull(br, data); err != nil {
		return Object{}, fmt.Errorf("%w: loose object %s: truncated content", ErrMalformed, id)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		return Object{}, fmt.Errorf("%w: loose object %s: content longer than declared", ErrMalformed, id)
	}
	o := Object{Type: t, Data: data}
	if o.ID() != id {
		return Object{}, fmt.Errorf("%w: loose object %s: hash mismatch", ErrMalformed, id)
	}
	return o, nil
}

// Put writes the object as a loose object file, atomically (temporary file
// in the same directory, fsync, rename), so a crash can never leave a
// partially written object under its final name.
func (d *DiskStore) Put(o Object) (ID, error) {
	if !o.Type.Valid() {
		return ZeroID, fmt.Errorf("%w: object type %d", ErrUnsupported, o.Type)
	}
	if len(o.Data) > maxLooseObjectBytes {
		return ZeroID, fmt.Errorf("%w: object of %d bytes", ErrLimit, len(o.Data))
	}
	id := o.ID()
	if d.Has(id) {
		return id, nil
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	var hdr [32]byte
	zw.Write(appendHeader(hdr[:0], o.Type, len(o.Data)))
	zw.Write(o.Data)
	if err := zw.Close(); err != nil {
		return ZeroID, fmt.Errorf("gitobj: disk store: %w", err)
	}
	p := d.path(id)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return ZeroID, fmt.Errorf("gitobj: disk store: %w", err)
	}
	// 0444 like Git: objects are immutable.
	if err := writeFileAtomic(filepath.Dir(p), p, buf.Bytes(), 0o444); err != nil {
		return ZeroID, fmt.Errorf("gitobj: disk store: %w", err)
	}
	return id, nil
}

func writeFileAtomic(tmpDir, dst string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(tmpDir, "tmp_obj_*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { f.Close(); os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ----------------------------------------------------------------- Overlay

// ErrReadOnly is returned by Put on an overlay store.
var ErrReadOnly = errors.New("gitobj: store is read-only")

type overlay struct {
	base Store
	objs map[ID]Object
}

// NewOverlay returns a read-only view: objects of b shadow base. It lets
// validators diff and render a candidate before anything is written to the
// real store. Objects of b with an invalid type are not visible.
func NewOverlay(base Store, b *Bundle) Store {
	ov := &overlay{base: base}
	if b != nil {
		ov.objs = make(map[ID]Object, len(b.Objects))
		for _, o := range b.Objects {
			if o.Type.Valid() {
				ov.objs[o.ID()] = o
			}
		}
	}
	return ov
}

func (ov *overlay) Has(id ID) bool {
	if _, ok := ov.objs[id]; ok {
		return true
	}
	return ov.base != nil && ov.base.Has(id)
}

func (ov *overlay) Get(id ID) (Object, error) {
	if o, ok := ov.objs[id]; ok {
		return o, nil
	}
	if ov.base == nil {
		return Object{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return ov.base.Get(id)
}

func (ov *overlay) TypeOf(id ID) (ObjType, error) {
	if o, ok := ov.objs[id]; ok {
		return o.Type, nil
	}
	if ov.base == nil {
		return 0, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return typeOf(ov.base, id)
}

func (ov *overlay) Put(Object) (ID, error) { return ZeroID, ErrReadOnly }
