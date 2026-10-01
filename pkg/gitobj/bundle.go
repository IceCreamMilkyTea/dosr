package gitobj

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// Bundle is a set of objects.
type Bundle struct{ Objects []Object }

const (
	bundleMagic   = "DOSRBNDL"
	bundleVersion = 1
	// bundleHeaderBytes = magic + version + count.
	bundleHeaderBytes = len(bundleMagic) + 1 + 4
	// bundleObjHeaderBytes = type + len.
	bundleObjHeaderBytes = 1 + 4
)

// Encode returns the canonical encoding:
//
//	magic "DOSRBNDL" | version u8 = 1 | count u32be |
//	count * ( type u8 | len u32be | data )
//
// with objects sorted by ascending ID and no duplicates. Encode treats
// b.Objects as a set: it does not modify b, sorts a copy, and drops
// repeated objects. The encoding is canonical so that the SHA-256 digest of
// a bundle identifies the object set, independent of how a client happened
// to enumerate it.
func (b *Bundle) Encode() []byte {
	type item struct {
		id  ID
		idx int
	}
	items := make([]item, len(b.Objects))
	for i, o := range b.Objects {
		items[i] = item{o.ID(), i}
	}
	// Ties (duplicates) are broken by index so the result does not
	// depend on the sort algorithm.
	sort.Slice(items, func(i, j int) bool {
		if c := compareIDs(items[i].id, items[j].id); c != 0 {
			return c < 0
		}
		return items[i].idx < items[j].idx
	})
	n := 0
	size := bundleHeaderBytes
	for i, it := range items {
		if i > 0 && it.id == items[i-1].id {
			continue
		}
		items[n] = it
		n++
		size += bundleObjHeaderBytes + len(b.Objects[it.idx].Data)
	}
	items = items[:n]
	out := make([]byte, 0, size)
	out = append(out, bundleMagic...)
	out = append(out, bundleVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(n))
	for _, it := range items {
		o := b.Objects[it.idx]
		out = append(out, byte(o.Type))
		out = binary.BigEndian.AppendUint32(out, uint32(len(o.Data)))
		out = append(out, o.Data...)
	}
	return out
}

// DecodeBundle strictly decodes a bundle.
//
// Order of checks (fixed, so every validator reports the same error for
// the same input): total size limit, magic, version, object count limit,
// then per object in order: header truncation, type, size limit, data
// truncation, ordering; finally trailing bytes.
//
// Every length field is validated against both the limits and the number
// of bytes actually remaining BEFORE anything is allocated, so a 13-byte
// input claiming 2^32-1 objects of 4 GiB costs nothing.
//
// Sentinels: ErrLimit (limits), ErrUnsupported (version, object type),
// ErrNonCanonical (unsorted/duplicate objects, trailing bytes),
// ErrMalformed (magic, truncation).
func DecodeBundle(data []byte, lim Limits) (*Bundle, error) {
	if len(data) > lim.MaxBundleBytes {
		return nil, fmt.Errorf("%w: bundle is %d bytes, limit %d", ErrLimit, len(data), lim.MaxBundleBytes)
	}
	if len(data) < bundleHeaderBytes {
		return nil, fmt.Errorf("%w: bundle header truncated", ErrMalformed)
	}
	if string(data[:len(bundleMagic)]) != bundleMagic {
		return nil, fmt.Errorf("%w: bad bundle magic", ErrMalformed)
	}
	if v := data[len(bundleMagic)]; v != bundleVersion {
		return nil, fmt.Errorf("%w: bundle version %d", ErrUnsupported, v)
	}
	count := uint64(binary.BigEndian.Uint32(data[len(bundleMagic)+1:]))
	if lim.MaxObjects < 0 || count > uint64(lim.MaxObjects) {
		return nil, fmt.Errorf("%w: bundle has %d objects, limit %d", ErrLimit, count, lim.MaxObjects)
	}
	rest := data[bundleHeaderBytes:]
	if count > uint64(len(rest)/bundleObjHeaderBytes) {
		return nil, fmt.Errorf("%w: bundle truncated: %d objects cannot fit in %d bytes", ErrMalformed, count, len(rest))
	}

	// One private copy of the payload; objects are sub-slices of it with
	// capacity clamped so that appending to one object's Data can never
	// overwrite its neighbour.
	buf := append([]byte(nil), rest...)
	objs := make([]Object, 0, count)
	var prev ID
	pos := 0
	for i := uint64(0); i < count; i++ {
		if len(buf)-pos < bundleObjHeaderBytes {
			return nil, fmt.Errorf("%w: bundle object %d: header truncated", ErrMalformed, i)
		}
		t := ObjType(buf[pos])
		if !t.Valid() {
			return nil, fmt.Errorf("%w: bundle object %d: type %d", ErrUnsupported, i, t)
		}
		n := uint64(binary.BigEndian.Uint32(buf[pos+1:]))
		pos += bundleObjHeaderBytes
		if lim.MaxObjectBytes < 0 || n > uint64(lim.MaxObjectBytes) {
			return nil, fmt.Errorf("%w: bundle object %d is %d bytes, limit %d", ErrLimit, i, n, lim.MaxObjectBytes)
		}
		if n > uint64(len(buf)-pos) {
			return nil, fmt.Errorf("%w: bundle object %d: data truncated", ErrMalformed, i)
		}
		end := pos + int(n)
		o := Object{Type: t, Data: buf[pos:end:end]}
		pos = end
		id := o.ID()
		if i > 0 && compareIDs(prev, id) >= 0 {
			return nil, fmt.Errorf("%w: bundle object %d: not in ascending id order", ErrNonCanonical, i)
		}
		prev = id
		objs = append(objs, o)
	}
	if pos != len(buf) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrNonCanonical, len(buf)-pos)
	}
	return &Bundle{Objects: objs}, nil
}

// ApplyBundle Puts every object of b into dst, in slice order. Call only
// after VerifyClosure succeeded. It stops at the first error; since Put is
// idempotent, a failed ApplyBundle can simply be retried.
func ApplyBundle(dst Store, b *Bundle) error {
	for i, o := range b.Objects {
		if _, err := dst.Put(o); err != nil {
			return fmt.Errorf("gitobj: apply bundle object %d: %w", i, err)
		}
	}
	return nil
}
