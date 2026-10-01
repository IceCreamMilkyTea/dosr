package gitobj

import (
	"crypto/sha1" //nolint:gosec // Git object IDs are SHA-1 by definition.
	"strconv"
)

// Valid reports whether t is one of the three object types DOSR supports.
func (t ObjType) Valid() bool {
	return t == TypeCommit || t == TypeTree || t == TypeBlob
}

// appendHeader appends Git's loose-object header "<type> <len>\x00".
func appendHeader(dst []byte, t ObjType, n int) []byte {
	dst = append(dst, t.String()...)
	dst = append(dst, ' ')
	dst = strconv.AppendInt(dst, int64(n), 10)
	return append(dst, 0)
}

// ID computes the Git object ID: sha1("<type> <len>\x00" || Data).
//
// The type name is part of the hashed header, so the same bytes stored as a
// blob and as a tree have different IDs. This is what makes "type confusion"
// detectable: an ID can only ever resolve to an object of one type.
//
// An Object with an invalid Type hashes with the type name "invalid"; such
// an ID never equals the ID of a real Git object and stores refuse to Put
// such objects.
func (o Object) ID() ID {
	var hdr [32]byte
	h := sha1.New() //nolint:gosec
	h.Write(appendHeader(hdr[:0], o.Type, len(o.Data)))
	h.Write(o.Data)
	var id ID
	h.Sum(id[:0])
	return id
}

// compareIDs orders IDs bytewise.
func compareIDs(a, b ID) int {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
