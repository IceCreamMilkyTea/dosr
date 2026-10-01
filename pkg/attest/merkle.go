package attest

import (
	"crypto/sha256"
	"encoding/binary"
)

// Domain-separation prefixes of the commitment scheme (see contract.go).
// NOTE: these deliberately differ from RFC 6962 (which uses 0x00 for leaves
// and 0x01 for interior nodes): DOSR has three hash domains, not two.
const (
	prefixLeaf   = 0x00 // leaf_i = H(0x00 || u32be(i) || u32be(len(n)) || n || valueCommit)
	prefixValue  = 0x01 // valueCommit = H(0x01 || salt || value)
	prefixInner  = 0x02 // node = H(0x02 || left || right)
	hashSize     = sha256.Size
	maxTreeDepth = 32
)

// valueCommit returns SHA256(0x01 || salt || value).
func valueCommit(salt, value []byte) [hashSize]byte {
	h := sha256.New()
	h.Write([]byte{prefixValue})
	h.Write(salt)
	h.Write(value)
	var out [hashSize]byte
	h.Sum(out[:0])
	return out
}

// leafHash returns SHA256(0x00 || u32be(i) || u32be(len(name)) || name || commit).
// commit must be hashSize bytes long.
func leafHash(i uint32, name string, commit []byte) [hashSize]byte {
	var hdr [9]byte
	hdr[0] = prefixLeaf
	binary.BigEndian.PutUint32(hdr[1:5], i)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(name)))
	h := sha256.New()
	h.Write(hdr[:])
	h.Write([]byte(name))
	h.Write(commit)
	var out [hashSize]byte
	h.Sum(out[:0])
	return out
}

// innerHash returns SHA256(0x02 || left || right).
func innerHash(l, r [hashSize]byte) [hashSize]byte {
	var buf [1 + 2*hashSize]byte
	buf[0] = prefixInner
	copy(buf[1:], l[:])
	copy(buf[1+hashSize:], r[:])
	return sha256.Sum256(buf[:])
}

// merkleRoot computes the RFC 6962 (section 2.1) Merkle tree hash over the
// given leaf hashes: for n > 1 leaves the tree is split at k, the largest
// power of two strictly smaller than n, and
//
//	MTH(D[0:n]) = H(0x02 || MTH(D[0:k]) || MTH(D[k:n])).
//
// The elements of leaves are already leaf hashes (leafHash), so MTH of a
// single element is the element itself. leaves must be non-empty; the
// empty tree is not a valid DOSR transcript and ok is false for it.
//
// The implementation is the iterative stack ("compact range") algorithm;
// it produces the same tree shape as the recursive definition, which the
// tests check against a straightforward recursive reference.
func merkleRoot(leaves [][hashSize]byte) (root [hashSize]byte, ok bool) {
	if len(leaves) == 0 {
		return root, false
	}
	// stack[j] holds the root of a perfect subtree of 2^level[j] leaves.
	var stack [maxTreeDepth + 1][hashSize]byte
	var level [maxTreeDepth + 1]uint8
	sp := 0
	for _, l := range leaves {
		stack[sp] = l
		level[sp] = 0
		sp++
		for sp >= 2 && level[sp-1] == level[sp-2] {
			stack[sp-2] = innerHash(stack[sp-2], stack[sp-1])
			level[sp-2]++
			sp--
		}
	}
	// Fold the remaining perfect subtrees right to left. This yields the
	// RFC 6962 shape: the left child of every node is the largest perfect
	// subtree that is strictly smaller than the node.
	for sp >= 2 {
		stack[sp-2] = innerHash(stack[sp-2], stack[sp-1])
		sp--
	}
	return stack[0], true
}
