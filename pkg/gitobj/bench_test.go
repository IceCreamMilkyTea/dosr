package gitobj

import (
	"fmt"
	"testing"
)

// benchChange builds a base repository of 500 files and a candidate that
// modifies n of them.
func benchChange(b *testing.B, n int) (base *MemStore, bundle *Bundle, head, cand ID) {
	b.Helper()
	base = NewMemStore()
	files := synthFiles(500, 0)
	b0, head := makeCommit(b, base, ZeroID, "base\n", files)
	if err := ApplyBundle(base, b0); err != nil {
		b.Fatal(err)
	}
	next := append([]File(nil), files...)
	mod := synthFiles(500, 1)
	for i := 0; i < n; i++ {
		next[i*(500/n)%500] = mod[i*(500/n)%500]
	}
	bundle, cand = makeCommit(b, base, head, "change\n", next)
	return
}

var benchSizes = []int{1, 10, 100}

func BenchmarkDecodeBundle(b *testing.B) {
	for _, n := range benchSizes {
		_, bundle, _, _ := benchChange(b, n)
		enc := bundle.Encode()
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(enc)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := DecodeBundle(enc, DefaultLimits); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyClosure(b *testing.B) {
	for _, n := range benchSizes {
		base, bundle, head, cand := benchChange(b, n)
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyClosure(base, bundle, cand, head, DefaultLimits); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDiffTrees(b *testing.B) {
	for _, n := range benchSizes {
		base, bundle, head, cand := benchChange(b, n)
		ov := NewOverlay(base, bundle)
		tree := func(id ID) ID {
			o, _ := ov.Get(id)
			c, err := ParseCommit(o.Data)
			if err != nil {
				b.Fatal(err)
			}
			return c.Tree
		}
		ot, nt := tree(head), tree(cand)
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cs, err := DiffTrees(ov, ot, nt, DefaultLimits)
				if err != nil || len(cs) != n {
					b.Fatal(err, len(cs))
				}
			}
		})
	}
}
