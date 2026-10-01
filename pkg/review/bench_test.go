package review

import (
	"fmt"
	"testing"

	"github.com/dosr/dosr/pkg/gitobj"
)

func benchFiles(n, gen int) []gitobj.File {
	files := make([]gitobj.File, 0, n)
	for i := 0; i < n; i++ {
		var data []byte
		for l := 0; l < 200; l++ {
			g := 0
			if l%40 == 17 {
				g = gen
			}
			data = fmt.Appendf(data, "func f%d_%d() int { return %d } // generation %d\n", i, l, l, g)
		}
		files = append(files, gitobj.File{Path: fmt.Sprintf("pkg%02d/file%04d.go", i%10, i), Mode: gitobj.ModeFile, Data: data})
	}
	return files
}

func BenchmarkBuildRequestBody(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		s := gitobj.NewMemStore()
		changes := fixture(b, s, benchFiles(n, 0), benchFiles(n, 1))
		if len(changes) != n {
			b.Fatal(len(changes))
		}
		pol, p := testPolicy(), testParams(b)
		pol.MaxDiffBytes = 8 << 20
		body, err := BuildRequestBody(pol, p, "benchmark\n", changes, s)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := BuildRequestBody(pol, p, "benchmark\n", changes, s); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUnifiedDiff(b *testing.B) {
	old := benchFiles(1, 0)[0].Data
	new := benchFiles(1, 1)[0].Data
	b.SetBytes(int64(len(old)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		UnifiedDiff(old, new, 3)
	}
}

func BenchmarkParseResponse(b *testing.B) {
	body := []byte(respBody("tool_use", `{"type":"text","text":"Reviewing."},`+toolUse(input("approve"))))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseResponse(body); err != nil {
			b.Fatal(err)
		}
	}
}
