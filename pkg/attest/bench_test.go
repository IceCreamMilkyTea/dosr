package attest

import (
	"fmt"
	"testing"
)

var benchSizes = []int{1 << 10, 10 << 10, 100 << 10}

// The benchmarks use the 13-field transcript of newFixture (a realistic
// Messages API call) and vary the response body size. The request body is
// small and Known, the API key Hidden, everything else Revealed.

func BenchmarkBuild(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("resp=%dKB", size>>10), func(b *testing.B) {
			f := newFixture(b, size)
			rnd := newDetRand("bench")
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := Build(f.priv, "api.anthropic.com", testSPKI, 1, f.names, f.values, rnd); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPresent(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("resp=%dKB", size>>10), func(b *testing.B) {
			f := newFixture(b, size)
			d := dosrDisclosure()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Present(f.att, f.sec, d); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("resp=%dKB", size>>10), func(b *testing.B) {
			f := newFixture(b, size)
			p := f.present(b, dosrDisclosure())
			trusted := f.trusted()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := (ProxyVerifier{}).Verify(p, trusted, f.known); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecodeVerify measures what a validator actually does per
// transaction: JSON-decode the presentation, then verify it.
func BenchmarkDecodeVerify(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("resp=%dKB", size>>10), func(b *testing.B) {
			f := newFixture(b, size)
			enc, err := f.present(b, dosrDisclosure()).Encode()
			if err != nil {
				b.Fatal(err)
			}
			trusted := f.trusted()
			b.SetBytes(int64(len(enc)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p, err := DecodePresentation(enc)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := (ProxyVerifier{}).Verify(p, trusted, f.known); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncode(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("resp=%dKB", size>>10), func(b *testing.B) {
			f := newFixture(b, size)
			p := f.present(b, dosrDisclosure())
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.Encode(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
