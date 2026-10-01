package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// encodings returns the byte strings under which secret would be visible
// in a JSON document: raw, hex, and the three possible alignments of
// standard/URL base64 (only the alignment-independent inner part).
func encodings(secret []byte) [][]byte {
	out := [][]byte{secret, []byte(hex.EncodeToString(secret))}
	for shift := 0; shift < 3; shift++ {
		padded := append(make([]byte, shift), secret...)
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			e := enc.EncodeToString(padded)
			// Drop the characters influenced by the padding bytes and by
			// whatever follows the secret.
			start := (shift*8 + 5) / 6
			end := len(e) - 2
			if start < end {
				out = append(out, []byte(e[start:end]))
			}
		}
	}
	return out
}

func fuzzSeeds(f *testing.F, fx *fixture) [][]byte {
	all := map[string]Disclosure{}
	mixed := map[string]Disclosure{}
	for i, n := range fx.names {
		all[n] = Hidden
		mixed[n] = Disclosure(i % 3)
	}
	var seeds [][]byte
	for _, d := range []map[string]Disclosure{nil, dosrDisclosure(), all, mixed} {
		p, err := Present(fx.att, fx.sec, d)
		if err != nil {
			f.Fatal(err)
		}
		b, err := p.Encode()
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, b)
		var ind bytes.Buffer
		_ = json.Indent(&ind, b, "", " ")
		seeds = append(seeds, ind.Bytes())
	}
	seeds = append(seeds, []byte(`{}`), []byte(`null`), []byte(`{"attestation":{"header":{"version":1}},"leaves":[{"name":"a","disclosure":0}]}`))
	return seeds
}

// FuzzDecodePresentation: DecodePresentation never panics; whatever it
// accepts is structurally valid, re-encodable, and decodes to the same
// thing again.
func FuzzDecodePresentation(f *testing.F) {
	fx := newFixture(f, 64)
	for _, s := range fuzzSeeds(f, fx) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodePresentation(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error does not wrap ErrMalformed: %v", err)
			}
			if p != nil {
				t.Fatal("non-nil presentation with error")
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("decoded presentation is invalid: %v", err)
		}
		enc, err := p.Encode()
		if err != nil {
			// Only possible through the size limit (re-encoding can be
			// longer than a compactly escaped input); never here since
			// inputs are small.
			t.Fatalf("re-encode: %v", err)
		}
		q, err := DecodePresentation(enc)
		if err != nil {
			t.Fatalf("decode of re-encoding: %v", err)
		}
		enc2, err := q.Encode()
		if err != nil || !bytes.Equal(enc, enc2) {
			t.Fatalf("encoding is not a fixed point (%v)", err)
		}
		// Verify must not panic on it either.
		_, _ = ProxyVerifier{}.Verify(p, fx.trusted(), fx.known)
	})
}

// FuzzVerify: no byte-level mutation of a valid encoded presentation
// verifies with content different from the original transcript.
func FuzzVerify(f *testing.F) {
	fx := newFixture(f, 64)
	for _, s := range fuzzSeeds(f, fx) {
		f.Add(s)
	}
	honest, err := Present(fx.att, fx.sec, nil)
	if err != nil {
		f.Fatal(err)
	}
	want, err := ProxyVerifier{}.Verify(honest, fx.trusted(), nil)
	if err != nil {
		f.Fatal(err)
	}
	orig := fx.origFields()
	// The verifier is given the correct value of every field as "known":
	// this is the most permissive setting for an attacker (any leaf may
	// be switched to Known).
	knownAll := orig
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodePresentation(data)
		if err != nil {
			return
		}
		for _, known := range []map[string][]byte{knownAll, fx.known, nil} {
			before, _ := json.Marshal(p)
			got, err := ProxyVerifier{}.Verify(p, fx.trusted(), known)
			after, _ := json.Marshal(p)
			if !bytes.Equal(before, after) {
				t.Fatal("Verify modified its input")
			}
			if err != nil {
				if got != nil {
					t.Fatal("non-nil transcript with error")
				}
				if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUntrustedNotary) &&
					!errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrRootMismatch) &&
					!errors.Is(err, ErrMissingKnown) {
					t.Fatalf("error is not one of the sentinels: %v", err)
				}
				continue
			}
			if err := checkNoNewContent(orig, want, got); err != nil {
				t.Fatalf("mutated presentation verified with different content: %v\ninput: %q", err, data)
			}
		}
	})
}

// FuzzVerifyMutate applies STRUCTURED mutations to the decoded honest
// presentation (byte-level fuzzing of JSON/base64 text rarely produces
// well-formed presentations with interesting field changes). ops is
// interpreted as a program of 4-byte instructions.
func FuzzVerifyMutate(f *testing.F) {
	fx := newFixture(f, 64)
	honest, err := Present(fx.att, fx.sec, dosrDisclosure())
	if err != nil {
		f.Fatal(err)
	}
	want, err := ProxyVerifier{}.Verify(honest, fx.trusted(), fx.known)
	if err != nil {
		f.Fatal(err)
	}
	orig := fx.origFields()
	f.Add([]byte{})
	for op := byte(0); op < 16; op++ {
		f.Add([]byte{op, 0, 0, 1})
		f.Add([]byte{op, 7, 3, 0x80, op, 1, 2, 3})
	}
	flip := func(b []byte, pos, x byte) {
		if len(b) > 0 {
			b[int(pos)%len(b)] ^= x
		}
	}
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 64 {
			ops = ops[:64]
		}
		p := clonePresentation(honest)
		known := map[string][]byte{FieldReqBody: append([]byte(nil), fx.known[FieldReqBody]...)}
		for ; len(ops) >= 4; ops = ops[4:] {
			op, a, b, x := ops[0]%16, ops[1], ops[2], ops[3]
			if len(p.Leaves) == 0 {
				break
			}
			i, j := int(a)%len(p.Leaves), int(b)%len(p.Leaves)
			l := &p.Leaves[i]
			h := &p.Attestation.Header
			switch op {
			case 0:
				flip(l.Value, b, x)
			case 1:
				flip(l.Salt, b, x)
			case 2:
				flip(l.Commit, b, x)
			case 3:
				nb := []byte(l.Name)
				flip(nb, b, x)
				l.Name = string(nb)
			case 4:
				l.Disclosure = Disclosure(x % 4)
			case 5:
				p.Leaves[i], p.Leaves[j] = p.Leaves[j], p.Leaves[i]
			case 6:
				p.Leaves = append(p.Leaves[:i], p.Leaves[i+1:]...)
			case 7:
				p.Leaves = append(p.Leaves, p.Leaves[j])
			case 8:
				h.LeafCount = uint32(len(p.Leaves)) + uint32(x) - 1
			case 9:
				flip(h.Root, a, x)
			case 10:
				flip(p.Attestation.Sig, a, x)
			case 11:
				switch b % 4 {
				case 0:
					flip(h.NotaryKey, a, x)
				case 1:
					flip(h.ServerSPKI, a, x)
				case 2:
					nb := []byte(h.ServerName)
					flip(nb, a, x)
					h.ServerName = string(nb)
				case 3:
					h.Time ^= int64(x) << (a % 56)
				}
			case 12:
				h.Version = x
			case 13:
				// Re-open the leaf in another (consistent) mode using the
				// prover's secret: legitimate, must never add content.
				for k, n := range fx.sec.Names {
					if n != l.Name {
						continue
					}
					c := valueCommit(fx.sec.Salts[k], fx.sec.Values[k])
					switch x % 3 {
					case 0:
						*l = Leaf{Name: n, Disclosure: Hidden, Commit: c[:]}
					case 1:
						*l = Leaf{Name: n, Disclosure: Revealed, Salt: fx.sec.Salts[k], Value: fx.sec.Values[k]}
					case 2:
						*l = Leaf{Name: n, Disclosure: Known, Salt: fx.sec.Salts[k]}
					}
				}
			case 14:
				flip(known[FieldReqBody], a, x)
			case 15:
				// Move fields between slots of a leaf.
				switch x % 3 {
				case 0:
					l.Commit, l.Value = l.Value, l.Commit
				case 1:
					l.Salt, l.Commit = l.Commit, l.Salt
				case 2:
					l.Value, l.Salt = l.Salt, l.Value
				}
			}
		}
		got, err := ProxyVerifier{}.Verify(p, fx.trusted(), known)
		if err != nil {
			if got != nil {
				t.Fatal("non-nil transcript with error")
			}
			return
		}
		if err := checkNoNewContent(orig, want, got); err != nil {
			t.Fatalf("mutated presentation verified with different content: %v", err)
		}
		// Accepted presentations survive the wire format unchanged.
		enc, err := p.Encode()
		if err != nil {
			t.Fatalf("verified presentation does not encode: %v", err)
		}
		q, err := DecodePresentation(enc)
		if err != nil {
			t.Fatalf("verified presentation does not decode: %v", err)
		}
		got2, err := ProxyVerifier{}.Verify(q, fx.trusted(), known)
		if err != nil {
			t.Fatalf("verification differs after encode/decode: %v", err)
		}
		if err := checkNoNewContent(orig, got, got2); err != nil {
			t.Fatal(err)
		}
	})
}
