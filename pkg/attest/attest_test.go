package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- Merkle

// refRoot is the textbook recursive RFC 6962 MTH with DOSR's interior
// prefix, used as an independent reference for merkleRoot.
func refRoot(l [][hashSize]byte) [hashSize]byte {
	if len(l) == 1 {
		return l[0]
	}
	k := 1
	for k*2 < len(l) {
		k *= 2
	}
	a, b := refRoot(l[:k]), refRoot(l[k:])
	return sha256.Sum256(append(append([]byte{0x02}, a[:]...), b[:]...))
}

func TestMerkleRootMatchesReference(t *testing.T) {
	var leaves [][hashSize]byte
	if _, ok := merkleRoot(nil); ok {
		t.Fatal("empty tree must not have a root")
	}
	seen := map[[hashSize]byte]int{}
	for n := 1; n <= 300; n++ {
		leaves = append(leaves, sha256.Sum256([]byte{byte(n), byte(n >> 8)}))
		got, ok := merkleRoot(leaves)
		if !ok {
			t.Fatalf("n=%d: !ok", n)
		}
		if want := refRoot(leaves); got != want {
			t.Fatalf("n=%d: root mismatch with reference", n)
		}
		if m, dup := seen[got]; dup {
			t.Fatalf("roots of %d and %d leaves collide", m, n)
		}
		seen[got] = n
	}
}

func TestCommitmentFormulas(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, SaltSize)
	val := []byte("value")
	vc := valueCommit(salt, val)
	if want := sha256.Sum256(append(append([]byte{0x01}, salt...), val...)); vc != want {
		t.Fatal("valueCommit does not match the contract formula")
	}
	var b []byte
	b = append(b, 0x00)
	b = binary.BigEndian.AppendUint32(b, 5)
	b = binary.BigEndian.AppendUint32(b, 8)
	b = append(b, "req.body"...)
	b = append(b, vc[:]...)
	if leafHash(5, "req.body", vc[:]) != sha256.Sum256(b) {
		t.Fatal("leafHash does not match the contract formula")
	}
	l, r := sha256.Sum256([]byte("l")), sha256.Sum256([]byte("r"))
	if innerHash(l, r) != sha256.Sum256(append(append([]byte{0x02}, l[:]...), r[:]...)) {
		t.Fatal("innerHash does not match the contract formula")
	}
}

func TestSigningBytesLayout(t *testing.T) {
	h := Header{Version: 1, NotaryKey: bytes.Repeat([]byte{1}, 32), ServerName: "ab",
		ServerSPKI: bytes.Repeat([]byte{2}, 32), Time: 0x0102030405060708, LeafCount: 9,
		Root: bytes.Repeat([]byte{3}, 32)}
	var w []byte
	w = append(w, "DOSR-ATTEST-V1\x00"...)
	w = append(w, 1)
	w = append(w, 0, 32)
	w = append(w, h.NotaryKey...)
	w = append(w, 0, 2, 'a', 'b')
	w = append(w, 0, 32)
	w = append(w, h.ServerSPKI...)
	w = append(w, 1, 2, 3, 4, 5, 6, 7, 8)
	w = append(w, 0, 0, 0, 9)
	w = append(w, h.Root...)
	if got := SigningBytes(h); !bytes.Equal(got, w) {
		t.Fatalf("SigningBytes layout:\n got %x\nwant %x", got, w)
	}
	h.Time = -1
	if got := SigningBytes(h); !bytes.Equal(got[len(got)-44:len(got)-36], bytes.Repeat([]byte{0xff}, 8)) {
		t.Fatal("negative time must be encoded as two's complement")
	}
	h.Root = h.Root[:31]
	if SigningBytes(h) != nil {
		t.Fatal("SigningBytes must refuse a short root")
	}
	h.Root = bytes.Repeat([]byte{3}, 32)
	h.ServerName = strings.Repeat("a", 70000)
	if SigningBytes(h) != nil {
		t.Fatal("SigningBytes must refuse an over-long field")
	}
}

// ------------------------------------------------------------ round trip

func TestRoundTripAllModes(t *testing.T) {
	f := newFixture(t, 1000)
	modes := map[string]map[string]Disclosure{
		"nil-map-all-revealed": nil,
		"dosr-policy":          dosrDisclosure(),
		"all-hidden":           {},
		"all-known":            {},
		"mixed":                {},
	}
	knownAll := f.origFields()
	for i, n := range f.names {
		modes["all-hidden"][n] = Hidden
		modes["all-known"][n] = Known
		modes["mixed"][n] = Disclosure(i % 3)
	}
	for name, d := range modes {
		t.Run(name, func(t *testing.T) {
			p := f.present(t, d)
			enc, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			q, err := DecodePresentation(enc)
			if err != nil {
				t.Fatal(err)
			}
			tr, err := ProxyVerifier{}.Verify(q, f.trusted(), knownAll)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !bytes.Equal(tr.NotaryKey, f.pub) || tr.ServerName != "api.anthropic.com" ||
				!bytes.Equal(tr.ServerSPKI, testSPKI) || tr.Time != 1790000000 {
				t.Fatalf("bad header in transcript: %+v", tr)
			}
			if fmt.Sprint(tr.Names) != fmt.Sprint(f.names) {
				t.Fatalf("names: %q", tr.Names)
			}
			var wantHidden []string
			for i, n := range f.names {
				dm, ok := d[n]
				if !ok {
					dm = Revealed
				}
				if dm == Hidden {
					wantHidden = append(wantHidden, n)
					if _, ok := tr.Fields[n]; ok {
						t.Fatalf("hidden field %q is in Fields", n)
					}
					continue
				}
				v, ok := tr.Fields[n]
				if !ok || !bytes.Equal(v, f.values[i]) {
					t.Fatalf("field %q = %q, %v", n, v, ok)
				}
			}
			if fmt.Sprint(tr.HiddenNames) != fmt.Sprint(wantHidden) {
				t.Fatalf("hidden names %q, want %q", tr.HiddenNames, wantHidden)
			}
			// Also through the interface and with a pointer receiver.
			var v Verifier = &ProxyVerifier{}
			if _, err := v.Verify(q, f.trusted(), knownAll); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSingleLeafAndEmptyValues(t *testing.T) {
	pub, priv := testKey("x")
	for _, n := range []int{1, 2, 3, 5, 8, 9, MaxLeaves} {
		names := make([]string, n)
		values := make([][]byte, n)
		for i := range names {
			names[i] = fmt.Sprintf("f%d", i)
			if i%2 == 1 {
				values[i] = []byte{byte(i)}
			} // even fields have nil (empty) values
		}
		att, sec, err := Build(priv, "h", testSPKI, 0, names, values, newDetRand("s"))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range []Disclosure{Hidden, Revealed, Known} {
			dm := map[string]Disclosure{}
			known := map[string][]byte{}
			for i, nm := range names {
				dm[nm] = d
				known[nm] = values[i]
			}
			p, err := Present(att, sec, dm)
			if err != nil {
				t.Fatal(err)
			}
			enc, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			q, err := DecodePresentation(enc)
			if err != nil {
				t.Fatalf("n=%d d=%d: %v", n, d, err)
			}
			tr, err := ProxyVerifier{}.Verify(q, []ed25519.PublicKey{pub}, known)
			if err != nil {
				t.Fatalf("n=%d d=%d: %v", n, d, err)
			}
			if d != Hidden && len(tr.Fields) != n {
				t.Fatalf("n=%d: %d fields", n, len(tr.Fields))
			}
		}
	}
}

func TestVerifyDoesNotAliasOrModifyInputs(t *testing.T) {
	f := newFixture(t, 100)
	p := f.present(t, dosrDisclosure())
	before, _ := json.Marshal(p)
	tr, err := ProxyVerifier{}.Verify(p, f.trusted(), f.known)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range tr.Fields {
		for i := range v {
			v[i] ^= 0xff
		}
	}
	tr.NotaryKey[0] ^= 1
	tr.ServerSPKI[0] ^= 1
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("mutating the transcript changed the presentation")
	}
	if string(f.known[FieldReqBody])[0] != '{' {
		t.Fatal("mutating the transcript changed the known map")
	}
	if _, err := (ProxyVerifier{}).Verify(p, f.trusted(), f.known); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDeterministic(t *testing.T) {
	f := newFixture(t, 100)
	p := f.present(t, dosrDisclosure())
	a, err := ProxyVerifier{}.Verify(p, f.trusted(), f.known)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		b, err := ProxyVerifier{}.Verify(p, f.trusted(), f.known)
		if err != nil || fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) {
			t.Fatal("Verify is not deterministic")
		}
	}
}

// ---------------------------------------------------------------- tamper

func mustFail(t *testing.T, what string, f *fixture, p *Presentation, known map[string][]byte, want error) {
	t.Helper()
	tr, err := ProxyVerifier{}.Verify(p, f.trusted(), known)
	if err == nil {
		t.Fatalf("%s: verified, transcript %+v", what, tr)
	}
	if tr != nil {
		t.Fatalf("%s: non-nil transcript with error", what)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("%s: got error %v, want %v", what, err, want)
	}
}

// TestFlipEveryByte flips every single byte (three different bit patterns)
// of every byte-string in the presentation and requires rejection.
func TestFlipEveryByte(t *testing.T) {
	f := newFixture(t, 300)
	base := f.present(t, dosrDisclosure())
	type target struct {
		name string
		get  func(p *Presentation) []byte
		want error
	}
	targets := []target{
		{"notary_key", func(p *Presentation) []byte { return p.Attestation.Header.NotaryKey }, ErrUntrustedNotary},
		{"server_spki", func(p *Presentation) []byte { return p.Attestation.Header.ServerSPKI }, ErrBadSignature},
		{"root", func(p *Presentation) []byte { return p.Attestation.Header.Root }, ErrBadSignature},
		{"sig", func(p *Presentation) []byte { return p.Attestation.Sig }, ErrBadSignature},
	}
	for i := range base.Leaves {
		i := i
		l := base.Leaves[i]
		if len(l.Value) > 0 {
			targets = append(targets, target{"value:" + l.Name, func(p *Presentation) []byte { return p.Leaves[i].Value }, ErrRootMismatch})
		}
		if len(l.Salt) > 0 {
			targets = append(targets, target{"salt:" + l.Name, func(p *Presentation) []byte { return p.Leaves[i].Salt }, ErrRootMismatch})
		}
		if len(l.Commit) > 0 {
			targets = append(targets, target{"commit:" + l.Name, func(p *Presentation) []byte { return p.Leaves[i].Commit }, ErrRootMismatch})
		}
	}
	count := 0
	for _, tg := range targets {
		n := len(tg.get(base))
		if n == 0 {
			t.Fatalf("%s: empty target", tg.name)
		}
		for pos := 0; pos < n; pos++ {
			for _, x := range []byte{0x01, 0x80, 0xff} {
				p := clonePresentation(base)
				tg.get(p)[pos] ^= x
				mustFail(t, fmt.Sprintf("%s[%d]^%02x", tg.name, pos, x), f, p, f.known, tg.want)
				count++
			}
		}
	}
	// The known value is part of the transcript too.
	for pos := range f.known[FieldReqBody] {
		k := map[string][]byte{FieldReqBody: append([]byte(nil), f.known[FieldReqBody]...)}
		k[FieldReqBody][pos] ^= 0x01
		mustFail(t, "known value flip", f, base, k, ErrRootMismatch)
		count++
	}
	t.Logf("%d single-byte tamperings rejected", count)
}

func TestTamperCases(t *testing.T) {
	f := newFixture(t, 200)
	otherPub, otherPriv := testKey("mallory")
	idx := func(p *Presentation, name string) int {
		for i, l := range p.Leaves {
			if l.Name == name {
				return i
			}
		}
		t.Fatalf("no leaf %q", name)
		return -1
	}
	const apiKeyField = FieldReqHeaderPfx + "x-api-key"

	cases := []struct {
		name   string
		resign bool // re-sign the header with the TRUSTED key after mutating
		mut    func(p *Presentation, known map[string][]byte)
		want   error
	}{
		// --- header fields
		{"version-0", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Version = 0 }, ErrMalformed},
		{"version-2", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Version = 2 }, ErrMalformed},
		{"version-2-resigned", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Version = 2 }, ErrMalformed},
		{"server-name", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerName = "api.anthropic.con" }, ErrBadSignature},
		{"server-name-case", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerName = "API.anthropic.com" }, ErrBadSignature},
		{"server-name-empty", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerName = "" }, ErrMalformed},
		{"server-name-nul", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerName = "a\x00b" }, ErrMalformed},
		{"server-name-non-utf8", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerName = "a\xffb" }, ErrMalformed},
		{"server-name-too-long", true, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.ServerName = strings.Repeat("a", MaxServerNameLen+1)
		}, ErrMalformed},
		{"time+1", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Time++ }, ErrBadSignature},
		{"time-negated", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Time = -p.Attestation.Header.Time }, ErrBadSignature},
		{"spki-short", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerSPKI = testSPKI[:31] }, ErrMalformed},
		{"spki-long", true, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.ServerSPKI = append(append([]byte{}, testSPKI...), 0)
		}, ErrMalformed},
		{"spki-nil", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.ServerSPKI = nil }, ErrMalformed},
		{"root-short", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Root = p.Attestation.Header.Root[:31] }, ErrMalformed},
		{"root-long", false, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.Root = append(p.Attestation.Header.Root, 0)
		}, ErrMalformed},
		{"root-nil", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.Root = nil }, ErrMalformed},
		{"root-other-resigned", true, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.Root = bytes.Repeat([]byte{0xaa}, 32)
		}, ErrRootMismatch},

		// --- keys and signature
		{"notary-key-short", false, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.NotaryKey = p.Attestation.Header.NotaryKey[:31]
		}, ErrMalformed},
		{"notary-key-long", false, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.NotaryKey = append(p.Attestation.Header.NotaryKey, 0)
		}, ErrMalformed},
		{"notary-key-nil", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.NotaryKey = nil }, ErrMalformed},
		{"untrusted-notary-valid-sig", false, func(p *Presentation, _ map[string][]byte) {
			// Mallory re-issues the whole attestation under her own key.
			p.Attestation.Header.NotaryKey = append([]byte{}, otherPub...)
			p.Attestation.Sig = ed25519.Sign(otherPriv, SigningBytes(p.Attestation.Header))
		}, ErrUntrustedNotary},
		{"trusted-key-but-signed-by-other", false, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Sig = ed25519.Sign(otherPriv, SigningBytes(p.Attestation.Header))
		}, ErrBadSignature},
		{"sig-short", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Sig = p.Attestation.Sig[:63] }, ErrMalformed},
		{"sig-long", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Sig = append(p.Attestation.Sig, 0) }, ErrMalformed},
		{"sig-nil", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Sig = nil }, ErrMalformed},
		{"sig-zero", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Sig = make([]byte, 64) }, ErrBadSignature},
		{"sig-over-different-context", false, func(p *Presentation, _ map[string][]byte) {
			// A signature by the trusted key over the same header bytes
			// WITHOUT the domain-separation context must not verify.
			p.Attestation.Sig = ed25519.Sign(f.priv, SigningBytes(p.Attestation.Header)[len(signingContext):])
		}, ErrBadSignature},

		// --- leaf count
		{"leafcount+1", false, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.LeafCount++ }, ErrMalformed},
		{"leafcount+1-resigned", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.LeafCount++ }, ErrMalformed},
		{"leafcount-0", true, func(p *Presentation, _ map[string][]byte) { p.Attestation.Header.LeafCount = 0 }, ErrMalformed},
		{"leafcount-wraps-u32", true, func(p *Presentation, _ map[string][]byte) {
			p.Attestation.Header.LeafCount = uint32(len(p.Leaves)) + 1<<31
		}, ErrMalformed},
		{"no-leaves", false, func(p *Presentation, _ map[string][]byte) { p.Leaves = nil }, ErrMalformed},
		{"no-leaves-count-0-resigned", true, func(p *Presentation, _ map[string][]byte) {
			p.Leaves = nil
			p.Attestation.Header.LeafCount = 0
		}, ErrMalformed},
		{"too-many-leaves-resigned", true, func(p *Presentation, _ map[string][]byte) {
			for i := len(p.Leaves); i < MaxLeaves+1; i++ {
				p.Leaves = append(p.Leaves, Leaf{Name: fmt.Sprintf("x%d", i), Disclosure: Hidden, Commit: make([]byte, 32)})
			}
			p.Attestation.Header.LeafCount = uint32(len(p.Leaves))
		}, ErrMalformed},

		// --- leaf list structure
		{"drop-last-leaf", false, func(p *Presentation, _ map[string][]byte) { p.Leaves = p.Leaves[:len(p.Leaves)-1] }, ErrMalformed},
		{"drop-last-leaf-resigned", true, func(p *Presentation, _ map[string][]byte) {
			p.Leaves = p.Leaves[:len(p.Leaves)-1]
			p.Attestation.Header.LeafCount--
		}, ErrRootMismatch},
		{"drop-first-leaf-resigned", true, func(p *Presentation, _ map[string][]byte) {
			p.Leaves = p.Leaves[1:]
			p.Attestation.Header.LeafCount--
		}, ErrRootMismatch},
		{"drop-hidden-leaf-add-dummy", false, func(p *Presentation, _ map[string][]byte) {
			// Try to make the api-key header disappear from the shape.
			i := idx(p, apiKeyField)
			p.Leaves[i] = Leaf{Name: FieldReqHeaderPfx + "x-other", Disclosure: Hidden, Commit: p.Leaves[i].Commit}
		}, ErrRootMismatch},
		{"append-leaf", false, func(p *Presentation, _ map[string][]byte) {
			p.Leaves = append(p.Leaves, Leaf{Name: "extra", Disclosure: Hidden, Commit: make([]byte, 32)})
		}, ErrMalformed},
		{"swap-first-two", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0], p.Leaves[1] = p.Leaves[1], p.Leaves[0] }, ErrRootMismatch},
		{"swap-last-two", false, func(p *Presentation, _ map[string][]byte) {
			n := len(p.Leaves)
			p.Leaves[n-1], p.Leaves[n-2] = p.Leaves[n-2], p.Leaves[n-1]
		}, ErrRootMismatch},
		{"rotate-leaves", false, func(p *Presentation, _ map[string][]byte) { p.Leaves = append(p.Leaves[1:], p.Leaves[0]) }, ErrRootMismatch},
		{"reverse-leaves", false, func(p *Presentation, _ map[string][]byte) {
			for i, j := 0, len(p.Leaves)-1; i < j; i, j = i+1, j-1 {
				p.Leaves[i], p.Leaves[j] = p.Leaves[j], p.Leaves[i]
			}
		}, ErrRootMismatch},
		{"duplicate-leaf-replacing-neighbour", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[1] = p.Leaves[0] }, ErrMalformed},
		{"duplicate-name-only", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[1].Name = p.Leaves[0].Name }, ErrMalformed},
		{"duplicate-leaf-appended-resigned", true, func(p *Presentation, _ map[string][]byte) {
			p.Leaves = append(p.Leaves, p.Leaves[0])
			p.Attestation.Header.LeafCount++
		}, ErrMalformed},

		// --- names
		{"rename-leaf", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Name = "req.methoD" }, ErrRootMismatch},
		{"rename-resp-body-to-other", false, func(p *Presentation, _ map[string][]byte) {
			p.Leaves[idx(p, FieldRespBody)].Name = "resp.header.x-body"
		}, ErrRootMismatch},
		{"swap-names-keep-values", false, func(p *Presentation, _ map[string][]byte) {
			// Present the request body as if it were the response body.
			i, j := idx(p, FieldRespStatus), idx(p, FieldRespBody)
			p.Leaves[i].Name, p.Leaves[j].Name = p.Leaves[j].Name, p.Leaves[i].Name
		}, ErrRootMismatch},
		{"name-empty", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Name = "" }, ErrMalformed},
		{"name-with-space", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Name = "req method" }, ErrMalformed},
		{"name-with-nul", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Name = "req.method\x00" }, ErrMalformed},
		{"name-non-ascii", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Name = "req.méthod" }, ErrMalformed},
		{"name-too-long", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Name = strings.Repeat("n", MaxNameLen+1) }, ErrMalformed},
		{"name-value-boundary-shift", false, func(p *Presentation, _ map[string][]byte) {
			// Move the last byte of the name into the commitment input;
			// the length prefix of the name must prevent this.
			l := &p.Leaves[0]
			l.Name = l.Name[:len(l.Name)-1]
		}, ErrRootMismatch},

		// --- values / salts / commits
		{"revealed-value-changed", false, func(p *Presentation, _ map[string][]byte) {
			p.Leaves[idx(p, FieldRespBody)].Value = []byte(`{"verdict":"approve"}`)
		}, ErrRootMismatch},
		{"revealed-value-truncated", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[idx(p, FieldRespBody)]
			l.Value = l.Value[:len(l.Value)-1]
		}, ErrRootMismatch},
		{"revealed-value-extended", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[idx(p, FieldRespBody)]
			l.Value = append(l.Value, 0)
		}, ErrRootMismatch},
		{"revealed-value-dropped", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[idx(p, FieldRespBody)].Value = nil }, ErrRootMismatch},
		{"salt-value-boundary-shift", false, func(p *Presentation, _ map[string][]byte) {
			// salt' = salt[:15], value' = salt[15:] || value hashes the
			// same byte string; the fixed salt length must prevent it.
			l := &p.Leaves[idx(p, FieldRespStatus)]
			l.Value = append([]byte{l.Salt[15]}, l.Value...)
			l.Salt = l.Salt[:15]
		}, ErrMalformed},
		{"salt-short", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Salt = p.Leaves[0].Salt[:15] }, ErrMalformed},
		{"salt-long", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Salt = append(p.Leaves[0].Salt, 0) }, ErrMalformed},
		{"salt-missing", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Salt = nil }, ErrMalformed},
		{"salts-swapped", false, func(p *Presentation, _ map[string][]byte) {
			p.Leaves[0].Salt, p.Leaves[1].Salt = p.Leaves[1].Salt, p.Leaves[0].Salt
		}, ErrRootMismatch},
		{"known-salt-short", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[idx(p, FieldReqBody)]
			l.Salt = l.Salt[:8]
		}, ErrMalformed},
		{"commit-short", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[idx(p, apiKeyField)]
			l.Commit = l.Commit[:31]
		}, ErrMalformed},
		{"commit-long", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[idx(p, apiKeyField)]
			l.Commit = append(l.Commit, 0)
		}, ErrMalformed},
		{"commit-missing", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[idx(p, apiKeyField)].Commit = nil }, ErrMalformed},

		// --- disclosure / field presence
		{"disclosure-unknown-3", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Disclosure = 3 }, ErrMalformed},
		{"disclosure-unknown-255", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Disclosure = 255 }, ErrMalformed},
		{"hidden-with-value", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[idx(p, apiKeyField)].Value = []byte("x") }, ErrMalformed},
		{"hidden-with-salt", false, func(p *Presentation, _ map[string][]byte) {
			p.Leaves[idx(p, apiKeyField)].Salt = make([]byte, SaltSize)
		}, ErrMalformed},
		{"revealed-with-commit", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[0]
			c := valueCommit(l.Salt, l.Value)
			l.Commit = c[:]
		}, ErrMalformed},
		{"known-with-value", false, func(p *Presentation, k map[string][]byte) {
			p.Leaves[idx(p, FieldReqBody)].Value = k[FieldReqBody]
		}, ErrMalformed},
		{"known-with-commit", false, func(p *Presentation, _ map[string][]byte) {
			p.Leaves[idx(p, FieldReqBody)].Commit = make([]byte, 32)
		}, ErrMalformed},
		{"revealed-relabelled-hidden", false, func(p *Presentation, _ map[string][]byte) { p.Leaves[0].Disclosure = Hidden }, ErrMalformed},
		{"hidden-commit-is-leaf-hash", false, func(p *Presentation, _ map[string][]byte) {
			// Confuse the two hash layers: give the leaf hash itself as
			// the value commitment.
			l := &p.Leaves[idx(p, apiKeyField)]
			h := leafHash(uint32(idx(p, apiKeyField)), l.Name, l.Commit)
			l.Commit = h[:]
		}, ErrRootMismatch},

		// --- known values
		{"known-missing", false, func(p *Presentation, k map[string][]byte) { delete(k, FieldReqBody) }, ErrMissingKnown},
		{"known-wrong", false, func(p *Presentation, k map[string][]byte) { k[FieldReqBody] = []byte(`{"model":"other"}`) }, ErrRootMismatch},
		{"known-empty", false, func(p *Presentation, k map[string][]byte) { k[FieldReqBody] = nil }, ErrRootMismatch},
		{"known-under-wrong-name", false, func(p *Presentation, k map[string][]byte) {
			k["req.Body"] = k[FieldReqBody]
			delete(k, FieldReqBody)
		}, ErrMissingKnown},
		{"revealed-to-known-without-value", false, func(p *Presentation, _ map[string][]byte) {
			l := &p.Leaves[idx(p, FieldRespBody)]
			l.Disclosure, l.Value = Known, nil
		}, ErrMissingKnown},
		{"known-supplied-but-leaf-revealed-with-other-value", true, func(p *Presentation, k map[string][]byte) {
			// A (trusted but faulty) notary attested a DIFFERENT request
			// body and the presenter reveals it, hoping the caller only
			// looks at what it passed in `known`.
			k[FieldReqMethod] = []byte("GET") // caller expects GET, transcript says POST
		}, ErrRootMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := f.present(t, dosrDisclosure())
			known := map[string][]byte{FieldReqBody: append([]byte(nil), f.known[FieldReqBody]...)}
			c.mut(p, known)
			if c.resign {
				f.resign(p)
			}
			mustFail(t, c.name, f, p, known, c.want)
			// The same must hold after an encode/decode cycle where the
			// mutated presentation is encodable at all.
			if b, err := json.Marshal(p); err == nil {
				if q, err := DecodePresentation(b); err == nil {
					mustFail(t, c.name+" (decoded)", f, q, known, nil)
				} else if !errors.Is(err, ErrMalformed) {
					t.Fatalf("decode error does not wrap ErrMalformed: %v", err)
				}
			}
		})
	}
}

func TestTrustedSetHandling(t *testing.T) {
	f := newFixture(t, 10)
	p := f.present(t, dosrDisclosure())
	other, _ := testKey("other")
	ok := [][]ed25519.PublicKey{
		{f.pub},
		{other, f.pub},
		{nil, f.pub[:5], other, f.pub, f.pub},
	}
	for i, tr := range ok {
		if _, err := (ProxyVerifier{}).Verify(p, tr, f.known); err != nil {
			t.Fatalf("trusted set %d: %v", i, err)
		}
	}
	bad := [][]ed25519.PublicKey{
		nil, {}, {other}, {nil}, {f.pub[:31]}, {append(append(ed25519.PublicKey{}, f.pub...), 0)},
	}
	for i, tr := range bad {
		if _, err := (ProxyVerifier{}).Verify(p, tr, f.known); !errors.Is(err, ErrUntrustedNotary) {
			t.Fatalf("bad trusted set %d: %v", i, err)
		}
	}
}

func TestVerifyNilAndZero(t *testing.T) {
	for _, p := range []*Presentation{nil, {}, {Leaves: []Leaf{{}}}} {
		if _, err := (ProxyVerifier{}).Verify(p, nil, nil); !errors.Is(err, ErrMalformed) {
			t.Fatalf("got %v", err)
		}
		if _, err := p.Encode(); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Encode: got %v", err)
		}
	}
}

// TestErrorPrecedence checks the documented order of checks.
func TestErrorPrecedence(t *testing.T) {
	f := newFixture(t, 10)
	p := f.present(t, dosrDisclosure())
	p.Leaves[0].Value = []byte("GET") // root mismatch ...
	p.Attestation.Sig[0] ^= 1         // ... and bad signature ...
	if _, err := (ProxyVerifier{}).Verify(p, f.trusted(), f.known); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature before ErrRootMismatch, got %v", err)
	}
	if _, err := (ProxyVerifier{}).Verify(p, nil, f.known); !errors.Is(err, ErrUntrustedNotary) {
		t.Fatalf("want ErrUntrustedNotary before ErrBadSignature, got %v", err)
	}
	p.Leaves[0].Salt = nil
	if _, err := (ProxyVerifier{}).Verify(p, nil, f.known); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed first, got %v", err)
	}
}

// ---------------------------------------------------- downgrade to hidden

// TestPresenterMayHideMore documents an inherent property of selective
// disclosure: whoever knows value and salt may present a leaf as Hidden.
// The verified transcript then simply lacks the field; it never contains
// different content. Callers must check presence of required fields.
func TestPresenterMayHideMore(t *testing.T) {
	f := newFixture(t, 50)
	honest := f.present(t, dosrDisclosure())
	want, err := ProxyVerifier{}.Verify(honest, f.trusted(), f.known)
	if err != nil {
		t.Fatal(err)
	}
	p := clonePresentation(honest)
	for i := range p.Leaves {
		l := &p.Leaves[i]
		if l.Name == FieldRespBody {
			c := valueCommit(l.Salt, l.Value)
			*l = Leaf{Name: l.Name, Disclosure: Hidden, Commit: c[:]}
		}
	}
	got, err := ProxyVerifier{}.Verify(p, f.trusted(), f.known)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Fields[FieldRespBody]; ok {
		t.Fatal("hidden field present in Fields")
	}
	if err := checkNoNewContent(f.origFields(), want, got); err != nil {
		t.Fatal(err)
	}
}

// ----------------------------------------------------------------- hiding

func TestHiddenValueNotInPresentation(t *testing.T) {
	f := newFixture(t, 100)
	p := f.present(t, dosrDisclosure())
	enc, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, enc, []byte(testAPIKey))
	// The request body is Known, so it must not travel either.
	assertAbsent(t, enc, f.known[FieldReqBody])
	// The salt of the hidden leaf must not be disclosed (it would allow
	// offline guessing of low-entropy values).
	for i, n := range f.sec.Names {
		if n == FieldReqHeaderPfx+"x-api-key" {
			assertAbsent(t, enc, f.sec.Salts[i])
			for _, l := range p.Leaves {
				if l.Name == n && (l.Salt != nil || l.Value != nil || l.Disclosure != Hidden) {
					t.Fatalf("hidden leaf leaks: %+v", l)
				}
			}
		}
	}
	// The name IS disclosed, by design.
	if !bytes.Contains(enc, []byte("req.header.x-api-key")) {
		t.Fatal("hidden leaf name should be visible")
	}
}

// assertAbsent checks that secret does not occur in data in raw form nor
// in any base64 alignment (standard and URL alphabets) nor hex.
func assertAbsent(t *testing.T, data, secret []byte) {
	t.Helper()
	if len(secret) < 8 {
		t.Fatalf("secret too short for a meaningful check")
	}
	for _, needle := range encodings(secret) {
		if bytes.Contains(data, needle) {
			t.Fatalf("secret material found in presentation bytes (as %q)", needle)
		}
	}
}

// TestHiddenCommitDependsOnSalt: equal secret values must give unrelated
// commitments in different attestations (otherwise API-key reuse would be
// linkable and dictionary attacks possible).
func TestHiddenCommitDependsOnSalt(t *testing.T) {
	_, priv := testKey("n")
	names := []string{"a", "b"}
	values := [][]byte{[]byte("same"), []byte("same")}
	a1, s1, err := Build(priv, "h", testSPKI, 1, names, values, nil) // crypto/rand
	if err != nil {
		t.Fatal(err)
	}
	a2, s2, err := Build(priv, "h", testSPKI, 1, names, values, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a1.Header.Root, a2.Header.Root) {
		t.Fatal("two builds with fresh salts produced the same root")
	}
	salts := map[string]bool{}
	for _, s := range append(append([][]byte{}, s1.Salts...), s2.Salts...) {
		if len(s) != SaltSize || salts[string(s)] {
			t.Fatal("salt reused or wrong size")
		}
		salts[string(s)] = true
	}
	d := map[string]Disclosure{"a": Hidden, "b": Hidden}
	p1, _ := Present(a1, s1, d)
	if bytes.Equal(p1.Leaves[0].Commit, p1.Leaves[1].Commit) {
		t.Fatal("equal values have equal commitments")
	}
}

// ------------------------------------------------ domain separation

// TestDomainSeparation exercises second-preimage style confusions between
// the three hash domains (leaf 0x00, value 0x01, interior 0x02).
func TestDomainSeparation(t *testing.T) {
	pub, priv := testKey("n")
	trusted := []ed25519.PublicKey{pub}
	names := []string{"f0", "f1", "f2", "f3"}
	values := [][]byte{[]byte("v0"), []byte("v1"), []byte("v2"), []byte("v3")}
	att, sec, err := Build(priv, "h", testSPKI, 1, names, values, newDetRand("d"))
	if err != nil {
		t.Fatal(err)
	}
	var lh [4][hashSize]byte
	var vc [4][hashSize]byte
	for i := range names {
		vc[i] = valueCommit(sec.Salts[i], values[i])
		lh[i] = leafHash(uint32(i), names[i], vc[i][:])
	}
	n01, n23 := innerHash(lh[0], lh[1]), innerHash(lh[2], lh[3])
	if root := innerHash(n01, n23); !bytes.Equal(root[:], att.Header.Root) {
		t.Fatal("unexpected tree shape for 4 leaves")
	}
	sign := func(h Header) *Attestation { return &Attestation{Header: h, Sig: ed25519.Sign(priv, SigningBytes(h))} }
	verify := func(p *Presentation, known map[string][]byte) error {
		_, err := ProxyVerifier{}.Verify(p, trusted, known)
		return err
	}

	// (1) Same root, claimed as a 2-leaf tree whose "leaves" are the
	// interior nodes. Even with a notary signature on LeafCount=2 (which
	// an honest notary would not give), an attacker would have to present
	// leaves hashing to n01 and n23; the natural attempts fail.
	h2 := cloneHeader(att.Header)
	h2.LeafCount = 2
	a2 := sign(h2)
	attempts := []Leaf{
		{Name: "f0", Disclosure: Hidden, Commit: n01[:]},
		{Name: "f0", Disclosure: Hidden, Commit: lh[0][:]},
		// value = lh0||lh1 with a chosen salt: H(0x01||salt||lh0||lh1) is
		// in the value domain, not the interior domain.
		{Name: "f0", Disclosure: Revealed, Salt: make([]byte, SaltSize), Value: append(append([]byte{}, lh[0][:]...), lh[1][:]...)},
	}
	for i, l := range attempts {
		p := &Presentation{Attestation: *a2, Leaves: []Leaf{l, {Name: "f1", Disclosure: Hidden, Commit: n23[:]}}}
		if err := verify(p, nil); !errors.Is(err, ErrRootMismatch) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}

	// (2) Same root claimed as a 1-leaf tree.
	h1 := cloneHeader(att.Header)
	h1.LeafCount = 1
	p := &Presentation{Attestation: *sign(h1), Leaves: []Leaf{{Name: "f0", Disclosure: Hidden, Commit: att.Header.Root}}}
	if err := verify(p, nil); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("1-leaf: %v", err)
	}

	// (3) An interior-node preimage (0x02||l||r, 65 bytes) offered as a
	// leaf preimage: a leaf preimage is 0x00||idx||len||name||commit, so
	// its first byte differs. Try to "spell" the interior preimage with
	// name and commit bytes anyway.
	inner := append(append([]byte{0x02}, lh[0][:]...), lh[1][:]...)
	for _, cut := range []int{1, 9, 33} {
		name := string(inner[:cut])
		commit := make([]byte, CommitSize)
		copy(commit, inner[cut:])
		p := &Presentation{Attestation: *a2, Leaves: []Leaf{
			{Name: name, Disclosure: Hidden, Commit: commit},
			{Name: "f1", Disclosure: Hidden, Commit: n23[:]}}}
		if err := verify(p, nil); err == nil {
			t.Fatalf("interior preimage accepted as leaf (cut %d)", cut)
		}
	}

	// (4) Position binding: equal (name-less) content at another index
	// gives another leaf hash.
	if leafHash(0, "f0", vc[0][:]) == leafHash(1, "f0", vc[0][:]) {
		t.Fatal("leaf hash does not bind the index")
	}
	// (5) Name/commit framing: ("ab", c) vs ("a", 'b'||c[:31]) differ
	// through the length prefix.
	c := vc[0][:]
	shifted := append([]byte{'b'}, c[:31]...)
	if leafHash(0, "ab", c) == leafHash(0, "a", shifted) {
		t.Fatal("leaf hash framing is ambiguous")
	}
	// (6) Trees of 3 leaves [a,b,c] and 2 leaves [H(a,b), c] have the
	// same root bytes; they are distinguished by the signed LeafCount and
	// by the leaf domain. Check the root equality claim and the
	// rejection.
	three := [][hashSize]byte{lh[0], lh[1], lh[2]}
	r3, _ := merkleRoot(three)
	r2, _ := merkleRoot([][hashSize]byte{n01, lh[2]})
	if r3 != r2 {
		t.Fatal("test assumption about tree shape is wrong")
	}
	h3 := cloneHeader(att.Header)
	h3.LeafCount = 2
	h3.Root = r3[:]
	p = &Presentation{Attestation: *sign(h3), Leaves: []Leaf{
		{Name: "f0", Disclosure: Hidden, Commit: n01[:]},
		{Name: "f2", Disclosure: Hidden, Commit: vc[2][:]}}}
	if err := verify(p, nil); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("3-as-2: %v", err)
	}
}

// ------------------------------------------------------------------ JSON

func TestDecodeStrictness(t *testing.T) {
	f := newFixture(t, 20)
	p := f.present(t, dosrDisclosure())
	enc, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePresentation(enc); err != nil {
		t.Fatal(err)
	}
	s := string(enc)
	bad := map[string]string{
		"empty":                     "",
		"null":                      "null",
		"array":                     "[]",
		"string":                    `"x"`,
		"empty-object":              "{}",
		"truncated":                 s[:len(s)-1],
		"truncated-half":            s[:len(s)/2],
		"trailing-object":           s + "{}",
		"trailing-garbage":          s + "x",
		"trailing-null":             s + " null",
		"trailing-copy":             s + s,
		"trailing-comma":            s + ",",
		"trailing-nul":              s + "\x00",
		"unknown-top-field":         strings.Replace(s, `{"attestation":`, `{"extra":1,"attestation":`, 1),
		"unknown-header-field":      strings.Replace(s, `{"version":`, `{"extra":"x","version":`, 1),
		"unknown-attestation-field": strings.Replace(s, `"sig":`, `"sig2":"AA==","sig":`, 1),
		"unknown-leaf-field":        strings.Replace(s, `{"name":"req.method",`, `{"name":"req.method","index":0,`, 1),
		"version-string":            strings.Replace(s, `"version":1`, `"version":"1"`, 1),
		"version-overflow":          strings.Replace(s, `"version":1`, `"version":257`, 1),
		"version-negative":          strings.Replace(s, `"version":1`, `"version":-1`, 1),
		"leafcount-overflow":        strings.Replace(s, `"leaf_count":13`, `"leaf_count":4294967309`, 1),
		"leafcount-negative":        strings.Replace(s, `"leaf_count":13`, `"leaf_count":-13`, 1),
		"time-float":                strings.Replace(s, `"time":1790000000`, `"time":1790000000.5`, 1),
		"time-overflow":             strings.Replace(s, `"time":1790000000`, `"time":9223372036854775808`, 1),
		"disclosure-overflow":       strings.Replace(s, `"disclosure":1`, `"disclosure":257`, 1),
		"disclosure-string":         strings.Replace(s, `"disclosure":1`, `"disclosure":"revealed"`, 1),
		"bad-base64":                strings.Replace(s, `"sig":"`, `"sig":"!`, 1),
		"leaves-object":             strings.Replace(s, `"leaves":[`, `"leaves":{"a":[`, 1),
		"name-number":               strings.Replace(s, `"name":"req.method"`, `"name":1`, 1),
	}
	for name, in := range bad {
		if in == s {
			t.Fatalf("%s: replacement did not apply", name)
		}
		q, err := DecodePresentation([]byte(in))
		if err == nil {
			t.Errorf("%s: accepted: %+v", name, q)
			continue
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error %v does not wrap ErrMalformed", name, err)
		}
	}

	// Harmless JSON-level malleability: accepted, identical content.
	want, err := ProxyVerifier{}.Verify(p, f.trusted(), f.known)
	if err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, enc, " ", "\t"); err != nil {
		t.Fatal(err)
	}
	harmless := map[string]string{
		"leading-trailing-space": " \n\t" + s + "\r\n ",
		"indented":               indented.String(),
		"escaped-name":           strings.Replace(s, `"name":"req.method"`, `"name":"req.method"`, 1),
	}
	for name, in := range harmless {
		q, err := DecodePresentation([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got, err := ProxyVerifier{}.Verify(q, f.trusted(), f.known)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			t.Errorf("%s: transcript differs", name)
		}
	}
}

func TestDecodeSizeLimit(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxPresentationBytes+1)
	if _, err := DecodePresentation(big); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversize input: %v", err)
	}
	f := newFixture(t, MaxPresentationBytes) // base64 of 1 MiB > limit
	p := f.present(t, dosrDisclosure())
	if _, err := p.Encode(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversize Encode: %v", err)
	}
}

// ---------------------------------------------------- Build/Present input

func TestBuildRejectsBadInput(t *testing.T) {
	_, priv := testKey("n")
	names := []string{"a", "b"}
	values := [][]byte{[]byte("1"), []byte("2")}
	many := make([]string, MaxLeaves+1)
	for i := range many {
		many[i] = fmt.Sprint("n", i)
	}
	type args struct {
		priv   ed25519.PrivateKey
		server string
		spki   []byte
		names  []string
		values [][]byte
	}
	bad := map[string]args{
		"short-key":       {priv[:10], "h", testSPKI, names, values},
		"nil-key":         {nil, "h", testSPKI, names, values},
		"empty-server":    {priv, "", testSPKI, names, values},
		"server-space":    {priv, "a b", testSPKI, names, values},
		"long-server":     {priv, strings.Repeat("a", 256), testSPKI, names, values},
		"short-spki":      {priv, "h", testSPKI[:5], names, values},
		"nil-spki":        {priv, "h", nil, names, values},
		"no-fields":       {priv, "h", testSPKI, nil, nil},
		"length-mismatch": {priv, "h", testSPKI, names, values[:1]},
		"dup-names":       {priv, "h", testSPKI, []string{"a", "a"}, values},
		"empty-name":      {priv, "h", testSPKI, []string{"a", ""}, values},
		"bad-name":        {priv, "h", testSPKI, []string{"a", "b\n"}, values},
		"non-utf8-name":   {priv, "h", testSPKI, []string{"a", "b\xff"}, values},
		"too-many":        {priv, "h", testSPKI, many, make([][]byte, len(many))},
	}
	for name, a := range bad {
		att, sec, err := Build(a.priv, a.server, a.spki, 1, a.names, a.values, newDetRand("x"))
		if err == nil || att != nil || sec != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Short randomness.
	if _, _, err := Build(priv, "h", testSPKI, 1, names, values, bytes.NewReader(make([]byte, 17))); err == nil {
		t.Error("short randomness accepted")
	}
	// Build must copy its inputs.
	v := [][]byte{[]byte("1"), []byte("2")}
	att, sec, err := Build(priv, "h", testSPKI, 1, names, v, newDetRand("x"))
	if err != nil {
		t.Fatal(err)
	}
	v[0][0] = 'X'
	if _, err := Present(att, sec, nil); err != nil {
		t.Fatalf("secret aliases Build input: %v", err)
	}
}

func TestPresentRejectsBadInput(t *testing.T) {
	f := newFixture(t, 10)
	g := func() *Secret {
		s := &Secret{Names: append([]string{}, f.sec.Names...)}
		for i := range f.sec.Values {
			s.Values = append(s.Values, append([]byte{}, f.sec.Values[i]...))
			s.Salts = append(s.Salts, append([]byte{}, f.sec.Salts[i]...))
		}
		return s
	}
	if _, err := Present(nil, f.sec, nil); err == nil {
		t.Error("nil attestation accepted")
	}
	if _, err := Present(f.att, nil, nil); err == nil {
		t.Error("nil secret accepted")
	}
	cases := map[string]func(s *Secret){
		"value-changed": func(s *Secret) { s.Values[0] = []byte("GET") },
		"salt-changed":  func(s *Secret) { s.Salts[0][0] ^= 1 },
		"salt-short":    func(s *Secret) { s.Salts[0] = s.Salts[0][:3] },
		"name-changed":  func(s *Secret) { s.Names[0] = "x" },
		"dup-name":      func(s *Secret) { s.Names[0] = s.Names[1] },
		"missing-field": func(s *Secret) { s.Names, s.Values, s.Salts = s.Names[1:], s.Values[1:], s.Salts[1:] },
		"ragged":        func(s *Secret) { s.Values = s.Values[1:] },
		"swapped": func(s *Secret) {
			s.Names[0], s.Names[1] = s.Names[1], s.Names[0]
			s.Values[0], s.Values[1] = s.Values[1], s.Values[0]
			s.Salts[0], s.Salts[1] = s.Salts[1], s.Salts[0]
		},
	}
	for name, mut := range cases {
		s := g()
		mut(s)
		if p, err := Present(f.att, s, dosrDisclosure()); err == nil || p != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Present(f.att, f.sec, map[string]Disclosure{FieldReqBody: 7}); !errors.Is(err, ErrMalformed) {
		t.Errorf("unknown disclosure: %v", err)
	}
	// Names in the policy map that are not in the transcript are ignored.
	p, err := Present(f.att, f.sec, map[string]Disclosure{"req.header.authorization": Hidden, "nonexistent": Known})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range p.Leaves {
		if l.Disclosure != Revealed {
			t.Fatalf("leaf %q: disclosure %d", l.Name, l.Disclosure)
		}
	}
	// Secret survives its own JSON encoding (it is returned by the notary
	// over HTTP).
	b, err := json.Marshal(f.sec)
	if err != nil {
		t.Fatal(err)
	}
	var s2 Secret
	if err := json.Unmarshal(b, &s2); err != nil {
		t.Fatal(err)
	}
	if _, err := Present(f.att, &s2, dosrDisclosure()); err != nil {
		t.Fatalf("secret after JSON round trip: %v", err)
	}
}
