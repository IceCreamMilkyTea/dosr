package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

// detRand is a deterministic byte stream (SHA-256 in counter mode) used as
// key and salt randomness so that tests, fuzz seeds and benchmarks are
// reproducible. NOT for production use.
type detRand struct {
	seed [32]byte
	ctr  uint64
	buf  []byte
}

func newDetRand(seed string) *detRand { return &detRand{seed: sha256.Sum256([]byte(seed))} }

func (r *detRand) Read(p []byte) (int, error) {
	for i := range p {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			s := sha256.Sum256(append(r.seed[:], c[:]...))
			r.buf = s[:]
		}
		p[i] = r.buf[0]
		r.buf = r.buf[1:]
	}
	return len(p), nil
}

func testKey(seed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := sha256.Sum256([]byte("key:" + seed))
	priv := ed25519.NewKeyFromSeed(s[:])
	return priv.Public().(ed25519.PublicKey), priv
}

const testAPIKey = "sk-ant-api03-THIS-IS-A-VERY-SECRET-KEY-0123456789"

var testSPKI = func() []byte { s := sha256.Sum256([]byte("spki")); return s[:] }()

// fixture is a realistic transcript with its attestation.
type fixture struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	names  []string
	values [][]byte
	att    *Attestation
	sec    *Secret
	known  map[string][]byte
}

// dosrDisclosure is the disclosure policy DOSR uses.
func dosrDisclosure() map[string]Disclosure {
	return map[string]Disclosure{
		FieldReqBody:                        Known,
		FieldReqHeaderPfx + "x-api-key":     Hidden,
		FieldReqHeaderPfx + "authorization": Hidden,
	}
}

func newFixture(tb testing.TB, respSize int) *fixture {
	tb.Helper()
	pub, priv := testKey("notary")
	reqBody := []byte(`{"model":"m","max_tokens":1024,"messages":[{"role":"user","content":"hello"}]}`)
	resp := bytes.Repeat([]byte("r"), respSize)
	names := []string{
		FieldReqMethod, FieldReqPath,
		FieldReqHeaderPfx + "accept-encoding",
		FieldReqHeaderPfx + "anthropic-version",
		FieldReqHeaderPfx + "content-type",
		FieldReqHeaderPfx + "host",
		FieldReqHeaderPfx + "x-api-key",
		FieldReqBody,
		FieldRespStatus,
		FieldRespHeadPfx + "content-type",
		FieldRespHeadPfx + "date",
		FieldRespHeadPfx + "request-id",
		FieldRespBody,
	}
	values := [][]byte{
		[]byte("POST"), []byte("/v1/messages"),
		[]byte("identity"),
		[]byte("2023-06-01"),
		[]byte("application/json"),
		[]byte("api.anthropic.com"),
		[]byte(testAPIKey),
		reqBody,
		[]byte("200"),
		[]byte("application/json"),
		[]byte("Tue, 29 Sep 2026 12:00:00 GMT"),
		[]byte("req_0123"),
		resp,
	}
	att, sec, err := Build(priv, "api.anthropic.com", testSPKI, 1790000000, names, values, newDetRand("salts"))
	if err != nil {
		tb.Fatalf("Build: %v", err)
	}
	return &fixture{pub: pub, priv: priv, names: names, values: values, att: att, sec: sec,
		known: map[string][]byte{FieldReqBody: reqBody}}
}

func (f *fixture) present(tb testing.TB, d map[string]Disclosure) *Presentation {
	tb.Helper()
	p, err := Present(f.att, f.sec, d)
	if err != nil {
		tb.Fatalf("Present: %v", err)
	}
	return p
}

func (f *fixture) trusted() []ed25519.PublicKey { return []ed25519.PublicKey{f.pub} }

// resign recomputes the notary signature after a header change (models a
// hypothetical malicious-but-trusted notary, or tests that want to reach
// the checks after the signature check).
func (f *fixture) resign(p *Presentation) {
	p.Attestation.Sig = ed25519.Sign(f.priv, SigningBytes(p.Attestation.Header))
}

func clonePresentation(p *Presentation) *Presentation {
	q := &Presentation{Attestation: Attestation{Header: cloneHeader(p.Attestation.Header),
		Sig: append([]byte(nil), p.Attestation.Sig...)}}
	q.Leaves = make([]Leaf, len(p.Leaves))
	for i, l := range p.Leaves {
		q.Leaves[i] = Leaf{Name: l.Name, Disclosure: l.Disclosure,
			Value:  append([]byte(nil), l.Value...),
			Salt:   append([]byte(nil), l.Salt...),
			Commit: append([]byte(nil), l.Commit...)}
	}
	return q
}

// checkNoNewContent is the soundness property used by the tests and the
// fuzzers: a transcript `got` obtained from ANY presentation that verifies
// under the fixture's notary key must not contain content differing from
// the transcript `want` of the honest presentation. Precisely: identical
// header fields, identical Names, every entry of got.Fields equal to the
// original value of that name, and Fields/HiddenNames partitioning Names.
// (A presentation may legitimately disclose LESS than the original, see
// the doc comment of ProxyVerifier.)
func checkNoNewContent(orig map[string][]byte, want, got *Transcript) error {
	if !bytes.Equal(got.NotaryKey, want.NotaryKey) || got.ServerName != want.ServerName ||
		!bytes.Equal(got.ServerSPKI, want.ServerSPKI) || got.Time != want.Time {
		return fmt.Errorf("header fields differ: %+v vs %+v", got, want)
	}
	if len(got.Names) != len(want.Names) {
		return fmt.Errorf("names differ: %q vs %q", got.Names, want.Names)
	}
	for i := range got.Names {
		if got.Names[i] != want.Names[i] {
			return fmt.Errorf("names differ: %q vs %q", got.Names, want.Names)
		}
	}
	hidden := map[string]bool{}
	for _, n := range got.HiddenNames {
		hidden[n] = true
	}
	if len(hidden) != len(got.HiddenNames) || len(hidden)+len(got.Fields) != len(got.Names) {
		return fmt.Errorf("fields and hidden names do not partition names")
	}
	for _, n := range got.Names {
		v, inFields := got.Fields[n]
		if inFields == hidden[n] {
			return fmt.Errorf("field %q: inFields=%v hidden=%v", n, inFields, hidden[n])
		}
		if inFields && !bytes.Equal(v, orig[n]) {
			return fmt.Errorf("field %q verified with different content", n)
		}
	}
	return nil
}

func (f *fixture) origFields() map[string][]byte {
	m := make(map[string][]byte, len(f.names))
	for i, n := range f.names {
		m[n] = f.values[i]
	}
	return m
}

var _ io.Reader = (*detRand)(nil)
