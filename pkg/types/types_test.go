package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dosr/dosr/pkg/gitobj"
)

func key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) []byte { return []byte(k.Public().(ed25519.PublicKey)) }

func goodPolicy() Policy {
	ms := [][]byte{pub(key("m0")), pub(key("m1")), pub(key("m2"))}
	SortKeys(ms)
	return Policy{
		ProviderHost: "api.anthropic.com", ProviderPath: "/v1/messages",
		Models: []string{"claude-opus-5-5"}, SystemPrompt: "Review strictly.",
		MaxTokens: 1024, Notaries: [][]byte{pub(key("n"))},
		MaxReceiptAgeSec: 600, MaxClockSkewSec: 30, MaxDiffBytes: 1 << 20,
		Maintainers: ms, Threshold: 2,
	}
}

func TestPolicyValidate(t *testing.T) {
	p := goodPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Policy){
		"upper-case host":        func(p *Policy) { p.ProviderHost = "API.anthropic.com" },
		"host with default port": func(p *Policy) { p.ProviderHost = "api.anthropic.com:443" },
		"host with path":         func(p *Policy) { p.ProviderHost = "a.com/x" },
		"relative path":          func(p *Policy) { p.ProviderPath = "v1/messages" },
		"path with space":        func(p *Policy) { p.ProviderPath = "/v1/ messages" },
		"no models":              func(p *Policy) { p.Models = nil },
		"unsorted models":        func(p *Policy) { p.Models = []string{"b", "a"} },
		"duplicate model":        func(p *Policy) { p.Models = []string{"a", "a"} },
		"model with newline":     func(p *Policy) { p.Models = []string{"a\nb"} },
		"empty prompt":           func(p *Policy) { p.SystemPrompt = "" },
		"invalid utf8 prompt":    func(p *Policy) { p.SystemPrompt = "a\xffb" },
		"nul in prompt":          func(p *Policy) { p.SystemPrompt = "a\x00b" },
		"huge prompt":            func(p *Policy) { p.SystemPrompt = strings.Repeat("x", 16<<10+1) },
		"max_tokens":             func(p *Policy) { p.MaxTokens = 1 },
		"no notary":              func(p *Policy) { p.Notaries = nil },
		"short notary key":       func(p *Policy) { p.Notaries = [][]byte{{1, 2, 3}} },
		"duplicate notary":       func(p *Policy) { p.Notaries = [][]byte{p.Notaries[0], p.Notaries[0]} },
		"zero age":               func(p *Policy) { p.MaxReceiptAgeSec = 0 },
		"negative skew":          func(p *Policy) { p.MaxClockSkewSec = -1 },
		"tiny diff limit":        func(p *Policy) { p.MaxDiffBytes = 10 },
		"threshold zero":         func(p *Policy) { p.Threshold = 0 },
		"threshold too high":     func(p *Policy) { p.Threshold = 4 },
		"unsorted maintainers":   func(p *Policy) { p.Maintainers[0], p.Maintainers[1] = p.Maintainers[1], p.Maintainers[0] },
		"intent without limit":   func(p *Policy) { p.RequireIntent = true },
		"limit without intent":   func(p *Policy) { p.MaxAttempts = 3 },
		"bad spki pin":           func(p *Policy) { p.ProviderSPKI = [][]byte{{1}} },
	}
	for name, mut := range bad {
		q := goodPolicy()
		mut(&q)
		if err := q.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPolicyHashInjective: valid policies that differ in any field have
// different hashes, and the hash survives a JSON round trip.
func TestPolicyHash(t *testing.T) {
	base := goodPolicy()
	seen := map[PolicyHash]string{base.Hash(): "base"}
	muts := map[string]func(*Policy){
		"host":    func(p *Policy) { p.ProviderHost = "api.example.com" },
		"path":    func(p *Policy) { p.ProviderPath = "/v2/messages" },
		"model":   func(p *Policy) { p.Models = []string{"claude-sonnet-5-5"} },
		"prompt":  func(p *Policy) { p.SystemPrompt += " " },
		"tokens":  func(p *Policy) { p.MaxTokens++ },
		"notary":  func(p *Policy) { p.Notaries = [][]byte{pub(key("other"))} },
		"age":     func(p *Policy) { p.MaxReceiptAgeSec++ },
		"skew":    func(p *Policy) { p.MaxClockSkewSec++ },
		"diff":    func(p *Policy) { p.MaxDiffBytes++ },
		"opaque":  func(p *Policy) { p.AllowOpaque = true },
		"intent":  func(p *Policy) { p.RequireIntent, p.MaxAttempts = true, 1 },
		"thresh":  func(p *Policy) { p.Threshold = 3 },
		"spki":    func(p *Policy) { p.ProviderSPKI = [][]byte{bytes.Repeat([]byte{1}, 32)} },
		"members": func(p *Policy) { p.Maintainers = p.Maintainers[:2] },
	}
	for name, mut := range muts {
		q := goodPolicy()
		mut(&q)
		if err := q.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		h := q.Hash()
		if other, dup := seen[h]; dup {
			t.Fatalf("policies %s and %s share a hash", name, other)
		}
		seen[h] = name
	}
	var rt Policy
	if err := json.Unmarshal(base.Canonical(), &rt); err != nil {
		t.Fatal(err)
	}
	if rt.Hash() != base.Hash() {
		t.Fatal("hash changed across a JSON round trip")
	}
}

func sampleTx(t testing.TB) *Tx {
	tx, err := SignTx(key("user"), TxReviewIntent, ReviewIntentBody{
		ChainID: "c", Repo: "r", Branch: "main", Candidate: gitobj.ID{1},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestTxRoundTripAndTamper(t *testing.T) {
	tx := sampleTx(t)
	if err := tx.VerifySig(); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ReviewIntent(); err != nil {
		t.Fatal(err)
	}
	raw := tx.Bytes()
	// Every single-bit change is either rejected by the decoder or by
	// the signature check: the signature covers every byte before it,
	// and ed25519 signatures are not malleable under Go's verifier.
	for i := range raw {
		for bit := 0; bit < 8; bit++ {
			m := append([]byte(nil), raw...)
			m[i] ^= 1 << uint(bit)
			d, err := DecodeTx(m)
			if err != nil {
				if !errors.Is(err, ErrTxMalformed) {
					t.Fatalf("byte %d: unexpected error type %v", i, err)
				}
				continue
			}
			if d.VerifySig() == nil {
				t.Fatalf("flipping bit %d of byte %d went unnoticed", bit, i)
			}
		}
	}
	// Truncations and extensions.
	for n := 0; n < len(raw); n++ {
		if d, err := DecodeTx(raw[:n]); err == nil && d.VerifySig() == nil {
			t.Fatalf("truncation to %d bytes accepted", n)
		}
	}
	if d, err := DecodeTx(append(append([]byte(nil), raw...), 0)); err == nil && d.VerifySig() == nil {
		t.Fatal("trailing byte accepted")
	}
}

func TestBodyStrictness(t *testing.T) {
	k := key("user")
	mk := func(typ TxType, body string, payload []byte) *Tx {
		// Assemble the envelope by hand: SignTx would refuse to
		// marshal a body that is not a single JSON value.
		raw := []byte(txMagic)
		raw = append(raw, txVersion, byte(typ))
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(body)))
		raw = append(raw, body...)
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(payload)))
		raw = append(raw, payload...)
		raw = append(raw, pub(k)...)
		raw = append(raw, ed25519.Sign(k, signingBytes(raw))...)
		tx, err := DecodeTx(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.VerifySig(); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	c := strings.Repeat("11", 20)
	cases := []struct {
		name string
		tx   *Tx
		f    func(*Tx) error
	}{
		{"unknown field", mk(TxReviewIntent, `{"chain_id":"c","repo":"r","branch":"main","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+c+`","x":1}`, nil),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"trailing json", mk(TxReviewIntent, `{"chain_id":"c","repo":"r","branch":"main","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+c+`"} {}`, nil),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"upper-case id", mk(TxReviewIntent, `{"chain_id":"c","repo":"r","branch":"main","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+strings.Repeat("AA", 20)+`"}`, nil),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"bad repo id", mk(TxReviewIntent, `{"chain_id":"c","repo":"../x","branch":"main","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+c+`"}`, nil),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"branch with NUL", mk(TxReviewIntent, `{"chain_id":"c","repo":"r","branch":"ma\u0000in","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+c+`"}`, nil),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"intent with payload", mk(TxReviewIntent, `{"chain_id":"c","repo":"r","branch":"main","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+c+`"}`, []byte{1}),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"candidate == head", mk(TxReviewIntent, `{"chain_id":"c","repo":"r","branch":"main","expected_head":"`+c+`","candidate":"`+c+`"}`, nil),
			func(t *Tx) error { _, err := t.ReviewIntent(); return err }},
		{"accept without bundle", mk(TxAcceptCommit, `{"chain_id":"c","repo":"r","branch":"main","expected_head":"`+strings.Repeat("0", 40)+`","candidate":"`+c+`","policy_version":1,"model":"m","receipt":{}}`, nil),
			func(t *Tx) error { _, err := t.AcceptCommit(); return err }},
		{"wrong type accessor", sampleTx(t), func(t *Tx) error { _, err := t.AcceptCommit(); return err }},
	}
	for _, tc := range cases {
		if err := tc.f(tc.tx); !errors.Is(err, ErrTxMalformed) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}
}

func FuzzDecodeTx(f *testing.F) {
	f.Add(sampleTx(f).Bytes())
	f.Add([]byte("DOSR\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		tx, err := DecodeTx(raw)
		if err != nil {
			return
		}
		// A decoded envelope accounts for every input byte.
		if !bytes.Equal(tx.Bytes(), raw) {
			t.Fatal("decoded tx does not alias its input")
		}
		if len(tx.Body)+len(tx.Payload)+MinTxBytes != len(raw) {
			t.Fatal("length accounting broken")
		}
		_ = tx.VerifySig()
		_, _ = tx.CreateRepo()
		_, _ = tx.AcceptCommit()
		_, _ = tx.UpdatePolicy()
		_, _ = tx.ReviewIntent()
	})
}
