package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Limits enforced by Build, Present, DecodePresentation and Verify.
const (
	// MaxLeaves bounds the number of transcript fields.
	MaxLeaves = 256
	// SaltSize is the length of a leaf salt.
	SaltSize = 16
	// CommitSize is the length of a value commitment and of the root.
	CommitSize = 32
	// SPKISize is the length of Header.ServerSPKI (a SHA-256 digest).
	SPKISize = 32
	// MaxNameLen bounds the length of a leaf name.
	MaxNameLen = 256
	// MaxServerNameLen bounds Header.ServerName.
	MaxServerNameLen = 255
	// MaxPresentationBytes bounds the encoded size DecodePresentation
	// accepts. It equals types.MaxBodyBytes (a presentation travels inside
	// a transaction body), duplicated here to keep this package free of
	// dependencies.
	MaxPresentationBytes = 1 << 20

	signingContext = "DOSR-ATTEST-V1\x00"
)

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// validToken reports whether s consists of 1..max printable, non-space
// ASCII bytes (0x21..0x7e). Leaf names and server names are restricted to
// this alphabet so that they survive JSON encoding byte-for-byte (Go's
// encoding/json silently replaces invalid UTF-8 with U+FFFD, which would
// otherwise make Encode/Decode lossy for names).
func validToken(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// checkHeader performs the structural checks on a header.
func checkHeader(h *Header) error {
	if h.Version != Version {
		return malformed("unsupported version %d", h.Version)
	}
	if len(h.NotaryKey) != ed25519.PublicKeySize {
		return malformed("notary_key has length %d, want %d", len(h.NotaryKey), ed25519.PublicKeySize)
	}
	if !validToken(h.ServerName, MaxServerNameLen) {
		return malformed("bad server_name")
	}
	if len(h.ServerSPKI) != SPKISize {
		return malformed("server_spki has length %d, want %d", len(h.ServerSPKI), SPKISize)
	}
	if h.LeafCount == 0 || h.LeafCount > MaxLeaves {
		return malformed("leaf_count %d out of range 1..%d", h.LeafCount, MaxLeaves)
	}
	if len(h.Root) != CommitSize {
		return malformed("root has length %d, want %d", len(h.Root), CommitSize)
	}
	return nil
}

// SigningBytes is the canonical byte string the notary signs:
//
//	"DOSR-ATTEST-V1\x00" | version u8 | u16be(len)+NotaryKey |
//	u16be(len)+ServerName | u16be(len)+ServerSPKI | i64be Time |
//	u32be LeafCount | Root(32)
//
// The encoding is injective for headers whose variable-length fields are
// shorter than 65536 bytes and whose Root is exactly 32 bytes. For any
// other header SigningBytes returns nil; Build and Verify validate the
// header first and never sign or verify such a header.
func SigningBytes(h Header) []byte {
	if len(h.NotaryKey) > 0xffff || len(h.ServerName) > 0xffff ||
		len(h.ServerSPKI) > 0xffff || len(h.Root) != CommitSize {
		return nil
	}
	b := make([]byte, 0, len(signingContext)+1+6+len(h.NotaryKey)+len(h.ServerName)+len(h.ServerSPKI)+8+4+CommitSize)
	b = append(b, signingContext...)
	b = append(b, h.Version)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.NotaryKey)))
	b = append(b, h.NotaryKey...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.ServerName)))
	b = append(b, h.ServerName...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.ServerSPKI)))
	b = append(b, h.ServerSPKI...)
	b = binary.BigEndian.AppendUint64(b, uint64(h.Time))
	b = binary.BigEndian.AppendUint32(b, h.LeafCount)
	b = append(b, h.Root...)
	return b
}

// checkNames validates a list of leaf names: count, alphabet, uniqueness.
func checkNames(names []string) error {
	if len(names) == 0 || len(names) > MaxLeaves {
		return malformed("%d leaves, want 1..%d", len(names), MaxLeaves)
	}
	seen := make(map[string]struct{}, len(names))
	for i, n := range names {
		if !validToken(n, MaxNameLen) {
			return malformed("leaf %d: bad name", i)
		}
		if _, dup := seen[n]; dup {
			return malformed("leaf %d: duplicate name %q", i, n)
		}
		seen[n] = struct{}{}
	}
	return nil
}

// Build commits to the transcript fields (names/values in transcript
// order) with fresh salts from rnd, and signs the attestation.
//
// rnd supplies the salts; nil means crypto/rand.Reader. The hiding property
// of Hidden leaves rests entirely on the salts being unpredictable, so
// anything other than a CSPRNG must only be used in tests. Build copies
// the values; the returned Secret does not alias the arguments.
func Build(priv ed25519.PrivateKey, serverName string, serverSPKI []byte, t int64,
	names []string, values [][]byte, rnd io.Reader) (*Attestation, *Secret, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("attest: bad private key length")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("attest: bad private key")
	}
	if len(names) != len(values) {
		return nil, nil, malformed("%d names but %d values", len(names), len(values))
	}
	if err := checkNames(names); err != nil {
		return nil, nil, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	n := len(names)
	sec := &Secret{
		Names:  make([]string, n),
		Values: make([][]byte, n),
		Salts:  make([][]byte, n),
	}
	saltBuf := make([]byte, n*SaltSize)
	if _, err := io.ReadFull(rnd, saltBuf); err != nil {
		return nil, nil, fmt.Errorf("attest: reading salt randomness: %w", err)
	}
	leaves := make([][hashSize]byte, n)
	for i := range names {
		sec.Names[i] = names[i]
		sec.Values[i] = append([]byte{}, values[i]...)
		sec.Salts[i] = saltBuf[i*SaltSize : (i+1)*SaltSize : (i+1)*SaltSize]
		c := valueCommit(sec.Salts[i], sec.Values[i])
		leaves[i] = leafHash(uint32(i), names[i], c[:])
	}
	root, _ := merkleRoot(leaves)
	h := Header{
		Version:    Version,
		NotaryKey:  append([]byte{}, pub...),
		ServerName: serverName,
		ServerSPKI: append([]byte{}, serverSPKI...),
		Time:       t,
		LeafCount:  uint32(n),
		Root:       root[:],
	}
	if err := checkHeader(&h); err != nil {
		return nil, nil, err
	}
	return &Attestation{Header: h, Sig: ed25519.Sign(priv, SigningBytes(h))}, sec, nil
}

// checkSecret validates the shape of a secret.
func checkSecret(s *Secret) error {
	if s == nil {
		return malformed("nil secret")
	}
	if len(s.Values) != len(s.Names) || len(s.Salts) != len(s.Names) {
		return malformed("secret has %d names, %d values, %d salts", len(s.Names), len(s.Values), len(s.Salts))
	}
	if err := checkNames(s.Names); err != nil {
		return err
	}
	for i, salt := range s.Salts {
		if len(salt) != SaltSize {
			return malformed("secret salt %d has length %d, want %d", i, len(salt), SaltSize)
		}
	}
	return nil
}

// Present builds a presentation from an attestation and its secret.
// disclose maps a field name to its Disclosure; names absent from the
// map default to Revealed. Entries of disclose that name no field of the
// transcript are ignored (so one fixed policy map can be applied to
// transcripts with differing header sets).
//
// Present checks that the secret actually opens the attestation (shape,
// leaf count and recomputed root) but does not check the notary signature;
// it returns ErrRootMismatch if the secret belongs to another attestation.
// The presentation does not alias a or s.
func Present(a *Attestation, s *Secret, disclose map[string]Disclosure) (*Presentation, error) {
	if a == nil {
		return nil, malformed("nil attestation")
	}
	if err := checkHeader(&a.Header); err != nil {
		return nil, err
	}
	if len(a.Sig) != ed25519.SignatureSize {
		return nil, malformed("sig has length %d, want %d", len(a.Sig), ed25519.SignatureSize)
	}
	if err := checkSecret(s); err != nil {
		return nil, err
	}
	if uint64(len(s.Names)) != uint64(a.Header.LeafCount) {
		return nil, malformed("secret has %d fields, attestation has %d", len(s.Names), a.Header.LeafCount)
	}
	p := &Presentation{
		Attestation: Attestation{Header: cloneHeader(a.Header), Sig: append([]byte{}, a.Sig...)},
		Leaves:      make([]Leaf, len(s.Names)),
	}
	hashes := make([][hashSize]byte, len(s.Names))
	for i, name := range s.Names {
		d, ok := disclose[name]
		if !ok {
			d = Revealed
		}
		c := valueCommit(s.Salts[i], s.Values[i])
		hashes[i] = leafHash(uint32(i), name, c[:])
		l := Leaf{Name: name, Disclosure: d}
		switch d {
		case Hidden:
			l.Commit = c[:]
		case Revealed:
			l.Value = append([]byte{}, s.Values[i]...)
			l.Salt = append([]byte{}, s.Salts[i]...)
		case Known:
			l.Salt = append([]byte{}, s.Salts[i]...)
		default:
			return nil, malformed("field %q: unknown disclosure %d", name, d)
		}
		p.Leaves[i] = l
	}
	root, _ := merkleRoot(hashes)
	if !bytes.Equal(root[:], a.Header.Root) {
		return nil, fmt.Errorf("%w: secret does not open this attestation", ErrRootMismatch)
	}
	return p, nil
}

func cloneHeader(h Header) Header {
	h.NotaryKey = append([]byte{}, h.NotaryKey...)
	h.ServerSPKI = append([]byte{}, h.ServerSPKI...)
	h.Root = append([]byte{}, h.Root...)
	return h
}

// Validate performs the structural checks of a presentation: version,
// key/digest/salt/commit/signature lengths, LeafCount == len(Leaves) and
// <= MaxLeaves, well-formed unique names, and per-disclosure field
// presence (Hidden: commit only; Revealed: salt, optional value; Known:
// salt only). It performs no cryptographic check. All failures wrap
// ErrMalformed.
func (p *Presentation) Validate() error {
	if p == nil {
		return malformed("nil presentation")
	}
	h := &p.Attestation.Header
	if err := checkHeader(h); err != nil {
		return err
	}
	if len(p.Attestation.Sig) != ed25519.SignatureSize {
		return malformed("sig has length %d, want %d", len(p.Attestation.Sig), ed25519.SignatureSize)
	}
	if len(p.Leaves) == 0 || len(p.Leaves) > MaxLeaves {
		return malformed("%d leaves, want 1..%d", len(p.Leaves), MaxLeaves)
	}
	if uint64(len(p.Leaves)) != uint64(h.LeafCount) {
		return malformed("leaf_count is %d but %d leaves given", h.LeafCount, len(p.Leaves))
	}
	seen := make(map[string]struct{}, len(p.Leaves))
	for i := range p.Leaves {
		l := &p.Leaves[i]
		if !validToken(l.Name, MaxNameLen) {
			return malformed("leaf %d: bad name", i)
		}
		if _, dup := seen[l.Name]; dup {
			return malformed("leaf %d: duplicate name %q", i, l.Name)
		}
		seen[l.Name] = struct{}{}
		switch l.Disclosure {
		case Hidden:
			if len(l.Value) != 0 || len(l.Salt) != 0 {
				return malformed("leaf %d: hidden leaf carries value or salt", i)
			}
			if len(l.Commit) != CommitSize {
				return malformed("leaf %d: commit has length %d, want %d", i, len(l.Commit), CommitSize)
			}
		case Revealed:
			if len(l.Commit) != 0 {
				return malformed("leaf %d: revealed leaf carries commit", i)
			}
			if len(l.Salt) != SaltSize {
				return malformed("leaf %d: salt has length %d, want %d", i, len(l.Salt), SaltSize)
			}
		case Known:
			if len(l.Value) != 0 || len(l.Commit) != 0 {
				return malformed("leaf %d: known leaf carries value or commit", i)
			}
			if len(l.Salt) != SaltSize {
				return malformed("leaf %d: salt has length %d, want %d", i, len(l.Salt), SaltSize)
			}
		default:
			return malformed("leaf %d: unknown disclosure %d", i, l.Disclosure)
		}
	}
	return nil
}

// ProxyVerifier verifies presentations produced by the attesting proxy.
// Checks, in order: structural validity (Presentation.Validate), notary
// key is in trusted, ed25519 signature, recomputed Merkle root ==
// Header.Root.
//
// What a successful Verify does and does not establish:
//
//   - The notary holding Header.NotaryKey signed a commitment to a
//     transcript with exactly the returned Names, in that order, in which
//     every field present in Transcript.Fields has exactly that value.
//   - Disclosure is chosen by the presenter, not the notary: anybody who
//     knows a field's value and salt can present it as Hidden instead. A
//     caller that REQUIRES a field must therefore look it up in
//     Transcript.Fields and treat absence as failure; it must never assume
//     a field is present because an honest prover would have revealed it.
//   - If known contains a name that the presentation opens as Revealed,
//     the revealed value must equal the supplied one (ErrRootMismatch
//     otherwise). Hence for every name in known: if Fields has it, the
//     value is the one the caller supplied. Entries of known naming Hidden
//     or non-existent leaves are ignored.
//   - Freshness (Header.Time), the server identity (ServerName,
//     ServerSPKI) and the meaning of the fields are NOT checked here.
//
// Verify is deterministic, does not consult the clock, the network or any
// global state, never panics on any input, and does not retain or modify
// its arguments. The returned Transcript does not alias p or known.
type ProxyVerifier struct{}

var _ Verifier = ProxyVerifier{}

// Verify implements Verifier.
func (ProxyVerifier) Verify(p *Presentation, trusted []ed25519.PublicKey, known map[string][]byte) (*Transcript, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	h := &p.Attestation.Header

	isTrusted := false
	for _, k := range trusted {
		if len(k) == ed25519.PublicKeySize && bytes.Equal(k, h.NotaryKey) {
			isTrusted = true
			break
		}
	}
	if !isTrusted {
		return nil, ErrUntrustedNotary
	}

	msg := SigningBytes(*h)
	if msg == nil || !ed25519.Verify(ed25519.PublicKey(h.NotaryKey), msg, p.Attestation.Sig) {
		return nil, ErrBadSignature
	}

	tr := &Transcript{
		NotaryKey:  append(ed25519.PublicKey{}, h.NotaryKey...),
		ServerName: h.ServerName,
		ServerSPKI: append([]byte{}, h.ServerSPKI...),
		Time:       h.Time,
		Fields:     make(map[string][]byte, len(p.Leaves)),
		Names:      make([]string, 0, len(p.Leaves)),
	}
	hashes := make([][hashSize]byte, len(p.Leaves))
	for i := range p.Leaves {
		l := &p.Leaves[i]
		var commit []byte
		switch l.Disclosure {
		case Hidden:
			commit = l.Commit
			tr.HiddenNames = append(tr.HiddenNames, l.Name)
		case Revealed:
			if kv, ok := known[l.Name]; ok && !bytes.Equal(kv, l.Value) {
				return nil, fmt.Errorf("%w: revealed value of %q differs from the expected value", ErrRootMismatch, l.Name)
			}
			c := valueCommit(l.Salt, l.Value)
			commit = c[:]
			tr.Fields[l.Name] = append([]byte{}, l.Value...)
		case Known:
			kv, ok := known[l.Name]
			if !ok {
				return nil, fmt.Errorf("%w: %q", ErrMissingKnown, l.Name)
			}
			c := valueCommit(l.Salt, kv)
			commit = c[:]
			tr.Fields[l.Name] = append([]byte{}, kv...)
		default: // unreachable after Validate
			return nil, malformed("leaf %d: unknown disclosure %d", i, l.Disclosure)
		}
		hashes[i] = leafHash(uint32(i), l.Name, commit)
		tr.Names = append(tr.Names, l.Name)
	}
	root, ok := merkleRoot(hashes)
	if !ok || !bytes.Equal(root[:], h.Root) {
		return nil, ErrRootMismatch
	}
	return tr, nil
}

// Encode returns the JSON encoding used inside transactions. It validates
// the presentation first, so that everything Encode emits is accepted by
// DecodePresentation (size permitting).
func (p *Presentation) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, malformed("encode: %v", err)
	}
	if len(b) > MaxPresentationBytes {
		return nil, malformed("encoded presentation is %d bytes, limit %d", len(b), MaxPresentationBytes)
	}
	return b, nil
}

// DecodePresentation parses the JSON encoding of a presentation. It
// rejects inputs larger than MaxPresentationBytes, unknown fields,
// trailing data after the JSON value, and structurally invalid
// presentations (Presentation.Validate). All failures wrap ErrMalformed.
//
// The JSON layer is malleable (whitespace, key order, key case, duplicate
// keys, string escapes); this is harmless because nothing is ever derived
// from the encoded bytes of a presentation: the signature covers
// SigningBytes and the root covers the decoded names and values.
func DecodePresentation(b []byte) (*Presentation, error) {
	if len(b) > MaxPresentationBytes {
		return nil, malformed("presentation is %d bytes, limit %d", len(b), MaxPresentationBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	p := new(Presentation)
	if err := dec.Decode(p); err != nil {
		return nil, malformed("decode: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, malformed("trailing data after presentation")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}
