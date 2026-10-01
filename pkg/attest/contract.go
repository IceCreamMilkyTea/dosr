// Package attest defines DOSR's attestation and presentation formats and
// their verification.
//
// The format is modelled on TLSNotary's split between an *attestation*
// (what the notary signs: a commitment to the TLS transcript plus the
// server identity and time) and a *presentation* (what the prover shows a
// verifier: the attestation plus a selective opening of the transcript).
//
// TRUST MODEL (important, stated honestly): in this prototype the attestor
// is a trusted proxy that terminates TLS to the LLM provider and therefore
// sees plaintext, including the contributor's API key. In real TLSNotary
// the notary participates in MPC-TLS and never sees plaintext. The
// verifier-facing object and the Verifier interface are the same shape in
// both cases, which is what lets a real TLSNotary backend be swapped in.
//
// This file is the package CONTRACT. Types and signatures here are frozen.
package attest

import (
	"crypto/ed25519"
	"errors"
)

// Version of the attestation format.
const Version = 1

// Field names of the transcript. Header names are lowercase. The set and
// order of fields is fixed by the attestor:
//
//	req.method, req.path, req.header.<name>... (sorted by name), req.body,
//	resp.status, resp.header.<name>... (sorted by name), resp.body
//
// resp.body is the response body after removing transfer/content encoding
// (the attestor requests "accept-encoding: identity").
const (
	FieldReqMethod    = "req.method"
	FieldReqPath      = "req.path"
	FieldReqHeaderPfx = "req.header."
	FieldReqBody      = "req.body"
	FieldRespStatus   = "resp.status"
	FieldRespHeadPfx  = "resp.header."
	FieldRespBody     = "resp.body"
)

// Commitment scheme. For field i with name n_i, value v_i and a fresh
// 16-byte random salt s_i:
//
//	valueCommit_i = SHA256( 0x01 || s_i || v_i )
//	leaf_i        = SHA256( 0x00 || u32be(i) || u32be(len(n_i)) || n_i || valueCommit_i )
//	root          = RFC 6962 Merkle tree hash over leaf_0 .. leaf_{k-1}
//	                (interior nodes: SHA256(0x02 || left || right))
//
// Names are always disclosed; values are hidden behind salted commitments.
// A presentation lists EVERY leaf, so the verifier learns the complete
// shape of the request (no header can be silently hidden) and recomputes
// the root directly.

// Header is the part of an attestation that the notary signs.
type Header struct {
	Version    uint8  `json:"version"`
	NotaryKey  []byte `json:"notary_key"`  // ed25519 public key of the notary
	ServerName string `json:"server_name"` // TLS SNI / verified certificate name
	ServerSPKI []byte `json:"server_spki"` // SHA-256 of the leaf certificate's SubjectPublicKeyInfo
	Time       int64  `json:"time"`        // notary clock, unix seconds, when the response completed
	LeafCount  uint32 `json:"leaf_count"`
	Root       []byte `json:"root"` // 32 bytes
}

// Attestation is a signed Header.
type Attestation struct {
	Header Header `json:"header"`
	// Sig is ed25519 over SigningBytes(Header).
	Sig []byte `json:"sig"`
}

// Disclosure says how a presentation opens one leaf.
type Disclosure uint8

const (
	// Hidden: only the value commitment is given. Used for secrets
	// (API keys). The verifier learns nothing about the value.
	Hidden Disclosure = 0
	// Revealed: value and salt are given.
	Revealed Disclosure = 1
	// Known: only the salt is given; the verifier supplies the value
	// itself. Used for req.body, which every validator recomputes from
	// the Git objects, so the (large) body never travels in transactions.
	Known Disclosure = 2
)

// Leaf is one transcript field as opened in a presentation.
type Leaf struct {
	Name       string     `json:"name"`
	Disclosure Disclosure `json:"disclosure"`
	Value      []byte     `json:"value,omitempty"`  // iff Revealed
	Salt       []byte     `json:"salt,omitempty"`   // iff Revealed or Known
	Commit     []byte     `json:"commit,omitempty"` // iff Hidden: the value commitment
}

// Presentation is what travels inside an AcceptCommit transaction.
type Presentation struct {
	Attestation Attestation `json:"attestation"`
	Leaves      []Leaf      `json:"leaves"`
}

// Secret is the prover-side opening material returned by the attestor:
// the full transcript with salts. It is never sent to validators.
type Secret struct {
	Names  []string `json:"names"`
	Values [][]byte `json:"values"`
	Salts  [][]byte `json:"salts"`
}

// Transcript is the verified view of a presentation.
type Transcript struct {
	NotaryKey  ed25519.PublicKey
	ServerName string
	ServerSPKI []byte
	Time       int64
	// Fields holds the values of Revealed and Known leaves by name.
	Fields map[string][]byte
	// HiddenNames lists the names of Hidden leaves, in transcript order.
	HiddenNames []string
	// Names lists all leaf names in transcript order.
	Names []string
}

// Sentinel errors (wrapped with %w by implementations).
var (
	ErrMalformed       = errors.New("attest: malformed presentation")
	ErrUntrustedNotary = errors.New("attest: notary key not trusted")
	ErrBadSignature    = errors.New("attest: bad notary signature")
	ErrRootMismatch    = errors.New("attest: transcript root mismatch")
	ErrMissingKnown    = errors.New("attest: value for known leaf not supplied")
)

// Verifier abstracts the proof system. The prototype implements it with
// ProxyVerifier; a TLSNotary presentation verifier would implement the
// same interface.
type Verifier interface {
	// Verify checks the presentation against the set of trusted notary
	// keys and returns the verified transcript. known supplies values for
	// leaves with Disclosure == Known, by name.
	//
	// Verify MUST be deterministic and MUST NOT consult the clock or the
	// network; freshness is checked by the caller against block time.
	Verify(p *Presentation, trusted []ed25519.PublicKey, known map[string][]byte) (*Transcript, error)
}

/*
Implemented in the other files of this package:

	// SigningBytes is the canonical byte string the notary signs:
	//   "DOSR-ATTEST-V1\x00" | version u8 | u16be(len)+NotaryKey |
	//   u16be(len)+ServerName | u16be(len)+ServerSPKI | i64be Time |
	//   u32be LeafCount | Root(32)
	func SigningBytes(h Header) []byte

	// Build commits to the transcript fields (names/values in transcript
	// order) with fresh salts from rnd, and signs the attestation.
	func Build(priv ed25519.PrivateKey, serverName string, serverSPKI []byte, t int64,
		names []string, values [][]byte, rnd io.Reader) (*Attestation, *Secret, error)

	// Present builds a presentation from an attestation and its secret.
	// disclose maps a field name to its Disclosure; names absent from the
	// map default to Revealed.
	func Present(a *Attestation, s *Secret, disclose map[string]Disclosure) (*Presentation, error)

	// ProxyVerifier verifies presentations produced by the attesting proxy.
	// Checks, in order: structural validity (version, key/salt/commit
	// lengths, LeafCount == len(Leaves) and <= MaxLeaves, unique names,
	// per-disclosure field presence), notary key is in trusted, ed25519
	// signature, recomputed Merkle root == Header.Root.
	type ProxyVerifier struct{}

	const MaxLeaves = 256

	// (*Presentation).Encode / DecodePresentation: JSON encoding used
	// inside transactions. DecodePresentation uses DisallowUnknownFields
	// and rejects trailing data.
	func (p *Presentation) Encode() ([]byte, error)
	func DecodePresentation(b []byte) (*Presentation, error)
*/
