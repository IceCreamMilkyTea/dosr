package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dosr/dosr/pkg/gitobj"
)

// TxType identifies a transaction kind.
type TxType uint8

const (
	TxCreateRepo   TxType = 1
	TxAcceptCommit TxType = 2
	TxUpdatePolicy TxType = 3
	TxReviewIntent TxType = 4
)

func (t TxType) String() string {
	switch t {
	case TxCreateRepo:
		return "CreateRepo"
	case TxAcceptCommit:
		return "AcceptCommit"
	case TxUpdatePolicy:
		return "UpdatePolicy"
	case TxReviewIntent:
		return "ReviewIntent"
	}
	return fmt.Sprintf("TxType(%d)", uint8(t))
}

// Wire format of a transaction (all integers big-endian):
//
//	magic   "DOSR"            4 bytes
//	version 0x01              1 byte
//	type    TxType            1 byte
//	blen    uint32            length of body
//	body    JSON              type-specific, see *Body structs
//	plen    uint32            length of payload
//	payload bytes             opaque (a Git bundle, or empty)
//	pubkey  ed25519 key       32 bytes
//	sig     ed25519 signature 64 bytes over "DOSR-TX-V1\x00" || all preceding bytes
//
// The signature covers the *bytes*, so verification never depends on
// re-serialising JSON. The body is decoded strictly (unknown fields and
// trailing data are rejected); that is a hygiene measure, not what
// signature security rests on.
//
// The payload is kept outside the JSON body so that bundles are not
// base64-inflated and can be hashed without parsing.
const (
	txMagic       = "DOSR"
	txVersion     = 1
	txHeaderLen   = 4 + 1 + 1 + 4
	txTrailerLen  = ed25519.PublicKeySize + ed25519.SignatureSize
	txSigContext  = "DOSR-TX-V1\x00"
	MaxBodyBytes  = 1 << 20 // presentations carry the LLM response
	MaxTxBytes    = 8 << 20 // hard cap; chain params may set a lower one
	MinTxBytes    = txHeaderLen + 4 + txTrailerLen
	maxPayloadLen = MaxTxBytes
)

// Tx is a decoded transaction envelope.
type Tx struct {
	Type    TxType
	Body    []byte // raw JSON
	Payload []byte
	PubKey  ed25519.PublicKey
	Sig     []byte

	raw []byte // the exact wire bytes, set by DecodeTx / Sign
}

// ID is the SHA-256 of the wire bytes.
type TxID [32]byte

func (id TxID) String() string { return hex.EncodeToString(id[:]) }

// Sentinel errors.
var (
	ErrTxMalformed = errors.New("tx: malformed")
	ErrTxSignature = errors.New("tx: bad signature")
)

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrTxMalformed, fmt.Sprintf(format, a...))
}

// SignTx builds and signs a transaction.
func SignTx(priv ed25519.PrivateKey, typ TxType, body any, payload []byte) (*Tx, error) {
	bj, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(bj) > MaxBodyBytes {
		return nil, malformed("body too large: %d", len(bj))
	}
	pub := priv.Public().(ed25519.PublicKey)
	n := txHeaderLen + len(bj) + 4 + len(payload) + txTrailerLen
	if n > MaxTxBytes {
		return nil, malformed("tx too large: %d", n)
	}
	raw := make([]byte, 0, n)
	raw = append(raw, txMagic...)
	raw = append(raw, txVersion, byte(typ))
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(bj)))
	raw = append(raw, bj...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(payload)))
	raw = append(raw, payload...)
	raw = append(raw, pub...)
	sig := ed25519.Sign(priv, signingBytes(raw))
	raw = append(raw, sig...)
	return DecodeTx(raw)
}

func signingBytes(prefix []byte) []byte {
	b := make([]byte, 0, len(txSigContext)+len(prefix))
	b = append(b, txSigContext...)
	return append(b, prefix...)
}

// DecodeTx parses the envelope. It does NOT verify the signature (see
// VerifySig) and does not interpret the body. The returned Tx aliases raw.
func DecodeTx(raw []byte) (*Tx, error) {
	if len(raw) < MinTxBytes {
		return nil, malformed("too short")
	}
	if len(raw) > MaxTxBytes {
		return nil, malformed("too large")
	}
	if string(raw[:4]) != txMagic {
		return nil, malformed("bad magic")
	}
	if raw[4] != txVersion {
		return nil, malformed("unsupported version %d", raw[4])
	}
	t := &Tx{Type: TxType(raw[5]), raw: raw}
	switch t.Type {
	case TxCreateRepo, TxAcceptCommit, TxUpdatePolicy, TxReviewIntent:
	default:
		return nil, malformed("unknown type %d", raw[5])
	}
	rest := raw[6:]
	blen := int(binary.BigEndian.Uint32(rest))
	rest = rest[4:]
	if blen > MaxBodyBytes || blen > len(rest) {
		return nil, malformed("bad body length")
	}
	t.Body, rest = rest[:blen], rest[blen:]
	if len(rest) < 4 {
		return nil, malformed("truncated")
	}
	plen := int(binary.BigEndian.Uint32(rest))
	rest = rest[4:]
	if plen > maxPayloadLen || plen > len(rest) {
		return nil, malformed("bad payload length")
	}
	t.Payload, rest = rest[:plen], rest[plen:]
	if len(rest) != txTrailerLen {
		return nil, malformed("bad trailer length %d", len(rest))
	}
	t.PubKey = ed25519.PublicKey(rest[:ed25519.PublicKeySize])
	t.Sig = rest[ed25519.PublicKeySize:]
	return t, nil
}

// Bytes returns the wire encoding.
func (t *Tx) Bytes() []byte { return t.raw }

// ID returns the transaction ID.
func (t *Tx) ID() TxID { return sha256.Sum256(t.raw) }

// VerifySig checks the envelope signature.
func (t *Tx) VerifySig() error {
	signed := t.raw[:len(t.raw)-ed25519.SignatureSize]
	if !ed25519.Verify(t.PubKey, signingBytes(signed), t.Sig) {
		return ErrTxSignature
	}
	return nil
}

// decodeBody strictly decodes the JSON body into v.
func (t *Tx) decodeBody(v any) error {
	dec := json.NewDecoder(bytes.NewReader(t.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return malformed("body: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return malformed("body: trailing data")
	}
	return nil
}

// CreateRepoBody creates a repository. If Genesis is non-zero the payload
// is the bundle of a root commit (no parents) which becomes the initial
// head of Branch without an LLM receipt: the creator vouches for it.
type CreateRepoBody struct {
	ChainID string    `json:"chain_id"`
	Repo    string    `json:"repo"`
	Branch  string    `json:"branch"`
	Policy  Policy    `json:"policy"`
	Genesis gitobj.ID `json:"genesis"`
}

// AcceptCommitBody proposes to advance Branch from ExpectedHead to
// Candidate. The payload is the bundle of Candidate on top of
// ExpectedHead.
type AcceptCommitBody struct {
	ChainID      string    `json:"chain_id"`
	Repo         string    `json:"repo"`
	Branch       string    `json:"branch"`
	ExpectedHead gitobj.ID `json:"expected_head"`
	Candidate    gitobj.ID `json:"candidate"`
	// PolicyVersion is the version the receipt was obtained under. It is
	// redundant with the policy hash bound inside the review request but
	// lets a node reject stale transactions without any crypto.
	PolicyVersion uint64 `json:"policy_version"`
	// Model is the model the contributor requested.
	Model string `json:"model"`
	// Intent is the ID of the ReviewIntent this receipt answers (hex,
	// empty unless the policy requires intents).
	Intent string `json:"intent,omitempty"`
	// Receipt is an encoded attest.Presentation.
	Receipt json.RawMessage `json:"receipt"`
}

// PolicyApproval is one maintainer's signature on a policy update.
type PolicyApproval struct {
	PubKey []byte `json:"pubkey"`
	Sig    []byte `json:"sig"`
}

// UpdatePolicyBody replaces the repository policy. Approvals must contain
// valid signatures of at least Threshold distinct maintainers OF THE
// CURRENT POLICY over PolicyUpdateSigningBytes.
type UpdatePolicyBody struct {
	ChainID         string           `json:"chain_id"`
	Repo            string           `json:"repo"`
	ExpectedVersion uint64           `json:"expected_version"`
	Policy          Policy           `json:"policy"`
	Approvals       []PolicyApproval `json:"approvals"`
}

// PolicyUpdateSigningBytes is what maintainers sign to approve replacing
// the policy at version expectedVersion with one hashing to newHash.
func PolicyUpdateSigningBytes(chainID, repo string, expectedVersion uint64, newHash PolicyHash) []byte {
	var b []byte
	b = append(b, "DOSR-POLICY-UPDATE-V1\x00"...)
	b = appendLP(b, []byte(chainID))
	b = appendLP(b, []byte(repo))
	b = binary.BigEndian.AppendUint64(b, expectedVersion)
	return append(b, newHash[:]...)
}

// ReviewIntentBody registers the intent to obtain one review of Candidate
// on top of ExpectedHead. See docs/DESIGN.md (approval grinding).
type ReviewIntentBody struct {
	ChainID      string    `json:"chain_id"`
	Repo         string    `json:"repo"`
	Branch       string    `json:"branch"`
	ExpectedHead gitobj.ID `json:"expected_head"`
	Candidate    gitobj.ID `json:"candidate"`
}

func appendLP(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

const maxChainIDLen = 50 // CometBFT's MaxChainIDLen

func checkCommon(chainID, repo, branch string, needBranch bool) error {
	if chainID == "" || len(chainID) > maxChainIDLen {
		return malformed("bad chain_id")
	}
	if !ValidRepoID(repo) {
		return malformed("bad repo id")
	}
	if needBranch && !ValidBranch(branch) {
		return malformed("bad branch")
	}
	return nil
}

// CreateRepo decodes and structurally validates a CreateRepo body.
func (t *Tx) CreateRepo() (*CreateRepoBody, error) {
	if t.Type != TxCreateRepo {
		return nil, malformed("not a CreateRepo")
	}
	var b CreateRepoBody
	if err := t.decodeBody(&b); err != nil {
		return nil, err
	}
	if err := checkCommon(b.ChainID, b.Repo, b.Branch, true); err != nil {
		return nil, err
	}
	if err := b.Policy.Validate(); err != nil {
		return nil, malformed("%v", err)
	}
	if b.Genesis.IsZero() != (len(t.Payload) == 0) {
		return nil, malformed("payload must be present iff genesis is set")
	}
	return &b, nil
}

// AcceptCommit decodes and structurally validates an AcceptCommit body.
func (t *Tx) AcceptCommit() (*AcceptCommitBody, error) {
	if t.Type != TxAcceptCommit {
		return nil, malformed("not an AcceptCommit")
	}
	var b AcceptCommitBody
	if err := t.decodeBody(&b); err != nil {
		return nil, err
	}
	if err := checkCommon(b.ChainID, b.Repo, b.Branch, true); err != nil {
		return nil, err
	}
	if b.Candidate.IsZero() {
		return nil, malformed("zero candidate")
	}
	if b.Candidate == b.ExpectedHead {
		return nil, malformed("candidate equals expected head")
	}
	if b.Model == "" || len(b.Model) > 128 {
		return nil, malformed("bad model")
	}
	if b.Intent != "" {
		if _, err := ParseTxID(b.Intent); err != nil {
			return nil, malformed("bad intent id")
		}
	}
	if len(b.Receipt) == 0 {
		return nil, malformed("missing receipt")
	}
	if len(t.Payload) == 0 {
		return nil, malformed("missing bundle")
	}
	return &b, nil
}

// UpdatePolicy decodes and structurally validates an UpdatePolicy body.
func (t *Tx) UpdatePolicy() (*UpdatePolicyBody, error) {
	if t.Type != TxUpdatePolicy {
		return nil, malformed("not an UpdatePolicy")
	}
	var b UpdatePolicyBody
	if err := t.decodeBody(&b); err != nil {
		return nil, err
	}
	if err := checkCommon(b.ChainID, b.Repo, "", false); err != nil {
		return nil, err
	}
	if err := b.Policy.Validate(); err != nil {
		return nil, malformed("%v", err)
	}
	if len(b.Approvals) == 0 || len(b.Approvals) > 64 {
		return nil, malformed("need 1..64 approvals")
	}
	for i, a := range b.Approvals {
		if len(a.PubKey) != ed25519.PublicKeySize || len(a.Sig) != ed25519.SignatureSize {
			return nil, malformed("approval %d: bad lengths", i)
		}
		// Sorted + unique so that "count distinct signers" is trivial
		// and the encoding of a given approval set is unique.
		if i > 0 && bytes.Compare(b.Approvals[i-1].PubKey, a.PubKey) >= 0 {
			return nil, malformed("approvals must be sorted by pubkey and unique")
		}
	}
	if len(t.Payload) != 0 {
		return nil, malformed("unexpected payload")
	}
	return &b, nil
}

// ReviewIntent decodes and structurally validates a ReviewIntent body.
func (t *Tx) ReviewIntent() (*ReviewIntentBody, error) {
	if t.Type != TxReviewIntent {
		return nil, malformed("not a ReviewIntent")
	}
	var b ReviewIntentBody
	if err := t.decodeBody(&b); err != nil {
		return nil, err
	}
	if err := checkCommon(b.ChainID, b.Repo, b.Branch, true); err != nil {
		return nil, err
	}
	if b.Candidate.IsZero() || b.Candidate == b.ExpectedHead {
		return nil, malformed("bad candidate")
	}
	if len(t.Payload) != 0 {
		return nil, malformed("unexpected payload")
	}
	return &b, nil
}

// ParseTxID parses a 64-character lowercase hex transaction ID.
func ParseTxID(s string) (TxID, error) {
	var id TxID
	if len(s) != 64 {
		return id, errors.New("tx id: bad length")
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return id, errors.New("tx id: must be lowercase hex")
		}
	}
	_, err := hex.Decode(id[:], []byte(s))
	return id, err
}

// MarshalText/UnmarshalText make TxID encode as hex in JSON.
func (id TxID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id *TxID) UnmarshalText(b []byte) error {
	p, err := ParseTxID(string(b))
	if err != nil {
		return err
	}
	*id = p
	return nil
}
