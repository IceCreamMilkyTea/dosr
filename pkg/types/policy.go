// Package types defines DOSR's on-chain data model: repository policies,
// transactions and result codes.
package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Policy is a repository's review policy. It is set at repository creation
// and changed only by UpdatePolicy transactions authorised by a threshold
// of maintainers. Receipts are bound to the hash of the policy they were
// obtained under, so changing the policy invalidates in-flight receipts.
type Policy struct {
	// Provider identifies the LLM API endpoint reviews must come from.
	ProviderHost string `json:"provider_host"` // e.g. "api.anthropic.com"
	ProviderPath string `json:"provider_path"` // e.g. "/v1/messages"
	// ProviderSPKI optionally pins the provider's leaf certificate keys
	// (SHA-256 of SubjectPublicKeyInfo). Empty means "any key the notary
	// validated for ProviderHost".
	ProviderSPKI [][]byte `json:"provider_spki,omitempty"`
	// Models is the allow-list of model identifiers. The model requested
	// AND the model reported in the response must both be in this list.
	Models []string `json:"models"`
	// SystemPrompt is the review instruction given to the model.
	SystemPrompt string `json:"system_prompt"`
	// MaxTokens is the max_tokens value of the review request.
	MaxTokens int `json:"max_tokens"`
	// Notaries are the ed25519 public keys of trusted attestors.
	Notaries [][]byte `json:"notaries"`
	// MaxReceiptAgeSec bounds block_time - attestation_time.
	MaxReceiptAgeSec int64 `json:"max_receipt_age_sec"`
	// MaxClockSkewSec bounds attestation_time - block_time.
	MaxClockSkewSec int64 `json:"max_clock_skew_sec"`
	// MaxDiffBytes bounds the rendered review text.
	MaxDiffBytes int `json:"max_diff_bytes"`
	// AllowOpaque permits changes whose content cannot be shown to the
	// model (binary or oversized files). If false such commits are
	// rejected outright.
	AllowOpaque bool `json:"allow_opaque"`
	// RequireIntent makes AcceptCommit require a previously committed
	// ReviewIntent whose chain-derived nonce is embedded in the review
	// request (anti-grinding, see docs/DESIGN.md).
	RequireIntent bool `json:"require_intent"`
	// MaxAttempts bounds the number of ReviewIntents per
	// (expected head, candidate) pair when RequireIntent is set.
	MaxAttempts int `json:"max_attempts"`
	// Maintainers may update the policy; Threshold of them must sign.
	Maintainers [][]byte `json:"maintainers"`
	Threshold   int      `json:"threshold"`
}

// PolicyHash is the SHA-256 of a policy's canonical encoding.
type PolicyHash [32]byte

var repoIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var branchRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)

// ValidRepoID reports whether s is a syntactically valid repository ID.
func ValidRepoID(s string) bool { return repoIDRe.MatchString(s) }

// ValidBranch reports whether s is a syntactically valid branch name.
func ValidBranch(s string) bool { return branchRe.MatchString(s) }

// Canonical returns the canonical encoding of the policy. Go's
// encoding/json is deterministic for structs (fields in declaration order,
// []byte as base64), and Validate guarantees that the slices which are
// semantically sets are sorted and duplicate-free, so equal policies have
// equal encodings.
func (p *Policy) Canonical() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		panic("types: policy marshal: " + err.Error()) // no unmarshalable fields
	}
	return b
}

// Hash returns the policy hash.
func (p *Policy) Hash() PolicyHash {
	return sha256.Sum256(append([]byte("DOSR-POLICY-V1\x00"), p.Canonical()...))
}

// Validate checks structural validity. It is deterministic.
func (p *Policy) Validate() error {
	if !hostRe.MatchString(p.ProviderHost) {
		return errors.New("policy: bad provider_host")
	}
	// The attested host header is canonical (default port omitted); a
	// policy naming ":443" could never be satisfied.
	if strings.HasSuffix(p.ProviderHost, ":443") {
		return errors.New("policy: provider_host must omit the default port 443")
	}
	if len(p.ProviderPath) == 0 || p.ProviderPath[0] != '/' || len(p.ProviderPath) > 256 {
		return errors.New("policy: bad provider_path")
	}
	if err := sortedUniqueKeys(p.ProviderSPKI, sha256.Size, 0, 16, "provider_spki"); err != nil {
		return err
	}
	if len(p.Models) == 0 || len(p.Models) > 16 {
		return errors.New("policy: need 1..16 models")
	}
	if !sort.StringsAreSorted(p.Models) {
		return errors.New("policy: models must be sorted")
	}
	for i, m := range p.Models {
		if m == "" || len(m) > 128 || !printableASCII(m) {
			return errors.New("policy: bad model name")
		}
		if i > 0 && p.Models[i-1] == m {
			return errors.New("policy: duplicate model")
		}
	}
	if len(p.SystemPrompt) == 0 || len(p.SystemPrompt) > 16<<10 {
		return errors.New("policy: system_prompt must be 1..16384 bytes")
	}
	// encoding/json replaces invalid UTF-8 by U+FFFD when marshalling, so
	// two different byte strings would share a canonical encoding - and a
	// policy hash. Only valid UTF-8 without NUL is a policy.
	if !utf8.ValidString(p.SystemPrompt) || strings.ContainsRune(p.SystemPrompt, 0) {
		return errors.New("policy: system_prompt must be valid UTF-8 without NUL")
	}
	if !printableASCII(p.ProviderPath) {
		return errors.New("policy: bad provider_path")
	}
	if p.MaxTokens < 16 || p.MaxTokens > 1<<16 {
		return errors.New("policy: bad max_tokens")
	}
	if err := sortedUniqueKeys(p.Notaries, ed25519.PublicKeySize, 1, 16, "notaries"); err != nil {
		return err
	}
	if p.MaxReceiptAgeSec <= 0 || p.MaxReceiptAgeSec > 30*24*3600 {
		return errors.New("policy: bad max_receipt_age_sec")
	}
	if p.MaxClockSkewSec < 0 || p.MaxClockSkewSec > 3600 {
		return errors.New("policy: bad max_clock_skew_sec")
	}
	if p.MaxDiffBytes < 1024 || p.MaxDiffBytes > 8<<20 {
		return errors.New("policy: bad max_diff_bytes")
	}
	if p.RequireIntent && (p.MaxAttempts < 1 || p.MaxAttempts > 1000) {
		return errors.New("policy: require_intent needs 1 <= max_attempts <= 1000")
	}
	if !p.RequireIntent && p.MaxAttempts != 0 {
		return errors.New("policy: max_attempts set without require_intent")
	}
	if err := sortedUniqueKeys(p.Maintainers, ed25519.PublicKeySize, 1, 64, "maintainers"); err != nil {
		return err
	}
	if p.Threshold < 1 || p.Threshold > len(p.Maintainers) {
		return errors.New("policy: bad threshold")
	}
	return nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func sortedUniqueKeys(keys [][]byte, size, min, max int, what string) error {
	if len(keys) < min || len(keys) > max {
		return fmt.Errorf("policy: need %d..%d %s", min, max, what)
	}
	for i, k := range keys {
		if len(k) != size {
			return fmt.Errorf("policy: %s[%d] has length %d, want %d", what, i, len(k), size)
		}
		if i > 0 && bytes.Compare(keys[i-1], k) >= 0 {
			return fmt.Errorf("policy: %s must be sorted and unique", what)
		}
	}
	return nil
}

// SortKeys sorts a key list in place into the order Validate requires.
func SortKeys(keys [][]byte) {
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
}

// HasModel reports whether m is in the allow-list.
func (p *Policy) HasModel(m string) bool {
	i := sort.SearchStrings(p.Models, m)
	return i < len(p.Models) && p.Models[i] == m
}

// HasNotary reports whether k is a trusted notary key.
func (p *Policy) HasNotary(k []byte) bool { return containsKey(p.Notaries, k) }

// HasMaintainer reports whether k is a maintainer key.
func (p *Policy) HasMaintainer(k []byte) bool { return containsKey(p.Maintainers, k) }

// SPKIAllowed reports whether the provider key pin set admits spki.
func (p *Policy) SPKIAllowed(spki []byte) bool {
	return len(p.ProviderSPKI) == 0 || containsKey(p.ProviderSPKI, spki)
}

func containsKey(keys [][]byte, k []byte) bool {
	for _, x := range keys {
		if bytes.Equal(x, k) {
			return true
		}
	}
	return false
}

// NotaryKeys returns the trusted notary keys as ed25519 public keys.
func (p *Policy) NotaryKeys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, len(p.Notaries))
	for i, k := range p.Notaries {
		out[i] = ed25519.PublicKey(k)
	}
	return out
}

func (h PolicyHash) String() string { return hex.EncodeToString(h[:]) }

// MarshalText/UnmarshalText make PolicyHash encode as hex in JSON.
func (h PolicyHash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }
func (h *PolicyHash) UnmarshalText(b []byte) error {
	if len(b) != 64 {
		return errors.New("policy hash: bad length")
	}
	_, err := hex.Decode(h[:], b)
	return err
}
