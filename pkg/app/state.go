// Package app implements DOSR's replicated state machine as an ABCI 2.0
// application for CometBFT.
package app

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/types"
)

// Branch is the consensus state of one branch.
type Branch struct {
	Head gitobj.ID `json:"head"`
	// Seq is the number of commits accepted on this branch (including
	// a genesis commit).
	Seq uint64 `json:"seq"`
	// HistDigest is a hash chain over the accepted commits, so the
	// constant-size state commits to the whole history.
	HistDigest gitobj.Digest `json:"hist_digest"`
}

// Repo is the consensus state of one repository.
//
// Policy is treated as immutable: an update replaces the pointer. That
// makes State.Clone cheap and safe.
type Repo struct {
	ID            string            `json:"id"`
	Creator       []byte            `json:"creator"`
	Policy        *types.Policy     `json:"policy"`
	PolicyVersion uint64            `json:"policy_version"`
	PolicyHash    types.PolicyHash  `json:"policy_hash"`
	Branches      map[string]Branch `json:"branches"`
}

// Intent is a registered review intent. Intents are immutable; using one
// or moving the branch head deletes it.
type Intent struct {
	ID        types.TxID `json:"id"`
	Repo      string     `json:"repo"`
	Branch    string     `json:"branch"`
	Base      gitobj.ID  `json:"base"`
	Candidate gitobj.ID  `json:"candidate"`
	Submitter []byte     `json:"submitter"`
	Nonce     []byte     `json:"nonce"`
	Height    int64      `json:"height"`
}

// Reputation is the lifetime record of one submitter identity. Unlike
// Intents and Attempts it is NEVER pruned: it is the on-chain evidence
// from which a trust policy (docs/analysis/02_cost.md §8) can compute an
// accepted/attempted ratio per identity. Rejections are not visible
// directly (a refused review never reaches the chain); Intents counts
// every review the identity committed to under a RequireIntent policy,
// so Accepted/Intents is the acceptance ratio where intents are required.
type Reputation struct {
	// Intents is the number of ReviewIntents this identity registered.
	Intents uint64 `json:"intents"`
	// Accepted is the number of commits this identity got accepted
	// (including genesis commits of repositories it created).
	Accepted uint64 `json:"accepted"`
	// FirstHeight is the height of the first transaction that created
	// this record.
	FirstHeight int64 `json:"first_height"`
}

// State is the full replicated state. Everything in it is a deterministic
// function of the sequence of finalized blocks.
type State struct {
	ChainID string `json:"chain_id"`
	Height  int64  `json:"height"`
	// AppHash is the hash of the state after executing block Height.
	AppHash []byte `json:"app_hash"`
	// Repos by ID.
	Repos map[string]*Repo `json:"repos"`
	// Intents by hex ID.
	Intents map[string]*Intent `json:"intents"`
	// Attempts counts ReviewIntents per attemptKey. Entries are pruned
	// together with intents when a branch head or policy changes.
	Attempts map[string]int `json:"attempts"`
	// Reputation by hex submitter public key. Never pruned.
	Reputation map[string]*Reputation `json:"reputation"`
}

// NewState returns an empty state.
func NewState(chainID string) *State {
	return &State{
		ChainID:    chainID,
		Repos:      map[string]*Repo{},
		Intents:    map[string]*Intent{},
		Attempts:   map[string]int{},
		Reputation: map[string]*Reputation{},
	}
}

// Clone returns a copy that can be mutated independently.
func (s *State) Clone() *State {
	c := &State{
		ChainID:    s.ChainID,
		Height:     s.Height,
		AppHash:    append([]byte(nil), s.AppHash...),
		Repos:      make(map[string]*Repo, len(s.Repos)),
		Intents:    make(map[string]*Intent, len(s.Intents)),
		Attempts:   make(map[string]int, len(s.Attempts)),
		Reputation: make(map[string]*Reputation, len(s.Reputation)),
	}
	for k, v := range s.Reputation {
		rc := *v
		c.Reputation[k] = &rc
	}
	for k, r := range s.Repos {
		rc := *r
		rc.Branches = make(map[string]Branch, len(r.Branches))
		for bk, b := range r.Branches {
			rc.Branches[bk] = b
		}
		c.Repos[k] = &rc
	}
	for k, v := range s.Intents {
		c.Intents[k] = v
	}
	for k, v := range s.Attempts {
		c.Attempts[k] = v
	}
	return c
}

// attemptKey identifies what MaxAttempts is counted against: one
// submitter identity on one head state of one branch. '\x00' cannot occur
// in repo IDs or branch names.
func attemptKey(repo, branch string, base gitobj.ID, submitter []byte) string {
	return repo + "\x00" + branch + "\x00" + base.String() + "\x00" + hex.EncodeToString(submitter)
}

// pruneIntents drops all intents and attempt counters of a branch (or of
// the whole repository if branch is empty). Called whenever receipts
// obtained for them can no longer be accepted: the head moved or the
// policy changed. This keeps the state bounded. The result does not
// depend on map iteration order.
func (s *State) pruneIntents(repo, branch string) {
	for k, in := range s.Intents {
		if in.Repo == repo && (branch == "" || in.Branch == branch) {
			delete(s.Intents, k)
		}
	}
	prefix := repo + "\x00"
	if branch != "" {
		prefix += branch + "\x00"
	}
	for k := range s.Attempts {
		if strings.HasPrefix(k, prefix) {
			delete(s.Attempts, k)
		}
	}
}

// reputationOf returns the record of a submitter, creating it (at the
// given height) if absent. Only call after validation: creating the
// record is a mutation.
func (s *State) reputationOf(pubKey []byte, height int64) *Reputation {
	k := hex.EncodeToString(pubKey)
	r, ok := s.Reputation[k]
	if !ok {
		r = &Reputation{FirstHeight: height}
		s.Reputation[k] = r
	}
	return r
}

// hashView is what the app hash commits to. Height and AppHash themselves
// are excluded (CometBFT already chains them through block headers).
type hashView struct {
	ChainID    string                 `json:"chain_id"`
	Repos      map[string]*Repo       `json:"repos"`
	Intents    map[string]*Intent     `json:"intents"`
	Attempts   map[string]int         `json:"attempts"`
	Reputation map[string]*Reputation `json:"reputation"`
}

// ComputeAppHash returns the hash of the state. encoding/json writes
// struct fields in declaration order and map keys in sorted order, so the
// encoding is canonical.
func (s *State) ComputeAppHash() []byte {
	b, err := json.Marshal(hashView{s.ChainID, s.Repos, s.Intents, s.Attempts, s.Reputation})
	if err != nil {
		panic("app: state marshal: " + err.Error())
	}
	h := sha256.Sum256(append([]byte("DOSR-STATE-V1\x00"), b...))
	return h[:]
}

// HistoryEntry records one accepted commit. Entries are stored outside
// State (they grow without bound) and are committed to by
// Branch.HistDigest.
type HistoryEntry struct {
	Repo          string        `json:"repo"`
	Branch        string        `json:"branch"`
	Seq           uint64        `json:"seq"` // 1-based
	Commit        gitobj.ID     `json:"commit"`
	Parent        gitobj.ID     `json:"parent"`
	Height        int64         `json:"height"`
	BlockTime     int64         `json:"block_time"`
	TxID          types.TxID    `json:"tx_id"`
	Submitter     []byte        `json:"submitter"`
	PolicyVersion uint64        `json:"policy_version"`
	ReceiptHash   gitobj.Digest `json:"receipt_hash"` // zero for genesis commits
	BundleDigest  gitobj.Digest `json:"bundle_digest"`
	NotaryKey     []byte        `json:"notary_key,omitempty"`
	Model         string        `json:"model,omitempty"`
	AttestedAt    int64         `json:"attested_at,omitempty"`
}

// chainDigest extends a history hash chain by one entry.
func chainDigest(prev gitobj.Digest, e *HistoryEntry) gitobj.Digest {
	h := sha256.New()
	h.Write([]byte("DOSR-HIST-V1\x00"))
	h.Write(prev[:])
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], e.Seq)
	h.Write(seq[:])
	h.Write(e.Parent[:])
	h.Write(e.Commit[:])
	h.Write(e.ReceiptHash[:])
	h.Write(e.BundleDigest[:])
	h.Write(e.TxID[:])
	var d gitobj.Digest
	h.Sum(d[:0])
	return d
}

// intentNonce derives the nonce of an intent. It depends on the app hash
// of the previous block and on the height at which the intent is
// committed, neither of which the submitter knows when signing the
// intent, so a review request embedding the nonce can only have been made
// after the intent was committed.
func intentNonce(chainID string, height int64, prevAppHash []byte, id types.TxID) []byte {
	h := sha256.New()
	h.Write([]byte("DOSR-NONCE-V1\x00"))
	h.Write([]byte(chainID))
	h.Write([]byte{0})
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], uint64(height))
	h.Write(hb[:])
	h.Write(prevAppHash)
	h.Write(id[:])
	return h.Sum(nil)[:16]
}

// ChainDigest is the exported form of the history hash chain step, for
// auditors and the test harness: starting from the zero digest and
// folding entries 1..Seq must reproduce Branch.HistDigest.
func ChainDigest(prev gitobj.Digest, e *HistoryEntry) gitobj.Digest { return chainDigest(prev, e) }
