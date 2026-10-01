package app

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/types"
)

// execCtx is one execution context: a mutable state, an object layer and
// the block the transactions are (or would be) part of. The same executor
// runs in CheckTx, PrepareProposal, ProcessProposal and FinalizeBlock; the
// contexts differ only in which state/layer they operate on. Having ONE
// code path is what makes "the proposer's simulation predicts the
// validators' execution" true by construction.
type execCtx struct {
	mode      execMode
	st        *State
	objs      *objLayer
	height    int64
	blockTime int64 // unix seconds
	hist      []*HistoryEntry
	prevHash  []byte // app hash of the previous block
}

// execMode says which ABCI phase an execution context serves. The state
// machine behaves identically in all modes; the mode exists only for the
// baseline (Config.Baseline), which has to know when a validator is
// forming its vote.
type execMode uint8

const (
	modeCheck execMode = iota
	modePrepare
	modeProcess
	modeFinalize
)

// result is the outcome of executing one transaction.
type result struct {
	code   uint32
	log    string
	events []abci.Event
}

func fail(code uint32, format string, a ...any) result {
	return result{code: code, log: types.CodeName(code) + ": " + fmt.Sprintf(format, a...)}
}

func ev(typ string, kv ...string) abci.Event {
	e := abci.Event{Type: typ}
	for i := 0; i+1 < len(kv); i += 2 {
		e.Attributes = append(e.Attributes, abci.EventAttribute{Key: kv[i], Value: kv[i+1], Index: true})
	}
	return e
}

// exec executes one transaction. On any non-zero code the context is left
// exactly as it was: every handler validates completely before mutating.
func (a *App) exec(c *execCtx, raw []byte) result {
	tx, err := types.DecodeTx(raw)
	if err != nil {
		return fail(types.CodeMalformed, "%v", err)
	}
	if err := a.verifyEnvelope(tx); err != nil {
		return fail(types.CodeBadSignature, "%v", err)
	}
	switch tx.Type {
	case types.TxCreateRepo:
		return a.execCreateRepo(c, tx)
	case types.TxAcceptCommit:
		return a.execAcceptCommit(c, tx)
	case types.TxUpdatePolicy:
		return a.execUpdatePolicy(c, tx)
	case types.TxReviewIntent:
		return a.execReviewIntent(c, tx)
	}
	return fail(types.CodeMalformed, "unknown type")
}

// verifyEnvelope checks the envelope signature, memoising successes by
// transaction ID (the ID covers the signature, so a hit is exact).
func (a *App) verifyEnvelope(tx *types.Tx) error {
	id := tx.ID()
	if a.sigs.seen(id) {
		return nil
	}
	if err := tx.VerifySig(); err != nil {
		return err
	}
	a.sigs.add(id)
	return nil
}

func (a *App) execCreateRepo(c *execCtx, tx *types.Tx) result {
	b, err := tx.CreateRepo()
	if err != nil {
		return fail(types.CodeMalformed, "%v", err)
	}
	if b.ChainID != c.st.ChainID {
		return fail(types.CodeWrongChain, "tx is for chain %q", b.ChainID)
	}
	if _, ok := c.st.Repos[b.Repo]; ok {
		return fail(types.CodeRepoExists, "%s", b.Repo)
	}
	pol := b.Policy
	repo := &Repo{
		ID:            b.Repo,
		Creator:       append([]byte(nil), tx.PubKey...),
		Policy:        &pol,
		PolicyVersion: 1,
		PolicyHash:    pol.Hash(),
		Branches:      map[string]Branch{},
	}
	br := Branch{}
	var entry *HistoryEntry
	var bundle *gitobj.Bundle
	if !b.Genesis.IsZero() {
		bundle, err = gitobj.DecodeBundle(tx.Payload, gitobj.DefaultLimits)
		if err != nil {
			return fail(types.CodeBadBundle, "%v", err)
		}
		store := c.objs.Repo(b.Repo)
		if _, err := gitobj.VerifyClosure(store, bundle, b.Genesis, gitobj.ZeroID, gitobj.DefaultLimits); err != nil {
			return fail(types.CodeBadBundle, "%v", err)
		}
		entry = &HistoryEntry{
			Repo: b.Repo, Branch: b.Branch, Seq: 1,
			Commit: b.Genesis, Height: c.height, BlockTime: c.blockTime,
			TxID: tx.ID(), Submitter: repo.Creator, PolicyVersion: 1,
			BundleDigest: gitobj.SumDigest(tx.Payload),
		}
		br = Branch{Head: b.Genesis, Seq: 1, HistDigest: chainDigest(gitobj.Digest{}, entry)}
	}

	// Commit point: no failure is possible below.
	if bundle != nil {
		mustApply(c.objs.Repo(b.Repo), bundle)
		c.hist = append(c.hist, entry)
		c.st.reputationOf(tx.PubKey, c.height).Accepted++
	}
	repo.Branches[b.Branch] = br
	c.st.Repos[b.Repo] = repo
	return result{events: []abci.Event{ev("dosr.create_repo",
		"repo", b.Repo, "branch", b.Branch, "head", br.Head.String(),
		"policy_hash", repo.PolicyHash.String())}}
}

func (a *App) execAcceptCommit(c *execCtx, tx *types.Tx) result {
	b, err := tx.AcceptCommit()
	if err != nil {
		return fail(types.CodeMalformed, "%v", err)
	}
	if b.ChainID != c.st.ChainID {
		return fail(types.CodeWrongChain, "tx is for chain %q", b.ChainID)
	}
	repo, ok := c.st.Repos[b.Repo]
	if !ok {
		return fail(types.CodeUnknownRepo, "%s", b.Repo)
	}
	br, ok := repo.Branches[b.Branch]
	if !ok {
		return fail(types.CodeUnknownBranch, "%s", b.Branch)
	}
	// Cheap state checks first: a stale transaction costs a validator
	// two map lookups, not a signature verification and a diff.
	if b.PolicyVersion != repo.PolicyVersion {
		return fail(types.CodeStalePolicy, "policy version is %d, tx has %d", repo.PolicyVersion, b.PolicyVersion)
	}
	if br.Head != b.ExpectedHead {
		return fail(types.CodeStaleHead, "head is %s, tx expects %s", br.Head, b.ExpectedHead)
	}

	var nonce []byte
	var intent *Intent
	if repo.Policy.RequireIntent {
		if b.Intent == "" {
			return fail(types.CodeIntentRequired, "policy requires a review intent")
		}
		intent, ok = c.st.Intents[b.Intent]
		if !ok {
			return fail(types.CodeIntentUnknown, "%s", b.Intent)
		}
		if intent.Repo != b.Repo || intent.Branch != b.Branch ||
			intent.Base != b.ExpectedHead || intent.Candidate != b.Candidate {
			return fail(types.CodeIntentMismatch, "intent is for a different change")
		}
		nonce = intent.Nonce
	} else if b.Intent != "" {
		return fail(types.CodeIntentNotEnabled, "policy does not use intents")
	}

	evd, verr := a.evidenceFor(c, tx, b, repo, nonce)
	if verr != nil {
		return fail(verr.code, "%v", verr.err)
	}

	// Freshness, against BFT block time (deterministic; never the local
	// clock). Not applicable to the baseline, which has no receipt.
	if a.cfg.Baseline == nil {
		age := c.blockTime - evd.attestedAt
		if age > repo.Policy.MaxReceiptAgeSec {
			return fail(types.CodeExpired, "receipt is %ds old, policy allows %ds", age, repo.Policy.MaxReceiptAgeSec)
		}
		if -age > repo.Policy.MaxClockSkewSec {
			return fail(types.CodeFromFuture, "receipt is %ds ahead of block time", -age)
		}
	}

	// Commit point: no failure is possible below.
	mustApply(c.objs.Repo(b.Repo), evd.bundle)
	entry := &HistoryEntry{
		Repo: b.Repo, Branch: b.Branch, Seq: br.Seq + 1,
		Commit: b.Candidate, Parent: b.ExpectedHead,
		Height: c.height, BlockTime: c.blockTime, TxID: tx.ID(),
		Submitter:     append([]byte(nil), tx.PubKey...),
		PolicyVersion: repo.PolicyVersion,
		ReceiptHash:   evd.receiptHash, BundleDigest: evd.bundleDigest,
		NotaryKey: evd.notaryKey, Model: evd.model, AttestedAt: evd.attestedAt,
	}
	repo.Branches[b.Branch] = Branch{
		Head:       b.Candidate,
		Seq:        entry.Seq,
		HistDigest: chainDigest(br.HistDigest, entry),
	}
	c.hist = append(c.hist, entry)
	c.st.reputationOf(tx.PubKey, c.height).Accepted++
	// Every outstanding intent of this branch was for the old head.
	c.st.pruneIntents(b.Repo, b.Branch)

	return result{events: []abci.Event{ev("dosr.accept",
		"repo", b.Repo, "branch", b.Branch,
		"head", b.Candidate.String(), "parent", b.ExpectedHead.String(),
		"seq", strconv.FormatUint(entry.Seq, 10),
		"receipt_hash", evd.receiptHash.String())}}
}

// evidenceFor returns the verified evidence of an AcceptCommit, from the
// cache if possible.
func (a *App) evidenceFor(c *execCtx, tx *types.Tx, b *types.AcceptCommitBody, repo *Repo, nonce []byte) (*evidence, *verifyError) {
	if a.cfg.Baseline != nil {
		return a.baselineEvidence(c, tx, b, repo, nonce)
	}
	key := evidenceKey(tx.ID(), repo.PolicyHash, nonce)
	if evd := a.cache.get(key); evd != nil {
		return evd, nil
	}
	start := time.Now()
	before := c.objs.pendingHits
	evd, verr := verifyAccept(c.st.ChainID, tx, b, repo.Policy, repo.PolicyHash, nonce, c.objs.Repo(b.Repo), a.verifier, false)
	a.stats.observeVerify(time.Since(start), verr == nil)
	if verr != nil {
		return nil, verr
	}
	// See design log D3: a success that depended on uncommitted objects
	// is only valid in this context.
	if c.objs.pendingHits == before {
		a.cache.put(key, evd)
	}
	return evd, nil
}

// baselineEvidence is the "every validator reviews itself" baseline used
// by the evaluation. No receipt is checked. When the node forms its vote
// (ProcessProposal) it calls the reviewer on the recomputed request and
// rejects the proposal if the verdict is negative; the verdict is
// memoised per transaction so that a node reviews a transaction once.
// Execution in FinalizeBlock trusts the vote. This is NOT deterministic
// across validators - that is the point of the comparison.
func (a *App) baselineEvidence(c *execCtx, tx *types.Tx, b *types.AcceptCommitBody, repo *Repo, nonce []byte) (*evidence, *verifyError) {
	evd, verr := verifyAccept(c.st.ChainID, tx, b, repo.Policy, repo.PolicyHash, nonce, c.objs.Repo(b.Repo), a.verifier, true)
	if verr != nil {
		return nil, verr
	}
	if c.mode != modeProcess && c.mode != modePrepare {
		return evd, nil
	}
	id := tx.ID()
	a.baselineMu.Lock()
	v, ok := a.baselineVerdicts[id]
	a.baselineMu.Unlock()
	if !ok {
		start := time.Now()
		approve, err := a.cfg.Baseline(evd.reqBody)
		a.stats.observeBaseline(time.Since(start), err)
		if err != nil {
			// A failed call is not a verdict; the validator cannot
			// vote for the block.
			return nil, vfail(types.CodeBadResponse, "baseline review: %v", err)
		}
		v = approve
		a.baselineMu.Lock()
		a.baselineVerdicts[id] = v
		a.baselineMu.Unlock()
	}
	if !v {
		return nil, vfail(types.CodeNotApproved, "this validator's reviewer rejected the change")
	}
	return evd, nil
}

func (a *App) execUpdatePolicy(c *execCtx, tx *types.Tx) result {
	b, err := tx.UpdatePolicy()
	if err != nil {
		return fail(types.CodeMalformed, "%v", err)
	}
	if b.ChainID != c.st.ChainID {
		return fail(types.CodeWrongChain, "tx is for chain %q", b.ChainID)
	}
	repo, ok := c.st.Repos[b.Repo]
	if !ok {
		return fail(types.CodeUnknownRepo, "%s", b.Repo)
	}
	if b.ExpectedVersion != repo.PolicyVersion {
		return fail(types.CodeStalePolicy, "policy version is %d, tx expects %d", repo.PolicyVersion, b.ExpectedVersion)
	}
	newPol := b.Policy
	newHash := newPol.Hash()
	msg := types.PolicyUpdateSigningBytes(b.ChainID, b.Repo, b.ExpectedVersion, newHash)
	// Approvals are sorted and unique (checked structurally), so counting
	// valid ones counts distinct maintainers. The CURRENT policy decides
	// who may approve.
	valid := 0
	for i, ap := range b.Approvals {
		if !repo.Policy.HasMaintainer(ap.PubKey) {
			return fail(types.CodeUnauthorized, "approval %d is not from a maintainer", i)
		}
		if !ed25519.Verify(ed25519.PublicKey(ap.PubKey), msg, ap.Sig) {
			return fail(types.CodeUnauthorized, "approval %d has a bad signature", i)
		}
		valid++
	}
	if valid < repo.Policy.Threshold {
		return fail(types.CodeUnauthorized, "%d approvals, threshold is %d", valid, repo.Policy.Threshold)
	}

	repo.Policy = &newPol
	repo.PolicyHash = newHash
	repo.PolicyVersion++
	// Receipts are bound to the policy hash; intents under the old policy
	// can no longer lead to an accept.
	c.st.pruneIntents(b.Repo, "")
	return result{events: []abci.Event{ev("dosr.update_policy",
		"repo", b.Repo, "version", strconv.FormatUint(repo.PolicyVersion, 10),
		"policy_hash", newHash.String())}}
}

func (a *App) execReviewIntent(c *execCtx, tx *types.Tx) result {
	b, err := tx.ReviewIntent()
	if err != nil {
		return fail(types.CodeMalformed, "%v", err)
	}
	if b.ChainID != c.st.ChainID {
		return fail(types.CodeWrongChain, "tx is for chain %q", b.ChainID)
	}
	repo, ok := c.st.Repos[b.Repo]
	if !ok {
		return fail(types.CodeUnknownRepo, "%s", b.Repo)
	}
	br, ok := repo.Branches[b.Branch]
	if !ok {
		return fail(types.CodeUnknownBranch, "%s", b.Branch)
	}
	if !repo.Policy.RequireIntent {
		return fail(types.CodeIntentNotEnabled, "policy does not use intents")
	}
	if br.Head != b.ExpectedHead {
		return fail(types.CodeStaleHead, "head is %s, intent expects %s", br.Head, b.ExpectedHead)
	}
	id := tx.ID()
	if _, dup := c.st.Intents[id.String()]; dup {
		return fail(types.CodeIntentUsed, "intent already registered")
	}
	ak := attemptKey(b.Repo, b.Branch, b.ExpectedHead, tx.PubKey)
	if c.st.Attempts[ak] >= repo.Policy.MaxAttempts {
		return fail(types.CodeTooManyAttempts, "limit is %d per head", repo.Policy.MaxAttempts)
	}
	in := &Intent{
		ID: id, Repo: b.Repo, Branch: b.Branch,
		Base: b.ExpectedHead, Candidate: b.Candidate,
		Submitter: append([]byte(nil), tx.PubKey...),
		Nonce:     intentNonce(c.st.ChainID, c.height, c.prevHash, id),
		Height:    c.height,
	}
	c.st.Attempts[ak]++
	c.st.Intents[id.String()] = in
	c.st.reputationOf(tx.PubKey, c.height).Intents++
	return result{events: []abci.Event{ev("dosr.intent",
		"id", id.String(), "repo", b.Repo, "branch", b.Branch,
		"candidate", b.Candidate.String(), "nonce", hex.EncodeToString(in.Nonce))}}
}

func mustApply(s gitobj.Store, b *gitobj.Bundle) {
	if err := gitobj.ApplyBundle(s, b); err != nil {
		// The layer's Put cannot fail; anything else is a bug.
		panic("app: apply bundle: " + err.Error())
	}
}

var _ = errors.New
var _ attest.Verifier = attest.ProxyVerifier{}
