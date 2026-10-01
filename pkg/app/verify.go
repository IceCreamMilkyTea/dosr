package app

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/types"
)

// AnthropicVersion is the API version header value reviews must use.
const AnthropicVersion = "2023-06-01"

// allowedReqHeaders is the complete set of request headers a review
// request may carry, with the value each must have ("" = any value).
//
// WHY AN ALLOW-LIST: the presentation discloses the names of all request
// headers, so validators see the full shape of the API call. Headers can
// change what the provider does (beta features, model fallbacks, ...), so
// anything not known to be harmless is rejected rather than ignored.
var allowedReqHeaders = map[string]string{
	"host":              "", // checked against the policy separately
	"content-type":      "application/json",
	"content-length":    "", // implied by the body, which is bound exactly
	"accept-encoding":   "identity",
	"anthropic-version": AnthropicVersion,
	"x-api-key":         "", // hidden
	"user-agent":        "",
	"connection":        "",
}

// hideableReqHeaders may be hidden in a presentation. Everything else
// must be revealed.
var hideableReqHeaders = map[string]bool{"x-api-key": true}

// evidence is the outcome of successfully verifying the bundle and the
// receipt of an AcceptCommit. It contains everything execution needs, so
// a cached evidence makes re-execution of the transaction cheap.
type evidence struct {
	bundle       *gitobj.Bundle
	bundleDigest gitobj.Digest
	receiptHash  gitobj.Digest
	attestedAt   int64
	notaryKey    []byte
	model        string
	requestBytes int
	changes      int
	// reqBody is kept only in baseline mode (see Config.Baseline).
	reqBody []byte
}

// verifyError carries the result code of a failed verification.
type verifyError struct {
	code uint32
	err  error
}

func (e *verifyError) Error() string { return e.err.Error() }

func vfail(code uint32, format string, a ...any) *verifyError {
	return &verifyError{code, fmt.Errorf(format, a...)}
}

// verifyAccept checks the evidence of an AcceptCommit against a policy
// and the objects of the base: the bundle must be exactly the closure of
// the candidate over the expected head, and the receipt must attest that
// the policy's provider approved the review request that THIS NODE
// derives from those objects.
//
// It is a pure function of (tx, policy, nonce, the objects reachable from
// the expected head): no clock, no network, no state besides `base`.
// Freshness is checked by the caller because it depends on block time.
//
// skipReceipt implements the "every validator reviews" baseline: the
// bundle and request are verified, but no receipt is checked; the caller
// obtains the verdict itself.
func verifyAccept(chainID string, tx *types.Tx, b *types.AcceptCommitBody,
	pol *types.Policy, polHash types.PolicyHash, nonce []byte,
	base gitobj.Store, ver attest.Verifier, skipReceipt bool) (*evidence, *verifyError) {

	// 1. Bundle: decode strictly, verify closure over the expected head.
	lim := gitobj.DefaultLimits
	bundle, err := gitobj.DecodeBundle(tx.Payload, lim)
	if err != nil {
		return nil, vfail(types.CodeBadBundle, "bundle: %v", err)
	}
	commit, err := gitobj.VerifyClosure(base, bundle, b.Candidate, b.ExpectedHead, lim)
	if err != nil {
		return nil, vfail(types.CodeBadBundle, "bundle: %v", err)
	}

	// 2. Recompute the review request from the objects.
	view := gitobj.NewOverlay(base, bundle)
	var oldTree gitobj.ID
	if !b.ExpectedHead.IsZero() {
		po, err := base.Get(b.ExpectedHead)
		if err != nil || po.Type != gitobj.TypeCommit {
			return nil, vfail(types.CodeBadBundle, "expected head is not a commit in the store")
		}
		pc, err := gitobj.ParseCommit(po.Data)
		if err != nil {
			return nil, vfail(types.CodeBadBundle, "expected head: %v", err)
		}
		oldTree = pc.Tree
	}
	changes, err := gitobj.DiffTrees(view, oldTree, commit.Tree, lim)
	if err != nil {
		return nil, vfail(types.CodeBadBundle, "diff: %v", err)
	}
	if !pol.HasModel(b.Model) {
		return nil, vfail(types.CodeWrongModel, "requested model %q not allowed", b.Model)
	}
	reqBody, err := review.BuildRequestBody(pol, review.Params{
		ChainID:    chainID,
		RepoID:     b.Repo,
		Branch:     b.Branch,
		Base:       b.ExpectedHead,
		Candidate:  b.Candidate,
		PolicyHash: polHash,
		Model:      b.Model,
		Nonce:      nonce,
	}, commit.Message, changes, view)
	if err != nil {
		if errors.Is(err, review.ErrTooLarge) || errors.Is(err, review.ErrOpaque) || errors.Is(err, review.ErrEmptyDiff) {
			return nil, vfail(types.CodeUnreviewable, "%v", err)
		}
		return nil, vfail(types.CodeBadBundle, "review request: %v", err)
	}

	if skipReceipt {
		return &evidence{
			bundle:       bundle,
			bundleDigest: gitobj.SumDigest(tx.Payload),
			model:        b.Model,
			requestBytes: len(reqBody),
			changes:      len(changes),
			reqBody:      reqBody,
		}, nil
	}

	// 3. Receipt: the attested transcript must commit to exactly that
	// request body (supplied by us as the "known" leaf).
	pres, err := attest.DecodePresentation(b.Receipt)
	if err != nil {
		return nil, vfail(types.CodeBadReceipt, "receipt: %v", err)
	}
	tr, err := ver.Verify(pres, pol.NotaryKeys(), map[string][]byte{attest.FieldReqBody: reqBody})
	if err != nil {
		return nil, vfail(types.CodeBadReceipt, "receipt: %v", err)
	}
	if verr := checkTranscript(tr, pol, reqBody); verr != nil {
		return nil, verr
	}

	// 4. Response: status 200 and an approving verdict for this candidate
	// from an allowed model.
	if s := string(tr.Fields[attest.FieldRespStatus]); s != "200" {
		return nil, vfail(types.CodeBadResponse, "provider status %q", s)
	}
	v, err := review.ParseResponse(tr.Fields[attest.FieldRespBody])
	if err != nil {
		return nil, vfail(types.CodeBadResponse, "%v", err)
	}
	if !pol.HasModel(v.Model) {
		return nil, vfail(types.CodeWrongModel, "responding model %q not allowed", v.Model)
	}
	if v.Candidate != b.Candidate {
		return nil, vfail(types.CodeWrongBinding, "verdict is for %s", v.Candidate)
	}
	if !v.Approve {
		return nil, vfail(types.CodeNotApproved, "model rejected the change")
	}

	return &evidence{
		bundle:       bundle,
		bundleDigest: gitobj.SumDigest(tx.Payload),
		receiptHash:  gitobj.SumDigest(b.Receipt),
		attestedAt:   tr.Time,
		notaryKey:    append([]byte(nil), tr.NotaryKey...),
		model:        v.Model,
		requestBytes: len(reqBody),
		changes:      len(changes),
	}, nil
}

// checkTranscript enforces the provider binding of the policy on a
// verified transcript.
func checkTranscript(tr *attest.Transcript, pol *types.Policy, reqBody []byte) *verifyError {
	host := pol.ProviderHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if tr.ServerName != host {
		return vfail(types.CodeWrongProvider, "server name %q, policy requires %q", tr.ServerName, host)
	}
	if !pol.SPKIAllowed(tr.ServerSPKI) {
		return vfail(types.CodeWrongProvider, "server key not pinned by policy")
	}
	hidden := map[string]bool{}
	for _, n := range tr.HiddenNames {
		hidden[n] = true
	}
	seenMethod, seenPath, seenBody, seenStatus, seenRespBody := false, false, false, false, false
	for _, n := range tr.Names {
		switch {
		case n == attest.FieldReqMethod:
			seenMethod = true
		case n == attest.FieldReqPath:
			seenPath = true
		case n == attest.FieldReqBody:
			seenBody = true
		case n == attest.FieldRespStatus:
			seenStatus = true
		case n == attest.FieldRespBody:
			seenRespBody = true
		case strings.HasPrefix(n, attest.FieldReqHeaderPfx):
			name := strings.TrimPrefix(n, attest.FieldReqHeaderPfx)
			want, ok := allowedReqHeaders[name]
			if !ok {
				return vfail(types.CodeWrongProvider, "request header %q not allowed", name)
			}
			if hidden[n] {
				if !hideableReqHeaders[name] {
					return vfail(types.CodeWrongProvider, "request header %q must be revealed", name)
				}
				continue
			}
			val := string(tr.Fields[n])
			if want != "" && val != want {
				return vfail(types.CodeWrongProvider, "request header %q has value %q", name, val)
			}
			if name == "host" && val != pol.ProviderHost {
				return vfail(types.CodeWrongProvider, "host header %q", val)
			}
		case strings.HasPrefix(n, attest.FieldRespHeadPfx):
			// Response headers carry no authority in DOSR.
		default:
			return vfail(types.CodeBadReceipt, "unknown transcript field %q", n)
		}
		if hidden[n] && !strings.HasPrefix(n, attest.FieldReqHeaderPfx) && !strings.HasPrefix(n, attest.FieldRespHeadPfx) {
			return vfail(types.CodeBadReceipt, "field %q must not be hidden", n)
		}
	}
	if !(seenMethod && seenPath && seenBody && seenStatus && seenRespBody) {
		return vfail(types.CodeBadReceipt, "transcript is missing mandatory fields")
	}
	if m := string(tr.Fields[attest.FieldReqMethod]); m != "POST" {
		return vfail(types.CodeWrongProvider, "method %q", m)
	}
	if p := string(tr.Fields[attest.FieldReqPath]); p != pol.ProviderPath {
		return vfail(types.CodeWrongProvider, "path %q", p)
	}
	// Defence in depth: the verifier already bound the body through the
	// commitment of the Known leaf.
	if !bytes.Equal(tr.Fields[attest.FieldReqBody], reqBody) {
		return vfail(types.CodeBadReceipt, "request body not bound")
	}
	return nil
}

// evidenceCache memoises SUCCESSFUL evidence verification.
//
// A transaction is verified up to three times per node (CheckTx,
// PrepareProposal/ProcessProposal, FinalizeBlock) and again on every
// mempool recheck. Verification is a pure function of the key below and
// of the objects reachable from the expected head, and the object store
// only ever grows, so a success stays a success. Failures are NOT cached:
// a closure that is incomplete now may become complete when the store
// grows, and caching it could make this node disagree with a node that
// verifies later. The cache never changes any result; it only avoids
// recomputing one.
type evidenceCache struct {
	mu   sync.Mutex
	max  int
	ll   *list.List
	m    map[[32]byte]*list.Element
	hits uint64
	miss uint64
}

type cacheEntry struct {
	key [32]byte
	ev  *evidence
}

func newEvidenceCache(max int) *evidenceCache {
	return &evidenceCache{max: max, ll: list.New(), m: map[[32]byte]*list.Element{}}
}

func evidenceKey(txID types.TxID, polHash types.PolicyHash, nonce []byte) [32]byte {
	h := sha256.New()
	h.Write(txID[:])
	h.Write(polHash[:])
	h.Write(nonce)
	var k [32]byte
	h.Sum(k[:0])
	return k
}

func (c *evidenceCache) get(k [32]byte) *evidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		c.hits++
		return e.Value.(*cacheEntry).ev
	}
	c.miss++
	return nil
}

func (c *evidenceCache) put(k [32]byte, ev *evidence) {
	if c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&cacheEntry{k, ev})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*cacheEntry).key)
	}
}
