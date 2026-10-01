// Package client implements the contributor side of DOSR: turning a local
// commit into an accepted commit on the chain.
//
//  1. read the repository's policy and head from a node
//  2. extract the bundle head..candidate and rebuild the review request
//     exactly as validators will
//  3. (if the policy requires it) register a review intent and wait for
//     its nonce
//  4. have the attestor perform the LLM call and attest it
//  5. open the attestation with the API key hidden, sign the
//     AcceptCommit transaction, broadcast it
//  6. wait until the transaction is decided
//
// Every step is timed; the Timeline is the raw material of the latency
// evaluation.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	rpcclient "github.com/cometbft/cometbft/rpc/client"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/notary"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/types"
)

// AnthropicVersion is the API version the client sends; validators
// require exactly this value.
const AnthropicVersion = app.AnthropicVersion

// Client is a contributor.
type Client struct {
	// RPC is a CometBFT RPC client of any node (HTTP or local).
	RPC rpcclient.Client
	// Notary is the attestor to use; its key must be in the policy.
	Notary *notary.Client
	// Key signs transactions.
	Key ed25519.PrivateKey
	// APIKey is the contributor's LLM API key. It is sent to the
	// attestor and nowhere else.
	APIKey string
	// ChainID of the chain.
	ChainID string
	// Model to request; empty means the first model of the policy.
	Model string
	// PollInterval for waiting on the chain (default 20ms).
	PollInterval time.Duration
	// Scheme of the provider URL (default "https").
	Scheme string
	// NoReceipt submits AcceptCommits without a review (for the
	// evaluation's "every validator reviews" baseline, where validators
	// ignore receipts). Notary and APIKey are not used.
	NoReceipt bool
}

// Change is what a contributor wants accepted.
type Change struct {
	Repo, Branch string
	// Base must be the current head; Candidate its direct child.
	Base, Candidate gitobj.ID
	Bundle          *gitobj.Bundle
	// Objects must contain the objects of Base (the contributor's
	// repository).
	Objects gitobj.Store
}

// Timeline holds the duration of each phase of a submission.
type Timeline struct {
	// Prepare: closure check, tree diff, rendering the request.
	Prepare time.Duration `json:"prepare_ns"`
	// Intent: registering the review intent and waiting for its commit
	// (zero if the policy does not require intents).
	Intent time.Duration `json:"intent_ns"`
	// Attest: the whole attestor call as seen by the client.
	Attest time.Duration `json:"attest_ns"`
	// Upstream: the LLM call as measured by the attestor.
	Upstream time.Duration `json:"upstream_ns"`
	// AttestOverhead: commitment + signature (+ nonce reservation) as
	// measured by the attestor.
	AttestOverhead time.Duration `json:"attest_overhead_ns"`
	// Present: opening the attestation, encoding and signing the tx.
	Present time.Duration `json:"present_ns"`
	// Admit: broadcast until CheckTx answered.
	Admit time.Duration `json:"admit_ns"`
	// Commit: from CheckTx's answer until the transaction is visible as
	// decided at the node the client talks to.
	Commit time.Duration `json:"commit_ns"`
	// Total: from the start of Submit to the decision.
	Total time.Duration `json:"total_ns"`
}

// Outcome of a submission.
type Outcome struct {
	// Code is the result code of the AcceptCommit (types.Code*).
	Code uint32 `json:"code"`
	Log  string `json:"log"`
	// Height at which the transaction was decided (0 if it never was).
	Height int64  `json:"height"`
	TxID   string `json:"tx_id"`
	// TxBytes, BundleBytes, RequestBytes, ReceiptBytes are sizes.
	TxBytes      int `json:"tx_bytes"`
	BundleBytes  int `json:"bundle_bytes"`
	RequestBytes int `json:"request_bytes"`
	ReceiptBytes int `json:"receipt_bytes"`
	// Reviewed reports whether an LLM call was made (and paid for).
	Reviewed bool `json:"reviewed"`
	// Approved reports the model's verdict (valid if Reviewed).
	Approved bool     `json:"approved"`
	Summary  string   `json:"summary,omitempty"`
	Timeline Timeline `json:"timeline"`
	// DecidedAt is the client's wall clock when it learned the decision.
	DecidedAt time.Time `json:"decided_at"`
}

// Errors returned by Submit. In all these cases Outcome is still returned
// and tells how far the submission got.
var (
	// ErrStale: the branch head is not (or no longer) Change.Base.
	ErrStale = errors.New("client: branch head moved; rebase and resubmit")
	// ErrRejected: the model rejected the change. Nothing was submitted.
	ErrRejected = errors.New("client: the reviewer rejected the change")
	// ErrNotAdmitted: CheckTx refused the transaction.
	ErrNotAdmitted = errors.New("client: transaction not admitted to the mempool")
	// ErrFailed: the transaction was decided with a failure code.
	ErrFailed = errors.New("client: transaction failed")
	// ErrBadReview: the provider's answer was not a usable verdict.
	ErrBadReview = errors.New("client: unusable review response")
)

func (c *Client) poll() time.Duration {
	if c.PollInterval > 0 {
		return c.PollInterval
	}
	return 20 * time.Millisecond
}

// query runs an ABCI query and decodes the JSON answer into v.
func (c *Client) query(ctx context.Context, path string, v any) (bool, error) {
	res, err := c.RPC.ABCIQuery(ctx, path, nil)
	if err != nil {
		return false, err
	}
	if res.Response.Code != 0 {
		return false, nil
	}
	return true, json.Unmarshal(res.Response.Value, v)
}

// Repo fetches the state of a repository.
func (c *Client) Repo(ctx context.Context, repo string) (*app.Repo, error) {
	var r app.Repo
	ok, err := c.query(ctx, "/repo/"+repo, &r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("client: repository %q not found", repo)
	}
	return &r, nil
}

// Head fetches the head of a branch.
func (c *Client) Head(ctx context.Context, repo, branch string) (gitobj.ID, error) {
	var b app.Branch
	ok, err := c.query(ctx, "/head/"+repo+"/"+branch, &b)
	if err != nil {
		return gitobj.ZeroID, err
	}
	if !ok {
		return gitobj.ZeroID, fmt.Errorf("client: branch %s/%s not found", repo, branch)
	}
	return b.Head, nil
}

// Submit runs the whole workflow for one change.
func (c *Client) Submit(ctx context.Context, ch Change) (*Outcome, error) {
	start := time.Now()
	out := &Outcome{}
	done := func(err error) (*Outcome, error) {
		out.Timeline.Total = time.Since(start)
		out.DecidedAt = time.Now()
		return out, err
	}

	repo, err := c.Repo(ctx, ch.Repo)
	if err != nil {
		return done(err)
	}
	br, ok := repo.Branches[ch.Branch]
	if !ok {
		return done(fmt.Errorf("client: branch %s/%s not found", ch.Repo, ch.Branch))
	}
	if br.Head != ch.Base {
		return done(ErrStale)
	}
	pol := repo.Policy
	model := c.Model
	if model == "" {
		model = pol.Models[0]
	}

	// Prepare: do exactly what validators will do, so that errors show
	// up here and not after the review has been paid for.
	t := time.Now()
	lim := gitobj.DefaultLimits
	payload := ch.Bundle.Encode()
	out.BundleBytes = len(payload)
	commit, err := gitobj.VerifyClosure(ch.Objects, ch.Bundle, ch.Candidate, ch.Base, lim)
	if err != nil {
		return done(fmt.Errorf("client: %w", err))
	}
	view := gitobj.NewOverlay(ch.Objects, ch.Bundle)
	var oldTree gitobj.ID
	if !ch.Base.IsZero() {
		bo, err := ch.Objects.Get(ch.Base)
		if err != nil {
			return done(fmt.Errorf("client: base commit: %w", err))
		}
		bc, err := gitobj.ParseCommit(bo.Data)
		if err != nil {
			return done(fmt.Errorf("client: base commit: %w", err))
		}
		oldTree = bc.Tree
	}
	changes, err := gitobj.DiffTrees(view, oldTree, commit.Tree, lim)
	if err != nil {
		return done(fmt.Errorf("client: %w", err))
	}
	params := review.Params{
		ChainID: c.ChainID, RepoID: ch.Repo, Branch: ch.Branch,
		Base: ch.Base, Candidate: ch.Candidate,
		PolicyHash: repo.PolicyHash, Model: model,
	}
	build := func() ([]byte, error) {
		return review.BuildRequestBody(pol, params, commit.Message, changes, view)
	}
	body, err := build()
	if err != nil {
		return done(fmt.Errorf("client: %w", err))
	}
	out.Timeline.Prepare = time.Since(t)

	// Intent.
	intentID := ""
	if pol.RequireIntent {
		t = time.Now()
		itx, err := types.SignTx(c.Key, types.TxReviewIntent, types.ReviewIntentBody{
			ChainID: c.ChainID, Repo: ch.Repo, Branch: ch.Branch,
			ExpectedHead: ch.Base, Candidate: ch.Candidate,
		}, nil)
		if err != nil {
			return done(err)
		}
		code, log, _, err := c.broadcastAndWait(ctx, itx, ch, nil)
		if err != nil {
			return done(err)
		}
		if code != types.CodeOK {
			out.Code, out.Log = code, log
			if code == types.CodeStaleHead {
				return done(ErrStale)
			}
			return done(fmt.Errorf("%w: intent: %s", ErrFailed, log))
		}
		var in app.Intent
		ok, err := c.query(ctx, "/intent/"+itx.ID().String(), &in)
		if err != nil {
			return done(err)
		}
		if !ok {
			// The head moved between the intent's commit and our
			// query; intents of the old head are pruned.
			return done(ErrStale)
		}
		intentID = itx.ID().String()
		params.Nonce = in.Nonce
		if body, err = build(); err != nil {
			return done(fmt.Errorf("client: %w", err))
		}
		out.Timeline.Intent = time.Since(t)
	}
	out.RequestBytes = len(body)

	// Review, attested.
	var receipt json.RawMessage
	if c.NoReceipt {
		receipt = json.RawMessage("null")
	} else {
		t = time.Now()
		scheme := c.Scheme
		if scheme == "" {
			scheme = "https"
		}
		ares, err := c.Notary.AttestTimed(ctx, &notary.Request{
			URL:    scheme + "://" + pol.ProviderHost + pol.ProviderPath,
			Method: "POST",
			Headers: map[string]string{
				"content-type":      "application/json",
				"anthropic-version": AnthropicVersion,
				"x-api-key":         c.APIKey,
			},
			Body: body,
		})
		out.Timeline.Attest = time.Since(t)
		if err != nil {
			return done(fmt.Errorf("client: attest: %w", err))
		}
		out.Reviewed = true
		out.Timeline.Upstream = time.Duration(ares.Timing.UpstreamNs)
		out.Timeline.AttestOverhead = time.Duration(ares.Timing.TotalNs - ares.Timing.UpstreamNs)

		// Look at the verdict before spending anybody's resources on it.
		var status, respBody []byte
		for i, n := range ares.Secret.Names {
			switch n {
			case "resp.status":
				status = ares.Secret.Values[i]
			case "resp.body":
				respBody = ares.Secret.Values[i]
			}
		}
		if string(status) != "200" {
			return done(fmt.Errorf("%w: provider status %s: %s", ErrBadReview, status, truncate(respBody, 200)))
		}
		v, err := review.ParseResponse(respBody)
		if err != nil {
			return done(fmt.Errorf("%w: %v", ErrBadReview, err))
		}
		out.Approved, out.Summary = v.Approve, truncate([]byte(v.Summary), 400)
		if !v.Approve {
			return done(ErrRejected)
		}
		t = time.Now()
		pres, err := notary.BuildPresentation(ares.Attestation, ares.Secret)
		if err != nil {
			return done(err)
		}
		if receipt, err = pres.Encode(); err != nil {
			return done(err)
		}
		out.Timeline.Present = time.Since(t)
	}

	// Sign.
	t = time.Now()
	out.ReceiptBytes = len(receipt)
	tx, err := types.SignTx(c.Key, types.TxAcceptCommit, types.AcceptCommitBody{
		ChainID: c.ChainID, Repo: ch.Repo, Branch: ch.Branch,
		ExpectedHead: ch.Base, Candidate: ch.Candidate,
		PolicyVersion: repo.PolicyVersion, Model: model,
		Intent: intentID, Receipt: receipt,
	}, payload)
	if err != nil {
		return done(err)
	}
	out.TxBytes = len(tx.Bytes())
	out.TxID = tx.ID().String()
	out.Timeline.Present += time.Since(t)

	code, log, height, err := c.broadcastAndWait(ctx, tx, ch, &out.Timeline)
	out.Code, out.Log, out.Height = code, log, height
	if err != nil {
		return done(err)
	}
	if code == types.CodeStaleHead {
		return done(ErrStale)
	}
	if code != types.CodeOK {
		return done(fmt.Errorf("%w: %s", ErrFailed, log))
	}
	return done(nil)
}

// broadcastAndWait submits a transaction and waits until it is decided,
// or until it can no longer be decided successfully because the head
// moved to something else.
func (c *Client) broadcastAndWait(ctx context.Context, tx *types.Tx, ch Change, tl *Timeline) (uint32, string, int64, error) {
	t := time.Now()
	res, err := c.RPC.BroadcastTxSync(ctx, tx.Bytes())
	if err != nil {
		// "tx already exists in cache" is CometBFT's answer to a
		// duplicate; the original may still be decided.
		if !strings.Contains(err.Error(), "already exists") {
			return 0, "", 0, fmt.Errorf("client: broadcast: %w", err)
		}
	} else if res.Code != 0 {
		if tl != nil {
			tl.Admit = time.Since(t)
		}
		if res.Code == types.CodeStaleHead {
			// The mempool already holds a competing transaction for
			// this head (the node's check state has moved on) while
			// the chain's head has not. Re-reviewing now would be
			// wasted money: any new transaction would be stale in
			// the same way. Wait until the head actually moves.
			c.waitHeadMoves(ctx, ch)
			return res.Code, res.Log, 0, nil
		}
		return res.Code, res.Log, 0, fmt.Errorf("%w: %s", ErrNotAdmitted, res.Log)
	}
	if tl != nil {
		tl.Admit = time.Since(t)
	}
	t = time.Now()
	id := tx.ID()
	tick := time.NewTicker(c.poll())
	defer tick.Stop()
	for {
		r, err := c.RPC.Tx(ctx, id[:], false)
		if err == nil {
			if tl != nil {
				tl.Commit = time.Since(t)
			}
			return r.TxResult.Code, r.TxResult.Log, r.Height, nil
		}
		// Not decided. If the head moved away, an honest proposer
		// will never include the transaction.
		if head, herr := c.Head(ctx, ch.Repo, ch.Branch); herr == nil && head != ch.Base {
			// The decision and the transaction index are updated
			// separately, so the index can lag the head by a
			// moment: give it a little time before concluding.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if r, err := c.RPC.Tx(ctx, id[:], false); err == nil {
					if tl != nil {
						tl.Commit = time.Since(t)
					}
					return r.TxResult.Code, r.TxResult.Log, r.Height, nil
				}
				time.Sleep(c.poll())
			}
			if tl != nil {
				tl.Commit = time.Since(t)
			}
			if tx.Type == types.TxAcceptCommit && head == ch.Candidate {
				// Someone else submitted the same change.
				return types.CodeOK, "accepted via another transaction", 0, nil
			}
			return types.CodeStaleHead, "head moved to " + head.String(), 0, nil
		}
		select {
		case <-ctx.Done():
			return 0, "", 0, fmt.Errorf("client: waiting for decision: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

// waitHeadMoves blocks until the branch head differs from ch.Base, or
// the context ends, or a generous bound elapses (the competing
// transaction may itself fail; then the caller's retry will succeed).
func (c *Client) waitHeadMoves(ctx context.Context, ch Change) {
	deadline := time.Now().Add(30 * time.Second)
	tick := time.NewTicker(c.poll())
	defer tick.Stop()
	for time.Now().Before(deadline) {
		if head, err := c.Head(ctx, ch.Repo, ch.Branch); err == nil && head != ch.Base {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// CreateRepo creates a repository with an optional genesis commit and
// waits for the decision.
func (c *Client) CreateRepo(ctx context.Context, repo, branch string, pol types.Policy,
	genesis gitobj.ID, bundle *gitobj.Bundle) (uint32, string, error) {
	var payload []byte
	if bundle != nil {
		payload = bundle.Encode()
	}
	tx, err := types.SignTx(c.Key, types.TxCreateRepo, types.CreateRepoBody{
		ChainID: c.ChainID, Repo: repo, Branch: branch, Policy: pol, Genesis: genesis,
	}, payload)
	if err != nil {
		return 0, "", err
	}
	res, err := c.RPC.BroadcastTxSync(ctx, tx.Bytes())
	if err != nil {
		return 0, "", err
	}
	if res.Code != 0 {
		return res.Code, res.Log, nil
	}
	id := tx.ID()
	tick := time.NewTicker(c.poll())
	defer tick.Stop()
	for {
		if r, err := c.RPC.Tx(ctx, id[:], false); err == nil {
			return r.TxResult.Code, r.TxResult.Log, nil
		}
		select {
		case <-ctx.Done():
			return 0, "", ctx.Err()
		case <-tick.C:
		}
	}
}

var _ = hex.EncodeToString
