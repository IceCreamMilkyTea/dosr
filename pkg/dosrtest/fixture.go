// Package dosrtest builds DOSR test worlds entirely in memory: Git
// histories, bundles, review requests, attested receipts and signed
// transactions, without any network. It plays the roles of contributor,
// LLM provider and notary at once, which lets tests produce both honest
// and precisely-malformed evidence.
package dosrtest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/types"
)

// DetRand is a deterministic io.Reader (SHA-256 in counter mode) used to
// derive keys and salts so that test worlds are reproducible from a seed.
type DetRand struct {
	seed [32]byte
	ctr  uint64
	buf  []byte
}

// NewDetRand returns a deterministic reader for a seed string.
func NewDetRand(seed string) *DetRand {
	return &DetRand{seed: sha256.Sum256([]byte(seed))}
}

func (r *DetRand) Read(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			h := sha256.Sum256(append(r.seed[:], c[:]...))
			r.buf = h[:]
		}
		k := copy(p, r.buf)
		p, r.buf = p[k:], r.buf[k:]
	}
	return n, nil
}

// Key derives an ed25519 key from a label.
func Key(label string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("dosrtest-key:" + label))
	return ed25519.NewKeyFromSeed(s[:])
}

// Pub returns the public key bytes of a private key.
func Pub(k ed25519.PrivateKey) []byte {
	return []byte(k.Public().(ed25519.PublicKey))
}

// World is a test universe: one chain, one notary, a set of maintainers.
type World struct {
	ChainID     string
	Notary      ed25519.PrivateKey
	Maintainers []ed25519.PrivateKey
	Host        string
	Model       string
	Rand        io.Reader
	// Now is the notary's clock (unix seconds) used for attestations.
	Now int64
}

// NewWorld returns a world with 3 maintainers (threshold 2 in the default
// policy).
func NewWorld(chainID string) *World {
	return &World{
		ChainID:     chainID,
		Notary:      Key("notary"),
		Maintainers: []ed25519.PrivateKey{Key("m0"), Key("m1"), Key("m2")},
		Host:        "api.llm.test",
		Model:       "mock-reviewer-1",
		Rand:        NewDetRand("world:" + chainID),
		Now:         1_790_000_000,
	}
}

// Policy returns the world's default policy.
func (w *World) Policy() types.Policy {
	var ms [][]byte
	for _, k := range w.Maintainers {
		ms = append(ms, Pub(k))
	}
	types.SortKeys(ms)
	return types.Policy{
		ProviderHost:     w.Host,
		ProviderPath:     "/v1/messages",
		Models:           []string{w.Model},
		SystemPrompt:     "You are a strict code reviewer. Approve only changes that are safe.",
		MaxTokens:        1024,
		Notaries:         [][]byte{Pub(w.Notary)},
		MaxReceiptAgeSec: 3600,
		MaxClockSkewSec:  30,
		MaxDiffBytes:     1 << 20,
		Maintainers:      ms,
		Threshold:        2,
	}
}

// Repo is a contributor-side Git repository held in memory.
type Repo struct {
	Store *gitobj.MemStore
	clock int64
}

// NewRepo returns an empty repository.
func NewRepo() *Repo { return &Repo{Store: gitobj.NewMemStore(), clock: 1_700_000_000} }

// Files maps slash-separated paths to contents.
type Files map[string]string

// Commit creates a commit with the given complete file set on top of
// parent (zero for a root commit) and returns its ID and the bundle of
// objects that are new relative to parent.
func (r *Repo) Commit(parent gitobj.ID, files Files, msg string) (gitobj.ID, *gitobj.Bundle) {
	r.clock++
	return r.CommitAt(parent, files, msg, r.clock)
}

// CommitAt is Commit with an explicit timestamp (to make distinct commits
// with identical content, or identical commits).
func (r *Repo) CommitAt(parent gitobj.ID, files Files, msg string, ts int64) (gitobj.ID, *gitobj.Bundle) {
	tree := r.writeTree(files, "")
	var sb strings.Builder
	fmt.Fprintf(&sb, "tree %s\n", tree)
	if !parent.IsZero() {
		fmt.Fprintf(&sb, "parent %s\n", parent)
	}
	fmt.Fprintf(&sb, "author Test <test@dosr.test> %d +0000\n", ts)
	fmt.Fprintf(&sb, "committer Test <test@dosr.test> %d +0000\n", ts)
	sb.WriteString("\n" + msg + "\n")
	id := r.put(gitobj.Object{Type: gitobj.TypeCommit, Data: []byte(sb.String())})
	return id, r.Bundle(parent, id)
}

func (r *Repo) put(o gitobj.Object) gitobj.ID {
	id, err := r.Store.Put(o)
	if err != nil {
		panic(err)
	}
	return id
}

func (r *Repo) writeTree(files Files, prefix string) gitobj.ID {
	type dir struct{ files Files }
	blobs := map[string]string{}
	dirs := map[string]Files{}
	for p, c := range files {
		if i := strings.IndexByte(p, '/'); i >= 0 {
			d := p[:i]
			if dirs[d] == nil {
				dirs[d] = Files{}
			}
			dirs[d][p[i+1:]] = c
		} else {
			blobs[p] = c
		}
	}
	var es []gitobj.TreeEntry
	for n, c := range blobs {
		id := r.put(gitobj.Object{Type: gitobj.TypeBlob, Data: []byte(c)})
		es = append(es, gitobj.TreeEntry{Mode: gitobj.ModeFile, Name: n, ID: id})
	}
	for n, f := range dirs {
		es = append(es, gitobj.TreeEntry{Mode: gitobj.ModeDir, Name: n, ID: r.writeTree(f, prefix+n+"/")})
	}
	gitobj.SortEntries(es)
	return r.put(gitobj.Object{Type: gitobj.TypeTree, Data: gitobj.EncodeTree(es)})
}

// reach adds everything reachable from id to set.
func (r *Repo) reach(id gitobj.ID, set map[gitobj.ID]bool, stopAtParents bool) {
	if id.IsZero() || set[id] {
		return
	}
	o, err := r.Store.Get(id)
	if err != nil {
		panic(err)
	}
	set[id] = true
	switch o.Type {
	case gitobj.TypeCommit:
		c, err := gitobj.ParseCommit(o.Data)
		if err != nil {
			panic(err)
		}
		r.reach(c.Tree, set, stopAtParents)
		if !stopAtParents {
			for _, p := range c.Parents {
				r.reach(p, set, false)
			}
		}
	case gitobj.TypeTree:
		es, err := gitobj.ParseTree(o.Data)
		if err != nil {
			panic(err)
		}
		for _, e := range es {
			r.reach(e.ID, set, stopAtParents)
		}
	}
}

// Bundle returns the objects reachable from commit but not from base
// (what `git rev-list --objects commit ^base` selects).
func (r *Repo) Bundle(base, commit gitobj.ID) *gitobj.Bundle {
	old := map[gitobj.ID]bool{}
	r.reach(base, old, false)
	cur := map[gitobj.ID]bool{}
	r.reach(commit, cur, true)
	var ids []gitobj.ID
	for id := range cur {
		if !old[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return string(ids[i][:]) < string(ids[j][:]) })
	b := &gitobj.Bundle{}
	for _, id := range ids {
		o, _ := r.Store.Get(id)
		b.Objects = append(b.Objects, o)
	}
	return b
}

// Review describes one review to fabricate. The zero values of the
// optional fields produce an honest, approving receipt.
type Review struct {
	Repo, Branch    string
	Base, Candidate gitobj.ID
	Bundle          *gitobj.Bundle
	Policy          types.Policy
	PolicyVersion   uint64
	Nonce           []byte
	Intent          string

	// Deviations, for negative tests.
	Reject        bool                     // the model rejects
	Notary        ed25519.PrivateKey       // sign with another notary key
	Time          int64                    // attestation time (default World.Now)
	Status        string                   // HTTP status (default "200")
	RespModel     string                   // model named in the response
	RespCandidate *gitobj.ID               // candidate echoed by the model
	StopReason    string                   // default "tool_use"
	ServerName    string                   // default host of the policy
	Path          string                   // default policy path
	ExtraHeaders  map[string]string        // additional request headers
	MutateBody    func(body []byte) []byte // alter the request body the "provider" saw
	RawResponse   []byte                   // use this response body verbatim
	Disclose      map[string]attest.Disclosure
	ReqModel      string // model in tx and request (default World.Model)
}

// Receipt fabricates the attested receipt for a review. base must hold
// the objects of rv.Base (the validator's view).
func (w *World) Receipt(rv Review, base gitobj.Store) (json.RawMessage, error) {
	model := rv.ReqModel
	if model == "" {
		model = w.Model
	}
	view := gitobj.NewOverlay(base, rv.Bundle)
	co, err := view.Get(rv.Candidate)
	if err != nil {
		return nil, err
	}
	cc, err := gitobj.ParseCommit(co.Data)
	if err != nil {
		return nil, err
	}
	var oldTree gitobj.ID
	if !rv.Base.IsZero() {
		bo, err := view.Get(rv.Base)
		if err != nil {
			return nil, err
		}
		bc, err := gitobj.ParseCommit(bo.Data)
		if err != nil {
			return nil, err
		}
		oldTree = bc.Tree
	}
	changes, err := gitobj.DiffTrees(view, oldTree, cc.Tree, gitobj.DefaultLimits)
	if err != nil {
		return nil, err
	}
	pol := rv.Policy
	body, err := review.BuildRequestBody(&pol, review.Params{
		ChainID: w.ChainID, RepoID: rv.Repo, Branch: rv.Branch,
		Base: rv.Base, Candidate: rv.Candidate, PolicyHash: pol.Hash(),
		Model: model, Nonce: rv.Nonce,
	}, cc.Message, changes, view)
	if err != nil {
		return nil, err
	}
	if rv.MutateBody != nil {
		body = rv.MutateBody(body)
	}

	resp := rv.RawResponse
	if resp == nil {
		verdict := "approve"
		if rv.Reject {
			verdict = "reject"
		}
		cand := rv.Candidate
		if rv.RespCandidate != nil {
			cand = *rv.RespCandidate
		}
		rm := rv.RespModel
		if rm == "" {
			rm = model
		}
		stop := rv.StopReason
		if stop == "" {
			stop = "tool_use"
		}
		resp, _ = json.Marshal(map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant", "model": rm,
			"content": []any{map[string]any{
				"type": "tool_use", "id": "toolu_test", "name": review.ToolName,
				"input": map[string]any{"verdict": verdict, "candidate": cand.String(), "summary": "fabricated by dosrtest"},
			}},
			"stop_reason": stop, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": len(body) / 4, "output_tokens": 50},
		})
	}

	host := pol.ProviderHost
	server := rv.ServerName
	if server == "" {
		server = host
		if i := strings.LastIndexByte(server, ':'); i >= 0 {
			server = server[:i]
		}
	}
	path := rv.Path
	if path == "" {
		path = pol.ProviderPath
	}
	status := rv.Status
	if status == "" {
		status = "200"
	}
	hdr := map[string]string{
		"accept-encoding":   "identity",
		"anthropic-version": "2023-06-01",
		"content-length":    strconv.Itoa(len(body)),
		"content-type":      "application/json",
		"host":              host,
		"x-api-key":         "sk-test-SECRET-KEY-MUST-NOT-LEAK",
	}
	for k, v := range rv.ExtraHeaders {
		hdr[k] = v
	}
	var hn []string
	for k := range hdr {
		hn = append(hn, k)
	}
	sort.Strings(hn)
	names := []string{attest.FieldReqMethod, attest.FieldReqPath}
	values := [][]byte{[]byte("POST"), []byte(path)}
	for _, k := range hn {
		names = append(names, attest.FieldReqHeaderPfx+k)
		values = append(values, []byte(hdr[k]))
	}
	names = append(names, attest.FieldReqBody, attest.FieldRespStatus,
		attest.FieldRespHeadPfx+"content-type", attest.FieldRespBody)
	values = append(values, body, []byte(status), []byte("application/json"), resp)

	key := rv.Notary
	if key == nil {
		key = w.Notary
	}
	ts := rv.Time
	if ts == 0 {
		ts = w.Now
	}
	spki := sha256.Sum256([]byte("spki:" + server))
	att, sec, err := attest.Build(key, server, spki[:], ts, names, values, w.Rand)
	if err != nil {
		return nil, err
	}
	disc := map[string]attest.Disclosure{
		attest.FieldReqBody:                    attest.Known,
		attest.FieldReqHeaderPfx + "x-api-key": attest.Hidden,
	}
	for k, v := range rv.Disclose {
		disc[k] = v
	}
	p, err := attest.Present(att, sec, disc)
	if err != nil {
		return nil, err
	}
	return p.Encode()
}

// AcceptTx fabricates a signed AcceptCommit transaction.
func (w *World) AcceptTx(signer ed25519.PrivateKey, rv Review, base gitobj.Store) (*types.Tx, error) {
	rc, err := w.Receipt(rv, base)
	if err != nil {
		return nil, err
	}
	model := rv.ReqModel
	if model == "" {
		model = w.Model
	}
	pv := rv.PolicyVersion
	if pv == 0 {
		pv = 1
	}
	return types.SignTx(signer, types.TxAcceptCommit, types.AcceptCommitBody{
		ChainID: w.ChainID, Repo: rv.Repo, Branch: rv.Branch,
		ExpectedHead: rv.Base, Candidate: rv.Candidate,
		PolicyVersion: pv, Model: model, Intent: rv.Intent, Receipt: rc,
	}, rv.Bundle.Encode())
}

// CreateRepoTx fabricates a signed CreateRepo transaction; bundle may be
// nil when genesis is zero.
func (w *World) CreateRepoTx(signer ed25519.PrivateKey, repo, branch string, pol types.Policy,
	genesis gitobj.ID, bundle *gitobj.Bundle) (*types.Tx, error) {
	var payload []byte
	if bundle != nil {
		payload = bundle.Encode()
	}
	return types.SignTx(signer, types.TxCreateRepo, types.CreateRepoBody{
		ChainID: w.ChainID, Repo: repo, Branch: branch, Policy: pol, Genesis: genesis,
	}, payload)
}

// UpdatePolicyTx fabricates a policy update approved by the given
// maintainers.
func (w *World) UpdatePolicyTx(signer ed25519.PrivateKey, repo string, expectedVersion uint64,
	pol types.Policy, approvers []ed25519.PrivateKey) (*types.Tx, error) {
	msg := types.PolicyUpdateSigningBytes(w.ChainID, repo, expectedVersion, pol.Hash())
	var aps []types.PolicyApproval
	for _, k := range approvers {
		aps = append(aps, types.PolicyApproval{PubKey: Pub(k), Sig: ed25519.Sign(k, msg)})
	}
	sort.Slice(aps, func(i, j int) bool { return string(aps[i].PubKey) < string(aps[j].PubKey) })
	return types.SignTx(signer, types.TxUpdatePolicy, types.UpdatePolicyBody{
		ChainID: w.ChainID, Repo: repo, ExpectedVersion: expectedVersion, Policy: pol, Approvals: aps,
	}, nil)
}

// IntentTx fabricates a signed ReviewIntent transaction.
func (w *World) IntentTx(signer ed25519.PrivateKey, repo, branch string, base, cand gitobj.ID) (*types.Tx, error) {
	return types.SignTx(signer, types.TxReviewIntent, types.ReviewIntentBody{
		ChainID: w.ChainID, Repo: repo, Branch: branch, ExpectedHead: base, Candidate: cand,
	}, nil)
}
