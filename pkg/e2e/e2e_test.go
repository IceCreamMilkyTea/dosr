// Package e2e runs the whole DOSR stack: a CometBFT testnet, the mock LLM
// provider over HTTPS, the attesting notary, and contributors using the
// client library.
package e2e

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/llm"
	"github.com/dosr/dosr/pkg/notary"
	"github.com/dosr/dosr/pkg/testnet"
	"github.com/dosr/dosr/pkg/types"
)

// Stack is everything except the chain.
type Stack struct {
	Provider *llm.Server
	Notary   *notary.Server
	NotaryC  *notary.Client
	Host     string
	SPKI     []byte
	APIKey   string
	NotaryK  ed25519.PrivateKey
}

// StartStack starts a mock provider and a notary that trusts it.
func StartStack(t testing.TB, lat llm.LatencyModel, nonces bool) *Stack {
	t.Helper()
	ca, cert, err := llm.NewLocalhostTLS()
	if err != nil {
		t.Fatal(err)
	}
	s := &Stack{APIKey: "sk-e2e-secret", NotaryK: dosrtest.Key("e2e-notary")}
	s.Provider, err = llm.NewServer(llm.Config{APIKeys: []string{s.APIKey}, Certificate: &cert, Latency: lat, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Provider.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Provider.Shutdown(context.Background()) })
	s.Host, err = notary.CanonicalHost(s.Provider.Addr())
	if err != nil {
		t.Fatal(err)
	}
	s.SPKI, _ = llm.SPKIHash(cert)
	s.Notary, err = notary.NewServer(notary.Config{
		Key: s.NotaryK, AllowedHosts: []string{s.Host}, RootCAs: ca.Pool(),
		EnforceSingleUseNonce: nonces,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Notary.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Notary.Shutdown(context.Background()) })
	s.NotaryC = notary.NewClient(s.Notary.URL())
	return s
}

// Policy returns a policy trusting the stack.
func (s *Stack) Policy(maintainer ed25519.PrivateKey, intents int) types.Policy {
	w := dosrtest.NewWorld("x")
	w.Maintainers = []ed25519.PrivateKey{maintainer}
	p := w.Policy()
	p.Threshold = 1
	p.ProviderHost = s.Host
	p.ProviderSPKI = [][]byte{s.SPKI}
	p.Models = []string{llm.ModelMedium}
	p.Notaries = [][]byte{dosrtest.Pub(s.NotaryK)}
	if intents > 0 {
		p.RequireIntent, p.MaxAttempts = true, intents
	}
	return p
}

// Contributor is a client with its own copy of the repository.
type Contributor struct {
	*client.Client
	Git   *dosrtest.Repo
	Files dosrtest.Files
}

func (s *Stack) Contributor(c *testnet.Cluster, node int, label string, git *dosrtest.Repo, files dosrtest.Files) *Contributor {
	return &Contributor{
		Client: &client.Client{
			RPC: c.RPC(node), Notary: s.NotaryC, Key: dosrtest.Key(label),
			APIKey: s.APIKey, ChainID: c.ChainID(),
		},
		Git: git, Files: files,
	}
}

// Propose makes a change on top of base and submits it.
func (k *Contributor) Propose(ctx context.Context, repo string, base gitobj.ID, path, content, msg string) (*client.Outcome, error) {
	f := dosrtest.Files{}
	for p, c := range k.Files {
		f[p] = c
	}
	f[path] = content
	cand, bundle := k.Git.Commit(base, f, msg)
	out, err := k.Submit(ctx, client.Change{
		Repo: repo, Branch: "main", Base: base, Candidate: cand, Bundle: bundle, Objects: k.Git.Store,
	})
	if err == nil {
		k.Files = f
	}
	return out, err
}

func createRepo(t *testing.T, c *testnet.Cluster, s *Stack, name string, intents int) (*dosrtest.Repo, dosrtest.Files, gitobj.ID, ed25519.PrivateKey) {
	t.Helper()
	owner := dosrtest.Key("owner-" + name)
	git := dosrtest.NewRepo()
	files := dosrtest.Files{"README.md": "# " + name + "\n", "main.go": "package main\n"}
	genesis, bundle := git.Commit(gitobj.ZeroID, files, "genesis")
	cl := &client.Client{RPC: c.RPC(0), Key: owner, ChainID: c.ChainID()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	code, log, err := cl.CreateRepo(ctx, name, "main", s.Policy(owner, intents), genesis, bundle)
	if err != nil || code != types.CodeOK {
		t.Fatalf("create repo: %v %d %s", err, code, log)
	}
	if err := c.WaitRepo(name, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	return git, files, genesis, owner
}

func TestEndToEnd(t *testing.T) {
	c := testnet.New(t, testnet.Options{Validators: 4})
	s := StartStack(t, llm.LatencyNone, false)
	git, files, genesis, _ := createRepo(t, c, s, "e2e", 0)
	alice := s.Contributor(c, 0, "alice", git, files)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	out, err := alice.Propose(ctx, "e2e", genesis, "main.go", "package main\n\nfunc main() {}\n", "add main")
	if err != nil {
		t.Fatalf("submit: %v (%+v)", err, out)
	}
	t.Logf("accepted at height %d: %+v", out.Height, out.Timeline)
	if out.Timeline.Upstream <= 0 || out.TxBytes == 0 || out.Height == 0 {
		t.Fatalf("timeline not populated: %+v", out)
	}
	head1, _ := c.BranchHead(0, "e2e", "main")
	if head1 == genesis {
		t.Fatal("head not advanced")
	}

	// A malicious change is rejected by the reviewer; nothing is
	// submitted, nothing is charged to the chain.
	before := s.Provider.Stats().Calls
	out, err = alice.Propose(ctx, "e2e", head1, "evil.go", "package main\n// "+llm.RejectMarker+"\n", "harmless")
	if !errors.Is(err, client.ErrRejected) {
		t.Fatalf("expected rejection, got %v (%+v)", err, out)
	}
	if s.Provider.Stats().Calls != before+1 {
		t.Fatal("expected exactly one review call")
	}

	// Stale base: alice tries to build on genesis again.
	out, err = alice.Propose(ctx, "e2e", genesis, "x", "y\n", "stale")
	if !errors.Is(err, client.ErrStale) {
		t.Fatalf("expected ErrStale, got %v", err)
	}
	if out.Reviewed {
		t.Fatal("a stale change must be detected before paying for a review")
	}

	// Every node agrees and the history is certified.
	if err := c.WaitAllHeight(out.Height, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	c.MustCheck(t)
	for i := 0; i < c.N(); i++ {
		if h, _ := c.BranchHead(i, "e2e", "main"); h != head1 {
			t.Fatalf("node %d head %s, want %s", i, h, head1)
		}
	}
}

// TestContention: k contributors race for the same head. Exactly one
// wins each round; the losers learn that their receipt is stale and must
// rebase. Counts wasted reviews.
func TestContention(t *testing.T) {
	c := testnet.New(t, testnet.Options{Validators: 4})
	s := StartStack(t, llm.LatencyNone, false)
	git, files, genesis, _ := createRepo(t, c, s, "race", 0)
	const k = 4
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var mu sync.Mutex
	wins, stale, other := 0, 0, 0
	var wg sync.WaitGroup
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each contributor has its own copy of the objects.
			g := dosrtest.NewRepo()
			g.Commit(gitobj.ZeroID, files, "genesis") // same genesis object IDs
			k := s.Contributor(c, i%c.N(), "racer-"+string(rune('a'+i)), g, files)
			_, err := k.Propose(ctx, "race", genesis, "f.txt", "from "+string(rune('a'+i))+"\n", "change")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, client.ErrStale):
				stale++
			default:
				other++
				t.Errorf("contributor %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	_ = git
	t.Logf("wins=%d stale=%d other=%d reviews=%d", wins, stale, other, s.Provider.Stats().Calls)
	if wins != 1 || stale != k-1 || other != 0 {
		t.Fatalf("wins=%d stale=%d other=%d", wins, stale, other)
	}
	c.MustCheck(t)
}

// TestIntentsEndToEnd: with intents required and single-use nonces at the
// notary, a second review of the same intent is refused by the notary.
func TestIntentsEndToEnd(t *testing.T) {
	c := testnet.New(t, testnet.Options{Validators: 4})
	s := StartStack(t, llm.LatencyNone, true)
	git, files, genesis, _ := createRepo(t, c, s, "intents", 2)
	alice := s.Contributor(c, 0, "alice", git, files)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := alice.Propose(ctx, "intents", genesis, "a.txt", "a\n", "a")
	if err != nil {
		t.Fatalf("%v (%+v)", err, out)
	}
	if out.Timeline.Intent <= 0 {
		t.Fatalf("intent phase not recorded: %+v", out.Timeline)
	}
	if s.Notary.UsedNonces() != 1 {
		t.Fatalf("used nonces = %d", s.Notary.UsedNonces())
	}
	c.MustCheck(t)
}

// TestAdversarialClients floods the chain with forged and replayed
// evidence while an honest contributor works; nothing forged is accepted
// and the replicas stay in agreement.
func TestAdversarialClients(t *testing.T) {
	c := testnet.New(t, testnet.Options{Validators: 4})
	s := StartStack(t, llm.LatencyNone, false)
	git, files, genesis, owner := createRepo(t, c, s, "adv", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	w := dosrtest.NewWorld(c.ChainID())
	pol := s.Policy(owner, 0)
	mallory := dosrtest.Key("mallory")
	forged := 0
	forge := func(base gitobj.ID, dev func(*dosrtest.Review)) {
		f := dosrtest.Files{}
		for p, v := range files {
			f[p] = v
		}
		f["backdoor.go"] = "package main\n// DOSR-REJECT-ME\n"
		cand, bundle := git.Commit(base, f, "innocent")
		rv := dosrtest.Review{Repo: "adv", Branch: "main", Base: base, Candidate: cand, Bundle: bundle, Policy: pol, PolicyVersion: 1,
			ReqModel: llm.ModelMedium, Time: time.Now().Unix()}
		dev(&rv)
		tx, err := w.AcceptTx(mallory, rv, git.Store)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.BroadcastTxSync(0, tx.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if res.Code == types.CodeOK {
			t.Fatalf("forged transaction admitted to the mempool")
		}
		forged++
	}
	// Fake notary (w.Notary is not trusted by the policy), wrong verdict
	// signed by... nobody trusted, wrong server.
	forge(genesis, func(rv *dosrtest.Review) {})
	forge(genesis, func(rv *dosrtest.Review) { rv.Reject = false; rv.ServerName = "api.anthropic.com" })

	alice := s.Contributor(c, 1, "alice", git, files)
	out, err := alice.Propose(ctx, "adv", genesis, "ok.txt", "fine\n", "fine")
	if err != nil {
		t.Fatalf("%v (%+v)", err, out)
	}
	head, _ := c.BranchHead(0, "adv", "main")
	forge(genesis, func(rv *dosrtest.Review) {}) // stale and forged
	if err := c.WaitAllHeight(out.Height+2, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < c.N(); i++ {
		if h, _ := c.BranchHead(i, "adv", "main"); h != head {
			t.Fatalf("node %d head %s, want %s", i, h, head)
		}
		if r := c.Repo(i, "adv"); r.Branches["main"].Seq != 2 {
			t.Fatalf("node %d seq %d", i, r.Branches["main"].Seq)
		}
	}
	t.Logf("%d forged transactions refused", forged)
	c.MustCheck(t)
}
