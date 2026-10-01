// Command dosr is the contributor's tool.
//
//	dosr keygen      -out key.hex
//	dosr policy      -host H -model M -notary <hex> -maintainer <hex> [...]  > policy.json
//	dosr create-repo -node URL -chain ID -key key.hex -repo NAME -policy policy.json [-git DIR -ref REF]
//	dosr submit      -node URL -chain ID -key key.hex -repo NAME -git DIR [-ref HEAD] -notary URL
//	dosr head        -node URL -repo NAME [-branch main]
//	dosr log         -node URL -repo NAME [-branch main]
//
// The LLM API key is read from the environment variable DOSR_API_KEY. It
// is sent to the attestor only.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/notary"
	"github.com/dosr/dosr/pkg/types"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "policy":
		err = policy(os.Args[2:])
	case "create-repo":
		err = createRepo(os.Args[2:])
	case "submit":
		err = submit(os.Args[2:])
	case "head":
		err = head(os.Args[2:])
	case "log":
		err = history(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dosr:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dosr keygen|policy|create-repo|submit|head|log [flags]")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "dosr-key.hex", "file to write the private key seed to")
	fs.Parse(args)
	key, created, err := notary.LoadOrCreateKey(*out)
	if err != nil {
		return err
	}
	if !created {
		fmt.Fprintln(os.Stderr, "key file exists; not overwritten")
	}
	fmt.Println(hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func policy(args []string) error {
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	host := fs.String("host", "api.anthropic.com", "provider host (canonical, no :443)")
	path := fs.String("path", "/v1/messages", "provider path")
	prompt := fs.String("prompt", "You are reviewing a change to an open-source repository. Approve only if the change is safe, does what its commit message says, and contains no malicious or obfuscated code.", "system prompt")
	maxTokens := fs.Int("max-tokens", 4096, "max_tokens of the review")
	threshold := fs.Int("threshold", 1, "maintainer threshold")
	age := fs.Int64("max-age", 900, "maximum receipt age in seconds")
	intent := fs.Int("max-attempts", 0, "require review intents, with this many attempts per head (0 = no intents)")
	var models, notaries, maintainers multi
	fs.Var(&models, "model", "allowed model (repeatable)")
	fs.Var(&notaries, "notary", "trusted notary public key, hex (repeatable)")
	fs.Var(&maintainers, "maintainer", "maintainer public key, hex (repeatable)")
	fs.Parse(args)
	p := types.Policy{
		ProviderHost: *host, ProviderPath: *path, Models: models,
		SystemPrompt: *prompt, MaxTokens: *maxTokens,
		MaxReceiptAgeSec: *age, MaxClockSkewSec: 30, MaxDiffBytes: 1 << 20,
		Threshold: *threshold, RequireIntent: *intent > 0, MaxAttempts: *intent,
	}
	for _, h := range notaries {
		b, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("notary key: %w", err)
		}
		p.Notaries = append(p.Notaries, b)
	}
	for _, h := range maintainers {
		b, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("maintainer key: %w", err)
		}
		p.Maintainers = append(p.Maintainers, b)
	}
	types.SortKeys(p.Notaries)
	types.SortKeys(p.Maintainers)
	sortStrings(p.Models)
	if err := p.Validate(); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

type common struct {
	node, chain, key, repo, branch string
	timeout                        time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.node, "node", "http://127.0.0.1:26657", "RPC address of a node")
	fs.StringVar(&c.chain, "chain", "dosr", "chain id")
	fs.StringVar(&c.key, "key", "dosr-key.hex", "private key file")
	fs.StringVar(&c.repo, "repo", "", "repository id")
	fs.StringVar(&c.branch, "branch", "main", "branch")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Minute, "overall timeout")
}

func (c *common) client(needKey bool) (*client.Client, error) {
	if c.repo == "" {
		return nil, errors.New("-repo is required")
	}
	rpc, err := rpchttp.New(c.node, "/websocket")
	if err != nil {
		return nil, err
	}
	cl := &client.Client{RPC: rpc, ChainID: c.chain, APIKey: os.Getenv("DOSR_API_KEY")}
	if needKey {
		if cl.Key, err = notary.LoadKey(c.key); err != nil {
			return nil, err
		}
	}
	return cl, nil
}

func createRepo(args []string) error {
	fs := flag.NewFlagSet("create-repo", flag.ExitOnError)
	var c common
	c.register(fs)
	polFile := fs.String("policy", "policy.json", "policy file")
	gitDir := fs.String("git", "", "local repository to take the genesis commit from (optional)")
	ref := fs.String("ref", "HEAD", "genesis commit; must be a root commit")
	fs.Parse(args)
	cl, err := c.client(true)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*polFile)
	if err != nil {
		return err
	}
	var pol types.Policy
	if err := json.Unmarshal(raw, &pol); err != nil {
		return err
	}
	var genesis gitobj.ID
	var bundle *gitobj.Bundle
	if *gitDir != "" {
		if genesis, err = gitobj.ResolveRef(*gitDir, *ref); err != nil {
			return err
		}
		if bundle, err = gitobj.ExtractBundle(*gitDir, gitobj.ZeroID, genesis); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	code, log, err := cl.CreateRepo(ctx, c.repo, c.branch, pol, genesis, bundle)
	if err != nil {
		return err
	}
	if code != types.CodeOK {
		return fmt.Errorf("rejected: %s", log)
	}
	fmt.Printf("created %s, %s = %s\n", c.repo, c.branch, genesis)
	return nil
}

func submit(args []string) error {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	var c common
	c.register(fs)
	gitDir := fs.String("git", ".", "local repository")
	ref := fs.String("ref", "HEAD", "commit to submit; must be a direct child of the branch head")
	notaryURL := fs.String("notary", "http://127.0.0.1:7443", "attestor address")
	model := fs.String("model", "", "model to request (default: first model of the policy)")
	fs.Parse(args)
	cl, err := c.client(true)
	if err != nil {
		return err
	}
	if cl.APIKey == "" {
		return errors.New("DOSR_API_KEY is not set")
	}
	cl.Notary = notary.NewClient(*notaryURL)
	cl.Model = *model
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	base, err := cl.Head(ctx, c.repo, c.branch)
	if err != nil {
		return err
	}
	cand, err := gitobj.ResolveRef(*gitDir, *ref)
	if err != nil {
		return err
	}
	bundle, err := gitobj.ExtractBundle(*gitDir, base, cand)
	if err != nil {
		return err
	}
	out, err := cl.Submit(ctx, client.Change{
		Repo: c.repo, Branch: c.branch, Base: base, Candidate: cand,
		Bundle: bundle, Objects: client.NewGitStore(*gitDir),
	})
	if out != nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	}
	return err
}

func head(args []string) error {
	fs := flag.NewFlagSet("head", flag.ExitOnError)
	var c common
	c.register(fs)
	fs.Parse(args)
	cl, err := c.client(false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	h, err := cl.Head(ctx, c.repo, c.branch)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

func history(args []string) error {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	var c common
	c.register(fs)
	fs.Parse(args)
	cl, err := c.client(false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	res, err := cl.RPC.ABCIQuery(ctx, "/history/"+c.repo+"/"+c.branch, []byte("1,1000"))
	if err != nil {
		return err
	}
	if res.Response.Code != 0 {
		return errors.New(res.Response.Log)
	}
	var es []app.HistoryEntry
	if err := json.Unmarshal(res.Response.Value, &es); err != nil {
		return err
	}
	for i := len(es) - 1; i >= 0; i-- {
		e := es[i]
		kind := "certified by " + e.Model
		if e.Model == "" {
			kind = "genesis"
		}
		fmt.Printf("%4d  %s  height %-6d %s  (%s)\n", e.Seq, e.Commit, e.Height,
			time.Unix(e.BlockTime, 0).UTC().Format(time.RFC3339), kind)
	}
	return nil
}
