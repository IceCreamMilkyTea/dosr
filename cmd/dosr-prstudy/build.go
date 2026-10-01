package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/types"
)

// tokensPerByteDefault is the ratio measured in eval/results/COST.md
// (tiktoken cl100k_base over rendered request bodies). It is an
// approximation used only for cost ESTIMATES before a real run; a real run
// records the provider's own usage counts.
const tokensPerByteDefault = 0.3805

// BuildSummary is written next to the corpus.
type BuildSummary struct {
	Repo           string             `json:"repo"`
	GoodRequested  int                `json:"good_requested"`
	Scanned        int                `json:"commits_scanned"`
	Skipped        map[string]int     `json:"skipped_by_reason"`
	Cases          int                `json:"cases"`
	ByClass        map[string]int     `json:"by_class"`
	GoodByCategory map[string]int     `json:"good_by_category"`
	BySubclass     map[string]int     `json:"by_subclass"`
	NotApplicable  map[string]int     `json:"operator_not_applicable"`
	TextBytes      map[string]int     `json:"text_bytes_total_by_class"`
	EstInputTokens int                `json:"est_input_tokens_total"`
	MeanTokens     map[string]float64 `json:"est_input_tokens_mean_by_class"`
	TokensPerByte  float64            `json:"tokens_per_byte_assumed"`
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	repo := fs.String("repo", "reference/cometbft", "reference Git repository")
	nGood := fs.Int("good", 60, "number of good commits to take (first-parent, newest first)")
	maxDeps := fs.Int("max-deps", 10, "at most this many dependency-bump commits (subject \"build(deps):\" or only go.mod/go.sum/workflow files) among the good ones; the branch head is dominated by them")
	out := fs.String("out", "eval/prstudy/corpus", "corpus directory")
	maxText := fs.Int("max-text-bytes", 96<<10, "skip commits whose rendered review text is larger (keeps the real-API cost bounded)")
	classes := fs.String("classes", "low_effort,subtly_harmful,obviously_harmful,injected", "mutation classes to generate")
	perClass := fs.Int("per-class", 1, "mutants per class per good commit")
	model := fs.String("model", "claude-sonnet-5-5", "model id written into the stored default request body")
	host := fs.String("host", "api.anthropic.com", "provider host written into the stored default request body")
	maxTokens := fs.Int("max-tokens", 8192, "policy max_tokens")
	tpb := fs.Float64("tokens-per-byte", tokensPerByteDefault, "assumed tokens per request byte for estimates")
	fs.Parse(args)

	raw, err := exec.Command("git", "-C", *repo, "log", "--first-parent", "--format=%H %P", "-n", fmt.Sprint(*nGood*8+50)).Output()
	if err != nil {
		return fmt.Errorf("git log: %w", err)
	}
	corpus, err := NewCorpus(*out)
	if err != nil {
		return err
	}
	store := client.NewGitStore(*repo)
	lim := gitobj.DefaultLimits
	pol, err := policyFor("default", *host, *model, *maxTokens, *maxText+4096)
	if err != nil {
		return err
	}
	// Opaque files are not reviewable under a strict policy; a good commit
	// that contains one is skipped (and counted) rather than rendered.
	pol.AllowOpaque = false

	sum := &BuildSummary{Repo: *repo, GoodRequested: *nGood, Skipped: map[string]int{}, ByClass: map[string]int{}, GoodByCategory: map[string]int{},
		BySubclass: map[string]int{}, NotApplicable: map[string]int{}, TextBytes: map[string]int{}, MeanTokens: map[string]float64{}, TokensPerByte: *tpb}
	classList := strings.Split(*classes, ",")
	goodIdx, deps := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if goodIdx >= *nGood {
			break
		}
		f := strings.Fields(line)
		if len(f) != 2 { // root or merge commit
			sum.Skipped["merge_or_root"]++
			continue
		}
		sum.Scanned++
		c, _ := gitobj.ParseID(f[0])
		p, _ := gitobj.ParseID(f[1])
		src, reason, err := renderSource(store, *repo, &pol, c, p, lim, *maxText)
		if err != nil {
			return err
		}
		if reason != "" {
			sum.Skipped[reason]++
			fmt.Fprintf(os.Stderr, "skip %s: %s\n", c.String()[:10], reason)
			continue
		}
		cat := categorize(src.commit.Message, src.changes)
		if cat == "deps" {
			if deps >= *maxDeps {
				sum.Skipped["deps_cap"]++
				continue
			}
			deps++
		}
		goodIdx++
		gc := &Case{ID: fmt.Sprintf("good-%03d", goodIdx), Class: "good", Expected: "approve", Category: cat,
			SourceCommit: c, Base: p, Candidate: c, Author: src.commit.Author, Committer: src.commit.Committer,
			Message: src.commit.Message, Changes: src.changes}
		fillSizes(gc, src.body, src.bundle, *tpb)
		if err := storeObjects(corpus.Store, src.view, src.bundle, src.changes); err != nil {
			return err
		}
		if err := corpus.Append(gc); err != nil {
			return err
		}
		sum.Cases++
		sum.ByClass["good"]++
		sum.GoodByCategory[cat]++
		sum.TextBytes["good"] += gc.TextBytes
		sum.EstInputTokens += gc.EstInputTokens
		fmt.Fprintf(os.Stderr, "%s %s %d files %d bytes\n", gc.ID, c.String()[:10], len(src.changes), gc.TextBytes)

		for _, class := range classList {
			ops := operators[class]
			if len(ops) == 0 {
				return fmt.Errorf("unknown class %q", class)
			}
			made := 0
			for k := 0; k < len(ops) && made < *perClass; k++ {
				op := ops[(goodIdx-1+k)%len(ops)]
				mc := newMutCtx(src.view, src.parentTree, src.commit.Tree, src.commit, c, src.changes)
				mut, ok, err := op.Apply(mc)
				if err != nil {
					return fmt.Errorf("%s on %s: %w", op.Name, c, err)
				}
				if !ok {
					sum.NotApplicable[op.Name]++
					continue
				}
				mcase, reason, err := materialize(store, src, mut, &pol, lim, *maxText, *tpb)
				if err != nil {
					return fmt.Errorf("%s on %s: %w", op.Name, c, err)
				}
				if reason != "" {
					sum.NotApplicable[op.Name+":"+reason]++
					fmt.Fprintf(os.Stderr, "  %s not materialised: %s\n", op.Name, reason)
					continue
				}
				made++
				mcase.c.ID = fmt.Sprintf("%s-%03d-%s", class, goodIdx, op.Name)
				mcase.c.Category = cat
				mcase.c.Class, mcase.c.Subclass = class, op.Name
				if err := storeObjects(corpus.Store, mcase.view, mcase.bundle, mcase.c.Changes); err != nil {
					return err
				}
				if err := corpus.Append(mcase.c); err != nil {
					return err
				}
				sum.Cases++
				sum.ByClass[class]++
				sum.BySubclass[op.Name]++
				sum.TextBytes[class] += mcase.c.TextBytes
				sum.EstInputTokens += mcase.c.EstInputTokens
				fmt.Fprintf(os.Stderr, "  %s: %s\n", mcase.c.ID, mut.Note)
			}
		}
	}
	for cl, n := range sum.ByClass {
		sum.MeanTokens[cl] = math.Round(float64(sum.TextBytes[cl]) * *tpb / float64(n)) // text only (without system prompt and tool definition)
	}
	b, _ := json.MarshalIndent(sum, "", " ")
	if err := os.WriteFile(filepath.Join(*out, "build_summary.json"), b, 0o644); err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// categorize labels a commit: deps (dependency bump), docs, tests or
// code, by its subject and paths.
func categorize(msg string, changes []gitobj.Change) string {
	subject := strings.ToLower(strings.SplitN(msg, "\n", 2)[0])
	if strings.HasPrefix(subject, "build(deps):") {
		return "deps"
	}
	docs, tests, deps := 0, 0, 0
	for _, c := range changes {
		base := c.Path[strings.LastIndex(c.Path, "/")+1:]
		switch {
		case base == "go.mod" || base == "go.sum" || strings.HasPrefix(c.Path, ".github/"):
			deps++
		case strings.HasSuffix(c.Path, ".md") || strings.HasPrefix(c.Path, "docs/") || strings.HasPrefix(c.Path, ".changelog/") || strings.HasPrefix(c.Path, "spec/"):
			docs++
		case strings.HasSuffix(c.Path, "_test.go") || strings.HasPrefix(c.Path, "test/") || strings.Contains(c.Path, "/testdata/"):
			tests++
		}
	}
	n := len(changes)
	switch {
	case deps == n:
		return "deps"
	case docs == n:
		return "docs"
	case tests == n:
		return "tests"
	}
	return "code"
}

// source is a rendered real commit.
type source struct {
	view       gitobj.Store
	bundle     *gitobj.Bundle
	commit     *gitobj.Commit
	parentTree gitobj.ID
	changes    []gitobj.Change
	body       []byte
}

// renderSource runs the validator pipeline on (p, c). reason != "" means
// the commit is not usable as a corpus entry.
func renderSource(store *client.GitStore, repo string, pol *types.Policy, c, p gitobj.ID, lim gitobj.Limits, maxText int) (*source, string, error) {
	bundle, err := gitobj.ExtractBundle(repo, p, c)
	if err != nil {
		return nil, "extract: " + short(err), nil
	}
	commit, err := gitobj.VerifyClosure(store, bundle, c, p, lim)
	if err != nil {
		return nil, "closure: " + short(err), nil
	}
	po, err := store.Get(p)
	if err != nil {
		return nil, "", err
	}
	pc, err := gitobj.ParseCommit(po.Data)
	if err != nil {
		return nil, "", err
	}
	view := gitobj.NewOverlay(store, bundle)
	changes, err := gitobj.DiffTrees(view, pc.Tree, commit.Tree, lim)
	if err != nil {
		return nil, "diff: " + short(err), nil
	}
	if len(changes) == 0 {
		return nil, "empty_diff", nil
	}
	body, err := review.BuildRequestBody(pol, review.Params{ChainID: "prstudy", RepoID: "cometbft", Branch: "main",
		Base: p, Candidate: c, PolicyHash: pol.Hash(), Model: pol.Models[0]}, commit.Message, changes, view)
	if err != nil {
		return nil, "render: " + short(err), nil
	}
	text, _ := review.ExtractRequestText(body)
	if len(text) > maxText {
		return nil, "too_large_for_study", nil
	}
	return &source{view: view, bundle: bundle, commit: commit, parentTree: pc.Tree, changes: changes, body: body}, "", nil
}

func short(err error) string {
	s := err.Error()
	switch {
	case errors.Is(err, review.ErrOpaque):
		return "opaque"
	case errors.Is(err, review.ErrTooLarge):
		return "too_large"
	case errors.Is(err, gitobj.ErrLimit):
		return "limit"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

type materialized struct {
	c      *Case
	view   gitobj.Store
	bundle *gitobj.Bundle
}

// materialize turns a mutation into a commit object, its bundle and a
// rendered case, running the same validator pipeline as for real commits.
func materialize(store *client.GitStore, src *source, mut *mutation, pol *types.Policy, lim gitobj.Limits, maxText int, tpb float64) (*materialized, string, error) {
	pt := newPatcher(src.view)
	base := src.commit.Tree
	if mut.FromParent {
		base = src.parentTree
	}
	tree, err := pt.apply(base, mut.Edits)
	if err != nil {
		return nil, "", err
	}
	msg := mut.Message
	if msg == "" {
		msg = src.commit.Message
	}
	var parents []gitobj.ID
	// The source commit has exactly one parent (first-parent, non-root).
	parents = append(parents, src.commitParent())
	cobj := gitobj.Object{Type: gitobj.TypeCommit, Data: gitobj.EncodeCommit(&gitobj.Commit{
		Tree: tree, Parents: parents, Author: src.commit.Author, Committer: src.commit.Committer, Message: msg})}
	cid, err := pt.put(cobj)
	if err != nil {
		return nil, "", err
	}
	bundle, err := pt.collectBundle(cid, src.bundle)
	if err != nil {
		return nil, "", err
	}
	commit, err := gitobj.VerifyClosure(store, bundle, cid, parents[0], lim)
	if err != nil {
		return nil, "closure: " + short(err), nil
	}
	view := gitobj.NewOverlay(store, bundle)
	changes, err := gitobj.DiffTrees(view, src.parentTree, commit.Tree, lim)
	if err != nil {
		return nil, "diff: " + short(err), nil
	}
	if len(changes) == 0 {
		return nil, "empty_diff", nil
	}
	body, err := review.BuildRequestBody(pol, review.Params{ChainID: "prstudy", RepoID: "cometbft", Branch: "main",
		Base: parents[0], Candidate: cid, PolicyHash: pol.Hash(), Model: pol.Models[0]}, msg, changes, view)
	if err != nil {
		return nil, "render: " + short(err), nil
	}
	text, _ := review.ExtractRequestText(body)
	if len(text) > maxText {
		return nil, "too_large_for_study", nil
	}
	// Sanity: the mutant must differ from the source in tree or message.
	if tree == src.commit.Tree && msg == src.commit.Message {
		return nil, "no_effect", nil
	}
	var paths []string
	for p := range mut.Edits {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	exp := mut.Expected
	if exp == "" {
		exp = "reject"
	}
	cs := &Case{Expected: exp, Soft: mut.Soft, SourceCommit: src.commitID(), Base: parents[0], Candidate: cid,
		Author: commit.Author, Committer: commit.Committer, Message: msg, Changes: changes,
		MutatedPaths: paths, MutationNote: mut.Note}
	fillSizes(cs, body, bundle, tpb)
	return &materialized{c: cs, view: view, bundle: bundle}, "", nil
}

func (s *source) commitParent() gitobj.ID { return s.commit.Parents[0] }
func (s *source) commitID() gitobj.ID {
	return gitobj.Object{Type: gitobj.TypeCommit, Data: gitobj.EncodeCommit(s.commit)}.ID()
}

func fillSizes(cs *Case, body []byte, bundle *gitobj.Bundle, tpb float64) {
	text, _ := review.ExtractRequestText(body)
	cs.TextBytes = len(text)
	cs.RequestBytes = len(body)
	cs.EstInputTokens = int(math.Round(float64(len(body)) * tpb))
	enc := bundle.Encode()
	cs.BundleBytes = len(enc)
	cs.BundleDigest = gitobj.SumDigest(enc).String()
	cs.RequestBodyDefault = string(body)
}

// storeObjects copies the bundle and the old side of every change into
// the corpus store, so that run can render requests without the reference
// repository.
func storeObjects(dst *gitobj.DiskStore, view gitobj.Store, bundle *gitobj.Bundle, changes []gitobj.Change) error {
	for _, o := range bundle.Objects {
		if _, err := dst.Put(o); err != nil {
			return err
		}
	}
	for _, ch := range changes {
		for _, id := range []gitobj.ID{ch.OldID, ch.NewID} {
			if id.IsZero() || dst.Has(id) {
				continue
			}
			o, err := view.Get(id)
			if err != nil {
				return err
			}
			if _, err := dst.Put(o); err != nil {
				return err
			}
		}
	}
	return nil
}
