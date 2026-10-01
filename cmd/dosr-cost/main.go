// Command dosr-cost renders DOSR's canonical review request for every
// commit of a real Git repository and reports its size, so that the cost
// of a review can be computed from real change-size distributions instead
// of synthetic ones.
//
//	dosr-cost -repo reference/cometbft -max 400 -out eval/results/raw/cost_commits.jsonl
//
// For each single-parent commit C with parent P it runs exactly the
// validator's pipeline: ExtractBundle(P, C) -> VerifyClosure -> DiffTrees
// -> BuildRequestBody, under a policy that allows opaque (binary / large)
// files, and records bytes, file counts and a path-based category.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/dosr/dosr/pkg/client"
	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/review"
)

// Record is one commit's rendering.
type Record struct {
	Commit       string   `json:"commit"`
	Parent       string   `json:"parent"`
	Files        int      `json:"files"`
	Added        int      `json:"added_lines"`
	Removed      int      `json:"removed_lines"`
	Opaque       int      `json:"opaque_files"`
	TextBytes    int      `json:"text_bytes"`    // the user message (header + diffs)
	RequestBytes int      `json:"request_bytes"` // the whole JSON body
	BundleBytes  int      `json:"bundle_bytes"`
	Category     string   `json:"category"` // docs | tests | code | sensitive | mixed
	Paths        []string `json:"paths"`
	Error        string   `json:"error,omitempty"`
	RenderMs     float64  `json:"render_ms"`
}

// sensitive path prefixes of a CometBFT-like repository: changes here
// would need the strongest review under a risk-adaptive policy.
var sensitivePrefixes = []string{"consensus/", "crypto/", "p2p/", "privval/", "state/", "evidence/", "mempool/", "light/", "abci/", "types/"}

func categorize(paths []string) string {
	docs, tests, sens, code := 0, 0, 0, 0
	for _, p := range paths {
		switch {
		case strings.HasSuffix(p, ".md") || strings.HasPrefix(p, "docs/") || strings.HasPrefix(p, ".changelog/") || strings.HasPrefix(p, "spec/"):
			docs++
		case strings.HasSuffix(p, "_test.go") || strings.HasPrefix(p, "test/") || strings.Contains(p, "/testdata/"):
			tests++
		default:
			isSens := false
			for _, s := range sensitivePrefixes {
				if strings.HasPrefix(p, s) {
					isSens = true
					break
				}
			}
			if isSens {
				sens++
			} else {
				code++
			}
		}
	}
	n := len(paths)
	switch {
	case docs == n:
		return "docs"
	case tests == n:
		return "tests"
	case sens > 0:
		return "sensitive"
	case docs+tests == n:
		return "docs+tests"
	default:
		return "code"
	}
}

func main() {
	repo := flag.String("repo", "reference/cometbft", "repository directory")
	max := flag.Int("max", 400, "maximum number of commits")
	out := flag.String("out", "eval/results/raw/cost_commits.jsonl", "output JSONL")
	flag.Parse()

	cmd := exec.Command("git", "-C", *repo, "log", "--first-parent", "--format=%H %P", "-n", fmt.Sprint(*max))
	raw, err := cmd.Output()
	if err != nil {
		fail(err)
	}
	f, err := os.Create(*out)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	w2 := dosrtest.NewWorld("cost")
	pol := w2.Policy()
	pol.AllowOpaque = true
	pol.MaxDiffBytes = 8 << 20
	store := client.NewGitStore(*repo)
	lim := gitobj.DefaultLimits
	lim.MaxBundleBytes, lim.MaxObjectBytes, lim.MaxObjects = 64<<20, 16<<20, 200000

	n, errs := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fs := strings.Fields(line)
		if len(fs) != 2 { // root or merge commit
			continue
		}
		rec := Record{Commit: fs[0], Parent: fs[1]}
		func() {
			c, _ := gitobj.ParseID(fs[0])
			p, _ := gitobj.ParseID(fs[1])
			t := time.Now()
			bundle, err := gitobj.ExtractBundle(*repo, p, c)
			if err != nil {
				rec.Error = "extract: " + err.Error()
				return
			}
			rec.BundleBytes = len(bundle.Encode())
			commit, err := gitobj.VerifyClosure(store, bundle, c, p, lim)
			if err != nil {
				rec.Error = "closure: " + err.Error()
				return
			}
			po, _ := store.Get(p)
			pc, _ := gitobj.ParseCommit(po.Data)
			view := gitobj.NewOverlay(store, bundle)
			changes, err := gitobj.DiffTrees(view, pc.Tree, commit.Tree, lim)
			if err != nil {
				rec.Error = "diff: " + err.Error()
				return
			}
			rec.Files = len(changes)
			for _, ch := range changes {
				rec.Paths = append(rec.Paths, ch.Path)
			}
			rec.Category = categorize(rec.Paths)
			body, err := review.BuildRequestBody(&pol, review.Params{
				ChainID: "cost", RepoID: "r", Branch: "main", Base: p, Candidate: c,
				PolicyHash: pol.Hash(), Model: w2.Model,
			}, commit.Message, changes, view)
			rec.RenderMs = float64(time.Since(t).Microseconds()) / 1000
			if err != nil {
				rec.Error = "render: " + err.Error()
				return
			}
			rec.RequestBytes = len(body)
			text, err := review.ExtractRequestText(body)
			if err != nil {
				rec.Error = "text: " + err.Error()
				return
			}
			rec.TextBytes = len(text)
			for _, l := range strings.Split(text, "\n") {
				switch {
				case strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++"):
					rec.Added++
				case strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---"):
					rec.Removed++
				case strings.HasPrefix(l, "[opaque content not shown"):
					rec.Opaque++
				}
			}
		}()
		if rec.Error != "" {
			errs++
		}
		b, _ := json.Marshal(rec)
		w.Write(b)
		w.WriteByte('\n')
		n++
	}
	fmt.Fprintf(os.Stderr, "%d commits, %d with errors, written to %s\n", n, errs, *out)
	_ = path.Base
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "dosr-cost:", err)
	os.Exit(1)
}
