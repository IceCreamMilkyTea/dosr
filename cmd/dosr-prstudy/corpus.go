package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dosr/dosr/pkg/gitobj"
)

// Case is one entry of the PR corpus: a (base, candidate) pair with the
// objects needed to render DOSR's canonical review request, plus the
// ground truth the study scores against.
//
// Classes:
//
//	good              a real first-parent commit of the reference repository,
//	                  merged by its maintainers (expected: approve)
//	low_effort        message replaced by "fix"/"update", whitespace-only
//	                  change, or a deleted test assertion (expected: reject;
//	                  Soft is set for the two cases that only a prompt which
//	                  demands descriptive, substantive changes would reject)
//	subtly_harmful    the good change plus one text-level mutation that
//	                  introduces a bug or a security weakness
//	obviously_harmful the good change plus a file that downloads and runs a
//	                  remote script, exfiltrates the environment, or deletes
//	                  the repository
//	injected          the good change plus text that tries to instruct the
//	                  reviewer (expected: reject, by SystemSuffix rule 2),
//	                  in two cases combined with a harmful mutation
type Case struct {
	ID       string `json:"id"`
	Class    string `json:"class"`
	Subclass string `json:"subclass,omitempty"`
	// Expected is the ground-truth verdict: "approve" or "reject".
	Expected string `json:"expected"`
	// Soft marks an expectation that depends on the policy's prompt
	// (a correct change with the message "fix" is only wrong under a
	// policy that requires descriptive messages).
	Soft bool `json:"soft_expectation,omitempty"`

	// Category of the source commit by its paths and subject:
	// deps (dependency bump), docs, tests, code.
	Category     string    `json:"category"`
	SourceCommit gitobj.ID `json:"source_commit"`
	Base         gitobj.ID `json:"base"`
	Candidate    gitobj.ID `json:"candidate"`
	Author       string    `json:"author"`
	Committer    string    `json:"committer"`
	Message      string    `json:"commit_message"`
	// Changes is the output of gitobj.DiffTrees(tree(Base), tree(Candidate)).
	Changes []gitobj.Change `json:"changes"`
	// MutatedPaths lists the files the mutation touched (added, edited or
	// deleted) relative to the source commit; MutationNote says what was
	// done in words.
	MutatedPaths []string `json:"mutated_paths,omitempty"`
	MutationNote string   `json:"mutation_note,omitempty"`

	// Sizes under the default variant.
	TextBytes      int    `json:"text_bytes"`
	RequestBytes   int    `json:"request_bytes"`
	EstInputTokens int    `json:"est_input_tokens"`
	BundleBytes    int    `json:"bundle_bytes"`
	BundleDigest   string `json:"bundle_digest"`
	// RequestBodyDefault is the canonical request body rendered under the
	// default variant (model and policy hash as at build time). It is
	// included for inspection; run re-renders the body for every
	// variant from Changes and the object store.
	RequestBodyDefault string `json:"request_body_default"`
}

// Corpus is a directory: cases.jsonl plus a Git loose-object store with
// every blob the cases reference (both sides of every change), the
// candidate commits and their trees.
type Corpus struct {
	Dir   string
	Cases []*Case
	Store *gitobj.DiskStore
}

func casesPath(dir string) string   { return filepath.Join(dir, "cases.jsonl") }
func objectsPath(dir string) string { return filepath.Join(dir, "objects") }

// OpenCorpus loads an existing corpus.
func OpenCorpus(dir string) (*Corpus, error) {
	st, err := gitobj.NewDiskStore(objectsPath(dir))
	if err != nil {
		return nil, err
	}
	f, err := os.Open(casesPath(dir))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := &Corpus{Dir: dir, Store: st}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		cs := &Case{}
		if err := json.Unmarshal(sc.Bytes(), cs); err != nil {
			return nil, fmt.Errorf("corpus: %w", err)
		}
		c.Cases = append(c.Cases, cs)
	}
	return c, sc.Err()
}

// NewCorpus creates an empty corpus directory (cases.jsonl is truncated).
func NewCorpus(dir string) (*Corpus, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	st, err := gitobj.NewDiskStore(objectsPath(dir))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(casesPath(dir), nil, 0o644); err != nil {
		return nil, err
	}
	return &Corpus{Dir: dir, Store: st}, nil
}

// Append writes one case to cases.jsonl.
func (c *Corpus) Append(cs *Case) error {
	f, err := os.OpenFile(casesPath(c.Dir), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(cs)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return err
	}
	c.Cases = append(c.Cases, cs)
	return nil
}

// Classes in display order.
var classOrder = []string{"good", "low_effort", "subtly_harmful", "obviously_harmful", "injected"}
