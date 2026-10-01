package testnet

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/node"
	"github.com/dosr/dosr/pkg/types"
)

// Key is an ed25519 key pair of a client (repository creator,
// maintainer, contributor, notary).
type Key struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// NewKey generates a key pair.
func NewKey() Key {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Key{pub, priv}
}

// Policy returns a policy that satisfies types.Policy.Validate, with the
// given maintainers (threshold 1) and notaries. If notaries is empty the
// first maintainer is also the notary. Callers may modify the result
// (and must keep key lists sorted: types.SortKeys).
func Policy(maintainers []ed25519.PublicKey, notaries []ed25519.PublicKey) types.Policy {
	if len(notaries) == 0 {
		notaries = maintainers[:1]
	}
	conv := func(in []ed25519.PublicKey) [][]byte {
		out := make([][]byte, len(in))
		for i, k := range in {
			out[i] = append([]byte(nil), k...)
		}
		types.SortKeys(out)
		return out
	}
	return types.Policy{
		ProviderHost:     "api.anthropic.com",
		ProviderPath:     "/v1/messages",
		Models:           []string{"test-model"},
		SystemPrompt:     "You are a code reviewer. Approve or reject the change.",
		MaxTokens:        1024,
		Notaries:         conv(notaries),
		MaxReceiptAgeSec: 3600,
		MaxClockSkewSec:  60,
		MaxDiffBytes:     1 << 20,
		Maintainers:      conv(maintainers),
		Threshold:        1,
	}
}

// CreateRepoTx returns a signed CreateRepo transaction without a genesis
// commit (which needs neither a bundle nor a receipt), creating repo
// with an empty branch "main" and creator as the only maintainer.
func CreateRepoTx(chainID, repo string, creator Key) ([]byte, error) {
	pol := Policy([]ed25519.PublicKey{creator.Pub}, nil)
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return SignedTx(creator, types.TxCreateRepo, types.CreateRepoBody{
		ChainID: chainID, Repo: repo, Branch: "main", Policy: pol, Genesis: gitobj.ZeroID,
	}, nil)
}

// SignedTx signs a transaction and returns its wire bytes.
func SignedTx(k Key, typ types.TxType, body any, payload []byte) ([]byte, error) {
	tx, err := types.SignTx(k.Priv, typ, body, payload)
	if err != nil {
		return nil, err
	}
	return tx.Bytes(), nil
}

// CreateRepo creates a repository through node i and waits until the
// transaction is committed. It returns the height of the block.
func (c *Cluster) CreateRepo(i int, repo string, creator Key) (int64, error) {
	tx, err := CreateRepoTx(c.chainID, repo, creator)
	if err != nil {
		return 0, err
	}
	res, err := c.BroadcastTxCommit(i, tx)
	if err != nil {
		return 0, err
	}
	if res.CheckTx.Code != types.CodeOK {
		return 0, fmt.Errorf("CheckTx: code %d (%s): %s", res.CheckTx.Code, types.CodeName(res.CheckTx.Code), res.CheckTx.Log)
	}
	if res.TxResult.Code != types.CodeOK {
		return res.Height, fmt.Errorf("height %d: code %d (%s): %s", res.Height, res.TxResult.Code, types.CodeName(res.TxResult.Code), res.TxResult.Log)
	}
	return res.Height, nil
}

// IntervalStats summarises the time between consecutive commits.
type IntervalStats struct {
	Blocks   int // number of intervals
	From, To int64
	Mean     time.Duration
	Median   time.Duration
	P95      time.Duration
	Min, Max time.Duration
}

func (s IntervalStats) String() string {
	return fmt.Sprintf("%d intervals (heights %d..%d): mean %v median %v p95 %v min %v max %v",
		s.Blocks, s.From, s.To, s.Mean.Round(time.Millisecond), s.Median.Round(time.Millisecond),
		s.P95.Round(time.Millisecond), s.Min.Round(time.Millisecond), s.Max.Round(time.Millisecond))
}

// BlockIntervals returns statistics of the wall-clock time between the
// commits of consecutive blocks from..to as observed by node i (the time
// at which each block became durable on that node).
func (c *Cluster) BlockIntervals(i int, from, to int64) IntervalStats {
	return intervals(c.Commits(i), from, to)
}

func intervals(recs map[int64]node.CommitRecord, from, to int64) IntervalStats {
	var ds []time.Duration
	for h := from + 1; h <= to; h++ {
		a, ok1 := recs[h-1]
		b, ok2 := recs[h]
		if ok1 && ok2 {
			ds = append(ds, time.Duration(b.CommittedAtUnixNano-a.CommittedAtUnixNano))
		}
	}
	st := IntervalStats{Blocks: len(ds), From: from, To: to}
	if len(ds) == 0 {
		return st
	}
	sort.Slice(ds, func(a, b int) bool { return ds[a] < ds[b] })
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	st.Mean = sum / time.Duration(len(ds))
	st.Median = ds[len(ds)/2]
	st.P95 = ds[(len(ds)-1)*95/100]
	st.Min, st.Max = ds[0], ds[len(ds)-1]
	return st
}

// Rounds returns, for each height from..to, the round in which the block
// was committed (0 = the first proposer succeeded), read from node i.
func (c *Cluster) Rounds(i int, from, to int64) (map[int64]int32, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return nil, fmt.Errorf("node %d is not running", i)
	}
	out := map[int64]int32{}
	for h := from; h <= to; h++ {
		h := h
		res, err := rpc.Commit(c.ctx, &h)
		if err != nil {
			return nil, err
		}
		out[h] = res.Commit.Round
	}
	return out, nil
}

// Proposer returns the index of the node that proposed block h, or -1.
func (c *Cluster) Proposer(i int, h int64) (int, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return -1, fmt.Errorf("node %d is not running", i)
	}
	res, err := rpc.Commit(c.ctx, &h)
	if err != nil {
		return -1, err
	}
	for k, v := range c.genesis.Validators {
		if v.Address.String() == res.Header.ProposerAddress.String() {
			return k, nil
		}
	}
	return -1, nil
}

// RootCommit builds a root commit (no parents) containing the given
// files (slash-separated paths) and returns its ID and the bundle of
// all its objects.
func RootCommit(files map[string][]byte, message string) (gitobj.ID, *gitobj.Bundle) {
	return BuildCommit(gitobj.ZeroID, files, message)
}

// BuildCommit builds a commit with the given parent (ZeroID: none)
// whose tree contains exactly the given files, and returns its ID and a
// bundle with the commit, all its trees and all its blobs.
func BuildCommit(parent gitobj.ID, files map[string][]byte, message string) (gitobj.ID, *gitobj.Bundle) {
	b := &gitobj.Bundle{}
	type dir struct {
		files map[string][]byte
		dirs  map[string]*dir
	}
	root := &dir{files: map[string][]byte{}, dirs: map[string]*dir{}}
	for path, data := range files {
		d := root
		for {
			i := -1
			for k := 0; k < len(path); k++ {
				if path[k] == '/' {
					i = k
					break
				}
			}
			if i < 0 {
				break
			}
			sub := d.dirs[path[:i]]
			if sub == nil {
				sub = &dir{files: map[string][]byte{}, dirs: map[string]*dir{}}
				d.dirs[path[:i]] = sub
			}
			d, path = sub, path[i+1:]
		}
		d.files[path] = data
	}
	var build func(d *dir) gitobj.ID
	build = func(d *dir) gitobj.ID {
		var entries []gitobj.TreeEntry
		for name, data := range d.files {
			o := gitobj.Object{Type: gitobj.TypeBlob, Data: data}
			b.Objects = append(b.Objects, o)
			entries = append(entries, gitobj.TreeEntry{Mode: gitobj.ModeFile, Name: name, ID: o.ID()})
		}
		for name, sub := range d.dirs {
			entries = append(entries, gitobj.TreeEntry{Mode: gitobj.ModeDir, Name: name, ID: build(sub)})
		}
		gitobj.SortEntries(entries)
		o := gitobj.Object{Type: gitobj.TypeTree, Data: gitobj.EncodeTree(entries)}
		b.Objects = append(b.Objects, o)
		return o.ID()
	}
	tree := build(root)
	text := "tree " + tree.String() + "\n"
	if !parent.IsZero() {
		text += "parent " + parent.String() + "\n"
	}
	text += "author Test Author <author@example.org> 1750000000 +0000\n" +
		"committer Test Author <author@example.org> 1750000000 +0000\n\n" + message + "\n"
	c := gitobj.Object{Type: gitobj.TypeCommit, Data: []byte(text)}
	b.Objects = append(b.Objects, c)
	return c.ID(), b
}

// CreateRepoWithGenesisTx returns a signed CreateRepo transaction whose
// branch "main" starts at a root commit with the given files (the
// creator vouches for a genesis commit, no receipt is needed), and the
// ID of that commit.
func CreateRepoWithGenesisTx(chainID, repo string, creator Key, files map[string][]byte) ([]byte, gitobj.ID, error) {
	pol := Policy([]ed25519.PublicKey{creator.Pub}, nil)
	id, bundle := RootCommit(files, "genesis of "+repo)
	tx, err := SignedTx(creator, types.TxCreateRepo, types.CreateRepoBody{
		ChainID: chainID, Repo: repo, Branch: "main", Policy: pol, Genesis: id,
	}, bundle.Encode())
	return tx, id, err
}

// CreateRepoWithGenesis creates a repository with a genesis commit
// through node i and waits until the transaction is committed.
func (c *Cluster) CreateRepoWithGenesis(i int, repo string, creator Key, files map[string][]byte) (gitobj.ID, int64, error) {
	tx, id, err := CreateRepoWithGenesisTx(c.chainID, repo, creator, files)
	if err != nil {
		return id, 0, err
	}
	res, err := c.BroadcastTxCommit(i, tx)
	if err != nil {
		return id, 0, err
	}
	if res.CheckTx.Code != types.CodeOK {
		return id, 0, fmt.Errorf("CheckTx: code %d (%s): %s", res.CheckTx.Code, types.CodeName(res.CheckTx.Code), res.CheckTx.Log)
	}
	if res.TxResult.Code != types.CodeOK {
		return id, res.Height, fmt.Errorf("height %d: code %d (%s): %s", res.Height, res.TxResult.Code, types.CodeName(res.TxResult.Code), res.TxResult.Log)
	}
	return id, res.Height, nil
}
