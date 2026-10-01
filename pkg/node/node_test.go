package node

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"

	"github.com/dosr/dosr/pkg/app"
)

func singleNodeConfig(t *testing.T, backend string) Config {
	t.Helper()
	home := t.TempDir()
	priv := ed25519.GenPrivKey()
	pvk := &privval.FilePVKey{Address: priv.PubKey().Address(), PubKey: priv.PubKey(), PrivKey: priv}
	gen, err := NewGenesis("dosr-node-test", time.Now(), []*privval.FilePVKey{pvk})
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := FreeAddrs(2)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Home: home, Moniker: "solo", Genesis: gen,
		NodeKey:    &p2p.NodeKey{PrivKey: ed25519.GenPrivKey()},
		PrivValKey: pvk,
		P2PListen:  addrs[0], RPCListen: addrs[1],
		Consensus: FastTimeouts(), DBBackend: backend,
		CommitLog: filepath.Join(home, "commits.jsonl"),
		App:       app.DefaultConfig(),
	}
}

func waitHeight(t *testing.T, n *Node, h int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for n.Height() < h {
		if time.Now().After(deadline) {
			t.Fatalf("height %d not reached within %v (at %d)", h, timeout, n.Height())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSingleNodeMemDB(t *testing.T) {
	cfg := singleNodeConfig(t, "memdb")
	n, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	waitHeight(t, n, 3, 30*time.Second)
	st, err := n.RPC().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.NodeInfo.ID() != n.ID() {
		t.Fatalf("node id mismatch")
	}
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := n.Stop(); err != nil {
		t.Fatal("second Stop:", err)
	}
}

// TestRestartFromDisk checks that Start on an existing home resumes the
// chain: heights continue, the app hash at the stop height is unchanged,
// and keys given in the config do not replace the ones on disk.
func TestRestartFromDisk(t *testing.T) {
	cfg := singleNodeConfig(t, "goleveldb")
	n, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := n.ID()
	waitHeight(t, n, 3, 30*time.Second)
	if err := n.Stop(); err != nil {
		t.Fatal(err)
	}
	h1 := n.Height()

	// Second start: from the saved config, as cmd/dosrd does.
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg2, err := LoadConfig(cfg.Home)
	if err != nil {
		t.Fatal(err)
	}
	cfg2.NodeKey = &p2p.NodeKey{PrivKey: ed25519.GenPrivKey()} // must be ignored
	n2, err := Start(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Stop()
	if n2.ID() != id {
		t.Fatal("restart changed the node ID")
	}
	if n2.Height() < h1 {
		t.Fatalf("height went back: %d < %d", n2.Height(), h1)
	}
	waitHeight(t, n2, h1+3, 30*time.Second)

	recs, err := ReadCommitLog(cfg.CommitLog)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64][]byte{}
	for _, r := range recs {
		if prev, ok := seen[r.Height]; ok && !bytes.Equal(prev, r.AppHash) {
			t.Fatalf("height %d committed twice with different app hashes", r.Height)
		}
		seen[r.Height] = r.AppHash
	}
	for h := int64(1); h <= h1+3; h++ {
		if _, ok := seen[h]; !ok {
			t.Fatalf("no commit record for height %d", h)
		}
	}
}
