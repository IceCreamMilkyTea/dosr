package testnet

import (
	"bytes"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	code := m.Run()
	RemoveBuiltBinary()
	os.Exit(code)
}

// TestSmoke: 4 validators and 1 full node produce blocks; a repository
// created through node 0 becomes visible everywhere; all p2p connections
// go through the harness's proxies.
func TestSmoke(t *testing.T) {
	start := time.Now()
	c := New(t, Options{Validators: 4, FullNodes: 1})
	t.Logf("5 nodes at height >= 2 after %v", time.Since(start).Round(time.Millisecond))

	creator := NewKey()
	h, err := c.CreateRepo(0, "smoke", creator)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WaitRepo("smoke", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	// A repository with a genesis commit: history entry and objects.
	files := map[string][]byte{"README.md": []byte("# smoke\n"), "src/main.go": []byte("package main\n"), "src/x/y.txt": []byte("y")}
	genesis, _, err := c.CreateRepoWithGenesis(1, "smoke-genesis", creator, files)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WaitRepo("smoke-genesis", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < c.N(); i++ {
		if head, ok := c.BranchHead(i, "smoke-genesis", "main"); !ok || head != genesis {
			t.Fatalf("node %d: head of smoke-genesis/main is %s, want %s", i, head, genesis)
		}
	}
	if err := c.WaitAllHeight(h+3, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, hd := range c.Heads() {
		if !hd.Running {
			t.Fatalf("node %d not running", hd.Node)
		}
		if _, ok := hd.Branches["smoke/main"]; !ok {
			t.Fatalf("node %d does not have smoke/main: %+v", hd.Node, hd)
		}
	}
	checkTopology(t, c)
	st := c.BlockIntervals(0, 2, c.MaxHeight())
	t.Logf("block intervals without emulated delay: %v", st)
	rep := c.MustCheck(t)
	if rep.EntriesChecked != c.N() || rep.ObjectsChecked != 7*c.N() || rep.BlocksCompared == 0 || rep.StatesCompared == 0 {
		t.Fatalf("the checker did not check what it should: %+v", rep)
	}

	// No path around the proxies: with all links blocked no node has a
	// peer left.
	c.Net().Partition()
	if err := c.waitFor(10*time.Second, "all peers to drop", func() bool {
		for i := 0; i < c.N(); i++ {
			if ids, err := c.Peers(i); err != nil || len(ids) != 0 {
				return false
			}
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	c.Heal()
	if err := c.WaitConnected(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	checkTopology(t, c)
	if err := c.WaitAllHeight(c.MaxHeight()+2, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	c.MustCheck(t)
}

// TestNoGoroutineLeak: starting, killing, restarting and closing a
// cluster leaves no goroutine of the harness or of the nodes behind.
func TestNoGoroutineLeak(t *testing.T) {
	// Stragglers of earlier tests (CometBFT stops most of its goroutines
	// synchronously, but a few finish shortly after Stop returns).
	time.Sleep(200 * time.Millisecond)
	before := runtime.NumGoroutine()
	c := New(t, Options{})
	if err := c.Kill(2); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitHeight(c.MaxHeight()+2, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.Restart(2); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitAllHeight(c.MaxHeight()+2, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	c.MustCheck(t)
	c.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		after := runtime.NumGoroutine()
		if after <= before+2 {
			t.Logf("goroutines: %d before, %d after Close", before, after)
			return
		}
		if time.Now().After(deadline) {
			var buf bytes.Buffer
			_ = pprof.Lookup("goroutine").WriteTo(&buf, 1)
			t.Fatalf("goroutines: %d before, %d after Close:\n%s", before, after, buf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// checkTopology verifies that there is exactly one connection per pair
// of nodes and that it runs through the pair's proxy.
func checkTopology(t *testing.T, c *Cluster) {
	t.Helper()
	if err := c.WaitConnected(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	n := c.N()
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if a := c.Net().Link(i, j).Stats().Active; a != 1 {
				t.Errorf("link %d-%d proxies %d connections, want 1", i, j, a)
			}
		}
	}
	for i := 0; i < n; i++ {
		peers := c.Node(i).Comet().Switch().Peers().List()
		if len(peers) != n-1 {
			t.Errorf("node %d has %d peers, want %d", i, len(peers), n-1)
		}
		for _, p := range peers {
			j := -1
			for k := 0; k < n; k++ {
				if c.NodeID(k) == p.ID() {
					j = k
				}
			}
			if j < 0 {
				t.Fatalf("node %d: unknown peer %s", i, p.ID())
			}
			addr := p.SocketAddr().DialString()
			if p.IsOutbound() {
				if i > j {
					t.Errorf("node %d dialled node %d: only the lower-numbered node may dial", i, j)
					continue
				}
				if addr != c.Net().ProxyAddr(i, j) {
					t.Errorf("node %d -> %d: connected to %s, the proxy is %s", i, j, addr, c.Net().ProxyAddr(i, j))
				}
			} else {
				// Inbound: the remote end must be the proxy's
				// upstream connection of link (j,i).
				if j > i {
					t.Errorf("node %d accepted a connection from node %d", i, j)
					continue
				}
				ok := false
				for _, a := range c.Net().Link(j, i).UpstreamLocalAddrs() {
					if sameAddr(a, addr) {
						ok = true
					}
				}
				if !ok {
					t.Errorf("node %d: inbound peer %d at %s is not a proxy connection %v", i, j, addr, c.Net().Link(j, i).UpstreamLocalAddrs())
				}
			}
		}
	}
}

func sameAddr(a, b string) bool {
	_, pa, _ := net.SplitHostPort(a)
	_, pb, _ := net.SplitHostPort(b)
	return pa != "" && pa == pb
}
