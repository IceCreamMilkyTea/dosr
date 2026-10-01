package testnet

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/node"
	"github.com/dosr/dosr/pkg/types"
)

const waitLong = 90 * time.Second

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// settle waits until the heights of the running nodes have not changed
// for the given time: blocks that were already decided when a fault was
// injected are committed by then.
func settle(t *testing.T, c *Cluster, quiet time.Duration) []int64 {
	t.Helper()
	deadline := time.Now().Add(waitLong)
	last := c.Heights()
	since := time.Now()
	for time.Since(since) < quiet {
		if time.Now().After(deadline) {
			t.Fatalf("heights do not settle: %v", last)
		}
		time.Sleep(20 * time.Millisecond)
		cur := c.Heights()
		for i := range cur {
			if cur[i] != last[i] {
				last, since = cur, time.Now()
				break
			}
		}
	}
	return last
}

func repoNames(c *Cluster, i int) []string {
	var out []string
	seen := map[string]bool{}
	for _, hd := range c.Heads() {
		if hd.Node != i {
			continue
		}
		for k := range hd.Branches {
			r := k[:strings.IndexByte(k, '/')]
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestCrashRestart: one of four validators is killed (f = 1); the
// network keeps committing; the restarted node catches up and agrees.
func TestCrashRestart(t *testing.T) {
	c := New(t, Options{})
	k := NewKey()
	_, err := c.CreateRepo(0, "before", k)
	must(t, err)

	must(t, c.Kill(3))
	h0 := c.MaxHeight()
	start := time.Now()
	must(t, c.WaitNodesHeight([]int{0, 1, 2}, h0+8, waitLong))
	t.Logf("3 of 4 validators: 8 blocks in %v (%v per block; the dead node's turns as proposer cost a timeout_propose each)",
		time.Since(start).Round(time.Millisecond), (time.Since(start) / 8).Round(time.Millisecond))
	_, _, err = c.CreateRepoWithGenesis(1, "during", k, map[string][]byte{"a/b/c": []byte("c"), "d": []byte("d")})
	must(t, err)

	behind := c.MaxHeight() - h0
	start = time.Now()
	must(t, c.Restart(3))
	up := time.Since(start)
	must(t, c.WaitRepo("during", waitLong, 3))
	must(t, c.WaitNodeHeight(3, c.MaxHeight(), waitLong))
	t.Logf("restart: node up after %v, caught up (%d+ blocks behind) after %v",
		up.Round(time.Millisecond), behind, time.Since(start).Round(time.Millisecond))

	// The restarted node takes part in consensus again: all four commit.
	h := c.MaxHeight()
	must(t, c.WaitAllHeight(h+6, waitLong))
	_, err = c.CreateRepo(3, "after", k)
	must(t, err)
	must(t, c.WaitRepo("after", waitLong))
	c.MustCheck(t)
}

// TestCrashRestartSubprocess: nodes are OS processes; one validator is
// killed with SIGKILL several times while transactions are being
// submitted, restarted, and must catch up and agree.
func TestCrashRestartSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	c := New(t, Options{Mode: Subprocess})
	k := NewKey()

	var submitted, accepted atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			case <-time.After(25 * time.Millisecond):
			}
			var tx []byte
			var err error
			if name := fmt.Sprintf("load-%05d", n); n%8 == 0 {
				// With a genesis commit: objects and history.
				tx, _, err = CreateRepoWithGenesisTx(c.ChainID(), name, k, map[string][]byte{
					"README": []byte(name), "src/lib.go": []byte("package lib\n"), "data/blob": bytes.Repeat([]byte{byte(n)}, 4096)})
			} else {
				tx, err = CreateRepoTx(c.ChainID(), name, k)
			}
			if err != nil {
				t.Error(err)
				return
			}
			submitted.Add(1)
			// Nodes 0 and 1 are never killed.
			if res, err := c.BroadcastTxSync(n%2, tx); err == nil && res.Code == types.CodeOK {
				accepted.Add(1)
			}
		}
	}()

	const victim = 2
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	for cycle := 0; cycle < 4; cycle++ {
		time.Sleep(time.Duration(rng.Intn(400)) * time.Millisecond)
		hk, _ := c.Height(victim)
		must(t, c.Kill(victim))
		h := c.MaxHeight()
		must(t, c.WaitNodesHeight([]int{0, 1, 3}, h+4, waitLong))
		start := time.Now()
		must(t, c.Restart(victim))
		up := time.Since(start)
		h = c.MaxHeight()
		must(t, c.WaitNodeHeight(victim, h, waitLong))
		// Catch-up takes >= 3 s: CometBFT's block pool waits peerConnWait
		// (3 s, a constant in blocksync/pool.go) before its first block
		// request, then switches to consensus on a 1 s ticker.
		t.Logf("cycle %d: SIGKILL at height %d, restarted at network height %d, process up after %v, caught up after %v",
			cycle, hk, h, up.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
		if rep := c.Check(); !rep.OK() {
			t.Fatalf("after cycle %d: %s", cycle, rep)
		}
	}
	close(stop)
	wg.Wait()
	h := c.MaxHeight()
	must(t, c.WaitAllHeight(h+4, waitLong))
	t.Logf("load: %d transactions submitted, %d passed CheckTx, %d repositories on node %d",
		submitted.Load(), accepted.Load(), len(repoNames(c, victim)), victim)
	if len(repoNames(c, victim)) == 0 {
		t.Fatal("no transaction was committed")
	}
	if rep := c.MustCheck(t); rep.EntriesChecked == 0 || rep.ObjectsChecked == 0 || rep.StatesCompared == 0 {
		t.Fatalf("the checker did not walk any history: %+v", rep)
	}

	// Close leaves no dosrd process behind.
	var pids []int
	for i := 0; i < c.N(); i++ {
		if pid := c.PID(i); pid > 0 {
			pids = append(pids, pid)
		}
	}
	if len(pids) != c.N() {
		t.Fatalf("expected %d processes, have pids %v", c.N(), pids)
	}
	start := time.Now()
	c.Close()
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); err == nil {
			t.Errorf("dosrd process %d is still alive after Close", pid)
		}
	}
	t.Logf("Close (SIGTERM, clean shutdown of %d processes) took %v", len(pids), time.Since(start).Round(time.Millisecond))
}

// TestSubprocessExitWithParent: a dosrd started with --exit-with-parent
// stops by itself when its parent process dies, so nodes of a test
// process that is killed (e.g. by the go test timeout) do not linger.
func TestSubprocessExitWithParent(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	bin, err := dosrdBinary("")
	must(t, err)
	home := t.TempDir()
	priv := ed25519.GenPrivKey()
	pvk := &privval.FilePVKey{Address: priv.PubKey().Address(), PubKey: priv.PubKey(), PrivKey: priv}
	gen, err := node.NewGenesis("dosr-orphan", time.Now(), []*privval.FilePVKey{pvk})
	must(t, err)
	addrs, err := node.FreeAddrs(2)
	must(t, err)
	must(t, node.SaveConfig(node.Config{
		Home: home, Genesis: gen, NodeKey: &p2p.NodeKey{PrivKey: ed25519.GenPrivKey()}, PrivValKey: pvk,
		P2PListen: addrs[0], RPCListen: addrs[1], Consensus: node.FastTimeouts(), App: app.DefaultConfig(),
		LogLevel: "error",
	}))
	// The shell is the parent; it exits right after printing the pid.
	out, err := exec.Command("sh", "-c", fmt.Sprintf("%q --home %q --exit-with-parent >%q 2>&1 & echo $!", bin, home, filepath.Join(home, "dosrd.out"))).Output()
	must(t, err)
	var pid int
	_, err = fmt.Sscan(string(out), &pid)
	must(t, err)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	start := time.Now()
	deadline := start.Add(30 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(filepath.Join(home, "dosrd.out"))
			t.Fatalf("orphaned dosrd %d still alive after 30 s:\n%s", pid, lastLines(string(b), 5))
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(filepath.Join(home, "dosrd.out"))
	t.Logf("orphaned dosrd exited after %v; output:\n%s", time.Since(start).Round(time.Millisecond), lastLines(string(b), 3))
	if !strings.Contains(string(b), "parent exited") {
		t.Errorf("dosrd did not stop because its parent exited")
	}
}

// TestCrashPoints: a validator process is killed at the two critical
// points of committing a block - just before and just after the
// application's durable commit, in both cases before CometBFT has saved
// its own state for the block - and must recover to the same state as
// the others.
func TestCrashPoints(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	c := New(t, Options{Mode: Subprocess})
	k := NewKey()
	const victim = 1
	for n, after := range []bool{false, true} {
		must(t, c.Stop(victim))
		// Something to execute in the blocks around the crash.
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for x := 0; ; x++ {
				select {
				case <-stop:
					return
				case <-time.After(30 * time.Millisecond):
				}
				tx, _, err := CreateRepoWithGenesisTx(c.ChainID(), fmt.Sprintf("cp%d-%04d", n, x), k,
					map[string][]byte{"f": []byte(fmt.Sprint(n, x))})
				if err == nil {
					_, _ = c.BroadcastTxSync(0, tx)
				}
			}
		}()
		target := c.MaxHeight() + 12
		must(t, c.RestartWithCrashPoint(victim, node.CrashPoint{Height: target, AfterAppCommit: after}))
		must(t, c.WaitExit(victim, waitLong))
		recs := c.Commits(victim)
		_, committed := recs[target]
		last := int64(0)
		for h := range recs {
			if h > last {
				last = h
			}
		}
		t.Logf("crash point at height %d, after app commit = %v: process died; last commit record of the application is for height %d",
			target, after, last)
		if !after && committed {
			t.Fatalf("crash before commit, but the application committed height %d", target)
		}
		if last > target || last < target-1 {
			t.Fatalf("crash point missed: last commit record %d, target %d", last, target)
		}
		start := time.Now()
		must(t, c.Restart(victim))
		must(t, c.WaitNodeHeight(victim, c.MaxHeight(), waitLong))
		t.Logf("recovered and caught up %v after the restart", time.Since(start).Round(time.Millisecond))
		close(stop)
		wg.Wait()
		must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
		rep := c.MustCheck(t)
		if !rep.OK() {
			t.FailNow()
		}
		// The application committed the crash height exactly once:
		// after the restart if it died before its commit (the
		// handshake replays the block), not again if it died after.
		raw, err := node.ReadCommitLog(filepath.Join(c.Home(victim), "commits.jsonl"))
		must(t, err)
		times := 0
		for _, r := range raw {
			if r.Height == target {
				times++
			}
		}
		if times != 1 {
			t.Fatalf("the application committed height %d %d times", target, times)
		}
		out, _ := exec.Command("grep", "-h", "-E", "ABCI Handshake App Info|Replay last block|ABCI Replay Blocks|Completed ABCI Handshake", filepath.Join(c.Home(victim), "node.log")).Output()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 4 {
			lines = lines[len(lines)-4:]
		}
		for _, l := range lines {
			if len(l) > 230 {
				l = l[:230]
			}
			t.Logf("node log: %s", l)
		}
	}
}

// TestTwoOfFourStopped: with 2 of 4 validators down there is no quorum
// (3 of 4 needed): no block is committed, nothing is violated; one
// restart restores liveness.
func TestTwoOfFourStopped(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	c := New(t, Options{})
	k := NewKey()
	_, err := c.CreateRepo(0, "before", k)
	must(t, err)

	must(t, c.Stop(2))
	must(t, c.Stop(3))
	settle(t, c, 500*time.Millisecond)
	h := c.MaxHeight()

	tx, err := CreateRepoTx(c.ChainID(), "stalled", k)
	must(t, err)
	res, err := c.BroadcastTxSync(0, tx)
	must(t, err)
	if res.Code != types.CodeOK {
		t.Fatalf("CheckTx: %d %s", res.Code, res.Log)
	}
	if p := c.Progress(5 * time.Second); p != 0 {
		t.Fatalf("2 of 4 validators committed %d blocks", p)
	}
	if c.HasRepo(0, "stalled") || c.HasRepo(1, "stalled") {
		t.Fatal("transaction took effect without a quorum")
	}
	if rep := c.Check(); !rep.OK() {
		t.Fatalf("during the stall: %s", rep)
	}

	start := time.Now()
	must(t, c.Restart(2))
	must(t, c.WaitHeight(h+1, waitLong))
	t.Logf("liveness restored %v after restarting one validator (stalled for about 6 s at height %d)",
		time.Since(start).Round(time.Millisecond), h)
	must(t, c.WaitRepo("stalled", waitLong, 0, 1, 2))

	must(t, c.Restart(3))
	must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
	c.MustCheck(t)
}

func peersOf(t *testing.T, c *Cluster, i int) int {
	t.Helper()
	ids, err := c.Peers(i)
	must(t, err)
	return len(ids)
}

// TestPartition22: a 2|2 partition stops progress on both sides; after
// healing progress resumes and agreement holds.
func TestPartition22(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	c := New(t, Options{})
	k := NewKey()
	_, err := c.CreateRepo(0, "before", k)
	must(t, err)

	start := time.Now()
	c.Partition([]int{0, 1}, []int{2, 3})
	must(t, c.waitFor(10*time.Second, "peers to drop", func() bool {
		for i := 0; i < 4; i++ {
			if ids, err := c.Peers(i); err != nil || len(ids) != 1 {
				return false
			}
		}
		return true
	}))
	t.Logf("all nodes noticed the partition after %v", time.Since(start).Round(time.Millisecond))
	settle(t, c, 500*time.Millisecond)
	h := c.MaxHeight()

	// One transaction on each side.
	for side, nd := range []int{0, 2} {
		tx, err := CreateRepoTx(c.ChainID(), fmt.Sprintf("side%d", side), k)
		must(t, err)
		_, err = c.BroadcastTxSync(nd, tx)
		must(t, err)
	}
	if p := c.Progress(5 * time.Second); p != 0 {
		t.Fatalf("progress during a 2|2 partition: %d blocks", p)
	}
	for i := 0; i < 4; i++ {
		if n := peersOf(t, c, i); n != 1 {
			t.Fatalf("node %d has %d peers during the partition", i, n)
		}
	}
	if rep := c.Check(); !rep.OK() {
		t.Fatalf("during the partition: %s", rep)
	}

	start = time.Now()
	c.Heal()
	must(t, c.WaitConnected(waitLong))
	conn := time.Since(start)
	must(t, c.WaitAllHeight(h+1, waitLong))
	t.Logf("heal: all links re-established after %v, first new block on all nodes after %v",
		conn.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	must(t, c.WaitRepo("side0", waitLong))
	must(t, c.WaitRepo("side1", waitLong))
	must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
	c.MustCheck(t)
}

// TestHealPassive measures how long CometBFT itself needs to
// re-establish connections after a partition is healed, without the
// harness re-dialling, for partitions of different lengths.
func TestHealPassive(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	c := New(t, Options{PassiveReconnect: true})
	must(t, c.WaitConnected(waitLong))
	for _, hold := range []time.Duration{1 * time.Second, 3 * time.Second, 6 * time.Second, 9 * time.Second} {
		c.Partition([]int{0, 1}, []int{2, 3})
		time.Sleep(hold)
		h := c.MaxHeight()
		start := time.Now()
		c.Heal()
		must(t, c.WaitHeight(h+1, waitLong))
		first := time.Since(start)
		must(t, c.WaitConnected(waitLong))
		t.Logf("partition held %v: first new block %v after heal, all 4 cut links re-established after %v",
			hold, first.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("reconnection took %v", d)
		}
	}
	must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
	c.MustCheck(t)
}

// TestPartition31: in a 3|1 partition the majority progresses and the
// minority does not; after healing the minority catches up.
func TestPartition31(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	c := New(t, Options{})
	k := NewKey()
	_, err := c.CreateRepo(0, "before", k)
	must(t, err)

	c.Partition([]int{0, 1, 2}, []int{3})
	must(t, c.waitFor(10*time.Second, "node 3 to lose its peers", func() bool {
		ids, err := c.Peers(3)
		return err == nil && len(ids) == 0
	}))
	// Node 3 may still commit a block it had all votes for.
	time.Sleep(500 * time.Millisecond)
	h3, err := c.Height(3)
	must(t, err)
	// A transaction submitted to the minority must not take effect
	// there.
	tx, err := CreateRepoTx(c.ChainID(), "minority", k)
	must(t, err)
	_, err = c.BroadcastTxSync(3, tx)
	must(t, err)

	h := c.MaxHeight()
	must(t, c.WaitNodesHeight([]int{0, 1, 2}, h+8, waitLong))
	_, err = c.CreateRepo(1, "majority", k)
	must(t, err)
	if got, _ := c.Height(3); got != h3 {
		t.Fatalf("isolated node went from height %d to %d", h3, got)
	}
	if c.HasRepo(3, "minority") || c.HasRepo(3, "majority") {
		t.Fatal("isolated node changed its state")
	}
	if rep := c.Check(); !rep.OK() {
		t.Fatalf("during the partition: %s", rep)
	}

	behind := c.MaxHeight() - h3
	start := time.Now()
	c.Heal()
	must(t, c.WaitConnected(waitLong))
	conn := time.Since(start)
	must(t, c.WaitRepo("majority", waitLong, 3))
	must(t, c.WaitNodeHeight(3, c.MaxHeight(), waitLong))
	t.Logf("heal: links re-established after %v, node 3 caught up %d blocks after %v",
		conn.Round(time.Millisecond), behind, time.Since(start).Round(time.Millisecond))
	// The minority's transaction reaches the others through the
	// mempool once the network is whole.
	must(t, c.WaitRepo("minority", waitLong))
	must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
	c.MustCheck(t)
}

// TestNetemBlockInterval: the block interval and the commit latency of
// a transaction grow with the one-way delay configured on all links.
func TestNetemBlockInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	to := node.FastTimeouts()
	to.Propose = 3 * time.Second // well above the largest delay
	to.Prevote, to.Precommit = time.Second, time.Second
	c := New(t, Options{Timeouts: to, PeerGossipSleep: 10 * time.Millisecond})
	k := NewKey()

	type result struct {
		d        time.Duration
		interval IntervalStats
		latency  time.Duration
		rounds   int
	}
	var results []result
	const blocks = 20
	for n, d := range []time.Duration{0, 10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond} {
		c.Net().SetUniformDelay(d, 0)
		must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
		h1 := c.MaxHeight()
		// Commit latency: the rest of the current height plus one full
		// height, so each sample carries up to one interval of phase
		// noise; the median of 8 is used.
		const txs = 8
		var lats []time.Duration
		for i := 0; i < txs; i++ {
			start := time.Now()
			_, err := c.CreateRepo(i%4, fmt.Sprintf("delay%d-%d", n, i), k)
			must(t, err)
			lats = append(lats, time.Since(start))
		}
		must(t, c.WaitAllHeight(h1+blocks, waitLong))
		r := result{d: d, interval: c.BlockIntervals(0, h1, h1+blocks), latency: percentile(lats, 0.5)}
		rounds, err := c.Rounds(0, h1, h1+blocks)
		must(t, err)
		for _, x := range rounds {
			if x > 0 {
				r.rounds++
			}
		}
		results = append(results, r)
		t.Logf("one-way delay %v: block interval %v; BroadcastTxCommit latency (median of %d) %v; heights decided after round 0: %d",
			d, r.interval, txs, r.latency.Round(time.Millisecond), r.rounds)
	}
	base := results[0]
	for k, r := range results[1:] {
		// Consistent: more delay, longer block intervals. Compared on the
		// minimum (the protocol's floor: timeout_commit + gossip + about
		// 3 one-way delays), which load on the machine can only raise.
		if prev := results[k]; r.interval.Min <= prev.interval.Min {
			t.Errorf("delay %v: minimum interval %v not above the one at delay %v (%v)",
				r.d, r.interval.Min, prev.d, prev.interval.Min)
		}
		inc := r.interval.Median - base.interval.Median
		t.Logf("one-way delay %v: median block interval +%v = %.1f x delay (minimum +%v); commit latency +%v = %.1f x delay",
			r.d, inc.Round(time.Millisecond), float64(inc)/float64(r.d), (r.interval.Min - base.interval.Min).Round(time.Millisecond),
			(r.latency - base.latency).Round(time.Millisecond), float64(r.latency-base.latency)/float64(r.d))
		if r.d < 50*time.Millisecond {
			// A 10 ms step is below the resolution of the medians (they
			// carry +-10 ms of scheduling noise, more under -race).
			continue
		}
		// A height needs at least proposal, prevotes and precommits to
		// cross the network: about 3 one-way delays (measured 2.7..3.0 x).
		if inc < 3*r.d/2 || inc > 8*r.d+150*time.Millisecond {
			t.Errorf("delay %v: block interval grew by %v, expected between %v and %v",
				r.d, inc, 3*r.d/2, 8*r.d+150*time.Millisecond)
		}
		// Expected growth of the commit latency: about 1.5 heights, i.e.
		// 4..5 x delay; the median of 8 samples still has +-50 ms of
		// phase noise, hence the loose bound.
		if r.latency < base.latency+3*r.d/2 {
			t.Errorf("delay %v: commit latency %v, without delay %v", r.d, r.latency, base.latency)
		}
	}
	c.Net().SetUniformDelay(0, 0)
	c.MustCheck(t)
}

// TestDuplicateReorderedTx: several conflicting CreateRepo transactions
// for one repository ID, and duplicates of each, are submitted to
// different nodes in different orders. Exactly one takes effect.
func TestDuplicateReorderedTx(t *testing.T) {
	c := New(t, Options{})
	const repos = 5
	const rivals = 4
	type cand struct {
		key Key
		tx  []byte
	}
	cands := make([][]cand, repos)
	for r := range cands {
		for v := 0; v < rivals; v++ {
			k := NewKey()
			tx, err := CreateRepoTx(c.ChainID(), fmt.Sprintf("contested-%d", r), k)
			must(t, err)
			cands[r] = append(cands[r], cand{k, tx})
		}
	}
	h0 := c.MaxHeight()
	var checkOK, checkRejected, dupErr atomic.Int64
	var wg sync.WaitGroup
	for nd := 0; nd < 4; nd++ {
		wg.Add(1)
		go func(nd int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(nd) + 1))
			// Every node receives every transaction twice, each node
			// in its own order.
			var list [][]byte
			for r := range cands {
				for _, cd := range cands[r] {
					list = append(list, cd.tx, cd.tx)
				}
			}
			rng.Shuffle(len(list), func(a, b int) { list[a], list[b] = list[b], list[a] })
			for _, tx := range list {
				res, err := c.BroadcastTxSync(nd, tx)
				switch {
				case err != nil:
					dupErr.Add(1) // "tx already exists in cache"
				case res.Code == types.CodeOK:
					checkOK.Add(1)
				case res.Code == types.CodeRepoExists:
					checkRejected.Add(1)
				default:
					t.Errorf("CheckTx: unexpected code %d (%s): %s", res.Code, types.CodeName(res.Code), res.Log)
				}
			}
		}(nd)
	}
	wg.Wait()
	for r := 0; r < repos; r++ {
		must(t, c.WaitRepo(fmt.Sprintf("contested-%d", r), waitLong))
	}
	must(t, c.WaitAllHeight(c.MaxHeight()+4, waitLong))
	h1 := c.MaxHeight()
	t.Logf("submissions: %d passed CheckTx, %d rejected by CheckTx with repo_exists, %d refused by the mempool cache",
		checkOK.Load(), checkRejected.Load(), dupErr.Load())

	included, failed := 0, 0
	for r := range cands {
		winners := 0
		var winner cand
		for _, cd := range cands[r] {
			res, err := c.FindTx(0, cd.tx, h0, h1)
			must(t, err)
			for _, x := range res {
				included++
				switch x.Code {
				case types.CodeOK:
					winners++
					winner = cd
				case types.CodeRepoExists:
					failed++
				default:
					t.Errorf("repo %d: tx in block %d has code %d (%s)", r, x.Height, x.Code, types.CodeName(x.Code))
				}
			}
		}
		if winners != 1 {
			t.Fatalf("contested-%d: %d CreateRepo transactions succeeded", r, winners)
		}
		for i := 0; i < 4; i++ {
			st := c.App(i).Committed()
			repo := st.Repos[fmt.Sprintf("contested-%d", r)]
			if repo == nil || !bytes.Equal(repo.Creator, winner.key.Pub) {
				t.Fatalf("node %d: contested-%d is not owned by the winning transaction's key", i, r)
			}
		}
	}
	t.Logf("chain: %d inclusions of the %d distinct transactions, %d succeeded, %d failed with repo_exists",
		included, repos*rivals, repos, failed)
	c.MustCheck(t)
}

// TestByzantineApp: validator 3 runs a Byzantine application that puts
// garbage and a replayed transaction at the front of every block it
// proposes and votes for every proposal.
func TestByzantineApp(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for _, strict := range []bool{true, false} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) { testByzantineApp(t, strict) })
	}
}

func testByzantineApp(t *testing.T, strict bool) {
	const byz = 3
	const window = 24 // heights per measurement: 6 turns of each proposer
	var active atomic.Bool
	var injected atomic.Pointer[[][]byte]
	var calls atomic.Int64
	faults := &app.Faults{
		AcceptAllProposals: true,
		InjectTxs: func(int64) [][]byte {
			if !active.Load() {
				return nil
			}
			calls.Add(1)
			return *injected.Load()
		},
	}
	acfg := app.DefaultConfig()
	acfg.StrictProposals = strict
	c := New(t, Options{App: &acfg, Faults: map[int]*app.Faults{byz: faults}})
	k := NewKey()
	old, err := CreateRepoTx(c.ChainID(), "victim", k)
	must(t, err)
	res, err := c.BroadcastTxCommit(0, old)
	must(t, err)
	if res.TxResult.Code != types.CodeOK {
		t.Fatalf("create: %v", res.TxResult)
	}

	garbage := make([]byte, 300)
	_, _ = rand.Read(garbage)
	// A well-formed CreateRepo with a broken signature.
	forged, err := CreateRepoTx(c.ChainID(), "forged", k)
	must(t, err)
	forged = append([]byte(nil), forged...)
	forged[len(forged)-1] ^= 1
	inj := [][]byte{garbage, old, forged}
	injected.Store(&inj)

	measure := func(label string) (IntervalStats, int, int) {
		must(t, c.WaitAllHeight(c.MaxHeight()+2, waitLong))
		h1 := c.MaxHeight()
		must(t, c.WaitNodesHeight([]int{0, 1, 2}, h1+window, 5*time.Minute))
		st := c.BlockIntervals(0, h1, h1+window)
		rounds, err := c.Rounds(0, h1+1, h1+window)
		must(t, err)
		extra, byzBlocks := 0, 0
		for h, r := range rounds {
			extra += int(r)
			p, err := c.Proposer(0, h)
			must(t, err)
			if p == byz {
				byzBlocks++
			}
		}
		t.Logf("%s: block interval %v; %d extra rounds in %d heights; %d blocks proposed by the Byzantine validator",
			label, st, extra, window, byzBlocks)
		return st, extra, byzBlocks
	}
	base, baseExtra, _ := measure("fault inactive")
	hA := c.MaxHeight()
	active.Store(true)
	faulty, extra, byzBlocks := measure(fmt.Sprintf("fault active, strict=%v", strict))
	active.Store(false)
	hB := c.MaxHeight()

	if calls.Load() == 0 {
		t.Fatal("the Byzantine validator never proposed")
	}
	dt := faulty.Mean*time.Duration(faulty.Blocks) - base.Mean*time.Duration(base.Blocks)
	turns := window / 4
	t.Logf("RESULT strict=%v: time for %d heights changed by %v against the same network without the fault (%v per turn of the Byzantine proposer; timeouts propose/prevote/precommit/commit = %v/%v/%v/%v); extra rounds %d (baseline %d); PrepareProposal calls on the Byzantine node %d",
		strict, window, dt.Round(time.Millisecond), (dt / time.Duration(turns)).Round(time.Millisecond),
		node.FastTimeouts().Propose, node.FastTimeouts().Prevote, node.FastTimeouts().Precommit, node.FastTimeouts().Commit,
		extra, baseExtra, calls.Load())

	// No injected transaction took effect.
	inclusions := 0
	for _, tx := range inj {
		found, err := c.FindTx(0, tx, hA, hB)
		must(t, err)
		for _, x := range found {
			inclusions++
			if x.Code == types.CodeOK {
				t.Errorf("injected transaction succeeded in block %d", x.Height)
			}
		}
	}
	for i := 0; i < 3; i++ {
		if got := repoNames(c, i); len(got) != 1 || got[0] != "victim" {
			t.Errorf("node %d has repositories %v", i, got)
		}
		st := c.App(i).Committed().Repos["victim"]
		if st.PolicyVersion != 1 || len(st.Branches) != 1 {
			t.Errorf("node %d: victim repository changed: %+v", i, st)
		}
	}
	rejected := 0
	for i := 0; i < 3; i++ {
		rejected += c.App(i).StatsSnapshot().RejectedProposals
	}
	t.Logf("strict=%v: %d inclusions of injected transactions in blocks %d..%d (all failed); proposals rejected by honest nodes: %d",
		strict, inclusions, hA, hB, rejected)
	if strict {
		if inclusions != 0 {
			t.Errorf("strict validators let %d injected transactions into the chain", inclusions)
		}
		if byzBlocks != 0 {
			t.Errorf("%d blocks of the Byzantine proposer were decided", byzBlocks)
		}
		if rejected == 0 || extra <= baseExtra {
			t.Errorf("expected rejected proposals and extra rounds, got %d and %d", rejected, extra)
		}
	} else {
		if inclusions == 0 {
			t.Errorf("lenient validators: expected the injected transactions in the chain (with failure codes)")
		}
	}
	must(t, c.WaitAllHeight(c.MaxHeight()+3, waitLong))
	rep := c.MustCheck(t)
	// The Byzantine application executes blocks like an honest one (its
	// faults are in PrepareProposal/ProcessProposal), so although the
	// checker excludes it, its app hash must equal the honest one here.
	recs := c.Commits(byz)
	ref := c.Commits(0)
	for h, r := range recs {
		if x, ok := ref[h]; ok && !bytes.Equal(x.AppHash, r.AppHash) {
			t.Errorf("height %d: Byzantine node's app hash differs", h)
		}
	}
	_ = rep
}
