package testnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	jsonrpc "github.com/cometbft/cometbft/rpc/jsonrpc/client"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/dosr/dosr/pkg/app"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/node"
)

// Mode selects how nodes are run.
type Mode int

const (
	// InProcess runs every node inside the calling process. Tests can
	// reach into the applications (Cluster.App) and give them Byzantine
	// faults, but a node cannot be killed at an arbitrary instruction.
	InProcess Mode = iota
	// Subprocess runs every node as a cmd/dosrd process, which can be
	// killed with SIGKILL. Nodes are observed through HTTP RPC and the
	// commit log files.
	Subprocess
)

func (m Mode) String() string {
	if m == Subprocess {
		return "subprocess"
	}
	return "in-process"
}

// Options configure a cluster. The zero value is a 4-validator in-process
// network with fast timeouts and no emulated delay.
type Options struct {
	// Validators (default 4) have equal voting power. They are nodes
	// 0..Validators-1; the FullNodes (non-validators) follow.
	Validators int
	FullNodes  int
	Mode       Mode
	// Dir is the directory for the nodes' homes (default: a fresh
	// temporary directory, removed by Close unless KeepDir is set).
	Dir     string
	KeepDir bool
	ChainID string // default "dosr-testnet"

	// Timeouts are the consensus timeouts of all nodes (default
	// node.FastTimeouts()).
	Timeouts node.Timeouts
	// App is the application configuration of all nodes (default
	// app.DefaultConfig()). OnCommit is chained after the harness's
	// recorder. Use AppFor for per-node changes.
	App *app.Config
	// AppFor, if set, may modify the app configuration of node i.
	AppFor func(i int, cfg *app.Config)
	// Faults gives the listed nodes a Byzantine application. Such nodes
	// are excluded from the honest set of the invariant checker.
	// In-process mode only.
	Faults map[int]*app.Faults
	// OnCommit, if set, is called for every block committed by any
	// node. In-process mode only.
	OnCommit func(i int, ci app.CommitInfo)

	// Delays is the initial one-way delay matrix (nil: no delay), with
	// jitter JitterFrac*delay.
	Delays     Matrix
	JitterFrac float64

	// HTTPRPC starts the HTTP RPC server of every node (always on in
	// subprocess mode).
	HTTPRPC bool
	// LogLevel of the nodes ("info" by default); logs go to
	// <home>/node.log.
	LogLevel string
	// TxIndex is "kv" (default) or "null".
	TxIndex string
	// ConnSyncABCI: see node.Config.
	ConnSyncABCI bool
	// PeerGossipSleep: see node.Config (0: CometBFT's default, 100 ms).
	PeerGossipSleep time.Duration
	// NoStateDigests disables hashing the application state after every
	// block (the checker then compares app hashes only).
	NoStateDigests bool
	// PassiveReconnect disables the harness's active re-dialling after a
	// link is unblocked or a node restarted, leaving reconnection to
	// CometBFT's persistent-peer logic (5..8 s between attempts).
	PassiveReconnect bool
	// StartTimeout bounds the wait for height 2 (default 60 s).
	StartTimeout time.Duration
	// DosrdBin is the dosrd binary for subprocess mode (default: built
	// with "go build" on first use).
	DosrdBin string
}

// Cluster is a running network.
type Cluster struct {
	opts    Options
	dir     string
	ownDir  bool
	chainID string
	genesis *cmttypes.GenesisDoc
	net     *Net
	members []*member
	dosrd   string

	ctx    context.Context
	cancel context.CancelFunc
	bg     sync.WaitGroup

	closeOnce sync.Once
}

// member is one node of the cluster.
type member struct {
	idx       int
	validator bool
	byzantine bool
	id        p2p.ID
	cfg       node.Config
	rec       *recorder

	life sync.Mutex // serialises start/stop

	mu    sync.RWMutex
	n     *node.Node       // in-process, while running
	cmd   *exec.Cmd        // subprocess, while running
	exitC chan struct{}    // closed when the subprocess has exited
	rpc   rpcclient.Client // while running
	raw   *jsonrpc.Client  // subprocess: for unsafe routes
	holds []net.Listener   // port placeholders while down
	crash *node.CrashPoint // for the next start (subprocess)
	stops int              // number of stops (clean or not)
}

// New starts a cluster for a test; it fails the test on error and stops
// the cluster when the test ends.
func New(tb testing.TB, opts Options) *Cluster {
	tb.Helper()
	if opts.Dir == "" {
		// Not tb.TempDir(): its cleanup fails the test if a node that
		// is still shutting down writes to the directory.
		d, err := os.MkdirTemp("", "dosr-testnet-")
		if err != nil {
			tb.Fatal(err)
		}
		opts.Dir = d
		if !opts.KeepDir {
			tb.Cleanup(func() {
				if tb.Failed() {
					tb.Logf("testnet: keeping %s for inspection", d)
					return
				}
				os.RemoveAll(d)
			})
		}
	}
	c, err := Start(opts)
	if err != nil {
		tb.Fatalf("testnet: %v", err)
	}
	tb.Cleanup(c.Close)
	return c
}

// Start starts a cluster and waits until every node has reached height 2.
func Start(opts Options) (_ *Cluster, err error) {
	if opts.Validators == 0 {
		opts.Validators = 4
	}
	if opts.ChainID == "" {
		opts.ChainID = "dosr-testnet"
	}
	if opts.Timeouts == (node.Timeouts{}) {
		opts.Timeouts = node.FastTimeouts()
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "info"
	}
	if opts.StartTimeout == 0 {
		opts.StartTimeout = 60 * time.Second
	}
	if opts.Mode == Subprocess && (len(opts.Faults) > 0 || opts.OnCommit != nil || opts.AppFor != nil) {
		return nil, errors.New("Faults, OnCommit and AppFor need in-process mode")
	}
	c := &Cluster{opts: opts, chainID: opts.ChainID}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if opts.Dir == "" {
		c.dir, err = os.MkdirTemp("", "dosr-testnet-")
		if err != nil {
			return nil, err
		}
		c.ownDir = !opts.KeepDir
	} else {
		c.dir = opts.Dir
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			return nil, err
		}
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if opts.Mode == Subprocess {
		if c.dosrd, err = dosrdBinary(opts.DosrdBin); err != nil {
			return nil, err
		}
	}

	n := opts.Validators + opts.FullNodes
	if c.net, err = NewNet(n); err != nil {
		return nil, err
	}
	if opts.Delays != nil {
		c.net.SetAllDelays(opts.Delays, opts.JitterFrac)
	}
	if !opts.PassiveReconnect {
		c.net.OnUnblock(func(i, j int) { c.ensureConnected(i, j, 15*time.Second) })
	}

	// Keys and genesis.
	pvKeys := make([]*privval.FilePVKey, n)
	nodeKeys := make([]*p2p.NodeKey, n)
	for i := 0; i < n; i++ {
		priv := ed25519.GenPrivKey()
		pvKeys[i] = &privval.FilePVKey{Address: priv.PubKey().Address(), PubKey: priv.PubKey(), PrivKey: priv}
		nodeKeys[i] = &p2p.NodeKey{PrivKey: ed25519.GenPrivKey()}
	}
	c.genesis, err = node.NewGenesis(c.chainID, time.Now(), pvKeys[:opts.Validators])
	if err != nil {
		return nil, err
	}

	// Listen addresses: p2p for everyone, RPC if served over HTTP.
	needRPC := opts.HTTPRPC || opts.Mode == Subprocess
	count := n
	if needRPC {
		count = 2 * n
	}
	addrs, err := node.FreeAddrs(count)
	if err != nil {
		return nil, err
	}

	for i := 0; i < n; i++ {
		m := &member{idx: i, validator: i < opts.Validators, id: nodeKeys[i].ID(), rec: newRecorder()}
		home := filepath.Join(c.dir, fmt.Sprintf("node%d", i))
		acfg := app.DefaultConfig()
		if opts.App != nil {
			acfg = *opts.App
		}
		if f := opts.Faults[i]; f != nil {
			acfg.Faults = f
			m.byzantine = true
		}
		if opts.AppFor != nil {
			opts.AppFor(i, &acfg)
		}
		m.cfg = node.Config{
			Home: home, Moniker: fmt.Sprintf("node%d", i),
			Genesis: c.genesis, NodeKey: nodeKeys[i], PrivValKey: pvKeys[i],
			P2PListen: addrs[i],
			Consensus: opts.Timeouts,
			LogLevel:  opts.LogLevel, LogFile: filepath.Join(home, "node.log"),
			TxIndex:         opts.TxIndex,
			ConnSyncABCI:    opts.ConnSyncABCI,
			PeerGossipSleep: opts.PeerGossipSleep,
			App:             acfg,
		}
		if needRPC {
			m.cfg.RPCListen = addrs[n+i]
			m.cfg.RPCUnsafe = true
		}
		if opts.Mode == Subprocess {
			m.cfg.CommitLog = filepath.Join(home, "commits.jsonl")
		}
		c.members = append(c.members, m)
		c.net.SetUpstream(i, m.cfg.P2PListen)
		// Hold the ports until the node binds them: the proxies and the
		// nodes started before this one open outgoing connections whose
		// ephemeral source ports come from the same range.
		m.reservePorts()
	}
	// Persistent peers: node i dials every j>i through the proxy.
	for i, m := range c.members {
		for j := i + 1; j < n; j++ {
			m.cfg.PersistentPeers = append(m.cfg.PersistentPeers, c.peerAddr(i, j))
		}
		if err := node.SaveConfig(m.cfg); err != nil {
			return nil, err
		}
	}

	// Start in reverse order: when node i starts, all nodes it dials are
	// already listening, so no dial fails and no reconnection timer
	// (5..8 s) delays the start.
	for i := n - 1; i >= 0; i-- {
		if err := c.start(i); err != nil {
			return nil, fmt.Errorf("start node %d: %w", i, err)
		}
	}
	if !opts.PassiveReconnect {
		// CometBFT dials its persistent peers after a random delay of
		// up to 3 s; do not wait for that.
		c.connectAll()
	}
	if err := c.WaitAllHeight(2, opts.StartTimeout); err != nil {
		return nil, fmt.Errorf("network did not start: %w", err)
	}
	return c, nil
}

// peerAddr is the address node i dials to reach node j (i<j).
func (c *Cluster) peerAddr(i, j int) string {
	return string(c.members[j].id) + "@" + c.net.ProxyAddr(i, j)
}

// Close stops all nodes and proxies. It is idempotent.
func (c *Cluster) Close() {
	c.closeOnce.Do(func() {
		c.cancel()
		var wg sync.WaitGroup
		for i := range c.members {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_ = c.stop(i, false)
			}(i)
		}
		wg.Wait()
		c.bg.Wait()
		for _, m := range c.members {
			m.releasePorts()
		}
		if c.net != nil {
			c.net.Close()
		}
		if c.ownDir {
			os.RemoveAll(c.dir)
		}
	})
}

// ------------------------------------------------------------ accessors

// N returns the number of nodes (validators + full nodes).
func (c *Cluster) N() int { return len(c.members) }

// NumValidators returns the number of validators.
func (c *Cluster) NumValidators() int { return c.opts.Validators }

// ChainID returns the chain ID (needed in transaction bodies).
func (c *Cluster) ChainID() string { return c.chainID }

// Dir returns the cluster's directory; node i lives in Dir/node<i>.
func (c *Cluster) Dir() string { return c.dir }

// Home returns the home directory of node i.
func (c *Cluster) Home(i int) string { return c.members[i].cfg.Home }

// Net returns the emulated network.
func (c *Cluster) Net() *Net { return c.net }

// Mode returns the cluster's mode.
func (c *Cluster) Mode() Mode { return c.opts.Mode }

// Genesis returns the genesis document.
func (c *Cluster) Genesis() *cmttypes.GenesisDoc { return c.genesis }

// Node returns node i, or nil if it is not running or the cluster is in
// subprocess mode.
func (c *Cluster) Node(i int) *node.Node {
	m := c.members[i]
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.n
}

// App returns the application of node i (nil if Node(i) is nil).
func (c *Cluster) App(i int) *app.App {
	if n := c.Node(i); n != nil {
		return n.App()
	}
	return nil
}

// RPC returns an RPC client of node i (in-process or HTTP, depending on
// the mode), or nil if the node is not running.
func (c *Cluster) RPC(i int) rpcclient.Client {
	m := c.members[i]
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rpc
}

// RPCAddr returns the HTTP RPC address of node i ("" if not served).
func (c *Cluster) RPCAddr(i int) string { return c.members[i].cfg.RPCListen }

// Running reports whether node i is running.
func (c *Cluster) Running(i int) bool { return c.RPC(i) != nil }

// PID returns the process ID of node i (subprocess mode, while running),
// or 0.
func (c *Cluster) PID(i int) int {
	m := c.members[i]
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return m.cmd.Process.Pid
	}
	return 0
}

// Byzantine reports whether node i was given application faults.
func (c *Cluster) Byzantine(i int) bool { return c.members[i].byzantine }

// IsValidator reports whether node i is a validator.
func (c *Cluster) IsValidator(i int) bool { return c.members[i].validator }

// NodeID returns the p2p ID of node i.
func (c *Cluster) NodeID(i int) p2p.ID { return c.members[i].id }

// Commits returns what node i recorded about the blocks it committed
// (over all its incarnations), by height.
func (c *Cluster) Commits(i int) map[int64]node.CommitRecord {
	recs, _ := c.commitRecords(i)
	return recs
}

// ------------------------------------------------------------ lifecycle

func holdPort(addr string) net.Listener {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				reset(tc)
			} else {
				c.Close()
			}
		}
	}()
	return l
}

// reservePorts binds the node's ports while it is down so that nothing
// else (in particular an outgoing connection, whose ephemeral source
// port comes from the same range as ports discovered with ":0") can take
// them before the node restarts.
func (m *member) reservePorts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range []string{m.cfg.P2PListen, m.cfg.RPCListen} {
		if a != "" {
			if l := holdPort(a); l != nil {
				m.holds = append(m.holds, l)
			}
		}
	}
}

func (m *member) releasePorts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.holds {
		l.Close()
	}
	m.holds = nil
}

func isAddrInUse(err error) bool {
	return err != nil && (errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use"))
}

func (c *Cluster) start(i int) error {
	m := c.members[i]
	m.life.Lock()
	defer m.life.Unlock()
	if c.Running(i) {
		return fmt.Errorf("node %d is running", i)
	}
	m.releasePorts()
	c.net.SetDown(i, false)
	var err error
	if c.opts.Mode == Subprocess {
		err = c.startProcess(m)
	} else {
		err = c.startInProcess(m)
	}
	if err != nil {
		c.net.SetDown(i, true)
		m.reservePorts()
		return err
	}
	return nil
}

func (c *Cluster) startInProcess(m *member) error {
	cfg := m.cfg
	user := cfg.App.OnCommit
	idx := m.idx
	var nd *node.Node
	var ndMu sync.Mutex
	cfg.App.OnCommit = func(ci app.CommitInfo) {
		rec := node.CommitRecord{
			Height: ci.Height, AppHash: ci.AppHash, BlockTime: ci.BlockTime,
			CommittedAtUnixNano: ci.CommittedAt.UnixNano(), Accepted: len(ci.Accepted),
		}
		if !c.opts.NoStateDigests {
			ndMu.Lock()
			n := nd
			ndMu.Unlock()
			// During the handshake replay Start has not returned yet
			// and the app is not reachable; those blocks are recorded
			// without a state digest.
			if n != nil {
				if st := n.App().Committed(); st.Height == ci.Height {
					rec.StateDigest = node.StateDigest(st)
				}
			}
		}
		m.rec.add(rec)
		if user != nil {
			user(ci)
		}
		if c.opts.OnCommit != nil {
			c.opts.OnCommit(idx, ci)
		}
	}
	var err error
	for attempt := 0; ; attempt++ {
		var n *node.Node
		n, err = node.Start(cfg)
		if err == nil {
			ndMu.Lock()
			nd = n
			ndMu.Unlock()
			m.mu.Lock()
			m.n, m.rpc = n, n.RPC()
			m.mu.Unlock()
			return nil
		}
		if !isAddrInUse(err) || attempt >= 20 {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Stop stops node i cleanly.
func (c *Cluster) Stop(i int) error { return c.stop(i, false) }

// Kill stops node i as abruptly as the mode allows.
//
// Subprocess mode: SIGKILL; the process gets no chance to flush or close
// anything.
//
// In-process mode: all connections of the node are reset at once (its
// peers see it vanish without a goodbye, messages in flight are lost),
// then the node is stopped. LIMITATION: the stop itself is orderly. A
// node inside the test process cannot be interrupted between two
// instructions - e.g. between CometBFT writing a block to its store and
// the application committing it - because its goroutines cannot be
// killed and its database locks must be released for a restart in the
// same process. Crash consistency is therefore tested in subprocess
// mode.
func (c *Cluster) Kill(i int) error { return c.stop(i, true) }

func (c *Cluster) stop(i int, kill bool) error {
	m := c.members[i]
	m.life.Lock()
	defer m.life.Unlock()
	m.mu.Lock()
	n, cmd, exitC := m.n, m.cmd, m.exitC
	running := m.rpc != nil
	m.n, m.cmd, m.rpc, m.raw, m.exitC = nil, nil, nil, nil, nil
	if running {
		m.stops++
	}
	m.mu.Unlock()
	if !running {
		return nil
	}
	var err error
	switch {
	case cmd != nil:
		if kill {
			_ = cmd.Process.Kill()
			<-exitC
			c.net.SetDown(i, true)
		} else {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-exitC:
			case <-time.After(60 * time.Second):
				_ = cmd.Process.Kill()
				<-exitC
				err = fmt.Errorf("node %d did not stop on SIGTERM", i)
			}
			c.net.SetDown(i, true)
		}
	case n != nil:
		if kill {
			c.net.SetDown(i, true)
		}
		err = n.Stop()
		c.net.SetDown(i, true)
	}
	m.reservePorts()
	return err
}

// RestartWithCrashPoint (subprocess mode) restarts node i so that its
// process kills itself with SIGKILL at the given point of the commit of
// one block; see node.CrashPoint. Use WaitExit to wait for the crash and
// Restart to bring the node back.
func (c *Cluster) RestartWithCrashPoint(i int, cp node.CrashPoint) error {
	if c.opts.Mode != Subprocess {
		return errors.New("crash points need subprocess mode")
	}
	m := c.members[i]
	m.mu.Lock()
	m.crash = &cp
	m.mu.Unlock()
	return c.Restart(i)
}

// WaitExit (subprocess mode) waits until the process of node i has
// exited by itself and marks the node as down.
func (c *Cluster) WaitExit(i int, timeout time.Duration) error {
	m := c.members[i]
	m.mu.RLock()
	exitC := m.exitC
	m.mu.RUnlock()
	if exitC == nil {
		return fmt.Errorf("node %d is not a running process", i)
	}
	select {
	case <-exitC:
	case <-time.After(timeout):
		return fmt.Errorf("node %d did not exit within %v", i, timeout)
	}
	return c.stop(i, true)
}

// Restart starts node i again from its home directory. The node must
// have been stopped or killed. Restart returns when the node is up (not
// when it has caught up; see WaitNodeHeight).
func (c *Cluster) Restart(i int) error {
	if err := c.start(i); err != nil {
		return err
	}
	if !c.opts.PassiveReconnect {
		// The restarted node dials the nodes above it by itself; the
		// nodes below it are told to re-dial it now.
		for k := 0; k < i; k++ {
			k := k
			c.bg.Add(1)
			go func() {
				defer c.bg.Done()
				c.ensureConnected(k, i, 15*time.Second)
			}()
		}
	}
	return nil
}

// ---------------------------------------------------------- subprocess

var (
	dosrdOnce sync.Once
	dosrdPath string
	dosrdDir  string // temporary directory of the binary we built
	dosrdErr  error
)

// RemoveBuiltBinary deletes the dosrd binary built by this process (if
// any). Test packages call it from TestMain.
func RemoveBuiltBinary() {
	if dosrdDir != "" {
		os.RemoveAll(dosrdDir)
		dosrdDir, dosrdPath = "", ""
	}
}

// dosrdBinary returns the path of the dosrd binary, building it on first
// use.
func dosrdBinary(given string) (string, error) {
	if given != "" {
		return given, nil
	}
	if env := os.Getenv("DOSRD_BIN"); env != "" {
		return env, nil
	}
	dosrdOnce.Do(func() {
		out, err := exec.Command("go", "env", "GOMOD").Output()
		if err != nil {
			dosrdErr = fmt.Errorf("go env GOMOD: %w", err)
			return
		}
		gomod := strings.TrimSpace(string(out))
		if gomod == "" || gomod == os.DevNull {
			dosrdErr = errors.New("not inside the dosr module; set DOSRD_BIN")
			return
		}
		dir, err := os.MkdirTemp("", "dosrd-bin-")
		if err != nil {
			dosrdErr = err
			return
		}
		bin := filepath.Join(dir, "dosrd")
		cmd := exec.Command("go", "build", "-o", bin, "github.com/dosr/dosr/cmd/dosrd")
		cmd.Dir = filepath.Dir(gomod)
		if b, err := cmd.CombinedOutput(); err != nil {
			os.RemoveAll(dir)
			dosrdErr = fmt.Errorf("go build dosrd: %v\n%s", err, b)
			return
		}
		dosrdPath, dosrdDir = bin, dir
	})
	return dosrdPath, dosrdErr
}

func (c *Cluster) startProcess(m *member) error {
	out, err := os.OpenFile(filepath.Join(m.cfg.Home, "dosrd.out"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	args := []string{"--home", m.cfg.Home, "--exit-with-parent"}
	m.mu.Lock()
	if cp := m.crash; cp != nil {
		flag := "--crash-before-commit"
		if cp.AfterAppCommit {
			flag = "--crash-after-commit"
		}
		args = append(args, flag, fmt.Sprint(cp.Height))
		m.crash = nil
	}
	m.mu.Unlock()
	cmd := exec.Command(c.dosrd, args...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return err
	}
	exitC := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exitC)
	}()
	remote := "http://" + m.cfg.RPCListen
	cl, err := rpchttp.New(remote, "/websocket")
	if err == nil {
		var raw *jsonrpc.Client
		raw, err = jsonrpc.New(remote)
		if err == nil {
			deadline := time.Now().Add(60 * time.Second)
			for {
				ctx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
				_, err = cl.Status(ctx)
				cancel()
				if err == nil {
					m.mu.Lock()
					m.cmd, m.exitC, m.rpc, m.raw = cmd, exitC, cl, raw
					m.mu.Unlock()
					return nil
				}
				select {
				case <-exitC:
					b, _ := os.ReadFile(filepath.Join(m.cfg.Home, "dosrd.out"))
					return fmt.Errorf("dosrd exited during start: %s", lastLines(string(b), 5))
				default:
				}
				if time.Now().After(deadline) || c.ctx.Err() != nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	_ = cmd.Process.Kill()
	<-exitC
	return fmt.Errorf("dosrd did not come up: %w", err)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ------------------------------------------------------------- peering

// dial asks node i to dial a peer now. It returns how long the caller
// should wait for the connection before dialling again.
//
// In-process the switch is called directly and the dial is synchronous.
// A subprocess can only be asked through the (unsafe) RPC route
// dial_peers, which dials asynchronously after a random delay of up to
// 3 s (Switch.dialPeersAsync sleeps dialRandomizerIntervalMilliseconds).
func (c *Cluster) dial(ctx context.Context, i int, peer string) (time.Duration, error) {
	m := c.members[i]
	m.mu.RLock()
	n, raw := m.n, m.raw
	m.mu.RUnlock()
	switch {
	case n != nil:
		addr, err := p2p.NewNetAddressString(peer)
		if err != nil {
			return 0, err
		}
		return 50 * time.Millisecond, n.Comet().Switch().DialPeerWithAddress(addr)
	case raw != nil:
		res := new(ctypes.ResultDialPeers)
		_, err := raw.Call(ctx, "dial_peers", map[string]interface{}{
			"peers": []string{peer}, "persistent": true, "unconditional": false, "private": false,
		}, res)
		return 3500 * time.Millisecond, err
	}
	return 0, fmt.Errorf("node %d is not running", i)
}

// Peers returns the IDs of the peers node i is connected to.
func (c *Cluster) Peers(i int) ([]p2p.ID, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return nil, fmt.Errorf("node %d is not running", i)
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	ni, err := rpc.NetInfo(ctx)
	if err != nil {
		return nil, err
	}
	var out []p2p.ID
	for _, p := range ni.Peers {
		out = append(out, p.NodeInfo.DefaultNodeID)
	}
	return out, nil
}

// connected reports whether nodes i and j both have the other as a
// peer. (The dialling side adds the peer a moment before the accepting
// side does.)
func (c *Cluster) connected(i, j int) bool {
	has := func(a, b int) bool {
		ids, err := c.Peers(a)
		if err != nil {
			return false
		}
		for _, id := range ids {
			if id == c.members[b].id {
				return true
			}
		}
		return false
	}
	return has(i, j) && has(j, i)
}

// ensureConnected makes node i (i<j) dial node j until the two are
// connected, the link is cut, a node is down or the timeout expires.
// CometBFT alone re-dials a persistent peer only every 5..8 s (constant
// reconnectInterval plus up to 3 s of random delay in p2p/switch.go), and
// after 20 failed attempts only with exponential back-off.
func (c *Cluster) ensureConnected(i, j int, timeout time.Duration) bool {
	if i > j {
		i, j = j, i
	}
	deadline := time.Now().Add(timeout)
	peer := c.peerAddr(i, j)
	for time.Now().Before(deadline) && c.ctx.Err() == nil {
		if c.net.Link(i, j).cut() || !c.Running(i) || !c.Running(j) {
			return false
		}
		if c.connected(i, j) {
			return true
		}
		ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
		wait, _ := c.dial(ctx, i, peer)
		cancel()
		// The peer is added a moment after the handshake, which takes
		// several round trips on the emulated link.
		wait += 8 * c.net.Link(i, j).Forward().Delay
		end := time.Now().Add(wait)
		for time.Now().Before(end) {
			if c.connected(i, j) {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return false
}

// connectAll makes every pair of running nodes connect now.
func (c *Cluster) connectAll() {
	var wg sync.WaitGroup
	for i := 0; i < c.N(); i++ {
		for j := i + 1; j < c.N(); j++ {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				c.ensureConnected(i, j, 15*time.Second)
			}(i, j)
		}
	}
	wg.Wait()
}

// WaitConnected waits until every pair of running nodes whose link is
// not blocked is connected.
func (c *Cluster) WaitConnected(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		missing := ""
		for i := 0; i < c.N() && missing == ""; i++ {
			for j := i + 1; j < c.N(); j++ {
				if c.Running(i) && c.Running(j) && !c.net.Link(i, j).cut() && !c.connected(i, j) {
					missing = fmt.Sprintf("%d-%d", i, j)
					break
				}
			}
		}
		if missing == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("nodes %s not connected after %v", missing, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Partition, Isolate and Heal are shorthands for the methods of Net.
func (c *Cluster) Partition(groups ...[]int) { c.net.Partition(groups...) }

// Isolate cuts node i off from all other nodes.
func (c *Cluster) Isolate(i int) { c.net.Isolate(i) }

// Heal unblocks all links.
func (c *Cluster) Heal() { c.net.Heal() }

// -------------------------------------------------------------- heights

// Height returns the height of the last block committed by node i.
func (c *Cluster) Height(i int) (int64, error) {
	m := c.members[i]
	m.mu.RLock()
	n, rpc := m.n, m.rpc
	m.mu.RUnlock()
	if n != nil {
		return n.Height(), nil
	}
	if rpc == nil {
		return 0, fmt.Errorf("node %d is not running", i)
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	st, err := rpc.Status(ctx)
	if err != nil {
		return 0, err
	}
	return st.SyncInfo.LatestBlockHeight, nil
}

// Heights returns the heights of all nodes; -1 for nodes that are not
// running.
func (c *Cluster) Heights() []int64 {
	out := make([]int64, c.N())
	for i := range out {
		h, err := c.Height(i)
		if err != nil {
			h = -1
		}
		out[i] = h
	}
	return out
}

// MaxHeight returns the largest height of the running nodes.
func (c *Cluster) MaxHeight() int64 {
	var max int64
	for _, h := range c.Heights() {
		if h > max {
			max = h
		}
	}
	return max
}

func (c *Cluster) waitFor(timeout time.Duration, what string, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %v waiting for %s; heights %v", timeout, what, c.Heights())
		}
		select {
		case <-c.ctx.Done():
			return errors.New("cluster closed")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// WaitHeight waits until SOME running node has committed height h.
func (c *Cluster) WaitHeight(h int64, timeout time.Duration) error {
	return c.waitFor(timeout, fmt.Sprintf("height %d", h), func() bool { return c.MaxHeight() >= h })
}

// WaitAllHeight waits until ALL running nodes have committed height h.
func (c *Cluster) WaitAllHeight(h int64, timeout time.Duration) error {
	return c.waitFor(timeout, fmt.Sprintf("height %d on all nodes", h), func() bool {
		any := false
		for i, x := range c.Heights() {
			if !c.Running(i) {
				continue
			}
			any = true
			if x < h {
				return false
			}
		}
		return any
	})
}

// WaitNodeHeight waits until node i has committed height h.
func (c *Cluster) WaitNodeHeight(i int, h int64, timeout time.Duration) error {
	return c.waitFor(timeout, fmt.Sprintf("height %d on node %d", h, i), func() bool {
		x, err := c.Height(i)
		return err == nil && x >= h
	})
}

// WaitNodesHeight waits until all the listed nodes have committed h.
func (c *Cluster) WaitNodesHeight(nodes []int, h int64, timeout time.Duration) error {
	return c.waitFor(timeout, fmt.Sprintf("height %d on nodes %v", h, nodes), func() bool {
		for _, i := range nodes {
			if x, err := c.Height(i); err != nil || x < h {
				return false
			}
		}
		return true
	})
}

// Progress observes the listed nodes (all running nodes if none are
// listed) for the given time and returns by how many blocks the most
// advanced of them progressed.
func (c *Cluster) Progress(window time.Duration, nodes ...int) int64 {
	if len(nodes) == 0 {
		for i := 0; i < c.N(); i++ {
			if c.Running(i) {
				nodes = append(nodes, i)
			}
		}
	}
	max := func() int64 {
		var m int64
		for _, i := range nodes {
			if h, err := c.Height(i); err == nil && h > m {
				m = h
			}
		}
		return m
	}
	before := max()
	select {
	case <-time.After(window):
	case <-c.ctx.Done():
	}
	return max() - before
}

// --------------------------------------------------------- transactions

// BroadcastTxAsync submits tx to node i without waiting for CheckTx.
func (c *Cluster) BroadcastTxAsync(i int, tx []byte) (*ctypes.ResultBroadcastTx, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return nil, fmt.Errorf("node %d is not running", i)
	}
	return rpc.BroadcastTxAsync(c.ctx, tx)
}

// BroadcastTxSync submits tx to node i and returns the result of CheckTx.
func (c *Cluster) BroadcastTxSync(i int, tx []byte) (*ctypes.ResultBroadcastTx, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return nil, fmt.Errorf("node %d is not running", i)
	}
	return rpc.BroadcastTxSync(c.ctx, tx)
}

// BroadcastTxCommit submits tx to node i and waits until it is committed
// in a block (or rejected by CheckTx); it returns both results.
func (c *Cluster) BroadcastTxCommit(i int, tx []byte) (*ctypes.ResultBroadcastTxCommit, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return nil, fmt.Errorf("node %d is not running", i)
	}
	return rpc.BroadcastTxCommit(c.ctx, tx)
}

// TxResult is the fate of a transaction in the chain.
type TxResult struct {
	Height int64
	Index  int
	Code   uint32
	Log    string
}

// FindTx scans the blocks from..to of node i for the transaction and
// returns its result(s): a transaction can be included more than once
// (at most one inclusion succeeds).
func (c *Cluster) FindTx(i int, tx []byte, from, to int64) ([]TxResult, error) {
	rpc := c.RPC(i)
	if rpc == nil {
		return nil, fmt.Errorf("node %d is not running", i)
	}
	var out []TxResult
	want := string(cmttypes.Tx(tx).Hash())
	for h := from; h <= to; h++ {
		h := h
		b, err := rpc.Block(c.ctx, &h)
		if err != nil {
			return nil, err
		}
		var res *ctypes.ResultBlockResults
		for k, t := range b.Block.Txs {
			if string(t.Hash()) != want {
				continue
			}
			if res == nil {
				if res, err = rpc.BlockResults(c.ctx, &h); err != nil {
					return nil, err
				}
			}
			out = append(out, TxResult{Height: h, Index: k, Code: res.TxsResults[k].Code, Log: res.TxsResults[k].Log})
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- heads

// Head describes the state of one node.
type Head struct {
	Node    int
	Running bool
	Height  int64
	AppHash []byte
	// Branches maps "repo/branch" to the branch state.
	Branches map[string]app.Branch
}

// Heads returns the current state of every node. For a node that is not
// running only Node is set.
func (c *Cluster) Heads() []Head {
	out := make([]Head, c.N())
	for i := range out {
		out[i].Node = i
		v := c.view(i)
		if v == nil {
			continue
		}
		snap, err := v.Snapshot()
		if err != nil {
			continue
		}
		out[i].Running = true
		out[i].Height = snap.Height
		out[i].AppHash = snap.AppHash
		out[i].Branches = map[string]app.Branch{}
		for id, r := range snap.Repos {
			for b, br := range r.Branches {
				out[i].Branches[id+"/"+b] = br
			}
		}
	}
	return out
}

// Repo returns a repository of node i's committed state, or nil if the
// node is down or does not have it.
func (c *Cluster) Repo(i int, repo string) *app.Repo {
	v := c.view(i)
	if v == nil {
		return nil
	}
	r, err := v.Repo(repo)
	if err != nil {
		return nil
	}
	return r
}

// BranchHead returns the head of a branch on node i (zero ID and false
// if the node does not have the branch).
func (c *Cluster) BranchHead(i int, repo, branch string) (gitobj.ID, bool) {
	r := c.Repo(i, repo)
	if r == nil {
		return gitobj.ZeroID, false
	}
	b, ok := r.Branches[branch]
	return b.Head, ok
}

// HasRepo reports whether node i has the repository in its committed
// state.
func (c *Cluster) HasRepo(i int, repo string) bool { return c.Repo(i, repo) != nil }

// WaitRepo waits until all the listed nodes (all running nodes if none
// are listed) have the repository.
func (c *Cluster) WaitRepo(repo string, timeout time.Duration, nodes ...int) error {
	return c.waitFor(timeout, "repo "+repo, func() bool {
		ns := nodes
		if len(ns) == 0 {
			for i := 0; i < c.N(); i++ {
				if c.Running(i) {
					ns = append(ns, i)
				}
			}
		}
		for _, i := range ns {
			if !c.HasRepo(i, repo) {
				return false
			}
		}
		return true
	})
}
