// Package node wires the DOSR application into an in-process CometBFT
// node. One Node = one CometBFT instance + one DOSR app + their databases,
// all living under one home directory, so that Start on an existing home
// restarts the node from its persisted state.
package node

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	cmtnode "github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/proxy"
	rpclocal "github.com/cometbft/cometbft/rpc/client/local"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/dosr/dosr/pkg/app"
	dosrtypes "github.com/dosr/dosr/pkg/types"
)

const (
	// MaxTxBytes is the largest transaction the mempool admits. It is the
	// application's hard cap (8 MiB).
	MaxTxBytes = dosrtypes.MaxTxBytes
	// BlockMaxBytes is the genesis consensus parameter block.max_bytes. A
	// block must be able to carry at least one maximum-size transaction
	// plus header, commit and evidence; 21 MiB leaves room for two.
	BlockMaxBytes = 21 << 20

	// ConfigFileName is the name of the node configuration file that
	// SaveConfig writes into (and LoadConfig reads from) the home
	// directory. cmd/dosrd runs a node from it.
	ConfigFileName = "dosr_node.json"

	appDBName = "dosr_app"
)

// Timeouts are CometBFT's consensus timeouts. They are node-local
// configuration in v0.38 (not consensus parameters).
type Timeouts struct {
	Propose        time.Duration `json:"timeout_propose"`
	ProposeDelta   time.Duration `json:"timeout_propose_delta"`
	Prevote        time.Duration `json:"timeout_prevote"`
	PrevoteDelta   time.Duration `json:"timeout_prevote_delta"`
	Precommit      time.Duration `json:"timeout_precommit"`
	PrecommitDelta time.Duration `json:"timeout_precommit_delta"`
	Commit         time.Duration `json:"timeout_commit"`
	// SkipTimeoutCommit proceeds to the next height as soon as ALL
	// precommits have been received instead of waiting for Commit.
	SkipTimeoutCommit bool `json:"skip_timeout_commit"`
	// NoEmptyBlocks disables create_empty_blocks (the zero value keeps
	// CometBFT's default of creating them).
	NoEmptyBlocks bool `json:"no_empty_blocks"`
	// EmptyBlocksInterval is create_empty_blocks_interval.
	EmptyBlocksInterval time.Duration `json:"create_empty_blocks_interval"`
}

// DefaultTimeouts are CometBFT's production defaults.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		Propose: 3 * time.Second, ProposeDelta: 500 * time.Millisecond,
		Prevote: time.Second, PrevoteDelta: 500 * time.Millisecond,
		Precommit: time.Second, PrecommitDelta: 500 * time.Millisecond,
		Commit: time.Second,
	}
}

// FastTimeouts are short timeouts for tests on localhost.
func FastTimeouts() Timeouts {
	return Timeouts{
		Propose: 800 * time.Millisecond, ProposeDelta: 200 * time.Millisecond,
		Prevote: 300 * time.Millisecond, PrevoteDelta: 100 * time.Millisecond,
		Precommit: 300 * time.Millisecond, PrecommitDelta: 100 * time.Millisecond,
		Commit: 150 * time.Millisecond,
	}
}

// AppFileConfig is the serialisable part of app.Config.
type AppFileConfig struct {
	StrictProposals   bool `json:"strict_proposals"`
	EvidenceCacheSize int  `json:"evidence_cache_size"`
}

// Config configures one node.
type Config struct {
	// Home is the node's directory. Layout:
	//   config/genesis.json, config/node_key.json,
	//   config/priv_validator_key.json, data/priv_validator_state.json,
	//   data/*.db (CometBFT), data/dosr_app.db (application).
	Home    string `json:"-"`
	Moniker string `json:"moniker"`

	// Genesis, NodeKey and PrivVal are written to Home if the
	// corresponding file does not exist yet. If nil, the files must exist.
	// Existing files always win: a restart never replaces keys or the
	// validator's last-sign state.
	Genesis *cmttypes.GenesisDoc `json:"-"`
	NodeKey *p2p.NodeKey         `json:"-"`
	// PrivValKey is the validator's consensus key (the last-sign state is
	// always file-based, see privval.FilePV).
	PrivValKey *privval.FilePVKey `json:"-"`

	// P2PListen is host:port.
	P2PListen string `json:"p2p_listen"`
	// RPCListen is host:port; empty disables the HTTP RPC server (the
	// in-process client returned by Node.RPC works regardless).
	RPCListen string `json:"rpc_listen"`
	// RPCUnsafe enables the unsafe RPC routes (dial_peers, ...).
	RPCUnsafe bool `json:"rpc_unsafe"`
	// PersistentPeers are id@host:port.
	PersistentPeers []string `json:"persistent_peers"`

	Consensus Timeouts `json:"consensus"`

	// MempoolSize is the maximum number of transactions in the mempool
	// (default 5000); MempoolMaxTxsBytes the maximum total size
	// (default 1 GiB). max_tx_bytes is always MaxTxBytes.
	MempoolSize        int   `json:"mempool_size"`
	MempoolMaxTxsBytes int64 `json:"mempool_max_txs_bytes"`

	// P2PSendRate / P2PRecvRate are CometBFT's per-connection rate limits
	// in bytes/s (default here 64 MiB/s: CometBFT's default of 5 MB/s
	// would throttle 8 MiB transactions; shaping is the netem proxy's
	// job). P2PFlushThrottle is flush_throttle_timeout (default here
	// 10 ms; CometBFT's default is 100 ms, which adds up to 100 ms to
	// every consensus message).
	P2PSendRate      int64         `json:"p2p_send_rate"`
	P2PRecvRate      int64         `json:"p2p_recv_rate"`
	P2PFlushThrottle time.Duration `json:"p2p_flush_throttle"`
	// PeerGossipSleep is consensus.peer_gossip_sleep_duration: how long
	// a gossip routine sleeps when it has nothing to send to a peer
	// (0: CometBFT's default of 100 ms).
	PeerGossipSleep time.Duration `json:"peer_gossip_sleep"`

	// DBBackend is "goleveldb" (default, on disk under Home/data) or
	// "memdb" (unit tests; a memdb node cannot be restarted).
	DBBackend string `json:"db_backend"`
	// TxIndex is the transaction indexer: "kv" (default) or "null".
	TxIndex string `json:"tx_index"`

	// LogLevel is "error" (default), "info", "debug" or "none".
	LogLevel string `json:"log_level"`
	// LogFile, if set, receives the log (appended); otherwise stderr.
	LogFile string `json:"log_file"`
	// LogWriter overrides LogFile.
	LogWriter io.Writer `json:"-"`

	// CommitLog, if set, is a file to which one CommitRecord per
	// committed block is appended as a JSON line.
	CommitLog string `json:"commit_log"`

	// ConnSyncABCI uses one mutex per ABCI connection instead of one
	// global mutex (proxy.NewConnSyncLocalClientCreator instead of
	// proxy.NewLocalClientCreator), so CheckTx and Query run concurrently
	// with block execution. The app is written for that; the default is
	// the conservative global mutex.
	ConnSyncABCI bool `json:"conn_sync_abci"`

	// Crash, if set, makes the node kill its own process at a point of
	// the commit of one block; see CrashPoint. Subprocess nodes only.
	Crash *CrashPoint `json:"-"`

	// App is the application configuration. Only AppFile is serialised;
	// LoadConfig rebuilds App from it.
	App     app.Config    `json:"-"`
	AppFile AppFileConfig `json:"app"`
}

// CommitRecord is what a node records about each block it commits.
type CommitRecord struct {
	Height int64 `json:"height"`
	// AppHash is the app hash AFTER executing the block.
	AppHash []byte `json:"app_hash"`
	// StateDigest is the SHA-256 of the JSON encoding of the complete
	// application state after the block.
	StateDigest []byte `json:"state_digest"`
	BlockTime   int64  `json:"block_time"`
	// CommittedAtUnixNano is the local wall-clock time at which the block
	// became durable on this node.
	CommittedAtUnixNano int64 `json:"committed_at"`
	Accepted            int   `json:"accepted"`
}

// StateDigest returns the digest recorded in CommitRecord.StateDigest.
func StateDigest(st *app.State) []byte {
	b, err := json.Marshal(st)
	if err != nil {
		panic("node: state marshal: " + err.Error())
	}
	h := sha256.Sum256(b)
	return h[:]
}

// Node is a running node.
type Node struct {
	cfg   Config
	comet *cmtnode.Node
	app   *app.App
	appDB dbm.DB
	// cometDBs are the databases CometBFT opened through our provider.
	// Node.OnStop closes the block, state and evidence stores but NOT the
	// transaction index, whose LOCK file would make a restart in the same
	// process fail, so Stop closes whatever is still open.
	dbMu     sync.Mutex
	cometDBs []dbm.DB
	rpc      *rpclocal.Local
	key      *p2p.NodeKey
	logF     *os.File
	clog     *os.File
	clogMu   sync.Mutex

	stopOnce sync.Once
	stopErr  error
}

func (c *Config) setDefaults() {
	if c.Moniker == "" {
		c.Moniker = filepath.Base(c.Home)
	}
	if c.Consensus == (Timeouts{}) {
		c.Consensus = DefaultTimeouts()
	}
	if c.MempoolSize == 0 {
		c.MempoolSize = 5000
	}
	if c.MempoolMaxTxsBytes == 0 {
		c.MempoolMaxTxsBytes = 1 << 30
	}
	if c.P2PSendRate == 0 {
		c.P2PSendRate = 64 << 20
	}
	if c.P2PRecvRate == 0 {
		c.P2PRecvRate = 64 << 20
	}
	if c.P2PFlushThrottle == 0 {
		c.P2PFlushThrottle = 10 * time.Millisecond
	}
	if c.DBBackend == "" {
		c.DBBackend = string(dbm.GoLevelDBBackend)
	}
	if c.TxIndex == "" {
		c.TxIndex = "kv"
	}
	if c.LogLevel == "" {
		c.LogLevel = "error"
	}
}

// SaveConfig writes the serialisable part of cfg to Home/ConfigFileName
// and the genesis document and keys (if given and not yet present) to
// their files, so that the node can be started from the home directory
// alone (LoadConfig + Start, which is what cmd/dosrd does).
func SaveConfig(cfg Config) error {
	if cfg.Home == "" {
		return errors.New("node: no home directory")
	}
	cfg.setDefaults()
	if err := initHome(&cfg); err != nil {
		return err
	}
	cfg.AppFile = AppFileConfig{
		StrictProposals:   cfg.App.StrictProposals,
		EvidenceCacheSize: cfg.App.EvidenceCacheSize,
	}
	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(cfg.Home, ConfigFileName), b)
}

// LoadConfig reads the configuration written by SaveConfig.
func LoadConfig(home string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(filepath.Join(home, ConfigFileName))
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("node: %s: %w", ConfigFileName, err)
	}
	cfg.Home = home
	cfg.App = app.DefaultConfig()
	cfg.App.StrictProposals = cfg.AppFile.StrictProposals
	cfg.App.EvidenceCacheSize = cfg.AppFile.EvidenceCacheSize
	return cfg, nil
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// cometConfig translates cfg into a CometBFT configuration.
func cometConfig(cfg *Config) *cmtcfg.Config {
	c := cmtcfg.DefaultConfig()
	c.SetRoot(cfg.Home)
	c.Moniker = cfg.Moniker
	c.DBBackend = cfg.DBBackend
	c.ProxyApp = "dosr-local"

	c.P2P.ListenAddress = "tcp://" + cfg.P2PListen
	c.P2P.PersistentPeers = strings.Join(cfg.PersistentPeers, ",")
	c.P2P.AllowDuplicateIP = true
	c.P2P.AddrBookStrict = false
	c.P2P.PexReactor = false
	c.P2P.SendRate = cfg.P2PSendRate
	c.P2P.RecvRate = cfg.P2PRecvRate
	c.P2P.FlushThrottleTimeout = cfg.P2PFlushThrottle

	if cfg.RPCListen == "" {
		c.RPC.ListenAddress = ""
	} else {
		c.RPC.ListenAddress = "tcp://" + cfg.RPCListen
	}
	c.RPC.GRPCListenAddress = ""
	c.RPC.Unsafe = cfg.RPCUnsafe
	// A transaction is base64-encoded inside a JSON-RPC request.
	c.RPC.MaxBodyBytes = int64(MaxTxBytes)*4/3 + (1 << 20)
	c.RPC.TimeoutBroadcastTxCommit = 60 * time.Second
	// The HTTP server's write timeout must exceed it (ValidateBasic).

	c.Mempool.Size = cfg.MempoolSize
	c.Mempool.MaxTxBytes = MaxTxBytes
	c.Mempool.MaxTxsBytes = cfg.MempoolMaxTxsBytes
	c.Mempool.CacheSize = 10000

	t := cfg.Consensus
	c.Consensus.TimeoutPropose = t.Propose
	c.Consensus.TimeoutProposeDelta = t.ProposeDelta
	c.Consensus.TimeoutPrevote = t.Prevote
	c.Consensus.TimeoutPrevoteDelta = t.PrevoteDelta
	c.Consensus.TimeoutPrecommit = t.Precommit
	c.Consensus.TimeoutPrecommitDelta = t.PrecommitDelta
	c.Consensus.TimeoutCommit = t.Commit
	c.Consensus.SkipTimeoutCommit = t.SkipTimeoutCommit
	c.Consensus.CreateEmptyBlocks = !t.NoEmptyBlocks
	c.Consensus.CreateEmptyBlocksInterval = t.EmptyBlocksInterval
	if cfg.PeerGossipSleep > 0 {
		c.Consensus.PeerGossipSleepDuration = cfg.PeerGossipSleep
	}

	c.TxIndex.Indexer = cfg.TxIndex
	c.Instrumentation.Prometheus = false
	c.StateSync.Enable = false
	return c
}

// initHome creates the directory layout and writes genesis and keys that
// were passed in memory and do not exist on disk.
func initHome(cfg *Config) error {
	c := cmtcfg.DefaultConfig()
	c.SetRoot(cfg.Home)
	for _, d := range []string{filepath.Join(cfg.Home, "config"), filepath.Join(cfg.Home, "data")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if cfg.Genesis != nil && !exists(c.GenesisFile()) {
		if err := cfg.Genesis.SaveAs(c.GenesisFile()); err != nil {
			return err
		}
	}
	if cfg.NodeKey != nil && !exists(c.NodeKeyFile()) {
		if err := cfg.NodeKey.SaveAs(c.NodeKeyFile()); err != nil {
			return err
		}
	}
	if cfg.PrivValKey != nil && !exists(c.PrivValidatorKeyFile()) {
		pv := privval.NewFilePV(cfg.PrivValKey.PrivKey, c.PrivValidatorKeyFile(), c.PrivValidatorStateFile())
		pv.Save() // writes the key and an empty last-sign state
	}
	return nil
}

func newLogger(cfg *Config) (cmtlog.Logger, *os.File, error) {
	if cfg.LogLevel == "none" {
		return cmtlog.NewNopLogger(), nil, nil
	}
	var w io.Writer = os.Stderr
	var f *os.File
	if cfg.LogWriter != nil {
		w = cfg.LogWriter
	} else if cfg.LogFile != "" {
		var err error
		f, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, err
		}
		w = f
	}
	opt, err := cmtlog.AllowLevel(cfg.LogLevel)
	if err != nil {
		if f != nil {
			f.Close()
		}
		return nil, nil, err
	}
	l := cmtlog.NewFilter(cmtlog.NewTMLogger(cmtlog.NewSyncWriter(w)), opt)
	return l.With("node", cfg.Moniker), f, nil
}

// Start starts a node. If cfg.Home holds the state of a previous run the
// node resumes from it: CometBFT compares its block store with the height
// and app hash the application reports in Info and replays the blocks the
// application has not committed.
func Start(cfg Config) (_ *Node, err error) {
	if cfg.Home == "" {
		return nil, errors.New("node: no home directory")
	}
	if cfg.P2PListen == "" {
		return nil, errors.New("node: no p2p listen address")
	}
	cfg.setDefaults()
	if err := initHome(&cfg); err != nil {
		return nil, fmt.Errorf("node: init home: %w", err)
	}
	cc := cometConfig(&cfg)
	if err := cc.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("node: config: %w", err)
	}
	for _, f := range []string{cc.GenesisFile(), cc.NodeKeyFile(), cc.PrivValidatorKeyFile()} {
		if !exists(f) {
			return nil, fmt.Errorf("node: %s does not exist", f)
		}
	}

	n := &Node{cfg: cfg}
	defer func() {
		if err != nil {
			n.closeFiles()
		}
	}()

	logger, logF, err := newLogger(&cfg)
	if err != nil {
		return nil, fmt.Errorf("node: log: %w", err)
	}
	n.logF = logF

	if cfg.CommitLog != "" {
		n.clog, err = os.OpenFile(cfg.CommitLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("node: commit log: %w", err)
		}
	}

	n.key, err = p2p.LoadNodeKey(cc.NodeKeyFile())
	if err != nil {
		return nil, fmt.Errorf("node: node key: %w", err)
	}
	// LoadFilePV exits the process if the state file is missing; create
	// an empty one for a key that was provisioned without state.
	if !exists(cc.PrivValidatorStateFile()) {
		privval.LoadFilePVEmptyState(cc.PrivValidatorKeyFile(), cc.PrivValidatorStateFile()).Save()
	}
	pv := privval.LoadFilePV(cc.PrivValidatorKeyFile(), cc.PrivValidatorStateFile())

	rawDB, err := dbm.NewDB(appDBName, dbm.BackendType(cfg.DBBackend), cc.DBDir())
	if err != nil {
		return nil, fmt.Errorf("node: app db: %w", err)
	}
	n.appDB = newSafeDB(rawDB)
	defer func() {
		if err != nil {
			n.appDB.Close()
		}
	}()

	acfg := cfg.App
	userHook := acfg.OnCommit
	if n.clog != nil {
		acfg.OnCommit = func(ci app.CommitInfo) {
			n.logCommit(ci)
			if userHook != nil {
				userHook(ci)
			}
		}
	}
	n.app, err = app.New(n.appDB, acfg)
	if err != nil {
		return nil, fmt.Errorf("node: app: %w", err)
	}

	var creator proxy.ClientCreator
	abciApp := queryExt{Application: n.app, app: n.app, crash: cfg.Crash, height: new(atomic.Int64)}
	if cfg.ConnSyncABCI {
		creator = proxy.NewConnSyncLocalClientCreator(abciApp)
	} else {
		creator = proxy.NewLocalClientCreator(abciApp)
	}
	provider := func(ctx *cmtcfg.DBContext) (dbm.DB, error) {
		db, err := cmtcfg.DefaultDBProvider(ctx)
		if err != nil {
			return nil, err
		}
		sdb := newSafeDB(db)
		n.dbMu.Lock()
		n.cometDBs = append(n.cometDBs, sdb)
		n.dbMu.Unlock()
		return sdb, nil
	}
	n.comet, err = cmtnode.NewNode(cc, pv, n.key, creator,
		cmtnode.DefaultGenesisDocProviderFunc(cc),
		provider,
		cmtnode.DefaultMetricsProvider(cc.Instrumentation),
		logger)
	if err != nil {
		n.closeCometDBs()
		return nil, fmt.Errorf("node: new: %w", err)
	}
	if err = n.comet.Start(); err != nil {
		n.closeCometDBs()
		return nil, fmt.Errorf("node: start: %w", err)
	}
	n.rpc = rpclocal.New(n.comet)
	return n, nil
}

func (n *Node) logCommit(ci app.CommitInfo) {
	st := n.app.Committed()
	rec := CommitRecord{
		Height: ci.Height, AppHash: ci.AppHash, BlockTime: ci.BlockTime,
		CommittedAtUnixNano: ci.CommittedAt.UnixNano(), Accepted: len(ci.Accepted),
	}
	if st.Height == ci.Height {
		rec.StateDigest = StateDigest(st)
	}
	b, _ := json.Marshal(rec)
	b = append(b, '\n')
	n.clogMu.Lock()
	defer n.clogMu.Unlock()
	if n.clog != nil {
		// Not synced: the commit log is an observation for the test
		// harness, not part of the node's state. A reader must tolerate
		// a truncated last line.
		n.clog.Write(b)
	}
}

// ReadCommitLog parses a commit log file. A truncated or corrupt last
// line (the node was killed while writing) is ignored.
func ReadCommitLog(path string) ([]CommitRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []CommitRecord
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		var r CommitRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// closeCometDBs closes the CometBFT databases that are still open.
func (n *Node) closeCometDBs() {
	n.dbMu.Lock()
	defer n.dbMu.Unlock()
	for _, db := range n.cometDBs {
		_ = db.Close() // idempotent, see safeDB
	}
	n.cometDBs = nil
}

func (n *Node) closeFiles() {
	n.clogMu.Lock()
	if n.clog != nil {
		n.clog.Close()
		n.clog = nil
	}
	n.clogMu.Unlock()
	if n.logF != nil {
		n.logF.Close()
		n.logF = nil
	}
}

// Stop stops the node: CometBFT is stopped (which waits for the consensus
// routine, so no ABCI call is in flight afterwards and closes CometBFT's
// databases), then the application database is closed. Stop is idempotent.
func (n *Node) Stop() error {
	n.stopOnce.Do(func() {
		var errs []error
		if n.comet.IsRunning() {
			if err := n.comet.Stop(); err != nil {
				errs = append(errs, err)
			}
			n.comet.Wait()
		}
		n.closeCometDBs()
		if err := n.appDB.Close(); err != nil {
			errs = append(errs, err)
		}
		n.closeFiles()
		n.stopErr = errors.Join(errs...)
	})
	return n.stopErr
}

// App returns the node's application.
func (n *Node) App() *app.App { return n.app }

// RPC returns an in-process RPC client of the node.
func (n *Node) RPC() *rpclocal.Local { return n.rpc }

// Comet returns the underlying CometBFT node.
func (n *Node) Comet() *cmtnode.Node { return n.comet }

// ID returns the node's p2p ID.
func (n *Node) ID() p2p.ID { return n.key.ID() }

// P2PAddr returns the node's p2p address as id@host:port.
func (n *Node) P2PAddr() string { return string(n.key.ID()) + "@" + n.cfg.P2PListen }

// RPCAddr returns the HTTP RPC address ("" if disabled).
func (n *Node) RPCAddr() string { return n.cfg.RPCListen }

// Config returns the node's configuration (with defaults filled in).
func (n *Node) Config() Config { return n.cfg }

// Height returns the height of the last block the application committed.
func (n *Node) Height() int64 { return n.app.Committed().Height }

// NewGenesis returns a genesis document for the given validators with
// equal voting power and DOSR's consensus parameters.
func NewGenesis(chainID string, genesisTime time.Time, validators []*privval.FilePVKey) (*cmttypes.GenesisDoc, error) {
	params := cmttypes.DefaultConsensusParams()
	params.Block.MaxBytes = BlockMaxBytes
	params.Block.MaxGas = -1
	g := &cmttypes.GenesisDoc{
		ChainID:         chainID,
		GenesisTime:     genesisTime,
		InitialHeight:   1,
		ConsensusParams: params,
	}
	for i, v := range validators {
		g.Validators = append(g.Validators, cmttypes.GenesisValidator{
			Address: v.Address, PubKey: v.PubKey, Power: 10,
			Name: fmt.Sprintf("val%d", i),
		})
	}
	if err := g.ValidateAndComplete(); err != nil {
		return nil, err
	}
	return g, nil
}

// FreeAddrs returns n distinct free TCP addresses on 127.0.0.1. The ports
// are discovered by binding port 0; all listeners are held until all
// addresses are known (so they are distinct) and then closed. There is an
// unavoidable window between this function returning and the caller
// binding the port.
func FreeAddrs(n int) ([]string, error) {
	var ls []net.Listener
	defer func() {
		for _, l := range ls {
			l.Close()
		}
	}()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
		out = append(out, l.Addr().String())
	}
	return out, nil
}
