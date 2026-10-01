# Implementation notes: `pkg/node`, `pkg/testnet`, `cmd/dosrd`

Multi-node test harness: in-process or subprocess CometBFT v0.38.17 nodes on
127.0.0.1 behind a userspace network emulator, plus an invariant checker.
Environment of all measurements below: macOS (Darwin 23.1.0, arm64, 8 cores),
Go 1.27.1, all nodes and proxies on one machine. Other agents were running
`dosr-bench` and a TLC model checker on the same machine during part of the
runs (see sections 6 and 7).

## 1. Files

| File | Content |
|---|---|
| `pkg/node/node.go` | `Config`, `Timeouts`, `Start`/`Stop`, `SaveConfig`/`LoadConfig`, `NewGenesis`, `FreeAddrs`, commit log |
| `pkg/node/queryext.go` | ABCI wrapper: `/node/state` query, `CrashPoint` (SIGKILL inside `Commit`) |
| `pkg/node/safedb.go` | database wrapper that survives reads after `Close` (section 4.5) |
| `pkg/testnet/netem.go` | `Link` (one TCP proxy per pair), `Net` (matrix of links, partitions), presets |
| `pkg/testnet/cluster.go` | `Cluster`: keys, genesis, start/stop/kill/restart, peering, heights, transactions |
| `pkg/testnet/checker.go` | commit-record recorder, `View`s (local / RPC), `Checker` and `Report` |
| `pkg/testnet/helpers.go` | client keys, policies, CreateRepo transactions, commit builder, interval statistics |
| `cmd/dosrd/main.go` | one node as an OS process, run from a home directory written by `SaveConfig` |

Tests: `pkg/node/node_test.go` (single node, restart from disk),
`pkg/testnet/netem_test.go` (proxy unit tests), `checker_test.go` (the checker
against fabricated histories), `cluster_test.go` (smoke, topology, goroutine
leak), `faults_test.go` (crashes, partitions, delay, duplicates, Byzantine app,
orphaned subprocess).

## 2. Design decisions

### 2.1 One proxy per pair, one connection per pair, nothing bypasses the proxy

For every pair `i<j` there is one listener `P(i,j)` (`Link`). Node `i` has
`nodeID_j@P(i,j)` as a persistent peer; node `j` does not know any address of
`i`. PEX is off and the address book is not strict (`AddrBookStrict=false`,
`AllowDuplicateIP=true`, needed for 127.0.0.1). Therefore the only connection
between `i` and `j` is the one `i` dials through the proxy, and every byte of
the consensus, mempool and block-sync traffic between them is shaped by the
link. `checkTopology` (in `TestSmoke`) verifies this: every link proxies
exactly one connection, every outbound peer connection of node `i` goes to
`P(i,j)` with `i<j`, every inbound one comes from the proxy's upstream socket.
A full partition (`Partition()` with no groups) leaves every node with zero
peers.

Both directions of a link have independent parameters (`SetDelay(i,j)` is
one-way), so asymmetric routes can be emulated. `Matrix` presets: `LAN`,
`Regional`, `WAN5` (round numbers of the magnitude of public inter-region
RTTs, explicitly not measured by us).

### 2.2 Delay as a release timestamp, not as a sleep

Each direction of a proxied connection is a reader/queue/writer pipeline. The
reader stamps each chunk with `now + delay + jitter` (clamped to be
non-decreasing), the writer sleeps until the stamp and writes. A proxy that
slept between read and write would add the delay per chunk and accumulate; with
timestamps every chunk is delayed by the configured amount independently of how
the sender splits its writes. `TestNetemDelayDoesNotAccumulate` sends 150
messages 2 ms apart through a 25 ms link: median 25.3 ms, p95 26.4 ms, max
30.5 ms (a sleeping proxy would delay the last message by 3.75 s). A single
writer per direction preserves the byte stream exactly (`TestNetemIntegrity`
pushes 6 MiB with random write sizes through delay+jitter and rate-capped links
under `-race`). The bandwidth cap is modelled as a "link free at" time
(a chunk of `n` bytes occupies the link for `n/Rate`); the reader stops reading
when the emulated transmit queue is more than 250 ms ahead of real time, so TCP
flow control pushes back on the sender (`TestNetemRate`: 2 MiB at 1 MiB/s took
2.002 s).

Blocking a link resets (RST, `SO_LINGER=0`) all its connections and resets new
ones right after accept, so both endpoints see the failure immediately instead
of after a TCP timeout. `SetDown` (node dead) is a separate flag with the same
effect, so partitions and crashes compose without one undoing the other.

### 2.3 Cluster lifecycle

- Ports come from `net.Listen("127.0.0.1:0")` (`node.FreeAddrs`) and proxies
  bind `:0` themselves; nothing is hard-coded. A node's p2p and RPC ports are
  held by a placeholder listener from allocation until the node binds them and
  again while the node is down, because outgoing connections of the other nodes
  and proxies take ephemeral ports from the same range. Without this a restart
  can fail with `address already in use`; `startInProcess` additionally retries
  that error for 2 s.
- Nodes start in reverse index order so that every persistent peer a node dials
  is already listening (a failed first dial would otherwise fall into
  CometBFT's 5..8 s reconnection timer, section 4.1). After the start, and
  after every unblock or restart, the harness makes the lower-numbered node
  dial immediately (`ensureConnected`, `OnUnblock`). `PassiveReconnect` turns
  this off to measure CometBFT's own behaviour (`TestHealPassive`).
- `Stop` is orderly (SIGTERM for a subprocess, `Node.Stop` in-process). `Kill`
  is SIGKILL for a subprocess; in-process it resets all connections of the node
  first and then stops it in an orderly way (limitation, section 7).
- `Close` stops all nodes concurrently, waits for background re-dial
  goroutines, releases the port holders, closes all proxies and removes the
  directory (kept with a log line if the test failed). `TestNoGoroutineLeak`
  starts, kills, restarts and closes a cluster and requires the goroutine count
  to return to within 2 of its value before (measured 73 -> 70 and 72 -> 68:
  neither CometBFT nor the harness leaks). `TestCrashRestartSubprocess` verifies after `Close` that no `dosrd`
  process is alive; `TestSubprocessExitWithParent` verifies that a `dosrd`
  whose parent dies stops on its own (`--exit-with-parent`), so a killed test
  binary does not leave nodes behind.

### 2.4 Two modes

In-process nodes give the tests the application (`Cluster.App(i)`), per-node
`OnCommit` hooks and Byzantine faults (`app.Faults`, injected through
`Options.Faults`). Subprocess nodes (`cmd/dosrd`, built once per test binary
with `go build` and removed in `TestMain`) can be killed with SIGKILL and can
kill themselves at a precise point of `Commit` (`node.CrashPoint`,
`--crash-before-commit`/`--crash-after-commit`). Subprocess nodes are observed
through HTTP RPC (with the unsafe `dial_peers` route enabled for re-dialling)
and a commit log (`commits.jsonl`, one `CommitRecord` per committed block:
height, app hash, SHA-256 of the state JSON, block time, wall-clock time of
durability). The `/node/state` ABCI query, answered by the node wrapper rather
than the application, returns the whole committed state in one round trip so
that the checker can snapshot a node that keeps committing.

### 2.5 The invariant checker

`Cluster.Check()` compares, for honest nodes only (nodes with `Faults` are
excluded and listed in the report):

- agreement: block hashes per height from every node's block store (via
  `BlockchainInfo`, 20 metas per call), app hash and state digest per height
  from the commit records (also of nodes that are down now), the app hash of
  each node's application against the header of block `h+1`, and the current
  state JSON byte-for-byte for nodes at the same height;
- validity: every branch's history is walked entry by entry (seq, parent
  chain, no duplicate commit, heights monotone and not in the future, receipts
  present after the genesis entry, `ChainDigest` equal to the branch's
  `HistDigest`, head equal to the last commit) and every object reachable from
  every accepted commit is fetched, re-hashed and type-checked;
- prefix: the state of a lagging node is a prefix of the most advanced node's
  (repositories, creators, policy versions, branch histories entry by entry);
- determinism: one node never committed a height twice with different results
  (matters after crash-point restarts).

The report counts what was compared so that "no violations" cannot mean
"nothing checked" (`TestSmoke` and `TestCrashRestartSubprocess` assert on the
counts). `checker_test.go` feeds the checker fabricated histories with one
defect each (12 kinds) and requires the corresponding violation. Every test
that starts a cluster ends with `MustCheck`; the fault tests also check in the
middle of the fault.

### 2.6 `pkg/node`

One `Node` = one CometBFT node + one DOSR app + their databases under one home
directory, so `Start` on an existing home restarts the node from disk. Keys and
genesis passed in memory are written only if the files do not exist: a restart
never replaces keys or the validator's last-sign state. `Config` is JSON
(`dosr_node.json`) so that `dosrd` can start from the directory alone.
`ConnSyncABCI` selects `proxy.NewConnSyncLocalClientCreator` (one mutex per
ABCI connection, so CheckTx/Query run concurrently with block execution; the
app is written for that) but the default stays the global mutex.

## 3. Defect found and fixed in this pass

`cmd/dosrd --exit-with-parent` captured `os.Getppid()` only after
`node.Start` returned. If the parent had already died during the (100-200 ms)
start-up, the captured parent was PID 1 and the poll loop never ended: the node
lived forever. `TestSubprocessExitWithParent` reproduced it (orphan still alive
after 30 s). Fixed by reading the parent PID first thing in `main` and treating
PID 1 as "already orphaned". The orphan now exits about 150 ms after its parent
(the poll interval is 500 ms).

## 4. CometBFT behaviours that had to be worked around

1. **Persistent-peer redial back-off.** `p2p/switch.go`: after a peer drops,
   `reconnectToPeer` dials once immediately, then sleeps `reconnectInterval`
   (5 s) plus a random 0..3 s between the next 20 attempts, then backs off
   exponentially (3^i seconds). While a link is blocked every attempt is reset
   by the proxy, so after healing the reconnection happens at the next attempt,
   i.e. up to ~8 s later. `TestHealPassive` measures this: after partitions of
   1, 3, 6 and 9 s the first new block came 4.6, 4.1, 1.2 and 4.0 s after the
   heal and all links were back after 6.8, 4.6, 1.2 and 6.0 s. With the
   harness's active re-dial (`OnUnblock`) the links are back 20 ms after the
   heal. Also, `DialPeersAsync` (the `dial_peers` RPC route used for
   subprocess nodes, and the initial persistent-peer dial) sleeps a random
   0..3 s (`dialRandomizerIntervalMilliseconds`) before dialling, hence the
   reverse start order and the 3.5 s wait in `ensureConnected` for subprocess
   nodes.
2. **Block sync waits 3 s before its first request.** `blocksync/pool.go`
   `peerConnWait = 3 * time.Second`: the pool sends no block request until
   3 s after it started, then the switch to consensus happens on a 1 s ticker.
   A restarted node that is more than one block behind therefore needs at
   least 3-4 s to catch up however fast its peers reconnect (measured 3.2-4.3 s
   for 6-8 blocks in `TestCrashRestartSubprocess`; traced with debug logs: peers
   connected 0.5-1.2 s after start, first block requests exactly 3.0 s after
   start, all blocks applied within 120 ms of them). A node one block behind
   catches up through the consensus reactor instead (`TestCrashPoints`: 170-190
   ms). Not configurable; documented, not worked around.
3. **Handshake replay on restart.** On start CometBFT compares the app's
   `Info` height with its block store and state. `TestCrashPoints` exercises
   both windows: killed before the app's commit of block h (store h, state
   h-1, app h-1: "Replay last block using real app", the block is executed once
   more) and killed after the app's commit but before CometBFT saved its state
   (app h, state h-1: "Replay last block using mock app", the saved
   FinalizeBlock responses are used and the app is NOT asked to execute h
   again). The commit log shows the application committed the crash height
   exactly once in both cases and the checker finds no determinism violation.
   Vote extensions are disabled, otherwise the restart would also need the
   extended commit of the last block.
4. **`LoadFilePV` exits the process** (`cmtos.Exit`) if the last-sign state
   file is missing. A key provisioned in memory is saved together with an
   empty state, and `Start` creates the state file if only the key exists.
5. **Block store panics on any read error, including "leveldb: closed".**
   `Node.OnStop` closes the block store while the consensus reactor's gossip
   routines may still be in their 100 ms sleep; when they wake up and read, the
   store panics and, in a test process with four nodes, kills all of them.
   `safeDB` answers reads after `Close` with "not found" (which the callers
   handle) and makes `Close` idempotent. Writes still fail.
6. **Tx indexer database is not closed by `Node.OnStop`.** Its goleveldb
   `LOCK` file makes a restart in the same process fail. The node keeps every
   database CometBFT opened through the DB provider and closes the remaining
   ones in `Stop`.
7. **Mempool cache.** A transaction that is in the mempool cache is refused by
   `BroadcastTxSync` with the RPC error `tx already exists in cache`
   (`mempool.ErrTxInCache`), not with a CheckTx code. `TestDuplicateReorderedTx`
   counts the three outcomes separately: with 5 contested repository IDs x 4
   rival transactions submitted twice to every node in per-node random order,
   20 passed CheckTx, 116-120 were rejected by CheckTx with `repo_exists`
   (the mempool's check state already had a rival), 20-24 were refused by the
   cache, exactly one transaction per ID took effect and the chain contains no
   failed inclusion (the honest `PrepareProposal` drops rivals).
8. **Timeouts.** CometBFT's defaults (`timeout_propose` 3 s, `timeout_commit`
   1 s) make every fault test minutes long; `node.FastTimeouts` uses
   800/300/300 ms and `timeout_commit` 150 ms. `flush_throttle_timeout`
   (default 100 ms, adds up to 100 ms to every message) is set to 10 ms;
   `send_rate`/`recv_rate` (default 5 MB/s, would throttle 8 MiB transactions)
   to 64 MiB/s, since shaping is the proxy's job. `peer_gossip_sleep_duration`
   (default 100 ms) is left at the default unless `Options.PeerGossipSleep` is
   set: with the default the block interval is ~400 ms, with 10 ms it is
   ~225-250 ms (`TestNetemBlockInterval` uses 10 ms so that the emulated delay
   is not hidden behind gossip sleeps).
9. **RPC limits.** `max_body_bytes` must hold a base64-encoded 8 MiB
   transaction; `timeout_broadcast_tx_commit` is 60 s (the HTTP write timeout
   must exceed it, `ValidateBasic` checks).
10. **`dial_peers` is an unsafe route.** Subprocess nodes run with
    `rpc.unsafe = true` so the harness can ask them to re-dial.
11. **Shutdown noise.** Stopping a node logs
    `Error serving server ... use of closed network connection` at error level
    (the RPC listener is closed under the server) and, in the peers,
    `Stopping peer for error ... EOF`; both are benign.
12. **`tb.TempDir` cleanup races with node shutdown.** A node still flushing
    its WAL when the cleanup runs made the test fail with "directory not
    empty"; `New` uses `os.MkdirTemp` and removes the directory after `Close`
    has returned.

## 5. Flaky behaviour seen and root causes

- **`TestNetemBlockInterval`, 10 ms step.** The first version required the
  median block interval to grow by at least 2x the delay for every step. At
  10 ms one-way delay the measured growth was 18.6 ms in a quiet run and 14 ms
  under `-race`, against a 20 ms (later 15 ms) bound: the medians of 16
  intervals carry about +-10 ms of scheduling noise, more under the race
  detector or with another process on the machine. The 10 ms step is now
  checked for consistency only, on the minimum interval (the protocol floor,
  which load can only raise; it grew by 24 ms in both runs); the 1.5x..8x band
  and the commit-latency check apply to the 50 and 100 ms steps, where the
  signal is 10x the noise. Twenty intervals per setting.
- **`TestNetemBlockInterval`, commit latency at 50 ms.** One of three
  `-count=3` repetitions failed the check "latency grows by at least 2x the
  delay" at 50 ms: +90 ms against a 100 ms bound. The latency of one
  `BroadcastTxCommit` is the rest of the current height plus one full height,
  so the mean of 4 samples has +-100 ms of phase noise (measured growth for
  100 ms of delay in three runs: +565, +689, +829 ms), and that repetition's
  baseline had a load spike (intervals up to 483 ms). The test now takes the
  median of 8 transactions and requires growth of 1.5x the delay (expected
  4-5x); 3/3 repetitions passed afterwards.
- **`TestSubprocessExitWithParent`** failed deterministically until the
  `dosrd` bug of section 3 was fixed; not flakiness.
- Everything else passed in every run: 21 tests x 1 (`-count=1`), x 1 under
  `-race`, x 3 (`-count=3`), see section 8. No data race was reported.

## 6. Measurements

All numbers are from `go test -v` logs of the runs listed in section 8 (the
"quiet" columns from the `-count=3` repetitions at 22:44-22:57, the "loaded"
column from the final run at 22:58-23:03 while a TLC model checker of another
agent used 2 cores). Timeouts `node.FastTimeouts()`: propose 800 ms (+200),
prevote 300 ms (+100), precommit 300 ms (+100), commit 150 ms.

### 6.1 Block interval vs configured one-way delay (4 validators)

`TestNetemBlockInterval`; `peer_gossip_sleep_duration` 10 ms, 20 intervals
per setting measured on node 0, delay set on all 12 directed links.

| one-way delay | median interval, 3 quiet runs | min interval, 3 quiet runs | median / min, loaded run | growth of the median per ms of delay |
|---|---|---|---|---|
| 0 ms | 226 / 231 / 220 ms | 191 / 190 / 192 ms | 233 / 167 ms | - |
| 10 ms | 251 / 260 / 248 ms | 216 / 201 / 214 ms | 260 / 190 ms | 2.6-2.9x (2.7x loaded) |
| 50 ms | 372 / 392 / 370 ms | 339 / 314 / 351 ms | 385 / 289 ms | 2.9-3.2x (3.0x loaded) |
| 100 ms | 531 / 548 / 568 ms | 495 / 505 / 506 ms | 602 / 528 ms | 3.1-3.5x (3.7x loaded) |

The interval grows by about three one-way delays per height (proposal,
prevotes, precommits each cross the network once; the commit timeout and the
gossip loop add the constant ~220 ms). Earlier runs with 25 ms gave 2.7x and
with 100 ms 2.9x. The 10 ms step is at the edge of resolution (see section 5).
All heights were decided in round 0 in every setting (no timeout fired).

Commit latency of one `BroadcastTxCommit` (median of 8, submitted round-robin
to the four nodes): 217 / 245 / 217 ms at 0 ms; 242 / 255 / 247 ms at 10 ms;
381 / 393 / 361 ms at 50 ms; 523 / 1067 / 523 ms at 100 ms (loaded run: 218,
271, 387, 1209 ms). At 100 ms the median is bimodal: a transaction that reaches
the next proposer's mempool in time is committed after about one interval
(~520 ms), one that does not waits a further height (~1.1 s); with 100 ms of
mempool-gossip delay about half the transactions miss the next block.

Without emulated delay and with CometBFT's default `peer_gossip_sleep_duration`
(100 ms) the interval is ~400 ms (`TestSmoke`: median 402 ms quiet, 576 ms
loaded; `TestByzantineApp` baselines: 395-406 ms). The proxy itself adds
~0.1-0.2 ms per direction (`TestNetemDelay`: RTT median 104-590 us with 0-0.2
ms configured; 101.9 ms median for 50+50 ms; chunks written on average 0.3-0.9
ms after their release time, at most 5-8 ms).

### 6.2 Recovery after a partition heals

- 2|2 partition (`TestPartition22`, harness re-dials on heal): all four
  nodes noticed the partition after 20-30 ms (connections are reset); no
  block was committed on either side for 5 s; after the heal all cut links
  were re-established after 20 ms and the first new block was committed on
  all nodes 1.154 s (quiet) / 1.167 s (loaded) after the heal. Both sides'
  pending transactions were committed afterwards.
- 3|1 partition (`TestPartition31`): the majority committed 8+ blocks and a
  transaction while node 3 stayed at its height and rejected nothing into its
  state; after the heal its links were back after 20 ms and it caught up 10
  blocks after 1.341 s (quiet) / 1.031 s (loaded).
- CometBFT alone (`TestHealPassive`, no harness re-dial), partitions held
  1 / 3 / 6 / 9 s: first new block 4.6 / 4.1 / 1.2 / 4.0 s after the heal and
  all links back after 6.8 / 4.6 / 1.2 / 6.0 s (quiet run); 4.2 / 2.3 / 2.9 /
  3.7 s and 5.7 / 4.7 / 5.5 / 5.9 s (loaded run). This is the 5 s + random
  0..3 s reconnection timer of section 4.1.
- No quorum (`TestTwoOfFourStopped`): with 2 of 4 validators stopped no block
  was committed in 5 s and a submitted transaction did not take effect;
  liveness returned 1.43-1.45 s after one validator was restarted.

### 6.3 Catch-up time of a restarted node

- In-process, 1 of 4 killed (`TestCrashRestart`): the three others committed 8
  blocks in 5.75-5.77 s (719-722 ms per block: every turn of the dead
  proposer costs a `timeout_propose` of 800 ms); after `Restart` the node was
  up after 141-144 ms and had caught up 9+ blocks (including a repository with
  objects created while it was down) after 4.82-4.88 s.
- Subprocess, SIGKILL x 4 under transaction load (`TestCrashRestartSubprocess`,
  ~900 CreateRepo transactions, 1 in 8 with a genesis commit and objects):
  process up (RPC answering) after 103-235 ms; caught up 6-9 blocks after
  3.17-3.40 s in every cycle (3.19 / 3.32 / 3.40 / 3.38 s and 3.27 / 3.32 /
  3.28 / 3.32 s). The 3 s floor is CometBFT's `peerConnWait` (section 4.2).
- Subprocess, SIGKILL inside `Commit` (`TestCrashPoints`), one block behind
  after the handshake: caught up 147-190 ms after the restart (consensus
  reactor, no block sync).

### 6.4 Cost of a Byzantine proposer, strict vs lenient `ProcessProposal`

`TestByzantineApp`: validator 3 runs `app.Faults{InjectTxs, AcceptAllProposals}`
and puts 300 bytes of garbage, a replayed (already committed) CreateRepo and a
CreateRepo with a broken signature at the front of every block it proposes.
24 heights per measurement = 6 turns of the Byzantine proposer, default gossip
sleep (baseline interval ~400 ms).

| | strict (`StrictProposals=true`, default) | lenient |
|---|---|---|
| extra rounds in 24 heights (baseline 0) | 6 (one per Byzantine turn) | 0 |
| blocks of the Byzantine proposer decided | 0 | 6 |
| proposals rejected by the 3 honest nodes | 21 quiet / 18 loaded | 0 |
| injected transactions included in the chain | 0 | 18 (3 per Byzantine block), all failed with their error codes |
| time for 24 heights vs the same network without the fault | +3.59 s quiet, +2.32 s loaded | -3 ms quiet, +394 ms loaded (noise) |
| per turn of the Byzantine proposer | +598 ms quiet, +386 ms loaded | -1 / +66 ms |
| block interval median / p95 with the fault | 402 / 1004 ms quiet | 400 / 410 ms |
| state of the honest nodes | unchanged | unchanged |

In strict mode a Byzantine turn costs one round: the honest nodes prevote nil,
precommit nil, wait `timeout_precommit` (300 ms + 100 ms delta) and the next
proposer's block is decided in round 1, i.e. roughly 0.4-0.6 s per turn with
these timeouts. In lenient mode the block is decided in round 0 with the
injected transactions inside it; each one fails in `FinalizeBlock` and the
state is the same on all four nodes (the Byzantine node's application executes
blocks honestly, and its app hashes equalled the honest ones at every height).
The price of lenient mode is chain bloat (here 3 junk transactions per
Byzantine block; a real attacker can use megabytes of bundle each); the price
of strict mode is one lost round per Byzantine turn, and the invariant checker
finds no violation in either mode.

## 7. Limitations

- **In-process `Kill` is not `kill -9`.** A goroutine cannot be killed and the
  databases must be released for a restart in the same process, so the stop is
  orderly after the connections have been reset. Crash consistency (the two
  windows of `Commit`) is only tested in subprocess mode (`TestCrashPoints`,
  `TestCrashRestartSubprocess`). Stopping in-process also means the node's
  WAL is complete; a real crash that truncates the WAL is not exercised.
- **Single machine.** All nodes, proxies and the test share 8 cores and one
  kernel. Timing numbers are for this machine and were partly taken while
  another agent's benchmark (`dosr-bench`) ran concurrently; the numbers vary
  by about 10% between runs. The commit timestamps of different nodes come from
  the same clock, which is what makes the block interval comparable across
  nodes, but no clock skew is emulated.
- **Emulated links.** The proxy delays TCP byte streams. It does not emulate
  packet loss, reordering (TCP would hide it) or bufferbloat; a "block" is a
  TCP reset, not silent packet drop, so peers notice a partition in ~30 ms
  rather than after a keep-alive timeout. Jitter is per chunk, not per packet.
  Delays below ~1 ms are at the mercy of the timer resolution (`LAN` = 0.2 ms
  measured as ~0.6 ms RTT).
- **Byzantine faults are application faults only** (`InjectTxs`,
  `AcceptAllProposals`): a validator with a malicious application. Equivocation
  or a malicious CometBFT are not emulated; CometBFT's own evidence handling is
  not tested here.
- **Only `CreateRepo` transactions** are used as load; the AcceptCommit path
  (bundles, receipts, notaries) is exercised by `pkg/app`'s own tests and the
  benchmark, not by the fault tests.
- The port-holding trick does not help a subprocess that loses the race for a
  port to an unrelated process on the machine; the node would fail to start and
  the test would fail visibly.

## 8. Test output

Command: `go test ./pkg/node/ ./pkg/testnet/ -count=1 -v -timeout 40m`
(final run, 2026-09-29 22:58-23:03, machine loaded by another agent's TLC run).
Earlier runs: the same command before the fixes of sections 3 and 5 (all 21
tests passed, 230 s), `-race` (294 s, no data race; the 10 ms step of
`TestNetemBlockInterval` failed once as described in section 5),
`-count=3` of `pkg/testnet` (812 s; every test passed three times except one
`TestNetemBlockInterval` repetition on the commit-latency bound, also section
5), and `-count=3 -run TestNetemBlockInterval` after the last change (3/3
passed, 33-35 s each).

Per-test results of the final run:

```
--- PASS: TestSingleNodeMemDB (0.59s)
--- PASS: TestRestartFromDisk (1.79s)
PASS
ok  	github.com/dosr/dosr/pkg/node	3.051s
--- PASS: TestCheckerAcceptsValidHistory (0.00s)
--- PASS: TestCheckerDetectsViolations (0.00s)
--- PASS: TestCheckerPrefixAndAgreement (0.00s)
--- PASS: TestSmoke (5.35s)
--- PASS: TestNoGoroutineLeak (5.44s)
--- PASS: TestCrashRestart (15.93s)
--- PASS: TestCrashRestartSubprocess (32.74s)
--- PASS: TestSubprocessExitWithParent (0.11s)
--- PASS: TestCrashPoints (18.89s)
--- PASS: TestTwoOfFourStopped (12.29s)
--- PASS: TestPartition22 (10.19s)
--- PASS: TestHealPassive (44.27s)
--- PASS: TestPartition31 (11.30s)
--- PASS: TestNetemBlockInterval (37.52s)
--- PASS: TestDuplicateReorderedTx (5.03s)
--- PASS: TestByzantineApp (51.88s)
--- PASS: TestNetemDelay (9.12s)
--- PASS: TestNetemDelayDoesNotAccumulate (0.48s)
--- PASS: TestNetemIntegrity (0.94s)
--- PASS: TestNetemRate (2.02s)
--- PASS: TestNetemBlock (0.01s)
--- PASS: TestPresets (0.00s)
PASS
ok  	github.com/dosr/dosr/pkg/testnet	263.976s
EXIT 0
```

Tail of the output (the last test's checker report and the netem unit tests):

```
    faults_test.go:789: fault active, strict=false: block interval 24 intervals (heights 31..55): mean 398ms median 394ms p95 446ms min 306ms max 531ms; 0 extra rounds in 24 heights; 6 blocks proposed by the Byzantine validator
    faults_test.go:805: RESULT strict=false: time for 24 heights changed by 394ms against the same network without the fault (66ms per turn of the Byzantine proposer; timeouts propose/prevote/precommit/commit = 800ms/300ms/300ms/150ms); extra rounds 0 (baseline 0); PrepareProposal calls on the Byzantine node 6
    faults_test.go:835: strict=false: 18 inclusions of injected transactions in blocks 29..55 (all failed); proposals rejected by honest nodes: 0
    faults_test.go:853: invariants OK (compared: 174 blocks, 174 commit records, 177 states; walked 0 history entries, 0 objects; 0 prefix entries; 1ms)
          node 0: running, honest, height 58, app hash cc291a16e007d160, 1 branches, 58 commit records
          node 1: running, honest, height 58, app hash cc291a16e007d160, 1 branches, 58 commit records
          node 2: running, honest, height 58, app hash cc291a16e007d160, 1 branches, 58 commit records
          node 3: running, BYZANTINE-APP (excluded), height 58, app hash cc291a16e007d160, 1 branches, 58 commit records
          note: node 3 has a Byzantine application and is not checked
        
--- PASS: TestByzantineApp (51.88s)
    --- PASS: TestByzantineApp/strict=true (27.87s)
    --- PASS: TestByzantineApp/strict=false (24.01s)
=== RUN   TestNetemDelay
    netem_test.go:102: one-way 0s/0s jitter 0s: RTT want 0s, min 97.417µs median 1.685833ms p95 6.1455ms
    netem_test.go:102: one-way 200µs/200µs jitter 0s: RTT want 400µs, min 715.584µs median 1.964292ms p95 5.941708ms
    netem_test.go:102: one-way 5ms/5ms jitter 0s: RTT want 10ms, min 10.902375ms median 13.816291ms p95 25.866209ms
    netem_test.go:102: one-way 20ms/0s jitter 0s: RTT want 20ms, min 20.560333ms median 22.745875ms p95 27.061834ms
    netem_test.go:102: one-way 50ms/50ms jitter 0s: RTT want 100ms, min 101.011167ms median 103.75675ms p95 113.135042ms
    netem_test.go:102: one-way 30ms/30ms jitter 10ms: RTT want 60ms, min 46.082167ms median 64.982709ms p95 83.290542ms
--- PASS: TestNetemDelay (9.12s)
=== RUN   TestNetemDelayDoesNotAccumulate
    netem_test.go:184: one-way delay 25ms: observed min 25.137ms median 25.99ms p95 28.982ms max 33.458ms; proxy: 160 chunks, written on average 941.185µs and at most 8.372459ms after their release time
--- PASS: TestNetemDelayDoesNotAccumulate (0.48s)
=== RUN   TestNetemIntegrity
=== RUN   TestNetemIntegrity/plain
=== RUN   TestNetemIntegrity/delay+jitter
=== RUN   TestNetemIntegrity/rate
--- PASS: TestNetemIntegrity (0.94s)
    --- PASS: TestNetemIntegrity/plain (0.13s)
    --- PASS: TestNetemIntegrity/delay+jitter (0.05s)
    --- PASS: TestNetemIntegrity/rate (0.76s)
=== RUN   TestNetemRate
    netem_test.go:301: 2097152 bytes at 1048576 B/s: took 2.012990208s, want about 2s
--- PASS: TestNetemRate (2.02s)
=== RUN   TestNetemBlock
--- PASS: TestNetemBlock (0.01s)
=== RUN   TestPresets
--- PASS: TestPresets (0.00s)
PASS
ok  	github.com/dosr/dosr/pkg/testnet	263.976s
EXIT 0
```
