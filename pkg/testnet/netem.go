// Package testnet runs N-validator DOSR networks on localhost with a
// controllable network between the nodes, and checks safety invariants
// on them. It is the basis of the multi-node tests and of the benchmark
// harness.
package testnet

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// This file implements the network emulator ("netem"): a userspace TCP
// proxy per pair of nodes.
//
// Topology. For each pair i<j there is ONE proxy listener P(i,j). Node i
// has nodeID_j@P(i,j) as a persistent peer; node j does not know any
// address of node i (PEX is off), so the only connection between i and j
// is the one i dials through the proxy:
//
//	node i  --dial-->  P(i,j)  ==proxy==>  node j's p2p listener
//
// Each direction of a proxied connection is a pipeline
//
//	reader: read chunk from src, stamp it with a release time, enqueue
//	writer: dequeue, sleep until the release time, write to dst
//
// The release time of a chunk is (time the chunk left the emulated link)
// + delay + jitter, forced to be non-decreasing. Because chunks are
// written in queue order by a single writer, the TCP byte stream is
// preserved exactly; because the delay is attached to the arrival time of
// each chunk (not implemented as a sleep between read and write) the
// imposed delay does not accumulate and does not depend on how the sender
// splits its writes.

// LinkParams are the emulation parameters of one direction of a link.
type LinkParams struct {
	// Delay is the constant one-way delay.
	Delay time.Duration
	// Jitter is added to Delay, uniformly distributed in
	// [-Jitter, +Jitter] (the sum is clamped at 0). Reordering is not
	// emulated: TCP would hide it anyway, so a chunk is never released
	// before its predecessor.
	Jitter time.Duration
	// Rate is the bandwidth cap in bytes per second; 0 means unlimited.
	Rate int64
}

// LinkStats are counters of one link.
type LinkStats struct {
	Accepted int64 // connections accepted by the proxy listener
	Refused  int64 // connections refused because the link was blocked or the upstream was down
	Active   int64 // connections currently proxied
	BytesFwd int64 // bytes delivered dialer -> listener side
	BytesRev int64 // bytes delivered listener -> dialer side
	// Chunks is the number of chunks delivered. LateMean and LateMax
	// say how long after its release time a chunk was completely
	// written to the destination socket: the emulator's own error
	// (timer resolution, scheduling, a destination that does not read).
	Chunks   int64
	LateMean time.Duration
	LateMax  time.Duration
}

const (
	readBufSize = 64 << 10
	// queueLen bounds the chunks queued per direction. With 64 KiB
	// chunks that is at most 128 MiB; when the queue is full the reader
	// stops reading and TCP flow control pushes back on the sender.
	queueLen = 2048
	// maxBacklog bounds how far the emulated link's transmit queue may
	// run ahead of real time when a bandwidth cap is set.
	maxBacklog = 250 * time.Millisecond
	// upstreamDialTimeout bounds the proxy's dial to the real listener.
	upstreamDialTimeout = 2 * time.Second
)

// Link is one proxied link: a listener, the address it forwards to, and
// emulation parameters per direction. Forward is the direction from the
// dialing side to the upstream.
type Link struct {
	ln net.Listener

	mu       sync.Mutex
	upstream string
	pairs    map[*pair]struct{}
	closed   bool

	blocked atomic.Bool
	down    atomic.Bool
	fwd     atomic.Pointer[LinkParams]
	rev     atomic.Pointer[LinkParams]

	accepted, refused, active atomic.Int64
	bytesFwd, bytesRev        atomic.Int64
	chunks, lateSum, lateMax  atomic.Int64

	wg sync.WaitGroup
}

// NewLink starts a proxy on a free port of 127.0.0.1 forwarding to
// upstream (which may be empty and set later with SetUpstream).
func NewLink(upstream string) (*Link, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &Link{ln: ln, upstream: upstream, pairs: map[*pair]struct{}{}}
	l.fwd.Store(&LinkParams{})
	l.rev.Store(&LinkParams{})
	l.wg.Add(1)
	go l.acceptLoop()
	return l, nil
}

// Addr is the address of the proxy listener.
func (l *Link) Addr() string { return l.ln.Addr().String() }

// SetUpstream sets the address the link forwards to.
func (l *Link) SetUpstream(addr string) {
	l.mu.Lock()
	l.upstream = addr
	l.mu.Unlock()
}

// SetForward sets the parameters of the dialer -> upstream direction.
// It takes effect for data read from now on.
func (l *Link) SetForward(p LinkParams) { l.fwd.Store(&p) }

// SetReverse sets the parameters of the upstream -> dialer direction.
func (l *Link) SetReverse(p LinkParams) { l.rev.Store(&p) }

// Forward returns the parameters of the forward direction.
func (l *Link) Forward() LinkParams { return *l.fwd.Load() }

// Reverse returns the parameters of the reverse direction.
func (l *Link) Reverse() LinkParams { return *l.rev.Load() }

// Block blocks or unblocks the link. Blocking resets all proxied
// connections (both endpoints see the connection fail immediately, data
// in flight is lost) and makes the proxy reset new connections right
// after accepting them.
func (l *Link) Block(blocked bool) {
	l.blocked.Store(blocked)
	if blocked {
		l.Reset()
	}
}

// Blocked reports whether the link is blocked.
func (l *Link) Blocked() bool { return l.blocked.Load() }

// SetDown marks an endpoint of the link as dead. It acts like Block but
// is independent of it, so that partitions and node crashes compose.
func (l *Link) SetDown(down bool) {
	l.down.Store(down)
	if down {
		l.Reset()
	}
}

// cut reports whether the link forwards nothing.
func (l *Link) cut() bool { return l.blocked.Load() || l.down.Load() }

// Reset resets all connections currently proxied by the link.
func (l *Link) Reset() {
	l.mu.Lock()
	ps := make([]*pair, 0, len(l.pairs))
	for p := range l.pairs {
		ps = append(ps, p)
	}
	l.mu.Unlock()
	for _, p := range ps {
		p.abort()
	}
}

// Stats returns the link's counters.
func (l *Link) Stats() LinkStats {
	st := LinkStats{
		Accepted: l.accepted.Load(), Refused: l.refused.Load(), Active: l.active.Load(),
		BytesFwd: l.bytesFwd.Load(), BytesRev: l.bytesRev.Load(),
		Chunks: l.chunks.Load(), LateMax: time.Duration(l.lateMax.Load()),
	}
	if st.Chunks > 0 {
		st.LateMean = time.Duration(l.lateSum.Load() / st.Chunks)
	}
	return st
}

// UpstreamLocalAddrs returns the local addresses of the proxy's
// connections to the upstream, i.e. the remote addresses the upstream
// node sees for its inbound peer.
func (l *Link) UpstreamLocalAddrs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for p := range l.pairs {
		out = append(out, p.up.LocalAddr().String())
	}
	return out
}

// ResetStats clears the lateness statistics.
func (l *Link) ResetStats() {
	l.chunks.Store(0)
	l.lateSum.Store(0)
	l.lateMax.Store(0)
}

// Close stops the proxy and resets its connections.
func (l *Link) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.mu.Unlock()
	l.ln.Close()
	l.Reset()
	l.wg.Wait()
}

func (l *Link) acceptLoop() {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		l.accepted.Add(1)
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.serve(c.(*net.TCPConn))
		}()
	}
}

// reset closes a connection so that the peer sees a reset instead of an
// orderly shutdown.
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

func (l *Link) serve(client *net.TCPConn) {
	l.mu.Lock()
	upstream := l.upstream
	closed := l.closed
	l.mu.Unlock()
	if closed || l.cut() || upstream == "" {
		l.refused.Add(1)
		reset(client)
		return
	}
	upc, err := net.DialTimeout("tcp", upstream, upstreamDialTimeout)
	if err != nil {
		// The node behind the link is down.
		l.refused.Add(1)
		reset(client)
		return
	}
	up := upc.(*net.TCPConn)
	p := &pair{l: l, client: client, up: up, done: make(chan struct{})}

	l.mu.Lock()
	if l.closed || l.cut() {
		l.mu.Unlock()
		l.refused.Add(1)
		reset(client)
		reset(up)
		return
	}
	l.pairs[p] = struct{}{}
	l.mu.Unlock()
	l.active.Add(1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.pump(client, up, &l.fwd, &l.bytesFwd) }()
	go func() { defer wg.Done(); p.pump(up, client, &l.rev, &l.bytesRev) }()
	wg.Wait()
	p.close()

	l.mu.Lock()
	delete(l.pairs, p)
	l.mu.Unlock()
	l.active.Add(-1)
}

// pair is one proxied connection.
type pair struct {
	l          *Link
	client, up *net.TCPConn
	done       chan struct{}
	once       sync.Once
}

func (p *pair) shutdown(rst bool) {
	p.once.Do(func() {
		close(p.done)
		if rst {
			reset(p.client)
			reset(p.up)
		} else {
			p.client.Close()
			p.up.Close()
		}
	})
}

func (p *pair) close() { p.shutdown(false) }
func (p *pair) abort() { p.shutdown(true) }

type chunk struct {
	data    []byte
	release time.Time
	eof     bool
}

var (
	jitterMu  sync.Mutex
	jitterRng = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func jitter(j time.Duration) time.Duration {
	if j <= 0 {
		return 0
	}
	jitterMu.Lock()
	defer jitterMu.Unlock()
	return time.Duration(jitterRng.Int63n(2*int64(j)+1)) - j
}

// pump forwards one direction of a connection.
func (p *pair) pump(src, dst *net.TCPConn, params *atomic.Pointer[LinkParams], counter *atomic.Int64) {
	q := make(chan chunk, queueLen)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.writer(dst, q, counter)
	}()
	defer wg.Wait()
	defer close(q)

	buf := make([]byte, readBufSize)
	var lastRelease, linkFree time.Time
	stamp := func(n int) time.Time {
		par := params.Load()
		now := time.Now()
		t := now
		if par.Rate > 0 {
			// The chunk starts transmission when the link is free
			// and occupies it for n/Rate.
			if linkFree.Before(now) {
				linkFree = now
			}
			linkFree = linkFree.Add(time.Duration(float64(n) / float64(par.Rate) * float64(time.Second)))
			t = linkFree
		}
		d := par.Delay + jitter(par.Jitter)
		if d < 0 {
			d = 0
		}
		rel := t.Add(d)
		if rel.Before(lastRelease) {
			rel = lastRelease
		}
		lastRelease = rel
		return rel
	}
	for {
		par := params.Load()
		rb := buf
		if par.Rate > 0 {
			// Keep chunks short in link time (<= 20 ms) so that the
			// cap shapes the stream smoothly, and do not read ahead
			// of the emulated transmit queue.
			if lim := par.Rate / 50; lim < int64(len(rb)) {
				if lim < 512 {
					lim = 512
				}
				rb = rb[:lim]
			}
			if ahead := time.Until(linkFree); ahead > maxBacklog {
				if !p.sleep(ahead - maxBacklog) {
					return
				}
			}
		}
		n, err := src.Read(rb)
		if n > 0 {
			c := chunk{data: append([]byte(nil), rb[:n]...), release: stamp(n)}
			select {
			case q <- c:
			case <-p.done:
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				// Orderly half-close: deliver it after the data.
				select {
				case q <- chunk{eof: true, release: stamp(0)}:
				case <-p.done:
				}
				return
			}
			p.abort()
			return
		}
	}
}

// sleep waits for d or until the pair is closed (returns false).
func (p *pair) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-p.done:
		return false
	}
}

func (p *pair) writer(dst *net.TCPConn, q <-chan chunk, counter *atomic.Int64) {
	for {
		var c chunk
		var ok bool
		select {
		case c, ok = <-q:
			if !ok {
				return
			}
		case <-p.done:
			return
		}
		if !p.sleep(time.Until(c.release)) {
			return
		}
		if p.l.cut() {
			// Nothing is delivered once the link is blocked.
			p.abort()
			return
		}
		if c.eof {
			_ = dst.CloseWrite()
			return
		}
		if _, err := dst.Write(c.data); err != nil {
			p.abort()
			return
		}
		counter.Add(int64(len(c.data)))
		late := int64(time.Since(c.release))
		p.l.chunks.Add(1)
		p.l.lateSum.Add(late)
		for {
			old := p.l.lateMax.Load()
			if late <= old || p.l.lateMax.CompareAndSwap(old, late) {
				break
			}
		}
	}
}

// ---------------------------------------------------------------- Net

// Matrix is a matrix of one-way delays: m[i][j] is the delay of data
// travelling from node i to node j.
type Matrix [][]time.Duration

// Net is the emulated network between n nodes: one Link per pair.
type Net struct {
	n     int
	links [][]*Link // links[i][j], i<j

	mu        sync.Mutex
	onUnblock func(i, j int)
	down      []bool
}

// NewNet creates the proxies for n nodes. Upstream addresses are set
// with SetUpstream once the nodes' listen addresses are known.
func NewNet(n int) (*Net, error) {
	nt := &Net{n: n, links: make([][]*Link, n)}
	for i := 0; i < n; i++ {
		nt.links[i] = make([]*Link, n)
		for j := i + 1; j < n; j++ {
			l, err := NewLink("")
			if err != nil {
				nt.Close()
				return nil, err
			}
			nt.links[i][j] = l
		}
	}
	return nt, nil
}

// N returns the number of nodes.
func (nt *Net) N() int { return nt.n }

// Link returns the link between i and j (in either order).
func (nt *Net) Link(i, j int) *Link {
	if i > j {
		i, j = j, i
	}
	if i == j || i < 0 || j >= nt.n {
		panic(fmt.Sprintf("netem: no link %d-%d", i, j))
	}
	return nt.links[i][j]
}

// ProxyAddr returns the address node i dials to reach node j (i<j).
func (nt *Net) ProxyAddr(i, j int) string {
	if i >= j {
		panic("netem: ProxyAddr needs i<j: the lower-numbered node dials")
	}
	return nt.links[i][j].Addr()
}

// SetUpstream sets node j's real p2p listen address.
func (nt *Net) SetUpstream(j int, addr string) {
	for i := 0; i < j; i++ {
		nt.links[i][j].SetUpstream(addr)
	}
}

// OnUnblock registers a function called (in its own goroutine) for every
// link that goes from blocked to unblocked. The cluster uses it to make
// the dialing node re-dial immediately instead of waiting for CometBFT's
// reconnection timer.
func (nt *Net) OnUnblock(f func(i, j int)) {
	nt.mu.Lock()
	nt.onUnblock = f
	nt.mu.Unlock()
}

func (nt *Net) each(f func(i, j int, l *Link)) {
	for i := 0; i < nt.n; i++ {
		for j := i + 1; j < nt.n; j++ {
			f(i, j, nt.links[i][j])
		}
	}
}

// setDir updates one direction (from -> to) of a link.
func (nt *Net) setDir(from, to int, f func(p *LinkParams)) {
	l := nt.Link(from, to)
	if from < to {
		p := l.Forward()
		f(&p)
		l.SetForward(p)
	} else {
		p := l.Reverse()
		f(&p)
		l.SetReverse(p)
	}
}

// SetDelay sets the ONE-WAY delay and jitter of data travelling from
// node i to node j. The opposite direction is unchanged.
func (nt *Net) SetDelay(i, j int, d, jitter time.Duration) {
	nt.setDir(i, j, func(p *LinkParams) { p.Delay, p.Jitter = d, jitter })
}

// SetLinkDelay sets the one-way delay of both directions between i and j
// (the round-trip time becomes 2d).
func (nt *Net) SetLinkDelay(i, j int, d, jitter time.Duration) {
	nt.SetDelay(i, j, d, jitter)
	nt.SetDelay(j, i, d, jitter)
}

// SetRate sets the bandwidth cap (bytes/s, 0 = unlimited) from i to j.
func (nt *Net) SetRate(i, j int, bytesPerSec int64) {
	nt.setDir(i, j, func(p *LinkParams) { p.Rate = bytesPerSec })
}

// SetAllRates sets the same bandwidth cap on all links, both directions.
func (nt *Net) SetAllRates(bytesPerSec int64) {
	nt.each(func(i, j int, _ *Link) {
		nt.SetRate(i, j, bytesPerSec)
		nt.SetRate(j, i, bytesPerSec)
	})
}

// SetAllDelays sets all one-way delays from a matrix (which must be at
// least n x n; the diagonal is ignored). Jitter is set to jitterFrac
// times the delay.
func (nt *Net) SetAllDelays(m Matrix, jitterFrac float64) {
	for i := 0; i < nt.n; i++ {
		for j := 0; j < nt.n; j++ {
			if i != j {
				d := m[i][j]
				nt.SetDelay(i, j, d, time.Duration(float64(d)*jitterFrac))
			}
		}
	}
}

// SetUniformDelay sets the same one-way delay on all links.
func (nt *Net) SetUniformDelay(d, jitter time.Duration) {
	nt.each(func(i, j int, _ *Link) { nt.SetLinkDelay(i, j, d, jitter) })
}

// Block blocks or unblocks the link between i and j.
func (nt *Net) Block(i, j int, blocked bool) {
	l := nt.Link(i, j)
	was := l.Blocked()
	l.Block(blocked)
	if was && !blocked {
		nt.mu.Lock()
		f := nt.onUnblock
		nt.mu.Unlock()
		if f != nil {
			if i > j {
				i, j = j, i
			}
			go f(i, j)
		}
	}
}

// Partition splits the network into the given groups: links inside a
// group are unblocked, links between groups are blocked. A node that is
// not listed in any group is isolated from everyone.
func (nt *Net) Partition(groups ...[]int) {
	g := make([]int, nt.n)
	for i := range g {
		g[i] = -1 - i // unique
	}
	for gi, members := range groups {
		for _, m := range members {
			g[m] = gi
		}
	}
	nt.each(func(i, j int, _ *Link) { nt.Block(i, j, g[i] != g[j]) })
}

// Isolate blocks all links of node i (other links are unchanged).
func (nt *Net) Isolate(i int) {
	for j := 0; j < nt.n; j++ {
		if j != i {
			nt.Block(i, j, true)
		}
	}
}

// Heal unblocks all links.
func (nt *Net) Heal() {
	nt.each(func(i, j int, _ *Link) { nt.Block(i, j, false) })
}

// SetDown marks node i as dead (or alive again): while a node is down
// all its connections are reset and its links forward nothing,
// independently of partitions. The cluster uses it to make a node
// disappear abruptly.
func (nt *Net) SetDown(i int, down bool) {
	nt.mu.Lock()
	if nt.down == nil {
		nt.down = make([]bool, nt.n)
	}
	nt.down[i] = down
	st := append([]bool(nil), nt.down...)
	nt.mu.Unlock()
	for j := 0; j < nt.n; j++ {
		if j != i {
			nt.Link(i, j).SetDown(st[i] || st[j])
		}
	}
}

// Close stops all proxies.
func (nt *Net) Close() {
	for i := range nt.links {
		for _, l := range nt.links[i] {
			if l != nil {
				l.Close()
			}
		}
	}
}

// ------------------------------------------------------------ presets

// LAN is a uniform matrix of 0.2 ms one-way delay (same data centre).
// Note that 0.2 ms is below the resolution of timers on most systems;
// the delay actually imposed is what the OS timer delivers (see
// TestNetemDelay for measurements).
func LAN(n int) Matrix { return Uniform(n, 200*time.Microsecond) }

// Regional is a uniform matrix of 10 ms one-way delay (data centres of
// one continent, RTT 20 ms).
func Regional(n int) Matrix { return Uniform(n, 10*time.Millisecond) }

// Uniform returns the n x n matrix with one-way delay d everywhere.
func Uniform(n int, d time.Duration) Matrix {
	m := make(Matrix, n)
	for i := range m {
		m[i] = make([]time.Duration, n)
		for j := range m[i] {
			if i != j {
				m[i][j] = d
			}
		}
	}
	return m
}

// WAN5Regions names the regions of the WAN5 preset.
var WAN5Regions = [5]string{"us-east", "us-west", "eu-west", "ap-northeast", "ap-southeast"}

// WAN5RTTms are the ROUND-TRIP times in milliseconds between the five
// regions of the WAN5 preset.
//
// ASSUMED REPRESENTATIVE VALUES. These numbers were NOT measured by us
// and are NOT copied from a dataset snapshot. They are round numbers
// chosen to be of the magnitude that public inter-region latency
// dashboards for the large clouds report (e.g. the community-run AWS
// inter-region ping matrix at cloudping.co, regions N. Virginia, Oregon,
// Ireland, Tokyo, Singapore), written down from memory. Actual values
// vary by provider, region pair, route and time of day by tens of
// percent. The diagonal is the RTT between two nodes of the same region.
var WAN5RTTms = [5][5]float64{
	//            us-east us-west eu-west ap-ne  ap-se
	/* us-east */ {1, 70, 75, 150, 220},
	/* us-west */ {70, 1, 130, 100, 170},
	/* eu-west */ {75, 130, 1, 215, 175},
	/* ap-ne   */ {150, 100, 215, 1, 70},
	/* ap-se   */ {220, 170, 175, 70, 1},
}

// WAN5Region returns the region index of node i (round-robin).
func WAN5Region(i int) int { return i % 5 }

// WAN5 returns the one-way delay matrix for n nodes assigned round-robin
// to the five regions of WAN5RTTms (one-way delay = RTT/2, i.e. routes
// are assumed symmetric).
func WAN5(n int) Matrix {
	m := make(Matrix, n)
	for i := range m {
		m[i] = make([]time.Duration, n)
		for j := range m[i] {
			if i != j {
				rtt := WAN5RTTms[WAN5Region(i)][WAN5Region(j)]
				m[i][j] = time.Duration(rtt / 2 * float64(time.Millisecond))
			}
		}
	}
	return m
}
