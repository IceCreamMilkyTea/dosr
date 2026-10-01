package testnet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sort"
	"testing"
	"time"
)

// echoServer echoes everything back; it half-closes when the client does.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().String()
}

func newTestLink(t *testing.T, upstream string) *Link {
	t.Helper()
	l, err := NewLink(upstream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}

func percentile(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

// TestNetemDelay measures the round-trip time of small messages over an
// echo connection for several configured one-way delays.
func TestNetemDelay(t *testing.T) {
	l := newTestLink(t, echoServer(t))
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ping := func() time.Duration {
		var b [8]byte
		start := time.Now()
		if _, err := c.Write(b[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, b[:]); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	cases := []struct {
		fwd, rev time.Duration
		jitter   time.Duration
		tol      time.Duration // allowed excess of the median over fwd+rev
	}{
		{0, 0, 0, 10 * time.Millisecond},
		{200 * time.Microsecond, 200 * time.Microsecond, 0, 10 * time.Millisecond},
		{5 * time.Millisecond, 5 * time.Millisecond, 0, 10 * time.Millisecond},
		{20 * time.Millisecond, 0, 0, 10 * time.Millisecond},
		{50 * time.Millisecond, 50 * time.Millisecond, 0, 12 * time.Millisecond},
		{30 * time.Millisecond, 30 * time.Millisecond, 10 * time.Millisecond, 12 * time.Millisecond},
	}
	for _, tc := range cases {
		l.SetForward(LinkParams{Delay: tc.fwd, Jitter: tc.jitter})
		l.SetReverse(LinkParams{Delay: tc.rev, Jitter: tc.jitter})
		n := 40
		if testing.Short() {
			n = 15
		}
		var rtts []time.Duration
		for i := 0; i < n; i++ {
			rtts = append(rtts, ping())
			time.Sleep(time.Millisecond)
		}
		want := tc.fwd + tc.rev
		min, med, p95 := percentile(rtts, 0), percentile(rtts, 0.5), percentile(rtts, 0.95)
		t.Logf("one-way %v/%v jitter %v: RTT want %v, min %v median %v p95 %v",
			tc.fwd, tc.rev, tc.jitter, want, min, med, p95)
		if lo := want - 2*tc.jitter; min < lo {
			t.Errorf("delay %v: minimum RTT %v is below %v", want, min, lo)
		}
		if med > want+tc.tol || med < want-tc.jitter {
			t.Errorf("delay %v: median RTT %v outside [%v, %v]", want, med, want-tc.jitter, want+tc.tol)
		}
	}
}

// TestNetemDelayDoesNotAccumulate sends a stream of messages spaced
// closer than the delay and with widely varying sizes, and checks that
// EVERY message is delayed by about the configured delay: a proxy that
// sleeps between read and write would accumulate delay.
func TestNetemDelayDoesNotAccumulate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const msgs = 150
	type rec struct {
		sent time.Time
		recv time.Time
	}
	done := make(chan []rec, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var out []rec
		var hdr [12]byte
		for i := 0; i < msgs; i++ {
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				break
			}
			n := binary.BigEndian.Uint32(hdr[8:])
			if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
				break
			}
			out = append(out, rec{time.Unix(0, int64(binary.BigEndian.Uint64(hdr[:8]))), time.Now()})
		}
		done <- out
	}()

	const delay = 25 * time.Millisecond
	l := newTestLink(t, ln.Addr().String())
	l.SetForward(LinkParams{Delay: delay})
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < msgs; i++ {
		size := 1 << uint(rng.Intn(17)) // 1 B .. 64 KiB
		msg := make([]byte, 12+size)
		binary.BigEndian.PutUint64(msg, uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint32(msg[8:], uint32(size))
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	var recs []rec
	select {
	case recs = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("timeout")
	}
	if len(recs) != msgs {
		t.Fatalf("received %d of %d messages", len(recs), msgs)
	}
	var ds []time.Duration
	for _, r := range recs {
		ds = append(ds, r.recv.Sub(r.sent))
	}
	min, med, p95, max := percentile(ds, 0), percentile(ds, 0.5), percentile(ds, 0.95), percentile(ds, 1)
	st := l.Stats()
	t.Logf("one-way delay %v: observed min %v median %v p95 %v max %v; proxy: %d chunks, written on average %v and at most %v after their release time",
		delay, min, med, p95, max, st.Chunks, st.LateMean, st.LateMax)
	// Never early. Lateness: the bulk must be within a few ms. Single
	// messages are sometimes 10..40 ms late (a 64 KiB write to a
	// loopback socket can take that long, also without the proxy; see
	// docs/notes/impl_testnet.md), so the bound on the maximum only
	// excludes accumulation: a proxy that sleeps per write would delay
	// the last message by msgs*delay = 3.75 s.
	if min < delay {
		t.Errorf("a message was delivered after %v, before the delay of %v", min, delay)
	}
	if med > delay+5*time.Millisecond {
		t.Errorf("median delay %v, configured %v", med, delay)
	}
	if p95 > delay+20*time.Millisecond {
		t.Errorf("p95 delay %v, configured %v", p95, delay)
	}
	if max > delay+150*time.Millisecond {
		t.Errorf("a message was delayed by %v, configured %v", max, delay)
	}
}

// TestNetemIntegrity pushes a pseudo-random stream with random write
// sizes through links with delay, jitter and a bandwidth cap, echoes it
// back and compares hashes. Run with -race.
func TestNetemIntegrity(t *testing.T) {
	total := 6 << 20
	if testing.Short() {
		total = 1 << 20
	}
	cases := []struct {
		name     string
		fwd, rev LinkParams
	}{
		{"plain", LinkParams{}, LinkParams{}},
		{"delay+jitter", LinkParams{Delay: 5 * time.Millisecond, Jitter: 4 * time.Millisecond},
			LinkParams{Delay: 2 * time.Millisecond, Jitter: 2 * time.Millisecond}},
		{"rate", LinkParams{Rate: 8 << 20, Delay: time.Millisecond}, LinkParams{Rate: 16 << 20}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLink(t, echoServer(t))
			l.SetForward(tc.fwd)
			l.SetReverse(tc.rev)
			c, err := net.Dial("tcp", l.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			rng := rand.New(rand.NewSource(42))
			sent := sha256.New()
			go func() {
				left := total
				for left > 0 {
					n := 1 + rng.Intn(100<<10)
					if rng.Intn(4) == 0 {
						n = 1 + rng.Intn(64)
					}
					if n > left {
						n = left
					}
					b := make([]byte, n)
					rng.Read(b)
					sent.Write(b)
					if _, err := c.Write(b); err != nil {
						return
					}
					left -= n
				}
				_ = c.(*net.TCPConn).CloseWrite()
			}()
			recv := sha256.New()
			_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := io.Copy(recv, c)
			if err != nil {
				t.Fatal(err)
			}
			if int(n) != total {
				t.Fatalf("received %d bytes, sent %d", n, total)
			}
			if !bytes.Equal(sent.Sum(nil), recv.Sum(nil)) {
				t.Fatal("stream corrupted")
			}
			st := l.Stats()
			if st.BytesFwd != int64(total) || st.BytesRev != int64(total) {
				t.Fatalf("stats: %+v", st)
			}
		})
	}
}

// TestNetemRate checks the bandwidth cap.
func TestNetemRate(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	l := newTestLink(t, echoServer(t))
	const rate = 1 << 20
	const total = 2 << 20
	l.SetForward(LinkParams{Rate: rate})
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	go func() {
		_, _ = c.Write(make([]byte, total))
		_ = c.(*net.TCPConn).CloseWrite()
	}()
	n, err := io.Copy(io.Discard, c)
	if err != nil || n != total {
		t.Fatal(n, err)
	}
	el := time.Since(start)
	want := time.Duration(float64(total) / rate * float64(time.Second))
	t.Logf("%d bytes at %d B/s: took %v, want about %v", total, rate, el, want)
	if el < want*9/10 || el > want*13/10 {
		t.Errorf("took %v, want about %v", el, want)
	}
}

// TestNetemBlock checks that blocking a link kills its connections,
// refuses new ones, and that the link works again after unblocking.
func TestNetemBlock(t *testing.T) {
	l := newTestLink(t, echoServer(t))
	roundTrip := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		var b [1]byte
		_, err := io.ReadFull(c, b[:])
		return err
	}
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := roundTrip(c); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	l.Block(true)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("read on a blocked link succeeded")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("endpoint noticed the block only after %v", el)
	}

	// A new connection is accepted by the kernel but reset by the proxy.
	c2, err := net.Dial("tcp", l.Addr())
	if err == nil {
		if err := roundTrip(c2); err == nil {
			t.Fatal("blocked link forwarded data")
		}
		c2.Close()
	}
	if l.Stats().Active != 0 {
		t.Fatalf("active connections on a blocked link: %+v", l.Stats())
	}

	l.Block(false)
	c3, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if err := roundTrip(c3); err != nil {
		t.Fatal("after unblock:", err)
	}
}

func TestPresets(t *testing.T) {
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if WAN5RTTms[i][j] != WAN5RTTms[j][i] {
				t.Fatalf("WAN5 matrix not symmetric at %d,%d", i, j)
			}
		}
	}
	m := WAN5(7)
	if m[0][5] != 500*time.Microsecond { // nodes 0 and 5 share a region
		t.Fatalf("same-region delay: %v", m[0][5])
	}
	if m[0][1] != 35*time.Millisecond || m[1][0] != m[0][1] {
		t.Fatalf("us-east/us-west one-way: %v", m[0][1])
	}
	if LAN(3)[0][1] != 200*time.Microsecond || Regional(3)[2][1] != 10*time.Millisecond {
		t.Fatal("uniform presets")
	}
	if m[3][3] != 0 {
		t.Fatal("diagonal")
	}
}
