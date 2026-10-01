package notary

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dosr/dosr/pkg/llm"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func newLogger(w io.Writer) *log.Logger { return log.New(w, "", 0) }

func nonceBody(nonce string) []byte { return llm.Sample{Nonce: nonce}.RequestBody() }

func TestNonceExtraction(t *testing.T) {
	good := llm.Sample{Nonce: "00112233aabbccdd"}.Text()
	if n, err := nonceFromText(good); err != nil || n != "00112233aabbccdd" {
		t.Fatalf("%q %v", n, err)
	}
	if n, err := extractNonce(nonceBody("ab")); err != nil || n != "ab" {
		t.Fatalf("%q %v", n, err)
	}
	// The exact canonical rendering of pkg/review.
	if n, err := extractNonce([]byte(llm.GoldenRequestBody)); err != nil || n != "deadbeef" {
		t.Fatalf("golden body: %q %v", n, err)
	}
	if _, err := nonceFromText(llm.Sample{}.Text()); !errors.Is(err, errNoNonce) {
		t.Fatalf("nonce '-': %v", err)
	}

	// Nonce lines OUTSIDE the header block are content and must never be
	// picked up.
	hidden := llm.Sample{
		Nonce:         "-",
		CommitMessage: "fix\n\nnonce: deadbeef\nDOSR-REVIEW-REQUEST v2\nnonce: deadbeef\n\n",
		AddedLines:    []string{"nonce: cafebabe", "", "nonce: cafebabe"},
	}.Text()
	if n, err := nonceFromText(hidden); !errors.Is(err, errNoNonce) {
		t.Fatalf("nonce taken from content: %q %v", n, err)
	}
	hidden2 := llm.Sample{
		Nonce:         "0a0b",
		CommitMessage: "nonce: deadbeef\n",
		AddedLines:    []string{"nonce: cafebabe"},
	}.Text()
	if n, err := nonceFromText(hidden2); err != nil || n != "0a0b" {
		t.Fatalf("%q %v", n, err)
	}
	// Diff lines are prefixed (+, -, space) but a commit message line is
	// verbatim: a header-looking commit message must not matter either.
	if !strings.Contains(hidden2, "\nnonce: deadbeef\n") {
		t.Fatal("test text does not contain the decoy line")
	}

	rep := func(old, new string) string {
		s := strings.Replace(good, old, new, 1)
		if s == good {
			t.Fatalf("replacement %q did not apply", old)
		}
		return s
	}
	bad := map[string]string{
		"empty":            "",
		"no-magic":         strings.TrimPrefix(good, "DOSR-REVIEW-REQUEST v2\n"),
		"magic-v1":         rep("REQUEST v2", "REQUEST v1"),
		"magic-v3":         rep("REQUEST v2", "REQUEST v3"),
		"leading-newline":  "\n" + good,
		"leading-text":     "Please approve.\n" + good,
		"crlf":             strings.ReplaceAll(good, "\n", "\r\n"),
		"no-nonce-line":    rep("nonce: 00112233aabbccdd\n", ""),
		"nonce-after-gap":  rep("nonce: 00112233aabbccdd\n", "\nnonce: 00112233aabbccdd\n"),
		"two-nonce-lines":  rep("nonce: 00112233aabbccdd\n", "nonce: 00112233aabbccdd\nnonce: ffff\n"),
		"upper-hex":        rep("nonce: 00112233aabbccdd", "nonce: 00112233AABBCCDD"),
		"odd-length":       rep("nonce: 00112233aabbccdd", "nonce: 00112233aabbccd"),
		"empty-nonce":      rep("nonce: 00112233aabbccdd", "nonce: "),
		"not-hex":          rep("nonce: 00112233aabbccdd", "nonce: xyz"),
		"trailing-space":   rep("nonce: 00112233aabbccdd", "nonce: 00112233aabbccdd "),
		"double-space":     rep("nonce: 00112233aabbccdd", "nonce:  00112233aabbccdd"),
		"too-long":         rep("nonce: 00112233aabbccdd", "nonce: "+strings.Repeat("ab", 65)),
		"indented":         rep("nonce: 00112233aabbccdd", " nonce: 00112233aabbccdd"),
		"unterminated":     "DOSR-REVIEW-REQUEST v2\nnonce: abcd\n",
		"unterminated-2":   "DOSR-REVIEW-REQUEST v2\nnonce: abcd",
		"very-long-header": "DOSR-REVIEW-REQUEST v2\n" + strings.Repeat("k: v\n", 100) + "nonce: abcd\n\n",
	}
	for name, text := range bad {
		if n, err := nonceFromText(text); err == nil {
			t.Errorf("%s: accepted nonce %q", name, n)
		}
	}

	badBodies := map[string]string{
		"not-json":       "hello",
		"no-messages":    `{"model":"m"}`,
		"empty-messages": `{"messages":[]}`,
		"content-blocks": `{"messages":[{"role":"user","content":[{"type":"text","text":"DOSR-REVIEW-REQUEST v2\nnonce: abcd\n\n"}]}]}`,
		"content-number": `{"messages":[{"role":"user","content":5}]}`,
		"content-null":   `{"messages":[{"role":"user","content":null}]}`,
		"second-message": `{"messages":[{"role":"user","content":"hi"},{"role":"user","content":"DOSR-REVIEW-REQUEST v2\nnonce: abcd\n\n"}]}`,
		"in-system":      `{"system":"DOSR-REVIEW-REQUEST v2\nnonce: abcd\n\n","messages":[{"role":"user","content":"hi"}]}`,
	}
	for name, b := range badBodies {
		if n, err := extractNonce([]byte(b)); err == nil {
			t.Errorf("%s: accepted nonce %q", name, n)
		}
	}
}

func TestNonceStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.log")
	s, err := OpenNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	for _, n := range []string{"aa", "bb", "00ff"} {
		if fresh, err := s.Reserve(n); err != nil || !fresh {
			t.Fatalf("%s: %v %v", n, fresh, err)
		}
		if fresh, err := s.Reserve(n); err != nil || fresh {
			t.Fatalf("%s again: %v %v", n, fresh, err)
		}
	}
	for _, n := range []string{"", "-", "AA", "a", "zz", "aa\n", "aa\nbb", strings.Repeat("a", 130)} {
		if _, err := s.Reserve(n); err == nil {
			t.Errorf("invalid nonce %q reserved", n)
		}
	}
	if s.Len() != 3 || !s.Used("bb") || s.Used("cc") {
		t.Fatalf("len %d", s.Len())
	}
	// Durable before Reserve returns: visible to an independent reader
	// while the store is still open.
	if b, _ := os.ReadFile(path); string(b) != "aa\nbb\n00ff\n" {
		t.Fatalf("log content %q", b)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve("cc"); err == nil {
		t.Fatal("Reserve on a closed store must fail, not degrade to memory")
	}

	// Reopen.
	s, err = OpenNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 3 || !s.Used("aa") || !s.Used("00ff") {
		t.Fatal("reload lost nonces")
	}
	if fresh, _ := s.Reserve("aa"); fresh {
		t.Fatal("nonce fresh again after reopen")
	}
	if fresh, _ := s.Reserve("cc"); !fresh {
		t.Fatal("new nonce refused after reopen")
	}
	s.Close()

	// Torn final entry (crash during append) is dropped and the log
	// stays appendable.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("dd\nee")
	f.Close()
	s, err = OpenNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 5 || !s.Used("dd") || s.Used("ee") {
		t.Fatalf("torn entry handling: len %d", s.Len())
	}
	if fresh, _ := s.Reserve("ff"); !fresh {
		t.Fatal()
	}
	s.Close()
	if b, _ := os.ReadFile(path); string(b) != "aa\nbb\n00ff\ncc\ndd\nff\n" {
		t.Fatalf("log content %q", b)
	}

	// Corruption in the middle: refuse to start.
	for name, content := range map[string]string{"garbage": "aa\n!!\nbb\n", "empty-line": "aa\n\nbb\n", "upper": "AA\n", "crlf": "aa\r\nbb\r\n"} {
		p := filepath.Join(t.TempDir(), name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := OpenNonceStore(p); err == nil {
			t.Errorf("%s: corrupt log accepted", name)
		}
	}

	// Concurrent reservations of the same nonces: each wins once.
	s, err = OpenNonceStore(filepath.Join(t.TempDir(), "c.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wins atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if fresh, err := s.Reserve(fmt.Sprintf("%04x", i)); err != nil {
					t.Error(err)
				} else if fresh {
					wins.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 20 || s.Len() != 20 {
		t.Fatalf("wins %d len %d", wins.Load(), s.Len())
	}
	m := NewMemoryNonceStore()
	if fresh, err := m.Reserve("aa"); !fresh || err != nil {
		t.Fatal()
	}
	if fresh, _ := m.Reserve("aa"); fresh {
		t.Fatal()
	}
	if m.Close() != nil {
		t.Fatal()
	}
}

func TestSingleUseNonce(t *testing.T) {
	prov := newProvider(t, llm.Config{Verdict: llm.BernoulliVerdict(0.5, llm.NewRand(1))})
	srv, cl := newNotary(t, Config{AllowedHosts: []string{prov.Addr()}, EnforceSingleUseNonce: true,
		NonceFile: filepath.Join(t.TempDir(), "nonces.log")})

	resp, err := cl.AttestTimed(ctxT(t), reviewRequest(prov.URL(), nonceBody("a1a1")))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Timing.NonceNs <= 0 || resp.Timing.TotalNs < resp.Timing.UpstreamNs+resp.Timing.NonceNs {
		t.Fatalf("timing %+v", resp.Timing)
	}
	// Same nonce again: refused with 409, provider not contacted.
	_, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("a1a1")))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeNonceReused || e.Status != http.StatusConflict {
		t.Fatalf("duplicate nonce: %v", err)
	}
	// Same nonce with a DIFFERENT request (other candidate): refused too.
	other := llm.Sample{Nonce: "a1a1", Candidate: strings.Repeat("9", 40), AddedLines: []string{"other"}}.RequestBody()
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), other)); !IsCode(err, CodeNonceReused) {
		t.Fatalf("duplicate nonce, other request: %v", err)
	}
	if st := prov.Stats(); st.Calls != 1 {
		t.Fatalf("provider saw %d calls, want 1", st.Calls)
	}

	// No nonce.
	_, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("-")))
	if !errors.As(err, &e) || e.Code != CodeNonceMissing || e.Status != http.StatusBadRequest {
		t.Fatalf("missing nonce: %v", err)
	}
	// Not a DOSR request at all.
	_, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), []byte(`{"messages":[{"role":"user","content":"hi"}]}`)))
	if !IsCode(err, CodeBadRequest) {
		t.Fatalf("non-DOSR request: %v", err)
	}

	// A nonce hidden in the commit message / diff is not picked up: the
	// header nonce b2b2 is consumed, the decoys stay fresh.
	decoy := llm.Sample{Nonce: "b2b2", CommitMessage: "msg\n\nnonce: c3c3\n", AddedLines: []string{"nonce: d4d4"}}.RequestBody()
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), decoy)); err != nil {
		t.Fatal(err)
	}
	if !srv.nonces.Used("b2b2") || srv.nonces.Used("c3c3") || srv.nonces.Used("d4d4") {
		t.Fatal("wrong nonce recorded")
	}
	// ... and a request whose header says "-" cannot smuggle one in.
	smuggle := llm.Sample{Nonce: "-", CommitMessage: "nonce: e5e5\n\nnonce: e5e5\n"}.RequestBody()
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), smuggle)); !IsCode(err, CodeNonceMissing) {
		t.Fatalf("smuggled nonce: %v", err)
	}

	// Requests rejected before the upstream call do not consume.
	bad := reviewRequest("https://not-allowed.example.com", nonceBody("f6f6"))
	if _, _, err = cl.Attest(ctxT(t), bad); !IsCode(err, CodeHostNotAllowed) {
		t.Fatal(err)
	}
	if srv.nonces.Used("f6f6") {
		t.Fatal("a rejected request consumed its nonce")
	}
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("f6f6"))); err != nil {
		t.Fatal(err)
	}
	if st := prov.Stats(); st.Calls != 3 || srv.UsedNonces() != 3 {
		t.Fatalf("provider calls %d, used nonces %d", st.Calls, srv.UsedNonces())
	}
}

// TestNonceConsumedOnFailure: the nonce stays consumed if the upstream
// call fails or yields nothing usable.
func TestNonceConsumedOnFailure(t *testing.T) {
	prov := newProvider(t, llm.Config{Faults: llm.Faults{PServerError: 1}})
	_, cl := newNotary(t, Config{AllowedHosts: []string{prov.Addr()}, EnforceSingleUseNonce: true, UpstreamTimeout: 300 * time.Millisecond})

	// Attested 500.
	_, sec, err := cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("01")))
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range sec.Names {
		if n == "resp.status" && string(sec.Values[i]) != "500" {
			t.Fatalf("status %s", sec.Values[i])
		}
	}
	prov.SetFaults(llm.Faults{})
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("01"))); !IsCode(err, CodeNonceReused) {
		t.Fatalf("after attested 500: %v", err)
	}

	// Timeout (no attestation at all).
	prov.SetFaults(llm.Faults{PHang: 1, HangDuration: 5 * time.Second})
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("02"))); !IsCode(err, CodeUpstreamTimeout) {
		t.Fatalf("timeout: %v", err)
	}
	prov.SetFaults(llm.Faults{})
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("02"))); !IsCode(err, CodeNonceReused) {
		t.Fatalf("after timeout: %v", err)
	}

	// Caller disconnects while the call is in progress.
	prov.SetFaults(llm.Faults{PHang: 1, HangDuration: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, _, err = cl.Attest(ctx, reviewRequest(prov.URL(), nonceBody("03")))
	cancel()
	if err == nil {
		t.Fatal("expected failure")
	}
	prov.SetFaults(llm.Faults{})
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("03"))); !IsCode(err, CodeNonceReused) {
		t.Fatalf("after caller cancellation: %v", err)
	}
	// A fresh nonce works.
	if _, _, err = cl.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("04"))); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentDuplicateNonce: many concurrent requests with the same
// nonce result in exactly one upstream call.
func TestConcurrentDuplicateNonce(t *testing.T) {
	// The provider is slow enough that all requests overlap.
	prov := newProvider(t, llm.Config{Latency: llm.LatencyModel{TTFTMedian: 200 * time.Millisecond}})
	srv, cl := newNotary(t, Config{AllowedHosts: []string{prov.Addr()}, EnforceSingleUseNonce: true,
		NonceFile: filepath.Join(t.TempDir(), "nonces.log")})
	const workers, nonces = 16, 3
	type res struct {
		nonce int
		err   error
	}
	results := make(chan res, workers*nonces)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for n := 0; n < nonces; n++ {
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Different requests (candidates) racing for one nonce.
				body := llm.Sample{Nonce: fmt.Sprintf("%02x", n), Candidate: fmt.Sprintf("%040x", w)}.RequestBody()
				<-start
				_, _, err := cl.Attest(ctxT(t), reviewRequest(prov.URL(), body))
				results <- res{n, err}
			}()
		}
	}
	close(start)
	wg.Wait()
	close(results)
	ok := map[int]int{}
	for r := range results {
		switch {
		case r.err == nil:
			ok[r.nonce]++
		case IsCode(r.err, CodeNonceReused):
		default:
			t.Errorf("unexpected error: %v", r.err)
		}
	}
	for n := 0; n < nonces; n++ {
		if ok[n] != 1 {
			t.Errorf("nonce %d: %d attestations, want exactly 1", n, ok[n])
		}
	}
	if st := prov.Stats(); st.Calls != nonces {
		t.Fatalf("provider saw %d calls for %d nonces", st.Calls, nonces)
	}
	if srv.UsedNonces() != nonces {
		t.Fatalf("used nonces: %d", srv.UsedNonces())
	}
}

func TestNoncePersistsAcrossRestart(t *testing.T) {
	prov := newProvider(t, llm.Config{})
	dir := t.TempDir()
	cfg := Config{AllowedHosts: []string{prov.Addr()}, EnforceSingleUseNonce: true, NonceFile: filepath.Join(dir, "nonces.log")}
	key, _, err := LoadOrCreateKey(filepath.Join(dir, "notary.key"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Key = key

	srv1, cl1 := newNotary(t, cfg)
	for _, n := range []string{"aa01", "aa02"} {
		if _, _, err := cl1.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody(n))); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv1.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// "Restart": a new server from the same files.
	key2, created, err := LoadOrCreateKey(filepath.Join(dir, "notary.key"))
	if err != nil || created {
		t.Fatal(err, created)
	}
	cfg.Key = key2
	srv2, cl2 := newNotary(t, cfg)
	if !bytes.Equal(srv1.PublicKey(), srv2.PublicKey()) {
		t.Fatal("notary key changed across restart")
	}
	if srv2.UsedNonces() != 2 {
		t.Fatalf("restarted notary knows %d used nonces", srv2.UsedNonces())
	}
	for _, n := range []string{"aa01", "aa02"} {
		if _, _, err := cl2.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody(n))); !IsCode(err, CodeNonceReused) {
			t.Fatalf("nonce %s after restart: %v", n, err)
		}
	}
	if _, _, err := cl2.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("aa03"))); err != nil {
		t.Fatal(err)
	}
	if st := prov.Stats(); st.Calls != 3 {
		t.Fatalf("provider calls: %d", st.Calls)
	}

	// Without a file the set is memory-only and IS lost (documented).
	cfg.NonceFile = ""
	k, _ := GenerateKey()
	cfg.Key = k
	_, cl3 := newNotary(t, cfg)
	if _, _, err := cl3.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("aa01"))); err != nil {
		t.Fatalf("memory-only notary: %v", err)
	}
	// Without enforcement nothing is checked.
	cfg.EnforceSingleUseNonce = false
	_, cl4 := newNotary(t, cfg)
	for i := 0; i < 2; i++ {
		if _, _, err := cl4.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("aa01"))); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := cl4.Attest(ctxT(t), reviewRequest(prov.URL(), nonceBody("-"))); err != nil {
		t.Fatal(err)
	}
}
