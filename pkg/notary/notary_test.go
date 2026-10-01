package notary

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/llm"
)

const apiKey = "sk-ant-api03-SUPER-SECRET-KEY-DO-NOT-LEAK-0123456789abcdef"

// pki is shared by all tests of the package (key generation is slow
// under -race).
var pki = sync.OnceValue(func() struct {
	ca   *llm.CA
	cert tls.Certificate
} {
	ca, cert, err := llm.NewLocalhostTLS()
	if err != nil {
		panic(err)
	}
	return struct {
		ca   *llm.CA
		cert tls.Certificate
	}{ca, cert}
})

// upstream starts an HTTPS server with the private CA's certificate.
func upstream(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{pki().cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func hostOf(t testing.TB, rawURL string) string {
	t.Helper()
	return strings.TrimPrefix(rawURL, "https://")
}

// newNotary starts a notary (plain HTTP on localhost) and returns it
// with a client.
func newNotary(t testing.TB, cfg Config) (*Server, *Client) {
	t.Helper()
	if cfg.Key == nil {
		k, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Key = k
	}
	if cfg.RootCAs == nil {
		cfg.RootCAs = pki().ca.Pool()
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	c := NewClient(s.URL())
	c.NotaryKey = s.PublicKey()
	return s, c
}

func newProvider(t testing.TB, cfg llm.Config) *llm.Server {
	t.Helper()
	cert := pki().cert
	cfg.Certificate = &cert
	if cfg.APIKeys == nil {
		cfg.APIKeys = []string{apiKey}
	}
	p, err := llm.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	return p
}

func reviewRequest(baseURL string, body []byte) *Request {
	return &Request{
		URL:    baseURL + llm.MessagesPath,
		Method: "POST",
		Headers: map[string]string{
			"X-Api-Key":         apiKey,
			"Anthropic-Version": "2023-06-01",
			"Content-Type":      "application/json",
		},
		Body: body,
	}
}

func ctxT(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// secretEncodings returns the forms in which secret could show up in
// JSON: raw, hex and base64 at any alignment.
func secretEncodings(secret []byte) [][]byte {
	out := [][]byte{secret, []byte(hex.EncodeToString(secret))}
	for shift := 0; shift < 3; shift++ {
		padded := append(make([]byte, shift), secret...)
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			e := enc.EncodeToString(padded)
			start, end := (shift*8+5)/6, len(e)-2
			if start < end {
				out = append(out, []byte(e[start:end]))
			}
		}
	}
	return out
}

func assertNoSecret(t *testing.T, what string, data, secret []byte) {
	t.Helper()
	for _, n := range secretEncodings(secret) {
		if bytes.Contains(data, n) {
			t.Fatalf("%s contains the secret (as %q)", what, n)
		}
	}
}

// ------------------------------------------------------------ end to end

func TestEndToEndWithMockProvider(t *testing.T) {
	prov := newProvider(t, llm.Config{})
	var logBuf syncBuffer
	fixed := time.Unix(1790000000, 0)
	srv, cl := newNotary(t, Config{
		AllowedHosts: []string{prov.Addr()},
		Now:          func() time.Time { return fixed },
		Logger:       newLogger(&logBuf),
	})
	body := llm.Sample{Candidate: strings.Repeat("c", 40)}.RequestBody()
	req := reviewRequest(prov.URL(), body)

	resp, err := cl.AttestTimed(ctxT(t), req)
	if err != nil {
		t.Fatal(err)
	}
	att, sec := resp.Attestation, resp.Secret

	// Header.
	wantSPKI, _ := llm.SPKIHash(pki().cert)
	h := att.Header
	if h.ServerName != "127.0.0.1" || !bytes.Equal(h.ServerSPKI, wantSPKI) || h.Time != fixed.Unix() ||
		!bytes.Equal(h.NotaryKey, srv.PublicKey()) || int(h.LeafCount) != len(sec.Names) {
		t.Fatalf("header: %+v", h)
	}

	// Timing.
	tm := resp.Timing
	if tm.UpstreamNs <= 0 || tm.AttestNs <= 0 || tm.ConnectNs <= 0 || tm.ConnectNs > tm.UpstreamNs ||
		tm.TotalNs < tm.UpstreamNs+tm.AttestNs || tm.NonceNs != 0 {
		t.Fatalf("timing: %+v", tm)
	}

	// Presentation with DOSR's disclosure policy.
	p, err := BuildPresentation(att, sec)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, "presentation", enc, []byte(apiKey))
	assertNoSecret(t, "presentation", enc, body)

	dec, err := attest.DecodePresentation(enc)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []ed25519.PublicKey{srv.PublicKey()}
	tr, err := attest.ProxyVerifier{}.Verify(dec, trusted, map[string][]byte{attest.FieldReqBody: body})
	if err != nil {
		t.Fatal(err)
	}
	wantFields := map[string]string{
		"req.method":                   "POST",
		"req.path":                     "/v1/messages",
		"req.header.accept-encoding":   "identity",
		"req.header.anthropic-version": "2023-06-01",
		"req.header.connection":        "close",
		"req.header.content-length":    strconv.Itoa(len(body)),
		"req.header.content-type":      "application/json",
		"req.header.host":              prov.Addr(),
		"req.body":                     string(body),
		"resp.status":                  "200",
		"resp.header.content-type":     "application/json",
	}
	for n, v := range wantFields {
		if got, ok := tr.Fields[n]; !ok || string(got) != v {
			t.Errorf("field %s = %q (%v), want %q", n, got, ok, v)
		}
	}
	if fmt.Sprint(tr.HiddenNames) != "[req.header.x-api-key]" {
		t.Errorf("hidden: %v", tr.HiddenNames)
	}
	// Order: method, path, sorted request headers, body, status, sorted
	// response headers, body.
	wantOrder := []string{"req.method", "req.path", "req.header.accept-encoding", "req.header.anthropic-version",
		"req.header.connection", "req.header.content-length", "req.header.content-type", "req.header.host",
		"req.header.x-api-key", "req.body", "resp.status"}
	if len(tr.Names) < len(wantOrder)+2 || fmt.Sprint(tr.Names[:len(wantOrder)]) != fmt.Sprint(wantOrder) ||
		tr.Names[len(tr.Names)-1] != "resp.body" {
		t.Fatalf("order: %v", tr.Names)
	}
	rh := tr.Names[len(wantOrder) : len(tr.Names)-1]
	for i, n := range rh {
		if !strings.HasPrefix(n, "resp.header.") || (i > 0 && rh[i-1] >= n) {
			t.Fatalf("response headers not sorted: %v", rh)
		}
		switch strings.TrimPrefix(n, "resp.header.") {
		case "content-length", "transfer-encoding", "connection":
			t.Fatalf("framing header %s attested", n)
		}
	}
	if _, ok := tr.Fields["resp.header.date"]; !ok {
		t.Error("date header missing from transcript")
	}

	// The response body is the provider's verdict.
	var msg struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string
			Input struct{ Verdict, Candidate string }
		}
	}
	if err := json.Unmarshal(tr.Fields["resp.body"], &msg); err != nil {
		t.Fatal(err)
	}
	last := msg.Content[len(msg.Content)-1]
	if msg.StopReason != "tool_use" || last.Type != "tool_use" || last.Input.Verdict != "approve" ||
		last.Input.Candidate != strings.Repeat("c", 40) {
		t.Fatalf("verdict: %s", tr.Fields["resp.body"])
	}
	if st := prov.Stats(); st.Calls != 1 || st.Approved != 1 {
		t.Fatalf("provider stats: %+v", st)
	}

	// A wrong body does not verify; neither does a wrong notary.
	if _, err := (attest.ProxyVerifier{}).Verify(dec, trusted, map[string][]byte{attest.FieldReqBody: append(body, ' ')}); !errors.Is(err, attest.ErrRootMismatch) {
		t.Errorf("wrong body: %v", err)
	}
	other, _ := GenerateKey()
	if _, err := (attest.ProxyVerifier{}).Verify(dec, []ed25519.PublicKey{other.Public().(ed25519.PublicKey)}, map[string][]byte{attest.FieldReqBody: body}); !errors.Is(err, attest.ErrUntrustedNotary) {
		t.Errorf("wrong notary: %v", err)
	}

	// An invalid API key is an attested 401, not a notary error.
	req.Headers["X-Api-Key"] = "sk-wrong-key-0000000000000000"
	att2, sec2, err := cl.Attest(ctxT(t), req)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := BuildPresentation(att2, sec2)
	tr2, err := attest.ProxyVerifier{}.Verify(p2, trusted, map[string][]byte{attest.FieldReqBody: body})
	if err != nil || string(tr2.Fields["resp.status"]) != "401" {
		t.Fatalf("401 case: %v %q", err, tr2.Fields["resp.status"])
	}
	assertNoSecret(t, "notary log", logBuf.Bytes(), []byte(apiKey))
}

func TestTimingHeadersAndRawAPI(t *testing.T) {
	prov := newProvider(t, llm.Config{Latency: llm.LatencyModel{TTFTMedian: 150 * time.Millisecond}})
	srv, _ := newNotary(t, Config{AllowedHosts: []string{prov.Addr()}})
	body, _ := json.Marshal(reviewRequest(prov.URL(), llm.Sample{}.RequestBody()))
	resp, err := http.Post(srv.URL()+AttestPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	var r Response
	if err := decodeStrict(raw, &r); err != nil {
		t.Fatal(err)
	}
	up, _ := strconv.ParseInt(resp.Header.Get(HeaderUpstreamNs), 10, 64)
	at, _ := strconv.ParseInt(resp.Header.Get(HeaderAttestNs), 10, 64)
	tot, _ := strconv.ParseInt(resp.Header.Get(HeaderTotalNs), 10, 64)
	if up != r.Timing.UpstreamNs || at != r.Timing.AttestNs || tot != r.Timing.TotalNs {
		t.Fatalf("headers %d %d %d vs body %+v", up, at, tot, r.Timing)
	}
	if time.Duration(up) < 150*time.Millisecond {
		t.Fatalf("upstream time %v does not include the provider latency", time.Duration(up))
	}
	if time.Duration(at) > 50*time.Millisecond {
		t.Fatalf("attestation overhead %v is implausibly large", time.Duration(at))
	}
	if !strings.Contains(resp.Header.Get("Server-Timing"), "upstream;dur=") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", resp.Header)
	}

	// Malformed attest requests.
	for name, in := range map[string]string{
		"not-json":      "hello",
		"unknown-field": `{"url":"https://x/","method":"POST","extra":1}`,
		"trailing":      string(body) + "{}",
		"bad-base64":    `{"url":"https://x/","method":"POST","body":"!!!"}`,
		"array":         `[]`,
	} {
		resp, err := http.Post(srv.URL()+AttestPath, "application/json", strings.NewReader(in))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var er struct{ Error Error }
		if resp.StatusCode != 400 || json.Unmarshal(b, &er) != nil || er.Error.Code != CodeBadRequest {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{{"GET", AttestPath, 405}, {"POST", InfoPath, 405}, {"GET", "/", 404}, {"GET", "/v1/other", 404}} {
		req, _ := http.NewRequest(c.method, srv.URL()+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestInfo(t *testing.T) {
	srv, cl := newNotary(t, Config{AllowedHosts: []string{"API.Example.com:443", "b.example.com:8443", "a.example.com"},
		EnforceSingleUseNonce: true, UpstreamTimeout: 7 * time.Second})
	in, err := cl.Info(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in.NotaryKey, srv.PublicKey()) || in.Version != attest.Version ||
		fmt.Sprint(in.AllowedHosts) != "[a.example.com api.example.com b.example.com:8443]" ||
		fmt.Sprint(in.AllowedMethods) != "[POST]" || !in.EnforceSingleUseNonce || in.UpstreamTimeoutMs != 7000 ||
		in.MaxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("info: %+v", in)
	}
}

// --------------------------------------------------- wire == transcript

// TestWireRequestMatchesTranscript records the exact bytes the notary
// sends and checks that the transcript describes them completely.
func TestWireRequestMatchesTranscript(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pki().cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	body := []byte(`{"hello":"world"}`)
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		var buf bytes.Buffer
		tmp := make([]byte, 4096)
		for !bytes.HasSuffix(buf.Bytes(), body) {
			n, err := c.Read(tmp)
			buf.Write(tmp[:n])
			if err != nil {
				break
			}
		}
		got <- buf.Bytes()
		io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Multi: a\r\nContent-Length: 2\r\nx-multi: b, c\r\nKeep-Alive: timeout=5\r\n"+
			"Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nX-Empty:\r\nX-MULTI: d\r\n\r\nok")
	}()
	_, cl := newNotary(t, Config{AllowedHosts: []string{ln.Addr().String()}})
	att, sec, err := cl.Attest(ctxT(t), &Request{
		URL:     "https://" + ln.Addr().String() + "/a%20b/c?x=1&y=%2F",
		Method:  "post",
		Headers: map[string]string{"X-Api-Key": apiKey, "X-Custom": "v w", "Accept-Encoding": "identity"},
		Body:    body,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := <-got
	want := "POST /a%20b/c?x=1&y=%2F HTTP/1.1\r\n" +
		"accept-encoding: identity\r\n" +
		"connection: close\r\n" +
		"content-length: 17\r\n" +
		"host: " + ln.Addr().String() + "\r\n" +
		"x-api-key: " + apiKey + "\r\n" +
		"x-custom: v w\r\n" +
		"\r\n" + string(body)
	if string(wire) != want {
		t.Fatalf("wire request:\n%q\nwant\n%q", wire, want)
	}
	// Rebuild the wire request from the transcript alone.
	var rebuilt strings.Builder
	f := map[string]string{}
	for i, n := range sec.Names {
		f[n] = string(sec.Values[i])
	}
	rebuilt.WriteString(f["req.method"] + " " + f["req.path"] + " HTTP/1.1\r\n")
	for _, n := range sec.Names {
		if h, ok := strings.CutPrefix(n, "req.header."); ok {
			rebuilt.WriteString(h + ": " + f[n] + "\r\n")
		}
	}
	rebuilt.WriteString("\r\n" + f["req.body"])
	if rebuilt.String() != want {
		t.Fatalf("transcript does not describe the wire request:\n%q", rebuilt.String())
	}
	// Response side: multi-valued header joined in order, hop-by-hop
	// headers and those named by Connection dropped.
	var resp []string
	for _, n := range sec.Names {
		if strings.HasPrefix(n, "resp.") {
			resp = append(resp, n+"="+f[n])
		}
	}
	wantResp := "[resp.status=200 resp.header.x-empty= resp.header.x-multi=a, b, c, d resp.body=ok]"
	if fmt.Sprint(resp) != wantResp {
		t.Fatalf("response fields %v\nwant %s", resp, wantResp)
	}
	if att.Header.LeafCount != uint32(len(sec.Names)) {
		t.Fatal("leaf count")
	}
}

// ----------------------------------------------------- request checking

func TestRequestValidation(t *testing.T) {
	var hits atomic.Int64
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "ok")
	}))
	host := hostOf(t, ts.URL)
	_, port, _ := net.SplitHostPort(host)
	_, cl := newNotary(t, Config{AllowedHosts: []string{host}, AllowedMethods: []string{"POST", "GET"}, MaxRequestBytes: 1000})
	good := func() *Request {
		return &Request{URL: ts.URL + "/p", Method: "POST", Headers: map[string]string{"x-api-key": apiKey}, Body: []byte("{}")}
	}
	if _, _, err := cl.Attest(ctxT(t), good()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "GET"}); err != nil {
		t.Fatalf("GET without path: %v", err)
	}
	if _, _, err := cl.Attest(ctxT(t), &Request{URL: "HTTPS://LOCALHOST:" + port + "/", Method: "GET"}); !IsCode(err, CodeHostNotAllowed) {
		t.Fatalf("localhost is not on the allow-list (only 127.0.0.1 is): %v", err)
	}
	before := hits.Load()

	cases := map[string]struct {
		mut  func(r *Request)
		code string
	}{
		"http-scheme":         {func(r *Request) { r.URL = "http://" + host + "/p" }, CodeBadRequest},
		"no-scheme":           {func(r *Request) { r.URL = host + "/p" }, CodeBadRequest},
		"file-scheme":         {func(r *Request) { r.URL = "file:///etc/passwd" }, CodeBadRequest},
		"empty-url":           {func(r *Request) { r.URL = "" }, CodeBadRequest},
		"other-host":          {func(r *Request) { r.URL = "https://example.com/p" }, CodeHostNotAllowed},
		"other-port":          {func(r *Request) { r.URL = "https://127.0.0.1:1/p" }, CodeHostNotAllowed},
		"default-port":        {func(r *Request) { r.URL = "https://127.0.0.1/p" }, CodeHostNotAllowed},
		"userinfo-confusion":  {func(r *Request) { r.URL = "https://" + host + "@example.com/p" }, CodeBadRequest},
		"userinfo":            {func(r *Request) { r.URL = "https://user:pw@" + host + "/p" }, CodeBadRequest},
		"fragment":            {func(r *Request) { r.URL = ts.URL + "/p#frag" }, CodeBadRequest},
		"empty-fragment":      {func(r *Request) { r.URL = ts.URL + "/p#" }, CodeBadRequest},
		"ipv6":                {func(r *Request) { r.URL = "https://[::1]:" + port + "/p" }, CodeBadRequest},
		"host-suffix":         {func(r *Request) { r.URL = "https://" + host + ".example.com/p" }, CodeBadRequest},
		"host-trailing-dot":   {func(r *Request) { r.URL = "https://127.0.0.1.:" + port + "/p" }, CodeBadRequest},
		"port-zero-padded":    {func(r *Request) { r.URL = "https://127.0.0.1:0" + port + "/p" }, CodeBadRequest},
		"space-in-path":       {func(r *Request) { r.URL = ts.URL + "/a b\r\nX: y" }, CodeBadRequest},
		"method-put":          {func(r *Request) { r.Method = "PUT" }, CodeBadRequest},
		"method-connect":      {func(r *Request) { r.Method = "CONNECT" }, CodeBadRequest},
		"method-empty":        {func(r *Request) { r.Method = "" }, CodeBadRequest},
		"method-injection":    {func(r *Request) { r.Method = "POST / HTTP/1.1\r\nX: y\r\n\r\nGET" }, CodeBadRequest},
		"get-with-body":       {func(r *Request) { r.Method = "GET" }, CodeBadRequest},
		"body-too-large":      {func(r *Request) { r.Body = make([]byte, 1001) }, CodeRequestTooLarge},
		"header-crlf-value":   {func(r *Request) { r.Headers["x-a"] = "1\r\nx-evil: 2" }, CodeBadRequest},
		"header-lf-value":     {func(r *Request) { r.Headers["x-a"] = "1\nx-evil: 2" }, CodeBadRequest},
		"header-nul-value":    {func(r *Request) { r.Headers["x-a"] = "1\x002" }, CodeBadRequest},
		"header-lead-space":   {func(r *Request) { r.Headers["x-a"] = " 1" }, CodeBadRequest},
		"header-bad-name":     {func(r *Request) { r.Headers["x a"] = "1" }, CodeBadRequest},
		"header-colon-name":   {func(r *Request) { r.Headers["x-a: 1\r\nx-b"] = "1" }, CodeBadRequest},
		"header-empty-name":   {func(r *Request) { r.Headers[""] = "1" }, CodeBadRequest},
		"header-dup-case":     {func(r *Request) { r.Headers["X-API-KEY"] = "other" }, CodeBadRequest},
		"override-host":       {func(r *Request) { r.Headers["Host"] = "example.com" }, CodeBadRequest},
		"override-encoding":   {func(r *Request) { r.Headers["Accept-Encoding"] = "gzip" }, CodeBadRequest},
		"override-length":     {func(r *Request) { r.Headers["Content-Length"] = "1" }, CodeBadRequest},
		"override-connection": {func(r *Request) { r.Headers["Connection"] = "keep-alive" }, CodeBadRequest},
		"transfer-encoding":   {func(r *Request) { r.Headers["Transfer-Encoding"] = "chunked" }, CodeBadRequest},
		"expect":              {func(r *Request) { r.Headers["Expect"] = "100-continue" }, CodeBadRequest},
		"upgrade":             {func(r *Request) { r.Headers["Upgrade"] = "websocket" }, CodeBadRequest},
		"proxy-authorization": {func(r *Request) { r.Headers["Proxy-Authorization"] = "x" }, CodeBadRequest},
		"te":                  {func(r *Request) { r.Headers["TE"] = "trailers" }, CodeBadRequest},
	}
	for name, c := range cases {
		r := good()
		c.mut(r)
		_, _, err := cl.Attest(ctxT(t), r)
		if !IsCode(err, c.code) {
			t.Errorf("%s: got %v, want code %s", name, err, c.code)
			continue
		}
		if strings.Contains(err.Error(), apiKey) {
			t.Errorf("%s: error message contains the API key", name)
		}
	}
	if hits.Load() != before {
		t.Fatalf("rejected requests reached the upstream server (%d)", hits.Load()-before)
	}
	// Redundant but equal notary headers are accepted.
	r := good()
	r.Headers["Host"] = host
	r.Headers["Content-Length"] = "2"
	r.Headers["Connection"] = "close"
	if _, _, err := cl.Attest(ctxT(t), r); err != nil {
		t.Fatalf("equal notary headers: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	k, _ := GenerateKey()
	for name, c := range map[string]Config{
		"no-key":     {AllowedHosts: []string{"a.example"}},
		"short-key":  {Key: k[:10], AllowedHosts: []string{"a.example"}},
		"no-hosts":   {Key: k},
		"bad-host":   {Key: k, AllowedHosts: []string{"https://a.example/"}},
		"bad-host-2": {Key: k, AllowedHosts: []string{"a.example:99999"}},
		"wildcard":   {Key: k, AllowedHosts: []string{"*.example.com"}},
		"bad-method": {Key: k, AllowedHosts: []string{"a.example"}, AllowedMethods: []string{"CONNECT"}},
		"huge-limit": {Key: k, AllowedHosts: []string{"a.example"}, MaxResponseBytes: 1 << 40},
		"bad-nonces": {Key: k, AllowedHosts: []string{"a.example"}, EnforceSingleUseNonce: true, NonceFile: filepath.Join(t.TempDir(), "no", "such", "dir", "f")},
	} {
		if _, err := NewServer(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for in, want := range map[string]string{"Example.COM": "example.com", "example.com:443": "example.com",
		"example.com:8443": "example.com:8443", "127.0.0.1:443": "127.0.0.1"} {
		if got, err := CanonicalHost(in); err != nil || got != want {
			t.Errorf("CanonicalHost(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "a b", "[::1]:443", "example.com:0", "example.com:65536", "example.com:0443", "-a.example", "a.example/", "user@a.example"} {
		if got, err := CanonicalHost(in); err == nil {
			t.Errorf("CanonicalHost(%q) = %q", in, got)
		}
	}
}

// ------------------------------------------------------- upstream faults

func TestOversizeResponse(t *testing.T) {
	const limit = 10000
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if r.URL.Query().Get("chunked") != "" {
			fl := w.(http.Flusher)
			for sent := 0; sent < n; {
				c := min(1000, n-sent)
				w.Write(bytes.Repeat([]byte("x"), c))
				fl.Flush()
				sent += c
			}
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Write(bytes.Repeat([]byte("x"), n))
	}))
	_, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}, MaxResponseBytes: limit, AllowedMethods: []string{"GET"}})
	for _, mode := range []string{"", "&chunked=1"} {
		for _, c := range []struct {
			n  int
			ok bool
		}{{0, true}, {limit - 1, true}, {limit, true}, {limit + 1, false}, {50 * limit, false}, {2000 * limit, false}} {
			att, sec, err := cl.Attest(ctxT(t), &Request{URL: fmt.Sprintf("%s/?n=%d%s", ts.URL, c.n, mode), Method: "GET"})
			if c.ok {
				if err != nil {
					t.Fatalf("n=%d%s: %v", c.n, mode, err)
				}
				if got := len(sec.Values[len(sec.Values)-1]); got != c.n || att == nil {
					t.Fatalf("n=%d%s: attested body of %d bytes", c.n, mode, got)
				}
				continue
			}
			if !IsCode(err, CodeResponseTooLarge) {
				t.Fatalf("n=%d%s: got %v, want %s", c.n, mode, err, CodeResponseTooLarge)
			}
			var e *Error
			if errors.As(err, &e); e.Status != http.StatusBadGateway {
				t.Fatalf("status %d", e.Status)
			}
		}
	}
}

func TestOversizeResponseHeader(t *testing.T) {
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 300; i++ {
			w.Header().Set(fmt.Sprintf("X-H-%d", i), "v")
		}
		io.WriteString(w, "ok")
	}))
	_, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}})
	_, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST"})
	if !IsCode(err, CodeUpstreamProtocol) {
		t.Fatalf("more than MaxLeaves fields: %v", err)
	}
}

func TestUpstreamTimeout(t *testing.T) {
	release := make(chan struct{})
	var cancelled atomic.Int64
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http notices a closed connection only once the request
		// body has been consumed.
		io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/slow-header":
		case "/slow-body":
			w.Header().Set("Content-Length", "10")
			w.Write([]byte("12345"))
			w.(http.Flusher).Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
			cancelled.Add(1)
		}
	}))
	defer close(release)
	_, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}, UpstreamTimeout: 300 * time.Millisecond})
	for _, p := range []string{"/slow-header", "/slow-body"} {
		start := time.Now()
		_, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL + p, Method: "POST", Body: []byte("x")})
		el := time.Since(start)
		if !IsCode(err, CodeUpstreamTimeout) {
			t.Fatalf("%s: got %v", p, err)
		}
		var e *Error
		if errors.As(err, &e); e.Status != http.StatusGatewayTimeout {
			t.Fatalf("status %d", e.Status)
		}
		if el < 300*time.Millisecond || el > 3*time.Second {
			t.Fatalf("%s: timed out after %v", p, el)
		}
	}
	// The notary closed its connections: the upstream handlers see the
	// cancellation.
	deadline := time.Now().Add(5 * time.Second)
	for cancelled.Load() != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("upstream connections were not closed (%d)", cancelled.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUpstreamHangingHandshakeAndUnreachable(t *testing.T) {
	// A TCP listener that never speaks TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	// A port nobody listens on.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()

	_, cl := newNotary(t, Config{AllowedHosts: []string{ln.Addr().String(), deadAddr}, UpstreamTimeout: 300 * time.Millisecond})
	_, _, err = cl.Attest(ctxT(t), &Request{URL: "https://" + ln.Addr().String() + "/", Method: "POST"})
	if !IsCode(err, CodeUpstreamTimeout) {
		t.Fatalf("hanging handshake: %v", err)
	}
	_, _, err = cl.Attest(ctxT(t), &Request{URL: "https://" + deadAddr + "/", Method: "POST"})
	if !IsCode(err, CodeUpstreamUnreachable) {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestCallerCancellationAbortsUpstream(t *testing.T) {
	started := make(chan struct{}, 1)
	done := make(chan struct{})
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
		close(done)
	}))
	_, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}, UpstreamTimeout: time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, _, err := cl.Attest(ctx, &Request{URL: ts.URL, Method: "POST"})
		errc <- err
	}()
	<-started
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream call was not aborted when the caller went away")
	}
}

func TestUntrustedUpstreamCertificate(t *testing.T) {
	var hits atomic.Int64
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	host := hostOf(t, ts.URL)
	_, port, _ := net.SplitHostPort(host)

	otherCA, err := llm.NewCA("some other CA")
	if err != nil {
		t.Fatal(err)
	}
	// Certificate for a different name, issued by the trusted CA.
	wrongName, err := pki().ca.Issue("other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tsWrong := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	tsWrong.TLS = &tls.Config{Certificates: []tls.Certificate{wrongName}}
	tsWrong.StartTLS()
	defer tsWrong.Close()
	// httptest's built-in self-signed certificate.
	tsSelf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer tsSelf.Close()

	cases := map[string]struct {
		roots *x509.CertPool
		url   string
	}{
		"other-ca":        {otherCA.Pool(), ts.URL},
		"empty-pool":      {x509.NewCertPool(), ts.URL},
		"self-signed":     {pki().ca.Pool(), tsSelf.URL},
		"wrong-name":      {pki().ca.Pool(), tsWrong.URL},
		"name-not-in-san": {pki().ca.Pool(), "https://evil.example.com:" + port},
	}
	for name, c := range cases {
		cfg := Config{AllowedHosts: []string{hostOf(t, c.url)}, RootCAs: c.roots,
			// Everything resolves to the test servers.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(addr)
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+p)
			}}
		_, cl := newNotary(t, cfg)
		_, _, err := cl.Attest(ctxT(t), &Request{URL: c.url, Method: "POST", Headers: map[string]string{"x-api-key": apiKey}, Body: []byte("{}")})
		if !IsCode(err, CodeUpstreamTLS) {
			t.Errorf("%s: got %v, want %s", name, err, CodeUpstreamTLS)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a request (with the API key) was sent to a server with an untrusted certificate")
	}
	// Control: DNS name "localhost" is in the certificate.
	_, cl := newNotary(t, Config{AllowedHosts: []string{"localhost:" + port}})
	att, _, err := cl.Attest(ctxT(t), &Request{URL: "https://localhost:" + port, Method: "POST"})
	if err != nil || att.Header.ServerName != "localhost" || hits.Load() != 1 {
		t.Fatalf("control: %v", err)
	}
}

func TestChunkedResponse(t *testing.T) {
	parts := []string{`{"id":"msg_1",`, `"content":"`, strings.Repeat("z", 5000), `"}`}
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Trailer", "X-Checksum")
		fl := w.(http.Flusher)
		for _, p := range parts {
			io.WriteString(w, p)
			fl.Flush()
			time.Sleep(5 * time.Millisecond)
		}
		w.Header().Set("X-Checksum", "abc")
	}))
	// Make sure the server really uses chunked encoding.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki().ca.Pool()}}}
	probe, err := hc.Post(ts.URL, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, probe.Body)
	probe.Body.Close()
	hc.CloseIdleConnections()
	if fmt.Sprint(probe.TransferEncoding) != "[chunked]" {
		t.Fatalf("test server did not chunk: %v", probe.TransferEncoding)
	}

	srv, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}})
	att, sec, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST", Body: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPresentation(att, sec)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := attest.ProxyVerifier{}.Verify(p, []ed25519.PublicKey{srv.PublicKey()}, map[string][]byte{attest.FieldReqBody: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(tr.Fields["resp.body"]); got != strings.Join(parts, "") {
		t.Fatalf("de-chunked body is wrong (%d bytes): %.80q", len(got), got)
	}
	for _, n := range tr.Names {
		switch n {
		case "resp.header.transfer-encoding", "resp.header.content-length", "resp.header.trailer", "resp.header.x-checksum", "resp.header.connection":
			t.Errorf("field %s must not be attested", n)
		}
	}
	if string(tr.Fields["resp.header.content-type"]) != "application/json" {
		t.Errorf("content-type: %q", tr.Fields["resp.header.content-type"])
	}
}

// rawUpstream serves one canned raw HTTP response per connection.
func rawUpstream(t *testing.T, response string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pki().cert}})
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
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				io.WriteString(c, response)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestMalformedUpstreamResponses(t *testing.T) {
	cases := map[string]struct {
		response string
		code     string // "" = success
		body     string
	}{
		"plain":            {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "", "ok"},
		"eof-delimited":    {"HTTP/1.1 200 OK\r\n\r\nuntil close", "", "until close"},
		"http-1.0":         {"HTTP/1.0 200 OK\r\n\r\nold", "", "old"},
		"chunked-raw":      {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nX-T: 1\r\n\r\n", "", "abcde"},
		"interim-100":      {"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "", "ok"},
		"interim-103":      {"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "", "ok"},
		"no-content-204":   {"HTTP/1.1 204 No Content\r\n\r\n", "", ""},
		"empty":            {"", CodeUpstreamProtocol, ""},
		"garbage":          {"SSH-2.0-OpenSSH\r\n", CodeUpstreamProtocol, ""},
		"bad-status":       {"HTTP/1.1 abc OK\r\n\r\n", CodeUpstreamProtocol, ""},
		"truncated-header": {"HTTP/1.1 200 OK\r\nContent-Le", CodeUpstreamProtocol, ""},
		"short-body":       {"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", CodeUpstreamProtocol, ""},
		"bad-chunk":        {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n", CodeUpstreamProtocol, ""},
		"truncated-chunk":  {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab", CodeUpstreamProtocol, ""},
		"switching":        {"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n", CodeUpstreamProtocol, ""},
		"endless-interim":  {strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 20) + "HTTP/1.1 200 OK\r\n\r\n", CodeUpstreamProtocol, ""},
		"gzip":             {"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n\x1f\x8b", CodeUpstreamProtocol, ""},
		"identity-coding":  {"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n\r\nok", "", "ok"},
		"two-lengths":      {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nokk", CodeUpstreamProtocol, ""},
		"smuggling-te-cl":  {"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", "", "ok"},
		"huge-header":      {"HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 3<<20) + "\r\n\r\n", "*", ""},
	}
	for name, c := range cases {
		addr := rawUpstream(t, c.response)
		_, cl := newNotary(t, Config{AllowedHosts: []string{addr}, UpstreamTimeout: 5 * time.Second, MaxResponseBytes: 1 << 16})
		_, sec, err := cl.Attest(ctxT(t), &Request{URL: "https://" + addr + "/", Method: "POST", Body: []byte("x")})
		switch {
		case c.code == "*":
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case c.code == "":
			if err != nil {
				t.Errorf("%s: %v", name, err)
			} else if got := string(sec.Values[len(sec.Values)-1]); got != c.body {
				t.Errorf("%s: body %q, want %q", name, got, c.body)
			}
		case !IsCode(err, c.code):
			t.Errorf("%s: got %v, want %s", name, err, c.code)
		}
	}
}

func TestRedirectIsAttestedNotFollowed(t *testing.T) {
	var targetHits atomic.Int64
	target := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHits.Add(1) }))
	for _, status := range []int{301, 302, 303, 307, 308} {
		ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", target.URL+"/elsewhere")
			w.WriteHeader(status)
		}))
		// Even if the redirect target is allow-listed.
		_, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL), hostOf(t, target.URL)}})
		_, sec, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST", Headers: map[string]string{"x-api-key": apiKey}, Body: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		f := map[string]string{}
		for i, n := range sec.Names {
			f[n] = string(sec.Values[i])
		}
		if f["resp.status"] != strconv.Itoa(status) || f["resp.header.location"] != target.URL+"/elsewhere" {
			t.Fatalf("status %d: fields %v", status, f)
		}
	}
	if targetHits.Load() != 0 {
		t.Fatal("the notary followed a redirect")
	}
}

func TestBusy(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
	}))
	_, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}, MaxConcurrent: 2})
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST"})
			errs <- err
		}()
	}
	<-started
	<-started
	_, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST"})
	if !IsCode(err, CodeBusy) {
		t.Fatalf("third concurrent request: %v", err)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST"}); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestShutdown(t *testing.T) {
	ts := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, "done")
	}))
	srv, cl := newNotary(t, Config{AllowedHosts: []string{hostOf(t, ts.URL)}})
	errc := make(chan error, 1)
	go func() {
		_, _, err := cl.Attest(ctxT(t), &Request{URL: ts.URL, Method: "POST"})
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	// The attestation in progress completed (graceful).
	if err := <-errc; err != nil {
		t.Fatalf("in-flight attestation: %v", err)
	}
	if _, err := cl.Info(ctxT(t)); err == nil {
		t.Fatal("server still answers after shutdown")
	}
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	if err := srv.Start("127.0.0.1:0"); err == nil {
		t.Fatal("restart after shutdown")
	}
}

func TestNotaryOverTLS(t *testing.T) {
	prov := newProvider(t, llm.Config{})
	k, _ := GenerateKey()
	srv, err := NewServer(Config{Key: k, AllowedHosts: []string{prov.Addr()}, RootCAs: pki().ca.Pool(),
		TLS: &tls.Config{Certificates: []tls.Certificate{pki().cert}, MinVersion: tls.VersionTLS12}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())
	if !strings.HasPrefix(srv.URL(), "https://") {
		t.Fatal(srv.URL())
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki().ca.Pool()}}
	defer tr.CloseIdleConnections()
	cl := &Client{BaseURL: srv.URL() + "/", HTTP: &http.Client{Transport: tr}}
	if _, _, err := cl.Attest(ctxT(t), reviewRequest(prov.URL(), llm.Sample{}.RequestBody())); err != nil {
		t.Fatal(err)
	}
	// In-process use without HTTP.
	r, err := srv.Attest(ctxT(t), reviewRequest(prov.URL(), llm.Sample{}.RequestBody()))
	if err != nil || r.Attestation == nil {
		t.Fatal(err)
	}
	if _, err := srv.Attest(ctxT(t), nil); !IsCode(err, CodeBadRequest) {
		t.Fatalf("nil request: %v", err)
	}
}

// --------------------------------------------------------------- client

// TestClientChecksNotary: the client does not blindly trust what comes
// back from the notary.
func TestClientChecksNotary(t *testing.T) {
	prov := newProvider(t, llm.Config{})
	real, _ := newNotary(t, Config{AllowedHosts: []string{prov.Addr()}})
	body := llm.Sample{}.RequestBody()
	var mode atomic.Value
	mode.Store("")
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &req)
		m := mode.Load().(string)
		switch m {
		case "html-error":
			w.WriteHeader(502)
			io.WriteString(w, "<html>bad gateway</html>")
			return
		case "garbage":
			io.WriteString(w, "not json")
			return
		case "empty":
			io.WriteString(w, "{}")
			return
		case "redirect":
			http.Redirect(w, r, real.URL()+AttestPath, http.StatusTemporaryRedirect)
			return
		case "other-body":
			req.Body = llm.Sample{Candidate: strings.Repeat("e", 40)}.RequestBody()
		}
		resp, err := real.Attest(r.Context(), &req)
		if err != nil {
			writeError(w, err.(*Error))
			return
		}
		switch m {
		case "tamper-secret":
			resp.Secret.Values[len(resp.Secret.Values)-1] = []byte(`{"verdict":"approve"}`)
		case "tamper-sig":
			resp.Attestation.Sig[3] ^= 1
		case "drop-secret-field":
			resp.Secret.Names = resp.Secret.Names[1:]
			resp.Secret.Values = resp.Secret.Values[1:]
			resp.Secret.Salts = resp.Secret.Salts[1:]
		}
		writeJSON(w, 200, resp)
	}))
	defer fake.Close()
	cl := NewClient(fake.URL)
	cl.NotaryKey = real.PublicKey()
	if _, _, err := cl.Attest(ctxT(t), reviewRequest(prov.URL(), body)); err != nil {
		t.Fatalf("honest relay: %v", err)
	}
	for _, m := range []string{"html-error", "garbage", "empty", "redirect", "other-body", "tamper-secret", "tamper-sig", "drop-secret-field"} {
		mode.Store(m)
		att, sec, err := cl.Attest(ctxT(t), reviewRequest(prov.URL(), body))
		if err == nil || att != nil || sec != nil {
			t.Errorf("%s: accepted", m)
		}
	}
	// Wrong expected key.
	mode.Store("")
	other, _ := GenerateKey()
	cl.NotaryKey = other.Public().(ed25519.PublicKey)
	if _, _, err := cl.Attest(ctxT(t), reviewRequest(prov.URL(), body)); !errors.Is(err, attest.ErrUntrustedNotary) {
		t.Errorf("unexpected notary key: %v", err)
	}
	if _, _, err := cl.Attest(ctxT(t), nil); err == nil {
		t.Error("nil request")
	}
	if _, _, err := NewClient("http://127.0.0.1:1").Attest(ctxT(t), reviewRequest(prov.URL(), body)); err == nil {
		t.Error("unreachable notary")
	}
}

func TestDisclosurePolicy(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	names := []string{"req.method", "req.path", "req.header.authorization", "req.header.x-api-key", "req.header.x-other",
		"req.body", "resp.status", "resp.header.x-api-key", "resp.body"}
	values := make([][]byte, len(names))
	for i := range values {
		values[i] = []byte("value-of-" + names[i] + "-0123456789")
	}
	att, sec, err := attest.Build(priv, "h", make([]byte, 32), 1, names, values, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPresentation(att, sec)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]attest.Disclosure{"req.header.authorization": attest.Hidden, "req.header.x-api-key": attest.Hidden, "req.body": attest.Known}
	for _, l := range p.Leaves {
		w, ok := want[l.Name]
		if !ok {
			w = attest.Revealed
		}
		if l.Disclosure != w {
			t.Errorf("%s: disclosure %d, want %d", l.Name, l.Disclosure, w)
		}
	}
	enc, _ := p.Encode()
	for i, n := range names {
		_, secret := want[n]
		found := false
		for _, e := range secretEncodings(values[i]) {
			found = found || bytes.Contains(enc, e)
		}
		if found == secret {
			t.Errorf("%s: present in encoding = %v", n, found)
		}
	}
	// The policy map is a fresh copy.
	DisclosurePolicy()["req.header.x-api-key"] = attest.Revealed
	if DisclosurePolicy()["req.header.x-api-key"] != attest.Hidden {
		t.Fatal("DisclosurePolicy returns shared state")
	}
	if _, err := BuildPresentation(nil, sec); err == nil {
		t.Fatal("nil attestation")
	}
}

// ------------------------------------------------------------------ keys

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notary.key")
	k1, created, err := LoadOrCreateKey(path)
	if err != nil || !created {
		t.Fatal(err, created)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	k2, created, err := LoadOrCreateKey(path)
	if err != nil || created || !k1.Equal(k2) {
		t.Fatalf("reload: %v %v", err, created)
	}
	msg := []byte("m")
	if !ed25519.Verify(k2.Public().(ed25519.PublicKey), msg, ed25519.Sign(k1, msg)) {
		t.Fatal("loaded key does not match")
	}
	// Never overwritten.
	if err := SaveKey(path, k1); err == nil {
		t.Fatal("SaveKey overwrote a key file")
	}
	// Wrong permissions.
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(path); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Fatalf("mode %o accepted: %v", mode, err)
		}
		if _, _, err := LoadOrCreateKey(path); err == nil {
			t.Fatalf("mode %o accepted by LoadOrCreateKey", mode)
		}
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err != nil {
		t.Fatalf("mode 0400: %v", err)
	}
	// Garbage.
	seedHex := hex.EncodeToString(k1.Seed())
	for name, content := range map[string]string{
		"empty": "", "short": seedHex[:62], "long": seedHex + "00", "not-hex": strings.Repeat("zz", 32),
		"huge": strings.Repeat("a", 5000), "two-lines": seedHex + "\n" + seedHex + "\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadKey(p)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), seedHex[:16]) {
			t.Errorf("%s: error leaks key material", name)
		}
	}
	// Whitespace tolerant.
	p := filepath.Join(dir, "ws")
	os.WriteFile(p, []byte("  "+seedHex+"\r\n\n"), 0o600)
	if k, err := LoadKey(p); err != nil || !k.Equal(k1) {
		t.Fatalf("whitespace: %v", err)
	}
	if _, err := LoadKey(dir); err == nil {
		t.Fatal("directory accepted as key file")
	}
	if _, _, err := LoadOrCreateKey(filepath.Join(dir, "no", "such", "dir", "k")); err == nil {
		t.Fatal("key created in a missing directory")
	}
	if err := SaveKey(filepath.Join(dir, "x"), k1[:5]); err == nil {
		t.Fatal("short key saved")
	}
}
