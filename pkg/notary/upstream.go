package notary

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dosr/dosr/pkg/attest"
)

// hostRe is the syntax of a canonical authority; the same expression as
// the one for provider_host in pkg/types.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)

// CanonicalHost returns the canonical form of an authority "host" or
// "host:port": lower case, with the port omitted iff it is 443. This is
// the form of the allow-list entries, of the attested host header, and
// what a policy's provider_host must use. IPv6 literals are not
// supported.
func CanonicalHost(authority string) (string, error) {
	a := strings.ToLower(authority)
	if !hostRe.MatchString(a) {
		return "", fmt.Errorf("bad host %q", authority)
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return a, nil // no port
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
		return "", fmt.Errorf("bad port in host %q", authority)
	}
	if p == 443 {
		return host, nil
	}
	return host + ":" + port, nil
}

// splitCanonical splits a canonical authority into host name and port.
func splitCanonical(canon string) (host, port string) {
	if h, p, err := net.SplitHostPort(canon); err == nil {
		return h, p
	}
	return canon, "443"
}

// target is a validated attest request.
type target struct {
	canonHost string // canonical authority
	hostname  string
	port      string
	method    string
	path      string // request target as sent
	names     []string
	values    []string // request header values, parallel to names (sorted by name)
	body      []byte
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func validHeaderName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !isTokenChar(n[i]) {
			return false
		}
	}
	return true
}

// validHeaderValue: visible ASCII, space, tab and obs-text; no control
// characters (in particular no CR/LF: header injection), no leading or
// trailing white space.
func validHeaderValue(v string) bool {
	if len(v) > 8192 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' || c >= 0x20 && c != 0x7f {
			continue
		}
		return false
	}
	return v == strings.Trim(v, " \t")
}

// Headers that describe the connection or the framing. Callers may not
// send them; in responses they are not part of the transcript.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"proxy-connection":    true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// parseTarget validates an attest request against the configuration.
func (s *Server) parseTarget(req *Request) (*target, *Error) {
	if req == nil {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "missing request")
	}
	if len(req.URL) > 8192 {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "url too long")
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "url does not parse")
	}
	if u.Scheme != "https" {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "url scheme must be https")
	}
	if u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || strings.Contains(req.URL, "#") {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "url must not contain userinfo or a fragment")
	}
	canon, err := CanonicalHost(u.Host)
	if err != nil {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "url has a bad host")
	}
	if !s.allowed[canon] {
		return nil, errf(http.StatusForbidden, CodeHostNotAllowed, "host %q is not on the notary's allow-list", canon)
	}
	t := &target{canonHost: canon, body: req.Body}
	t.hostname, t.port = splitCanonical(canon)

	t.method = strings.ToUpper(req.Method)
	if !s.methods[t.method] {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "method %q is not allowed", req.Method)
	}
	if t.method == "GET" && len(req.Body) > 0 {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "GET request with a body")
	}
	if int64(len(req.Body)) > s.cfg.MaxRequestBytes {
		return nil, errf(http.StatusRequestEntityTooLarge, CodeRequestTooLarge, "request body exceeds %d bytes", s.cfg.MaxRequestBytes)
	}

	t.path = u.EscapedPath()
	if t.path == "" {
		t.path = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		t.path += "?" + u.RawQuery
	}
	if t.path[0] != '/' || len(t.path) > 4096 {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "bad url path")
	}
	for i := 0; i < len(t.path); i++ {
		if c := t.path[i]; c <= 0x20 || c >= 0x7f {
			return nil, errf(http.StatusBadRequest, CodeBadRequest, "url path contains an invalid character")
		}
	}

	// Headers: the caller's plus the notary's own.
	hdr := map[string]string{}
	for k, v := range req.Headers {
		name := strings.ToLower(k)
		// Never echo header VALUES in errors: they may be secrets.
		if !validHeaderName(name) {
			return nil, errf(http.StatusBadRequest, CodeBadRequest, "invalid header name")
		}
		if !validHeaderValue(v) {
			return nil, errf(http.StatusBadRequest, CodeBadRequest, "invalid value for header %q", name)
		}
		if _, dup := hdr[name]; dup {
			return nil, errf(http.StatusBadRequest, CodeBadRequest, "header %q given more than once", name)
		}
		if (hopByHop[name] && name != "connection") || name == "expect" || strings.HasPrefix(name, "proxy-") {
			return nil, errf(http.StatusBadRequest, CodeBadRequest, "header %q is not allowed", name)
		}
		hdr[name] = v
	}
	own := map[string]string{
		"host":            canon,
		"accept-encoding": "identity",
		"connection":      "close",
	}
	if t.method != "GET" || len(req.Body) > 0 {
		own["content-length"] = strconv.Itoa(len(req.Body))
	} else if _, ok := hdr["content-length"]; ok {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "header %q is set by the notary", "content-length")
	}
	for name, v := range own {
		if cv, ok := hdr[name]; ok && cv != v {
			return nil, errf(http.StatusBadRequest, CodeBadRequest, "header %q is set by the notary and cannot be overridden", name)
		}
		hdr[name] = v
	}
	// 5 fixed fields plus at least one response header must still fit.
	if len(hdr) > attest.MaxLeaves-16 {
		return nil, errf(http.StatusBadRequest, CodeBadRequest, "too many headers")
	}
	for name := range hdr {
		t.names = append(t.names, name)
	}
	sort.Strings(t.names)
	for _, n := range t.names {
		t.values = append(t.values, hdr[n])
	}
	return t, nil
}

// wireRequest renders the HTTP/1.1 request exactly as attested.
func (t *target) wireRequest() []byte {
	var b bytes.Buffer
	b.Grow(256 + len(t.body))
	b.WriteString(t.method + " " + t.path + " HTTP/1.1\r\n")
	for i, n := range t.names {
		b.WriteString(n + ": " + t.values[i] + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(t.body)
	return b.Bytes()
}

// exchange is the result of the upstream call.
type exchange struct {
	status      int
	respNames   []string // lower case, sorted
	respValues  []string
	body        []byte
	spki        [32]byte
	connectTime time.Duration // dial + TLS handshake
}

// countingReader fails once more than limit bytes have been read.
type limitReader struct {
	r     io.Reader
	left  int64
	tripd bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		l.tripd = true
		return 0, errResponseTooLarge
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

var errResponseTooLarge = errors.New("response exceeds the size limit")

// upstreamError classifies a failure of the upstream call.
func upstreamError(ctx context.Context, stage string, err error) *Error {
	var ne net.Error
	switch {
	case errors.Is(err, errResponseTooLarge):
		return errf(http.StatusBadGateway, CodeResponseTooLarge, "upstream response exceeds the notary's size limit")
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return errf(http.StatusGatewayTimeout, CodeUpstreamTimeout, "upstream call timed out (%s)", stage)
	case errors.Is(ctx.Err(), context.Canceled):
		return errf(499, CodeCanceled, "request cancelled (%s)", stage)
	}
	var (
		ua  x509.UnknownAuthorityError
		hn  x509.HostnameError
		ci  x509.CertificateInvalidError
		cve *tls.CertificateVerificationError
	)
	if errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) || errors.As(err, &cve) {
		return errf(http.StatusBadGateway, CodeUpstreamTLS, "upstream certificate rejected: %v", err)
	}
	if stage == "tls" {
		return errf(http.StatusBadGateway, CodeUpstreamTLS, "TLS handshake with upstream failed: %v", err)
	}
	if stage == "dial" {
		return errf(http.StatusBadGateway, CodeUpstreamUnreachable, "cannot connect to upstream: %v", err)
	}
	return errf(http.StatusBadGateway, CodeUpstreamProtocol, "upstream call failed (%s): %v", stage, err)
}

// call performs the API call on a fresh TLS connection. ctx bounds the
// whole exchange.
func (s *Server) call(ctx context.Context, t *target) (*exchange, *Error) {
	start := time.Now()
	addr := net.JoinHostPort(t.hostname, t.port)
	raw, err := s.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, upstreamError(ctx, "dial", err)
	}
	// Closing the connection when ctx ends aborts any blocked read or
	// write; the deadline does the same for the timeout.
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		RootCAs:    s.cfg.RootCAs, // nil: system roots
		ServerName: t.hostname,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, upstreamError(ctx, "tls", err)
	}
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		return nil, errf(http.StatusBadGateway, CodeUpstreamTLS, "upstream presented no verified certificate")
	}
	ex := &exchange{
		spki:        sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo),
		connectTime: time.Since(start),
	}

	if _, err := conn.Write(t.wireRequest()); err != nil {
		return nil, upstreamError(ctx, "write", err)
	}

	// Everything read from the connection is bounded: headers, chunk
	// framing and body together.
	lr := &limitReader{r: conn, left: 8*s.cfg.MaxResponseBytes + 1<<20}
	br := bufio.NewReaderSize(lr, 16<<10)
	var resp *http.Response
	for i := 0; ; i++ {
		resp, err = http.ReadResponse(br, &http.Request{Method: t.method})
		if err != nil {
			return nil, upstreamError(ctx, "read response header", err)
		}
		if resp.StatusCode >= 200 {
			break
		}
		// Interim response.
		resp.Body.Close()
		if resp.StatusCode == http.StatusSwitchingProtocols || i >= 8 {
			return nil, errf(http.StatusBadGateway, CodeUpstreamProtocol, "unexpected interim response %d from upstream", resp.StatusCode)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode > 999 {
		return nil, errf(http.StatusBadGateway, CodeUpstreamProtocol, "bad status code from upstream")
	}
	ex.status = resp.StatusCode
	if resp.ContentLength > s.cfg.MaxResponseBytes {
		return nil, upstreamError(ctx, "read response body", errResponseTooLarge)
	}
	for _, ce := range resp.Header.Values("Content-Encoding") {
		for _, tok := range strings.Split(ce, ",") {
			if tok = strings.ToLower(strings.TrimSpace(tok)); tok != "" && tok != "identity" {
				return nil, errf(http.StatusBadGateway, CodeUpstreamProtocol,
					"upstream sent a content-encoded response although identity was requested")
			}
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, upstreamError(ctx, "read response body", err)
	}
	if int64(len(body)) > s.cfg.MaxResponseBytes {
		return nil, upstreamError(ctx, "read response body", errResponseTooLarge)
	}
	ex.body = body

	// Response headers of the transcript.
	drop := map[string]bool{"content-length": true}
	for k := range hopByHop {
		drop[k] = true
	}
	for _, v := range resp.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.ToLower(strings.TrimSpace(tok)); tok != "" {
				drop[tok] = true
			}
		}
	}
	merged := map[string][]string{}
	for k, vs := range resp.Header {
		name := strings.ToLower(k)
		if drop[name] {
			continue
		}
		if !validHeaderName(name) {
			return nil, errf(http.StatusBadGateway, CodeUpstreamProtocol, "upstream sent an invalid header name")
		}
		// Keys differing only in case cannot occur for valid names
		// (net/textproto canonicalises them); handled anyway, in a
		// deterministic order.
		if _, dup := merged[name]; dup {
			return nil, errf(http.StatusBadGateway, CodeUpstreamProtocol, "upstream sent ambiguous header %q", name)
		}
		merged[name] = vs
	}
	for name := range merged {
		ex.respNames = append(ex.respNames, name)
	}
	sort.Strings(ex.respNames)
	for _, name := range ex.respNames {
		ex.respValues = append(ex.respValues, strings.Join(merged[name], ", "))
	}
	if len(t.names)+len(ex.respNames)+5 > attest.MaxLeaves {
		return nil, errf(http.StatusBadGateway, CodeUpstreamProtocol, "transcript has more than %d fields", attest.MaxLeaves)
	}
	return ex, nil
}

// transcript lays out the attested fields in contract order.
func transcript(t *target, ex *exchange) (names []string, values [][]byte) {
	add := func(n string, v []byte) {
		names = append(names, n)
		values = append(values, v)
	}
	add(attest.FieldReqMethod, []byte(t.method))
	add(attest.FieldReqPath, []byte(t.path))
	for i, n := range t.names {
		add(attest.FieldReqHeaderPfx+n, []byte(t.values[i]))
	}
	add(attest.FieldReqBody, t.body)
	add(attest.FieldRespStatus, []byte(strconv.Itoa(ex.status)))
	for i, n := range ex.respNames {
		add(attest.FieldRespHeadPfx+n, []byte(ex.respValues[i]))
	}
	add(attest.FieldRespBody, ex.body)
	return names, values
}
