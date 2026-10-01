package notary

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dosr/dosr/pkg/attest"
)

// Paths of the notary API.
const (
	AttestPath = "/v1/attest"
	InfoPath   = "/v1/info"
)

// Defaults of Config.
const (
	DefaultUpstreamTimeout  = 120 * time.Second
	DefaultMaxRequestBytes  = 8 << 20
	DefaultMaxResponseBytes = 512 << 10 // a presentation must fit into a transaction (1 MiB, base64)
	DefaultMaxConcurrent    = 64
)

// Error codes of the notary API (field error.code of an error response).
const (
	CodeBadRequest          = "bad_request"          // 400
	CodeHostNotAllowed      = "host_not_allowed"     // 403
	CodeRequestTooLarge     = "request_too_large"    // 413
	CodeNonceMissing        = "nonce_missing"        // 400: single-use nonces enforced, request has none
	CodeNonceReused         = "nonce_reused"         // 409
	CodeBusy                = "busy"                 // 503: too many concurrent attestations
	CodeUpstreamUnreachable = "upstream_unreachable" // 502
	CodeUpstreamTLS         = "upstream_tls"         // 502: handshake or certificate validation failed
	CodeUpstreamProtocol    = "upstream_protocol"    // 502: malformed or unsupported response
	CodeResponseTooLarge    = "response_too_large"   // 502
	CodeUpstreamTimeout     = "upstream_timeout"     // 504
	CodeCanceled            = "canceled"             // 499: the caller went away
	CodeInternal            = "internal"             // 500
)

// Error is an error of the notary API. The client returns the same type,
// so callers can switch on Code on either side.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return "notary: " + e.Code + ": " + e.Message }

func errf(status int, code, format string, a ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, a...)}
}

// IsCode reports whether err is (or wraps) a notary *Error with the code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Request is the body of POST /v1/attest: the API call to make.
type Request struct {
	// URL is the https URL of the call; its authority must be on the
	// notary's allow-list.
	URL string `json:"url"`
	// Method is "POST" (or another method the notary allows).
	Method string `json:"method"`
	// Headers are the request headers; names are case-insensitive. The
	// notary adds host, accept-encoding, connection and content-length.
	Headers map[string]string `json:"headers"`
	// Body is the request body (base64 in JSON).
	Body []byte `json:"body"`
}

// Timing is the notary's time measurement of one attestation, in
// nanoseconds. It separates the latency of the LLM call from the
// overhead the attestation adds:
//
//	overhead of attestation = TotalNs - UpstreamNs
//	                        = NonceNs + AttestNs + (request parsing)
type Timing struct {
	// UpstreamNs is the duration of the upstream call: connect, TLS
	// handshake, sending the request and reading the full response.
	UpstreamNs int64 `json:"upstream_ns"`
	// ConnectNs is the part of UpstreamNs spent on TCP connect and TLS
	// handshake.
	ConnectNs int64 `json:"connect_ns"`
	// NonceNs is the time to extract and durably reserve the review
	// nonce (0 unless single-use nonces are enforced).
	NonceNs int64 `json:"nonce_ns"`
	// AttestNs is the time to commit to the transcript and sign it
	// (attest.Build).
	AttestNs int64 `json:"attest_ns"`
	// TotalNs is the time from the decoded request to the finished
	// attestation (excluding reading the request and writing the
	// response).
	TotalNs int64 `json:"total_ns"`
}

// Timing response headers of POST /v1/attest (decimal nanoseconds).
const (
	HeaderUpstreamNs = "X-Dosr-Upstream-Ns"
	HeaderAttestNs   = "X-Dosr-Attest-Ns"
	HeaderTotalNs    = "X-Dosr-Total-Ns"
)

// Response is the body of a successful POST /v1/attest.
type Response struct {
	Attestation *attest.Attestation `json:"attestation"`
	// Secret is the opening material (all values and salts). It stays
	// with the contributor and is never sent to validators.
	Secret *attest.Secret `json:"secret"`
	Timing Timing         `json:"timing"`
}

// Info is the body of GET /v1/info.
type Info struct {
	Version               int      `json:"version"`    // attest.Version
	NotaryKey             []byte   `json:"notary_key"` // ed25519 public key
	AllowedHosts          []string `json:"allowed_hosts"`
	AllowedMethods        []string `json:"allowed_methods"`
	MaxRequestBytes       int64    `json:"max_request_bytes"`
	MaxResponseBytes      int64    `json:"max_response_bytes"`
	UpstreamTimeoutMs     int64    `json:"upstream_timeout_ms"`
	EnforceSingleUseNonce bool     `json:"enforce_single_use_nonce"`
}

// Config configures a notary.
type Config struct {
	// Key is the notary's signing key. Required (see LoadOrCreateKey).
	Key ed25519.PrivateKey
	// AllowedHosts is the allow-list of upstream authorities, "host" or
	// "host:port" (port 443 if omitted). Required.
	AllowedHosts []string
	// AllowedMethods defaults to {"POST"}.
	AllowedMethods []string
	// RootCAs are the roots upstream certificates are validated against;
	// nil means the system roots. Tests use a private CA.
	RootCAs *x509.CertPool
	// UpstreamTimeout bounds one upstream call (connect to last body
	// byte). Default DefaultUpstreamTimeout.
	UpstreamTimeout time.Duration
	// MaxRequestBytes bounds the body of the API call. Default
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// MaxResponseBytes bounds the upstream response body. Default
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// MaxConcurrent bounds the number of attestations in progress;
	// further requests are refused with CodeBusy. Default
	// DefaultMaxConcurrent.
	MaxConcurrent int

	// EnforceSingleUseNonce makes the notary attest at most one call per
	// DOSR review nonce (see nonce.go).
	EnforceSingleUseNonce bool
	// NonceFile is the path of the persistent used-nonce log. If empty
	// while EnforceSingleUseNonce is set, the set is kept in memory only
	// and a restart forgets it (tests/experiments only).
	NonceFile string

	// TLS, if set, makes Start serve HTTPS with this configuration.
	// Otherwise the notary API is served over PLAIN HTTP, which is only
	// acceptable on localhost or a trusted network (requests carry API
	// keys).
	TLS *tls.Config

	// Now is the clock (default time.Now), Rand the source of salts
	// (default crypto/rand), DialContext the dialer (default net.Dialer);
	// they exist for tests.
	Now         func() time.Time
	Rand        io.Reader
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logger receives one line per failed attestation. Header values and
	// bodies are never logged. Default: discard.
	Logger *log.Logger
}

// Server is a notary.
type Server struct {
	cfg     Config
	pub     ed25519.PublicKey
	allowed map[string]bool
	methods map[string]bool
	sem     chan struct{}
	nonces  *NonceStore // nil unless enforced
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)

	mu       sync.Mutex
	httpSrv  *http.Server
	ln       net.Listener
	serveCh  chan struct{}
	shutdown bool
}

// NewServer validates cfg, opens the nonce log if configured, and
// returns a notary. Call Shutdown to release the nonce log.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("notary: Config.Key is required")
	}
	pub, ok := cfg.Key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("notary: bad key")
	}
	s := &Server{pub: pub, allowed: map[string]bool{}, methods: map[string]bool{}}
	if len(cfg.AllowedHosts) == 0 {
		return nil, errors.New("notary: Config.AllowedHosts is required")
	}
	for _, h := range cfg.AllowedHosts {
		c, err := CanonicalHost(h)
		if err != nil {
			return nil, fmt.Errorf("notary: allow-list: %v", err)
		}
		s.allowed[c] = true
	}
	if len(cfg.AllowedMethods) == 0 {
		cfg.AllowedMethods = []string{"POST"}
	}
	for _, m := range cfg.AllowedMethods {
		if m != "POST" && m != "GET" && m != "PUT" && m != "PATCH" && m != "DELETE" {
			return nil, fmt.Errorf("notary: unsupported method %q", m)
		}
		s.methods[m] = true
	}
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = DefaultUpstreamTimeout
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if cfg.MaxResponseBytes > 1<<30 || cfg.MaxRequestBytes > 1<<30 {
		return nil, errors.New("notary: size limits must not exceed 1 GiB")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultMaxConcurrent
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	s.dial = cfg.DialContext
	if s.dial == nil {
		d := &net.Dialer{Timeout: 30 * time.Second}
		s.dial = d.DialContext
	}
	s.sem = make(chan struct{}, cfg.MaxConcurrent)
	if cfg.EnforceSingleUseNonce {
		if cfg.NonceFile == "" {
			s.nonces = NewMemoryNonceStore()
		} else {
			ns, err := OpenNonceStore(cfg.NonceFile)
			if err != nil {
				return nil, err
			}
			s.nonces = ns
		}
	}
	s.cfg = cfg
	return s, nil
}

// PublicKey returns the notary's public key.
func (s *Server) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey{}, s.pub...)
}

// Info returns what GET /v1/info serves.
func (s *Server) Info() Info {
	in := Info{
		Version:               attest.Version,
		NotaryKey:             s.PublicKey(),
		MaxRequestBytes:       s.cfg.MaxRequestBytes,
		MaxResponseBytes:      s.cfg.MaxResponseBytes,
		UpstreamTimeoutMs:     s.cfg.UpstreamTimeout.Milliseconds(),
		EnforceSingleUseNonce: s.cfg.EnforceSingleUseNonce,
	}
	for h := range s.allowed {
		in.AllowedHosts = append(in.AllowedHosts, h)
	}
	for m := range s.methods {
		in.AllowedMethods = append(in.AllowedMethods, m)
	}
	sort.Strings(in.AllowedHosts)
	sort.Strings(in.AllowedMethods)
	return in
}

// UsedNonces returns the number of consumed review nonces (0 if
// single-use nonces are not enforced).
func (s *Server) UsedNonces() int {
	if s.nonces == nil {
		return 0
	}
	return s.nonces.Len()
}

// Attest performs and attests one API call. It is what POST /v1/attest
// does, usable in-process. Errors are of type *Error.
func (s *Server) Attest(ctx context.Context, req *Request) (*Response, error) {
	start := time.Now()
	t, e := s.parseTarget(req)
	if e != nil {
		return nil, e
	}
	var nonce string
	if s.nonces != nil {
		n, err := extractNonce(t.body)
		if err != nil {
			code := CodeBadRequest
			if errors.Is(err, errNoNonce) {
				code = CodeNonceMissing
			}
			return nil, errf(http.StatusBadRequest, code, "single-use nonces are enforced: %v", err)
		}
		nonce = n
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		return nil, errf(http.StatusServiceUnavailable, CodeBusy, "too many attestations in progress")
	}
	if err := ctx.Err(); err != nil {
		return nil, errf(499, CodeCanceled, "request cancelled")
	}

	var tm Timing
	if s.nonces != nil {
		// Reserve BEFORE the upstream call; never released (nonce.go).
		t0 := time.Now()
		fresh, err := s.nonces.Reserve(nonce)
		tm.NonceNs = int64(time.Since(t0))
		if err != nil {
			s.cfg.Logger.Printf("notary: %v", err)
			return nil, errf(http.StatusInternalServerError, CodeInternal, "cannot record the review nonce")
		}
		if !fresh {
			return nil, errf(http.StatusConflict, CodeNonceReused,
				"review nonce %s was already used; the notary attests one call per nonce", nonce)
		}
	}

	cctx, cancel := context.WithTimeout(ctx, s.cfg.UpstreamTimeout)
	defer cancel()
	t0 := time.Now()
	ex, e := s.call(cctx, t)
	tm.UpstreamNs = int64(time.Since(t0))
	if e != nil {
		return nil, e
	}
	tm.ConnectNs = int64(ex.connectTime)
	now := s.cfg.Now().Unix()

	t0 = time.Now()
	names, values := transcript(t, ex)
	att, sec, err := attest.Build(s.cfg.Key, t.hostname, ex.spki[:], now, names, values, s.cfg.Rand)
	tm.AttestNs = int64(time.Since(t0))
	if err != nil {
		s.cfg.Logger.Printf("notary: build: %v", err)
		return nil, errf(http.StatusInternalServerError, CodeInternal, "cannot build the attestation")
	}
	tm.TotalNs = int64(time.Since(start))
	return &Response{Attestation: att, Secret: sec, Timing: tm}, nil
}

// ------------------------------------------------------------------ HTTP

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":{"code":"internal","message":"encoding failure"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	// Responses contain secrets.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, e *Error) {
	writeJSON(w, e.Status, struct {
		Error *Error `json:"error"`
	}{e})
}

// Handler returns the HTTP handler of the notary API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(AttestPath, s.handleAttest)
	mux.HandleFunc(InfoPath, s.handleInfo)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, errf(http.StatusNotFound, CodeBadRequest, "not found"))
	})
	return mux
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		writeError(w, errf(http.StatusMethodNotAllowed, CodeBadRequest, "method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.Info())
}

func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, errf(http.StatusMethodNotAllowed, CodeBadRequest, "method not allowed"))
		return
	}
	// The JSON envelope: base64 body (4/3) plus URL and headers.
	limit := s.cfg.MaxRequestBytes/3*4 + 1<<20
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, errf(http.StatusRequestEntityTooLarge, CodeRequestTooLarge, "attest request too large"))
			return
		}
		writeError(w, errf(http.StatusBadRequest, CodeBadRequest, "cannot read request"))
		return
	}
	var req Request
	if err := decodeStrict(raw, &req); err != nil {
		// The decoder's message may quote input; keep it generic.
		writeError(w, errf(http.StatusBadRequest, CodeBadRequest, "attest request is not valid JSON of the expected shape"))
		return
	}
	resp, err := s.Attest(r.Context(), &req)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = errf(http.StatusInternalServerError, CodeInternal, "internal error")
		}
		s.cfg.Logger.Printf("notary: attest failed: %s: %s", e.Code, e.Message)
		writeError(w, e)
		return
	}
	h := w.Header()
	h.Set(HeaderUpstreamNs, strconv.FormatInt(resp.Timing.UpstreamNs, 10))
	h.Set(HeaderAttestNs, strconv.FormatInt(resp.Timing.AttestNs, 10))
	h.Set(HeaderTotalNs, strconv.FormatInt(resp.Timing.TotalNs, 10))
	h.Set("Server-Timing", fmt.Sprintf("upstream;dur=%.3f, attest;dur=%.3f, total;dur=%.3f",
		float64(resp.Timing.UpstreamNs)/1e6, float64(resp.Timing.AttestNs)/1e6, float64(resp.Timing.TotalNs)/1e6))
	writeJSON(w, http.StatusOK, resp)
}

// Start listens on addr (e.g. "127.0.0.1:0") and serves the notary API in
// a background goroutine: HTTPS if Config.TLS is set, otherwise PLAIN
// HTTP (localhost / trusted networks only).
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("notary: listen: %w", err)
	}
	if err := s.Serve(ln); err != nil {
		ln.Close()
		return err
	}
	return nil
}

// Serve is like Start with a listener supplied by the caller.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		return errors.New("notary: server was shut down")
	}
	if s.httpSrv != nil {
		return errors.New("notary: server already started")
	}
	s.ln = ln
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         s.cfg.TLS,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		// The response is written after the upstream call.
		WriteTimeout:   s.cfg.UpstreamTimeout + 60*time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       s.cfg.Logger,
	}
	s.serveCh = make(chan struct{})
	srv, ch, useTLS := s.httpSrv, s.serveCh, s.cfg.TLS != nil
	go func() {
		defer close(ch)
		var err error
		if useTLS {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.cfg.Logger.Printf("notary: serve: %v", err)
		}
	}()
	return nil
}

// Addr returns the listening address, or "" if not started.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// URL returns the base URL of the notary API ("http://127.0.0.1:port"),
// or "" if not started.
func (s *Server) URL() string {
	a := s.Addr()
	if a == "" {
		return ""
	}
	if s.cfg.TLS != nil {
		return "https://" + a
	}
	return "http://" + a
}

// Shutdown stops the server gracefully: no new connections are accepted,
// attestations in progress get until ctx is done to finish, then
// connections are closed (which cancels their upstream calls). Finally
// the nonce log is closed. Safe to call more than once and on a server
// that was never started.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv, ch := s.httpSrv, s.serveCh
	already := s.shutdown
	s.shutdown = true
	s.mu.Unlock()
	var err error
	if srv != nil {
		if err = srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
		select {
		case <-ch:
		case <-ctx.Done():
		}
	}
	if s.nonces != nil && !already {
		if cerr := s.nonces.Close(); err == nil {
			err = cerr
		}
	}
	return err
}
