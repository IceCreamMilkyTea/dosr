package llm

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Default limits.
const (
	// DefaultMaxRequestBytes bounds the request body.
	DefaultMaxRequestBytes = 16 << 20
	// MessagesPath is the path of the Messages API endpoint.
	MessagesPath = "/v1/messages"
	// StatsPath is the path of the accounting endpoint (mock only).
	StatsPath = "/stats"
)

// Config configures a mock provider.
type Config struct {
	// APIKeys are the accepted values of the x-api-key header. Required.
	APIKeys []string
	// Models are the known model identifiers. Default: the keys of
	// DefaultPrices().
	Models []string
	// Verdict decides the verdicts. Default: MarkerVerdict.
	Verdict VerdictFunc
	// Latency is the latency model. Default: LatencyNone.
	Latency LatencyModel
	// Faults configures fault injection. Default: none.
	Faults Faults
	// Prices is the price table (USD per million tokens) by model.
	// Default: DefaultPrices(). Models without an entry cost nothing.
	Prices map[string]Price
	// Seed seeds the random generator used for latency, fault selection
	// and response identifiers.
	Seed int64
	// TargetOutputTokens, if positive, pads the review summary so that
	// the response has about this many (estimated) output tokens. Real
	// reviews are a few hundred tokens long; the latency and cost models
	// depend on the output length.
	TargetOutputTokens int
	// MaxRequestBytes bounds the request body. Default:
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// RejectForcedToolChoice (default TRUE when nil) answers requests
	// whose tool_choice type is "tool" or "any" with HTTP 400
	// (ForcedToolChoiceMessage), as current models do. Set it to
	// Bool(false) to model an older model that supports forced tool use.
	RejectForcedToolChoice *bool
	// EmitThinking (default TRUE when nil) makes every response start
	// with a {"type":"thinking","thinking":"","signature":"..."} block,
	// as models on which thinking is always on do (with the thinking
	// text omitted).
	EmitThinking *bool
	// Certificate is the TLS server certificate used by Start. The mock
	// provider never serves plain HTTP.
	Certificate *tls.Certificate
	// Logger receives server errors. Default: discard.
	Logger *log.Logger
}

// Bool returns a pointer to v, for the optional boolean fields of Config.
func Bool(v bool) *bool { return &v }

// Server is a mock LLM provider.
type Server struct {
	rejectForced bool
	emitThinking bool
	keys         [][]byte
	models       map[string]bool
	maxBody      int64
	target       int
	seed         int64
	cert         *tls.Certificate
	logger       *log.Logger
	rng          *Rand
	done         chan struct{}
	doneOnce     sync.Once

	mu      sync.Mutex // guards everything below
	verdict VerdictFunc
	latency LatencyModel
	faults  Faults
	prices  map[string]Price
	stats   Stats
	seq     uint64
	httpSrv *http.Server
	ln      net.Listener
	serveCh chan struct{}
}

// NewServer validates cfg and creates a server. Use Handler to mount it
// in a test server or Start to listen.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.APIKeys) == 0 {
		return nil, errors.New("llm: at least one API key is required")
	}
	s := &Server{
		models:  map[string]bool{},
		maxBody: cfg.MaxRequestBytes,
		target:  cfg.TargetOutputTokens,
		seed:    cfg.Seed,
		cert:    cfg.Certificate,
		logger:  cfg.Logger,
		rng:     NewRand(cfg.Seed),
		done:    make(chan struct{}),
		verdict: cfg.Verdict,
		latency: cfg.Latency,
		faults:  cfg.Faults,
		prices:  map[string]Price{},

		rejectForced: cfg.RejectForcedToolChoice == nil || *cfg.RejectForcedToolChoice,
		emitThinking: cfg.EmitThinking == nil || *cfg.EmitThinking,
	}
	for _, k := range cfg.APIKeys {
		if k == "" {
			return nil, errors.New("llm: empty API key")
		}
		s.keys = append(s.keys, []byte(k))
	}
	prices := cfg.Prices
	if prices == nil {
		prices = DefaultPrices()
	}
	for m, p := range prices {
		if p.InputPerMTok < 0 || p.OutputPerMTok < 0 {
			return nil, fmt.Errorf("llm: negative price for model %q", m)
		}
		s.prices[m] = p
	}
	models := cfg.Models
	if len(models) == 0 {
		for m := range DefaultPrices() {
			models = append(models, m)
		}
	}
	for _, m := range models {
		if m == "" {
			return nil, errors.New("llm: empty model name")
		}
		s.models[m] = true
	}
	if s.maxBody <= 0 {
		s.maxBody = DefaultMaxRequestBytes
	}
	if s.target < 0 {
		return nil, errors.New("llm: negative TargetOutputTokens")
	}
	if s.verdict == nil {
		s.verdict = MarkerVerdict
	}
	if s.logger == nil {
		s.logger = log.New(io.Discard, "", 0)
	}
	if err := s.latency.validate(); err != nil {
		return nil, err
	}
	if err := s.faults.validate(); err != nil {
		return nil, err
	}
	s.stats.PerModel = map[string]ModelStats{}
	return s, nil
}

// SetVerdict replaces the verdict function (nil = MarkerVerdict).
func (s *Server) SetVerdict(v VerdictFunc) {
	if v == nil {
		v = MarkerVerdict
	}
	s.mu.Lock()
	s.verdict = v
	s.mu.Unlock()
}

// SetLatency replaces the latency model.
func (s *Server) SetLatency(m LatencyModel) error {
	if err := m.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.latency = m
	s.mu.Unlock()
	return nil
}

// SetFaults replaces the fault injection configuration.
func (s *Server) SetFaults(f Faults) error {
	if err := f.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.faults = f
	s.mu.Unlock()
	return nil
}

// Handler returns the HTTP handler of the provider:
//
//	POST /v1/messages   the Messages API
//	GET  /stats         accounting (JSON encoding of Stats)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(MessagesPath, s.handleMessages)
	mux.HandleFunc(StatsPath, s.handleStats)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found_error", "not found", "")
	})
	return mux
}

// Start listens on addr (e.g. "127.0.0.1:0") and serves HTTPS with
// Config.Certificate in a background goroutine.
func (s *Server) Start(addr string) error {
	if s.cert == nil {
		return errors.New("llm: Config.Certificate is required to Start")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpSrv != nil {
		return errors.New("llm: server already started")
	}
	select {
	case <-s.done:
		return errors.New("llm: server was shut down")
	default:
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("llm: listen: %w", err)
	}
	s.ln = ln
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{*s.cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          s.logger,
	}
	s.serveCh = make(chan struct{})
	srv, ch := s.httpSrv, s.serveCh
	go func() {
		defer close(ch)
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Printf("llm: serve: %v", err)
		}
	}()
	return nil
}

// Addr returns the listening address ("127.0.0.1:port"), or "" if the
// server was not started.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// URL returns "https://" + Addr().
func (s *Server) URL() string {
	a := s.Addr()
	if a == "" {
		return ""
	}
	return "https://" + a
}

// Shutdown stops the server gracefully: simulated latencies and hangs are
// aborted, in-flight requests get until ctx is done to finish, then
// connections are closed. It is safe to call more than once and on a
// server that was never started.
func (s *Server) Shutdown(ctx context.Context) error {
	s.doneOnce.Do(func() { close(s.done) })
	s.mu.Lock()
	srv, ch := s.httpSrv, s.serveCh
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	if err != nil {
		_ = srv.Close()
	}
	select {
	case <-ch:
	case <-ctx.Done():
	}
	return err
}

// ---------------------------------------------------------------- wire

type wireError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, reqID string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"type":"error","error":{"type":"api_error","message":"encoding failure"}}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", fmt.Sprint(len(b)))
	if reqID != "" {
		h.Set("Request-Id", reqID)
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeError writes an error in Anthropic's error JSON shape.
func writeError(w http.ResponseWriter, status int, typ, msg, reqID string) {
	var e wireError
	e.Type = "error"
	e.Error.Type = typ
	e.Error.Message = msg
	e.RequestID = reqID
	writeJSON(w, status, reqID, e)
}

type wireUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type wireBlock struct {
	Type      string          `json:"type"`
	Thinking  *string         `json:"thinking,omitempty"`
	Signature string          `json:"signature,omitempty"`
	Text      *string         `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
}

type wireStopDetails struct {
	Type        string  `json:"type"`
	Category    *string `json:"category"`
	Explanation string  `json:"explanation"`
}

type wireResponse struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Role         string           `json:"role"`
	Model        string           `json:"model"`
	Content      []wireBlock      `json:"content"`
	StopReason   string           `json:"stop_reason"`
	StopSequence *string          `json:"stop_sequence"`
	StopDetails  *wireStopDetails `json:"stop_details"` // null unless stop_reason is "refusal"
	Usage        wireUsage        `json:"usage"`
}

type toolInput struct {
	Verdict   string `json:"verdict"`
	Candidate string `json:"candidate"`
	Summary   string `json:"summary"`
}

// newID derives a response identifier from the seed and a counter.
func (s *Server) newIDs() (msgID, toolID, reqID, signature string) {
	s.mu.Lock()
	s.seq++
	n := s.seq
	s.mu.Unlock()
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(s.seed))
	binary.BigEndian.PutUint64(b[8:], n)
	h := sha256.Sum256(b[:])
	x := hex.EncodeToString(h[:])
	// The signature of a thinking block is opaque to clients.
	sig := sha256.Sum256(append([]byte("signature"), h[:]...))
	signature = base64.StdEncoding.EncodeToString(append(h[:], sig[:]...))
	return "msg_" + x[:24], "toolu_" + x[24:48], "req_" + x[48:64], signature
}

const padSentence = " The change was examined for correctness, security and maintainability."

// ------------------------------------------------------------- handlers

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed", "")
		return
	}
	writeJSON(w, http.StatusOK, "", s.Stats())
}

func (s *Server) authorized(key string) bool {
	ok := 0
	for _, k := range s.keys {
		ok |= subtle.ConstantTimeCompare(k, []byte(key))
	}
	return ok == 1
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	msgID, toolID, reqID, signature := s.newIDs()
	s.count(func(st *Stats) { st.Calls++ })

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.count(func(st *Stats) { st.BadRequests++ })
		writeError(w, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed", reqID)
		return
	}
	keys := r.Header.Values("X-Api-Key")
	if len(keys) != 1 || !s.authorized(keys[0]) {
		s.count(func(st *Stats) { st.AuthFailures++ })
		writeError(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key", reqID)
		return
	}
	if r.Header.Get("Anthropic-Version") == "" {
		s.count(func(st *Stats) { st.BadRequests++ })
		writeError(w, http.StatusBadRequest, "invalid_request_error", "anthropic-version: header is required", reqID)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, _ := strings.Cut(ct, ";")
		if !strings.EqualFold(strings.TrimSpace(mt), "application/json") {
			s.count(func(st *Stats) { st.BadRequests++ })
			writeError(w, http.StatusBadRequest, "invalid_request_error", "content-type must be application/json", reqID)
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	if err != nil {
		s.count(func(st *Stats) { st.BadRequests++ })
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request exceeds the maximum allowed number of bytes", reqID)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request_error", "could not read request body", reqID)
		return
	}
	req, rerr := parseRequest(body, s.models, s.rejectForced)
	if rerr != nil {
		s.count(func(st *Stats) { st.BadRequests++ })
		writeError(w, rerr.status, rerr.typ, rerr.msg, reqID)
		return
	}

	s.mu.Lock()
	verdictFn, latency, faults := s.verdict, s.latency, s.faults
	s.mu.Unlock()

	// Fault selection.
	kind := faults.pick(s.rng.Float64())
	delay := faults.ExtraLatency
	if faults.PHang > 0 && s.rng.Float64() < faults.PHang {
		delay += faults.HangDuration
	}
	switch kind {
	case faultOverloaded, faultServerError:
		if err := sleep(r.Context(), s.done, delay); err != nil {
			s.aborted(w, err, reqID)
			return
		}
		if kind == faultOverloaded {
			s.count(func(st *Stats) { st.Overloaded++ })
			writeError(w, 529, "overloaded_error", "Overloaded", reqID)
		} else {
			s.count(func(st *Stats) { st.ServerErrors++ })
			writeError(w, http.StatusInternalServerError, "api_error", "Internal server error", reqID)
		}
		return
	}

	// Build the response.
	resp := wireResponse{ID: msgID, Type: "message", Role: "assistant", Model: req.Model, Content: []wireBlock{}}
	inTok := EstimateTokens(len(body))
	var outTok int
	var outcome func(st *Stats)
	// Thinking is billed as output although its text is omitted; the mock
	// accounts the signature bytes for it.
	thinkTok := 0
	if s.emitThinking && kind != faultSafetyRefusal {
		empty := ""
		resp.Content = append(resp.Content, wireBlock{Type: "thinking", Thinking: &empty, Signature: signature})
		thinkTok = EstimateTokens(len(signature))
	}
	switch kind {
	case faultSafetyRefusal:
		// Declined by a safety classifier: no content at all.
		cat := "cyber"
		resp.StopReason = "refusal"
		resp.StopDetails = &wireStopDetails{Type: "refusal", Category: &cat,
			Explanation: "The request was declined by a safety classifier (mock)."}
		outTok = 0
		outcome = func(st *Stats) { st.SafetyRefused++ }
	case faultNoToolCall:
		text := "I'm not able to review this change."
		resp.Content = append(resp.Content, wireBlock{Type: "text", Text: &text})
		resp.StopReason = "end_turn"
		outTok = thinkTok + EstimateTokens(len(text))
		if outTok > req.MaxTokens {
			outTok = req.MaxTokens
		}
		outcome = func(st *Stats) { st.NoToolCall++ }
	default:
		v := verdictFn(req)
		in := toolInput{Verdict: "reject", Candidate: req.Candidate, Summary: v.Summary}
		if v.Approve {
			in.Verdict = "approve"
		}
		raw, _ := json.Marshal(in)
		if s.target > 0 {
			if missing := (s.target-thinkTok)*4 - len(raw); missing > 0 {
				n := (missing + len(padSentence) - 1) / len(padSentence)
				in.Summary += strings.Repeat(padSentence, n)
				raw, _ = json.Marshal(in)
			}
		}
		outTok = thinkTok + EstimateTokens(len(raw))
		truncated := kind == faultTruncate
		if outTok > req.MaxTokens {
			// The answer does not fit into max_tokens: the real API
			// stops generating and reports stop_reason "max_tokens".
			truncated = true
			outTok = req.MaxTokens
		} else if truncated {
			outTok = (outTok + 1) / 2
		}
		if truncated {
			// An incomplete tool call: the input never finished, so it
			// carries no verdict.
			resp.Content = append(resp.Content, wireBlock{Type: "tool_use", ID: toolID, Name: req.ToolName, Input: json.RawMessage(`{}`)})
			resp.StopReason = "max_tokens"
			outcome = func(st *Stats) { st.Truncated++ }
		} else {
			resp.Content = append(resp.Content, wireBlock{Type: "tool_use", ID: toolID, Name: req.ToolName, Input: raw})
			resp.StopReason = "tool_use"
			if v.Approve {
				outcome = func(st *Stats) { st.Approved++ }
			} else {
				outcome = func(st *Stats) { st.Rejected++ }
			}
		}
	}
	resp.Usage = wireUsage{InputTokens: inTok, OutputTokens: outTok}

	delay += latency.Sample(s.rng, inTok, outTok)
	if err := sleep(r.Context(), s.done, delay); err != nil {
		// The client went away (or the server is shutting down) before
		// the response was produced; nothing is billed.
		s.aborted(w, err, reqID)
		return
	}
	s.count(func(st *Stats) {
		st.Completed++
		outcome(st)
		st.InputTokens += uint64(inTok)
		st.OutputTokens += uint64(outTok)
		st.SimulatedLatencyNs += uint64(delay)
		m := st.PerModel[req.Model]
		m.Calls++
		m.InputTokens += uint64(inTok)
		m.OutputTokens += uint64(outTok)
		st.PerModel[req.Model] = m
	})
	writeJSON(w, http.StatusOK, reqID, resp)
}

// aborted ends a call whose simulated delay was interrupted. If the
// client is gone nothing can be sent; if the server is shutting down the
// call is answered with 503 (returning from the handler without writing
// would make net/http send an empty 200).
func (s *Server) aborted(w http.ResponseWriter, err error, reqID string) {
	s.count(func(st *Stats) { st.Canceled++ })
	if errors.Is(err, errShuttingDown) {
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusServiceUnavailable, "api_error", "server is shutting down", reqID)
	}
}

// ----------------------------------------------------------- accounting

// ModelStats is the accounting of one model.
type ModelStats struct {
	Calls        uint64  `json:"calls"` // billed (completed) calls
	InputTokens  uint64  `json:"input_tokens"`
	OutputTokens uint64  `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// Stats is the accounting of a provider.
//
// Calls counts every request to /v1/messages. Exactly one of the outcome
// counters is incremented per call:
//
//	Calls = Completed + AuthFailures + BadRequests + Overloaded +
//	        ServerErrors + Canceled           (once all calls have ended)
//	Completed = Approved + Rejected + Truncated + NoToolCall + SafetyRefused
//
// Only Completed calls (HTTP 200) are billed; this includes truncated
// responses and responses without tool call, which a real provider bills
// as well although they are useless to DOSR. A safety refusal is billed
// for its input tokens only (ASSUMPTION of the mock). Tokens are ESTIMATES (bytes/4, see EstimateTokens)
// and the cost follows from the configured price table.
type Stats struct {
	Calls     uint64 `json:"calls"`
	Completed uint64 `json:"completed"`
	Approved  uint64 `json:"approved"`
	Rejected  uint64 `json:"rejected"`
	Truncated uint64 `json:"truncated"`
	// NoToolCall counts plain-text answers (stop_reason "end_turn").
	NoToolCall uint64 `json:"no_tool_call"`
	// SafetyRefused counts responses with stop_reason "refusal".
	SafetyRefused uint64 `json:"safety_refused"`
	AuthFailures  uint64 `json:"auth_failures"`
	BadRequests   uint64 `json:"bad_requests"`
	Overloaded    uint64 `json:"overloaded"`
	ServerErrors  uint64 `json:"server_errors"`
	Canceled      uint64 `json:"canceled"`

	InputTokens  uint64  `json:"input_tokens"`
	OutputTokens uint64  `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	// SimulatedLatencyNs is the sum of the artificial delays of completed
	// calls, in nanoseconds.
	SimulatedLatencyNs uint64 `json:"simulated_latency_ns"`

	PerModel map[string]ModelStats `json:"per_model"`
}

func (s *Server) count(f func(st *Stats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

// Stats returns a snapshot of the accounting.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.PerModel = make(map[string]ModelStats, len(s.stats.PerModel))
	// Sum in a fixed order so that the floating point result is
	// reproducible.
	names := make([]string, 0, len(s.stats.PerModel))
	for m := range s.stats.PerModel {
		names = append(names, m)
	}
	sort.Strings(names)
	out.CostUSD = 0
	for _, m := range names {
		ms := s.stats.PerModel[m]
		p := s.prices[m]
		ms.CostUSD = (float64(ms.InputTokens)*p.InputPerMTok + float64(ms.OutputTokens)*p.OutputPerMTok) / 1e6
		out.PerModel[m] = ms
		out.CostUSD += ms.CostUSD
	}
	return out
}

// ResetStats zeroes the accounting (between experiment runs).
func (s *Server) ResetStats() {
	s.mu.Lock()
	s.stats = Stats{PerModel: map[string]ModelStats{}}
	s.mu.Unlock()
}
