package llm

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// ------------------------------------------------------------------ Rand

// Rand is a seeded pseudo-random generator that is safe for concurrent
// use. It makes experiments reproducible: with the same seed and the same
// SEQUENCE of calls the same values are drawn. (With concurrent requests
// the assignment of draws to requests depends on scheduling; the
// distribution does not.) Not cryptographically secure.
type Rand struct {
	mu sync.Mutex
	r  *rand.Rand
}

// NewRand returns a generator seeded with seed.
func NewRand(seed int64) *Rand { return &Rand{r: rand.New(rand.NewSource(seed))} }

// Float64 returns a uniform value in [0,1).
func (r *Rand) Float64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Float64()
}

// NormFloat64 returns a standard normal value.
func (r *Rand) NormFloat64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.NormFloat64()
}

// --------------------------------------------------------------- Verdict

// RejectMarker is the string that makes MarkerVerdict reject a change.
const RejectMarker = "DOSR-REJECT-ME"

// Verdict is the outcome the mock model reports.
type Verdict struct {
	Approve bool
	Summary string
}

// VerdictFunc decides the verdict for one (valid, authenticated) review
// request. It must be safe for concurrent use.
type VerdictFunc func(r *ReviewRequest) Verdict

// MarkerVerdict rejects iff any ADDED line of any change (a line starting
// with '+' inside a change section) contains RejectMarker, and approves
// otherwise. It models "the LLM catches bad code" deterministically.
// Occurrences of the marker in the commit message, in removed or context
// lines, or in file paths do not count.
func MarkerVerdict(r *ReviewRequest) Verdict {
	for _, l := range r.AddedLines {
		if strings.Contains(l, RejectMarker) {
			return Verdict{Approve: false, Summary: "Rejected: an added line contains the marker " + RejectMarker + "."}
		}
	}
	return Verdict{Approve: true, Summary: "Approved: no problems found in the change."}
}

// BernoulliVerdict approves with probability pApprove, independently for
// every call, regardless of content. It models the non-determinism of an
// LLM reviewer and is used to study approval grinding (re-asking until
// the answer is "approve"). pApprove is clamped to [0,1].
func BernoulliVerdict(pApprove float64, rng *Rand) VerdictFunc {
	if rng == nil {
		rng = NewRand(1)
	}
	return func(*ReviewRequest) Verdict {
		if rng.Float64() < pApprove {
			return Verdict{Approve: true, Summary: "Approved (random verdict)."}
		}
		return Verdict{Approve: false, Summary: "Rejected (random verdict)."}
	}
}

// MarkerThenBernoulli is the composition: a change containing the marker
// is always rejected; any other change is approved with probability
// pApprove.
func MarkerThenBernoulli(pApprove float64, rng *Rand) VerdictFunc {
	b := BernoulliVerdict(pApprove, rng)
	return func(r *ReviewRequest) Verdict {
		if v := MarkerVerdict(r); !v.Approve {
			return v
		}
		return b(r)
	}
}

// --------------------------------------------------------------- Latency

// LatencyModel is a parametric model of the response time of a
// non-streaming Messages API call:
//
//	latency = ttft + output_tokens / TokensPerSec + input_tokens * PerInputToken
//
// where ttft ("time to first token") is lognormal(mu, sigma) with
// mu = ln(TTFTMedian in seconds) and sigma = TTFTSigma. A zero TTFTMedian
// means no ttft term, a zero TokensPerSec no generation term. The zero
// LatencyModel is LatencyNone.
type LatencyModel struct {
	// TTFTMedian is the median time to first token, exp(mu).
	TTFTMedian time.Duration
	// TTFTSigma is the sigma of the lognormal distribution (of ln seconds).
	TTFTSigma float64
	// TokensPerSec is the output generation speed.
	TokensPerSec float64
	// PerInputToken is the prompt processing time per input token.
	PerInputToken time.Duration
	// Max caps the sampled latency (0 = DefaultMaxLatency); it protects
	// experiments from the unbounded tail of the lognormal distribution.
	Max time.Duration
}

// DefaultMaxLatency caps sampled latencies of models without their own cap.
const DefaultMaxLatency = 2 * time.Minute

// Latency presets.
//
// IMPORTANT: the numbers below are ASSUMED MODELLING PARAMETERS chosen to
// be plausible; they are NOT measurements of any provider or model. Any
// figure in the evaluation derived from them must say so.
var (
	// LatencyNone adds no latency. Use it in tests.
	LatencyNone = LatencyModel{}

	// LatencyFast: a few hundred milliseconds per call, for integration
	// tests and quick experiments that still want non-zero, variable
	// provider latency. ASSUMED: median ttft 150 ms (sigma 0.25),
	// 2000 output tokens/s, 2 us per input token.
	// A call with 300 output and 10k input tokens takes about
	// 0.15 + 0.15 + 0.02 = 0.32 s at the median.
	LatencyFast = LatencyModel{
		TTFTMedian:    150 * time.Millisecond,
		TTFTSigma:     0.25,
		TokensPerSec:  2000,
		PerInputToken: 2 * time.Microsecond,
		Max:           5 * time.Second,
	}

	// LatencyRealistic: several seconds per call. ASSUMED parameters for
	// "a current frontier model answering a code review with roughly 300
	// output tokens": median ttft 1.2 s (sigma 0.4, i.e. p95 of about
	// 2.3 s), 60 output tokens/s, 50 us per input token (0.5 s per 10k
	// input tokens). A call with 300 output and 10k input tokens takes
	// about 1.2 + 5.0 + 0.5 = 6.7 s at the median.
	LatencyRealistic = LatencyModel{
		TTFTMedian:    1200 * time.Millisecond,
		TTFTSigma:     0.4,
		TokensPerSec:  60,
		PerInputToken: 50 * time.Microsecond,
		Max:           60 * time.Second,
	}
)

// Sample draws the latency of a call with the given token counts.
func (m LatencyModel) Sample(rng *Rand, inputTokens, outputTokens int) time.Duration {
	var sec float64
	if m.TTFTMedian > 0 {
		// exp(mu + sigma*z) with mu = ln(median), written as
		// median * exp(sigma*z) so that sigma = 0 gives the median exactly.
		z := 0.0
		if m.TTFTSigma > 0 && rng != nil {
			z = rng.NormFloat64()
		}
		sec += m.TTFTMedian.Seconds() * math.Exp(m.TTFTSigma*z)
	}
	if m.TokensPerSec > 0 && outputTokens > 0 {
		sec += float64(outputTokens) / m.TokensPerSec
	}
	if m.PerInputToken > 0 && inputTokens > 0 {
		sec += float64(inputTokens) * m.PerInputToken.Seconds()
	}
	max := m.Max
	if max <= 0 {
		max = DefaultMaxLatency
	}
	if math.IsNaN(sec) || sec < 0 {
		return 0
	}
	if sec > max.Seconds() {
		return max
	}
	return time.Duration(math.Round(sec * float64(time.Second)))
}

func (m LatencyModel) validate() error {
	if m.TTFTMedian < 0 || m.PerInputToken < 0 || m.Max < 0 || m.TTFTSigma < 0 || m.TokensPerSec < 0 ||
		math.IsNaN(m.TTFTSigma) || math.IsNaN(m.TokensPerSec) || math.IsInf(m.TTFTSigma, 0) {
		return errors.New("llm: latency model parameters must be finite and non-negative")
	}
	return nil
}

var errShuttingDown = errors.New("llm: server shutting down")

// sleep waits for d or until ctx is cancelled or done is closed.
func sleep(ctx context.Context, done <-chan struct{}, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return errShuttingDown
	}
}

// ---------------------------------------------------------------- Faults

// Faults configures fault injection. The P* fields are probabilities in
// [0,1]. For every valid, authenticated call ONE uniform number selects at
// most one of the mutually exclusive response faults (overloaded, server
// error, truncation, no tool call, safety refusal), so their probabilities
// must sum to at most 1. The hang is drawn independently and delays whatever response follows.
type Faults struct {
	// POverloaded: respond HTTP 529 with an overloaded_error.
	POverloaded float64
	// PServerError: respond HTTP 500 with an api_error.
	PServerError float64
	// PTruncate: respond 200 with stop_reason "max_tokens" and an
	// incomplete tool call (the verdict is NOT usable).
	PTruncate float64
	// PNoToolCall: respond 200 with plain text and stop_reason "end_turn"
	// WITHOUT calling the tool. With tool_choice "auto" nothing forces a
	// model to call the tool; it may answer (or decline) in prose.
	PNoToolCall float64
	// PRefusal is a deprecated alias of PNoToolCall (the two are the same
	// response); the probabilities are added.
	PRefusal float64
	// PSafetyRefusal: respond 200 with stop_reason "refusal", empty
	// content and a stop_details object, as the provider's safety
	// classifiers do when they decline a request.
	PSafetyRefusal float64
	// PHang: delay the response by HangDuration (in addition to the
	// latency model).
	PHang        float64
	HangDuration time.Duration
	// ExtraLatency is added to every call.
	ExtraLatency time.Duration
}

func (f Faults) validate() error {
	sum := 0.0
	for _, p := range []float64{f.POverloaded, f.PServerError, f.PTruncate, f.PRefusal, f.PNoToolCall, f.PSafetyRefusal, f.PHang} {
		if math.IsNaN(p) || p < 0 || p > 1 {
			return errors.New("llm: fault probabilities must be in [0,1]")
		}
	}
	sum = f.POverloaded + f.PServerError + f.PTruncate + f.PRefusal + f.PNoToolCall + f.PSafetyRefusal
	if sum > 1+1e-9 {
		return errors.New("llm: probabilities of response faults sum to more than 1")
	}
	if f.HangDuration < 0 || f.ExtraLatency < 0 {
		return errors.New("llm: negative fault duration")
	}
	return nil
}

type faultKind int

const (
	faultNone faultKind = iota
	faultOverloaded
	faultServerError
	faultTruncate
	faultNoToolCall
	faultSafetyRefusal
)

// pick maps a uniform u in [0,1) to a response fault.
func (f Faults) pick(u float64) faultKind {
	for _, c := range []struct {
		p float64
		k faultKind
	}{{f.POverloaded, faultOverloaded}, {f.PServerError, faultServerError},
		{f.PTruncate, faultTruncate}, {f.PNoToolCall + f.PRefusal, faultNoToolCall},
		{f.PSafetyRefusal, faultSafetyRefusal}} {
		if u < c.p {
			return c.k
		}
		u -= c.p
	}
	return faultNone
}

// ----------------------------------------------------------------- Price

// Price is the price of a model in USD per million tokens.
type Price struct {
	InputPerMTok  float64 `json:"input_per_mtok"`
	OutputPerMTok float64 `json:"output_per_mtok"`
}

// Default model identifiers and prices of the mock.
//
// ASSUMED values for the evaluation (list-price style figures in USD per
// million tokens); they are configuration, not facts about any provider.
// Set Config.Models / Config.Prices to whatever the experiment states.
const (
	ModelLarge  = "mock-reviewer-large"
	ModelMedium = "mock-reviewer-medium"
	ModelSmall  = "mock-reviewer-small"
)

// DefaultPrices returns a fresh copy of the default price table.
func DefaultPrices() map[string]Price {
	return map[string]Price{
		ModelLarge:  {InputPerMTok: 15, OutputPerMTok: 75},
		ModelMedium: {InputPerMTok: 3, OutputPerMTok: 15},
		ModelSmall:  {InputPerMTok: 1, OutputPerMTok: 5},
	}
}

// EstimateTokens estimates the number of tokens of n bytes of text as
// ceil(n/4). This is a crude APPROXIMATION (a common rule of thumb for
// English text and code), not a tokenizer.
func EstimateTokens(nBytes int) int {
	if nBytes <= 0 {
		return 0
	}
	return (nBytes + 3) / 4
}
