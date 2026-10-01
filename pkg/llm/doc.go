// Package llm implements a MOCK LLM provider that speaks the subset of the
// Anthropic Messages API which DOSR uses (POST /v1/messages with a forced
// tool call), over HTTPS.
//
// It exists so that the contributor client, the notary and the validators
// can be tested and benchmarked without a real provider and without
// spending money, and so that provider behaviour which matters for the
// evaluation can be CONTROLLED:
//
//   - the verdict (deterministic marker-based, random, or a composition),
//   - the latency (a parametric model with a seeded random generator),
//   - faults (overload, server errors, truncation, refusals, hangs),
//   - accounting of calls, tokens and cost (what the cost evaluation reads).
//
// Everything about the model's behaviour here is a MODELLING ASSUMPTION,
// not a measurement of any real model: token counts are estimated as
// bytes/4, latency parameters and prices are plausible placeholders that
// the evaluation must state explicitly. The mock does not try to judge
// code; MarkerVerdict merely lets tests decide which commits "the LLM"
// rejects.
//
// The server holds no global state; several servers can run in one
// process. All methods are safe for concurrent use.
package llm
