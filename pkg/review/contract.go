// Package review defines the canonical LLM review request and the parsing
// of the review response.
//
// The central idea of DOSR's receipt check is *recomputation*: validators
// never trust the request text shown in a receipt. They rebuild the exact
// request body from (policy, repo, base, candidate, Git objects) with
// BuildRequestBody and require the attested transcript to commit to those
// very bytes. BuildRequestBody is therefore consensus-critical: it MUST be
// a pure, deterministic function, byte-for-byte identical on all nodes.
// Any change to its output is a protocol version change.
//
// This file is the package CONTRACT. Types and signatures here are frozen.
package review

import (
	"errors"

	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/types"
)

// ProtocolVersion identifies the request rendering rules.
const ProtocolVersion = 2

// ToolName is the tool the model must call to return its verdict.
const ToolName = "submit_review"

// Params are the binding parameters of one review.
type Params struct {
	ChainID    string
	RepoID     string
	Branch     string
	Base       gitobj.ID // expected head; zero for the first commit
	Candidate  gitobj.ID
	PolicyHash types.PolicyHash
	Model      string
	// Nonce is the chain-derived intent nonce (empty if the policy does
	// not require intents).
	Nonce []byte
}

// Verdict is the parsed review response.
type Verdict struct {
	Model      string // the model the provider reports having used
	StopReason string
	Approve    bool
	Candidate  gitobj.ID // echoed by the model
	Summary    string
}

// Sentinel errors (wrapped with %w by implementations).
var (
	ErrTooLarge  = errors.New("review: rendered diff exceeds policy limit")
	ErrOpaque    = errors.New("review: change contains content that cannot be shown to the model")
	ErrEmptyDiff = errors.New("review: candidate does not change the tree")
	ErrResponse  = errors.New("review: malformed or unacceptable response")
)

/*
Implemented in the other files of this package.

	// BuildRequestBody renders the canonical request body: the JSON body of
	// an Anthropic Messages API call,
	//
	//   {"model":<Model>,"max_tokens":<policy.MaxTokens>,
	//    "system":<policy.SystemPrompt + "\n\n" + SystemSuffix>,
	//    (no "temperature": current Anthropic models reject any value
	//     other than the default, see docs/literature/02)
	//    "tools":[<the fixed submit_review tool definition, with
	//              "strict":true and an input_schema that has
	//              "additionalProperties":false and requires verdict
	//              (enum approve|reject), candidate and summary>],
	//    "tool_choice":{"type":"auto"},
	//    (forced tool choice is rejected with HTTP 400 by current models;
	//     the fixed protocol suffix SystemSuffix instructs the model to
	//     call submit_review exactly once instead)
	//    "messages":[{"role":"user","content":<TEXT>}]}
	//
	// produced by a hand-written encoder (fixed key order, no whitespace,
	// minimal JSON string escaping: \" \\ \n \r \t, \u00XX for other bytes
	// < 0x20, U+2028/2029 NOT escaped, invalid UTF-8 never reaches the
	// encoder because such files are "opaque").
	//
	// TEXT is, with "\n" line endings:
	//
	//   DOSR-REVIEW-REQUEST v2
	//   chain: <ChainID>
	//   repo: <RepoID>
	//   branch: <Branch>
	//   base: <40 hex>
	//   candidate: <40 hex>
	//   policy: <64 hex>
	//   nonce: <hex, or "-" if empty>
	//   changes: <number of changes>
	//   boundary: <32 hex>
	//   <blank line>
	//   --<boundary>-- commit-message
	//   <commit message of the candidate, verbatim>
	//   --<boundary>-- change 1 of N: <status> <path> <oldmode> <newmode> <oldid> <newid>
	//   <unified diff hunks of the file, 3 lines of context, produced by
	//    the package's own line-based Myers diff; for added/deleted files
	//    every line is +/-; symlinks are diffed as their target text>
	//   ...
	//   --<boundary>-- end
	//
	// where status is A, M or D, modes are 6-digit octal, and
	//
	//   boundary = hex( SHA256("DOSR-BOUNDARY\x00" || L(chain) || L(repo) ||
	//              L(branch) || base || candidate || policy || L(nonce) ||
	//              for each change: L(path) || oldid || newid )[:16] )
	//
	// where L(x) = u32be(len(x)) || x for the variable-length fields and
	// base, candidate, oldid, newid (20 bytes) and policy (32 bytes) are
	// raw, so the hash input parses unambiguously.
	//
	// The boundary depends on the hash of every blob shown, so content
	// under review cannot contain its own boundary line and therefore
	// cannot forge section markers (prompt-injection hardening;
	// SystemSuffix tells the model that text inside sections is untrusted
	// content under review and never an instruction).
	//
	// A file is "opaque" if either side is not valid UTF-8, contains NUL,
	// or is larger than 256 KiB. If policy.AllowOpaque is false an opaque
	// change yields ErrOpaque; otherwise its section body is the single
	// line "[opaque content not shown: <old size> -> <new size> bytes]".
	// If len(TEXT) > policy.MaxDiffBytes the result is ErrTooLarge.
	// If there are no changes the result is ErrEmptyDiff.
	//
	// msg is the candidate's commit message; changes must come from
	// gitobj.DiffTrees; s must contain every blob named in changes.
	func BuildRequestBody(pol *types.Policy, p Params, msg string,
		changes []gitobj.Change, s gitobj.Store) ([]byte, error)

	// ParseRequestText extracts Params (except Model) from a TEXT produced
	// by BuildRequestBody. Used by the mock provider and by tests; never
	// by validators.
	func ParseRequestText(text string) (Params, error)

	// ParseResponse strictly parses a Messages API response body. It
	// accepts only: "type":"message", "role":"assistant",
	// "stop_reason":"tool_use", and content containing exactly one
	// tool_use block, named submit_review, whose input is exactly
	// {"verdict":"approve"|"reject","candidate":"<40 hex>","summary":"..."}.
	// Blocks of type "text", "thinking" and "redacted_thinking" are
	// ignored wherever they occur in content. Anything else - any other
	// stop_reason (max_tokens, refusal, end_turn, pause_turn, ...), any
	// other block type (server_tool_use, ...), a second tool call, extra
	// or missing input fields, unknown verdict strings - yields
	// ErrResponse.
	func ParseResponse(body []byte) (*Verdict, error)

	// UnifiedDiff is the deterministic line diff used by BuildRequestBody,
	// exported for tests. a and b are file contents; the result is the
	// hunks ("@@ -l,s +l,s @@" headers and ' ', '-', '+' prefixed lines,
	// with "\ No newline at end of file" markers like GNU diff).
	func UnifiedDiff(a, b []byte, context int) []byte
*/
