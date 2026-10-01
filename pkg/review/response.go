package review

import (
	"fmt"

	"github.com/dosr/dosr/pkg/gitobj"
)

// MaxResponseBytes bounds the response body ParseResponse accepts. A
// verdict is a few hundred bytes; the bound keeps the cost of parsing a
// hostile body small and fixed.
const MaxResponseBytes = 1 << 20

// ParseResponse strictly parses a Messages API response body.
//
// Accepted: a JSON object with "type":"message", "role":"assistant",
// "stop_reason":"tool_use", a string "model", and a "content" array that
// contains exactly one tool_use block, named submit_review. Blocks of type
// "text", "thinking" and "redacted_thinking" are ignored wherever they
// occur (models on which thinking is always on emit them). The tool input
// must be an object with exactly the members verdict ("approve" or
// "reject"), candidate (40 lowercase hex) and summary (string), in any
// order. Unknown members of the top-level object and of content blocks
// (id, usage, stop_sequence, signature, ...) are ignored.
//
// Everything else yields ErrResponse, in particular: every other
// stop_reason ("max_tokens", "refusal", "end_turn", "pause_turn", ...), a
// second tool call, any other block type (server_tool_use, ...), unknown
// verdict strings, extra members in the tool input, duplicate object keys
// anywhere, invalid UTF-8 and bodies above MaxResponseBytes.
//
// The request no longer forces the tool call (tool_choice is "auto"), so
// a model may answer in prose. That is deliberately NOT an approval: such
// a response has stop_reason "end_turn" and no tool_use block.
//
// Fail-closed rationale: the verdict gates what enters a repository. When
// the response is anything but the one unambiguous shape, the safe
// interpretation is "no approval".
func ParseResponse(body []byte) (*Verdict, error) {
	if len(body) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: body is %d bytes, limit %d", ErrResponse, len(body), MaxResponseBytes)
	}
	root, err := parseJSON(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrResponse, err)
	}
	if root.kind != jObject {
		return nil, fmt.Errorf("%w: body is not an object", ErrResponse)
	}
	if s, ok := root.getString("type"); !ok || s != "message" {
		return nil, fmt.Errorf("%w: type is not \"message\"", ErrResponse)
	}
	if s, ok := root.getString("role"); !ok || s != "assistant" {
		return nil, fmt.Errorf("%w: role is not \"assistant\"", ErrResponse)
	}
	v := &Verdict{}
	var ok bool
	if v.Model, ok = root.getString("model"); !ok || v.Model == "" {
		return nil, fmt.Errorf("%w: missing model", ErrResponse)
	}
	if v.StopReason, ok = root.getString("stop_reason"); !ok {
		return nil, fmt.Errorf("%w: missing stop_reason", ErrResponse)
	}
	if v.StopReason != "tool_use" {
		return nil, fmt.Errorf("%w: stop_reason %q", ErrResponse, v.StopReason)
	}
	content := root.get("content")
	if content == nil || content.kind != jArray {
		return nil, fmt.Errorf("%w: content is not an array", ErrResponse)
	}
	var input *jvalue
	for i, blk := range content.arr {
		t, ok := blk.getString("type")
		if !ok {
			return nil, fmt.Errorf("%w: content block %d has no type", ErrResponse, i)
		}
		switch t {
		case "text", "thinking", "redacted_thinking":
			// Ignored. Their content is model prose and never
			// interpreted; only the tool input carries the verdict.
		case "tool_use":
			if input != nil {
				return nil, fmt.Errorf("%w: more than one tool call", ErrResponse)
			}
			if name, ok := blk.getString("name"); !ok || name != ToolName {
				return nil, fmt.Errorf("%w: tool call is not %s", ErrResponse, ToolName)
			}
			input = blk.get("input")
			if input == nil || input.kind != jObject {
				return nil, fmt.Errorf("%w: tool input is not an object", ErrResponse)
			}
		default:
			return nil, fmt.Errorf("%w: content block %d has type %q", ErrResponse, i, t)
		}
	}
	if input == nil {
		return nil, fmt.Errorf("%w: no tool call", ErrResponse)
	}
	if len(input.obj) != 3 {
		return nil, fmt.Errorf("%w: tool input must have exactly verdict, candidate and summary", ErrResponse)
	}
	verdict, ok := input.getString("verdict")
	if !ok {
		return nil, fmt.Errorf("%w: missing verdict", ErrResponse)
	}
	switch verdict {
	case "approve":
		v.Approve = true
	case "reject":
		v.Approve = false
	default:
		return nil, fmt.Errorf("%w: unknown verdict %q", ErrResponse, verdict)
	}
	cand, ok := input.getString("candidate")
	if !ok {
		return nil, fmt.Errorf("%w: missing candidate", ErrResponse)
	}
	if v.Candidate, err = gitobj.ParseID(cand); err != nil {
		return nil, fmt.Errorf("%w: candidate: %s", ErrResponse, err)
	}
	if v.Summary, ok = input.getString("summary"); !ok {
		return nil, fmt.Errorf("%w: missing summary", ErrResponse)
	}
	return v, nil
}
