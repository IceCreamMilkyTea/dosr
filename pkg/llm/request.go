package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ReviewTextMagic is the first line of a DOSR review request text.
const ReviewTextMagic = "DOSR-REVIEW-REQUEST v2"

// ReviewToolName is the tool through which a review verdict is returned.
const ReviewToolName = "submit_review"

// ForcedToolChoiceMessage is the error message for a forced tool_choice
// (the message of the real API for models without forced tool use).
const ForcedToolChoiceMessage = `tool_choice: type "tool" and "any" are not supported for this model.`

// Change is one change section of a review request text.
type Change struct {
	// Header is the text after "change i of N: ", i.e.
	// "<status> <path> <oldmode> <newmode> <oldid> <newid>".
	Header string
	// Status is "A", "M" or "D".
	Status string
	// Body is the section body (unified diff hunks or the opaque marker).
	Body string
}

// ReviewRequest is a parsed and validated review request: the fields of
// the Messages API body the mock looks at, plus the parsed DOSR review
// text (format: pkg/review/contract.go).
//
// The parser is written here rather than imported from pkg/review so that
// the mock provider stays an independent implementation of the format.
type ReviewRequest struct {
	Model     string
	MaxTokens int
	System    string
	ToolName  string // the tool the mock calls
	Text      string // content of the first (user) message

	Chain     string
	Repo      string
	Branch    string
	Base      string // 40 hex
	Candidate string // 40 hex
	Policy    string // 64 hex
	Nonce     string // hex, or "-"
	Boundary  string // 32 hex

	CommitMessage string
	Changes       []Change
	// AddedLines are the lines starting with '+' of all change sections,
	// without the '+'.
	AddedLines []string

	// BodyBytes is the size of the HTTP request body.
	BodyBytes int
}

// requestError is a request that the provider answers with HTTP 4xx.
type requestError struct {
	status int
	typ    string
	msg    string
}

func (e *requestError) Error() string { return e.msg }

func badRequest(format string, a ...any) *requestError {
	return &requestError{status: 400, typ: "invalid_request_error", msg: fmt.Sprintf(format, a...)}
}

// wire format of the request body. Unknown top-level keys are rejected
// like the real API does ("Extra inputs are not permitted").
type wireRequest struct {
	Model         *string           `json:"model"`
	MaxTokens     json.RawMessage   `json:"max_tokens"`
	Temperature   json.RawMessage   `json:"temperature"`
	System        json.RawMessage   `json:"system"`
	Tools         []json.RawMessage `json:"tools"`
	ToolChoice    json.RawMessage   `json:"tool_choice"`
	Messages      []wireMessage     `json:"messages"`
	Stream        *bool             `json:"stream"`
	Metadata      json.RawMessage   `json:"metadata"`
	StopSequences []string          `json:"stop_sequences"`
	Fallbacks     json.RawMessage   `json:"fallbacks"`
	// Accepted and ignored by the mock.
	Thinking     json.RawMessage `json:"thinking"`
	OutputConfig json.RawMessage `json:"output_config"`
	ServiceTier  json.RawMessage `json:"service_tier"`
}

type wireMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type wireTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type wireContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// textContent decodes a "string or list of text blocks" value.
func textContent(raw json.RawMessage, what string) (string, *requestError) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", badRequest("%s: field required", what)
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", badRequest("%s: invalid string", what)
		}
		return s, nil
	case '[':
		var blocks []wireContentBlock
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return "", badRequest("%s: invalid content blocks", what)
		}
		var sb strings.Builder
		for i, b := range blocks {
			if b.Type != "text" {
				return "", badRequest("%s.%d.type: the mock provider supports only text blocks", what, i)
			}
			sb.WriteString(b.Text)
		}
		return sb.String(), nil
	}
	return "", badRequest("%s: input should be a string or a list of content blocks", what)
}

// parseRequest validates the body of a Messages API call and parses the
// review text. models is the set of known model identifiers.
func parseRequest(body []byte, models map[string]bool, rejectForced bool) (*ReviewRequest, *requestError) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var w wireRequest
	if err := dec.Decode(&w); err != nil {
		return nil, badRequest("invalid request body: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, badRequest("invalid request body: trailing data")
	}
	if w.Model == nil || *w.Model == "" {
		return nil, badRequest("model: field required")
	}
	if !models[*w.Model] {
		return nil, &requestError{status: 404, typ: "not_found_error", msg: "model: " + *w.Model}
	}
	if len(w.MaxTokens) == 0 {
		return nil, badRequest("max_tokens: field required")
	}
	// Parsed by hand: encoding/json would also accept the quoted form
	// "1024" for a json.Number.
	maxTokens, err := strconv.Atoi(string(w.MaxTokens))
	if err != nil || maxTokens < 1 {
		return nil, badRequest("max_tokens: input should be an integer greater than or equal to 1")
	}
	if len(w.Temperature) != 0 {
		// Current models accept only the default temperature; the
		// canonical DOSR request does not send the key at all.
		if t, err := strconv.ParseFloat(string(w.Temperature), 64); err != nil || t != 1 {
			return nil, badRequest("temperature: this model only supports the default value 1")
		}
	}
	if len(w.Fallbacks) != 0 {
		// A fallback model could answer instead of the requested one;
		// DOSR requests never carry the field.
		return nil, badRequest("fallbacks: the mock provider does not accept fallbacks")
	}
	if w.Stream != nil && *w.Stream {
		return nil, badRequest("stream: the mock provider does not support streaming")
	}
	system := ""
	if len(bytes.TrimSpace(w.System)) > 0 && !bytes.Equal(bytes.TrimSpace(w.System), []byte("null")) {
		s, rerr := textContent(w.System, "system")
		if rerr != nil {
			return nil, rerr
		}
		system = s
	}
	if len(w.Messages) == 0 {
		return nil, badRequest("messages: at least one message is required")
	}
	for i, m := range w.Messages {
		if m.Role != "user" && m.Role != "assistant" {
			return nil, badRequest("messages.%d.role: input should be 'user' or 'assistant'", i)
		}
	}
	if w.Messages[0].Role != "user" {
		return nil, badRequest("messages.0.role: first message must use the user role")
	}
	if len(w.Messages) != 1 {
		return nil, badRequest("messages: the mock provider expects exactly one user message")
	}
	text, rerr := textContent(w.Messages[0].Content, "messages.0.content")
	if rerr != nil {
		return nil, rerr
	}
	if len(w.Tools) == 0 {
		return nil, badRequest("tools: field required (DOSR reviews answer through the submit_review tool)")
	}
	toolNames := map[string]bool{}
	firstTool := ""
	for i, raw := range w.Tools {
		var t wireTool
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, badRequest("tools.%d: invalid tool definition", i)
		}
		if t.Name == "" {
			return nil, badRequest("tools.%d.name: field required", i)
		}
		var schema map[string]json.RawMessage
		if err := json.Unmarshal(t.InputSchema, &schema); err != nil || schema == nil {
			return nil, badRequest("tools.%d.input_schema: field required", i)
		}
		if toolNames[t.Name] {
			return nil, badRequest("tools: tool names must be unique")
		}
		toolNames[t.Name] = true
		if firstTool == "" {
			firstTool = t.Name
		}
	}
	// tool_choice. Current models reject forced tool use; the canonical
	// DOSR request uses {"type":"auto"} (also the API default when the
	// field is absent).
	tc := struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}{Type: "auto"}
	if len(w.ToolChoice) != 0 {
		tc.Type = ""
		if err := json.Unmarshal(w.ToolChoice, &tc); err != nil {
			return nil, badRequest("tool_choice: invalid value")
		}
	}
	toolName := ""
	switch tc.Type {
	case "auto":
		// The model decides; the mock "decides" to call the review
		// tool, or the first tool if there is no submit_review.
		toolName = firstTool
		if toolNames[ReviewToolName] {
			toolName = ReviewToolName
		}
	case "tool", "any":
		if rejectForced {
			return nil, badRequest(ForcedToolChoiceMessage)
		}
		toolName = firstTool
		if tc.Type == "tool" {
			if !toolNames[tc.Name] {
				return nil, badRequest("tool_choice: tool %q not found in tools", tc.Name)
			}
			toolName = tc.Name
		}
	default:
		return nil, badRequest("tool_choice.type: the mock provider supports 'auto' (and 'tool'/'any' if configured)")
	}
	r := &ReviewRequest{Model: *w.Model, MaxTokens: maxTokens, System: system,
		ToolName: toolName, Text: text, BodyBytes: len(body)}
	if err := parseReviewText(r, text); err != nil {
		return nil, badRequest("messages.0.content: not a DOSR review request: %v", err)
	}
	return r, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseReviewText parses a DOSR review request text.
func ParseReviewText(text string) (*ReviewRequest, error) {
	r := &ReviewRequest{Text: text}
	if err := parseReviewText(r, text); err != nil {
		return nil, err
	}
	return r, nil
}

// parseReviewText parses the DOSR review text into r.
//
// Only the header block (the lines before the first blank line) and the
// section markers carrying the header's boundary are structure;
// everything else is content under review and never interpreted.
func parseReviewText(r *ReviewRequest, text string) error {
	rest := text
	next := func() (string, bool) {
		if rest == "" {
			return "", false
		}
		i := strings.IndexByte(rest, '\n')
		if i < 0 {
			l := rest
			rest = ""
			return l, true
		}
		l := rest[:i]
		rest = rest[i+1:]
		return l, true
	}
	l, ok := next()
	if !ok || l != ReviewTextMagic {
		return errors.New("missing magic line")
	}
	var changes string
	for _, f := range []struct {
		key string
		dst *string
	}{{"chain", &r.Chain}, {"repo", &r.Repo}, {"branch", &r.Branch}, {"base", &r.Base},
		{"candidate", &r.Candidate}, {"policy", &r.Policy}, {"nonce", &r.Nonce},
		{"changes", &changes}, {"boundary", &r.Boundary}} {
		l, ok := next()
		if !ok || !strings.HasPrefix(l, f.key+": ") {
			return fmt.Errorf("header line %q missing or out of order", f.key)
		}
		*f.dst = l[len(f.key)+2:]
	}
	if l, ok := next(); !ok || l != "" {
		return errors.New("header is not followed by a blank line")
	}
	if !isLowerHex(r.Base, 40) || !isLowerHex(r.Candidate, 40) {
		return errors.New("base and candidate must be 40 hex digits")
	}
	if !isLowerHex(r.Policy, 64) {
		return errors.New("policy must be 64 hex digits")
	}
	if r.Nonce != "-" && (r.Nonce == "" || len(r.Nonce)%2 != 0 || !isLowerHex(r.Nonce, len(r.Nonce))) {
		return errors.New("nonce must be hex or \"-\"")
	}
	if !isLowerHex(r.Boundary, 32) {
		return errors.New("boundary must be 32 hex digits")
	}
	n, err := strconv.Atoi(changes)
	if err != nil || n < 1 || strconv.Itoa(n) != changes {
		return errors.New("bad number of changes")
	}

	marker := "--" + r.Boundary + "-- "
	// Sections. state: 0 = expecting commit-message marker, 1 = in commit
	// message, 2 = in change, 3 = after end.
	state := 0
	var body strings.Builder
	var cur *Change
	flush := func() {
		b := body.String()
		body.Reset()
		switch state {
		case 1:
			r.CommitMessage = b
		case 2:
			cur.Body = b
			r.Changes = append(r.Changes, *cur)
		}
	}
	for {
		l, ok := next()
		if !ok {
			break
		}
		if state == 3 {
			return errors.New("text after the end marker")
		}
		if !strings.HasPrefix(l, marker) {
			if state == 0 {
				return errors.New("missing commit-message section")
			}
			body.WriteString(l)
			body.WriteByte('\n')
			if state == 2 && strings.HasPrefix(l, "+") {
				r.AddedLines = append(r.AddedLines, l[1:])
			}
			continue
		}
		title := l[len(marker):]
		switch {
		case title == "commit-message":
			if state != 0 {
				return errors.New("duplicate commit-message section")
			}
			state = 1
		case title == "end":
			if state == 0 {
				return errors.New("missing commit-message section")
			}
			flush()
			state = 3
		case strings.HasPrefix(title, "change "):
			if state == 0 {
				return errors.New("missing commit-message section")
			}
			flush()
			want := fmt.Sprintf("change %d of %d: ", len(r.Changes)+1, n)
			if !strings.HasPrefix(title, want) {
				return fmt.Errorf("bad change section title %q", title)
			}
			hdr := title[len(want):]
			st, _, _ := strings.Cut(hdr, " ")
			if st != "A" && st != "M" && st != "D" {
				return fmt.Errorf("bad change status %q", st)
			}
			cur = &Change{Header: hdr, Status: st}
			state = 2
		default:
			return fmt.Errorf("unknown section %q", title)
		}
	}
	if state != 3 {
		return errors.New("missing end marker")
	}
	if len(r.Changes) != n {
		return fmt.Errorf("header announces %d changes, text has %d", n, len(r.Changes))
	}
	return nil
}
