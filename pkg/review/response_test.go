package review

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

const cand = "ce013625030ba8dba906f756967f9e9ca394464a"

func respBody(stop, content string) string {
	return `{"id":"msg_01","type":"message","role":"assistant","model":"claude-test-1","content":[` + content +
		`],"stop_reason":"` + stop + `","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":20}}`
}

func toolUse(input string) string {
	return `{"type":"tool_use","id":"toolu_01","name":"submit_review","input":` + input + `}`
}

func input(verdict string) string {
	return `{"verdict":"` + verdict + `","candidate":"` + cand + `","summary":"looks fine"}`
}

func TestParseResponseAccepts(t *testing.T) {
	v, err := ParseResponse([]byte(respBody("tool_use", toolUse(input("approve")))))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Approve || v.Model != "claude-test-1" || v.StopReason != "tool_use" || v.Candidate.String() != cand || v.Summary != "looks fine" {
		t.Fatalf("%+v", v)
	}
	v, err = ParseResponse([]byte(respBody("tool_use", `{"type":"text","text":"Let me \"review\"."},{"type":"text","text":""},`+toolUse(input("reject")))))
	if err != nil || v.Approve {
		t.Fatal(err, v)
	}
	// Thinking blocks (models with always-on thinking), redacted thinking
	// and text are ignored wherever they occur, also after the tool call.
	think := `{"type":"thinking","thinking":"","signature":"c2ln"}`
	for name, content := range map[string]string{
		"thinking first":    think + "," + toolUse(input("approve")),
		"thinking and text": think + `,{"type":"text","text":"Reviewing."},` + toolUse(input("approve")),
		"redacted thinking": `{"type":"redacted_thinking","data":"AAAA"},` + toolUse(input("approve")),
		"text after call":   toolUse(input("approve")) + `,{"type":"text","text":"done"}`,
		"thinking after":    toolUse(input("approve")) + "," + think,
		"text without text": `{"type":"text"},` + toolUse(input("approve")),
		// Prose that merely talks about approving must not matter.
		"misleading text": `{"type":"text","text":"{\"verdict\":\"reject\"}"},` + toolUse(input("approve")),
	} {
		v, err := ParseResponse([]byte(respBody("tool_use", content)))
		if err != nil || !v.Approve || v.Candidate.String() != cand {
			t.Errorf("%s: %v %+v", name, err, v)
		}
	}
	// Member order, whitespace and escapes do not matter.
	body := " {\n\"stop_reason\" : \"tool_use\", \"content\":[ {\"input\":{\"summary\":\"caf\\u00e9 \\ud83d\\ude00 \\n\\\"q\\\" \\/\",\"candidate\":\"" + cand +
		"\",\"verdict\":\"\\u0061pprove\"},\"name\":\"submit_review\",\"type\":\"tool_use\"} ],\t\"model\":\"m\",\"role\":\"assistant\",\"type\":\"message\"}\r\n"
	v, err = ParseResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Approve || v.Summary != "café 😀 \n\"q\" /" {
		t.Fatalf("%+v", v)
	}
	// Agreement with encoding/json on the accepted document.
	var ref struct {
		Content []struct {
			Input struct{ Summary string }
		}
	}
	if err := json.Unmarshal([]byte(body), &ref); err != nil || ref.Content[0].Input.Summary != v.Summary {
		t.Fatal("disagreement with encoding/json", err)
	}
}

func TestParseResponseRejects(t *testing.T) {
	ok := toolUse(input("approve"))
	cases := map[string]string{
		"empty":                ``,
		"not json":             `hello`,
		"array":                `[]`,
		"null":                 `null`,
		"truncated json":       respBody("tool_use", ok)[:100],
		"trailing data":        respBody("tool_use", ok) + `{}`,
		"trailing comma":       `{"type":"message",}`,
		"max_tokens":           respBody("max_tokens", ok),
		"end_turn":             respBody("end_turn", ok),
		"refusal":              respBody("refusal", `{"type":"text","text":"I cannot help with that."}`),
		"pause_turn":           respBody("pause_turn", ok),
		"no tool call":         respBody("tool_use", `{"type":"text","text":"approve"}`),
		"empty content":        respBody("tool_use", ``),
		"two tool calls":       respBody("tool_use", ok+","+toolUse(input("reject"))),
		"two equal calls":      respBody("tool_use", ok+","+ok),
		"three tool calls":     respBody("tool_use", ok+`,{"type":"text","text":"x"},`+ok+","+ok),
		"call, thinking, call": respBody("tool_use", ok+`,{"type":"thinking","thinking":"","signature":"x"},`+toolUse(input("reject"))),
		"only thinking":        respBody("tool_use", `{"type":"thinking","thinking":"","signature":"x"}`),
		"thinking, end_turn":   respBody("end_turn", `{"type":"thinking","thinking":"","signature":"x"},{"type":"text","text":"I approve."}`),
		"stop_sequence":        respBody("stop_sequence", ok),
		"stop reason null":     strings.Replace(respBody("tool_use", ok), `"stop_reason":"tool_use"`, `"stop_reason":null`, 1),
		"tool_result block":    respBody("tool_use", ok+`,{"type":"tool_result","tool_use_id":"toolu_01","content":"x"}`),
		"web search result":    respBody("tool_use", `{"type":"web_search_tool_result","tool_use_id":"x","content":[]},`+ok),
		"mcp tool use":         respBody("tool_use", `{"type":"mcp_tool_use","id":"x","name":"submit_review","input":`+input("approve")+`},`+ok),
		"block type case":      respBody("tool_use", `{"type":"Thinking","thinking":""},`+ok),
		"server tool":          respBody("tool_use", `{"type":"server_tool_use","id":"x","name":"web_search","input":{}},`+ok),
		"other tool":           respBody("tool_use", strings.Replace(ok, "submit_review", "submit_reviews", 1)),
		"tool name case":       respBody("tool_use", strings.Replace(ok, "submit_review", "Submit_Review", 1)),
		"block without type":   respBody("tool_use", `{"text":"x"},`+ok),
		"block not object":     respBody("tool_use", `"text",`+ok),
		"unknown verdict":      respBody("tool_use", toolUse(input("approved"))),
		"verdict case":         respBody("tool_use", toolUse(input("Approve"))),
		"verdict empty":        respBody("tool_use", toolUse(input(""))),
		"verdict bool":         respBody("tool_use", toolUse(`{"verdict":true,"candidate":"`+cand+`","summary":"s"}`)),
		"verdict padded":       respBody("tool_use", toolUse(input("approve "))),
		"missing summary":      respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`"}`)),
		"missing candidate":    respBody("tool_use", toolUse(`{"verdict":"approve","summary":"s"}`)),
		"extra input member":   respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"s","x":1}`)),
		"short candidate":      respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"abc","summary":"s"}`)),
		"uppercase candidate":  respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+strings.ToUpper(cand)+`","summary":"s"}`)),
		"summary not string":   respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":null}`)),
		"input is string":      respBody("tool_use", toolUse(`"{\"verdict\":\"approve\"}"`)),
		"input is array":       respBody("tool_use", toolUse(`[]`)),
		"duplicate verdict":    respBody("tool_use", toolUse(`{"verdict":"reject","verdict":"approve","candidate":"`+cand+`","summary":"s"}`)),
		"duplicate top key":    strings.Replace(respBody("tool_use", ok), `"role":"assistant"`, `"role":"user","role":"assistant"`, 1),
		"duplicate escaped":    respBody("tool_use", toolUse(`{"verdict":"reject","\u0076erdict":"approve","candidate":"`+cand+`","summary":"s"}`)),
		"duplicate stop":       strings.Replace(respBody("tool_use", ok), `"stop_sequence":null`, `"stop_reason":"tool_use"`, 1),
		"wrong type":           strings.Replace(respBody("tool_use", ok), `"type":"message"`, `"type":"error"`, 1),
		"error body":           `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
		"wrong role":           strings.Replace(respBody("tool_use", ok), `"assistant"`, `"user"`, 1),
		"field name case":      strings.Replace(respBody("tool_use", ok), `"stop_reason"`, `"Stop_Reason"`, 1),
		"missing model":        strings.Replace(respBody("tool_use", ok), `"model":"claude-test-1",`, ``, 1),
		"empty model":          strings.Replace(respBody("tool_use", ok), `"claude-test-1"`, `""`, 1),
		"model not string":     strings.Replace(respBody("tool_use", ok), `"claude-test-1"`, `7`, 1),
		"content not array":    strings.Replace(respBody("tool_use", ok), `"content":[`+ok+`]`, `"content":`+ok, 1),
		"invalid utf8":         respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"`+"\xff"+`"}`)),
		"raw newline":          respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"a`+"\n"+`b"}`)),
		"lone surrogate":       respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"\ud83d"}`)),
		"reversed surrogates":  respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"\ude00\ud83d"}`)),
		"bad escape":           respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"\x41"}`)),
		"bad number":           strings.Replace(respBody("tool_use", ok), `"input_tokens":10`, `"input_tokens":010`, 1),
		"single quotes":        `{'type':'message'}`,
		"comment":              `/* x */` + respBody("tool_use", ok),
		"bom":                  "\xef\xbb\xbf" + respBody("tool_use", ok),
		"deep nesting":         strings.Replace(respBody("tool_use", ok), `"stop_sequence":null`, `"stop_sequence":`+strings.Repeat("[", 100)+strings.Repeat("]", 100), 1),
		"too large":            strings.Replace(respBody("tool_use", ok), "looks fine", strings.Repeat("x", MaxResponseBytes), 1),
	}
	for name, body := range cases {
		v, err := ParseResponse([]byte(body))
		if err == nil {
			t.Errorf("%s: accepted: %+v", name, v)
			continue
		}
		if v != nil {
			t.Errorf("%s: verdict returned with error", name)
		}
		if !errors.Is(err, ErrResponse) {
			t.Errorf("%s: error %v does not wrap ErrResponse", name, err)
		}
	}
	// Depth bomb far beyond any stack-friendly depth must not crash.
	if _, err := ParseResponse([]byte(strings.Repeat("[", 500000))); err == nil {
		t.Fatal("depth bomb accepted")
	}
	if _, err := ParseResponse([]byte(strings.Repeat(`{"a":`, 100000))); err == nil {
		t.Fatal("depth bomb accepted")
	}
}

func FuzzParseResponse(f *testing.F) {
	ok := toolUse(input("approve"))
	f.Add([]byte(respBody("tool_use", ok)))
	f.Add([]byte(respBody("tool_use", `{"type":"text","text":"hi \u00e9 \ud83d\ude00"},`+toolUse(input("reject")))))
	f.Add([]byte(respBody("tool_use", `{"type":"thinking","thinking":"","signature":"c2ln"},{"type":"text","text":"ok"},`+ok+`,{"type":"text","text":"done"}`)))
	f.Add([]byte(respBody("tool_use", `{"type":"redacted_thinking","data":"AAAA"},`+toolUse(input("reject")))))
	f.Add([]byte(respBody("tool_use", `{"type":"server_tool_use","id":"x","name":"web_search","input":{}},`+ok)))
	f.Add([]byte(respBody("tool_use", toolUse(`{"verdict":"approve","candidate":"`+cand+`","summary":"s","extra":1}`))))
	f.Add([]byte(respBody("refusal", `{"type":"text","text":"no"}`)))
	f.Add([]byte(respBody("max_tokens", ok)))
	f.Add([]byte(respBody("tool_use", ok+","+ok)))
	f.Add([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"x"}}`))
	f.Add([]byte(`{"a":[1,-2.5e+3,true,false,null,{"b":"\\\"\/\b\f\n\r\t"}]}`))
	f.Add([]byte(`[[[[`))
	f.Fuzz(func(t *testing.T, body []byte) {
		v, err := ParseResponse(body)
		if err != nil {
			if v != nil || !errors.Is(err, ErrResponse) {
				t.Fatalf("bad error result: %v %v", v, err)
			}
			return
		}
		// Anything accepted is valid JSON for the reference parser
		// too, and the reference parser sees the same verdict.
		if !utf8.Valid(body) {
			t.Fatal("accepted invalid UTF-8")
		}
		var ref struct {
			Type       string `json:"type"`
			Role       string `json:"role"`
			Model      string `json:"model"`
			StopReason string `json:"stop_reason"`
			Content    []struct {
				Type  string `json:"type"`
				Name  string `json:"name"`
				Input *struct {
					Verdict   *string `json:"verdict"`
					Candidate *string `json:"candidate"`
					Summary   *string `json:"summary"`
				} `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &ref); err != nil {
			t.Fatalf("encoding/json rejects accepted body: %v", err)
		}
		if ref.Type != "message" || ref.Role != "assistant" || ref.StopReason != "tool_use" || ref.Model != v.Model || len(ref.Content) == 0 {
			t.Fatalf("envelope disagreement: %+v", ref)
		}
		last := ref.Content[0]
		calls := 0
		for _, b := range ref.Content {
			switch b.Type {
			case "tool_use":
				calls++
				last = b
			case "text", "thinking", "redacted_thinking":
			default:
				t.Fatalf("block of type %q accepted", b.Type)
			}
		}
		if calls != 1 {
			t.Fatalf("%d tool calls accepted", calls)
		}
		if last.Type != "tool_use" || last.Name != ToolName || last.Input == nil || last.Input.Verdict == nil ||
			last.Input.Candidate == nil || last.Input.Summary == nil {
			t.Fatalf("tool call disagreement: %+v", last)
		}
		if (*last.Input.Verdict == "approve") != v.Approve || *last.Input.Candidate != v.Candidate.String() || *last.Input.Summary != v.Summary {
			t.Fatalf("verdict disagreement")
		}
		if *last.Input.Verdict != "approve" && *last.Input.Verdict != "reject" {
			t.Fatal("unknown verdict accepted")
		}
	})
}
