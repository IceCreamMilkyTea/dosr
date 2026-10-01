package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "sk-test-key-1"

type testEnv struct {
	t      *testing.T
	srv    *Server
	client *http.Client
	ca     *CA
	cert   tls.Certificate
}

func newEnv(t *testing.T, cfg Config) *testEnv {
	t.Helper()
	ca, cert, err := NewLocalhostTLS()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKeys == nil {
		cfg.APIKeys = []string{testKey, "sk-test-key-2"}
	}
	cfg.Certificate = &cert
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool()}}
	t.Cleanup(func() {
		tr.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &testEnv{t: t, srv: srv, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}, ca: ca, cert: cert}
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (e *testEnv) post(body []byte, hdr map[string]string) reply {
	e.t.Helper()
	return e.postCtx(context.Background(), body, hdr)
}

func (e *testEnv) postCtx(ctx context.Context, body []byte, hdr map[string]string) reply {
	e.t.Helper()
	r, err := e.do(ctx, body, hdr)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *testEnv) do(ctx context.Context, body []byte, hdr map[string]string) (reply, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", e.srv.URL()+MessagesPath, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	if hdr == nil {
		hdr = map[string]string{"x-api-key": testKey, "anthropic-version": "2023-06-01", "content-type": "application/json"}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, err
	}
	return reply{resp.StatusCode, resp.Header, b}, nil
}

// parsed mirrors the strict parsing rules of review.ParseResponse.
type parsed struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Role         string  `json:"role"`
	Model        string  `json:"model"`
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
	StopDetails  *struct {
		Type        string  `json:"type"`
		Category    *string `json:"category"`
		Explanation string  `json:"explanation"`
	} `json:"stop_details"`
	Content []parsedBlock `json:"content"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type parsedBlock struct {
	Type      string          `json:"type"`
	Thinking  *string         `json:"thinking"`
	Signature string          `json:"signature"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

// tool returns the single tool_use block of p, or nil.
func (p parsed) tool() *parsedBlock {
	var found *parsedBlock
	for i := range p.Content {
		if p.Content[i].Type == "tool_use" {
			if found != nil {
				return nil
			}
			found = &p.Content[i]
		}
	}
	return found
}

func parseReply(t *testing.T, r reply) (parsed, toolInput) {
	t.Helper()
	var p parsed
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("response does not parse: %v\n%s", err, r.body)
	}
	var in toolInput
	if !bytes.Contains(r.body, []byte(`"stop_details":`)) || (p.StopDetails != nil) != (p.StopReason == "refusal") {
		t.Fatalf("stop_details must be present, and non-null exactly for refusals: %s", r.body)
	}
	if tb := p.tool(); tb != nil {
		d := json.NewDecoder(bytes.NewReader(tb.Input))
		d.DisallowUnknownFields()
		if err := d.Decode(&in); err != nil {
			t.Fatalf("tool input does not parse: %v", err)
		}
	}
	return p, in
}

func errorType(t *testing.T, r reply) string {
	t.Helper()
	var e struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(r.body, &e); err != nil || e.Type != "error" || e.Error.Message == "" {
		t.Fatalf("not an Anthropic-style error body: %s", r.body)
	}
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	return e.Error.Type
}

// -------------------------------------------------------------- success

func TestApproveResponseShape(t *testing.T) {
	e := newEnv(t, Config{})
	s := Sample{Candidate: strings.Repeat("ab", 20), Nonce: "00ff"}
	body := s.RequestBody()
	r := e.post(body, nil)
	if r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
	// Exact key order and presence, as review.ParseResponse expects.
	for _, frag := range []string{`{"id":"msg_`, `","type":"message","role":"assistant","model":"` + ModelMedium + `","content":[{"type":"thinking","thinking":"","signature":"`,
		`"},{"type":"tool_use","id":"toolu_`,
		`","name":"submit_review","input":{"verdict":"approve","candidate":"` + s.Candidate + `","summary":"`,
		`"}}],"stop_reason":"tool_use","stop_sequence":null,"stop_details":null,"usage":{"input_tokens":`} {
		if !bytes.Contains(r.body, []byte(frag)) {
			t.Fatalf("response lacks %q:\n%s", frag, r.body)
		}
	}
	p, in := parseReply(t, r)
	if p.Type != "message" || p.Role != "assistant" || p.StopReason != "tool_use" || p.Model != ModelMedium {
		t.Fatalf("bad envelope: %+v", p)
	}
	if len(p.Content) != 2 || p.tool() == nil || p.tool().Name != "submit_review" || !strings.HasPrefix(p.tool().ID, "toolu_") {
		t.Fatalf("bad content: %+v", p.Content)
	}
	th := p.Content[0]
	if th.Type != "thinking" || th.Thinking == nil || *th.Thinking != "" || len(th.Signature) < 40 {
		t.Fatalf("bad thinking block: %+v", th)
	}
	if _, err := base64.StdEncoding.DecodeString(th.Signature); err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if in.Verdict != "approve" || in.Candidate != s.Candidate || in.Summary == "" {
		t.Fatalf("bad tool input: %+v", in)
	}
	if p.Usage.InputTokens != (len(body)+3)/4 || p.Usage.OutputTokens != (len(p.tool().Input)+3)/4+(len(th.Signature)+3)/4 {
		t.Fatalf("usage %+v", p.Usage)
	}
	if r.header.Get("Request-Id") == "" || r.header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", r.header)
	}
	// Second allowed key works too, and ids are unique.
	r2 := e.post(body, map[string]string{"x-api-key": "sk-test-key-2", "anthropic-version": "2023-06-01"})
	p2, _ := parseReply(t, r2)
	if r2.status != 200 || p2.ID == p.ID || p2.tool().ID == p.tool().ID || p2.Content[0].Signature == th.Signature {
		t.Fatalf("second call: %d %s", r2.status, r2.body)
	}
}

func TestContentBlocksAndTemperature(t *testing.T) {
	e := newEnv(t, Config{})
	text := Sample{}.Text()
	mk := func(extra string, content any) []byte {
		c, _ := json.Marshal(content)
		return []byte(`{"model":"` + ModelSmall + `","max_tokens":500,` + extra +
			`"tools":[{"name":"submit_review","input_schema":{"type":"object"}}],` +
			`"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":` + string(c) + `}]}`)
	}
	half := len(text) / 2
	blocks := []map[string]string{{"type": "text", "text": text[:half]}, {"type": "text", "text": text[half:]}}
	for name, c := range map[string]struct {
		body []byte
		want int
	}{
		"string":          {mk("", text), 200},
		"blocks":          {mk("", blocks), 200},
		"no-system":       {mk("", text), 200},
		"system-blocks":   {mk(`"system":[{"type":"text","text":"be strict"}],`, text), 200},
		"temperature-1":   {mk(`"temperature":1,`, text), 200},
		"temperature-1.0": {mk(`"temperature":1.0,`, text), 200},
		"temperature-0":   {mk(`"temperature":0,`, text), 400},
		"temperature-0.5": {mk(`"temperature":0.5,`, text), 400},
		"temperature-str": {mk(`"temperature":"1",`, text), 400},
		"stream-false":    {mk(`"stream":false,`, text), 200},
		"stream-true":     {mk(`"stream":true,`, text), 400},
		"fallbacks":       {mk(`"fallbacks":[{"model":"`+ModelSmall+`"}],`, text), 400},
		"fallbacks-str":   {mk(`"fallbacks":"default",`, text), 400},
		"thinking":        {mk(`"thinking":{"type":"adaptive"},`, text), 200},
		"output-config":   {mk(`"output_config":{"effort":"low"},`, text), 200},
	} {
		if r := e.post(c.body, nil); r.status != c.want {
			t.Errorf("%s: status %d, want %d: %s", name, r.status, c.want, r.body)
		}
	}
}

// ------------------------------------------------------ auth/validation

func TestAuth(t *testing.T) {
	e := newEnv(t, Config{})
	body := Sample{}.RequestBody()
	for name, hdr := range map[string]map[string]string{
		"missing":     {"anthropic-version": "2023-06-01"},
		"wrong":       {"anthropic-version": "2023-06-01", "x-api-key": "sk-wrong"},
		"empty":       {"anthropic-version": "2023-06-01", "x-api-key": ""},
		"prefix":      {"anthropic-version": "2023-06-01", "x-api-key": testKey[:len(testKey)-1]},
		"bearer-only": {"anthropic-version": "2023-06-01", "authorization": "Bearer " + testKey},
	} {
		r := e.post(body, hdr)
		if r.status != 401 || errorType(t, r) != "authentication_error" {
			t.Errorf("%s: status %d body %s", name, r.status, r.body)
		}
		if bytes.Contains(r.body, []byte(testKey)) {
			t.Errorf("%s: error body echoes a valid key", name)
		}
	}
	r := e.post(body, map[string]string{"x-api-key": testKey})
	if r.status != 400 || errorType(t, r) != "invalid_request_error" || !bytes.Contains(r.body, []byte("anthropic-version")) {
		t.Errorf("missing anthropic-version: %d %s", r.status, r.body)
	}
	r = e.post(body, map[string]string{"x-api-key": testKey, "anthropic-version": "2023-06-01", "content-type": "text/plain"})
	if r.status != 400 {
		t.Errorf("wrong content type: %d", r.status)
	}
	st := e.srv.Stats()
	if st.Calls != 7 || st.AuthFailures != 5 || st.BadRequests != 2 || st.Completed != 0 || st.InputTokens != 0 || st.CostUSD != 0 {
		t.Errorf("stats: %+v", st)
	}
}

func TestBodyValidation(t *testing.T) {
	e := newEnv(t, Config{MaxRequestBytes: 64 << 10})
	good := string(Sample{}.RequestBody())
	if r := e.post([]byte(good), nil); r.status != 200 {
		t.Fatalf("good request: %d %s", r.status, r.body)
	}
	rep := func(old, new string) string {
		s := strings.Replace(good, old, new, 1)
		if s == good {
			t.Fatalf("replacement %q did not apply", old)
		}
		return s
	}
	text := Sample{}.Text()
	withText := func(txt string) string {
		return string(RequestBodyForText(ModelMedium, 1024, "s", txt))
	}
	cases := map[string]struct {
		body   string
		status int
		typ    string
	}{
		"empty":               {"", 400, "invalid_request_error"},
		"not-json":            {"hello", 400, "invalid_request_error"},
		"array":               {"[]", 400, "invalid_request_error"},
		"null":                {"null", 400, "invalid_request_error"},
		"truncated":           {good[:len(good)-2], 400, "invalid_request_error"},
		"trailing":            {good + "{}", 400, "invalid_request_error"},
		"unknown-field":       {rep(`{"model"`, `{"bogus":1,"model"`), 400, "invalid_request_error"},
		"unknown-model":       {rep(ModelMedium, "gpt-unknown"), 404, "not_found_error"},
		"model-missing":       {rep(`"model":"`+ModelMedium+`",`, ""), 400, "invalid_request_error"},
		"model-number":        {rep(`"model":"`+ModelMedium+`"`, `"model":5`), 400, "invalid_request_error"},
		"max-tokens-missing":  {rep(`"max_tokens":1024,`, ""), 400, "invalid_request_error"},
		"max-tokens-zero":     {rep(`"max_tokens":1024`, `"max_tokens":0`), 400, "invalid_request_error"},
		"max-tokens-negative": {rep(`"max_tokens":1024`, `"max_tokens":-5`), 400, "invalid_request_error"},
		"max-tokens-float":    {rep(`"max_tokens":1024`, `"max_tokens":10.5`), 400, "invalid_request_error"},
		"max-tokens-string":   {rep(`"max_tokens":1024`, `"max_tokens":"1024"`), 400, "invalid_request_error"},
		"max-tokens-huge":     {rep(`"max_tokens":1024`, `"max_tokens":99999999999999999999999`), 400, "invalid_request_error"},
		"messages-missing":    {rep(`"messages":[`, `"metadata":[`), 400, "invalid_request_error"},
		"messages-empty":      {good[:strings.Index(good, `"messages":[`)] + `"messages":[]}`, 400, "invalid_request_error"},
		"role-assistant":      {rep(`"role":"user"`, `"role":"assistant"`), 400, "invalid_request_error"},
		"role-system":         {rep(`"role":"user"`, `"role":"system"`), 400, "invalid_request_error"},
		"content-number":      {good[:strings.Index(good, `"messages":[`)] + `"messages":[{"role":"user","content":5}]}`, 400, "invalid_request_error"},
		"content-image-block": {good[:strings.Index(good, `"messages":[`)] + `"messages":[{"role":"user","content":[{"type":"image"}]}]}`, 400, "invalid_request_error"},
		"two-messages":        {rep(`"messages":[`, `"messages":[{"role":"user","content":"x"},`), 400, "invalid_request_error"},
		"tools-missing":       {rep(`"tools":[`, `"stop_sequences":[],"metadata":[`), 400, "invalid_request_error"},
		"tools-empty":         {good[:strings.Index(good, `"tools":[`)] + `"tools":[],"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":"x"}]}`, 400, "invalid_request_error"},
		"tool-no-name":        {rep(`{"name":"submit_review","strict":true,`, `{"strict":true,`), 400, "invalid_request_error"},
		"tool-no-schema":      {rep(`"input_schema":{`, `"description":"x","x":{`), 400, "invalid_request_error"},
		"tool-choice-tool":    {rep(`"tool_choice":{"type":"auto"}`, `"tool_choice":{"type":"tool","name":"submit_review"}`), 400, "invalid_request_error"},
		"tool-choice-any":     {rep(`"tool_choice":{"type":"auto"}`, `"tool_choice":{"type":"any"}`), 400, "invalid_request_error"},
		"tool-choice-none":    {rep(`"tool_choice":{"type":"auto"}`, `"tool_choice":{"type":"none"}`), 400, "invalid_request_error"},
		"tool-choice-bogus":   {rep(`"tool_choice":{"type":"auto"}`, `"tool_choice":{"type":"bogus"}`), 400, "invalid_request_error"},
		"tool-choice-empty":   {rep(`"tool_choice":{"type":"auto"}`, `"tool_choice":{}`), 400, "invalid_request_error"},
		"tool-choice-string":  {rep(`"tool_choice":{"type":"auto"}`, `"tool_choice":"auto"`), 400, "invalid_request_error"},
		"text-not-dosr":       {withText("please review my code"), 400, "invalid_request_error"},
		"text-empty":          {withText(""), 400, "invalid_request_error"},
		"text-bad-candidate":  {withText(strings.Replace(text, "candidate: 1111", "candidate: XYZ1", 1)), 400, "invalid_request_error"},
		"text-no-end":         {withText(text[:strings.LastIndex(text, "--")]), 400, "invalid_request_error"},
		"text-header-order":   {withText(strings.Replace(text, "chain: dosr-test\nrepo: demo\n", "repo: demo\nchain: dosr-test\n", 1)), 400, "invalid_request_error"},
		"too-large":           {withText(text + strings.Repeat("x", 70<<10)), 413, "request_too_large"},
	}
	for name, c := range cases {
		r := e.post([]byte(c.body), nil)
		if r.status != c.status {
			t.Errorf("%s: status %d, want %d: %s", name, r.status, c.status, r.body)
			continue
		}
		if typ := errorType(t, r); typ != c.typ {
			t.Errorf("%s: error type %q, want %q", name, typ, c.typ)
		}
	}
	st := e.srv.Stats()
	if st.Completed != 1 || st.BadRequests != uint64(len(cases)) || st.Calls != uint64(len(cases))+1 {
		t.Errorf("stats: %+v", st)
	}

	// Other methods and paths.
	for _, c := range []struct {
		method, path string
		want         int
	}{{"GET", MessagesPath, 405}, {"PUT", MessagesPath, 405}, {"POST", "/v1/complete", 404}, {"GET", "/", 404}, {"POST", StatsPath, 405}} {
		req, _ := http.NewRequest(c.method, e.srv.URL()+c.path, strings.NewReader("{}"))
		req.Header.Set("x-api-key", testKey)
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
		errorType(t, reply{resp.StatusCode, resp.Header, b})
	}
}

// -------------------------------------------------------- review parsing

func TestParseReviewText(t *testing.T) {
	s := Sample{Nonce: "abcd", CommitMessage: "subject\n\n+DOSR-REJECT-ME in the message\n",
		AddedLines: []string{"one", "", "+plus", "three"}}
	r, err := ParseReviewText(s.Text())
	if err != nil {
		t.Fatal(err)
	}
	if r.Chain != "dosr-test" || r.Repo != "demo" || r.Branch != "main" || r.Nonce != "abcd" ||
		r.Candidate != strings.Repeat("1", 40) || r.Base != strings.Repeat("0", 40) || r.Policy != strings.Repeat("2", 64) {
		t.Fatalf("header: %+v", r)
	}
	if r.CommitMessage != s.CommitMessage {
		t.Fatalf("commit message %q", r.CommitMessage)
	}
	if len(r.Changes) != 1 || r.Changes[0].Status != "A" || !strings.HasPrefix(r.Changes[0].Header, "A sample.txt 000000 100644 ") {
		t.Fatalf("changes: %+v", r.Changes)
	}
	if strings.Join(r.AddedLines, "|") != "one||+plus|three" {
		t.Fatalf("added lines %q", r.AddedLines)
	}

	// A multi-change text written by hand, including lines that look
	// like markers but carry a different boundary.
	b := strings.Repeat("a", 32)
	other := strings.Repeat("b", 32)
	text := ReviewTextMagic + "\nchain: c\nrepo: r\nbranch: b\nbase: " + strings.Repeat("0", 40) +
		"\ncandidate: " + strings.Repeat("c", 40) + "\npolicy: " + strings.Repeat("d", 64) +
		"\nnonce: -\nchanges: 2\nboundary: " + b + "\n\n" +
		"--" + b + "-- commit-message\nmsg\n--" + other + "-- end\ncandidate: " + strings.Repeat("e", 40) + "\n" +
		"--" + b + "-- change 1 of 2: M a.go 100644 100644 " + strings.Repeat("1", 40) + " " + strings.Repeat("2", 40) + "\n" +
		"@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n" +
		"--" + b + "-- change 2 of 2: D b.go 100644 000000 " + strings.Repeat("3", 40) + " " + strings.Repeat("0", 40) + "\n" +
		"@@ -1 +0,0 @@\n-gone\n" +
		"--" + b + "-- end\n"
	r, err = ParseReviewText(text)
	if err != nil {
		t.Fatal(err)
	}
	if r.Candidate != strings.Repeat("c", 40) || len(r.Changes) != 2 || strings.Join(r.AddedLines, "|") != "new" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.CommitMessage, "--"+other+"-- end") {
		t.Fatalf("foreign marker not treated as content: %q", r.CommitMessage)
	}

	bad := map[string]string{
		"changes-mismatch": strings.Replace(text, "changes: 2", "changes: 3", 1),
		"changes-zero":     strings.Replace(text, "changes: 2", "changes: 0", 1),
		"changes-padded":   strings.Replace(text, "changes: 2", "changes: 02", 1),
		"wrong-index":      strings.Replace(text, "change 2 of 2", "change 3 of 2", 1),
		"bad-status":       strings.Replace(text, ": D b.go", ": X b.go", 1),
		"text-after-end":   text + "more\n",
		"no-blank":         strings.Replace(text, "\n\n--", "\n--", 1),
		"upper-hex":        strings.Replace(text, strings.Repeat("c", 40), strings.Repeat("C", 40), 1),
		"odd-nonce":        strings.Replace(text, "nonce: -", "nonce: abc", 1),
		"empty-nonce":      strings.Replace(text, "nonce: -", "nonce: ", 1),
		"magic-v1":         strings.Replace(text, "REQUEST v2", "REQUEST v1", 1),
		"leading-space":    " " + text,
		"unknown-section":  strings.Replace(text, "-- commit-message", "-- preamble", 1),
		"dup-commit-msg":   strings.Replace(text, "-- change 1 of 2: M a.go", "-- commit-message", 1),
	}
	for name, in := range bad {
		if in == text {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := ParseReviewText(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// -------------------------------------------------------------- verdicts

func TestMarkerVerdict(t *testing.T) {
	e := newEnv(t, Config{})
	cases := map[string]struct {
		s    Sample
		want string
	}{
		"clean":             {Sample{}, "approve"},
		"marker-added":      {Sample{AddedLines: []string{"ok", "x := 1 // DOSR-REJECT-ME"}}, "reject"},
		"marker-in-message": {Sample{CommitMessage: "DOSR-REJECT-ME\n+DOSR-REJECT-ME\n"}, "approve"},
		"marker-lowercase":  {Sample{AddedLines: []string{"dosr-reject-me"}}, "approve"},
	}
	for name, c := range cases {
		r := e.post(c.s.RequestBody(), nil)
		_, in := parseReply(t, r)
		if r.status != 200 || in.Verdict != c.want {
			t.Errorf("%s: %d verdict %q, want %q", name, r.status, in.Verdict, c.want)
		}
	}
	// Marker in removed and context lines only.
	text := Sample{}.Text()
	text = strings.Replace(text, "+hello\n", " ctx DOSR-REJECT-ME\n-old DOSR-REJECT-ME\n+new\n", 1)
	r := e.post(RequestBodyForText(ModelMedium, 1024, "s", text), nil)
	if _, in := parseReply(t, r); in.Verdict != "approve" {
		t.Errorf("marker in removed/context lines: %d %q", r.status, r.body)
	}
	st := e.srv.Stats()
	if st.Approved != 4 || st.Rejected != 1 || st.Completed != 5 {
		t.Errorf("stats %+v", st)
	}
}

func TestBernoulliVerdict(t *testing.T) {
	count := func(f VerdictFunc, r *ReviewRequest, n int) int {
		a := 0
		for i := 0; i < n; i++ {
			if f(r).Approve {
				a++
			}
		}
		return a
	}
	clean := &ReviewRequest{AddedLines: []string{"fine"}}
	dirty := &ReviewRequest{AddedLines: []string{"fine", "bad " + RejectMarker}}
	const n = 20000
	for _, p := range []float64{0, 0.1, 0.5, 0.9, 1} {
		got := float64(count(BernoulliVerdict(p, NewRand(42)), clean, n)) / n
		if math.Abs(got-p) > 0.02 {
			t.Errorf("p=%v: observed %v", p, got)
		}
		// Content does not matter for the pure Bernoulli model.
		got = float64(count(BernoulliVerdict(p, NewRand(42)), dirty, n)) / n
		if math.Abs(got-p) > 0.02 {
			t.Errorf("p=%v (dirty): observed %v", p, got)
		}
		if c := count(MarkerThenBernoulli(p, NewRand(42)), dirty, 1000); c != 0 {
			t.Errorf("composition approved a marked change %d times", c)
		}
		got = float64(count(MarkerThenBernoulli(p, NewRand(42)), clean, n)) / n
		if math.Abs(got-p) > 0.02 {
			t.Errorf("composition p=%v: observed %v", p, got)
		}
	}
	// Reproducible with equal seeds, different with different seeds.
	seq := func(seed int64) string {
		f := BernoulliVerdict(0.5, NewRand(seed))
		var sb strings.Builder
		for i := 0; i < 64; i++ {
			if f(clean).Approve {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
		return sb.String()
	}
	if seq(7) != seq(7) || seq(7) == seq(8) {
		t.Error("seeding is not reproducible")
	}
	if !BernoulliVerdict(1, nil)(clean).Approve {
		t.Error("nil rng")
	}

	// Through the server: the same request gets different verdicts
	// (approval grinding works against an unprotected provider).
	e := newEnv(t, Config{Verdict: BernoulliVerdict(0.5, NewRand(3))})
	body := Sample{}.RequestBody()
	seen := map[string]int{}
	for i := 0; i < 40; i++ {
		_, in := parseReply(t, e.post(body, nil))
		seen[in.Verdict]++
	}
	if seen["approve"] == 0 || seen["reject"] == 0 || seen["approve"]+seen["reject"] != 40 {
		t.Errorf("verdicts: %v", seen)
	}
	e.srv.SetVerdict(nil)
	if _, in := parseReply(t, e.post(body, nil)); in.Verdict != "approve" {
		t.Error("SetVerdict(nil) should restore MarkerVerdict")
	}
}

// --------------------------------------------------------------- latency

func TestLatencyModel(t *testing.T) {
	if d := LatencyNone.Sample(NewRand(1), 100000, 100000); d != 0 {
		t.Fatalf("LatencyNone = %v", d)
	}
	// Deterministic part.
	m := LatencyModel{TTFTMedian: time.Second, TokensPerSec: 100, PerInputToken: time.Millisecond}
	if d := m.Sample(nil, 1000, 300); d != 5*time.Second {
		t.Fatalf("got %v, want 5s", d)
	}
	// Lognormal: the median of samples is near TTFTMedian, and the mean
	// of ln is mu with standard deviation sigma.
	m = LatencyModel{TTFTMedian: 2 * time.Second, TTFTSigma: 0.5, Max: time.Hour}
	rng := NewRand(99)
	const n = 20000
	var sum, sumsq float64
	below := 0
	for i := 0; i < n; i++ {
		d := m.Sample(rng, 0, 0)
		if d <= 0 {
			t.Fatal("non-positive sample")
		}
		if d < 2*time.Second {
			below++
		}
		l := math.Log(d.Seconds())
		sum += l
		sumsq += l * l
	}
	mean := sum / n
	sd := math.Sqrt(sumsq/n - mean*mean)
	if math.Abs(mean-math.Log(2)) > 0.02 || math.Abs(sd-0.5) > 0.02 || math.Abs(float64(below)/n-0.5) > 0.02 {
		t.Fatalf("lognormal parameters off: mean %v sd %v below-median %v", mean, sd, float64(below)/n)
	}
	// Cap.
	m = LatencyModel{TTFTMedian: time.Hour, Max: time.Second}
	if d := m.Sample(rng, 0, 0); d != time.Second {
		t.Fatalf("cap: %v", d)
	}
	if d := (LatencyModel{TTFTMedian: 24 * time.Hour}).Sample(rng, 0, 0); d != DefaultMaxLatency {
		t.Fatalf("default cap: %v", d)
	}
	// Presets: orders of magnitude for a 300-token answer to a 10k-token
	// prompt.
	avg := func(m LatencyModel) time.Duration {
		rng := NewRand(5)
		var s time.Duration
		for i := 0; i < 2000; i++ {
			s += m.Sample(rng, 10000, 300)
		}
		return s / 2000
	}
	if a := avg(LatencyFast); a < 100*time.Millisecond || a > time.Second {
		t.Errorf("LatencyFast mean %v", a)
	}
	if a := avg(LatencyRealistic); a < 3*time.Second || a > 15*time.Second {
		t.Errorf("LatencyRealistic mean %v", a)
	}
	// Same seed, same samples.
	a, b := NewRand(11), NewRand(11)
	for i := 0; i < 100; i++ {
		if LatencyRealistic.Sample(a, 10, 10) != LatencyRealistic.Sample(b, 10, 10) {
			t.Fatal("latency samples are not reproducible")
		}
	}
	for _, bad := range []LatencyModel{{TTFTMedian: -1}, {TTFTSigma: -1}, {TokensPerSec: -1}, {TTFTSigma: math.NaN()}, {PerInputToken: -1}} {
		if _, err := NewServer(Config{APIKeys: []string{"k"}, Latency: bad}); err == nil {
			t.Errorf("accepted latency model %+v", bad)
		}
	}
}

func TestLatencyAppliedAndCancellable(t *testing.T) {
	e := newEnv(t, Config{Latency: LatencyModel{TTFTMedian: 300 * time.Millisecond}})
	body := Sample{}.RequestBody()
	start := time.Now()
	if r := e.post(body, nil); r.status != 200 {
		t.Fatalf("status %d", r.status)
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("latency not applied: %v", el)
	}
	if st := e.srv.Stats(); st.SimulatedLatencyNs != uint64(300*time.Millisecond) {
		t.Fatalf("simulated latency %d", st.SimulatedLatencyNs)
	}

	// Cancellation: the handler must stop sleeping when the client goes
	// away.
	if err := e.srv.SetLatency(LatencyModel{TTFTMedian: 30 * time.Second, Max: 30 * time.Second}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err := e.do(ctx, body, nil)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.Stats().Canceled != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("handler did not notice the cancellation: %+v", e.srv.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("cancellation took %v", el)
	}
	st := e.srv.Stats()
	if st.Completed != 1 || st.Calls != 2 {
		t.Fatalf("a cancelled call must not be billed: %+v", st)
	}
}

func TestShutdownAbortsSleepingHandlers(t *testing.T) {
	e := newEnv(t, Config{Latency: LatencyModel{TTFTMedian: 30 * time.Second, Max: 30 * time.Second}})
	type result struct {
		reply
		err error
	}
	errc := make(chan result, 1)
	go func() {
		r, err := e.do(context.Background(), Sample{}.RequestBody(), nil)
		errc <- result{r, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.Stats().Calls != 1 {
		if time.Now().After(deadline) {
			t.Fatal("request did not arrive")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := e.srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("shutdown took %v", el)
	}
	select {
	case r := <-errc:
		// The aborted call is answered with 503, never with a verdict.
		if r.err == nil && (r.status != 503 || errorType(t, r.reply) != "api_error") {
			t.Fatalf("request got %d %s although the server shut down", r.status, r.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client still waiting")
	}
	if err := e.srv.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	if err := e.srv.Start("127.0.0.1:0"); err == nil {
		t.Fatal("restart after shutdown should fail")
	}
}

// ---------------------------------------------------------------- faults

func TestFaults(t *testing.T) {
	e := newEnv(t, Config{})
	body := Sample{}.RequestBody()
	set := func(f Faults) {
		t.Helper()
		if err := e.srv.SetFaults(f); err != nil {
			t.Fatal(err)
		}
	}

	set(Faults{POverloaded: 1})
	r := e.post(body, nil)
	if r.status != 529 || errorType(t, r) != "overloaded_error" {
		t.Fatalf("overloaded: %d %s", r.status, r.body)
	}

	set(Faults{PServerError: 1})
	r = e.post(body, nil)
	if r.status != 500 || errorType(t, r) != "api_error" {
		t.Fatalf("server error: %d %s", r.status, r.body)
	}

	set(Faults{PTruncate: 1})
	r = e.post(body, nil)
	p, in := parseReply(t, r)
	if r.status != 200 || p.StopReason != "max_tokens" || p.Type != "message" || in.Verdict != "" || in.Candidate != "" {
		t.Fatalf("truncate: %d %s", r.status, r.body)
	}
	if bytes.Contains(r.body, []byte("approve")) || bytes.Contains(r.body, []byte("reject")) {
		t.Fatalf("truncated response carries a verdict: %s", r.body)
	}

	// No tool call (PRefusal is the deprecated alias).
	for _, f := range []Faults{{PNoToolCall: 1}, {PRefusal: 1}, {PNoToolCall: 0.5, PRefusal: 0.5}} {
		set(f)
		r = e.post(body, nil)
		p, _ = parseReply(t, r)
		if r.status != 200 || p.StopReason != "end_turn" || len(p.Content) != 2 || p.Content[0].Type != "thinking" ||
			p.Content[1].Type != "text" || p.Content[1].Text == "" {
			t.Fatalf("no tool call: %d %s", r.status, r.body)
		}
		if bytes.Contains(r.body, []byte("tool_use")) || bytes.Contains(r.body, []byte("approve")) {
			t.Fatalf("response contains a tool call: %s", r.body)
		}
	}

	set(Faults{PSafetyRefusal: 1})
	r = e.post(body, nil)
	p, _ = parseReply(t, r)
	if r.status != 200 || p.StopReason != "refusal" || len(p.Content) != 0 || !bytes.Contains(r.body, []byte(`"content":[]`)) ||
		p.StopDetails == nil || p.StopDetails.Type != "refusal" || p.StopDetails.Category == nil || p.StopDetails.Explanation == "" ||
		p.Usage.OutputTokens != 0 || p.Usage.InputTokens == 0 {
		t.Fatalf("safety refusal: %d %s", r.status, r.body)
	}

	set(Faults{PHang: 1, HangDuration: 250 * time.Millisecond, ExtraLatency: 50 * time.Millisecond})
	start := time.Now()
	r = e.post(body, nil)
	if el := time.Since(start); r.status != 200 || el < 300*time.Millisecond {
		t.Fatalf("hang: %d after %v", r.status, el)
	}

	// A hang is cancellable.
	set(Faults{PHang: 1, HangDuration: 30 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err := e.do(ctx, body, nil)
	cancel()
	if err == nil {
		t.Fatal("hang did not hang")
	}

	set(Faults{})
	if r = e.post(body, nil); r.status != 200 {
		t.Fatalf("after clearing faults: %d", r.status)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.Stats().Canceled != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := e.srv.Stats()
	if st.Calls != 10 || st.Overloaded != 1 || st.ServerErrors != 1 || st.Truncated != 1 || st.NoToolCall != 3 ||
		st.SafetyRefused != 1 || st.Approved != 2 || st.Canceled != 1 || st.Completed != 7 {
		t.Fatalf("stats %+v", st)
	}

	// Invalid configurations.
	for _, f := range []Faults{{POverloaded: 1.5}, {PRefusal: -0.1}, {POverloaded: 0.6, PServerError: 0.6},
		{PNoToolCall: 0.6, PRefusal: 0.6}, {PSafetyRefusal: 1.1}, {PSafetyRefusal: 0.5, PNoToolCall: 0.6},
		{PHang: math.NaN()}, {HangDuration: -1}, {ExtraLatency: -1}} {
		if err := e.srv.SetFaults(f); err == nil {
			t.Errorf("accepted %+v", f)
		}
	}
}

func TestFaultProbabilities(t *testing.T) {
	f := Faults{POverloaded: 0.1, PServerError: 0.2, PTruncate: 0.3, PRefusal: 0.05, PNoToolCall: 0.05, PSafetyRefusal: 0.05}
	rng := NewRand(1)
	counts := map[faultKind]int{}
	const n = 100000
	for i := 0; i < n; i++ {
		counts[f.pick(rng.Float64())]++
	}
	for k, want := range map[faultKind]float64{faultOverloaded: 0.1, faultServerError: 0.2, faultTruncate: 0.3, faultNoToolCall: 0.1, faultSafetyRefusal: 0.05, faultNone: 0.25} {
		if got := float64(counts[k]) / n; math.Abs(got-want) > 0.01 {
			t.Errorf("fault %d: %v, want %v", k, got, want)
		}
	}
	if (Faults{}).pick(0) != faultNone || (Faults{}).pick(0.999) != faultNone {
		t.Error("no faults configured but one was picked")
	}

	// Mixed faults through the server: every response is one of the
	// expected shapes and the accounting adds up.
	e := newEnv(t, Config{Faults: Faults{POverloaded: 0.2, PServerError: 0.2, PTruncate: 0.15, PNoToolCall: 0.15, PSafetyRefusal: 0.15}, Seed: 5})
	sawThinking := 0
	body := Sample{}.RequestBody()
	for i := 0; i < 60; i++ {
		r := e.post(body, nil)
		switch r.status {
		case 200:
			p, in := parseReply(t, r)
			// Only a tool_use stop carries a verdict.
			if (in.Verdict != "") != (p.StopReason == "tool_use") {
				t.Fatalf("verdict %q with stop_reason %q", in.Verdict, p.StopReason)
			}
			if len(p.Content) > 0 && p.Content[0].Type == "thinking" {
				sawThinking++
			}
		case 500, 529:
			errorType(t, r)
		default:
			t.Fatalf("status %d", r.status)
		}
	}
	st := e.srv.Stats()
	if st.Calls != 60 || st.Completed+st.Overloaded+st.ServerErrors != 60 ||
		st.Approved+st.Rejected+st.Truncated+st.NoToolCall+st.SafetyRefused != st.Completed ||
		uint64(sawThinking) != st.Completed-st.SafetyRefused {
		t.Fatalf("stats do not add up: %+v", st)
	}
	if st.Overloaded == 0 || st.ServerErrors == 0 || st.Truncated == 0 || st.NoToolCall == 0 || st.SafetyRefused == 0 || st.Approved == 0 {
		t.Fatalf("some fault never happened in 60 calls: %+v", st)
	}
}

func TestMaxTokensTruncation(t *testing.T) {
	e := newEnv(t, Config{TargetOutputTokens: 300})
	r := e.post(Sample{MaxTokens: 1024}.RequestBody(), nil)
	p, in := parseReply(t, r)
	if p.StopReason != "tool_use" || in.Verdict != "approve" {
		t.Fatalf("%s", r.body)
	}
	if p.Usage.OutputTokens < 300 || p.Usage.OutputTokens > 330 {
		t.Fatalf("output tokens %d, want about 300", p.Usage.OutputTokens)
	}
	r = e.post(Sample{MaxTokens: 100}.RequestBody(), nil)
	p, in = parseReply(t, r)
	if p.StopReason != "max_tokens" || in.Verdict != "" || p.Usage.OutputTokens != 100 {
		t.Fatalf("expected truncation at max_tokens: %s", r.body)
	}
	if st := e.srv.Stats(); st.Truncated != 1 || st.Approved != 1 {
		t.Fatalf("%+v", st)
	}
}

// ------------------------------------------------------------ accounting

func TestAccounting(t *testing.T) {
	prices := map[string]Price{"m-a": {InputPerMTok: 2, OutputPerMTok: 10}, "m-b": {InputPerMTok: 0.5, OutputPerMTok: 1}}
	e := newEnv(t, Config{Models: []string{"m-a", "m-b", "m-free"}, Prices: prices})
	var wantIn, wantOut [3]uint64
	var wg sync.WaitGroup
	var mu sync.Mutex
	models := []string{"m-a", "m-b", "m-free"}
	for i := 0; i < 30; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := Sample{Model: models[i%3], AddedLines: []string{strings.Repeat("x", i*10)}}.RequestBody()
			r, err := e.do(context.Background(), body, nil)
			if err != nil || r.status != 200 {
				t.Errorf("call %d: %v %d", i, err, r.status)
				return
			}
			var p parsed
			if err := json.Unmarshal(r.body, &p); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			wantIn[i%3] += uint64(p.Usage.InputTokens)
			wantOut[i%3] += uint64(p.Usage.OutputTokens)
			mu.Unlock()
		}()
	}
	wg.Wait()
	st := e.srv.Stats()
	if st.Calls != 30 || st.Completed != 30 || st.Approved != 30 {
		t.Fatalf("%+v", st)
	}
	if st.InputTokens != wantIn[0]+wantIn[1]+wantIn[2] || st.OutputTokens != wantOut[0]+wantOut[1]+wantOut[2] {
		t.Fatalf("token totals: %+v", st)
	}
	var wantCost float64
	for i, m := range models {
		ms := st.PerModel[m]
		if ms.Calls != 10 || ms.InputTokens != wantIn[i] || ms.OutputTokens != wantOut[i] {
			t.Fatalf("model %s: %+v", m, ms)
		}
		c := (float64(wantIn[i])*prices[m].InputPerMTok + float64(wantOut[i])*prices[m].OutputPerMTok) / 1e6
		if math.Abs(ms.CostUSD-c) > 1e-12 {
			t.Fatalf("model %s cost %v, want %v", m, ms.CostUSD, c)
		}
		wantCost += c
	}
	if st.PerModel["m-free"].CostUSD != 0 || st.CostUSD <= 0 || math.Abs(st.CostUSD-wantCost) > 1e-12 {
		t.Fatalf("cost %v, want %v", st.CostUSD, wantCost)
	}

	// GET /stats returns the same numbers.
	resp, err := e.client.Get(e.srv.URL() + StatsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Stats
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(st)
	if resp.StatusCode != 200 || !bytes.Equal(a, b) {
		t.Fatalf("/stats: %s\nwant %s", a, b)
	}
	// The snapshot is a copy.
	st.PerModel["m-a"] = ModelStats{}
	if e.srv.Stats().PerModel["m-a"].Calls != 10 {
		t.Fatal("Stats() exposes internal state")
	}
	e.srv.ResetStats()
	if st := e.srv.Stats(); st.Calls != 0 || st.CostUSD != 0 || len(st.PerModel) != 0 {
		t.Fatalf("after reset: %+v", st)
	}
}

func TestEstimateTokens(t *testing.T) {
	for n, want := range map[int]int{-1: 0, 0: 0, 1: 1, 4: 1, 5: 2, 8: 2, 4000: 1000} {
		if got := EstimateTokens(n); got != want {
			t.Errorf("EstimateTokens(%d) = %d, want %d", n, got, want)
		}
	}
}

// ------------------------------------------------------------ config/TLS

func TestConfigValidation(t *testing.T) {
	for name, c := range map[string]Config{
		"no-keys":        {},
		"empty-key":      {APIKeys: []string{""}},
		"empty-model":    {APIKeys: []string{"k"}, Models: []string{""}},
		"negative-price": {APIKeys: []string{"k"}, Prices: map[string]Price{"m": {InputPerMTok: -1}}},
		"negative-pad":   {APIKeys: []string{"k"}, TargetOutputTokens: -1},
		"bad-faults":     {APIKeys: []string{"k"}, Faults: Faults{PNoToolCall: 2}},
	} {
		if _, err := NewServer(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := NewServer(Config{APIKeys: []string{"k"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("127.0.0.1:0"); err == nil {
		t.Error("Start without certificate must fail")
	}
	if s.Addr() != "" || s.URL() != "" {
		t.Error("address of a server that is not started")
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown of a server that is not started: %v", err)
	}
}

func TestTLSHelper(t *testing.T) {
	e := newEnv(t, Config{})
	// A client that does not trust the private CA must fail.
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}, Timeout: 5 * time.Second}
	if _, err := c.Get(e.srv.URL() + StatsPath); err == nil {
		t.Fatal("connection with an empty root pool succeeded")
	}
	// Plain HTTP is not served.
	if resp, err := http.Get("http://" + e.srv.Addr() + StatsPath); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plain HTTP request succeeded")
		}
	}
	// The certificate is valid for localhost and 127.0.0.1.
	leaf := e.cert.Leaf
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("certificate not valid for %s: %v", h, err)
		}
	}
	if err := leaf.VerifyHostname("example.com"); err == nil {
		t.Error("certificate valid for example.com")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: e.ca.Pool(), DNSName: "localhost"}); err != nil {
		t.Errorf("chain does not verify: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(e.ca.CertPEM()) {
		t.Error("CertPEM is not parseable")
	}
	h, err := SPKIHash(e.cert)
	if err != nil || len(h) != 32 {
		t.Fatalf("SPKIHash: %x %v", h, err)
	}
	noLeaf := tls.Certificate{Certificate: e.cert.Certificate}
	if h2, err := SPKIHash(noLeaf); err != nil || !bytes.Equal(h, h2) {
		t.Fatal("SPKIHash without parsed leaf differs")
	}
	if _, err := SPKIHash(tls.Certificate{}); err == nil {
		t.Fatal("SPKIHash of an empty certificate")
	}
	if _, err := e.ca.Issue(); err == nil {
		t.Fatal("Issue without names")
	}
}

// TestGoldenRequest checks the mock against a request body in the exact
// canonical rendering of pkg/review.
func TestGoldenRequest(t *testing.T) {
	e := newEnv(t, Config{Models: []string{"claude-test-1"}})
	r := e.post([]byte(GoldenRequestBody), nil)
	p, in := parseReply(t, r)
	if r.status != 200 || p.Model != "claude-test-1" || in.Verdict != "approve" || in.Candidate != strings.Repeat("2", 40) {
		t.Fatalf("%d %s", r.status, r.body)
	}
	var w wireRequest
	if err := json.Unmarshal([]byte(GoldenRequestBody), &w); err != nil {
		t.Fatal(err)
	}
	var text string
	if err := json.Unmarshal(w.Messages[0].Content, &text); err != nil {
		t.Fatal(err)
	}
	rr, err := ParseReviewText(text)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Chain != "dosr-test-1" || rr.Nonce != "deadbeef" || rr.Base != strings.Repeat("1", 40) || len(rr.Changes) != 5 ||
		rr.CommitMessage != "Fix greeting\n\nLonger explanation.\n" {
		t.Fatalf("%+v", rr)
	}
	want := []string{`hello "world"`, "README.md", "tab\there\r", "no newline"}
	if strings.Join(rr.AddedLines, "|") != strings.Join(want, "|") {
		t.Fatalf("added lines %q", rr.AddedLines)
	}
	var st []string
	for _, c := range rr.Changes {
		st = append(st, c.Status)
	}
	if strings.Join(st, "") != "MDAMA" || rr.Changes[3].Body != "" {
		t.Fatalf("changes %+v", rr.Changes)
	}
	// With the marker in an added line the same request is rejected.
	marked := strings.Replace(GoldenRequestBody, `+hello \"world\"`, `+hello DOSR-REJECT-ME`, 1)
	if marked == GoldenRequestBody {
		t.Fatal("replacement did not apply")
	}
	if _, in := parseReply(t, e.post([]byte(marked), nil)); in.Verdict != "reject" {
		t.Fatalf("verdict %q", in.Verdict)
	}
}

// TestToolChoice: forced tool use is rejected by default, as on current
// models, and can be enabled to model older ones.
func TestToolChoice(t *testing.T) {
	auto := string(Sample{}.RequestBody())
	with := func(tc string) []byte {
		s := strings.Replace(auto, `"tool_choice":{"type":"auto"}`, tc, 1)
		if s == auto {
			t.Fatalf("replacement did not apply")
		}
		return []byte(s)
	}
	forcedTool := with(`"tool_choice":{"type":"tool","name":"submit_review"}`)
	forcedAny := with(`"tool_choice":{"type":"any"}`)
	absent := with(`"stop_sequences":[]`)

	e := newEnv(t, Config{}) // defaults
	for name, body := range map[string][]byte{"tool": forcedTool, "any": forcedAny} {
		r := e.post(body, nil)
		var er struct {
			Error struct{ Type, Message string }
		}
		if err := json.Unmarshal(r.body, &er); err != nil {
			t.Fatal(err)
		}
		if r.status != 400 || er.Error.Type != "invalid_request_error" ||
			er.Error.Message != `tool_choice: type "tool" and "any" are not supported for this model.` {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	for name, body := range map[string][]byte{"auto": []byte(auto), "absent": absent} {
		r := e.post(body, nil)
		p, in := parseReply(t, r)
		if r.status != 200 || in.Verdict != "approve" || p.tool().Name != "submit_review" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// With several tools the mock calls submit_review.
	multi := strings.Replace(auto, `"tools":[`, `"tools":[{"name":"other","input_schema":{"type":"object"}},`, 1)
	if p, _ := parseReply(t, e.post([]byte(multi), nil)); p.tool() == nil || p.tool().Name != "submit_review" {
		t.Errorf("multi-tool request: %+v", p.Content)
	}
	if st := e.srv.Stats(); st.BadRequests != 2 || st.Completed != 3 {
		t.Errorf("stats %+v", st)
	}

	old := newEnv(t, Config{RejectForcedToolChoice: Bool(false), EmitThinking: Bool(false)})
	for name, body := range map[string][]byte{"tool": forcedTool, "any": forcedAny, "auto": []byte(auto)} {
		r := old.post(body, nil)
		p, in := parseReply(t, r)
		if r.status != 200 || in.Verdict != "approve" || len(p.Content) != 1 || p.Content[0].Type != "tool_use" {
			t.Errorf("legacy %s: %d %s", name, r.status, r.body)
		}
		if bytes.Contains(r.body, []byte("thinking")) {
			t.Errorf("legacy %s: thinking block emitted", name)
		}
	}
	r := old.post(with(`"tool_choice":{"type":"tool","name":"nope"}`), nil)
	if r.status != 400 {
		t.Errorf("unknown forced tool: %d", r.status)
	}
	// A temperature other than 1 is rejected in both configurations.
	r = old.post([]byte(strings.Replace(auto, `{"model"`, `{"temperature":0,"model"`, 1)), nil)
	if r.status != 400 || !bytes.Contains(r.body, []byte("temperature")) {
		t.Errorf("temperature 0: %d %s", r.status, r.body)
	}
}
