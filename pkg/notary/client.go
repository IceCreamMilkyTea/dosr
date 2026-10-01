package notary

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dosr/dosr/pkg/attest"
)

// decodeStrict decodes exactly one JSON value without unknown fields.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// DefaultClientTimeout bounds a client call whose context has no
// deadline.
const DefaultClientTimeout = 5 * time.Minute

// maxClientResponse bounds what the client reads from the notary.
const maxClientResponse = 64 << 20

// Client talks to a notary.
//
// The connection to the notary carries the API key (in Request.Headers)
// and the Secret. Use an https BaseURL unless the notary runs on
// localhost.
type Client struct {
	// BaseURL is the notary's base URL, e.g. "http://127.0.0.1:7070".
	BaseURL string
	// HTTP is the HTTP client (default: a client without redirects).
	HTTP *http.Client
	// NotaryKey, if set, is the expected notary key: Attest then fails
	// unless the attestation is signed by it.
	NotaryKey ed25519.PublicKey
}

// NewClient returns a client for the notary at baseURL.
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL}
}

var defaultHTTP = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, []byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultClientTimeout)
		defer cancel()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return nil, nil, fmt.Errorf("notary client: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("notary client: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxClientResponse+1))
	if err != nil {
		return nil, nil, fmt.Errorf("notary client: reading response: %w", err)
	}
	if len(b) > maxClientResponse {
		return nil, nil, errors.New("notary client: response too large")
	}
	if resp.StatusCode != http.StatusOK {
		var er struct {
			Error *Error `json:"error"`
		}
		if json.Unmarshal(b, &er) == nil && er.Error != nil && er.Error.Code != "" {
			er.Error.Status = resp.StatusCode
			return nil, nil, er.Error
		}
		return nil, nil, &Error{Status: resp.StatusCode, Code: CodeInternal, Message: "unexpected response from notary: " + resp.Status}
	}
	return resp, b, nil
}

// Info fetches the notary's public key and configuration.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	_, b, err := c.do(ctx, http.MethodGet, InfoPath, nil)
	if err != nil {
		return nil, err
	}
	var in Info
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("notary client: bad info response: %w", err)
	}
	if len(in.NotaryKey) != ed25519.PublicKeySize {
		return nil, errors.New("notary client: info response has a bad notary key")
	}
	return &in, nil
}

// Attest asks the notary to make and attest the API call req. Failures
// reported by the notary are of type *Error (see the Code* constants).
//
// The result is checked before it is returned: the secret must open the
// attestation, the attested method and body must be the requested ones,
// and, if NotaryKey is set, the signature must verify under it.
func (c *Client) Attest(ctx context.Context, req *Request) (*attest.Attestation, *attest.Secret, error) {
	r, err := c.AttestTimed(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	return r.Attestation, r.Secret, nil
}

// AttestTimed is Attest returning the full response including the
// notary's timing breakdown.
func (c *Client) AttestTimed(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, errors.New("notary client: nil request")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("notary client: %w", err)
	}
	_, b, err := c.do(ctx, http.MethodPost, AttestPath, body)
	if err != nil {
		return nil, err
	}
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("notary client: bad attest response: %w", err)
	}
	if r.Attestation == nil || r.Secret == nil {
		return nil, errors.New("notary client: attest response lacks attestation or secret")
	}
	if err := checkResult(req, &r, c.NotaryKey); err != nil {
		return nil, fmt.Errorf("notary client: %w", err)
	}
	return &r, nil
}

// checkResult validates an attest response against the request.
func checkResult(req *Request, r *Response, key ed25519.PublicKey) error {
	// All leaves Known with the secret's values: exercises exactly the
	// verifier's code path.
	if len(r.Secret.Names) != len(r.Secret.Values) {
		return errors.New("malformed secret")
	}
	disclose := make(map[string]attest.Disclosure, len(r.Secret.Names))
	known := make(map[string][]byte, len(r.Secret.Names))
	for i, n := range r.Secret.Names {
		disclose[n] = attest.Known
		known[n] = r.Secret.Values[i]
	}
	p, err := attest.Present(r.Attestation, r.Secret, disclose)
	if err != nil {
		return fmt.Errorf("secret does not open the attestation: %w", err)
	}
	trusted := []ed25519.PublicKey{ed25519.PublicKey(r.Attestation.Header.NotaryKey)}
	if len(key) != 0 {
		trusted = []ed25519.PublicKey{key}
	}
	tr, err := attest.ProxyVerifier{}.Verify(p, trusted, known)
	if err != nil {
		return fmt.Errorf("attestation does not verify: %w", err)
	}
	if got, ok := tr.Fields[attest.FieldReqBody]; !ok || !bytes.Equal(got, req.Body) {
		return errors.New("attested request body differs from the requested one")
	}
	if got := string(tr.Fields[attest.FieldReqMethod]); got != strings.ToUpper(req.Method) {
		return errors.New("attested method differs from the requested one")
	}
	for k, v := range req.Headers {
		if got, ok := tr.Fields[attest.FieldReqHeaderPfx+strings.ToLower(k)]; !ok || string(got) != v {
			return fmt.Errorf("attested header %q differs from the requested one", strings.ToLower(k))
		}
	}
	for _, n := range []string{attest.FieldReqPath, attest.FieldRespStatus, attest.FieldRespBody} {
		if _, ok := tr.Fields[n]; !ok {
			return fmt.Errorf("attestation lacks field %q", n)
		}
	}
	return nil
}

// HiddenFields are the transcript fields DOSR never discloses: the
// request headers that carry credentials.
var hiddenFields = []string{
	attest.FieldReqHeaderPfx + "x-api-key",
	attest.FieldReqHeaderPfx + "authorization",
}

// DisclosurePolicy returns DOSR's disclosure policy as a map for
// attest.Present:
//
//	req.body                   -> Known    (validators recompute it from
//	                                        the Git objects; it does not
//	                                        travel in the transaction)
//	req.header.x-api-key       -> Hidden   (credentials)
//	req.header.authorization   -> Hidden
//	everything else            -> Revealed (absent from the map)
func DisclosurePolicy() map[string]attest.Disclosure {
	m := map[string]attest.Disclosure{attest.FieldReqBody: attest.Known}
	for _, n := range hiddenFields {
		m[n] = attest.Hidden
	}
	return m
}

// BuildPresentation opens an attestation according to DisclosurePolicy.
// The result is what a contributor puts into an AcceptCommit transaction
// (after Encode). It contains neither the API key nor the request body.
func BuildPresentation(att *attest.Attestation, secret *attest.Secret) (*attest.Presentation, error) {
	return attest.Present(att, secret, DisclosurePolicy())
}
