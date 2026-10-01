//go:build dosr_integration

// This test ties pkg/notary and pkg/llm to the REAL pkg/review and
// pkg/gitobj. It is behind a build tag because those packages are
// developed concurrently; run it with
//
//	go test -tags dosr_integration -run TestIntegration ./pkg/notary/
package notary_test

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/dosr/dosr/pkg/attest"
	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/llm"
	"github.com/dosr/dosr/pkg/notary"
	"github.com/dosr/dosr/pkg/review"
	"github.com/dosr/dosr/pkg/types"
)

func TestIntegrationReviewNotaryProvider(t *testing.T) {
	ca, cert, err := llm.NewLocalhostTLS()
	if err != nil {
		t.Fatal(err)
	}
	prov, err := llm.NewServer(llm.Config{APIKeys: []string{"sk-integration"}, Models: []string{"claude-test-1"}, Certificate: &cert})
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer prov.Shutdown(context.Background())
	key, err := notary.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := notary.NewServer(notary.Config{Key: key, AllowedHosts: []string{prov.Addr()}, RootCAs: ca.Pool(),
		EnforceSingleUseNonce: true, NonceFile: filepath.Join(t.TempDir(), "nonces.log")})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())
	cl := notary.NewClient(srv.URL())

	pol := &types.Policy{ProviderHost: prov.Addr(), ProviderPath: "/v1/messages", Models: []string{"claude-test-1"},
		SystemPrompt: "You are a code reviewer.", MaxTokens: 1024, MaxDiffBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for i, c := range []struct {
		content string
		approve bool
	}{{"fine\n", true}, {"bad " + llm.RejectMarker + "\n", false}} {
		s := gitobj.NewMemStore()
		ot, err := gitobj.WriteTree(s, []gitobj.File{{Path: "a.txt", Mode: gitobj.ModeFile, Data: []byte("old\n")}})
		if err != nil {
			t.Fatal(err)
		}
		nt, err := gitobj.WriteTree(s, []gitobj.File{{Path: "a.txt", Mode: gitobj.ModeFile, Data: []byte(c.content)}})
		if err != nil {
			t.Fatal(err)
		}
		changes, err := gitobj.DiffTrees(s, ot, nt, gitobj.DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		cand, _ := gitobj.ParseID("2222222222222222222222222222222222222222")
		p := review.Params{ChainID: "c", RepoID: "demo", Branch: "main", Candidate: cand, Model: "claude-test-1",
			PolicyHash: pol.Hash(), Nonce: []byte{0xaa, byte(i)}}
		body, err := review.BuildRequestBody(pol, p, "message\n", changes, s)
		if err != nil {
			t.Fatal(err)
		}
		req := &notary.Request{URL: prov.URL() + "/v1/messages", Method: "POST", Body: body,
			Headers: map[string]string{"x-api-key": "sk-integration", "anthropic-version": "2023-06-01", "content-type": "application/json"}}
		att, sec, err := cl.Attest(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		pres, err := notary.BuildPresentation(att, sec)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := pres.Encode()
		if err != nil {
			t.Fatal(err)
		}
		dec, err := attest.DecodePresentation(enc)
		if err != nil {
			t.Fatal(err)
		}
		// The validator recomputes the body.
		body2, _ := review.BuildRequestBody(pol, p, "message\n", changes, s)
		tr, err := attest.ProxyVerifier{}.Verify(dec, []ed25519.PublicKey{srv.PublicKey()}, map[string][]byte{attest.FieldReqBody: body2})
		if err != nil {
			t.Fatal(err)
		}
		if string(tr.Fields[attest.FieldRespStatus]) != "200" {
			t.Fatalf("status %s: %s", tr.Fields[attest.FieldRespStatus], tr.Fields[attest.FieldRespBody])
		}
		v, err := review.ParseResponse(tr.Fields[attest.FieldRespBody])
		if err != nil {
			t.Fatalf("review.ParseResponse rejects the mock's response: %v\n%s", err, tr.Fields[attest.FieldRespBody])
		}
		if v.Approve != c.approve || v.Candidate != cand || v.Model != "claude-test-1" {
			t.Fatalf("verdict %+v", v)
		}
		// Second attempt with the same nonce is refused.
		if _, _, err := cl.Attest(ctx, req); !notary.IsCode(err, notary.CodeNonceReused) {
			t.Fatalf("second attempt: %v", err)
		}
	}
	// Faulty responses are rejected by review.ParseResponse.
	nonces := map[string]string{"truncate": "bb01", "no-tool-call": "bb02", "safety-refusal": "bb03"}
	for name, f := range map[string]llm.Faults{"truncate": {PTruncate: 1}, "no-tool-call": {PNoToolCall: 1}, "safety-refusal": {PSafetyRefusal: 1}} {
		if err := prov.SetFaults(f); err != nil {
			t.Fatal(err)
		}
		r, err := srv.Attest(ctx, &notary.Request{URL: prov.URL() + "/v1/messages", Method: "POST",
			Body:    llm.Sample{Model: "claude-test-1", Nonce: nonces[name]}.RequestBody(),
			Headers: map[string]string{"x-api-key": "sk-integration", "anthropic-version": "2023-06-01"}})
		if err != nil {
			t.Fatal(err)
		}
		respBody := r.Secret.Values[len(r.Secret.Values)-1]
		if v, err := review.ParseResponse(respBody); err == nil {
			t.Fatalf("%s: review.ParseResponse accepted %s as %+v", name, respBody, v)
		}
	}
}
