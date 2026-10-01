package notary

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dosr/dosr/pkg/llm"
)

// BenchmarkAttest measures a full attestation through the notary's HTTP
// API against a local HTTPS server that answers immediately with a body
// of the given size, and reports the notary's own timing breakdown:
//
//	upstream-ms  connect + TLS handshake + request + response
//	attest-ms    commit + sign (attest.Build)
//	overhead-ms  everything the notary adds on top of the upstream call,
//	             as seen by the client: wall time - upstream
func BenchmarkAttest(b *testing.B) {
	for _, size := range []int{1 << 10, 10 << 10, 100 << 10} {
		b.Run(fmt.Sprintf("resp=%dKB", size>>10), func(b *testing.B) {
			payload := bytes.Repeat([]byte("r"), size)
			ts := upstream(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				w.Write(payload)
			}))
			_, cl := newNotary(b, Config{AllowedHosts: []string{hostOf(b, ts.URL)}})
			req := &Request{URL: ts.URL + "/v1/messages", Method: "POST",
				Headers: map[string]string{"x-api-key": apiKey, "content-type": "application/json", "anthropic-version": "2023-06-01"},
				Body:    llm.Sample{}.RequestBody()}
			var up, at, tot int64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r, err := cl.AttestTimed(context.Background(), req)
				if err != nil {
					b.Fatal(err)
				}
				up += r.Timing.UpstreamNs
				at += r.Timing.AttestNs
				tot += r.Timing.TotalNs
			}
			b.StopTimer()
			n := float64(b.N)
			wall := float64(b.Elapsed().Nanoseconds()) / n
			b.ReportMetric(float64(up)/n/1e6, "upstream-ms")
			b.ReportMetric(float64(at)/n/1e6, "attest-ms")
			b.ReportMetric((wall-float64(up)/n)/1e6, "overhead-ms")
		})
	}
}

// BenchmarkNonceReserve measures the durable reservation of a nonce
// (append + fsync), the cost single-use nonces add to each attestation.
func BenchmarkNonceReserve(b *testing.B) {
	s, err := OpenNonceStore(filepath.Join(b.TempDir(), "nonces.log"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if fresh, err := s.Reserve(fmt.Sprintf("%032x", i)); err != nil || !fresh {
			b.Fatal(err, fresh)
		}
	}
}

var _ = time.Second
