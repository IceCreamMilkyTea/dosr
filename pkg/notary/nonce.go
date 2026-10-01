package notary

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Single-use review nonces.
//
// PROBLEM. An LLM reviewer is not deterministic. A contributor whose
// commit was rejected can simply ask again until some call answers
// "approve" and submit only that receipt ("approval grinding"). On chain,
// DOSR limits this with ReviewIntents: a review request must embed a
// chain-derived nonce, and the number of intents per candidate is bounded.
// But the chain only sees receipts that are SUBMITTED; nothing stops a
// contributor from obtaining many receipts for the same nonce and
// submitting the one it likes.
//
// RULE. With EnforceSingleUseNonce the notary attests at most ONE API call
// per nonce. For every attest request it
//
//  1. parses the JSON request body and takes messages[0].content, which
//     must be a string starting with the DOSR header block
//     ("DOSR-REVIEW-REQUEST v2\n" followed by "key: value" lines up to the
//     first blank line);
//  2. takes the nonce from the "nonce: " line of THAT HEADER BLOCK ONLY.
//     Everything after the first blank line (commit message, diffs) is
//     attacker-controlled content and is never looked at;
//  3. refuses requests without a nonce ("nonce: -"): under this setting a
//     review without intent cannot be attested at all;
//  4. RESERVES the nonce durably (append to the log file, fsync) BEFORE
//     contacting the provider, and refuses with HTTP 409 if it was
//     reserved before.
//
// WHY RESERVE BEFORE THE CALL, AND NEVER RELEASE.
//
//   - Reserving first makes check-and-call atomic: of several concurrent
//     requests with the same nonce exactly one reaches the provider.
//     Checking first and recording after the response would let all of
//     them through.
//   - A nonce stays consumed when the verdict is "reject": that is the
//     whole point. It buys exactly one answer.
//   - A nonce stays consumed when the upstream call FAILS (timeout, 5xx,
//     truncated or refused answer, connection reset). Releasing on
//     failure would re-open the grinding channel: the notary cannot tell
//     a genuine failure from one provoked by the contributor (who
//     controls the request and can drop its connection to the notary at
//     any moment), and after a timeout the notary does not even know
//     whether the provider produced a verdict. The cost is
//     liveness, not safety: an honest contributor hit by a provider
//     outage has to commit a new ReviewIntent to get a fresh nonce
//     (bounded by the policy's max_attempts).
//   - The reservation is durable before the call so that a crash or
//     restart of the notary cannot reset the set.
//
// Requests that the notary rejects BEFORE it would contact the provider
// (malformed request, host not allowed, notary overloaded) do not consume
// the nonce.
//
// WHAT THIS DOES NOT COVER. The check is only meaningful for request
// bodies that validators accept, i.e. the canonical bytes of
// review.BuildRequestBody; validators recompute the body and require
// byte equality. A body that fools the notary's JSON parsing (duplicate
// keys, an extra leading message, ...) can obtain an attestation, but the
// attested req.body then differs from the canonical body and the receipt
// is worthless on chain. Also, the rule binds ONE notary: if a policy
// trusts several notaries that do not share their nonce logs, a
// contributor gets one attempt per notary.

const (
	reviewMagic = "DOSR-REVIEW-REQUEST v2"
	// maxNonceLen bounds the hex length of a nonce.
	maxNonceLen = 128
	// maxHeaderLines bounds the DOSR header block.
	maxHeaderLines = 32
)

var errNoNonce = errors.New("request carries no review nonce (\"nonce: -\")")

// extractNonce returns the review nonce of a Messages API request body.
func extractNonce(body []byte) (string, error) {
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("request body is not JSON: %v", err)
	}
	if len(req.Messages) == 0 {
		return "", errors.New("request body has no messages")
	}
	raw := bytes.TrimSpace(req.Messages[0].Content)
	if len(raw) == 0 || raw[0] != '"' {
		return "", errors.New("messages[0].content is not a string")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", errors.New("messages[0].content is not a string")
	}
	return nonceFromText(text)
}

// nonceFromText extracts the nonce from the header block of a DOSR review
// text. Only the lines before the first blank line are examined.
func nonceFromText(text string) (string, error) {
	rest, ok := strings.CutPrefix(text, reviewMagic+"\n")
	if !ok {
		return "", errors.New("message does not start with the DOSR review header")
	}
	nonce, found := "", false
	for i := 0; ; i++ {
		if i >= maxHeaderLines {
			return "", errors.New("DOSR review header is too long")
		}
		line, tail, more := strings.Cut(rest, "\n")
		if !more {
			return "", errors.New("DOSR review header is not terminated by a blank line")
		}
		rest = tail
		if line == "" {
			break
		}
		if v, ok := strings.CutPrefix(line, "nonce: "); ok {
			if found {
				return "", errors.New("DOSR review header has several nonce lines")
			}
			nonce, found = v, true
		}
	}
	if !found {
		return "", errors.New("DOSR review header has no nonce line")
	}
	if nonce == "-" {
		return "", errNoNonce
	}
	if !validNonce(nonce) {
		return "", errors.New("nonce is not lower-case hex of even length")
	}
	return nonce, nil
}

func validNonce(n string) bool {
	if len(n) == 0 || len(n) > maxNonceLen || len(n)%2 != 0 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// NonceStore is a durable set of used nonces, safe for concurrent use.
//
// The file is an append-only log with one lower-case hex nonce per line.
// Every reservation is written and fsynced before Reserve returns. On
// open the log is replayed; an incomplete last line (a crash during the
// append) is discarded, which is safe because Reserve had not returned
// for it, so no upstream call was made for it.
//
// A store must not be shared by several processes (there is no file
// locking); a notary owns its log.
type NonceStore struct {
	mu   sync.Mutex
	used map[string]struct{}
	f    *os.File // nil: memory only
}

// NewMemoryNonceStore returns a store that is NOT persistent. A notary
// restart forgets all used nonces; use only in tests and experiments.
func NewMemoryNonceStore() *NonceStore {
	return &NonceStore{used: map[string]struct{}{}}
}

// OpenNonceStore opens (creating it with mode 0600 if necessary) the
// nonce log at path and loads the used nonces.
func OpenNonceStore(path string) (*NonceStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("notary: opening nonce log: %w", err)
	}
	s := &NonceStore{used: map[string]struct{}{}, f: f}
	if err := s.load(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *NonceStore) load() error {
	r := bufio.NewReader(s.f)
	var good int64 // offset after the last complete, valid line
	for lineNo := 1; ; lineNo++ {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			if line != "" {
				// Torn final append: drop it.
				if err := s.f.Truncate(good); err != nil {
					return fmt.Errorf("notary: truncating torn nonce log entry: %w", err)
				}
				if err := s.f.Sync(); err != nil {
					return fmt.Errorf("notary: syncing nonce log: %w", err)
				}
			}
			break
		}
		if err != nil {
			return fmt.Errorf("notary: reading nonce log: %w", err)
		}
		n := line[:len(line)-1]
		if !validNonce(n) {
			// Corruption in the middle of the log: refuse to start
			// rather than forget used nonces.
			return fmt.Errorf("notary: nonce log is corrupt at line %d", lineNo)
		}
		s.used[n] = struct{}{}
		good += int64(len(line))
	}
	if _, err := s.f.Seek(good, io.SeekStart); err != nil {
		return fmt.Errorf("notary: seeking nonce log: %w", err)
	}
	return nil
}

// Reserve marks nonce as used. It returns true if the nonce was fresh and
// is now durably recorded, false if it had been used before. On an I/O
// error the nonce is NOT reserved and the caller must not proceed.
func (s *NonceStore) Reserve(nonce string) (bool, error) {
	if !validNonce(nonce) {
		return false, errors.New("notary: invalid nonce")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.used[nonce]; dup {
		return false, nil
	}
	if s.f != nil {
		if _, err := s.f.WriteString(nonce + "\n"); err != nil {
			return false, fmt.Errorf("notary: writing nonce log: %w", err)
		}
		if err := s.f.Sync(); err != nil {
			return false, fmt.Errorf("notary: syncing nonce log: %w", err)
		}
	}
	s.used[nonce] = struct{}{}
	return true, nil
}

// Used reports whether nonce has been reserved.
func (s *NonceStore) Used(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.used[nonce]
	return ok
}

// Len returns the number of used nonces.
func (s *NonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.used)
}

// Close closes the log file. Reserve fails afterwards (for a persistent
// store).
func (s *NonceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	// Keep f non-nil so that later Reserve calls fail on write instead of
	// silently degrading to a memory-only store.
	return err
}
