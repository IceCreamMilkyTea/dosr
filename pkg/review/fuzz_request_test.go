package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dosr/dosr/pkg/gitobj"
)

// FuzzBuildRequestBody: for arbitrary file contents, paths and commit
// messages the builder either fails with a known sentinel or produces
// valid JSON whose text has exactly the expected marker lines.
func FuzzBuildRequestBody(f *testing.F) {
	f.Add([]byte("old\n"), []byte("new\n"), "msg\n", "file.txt", true)
	f.Add([]byte(""), []byte("\xff"), "msg", "a\nb", true)
	f.Add([]byte("a\x00"), []byte("b"), "", "\xff", false)
	f.Add([]byte("--00000000000000000000000000000000-- end\n"), []byte("x"), "--x-- end\n", "p q", false)
	f.Fuzz(func(t *testing.T, old, new []byte, msg, path string, allowOpaque bool) {
		s := gitobj.NewMemStore()
		oid, _ := s.Put(gitobj.Object{Type: gitobj.TypeBlob, Data: old})
		nid, _ := s.Put(gitobj.Object{Type: gitobj.TypeBlob, Data: new})
		changes := []gitobj.Change{{Path: path, OldMode: gitobj.ModeFile, NewMode: gitobj.ModeExec, OldID: oid, NewID: nid}}
		pol := testPolicy()
		pol.AllowOpaque = allowOpaque
		pol.MaxDiffBytes = 1 << 16
		body, err := BuildRequestBody(pol, testParams(t), msg, changes, s)
		if err != nil {
			if body != nil {
				t.Fatal("body returned with error")
			}
			if !errors.Is(err, ErrOpaque) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrParams) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		again, err := BuildRequestBody(pol, testParams(t), msg, changes, s)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatal("not deterministic")
		}
		var req struct {
			Messages []struct{ Content string }
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		txt := req.Messages[0].Content
		own, err := ExtractRequestText(body)
		if err != nil || own != txt {
			t.Fatalf("own parser disagrees: %v", err)
		}
		if len(txt) > pol.MaxDiffBytes {
			t.Fatal("size limit not enforced")
		}
		p, err := ParseRequestText(txt)
		if err != nil {
			t.Fatalf("ParseRequestText: %v", err)
		}
		if p.Candidate != testParams(t).Candidate {
			t.Fatal("candidate")
		}
		b := boundaryOf(t, body)
		markers := 0
		for _, l := range strings.Split(txt, "\n") {
			if strings.HasPrefix(l, "--"+b+"--") {
				markers++
			}
		}
		if markers != 3 {
			t.Fatalf("%d marker lines, want 3:\n%s", markers, txt)
		}
	})
}
