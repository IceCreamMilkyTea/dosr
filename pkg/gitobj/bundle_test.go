package gitobj

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func rawBundle(objs ...Object) []byte {
	out := []byte(bundleMagic)
	out = append(out, bundleVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(objs)))
	for _, o := range objs {
		out = append(out, byte(o.Type))
		out = binary.BigEndian.AppendUint32(out, uint32(len(o.Data)))
		out = append(out, o.Data...)
	}
	return out
}

func sorted(objs ...Object) []Object {
	o := append([]Object(nil), objs...)
	sortObjects(o)
	return o
}

func TestBundleRoundTrip(t *testing.T) {
	a, b, c := blob("a"), blob("bb"), treeObj()
	bn := &Bundle{Objects: []Object{a, b, c, a}} // unsorted, duplicate
	enc := bn.Encode()
	if len(bn.Objects) != 4 || !bytes.Equal(bn.Objects[0].Data, []byte("a")) {
		t.Fatal("Encode modified the bundle")
	}
	if want := rawBundle(sorted(a, b, c)...); !bytes.Equal(enc, want) {
		t.Fatalf("encoding not canonical:\n%x\n%x", enc, want)
	}
	dec, err := DecodeBundle(enc, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Objects) != 3 {
		t.Fatalf("got %d objects", len(dec.Objects))
	}
	if !bytes.Equal(dec.Encode(), enc) {
		t.Fatal("round trip differs")
	}
	// Decoded objects must not alias the input or each other.
	enc2 := append([]byte(nil), enc...)
	for i := range enc {
		enc[i] = 0xff
	}
	dec.Objects[0].Data = append(dec.Objects[0].Data, "overflow"...)
	if !bytes.Equal((&Bundle{Objects: dec.Objects[1:]}).Encode(), (&Bundle{Objects: sorted(a, b, c)[1:]}).Encode()) {
		t.Fatal("objects alias")
	}
	_ = enc2

	// Empty bundle.
	e := (&Bundle{}).Encode()
	if d, err := DecodeBundle(e, DefaultLimits); err != nil || len(d.Objects) != 0 {
		t.Fatal("empty bundle", err)
	}
}

func TestDecodeBundleRejects(t *testing.T) {
	a, b := blob("a"), blob("bb")
	s := sorted(a, b)
	good := rawBundle(s...)
	mut := func(f func(x []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	lim := DefaultLimits

	cases := []struct {
		name string
		data []byte
		lim  Limits
		want error
	}{
		{"empty", nil, lim, ErrMalformed},
		{"short header", good[:12], lim, ErrMalformed},
		{"bad magic", mut(func(x []byte) []byte { x[0] = 'X'; return x }), lim, ErrMalformed},
		{"version 0", mut(func(x []byte) []byte { x[8] = 0; return x }), lim, ErrUnsupported},
		{"version 2", mut(func(x []byte) []byte { x[8] = 2; return x }), lim, ErrUnsupported},
		{"trailing byte", append(append([]byte(nil), good...), 0), lim, ErrNonCanonical},
		{"truncated data", good[:len(good)-1], lim, ErrMalformed},
		{"truncated obj header", good[:bundleHeaderBytes+3], lim, ErrMalformed},
		{"count too high", mut(func(x []byte) []byte { x[12] = 3; return x }), lim, ErrMalformed},
		{"count too low", mut(func(x []byte) []byte { x[12] = 1; return x }), lim, ErrNonCanonical},
		{"huge count", mut(func(x []byte) []byte { x[9], x[10], x[11], x[12] = 0xff, 0xff, 0xff, 0xff; return x }), Limits{1 << 20, 1 << 40, 1 << 20, 64, 4096}, ErrMalformed},
		{"huge count vs limit", mut(func(x []byte) []byte { x[9] = 0xff; return x }), lim, ErrLimit},
		{"huge length", mut(func(x []byte) []byte { x[14], x[15] = 0xff, 0xff; return x }), Limits{1 << 20, 10, 1 << 40, 64, 4096}, ErrMalformed},
		{"huge length vs limit", mut(func(x []byte) []byte { x[14] = 0xff; return x }), lim, ErrLimit},
		{"type 0", mut(func(x []byte) []byte { x[13] = 0; return x }), lim, ErrUnsupported},
		{"type tag", mut(func(x []byte) []byte { x[13] = 4; return x }), lim, ErrUnsupported},
		{"type 255", mut(func(x []byte) []byte { x[13] = 255; return x }), lim, ErrUnsupported},
		{"unsorted", rawBundle(s[1], s[0]), lim, ErrNonCanonical},
		{"duplicate", rawBundle(s[0], s[0]), lim, ErrNonCanonical},
		{"bundle too large", good, Limits{len(good) - 1, 10, 100, 64, 4096}, ErrLimit},
		{"too many objects", good, Limits{1 << 20, 1, 100, 64, 4096}, ErrLimit},
		{"object too large", good, Limits{1 << 20, 10, 1, 64, 4096}, ErrLimit},
		{"zero limits", good, Limits{}, ErrLimit},
		{"negative limits", good, Limits{1 << 20, -1, -1, 64, 4096}, ErrLimit},
	}
	for _, c := range cases {
		_, err := DecodeBundle(c.data, c.lim)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		wantErrT(t, c.name, err, c.want)
	}
	// Exact limits are accepted.
	if _, err := DecodeBundle(good, Limits{len(good), 2, 2, 0, 0}); err != nil {
		t.Errorf("exact limits: %v", err)
	}
}
