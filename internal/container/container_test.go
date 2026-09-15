package container

import (
	"bytes"
	"testing"
)

func TestEncodeDeterministic(t *testing.T) {
	a := []Entry{{Path: "/b", Mode: 0o644, Data: []byte("bee")}, {Path: "/a", Mode: 0o600, Data: []byte("ay")}}
	b := []Entry{a[1], a[0]}
	ea, _ := Encode(a)
	eb, _ := Encode(b)
	if !bytes.Equal(ea, eb) {
		t.Fatal("order must not matter")
	}
	back, err := Decode(ea)
	if err != nil || len(back) != 2 || back[0].Path != "/a" || back[1].Mode != 0o644 {
		t.Fatal("decode", err)
	}
	if _, err := Encode([]Entry{{Path: "/a"}, {Path: "/a"}}); err == nil {
		t.Fatal("duplicate path must fail")
	}
	ea[len(ea)-1] ^= 1
	if _, err := Decode(ea); err == nil {
		t.Fatal("corrupted content must fail hash check")
	}
}

func TestPackRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 957, 958, 959, 960, 5000} {
		raw := bytes.Repeat([]byte("config line\n"), n)
		p, err := Pack(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(p)%BlockLen != 0 {
			t.Fatalf("n=%d len=%d", n, len(p))
		}
		p2, _ := Pack(raw)
		if !bytes.Equal(p, p2) {
			t.Fatal("pack must be deterministic")
		}
		back, err := Unpack(p)
		if err != nil || !bytes.Equal(back, raw) {
			t.Fatalf("n=%d unpack: %v", n, err)
		}
	}
	if _, err := Unpack([]byte{1, 2, 3}); err == nil {
		t.Fatal("bad length must fail")
	}
}
