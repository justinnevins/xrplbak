package container

import (
	"bytes"
	"testing"
)

// FuzzDecodeNoPanic asserts that a hostile container never panics and never
// returns entries alongside an error. A restore reads this from the ledger,
// so the bytes are attacker-reachable.
func FuzzDecodeNoPanic(f *testing.F) {
	good, err := Encode([]Entry{{Path: "a.cfg", Mode: 0o600, Data: []byte("x")}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("XBC1"))
	f.Add([]byte("XBC1\x00\x00\xff\xff"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := Decode(b)
		if err != nil && out != nil {
			t.Fatalf("Decode returned %d entries alongside error %v", len(out), err)
		}
	})
}

// FuzzEncodeDecodeRoundTrip asserts that a container survives its own
// encoding for arbitrary paths and contents.
func FuzzEncodeDecodeRoundTrip(f *testing.F) {
	f.Add("a.cfg", []byte("x"), "b.cfg", []byte(""))
	f.Add("z", []byte{0x00, 0xff}, "a", []byte("\n\n"))
	f.Fuzz(func(t *testing.T, p1 string, d1 []byte, p2 string, d2 []byte) {
		if p1 == "" || p2 == "" || p1 == p2 || len(p1) > 65535 || len(p2) > 65535 {
			return
		}
		in := []Entry{{Path: p1, Mode: 0o600, Data: d1}, {Path: p2, Mode: 0o644, Data: d2}}
		b, err := Encode(in)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		out, err := Decode(b)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) != 2 {
			t.Fatalf("got %d entries", len(out))
		}
		for _, e := range out {
			want := d1
			if e.Path == p2 {
				want = d2
			}
			if !bytes.Equal(e.Data, want) {
				t.Fatalf("data changed for %q", e.Path)
			}
		}
	})
}

// FuzzPackUnpackRoundTrip asserts that padding and compression are
// reversible for arbitrary input, including empty and block-aligned sizes.
func FuzzPackUnpackRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("a"), BlockLen))
	f.Add(bytes.Repeat([]byte{0}, BlockLen*3-2))
	f.Fuzz(func(t *testing.T, raw []byte) {
		packed, err := Pack(raw)
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		if len(packed)%BlockLen != 0 {
			t.Fatalf("packed length %d is not block aligned", len(packed))
		}
		back, err := Unpack(packed)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if !bytes.Equal(back, raw) {
			t.Fatalf("round trip changed %d bytes into %d", len(raw), len(back))
		}
	})
}

// FuzzUnpackNoPanic asserts that hostile packed data cannot panic or
// allocate without bound through the decompressor.
func FuzzUnpackNoPanic(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, BlockLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Unpack(b)
	})
}
