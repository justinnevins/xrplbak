package backup

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// F-069: an --include file saved as UTF-16 hid secret_key and a PEM
// marker from the key material scan, because every other byte is zero.
func TestF069IncludeKeyMaterialRefusedInUTF16(t *testing.T) {
	e := newEnv(t)
	enc := func(s string, bigEndian bool) []byte {
		b := []byte{0xff, 0xfe}
		if bigEndian {
			b = []byte{0xfe, 0xff}
		}
		for _, u := range utf16.Encode([]rune(s)) {
			if bigEndian {
				b = append(b, byte(u>>8), byte(u))
			} else {
				b = append(b, byte(u), byte(u>>8))
			}
		}
		return b
	}
	i := 0
	for _, body := range []string{"{\"secret_key\": \"abc\"}\n", "-----BEGIN PRIVATE KEY-----\nMIIB\n"} {
		for _, big := range []bool{false, true} {
			i++
			inc := filepath.Join(e.dir, "notes"+string(rune('a'+i))+".txt")
			if err := os.WriteFile(inc, enc(body, big), 0o600); err != nil {
				t.Fatal(err)
			}
			o := e.opts(t, 1)
			o.Includes = []string{inc}
			if _, err := Build(o); err == nil {
				t.Errorf("%q (big endian %v): include accepted", body, big)
			}
		}
	}
}
