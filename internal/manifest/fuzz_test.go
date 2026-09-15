package manifest

import "testing"

// FuzzUnmarshalNoPanic asserts that a hostile manifest cannot panic and
// cannot return a manifest alongside an error. Manifest bytes come off the
// ledger after decryption, so a forged one is reachable by anyone who can
// reach the writer account's key.
func FuzzUnmarshalNoPanic(f *testing.F) {
	m := &Manifest{Epoch: 1, Seq: 1, BackupID: "0123456789abcdef0123456789abcdef"}
	if b, err := Marshal(m); err == nil {
		f.Add(b)
	}
	f.Add([]byte("{}"))
	f.Add([]byte(`{"v":1}`))
	f.Add([]byte(`{"v":99,"backup_id":"0123456789abcdef0123456789abcdef"}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := Unmarshal(b)
		if err != nil && out != nil {
			t.Fatalf("Unmarshal returned a manifest alongside error %v", err)
		}
		if err == nil && len(out.BackupID) != 32 {
			t.Fatalf("accepted a manifest with backup id %q", out.BackupID)
		}
	})
}

// FuzzMarshalIsStable asserts that canonical manifest bytes survive a round
// trip unchanged. The manifest hash is what a verify compares, so drift
// here would fail a good backup.
func FuzzMarshalIsStable(f *testing.F) {
	f.Add("0123456789abcdef0123456789abcdef", uint32(1), uint32(2), "node")
	f.Fuzz(func(t *testing.T, id string, epoch, seq uint32, role string) {
		if len(id) != 32 {
			return
		}
		m := &Manifest{Epoch: epoch, Seq: seq, BackupID: id}
		m.Node.Role = role
		once, err := Marshal(m)
		if err != nil {
			return
		}
		back, err := Unmarshal(once)
		if err != nil {
			t.Fatalf("own output did not parse: %v", err)
		}
		twice, err := Marshal(back)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		if string(once) != string(twice) {
			t.Fatalf("manifest bytes drifted:\n%s\n%s", once, twice)
		}
	})
}
