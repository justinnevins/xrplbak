package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
)

// unknownAmendments is a server whose feature RPC cannot be read.
type unknownAmendments struct{ *fake.Ledger }

func (unknownAmendments) AmendmentEnabled(string) (bool, error) {
	return false, errors.New("feature: forbidden")
}

// TestBatchDecision pins the default: batched wherever the ledger offers
// it, one transaction at a time everywhere else, and never a guess when
// the server's answer cannot be read.
func TestBatchDecision(t *testing.T) {
	live := fake.New()
	live.Batch = true
	old := fake.New()
	cases := []struct {
		name   string
		client xrpl.Client
		flag   string
		want   bool
		note   string
		err    string
	}{
		{"auto on a live server", live, "auto", true, "yes", ""},
		{"auto on an old server", old, "auto", false, "not have the Batch amendment", ""},
		{"auto when unreadable", unknownAmendments{old}, "auto", false, "could not be read", ""},
		{"off on a live server", live, "off", false, "--batch=off", ""},
		{"on on a live server", live, "on", true, "yes", ""},
		{"on on an old server", old, "on", false, "", "does not have the Batch amendment"},
		{"on when unreadable", unknownAmendments{old}, "on", false, "", "could not be read"},
	}
	for _, c := range cases {
		got, note, err := decideBatch(c.client, c.flag)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want || !strings.Contains(note, c.note) {
			t.Errorf("%s: got %v %q %v, want %v containing %q", c.name, got, note, err, c.want, c.note)
		}
	}
	if _, _, err := decideBatch(live, "auto"); err != nil {
		t.Fatal(err)
	}
}

// TestBatchFlagRejectsUnknownValues keeps a typo from choosing a path.
func TestBatchFlagRejectsUnknownValues(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--batch=maybe")
	if r.code != exitUsage || !strings.Contains(r.out, "--batch must be") {
		t.Fatalf("exit %d:\n%s", r.code, r.out)
	}
}
