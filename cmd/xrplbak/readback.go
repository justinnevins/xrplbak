package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// Servers behind a load balancer can answer account_tx from a node that has
// not seen the newest ledger yet. The read-back asks again for up to a
// minute before it calls the backup missing.
const (
	readBackTries = 12
	readBackPoll  = 5 * time.Second
)

// readBack proves a backup that was just submitted by reading it from the
// ledger the way restore does: discovery with the key file, the chunks, the
// bundle from this run, and restore.Build. It passes only when this backup
// is the newest one that authenticates and every file rebuilds to the bytes
// the manifest names. It returns the number of files proved.
//
// Outcomes: nil is PASS. exitNetwork means it could not finish, and the
// backup may well be fine. Any other code means the ledger does not hold a
// backup that restores, and the run must not report success.
func readBack(client xrpl.Client, kf *crypto.KeyFile, account string, p *backup.Plan) (int, error) {
	keys := discover.FileKeys{E: kf.Epoch, Key: kf.Key}
	id := p.Manifest.BackupID
	var res *discover.Result
	var cand *discover.Candidate
	var lastErr error
	for i := 0; i < readBackTries && cand == nil; i++ {
		if i > 0 {
			submitSleep(readBackPoll)
		}
		r, err := discover.Run(client, keys, account, kf.Epoch)
		if err != nil {
			lastErr = err
			continue
		}
		for _, c := range r.Candidates {
			if c.Manifest.BackupID == id {
				res, cand = r, c
			}
		}
	}
	if cand == nil {
		if lastErr != nil {
			return 0, fail(exitNetwork, "backup %s was not found on the ledger after %s (%v)", id, readBackTries*readBackPoll, lastErr)
		}
		return 0, fail(exitNetwork, "backup %s was not found on the ledger after %s", id, readBackTries*readBackPoll)
	}
	if res.Latest != cand {
		newest := "none"
		if res.Latest != nil {
			newest = res.Latest.Manifest.BackupID
		}
		return 0, fail(exitIncomplete, "backup %s is on the ledger, but restore would pick %s, not this one", id, newest)
	}
	entries, err := discover.Fetch(client, keys, res, cand)
	if err != nil {
		var me *chunk.MissingError
		if errors.As(err, &me) {
			return 0, fail(exitIncomplete, "read-back FAILED: %v", err)
		}
		var ne *discover.NetworkError
		if errors.As(err, &ne) {
			return 0, fail(exitNetwork, "%v", err)
		}
		return 0, fail(exitAuth, "read-back FAILED: %v", err)
	}
	bundle, err := discover.OpenBundle(keys, cand, p.Bundle)
	if err != nil {
		return 0, fail(exitAuth, "read-back FAILED: bundle: %v", err)
	}
	plan, err := restore.Build(cand.Manifest, entries, bundle)
	if err != nil {
		return 0, fail(exitIncomplete, "read-back FAILED: %v", err)
	}
	if len(plan.Files) != len(p.Manifest.Files) {
		return 0, fail(exitIncomplete, "read-back FAILED: %d file(s) rebuilt, the backup has %d", len(plan.Files), len(p.Manifest.Files))
	}
	for _, f := range plan.Files {
		if !f.Complete() {
			return 0, fail(exitIncomplete, "read-back FAILED: %s did not rebuild to the backed-up bytes", f.Path)
		}
	}
	return len(plan.Files), nil
}

// warnChangedFiles compares each backed-up file with the file on disk now.
// A difference means the file changed while the backup ran, so the backup
// holds the earlier version. That is a warning: the backup is still exact.
func warnChangedFiles(p *backup.Plan) {
	for _, f := range p.Manifest.Files {
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}
		if sha256hex(raw) != f.SHA256 {
			fmt.Fprintf(stdout, "  WARNING: %s changed on disk after the backup read it. The backup holds the earlier version. Run backup again to capture the new one.\n", f.Path)
		}
	}
}
