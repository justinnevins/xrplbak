package main

import (
	"fmt"
	"strings"

	"github.com/justinnevins/xrplbak/internal/pubattest"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// cmdAttestVerify checks a public backup attestation from the ledger using
// only the account and, optionally, the validator key to assert against. It
// needs no recovery key and decrypts nothing: this is the check a third
// party runs to see that a validator is backing up its configuration.
func cmdAttestVerify(args []string) error {
	fs := newFlags("attest-verify", "check a validator's public backup attestation from the ledger, no keys needed")
	rpcURL := fs.String("rpc", "", "XRPL JSON-RPC URL, or mainnet / testnet / devnet")
	account := fs.String("account", "", "the writer account that publishes the backups (r...)")
	wantVPK := fs.String("validator-key", "", "optional: require the attestation to be by this validator key (nHB...)")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}
	if *account == "" {
		return fail(exitUsage, "attest-verify needs --account")
	}
	if _, err := sign.DecodeAddress(*account); err != nil {
		return fail(exitUsage, "--account is not a valid address: %v", err)
	}
	if *wantVPK != "" {
		if _, err := sign.DecodeNodePublic(*wantVPK); err != nil {
			return fail(exitUsage, "--validator-key is not a valid node public key: %v", err)
		}
	}
	client, source, err := openClient(*rpcURL, "")
	if err != nil {
		return err
	}
	txs, rng, err := client.AccountTx(*account)
	if err != nil {
		return fail(exitNetwork, "account_tx for %s: %v", *account, err)
	}

	// Newest wins: AccountTx returns oldest first, so the last valid memo is
	// the current attestation.
	var latest *pubattest.Record
	var latestLedger uint32
	for i := range txs {
		t := txs[i]
		if t.Account != *account || t.Result != "tesSUCCESS" {
			continue
		}
		for _, m := range t.Memos {
			r, ok := pubattest.Decode(m)
			if !ok {
				continue
			}
			if t.LedgerIndex >= latestLedger {
				rec := r
				latest = &rec
				latestLedger = t.LedgerIndex
			}
		}
	}

	hr("Public attestation")
	fmt.Fprintf(stdout, "  source:   %s\n", source)
	fmt.Fprintf(stdout, "  account:  %s\n", *account)
	fmt.Fprintf(stdout, "  searched: ledgers %d to %d\n", rng.Min, rng.Max)
	if latest == nil {
		fmt.Fprintln(stdout, "  result:   none. This account publishes no public backup attestation.")
		return fail(exitRefused, "no public attestation found for %s", *account)
	}
	if !latest.Verify(*account) {
		fmt.Fprintf(stdout, "  result:   INVALID signature, claiming validator %s\n", latest.NodePublic())
		return fail(exitAuth, "the attestation on %s does not verify", *account)
	}
	if *wantVPK != "" && !strings.EqualFold(*wantVPK, latest.NodePublic()) {
		fmt.Fprintf(stdout, "  result:   valid, but by %s, not the key you asked for\n", latest.NodePublic())
		return fail(exitAuth, "attestation is by %s, not %s", latest.NodePublic(), *wantVPK)
	}
	fmt.Fprintf(stdout, "  result:   valid. Validator %s vouches for this account.\n", latest.NodePublic())
	fmt.Fprintf(stdout, "  backup:   epoch %d seq %d, id %s, in ledger %d\n", latest.Epoch, latest.Seq, latest.BackupIDHex(), latestLedger)
	fmt.Fprintln(stdout, "  note:     this proves identity, publication and recency. It does not prove the operator can still restore.")
	return nil
}
