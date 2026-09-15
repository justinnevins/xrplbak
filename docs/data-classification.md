# Data classification

Rules are code in `internal/redact`. This page explains them.

## Refused (C0)

Stanzas `[validation_seed]`, `[node_seed]`, `[ssl_key]`. Any line matching a base58 seed (`s` + 28 to 30 base58 chars), an RFC 1751 12-word key, or a PEM header, in any stanza except the key stanzas listed below. Any `--include` named validator-keys.json, wallet.db, *.pem, *.key, or containing `secret_key` or a PEM header.

The run aborts with exit code 3 and names the stanza and line.

## Bundle only (C1 and C2)

Whole stanzas: `[validator_token]`, `[validator_key_revocation]`, `[ips_fixed]`, `[cluster_nodes]`, `[rpc_startup]`, `[ssl_cert]`, `[peer_private]`, and every stanza not on the on-chain allowlist.

Single lines inside allowed stanzas: `admin =` and `secure_gateway =` in `[port_*]`, any private or link-local address, `ip =` with a non-local listen address in `[port_*]`, hex runs of 64+ or base64 runs of 44+ characters outside the key stanzas.

Each moved line leaves the marker `# xrplbak: content moved to the off-chain bundle` in the on-chain copy so restore can put it back in place, and so a bundle-less restore shows the gap.

## On-chain allowed (C3)

server, node_size, node_db, database_path, ledger_history, fetch_depth, path_search*, debug_logfile, sntp_servers, voting, amendments, veto_amendments, ssl_verify*, validators_file, validator_list_sites, validator_list_keys, validator_list_threshold, validators, ips, peers_max, peers_in_max, peers_out_max, reduce_relay, compression, ledger_tx_tables, workers, io_workers, prefetch_workers, overlay, transaction_queue, network_id, relay_proposals, relay_validations, beta_rpc_api, max_transactions, insight, perf, signing_support, crawl, vl, import_db, ledger_replay, sqlite, load, rpc_ip, rpc_port, and port_* after line filtering.

Key stanzas exempt from the hex and base58 scanners: validator_list_keys, validators, amendments, veto_amendments, cluster_nodes, validator_token, validator_key_revocation.

## Canonical form

Comments dropped, whitespace trimmed, LF endings, stanzas sorted by name, lines kept in order. Same input gives the same bytes. The manifest records the SHA-256 of the canonical original so restore can say "complete".
