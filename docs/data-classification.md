# Data classification

Rules are code in `internal/redact`. This page explains them.

## Refused (C0)

Stanzas `[validation_seed]`, `[node_seed]`, `[ssl_key]`. Any line matching a base58 seed (`s` + 28 to 30 base58 chars) or an RFC 1751 12-word key in any stanza except `[validator_token]` and `[validator_key_revocation]` (their base64 bodies can contain look-alike runs). Any PEM header anywhere. Any `# xrplbak:` restore marker (finish the restore before backing up). Any `--include` named validator-keys.json, wallet.db, *.pem, *.key, or containing `secret_key` or a PEM header.

The run aborts with exit code 3 and names the stanza and line.

## Bundle only (C1 and C2)

Whole stanzas: `[validator_token]`, `[validator_key_revocation]`, `[ips_fixed]`, `[cluster_nodes]`, `[rpc_startup]`, `[ssl_cert]`, `[peer_private]`, and every stanza not on the on-chain allowlist.

Single lines inside allowed stanzas: `admin`, `secure_gateway`, `user`, `password`, `admin_user`, `admin_password`, `ssl_key`, `ssl_cert`, `ssl_chain` in `[port_*]`, any private or link-local address, `ip =` with a non-local listen address in `[port_*]`, hex runs of 64+ or base64 runs of 44+ characters outside the key stanzas.

Hostnames follow two rules. A name ending in a suffix reserved for private networks moves wherever it appears: `.local`, `.localhost`, `.localdomain`, `.internal`, `.intranet`, `.lan`, `.home`, `.home.arpa`, `.corp`, `.private`, `.test`, `.onion`. A single-label name with no domain at all moves when it sits in a host-valued stanza (`[ips]`, `[ips_fixed]`, `[sntp_servers]`, `[cluster_nodes]`, `[validator_list_sites]`) or in `ip =` inside `[port_*]`; `localhost` is the one exception.

Known limit: a public FQDN stays on-chain even when it is the operator's own machine, because nothing in the text separates `myvalidator.example.com` from a public hub like `r.ripple.com`. Move those stanzas by hand, or put them in a stanza that is bundle-only.

Each moved line leaves the marker `# xrplbak: content moved to the off-chain bundle` in the on-chain copy so restore can put it back in place, and so a bundle-less restore shows the gap.

## On-chain allowed (C3)

server, node_size, node_db, database_path, ledger_history, fetch_depth, path_search*, debug_logfile, sntp_servers, voting, amendments, veto_amendments, ssl_verify*, validators_file, validator_list_sites, validator_list_keys, validator_list_threshold, validators, ips, peers_max, peers_in_max, peers_out_max, reduce_relay, compression, ledger_tx_tables, workers, io_workers, prefetch_workers, overlay, transaction_queue, network_id, relay_proposals, relay_validations, beta_rpc_api, max_transactions, insight, perf, signing_support, crawl, vl, import_db, ledger_replay, sqlite, load, rpc_ip, rpc_port, and port_* after line filtering.

Key stanzas exempt from the hex and base64 length scanners (the seed scanner still runs on them): validator_list_keys, validators, amendments, veto_amendments, cluster_nodes, validator_token, validator_key_revocation.

## Canonical form

Comments dropped, whitespace trimmed, LF endings, stanzas sorted by name, lines kept in order. A repeated stanza name continues the first one. Same input gives the same bytes. The manifest records the SHA-256 of the canonical original so restore can say "complete".
