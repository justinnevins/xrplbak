// Package redact classifies config content and splits it into the on-chain
// set (C3) and the bundle set (C1/C2). It refuses C0 outright. The
// classification is an allowlist: a stanza the tool does not know goes to
// the bundle, never on-chain.
package redact

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

// Class is where a piece of config may go.
type Class int

const (
	// Never means the tool refuses to handle the content at all.
	Never Class = iota
	// Bundle means off-chain encrypted bundle only.
	Bundle
	// OnChain means on-chain ciphertext is allowed.
	OnChain
)

// MovedMarker is the line left in the on-chain copy where a stanza or line
// moved to the bundle, so a bundle-less restore still boots and a human
// sees what is missing.
const MovedMarker = "# xrplbak: content moved to the off-chain bundle"

// Stanzas the tool refuses. Their presence means the operator is about to
// back up something xrplbak must never touch.
var neverStanzas = map[string]string{
	"validation_seed": "legacy validator secret; use a validator token instead",
	"node_seed":       "node identity secret; xrplbak never handles node seeds",
	"ssl_key":         "TLS private key path; keep it out of backups",
}

// Stanzas that go to the bundle whole.
var bundleStanzas = map[string]bool{
	"validator_token":          true,
	"validator_key_revocation": true,
	"ips_fixed":                true,
	"cluster_nodes":            true,
	"rpc_startup":              true,
	"ssl_cert":                 true,
	"peer_private":             true,
}

// Stanzas allowed on-chain after line scanning.
var onChainStanzas = map[string]bool{
	"server": true, "node_size": true, "node_db": true, "database_path": true,
	"ledger_history": true, "fetch_depth": true, "path_search": true, "path_search_fast": true,
	"path_search_max": true, "path_search_old": true, "debug_logfile": true, "sntp_servers": true,
	"voting": true, "amendments": true, "veto_amendments": true, "ssl_verify": true,
	"ssl_verify_file": true, "ssl_verify_dir": true, "validators_file": true,
	"validator_list_sites": true, "validator_list_keys": true, "validator_list_threshold": true,
	"validators": true, "ips": true, "peers_max": true, "peers_in_max": true, "peers_out_max": true,
	"reduce_relay": true, "compression": true, "ledger_tx_tables": true, "workers": true,
	"io_workers": true, "prefetch_workers": true, "overlay": true, "transaction_queue": true,
	"network_id": true, "relay_proposals": true, "relay_validations": true, "beta_rpc_api": true,
	"max_transactions": true, "insight": true, "perf": true, "signing_support": true, "crawl": true,
	"vl": true, "import_db": true, "ledger_replay": true, "sqlite": true, "load": true,
	"rpc_ip": true, "rpc_port": true,
}

// Stanzas whose lines legitimately contain long hex or base58 keys.
var keyStanzas = map[string]bool{
	"validator_list_keys": true, "validators": true, "amendments": true, "veto_amendments": true,
	"cluster_nodes": true, "validator_token": true, "validator_key_revocation": true,
}

var (
	reSeed    = regexp.MustCompile(`\bs[1-9A-HJ-NP-Za-km-z]{28,30}\b`)
	reRFC1751 = regexp.MustCompile(`\b(?:[A-Z]{1,4} ){11}[A-Z]{1,4}\b`)
	reHex     = regexp.MustCompile(`[0-9A-Fa-f]{64,}`)
	reBase64  = regexp.MustCompile(`[A-Za-z0-9+/=]{44,}`)
	reIP      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
)

// Move records one redaction for the report and the manifest.
type Move struct {
	Stanza string
	Lines  int
	Reason string
}

// Result is the split output.
type Result struct {
	OnChain *cfg.File
	Bundle  *cfg.File
	Moves   []Move
	// Role is "validator" when a validator token is present, else "node".
	Role string
}

// RefusedError names the C0 content that stopped the run.
type RefusedError struct {
	Stanza string
	LineNo int
	Reason string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("refused: [%s] (line %d): %s", e.Stanza, e.LineNo, e.Reason)
}

// Split classifies f. The config is the main xrpld.cfg. validators.txt
// uses the same rules and simply ends up all on-chain.
func Split(f *cfg.File) (*Result, error) {
	res := &Result{OnChain: &cfg.File{}, Bundle: &cfg.File{}, Role: "node"}
	for _, s := range f.Stanzas {
		if reason, bad := neverStanzas[s.Name]; bad {
			return nil, &RefusedError{Stanza: s.Name, LineNo: s.LineNo, Reason: reason}
		}
		if !keyStanzas[s.Name] {
			for i, l := range s.Lines {
				if reSeed.MatchString(l) || reRFC1751.MatchString(l) {
					return nil, &RefusedError{Stanza: s.Name, LineNo: s.LineNo + i + 1, Reason: "line looks like a seed or secret key"}
				}
			}
		}
		for i, l := range s.Lines {
			if strings.Contains(l, "-----BEGIN") {
				return nil, &RefusedError{Stanza: s.Name, LineNo: s.LineNo + i + 1, Reason: "PEM key material"}
			}
		}
		if s.Name == "validator_token" {
			res.Role = "validator"
		}
		switch {
		case bundleStanzas[s.Name]:
			res.moveStanza(s, "bundle-only stanza")
		case !onChainStanzas[s.Name] && !strings.HasPrefix(s.Name, "port_"):
			res.moveStanza(s, "stanza not on the on-chain allowlist")
		default:
			res.splitLines(s)
		}
	}
	return res, nil
}

func (r *Result) moveStanza(s *cfg.Stanza, reason string) {
	r.Bundle.Stanzas = append(r.Bundle.Stanzas, &cfg.Stanza{Name: s.Name, Lines: append([]string{}, s.Lines...)})
	r.OnChain.Stanzas = append(r.OnChain.Stanzas, &cfg.Stanza{Name: s.Name, Lines: []string{MovedMarker}})
	r.Moves = append(r.Moves, Move{Stanza: s.Name, Lines: len(s.Lines), Reason: reason})
}

func (r *Result) splitLines(s *cfg.Stanza) {
	keep := &cfg.Stanza{Name: s.Name}
	moved := &cfg.Stanza{Name: s.Name}
	reason := ""
	for _, l := range s.Lines {
		why := lineReason(s.Name, l)
		if why == "" {
			keep.Lines = append(keep.Lines, l)
			continue
		}
		// One marker per moved line, in place, so Merge restores order.
		keep.Lines = append(keep.Lines, MovedMarker)
		moved.Lines = append(moved.Lines, l)
		reason = why
	}
	if len(moved.Lines) > 0 {
		r.Bundle.Stanzas = append(r.Bundle.Stanzas, moved)
		r.Moves = append(r.Moves, Move{Stanza: s.Name, Lines: len(moved.Lines), Reason: reason})
	}
	r.OnChain.Stanzas = append(r.OnChain.Stanzas, keep)
}

// lineReason returns "" if the line may stay on-chain, else why it moves.
func lineReason(stanza, line string) string {
	key := strings.ToLower(strings.TrimSpace(strings.SplitN(line, "=", 2)[0]))
	if strings.HasPrefix(stanza, "port_") && (key == "admin" || key == "secure_gateway") {
		return "admin access list"
	}
	if !keyStanzas[stanza] {
		if reHex.MatchString(line) {
			return "long hex value"
		}
		if reBase64.MatchString(line) {
			return "long base64 value"
		}
	}
	for _, m := range reIP.FindAllString(line, -1) {
		ip := net.ParseIP(m)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return "private network address"
		}
		if strings.HasPrefix(stanza, "port_") && key == "ip" {
			return "listen address"
		}
	}
	return ""
}

// Merge recombines an on-chain file with its bundle for restore. Each
// marker in an on-chain stanza is replaced by the next bundle line for that
// stanza; a stanza that is a single marker takes the whole bundle stanza.
// Bundle-only stanzas are appended. Without a bundle the markers stay so
// the operator sees the gaps.
func Merge(onChain, bundle *cfg.File) *cfg.File {
	out := &cfg.File{}
	seen := map[string]bool{}
	for _, s := range onChain.Stanzas {
		c := &cfg.Stanza{Name: s.Name}
		var bl []string
		if b := bundle.Get(s.Name); b != nil {
			bl = append([]string{}, b.Lines...)
		}
		markers := 0
		for _, l := range s.Lines {
			if l == MovedMarker {
				markers++
			}
		}
		for _, l := range s.Lines {
			if l != MovedMarker {
				c.Lines = append(c.Lines, l)
				continue
			}
			switch {
			case len(bl) == 0:
				c.Lines = append(c.Lines, MovedMarker)
			case markers == 1:
				c.Lines = append(c.Lines, bl...)
				bl = nil
			default:
				c.Lines = append(c.Lines, bl[0])
				bl = bl[1:]
			}
		}
		c.Lines = append(c.Lines, bl...)
		out.Stanzas = append(out.Stanzas, c)
		seen[s.Name] = true
	}
	for _, b := range bundle.Stanzas {
		if !seen[b.Name] {
			out.Stanzas = append(out.Stanzas, &cfg.Stanza{Name: b.Name, Lines: append([]string{}, b.Lines...)})
		}
	}
	return out
}
