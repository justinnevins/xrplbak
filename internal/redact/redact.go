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

// MovedMarker is the line left in the on-chain copy where a line moved to
// the bundle, so a bundle-less restore still boots and a human sees what is
// missing.
const MovedMarker = "# xrplbak: content moved to the off-chain bundle"

// CommentMarker is left in place of a line's inline comment when only the
// comment moved. The setting itself stays on-chain, so a bundle-less restore
// keeps working, and the operator can still see that something was removed.
const CommentMarker = "# xrplbak: comment moved to the off-chain bundle"

// Mode says where the operator's comments go. Comments are free text the
// tool cannot classify, so the default keeps them off a public ledger. They
// are never discarded in either mode.
type Mode int

const (
	// CommentsToBundle puts comments in the encrypted off-chain bundle.
	CommentsToBundle Mode = iota
	// CommentsOnChain puts them in the on-chain ciphertext instead. The
	// operator asks for this explicitly and acknowledges it once.
	CommentsOnChain
)

// Options for one split.
type Options struct {
	Comments Mode
	// PeersOnChain puts [ips_fixed] on-chain, line by line, after the
	// operator acknowledges it. Each line is still scanned, so a private
	// address or an internal hostname moves to the bundle anyway.
	PeersOnChain bool
}

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

// Stanzas whose lines legitimately contain long hex or base58 keys, so the
// hex and base64 scanners skip them.
var keyStanzas = map[string]bool{
	"validator_list_keys": true, "validators": true, "amendments": true, "veto_amendments": true,
	"cluster_nodes": true, "validator_token": true, "validator_key_revocation": true,
}

// Stanzas whose base64 bodies can contain runs that look like seeds. The
// seed scanner skips only these two; everything else is scanned.
var blobStanzas = map[string]bool{"validator_token": true, "validator_key_revocation": true}

// Stanzas whose lines are network hosts rather than key=value settings.
// Their first field is the host, so a single-label name there is an
// internal name, not a public one.
var hostValueStanzas = map[string]bool{
	"ips": true, "ips_fixed": true, "sntp_servers": true,
	"cluster_nodes": true, "validator_list_sites": true,
}

// specialUseSuffixes are DNS suffixes reserved for private or internal
// networks (RFC 6761 .test/.localhost, RFC 6762 .local, RFC 8375
// .home.arpa, RFC 7686 .onion) plus the conventional corporate ones. A
// name under any of them describes the operator's own network and never
// belongs on a public ledger.
var specialUseSuffixes = []string{
	".local", ".localhost", ".localdomain", ".internal", ".intranet",
	".lan", ".home", ".home.arpa", ".corp", ".private", ".test", ".onion",
}

// Keys inside [port_*] stanzas that carry credentials or key paths.
var portSecretKeys = map[string]bool{
	"admin": true, "secure_gateway": true, "user": true, "password": true,
	"admin_user": true, "admin_password": true, "ssl_key": true, "ssl_cert": true, "ssl_chain": true,
}

var (
	reSeed    = regexp.MustCompile(`\bs[1-9A-HJ-NP-Za-km-z]{28,30}\b`)
	reRFC1751 = regexp.MustCompile(`\b(?:[A-Z]{1,4} ){11}[A-Z]{1,4}\b`)
	reHex     = regexp.MustCompile(`[0-9A-Fa-f]{64,}`)
	reBase64  = regexp.MustCompile(`[A-Za-z0-9+/=]{44,}`)
	reDotted  = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\b`)
	reIP      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
)

// Move records one redaction for the report and the manifest.
type Move struct {
	File   string // set by backup, which knows the path; Split does not
	Stanza string
	Lines  int
	// Comments counts the lines in Lines that were comments, or settings
	// whose comment alone moved. When Comments == Lines every setting in
	// the stanza is still on-chain, and a restore without the bundle is
	// missing prose, not configuration.
	Comments int
	Reason   string
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

// Split classifies f line by line. The config is the main xrpld.cfg.
// validators.txt uses the same rules and simply ends up all on-chain.
//
// Both outputs are whole documents. OnChain is the operator's file with
// every moved line replaced by a marker, so it still parses as a config and
// a bundle-less restore boots. Bundle holds the moved lines in the order
// they were taken. Merge puts them back, and the result is the operator's
// original bytes.
func Split(f *cfg.File, opt Options) (*Result, error) {
	res := &Result{OnChain: &cfg.File{}, Bundle: &cfg.File{}, Role: "node"}
	if err := refuse(f); err != nil {
		return nil, err
	}
	for _, s := range f.Stanzas {
		if s.Name == "validator_token" && len(s.Lines) > 0 {
			res.Role = "validator"
		}
	}
	// One Move per stanza, in the order stanzas first lose a line.
	at := map[string]int{}
	move := func(l cfg.Line, marker, reason string) {
		out := l
		out.Raw = marker
		if marker == CommentMarker {
			out.Raw = l.Value + " " + CommentMarker
		}
		res.OnChain.Lines = append(res.OnChain.Lines, out)
		res.Bundle.Lines = append(res.Bundle.Lines, l)
		i, ok := at[l.Stanza]
		if !ok {
			i = len(res.Moves)
			at[l.Stanza] = i
			res.Moves = append(res.Moves, Move{Stanza: l.Stanza})
		}
		res.Moves[i].Lines++
		if l.Kind == cfg.Comment || marker == CommentMarker {
			res.Moves[i].Comments++
		}
		res.Moves[i].Reason = reason
	}
	keep := func(l cfg.Line) { res.OnChain.Lines = append(res.OnChain.Lines, l) }

	for _, l := range f.Lines {
		switch l.Kind {
		case cfg.Blank, cfg.Header:
			keep(l)
		case cfg.Comment:
			if opt.Comments == CommentsToBundle {
				move(l, MovedMarker, "operator comment")
				continue
			}
			if why := lineReason(l.Stanza, l.Raw); why != "" {
				move(l, MovedMarker, why)
				continue
			}
			keep(l)
		case cfg.Value:
			if why := valueReasonOpt(l.Stanza, l.Value, opt); why != "" {
				move(l, MovedMarker, why)
				continue
			}
			if l.Comment == "" {
				keep(l)
				continue
			}
			// The setting may stay; its comment is judged on its own.
			if opt.Comments == CommentsToBundle {
				move(l, CommentMarker, "operator comment")
				continue
			}
			if why := lineReason(l.Stanza, l.Comment); why != "" {
				move(l, CommentMarker, why)
				continue
			}
			keep(l)
		}
	}
	res.OnChain.Stanzas = cfg.Parse(res.OnChain.Render()).Stanzas
	res.Bundle.Stanzas = cfg.Parse(res.Bundle.Render()).Stanzas
	return res, nil
}

// refuse stops the run on content xrplbak must never handle. It reads every
// line, comments included: a seed written in a comment is still a seed in
// the file.
func refuse(f *cfg.File) error {
	for _, s := range f.Stanzas {
		if reason, bad := neverStanzas[s.Name]; bad {
			return &RefusedError{Stanza: s.Name, LineNo: s.LineNo, Reason: reason}
		}
	}
	for _, l := range f.Lines {
		if l.Kind == cfg.Blank || l.Kind == cfg.Header {
			continue
		}
		text := l.Raw
		if !blobStanzas[l.Stanza] && (reSeed.MatchString(text) || reRFC1751.MatchString(text)) {
			return &RefusedError{Stanza: l.Stanza, LineNo: l.No, Reason: "line looks like a seed or secret key"}
		}
		if strings.Contains(text, "-----BEGIN") {
			return &RefusedError{Stanza: l.Stanza, LineNo: l.No, Reason: "PEM key material"}
		}
		if strings.Contains(text, cfg.MarkerPrefix) {
			return &RefusedError{Stanza: l.Stanza, LineNo: l.No, Reason: "file contains an xrplbak restore marker; finish the restore (merge the bundle) before backing it up"}
		}
	}
	return nil
}

// peerStanzas may go on-chain line by line when the operator opts in with
// PeersOnChain. [cluster_nodes] is not here: its lines name the node keys
// of the operator's own cluster.
var peerStanzas = map[string]bool{"ips_fixed": true}

// valueReasonOpt is valueReason with the operator's opt-ins applied.
func valueReasonOpt(stanza, value string, opt Options) string {
	if opt.PeersOnChain && peerStanzas[stanza] {
		return lineReason(stanza, value)
	}
	return valueReason(stanza, value)
}

// valueReason decides a setting line: the stanza allowlist first, then the
// per-line scanners.
func valueReason(stanza, value string) string {
	switch {
	case bundleStanzas[stanza]:
		return "bundle-only stanza"
	case !onChainStanzas[stanza] && !strings.HasPrefix(stanza, "port_") && stanza != "":
		return "stanza not on the on-chain allowlist"
	case stanza == "":
		return "line sits outside any stanza"
	}
	return lineReason(stanza, value)
}

// Merge recombines an on-chain document with its bundle. Each marker in the
// on-chain document takes the next line from the bundle, in the order Split
// took them, so the result is the operator's original file. Without a bundle
// the markers stay, so the operator sees the gaps rather than a quietly
// shorter file.
func Merge(onChain, bundle *cfg.File) *cfg.File {
	out := &cfg.File{}
	rest := bundle.Lines
	take := func() (cfg.Line, bool) {
		for len(rest) > 0 {
			l := rest[0]
			rest = rest[1:]
			// Render appends a final empty segment; it is not a moved line.
			if l.Raw == "" && l.End == "" {
				continue
			}
			return l, true
		}
		return cfg.Line{}, false
	}
	for _, l := range onChain.Lines {
		if !isMarker(l) {
			out.Lines = append(out.Lines, l)
			continue
		}
		b, ok := take()
		if !ok {
			out.Lines = append(out.Lines, l)
			continue
		}
		b.End = l.End
		out.Lines = append(out.Lines, b)
	}
	for {
		b, ok := take()
		if !ok {
			break
		}
		out.Lines = append(out.Lines, b)
	}
	out.Stanzas = cfg.Parse(out.Render()).Stanzas
	return out
}

// isMarker reports whether a line stands in for content in the bundle,
// either as a whole line or as a replaced inline comment.
func isMarker(l cfg.Line) bool {
	t := strings.TrimSpace(l.Raw)
	return t == MovedMarker || strings.HasSuffix(t, CommentMarker)
}

// lineReason returns "" if the line may stay on-chain, else why it moves.
func lineReason(stanza, line string) string {
	key := strings.ToLower(strings.TrimSpace(strings.SplitN(line, "=", 2)[0]))
	if strings.HasPrefix(stanza, "port_") && portSecretKeys[key] && !loopbackOnly(key, line) {
		return "access list, credential, or key path"
	}
	if !keyStanzas[stanza] {
		if reHex.MatchString(line) {
			return "long hex value"
		}
		if reBase64.MatchString(line) {
			return "long base64 value"
		}
	}
	if why := hostReason(stanza, key, line); why != "" {
		return why
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

// hostReason moves lines that name a host on the operator's own network.
// Two rules, both deliberately conservative: a name under a special-use
// suffix is internal wherever it appears, and in a host-valued stanza a
// single-label name has no public domain and so is internal too. A public
// FQDN stays on-chain even when it is the operator's own machine, because
// nothing in the text distinguishes it from a public hub; operators who
// care must move those stanzas by hand.
func hostReason(stanza, key, line string) string {
	for _, tok := range reDotted.FindAllString(line, -1) {
		if specialUse(strings.ToLower(tok)) {
			return "internal hostname"
		}
	}
	if !hostValueStanzas[stanza] && !(strings.HasPrefix(stanza, "port_") && key == "ip") {
		return ""
	}
	h := hostValue(stanza, line)
	switch {
	case h == "" || h == "localhost" || strings.Contains(h, "."):
		return ""
	case net.ParseIP(h) != nil:
		return ""
	}
	return "bare hostname with no public domain"
}

// specialUse reports whether a lowercased dotted name ends in a suffix
// reserved for private or internal networks.
func specialUse(name string) bool {
	for _, suf := range specialUseSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// hostValue pulls the host out of a host-valued line: the first field of
// an [ips]-style line, or the value of a [port_*] key, minus any scheme,
// path, or port. It returns "" for anything it cannot read as one host,
// including bracketed IPv6, which the IP scanner handles.
func hostValue(stanza, line string) string {
	v := strings.TrimSpace(line)
	if strings.HasPrefix(stanza, "port_") {
		i := strings.Index(v, "=")
		if i < 0 {
			return ""
		}
		v = strings.TrimSpace(v[i+1:])
	}
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	h := f[0]
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") {
		return ""
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// loopbackOnly reports whether an admin or secure_gateway line lists only
// loopback addresses (127.0.0.0/8 and ::1, as addresses or CIDR blocks
// inside them). Such a list says nothing about the operator's network. An
// empty list, a name, or any other address returns false.
func loopbackOnly(key, line string) bool {
	if key != "admin" && key != "secure_gateway" {
		return false
	}
	i := strings.Index(line, "=")
	if i < 0 {
		return false
	}
	fields := strings.FieldsFunc(line[i+1:], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(fields) == 0 {
		return false
	}
	loop4 := &net.IPNet{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}
	for _, f := range fields {
		if ip := net.ParseIP(f); ip != nil {
			if !ip.IsLoopback() {
				return false
			}
			continue
		}
		ip, n, err := net.ParseCIDR(f)
		if err != nil || !ip.IsLoopback() {
			return false
		}
		ones, bits := n.Mask.Size()
		if bits == 32 && (ones < 8 || !loop4.Contains(n.IP)) {
			return false
		}
		if bits == 128 && ones != 128 {
			return false
		}
	}
	return true
}
