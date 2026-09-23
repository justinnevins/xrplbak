package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildPeersOnChain pins that Options.PeersOnChain reaches the split:
// a public fixed peer goes on-chain only when asked, and a private one
// never does.
func TestBuildPeersOnChain(t *testing.T) {
	e := newEnv(t)
	cfgPath := filepath.Join(e.dir, "xrpld.cfg")
	conf := "[server]\nport_peer\n\n[port_peer]\nport = 51235\nip = 0.0.0.0\nprotocol = peer\n\n[ips_fixed]\nr.ripple.com 51235\n10.20.30.40 2459\n"
	if err := os.WriteFile(cfgPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{false, true} {
		o := e.opts(t, 1)
		o.ConfigPath, o.ValidatorsPath, o.PeersOnChain = cfgPath, "", on
		p, err := Build(o)
		if err != nil {
			t.Fatal(err)
		}
		txt := p.OnChainTxt[cfgPath]
		if got := strings.Contains(txt, "r.ripple.com 51235"); got != on {
			t.Fatalf("PeersOnChain=%v: public peer on-chain = %v:\n%s", on, got, txt)
		}
		if strings.Contains(txt, "10.20.30.40") {
			t.Fatalf("PeersOnChain=%v: a private peer reached the on-chain text:\n%s", on, txt)
		}
	}
}
