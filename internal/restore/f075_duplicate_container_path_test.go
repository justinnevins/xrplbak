package restore

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
)

// F-075: Build refused a manifest that lists one path twice, but took a
// container that carries one path twice and kept the last entry without a
// word. container.Encode never writes that, so only someone holding the
// epoch key can author it.
func TestF075BuildRefusesAPathTwiceInOneContainer(t *testing.T) {
	const path = "/etc/xrpld/xrpld.cfg"
	m := &manifest.Manifest{Files: []manifest.File{{Path: path, Where: "onchain+bundle"}}}
	a := container.Entry{Path: path, Data: []byte("[a]\n1\n")}
	b := container.Entry{Path: path, Data: []byte("[b]\n2\n")}

	for name, c := range map[string]struct{ on, bundle []container.Entry }{
		"twice on-chain":      {on: []container.Entry{a, b}},
		"twice in the bundle": {on: []container.Entry{a}, bundle: []container.Entry{a, b}},
	} {
		p, err := Build(m, c.on, c.bundle)
		if err == nil {
			t.Errorf("%s: Build returned a plan with %d file(s); want a refusal", name, len(p.Files))
			continue
		}
		if !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "more than once") {
			t.Errorf("%s: the refusal does not name the path and the reason: %v", name, err)
		}
	}

	// One entry on-chain plus one in the bundle is the normal split file.
	if _, err := Build(m, []container.Entry{a}, []container.Entry{b}); err != nil {
		t.Fatalf("one entry per container must still build: %v", err)
	}
}
