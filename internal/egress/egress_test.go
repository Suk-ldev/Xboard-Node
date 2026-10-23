package egress

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/vpngate"
)

func TestValidateCombinations(t *testing.T) {
	cases := []struct {
		warp, vg string
		ok       bool
	}{
		{"off", "off", true},
		{"", "off", true},
		{"v6", "off", true},
		{"off", "all", true}, // url filled below
		{"v6", "all", true},
		{"all", "off", true},
		{"all", "all", false}, // WARP would swallow the tunnel exit
		{"bogus", "off", false},
		{"off", "bogus", false},
	}
	for _, c := range cases {
		st := &State{WarpMode: c.warp, Vpngate: VpngateMode(c.vg)}
		if c.vg == "all" {
			st.VpngateSource.URL = DefaultTestURL
		}
		err := st.Validate()
		if c.ok && err != nil {
			t.Errorf("warp=%q vg=%q: unexpected error %v", c.warp, c.vg, err)
		}
		if !c.ok && err == nil {
			t.Errorf("warp=%q vg=%q: expected error", c.warp, c.vg)
		}
	}
}

const DefaultTestURL = "https://example.com/api"

func TestValidateVpngateNeedsURL(t *testing.T) {
	st := &State{WarpMode: "off", Vpngate: VpngateAll}
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "url") {
		t.Errorf("expected url error, got %v", err)
	}
	st.VpngateSource.URL = DefaultTestURL
	if err := st.Validate(); err != nil {
		t.Errorf("with url: %v", err)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	st := &State{
		WarpMode: "v6",
		Vpngate:  VpngateAll,
		VpngateSource: vpngate.Source{
			URL:             DefaultTestURL,
			ResidentialOnly: true,
			MaxFraudScore:   25,
			Countries:       []string{"Japan"},
		},
		PinnedNode: "vpn1.opengw.net:992",
	}
	if err := store.Save(st); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.WarpMode != "v6" || got.Vpngate != VpngateAll || got.PinnedNode != st.PinnedNode {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if got.VpngateSource.MaxFraudScore != 25 || len(got.VpngateSource.Countries) != 1 {
		t.Errorf("source mismatch: %+v", got.VpngateSource)
	}
	if !got.WarpEnabled() || !got.VpngateEnabled() {
		t.Errorf("enabled flags wrong")
	}
}

func TestPickInitialSkipsUsedRing(t *testing.T) {
	st := &State{WarpMode: "off", Vpngate: VpngateAll, VpngateSource: vpngate.Source{URL: "x"}}
	h := NewHealthLoop(st, NewStore(t.TempDir()), vpngate.NewManager(st.VpngateSource), nil, nil, vpngate.NewEgress(""))
	rows := []vpngate.Row{
		{Host: "a.opengw.net", IP: "1.2.3.4", Port: 1},
		{Host: "b.opengw.net", IP: "5.6.7.8", Port: 2},
	}
	r1, ok := h.PickInitial(rows)
	if !ok || r1.Host != "a.opengw.net" {
		t.Fatalf("first pick = %+v ok=%v", r1, ok)
	}
	h.markUsed(r1.Key())
	r2, ok := h.PickInitial(rows)
	if !ok || r2.Host != "b.opengw.net" {
		t.Fatalf("second pick should skip used: %+v ok=%v", r2, ok)
	}
}
