package singbox

import (
	"encoding/json"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	singJSON "github.com/sagernet/sing/common/json"
	"context"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/warp"
)

func testWarpAccount() *warp.Account {
	return &warp.Account{
		DeviceID:     "test-device",
		AccessToken:  "token",
		PrivateKey:   "eD3LQbPHWBhMNzCTDK3fFPssDCnTmSROGvGhP7h4WI=",
		Addresses:    [2]string{"172.16.0.2", "2606:4700:110:8a62:6c34:1478:2a49:7a4b"},
		PeerKey:      "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		Reserved:     [3]byte{1, 2, 3},
		EndpointHost: "162.159.192.1",
		EndpointPort: 2408,
	}
}

// assertParsesAsSingbox verifies the generated config is accepted by the
// vendored sing-box option parser (the same code path Start uses). It does
// not create an instance — that needs listeners.
func assertParsesAsSingbox(t *testing.T, cfg M) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ctx := include.Context(context.Background())
	if _, err := singJSON.UnmarshalExtendedContext[box.Options](ctx, data); err != nil {
		t.Fatalf("sing-box rejects config: %v\nconfig: %s", err, data)
	}
}

func TestBuildConfig_WarpAll(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{}, testWarpAccount(), "all", nil)

	eps, ok := cfg["endpoints"].([]M)
	if !ok || len(eps) != 1 {
		t.Fatalf("endpoints: got %#v", cfg["endpoints"])
	}
	assertMapValue(t, eps[0], "type", "wireguard")
	assertMapValue(t, eps[0], "tag", "warp")
	assertMapValue(t, eps[0], "private_key", "eD3LQbPHWBhMNzCTDK3fFPssDCnTmSROGvGhP7h4WI=")

	route := cfg["route"].(M)
	assertMapValue(t, route, "final", "warp")

	if _, ok := cfg["dns"]; !ok {
		t.Error("dns not injected for warp resolve")
	}

	assertParsesAsSingbox(t, cfg)
}

func TestBuildConfig_WarpV6(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{}, testWarpAccount(), "v6", nil)

	route := cfg["route"].(M)
	assertMapValue(t, route, "final", "direct")

	rules := route["rules"].([]M)
	found := false
	for _, r := range rules {
		if v, ok := r["ip_version"]; ok && v == 6 {
			if o, ok := r["outbound"]; ok && o == "warp" {
				found = true
			}
		}
	}
	if !found {
		t.Error("no ip_version=6 -> warp rule in v6 mode")
	}
	assertParsesAsSingbox(t, cfg)
}

func TestBuildConfig_WarpWithoutAccount(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{}, nil, "", nil)

	if _, ok := cfg["endpoints"]; ok {
		t.Error("endpoints injected without warp account")
	}
	route := cfg["route"].(M)
	assertMapValue(t, route, "final", "direct")
}

func TestBuildRoutes_WarpCustomRouteWins(t *testing.T) {
	customRules := []model.CustomRouteRule{{
		Name: "direct-example",
		Match: model.RouteMatch{
			DomainSuffixes: []string{"example.com"},
		},
		Action: model.RouteAction{Type: "direct"},
	}}
	route := buildRoutes(nil, customRules, nil, "warp", "all", "")

	allRules := route["rules"].([]M)
	// Structured custom rules must stay first.
	if allRules[0]["outbound"] != "direct" {
		t.Errorf("custom direct rule should be first rule, got %#v", allRules[0])
	}
	assertMapValue(t, route, "final", "warp")
}

func TestOutboundConfigToSingbox_WireguardBecomesEndpoint(t *testing.T) {
	oc := model.OutboundConfig{
		Tag:      "warp-tag",
		Protocol: "wireguard",
		Settings: map[string]any{
			"secret_key": "privkey=",
			"address":    []any{"172.16.0.2/32"},
			"peers": []any{
				map[string]any{
					"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
					"endpoint":   "162.159.192.1:2408",
				},
			},
		},
	}
	outbound, ep := outboundConfigToSingbox(oc)
	if ep == nil {
		t.Fatal("wireguard outbound should produce an endpoint")
	}
	assertMapValue(t, ep, "type", "wireguard")
	assertMapValue(t, ep, "tag", "warp-tag")
	assertMapValue(t, ep, "private_key", "privkey=")
	peers := ep["peers"].([]M)
	if len(peers) != 1 {
		t.Fatalf("peers: got %d", len(peers))
	}
	assertMapValue(t, peers[0], "address", "162.159.192.1")
	if port, ok := peers[0]["port"].(int); !ok || port != 2408 {
		t.Errorf("peer port: got %#v", peers[0]["port"])
	}
	assertMapValue(t, outbound, "tag", "warp-tag")
}

func TestBuildConfig_AllProtocolsParseWithWarp(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "warn"}
	protocols := []string{"vmess", "vless", "trojan", "shadowsocks", "socks", "http"}
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			nc := &panel.NodeConfig{Protocol: proto, ServerPort: 443}
			cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{}, testWarpAccount(), "all", nil)
			assertParsesAsSingbox(t, cfg)
		})
	}
}
