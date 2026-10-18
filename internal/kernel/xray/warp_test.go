package xray

import (
	"encoding/json"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
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

func TestBuildConfig_WarpAll(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{}, testWarpAccount(), nil)

	outbounds := cfg["outbounds"].([]M)
	var warpOut M
	for _, ob := range outbounds {
		if ob["tag"] == "warp" {
			warpOut = ob
		}
	}
	if warpOut == nil {
		t.Fatal("warp outbound missing")
	}
	if warpOut["protocol"] != "wireguard" {
		t.Errorf("protocol: got %v", warpOut["protocol"])
	}
	settings := warpOut["settings"].(M)
	if settings["NoKernelTun"] != true {
		t.Error("NoKernelTun must be true in containers")
	}
	peers := settings["peers"].([]M)
	if len(peers) != 1 || peers[0]["endpoint"] != "162.159.192.1:2408" {
		t.Errorf("peers: got %#v", peers)
	}
	if reserved, ok := peers[0]["reserved"].([]uint8); !ok || len(reserved) != 3 {
		t.Errorf("reserved: got %#v", peers[0]["reserved"])
	}

	// Anti-loop rule must exist and come before the final warp rule.
	routing := cfg["routing"].(M)
	rules := routing["rules"].([]M)
	antiLoopIdx, finalWarpIdx := -1, -1
	for i, r := range rules {
		if ip, ok := r["ip"].([]string); ok && len(ip) > 0 && ip[0] == "162.159.192.0/24" {
			antiLoopIdx = i
		}
		if r["outboundTag"] == "warp" {
			finalWarpIdx = i
		}
	}
	if antiLoopIdx == -1 {
		t.Error("anti-loop rule missing")
	}
	if finalWarpIdx == -1 {
		t.Error("final warp rule missing")
	}
	if antiLoopIdx > finalWarpIdx {
		t.Errorf("anti-loop rule (%d) must precede final warp rule (%d)", antiLoopIdx, finalWarpIdx)
	}

	// JSON must round-trip (full protobuf parse needs a running instance;
	// marshal is the practical smoke test).
	data, err := json.Marshal(cfg)
	if err != nil || len(data) == 0 {
		t.Fatalf("marshal: %v", err)
	}
}

func TestBuildConfig_WarpNoAccount(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{}, nil, nil)

	for _, ob := range cfg["outbounds"].([]M) {
		if ob["tag"] == "warp" {
			t.Fatal("warp outbound present without account")
		}
	}
	routing := cfg["routing"].(M)
	for _, r := range routing["rules"].([]M) {
		if r["outboundTag"] == "warp" {
			t.Fatal("warp routing rule present without account")
		}
	}
}
