package warp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestDecodeReserved(t *testing.T) {
	// client_id is unpadded base64url of 3 bytes.
	got := decodeReserved("AQID") // 01 02 03
	if got != [3]byte{1, 2, 3} {
		t.Errorf("decodeReserved(AQID) = %v, want [1 2 3]", got)
	}
	if got := decodeReserved(""); got != [3]byte{} {
		t.Errorf("decodeReserved(\"\") = %v, want zero", got)
	}
	if got := decodeReserved("!!!not-base64!!!"); got != [3]byte{} {
		t.Errorf("invalid input should produce zero, got %v", got)
	}
}

func TestAccountAddressList(t *testing.T) {
	acc := &Account{Addresses: [2]string{"172.16.0.2", "2606:4700:110::7a4b"}}
	got := acc.AddressList()
	if len(got) != 2 || got[0] != "172.16.0.2/32" || got[1] != "2606:4700:110::7a4b/128" {
		t.Errorf("AddressList() = %v", got)
	}

	// Already-prefixed input is passed through untouched.
	acc2 := &Account{Addresses: [2]string{"172.16.0.2/32", ""}}
	got2 := acc2.AddressList()
	if len(got2) != 1 || got2[0] != "172.16.0.2/32" {
		t.Errorf("AddressList(prefixed) = %v", got2)
	}
}

func TestAccountFamilies(t *testing.T) {
	both := &Account{Addresses: [2]string{"172.16.0.2", "2606:4700:110::7a4b"}}
	if !both.HasV4() || !both.HasV6() {
		t.Error("full WARP account should have both families")
	}
	v4only := &Account{Addresses: [2]string{"172.16.0.2", ""}}
	if !v4only.HasV4() || v4only.HasV6() {
		t.Error("v4only family detection wrong")
	}
}

func TestManagerPersistence(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "warp")
	mgr, err := NewManager(&config.WarpConfig{}, dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	_ = stateDir
	acc := &Account{
		DeviceID:     "dev-1",
		AccessToken:  "tok",
		PrivateKey:   "key=",
		Addresses:    [2]string{"172.16.0.2", "2606:4700:110::7a4b"},
		PeerKey:      "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		EndpointHost: "162.159.192.1",
		EndpointPort: 2408,
	}
	if err := mgr.save(acc); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := loadAccountFile(filepath.Join(stateDir, "node-7.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.DeviceID != "dev-1" || loaded.EndpointPort != 2408 {
		t.Errorf("round-trip mismatch: %+v", loaded)
	}
	data, _ := json.Marshal(loaded)
	if len(data) == 0 {
		t.Error("empty json")
	}
}

func TestManagerNodeFileNames(t *testing.T) {
	dir := t.TempDir()
	mgr7, _ := NewManager(&config.WarpConfig{}, dir, 7)
	mgr0, _ := NewManager(&config.WarpConfig{}, dir, 0)
	if mgr7.fileName != "node-7.json" {
		t.Errorf("node 7 file: %s", mgr7.fileName)
	}
	if mgr0.fileName != "node.json" {
		t.Errorf("node 0 file: %s", mgr0.fileName)
	}
}

func TestCandidateEndpoints(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewManager(&config.WarpConfig{}, dir, 1)
	eps := mgr.CandidateEndpoints()
	if len(eps) == 0 {
		t.Fatal("no default endpoints")
	}
	if eps[0] != "162.159.192.1:2408" {
		t.Errorf("first default: %s", eps[0])
	}

	// Explicit override wins.
	mgr2, _ := NewManager(&config.WarpConfig{Endpoints: "10.0.0.1:1234, 10.0.0.2:1234"}, dir, 1)
	got := mgr2.CandidateEndpoints()
	if len(got) != 2 || got[0] != "10.0.0.1:1234" {
		t.Errorf("override endpoints: %v", got)
	}

	// Registered endpoint from the account goes first.
	mgr3, _ := NewManager(&config.WarpConfig{}, dir, 1)
	mgr3.account = &Account{EndpointHost: "203.0.113.5", EndpointPort: 8443}
	got3 := mgr3.CandidateEndpoints()
	if got3[0] != "203.0.113.5:8443" {
		t.Errorf("registered endpoint first: %v", got3)
	}
}

func TestStateFilePermissions(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewManager(&config.WarpConfig{}, dir, 3)
	acc := &Account{DeviceID: "d", AccessToken: "t", PrivateKey: "k", Addresses: [2]string{"172.16.0.2", ""}}
	if err := mgr.save(acc); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "warp", "node-3.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file perms: %v, want 0600 (contains secrets)", perm)
	}
}
