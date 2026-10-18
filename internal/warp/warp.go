// Package warp manages Cloudflare WARP accounts and produces userspace
// WireGuard settings for both kernels (sing-box endpoint / xray outbound).
//
// Account state is persisted per node under <config_dir>/warp so that
// restarts and container rebuilds reuse the same device instead of
// re-registering (registration from datacenter IPs is frequently
// rate-limited by Cloudflare).
package warp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	wcfg "github.com/ViRb3/wgcf/v2/config"
	"github.com/ViRb3/wgcf/v2/openapi"
	"github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Account is the persisted WARP device state. Field names match wgcf's
// wgcf-account.toml semantics so accounts can be migrated by hand.
type Account struct {
	DeviceID    string `json:"device_id"`
	AccessToken string `json:"access_token"`
	PrivateKey  string `json:"private_key"`
	LicenseKey  string `json:"license_key"`
	// Config snapshot from registration — lets the kernel start without an
	// extra API round-trip, and keeps working offline if CF API hiccups.
	Addresses    [2]string `json:"addresses"`    // [v4/32, v6/128]
	PeerKey      string    `json:"peer_key"`     // CF peer public key
	Reserved     [3]byte   `json:"reserved"`     // client_id from CF config
	EndpointHost string    `json:"endpoint_host"`
	EndpointPort int       `json:"endpoint_port"`
}

// Manager owns the per-node WARP account lifecycle.
type Manager struct {
	mu       sync.Mutex
	cfg      *config.WarpConfig
	stateDir string
	fileName string
	account  *Account
}

// NewManager builds a Manager for one node instance.
func NewManager(cfg *config.WarpConfig, configDir string, nodeID int) (*Manager, error) {
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(configDir, "warp")
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create warp state dir: %w", err)
	}
	name := "node.json"
	if nodeID > 0 {
		name = fmt.Sprintf("node-%d.json", nodeID)
	}
	return &Manager{
		cfg:      cfg,
		stateDir: stateDir,
		fileName: name,
	}, nil
}

// Account returns the loaded account (after Ensure).
func (m *Manager) Account() *Account { return m.account }

// Reset drops the stored device and forces a fresh registration on the next
// Ensure. Used by the admin panel ("re-register" button). Registration from
// datacenter IPs is heavily rate-limited — the caller surfaces the error.
func (m *Manager) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.account = nil
	path := filepath.Join(m.stateDir, m.fileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	nlog.Core().Info("warp: account reset, will re-register on next start", "path", path)
	return nil
}

// CandidateEndpoints lists WARP ingress endpoints to try, most preferred
// first. WARP ingress is anycast — one address reaches the nearest
// Cloudflare PoP — but some hosts block specific ports or ranges, so the
// well-known alternates are kept as fallbacks.
func (m *Manager) CandidateEndpoints() []string {
	if m.cfg.Endpoints != "" {
		var out []string
		for _, part := range strings.Split(m.cfg.Endpoints, ",") {
			if ep := strings.TrimSpace(part); ep != "" {
				out = append(out, ep)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	defaults := []string{"162.159.192.1:2408", "162.159.193.1:2408", "162.159.195.1:500"}
	if a := m.account; a != nil && a.EndpointHost != "" {
		registered := net.JoinHostPort(a.EndpointHost, strconv.Itoa(a.EndpointPort))
		// Registered endpoint first, but skip duplicates of the defaults.
		return append([]string{registered}, defaults...)
	}
	return defaults
}

// Ensure loads the persisted account, imports from AccountFile, or registers
// a new device. It never registers more than once per call.
func (m *Manager) Ensure(ctx timeoutContext) (*Account, error) {
	if m.account != nil {
		return m.account, nil
	}

	// 1. Explicit import file takes precedence over persisted state.
	if m.cfg.AccountFile != "" {
		acc, err := loadAccountFile(m.cfg.AccountFile)
		if err != nil {
			return nil, err
		}
		if err := m.completeAccount(acc); err != nil {
			return nil, fmt.Errorf("import account: %w", err)
		}
		if err := m.save(acc); err != nil {
			return nil, err
		}
		m.account = acc
		nlog.Core().Info("warp: imported account", "file", m.cfg.AccountFile, "device_id", acc.DeviceID)
		return m.account, nil
	}

	// 2. Persisted state from a previous run.
	path := filepath.Join(m.stateDir, m.fileName)
	if acc, err := loadAccountFile(path); err == nil {
		if err := m.completeAccount(acc); err != nil {
			return nil, fmt.Errorf("stored account: %w", err)
		}
		m.account = acc
		nlog.Core().Info("warp: loaded stored account", "path", path, "device_id", acc.DeviceID)
		return m.account, nil
	}

	// 3. Register a new device (with retry backoff — CF rate-limits
	// datacenter IPs aggressively).
	timeout := time.Duration(m.cfg.RegisterTimeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt)) * 5 * time.Second // 10s, 20s
			nlog.Core().Warn("warp: registration failed, retrying", "attempt", attempt, "delay", delay, "error", lastErr)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		acc, err := m.register(ctx, timeout)
		if err == nil {
			if err := m.save(acc); err != nil {
				return nil, err
			}
			m.account = acc
			nlog.Core().Info("warp: registered new device", "device_id", acc.DeviceID, "state", filepath.Join(m.stateDir, m.fileName))
			return m.account, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("register WARP device after 3 attempts: %w", lastErr)
}

type timeoutContext interface {
	Done() <-chan struct{}
	Err() error
}

func (m *Manager) register(ctx timeoutContext, timeout time.Duration) (*Account, error) {
	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	type regResult struct {
		device *openapi.Register200Response
		err    error
	}
	ch := make(chan regResult, 1)
	go func() {
		device, err := cloudflare.Register(privateKey.Public(), "xboard-node")
		ch <- regResult{device, err}
	}()
	var device *openapi.Register200Response
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		device = r.device
	case <-time.After(timeout):
		return nil, fmt.Errorf("registration timed out after %s", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if device.Config == nil || len(device.Config.Peers) == 0 {
		return nil, fmt.Errorf("CF response missing wireguard peer config")
	}
	peer := device.Config.Peers[0]
	ep, err := cloudflare.WireGuardEndpoint(peer.Endpoint)
	if err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint %q: %w", ep, err)
	}
	port, _ := strconv.Atoi(portStr)

	acc := &Account{
		DeviceID:     device.Id,
		AccessToken:  device.Token,
		PrivateKey:   privateKey.String(),
		LicenseKey:   m.cfg.LicenseKey,
		Addresses:    [2]string{device.Config.Interface.Addresses.V4, device.Config.Interface.Addresses.V6},
		PeerKey:      peer.PublicKey,
		EndpointHost: host,
		EndpointPort: port,
	}
	if cid := device.Config.ClientId; cid != "" {
		acc.Reserved = decodeReserved(cid)
	}
	if acc.Addresses[0] == "" && acc.Addresses[1] == "" {
		return nil, fmt.Errorf("CF response missing interface addresses")
	}
	return acc, nil
}

// completeAccount fills in config details missing from an imported/stored
// account (e.g. hand-written files with only credentials) by querying the
// device API. A stored config snapshot short-circuits the API call.
func (m *Manager) completeAccount(acc *Account) error {
	if acc.DeviceID == "" || acc.AccessToken == "" || acc.PrivateKey == "" {
		return fmt.Errorf("device_id, access_token and private_key are required")
	}
	if m.cfg.LicenseKey != "" {
		acc.LicenseKey = m.cfg.LicenseKey
	}
	if len(acc.Addresses) == 2 && acc.Addresses[0]+acc.Addresses[1] != "" && acc.PeerKey != "" {
		applyLicense(m.cfg.LicenseKey, acc)
		return nil
	}
	// Snapshot incomplete — refresh from API.
	ctx := wcfg.Context{DeviceId: acc.DeviceID, AccessToken: acc.AccessToken, LicenseKey: acc.LicenseKey}
	dev, err := cloudflare.GetSourceDevice(&ctx)
	if err != nil {
		return fmt.Errorf("fetch device config (account may be expired): %w", err)
	}
	if dev.Config == nil || len(dev.Config.Peers) == 0 {
		return fmt.Errorf("device has no wireguard peer config")
	}
	peer := dev.Config.Peers[0]
	ep, err := cloudflare.WireGuardEndpoint(peer.Endpoint)
	if err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return fmt.Errorf("parse endpoint %q: %w", ep, err)
	}
	port, _ := strconv.Atoi(portStr)
	acc.Addresses = [2]string{dev.Config.Interface.Addresses.V4, dev.Config.Interface.Addresses.V6}
	acc.PeerKey = peer.PublicKey
	acc.EndpointHost = host
	acc.EndpointPort = port
	if cid := dev.Config.ClientId; cid != "" {
		acc.Reserved = decodeReserved(cid)
	}
	applyLicense(m.cfg.LicenseKey, acc)
	return nil
}

// applyLicense pushes a configured license key to the CF account (WARP+).
// Failures are logged, not fatal — the free tier keeps working without it.
func applyLicense(licenseKey string, acc *Account) {
	if licenseKey == "" || licenseKey == acc.LicenseKey {
		return
	}
	ctx := wcfg.Context{DeviceId: acc.DeviceID, AccessToken: acc.AccessToken, LicenseKey: licenseKey}
	if err := cloudflare.UpdateLicenseKey(&ctx); err != nil {
		nlog.Core().Warn("warp: license key update failed, staying on current plan", "error", err)
		return
	}
	acc.LicenseKey = licenseKey
}

func (m *Manager) save(acc *Account) error {
	data, err := json.MarshalIndent(acc, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(m.stateDir, m.fileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("save warp account: %w", err)
	}
	return nil
}

func loadAccountFile(path string) (*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	acc := &Account{}
	if err := json.Unmarshal(data, acc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return acc, nil
}

// decodeReserved converts the CF client_id (base64url, 3 bytes) into the
// WireGuard "reserved" bytes required by both kernels.
func decodeReserved(clientID string) [3]byte {
	var out [3]byte
	if clientID == "" {
		return out
	}
	raw, err := base64RawURL.DecodeString(clientID)
	if err != nil || len(raw) != 3 {
		return out
	}
	copy(out[:], raw)
	return out
}

var base64RawURL = base64URLEncoding()

func base64URLEncoding() *base64.Encoding {
	// Cloudflare uses unpadded base64url for client_id.
	return base64.RawURLEncoding
}

// AddressList returns the tunnel-local addresses as full prefixes.
func (a *Account) AddressList() []string {
	var out []string
	for _, addr := range a.Addresses {
		if addr == "" {
			continue
		}
		if strings.Contains(addr, "/") {
			out = append(out, addr)
			continue
		}
		if strings.Contains(addr, ":") {
			out = append(out, addr+"/128")
		} else {
			out = append(out, addr+"/32")
		}
	}
	return out
}

// HasV6 reports whether the account has an IPv6 tunnel address. WARP accounts
// always get both, but hand-imported configs might not.
func (a *Account) HasV6() bool {
	for _, addr := range a.Addresses {
		if strings.Contains(addr, ":") {
			return true
		}
	}
	return false
}

// HasV4 reports whether the account has an IPv4 tunnel address.
func (a *Account) HasV4() bool {
	for _, addr := range a.Addresses {
		if addr != "" && !strings.Contains(addr, ":") {
			return true
		}
	}
	return false
}
