// Package admin serves the built-in control panel (fanout-style): a single
// HTML page behind a secret base path + password, managing WARP and vpngate
// egress settings live. State persists via egress.Store; applying a change
// rewrites egress.json and forces the service to reload the kernel.
package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/egress"
	"github.com/cedar2025/xboard-node/internal/vpngate"
	"github.com/cedar2025/xboard-node/internal/warp"
)

// Panel is the HTTP control plane.
type Panel struct {
	mu      sync.Mutex
	store   *egress.Store
	state   *egress.State
	sub     *vpngate.Manager
	vg      *vpngate.Egress
	warpMgr *warp.Manager
	// Apply forces the service to reload the kernel after a state change.
	Apply func()
	// Switch delegates to egress.HealthLoop.Switch (service-injected).
	Switch func()
	// warpResetHook re-registers a fresh WARP device (service-injected).
	warpResetHook func() error
	started time.Time
}

// SetWarpResetHook wires the service-side re-registration callback.
func (p *Panel) SetWarpResetHook(fn func() error) { p.warpResetHook = fn }


// New builds a panel. state must already be loaded/persisted by the service.
func New(store *egress.Store, state *egress.State, sub *vpngate.Manager, vg *vpngate.Egress, warpMgr *warp.Manager) *Panel {
	return &Panel{store: store, state: state, sub: sub, vg: vg, warpMgr: warpMgr, started: time.Now()}
}

// Handler returns the mounted mux for the secret base path.
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.handleIndex)
	mux.HandleFunc("GET /api/state", p.handleGetState)
	mux.HandleFunc("POST /api/state", p.handleSetState)
	mux.HandleFunc("POST /api/vpngate/refresh", p.handleRefresh)
	mux.HandleFunc("POST /api/vpngate/switch", p.handleSwitch)
	mux.HandleFunc("POST /api/vpngate/pin", p.handlePin)
	mux.HandleFunc("POST /api/warp/reset", p.handleWarpReset)
	mux.HandleFunc("GET /api/links", p.handleLinks)
	mux.HandleFunc("POST /api/password", p.handlePassword)
	mux.HandleFunc("POST /api/basepath", p.handleBasePath)
	return mux
}

// writeJSON is the standard JSON responder.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ─── handlers ───────────────────────────────────────────────────────────────

func (p *Panel) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func (p *Panel) handleGetState(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur, hasCur := p.currentSnapshot()
	writeJSON(w, 200, map[string]any{
		"state":       p.state,
		"current":     cur,
		"has_current": hasCur,
		"uptime_s":    int(time.Since(p.started).Seconds()),
		"warp_device": p.warpDeviceID(),
	})
}

type statePatch struct {
	WarpMode          *string `json:"warp_mode"`
	Vpngate           *string `json:"vpngate"`
	SubURL            *string `json:"sub_url"`
	ResidentialOnly   *bool   `json:"residential_only"`
	MaxFraudScore     *int    `json:"max_fraud_score"`
	Countries         *string `json:"countries"`   // comma-separated; empty clears
	ManualUUID        *string `json:"manual_uuid"` // empty = public default
}

// SetBasePath changes the panel's secret URL path (runtime-effective: the
// mount gate reads it per request). Also available as a dedicated endpoint
// (POST api/basepath) so a stale page can rehome itself via the redirect
// flow. Empty/whitespace generates a fresh random path.
func (p *Panel) SetBasePath(newPath string) (string, error) {
	newPath = strings.TrimSpace(newPath)
	if newPath == "" {
		newPath = "/" + egress.RandomHex(8)
	}
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}
	newPath = strings.TrimSuffix(newPath, "/")
	if len(newPath) < 2 {
		return "", fmt.Errorf("base path too short")
	}
	forbidden := []string{"/api", "/static", "/admin"}
	for _, f := range forbidden {
		if newPath == f {
			return "", fmt.Errorf("base path %q is reserved", f)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.Admin.BasePath = newPath
	if err := p.store.Save(p.state); err != nil {
		return "", err
	}
	return newPath, nil
}

// BasePath returns the current secret path (mount gate reads per request).
func (p *Panel) BasePath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state.Admin.BasePath
}

func (p *Panel) handleSetState(w http.ResponseWriter, r *http.Request) {
	var patch statePatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		apiErr(w, 400, "bad json: "+err.Error())
		return
	}
	p.mu.Lock()
	st := p.state
	if patch.WarpMode != nil {
		st.WarpMode = *patch.WarpMode
	}
	if patch.Vpngate != nil {
		switch egress.VpngateMode(*patch.Vpngate) {
		case egress.VpngateOff, egress.VpngateAll:
			st.Vpngate = egress.VpngateMode(*patch.Vpngate)
		default:
			p.mu.Unlock()
			apiErr(w, 400, "vpngate must be off/all")
			return
		}
	}
	if patch.SubURL != nil && strings.TrimSpace(*patch.SubURL) != "" {
		st.VpngateSource.URL = strings.TrimSpace(*patch.SubURL)
	}
	if patch.ResidentialOnly != nil {
		st.VpngateSource.ResidentialOnly = *patch.ResidentialOnly
	}
	if patch.MaxFraudScore != nil {
		if *patch.MaxFraudScore < 0 || *patch.MaxFraudScore > 100 {
			p.mu.Unlock()
			apiErr(w, 400, "max_fraud_score must be 0-100")
			return
		}
		st.VpngateSource.MaxFraudScore = *patch.MaxFraudScore
	}
	if patch.Countries != nil {
		var list []string
		for _, c := range strings.Split(*patch.Countries, ",") {
			if c = strings.TrimSpace(c); c != "" {
				list = append(list, c)
			}
		}
		st.VpngateSource.Countries = list
	}
	if err := st.Validate(); err != nil {
		p.mu.Unlock()
		apiErr(w, 400, err.Error())
		return
	}
	if err := p.store.Save(st); err != nil {
		p.mu.Unlock()
		apiErr(w, 500, "persist: "+err.Error())
		return
	}
	// Reconfigure live managers with the new source.
	if p.sub != nil {
		p.sub.SetSource(st.VpngateSource)
	}
	apply := p.Apply
	warpMode := st.WarpMode
	vgMode := st.Vpngate
	// NOTE: WARP mode changes take effect via process-level reload path
	// (Apply) because the tunnel itself cannot be rebuilt hot in every
	// kernel; the panel reports that to the user.
	p.mu.Unlock()

	if apply != nil {
		go apply()
	}
	writeJSON(w, 200, map[string]any{
		"ok": true,
		"note": warpApplyNote(warpMode, vgMode),
	})
}

func warpApplyNote(warpMode string, vg egress.VpngateMode) string {
	var parts []string
	if warpMode != "" {
		parts = append(parts, "warp="+warpMode)
	}
	if vg != "" {
		parts = append(parts, "vpngate="+string(vg))
	}
	return "saved (" + strings.Join(parts, ", ") + "); kernel reload triggered"
}

func (p *Panel) handleRefresh(w http.ResponseWriter, _ *http.Request) {
	if p.sub == nil {
		apiErr(w, 400, "vpngate is disabled")
		return
	}
	links, at, err := p.sub.Fetch(false)
	if err != nil {
		apiErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "links": len(links), "fetched_at": at})
}

func (p *Panel) handleSwitch(w http.ResponseWriter, _ *http.Request) {
	if p.sub == nil {
		apiErr(w, 400, "vpngate is disabled")
		return
	}
	p.mu.Lock()
	apply := p.Apply
	p.mu.Unlock()
	// Switch is implemented by the health loop (used-ring aware).
	if p.vg == nil {
		apiErr(w, 400, "vpngate is disabled")
		return
	}
	// Trigger a switch via the loop hook if wired; otherwise reload with the
	// next candidate chosen by the subscription manager.
	switcher := p.switchHook()
	if switcher != nil {
		switcher()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	_ = apply
	apiErr(w, 500, "health loop not running")
}

// switchHook returns the service-injected switch callback.
func (p *Panel) switchHook() func() {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Switch
}

// Switch and warpResetHook are service-injected (avoids import cycles).

func (p *Panel) handlePin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Node == "" {
		apiErr(w, 400, "node required (host:port)")
		return
	}
	p.mu.Lock()
	p.state.PinnedNode = req.Node
	err := p.store.Save(p.state)
	p.mu.Unlock()
	if err != nil {
		apiErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "pinned": req.Node})
}

func (p *Panel) handleWarpReset(w http.ResponseWriter, _ *http.Request) {
	if p.warpMgr == nil {
		apiErr(w, 400, "warp is disabled")
		return
	}
	// Re-registration is a service-level operation (needs kernel rebuild).
	if p.warpResetHook == nil {
		apiErr(w, 500, "warp reset not wired")
		return
	}
	if err := p.warpResetHook(); err != nil {
		apiErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (p *Panel) handleLinks(w http.ResponseWriter, _ *http.Request) {
	if p.sub == nil {
		apiErr(w, 400, "vpngate is disabled")
		return
	}
	links, at, err := p.sub.Fetch(true)
	if err != nil {
		// Still return cached links with the warning.
		writeJSON(w, 200, map[string]any{"links": vpngateRowList(links), "fetched_at": at, "warning": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"links": vpngateRowList(links), "fetched_at": at})
}

func vpngateRowList(rows []vpngate.Row) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"node":       r.Key(),
			"country":    r.Country,
			"ip":         r.IP,
			"sessions":   r.Sessions,
			"speed_mbps": r.SpeedMbps,
			"operator":   r.Operator,
		})
	}
	return out
}

func (p *Panel) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Password) < 8 {
		apiErr(w, 400, "password must be at least 8 chars")
		return
	}
	salt := egress.RandomHex(8)
	hash := HashPassword(req.Password, salt)
	p.mu.Lock()
	p.state.Admin.PasswordHash = salt + ":" + hash
	err := p.store.Save(p.state)
	p.mu.Unlock()
	if err != nil {
		apiErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleBasePath changes the secret URL path. Takes {"base_path": "..."}
// (leading slash optional; empty = regenerate). Response carries the new
// path so the browser can follow immediately.
func (p *Panel) handleBasePath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BasePath string `json:"base_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErr(w, 400, "bad json: "+err.Error())
		return
	}
	newPath, err := p.SetBasePath(req.BasePath)
	if err != nil {
		apiErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "base_path": newPath})
}

// HashPassword derives a scrypt-less salted SHA-256 (sufficient for a
// single-operator panel; the secret path is the primary gate).
func HashPassword(password, salt string) string {
	h := sha256Hex(salt + ":" + password)
	for i := 0; i < 4096; i++ {
		h = sha256Hex(h + salt)
	}
	return h
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (p *Panel) currentSnapshot() (map[string]any, bool) {
	if p.vg == nil {
		return nil, false
	}
	r := p.vg.Row()
	if r == nil {
		return map[string]any{}, false
	}
	return map[string]any{
		"node":    r.Key(),
		"country": r.Country,
		"ip":      r.IP,
	}, true
}

func (p *Panel) warpDeviceID() string {
	if p.warpMgr == nil {
		return ""
	}
	acc := p.warpMgr.Account()
	if acc == nil {
		return ""
	}
	return acc.DeviceID
}

// checkPassword verifies a plaintext password against the stored hash.
func (p *Panel) checkPassword(password string) bool {
	p.mu.Lock()
	stored := p.state.Admin.PasswordHash
	p.mu.Unlock()
	if stored == "" {
		return false
	}
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return false
	}
	want := HashPassword(password, parts[0])
	return subtle.ConstantTimeCompare([]byte(want), []byte(parts[1])) == 1
}
