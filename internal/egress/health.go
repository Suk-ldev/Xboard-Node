package egress

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/vpngate"
)

// Current is the runtime view of the chosen vpngate node plus health state.
// Reported to the admin panel and updated by the health loop.
type Current struct {
	Row        vpngate.Row `json:"row"`
	ExitIP     string      `json:"exit_ip"`
	Resident   bool        `json:"residential"`
	Fraud      int         `json:"fraud_score"`
	ChangedAt  time.Time   `json:"changed_at"`
	LastCheck  time.Time   `json:"last_check"`
	LastOK     bool        `json:"last_ok"`
	FailStreak int         `json:"fail_streak"`
}

// HealthLoop watches the active vpngate exit and switches nodes when it dies
// or degrades (leaves the residential pool / fraud ceiling). Probes ride the
// local SOCKS proxy (which binds to the tun device) — the probe path and the
// user path are identical by construction.
type HealthLoop struct {
	mu       sync.Mutex
	state    *State
	current  *Current
	store    *Store
	sub      *vpngate.Manager
	runner   *vpngate.Runner
	proxy    *vpngate.Proxy
	vg       *vpngate.Egress
	usedRing []string // recently used node keys (avoid immediate reuse)

	// OnChange fires after a tunnel switch (informational; the kernel does
	// not need reloads in the OpenVPN model).
	OnChange func()
}

// SwitchAfter is the fail-streak threshold before switching nodes.
const SwitchAfter = 2

// RefreshEvery re-downloads the server list at least this often.
const RefreshEvery = 1 * time.Hour

// CheckEvery is the health probe cadence.
const CheckEvery = 30 * time.Second

// ProbeURL returns exit-IP intelligence: the reply describes the *egress*
// IP, so it must be requested through the tunnel.
const ProbeURL = "https://my.ippure.com/v1/info"

// ExitInfo is the decoded probe payload (subset we care about).
type ExitInfo struct {
	IP            string `json:"ip"`
	Country       string `json:"country"`
	FraudScore    int    `json:"fraudScore"`
	IsResidential bool   `json:"isResidential"`
}

func NewHealthLoop(state *State, store *Store, sub *vpngate.Manager, runner *vpngate.Runner, proxy *vpngate.Proxy, vg *vpngate.Egress) *HealthLoop {
	return &HealthLoop{
		state:  state,
		store:  store,
		sub:    sub,
		runner: runner,
		proxy:  proxy,
		vg:     vg,
	}
}

func (h *HealthLoop) getState() *State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// Current returns a copy of the runtime selection.
func (h *HealthLoop) Current() (Current, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.current == nil {
		return Current{}, false
	}
	return *h.current, true
}

// PickInitial selects the first row honoring PinnedNode and the used-ring.
func (h *HealthLoop) PickInitial(rows []vpngate.Row) (vpngate.Row, bool) {
	h.mu.Lock()
	pinned := h.state.PinnedNode
	h.mu.Unlock()
	if pinned != "" {
		for _, r := range rows {
			if r.Key() == pinned {
				return r, true
			}
		}
		nlog.Core().Warn("vpngate: pinned node not in server list, falling back to auto", "pinned", pinned)
	}
	for _, r := range rows {
		if !h.recentlyUsed(r.Key()) {
			return r, true
		}
	}
	h.mu.Lock()
	h.usedRing = nil
	h.mu.Unlock()
	if len(rows) > 0 {
		return rows[0], true
	}
	return vpngate.Row{}, false
}

func (h *HealthLoop) recentlyUsed(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range h.usedRing {
		if u == id {
			return true
		}
	}
	return false
}

func (h *HealthLoop) markUsed(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.usedRing = append(h.usedRing, id)
	if len(h.usedRing) > 16 {
		h.usedRing = h.usedRing[len(h.usedRing)-16:]
	}
}

// Switch moves to the next candidate (skipping the current one), reconnects
// the tunnel and triggers OnChange.
func (h *HealthLoop) Switch(reason string) {
	rows, _, err := h.sub.Fetch(true)
	if err != nil {
		nlog.Core().Warn("vpngate switch: fetch failed", "error", err)
	}
	vpngate.SortBySpeed(rows)
	if len(rows) == 0 {
		nlog.Core().Error("vpngate switch: no candidates available")
		return
	}
	cur, _ := h.Current()
	next, ok := h.pickNext(rows, cur.Row.Key())
	if !ok {
		nlog.Core().Error("vpngate switch: no alternative node available")
		return
	}
	h.apply(next, "switch: "+reason)
}

// pickNext chooses the first candidate that isn't the current node or in the
// used ring; falls back to any non-current node.
func (h *HealthLoop) pickNext(rows []vpngate.Row, curKey string) (vpngate.Row, bool) {
	var fallback *vpngate.Row
	for i := range rows {
		r := rows[i]
		if r.Key() == curKey {
			continue
		}
		if !h.recentlyUsed(r.Key()) {
			return r, true
		}
		if fallback == nil {
			fallback = &rows[i]
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return vpngate.Row{}, false
}

// connect (re)connects the OpenVPN tunnel to the given node.
func (h *HealthLoop) connect(r vpngate.Row) error {
	meta, err := vpngate.ParseConfig(r.ConfigB64, r.IP, r.Port, r.Proto)
	if err != nil {
		return err
	}
	if err := h.runner.Start(meta, 25*time.Second); err != nil {
		return err
	}
	h.proxy.SetDevice(vpngate.TunName)
	return nil
}

// apply records the new node, reconnects and fires the change hook.
func (h *HealthLoop) apply(r vpngate.Row, why string) {
	if err := h.connect(r); err != nil {
		nlog.Core().Error("vpngate: connect failed, keeping old tunnel", "node", r.LogSummary(), "error", err)
		// Try the next candidate once.
		rows, _, ferr := h.sub.Fetch(true)
		if ferr == nil && len(rows) > 0 {
			vpngate.SortBySpeed(rows)
			if next, ok := h.pickNext(rows, r.Key()); ok {
				if cerr := h.connect(next); cerr == nil {
					r = next
				} else {
					return
				}
			} else {
				return
			}
		} else {
			return
		}
	}
	h.mu.Lock()
	h.current = &Current{Row: r, ChangedAt: time.Now()}
	h.mu.Unlock()
	if h.vg != nil {
		h.vg.Set(r)
	}
	h.markUsed(r.Key())
	nlog.Core().Info("vpngate: node selected", "why", why, "node", r.LogSummary())
	if h.OnChange != nil {
		h.OnChange()
	}
}

// SetProbeResult folds a probe outcome into the health state.
func (h *HealthLoop) SetProbeResult(ok bool, info *ExitInfo) {
	h.mu.Lock()
	if h.current == nil {
		h.mu.Unlock()
		return
	}
	h.current.LastCheck = time.Now()
	h.current.LastOK = ok
	if ok && info != nil {
		h.current.ExitIP = info.IP
		h.current.Resident = info.IsResidential
		h.current.Fraud = info.FraudScore
		h.current.FailStreak = 0
	} else if !ok {
		h.current.FailStreak++
		streak := h.current.FailStreak
		h.mu.Unlock()
		if streak >= SwitchAfter {
			h.Switch(fmt.Sprintf("%d consecutive probe failures", streak))
		}
		return
	}
	h.mu.Unlock()
}

// degraded reports whether the current node left the residential pool.
func (h *HealthLoop) degraded(info ExitInfo) bool {
	st := h.getState()
	src := st.VpngateSource
	if src.MaxFraudScore > 0 && info.FraudScore > src.MaxFraudScore && info.FraudScore > 0 {
		return true
	}
	return false
}

// Run drives the loop until ctx is done. Returns immediately if vpngate is
// disabled.
func (h *HealthLoop) Run(ctx context.Context) {
	if !h.getState().VpngateEnabled() {
		return
	}
	go h.loop(ctx)
}

func (h *HealthLoop) loop(ctx context.Context) {
	// The service made the synchronous initial pick (selectInitialNode).
	// This loop takes over: probing, failover switching, periodic refresh.
	t := time.NewTicker(CheckEvery)
	defer t.Stop()
	for {
		if _, ok := h.Current(); !ok {
			// No selection yet (initial fetch failed): retry.
			rows, _, err := h.sub.Fetch(true)
			if err != nil {
				nlog.Core().Warn("vpngate: fetch failed", "error", err)
			}
			if len(rows) == 0 {
				if cached := vpngate.LoadCache(h.store.Dir()); len(cached) > 0 {
					rows = h.sub.Filter(cached)
				}
			}
			if len(rows) > 0 {
				vpngate.SortBySpeed(rows)
				if r, ok := h.PickInitial(rows); ok {
					if err := h.ApplyInitialRetrying(r, rows); err != nil {
						// Whole burst failed — the nodes (or our network)
						// need a cooldown; back off before hammering again.
						nlog.Core().Warn("vpngate: all candidates failed, backing off 5m", "error", err)
						select {
						case <-ctx.Done():
							return
						case <-time.After(5 * time.Minute):
						}
					}
				}
			} else {
				nlog.Core().Warn("vpngate: no usable servers yet; residential egress inactive")
			}
		}
		h.probeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Since(h.lastFetch()) > RefreshEvery {
			if rows, _, err := h.sub.Fetch(false); err == nil && len(rows) > 0 {
				_ = vpngate.PersistCache(h.store.Dir(), rows)
			}
		}
	}
}

// applyInitialRetrying walks candidates until one connects.
func (h *HealthLoop) ApplyInitialRetrying(first vpngate.Row, rows []vpngate.Row) error {
	r := first
	for attempt := 0; attempt < 10; attempt++ {
		err := h.connect(r)
		if err == nil {
			h.mu.Lock()
			h.current = &Current{Row: r, ChangedAt: time.Now()}
			h.mu.Unlock()
			if h.vg != nil {
				h.vg.Set(r)
			}
			h.markUsed(r.Key())
			nlog.Core().Info("vpngate: node selected", "why", "initial", "node", r.LogSummary())
			return nil
		}
		h.markUsed(r.Key()) // don't bounce between the same failures
		nlog.Core().Warn("vpngate: connect failed, trying next candidate", "node", r.LogSummary(), "error", err)
		next, ok := h.pickNext(rows, r.Key())
		if !ok {
			return fmt.Errorf("no more candidates")
		}
		r = next
	}
	return fmt.Errorf("all candidates failed")
}

func (h *HealthLoop) lastFetch() time.Time {
	_, at := h.sub.Cache()
	return at
}

// probeOnce dials the probe URL through the local SOCKS proxy (bound to the
// tunnel device) and folds the result into health state.
func (h *HealthLoop) probeOnce(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, ok := probeVia(cctx, vpngate.ProxyPort)
	if !ok {
		h.SetProbeResult(false, nil)
		return
	}
	h.SetProbeResult(true, info)
	if h.degraded(*info) {
		h.Switch("node degraded (fraud too high / not residential)")
	}
}

func probeVia(ctx context.Context, proxyPort int) (*ExitInfo, bool) {
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort))
		},
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ProbeURL, nil)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		nlog.Core().Debug("vpngate probe failed", "error", err)
		return nil, false
	}
	defer resp.Body.Close()
	info := &ExitInfo{}
	if err := json.NewDecoder(resp.Body).Decode(info); err != nil || info.IP == "" {
		return nil, false
	}
	return info, true
}

// Sorting helper for the panel's node list.
func SortRowsBySpeed(rows []vpngate.Row) []vpngate.Row {
	out := make([]vpngate.Row, len(rows))
	copy(out, rows)
	sort.SliceStable(out, func(i, j int) bool { return out[i].SpeedMbps > out[j].SpeedMbps })
	return out
}

// RandomHex generates n random bytes as hex (admin path/password salt).
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
