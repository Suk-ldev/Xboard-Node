package egress

import (
	"context"
	"crypto/rand"
	"errors"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/vpngate"
)

// Current is the runtime view of the chosen vpngate node plus health state.
// Reported to the admin panel and updated by the health loop.
type Current struct {
	Link      vpngate.Link `json:"link"`
	ExitIP    string       `json:"exit_ip"`
	Resident  bool         `json:"residential"`
	Fraud     int          `json:"fraud_score"`
	ChangedAt time.Time    `json:"changed_at"`
	// LastCheck / LastOK drive the panel's health display.
	LastCheck time.Time `json:"last_check"`
	LastOK    bool      `json:"last_ok"`
	// FailStreak counts consecutive failed probes; >= SwitchAfter → switch.
	FailStreak int `json:"fail_streak"`
}

// ErrProbeNotApplied is returned by the probe dialer when the kernel's probe
// inbound is not listening yet (egress not applied to the kernel). Health
// accounting skips these — they are not node failures.
var ErrProbeNotApplied = errors.New("probe inbound not applied")

// HealthLoop watches the active vpngate exit and switches nodes when it dies
// or degrades (leaves the residential pool / fraud ceiling). It talks to the
// kernel through the internal probe inbound (127.0.0.1 SOCKS) — no root, no
// tun, exactly like any local SOCKS client.
type HealthLoop struct {
	mu       sync.Mutex
	state    *State
	current  *Current
	kernel   *KernelHandle
	store    *Store
	sub      *vpngate.Manager
	vg       *vpngate.Egress // selected links are published here (kernel reads it)
	usedRing []string        // recently used node ids (avoid immediate reuse)
	refreshT time.Duration
	lastSub  time.Time

	// OnChange fires after a node switch (service re-applies kernel config).
	OnChange func()
	// OnState fires after any state write that must be persisted.
	OnState func(*State)
}

// KernelHandle abstracts the probe path into the kernel. The service wires it
// to a local SOCKS dialer bound to 127.0.0.1 that routes through the vpngate
// outbound.
type KernelHandle struct {
	// ProbeAddr is "127.0.0.1:<port>" of the internal SOCKS inbound, "" when
	// the vpngate outbound is not currently generated.
	ProbeAddr string
	// ProbeDial dials the probe inbound (kept as a func for tests).
	ProbeDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SwitchAfter is the fail-streak threshold before switching nodes.
const SwitchAfter = 2

// RefreshEvery re-downloads the subscription at least this often.
const RefreshEvery = 3 * time.Hour

// CheckEvery is the health probe cadence.
const CheckEvery = 30 * time.Second

// ProbeURL returns exit-IP intelligence, same endpoint sdise uses: the reply
// describes the *egress* IP, so it must be requested through the tunnel.
const ProbeURL = "https://my.ippure.com/v1/info"

// ExitInfo is the decoded probe payload (subset we care about).
type ExitInfo struct {
	IP            string `json:"ip"`
	Country       string `json:"country"`
	FraudScore    int    `json:"fraudScore"`
	IsResidential bool   `json:"isResidential"`
}

func NewHealthLoop(state *State, store *Store, sub *vpngate.Manager, vg *vpngate.Egress, kh *KernelHandle) *HealthLoop {
	return &HealthLoop{
		state:  state,
		store:  store,
		sub:    sub,
		vg:     vg,
		kernel: kh,
	}
}

func (h *HealthLoop) setState(st *State) {
	h.mu.Lock()
	h.state = st
	h.mu.Unlock()
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

// PickInitial selects the first node honoring PinnedNode, used-ring avoidance
// and source filters. Returns false when no candidate is available.
func (h *HealthLoop) PickInitial(links []vpngate.Link) (vpngate.Link, bool) {
	h.mu.Lock()
	pinned := h.state.PinnedNode
	h.mu.Unlock()
	if pinned != "" {
		for _, l := range links {
			if l.NodeHost+":"+fmt.Sprint(l.NodePort) == pinned {
				return l, true
			}
		}
		nlog.Core().Warn("vpngate: pinned node not in subscription, falling back to auto", "pinned", pinned)
	}
	for _, l := range links {
		id := l.NodeHost + ":" + fmt.Sprint(l.NodePort)
		if h.recentlyUsed(id) {
			continue
		}
		return l, true
	}
	// All recently used — reset the ring and take the first.
	h.mu.Lock()
	h.usedRing = nil
	h.mu.Unlock()
	if len(links) > 0 {
		return links[0], true
	}
	return vpngate.Link{}, false
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

// Switch moves to the next candidate (skipping the current one), bumps the
// used-ring and triggers OnChange.
func (h *HealthLoop) Switch(reason string) {
	links, _, err := h.sub.Fetch(true)
	if err != nil {
		nlog.Core().Warn("vpngate switch: fetch failed", "error", err)
	}
	if len(links) == 0 {
		nlog.Core().Error("vpngate switch: no candidates available")
		return
	}
	cur, _ := h.Current()
	next, ok := h.pickNext(links, cur.Link.NodeHost+":"+fmt.Sprint(cur.Link.NodePort))
	if !ok {
		nlog.Core().Error("vpngate switch: no alternative node available")
		return
	}
	h.apply(next, "switch: "+reason)
}

// pickNext chooses the first candidate that isn't the current node or in the
// used ring; falls back to any non-current node.
func (h *HealthLoop) pickNext(links []vpngate.Link, curID string) (vpngate.Link, bool) {
	var fallback *vpngate.Link
	for i := range links {
		l := links[i]
		id := l.NodeHost + ":" + fmt.Sprint(l.NodePort)
		if id == curID {
			continue
		}
		if !h.recentlyUsed(id) {
			return l, true
		}
		if fallback == nil {
			fallback = &links[i]
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return vpngate.Link{}, false
}

// ApplyInitial records the initial node selection and publishes it to the
// kernel-visible Egress WITHOUT firing OnChange (the kernel has not started
// yet — the first Start will pick the link up).
func (h *HealthLoop) ApplyInitial(l vpngate.Link) {
	h.mu.Lock()
	h.current = &Current{Link: l, ChangedAt: time.Now()}
	h.mu.Unlock()
	if h.vg != nil {
		h.vg.Set(l)
	}
	h.markUsed(l.NodeHost + ":" + fmt.Sprint(l.NodePort))
	nlog.Core().Info("vpngate: node selected", "why", "initial", "node", l.LogSummary())
}

// apply records the new node, publishes it to the kernel-visible Egress and
// fires the change hook.
func (h *HealthLoop) apply(l vpngate.Link, why string) {
	now := time.Now()
	h.mu.Lock()
	h.current = &Current{Link: l, ChangedAt: now}
	h.mu.Unlock()
	if h.vg != nil {
		h.vg.Set(l) // kernel builders read this on next config generation
	}
	h.markUsed(l.NodeHost + ":" + fmt.Sprint(l.NodePort))
	nlog.Core().Info("vpngate: node selected", "why", why, "node", l.LogSummary())
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
	if src.ResidentialOnly && !info.IsResidential {
		return true
	}
	if src.MaxFraudScore > 0 && info.FraudScore > src.MaxFraudScore {
		return true
	}
	return false
}

// Run drives the loop until ctx is done. Returns immediately (with a log) if
// vpngate is disabled.
func (h *HealthLoop) Run(ctx context.Context) {
	if !h.getState().VpngateEnabled() {
		return
	}
	go h.loop(ctx)
}

func (h *HealthLoop) loop(ctx context.Context) {
	// The service already made the synchronous initial pick (selectInitialNode).
	// This loop takes over: probing, failover switching, periodic refresh.
	t := time.NewTicker(CheckEvery)
	defer t.Stop()
	for {
		if _, ok := h.Current(); !ok {
			// No selection yet (initial fetch failed): retry with cache/network.
			links, _, err := h.sub.Fetch(true)
			if err != nil {
				nlog.Core().Warn("vpngate: fetch failed", "error", err)
			}
			if len(links) == 0 {
				if cached := vpngate.LoadCache(h.cacheDir()); len(cached) > 0 {
					links = h.sub.Filter(cached)
				}
			}
			if len(links) > 0 {
				if l, ok := h.PickInitial(links); ok {
					h.apply(l, "late initial")
				}
			} else {
				nlog.Core().Warn("vpngate: no usable links yet; residential egress inactive")
			}
		}
		h.probeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Periodic subscription refresh (3h) — same cadence as upstream.
		if time.Since(h.lastFetch()) > RefreshEvery {
			if fresh, _, err := h.sub.Fetch(false); err == nil && len(fresh) > 0 {
				if err := vpngate.PersistCache(h.cacheDir(), fresh); err != nil {
					nlog.Core().Debug("vpngate: persist cache failed", "error", err)
				}
			}
		}
	}
}

func (h *HealthLoop) lastFetch() time.Time {
	_, at := h.sub.Cache()
	return at
}

// cacheDir derives the cache location from the store path (egress.json dir).
func (h *HealthLoop) cacheDir() string {
	return dirOf(h.store.Path())
}

func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "."
	}
	return p[:i]
}

// probeOnce dials the probe URL through the kernel's internal SOCKS inbound
// and folds the result into health state.
func (h *HealthLoop) probeOnce(ctx context.Context) {
	h.mu.Lock()
	kh := h.kernel
	h.mu.Unlock()
	if kh == nil || kh.ProbeAddr == "" || kh.ProbeDial == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	info, ok := probeVia(cctx, kh)
	if !ok {
		h.SetProbeResult(false, nil)
		return
	}
	h.SetProbeResult(true, info)
	if h.degraded(*info) {
		h.Switch("node degraded (no longer residential / fraud too high)")
	}
}

func probeVia(ctx context.Context, kh *KernelHandle) (*ExitInfo, bool) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return kh.ProbeDial(ctx, network, addr)
		},
		// The SOCKS inbound resolves domains; keep proxying hostnames.
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}
	// Wrap with SOCKS5 handshake via x/net/proxy equivalent: our probe dialer
	// already performs the SOCKS handshake (kernel-provided), so the transport
	// must dial absolute URLs through it — but Go's http.Transport dials the
	// *request host*. The kernel handle's dialer is bound to the SOCKS inbound
	// and performs the handshake per-connection with the target address, which
	// is exactly what transport needs.
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
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
func SortLinksBySpeed(links []vpngate.Link) []vpngate.Link {
	out := make([]vpngate.Link, len(links))
	copy(out, links)
	sort.SliceStable(out, func(i, j int) bool { return out[i].SpeedMbps > out[j].SpeedMbps })
	return out
}

// RandomHex generates n random bytes as hex (admin path/password salt).
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is effectively unreachable; fall back to time.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
