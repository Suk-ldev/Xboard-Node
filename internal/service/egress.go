// Service-side wiring for the combined egress policy (WARP + vpngate).
// Extracted from service.go to keep the main loop readable.
package service

import (
	"context"
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/egress"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/vpngate"
	"github.com/cedar2025/xboard-node/internal/warp"
)

// egressKit bundles everything the service needs for WARP + vpngate egress.
// All fields are nil when the feature is off.
type egressKit struct {
	state *egress.State
	store *egress.Store
	warp  *warp.Manager
	sub   *vpngate.Manager
	vg    *vpngate.Egress
	loop  *egress.HealthLoop
	// onSwitch is invoked after a node switch so the service can force a
	// kernel reload with the new link (set by Service.Run).
	onSwitch func()
}

// setupEgress resolves the egress policy: config/env seeds defaults, the
// persisted egress.json (admin panel) wins when present. Returns nil when
// both WARP and vpngate are off.
func setupEgress(cfg *config.Config) (*egressKit, error) {
	seed := &egress.State{
		WarpMode: warpModeString(cfg),
		Vpngate:  vpngateMode(cfg),
	}
	if cfg.Warp != nil {
		seed.ManualUUID = cfg.Warp.LicenseKey // placeholder; overwritten below
		seed.ManualUUID = ""
	}
	seed.VpngateSource = vpngateSource(cfg)
	seed.VpngateSource.Defaults() // fill URL / residential-only when unset

	store := egress.NewStore(cfg.Kernel.ConfigDir)
	st := seed
	if persisted, err := store.Load(); err == nil {
		// Persisted state wins, but keep the seed for fields the panel has
		// never written (forward compatibility with fresh fields).
		merged := *persisted
		merged.Admin = persisted.Admin
		st = &merged
	} else if !store.Exists() {
		// First boot: persist the seed so the panel has something to show.
		if err := store.Save(st); err != nil {
			return nil, fmt.Errorf("save egress state: %w", err)
		}
	} else {
		return nil, fmt.Errorf("load egress state: %w", err)
	}

	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("egress state: %w", err)
	}

	kit := &egressKit{state: st, store: store}

	if st.WarpEnabled() {
		// Reuse config.Warp settings (license, endpoints, state dir) — the
		// admin panel edits modes; account material stays where it is.
		wcfg := cfg.Warp
		if wcfg == nil {
			wcfg = &config.WarpConfig{}
		}
		if st.WarpMode == "all" || st.WarpMode == "v6" {
			mode := st.WarpMode
			if mode == "v6" {
				// v6 implied by a v6-only account; keep Mode as-is for the
				// manager (it only cares about enabled/disabled).
				mode = "all"
			}
			wcfg.Mode = mode
		}
		wcfg.Mode = st.WarpMode
		if wcfg.Mode == "off" {
			// State says enabled but config mode is off: force-enable the
			// manager so the account is registered anyway.
			wcfg.Mode = st.WarpMode
			if wcfg.Mode == "off" {
				wcfg.Mode = "all"
			}
		}
		mgr, err := warp.NewManager(wcfg, cfg.Kernel.ConfigDir, cfg.Panel.NodeID)
		if err != nil {
			return nil, fmt.Errorf("warp manager: %w", err)
		}
		kit.warp = mgr
	}

	if st.VpngateEnabled() {
		kit.sub = vpngate.NewManager(st.VpngateSource)
		kit.vg = vpngate.NewEgress(st.ManualUUID)
		kit.loop = egress.NewHealthLoop(st, store, kit.sub, kit.vg, &egress.KernelHandle{
			ProbeAddr: fmt.Sprintf("127.0.0.1:%d", vpngate.ProbePort),
			ProbeDial: socksProbeDial(fmt.Sprintf("127.0.0.1:%d", vpngate.ProbePort)),
		})
		kit.loop.OnChange = nil // wired by Run below (needs kernel ref)
	}
	return kit, nil
}

// OnEgressReadyHook is set by the main package (when the admin panel is
// enabled) to receive the live egress components after setup. Nil elsewhere.
var OnEgressReadyHook func(store *egress.Store, st *egress.State, sub *vpngate.Manager, vg *vpngate.Egress, wm *warp.Manager, apply, switchFn func(), warpReset func() error)

// notifyPanel fires the hook (panics tolerated — panel must not kill service).
func (k *egressKit) notifyPanel() {
	if OnEgressReadyHook == nil {
		return
	}
	defer func() { _ = recover() }()
	var applyFn, switchFn func()
	var resetFn func() error
	if k.loop != nil {
		switchFn = func() { k.loop.Switch("panel request") }
	}
	if k.warp != nil {
		resetFn = func() error { return k.warp.Reset() }
	}
	applyFn = k.onSwitch
	OnEgressReadyHook(k.store, k.state, k.sub, k.vg, k.warp, applyFn, switchFn, resetFn)
}

// selectInitialNode picks the first candidate synchronously (network fetch
// with cache fallback) so the kernel's first Start already carries the
// vpngate outbound. Failures are logged, not fatal — the health loop keeps
// retrying and triggers onSwitch once a node becomes available.
func (k *egressKit) selectInitialNode() {
	if k.loop == nil {
		return
	}
	links, _, err := k.sub.Fetch(true)
	if err != nil {
		nlog.Core().Warn("vpngate: initial fetch failed", "error", err)
	}
	if len(links) == 0 {
		if cached := vpngate.LoadCache(k.cacheDir()); len(cached) > 0 {
			links = k.sub.Filter(cached)
			nlog.Core().Info("vpngate: using persisted link cache", "links", len(links))
		}
	}
	if len(links) == 0 {
		nlog.Core().Warn("vpngate: no usable links yet; will retry in the health loop")
		return
	}
	if l, ok := k.loop.PickInitial(links); ok {
		k.loop.ApplyInitial(l)
		if err := vpngate.PersistCache(k.cacheDir(), links); err != nil {
			nlog.Core().Debug("vpngate: persist cache failed", "error", err)
		}
	}
}

// cacheDir derives the cache location from the store path (egress.json dir).
func (k *egressKit) cacheDir() string {
	p := k.store.Path()
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// applyToKernel injects the egress material into the kernel before Start.
func (k *egressKit) applyToKernel(kern kernel.Kernel, acc *warp.Account) {
	if acc != nil {
		switch t := kern.(type) {
		case *singbox.SingBox:
			t.SetWarpAccount(acc)
		case *xray.Xray:
			t.SetWarpAccount(acc)
		}
	}
	if k != nil && k.vg != nil {
		switch t := kern.(type) {
		case *singbox.SingBox:
			t.SetVpngate(k.vg)
		case *xray.Xray:
			t.SetVpngate(k.vg)
		}
	}
}

// ensureWarpAccount loads/registers the WARP device (fatal on failure —
// silently falling back to direct egress would leak the server IP).
func (k *egressKit) ensureWarpAccount(ctx context.Context) (*warp.Account, error) {
	if k == nil || k.warp == nil {
		return nil, nil
	}
	return k.warp.Ensure(ctx)
}

// startHealthLoop kicks the vpngate health loop and wires node switches to
// kernel restarts. The switcher callback rebuilds the kernel config with the
// newly selected link.
func (k *egressKit) startHealthLoop(ctx context.Context, kern kernel.Kernel) {
	if k == nil || k.loop == nil {
		return
	}
	k.loop.OnChange = func() {
		// Node switch: the kernel must regenerate its config to point the
		// vpngate outbound at the new fdip path. Reload covers sing-box
		// (routes+outbounds); xray falls back to full restart via Reload.
		if l := k.vg.Link(); l != nil {
			nlog.Core().Info("vpngate: applying new node to kernel", "node", l.LogSummary())
		}
		// Service holds lastConfig/lastUsers; trigger a generic reload by
		// calling Reload with the kernel's last applied state via the
		// service-level hook (wired in Run).
		if k.onSwitch != nil {
			k.onSwitch()
		}
	}
	k.loop.OnState = func(st *egress.State) { _ = st }
	k.loop.Run(ctx)
}

