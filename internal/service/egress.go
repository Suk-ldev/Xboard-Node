// Service-side wiring for the combined egress policy (WARP + vpngate).
// The vpngate exit runs an OpenVPN child (fanout model): the proxy kernel's
// egress rides a loopback SOCKS proxy bound to the tun device, so node
// switches NEVER touch the kernel.
package service

import (
	"context"
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/egress"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
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
	proxy *vpngate.Proxy
	vg    *vpngate.Egress
	loop  *egress.HealthLoop
	// onSwitch is invoked after a tunnel switch (informational hook).
	onSwitch func()
}

// OnEgressReadyHook is set by the main package (when the admin panel is
// enabled) to receive the live egress components after setup. Nil elsewhere.
var OnEgressReadyHook func(store *egress.Store, st *egress.State, sub *vpngate.Manager, vg *vpngate.Egress, wm *warp.Manager, apply, switchFn func(), warpReset func() error)

// setupEgress resolves the egress policy: config/env seeds defaults, the
// persisted egress.json (admin panel) wins when present. Returns nil when
// both WARP and vpngate are off.
func setupEgress(cfg *config.Config) (*egressKit, error) {
	seed := &egress.State{
		WarpMode: warpModeString(cfg),
		Vpngate:  vpngateMode(cfg),
	}
	seed.VpngateSource = vpngateSource(cfg)
	seed.VpngateSource.Defaults() // fill URL / residential-only when unset

	store := egress.NewStore(cfg.Kernel.ConfigDir)
	st := seed
	if persisted, err := store.Load(); err == nil {
		st = persisted
		// Backfill fields the panel hasn't written yet (e.g. URL from an
		// older state file) without overriding explicit values.
		if st.VpngateSource.URL == "" {
			st.VpngateSource.URL = seed.VpngateSource.URL
		} else if st.Vpngate == egress.VpngateAll {
			st.VpngateSource.Defaults()
		}
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
		wcfg.Mode = st.WarpMode
		if wcfg.Mode == "off" {
			wcfg.Mode = "all" // state says enabled; force the manager on
		}
		mgr, err := warp.NewManager(wcfg, cfg.Kernel.ConfigDir, cfg.Panel.NodeID)
		if err != nil {
			return nil, fmt.Errorf("warp manager: %w", err)
		}
		kit.warp = mgr
	}

	if st.VpngateEnabled() {
		runner, err := vpngate.NewRunner(cfg.Kernel.ConfigDir + "/ovpn")
		if err != nil {
			return nil, fmt.Errorf("vpngate runner: %w", err)
		}
		proxy, err := vpngate.NewProxy(vpngate.ProxyPort)
		if err != nil {
			return nil, fmt.Errorf("vpngate proxy: %w", err)
		}
		kit.sub = vpngate.NewManager(st.VpngateSource)
		kit.proxy = proxy
		kit.vg = vpngate.NewEgress("")
		kit.loop = egress.NewHealthLoop(st, store, kit.sub, runner, proxy, kit.vg)
	}
	return kit, nil
}

// startVpngate kicks the OpenVPN egress: local SOCKS proxy, initial node
// selection (retrying candidates), then the health loop.
func (k *egressKit) startVpngate(ctx context.Context) {
	if k == nil || k.loop == nil || k.proxy == nil {
		return
	}
	// Loopback SOCKS proxy: the kernel's custom outbound (or operators) route
	// user traffic here; sockets are pinned to the tunnel device.
	go k.proxy.Serve(ctx)

	k.loop.OnChange = k.onSwitch
	k.loop.Run(ctx)
}

// notifyPanel fires the panel hook (panics tolerated — panel must not kill
// the service).
func (k *egressKit) notifyPanel() {
	if OnEgressReadyHook == nil {
		return
	}
	defer func() { _ = recover() }()
	var switchFn func()
	var resetFn func() error
	if k.loop != nil {
		switchFn = func() { k.loop.Switch("panel request") }
	}
	if k.warp != nil {
		resetFn = func() error { return k.warp.Reset() }
	}
	OnEgressReadyHook(k.store, k.state, k.sub, k.vg, k.warp, k.onSwitch, switchFn, resetFn)
}

// applyToKernel injects the WARP account into the kernel before Start.
// (The vpngate exit no longer touches the kernel in the OpenVPN model.)
func (k *egressKit) applyToKernel(kern kernel.Kernel, acc *warp.Account) {
	if acc == nil {
		return
	}
	switch kern.(type) {
	case *singbox.SingBox:
		kern.(*singbox.SingBox).SetWarpAccount(acc)
	case *xray.Xray:
		kern.(*xray.Xray).SetWarpAccount(acc)
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

var _ = kernel.Kernel(nil) // keep the kernel import for future hooks
