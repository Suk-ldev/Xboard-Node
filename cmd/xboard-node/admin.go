package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cedar2025/xboard-node/internal/admin"
	"github.com/cedar2025/xboard-node/internal/egress"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/vpngate"
	"github.com/cedar2025/xboard-node/internal/warp"
)

// startAdminPanel arms the panel: it waits for the service's egress kit
// (OnEgressReady), generates first-boot credentials, then serves.
func startAdminPanel(port int) {
	adminGlobal.ready = make(chan struct{})
	ready := adminGlobal.ready
	go func() {
		select {
		case <-ready:
		case <-time.After(60 * time.Second):
			nlog.Core().Warn("admin panel disabled: egress not ready in time")
			return
		}
		if err := serveAdmin(port); err != nil {
			nlog.Core().Error("admin panel failed", "error", err)
		}
	}()
}

// serveAdmin generates first-boot credentials and serves the panel. It runs
// in a goroutine after the egress kit is ready.
func serveAdmin(port int) error {
	store, st := adminGlobal.Store, adminGlobal.State

	// Generate secret path + password on first boot.
	changed := false
	if st.Admin.BasePath == "" {
		st.Admin.BasePath = "/" + egress.RandomHex(8)
		changed = true
	}
	password := ""
	if st.Admin.PasswordHash == "" {
		password = egress.RandomHex(12)
		salt := egress.RandomHex(8)
		st.Admin.PasswordHash = salt + ":" + admin.HashPassword(password, salt)
		changed = true
	}
	if changed {
		if err := store.Save(st); err != nil {
			return fmt.Errorf("save admin credentials: %w", err)
		}
	}

	panel := admin.New(store, st, adminGlobal.Sub, adminGlobal.Vg, adminGlobal.Warp)
	panel.Apply = adminGlobal.Apply
	panel.Switch = adminGlobal.Switch
	panel.SetWarpResetHook(adminGlobal.WarpReset)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen admin port %d: %w", port, err)
	}
	srv := &http.Server{
		Handler:           admin.Mount(st.Admin.BasePath, panel),
		ReadHeaderTimeout: 5 * time.Second,
	}
	nlog.Core().Info("admin panel listening",
		"port", port,
		"path", st.Admin.BasePath,
	)
	if password != "" {
		// Print once; only the hash is persisted, the plaintext never shown again.
		nlog.Core().Info("admin panel generated credentials (shown once)",
			"url", fmt.Sprintf("http://<host>:%d%s/", port, st.Admin.BasePath),
			"password", password,
		)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			nlog.Core().Warn("admin panel stopped", "error", err)
		}
	}()
	return nil
}

// adminGlobal wires the panel to the (single) running service. Multi-instance
// deployments bind the panel to the first instance; hooks are re-pointed on
// each service start via OnEgressReady.
var adminGlobal struct {
	ready     chan struct{}
	Store     *egress.Store
	State     *egress.State
	Sub       *vpngate.Manager
	Vg        *vpngate.Egress
	Warp      *warp.Manager
	Apply     func()
	Switch    func()
	WarpReset func() error
}

// OnEgressReady is exported for the service bootstrap: it stores the live
// components and unblocks the panel. apply and switchFn take no arguments;
// warpReset returns an error.
func OnEgressReady(store *egress.Store, st *egress.State, sub *vpngate.Manager, vg *vpngate.Egress, wm *warp.Manager, apply, switchFn func(), warpReset func() error) {
	adminGlobal.Store = store
	adminGlobal.State = st
	adminGlobal.Sub = sub
	adminGlobal.Vg = vg
	adminGlobal.Warp = wm
	adminGlobal.Apply = apply
	adminGlobal.Switch = switchFn
	adminGlobal.WarpReset = warpReset
	if adminGlobal.ready != nil {
		close(adminGlobal.ready)
	}
}
