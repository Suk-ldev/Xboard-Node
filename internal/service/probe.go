package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/egress"
	"github.com/cedar2025/xboard-node/internal/vpngate"
)

// warpModeString maps the static config's WARP settings into the state seed.
func warpModeString(cfg *config.Config) string {
	if cfg.Warp == nil {
		return "off"
	}
	if cfg.Warp.Enabled() {
		return cfg.Warp.Mode
	}
	return "off"
}

// vpngateMode reads the static config seed: VG_MODE env / config (all|off).
func vpngateMode(cfg *config.Config) egress.VpngateMode {
	if cfg.Vpngate != nil && cfg.Vpngate.Enabled {
		return egress.VpngateAll
	}
	return egress.VpngateOff
}

// vpngateSource builds the subscription source seed from config/env.
func vpngateSource(cfg *config.Config) vpngate.Source {
	if cfg.Vpngate == nil {
		return vpngate.Source{}
	}
	return cfg.Vpngate.Source
}

// socksProbeDial returns a dialer that connects to the kernel's loopback SOCKS
// probe inbound and performs the SOCKS5 handshake for the given target — this
// is the entire health-check transport (no root, no tun).
func socksProbeDial(probeAddr string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("probe dialer only supports tcp")
		}
		var d net.Dialer
		raw, err := d.DialContext(ctx, "tcp", probeAddr)
		if err != nil {
			return nil, fmt.Errorf("dial probe inbound: %w", err)
		}
		if err := socksGreeting(raw, addr, ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return raw, nil
	}
}

// socksGreeting performs a minimal SOCKS5 CONNECT handshake (no auth).
func socksGreeting(conn net.Conn, target string, ctx context.Context) error {
	_ = ctx
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		return fmt.Errorf("socks greeting: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks greeting rejected: %x", resp)
	}

	// CONNECT request: host must resolve remotely — send the domain as-is.
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("probe target: %w", err)
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	// Reply: VER REP RSV ATYP ADDR(1-16) PORT(2) — up to 10 bytes for v4.
	reply := make([]byte, 10)
	if _, err := readFull(conn, reply); err != nil {
		return fmt.Errorf("socks connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks connect refused: code %d", reply[1])
	}
	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// probeJSON decodes the ExitInfo payload from the tunnel (shared with the
// health loop's decode path in case it needs custom fields later).
var _ = json.Unmarshal
var _ = http.StatusOK
