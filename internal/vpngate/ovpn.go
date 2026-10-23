package vpngate

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// TunName is the fixed tunnel device used for the vpngate egress. Fixed so
// route setup survives node switches (openvpn is restarted with the same
// dev name; the kernel-side SOCKS proxy keeps binding to it).
const TunName = "xboard-vg"

// DefaultProbePort / ProxyPort reserve the loopback range for the egress:
// 64510 was the (fdip-era) kernel probe inbound; 64520 is the local SOCKS5
// proxy that routes user traffic into the tun device.
const ProxyPort = 64520

// ConfigMeta carries the parsed bits of an OpenVPN config needed to run it.
type ConfigMeta struct {
	Body    string // full inline config (ca/cert/key included)
	Proto   string // tcp|udp
	Remote  string // host (IP preferred)
	Port    int
	Cipher  string // from data-ciphers/cipher, "" = default
	DevType string // tun
}

// ParseConfig decodes a base64 VPNGate config into a runnable form. It
// rewrites remote to the API-provided IP (DDNS hostnames may lag) and forces
// settings we depend on (fixed dev name, no route hijack).
func ParseConfig(b64, ip string, port int, proto string) (ConfigMeta, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ConfigMeta{}, fmt.Errorf("decode config: %w", err)
	}
	body := string(raw)
	if ip == "" || net.ParseIP(ip) == nil {
		return ConfigMeta{}, fmt.Errorf("bad server ip %q", ip)
	}
	if port <= 0 || port > 65535 {
		return ConfigMeta{}, fmt.Errorf("bad port %d", port)
	}
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	meta := ConfigMeta{Proto: proto, Remote: ip, Port: port, Body: body}
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "data-ciphers", "cipher":
			if len(f) >= 2 {
				meta.Cipher = f[1]
			}
		case "dev":
			if len(f) >= 2 {
				meta.DevType = f[1]
			}
		}
	}
	if meta.DevType != "" && meta.DevType != "tun" {
		return ConfigMeta{}, fmt.Errorf("unsupported dev type %q", meta.DevType)
	}
	return meta, nil
}

// Runner supervises one openvpn child process connected to the currently
// selected VPNGate node. It owns:
//   - writing the client config (fixed dev name, route-nothing mode)
//   - starting/restarting the process on Switch()
//   - a high-metric default route + loopback SOCKS proxy bound to the tun
//     device (SO_BINDTODEVICE), so ONLY proxy traffic uses the tunnel and
//     the host's own routing (panel sync etc.) is untouched.
//
// Requires: openvpn binary, /dev/net/tun, NET_ADMIN (root or cap).
type Runner struct {
	mu       sync.Mutex
	binPath  string // resolved openvpn binary
	stateDir string
	meta     *ConfigMeta
	cmd      *exec.Cmd
	running  bool
	devIP    netip.Addr // tunnel-local address once up

	// OnUp fires after the tunnel reports INITIALIZATION (routing ready).
	OnUp func()
}

// NewRunner locates the openvpn binary and prepares the state dir.
func NewRunner(stateDir string) (*Runner, error) {
	bin, err := exec.LookPath("openvpn")
	if err != nil {
		// Common container locations.
		for _, p := range []string{"/usr/sbin/openvpn", "/usr/bin/openvpn", "/usr/local/sbin/openvpn"} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				bin = p
				break
			}
		}
	}
	if bin == "" {
		return nil, fmt.Errorf("openvpn binary not found (install openvpn or bake it into the image)")
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	return &Runner{binPath: bin, stateDir: stateDir}, nil
}

// DevIP returns the tunnel-local address of the current connection.
func (r *Runner) DevIP() netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.devIP
}

// IsRunning reports whether an openvpn child is currently alive.
func (r *Runner) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Start connects to the given node, replacing any existing tunnel. Blocking
// until the tunnel is up (or times out). Safe to call repeatedly — each call
// switches the exit node without touching the proxy kernels.
func (r *Runner) Start(meta ConfigMeta, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Tear down the previous child first (same dev name must be free).
	if r.running {
		r.stopLocked()
	}

	cfgPath := filepath.Join(r.stateDir, TunName+".conf")
	if err := os.WriteFile(cfgPath, []byte(renderConfig(meta)), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	cmd := exec.Command(r.binPath,
		"--config", cfgPath,
		"--dev", TunName, "--dev-type", "tun",
		// SoftEther pushes redirect-gateway + DNS options; ignore them so
		// the host's own routing stays intact (we install a high-metric
		// default through the tunnel ourselves).
		"--pull-filter", "ignore", "redirect-gateway",
		"--pull-filter", "ignore", "route",
		"--pull-filter", "ignore", "dhcp-option",
		"--pull-filter", "ignore", "route-gateway",
		"--verb", "3")
	// openvpn needs NET_ADMIN for tun creation; it inherits our uid (root in
	// the container). No special env needed.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn: %w", err)
	}
	r.cmd = cmd
	r.meta = &meta

	// Wait for INITIALIZATION COMPLETED (SoftEther prints it on success).
	deadline := time.Now().Add(timeout)
	up := false
	lineCh := make(chan string, 32)
	go func() {
		sc := newLineScanner(stderr)
		for sc.Scan() {
			select {
			case lineCh <- sc.Text():
			default: // drop if the waiter is gone
			}
		}
	}()
	for time.Now().Before(deadline) {
		select {
		case line := <-lineCh:
			if strings.Contains(line, "Initialization Sequence Completed") ||
				strings.Contains(line, "Initialization Sequence Completed With Errors") {
				up = true
			}
			if strings.Contains(line, "AUTH_FAILED") || strings.Contains(line, "Connection refused") ||
				strings.Contains(line, "TLS Error") || strings.Contains(line, "SIGUSR1[soft,") {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				r.running = false
				return fmt.Errorf("openvpn: %s", strings.TrimSpace(line))
			}
		case <-time.After(500 * time.Millisecond):
		}
		if up {
			break
		}
	}
	if !up {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		r.running = false
		return fmt.Errorf("openvpn tunnel not up within %s", timeout)
	}

	// The tun may take another moment to get its address; fetch it with
	// retries, then install the high-metric route.
	var devIP netip.Addr
	for i := 0; i < 10; i++ {
		if a, err := devAddress(TunName); err == nil {
			devIP = a
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !devIP.IsValid() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		r.running = false
		return fmt.Errorf("tun device %s has no address", TunName)
	}
	r.devIP = devIP
	r.running = true

	if err := installTunRoute(TunName, devIP); err != nil {
		r.stopLocked()
		return fmt.Errorf("route setup: %w", err)
	}
	nlog.Core().Info("vpngate: openvpn tunnel up",
		"node", meta.Remote+":"+strconv.Itoa(meta.Port),
		"dev", TunName, "dev_ip", devIP.String())
	return nil
}

// Stop tears down the tunnel (route first, then the child).
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
}

func (r *Runner) stopLocked() {
	if r.devIP.IsValid() {
		removeTunRoute(TunName, r.devIP)
	}
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		_, _ = r.cmd.Process.Wait()
	}
	r.cmd = nil
	r.running = false
	r.meta = nil
	r.devIP = netip.Addr{}
}

// renderConfig rewrites the VPNGate client config for our supervision mode:
// fixed dev name, explicit remote (API IP), no automatic route changes
// (we install a high-metric route ourselves), keep inline ca/cert/key.
func renderConfig(meta ConfigMeta) string {
	var b strings.Builder
	sc := newLineScanner(strings.NewReader(meta.Body))
	skipNext := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		f := strings.Fields(line)
		key := ""
		if len(f) > 0 {
			key = f[0]
		}
		switch key {
		case "dev", "dev-node":
			skipNext = false
			continue // we pass --dev on the command line
		case "proto":
			fmt.Fprintf(&b, "proto %s\n", meta.Proto)
			continue
		case "remote":
			fmt.Fprintf(&b, "remote %s %d\n", meta.Remote, meta.Port)
			continue
		case "resolv-retry", "verb", "status", "log", "log-append", "iproute":
			continue // we set these / don't want them
		case "route", "route-method", "route-delay", "redirect-gateway", "dhcp-option":
			continue // no route hijacking
		case "<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>":
			// inline blocks: copy verbatim
			b.WriteString(line + "\n")
			inside := true
			for inside && sc.Scan() {
				l := sc.Text()
				b.WriteString(l + "\n")
				if strings.HasPrefix(strings.TrimSpace(l), "</") {
					inside = false
				}
			}
			skipNext = false
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		b.WriteString(line + "\n")
	}
	// Supervision extras.
	b.WriteString("client\n")
	b.WriteString("persist-key\npersist-tun\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth-nocache\n")
	b.WriteString("connect-retry-max 1\n")
	b.WriteString("tun-mtu 1500\n")
	b.WriteString("script-security 1\n")
	return b.String()
}

func newLineScanner(rd interface{ Read([]byte) (int, error) }) *bufio.Scanner {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	return sc
}
