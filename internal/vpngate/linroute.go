package vpngate

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// devAddress returns the first IPv4 address assigned to the named tun
// device (ip -4 addr show dev <name>).
func devAddress(name string) (netip.Addr, error) {
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", name).Output()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ip addr show %s: %w", name, err)
	}
	// <idx>: <name> inet 10.211.1.2/24 ...
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i, w := range f {
			if w == "inet" && i+1 < len(f) {
				addr, err := netip.ParseAddr(strings.Split(f[i+1], "/")[0])
				if err == nil {
					return addr, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no inet address on %s", name)
}

// installTunRoute adds a high-metric default route through the tunnel so
// that ONLY sockets bound to the tun device (our SOCKS proxy) use it — the
// host's own traffic keeps the normal default route. The proxy sets
// SO_BINDTODEVICE on every connection it forwards.
func installTunRoute(dev string, devIP netip.Addr) error {
	gw := gatewayFor(devIP)
	// Idempotent: replace wins over an existing entry.
	cmds := [][]string{
		{"ip", "route", "replace", "0.0.0.0/0", "via", gw.String(), "dev", dev, "metric", "42420"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// removeTunRoute drops the high-metric route (best-effort).
func removeTunRoute(dev string, devIP netip.Addr) {
	gw := gatewayFor(devIP)
	_ = exec.Command("ip", "route", "del", "0.0.0.0/0", "via", gw.String(), "dev", dev, "metric", "42420").Run()
}

// gatewayFor derives the tunnel gateway: SoftEther/VPNGate hands out
// x.x.x.1 on the tunnel network in practice (same subnet as the local addr).
func gatewayFor(devIP netip.Addr) netip.Addr {
	if !devIP.IsValid() {
		return netip.Addr{}
	}
	b := devIP.As4()
	b[3] = 1
	return netip.AddrFrom4(b)
}

// dialerOnDev returns a control function that binds sockets to the tunnel
// device via SO_BINDTODEVICE (needs CAP_NET_RAW/NET_ADMIN — the container
// already has it for openvpn).
func dialerOnDev(dev string) (func(string, string, syscallConn) error, error) {
	if dev == "" {
		return nil, fmt.Errorf("empty device")
	}
	return func(_, _ string, c syscallConn) error {
		return bindToDevice(c, dev)
	}, nil
}

// syscallConn narrows what bindToDevice needs.
type syscallConn interface {
	SyscallConn() (syscallRawConn, error)
}

type syscallRawConn interface {
	Control(fn func(fd uintptr))
}

// bindToDevice pins an established net.Conn (TCPConn/UDPConn) to dev.
func bindToDevice(c syscallConn, dev string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var bindErr error
	raw.Control(func(fd uintptr) {
		bindErr = sockBindToDevice(fd, dev)
	})
	return bindErr
}
