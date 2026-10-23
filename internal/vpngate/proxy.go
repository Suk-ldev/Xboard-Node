package vpngate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Proxy is the loopback SOCKS5 server whose connections are pinned to the
// vpngate tun device (SO_BINDTODEVICE). The proxy kernel's vpngate outbound
// dials this; every user connection therefore leaves through the volunteer
// node. Zero auth, loopback-only.
type Proxy struct {
	ln     net.Listener
	dev    string // tun device to bind to, "" until the tunnel is up
	binder func(fd uintptr) error

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// NewProxy listens on 127.0.0.1:port.
func NewProxy(port int) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("listen socks proxy: %w", err)
	}
	return &Proxy{ln: ln, conns: make(map[net.Conn]struct{})}, nil
}

// SetDevice updates the tun device sockets must bind to (called after each
// tunnel (re)connect). Existing connections keep their old binding.
func (p *Proxy) SetDevice(dev string) {
	p.mu.Lock()
	p.dev = dev
	p.mu.Unlock()
}

// Close stops the listener and tears down tracked connections.
func (p *Proxy) Close() {
	_ = p.ln.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
}

// Serve accepts until ln closes or ctx is done.
func (p *Proxy) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = p.ln.Close()
	}()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				nlog.Core().Debug("vpngate proxy stopped", "error", err)
			}
			return
		}
		p.mu.Lock()
		p.conns[c] = struct{}{}
		p.mu.Unlock()
		go func() {
			defer func() {
				p.mu.Lock()
				delete(p.conns, c)
				p.mu.Unlock()
				_ = c.Close()
			}()
			p.handle(c)
		}()
	}
}

// handle speaks minimal SOCKS5 (CONNECT only, no auth), then splices the
// client to the target with both sockets pinned to the tun device.
func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(15 * time.Second))

	// Greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	nmethods := int(hdr[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil { // no-auth
		return
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[1] != 1 { // CONNECT only
		client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3: // Domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(client, l); err != nil {
			return
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(client, d); err != nil {
			return
		}
		host = string(d)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(client, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	// Resolve locally (the tun carries the traffic; names resolve on the
	// host resolver — same semantics as the fdip era).
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upconn, err := p.dialBound(addr)
	if err != nil {
		reply := byte(5) // network unreachable
		if errors.Is(err, errNoDevice) {
			reply = 1 // general failure — tunnel down
		}
		client.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upconn.Close()

	// Success reply (BND.ADDR placeholder)
	client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	client.SetDeadline(time.Time{})
	upconn.SetDeadline(time.Time{})

	// Splice
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upconn, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upconn); done <- struct{}{} }()
	<-done
}

var errNoDevice = errors.New("tunnel device not ready")

// dialBound dials addr with SO_BINDTODEVICE pinned to the current tun dev.
func (p *Proxy) dialBound(addr string) (net.Conn, error) {
	p.mu.Lock()
	dev := p.dev
	p.mu.Unlock()
	if dev == "" {
		return nil, errNoDevice
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := bindToDevice(c.(syscallConn), dev); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("bind %s: %w", dev, err)
	}
	return c, nil
}
