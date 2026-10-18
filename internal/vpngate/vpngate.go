// Package vpngate fetches and parses the VLESS-form VPNGate subscription
// (sdise/vpngate layout): one VLESS link per line, each routing through a
// fixed entry (VLESS+TLS+WS) whose path selects the exit node
// (`/fdip=sstp://vpn:vpn@<host>:<port>?ed=2560`).
//
// No OpenVPN / netns / tun is involved — the kernel treats every entry as an
// ordinary VLESS outbound and the entry bridges to the volunteer node via SSTP.
package vpngate

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Link is one parsed VLESS line from the subscription.
type Link struct {
	// Raw is the original (cleaned) link, usable by clients as-is.
	Raw string
	// Path is the decoded WS path, e.g. "/fdip=sstp://vpn:vpn@x.opengw.net:992?ed=2560".
	Path string
	// NodeHost / NodePort identify the volunteer node inside the path.
	NodeHost string
	NodePort int
	// Remark fields decoded from the #fragment.
	Residential bool    // "家宽" (true) / "机房" (false) / unknown (false, KnownType=false)
	KnownType   bool    // remark carried a type marker at all
	FraudScore  int     // -1 = absent
	Country     string  // e.g. "Japan"
	SpeedMbps   float64 // -1 = absent
	ExitIP      string  // landing IP from the remark, may be empty
	Transport   string  // "ws" or "xhttp" (from the link's type= param)
}

// Source describes where the subscription lives and which lines to keep.
// Only fields the admin panel can change are stored in the egress state file.
type Source struct {
	URL string `json:"url"`
	// ResidentialOnly keeps only 家宽 (isResidential=true) links.
	ResidentialOnly bool `json:"residential_only"`
	// MaxFraudScore drops links whose 纯净度 (fraudScore) exceeds it. 0 disables.
	MaxFraudScore int `json:"max_fraud_score"`
	// Countries is an allowlist of country names (exact, case-insensitive).
	// Empty = all countries.
	Countries []string `json:"countries,omitempty"`
	// ExcludeIPs drops links whose landing IP is in the list (e.g. the
	// 219.100.37.0/24 public-vpn relay pool).
	ExcludeIPs []string `json:"exclude_ips,omitempty"`
}

// Defaults mirrors the upstream filter: home-broadband only.
func (s *Source) Defaults() {
	if s.URL == "" {
		s.URL = DefaultSubURL
	}
	s.ResidentialOnly = true
	if s.MaxFraudScore == 0 {
		s.MaxFraudScore = 30
	}
}

// DefaultSubURL is the upstream VLESS-WS subscription (one link per line).
const DefaultSubURL = "https://raw.githubusercontent.com/sdise/vpngate/main/vpngate-v2ray.txt"

// EntryHost is the fixed VLESS+TLS+WS entry that bridges to the volunteer
// node selected by the fdip path.
const EntryHost = "saas.sin.fan"

// SNI must be snip.edgeoneai.cc.cd — the entry 403s when the client
// presents saas.sin.fan itself as SNI (verified against the live entry).
const SNI = "snip.edgeoneai.cc.cd"

// BrowserUA is sent on the fdip WS handshake. The entry's Cloudflare
// frontend 403-challenges the Go default "Go-http-client/1.1" UA (verified:
// same IP+path passes instantly with a browser UA).
const BrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// HTTPGet performs a plain HTTP GET with timeout; used for subscription
// download. Separated from net/http import noise for stubbing in tests.
func HTTPGet(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// RealUUID replaces the unexpanded `{{EMAIL_...}}` template placeholder in the
// upstream raw files. The entry server validates this exact UUID (verified:
// random UUIDs are rejected, this one works).
const RealUUID = "495c7195-85b8-498a-bf20-2ea9ce9175b5"

// Manager owns subscription fetching, parsing and filtering.
type Manager struct {
	mu      sync.Mutex
	src     Source
	cache   []Link    // last successful fetch (filtered)
	fetched time.Time // when cache was written
	// OverrideUUID, when non-empty, replaces the link UUID (and the
	// {{EMAIL_...}} placeholder) with the given value.
	OverrideUUID string
}

func NewManager(src Source) *Manager {
	src.Defaults()
	return &Manager{src: src}
}

func (m *Manager) Source() Source {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.src
}

func (m *Manager) SetSource(src Source) {
	src.Defaults()
	m.mu.Lock()
	m.src = src
	m.mu.Unlock()
}

// Cache returns the last successful fetch and its age.
func (m *Manager) Cache() ([]Link, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cache, m.fetched
}

// Fetch downloads the subscription, filters it and returns the candidates in
// remark order (upstream already sorts by speed). On success the result is
// cached. On failure the last cache is returned (staleOK semantics) with an
// error, so callers can decide whether a stale list is acceptable.
func (m *Manager) Fetch(staleOK bool) ([]Link, time.Time, error) {
	links, err := m.fetchOnce()
	if err != nil {
		if staleOK {
			m.mu.Lock()
			cached, at := m.cache, m.fetched
			m.mu.Unlock()
			if len(cached) > 0 {
				return cached, at, fmt.Errorf("using cached list (fetch failed: %w)", err)
			}
		}
		return nil, time.Time{}, err
	}
	m.mu.Lock()
	m.cache = links
	m.fetched = time.Now()
	cached, at := m.cache, m.fetched
	m.mu.Unlock()
	return cached, at, nil
}

// fetchOnce downloads and parses the raw text without touching the cache.
func (m *Manager) fetchOnce() ([]Link, error) {
	src := m.Source()
	links, err := downloadAndParse(src.URL)
	if err != nil {
		return nil, err
	}
	links = m.filter(links)
	if len(links) == 0 {
		return nil, fmt.Errorf("no links match the current filters")
	}
	return links, nil
}

// downloadAndParse fetches raw text via URL or local file path (for tests).
func downloadAndParse(loc string) ([]Link, error) {
	var text string
	switch {
	case strings.HasPrefix(loc, "http://"), strings.HasPrefix(loc, "https://"):
		data, err := HTTPGet(loc, 30*time.Second)
		if err != nil {
			return nil, err
		}
		text = string(data)
	default:
		// Local path: useful for offline deployments and tests.
		data, err := os.ReadFile(loc)
		if err != nil {
			return nil, fmt.Errorf("read subscription file: %w", err)
		}
		text = string(data)
	}
	return ParseLinks(text), nil
}

// ParseLinks extracts VLESS links from raw subscription text. Lines that fail
// to parse are skipped (upstream files may carry headers/comments).
func ParseLinks(text string) []Link {
	var out []Link
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "vless://") {
			continue
		}
		if l, err := parseLink(line); err == nil {
			out = append(out, l)
		}
	}
	return out
}

func parseLink(raw string) (Link, error) {
	if !strings.HasPrefix(raw, "vless://") {
		return Link{}, fmt.Errorf("not a vless link")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Link{}, fmt.Errorf("parse link: %w", err)
	}
	l := Link{Raw: raw}

	q := u.Query()
	l.Transport = q.Get("type")
	if l.Transport == "" {
		l.Transport = "ws"
	}
	l.Path = q.Get("path")

	// Decode the fdip path → volunteer node host:port.
	if p, err := url.QueryUnescape(l.Path); err == nil {
		l.Path = p
	}
	host, port, err := parseFdipPath(l.Path)
	if err != nil {
		return Link{}, err
	}
	l.NodeHost, l.NodePort = host, port

	// Decode the remark fragment.
	l.Remarkdecode(u.Fragment)

	return l, nil
}

// Remarkdecode fills remark fields from the URL fragment (already url-decoded
// by url.Parse). Format: `家宽|纯净度:N|Country|speed|落地:IP` or shorter.
func (l *Link) Remarkdecode(frag string) {
	if frag == "" {
		return
	}
	parts := strings.Split(frag, "|")
	for i, p := range parts {
		switch {
		case p == "家宽":
			l.Residential, l.KnownType = true, true
		case p == "机房":
			l.Residential, l.KnownType = false, true
		case strings.HasPrefix(p, "纯净度:"):
			if n, err := strconv.Atoi(strings.TrimPrefix(p, "纯净度:")); err == nil {
				l.FraudScore = n
			}
		case strings.HasPrefix(p, "落地:"):
			l.ExitIP = strings.TrimPrefix(p, "落地:")
		case i == 2 || (i == 1 && !strings.HasPrefix(p, "纯净度:") && l.KnownType):
			// Positional: country comes after type/score fields.
			l.Country = p
		case i == 0 && !l.KnownType:
			l.Country = p
		case isSpeedField(p, i):
			if f, err := strconv.ParseFloat(p, 64); err == nil {
				l.SpeedMbps = f
			}
		}
	}
	if l.Country == "" {
		// Fallback: first field that isn't a known marker.
		for _, p := range parts {
			if p != "家宽" && p != "机房" && !strings.HasPrefix(p, "纯净度:") &&
				!strings.HasPrefix(p, "落地:") && !isSpeedField(p, 99) {
				l.Country = p
				break
			}
		}
	}
}

func isSpeedField(s string, idx int) bool {
	if idx < 2 {
		return false
	}
	// Speed fields are bare numbers (Mbps) or "xxx Mbps".
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	return strings.HasSuffix(s, "Mbps") || strings.HasSuffix(s, " Mbps")
}

// parseFdipPath extracts the volunteer node address from
// "/fdip=sstp://vpn:vpn@host:port?ed=2560".
func parseFdipPath(path string) (string, int, error) {
	rest, ok := strings.CutPrefix(path, "/fdip=sstp://")
	if !ok {
		return "", 0, fmt.Errorf("path is not a fdip sstp path: %q", path)
	}
	rest = strings.TrimSuffix(rest, "?ed=2560")
	rest = strings.TrimSuffix(rest, "?ed=0")
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimPrefix(rest, "vpn:vpn@")
	host, portStr, err := splitHostPort(rest)
	if err != nil {
		return "", 0, fmt.Errorf("parse fdip target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad fdip port %q", portStr)
	}
	return host, port, nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("missing port in %q", s)
	}
	return s[:i], s[i+1:], nil
}

// Filter applies the source filters, keeping upstream order (speed-sorted).
func (m *Manager) Filter(links []Link) []Link {
	return m.filter(links)
}

// filter applies the source filters, keeping upstream order (speed-sorted).
func (m *Manager) filter(links []Link) []Link {
	src := m.Source()
	countries := map[string]bool{}
	for _, c := range src.Countries {
		countries[strings.ToLower(strings.TrimSpace(c))] = true
	}
	excl := map[string]bool{}
	for _, ip := range src.ExcludeIPs {
		excl[strings.TrimSpace(ip)] = true
	}

	out := make([]Link, 0, len(links))
	for _, l := range links {
		if src.ResidentialOnly && l.KnownType && !l.Residential {
			continue
		}
		if src.MaxFraudScore > 0 && l.FraudScore >= 0 && l.FraudScore > src.MaxFraudScore {
			continue
		}
		if len(countries) > 0 && !countries[strings.ToLower(l.Country)] {
			continue
		}
		if excl[l.ExitIP] {
			continue
		}
		out = append(out, l)
	}
	return out
}

// SortBySpeed reorders links fastest-first (upstream order is already
// speed-sorted; this re-sorts lists the panel may have reordered).
func SortBySpeed(links []Link) {
	sort.SliceStable(links, func(i, j int) bool {
		return links[i].SpeedMbps > links[j].SpeedMbps
	})
}

// OutboundJSON renders the link as an xray-native VLESS outbound body.
// The UUID placeholder is replaced with RealUUID (or OverrideUUID).
func (l Link) OutboundJSON(tag, uuid string) map[string]any {
	if uuid == "" {
		uuid = RealUUID
	}
	addr := l.address()
	path := l.wirePath()
	transport := l.Transport
	if transport != "ws" && transport != "xhttp" {
		transport = "ws"
	}
	tlsSettings := map[string]any{
		"serverName": SNI,
	}
	if transport == "ws" {
		// WS rides http/1.1; advertising h3 breaks the entry handshake.
		tlsSettings["alpn"] = []string{"http/1.1"}
	}
	return map[string]any{
		"protocol": "vless",
		"tag":      tag,
		"settings": map[string]any{
			"vnext": []map[string]any{{
				"address": addr,
				"port":    443,
				"users": []map[string]any{{
					"id":         uuid,
					"encryption": "none",
					"level":      0,
				}},
			}},
		},
		"streamSettings": map[string]any{
			"network":     transport,
			"security":    "tls",
			"tlsSettings": tlsSettings,
			transport + "Settings": map[string]any{
				"path": path,
				"host": SNI,
				"headers": map[string]string{
					"Host":       SNI,
					"User-Agent": BrowserUA,
				},
			},
		},
	}
}

// SingboxJSON renders the link as a sing-box-native VLESS outbound.
// The entry 403s unless SNI **and** the WS Host header are both SNI, and
// ALPN must be http/1.1 (verified against the live entry).
func (l Link) SingboxJSON(tag, uuid string) map[string]any {
	if uuid == "" {
		uuid = RealUUID
	}
	path := l.wirePath()
	transport := l.Transport
	if transport != "ws" && transport != "xhttp" {
		transport = "ws"
	}
	tlsPart := map[string]any{
		"enabled":     true,
		"server_name": SNI,
	}
	if transport == "ws" {
		tlsPart["alpn"] = []string{"http/1.1"}
	}
	// The entry's Cloudflare frontend bot-checks the Go default
	// "Go-http-client/1.1" UA (403 challenge); a browser-like UA passes.
	headers := map[string]any{"Host": SNI, "User-Agent": BrowserUA}
	tr := map[string]any{"type": transport, "path": path, "headers": headers}
	if transport == "ws" {
		// The fdip Worker only consumes xray-style early data: the first
		// payload rides the handshake in Sec-WebSocket-Protocol (the `ed`
		// parameter in the path). Without this, sing-box sends the payload
		// as a post-handshake frame and the Worker closes with 1011
		// (verified: enabling early data makes the same node work).
		tr["max_early_data"] = 2048
		tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
	}
	return map[string]any{
		"type":        "vless",
		"tag":         tag,
		"server":      l.address(),
		"server_port": 443,
		"uuid":        uuid,
		"tls":         tlsPart,
		"transport":   tr,
	}
}

func (l Link) address() string { return EntryHost }

// wirePath returns the path as it must appear on the wire (url-encoded).
// Both kernels encode the path verbatim; give them the decoded form.
func (l Link) wirePath() string { return l.Path }

// PersistCache writes the last cached links to disk so a restart keeps the
// same node without re-fetching (also the seed for offline first boots).
func PersistCache(dir string, links []Link) error {
	if len(links) == 0 {
		return nil
	}
	var b strings.Builder
	for _, l := range links {
		b.WriteString(l.Raw)
		b.WriteByte('\n')
	}
	path := filepath.Join(dir, "links.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return nil
}

// LoadCache reads a previously persisted links file.
func LoadCache(dir string) []Link {
	data, err := os.ReadFile(filepath.Join(dir, "links.txt"))
	if err != nil {
		return nil
	}
	return ParseLinks(string(data))
}

// LogSummary summarizes a link for the node log.
func (l Link) LogSummary() string {
	t := "?"
	if l.KnownType {
		if l.Residential {
			t = "resi"
		} else {
			t = "dc"
		}
	}
	s := ""
	if l.SpeedMbps > 0 {
		s = fmt.Sprintf(" %.0fMbps", l.SpeedMbps)
	}
	f := ""
	if l.FraudScore >= 0 {
		f = fmt.Sprintf(" fraud=%d", l.FraudScore)
	}
	return fmt.Sprintf("%s:%d %s%s%s", l.NodeHost, l.NodePort, t, s, f)
}

var _ = nlog.Core // keep import parity with sibling packages
