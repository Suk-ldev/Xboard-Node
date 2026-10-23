// Package vpngate fetches and filters the official VPNGate server list
// (http://www.vpngate.net/api/iphone/ — CSV with embedded OpenVPN configs).
//
// Egress rides a real OpenVPN tunnel to the volunteer node (fanout-style):
// no third-party relay, no quota. Home-broadband candidates are picked by
// excluding the university relay pool (public-vpn-* hostnames and
// 219.100.37.0/24); the health probe keeps enforcing isResidential/fraud
// after connect (the API has no such fields).
package vpngate

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Source describes where the server list lives and which rows to keep.
// Stored in the egress state file; the admin panel edits it live.
type Source struct {
	URL string `json:"url"`
	// ResidentialOnly excludes the known datacenter relay pool
	// (public-vpn-* hostnames / 219.100.37.0/24). The probe enforces the
	// rest (isResidential on the exit IP).
	ResidentialOnly bool `json:"residential_only"`
	// MaxFraudScore is probe-enforced after connect (0 disables).
	MaxFraudScore int `json:"max_fraud_score"`
	// Countries is an allowlist of CountryLong names (case-insensitive).
	Countries []string `json:"countries,omitempty"`
	// ExcludeIPs drops rows whose server IP is in the list.
	ExcludeIPs []string `json:"exclude_ips,omitempty"`
}

// Defaults fills unset fields. It does NOT touch ResidentialOnly — that
// flag is meaningful as false too (callers seeding from config pass it
// explicitly).
func (s *Source) Defaults() {
	if s.URL == "" {
		s.URL = DefaultAPIURL
	}
}

// DefaultAPIURL is the official VPNGate CSV API (every row embeds a full
// OpenVPN client config: CA, client cert, key).
const DefaultAPIURL = "https://www.vpngate.net/api/iphone/"

// Row is one usable VPNGate server entry.
type Row struct {
	Host      string  `json:"host"` // e.g. vpn661982.opengw.net (may be bare hostname)
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	Proto     string  `json:"proto"` // tcp|udp (from the embedded config)
	SpeedMbps float64 `json:"speed_mbps"`
	Country   string  `json:"country"`
	Sessions  int     `json:"sessions"`
	Operator  string  `json:"operator,omitempty"`
	// ConfigB64 is the embedded OpenVPN config (base64, verbatim from API).
	ConfigB64 string `json:"config_b64"`
}

// Key identifies a row (host:port) for pinning and the used-ring.
func (r Row) Key() string { return r.Host + ":" + strconv.Itoa(r.Port) }

// Manager owns server-list fetching, parsing and filtering.
type Manager struct {
	mu      sync.Mutex
	src     Source
	cache   []Row
	fetched time.Time
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
func (m *Manager) Cache() ([]Row, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cache, m.fetched
}

// Fetch downloads the server list, filters it and returns candidates
// (unsorted upstream order; callers usually sort by speed). On success the
// result is cached. With staleOK, a failed fetch falls back to the cache.
func (m *Manager) Fetch(staleOK bool) ([]Row, time.Time, error) {
	rows, err := m.fetchOnce()
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
	m.cache = rows
	m.fetched = time.Now()
	cached, at := m.cache, m.fetched
	m.mu.Unlock()
	return cached, at, nil
}

func (m *Manager) fetchOnce() ([]Row, error) {
	src := m.Source()
	body, err := HTTPGet(src.URL, 90*time.Second)
	if err != nil {
		return nil, err
	}
	rows := ParseAPI(string(body))
	rows = m.Filter(rows)
	if len(rows) == 0 {
		return nil, fmt.Errorf("no servers match the current filters")
	}
	return rows, nil
}

// ParseAPI parses the VPNGate CSV (first line "*vpn_servers", second the
// header, one row per server, last line "*"). Malformed rows are skipped.
func ParseAPI(text string) []Row {
	var out []Row
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 256*1024), 8<<20)
	var header []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "*") {
			if header != nil {
				break // trailing "*"
			}
			continue
		}
		recs, err := parseCSVLine(line)
		if err != nil {
			continue
		}
		if header == nil {
			for _, h := range recs {
				header = append(header, strings.TrimPrefix(h, "#"))
			}
			continue
		}
		if len(recs) != len(header) {
			continue
		}
		row, err := rowFromRecord(header, recs)
		if err == nil {
			out = append(out, row)
		}
	}
	return out
}

func rowFromRecord(header, recs []string) (Row, error) {
	get := func(name string) string {
		for i, h := range header {
			if h == name {
				return recs[i]
			}
		}
		return ""
	}
	cfgB64 := get("OpenVPN_ConfigData_Base64")
	if cfgB64 == "" {
		return Row{}, fmt.Errorf("no openvpn config")
	}
	cfg, err := base64.StdEncoding.DecodeString(cfgB64)
	if err != nil {
		return Row{}, fmt.Errorf("decode config: %w", err)
	}
	cfgStr := string(cfg)
	proto, host, port, err := parseRemote(cfgStr)
	if err != nil {
		return Row{}, err
	}
	speed, _ := strconv.ParseFloat(get("Speed"), 64)
	sessions, _ := strconv.Atoi(get("NumVpnSessions"))
	ip := get("IP")
	if net.ParseIP(ip) == nil {
		return Row{}, fmt.Errorf("bad ip %q", ip)
	}
	r := Row{
		Host:      get("HostName"),
		IP:        ip,
		Port:      port,
		Proto:     proto,
		SpeedMbps: speed / 1_000_000,
		Country:   get("CountryLong"),
		Sessions:  sessions,
		Operator:  get("Operator"),
		ConfigB64: cfgB64,
	}
	if r.Host == "" {
		r.Host = ip
	}
	// Prefer the API IP over the config's remote host (DDNS names may lag);
	// the config generator rewrites remote with the row IP.
	_ = host
	return r, nil
}

// parseRemote extracts proto/host/port from the embedded config's `remote`
// and `proto` directives.
func parseRemote(cfg string) (proto, host string, port int, err error) {
	proto = "tcp"
	for _, line := range strings.Split(cfg, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "proto":
			if len(f) >= 2 {
				proto = strings.TrimSuffix(f[1], "-client")
			}
		case "remote":
			if len(f) >= 3 {
				host = f[1]
				p, e := strconv.Atoi(f[2])
				if e == nil {
					port = p
				}
			}
		}
	}
	if host == "" || port <= 0 || port > 65535 {
		return "", "", 0, fmt.Errorf("config missing remote")
	}
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	return proto, host, port, nil
}

// parseCSVLine handles quoted CSV fields (the API quotes commas inside
// operator/message fields).
func parseCSVLine(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			if inQ && i+1 < len(line) && line[i+1] == '"' {
				cur.WriteByte('"')
				i++
			} else {
				inQ = !inQ
			}
		case c == ',' && !inQ:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out, nil
}

// relayPool4 is the SoftEther university relay range fanout treats as
// datacenter (public-vpn-* hosts).
var relayPool4 = netip.MustParsePrefix("219.100.37.0/24")

// Filter applies the source filters. Rows are returned in upstream order;
// callers sort by Speed for priority.
func (m *Manager) Filter(rows []Row) []Row {
	src := m.Source()
	countries := map[string]bool{}
	for _, c := range src.Countries {
		countries[strings.ToLower(strings.TrimSpace(c))] = true
	}
	excl := map[string]bool{}
	for _, ip := range src.ExcludeIPs {
		excl[strings.TrimSpace(ip)] = true
	}

	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		if src.ResidentialOnly {
			if strings.HasPrefix(r.Host, "public-vpn") {
				continue
			}
			if p, err := netip.ParseAddr(r.IP); err == nil && relayPool4.Contains(p) {
				continue
			}
		}
		if len(countries) > 0 && !countries[strings.ToLower(r.Country)] {
			continue
		}
		if excl[r.IP] || excl[r.Host] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// SortBySpeed reorders rows fastest-first.
func SortBySpeed(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].SpeedMbps > rows[j].SpeedMbps })
}

// LogSummary summarizes a row for the node log.
func (r Row) LogSummary() string {
	return fmt.Sprintf("%s:%d %s %.0fMbps", r.Host, r.Port, r.Country, r.SpeedMbps)
}

// HTTPGet performs a plain HTTP GET with timeout; used for the server list.
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
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// PersistCache writes rows to disk so a restart keeps the same pool without
// re-fetching (also the seed for offline first boots).
func PersistCache(dir string, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.ConfigB64)
		b.WriteByte('\n')
		b.WriteString(r.Host)
		b.WriteByte('|')
		b.WriteString(r.IP)
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(r.Port))
		b.WriteByte('|')
		b.WriteString(r.Proto)
		b.WriteByte('|')
		b.WriteString(strconv.FormatFloat(r.SpeedMbps, 'f', -1, 64))
		b.WriteByte('|')
		b.WriteString(r.Country)
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(r.Sessions))
		b.WriteByte('\n')
	}
	return os.WriteFile(dir+"/rows.txt", []byte(b.String()), 0o600)
}

// LoadCache reads a previously persisted rows file
// (ConfigB64\n host|ip|port|proto|speed|country|sessions per row).
func LoadCache(dir string) []Row {
	data, err := os.ReadFile(dir + "/rows.txt")
	if err != nil {
		return nil
	}
	var out []Row
	lines := strings.Split(string(data), "\n")
	for i := 0; i+1 < len(lines); i += 2 {
		cfgB64 := strings.TrimSpace(lines[i])
		fields := strings.Split(strings.TrimSpace(lines[i+1]), "|")
		if cfgB64 == "" || len(fields) != 7 {
			continue
		}
		port, _ := strconv.Atoi(fields[2])
		speed, _ := strconv.ParseFloat(fields[4], 64)
		sessions, _ := strconv.Atoi(fields[6])
		out = append(out, Row{
			ConfigB64: cfgB64, Host: fields[0], IP: fields[1],
			Port: port, Proto: fields[3], SpeedMbps: speed,
			Country: fields[5], Sessions: sessions,
		})
	}
	return out
}
