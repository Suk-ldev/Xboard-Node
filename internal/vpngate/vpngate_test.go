package vpngate

import (
	"strings"
	"testing"
)

// Sample rows from the official API (subset of fields; config abbreviated).
const sampleAPI = `*vpn_servers
#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
vpn661982,14.10.120.193,2757531,9,326000000,Japan,JP,17,1771632120,12047,600438992411,1,DESKTOP-OTAKK73's owner,,"IyMjIyMjIyMjIyMjIyMjCmRldiB0dW4KcHJvdG8gdGNwCnJlbW90ZSAxNC4xMC4xMjAuMTkzIDc1NTEKY2lwaGVyIEFFUy0xMjgtQ0JDCmRhdGEtY2lwaGVycyBBRVMtMTI4LUNCQwphdXRoIFNIQTEKcmVzb2x2LXJldHJ5IGluZmluaXRlCm5vYmluZApwZXJzaXN0LWtleQpwZXJzaXN0LXR1bgpjbGllbnQKdmVyYiAzCg=="
public-vpn-137,219.100.37.240,2757531,9,1165000000,Japan,JP,117,1771632120,12047,600438992411,1,Daiyuu Nobori,,"IyMjIyMjIyMjIyMjIyMjCmRldiB0dW4KcHJvdG8gdGNwCnJlbW90ZSAyMTkuMTAwLjM3LjI0MCA0NDMKY2lwaGVyIEFFUy0xMjgtQ0JDCmNsaWVudAo="
*`

// The sample config base64 decodes to a minimal OpenVPN client config with
// remote/proto directives. Verify:
func TestParseAPI(t *testing.T) {
	rows := ParseAPI(sampleAPI)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	r := rows[0]
	if r.Host != "vpn661982" || r.IP != "14.10.120.193" || r.Port != 7551 || r.Proto != "tcp" {
		t.Errorf("row 0 = %+v", r)
	}
	if r.SpeedMbps < 320 || r.SpeedMbps > 330 {
		t.Errorf("speed = %v, want ~326", r.SpeedMbps)
	}
	if !strings.Contains(r.ConfigB64, "IyMj") {
		t.Errorf("config not carried")
	}
	// Decoding the embedded config must yield the remote line.
	meta, err := ParseConfig(r.ConfigB64, r.IP, r.Port, r.Proto)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if meta.Remote != r.IP || meta.Port != 7551 || meta.Proto != "tcp" {
		t.Errorf("meta = %+v", meta)
	}
	if !strings.Contains(meta.Body, "cipher AES-128-CBC") {
		t.Errorf("config body lost: %q", meta.Body)
	}
}

func TestFilterResidentialOnly(t *testing.T) {
	m := NewManager(Source{URL: "x", ResidentialOnly: true})
	rows := m.Filter(ParseAPI(sampleAPI))
	if len(rows) != 1 {
		t.Fatalf("residential-only: want 1 (public-vpn excluded), got %d", len(rows))
	}
	if rows[0].Host != "vpn661982" {
		t.Errorf("wrong survivor: %+v", rows[0])
	}
}

func TestFilterCountry(t *testing.T) {
	m := NewManager(Source{URL: "x", ResidentialOnly: false, Countries: []string{"japan"}})
	rows := m.Filter(ParseAPI(sampleAPI))
	if len(rows) != 2 {
		t.Fatalf("japan filter: want 2, got %d", len(rows))
	}
	m2 := NewManager(Source{URL: "x", ResidentialOnly: false, Countries: []string{"United States"}})
	if rows := m2.Filter(ParseAPI(sampleAPI)); len(rows) != 0 {
		t.Fatalf("us filter: want 0, got %d", len(rows))
	}
}

func TestRenderConfigRewrites(t *testing.T) {
	meta, err := ParseConfig(sampleAPIrows[0].ConfigB64, "14.10.120.193", 7551, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	out := renderConfig(meta)
	for _, want := range []string{
		"remote 14.10.120.193 7551",
		"proto tcp",
		"client",
		"persist-key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q:\n%s", want, out)
		}
	}
	for _, banned := range []string{"redirect-gateway", "route ", "resolv-retry", "dev tun"} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered config must not contain %q:\n%s", banned, out)
		}
	}
}

var sampleAPIrows = ParseAPI(sampleAPI)

func TestParseCSVLine(t *testing.T) {
	recs, err := parseCSVLine(`a,"b,c","d""e",f`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "b,c", `d"e`, "f"}
	if len(recs) != len(want) {
		t.Fatalf("got %v", recs)
	}
	for i := range want {
		if recs[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, recs[i], want[i])
		}
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rows := ParseAPI(sampleAPI)
	if err := PersistCache(dir, rows); err != nil {
		t.Fatal(err)
	}
	got := LoadCache(dir)
	if len(got) != len(rows) {
		t.Fatalf("round trip: want %d, got %d", len(rows), len(got))
	}
	if got[0].Host != rows[0].Host || got[0].IP != rows[0].IP || got[0].Port != rows[0].Port {
		t.Errorf("mismatch: %+v vs %+v", got[0], rows[0])
	}
}
