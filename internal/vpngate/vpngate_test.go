package vpngate

import (
	"strings"
	"testing"
)

const sampleSub = `vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@saas.sin.fan:443?encryption=none&security=tls&sni=snip.edgeoneai.cc.cd&fp=chrome&alpn=h3%2Ch2&type=ws&host=snip.edgeoneai.cc.cd&path=%2Ffdip%3Dsstp%3A%2F%2Fvpn%3Avpn%40cetsssa.opengw.net%3A992%3Fed%3D2560#%E5%AE%B6%E5%AE%BD%7C%E7%BA%AF%E5%87%80%E5%BA%A6%3A1%7CMexico%7C81.92%7C%E8%90%BD%E5%9C%B0%3A189.186.183.153
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@saas.sin.fan:443?encryption=none&security=tls&sni=snip.edgeoneai.cc.cd&fp=chrome&alpn=h3%2Ch2&type=ws&host=snip.edgeoneai.cc.cd&path=%2Ffdip%3Dsstp%3A%2F%2Fvpn%3Avpn%40public-vpn-137.opengw.net%3A443%3Fed%3D2560#%E6%9C%BA%E6%88%BF%7C%E7%BA%AF%E5%87%80%E5%BA%A6%3A85%7CJapan%7C1165.07%7C%E8%90%BD%E5%9C%B0%3A219.100.37.240
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@saas.sin.fan:443?encryption=none&security=tls&sni=snip.edgeoneai.cc.cd&fp=chrome&alpn=h3%2Ch2&type=ws&host=snip.edgeoneai.cc.cd&path=%2Ffdip%3Dsstp%3A%2F%2Fvpn%3Avpn%40vpn584377130.opengw.net%3A1822%3Fed%3D2560#%E5%AE%B6%E5%AE%BD%7C%E7%BA%AF%E5%87%80%E5%BA%A6%3A6%7CJapan%7C84.79%7C%E8%90%BD%E5%9C%B0%3A14.14.148.93
# comment line
not-a-link
`

func TestParseLinks(t *testing.T) {
	links := ParseLinks(sampleSub)
	if len(links) != 3 {
		t.Fatalf("expected 3 links, got %d", len(links))
	}
	l := links[0]
	if l.NodeHost != "cetsssa.opengw.net" || l.NodePort != 992 {
		t.Errorf("node = %s:%d, want cetsssa.opengw.net:992", l.NodeHost, l.NodePort)
	}
	if !l.Residential || !l.KnownType {
		t.Errorf("link 0 should be residential (家宽), got %+v", l)
	}
	if l.FraudScore != 1 {
		t.Errorf("fraud = %d, want 1", l.FraudScore)
	}
	if l.Country != "Mexico" {
		t.Errorf("country = %q, want Mexico", l.Country)
	}
	if l.SpeedMbps != 81.92 {
		t.Errorf("speed = %v, want 81.92", l.SpeedMbps)
	}
	if l.ExitIP != "189.186.183.153" {
		t.Errorf("exit ip = %q", l.ExitIP)
	}
	if links[1].Residential || !links[1].KnownType {
		t.Errorf("link 1 should be datacenter (机房)")
	}
	if links[2].Country != "Japan" {
		t.Errorf("link 2 country = %q", links[2].Country)
	}
}

func TestFilterResidentialOnly(t *testing.T) {
	m := NewManager(Source{URL: "x", ResidentialOnly: true, MaxFraudScore: 30})
	links := m.Filter(ParseLinks(sampleSub))
	if len(links) != 2 {
		t.Fatalf("residential-only filter: want 2, got %d", len(links))
	}
	for _, l := range links {
		if !l.Residential {
			t.Errorf("datacenter link leaked: %+v", l)
		}
	}
}

func TestFilterFraudAndCountry(t *testing.T) {
	m := NewManager(Source{URL: "x", ResidentialOnly: false, MaxFraudScore: 50, Countries: []string{"japan"}})
	links := m.Filter(ParseLinks(sampleSub))
	if len(links) != 1 {
		t.Fatalf("japan+fraud50: want 1, got %d", len(links))
	}
	if links[0].NodeHost != "vpn584377130.opengw.net" {
		t.Errorf("wrong survivor: %+v", links[0])
	}
}

func TestFilterExcludeIP(t *testing.T) {
	m := NewManager(Source{URL: "x", ResidentialOnly: false, ExcludeIPs: []string{"219.100.37.240"}})
	links := m.Filter(ParseLinks(sampleSub))
	if len(links) != 2 {
		t.Fatalf("exclude 219.100.37.240: want 2, got %d", len(links))
	}
}

func TestOutboundJSON(t *testing.T) {
	l := ParseLinks(sampleSub)[0]
	obj := l.OutboundJSON("vpngate", "")
	vnext := obj["settings"].(map[string]any)["vnext"].([]map[string]any)[0]
	if vnext["address"] != EntryHost {
		t.Errorf("address = %v, want %s", vnext["address"], EntryHost)
	}
	if vnext["users"].([]map[string]any)[0]["id"] != RealUUID {
		t.Errorf("uuid placeholder not replaced")
	}
	ss := obj["streamSettings"].(map[string]any)
	if ss["network"] != "ws" {
		t.Errorf("network = %v", ss["network"])
	}
	tls := ss["tlsSettings"].(map[string]any)
	if tls["serverName"] != SNI {
		t.Errorf("sni = %v, want %s", tls["serverName"], SNI)
	}
	if tls["alpn"].([]string)[0] != "http/1.1" {
		t.Errorf("alpn must be http/1.1 for WS (h3 breaks the entry)")
	}
	ws := ss["wsSettings"].(map[string]any)
	if !strings.Contains(ws["path"].(string), "fdip=sstp://vpn:vpn@cetsssa.opengw.net:992") {
		t.Errorf("ws path wrong: %v", ws["path"])
	}
}

func TestSingboxJSON(t *testing.T) {
	l := ParseLinks(sampleSub)[2]
	obj := l.SingboxJSON("vpngate", "custom-uuid")
	if obj["server"] != EntryHost || obj["uuid"] != "custom-uuid" {
		t.Errorf("singbox outbound wrong: %+v", obj)
	}
	tr := obj["transport"].(map[string]any)
	if tr["type"] != "ws" || tr["path"] != l.Path {
		t.Errorf("transport = %+v", tr)
	}
}

func TestParseFdipPath(t *testing.T) {
	host, port, err := parseFdipPath("/fdip=sstp://vpn:vpn@vpn699884073.opengw.net:1556?ed=2560")
	if err != nil || host != "vpn699884073.opengw.net" || port != 1556 {
		t.Errorf("got %s:%d err=%v", host, port, err)
	}
	if _, _, err := parseFdipPath("/wrong=prefix"); err == nil {
		t.Error("non-fdip path should error")
	}
}
