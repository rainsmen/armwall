package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeTransportAndConfigOmission(t *testing.T) {
	if normalizeTransport("tcp") != "" || normalizeTransport("none") != "" || normalizeTransport("") != "" {
		t.Fatal("tcp/none/empty should normalize to empty string")
	}
	if normalizeTransport("h2") != "http" {
		t.Fatalf("h2 should normalize to http, got %s", normalizeTransport("h2"))
	}
	if normalizeTransport("ws") != "ws" || normalizeTransport("grpc") != "grpc" {
		t.Fatal("ws and grpc should be preserved")
	}

	// VMess with "net":"tcp" should have empty Transport and no transport object in config
	vmessJSON := `{"v":"2","ps":"VMess-TCP","add":"vm.example","port":443,"id":"11111111-1111-1111-1111-111111111111","aid":0,"scy":"auto","net":"tcp","tls":"none"}`
	vmessLink := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	nodes := parseSubscription(vmessLink)
	if len(nodes) != 1 {
		t.Fatalf("failed to parse vmess link")
	}
	if nodes[0].Transport != "" {
		t.Fatalf("expected empty transport for net=tcp, got %q", nodes[0].Transport)
	}

	// Trojan link with ?type=tcp
	trojanLink := "trojan://password@tr.example:443?type=tcp&sni=tr.example#Trojan-TCP"
	parsed := parseSubscription(trojanLink)
	if len(parsed) != 1 {
		t.Fatalf("failed to parse trojan link")
	}
	if parsed[0].Transport != "" {
		t.Fatalf("expected empty transport for type=tcp, got %q", parsed[0].Transport)
	}

	// Trojan link with ?type=h2
	trojanH2 := "trojan://password@tr.example:443?type=h2&sni=tr.example#Trojan-H2"
	parsedH2 := parseSubscription(trojanH2)
	if len(parsedH2) != 1 || parsedH2[0].Transport != "http" {
		t.Fatalf("expected transport=http for type=h2, got %+v", parsedH2)
	}

	// Verify sing-box config generation does not render "transport" block when transport is empty or tcp
	gen := config(Store{Mode: "global", SelectedNode: nodes[0].ID, Nodes: nodes})
	outbounds := gen["outbounds"].([]any)
	nodeOutbound := outbounds[2].(map[string]any)
	if nodeOutbound["transport"] != nil {
		t.Fatalf("config should not contain transport object for tcp, got: %+v", nodeOutbound["transport"])
	}

	// ValidateNode rejects invalid transports like "kcp"
	invalidNode := Node{Name: "invalid", Type: "vmess", Server: "example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Transport: "kcp"}
	if err := validateNode(&invalidNode); err == nil {
		t.Fatal("validateNode should reject unsupported transport kcp")
	}
}

func TestRealityOutboundDefaultsToUTLS(t *testing.T) {
	node := Node{ID: "reality", Name: "Reality", Type: "vless", Server: "example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", TLS: true, RealityPublicKey: "jNXHtI83KYx3XXLs6VJZMBpTqJ8xIuVKvvKDPOv-gRs", RealityShortID: "0123456789abcdef", Enabled: true}
	generated := config(Store{Mode: "global", SelectedNode: node.ID, Nodes: []Node{node}})
	outbound := generated["outbounds"].([]any)[2].(map[string]any)
	tls := outbound["tls"].(map[string]any)
	utls := tls["utls"].(map[string]any)
	if !utls["enabled"].(bool) || utls["fingerprint"] != "chrome" || tls["reality"] == nil {
		t.Fatalf("Reality did not receive a default uTLS fingerprint: %+v", tls)
	}
}

func TestNaiveProxyUsesLocalSOCKSBridge(t *testing.T) {
	dir := t.TempDir()
	oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldNaivePort := configPath, macACLPath, naiveConfigDir, logDir, naiveProxyPort
	configPath = filepath.Join(dir, "sing-box.json")
	macACLPath = filepath.Join(dir, "mac-acl.tsv")
	naiveConfigDir = filepath.Join(dir, "naive")
	logDir = filepath.Join(dir, "logs")
	naiveProxyPort = 12000
	t.Cleanup(func() {
		configPath, macACLPath, naiveConfigDir, logDir, naiveProxyPort = oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldNaivePort
	})
	s := Store{Mode: "global", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "naive", Type: "naive", Server: "example.com", Port: 443, Username: "alice@example.com", Password: "p@ss", Transport: "https", Enabled: true}}}
	generated := config(s)
	outbounds := generated["outbounds"].([]any)
	found := false
	for _, raw := range outbounds {
		outbound := raw.(map[string]any)
		if outbound["tag"] == "n1" {
			found = outbound["type"] == "socks" && outbound["server"] == "127.0.0.1" && outbound["server_port"] == 12000
		}
	}
	if !found {
		t.Fatalf("missing NaiveProxy SOCKS bridge: %+v", outbounds)
	}
	if err := writeConfig(s); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(naiveConfigDir, "0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	var naiveConfig map[string]string
	if json.Unmarshal(data, &naiveConfig) != nil || naiveConfig["listen"] != "socks://127.0.0.1:12000" || naiveConfig["proxy"] != "https://alice%40example.com:p%40ss@example.com:443" {
		t.Fatalf("unexpected NaiveProxy config: %s", data)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil || strings.Contains(string(configBytes), `"type": "naive"`) {
		t.Fatalf("invalid sing-box NaiveProxy output: %v %s", err, configBytes)
	}
}

func TestConfigRoutingModes(t *testing.T) {
	s := Store{Mode: "bypass_cn", Nodes: []Node{{ID: "n1", Type: "anytls", Server: "example.com", Port: 443, Password: "pw", TLS: true, Enabled: true}}}
	c := config(s)
	route := c["route"].(map[string]any)
	if route["final"] != "n1" {
		t.Fatalf("bypass final=%v", route["final"])
	}
	if len(route["rule_set"].([]any)) < 2 {
		t.Fatal("bypass should include CN rule sets")
	}
	s.Mode = "gfw"
	route = config(s)["route"].(map[string]any)
	if route["final"] != "direct" {
		t.Fatalf("gfw final=%v", route["final"])
	}
	s.Mode = "global"
	route = config(s)["route"].(map[string]any)
	if route["final"] != "n1" {
		t.Fatalf("global final=%v", route["final"])
	}
}

func BenchmarkConfigGeneration(b *testing.B) {
	nodes := make([]Node, 0, 200)
	for i := 0; i < 200; i++ {
		nodes = append(nodes, Node{ID: fmt.Sprintf("n-%d", i), Name: fmt.Sprintf("node-%d", i), Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true})
	}
	s := Store{Mode: "global", ProxyPort: 11080, Nodes: nodes, DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.1", ListenPort: 5353, RemoteServer: "https://1.1.1.1/dns-query", DirectServer: "udp://223.5.5.5"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = config(s)
	}
}

func TestConfigCanDisableAdBlockingRule(t *testing.T) {
	disabled := false
	s := Store{Mode: "global", AdBlockEnabled: &disabled, Nodes: []Node{{ID: "n1", Type: "anytls", Server: "example.com", Port: 443, Password: "pw", TLS: true, Enabled: true}}}
	route := config(s)["route"].(map[string]any)
	for _, raw := range route["rules"].([]any) {
		rule := raw.(map[string]any)
		if fmt.Sprint(rule["rule_set"]) == "[geosite-ads]" {
			t.Fatalf("ad block rule should be disabled: %+v", route["rules"])
		}
	}
	for _, raw := range route["rule_set"].([]any) {
		ruleSet := raw.(map[string]any)
		if ruleSet["tag"] == "geosite-ads" {
			t.Fatalf("ad rule set should be disabled: %+v", route["rule_set"])
		}
	}
}

func TestConfigStrategyAndSeparateUDPOutbound(t *testing.T) {
	s := Store{Mode: "global", SelectedNode: "n1", TCPOutbound: "g1", UDPOutbound: "n2", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
		{ID: "n2", Name: "two", Type: "hysteria2", Server: "two.example", Port: 8443, Password: "secret", TLS: true, Enabled: true},
	}, StrategyGroups: []StrategyGroup{{ID: "g1", Name: "auto", Type: "urltest", NodeIDs: []string{"n1", "n2"}, Selected: "n1", TestURL: "https://example.com/204", IntervalSec: 120, ToleranceMS: 75}}}
	c := config(s)
	outbounds := c["outbounds"].([]any)
	var group map[string]any
	for _, raw := range outbounds {
		outbound := raw.(map[string]any)
		if outbound["tag"] == "g1" {
			group = outbound
		}
	}
	if group == nil || group["type"] != "urltest" || group["interval"] != "120s" {
		t.Fatalf("unexpected strategy outbound: %+v", group)
	}
	route := c["route"].(map[string]any)
	if route["final"] != "g1" {
		t.Fatalf("final=%v", route["final"])
	}
	foundUDP := false
	for _, raw := range route["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["network"] == "udp" && rule["outbound"] == "n2" {
			foundUDP = true
		}
	}
	if !foundUDP {
		t.Fatalf("missing UDP rule: %+v", route["rules"])
	}
}

func TestConfigurationReloadsActiveGateway(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	if err := os.WriteFile(gatewayStatePath, []byte("eth0\teth0\t11081\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	reloadGatewayFn = func() error {
		reloads++
		return nil
	}
	recorder := callAPI(t, "/api/settings", `{"proxyPort":12080}`)
	if recorder.Code != http.StatusOK || reloads != 1 {
		t.Fatalf("status=%d reloads=%d body=%s", recorder.Code, reloads, recorder.Body.String())
	}
}

func TestConfigurationWhileStoppedDoesNotStartProxy(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	proxyRunningFn = func() bool { return false }
	restarts := 0
	restartProxyFn = func() error {
		restarts++
		return nil
	}
	recorder := callAPI(t, "/api/settings", `{"proxyPort":12080}`)
	generated, readErr := os.ReadFile(configPath)
	if recorder.Code != http.StatusOK || readErr != nil || restarts != 0 || load().ProxyPort != 12080 || !bytes.Contains(generated, []byte(`"listen_port": 12080`)) {
		t.Fatalf("status=%d restarts=%d stored=%d body=%s", recorder.Code, restarts, load().ProxyPort, recorder.Body.String())
	}
}

func TestConfigACLAndDNS(t *testing.T) {
	s := Store{Mode: "global", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}, ACLRules: []ACLRule{{ID: "a1", Name: "client", Enabled: true, SourceCIDRs: []string{"192.168.10.20/32"}, SourceMACs: []string{"00:11:22:33:44:55"}, Network: "tcp", PortRanges: []string{"443", "1000:2000"}, Outbound: "direct"}}, DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.217", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", RemoteSNI: "cloudflare-dns.com", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true, FakeIP: true}}
	c := config(s)
	dns, ok := c["dns"].(map[string]any)
	if !ok || dns["final"] != "remote-dns" {
		t.Fatalf("unexpected DNS config: %+v", c["dns"])
	}
	servers := dns["servers"].([]any)
	if len(servers) != 3 || servers[0].(map[string]any)["type"] != "https" || servers[1].(map[string]any)["detour"] != nil {
		t.Fatalf("unexpected DNS servers: %+v", servers)
	}
	route := c["route"].(map[string]any)
	if route["default_domain_resolver"] != "direct-dns" {
		t.Fatalf("missing default domain resolver: %+v", route)
	}
	rules := route["rules"].([]any)
	aclFound, macACLFound, hijackFound := false, false, false
	for _, raw := range rules {
		rule := raw.(map[string]any)
		if rule["source_mac_address"] != nil {
			t.Fatalf("sing-box 1.13 does not support source_mac_address: %+v", rule)
		}
		if rule["source_ip_cidr"] != nil && rule["outbound"] == "direct" {
			if fmt.Sprint(rule["port"]) != "[443]" || fmt.Sprint(rule["port_range"]) != "[1000:2000]" {
				t.Fatalf("ACL ports were not split correctly: %+v", rule)
			}
			aclFound = true
		}
		if inbound, ok := rule["inbound"].([]string); ok && len(inbound) == 1 && inbound[0] == "acl-mac-1" && rule["outbound"] == "direct" {
			macACLFound = true
		}
		if rule["action"] == "hijack-dns" {
			hijackFound = true
		}
	}
	if !aclFound || !macACLFound || !hijackFound {
		t.Fatalf("missing ACL/DNS hijack rule: %+v", rules)
	}
	inbounds := c["inbounds"].([]any)
	dnsInbound, macInbound := false, false
	for _, raw := range inbounds {
		inbound := raw.(map[string]any)
		if inbound["tag"] == "dns-in" && inbound["listen"] == "192.168.10.217" && inbound["listen_port"] == 53 {
			dnsInbound = true
		}
		if inbound["tag"] == "acl-mac-1" && inbound["listen_port"] == tproxyPort+1 {
			macInbound = true
		}
	}
	if !dnsInbound || !macInbound {
		t.Fatalf("missing DNS/MAC inbound: %+v", inbounds)
	}
	dnsRules := dns["rules"].([]any)
	if dns["final"] != "remote-dns" || len(dnsRules) != 2 || dnsRules[1].(map[string]any)["server"] != "fakeip" {
		t.Fatalf("unexpected FakeIP routing: %+v", dns)
	}
}

func TestWriteConfigCreatesMACACLBindings(t *testing.T) {
	dir := t.TempDir()
	oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldTProxyPort := configPath, macACLPath, naiveConfigDir, logDir, tproxyPort
	configPath = filepath.Join(dir, "sing-box.json")
	macACLPath = filepath.Join(dir, "mac-acl.tsv")
	naiveConfigDir = filepath.Join(dir, "naive")
	logDir = filepath.Join(dir, "logs")
	tproxyPort = 11081
	t.Cleanup(func() {
		configPath, macACLPath, naiveConfigDir, logDir, tproxyPort = oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldTProxyPort
	})
	s := Store{Mode: "global", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "pw", TLS: true, Enabled: true}}, ACLRules: []ACLRule{{ID: "a1", Name: "client", Enabled: true, SourceMACs: []string{"00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"}, Network: "tcp", PortRanges: []string{"443", "1000:2000"}, Outbound: "n1"}}}
	if err := writeConfig(s); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(macACLPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "11082\t00:11:22:33:44:55\ttcp\t443,1000:2000\n11082\taa:bb:cc:dd:ee:ff\ttcp\t443,1000:2000\n"
	if string(b) != want {
		t.Fatalf("MAC ACL bindings = %q, want %q", b, want)
	}
	var generated map[string]any
	configBytes, err := os.ReadFile(configPath)
	if err != nil || json.Unmarshal(configBytes, &generated) != nil {
		t.Fatalf("cannot read generated config: %v", err)
	}
	if strings.Contains(string(configBytes), "source_mac_address") {
		t.Fatal("generated config contains unsupported source_mac_address")
	}
}

func TestWriteConfigRestoresNaiveFilesWhenMACCommitFails(t *testing.T) {
	dir := t.TempDir()
	oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir := configPath, macACLPath, naiveConfigDir, logDir
	configPath = filepath.Join(dir, "sing-box.json")
	macACLPath = filepath.Join(dir, "mac-acl")
	naiveConfigDir = filepath.Join(dir, "naive")
	logDir = filepath.Join(dir, "logs")
	t.Cleanup(func() {
		configPath, macACLPath, naiveConfigDir, logDir = oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir
	})
	if err := os.MkdirAll(naiveConfigDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(naiveConfigDir, "old.json"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(macACLPath, 0750); err != nil {
		t.Fatal(err)
	}
	s := Store{Mode: "global", Nodes: []Node{{ID: "n1", Type: "naive", Server: "example.com", Port: 443, Enabled: true, Transport: "https"}}}
	if err := writeConfig(s); err == nil {
		t.Fatal("expected MAC ACL target failure")
	}
	data, err := os.ReadFile(filepath.Join(naiveConfigDir, "old.json"))
	if err != nil || string(data) != "old" {
		t.Fatalf("previous Naive config was not restored: data=%q err=%v", data, err)
	}
}

func TestRouteRulesHaveSniffing(t *testing.T) {
	tproxyEnabled = true
	defer func() { tproxyEnabled = false }()
	s := Store{
		Mode:      "bypass_cn",
		ProxyPort: 11080,
		Nodes: []Node{
			{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
		},
		ACLRules: []ACLRule{
			{ID: "a1", Name: "mac-rule", Enabled: true, SourceMACs: []string{"00:11:22:33:44:55"}, Outbound: "direct"},
		},
		DNS: DNSSettings{
			Enabled: true,
			Hijack:  true,
		},
	}
	c := config(s)
	route, ok := c["route"].(map[string]any)
	if !ok {
		t.Fatalf("missing route in config: %+v", c)
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		t.Fatalf("missing rules in route: %+v", route)
	}
	sniffIdx := -1
	dnsProtoIdx := -1
	for idx, raw := range rules {
		rule, ok := raw.(map[string]any)
		if ok {
			if rule["action"] == "sniff" {
				sniffIdx = idx
			}
			if rule["protocol"] == "dns" {
				dnsProtoIdx = idx
			}
		}
	}
	if sniffIdx == -1 {
		t.Fatalf("missing sniff rule in route: %+v", rules)
	}
	if dnsProtoIdx == -1 {
		t.Fatalf("missing protocol:dns rule in route: %+v", rules)
	}
	if sniffIdx > dnsProtoIdx {
		t.Fatalf("action:sniff (idx=%d) must come before protocol:dns (idx=%d) for TProxy packet classification", sniffIdx, dnsProtoIdx)
	}
}
