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

func TestNaiveProxyMapsServerNameToDialAddress(t *testing.T) {
	cases := []struct {
		name      string
		server    string
		sni       string
		wantProxy string
		wantRule  string
	}{
		{"relay hostname", "relay.example.com", "origin.example.com", "https://u:p@origin.example.com:4435", "MAP origin.example.com relay.example.com"},
		{"ipv4 server", "203.0.113.7", "origin.example.com", "https://u:p@origin.example.com:4435", "MAP origin.example.com 203.0.113.7"},
		{"ipv6 server", "2001:db8::7", "origin.example.com", "https://u:p@origin.example.com:4435", "MAP origin.example.com [2001:db8::7]"},
		{"sni equals server", "origin.example.com", "ORIGIN.example.com", "https://u:p@origin.example.com:4435", ""},
		{"empty sni", "relay.example.com", "", "https://u:p@relay.example.com:4435", ""},
		{"malformed sni", "relay.example.com", "a.example.com, MAP * evil", "https://u:p@relay.example.com:4435", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Store{ProxyPort: 11080, Nodes: []Node{{ID: "n1", Type: "naive", Server: tc.server, Port: 4435, ServerName: tc.sni, Username: "u", Password: "p", Transport: "https", Enabled: true, NaivePort: 12000}}}
			bindings := naiveBindings(s)
			if len(bindings) != 1 {
				t.Fatalf("bindings=%d", len(bindings))
			}
			var got map[string]string
			if err := json.Unmarshal([]byte(bindings[0].Config), &got); err != nil {
				t.Fatal(err)
			}
			if got["proxy"] != tc.wantProxy || got["host-resolver-rules"] != tc.wantRule {
				t.Fatalf("unexpected NaiveProxy config: %s", bindings[0].Config)
			}
		})
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
	reloadProxyFn = func(bool, bool) error {
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
	// Domains sing-box has to resolve itself must go through the remote
	// resolver; the direct outbound overrides this with the domestic one.
	if route["default_domain_resolver"] != "remote-dns" {
		t.Fatalf("default domain resolver must use the remote resolver: %+v", route)
	}
	for _, raw := range c["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		if outbound["tag"] == "direct" && outbound["domain_resolver"] != "direct-dns" {
			t.Fatalf("direct outbound must resolve through the domestic resolver: %+v", outbound)
		}
		if outbound["tag"] == "n1" && outbound["domain_resolver"] != "remote-dns" {
			t.Fatalf("proxy outbound must resolve through the remote resolver: %+v", outbound)
		}
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
	fakeipRule, directRule := false, false
	for _, raw := range dnsRules {
		rule := raw.(map[string]any)
		if rule["server"] == "fakeip" {
			fakeipRule = true
		}
		if rule["server"] == "direct-dns" {
			directRule = true
		}
	}
	if dns["final"] != "remote-dns" || !fakeipRule || !directRule {
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

func TestConfigAlwaysEmitsDNSResolver(t *testing.T) {
	s := Store{Mode: "bypass_cn", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}}
	c := config(s)
	dns, ok := c["dns"].(map[string]any)
	if !ok {
		t.Fatal("dns block must be emitted even when the DNS module is disabled")
	}
	if _, deprecated := dns["independent_cache"]; deprecated {
		t.Fatal("independent_cache is deprecated in sing-box 1.14")
	}
	if dns["final"] != "remote-dns" || dns["strategy"] != "prefer_ipv4" {
		t.Fatalf("unexpected dns block: %+v", dns)
	}
	servers := dns["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("expected a remote and a direct resolver: %+v", servers)
	}
	remote := servers[0].(map[string]any)
	if remote["tag"] != "remote-dns" || remote["detour"] != "n1" || remote["domain_resolver"] != "direct-dns" {
		t.Fatalf("unexpected remote resolver: %+v", remote)
	}
	direct := servers[1].(map[string]any)
	if direct["tag"] != "direct-dns" || direct["type"] != "udp" || direct["server"] != "223.5.5.5" {
		t.Fatalf("unexpected direct resolver: %+v", direct)
	}
	if rules := dns["rules"].([]any); len(rules) == 0 {
		t.Fatal("dns rules must route domestic domains to the direct resolver")
	}
	route := c["route"].(map[string]any)
	if route["default_domain_resolver"] != "remote-dns" {
		t.Fatalf("default_domain_resolver=%v", route["default_domain_resolver"])
	}
	tags := map[string]bool{}
	for _, raw := range route["rule_set"].([]any) {
		tags[raw.(map[string]any)["tag"].(string)] = true
	}
	if !tags["geosite-cn"] {
		t.Fatalf("geosite-cn must be declared for the dns rules: %+v", route["rule_set"])
	}
	resolvers := map[string]string{}
	for _, raw := range c["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		if tag, isString := outbound["tag"].(string); isString {
			resolvers[tag], _ = outbound["domain_resolver"].(string)
		}
	}
	if resolvers["direct"] != "direct-dns" {
		t.Fatalf("direct resolver=%q", resolvers["direct"])
	}
	if resolvers["n1"] != "remote-dns" {
		t.Fatalf("proxy resolver=%q", resolvers["n1"])
	}
}

func TestForceProxyRulePrecedesCNBypass(t *testing.T) {
	s := Store{Mode: "bypass_cn", SelectedNode: "n1", ForceProxyDomains: []string{"*.Example.COM", "example.com", "example.com"}, Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}}
	route := config(s)["route"].(map[string]any)
	forceIndex, cnIndex, geoIndex := -1, -1, -1
	for i, raw := range route["rules"].([]any) {
		rule := raw.(map[string]any)
		if suffixes, isList := rule["domain_suffix"].([]string); isList {
			found := map[string]int{}
			for _, suffix := range suffixes {
				found[suffix]++
			}
			if found["www.gstatic.com"] > 0 && found["googleapis.com"] > 0 {
				forceIndex = i
				if rule["outbound"] != "n1" {
					t.Fatalf("force proxy rule outbound=%v", rule["outbound"])
				}
				if found["example.com"] != 1 {
					t.Fatalf("user domains must be lowercased and de-duplicated: %v", suffixes)
				}
			}
		}
		if ruleSets, isList := rule["rule_set"].([]string); isList && len(ruleSets) == 1 {
			switch ruleSets[0] {
			case "geosite-cn":
				cnIndex = i
			case "geoip-cn":
				geoIndex = i
			}
		}
	}
	if forceIndex < 0 || cnIndex < 0 || geoIndex < 0 {
		t.Fatalf("missing rules: force=%d cn=%d geo=%d (%+v)", forceIndex, cnIndex, geoIndex, route["rules"])
	}
	if forceIndex > cnIndex || cnIndex > geoIndex {
		t.Fatalf("rules must be ordered force-proxy, geosite-cn, geoip-cn: %d %d %d", forceIndex, cnIndex, geoIndex)
	}
}

func TestNaiveTCPOutboundBlocksUDP(t *testing.T) {
	s := Store{Mode: "global", SelectedNode: "n1", Nodes: []Node{
		{ID: "n1", Name: "naive", Type: "naive", Server: "naive.example", Port: 443, Username: "user", Password: "secret", Enabled: true},
		{ID: "n2", Name: "hy2", Type: "hysteria2", Server: "hy2.example", Port: 8443, Password: "secret", TLS: true, Enabled: true},
	}}
	udpRule := func(s Store) (string, bool) {
		route := config(s)["route"].(map[string]any)
		rules := route["rules"].([]any)
		udpIndex, geoIndex := -1, -1
		for i, raw := range rules {
			rule := raw.(map[string]any)
			if rule["network"] == "udp" {
				udpIndex = i
			}
			if ruleSets, isList := rule["rule_set"].([]string); isList && len(ruleSets) == 1 && ruleSets[0] == "geoip-cn" {
				geoIndex = i
			}
		}
		if udpIndex < 0 {
			return "", false
		}
		if geoIndex >= 0 && udpIndex < geoIndex {
			t.Fatalf("the UDP rule must follow the China rules so domestic UDP stays direct: udp=%d geoip=%d", udpIndex, geoIndex)
		}
		return rules[udpIndex].(map[string]any)["outbound"].(string), true
	}
	if target, found := udpRule(s); !found || target != "block" {
		t.Fatalf("UDP through a naive node must be blocked, got %q (found=%v)", target, found)
	}
	s.UDPOutbound = "n2"
	if target, found := udpRule(s); !found || target != "n2" {
		t.Fatalf("an explicit UDP outbound must be kept, got %q (found=%v)", target, found)
	}
	s.UDPOutbound = ""
	s.Mode = "bypass_cn"
	if target, found := udpRule(s); !found || target != "block" {
		t.Fatalf("bypass_cn must block naive UDP, got %q (found=%v)", target, found)
	}
	s.Mode = "gfw"
	if target, found := udpRule(s); found {
		t.Fatalf("gfw must not inject a UDP block rule, got %q", target)
	}
}

func TestConfigForcedDomainsResolveRemotely(t *testing.T) {
	s := Store{Mode: "bypass_cn", SelectedNode: "n1", DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.1", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true}, Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}}
	dns, ok := config(s)["dns"].(map[string]any)
	if !ok {
		t.Fatal("missing dns block")
	}
	rules := dns["rules"].([]any)
	forceIndex, cnIndex := -1, -1
	for i, raw := range rules {
		rule := raw.(map[string]any)
		if suffixes, isList := rule["domain_suffix"].([]string); isList {
			for _, suffix := range suffixes {
				if suffix == "www.gstatic.com" {
					forceIndex = i
					if rule["server"] != "remote-dns" {
						t.Fatalf("forced proxy domains must be resolved remotely: %+v", rule)
					}
				}
			}
		}
		if ruleSets, isList := rule["rule_set"].([]string); isList && len(ruleSets) == 1 && ruleSets[0] == "geosite-cn" {
			cnIndex = i
		}
	}
	if forceIndex < 0 || cnIndex < 0 {
		t.Fatalf("missing dns rules: force=%d cn=%d (%+v)", forceIndex, cnIndex, rules)
	}
	if forceIndex > cnIndex {
		t.Fatalf("forced proxy domains must be resolved remotely before the China rule: force=%d cn=%d", forceIndex, cnIndex)
	}
}

func TestConfigDNSHijackSkipsPublicResolvers(t *testing.T) {
	s := Store{Mode: "global", SelectedNode: "n1", DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.1", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true}, Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}}
	rules := config(s)["route"].(map[string]any)["rules"].([]any)
	hijackIndex := -1
	for i, raw := range rules {
		rule := raw.(map[string]any)
		if rule["action"] != "hijack-dns" || rule["protocol"] != "dns" {
			continue
		}
		hijackIndex = i
		if inverted, isBool := rule["invert"].(bool); !isBool || !inverted {
			t.Fatalf("the protocol hijack rule must invert the public resolver list: %+v", rule)
		}
		cidrs, isList := rule["ip_cidr"].([]string)
		if !isList {
			t.Fatalf("the protocol hijack rule needs the resolver list: %+v", rule)
		}
		found := false
		for _, cidr := range cidrs {
			if cidr == "8.8.8.8/32" {
				found = true
			}
		}
		if !found {
			t.Fatalf("public resolvers must be exempt from hijacking: %+v", cidrs)
		}
	}
	if hijackIndex < 0 {
		t.Fatalf("missing protocol dns hijack rule: %+v", rules)
	}
	if hijackIndex < 2 {
		t.Fatalf("the dns-in hijack rule must stay first: %d", hijackIndex)
	}
}
