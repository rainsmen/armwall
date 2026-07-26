package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupAPITest(t *testing.T, initial Store) {
	t.Helper()
	oldDB, oldData, oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir := dbPath, dataPath, configPath, macACLPath, naiveConfigDir, logDir
	oldRestart, oldProxyPort, oldTProxyPort, oldTProxyEnabled := restartProxyFn, proxyPort, tproxyPort, tproxyEnabled
	oldBackupDir, oldCoreUploadDir, oldUpdateCorePath := backupDir, coreUploadDir, updateCorePath
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	configPath = filepath.Join(dir, "sing-box.json")
	macACLPath = filepath.Join(dir, "mac-acl.tsv")
	naiveConfigDir = filepath.Join(dir, "naive")
	logDir = filepath.Join(dir, "logs")
	backupDir = filepath.Join(dir, "backups")
	coreUploadDir = filepath.Join(dir, "uploads")
	proxyPort = 11080
	restartProxyFn = func() error { return nil }
	t.Cleanup(func() {
		dbPath, dataPath, configPath, macACLPath, naiveConfigDir, logDir = oldDB, oldData, oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir
		restartProxyFn, proxyPort, tproxyPort, tproxyEnabled = oldRestart, oldProxyPort, oldTProxyPort, oldTProxyEnabled
		backupDir, coreUploadDir, updateCorePath = oldBackupDir, oldCoreUploadDir, oldUpdateCorePath
	})
	if err := save(initial); err != nil {
		t.Fatal(err)
	}
}

func TestConfigArchiveAndBackupLifecycle(t *testing.T) {
	dir := t.TempDir()
	oldBackupDir := backupDir
	backupDir = dir
	t.Cleanup(func() { backupDir = oldBackupDir })
	want := Store{Mode: "global", ProxyPort: 11080, LogLevel: "info", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", Enabled: true}}}
	created, err := createConfigBackup(want, "armwall-backup")
	if err != nil {
		t.Fatal(err)
	}
	if !validBackupName(created.Name) || validBackupName("../"+created.Name) {
		t.Fatalf("unexpected backup name validation for %q", created.Name)
	}
	backups, err := listConfigBackups()
	if err != nil || len(backups) != 1 || backups[0].Name != created.Name {
		t.Fatalf("unexpected backup list: %+v, %v", backups, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, created.Name))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseConfigArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyPort != want.ProxyPort || len(got.Nodes) != 1 || got.Nodes[0].Password != "secret" {
		t.Fatalf("unexpected restored store: %+v", got)
	}
}

func TestCoreUploadUsesManagedTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	oldUploadDir, oldUpdateCorePath := coreUploadDir, updateCorePath
	coreUploadDir = filepath.Join(dir, "uploads")
	updateCorePath = filepath.Join(dir, "fake-update")
	t.Cleanup(func() { coreUploadDir, updateCorePath = oldUploadDir, oldUpdateCorePath })
	script := "#!/bin/sh\n[ \"$1:$2\" = \"naive:manual\" ] || exit 2\n[ -s \"$3\" ] || exit 3\nprintf 'naive uploaded\\n'\n"
	if err := os.WriteFile(updateCorePath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("core", "naive"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", "naive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("test binary")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/core/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	handleCoreUpload(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "naive uploaded") {
		t.Fatalf("upload status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(coreUploadDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary upload was not removed: %+v, %v", entries, err)
	}
}

func TestStrategyRuntimeStatusAndDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxies":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"proxies":{"g1":{"now":"n2","history":[]},"n1":{"history":[{"delay":80}]},"n2":{"history":[{"delay":42}]}}}`))
		case "/proxies/g1/delay":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"delay":39}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldBase := clashAPIBase
	clashAPIBase = server.URL
	t.Cleanup(func() { clashAPIBase = oldBase })
	s := Store{StrategyGroups: []StrategyGroup{{ID: "g1", Name: "auto", Type: "urltest", NodeIDs: []string{"n1", "n2"}}}}
	statuses := strategyRuntimeStatuses(s)
	if len(statuses) != 1 || !statuses[0].Available || statuses[0].Selected != "n2" || statuses[0].DelayMS != 42 || statuses[0].MemberDelays["n1"] != 80 {
		t.Fatalf("unexpected runtime status: %+v", statuses)
	}
	delay, err := clashDelay("g1", "https://example.com/204")
	if err != nil || delay != 39 {
		t.Fatalf("delay=%d err=%v", delay, err)
	}
}

func callAPI(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	api(recorder, req)
	return recorder
}

func TestParseSubscriptionProtocols(t *testing.T) {
	raw := "anytls://secret@example.com:443?sni=example.com#A\n" +
		"hysteria2://pw@example.net:8443?sni=example.net#B\n" +
		"trojan://pw@example.org:443#C\n" +
		"naive+https://alice:secret@naive.example:443#N"
	nodes := parseSubscription(raw)
	if len(nodes) != 4 {
		t.Fatalf("got %d nodes", len(nodes))
	}
	if nodes[0].Type != "anytls" || nodes[0].Password != "secret" || nodes[0].ServerName != "example.com" {
		t.Fatalf("unexpected anytls node: %+v", nodes[0])
	}
	if nodes[1].Type != "hysteria2" || nodes[1].Password != "pw" {
		t.Fatalf("unexpected hysteria2 node: %+v", nodes[1])
	}
	if nodes[2].Type != "trojan" || nodes[2].Password != "pw" {
		t.Fatalf("unexpected trojan node: %+v", nodes[2])
	}
	if nodes[3].Type != "naive" || nodes[3].Transport != "https" || nodes[3].Username != "alice" || nodes[3].Password != "secret" {
		t.Fatalf("unexpected NaiveProxy node: %+v", nodes[3])
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

func TestSQLiteRoundTrip(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath = oldDB; dataPath = oldData })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	want := Store{Mode: "gfw", ProxyPort: 11080, SelectedNode: "n1", TCPOutbound: "g1", UDPOutbound: "same", DNS: DNSSettings{Enabled: true, RemoteServer: "https://1.1.1.1/dns-query", RemoteSNI: "cloudflare-dns.com", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true}, ACLRules: []ACLRule{{ID: "a1", Name: "客户端", Enabled: true, SourceCIDRs: []string{"192.168.10.20/32"}, Network: "tcp", PortRanges: []string{"443"}, Outbound: "direct"}}, StrategyGroups: []StrategyGroup{{ID: "g1", Name: "自动选择", Type: "urltest", NodeIDs: []string{"n1"}, Selected: "n1", TestURL: "https://example.com/204", IntervalSec: 180, ToleranceMS: 50}}, Subscriptions: []Subscription{{ID: "s1", Name: "测试订阅", URL: "https://example.com/sub", UpdateHours: 6, Enabled: true}}, Nodes: []Node{{ID: "n1", Name: "节点", Type: "anytls", Server: "example.com", Port: 443, Enabled: true, Group: "测试订阅", SubscriptionID: "s1"}}}
	if err := save(want); err != nil {
		t.Fatal(err)
	}
	got := load()
	if len(got.Nodes) != 1 || len(got.Subscriptions) != 1 || len(got.StrategyGroups) != 1 || len(got.ACLRules) != 1 || !got.DNS.Enabled || got.Nodes[0].SubscriptionID != "s1" || got.ProxyPort != 11080 || got.TCPOutbound != "g1" {
		t.Fatalf("unexpected round trip: %+v", got)
	}
}

func TestLegacyMigration(t *testing.T) {
	s := migrateLegacy(Store{SubscriptionURLs: []string{"https://example.com/sub"}, Nodes: []Node{{ID: "sub-1", Name: "legacy"}}})
	if len(s.Subscriptions) != 1 || s.Nodes[0].SubscriptionID == "" || !s.Nodes[0].Enabled {
		t.Fatalf("migration failed: %+v", s)
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

func TestParseSubscriptionIgnoresUnsupported(t *testing.T) {
	nodes := parseSubscription(strings.Join([]string{"not-a-node", "https://example.com/no-protocol"}, "\n"))
	if len(nodes) != 0 {
		t.Fatalf("got unsupported nodes: %+v", nodes)
	}
}

func TestToggleSelectedNodeChoosesEnabledFallback(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Enabled: true},
		{ID: "n2", Name: "two", Type: "anytls", Server: "two.example", Port: 443, Enabled: true},
	}})
	recorder := callAPI(t, "/api/node/toggle", `{"ID":"n1","Enabled":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if got.SelectedNode != "n2" || got.Nodes[0].Enabled {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestBatchToggleAndCopyNode(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Enabled: true, SubscriptionID: "s1", Group: "source"},
		{ID: "n2", Name: "two", Type: "hysteria2", Server: "two.example", Port: 8443, Enabled: true},
	}})
	recorder := callAPI(t, "/api/node/batch-toggle", `{"IDs":["n1","n2"],"Enabled":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if got.SelectedNode != "" || got.Nodes[0].Enabled || got.Nodes[1].Enabled {
		t.Fatalf("unexpected batch toggle: %+v", got)
	}
	recorder = callAPI(t, "/api/node/copy", `{"ID":"n1"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("copy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got = load()
	if len(got.Nodes) != 3 || got.Nodes[2].SubscriptionID != "" || got.Nodes[2].Group != "手动节点" || !got.Nodes[2].Enabled {
		t.Fatalf("unexpected copy: %+v", got.Nodes)
	}
}

func TestSubscriptionEditUpdatesOwnedNodeGroup(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, Subscriptions: []Subscription{{ID: "s1", Name: "old", URL: "https://example.com/old", UpdateHours: 6, Enabled: true}}, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Enabled: true, SubscriptionID: "s1", Group: "old"}}})
	recorder := callAPI(t, "/api/subscription/edit", `{"id":"s1","name":"new","url":"https://example.com/new","update_hours":12,"enabled":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if got.Subscriptions[0].Name != "new" || got.Subscriptions[0].Enabled || got.Nodes[0].Group != "new" {
		t.Fatalf("unexpected edit: %+v", got)
	}
}

func TestEmbeddedWebAssets(t *testing.T) {
	for _, name := range []string{"web/index.html", "web/styles.css", "web/app.js"} {
		content, err := webFiles.ReadFile(name)
		if err != nil || len(content) == 0 {
			t.Fatalf("asset %s: size=%d err=%v", name, len(content), err)
		}
	}
}

func TestConfigStrategyAndSeparateUDPOutbound(t *testing.T) {
	s := Store{Mode: "global", SelectedNode: "n1", TCPOutbound: "g1", UDPOutbound: "n2", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Enabled: true},
		{ID: "n2", Name: "two", Type: "hysteria2", Server: "two.example", Port: 8443, Enabled: true},
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

func TestStrategyAPIAndRoutingSelection(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Enabled: true},
		{ID: "n2", Name: "two", Type: "hysteria2", Server: "two.example", Port: 8443, Enabled: true},
	}})
	recorder := callAPI(t, "/api/strategy", `{"name":"auto","type":"urltest","node_ids":["n1","n2"],"selected":"n1","test_url":"https://example.com/204","interval_sec":60,"tolerance_ms":50}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("strategy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if len(got.StrategyGroups) != 1 {
		t.Fatalf("missing strategy: %+v", got)
	}
	groupID := got.StrategyGroups[0].ID
	recorder = callAPI(t, "/api/routing", `{"Mode":"global","TCPOutbound":"`+groupID+`","UDPOutbound":"n2"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("routing status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got = load()
	if got.Mode != "global" || got.TCPOutbound != groupID || got.UDPOutbound != "n2" {
		t.Fatalf("unexpected routing: %+v", got)
	}
}

func TestSubscriptionDueUsesPerSubscriptionInterval(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	if !subscriptionDue(Subscription{UpdateHours: 6}, now) {
		t.Fatal("never-updated subscription should be due")
	}
	if subscriptionDue(Subscription{UpdateHours: 6, LastUpdated: now.Add(-5 * time.Hour)}, now) {
		t.Fatal("subscription should not be due before its interval")
	}
	if !subscriptionDue(Subscription{UpdateHours: 6, LastUpdated: now.Add(-6 * time.Hour)}, now) {
		t.Fatal("subscription should be due at its interval")
	}
}

func TestConfigACLAndDNS(t *testing.T) {
	s := Store{Mode: "global", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Enabled: true}}, ACLRules: []ACLRule{{ID: "a1", Name: "client", Enabled: true, SourceCIDRs: []string{"192.168.10.20/32"}, SourceMACs: []string{"00:11:22:33:44:55"}, Network: "tcp", PortRanges: []string{"443", "1000:2000"}, Outbound: "direct"}}, DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.217", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", RemoteSNI: "cloudflare-dns.com", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true, FakeIP: true}}
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
	s := Store{Mode: "global", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "pw", Enabled: true}}, ACLRules: []ACLRule{{ID: "a1", Name: "client", Enabled: true, SourceMACs: []string{"00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"}, Network: "tcp", PortRanges: []string{"443", "1000:2000"}, Outbound: "n1"}}}
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

func TestACLAndDNSAPI(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Enabled: true}}})
	recorder := callAPI(t, "/api/acl", `{"name":"客户端","enabled":true,"source_cidrs":["192.168.10.20"],"source_macs":["00:11:22:33:44:55"],"network":"tcp","port_ranges":["443"],"outbound":"direct"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ACL status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = callAPI(t, "/api/dns", `{"enabled":true,"remote_server":"https://1.1.1.1/dns-query","remote_sni":"cloudflare-dns.com","direct_server":"udp://223.5.5.5","strategy":"prefer_ipv4","hijack":true,"fake_ip":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("DNS status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if len(got.ACLRules) != 1 || got.ACLRules[0].SourceCIDRs[0] != "192.168.10.20/32" || !got.DNS.Enabled {
		t.Fatalf("unexpected ACL/DNS state: %+v", got)
	}
}
