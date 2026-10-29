package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func setupAPITest(t *testing.T, initial Store) {
	t.Helper()
	oldDB, oldData, oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldRuleDataDir := dbPath, dataPath, configPath, macACLPath, naiveConfigDir, logDir, ruleDataDir
	oldRestart, oldFetch, oldReload, oldProxyRunning, oldProxyPort, oldTProxyPort, oldTProxyEnabled := restartProxyFn, fetchSubscriptionFn, reloadGatewayFn, proxyRunningFn, getProxyPort(), tproxyPort, tproxyEnabled
	oldGatewayPath, oldGatewayStatePath := gatewayPath, gatewayStatePath
	oldBackupDir, oldCoreUploadDir, oldUpdateCorePath := backupDir, coreUploadDir, updateCorePath
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	configPath = filepath.Join(dir, "sing-box.json")
	macACLPath = filepath.Join(dir, "mac-acl.tsv")
	naiveConfigDir = filepath.Join(dir, "naive")
	logDir = filepath.Join(dir, "logs")
	ruleDataDir = filepath.Join(dir, "rules")
	backupDir = filepath.Join(dir, "backups")
	coreUploadDir = filepath.Join(dir, "uploads")
	gatewayPath = filepath.Join(dir, "gateway")
	gatewayStatePath = filepath.Join(dir, "gateway.state")
	setProxyPort(11080)
	restartProxyFn = func() error { return nil }
	proxyRunningFn = func() bool { return true }
	t.Cleanup(func() {
		dbPath, dataPath, configPath, macACLPath, naiveConfigDir, logDir, ruleDataDir = oldDB, oldData, oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldRuleDataDir
		restartProxyFn, fetchSubscriptionFn, reloadGatewayFn, proxyRunningFn, tproxyPort, tproxyEnabled = oldRestart, oldFetch, oldReload, oldProxyRunning, oldTProxyPort, oldTProxyEnabled
		setProxyPort(oldProxyPort)
		gatewayPath, gatewayStatePath = oldGatewayPath, oldGatewayStatePath
		backupDir, coreUploadDir, updateCorePath = oldBackupDir, oldCoreUploadDir, oldUpdateCorePath
	})
	if err := save(initial); err != nil {
		t.Fatal(err)
	}
}

func TestRuleBackupRestoreHandlesExistingAndNewFiles(t *testing.T) {
	dir := t.TempDir()
	oldRuleDataDir := ruleDataDir
	ruleDataDir = dir
	t.Cleanup(func() { ruleDataDir = oldRuleDataDir })

	oldPath := filepath.Join(dir, "existing.srs")
	if err := os.WriteFile(filepath.Join(dir, "existing.srs.bak"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(dir, "new.srs")
	if err := os.WriteFile(newPath, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath+".bak.absent", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreRuleBackups([]string{"existing", "new"}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(oldPath); err != nil || string(got) != "old" {
		t.Fatalf("existing file restore = %q, %v", got, err)
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatalf("new file remains after rollback, stat error=%v", err)
	}
}

func TestStoreRevisionIncrementsAndPersists(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080})
	initial := load()
	initialRev := initial.Revision
	initial.Mode = "bypass_cn"
	if err := save(initial); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	updated := load()
	if updated.Revision <= initialRev {
		t.Fatalf("expected revision to increment, got initial=%d, updated=%d", initialRev, updated.Revision)
	}
}

func TestConfigArchiveAndBackupLifecycle(t *testing.T) {
	dir := t.TempDir()
	oldBackupDir := backupDir
	backupDir = dir
	t.Cleanup(func() { backupDir = oldBackupDir })
	want := Store{Mode: "global", ProxyPort: 11080, LogLevel: "info", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}}
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

func TestCoreUpdateReceivesCurrentProxyPort(t *testing.T) {
	dir := t.TempDir()
	oldUpdateCorePath, oldProxyPort := updateCorePath, proxyPort
	updateCorePath = filepath.Join(dir, "fake-update")
	proxyPort = 12080
	t.Cleanup(func() { updateCorePath, proxyPort = oldUpdateCorePath, oldProxyPort })
	if err := os.WriteFile(updateCorePath, []byte("#!/bin/sh\nprintf '%s' \"$ARMWALL_PROXY_PORT\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runCoreUpdate(recorder, "sing-box", "latest")
	if recorder.Code != http.StatusOK || recorder.Body.String() != "12080" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
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

func TestClashDelayChecksHTTPStatusBeforeDecoding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not json", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	oldBase := clashAPIBase
	clashAPIBase = server.URL
	t.Cleanup(func() { clashAPIBase = oldBase })
	_, err := clashDelay("missing", "https://example.com/204")
	if err == nil || !strings.Contains(err.Error(), "urltest failed: 503") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIAuthAndServerHardening(t *testing.T) {
	if _, err := validateAuthToken(""); err == nil {
		t.Fatal("empty token should be rejected")
	}
	token, err := validateAuthToken("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	webConfig := webAccessConfig{
		Mode:            "local",
		ListenAddress:   "127.0.0.1:0",
		AllowedPrefixes: mustWebPrefixes(t, "127.0.0.0/8,::1/128"),
	}
	server, err := newHTTPServer(webConfig, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if server.ReadHeaderTimeout == 0 || server.ReadTimeout == 0 || server.WriteTimeout == 0 || server.IdleTimeout == 0 || server.MaxHeaderBytes == 0 {
		t.Fatalf("server is missing hardening timeouts: %+v", server)
	}
	handler := authHandler(token, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d", recorder.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	recorder = httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status=%d", recorder.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("valid token status=%d", recorder.Code)
	}
}

func mustWebPrefixes(t *testing.T, raw string) []netip.Prefix {
	t.Helper()
	prefixes, err := parseWebAllowedCIDRs(raw)
	if err != nil {
		t.Fatal(err)
	}
	return prefixes
}

func TestWebAccessConfigAndMiddleware(t *testing.T) {
	t.Setenv("ARMWALL_WEB_ACCESS", "lan")
	t.Setenv("ARMWALL_LISTEN", "0.0.0.0:8080")
	t.Setenv("ARMWALL_WEB_ALLOWED_CIDRS", "192.168.0.0/16,10.0.0.0/8")
	config, err := loadWebAccessConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != "lan" || config.ListenAddress != "0.0.0.0:8080" {
		t.Fatalf("unexpected web config: %+v", config)
	}

	handler := webAccessMiddleware(config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		name       string
		remoteAddr string
		wantStatus int
	}{
		{name: "private lan", remoteAddr: "192.168.50.12:1234", wantStatus: http.StatusNoContent},
		{name: "second private range", remoteAddr: "10.20.30.40:1234", wantStatus: http.StatusNoContent},
		{name: "public address", remoteAddr: "203.0.113.5:1234", wantStatus: http.StatusForbidden},
		{name: "invalid address", remoteAddr: "invalid", wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = test.remoteAddr
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", recorder.Code, test.wantStatus)
			}
		})
	}
}

func TestWebAccessConfigValidation(t *testing.T) {
	t.Setenv("ARMWALL_WEB_ACCESS", "local")
	t.Setenv("ARMWALL_LISTEN", "0.0.0.0:8080")
	if _, err := loadWebAccessConfig(); err == nil {
		t.Fatal("local mode should reject a non-loopback listener")
	}
	t.Setenv("ARMWALL_WEB_ACCESS", "custom")
	t.Setenv("ARMWALL_LISTEN", "0.0.0.0:8080")
	t.Setenv("ARMWALL_WEB_ALLOWED_CIDRS", "")
	if _, err := loadWebAccessConfig(); err == nil {
		t.Fatal("custom mode should require allowed CIDRs")
	}
}

func TestWebListenNetwork(t *testing.T) {
	for _, test := range []struct {
		address string
		want    string
	}{
		{address: "0.0.0.0:8080", want: "tcp4"},
		{address: "127.0.0.1:8080", want: "tcp4"},
		{address: "[::1]:8080", want: "tcp6"},
		{address: "localhost:8080", want: "tcp"},
	} {
		if got := webListenNetwork(test.address); got != test.want {
			t.Errorf("webListenNetwork(%q)=%q want=%q", test.address, got, test.want)
		}
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
		"hy2://pw@example.net:8443?sni=example.net&obfs=salamander&obfs-password=mask#B\n" +
		"trojan://pw@example.org:443#C\n" +
		"naive+https://alice:secret@naive.example:443#N"
	nodes := parseSubscription(raw)
	if len(nodes) != 4 {
		t.Fatalf("got %d nodes", len(nodes))
	}
	if nodes[0].Type != "anytls" || nodes[0].Password != "secret" || nodes[0].ServerName != "example.com" {
		t.Fatalf("unexpected anytls node: %+v", nodes[0])
	}
	if nodes[1].Type != "hysteria2" || nodes[1].Password != "pw" || nodes[1].Obfs != "salamander" || nodes[1].ObfsPassword != "mask" {
		t.Fatalf("unexpected hysteria2 node: %+v", nodes[1])
	}
	if nodes[2].Type != "trojan" || nodes[2].Password != "pw" {
		t.Fatalf("unexpected trojan node: %+v", nodes[2])
	}
	if nodes[3].Type != "naive" || nodes[3].Transport != "https" || nodes[3].Username != "alice" || nodes[3].Password != "secret" {
		t.Fatalf("unexpected NaiveProxy node: %+v", nodes[3])
	}
	generated := config(Store{Mode: "global", SelectedNode: nodes[1].ID, Nodes: nodes})
	hysteria := generated["outbounds"].([]any)[3].(map[string]any)
	obfs := hysteria["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "mask" {
		t.Fatalf("unexpected Hysteria2 outbound: %+v", hysteria)
	}
}

func TestParseShadowsocksAndVMessShareLinks(t *testing.T) {
	credentials := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:p@ss"))
	ssLink := "ss://" + credentials + "@ss.example:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket#SS"
	vmessJSON := `{"v":"2","ps":"VMess","add":"vm.example","port":443,"id":"11111111-1111-1111-1111-111111111111","aid":0,"scy":"auto","net":"ws","host":"cdn.example","path":"/ws","tls":"tls","sni":"vm.example","fp":"chrome"}`
	vmessLink := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	nodes := parseSubscription(ssLink + "\n" + vmessLink)
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes: %+v", len(nodes), nodes)
	}
	ss := nodes[0]
	if ss.Type != "shadowsocks" || ss.Method != "aes-128-gcm" || ss.Password != "p@ss" || ss.Plugin != "v2ray-plugin" || ss.PluginOpts != "mode=websocket" {
		t.Fatalf("unexpected Shadowsocks node: %+v", ss)
	}
	vmess := nodes[1]
	if vmess.Type != "vmess" || vmess.Security != "auto" || vmess.Transport != "ws" || vmess.Host != "cdn.example" || vmess.Path != "/ws" || !vmess.TLS || vmess.Fingerprint != "chrome" {
		t.Fatalf("unexpected VMess node: %+v", vmess)
	}
	generated := config(Store{Mode: "global", SelectedNode: vmess.ID, Nodes: nodes})
	outbounds := generated["outbounds"].([]any)
	if outbounds[2].(map[string]any)["plugin"] != "v2ray-plugin" || outbounds[3].(map[string]any)["security"] != "auto" {
		t.Fatalf("protocol fields were not mapped to sing-box: %+v", outbounds)
	}
}

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

func TestValidateNodeRequiresProtocolCredentials(t *testing.T) {
	validUUID := "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name    string
		node    Node
		wantErr bool
	}{
		{"anytls missing tls", Node{Name: "n", Type: "anytls", Server: "example.com", Port: 443, Password: "pw"}, true},
		{"anytls valid", Node{Name: "n", Type: "anytls", Server: "example.com", Port: 443, Password: "pw", TLS: true}, false},
		{"hysteria2 missing password", Node{Name: "n", Type: "hysteria2", Server: "example.com", Port: 443, TLS: true}, true},
		{"trojan missing tls", Node{Name: "n", Type: "trojan", Server: "example.com", Port: 443, Password: "pw"}, true},
		{"vless missing uuid", Node{Name: "n", Type: "vless", Server: "example.com", Port: 443, TLS: true}, true},
		{"vless valid", Node{Name: "n", Type: "vless", Server: "example.com", Port: 443, UUID: validUUID, TLS: true}, false},
		{"shadowsocks missing method", Node{Name: "n", Type: "shadowsocks", Server: "example.com", Port: 8388, Password: "pw"}, true},
		{"naive valid", Node{Name: "n", Type: "naive", Server: "example.com", Port: 443, Username: "user", Password: "pw"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNode(&tc.node)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
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
	want := Store{Mode: "gfw", ProxyPort: 11080, SelectedNode: "n1", TCPOutbound: "g1", UDPOutbound: "same", DNS: DNSSettings{Enabled: true, RemoteServer: "https://1.1.1.1/dns-query", RemoteSNI: "cloudflare-dns.com", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true}, RuleSettings: map[string]RuleUpdateSetting{"geosite-ads": {BackupURL: "https://example.com/ads.srs", AutoUpdate: true, UpdateHours: 12, LastUpdated: time.Now().UTC().Truncate(time.Second)}}, ACLRules: []ACLRule{{ID: "a1", Name: "客户端", Enabled: true, SourceCIDRs: []string{"192.168.10.20/32"}, Network: "tcp", PortRanges: []string{"443"}, Outbound: "direct"}}, StrategyGroups: []StrategyGroup{{ID: "g1", Name: "自动选择", Type: "urltest", NodeIDs: []string{"n1"}, Selected: "n1", TestURL: "https://example.com/204", IntervalSec: 180, ToleranceMS: 50}}, Subscriptions: []Subscription{{ID: "s1", Name: "测试订阅", URL: "https://example.com/sub", UpdateHours: 6, Enabled: true}}, Nodes: []Node{{ID: "n1", Name: "节点", NameOverride: "自定义", GroupOverride: "我的分组", NaivePort: 12009, Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true, Group: "测试订阅", SubscriptionID: "s1"}}}
	if err := save(want); err != nil {
		t.Fatal(err)
	}
	got := load()
	if len(got.Nodes) != 1 || len(got.Subscriptions) != 1 || len(got.StrategyGroups) != 1 || len(got.ACLRules) != 1 || !got.DNS.Enabled || got.Nodes[0].SubscriptionID != "s1" || got.Nodes[0].NameOverride != "自定义" || got.Nodes[0].GroupOverride != "我的分组" || got.Nodes[0].NaivePort != 12009 || got.ProxyPort != 11080 || got.TCPOutbound != "g1" || !got.RuleSettings["geosite-ads"].AutoUpdate || got.RuleSettings["geosite-ads"].UpdateHours != 12 {
		t.Fatalf("unexpected round trip: %+v", got)
	}
}

func TestSQLiteSettingsWithoutNodesDoNotFallBackToJSON(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath = oldDB; dataPath = oldData })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := saveDB(Store{Mode: "global", ProxyPort: 12080, LogLevel: "debug", DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.1", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", DirectServer: "udp://223.5.5.5"}}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(Store{Mode: "bypass_cn", ProxyPort: 11080}); err != nil {
		t.Fatal(err)
	}
	got := load()
	if got.Mode != "global" || got.ProxyPort != 12080 || got.LogLevel != "debug" || !got.DNS.Enabled {
		t.Fatalf("settings-only database was not used: %+v", got)
	}
}

func TestCorruptSQLiteDoesNotFallBackToJSON(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := os.WriteFile(dbPath, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(Store{Mode: "global", ProxyPort: 12080}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("corrupt SQLite database unexpectedly fell back to JSON")
	}
}

func TestCorruptNodePayloadRefusesLoad(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData; closeDB() })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := save(Store{Mode: "global", Nodes: []Node{{ID: "n1", Type: "anytls", Server: "example.com", Port: 443, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE nodes SET payload = ? WHERE id = ?", "{broken", "n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil || !strings.Contains(err.Error(), "corrupted node payload") {
		t.Fatalf("corrupted node payload was not refused: %v", err)
	}
}

func TestLegacyMigration(t *testing.T) {
	s := migrateLegacy(Store{SubscriptionURLs: []string{"https://example.com/sub"}, Nodes: []Node{{ID: "sub-1", Name: "legacy"}}})
	if len(s.Subscriptions) != 1 || s.Nodes[0].SubscriptionID == "" || !s.Nodes[0].Enabled {
		t.Fatalf("migration failed: %+v", s)
	}
}

func TestLegacyJSONMigrationArchivesSourceAndPersistsSchemaVersion(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData; closeDB() })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	legacy := Store{Mode: "global", ProxyPort: 11080, StrategyGroups: []StrategyGroup{{ID: "g1", Name: "old fallback", Type: "fallback"}}}
	if err := saveJSON(legacy); err != nil {
		t.Fatal(err)
	}
	got, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.StrategyGroups[0].Type != "urltest" {
		t.Fatalf("legacy strategy migration = version %d type %q", got.SchemaVersion, got.StrategyGroups[0].Type)
	}
	if _, err := os.Stat(dataPath); !os.IsNotExist(err) {
		t.Fatalf("legacy credential file was not archived, stat error=%v", err)
	}
	if _, err := os.Stat(dataPath + ".migrated"); err != nil {
		t.Fatalf("legacy archive missing: %v", err)
	}
	got, err = loadStore()
	if err != nil || got.SchemaVersion != 1 || got.StrategyGroups[0].Type != "urltest" {
		t.Fatalf("migrated store did not round trip: %+v err=%v", got, err)
	}
}

func TestLegacyJSONMigrationRefusesCorruptSourceAndArchiveCollision(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData; closeDB() })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := os.WriteFile(dataPath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("expected corrupt legacy JSON to be rejected")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("corrupt migration created a database: %v", err)
	}
	if err := os.WriteFile(dataPath, []byte(`{"mode":"global"}`), 0600); err != nil {
		t.Fatal(err)
	}
	archivePath := dataPath + ".migrated"
	if err := os.WriteFile(archivePath, []byte("previous archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("expected existing migration archive to block overwrite")
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil || string(archive) != "previous archive" {
		t.Fatalf("existing migration archive changed: %q, %v", archive, err)
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

func TestParseSubscriptionIgnoresUnsupported(t *testing.T) {
	nodes := parseSubscription(strings.Join([]string{"not-a-node", "https://example.com/no-protocol"}, "\n"))
	if len(nodes) != 0 {
		t.Fatalf("got unsupported nodes: %+v", nodes)
	}
}

func TestToggleSelectedNodeChoosesEnabledFallback(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
		{ID: "n2", Name: "two", Type: "anytls", Server: "two.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
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
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true, SubscriptionID: "s1", Group: "source"},
		{ID: "n2", Name: "two", Type: "hysteria2", Server: "two.example", Port: 8443, Password: "secret", TLS: true, Enabled: true},
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

func TestAPIRejectsMalformedJSON(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	for _, path := range []string{"/api/node/delete", "/api/node/copy", "/api/node/toggle", "/api/rules/settings"} {
		recorder := callAPI(t, path, `{"id":`)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
	recorder := callAPI(t, "/api/node", strings.Repeat(" ", maxAPIJSONBodySize+1))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAddSubscriptionAcceptsFrontendPayload(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	fetchSubscriptionFn = func(_ context.Context, rawURL string) ([]Node, error) {
		return []Node{{ID: "n1", Name: "subnode", Type: "anytls", Server: "node.example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}, nil
	}
	// Exact payload shape produced by web/app.js saveSubscription
	payload := `{"id":"","name":"我的订阅","url":"https://airport.example/sub","update_hours":8,"enabled":true,"last_updated":""}`
	recorder := callAPI(t, "/api/subscription", payload)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /api/subscription status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if len(got.Subscriptions) != 1 {
		t.Fatalf("expected 1 subscription, got: %+v", got.Subscriptions)
	}
	sub := got.Subscriptions[0]
	if sub.Name != "我的订阅" || sub.URL != "https://airport.example/sub" || sub.UpdateHours != 8 || !sub.Enabled {
		t.Fatalf("unexpected subscription: %+v", sub)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].SubscriptionID != sub.ID {
		t.Fatalf("unexpected nodes: %+v", got.Nodes)
	}
}

func TestSubscriptionEditUpdatesOwnedNodeGroup(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, Subscriptions: []Subscription{{ID: "s1", Name: "old", URL: "https://example.com/old", UpdateHours: 6, Enabled: true}}, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true, SubscriptionID: "s1", Group: "old"}}})
	recorder := callAPI(t, "/api/subscription/edit", `{"id":"s1","name":"new","url":"https://example.com/new","update_hours":12,"enabled":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if got.Subscriptions[0].Name != "new" || got.Subscriptions[0].Enabled || got.Nodes[0].Group != "new" {
		t.Fatalf("unexpected edit: %+v", got)
	}
}

func TestSubscriptionClearPreservesManualSubPrefixedNode(t *testing.T) {
	setupAPITest(t, Store{
		Mode:      "global",
		ProxyPort: 11080,
		Subscriptions: []Subscription{
			{ID: "s1", Name: "sub", URL: "https://example.com/sub", UpdateHours: 6, Enabled: true},
		},
		Nodes: []Node{
			{ID: "sub-manual", Name: "manual", Type: "anytls", Server: "manual.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
			{ID: "owned", Name: "owned", Type: "anytls", Server: "owned.example", Port: 443, Password: "secret", TLS: true, SubscriptionID: "s1", Group: "sub", Enabled: true},
		},
	})
	recorder := callAPI(t, "/api/subscription/clear", `{}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if len(got.Nodes) != 1 || got.Nodes[0].ID != "sub-manual" || len(got.Subscriptions) != 0 {
		t.Fatalf("unexpected cleared state: %+v", got)
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

func TestStrategyAPIAndRoutingSelection(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
		{ID: "n2", Name: "two", Type: "hysteria2", Server: "two.example", Port: 8443, Password: "secret", TLS: true, Enabled: true},
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

func TestReconcileSubscriptionNodesPreservesIdentityAndEnabledState(t *testing.T) {
	sub := Subscription{ID: "subscription-1", Name: "测试订阅"}
	existing := []Node{
		{ID: "existing-node-id", Name: "旧名称", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, SubscriptionID: sub.ID, Group: sub.Name, Enabled: false},
		{ID: "manual-node", Name: "手动", Type: "trojan", Server: "manual.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
	}
	fetched := []Node{
		{ID: "temporary-1", Name: "新名称", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
		{ID: "temporary-2", Name: "新增节点", Type: "hysteria2", Server: "two.example", Port: 8443, Password: "new", TLS: true, Enabled: true},
	}
	first := reconcileSubscriptionNodes(existing, fetched, sub)
	if first[0].ID != "existing-node-id" || first[0].Enabled || first[0].Name != "新名称" || first[0].SubscriptionID != sub.ID || first[0].Group != sub.Name {
		t.Fatalf("existing subscription node was not preserved: %+v", first[0])
	}
	if first[1].ID == "" || first[1].ID == "temporary-2" || !first[1].Enabled {
		t.Fatalf("new subscription node did not receive a stable identity: %+v", first[1])
	}
	second := reconcileSubscriptionNodes(append(existing[:1], first[1]), fetched, sub)
	if second[1].ID != first[1].ID {
		t.Fatalf("stable id changed across refreshes: first=%s second=%s", first[1].ID, second[1].ID)
	}
}

func TestReconcileSubscriptionPreservesUserNameAndGroupOverrides(t *testing.T) {
	sub := Subscription{ID: "subscription-1", Name: "Feed Name"}
	existing := []Node{{ID: "node-1", Name: "My Name", NameOverride: "My Name", Type: "anytls", Server: "node.example", Port: 443, SubscriptionID: sub.ID, Group: "My Group", GroupOverride: "My Group", Enabled: true, NaivePort: 12005}}
	fetched := []Node{{Name: "Feed Node", Type: "anytls", Server: "node.example", Port: 443, Enabled: true}}
	got := reconcileSubscriptionNodes(existing, fetched, sub)[0]
	if got.ID != "node-1" || got.Name != "My Name" || got.Group != "My Group" || got.NaivePort != 12005 {
		t.Fatalf("user overrides or runtime port were lost: %+v", got)
	}
}

func TestSubscriptionNodeEditRecordsUserOverrides(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Subscriptions: []Subscription{{ID: "sub-1", Name: "Feed"}}, Nodes: []Node{{ID: "node-1", Name: "Feed Node", Type: "anytls", Server: "node.example", Port: 443, Password: "secret", SubscriptionID: "sub-1", Group: "Feed", Enabled: true}}})
	recorder := callAPI(t, "/api/node/update", `{"id":"node-1","name":"Custom Node","type":"anytls","server":"node.example","port":443,"password":"******","tls":true,"group":"Custom Group"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load().Nodes[0]
	if got.NameOverride != "Custom Node" || got.GroupOverride != "Custom Group" {
		t.Fatalf("node edit did not record overrides: %+v", got)
	}
}

func TestNaivePortsRemainStableAcrossReorderAndAddition(t *testing.T) {
	s := Store{Nodes: []Node{
		{ID: "naive-a", Type: "naive", Server: "a.example", Port: 443, Enabled: true, NaivePort: 12000},
		{ID: "naive-b", Type: "naive", Server: "b.example", Port: 443, Enabled: true, NaivePort: 12001},
	}}
	first := naiveBindings(s)
	reordered := Store{Nodes: []Node{s.Nodes[1], s.Nodes[0], {ID: "naive-c", Type: "naive", Server: "c.example", Port: 443, Enabled: true}}}
	second := naiveBindings(reordered)
	ports := make(map[string]int)
	for _, binding := range second {
		ports[binding.Node.ID] = binding.Port
	}
	if ports["naive-a"] != first[0].Port || ports["naive-b"] != first[1].Port || ports["naive-c"] != 12002 {
		t.Fatalf("ports changed or new port collided: first=%+v second=%+v", first, second)
	}
}

func TestNaivePortAllocationSkipsExistingRuntimeListeners(t *testing.T) {
	oldNaiveProxyPort := naiveProxyPort
	naiveProxyPort = 12000
	t.Cleanup(func() { naiveProxyPort = oldNaiveProxyPort })
	s := Store{ProxyPort: 12000, Nodes: []Node{{ID: "naive-a", Type: "naive", Server: "a.example", Port: 443, Enabled: true}}}
	if err := assignNaivePorts(&s); err != nil {
		t.Fatal(err)
	}
	if s.Nodes[0].NaivePort != 12001 {
		t.Fatalf("allocated port=%d, want next free port 12001", s.Nodes[0].NaivePort)
	}
}

func TestValidateRuntimePortsDoesNotSilentlyRemapPersistedConflict(t *testing.T) {
	oldTProxyPort, oldNaiveProxyPort := tproxyPort, naiveProxyPort
	t.Cleanup(func() { tproxyPort, naiveProxyPort = oldTProxyPort, oldNaiveProxyPort })
	tproxyPort = 11081
	naiveProxyPort = 12000
	s := Store{ProxyPort: 12000, Nodes: []Node{{ID: "naive-a", Type: "naive", Server: "a.example", Port: 443, Enabled: true, NaivePort: 12000}}}
	if err := validateRuntimePorts(s); err == nil {
		t.Fatal("expected persisted Naive/Proxy collision to be rejected")
	}
	if s.Nodes[0].NaivePort != 12000 {
		t.Fatalf("persisted port was silently remapped: %d", s.Nodes[0].NaivePort)
	}
}

func TestServeUntilShutdownClosesListenerGracefully(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveUntilShutdown(ctx, server, listener) }()
	response, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down after context cancellation")
	}
}

func TestSubscriptionRefreshContinuesAfterOneSourceFails(t *testing.T) {
	initial := Store{
		Mode:      "bypass_cn",
		ProxyPort: 11080,
		Subscriptions: []Subscription{
			{ID: "good", Name: "可用订阅", URL: "https://good.example/sub", UpdateHours: 6, Enabled: true},
			{ID: "bad", Name: "故障订阅", URL: "https://bad.example/sub", UpdateHours: 6, Enabled: true},
		},
		Nodes: []Node{
			{ID: "good-node", Name: "旧名称", Type: "anytls", Server: "good.example", Port: 443, Password: "secret", TLS: true, SubscriptionID: "good", Group: "可用订阅", Enabled: false},
			{ID: "bad-node", Name: "保留节点", Type: "trojan", Server: "bad.example", Port: 443, Password: "secret", SubscriptionID: "bad", Group: "故障订阅", Enabled: true},
		},
	}
	setupAPITest(t, initial)
	fetchSubscriptionFn = func(_ context.Context, rawURL string) ([]Node, error) {
		if strings.Contains(rawURL, "bad.example") {
			return nil, fmt.Errorf("temporary failure")
		}
		return []Node{{Name: "新名称", Type: "anytls", Server: "good.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}, nil
	}
	err := updateSubscriptionsWithForce(true)
	if err == nil || !strings.Contains(err.Error(), "故障订阅") {
		t.Fatalf("expected partial failure, got %v", err)
	}
	got := load()
	nodes := map[string]Node{}
	for _, node := range got.Nodes {
		nodes[node.ID] = node
	}
	if len(nodes) != 2 || nodes["good-node"].Enabled || nodes["good-node"].Name != "新名称" || nodes["bad-node"].Name != "保留节点" {
		t.Fatalf("partial refresh did not preserve node state: %+v", got.Nodes)
	}
	subscriptions := map[string]Subscription{}
	for _, sub := range got.Subscriptions {
		subscriptions[sub.ID] = sub
	}
	if subscriptions["good"].LastUpdated.IsZero() || !subscriptions["bad"].LastUpdated.IsZero() {
		t.Fatalf("unexpected subscription timestamps: %+v", got.Subscriptions)
	}
}

func TestCanceledSingleSubscriptionFetchDoesNotCommit(t *testing.T) {
	initial := Store{Mode: "global", ProxyPort: 11080, Subscriptions: []Subscription{{ID: "s1", Name: "source", URL: "https://source.example/sub", UpdateHours: 6, Enabled: true}}}
	setupAPITest(t, initial)
	fetchSubscriptionFn = func(ctx context.Context, _ string) ([]Node, error) {
		return []Node{{Name: "new", Type: "anytls", Server: "new.example", Port: 443, Password: "secret", Enabled: true}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/subscription/update-one", strings.NewReader(`{"id":"s1"}`)).WithContext(ctx)
	recorder := httptest.NewRecorder()
	api(recorder, req)
	if recorder.Code != 499 || len(load().Nodes) != 0 {
		t.Fatalf("canceled fetch committed: status=%d nodes=%+v", recorder.Code, load().Nodes)
	}
}

func TestRuleSettingsMigrationAndDue(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	s := Store{RuleUpdateHours: 12, RuleBackups: map[string]string{"geosite-ads": "https://backup.example/ads.srs"}}
	normalizeRuleSettings(&s)
	setting := s.RuleSettings["geosite-ads"]
	if setting.BackupURL != "https://backup.example/ads.srs" || setting.UpdateHours != 12 || setting.AutoUpdate {
		t.Fatalf("legacy rule settings were not migrated: %+v", setting)
	}
	setting.AutoUpdate = true
	setting.LastUpdated = now.Add(-11 * time.Hour)
	if ruleUpdateDue(setting, now) {
		t.Fatal("rule should not be due before its interval")
	}
	setting.LastUpdated = now.Add(-12 * time.Hour)
	if !ruleUpdateDue(setting, now) {
		t.Fatal("rule should be due at its interval")
	}
}

func TestUpdateConfiguredRulesHonorsPerRuleSchedule(t *testing.T) {
	oldUpdateRule := updateRuleFn
	t.Cleanup(func() { updateRuleFn = oldUpdateRule })
	calls := map[string]string{}
	updateRuleFn = func(tag, backup string) error {
		calls[tag] = backup
		return nil
	}
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	s := Store{RuleSettings: map[string]RuleUpdateSetting{
		"geosite-ads": {BackupURL: "https://backup.example/ads.srs", AutoUpdate: true, UpdateHours: 6, LastUpdated: now.Add(-6 * time.Hour)},
		"geosite-cn":  {AutoUpdate: false, UpdateHours: 1},
	}}
	updated, err := updateConfiguredRules(&s, false, "", now)
	if err != nil || len(updated) != 1 || updated[0] != "geosite-ads" || calls["geosite-ads"] != "https://backup.example/ads.srs" {
		t.Fatalf("unexpected scheduled update: updated=%v calls=%v err=%v", updated, calls, err)
	}
	if !s.RuleSettings["geosite-ads"].LastUpdated.Equal(now) {
		t.Fatalf("last update was not recorded: %+v", s.RuleSettings["geosite-ads"])
	}
	updated, err = updateConfiguredRules(&s, true, "geosite-cn", now.Add(time.Minute))
	if err != nil || len(updated) != 1 || updated[0] != "geosite-cn" || calls["geosite-cn"] != "" {
		t.Fatalf("unexpected manual update: updated=%v calls=%v err=%v", updated, calls, err)
	}
}

func TestRuleSettingsAPIStoresAutoUpdate(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	recorder := callAPI(t, "/api/rules/settings", `{"tag":"geosite-proxy","backup":"https://backup.example/proxy.srs","hours":24,"autoUpdate":true}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	setting := load().RuleSettings["geosite-proxy"]
	if setting.BackupURL != "https://backup.example/proxy.srs" || setting.UpdateHours != 24 || !setting.AutoUpdate {
		t.Fatalf("unexpected stored rule setting: %+v", setting)
	}
}

func TestRuleSettingsAPITogglesAdBlocking(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	recorder := callAPI(t, "/api/rules/settings", `{"tag":"geosite-ads","hours":6,"autoUpdate":false,"adBlockEnabled":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if got.AdBlockEnabled == nil || *got.AdBlockEnabled {
		t.Fatalf("ad blocking was not disabled: %+v", got.AdBlockEnabled)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configBytes), "geosite-ads") {
		t.Fatalf("generated config still includes ads rule: %s", configBytes)
	}
}

func TestShareLinkImportPreservesRuntimeConfiguration(t *testing.T) {
	initial := Store{
		Mode:         "global",
		ProxyPort:    11080,
		SelectedNode: "n1",
		LogLevel:     "debug",
		DNS:          DNSSettings{Enabled: true, ListenAddress: "192.168.10.217", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true},
		Nodes:        []Node{{ID: "n1", Name: "existing", Type: "anytls", Server: "existing.example", Port: 443, Password: "secret", TLS: true, Enabled: true}},
		ACLRules:     []ACLRule{{ID: "a1", Name: "client", Enabled: true, SourceCIDRs: []string{"192.168.10.20/32"}, Network: "tcp", Outbound: "direct"}},
	}
	setupAPITest(t, initial)
	recorder := callAPI(t, "/api/node/import", `{"links":"anytls://new-secret@new.example:443#Imported"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if len(got.Nodes) != 2 || got.Nodes[1].Group != "手动节点" || !got.DNS.Enabled || len(got.ACLRules) != 1 || got.LogLevel != "debug" || got.SelectedNode != "n1" {
		t.Fatalf("import discarded stored configuration: %+v", got)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var generated map[string]any
	if json.Unmarshal(configBytes, &generated) != nil || generated["dns"] == nil || generated["log"].(map[string]any)["level"] != "debug" {
		t.Fatalf("import discarded runtime configuration: %s", configBytes)
	}
}

func TestProxyPortAPIUsesTransactionalReload(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	recorder := callAPI(t, "/api/settings", `{"proxyPort":12080}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := load().ProxyPort; got != 12080 {
		t.Fatalf("stored proxy port=%d, want 12080", got)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var generated map[string]any
	if json.Unmarshal(configBytes, &generated) != nil {
		t.Fatalf("invalid generated config: %s", configBytes)
	}
	inbounds := generated["inbounds"].([]any)
	if inbounds[0].(map[string]any)["listen_port"] != float64(12080) {
		t.Fatalf("runtime config did not use new port: %+v", inbounds[0])
	}
}

func TestLogPreviewIsBoundedAndExportIsComplete(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	if err := os.MkdirAll(logDir, 0750); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("0123456789abcdef"), 20000)
	if err := os.WriteFile(filepath.Join(logDir, "sing-box.log"), content, 0640); err != nil {
		t.Fatal(err)
	}
	previewRequest := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	preview := httptest.NewRecorder()
	api(preview, previewRequest)
	if preview.Code != http.StatusOK || preview.Body.Len() != 256<<10 {
		t.Fatalf("preview status=%d size=%d", preview.Code, preview.Body.Len())
	}
	exportRequest := httptest.NewRequest(http.MethodGet, "/api/logs?download=1", nil)
	export := httptest.NewRecorder()
	api(export, exportRequest)
	if export.Code != http.StatusOK || !bytes.Equal(export.Body.Bytes(), content) || !strings.Contains(export.Header().Get("Content-Disposition"), "armwall.log") {
		t.Fatalf("export status=%d size=%d disposition=%q", export.Code, export.Body.Len(), export.Header().Get("Content-Disposition"))
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

func TestACLAndDNSAPI(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
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

func TestNodeAPIValidatesReservedAndDuplicateIDs(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "existing-id", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	recorder := callAPI(t, "/api/node", `{"id":"direct","name":"fake-direct","type":"anytls","server":"example.com","port":443,"password":"pass","tls":true}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reserved id, got %d", recorder.Code)
	}
	recorder = callAPI(t, "/api/node", `{"id":"existing-id","name":"duplicate","type":"anytls","server":"example.com","port":443,"password":"pass","tls":true}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate id, got %d", recorder.Code)
	}
}

func TestSettingsAPIRejectsConflictingPorts(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080})
	for _, port := range []int{8080, 9090, 11081, 53, 22} {
		recorder := callAPI(t, "/api/settings", fmt.Sprintf(`{"proxyPort":%d}`, port))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for conflicting port %d, got %d", port, recorder.Code)
		}
	}
}

func TestSubscriptionScheduleDoesNotRewriteSystemdTimer(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, UpdateHours: 6})
	recorder := callAPI(t, "/api/subscription/schedule", `{"hours":12}`)
	if recorder.Code != http.StatusOK || load().UpdateHours != 6 || !strings.Contains(recorder.Body.String(), `"schedule":"per-subscription"`) {
		t.Fatalf("schedule update status=%d store=%+v body=%s", recorder.Code, load(), recorder.Body.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dataPath), "armwall-subscription-update.timer.d")); !os.IsNotExist(err) {
		t.Fatalf("schedule API created a timer override, stat error=%v", err)
	}
}

func TestBootstrapRuleUpdatesIgnoreAutoUpdateOptOut(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, RuleSettings: map[string]RuleUpdateSetting{}})
	oldUpdateRule := updateRuleFn
	t.Cleanup(func() { updateRuleFn = oldUpdateRule })
	calls := 0
	updateRuleFn = func(_, _ string) error { calls++; return nil }
	if count, err := applyScheduledRuleUpdates(); err != nil || count != 0 || calls != 0 {
		t.Fatalf("scheduled updates should respect opt-out: count=%d calls=%d err=%v", count, calls, err)
	}
	count, err := applyRuleUpdates(true)
	if err != nil || count != len(ruleURLs) || calls != len(ruleURLs) {
		t.Fatalf("bootstrap should force all rules: count=%d calls=%d err=%v", count, calls, err)
	}
}

func TestValidateRuntimePortsRejectsGeneratedListenerConflicts(t *testing.T) {
	oldTProxyPort, oldNaiveProxyPort := tproxyPort, naiveProxyPort
	t.Cleanup(func() { tproxyPort, naiveProxyPort = oldTProxyPort, oldNaiveProxyPort })

	tproxyPort = 12000
	naiveProxyPort = 13000
	if err := validateRuntimePorts(Store{ProxyPort: 12000}); err == nil {
		t.Fatal("expected proxy/TProxy conflict")
	}

	tproxyPort = 12000
	naiveProxyPort = 12001
	s := Store{
		ProxyPort: 11080,
		ACLRules:  []ACLRule{{Enabled: true, SourceMACs: []string{"00:11:22:33:44:55"}}},
		Nodes:     []Node{{Type: "naive", Enabled: true, Server: "example.com", Port: 443, NaivePort: 12001}},
	}
	if err := validateRuntimePorts(s); err == nil {
		t.Fatal("expected NaiveProxy/MAC ACL derived port conflict")
	}
}

func TestValidateRuntimePortsCoversWebDNSAndClash(t *testing.T) {
	oldAccess, oldListen := os.Getenv("ARMWALL_WEB_ACCESS"), os.Getenv("ARMWALL_LISTEN")
	t.Cleanup(func() {
		os.Setenv("ARMWALL_WEB_ACCESS", oldAccess)
		os.Setenv("ARMWALL_LISTEN", oldListen)
	})
	os.Setenv("ARMWALL_WEB_ACCESS", "custom")
	os.Setenv("ARMWALL_LISTEN", "127.0.0.1:9090")
	if err := validateRuntimePorts(Store{ProxyPort: 11080}); err == nil {
		t.Fatal("expected Web/Clash conflict")
	}
	os.Setenv("ARMWALL_LISTEN", "127.0.0.1:18080")
	if err := validateRuntimePorts(Store{ProxyPort: 11080, DNS: DNSSettings{Enabled: true, ListenAddress: "127.0.0.1", ListenPort: 11080}}); err == nil {
		t.Fatal("expected DNS/Mixed conflict")
	}
}

func TestValidateSRSRejectsInvalidMagic(t *testing.T) {
	if err := validateSRS([]byte("not-a-valid-rule-set")); err == nil {
		t.Fatal("expected invalid SRS magic to be rejected")
	}
}

func TestNodeTestRejectsFlagInjection(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "bad", Type: "anytls", Server: "-c 2", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	recorder := callAPI(t, "/api/node/test?id=n1&method=ping", "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for flag-injected host, got %d", recorder.Code)
	}
}

func TestBatchNodeTestAndCredentialMasking(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	setupAPITest(t, Store{
		Mode:      "global",
		ProxyPort: 11080,
		Nodes: []Node{
			{ID: "node-1", Name: "Local Test", Type: "shadowsocks", Server: "127.0.0.1", Port: port, Password: "supersecretpassword", Method: "aes-128-gcm", Enabled: true},
			{ID: "node-2", Name: "Bad Node", Type: "shadowsocks", Server: "127.0.0.1", Port: 1, Password: "anotherpassword", Method: "aes-128-gcm", Enabled: true},
		},
	})

	recorder := callAPI(t, "/api/state", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("state status=%d", recorder.Code)
	}
	var state Store
	if err := json.Unmarshal(recorder.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Nodes) != 2 || state.Nodes[0].Password != "******" || state.Nodes[1].Password != "******" {
		t.Fatalf("expected masked password '******', got: %+v", state.Nodes)
	}

	recorder = callAPI(t, "/api/node/get?id=node-1", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("node/get status=%d", recorder.Code)
	}
	var node1 Node
	if err := json.Unmarshal(recorder.Body.Bytes(), &node1); err != nil {
		t.Fatal(err)
	}
	if node1.Password != "supersecretpassword" {
		t.Fatalf("expected unmasked password, got %s", node1.Password)
	}

	recorder = callAPI(t, "/api/node/batch-test", `{"ids":["node-1","node-2"],"method":"tcp"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("batch-test status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var batchResp struct {
		Method  string `json:"method"`
		Results map[string]struct {
			MS    int64  `json:"ms"`
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &batchResp); err != nil {
		t.Fatal(err)
	}
	if batchResp.Method != "tcp" {
		t.Fatalf("unexpected method: %s", batchResp.Method)
	}
	res1, ok1 := batchResp.Results["node-1"]
	if !ok1 || res1.MS < 0 || res1.Error != "" {
		t.Fatalf("expected node-1 to succeed: %+v", res1)
	}
	res2, ok2 := batchResp.Results["node-2"]
	if !ok2 || res2.MS != -1 || res2.Error == "" {
		t.Fatalf("expected node-2 to fail: %+v", res2)
	}

	recorder = callAPI(t, "/api/node/update", fmt.Sprintf(`{"id":"node-1","name":"Renamed Node","type":"shadowsocks","server":"127.0.0.1","port":%d,"password":"******","method":"aes-128-gcm"}`, port))
	if recorder.Code != http.StatusOK {
		t.Fatalf("node/update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	saved := load()
	if saved.Nodes[0].Password != "supersecretpassword" || saved.Nodes[0].Name != "Renamed Node" {
		t.Fatalf("expected preserved password, got: %+v", saved.Nodes[0])
	}
}

func TestUpdateSubscriptionsCLIEntrypointDoesNotDeadlock(t *testing.T) {
	initial := Store{
		Mode: "whitelist",
		Subscriptions: []Subscription{
			{
				ID:          "sub-1",
				Name:        "Sub 1",
				URL:         "https://example.com/sub.txt",
				UpdateHours: 1,
				Enabled:     true,
				LastUpdated: time.Now().Add(-2 * time.Hour), // Due for update
			},
		},
	}
	setupAPITest(t, initial)

	fetchSubscriptionFn = func(_ context.Context, rawURL string) ([]Node, error) {
		return []Node{{
			ID:       "fetched-node-1",
			Name:     "Fetched Node 1",
			Type:     "shadowsocks",
			Server:   "1.2.3.4",
			Port:     8388,
			Password: "pass",
			Method:   "aes-128-gcm",
			Enabled:  true,
		}}, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- updateSubscriptions()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("updateSubscriptions returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("updateSubscriptions deadlocked on store file lock!")
	}

	updated := load()
	if len(updated.Nodes) != 1 || updated.Nodes[0].Name != "Fetched Node 1" {
		t.Fatalf("expected updated nodes, got: %+v", updated.Nodes)
	}
}

func TestProxyPortConcurrentAccess(t *testing.T) {
	oldPort := getProxyPort()
	defer setProxyPort(oldPort)

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					p := getProxyPort()
					if p <= 0 {
						t.Errorf("invalid port read: %d", p)
					}
					_ = config(Store{Mode: "global", ProxyPort: p})
				}
			}
		}()
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					setProxyPort(1080 + (id % 100))
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
}
