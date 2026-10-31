package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func TestParseSubscriptionIgnoresUnsupported(t *testing.T) {
	nodes := parseSubscription(strings.Join([]string{"not-a-node", "https://example.com/no-protocol"}, "\n"))
	if len(nodes) != 0 {
		t.Fatalf("got unsupported nodes: %+v", nodes)
	}
}

func TestAddSubscriptionAcceptsFrontendPayload(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	fetchSubscriptionFn = func(_ context.Context, rawURL string) ([]Node, error) {
		return []Node{{ID: "n1", Name: "subnode", Type: "anytls", Server: "node.example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}, nil
	}
	// Exact payload shape produced by web/js/editors.js saveSubscription
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

func TestReplaceSubscriptionNodesKeepsPosition(t *testing.T) {
	nodes := []Node{{ID: "m1"}, {ID: "a1", SubscriptionID: "a"}, {ID: "a2", SubscriptionID: "a"}, {ID: "m2"}}
	got := replaceSubscriptionNodes(nodes, "a", []Node{{ID: "a3", SubscriptionID: "a"}})
	ids := []string{}
	for _, n := range got {
		ids = append(ids, n.ID)
	}
	if strings.Join(ids, ",") != "m1,a3,m2" {
		t.Fatalf("replace in place = %v", ids)
	}
	got = replaceSubscriptionNodes(nodes, "b", []Node{{ID: "b1", SubscriptionID: "b"}})
	if len(got) != 5 || got[4].ID != "b1" {
		t.Fatalf("new subscription should append: %+v", got)
	}
}
