package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func boolPtr(v bool) *bool { return &v }

func makeTestFailoverStore(autoFailback bool) Store {
	return Store{
		Mode:         "global",
		ProxyPort:    11080,
		SelectedNode: "primary",
		Nodes: []Node{
			{ID: "primary", Name: "Primary", Type: "naive", Server: "p.example.com", Port: 443, Username: "u", Password: "p", Enabled: true},
			{ID: "backup1", Name: "Backup 1", Type: "naive", Server: "b1.example.com", Port: 443, Username: "u", Password: "p", Enabled: true},
			{ID: "backup2", Name: "Backup 2", Type: "hysteria2", Server: "b2.example.com", Port: 8443, Password: "p", TLS: true, Enabled: true},
		},
		Failover: FailoverSettings{
			Enabled:           true,
			BackupNodeIDs:     []string{"backup1", "backup2"},
			CheckIntervalSec:  30,
			FailureThreshold:  3,
			RecoveryThreshold: 2,
			AutoFailback:      boolPtr(autoFailback),
			TestURL:           "https://www.gstatic.com/generate_204",
		},
	}
}

func TestFailoverPrimaryToBackup1AndAutoFailback(t *testing.T) {
	store := makeTestFailoverStore(true)
	health := map[string]bool{"primary": false, "backup1": true, "backup2": true}
	var switches []string
	currentNow := "primary"

	m := newFailoverManager()
	m.loadStoreFn = func() (Store, error) { return store, nil }
	m.proxyRunningFn = func() bool { return true }
	m.proxyNowFn = func(tag string) (string, error) { return currentNow, nil }
	m.probeFn = func(tag, _ string) (int64, error) {
		if health[tag] {
			return 45, nil
		}
		return 0, fmt.Errorf("timeout")
	}
	m.selectFn = func(groupTag, targetTag string) error {
		if groupTag != failoverOutboundTag {
			t.Fatalf("unexpected groupTag: %s", groupTag)
		}
		switches = append(switches, targetTag)
		currentNow = targetTag
		return nil
	}

	ctx := context.Background()
	// 1st and 2nd failures: degraded, stay on primary.
	m.step(ctx)
	if st := m.status(); st.State != "degraded" || st.ActiveNodeID != "primary" || st.ConsecutiveFailures != 1 || len(switches) != 0 {
		t.Fatalf("after 1st failure: %+v switches=%v", st, switches)
	}
	m.step(ctx)
	if st := m.status(); st.State != "degraded" || st.ActiveNodeID != "primary" || st.ConsecutiveFailures != 2 || len(switches) != 0 {
		t.Fatalf("after 2nd failure: %+v switches=%v", st, switches)
	}
	// 3rd failure: fails over to backup1.
	m.step(ctx)
	if st := m.status(); st.State != "failed_over" || st.ActiveNodeID != "backup1" || st.ConsecutiveFailures != 0 || !slices.Equal(switches, []string{"backup1"}) {
		t.Fatalf("after 3rd failure: %+v switches=%v", st, switches)
	}

	// Primary recovers once: recovery count 1/2, still on backup1.
	health["primary"] = true
	m.step(ctx)
	if st := m.status(); st.State != "failed_over" || st.ActiveNodeID != "backup1" || st.PrimaryRecoveryCount != 1 {
		t.Fatalf("after 1st recovery probe: %+v", st)
	}
	// Primary recovers twice: auto failback to primary.
	m.step(ctx)
	if st := m.status(); st.State != "healthy" || st.ActiveNodeID != "primary" || st.PrimaryRecoveryCount != 0 || !slices.Equal(switches, []string{"backup1", "primary"}) {
		t.Fatalf("after 2nd recovery probe: %+v switches=%v", st, switches)
	}
}

func TestFailoverSkipsUnavailableBackup1ToBackup2(t *testing.T) {
	store := makeTestFailoverStore(true)
	store.Failover.FailureThreshold = 2
	health := map[string]bool{"primary": false, "backup1": false, "backup2": true}
	var switches []string

	m := newFailoverManager()
	m.loadStoreFn = func() (Store, error) { return store, nil }
	m.proxyRunningFn = func() bool { return true }
	m.proxyNowFn = func(string) (string, error) { return "primary", nil }
	m.probeFn = func(tag, _ string) (int64, error) {
		if health[tag] {
			return 60, nil
		}
		return 0, fmt.Errorf("down")
	}
	m.selectFn = func(_, target string) error {
		switches = append(switches, target)
		return nil
	}

	ctx := context.Background()
	m.step(ctx)
	m.step(ctx)
	if st := m.status(); st.State != "failed_over" || st.ActiveNodeID != "backup2" || !slices.Equal(switches, []string{"backup2"}) {
		t.Fatalf("expected direct switch to backup2, got %+v switches=%v", st, switches)
	}
}

func TestFailoverBackup1FailsThenBackup2ThenPrimaryRecovers(t *testing.T) {
	store := makeTestFailoverStore(true)
	store.Failover.FailureThreshold = 2
	store.Failover.RecoveryThreshold = 2
	health := map[string]bool{"primary": false, "backup1": true, "backup2": true}
	var switches []string
	currentNow := "primary"

	m := newFailoverManager()
	m.loadStoreFn = func() (Store, error) { return store, nil }
	m.proxyRunningFn = func() bool { return true }
	m.proxyNowFn = func(string) (string, error) { return currentNow, nil }
	m.probeFn = func(tag, _ string) (int64, error) {
		if health[tag] {
			return 50, nil
		}
		return 0, fmt.Errorf("down")
	}
	m.selectFn = func(_, target string) error {
		switches = append(switches, target)
		currentNow = target
		return nil
	}

	ctx := context.Background()
	// Primary fails -> backup1.
	m.step(ctx)
	m.step(ctx)
	if m.status().ActiveNodeID != "backup1" {
		t.Fatalf("expected backup1, got %+v", m.status())
	}

	// Backup1 fails -> backup2.
	health["backup1"] = false
	m.step(ctx)
	m.step(ctx)
	if st := m.status(); st.ActiveNodeID != "backup2" || st.State != "failed_over" {
		t.Fatalf("expected backup2, got %+v", st)
	}

	// Primary recovers -> auto failback from backup2 directly to primary.
	health["primary"] = true
	m.step(ctx)
	m.step(ctx)
	if st := m.status(); st.ActiveNodeID != "primary" || st.State != "healthy" || !slices.Equal(switches, []string{"backup1", "backup2", "primary"}) {
		t.Fatalf("expected failback to primary, got %+v switches=%v", st, switches)
	}
}

func TestFailoverAutoFailbackDisabledStaysOnBackup(t *testing.T) {
	store := makeTestFailoverStore(false)
	store.Failover.FailureThreshold = 1
	health := map[string]bool{"primary": false, "backup1": true, "backup2": true}
	probedPrimaryAfterFailover := 0
	currentNow := "primary"

	m := newFailoverManager()
	m.loadStoreFn = func() (Store, error) { return store, nil }
	m.proxyRunningFn = func() bool { return true }
	m.proxyNowFn = func(string) (string, error) { return currentNow, nil }
	m.probeFn = func(tag, _ string) (int64, error) {
		if currentNow == "backup1" && tag == "primary" {
			probedPrimaryAfterFailover++
		}
		if health[tag] {
			return 40, nil
		}
		return 0, fmt.Errorf("down")
	}
	m.selectFn = func(_, target string) error {
		currentNow = target
		return nil
	}

	ctx := context.Background()
	m.step(ctx) // -> backup1
	health["primary"] = true
	m.step(ctx)
	m.step(ctx)
	if st := m.status(); st.ActiveNodeID != "backup1" || probedPrimaryAfterFailover != 0 {
		t.Fatalf("auto_failback=false must stay on backup1 without probing primary: st=%+v probed=%d", st, probedPrimaryAfterFailover)
	}

	// When backup1 dies while auto_failback=false, backup2 is tried before primary.
	health["backup1"] = false
	m.step(ctx)
	if st := m.status(); st.ActiveNodeID != "backup2" {
		t.Fatalf("expected switch to backup2 when backup1 fails, got %+v", st)
	}
}

func TestFailoverAllDownAndRealignAfterExternalRestart(t *testing.T) {
	store := makeTestFailoverStore(true)
	store.Failover.FailureThreshold = 1
	health := map[string]bool{"primary": false, "backup1": false, "backup2": false}
	var switches []string
	currentNow := "primary"

	m := newFailoverManager()
	m.loadStoreFn = func() (Store, error) { return store, nil }
	m.proxyRunningFn = func() bool { return true }
	m.proxyNowFn = func(string) (string, error) { return currentNow, nil }
	m.probeFn = func(tag, _ string) (int64, error) {
		if health[tag] {
			return 35, nil
		}
		return 0, fmt.Errorf("down")
	}
	m.selectFn = func(_, target string) error {
		switches = append(switches, target)
		currentNow = target
		return nil
	}

	ctx := context.Background()
	m.step(ctx)
	m.step(ctx)
	if st := m.status(); st.State != "all_down" || st.ActiveNodeID != "primary" || len(switches) != 0 || len(st.Events) != 1 {
		t.Fatalf("expected deduplicated all_down with no switches: %+v switches=%v", st, switches)
	}

	// Backup1 comes up -> fails over to backup1.
	health["backup1"] = true
	m.step(ctx)
	if m.status().ActiveNodeID != "backup1" {
		t.Fatalf("expected backup1, got %+v", m.status())
	}

	// Simulate external sing-box restart resetting selector back to primary.
	currentNow = "primary"
	m.step(ctx)
	if currentNow != "backup1" || !slices.Equal(switches, []string{"backup1", "backup1"}) {
		t.Fatalf("expected realignment back to backup1, now=%s switches=%v", currentNow, switches)
	}
}

func TestFailoverConfigGenerationAndAPI(t *testing.T) {
	initial := makeTestFailoverStore(true)
	initial.Failover.Enabled = false
	initial.Failover.BackupNodeIDs = nil
	setupAPITest(t, initial)

	oldManager := defaultFailover
	mockManager := newFailoverManager()
	mockManager.loadStoreFn = loadAPIStoreSnapshot
	mockManager.proxyRunningFn = func() bool { return true }
	mockManager.probeFn = func(string, string) (int64, error) { return 30, nil }
	mockManager.selectFn = func(string, string) error { return nil }
	mockManager.proxyNowFn = func(string) (string, error) { return "primary", nil }
	defaultFailover = mockManager
	t.Cleanup(func() { defaultFailover = oldManager })

	// Enabling failover without backups must be rejected.
	rec := callAPI(t, "/api/failover", `{"enabled":true,"backup_node_ids":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without backups, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Save valid failover settings after an initial disabled status sync.
	if code := callAPIGet(t, "/api/failover/status").Code; code != http.StatusOK {
		t.Fatalf("initial status=%d", code)
	}
	rec = callAPI(t, "/api/failover", `{"enabled":true,"backup_node_ids":["backup1","backup2"],"check_interval_sec":20,"failure_threshold":3,"recovery_threshold":2,"auto_failback":true,"test_url":"https://www.gstatic.com/generate_204"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save failover status=%d body=%s", rec.Code, rec.Body.String())
	}
	var saveResp struct {
		Status FailoverStatus `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saveResp); err != nil {
		t.Fatal(err)
	}
	if saveResp.Status.State != "healthy" || !saveResp.Status.Managing {
		t.Fatalf("expected healthy/managing immediately after enabling failover, got %+v", saveResp.Status)
	}

	saved := load()
	generated := config(saved)
	route := generated["route"].(map[string]any)
	if route["final"] != failoverOutboundTag {
		t.Fatalf("route.final=%v want %s", route["final"], failoverOutboundTag)
	}
	dnsServers := generated["dns"].(map[string]any)["servers"].([]any)
	if dnsServers[0].(map[string]any)["detour"] != failoverOutboundTag {
		t.Fatalf("remote-dns detour=%v want %s", dnsServers[0].(map[string]any)["detour"], failoverOutboundTag)
	}

	var foundSelector map[string]any
	for _, raw := range generated["outbounds"].([]any) {
		out := raw.(map[string]any)
		if out["tag"] == failoverOutboundTag {
			foundSelector = out
		}
	}
	if foundSelector == nil || foundSelector["type"] != "selector" || foundSelector["default"] != "primary" {
		t.Fatalf("missing managed failover selector: %+v", foundSelector)
	}

	// Changing only check_interval_sec must not alter sing-box configFingerprint.
	fp1 := configFingerprint(saved)
	saved.Failover.CheckIntervalSec = 45
	fp2 := configFingerprint(saved)
	if !bytes.Equal(fp1, fp2) {
		t.Fatal("changing failover interval must not change sing-box config fingerprint")
	}

	// Mixed naive + hysteria2 chain can relay UDP; all-naive chain blocks UDP.
	if udpOutboundCannotRelay(saved, failoverOutboundTag) {
		t.Fatal("mixed failover chain with hysteria2 should be able to relay UDP")
	}
	saved.Failover.BackupNodeIDs = []string{"backup1"}
	if !udpOutboundCannotRelay(saved, failoverOutboundTag) {
		t.Fatal("all-naive failover chain must block UDP")
	}

	// Status, check, failback endpoints respond 200.
	if code := callAPIGet(t, "/api/failover/status").Code; code != http.StatusOK {
		t.Fatalf("status endpoint=%d", code)
	}
	if code := callAPI(t, "/api/failover/check", "").Code; code != http.StatusOK {
		t.Fatalf("check endpoint=%d", code)
	}
	if code := callAPI(t, "/api/failover/failback", "").Code; code != http.StatusOK {
		t.Fatalf("failback endpoint=%d", code)
	}

	// Clash API PUT helper test.
	var gotMethod, gotPath, gotName string
	clashServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		var payload struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		gotName = payload.Name
		w.WriteHeader(http.StatusNoContent)
	}))
	defer clashServer.Close()
	oldBase := clashAPIBase
	clashAPIBase = clashServer.URL
	t.Cleanup(func() { clashAPIBase = oldBase })
	if err := clashSelectProxy(failoverOutboundTag, "backup1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut || gotPath != "/proxies/failover-auto" || gotName != "backup1" {
		t.Fatalf("unexpected clash select request: %s %s name=%s", gotMethod, gotPath, gotName)
	}

	// Test context cancellation stops run loop promptly.
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mockManager.run(runCtx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("failover run loop did not exit on context cancel")
	}
}
