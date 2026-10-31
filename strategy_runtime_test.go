package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
