package main

import (
	"net/http"
	"testing"
)

// A store change must only restart the service whose configuration changed:
// restarts drop every relayed connection.

func TestNodeReorderDoesNotRestartProxy(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
		{ID: "n2", Name: "two", Type: "anytls", Server: "two.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
	}})
	reloads := 0
	reloadProxyFn = func(bool, bool) error { reloads++; return nil }
	recorder := callAPI(t, "/api/node/reorder", `{"ids":["n2","n1"]}`)
	if recorder.Code != http.StatusOK || reloads != 0 {
		t.Fatalf("reordering nodes must not restart the proxy: code=%d reloads=%d body=%s", recorder.Code, reloads, recorder.Body.String())
	}
}

func TestNaiveCredentialChangeRestartsNaiveOnly(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{
		{ID: "n1", Name: "naive", Type: "naive", Server: "naive.example", Port: 443, Username: "user", Password: "secret", Enabled: true},
	}})
	var singBoxChanged, naiveChanged bool
	reloadProxyFn = func(singBox, naive bool) error {
		singBoxChanged, naiveChanged = singBox, naive
		return nil
	}
	recorder := callAPI(t, "/api/node/update", `{"id":"n1","name":"naive","type":"naive","server":"naive.example","port":443,"username":"user","password":"rotated","enabled":true}`)
	if recorder.Code != http.StatusOK || !naiveChanged || singBoxChanged {
		t.Fatalf("a naive credential change must restart only naive: code=%d singbox=%v naive=%v body=%s", recorder.Code, singBoxChanged, naiveChanged, recorder.Body.String())
	}
}

func TestRoutingChangeRestartsSingBox(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, Nodes: []Node{
		{ID: "n1", Name: "one", Type: "anytls", Server: "one.example", Port: 443, Password: "secret", TLS: true, Enabled: true},
	}})
	var singBoxChanged, naiveChanged bool
	reloadProxyFn = func(singBox, naive bool) error {
		singBoxChanged, naiveChanged = singBox, naive
		return nil
	}
	recorder := callAPI(t, "/api/mode", `{"Mode":"global"}`)
	if recorder.Code != http.StatusOK || !singBoxChanged || naiveChanged {
		t.Fatalf("a mode change must restart sing-box only: code=%d singbox=%v naive=%v body=%s", recorder.Code, singBoxChanged, naiveChanged, recorder.Body.String())
	}
}
