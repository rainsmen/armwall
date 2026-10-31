package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

func TestEmbeddedWebAssets(t *testing.T) {
	for _, name := range []string{"web/index.html", "web/styles.css", "web/js/core.js", "web/js/main.js"} {
		content, err := webFiles.ReadFile(name)
		if err != nil || len(content) == 0 {
			t.Fatalf("asset %s: size=%d err=%v", name, len(content), err)
		}
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

func TestLegacyListenDefaultsToPrivateClients(t *testing.T) {
	t.Setenv("ARMWALL_WEB_ACCESS", "")
	t.Setenv("ARMWALL_LISTEN", "0.0.0.0:8080")
	t.Setenv("ARMWALL_WEB_ALLOWED_CIDRS", "")
	cfg, err := loadWebAccessConfig()
	if err != nil || cfg.Mode != "legacy" {
		t.Fatalf("legacy config: mode=%q err=%v", cfg.Mode, err)
	}
	if !webClientAllowed("192.168.10.5:5000", cfg.AllowedPrefixes) {
		t.Fatal("legacy mode must keep LAN clients reachable")
	}
	if webClientAllowed("8.8.8.8:5000", cfg.AllowedPrefixes) || webClientAllowed("[2001:db8::1]:5000", cfg.AllowedPrefixes) {
		t.Fatal("legacy mode must not allow public clients by default")
	}
	t.Setenv("ARMWALL_WEB_ALLOWED_CIDRS", "100.64.0.0/10")
	cfg, err = loadWebAccessConfig()
	if err != nil || !webClientAllowed("100.100.1.1:5000", cfg.AllowedPrefixes) || webClientAllowed("192.168.10.5:5000", cfg.AllowedPrefixes) {
		t.Fatalf("legacy mode should honor explicit CIDRs: err=%v", err)
	}
}
