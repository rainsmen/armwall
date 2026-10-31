package main

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

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

func TestReadOnlyEndpointsDoNotWaitForWriteLock(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/api/state", "/api/rules", "/api/backups", "/api/config/export"} {
		done := make(chan int, 1)
		go func(p string) { done <- callAPIGet(t, p).Code }(path)
		select {
		case code := <-done:
			if code != http.StatusOK {
				t.Fatalf("%s status=%d", path, code)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s blocked on the API write mutex", path)
		}
	}
	if code := callAPI(t, "/api/state", "").Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/state status=%d", code)
	}
}

// TestFrontendAPIPathsAreRouted guards the route tables: every API path the
// web UI calls must reach a handler instead of falling through to 404.
func TestFrontendAPIPathsAreRouted(t *testing.T) {
	scripts, err := fs.Glob(webFiles, "web/js/*.js")
	if err != nil || len(scripts) == 0 {
		t.Fatalf("no embedded scripts: %v", err)
	}
	var script []byte
	for _, name := range scripts {
		data, err := webFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		script = append(script, data...)
	}
	paths := map[string]bool{"/api/service/start": true, "/api/service/stop": true}
	for _, match := range regexp.MustCompile("[\"`](/api/[a-z/-]+)").FindAllStringSubmatch(string(script), -1) {
		if !strings.HasSuffix(match[1], "/") {
			paths[match[1]] = true
		}
	}
	if len(paths) < 40 {
		t.Fatalf("found only %d API paths in web/js", len(paths))
	}
	for path := range paths {
		_, unlocked := unlockedAPIRoutes[path]
		_, locked := lockedAPIRoutes[path]
		if unlocked == locked {
			t.Errorf("%s: unlocked=%v locked=%v, want exactly one route", path, unlocked, locked)
		}
	}
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	if code := callAPIGet(t, "/api/does-not-exist").Code; code != http.StatusNotFound {
		t.Fatalf("unknown API path status=%d", code)
	}
}
