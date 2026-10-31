package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
)

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

	recorder := callAPIGet(t, "/api/state")
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

	recorder = callAPIGet(t, "/api/node/get?id=node-1")
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
