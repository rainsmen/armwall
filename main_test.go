package main

import (
	"strings"
	"testing"
)

func TestParseSubscriptionProtocols(t *testing.T) {
	raw := "anytls://secret@example.com:443?sni=example.com#A\n" +
		"hysteria2://pw@example.net:8443?sni=example.net#B\n" +
		"trojan://pw@example.org:443#C"
	nodes := parseSubscription(raw)
	if len(nodes) != 3 {
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
}

func TestConfigRoutingModes(t *testing.T) {
	s := Store{Mode: "bypass_cn", Nodes: []Node{{ID: "n1", Type: "anytls", Server: "example.com", Port: 443, Password: "pw", TLS: true}}}
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
