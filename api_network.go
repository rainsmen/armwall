package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

func apiNetworkTest(w http.ResponseWriter, r *http.Request) {
	targets := map[string]string{"google": "https://www.google.com/generate_204", "youtube": "https://www.youtube.com/generate_204", "github": "https://github.com/", "facebook": "https://www.facebook.com/", "baidu": "https://www.baidu.com/", "qq": "https://www.qq.com/", "bilibili": "https://www.bilibili.com/", "microsoft": "https://www.microsoft.com/"}
	name := r.URL.Query().Get("target")
	target, ok := targets[name]
	if !ok {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	port := getProxyPort()
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp.Body.Close()
	json.NewEncoder(w).Encode(map[string]any{"target": name, "status": resp.StatusCode, "ms": time.Since(start).Milliseconds()})
}

func apiGatewayStatus(w http.ResponseWriter, r *http.Request) {
	run(w, gatewayPath, "status")
}

func apiAcl(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var rule ACLRule
	if decodeJSONBody(r, &rule) != nil {
		http.Error(w, "invalid ACL rule", 400)
		return
	}
	creating := rule.ID == ""
	if creating {
		rule.ID = fmt.Sprintf("acl-%d", time.Now().UnixNano())
	}
	if err := validateACLRule(&rule, s); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if creating {
		s.ACLRules = append(s.ACLRules, rule)
	} else {
		index := -1
		for i := range s.ACLRules {
			if s.ACLRules[i].ID == rule.ID {
				index = i
				break
			}
		}
		if index < 0 {
			http.Error(w, "ACL rule not found", 404)
			return
		}
		s.ACLRules[index] = rule
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(rule)
}

func apiAclToggle(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		ID      string
		Enabled bool
	}
	if decodeJSONBody(r, &v) != nil || v.ID == "" {
		http.Error(w, "ACL rule id is required", 400)
		return
	}
	found := false
	for i := range s.ACLRules {
		if s.ACLRules[i].ID == v.ID {
			s.ACLRules[i].Enabled = v.Enabled
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "ACL rule not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiAclDelete(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ID string }
	if decodeJSONBody(r, &v) != nil || v.ID == "" {
		http.Error(w, "ACL rule id is required", 400)
		return
	}
	before := len(s.ACLRules)
	kept := s.ACLRules[:0]
	for _, rule := range s.ACLRules {
		if rule.ID != v.ID {
			kept = append(kept, rule)
		}
	}
	s.ACLRules = kept
	if len(s.ACLRules) == before {
		http.Error(w, "ACL rule not found", 404)
		return
	}
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiDns(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var settings DNSSettings
	if decodeJSONBody(r, &settings) != nil {
		http.Error(w, "invalid DNS settings", 400)
		return
	}
	if err := validateDNSSettings(&settings); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.DNS = settings
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s.DNS)
}

func apiRouting(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		Mode        string
		TCPOutbound string
		UDPOutbound string
		DNS         *DNSSettings
	}
	if decodeJSONBody(r, &v) != nil || (v.Mode != "bypass_cn" && v.Mode != "gfw" && v.Mode != "global") {
		http.Error(w, "invalid routing settings", 400)
		return
	}
	valid := map[string]bool{"": true, "same": true, "direct": true}
	for _, node := range s.Nodes {
		valid[node.ID] = true
	}
	for _, group := range s.StrategyGroups {
		valid[group.ID] = true
	}
	if !valid[v.TCPOutbound] || !valid[v.UDPOutbound] {
		http.Error(w, "unknown routing outbound", 400)
		return
	}
	if v.DNS != nil {
		if err := validateDNSSettings(v.DNS); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.DNS = *v.DNS
	}
	s.Mode = v.Mode
	s.TCPOutbound = v.TCPOutbound
	s.UDPOutbound = v.UDPOutbound
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiMode(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ Mode string }
	if decodeJSONBody(r, &v) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if v.Mode != "bypass_cn" && v.Mode != "gfw" && v.Mode != "global" {
		http.Error(w, "invalid mode", 400)
		return
	}
	s.Mode = v.Mode
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiGatewayEnable(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ LAN, WAN string }
	if err := decodeOptionalJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if (v.LAN != "" && !safeIface(v.LAN)) || (v.WAN != "" && !safeIface(v.WAN)) {
		http.Error(w, "invalid interface", 400)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gatewayPath, "enable")
	cmd.Env = os.Environ()
	if v.LAN != "" {
		cmd.Env = append(cmd.Env, "ARMWALL_LAN_IF="+v.LAN)
	}
	if v.WAN != "" {
		cmd.Env = append(cmd.Env, "ARMWALL_WAN_IF="+v.WAN)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), 500)
		return
	}
	if serviceOut, serviceErr := runCommandTimeout(5*time.Second, "systemctl", "enable", "--now", "armwall-gateway.service"); serviceErr != nil {
		_, _ = runCommandTimeout(5*time.Second, gatewayPath, "disable")
		http.Error(w, string(serviceOut), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}

func apiGatewayDisable(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	out, err := runCommandTimeout(5*time.Second, gatewayPath, "disable")
	if err != nil {
		http.Error(w, string(out), 500)
		return
	}
	if serviceOut, serviceErr := runCommandTimeout(5*time.Second, "systemctl", "disable", "--now", "armwall-gateway.service"); serviceErr != nil {
		http.Error(w, string(serviceOut), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}
