package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Node struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Server      string `json:"server"`
	UUID        string `json:"uuid"`
	Password    string `json:"password"`
	Port        int    `json:"port"`
	TLS         bool   `json:"tls"`
	ServerName  string `json:"server_name"`
	Insecure    bool   `json:"insecure"`
	Username    string `json:"username"`
	Method      string `json:"method"`
	Flow        string `json:"flow"`
	Transport   string `json:"transport"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	ALPN        string `json:"alpn"`
	Fingerprint string `json:"fingerprint"`
	Plugin      string `json:"plugin"`
	PluginOpts  string `json:"plugin_opts"`
}
type Store struct {
	Nodes            []Node            `json:"nodes"`
	SubscriptionURLs []string          `json:"subscription_urls"`
	Mode             string            `json:"mode"`
	ProxyPort        int               `json:"proxy_port"`
	SelectedNode     string            `json:"selected_node"`
	UpdateHours      int               `json:"update_hours"`
	LogLevel         string            `json:"log_level"`
	RuleUpdateHours  int               `json:"rule_update_hours"`
	RuleBackups      map[string]string `json:"rule_backups"`
}

func parseSubscription(raw string) []Node {
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw)); err == nil {
		raw = string(b)
	}
	var out []Node
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vmess://") {
			if b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, "vmess://")); err == nil {
				var v struct{ PS, Add, Port, ID, TLS, SNI string }
				if json.Unmarshal(b, &v) == nil {
					p, _ := strconv.Atoi(v.Port)
					out = append(out, Node{ID: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Name: v.PS, Type: "vmess", Server: v.Add, Port: p, UUID: v.ID, TLS: v.TLS != "", ServerName: v.SNI})
					continue
				}
			}
		}
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if u.Scheme != "vless" && u.Scheme != "trojan" && u.Scheme != "shadowsocks" && u.Scheme != "ss" && u.Scheme != "hysteria2" && u.Scheme != "anytls" && u.Scheme != "naive" {
			continue
		}
		n := Node{ID: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Name: u.Fragment, Type: u.Scheme, Server: u.Hostname(), TLS: true}
		if p, err := strconv.Atoi(u.Port()); err == nil {
			n.Port = p
		}
		if n.Port == 0 {
			n.Port = 443
		}
		if u.User != nil {
			n.Password, _ = u.User.Password()
			n.UUID = u.User.Username()
			if n.Type == "trojan" || n.Type == "anytls" || n.Type == "hysteria2" {
				n.Password = u.User.Username()
				n.UUID = ""
			}
		}
		n.ServerName = u.Query().Get("sni")
		n.Insecure = u.Query().Get("insecure") == "1"
		n.Transport = u.Query().Get("type")
		n.Host = u.Query().Get("host")
		n.Path = u.Query().Get("path")
		n.Flow = u.Query().Get("flow")
		n.ALPN = u.Query().Get("alpn")
		n.Fingerprint = u.Query().Get("fp")
		if n.Type == "naive" {
			n.Username = n.UUID
			n.UUID = ""
		}
		if n.Type == "ss" {
			n.Type = "shadowsocks"
		}
		out = append(out, n)
	}
	return out
}

func fetchSubscription(rawURL string) ([]Node, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("subscription must use https")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := client.Get(rawURL)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if readErr == nil && resp.StatusCode < 300 {
				nodes := parseSubscription(string(body))
				if len(nodes) > 0 {
					return nodes, nil
				}
				lastErr = fmt.Errorf("no supported nodes")
			} else if readErr != nil {
				lastErr = readErr
			} else {
				lastErr = fmt.Errorf("subscription http status %d", resp.StatusCode)
			}
		} else {
			lastErr = err
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
		}
	}
	return nil, lastErr
}

func updateSubscriptions() error {
	s := load()
	var nodes []Node
	for _, rawURL := range s.SubscriptionURLs {
		fetched, err := fetchSubscription(rawURL)
		if err != nil {
			return fmt.Errorf("%s: %w", rawURL, err)
		}
		nodes = append(nodes, fetched...)
	}
	if len(s.SubscriptionURLs) == 0 {
		return fmt.Errorf("no subscriptions configured")
	}
	kept := s.Nodes[:0]
	for _, n := range s.Nodes {
		if !strings.HasPrefix(n.ID, "sub-") {
			kept = append(kept, n)
		}
	}
	s.Nodes = append(kept, nodes...)
	if err := writeConfig(s); err != nil {
		return err
	}
	if err := save(s); err != nil {
		return err
	}
	return restartProxy()
}

var mu sync.Mutex
var dataPath = "/var/lib/armwall/store.json"
var configPath = "/etc/armwall/sing-box.json"
var proxyPort = 1080
var tproxyEnabled bool
var tproxyPort = 11081
var ruleURLs = map[string]string{
	"geosite-ads":   "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
	"geosite-cn":    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
	"geoip-cn":      "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
	"geosite-proxy": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
}

func ruleSet(tag string) map[string]any {
	path := "/var/lib/armwall/rules/" + tag + ".srs"
	if _, err := os.Stat(path); err == nil {
		return map[string]any{"type": "local", "tag": tag, "format": "binary", "path": path}
	}
	return map[string]any{"type": "remote", "tag": tag, "format": "binary", "url": ruleURLs[tag], "download_detour": "direct"}
}
func updateRule(tag, backup string) error {
	primary, ok := ruleURLs[tag]
	if !ok {
		return fmt.Errorf("unknown rule")
	}
	urls := []string{primary}
	if backup != "" {
		urls = append(urls, backup)
	}
	var last error
	for _, raw := range urls {
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(raw)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode >= 300 || len(body) < 16 {
			last = fmt.Errorf("download failed")
			continue
		}
		dir := "/var/lib/armwall/rules"
		if err = os.MkdirAll(dir, 0750); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, tag+".srs"), body, 0640)
	}
	return last
}

func load() Store {
	b, err := os.ReadFile(dataPath)
	if err != nil {
		return Store{Mode: "bypass_cn"}
	}
	var s Store
	_ = json.Unmarshal(b, &s)
	return s
}
func save(s Store) error {
	if err := os.MkdirAll(filepath.Dir(dataPath), 0750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(dataPath, b, 0600)
}
func config(s Store) map[string]any {
	outs := []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "block", "tag": "block"}}
	for _, n := range s.Nodes {
		o := map[string]any{"type": n.Type, "tag": n.ID, "server": n.Server, "server_port": n.Port}
		if n.UUID != "" {
			o["uuid"] = n.UUID
		}
		if n.Password != "" {
			o["password"] = n.Password
		}
		if n.Username != "" {
			o["username"] = n.Username
		}
		if n.Method != "" {
			o["method"] = n.Method
		}
		if n.Flow != "" {
			o["flow"] = n.Flow
		}
		if n.Transport != "" {
			tr := map[string]any{"type": n.Transport}
			if n.Path != "" {
				tr["path"] = n.Path
			}
			if n.Host != "" {
				tr["headers"] = map[string]any{"Host": n.Host}
			}
			o["transport"] = tr
		}
		if n.TLS {
			serverName := n.ServerName
			if serverName == "" {
				serverName = n.Server
			}
			tls := map[string]any{"enabled": true, "server_name": serverName, "insecure": n.Insecure}
			if n.ALPN != "" {
				tls["alpn"] = strings.Split(n.ALPN, ",")
			}
			if n.Fingerprint != "" {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fingerprint}
			}
			o["tls"] = tls
		}
		outs = append(outs, o)
	}
	proxy := "direct"
	if len(s.Nodes) > 0 {
		proxy = s.Nodes[0].ID
	}
	if s.SelectedNode != "" {
		for _, n := range s.Nodes {
			if n.ID == s.SelectedNode {
				proxy = n.ID
				break
			}
		}
	}
	rules := []any{map[string]any{"ip_is_private": true, "outbound": "direct"}, map[string]any{"rule_set": []string{"geosite-ads"}, "outbound": "block"}}
	ruleSets := []any{ruleSet("geosite-ads")}
	final := proxy
	switch s.Mode {
	case "bypass_cn":
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-cn", "geoip-cn"}, "outbound": "direct"})
		ruleSets = append(ruleSets, ruleSet("geosite-cn"), ruleSet("geoip-cn"))
	case "gfw":
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-proxy"}, "outbound": proxy})
		ruleSets = append(ruleSets, ruleSet("geosite-proxy"))
		final = "direct"
	}
	listenPort := proxyPort
	if s.ProxyPort > 0 {
		listenPort = s.ProxyPort
	}
	inbounds := []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": listenPort}}
	if tproxyEnabled {
		inbounds = append(inbounds, map[string]any{"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": tproxyPort})
	}
	level := s.LogLevel
	if level == "" {
		level = "info"
	}
	return map[string]any{"log": map[string]any{"level": level, "output": "/var/log/armwall/sing-box.log", "timestamp": true}, "inbounds": inbounds, "outbounds": outs, "route": map[string]any{"auto_detect_interface": true, "rules": rules, "rule_set": ruleSets, "final": final}, "experimental": map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:9090"}}}
}
func writeConfig(s Store) error {
	b, _ := json.MarshalIndent(config(s), "", "  ")
	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		return err
	}
	if err := os.MkdirAll("/var/log/armwall", 0750); err != nil {
		return err
	}
	candidate := configPath + ".candidate"
	if err := os.WriteFile(candidate, b, 0640); err != nil {
		return err
	}
	checker, lookErr := exec.LookPath("sing-box")
	if lookErr == nil {
		out, err := exec.Command(checker, "check", "-c", candidate).CombinedOutput()
		if err != nil {
			_ = os.Remove(candidate)
			return fmt.Errorf("invalid sing-box config: %s", strings.TrimSpace(string(out)))
		}
	}
	if err := os.Rename(candidate, configPath); err != nil {
		_ = os.Remove(candidate)
		return err
	}
	return nil
}
func run(w http.ResponseWriter, name string, args ...string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}
func restartProxy() error {
	out, err := exec.Command("systemctl", "restart", "armwall-sing-box.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box restart failed: %s", strings.TrimSpace(string(out)))
	}
	address := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	for i := 0; i < 30; i++ {
		conn, dialErr := net.DialTimeout("tcp", address, 150*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("sing-box restarted but proxy port %d is not ready", proxyPort)
}
func api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mu.Lock()
	defer mu.Unlock()
	s := load()
	switch r.URL.Path {
	case "/api/state":
		json.NewEncoder(w).Encode(s)
	case "/api/node":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var n Node
		if json.NewDecoder(r.Body).Decode(&n) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if n.ID == "" {
			n.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
		}
		s.Nodes = append(s.Nodes, n)
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(n)
	case "/api/node/delete":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
		if v.ID == "" {
			v.ID = r.URL.Query().Get("id")
		}
		for i := range s.Nodes {
			if s.Nodes[i].ID == v.ID {
				s.Nodes = append(s.Nodes[:i], s.Nodes[i+1:]...)
				break
			}
		}
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/node/select":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
		found := false
		for _, n := range s.Nodes {
			if n.ID == v.ID {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "node not found", 404)
			return
		}
		s.SelectedNode = v.ID
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/subscription":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ URL string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || !strings.HasPrefix(v.URL, "https://") {
			http.Error(w, "invalid url", 400)
			return
		}
		nodes, err := fetchSubscription(v.URL)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		kept := s.Nodes[:0]
		for _, n := range s.Nodes {
			if !strings.HasPrefix(n.ID, "sub-") {
				kept = append(kept, n)
			}
		}
		s.Nodes = append(kept, nodes...)
		found := false
		for _, existing := range s.SubscriptionURLs {
			if existing == v.URL {
				found = true
				break
			}
		}
		if !found {
			s.SubscriptionURLs = append(s.SubscriptionURLs, v.URL)
		}
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
	case "/api/subscription/clear":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		kept := s.Nodes[:0]
		for _, n := range s.Nodes {
			if !strings.HasPrefix(n.ID, "sub-") {
				kept = append(kept, n)
			}
		}
		s.Nodes = kept
		s.SubscriptionURLs = nil
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"cleared": true})
	case "/api/subscription/update":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if err := updateSubscriptions(); err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"updated": true})
	case "/api/subscription/schedule":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Hours int }
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.Hours < 1 || v.Hours > 168 {
			http.Error(w, "hours must be 1-168", 400)
			return
		}
		s.UpdateHours = v.Hours
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		dir := "/etc/systemd/system/armwall-subscription-update.timer.d"
		if err := os.MkdirAll(dir, 0755); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		override := fmt.Sprintf("[Timer]\nOnUnitActiveSec=\nOnUnitActiveSec=%dh\n", v.Hours)
		if err := os.WriteFile(filepath.Join(dir, "interval.conf"), []byte(override), 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "restart", "armwall-subscription-update.timer").Run()
		json.NewEncoder(w).Encode(s)
	case "/api/mode":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Mode string }
		json.NewDecoder(r.Body).Decode(&v)
		if v.Mode != "bypass_cn" && v.Mode != "gfw" && v.Mode != "global" {
			http.Error(w, "invalid mode", 400)
			return
		}
		s.Mode = v.Mode
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/settings":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ProxyPort int }
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.ProxyPort < 1 || v.ProxyPort > 65535 {
			http.Error(w, "invalid port", 400)
			return
		}
		s.ProxyPort = v.ProxyPort
		proxyPort = v.ProxyPort
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/service/start":
		writeConfig(s)
		run(w, "systemctl", "restart", "armwall-sing-box.service")
	case "/api/service/stop":
		run(w, "systemctl", "stop", "armwall-sing-box.service")
	case "/api/service/status":
		run(w, "systemctl", "is-active", "armwall-sing-box.service")
	case "/api/logs":
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", "attachment; filename=armwall.log")
		}
		b, err := os.ReadFile("/var/log/armwall/sing-box.log")
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(b) > 256<<10 {
			b = b[len(b)-(256<<10):]
		}
		w.Write(b)
	case "/api/log/clear":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if err := os.WriteFile("/var/log/armwall/sing-box.log", nil, 0640); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"cleared": true})
	case "/api/log/level":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Level string }
		json.NewDecoder(r.Body).Decode(&v)
		if v.Level != "trace" && v.Level != "debug" && v.Level != "info" && v.Level != "warn" && v.Level != "error" {
			http.Error(w, "invalid level", 400)
			return
		}
		s.LogLevel = v.Level
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		save(s)
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/rules":
		json.NewEncoder(w).Encode(map[string]any{"rules": ruleURLs, "backups": s.RuleBackups, "update_hours": s.RuleUpdateHours})
	case "/api/rules/update":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Tag string }
		json.NewDecoder(r.Body).Decode(&v)
		backup := ""
		if s.RuleBackups != nil {
			backup = s.RuleBackups[v.Tag]
		}
		if err := updateRule(v.Tag, backup); err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"updated": v.Tag})
	case "/api/rules/settings":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			Tag, Backup string
			Hours       int
		}
		json.NewDecoder(r.Body).Decode(&v)
		if _, ok := ruleURLs[v.Tag]; !ok || v.Hours < 1 || v.Hours > 168 {
			http.Error(w, "invalid rule settings", 400)
			return
		}
		if s.RuleBackups == nil {
			s.RuleBackups = map[string]string{}
		}
		s.RuleBackups[v.Tag] = v.Backup
		s.RuleUpdateHours = v.Hours
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/network/test":
		targets := map[string]string{"google": "https://www.google.com/generate_204", "youtube": "https://www.youtube.com/generate_204", "github": "https://github.com/", "facebook": "https://www.facebook.com/", "baidu": "https://www.baidu.com/", "qq": "https://www.qq.com/", "bilibili": "https://www.bilibili.com/", "microsoft": "https://www.microsoft.com/"}
		name := r.URL.Query().Get("target")
		target, ok := targets[name]
		if !ok {
			http.Error(w, "invalid target", 400)
			return
		}
		transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)})}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		start := time.Now()
		resp, err := client.Get(target)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		resp.Body.Close()
		json.NewEncoder(w).Encode(map[string]any{"target": name, "status": resp.StatusCode, "ms": time.Since(start).Milliseconds()})
	case "/api/gateway/status":
		run(w, "/usr/local/bin/armwall-gateway", "status")
	case "/api/gateway/enable":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ LAN, WAN string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || !safeIface(v.LAN) || !safeIface(v.WAN) {
			http.Error(w, "invalid interface", 400)
			return
		}
		cmd := exec.Command("/usr/local/bin/armwall-gateway", "enable")
		cmd.Env = append(os.Environ(), "ARMWALL_LAN_IF="+v.LAN, "ARMWALL_WAN_IF="+v.WAN)
		out, err := cmd.CombinedOutput()
		if err != nil {
			http.Error(w, string(out), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(out)
	case "/api/gateway/disable":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		run(w, "/usr/local/bin/armwall-gateway", "disable")
	case "/api/node/test":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
		if v.ID == "" {
			v.ID = r.URL.Query().Get("id")
		}
		var host, tag string
		var port int
		for _, n := range s.Nodes {
			if n.ID == v.ID {
				host, tag, port = n.Server, n.ID, n.Port
				break
			}
		}
		if host == "" {
			http.Error(w, "node not found", 404)
			return
		}
		method := r.URL.Query().Get("method")
		start := time.Now()
		switch method {
		case "ping":
			out, err := exec.Command("ping", "-c", "1", "-W", "3", host).CombinedOutput()
			if err != nil {
				http.Error(w, string(out), 502)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"method": "ping", "ms": time.Since(start).Milliseconds()})
		case "tcp":
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			conn.Close()
			json.NewEncoder(w).Encode(map[string]any{"method": "tcp", "ms": time.Since(start).Milliseconds()})
		case "urltest":
			endpoint := "http://127.0.0.1:9090/proxies/" + url.PathEscape(tag) + "/delay?url=" + url.QueryEscape("https://www.google.com/generate_204") + "&timeout=10000"
			resp, err := http.Get(endpoint)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		default:
			http.Error(w, "invalid method", 400)
		}
	case "/api/node/import":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Links string }
		if json.NewDecoder(r.Body).Decode(&v) != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		nodes := parseSubscription(v.Links)
		if len(nodes) == 0 {
			http.Error(w, "no supported links", 422)
			return
		}
		if err := writeConfig(Store{Nodes: append(s.Nodes, nodes...), Mode: s.Mode, ProxyPort: s.ProxyPort}); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.Nodes = append(s.Nodes, nodes...)
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := restartProxy(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
	case "/api/core/update":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Core, Action, File string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || (v.Core != "sing-box" && v.Core != "naive") {
			http.Error(w, "invalid core", 400)
			return
		}
		if v.Action != "version" && v.Action != "latest" && v.Action != "manual" {
			http.Error(w, "invalid action", 400)
			return
		}
		args := []string{v.Core, v.Action}
		if v.Action == "manual" {
			if !filepath.IsAbs(v.File) || strings.Contains(v.File, "..") {
				http.Error(w, "invalid file", 400)
				return
			}
			args = append(args, v.File)
		}
		run(w, "/usr/local/bin/armwall-update-core", args...)
	default:
		http.NotFound(w, r)
	}
}
func safeIface(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for _, r := range v {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	template.Must(template.New("p").Parse(indexHTML2)).Execute(w, nil)
}
func main() {
	if v := os.Getenv("ARMWALL_DATA"); v != "" {
		dataPath = v
	}
	if v := os.Getenv("ARMWALL_PROXY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			proxyPort = p
		}
	}
	if stored := load().ProxyPort; stored > 0 && stored < 65536 {
		proxyPort = stored
	}
	if os.Getenv("ARMWALL_TPROXY") == "1" {
		tproxyEnabled = true
	}
	if v := os.Getenv("ARMWALL_TPROXY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			tproxyPort = p
		}
	}
	if v := os.Getenv("ARMWALL_CONFIG"); v != "" {
		configPath = v
	}
	if len(os.Args) > 1 && os.Args[1] == "--update-subscriptions" {
		if err := updateSubscriptions(); err != nil {
			log.Fatal(err)
		}
		log.Print("subscriptions updated")
		return
	}
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if token := os.Getenv("ARMWALL_TOKEN"); token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", 401)
			return
		}
		api(w, r)
	})
	http.HandleFunc("/", page)
	addr := os.Getenv("ARMWALL_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	log.Printf("armwall listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

var indexHTML = `<!doctype html><html><head><meta charset="utf-8"><title>ArmWall</title><style>body{font:15px sans-serif;max-width:900px;margin:32px auto;padding:0 16px;background:#f5f6f8}section{background:#fff;padding:20px;margin:14px 0;border:1px solid #ddd}input,select,button{padding:8px;margin:4px}button{cursor:pointer}</style></head><body><h1>ArmWall</h1><section><h2>认证</h2><input id="token" type="password" placeholder="管理 Token" onchange="localStorage.token=this.value"><button onclick="token.value='';localStorage.removeItem('token')">清除</button></section><section><h2>服务</h2><button onclick="svc('start')">启动/重启</button><button onclick="svc('stop')">停止</button><button onclick="svc('status')">状态</button><pre id="out"></pre></section><section><h2>订阅</h2><input id="sub" size="60" placeholder="HTTPS 订阅地址"><button onclick="importSub()">导入订阅</button></section><section><h2>分流模式</h2><select id="mode"><option value="bypass_cn">绕过国内</option><option value="gfw">GFW 模式</option><option value="global">全局代理</option></select><button onclick="saveMode()">保存</button></section><section><h2>添加节点</h2><input id="name" placeholder="名称"><input id="server" placeholder="服务器"><input id="port" type="number" value="443"><input id="uuid" placeholder="UUID/密码"><select id="type"><option>vless</option><option>trojan</option><option>shadowsocks</option></select><button onclick="add()">添加</button></section><section><h2>本机代理</h2><p>SOCKS5/HTTP mixed: <code>Armbian_IP:11080</code></p></section><script>token.value=localStorage.token||'';async function api(p,o){o=o||{};o.headers=Object.assign({},o.headers,{'Authorization':'Bearer '+token.value});return fetch(p,o)}async function svc(x){let r=await api('/api/service/'+x,{method:'POST'});out.textContent=await r.text()}async function add(){let d={name:name.value,server:server.value,port:+port.value,uuid:uuid.value,type:type.value,tls:true};let r=await api('/api/node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});out.textContent=await r.text()}async function saveMode(){let r=await api('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode.value})});out.textContent=await r.text()}async function importSub(){let r=await api('/api/subscription',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:sub.value})});out.textContent=await r.text()}</script></body></html>`

var indexHTML2 = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ArmWall</title><style>
:root{font:14px system-ui,sans-serif;color:#202735;background:#eef1f5}*{box-sizing:border-box}body{margin:0}.top{height:58px;background:#172335;color:#fff;display:flex;align-items:center;padding:0 24px;gap:28px}.brand{font-size:20px;font-weight:650}.top small{color:#aebbd0}.layout{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:calc(100vh - 58px)}aside{background:#fff;border-right:1px solid #d9dee7;padding:18px 12px}aside button{display:block;width:100%;text-align:left;border:0;background:transparent;padding:11px 13px;color:#4b5667;border-radius:5px;cursor:pointer}aside button.active,aside button:hover{background:#e8edf6;color:#1c4c98;font-weight:600}.main{padding:24px;max-width:1200px;width:100%}.view{display:none}.view.active{display:block}.title{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.title h1{font-size:23px;margin:0}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.card{background:#fff;border:1px solid #d9dee7;border-radius:6px;padding:17px}.card h3{margin:0 0 12px;font-size:15px}.metric{font-size:25px;font-weight:650}.muted{color:#687487}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}label{display:block;color:#5c6879;font-size:13px;margin:12px 0 5px}input,select,textarea{border:1px solid #cbd3df;border-radius:4px;padding:9px;background:#fff;min-width:180px}textarea{width:100%;min-height:85px}button.primary,button.danger{border:0;border-radius:4px;padding:9px 14px;color:#fff;cursor:pointer}button.primary{background:#2765b8}button.danger{background:#b84a4a}table{border-collapse:collapse;width:100%;background:#fff}th,td{padding:10px;border-bottom:1px solid #e5e8ee;text-align:left}th{background:#f7f8fa;color:#566275;font-weight:600}pre{white-space:pre-wrap;background:#172335;color:#d8e2f2;padding:12px;border-radius:4px;min-height:50px}.sitebtn{display:flex;align-items:center;gap:8px;border:1px solid #d6dce6;background:#fff;color:#273449;border-radius:6px;padding:9px 13px;cursor:pointer}.sitebtn img{width:20px;height:20px;object-fit:contain}.status{display:inline-block;border-radius:10px;padding:3px 9px;background:#e4f5e9;color:#18753a;font-size:12px}@media(max-width:760px){.layout{grid-template-columns:1fr}aside{display:flex;overflow:auto;border-right:0;border-bottom:1px solid #d9dee7}.grid{grid-template-columns:1fr}.main{padding:15px}}
</style></head><body><header class="top"><span class="brand">ArmWall</span><small>Armbian proxy gateway</small><span style="margin-left:auto" id="badge">未连接</span></header><div class="layout"><aside><button class="active" data-tab="dashboard">概览</button><button data-tab="nodes">节点管理</button><button data-tab="subscriptions">订阅管理</button><button data-tab="routing">分流与 DNS</button><button data-tab="service">服务与组件</button><button data-tab="logs">运行日志</button></aside><main class="main"><section id="dashboard" class="view active"><div class="title"><h1>概览</h1><button class="primary" onclick="service('start')">启动 / 重启</button></div><div class="grid"><div class="card"><h3>代理服务</h3><div class="metric" id="svc">检查中</div><p class="muted">mixed SOCKS5 / HTTP · 11080</p></div><div class="card"><h3>节点数量</h3><div class="metric" id="nodeCount">-</div><p class="muted">当前配置中的出站节点</p></div><div class="card"><h3>运行模式</h3><div class="metric" id="modeText">-</div><p class="muted">可在“分流与 DNS”中调整</p></div></div><div class="card" style="margin-top:14px"><h3>当前运行节点</h3><select id="activeNode" style="min-width:360px"></select><button class="primary" onclick="selectNode()">切换节点</button><h3 style="margin-top:18px">网络测试</h3><div class="row"><button class="sitebtn" onclick="netTest('google',this)"><img src="https://www.google.com/favicon.ico">Google</button><button class="sitebtn" onclick="netTest('youtube',this)"><img src="https://www.youtube.com/favicon.ico">YouTube</button><button class="sitebtn" onclick="netTest('github',this)"><img src="https://github.com/favicon.ico">GitHub</button><button class="sitebtn" onclick="netTest('facebook',this)"><img src="https://www.facebook.com/favicon.ico">Facebook</button><button class="sitebtn" onclick="netTest('baidu',this)"><img src="https://www.baidu.com/favicon.ico">百度</button><button class="sitebtn" onclick="netTest('qq',this)"><img src="https://www.qq.com/favicon.ico">腾讯</button><button class="sitebtn" onclick="netTest('bilibili',this)"><img src="https://www.bilibili.com/favicon.ico">哔哩哔哩</button><button class="sitebtn" onclick="netTest('microsoft',this)"><img src="https://www.microsoft.com/favicon.ico">Microsoft</button></div></div><div class="card" style="margin-top:14px"><h3>快速连接</h3><p>SOCKS5 / HTTP mixed：<input id="proxyPort" type="number" value="11080" style="min-width:100px"><button class="primary" onclick="savePort()">应用端口</button></p><p class="muted">透明网关端口：11081（需要手动启用 nftables 网关规则）</p></div></section><section id="nodes" class="view"><div class="title"><h1>节点管理</h1><button class="primary" onclick="document.getElementById('nodeForm').hidden=!document.getElementById('nodeForm').hidden">添加节点</button></div><div class="card" id="nodeForm" hidden><div class="row"><input id="nName" placeholder="备注名称"><select id="nType"><option>vless</option><option>trojan</option><option>hysteria2</option><option>anytls</option><option>vmess</option><option>naive</option></select><input id="nServer" placeholder="服务器地址"><input id="nPort" type="number" value="443"><input id="nUser" placeholder="用户名"><input id="nSecret" placeholder="密码 / UUID"><input id="nSNI" placeholder="TLS SNI"><input id="nHost" placeholder="HTTP Host"><input id="nPath" placeholder="路径"><input id="nALPN" placeholder="ALPN, 逗号分隔"><input id="nFlow" placeholder="VLESS Flow"><input id="nMethod" placeholder="SS 加密方法"><label><input id="nInsecure" type="checkbox">跳过证书验证</label></div><button class="primary" onclick="addNode()">保存节点</button><label>分享链接导入（每行一个）</label><textarea id="shareLinks" placeholder="vless://... 或 naive://..."></textarea><button class="primary" onclick="importLinks()">导入分享链接</button></div><div class="card" style="margin-top:14px;padding:0;overflow:auto"><table><thead><tr><th>备注</th><th>协议</th><th>服务器</th><th>端口</th><th>操作</th></tr></thead><tbody id="nodesTable"></tbody></table></div></section><section id="subscriptions" class="view"><div class="title"><h1>订阅管理</h1></div><div class="card"><h3>已添加订阅</h3><div id="subscriptionList" class="muted"></div><div class="row"><button class="primary" onclick="updateSubscriptions()">手动更新全部</button><label>自动更新间隔（小时）</label><input id="updateHours" type="number" min="1" max="168" value="6"><button class="primary" onclick="saveSchedule()">保存间隔</button></div><label>HTTPS 订阅地址</label><input id="subURL" style="width:75%" placeholder="https://..."><div class="row"><button class="primary" onclick="importSubscription()">立即更新并导入</button><span class="muted">更新成功后会自动生成并校验 sing-box 配置</span></div></div></section><section id="routing" class="view"><div class="title"><h1>分流与 DNS</h1><button class="primary" onclick="saveRouting()">保存并重启</button></div><div class="card"><label>代理模式</label><select id="routeMode"><option value="bypass_cn">绕过国内：国内直连，其余代理</option><option value="gfw">GFW：规则匹配代理，其余直连</option><option value="global">全局代理</option></select><label>DNS 说明</label><p class="muted">当前使用 sing-box DNS 和远程 GeoIP/Geosite 规则集。透明网关部署时请将客户端 DNS 指向本机。</p><h3 style="margin-top:22px">规则更新</h3><div id="ruleManager"></div><label>透明网关</label><div class="row"><input id="lanIf" value="eth0" placeholder="LAN 接口"><input id="wanIf" value="eth0" placeholder="WAN 接口"><button class="primary" onclick="gatewayEnable()">启用网关</button><button class="primary" onclick="gateway('status')">查看状态</button><button class="danger" onclick="gateway('disable')">关闭网关规则</button><span class="muted">启用前请确认 LAN/WAN 接口，避免影响现有网络。</span></div><pre id="gatewayOut"></pre></div></section><section id="service" class="view"><div class="title"><h1>服务与组件</h1></div><div class="grid"><div class="card"><h3>ArmWall Web</h3><span class="status">运行中</span><p class="muted">systemd · :8080</p></div><div class="card"><h3>sing-box</h3><p id="coreVersion">检查中</p><button class="primary" onclick="updateCore('sing-box','version')">检查版本</button><button class="primary" onclick="updateCore('sing-box','latest')">更新</button></div><div class="card"><h3>代理服务</h3><button class="primary" onclick="service('start')">启动</button><button class="danger" onclick="service('stop')">停止</button><p id="serviceOut" class="muted"></p></div></div></section><section id="logs" class="view"><div class="title"><h1>运行日志</h1><div><select id="logLevel"><option>trace</option><option>debug</option><option selected>info</option><option>warn</option><option>error</option></select><button class="primary" onclick="saveLogLevel()">应用级别</button><button class="primary" onclick="refreshLogs()">刷新</button><button class="primary" onclick="exportLogs()">导出</button><button class="danger" onclick="clearLogs()">清屏</button></div></div><pre id="logOut">点击服务状态按钮查看 sing-box 状态。</pre></section><div id="out" hidden></div></main></div><script>
const $=id=>document.getElementById(id);let token=localStorage.armwallToken||'';function api(path,opt={}){opt.headers=Object.assign({},opt.headers,{'Authorization':'Bearer '+token});return fetch(path,opt)}function show(msg){$('out').textContent=typeof msg==='string'?msg:JSON.stringify(msg,null,2)}document.querySelectorAll('aside button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));document.querySelectorAll('aside button').forEach(x=>x.classList.remove('active'));$(b.dataset.tab).classList.add('active');b.classList.add('active')});async function state(){let r=await api('/api/state');if(r.status===401){token=prompt('请输入 ArmWall 管理 Token')||'';localStorage.armwallToken=token;r=await api('/api/state')}let s=await r.json();$('nodeCount').textContent=(s.nodes||[]).length;$('modeText').textContent={bypass_cn:'绕过国内',gfw:'GFW 模式',global:'全局代理'}[s.mode]||s.mode;$('routeMode').value=s.mode;renderNodes(s.nodes||[]);renderSelectors(s);renderRules();$('badge').textContent='已连接';service('status')}function renderNodes(ns){let b=document.getElementById("nodesTable");b.textContent="";ns.forEach(function(n){let r=b.insertRow();[n.Name||n.name||"未命名",n.Type||n.type,n.Server||n.server,n.Port||n.port].forEach(function(v){r.insertCell().textContent=v});let c=r.insertCell(),x=document.createElement("button");x.className="danger";x.textContent="删除";x.onclick=function(){deleteNode(n.ID||n.id)};c.appendChild(x);["ping","tcp","urltest"].forEach(function(m){let y=document.createElement("button");y.className="primary";y.textContent=m;y.onclick=function(){testNode(n.id,m,y)};c.appendChild(y)})})}function testNode(id,m,b){let old=b.textContent;b.textContent="测试中";api("/api/node/test?id="+encodeURIComponent(id)+"&method="+m,{method:"POST"}).then(function(r){return r.json()}).then(function(d){b.textContent=m+" "+d.ms+"ms"}).catch(function(){b.textContent=old+" 失败"})}function esc(x){return String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function service(a){let r=await api('/api/service/'+a,{method:'POST'});let t=await r.text();$('svc').textContent=t.trim()||'已提交';$('serviceOut').textContent=t;$('logOut').textContent=t}async function addNode(){let d={Name:$('nName').value,Type:$('nType').value,Server:$('nServer').value,Port:+$('nPort').value,Username:$('nUser').value,UUID:$('nSecret').value,ServerName:$('nSNI').value,Host:$('nHost').value,Path:$('nPath').value,ALPN:$('nALPN').value,Flow:$('nFlow').value,Method:$('nMethod').value,Insecure:$('nInsecure').checked,TLS:true};let r=await api('/api/node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});show(await r.text());state()}async function importLinks(){let r=await api("/api/node/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({Links:$("shareLinks").value})});show(await r.text());state()}async function savePort(){let r=await api("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ProxyPort:+$("proxyPort").value})});show(await r.text());state()}async function importSubscription(){let r=await api('/api/subscription',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({URL:$('subURL').value})});show(await r.text());state()}async function saveRouting(){let r=await api('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Mode:$('routeMode').value})});show(await r.text());state()}async function deleteNode(id){let r=await api('/api/node/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ID:id})});show(await r.text());state()}async function gatewayEnable(){let r=await api("/api/gateway/enable",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({LAN:document.getElementById("lanIf").value,WAN:document.getElementById("wanIf").value})});document.getElementById("gatewayOut").textContent=await r.text()}async function gateway(a){let r=await api("/api/gateway/"+a,{method:a==="status"?"GET":"POST"});document.getElementById("gatewayOut").textContent=await r.text()}async function refreshLogs(){let r=await api("/api/logs");document.getElementById("logOut").textContent=await r.text()}async function renderRules(){let r=await api("/api/rules");if(!r.ok)return;let d=await r.json(),box=document.getElementById("ruleManager");box.innerHTML="";Object.keys(d.rules||{}).forEach(function(tag){let row=document.createElement("div");row.className="row";row.innerHTML="<b>"+tag+"</b><input id=\"rule-"+tag+"\" placeholder=\"备用规则 URL\" value=\""+((d.backups||{})[tag]||"")+"\"><input id=\"hours-"+tag+"\" type=\"number\" min=\"1\" max=\"168\" value=\""+(d.update_hours||6)+"\"><button class=\"primary\">更新</button>";row.querySelector("button").onclick=function(){updateRule(tag)};box.appendChild(row)})}async function updateRule(tag){let r=await api("/api/rules/update",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({Tag:tag})});alert(r.ok?"规则更新成功":await r.text())}function renderSelectors(s){let n=document.getElementById("activeNode");n.innerHTML="";(s.nodes||[]).forEach(function(x){let o=document.createElement("option");o.value=x.id;o.textContent=(x.name||"未命名")+" ["+x.type+"]";o.selected=x.id===s.selected_node;n.appendChild(o)});document.getElementById("subscriptionList").textContent=(s.subscription_urls||[]).join("\n")||"暂无订阅";document.getElementById("updateHours").value=s.update_hours||6;document.getElementById("logLevel").value=s.log_level||"info"}async function selectNode(){let r=await api("/api/node/select",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ID:document.getElementById("activeNode").value})});alert(r.ok?"节点切换成功":await r.text());state()}async function netTest(t,b){let old=b.textContent;b.textContent="测试中";let r=await api("/api/network/test?target="+t);if(r.ok){let d=await r.json();b.textContent=old+" "+d.ms+"ms"}else{b.textContent=old+" 失败"}}async function updateSubscriptions(){let r=await api("/api/subscription/update",{method:"POST"});alert(r.ok?"订阅更新成功":await r.text());state()}async function saveSchedule(){let r=await api("/api/subscription/schedule",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({Hours:+document.getElementById("updateHours").value})});alert(r.ok?"更新间隔已保存":await r.text());state()}async function saveLogLevel(){let r=await api("/api/log/level",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({Level:document.getElementById("logLevel").value})});alert(r.ok?"日志级别已应用":await r.text())}function exportLogs(){window.open("/api/logs?download=1","_blank")}async function clearLogs(){let r=await api("/api/log/clear",{method:"POST"});if(r.ok){document.getElementById("logOut").textContent=""}else{alert(await r.text())}}async function updateCore(c,a){let r=await api('/api/core/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Core:c,Action:a})});$('coreVersion').textContent=await r.text()}state();</script></body></html>`
