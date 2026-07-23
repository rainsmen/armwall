package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
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
	ID, Name, Type, Server, UUID, Password string
	Port                                   int
	TLS                                    bool
	ServerName                             string
	Insecure                               bool
}
type Store struct {
	Nodes            []Node   `json:"nodes"`
	SubscriptionURLs []string `json:"subscription_urls"`
	Mode             string   `json:"mode"`
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
		out = append(out, n)
	}
	return out
}

var mu sync.Mutex
var dataPath = "/var/lib/armwall/store.json"
var configPath = "/etc/armwall/sing-box.json"
var proxyPort = 1080
var tproxyEnabled bool
var tproxyPort = 11081

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
		if n.TLS {
			serverName := n.ServerName
			if serverName == "" {
				serverName = n.Server
			}
			o["tls"] = map[string]any{"enabled": true, "server_name": serverName, "insecure": n.Insecure}
		}
		outs = append(outs, o)
	}
	proxy := "direct"
	if len(s.Nodes) > 0 {
		proxy = s.Nodes[0].ID
	}
	rules := []any{map[string]any{"ip_is_private": true, "outbound": "direct"}, map[string]any{"rule_set": []string{"geosite-ads"}, "outbound": "block"}}
	ruleSets := []any{map[string]any{"type": "remote", "tag": "geosite-ads", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs", "download_detour": "direct"}}
	final := proxy
	switch s.Mode {
	case "bypass_cn":
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-cn", "geoip-cn"}, "outbound": "direct"})
		ruleSets = append(ruleSets, map[string]any{"type": "remote", "tag": "geosite-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "direct"}, map[string]any{"type": "remote", "tag": "geoip-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "direct"})
	case "gfw":
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-proxy"}, "outbound": proxy})
		ruleSets = append(ruleSets, map[string]any{"type": "remote", "tag": "geosite-proxy", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs", "download_detour": "direct"})
		final = "direct"
	}
	inbounds := []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": proxyPort}}
	if tproxyEnabled {
		inbounds = append(inbounds, map[string]any{"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": tproxyPort})
	}
	return map[string]any{"log": map[string]any{"level": "info"}, "inbounds": inbounds, "outbounds": outs, "route": map[string]any{"auto_detect_interface": true, "rules": rules, "rule_set": ruleSets, "final": final}}
}
func writeConfig(s Store) error {
	b, _ := json.MarshalIndent(config(s), "", "  ")
	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		return err
	}
	return os.WriteFile(configPath, b, 0640)
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
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = writeConfig(s)
		json.NewEncoder(w).Encode(n)
	case "/api/node/delete":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
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
		resp, err := http.Get(v.URL)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if resp.StatusCode >= 300 {
			http.Error(w, "subscription http error", 502)
			return
		}
		nodes := parseSubscription(string(body))
		if len(nodes) == 0 {
			http.Error(w, "no supported nodes", 422)
			return
		}
		s.Nodes = append(s.Nodes, nodes...)
		s.SubscriptionURLs = append(s.SubscriptionURLs, v.URL)
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
	case "/api/mode":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Mode string }
		json.NewDecoder(r.Body).Decode(&v)
		s.Mode = v.Mode
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := writeConfig(s); err != nil {
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
	default:
		http.NotFound(w, r)
	}
}
func page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	template.Must(template.New("p").Parse(indexHTML)).Execute(w, nil)
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
