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
	case "/api/logs":
		run(w, "journalctl", "-u", "armwall-sing-box.service", "-n", "120", "--no-pager")
	case "/api/gateway/status":
		run(w, "/usr/local/bin/armwall-gateway", "status")
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
		var host string
		for _, n := range s.Nodes {
			if n.ID == v.ID {
				host = n.Server
				break
			}
		}
		if host == "" {
			http.Error(w, "node not found", 404)
			return
		}
		run(w, "ping", "-c", "3", "-W", "2", host)
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

var indexHTML2 = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ArmWall</title><style>
:root{font:14px system-ui,sans-serif;color:#202735;background:#eef1f5}*{box-sizing:border-box}body{margin:0}.top{height:58px;background:#172335;color:#fff;display:flex;align-items:center;padding:0 24px;gap:28px}.brand{font-size:20px;font-weight:650}.top small{color:#aebbd0}.layout{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:calc(100vh - 58px)}aside{background:#fff;border-right:1px solid #d9dee7;padding:18px 12px}aside button{display:block;width:100%;text-align:left;border:0;background:transparent;padding:11px 13px;color:#4b5667;border-radius:5px;cursor:pointer}aside button.active,aside button:hover{background:#e8edf6;color:#1c4c98;font-weight:600}.main{padding:24px;max-width:1200px;width:100%}.view{display:none}.view.active{display:block}.title{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.title h1{font-size:23px;margin:0}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.card{background:#fff;border:1px solid #d9dee7;border-radius:6px;padding:17px}.card h3{margin:0 0 12px;font-size:15px}.metric{font-size:25px;font-weight:650}.muted{color:#687487}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}label{display:block;color:#5c6879;font-size:13px;margin:12px 0 5px}input,select,textarea{border:1px solid #cbd3df;border-radius:4px;padding:9px;background:#fff;min-width:180px}textarea{width:100%;min-height:85px}button.primary,button.danger{border:0;border-radius:4px;padding:9px 14px;color:#fff;cursor:pointer}button.primary{background:#2765b8}button.danger{background:#b84a4a}table{border-collapse:collapse;width:100%;background:#fff}th,td{padding:10px;border-bottom:1px solid #e5e8ee;text-align:left}th{background:#f7f8fa;color:#566275;font-weight:600}pre{white-space:pre-wrap;background:#172335;color:#d8e2f2;padding:12px;border-radius:4px;min-height:50px}.status{display:inline-block;border-radius:10px;padding:3px 9px;background:#e4f5e9;color:#18753a;font-size:12px}@media(max-width:760px){.layout{grid-template-columns:1fr}aside{display:flex;overflow:auto;border-right:0;border-bottom:1px solid #d9dee7}.grid{grid-template-columns:1fr}.main{padding:15px}}
</style></head><body><header class="top"><span class="brand">ArmWall</span><small>Armbian proxy gateway</small><span style="margin-left:auto" id="badge">未连接</span></header><div class="layout"><aside><button class="active" data-tab="dashboard">概览</button><button data-tab="nodes">节点管理</button><button data-tab="subscriptions">订阅管理</button><button data-tab="routing">分流与 DNS</button><button data-tab="service">服务与组件</button><button data-tab="logs">运行日志</button></aside><main class="main"><section id="dashboard" class="view active"><div class="title"><h1>概览</h1><button class="primary" onclick="service('start')">启动 / 重启</button></div><div class="grid"><div class="card"><h3>代理服务</h3><div class="metric" id="svc">检查中</div><p class="muted">mixed SOCKS5 / HTTP · 11080</p></div><div class="card"><h3>节点数量</h3><div class="metric" id="nodeCount">-</div><p class="muted">当前配置中的出站节点</p></div><div class="card"><h3>运行模式</h3><div class="metric" id="modeText">-</div><p class="muted">可在“分流与 DNS”中调整</p></div></div><div class="card" style="margin-top:14px"><h3>快速连接</h3><p>SOCKS5 / HTTP mixed：<code>192.168.10.217:11080</code></p><p class="muted">透明网关端口：11081（需要手动启用 nftables 网关规则）</p></div></section><section id="nodes" class="view"><div class="title"><h1>节点管理</h1><button class="primary" onclick="document.getElementById('nodeForm').hidden=!document.getElementById('nodeForm').hidden">添加节点</button></div><div class="card" id="nodeForm" hidden><div class="row"><input id="nName" placeholder="备注名称"><select id="nType"><option>vless</option><option>trojan</option><option>hysteria2</option><option>anytls</option><option>vmess</option></select><input id="nServer" placeholder="服务器地址"><input id="nPort" type="number" value="443"><input id="nSecret" placeholder="UUID / 密码"></div><button class="primary" onclick="addNode()">保存节点</button></div><div class="card" style="margin-top:14px;padding:0;overflow:auto"><table><thead><tr><th>备注</th><th>协议</th><th>服务器</th><th>端口</th><th>操作</th></tr></thead><tbody id="nodesTable"></tbody></table></div></section><section id="subscriptions" class="view"><div class="title"><h1>订阅管理</h1></div><div class="card"><label>HTTPS 订阅地址</label><input id="subURL" style="width:75%" placeholder="https://..."><div class="row"><button class="primary" onclick="importSubscription()">立即更新并导入</button><span class="muted">更新成功后会自动生成并校验 sing-box 配置</span></div></div></section><section id="routing" class="view"><div class="title"><h1>分流与 DNS</h1><button class="primary" onclick="saveRouting()">保存并重启</button></div><div class="card"><label>代理模式</label><select id="routeMode"><option value="bypass_cn">绕过国内：国内直连，其余代理</option><option value="gfw">GFW：规则匹配代理，其余直连</option><option value="global">全局代理</option></select><label>DNS 说明</label><p class="muted">当前使用 sing-box DNS 和远程 GeoIP/Geosite 规则集。透明网关部署时请将客户端 DNS 指向本机。</p><label>透明网关</label><div class="row"><button class="primary" onclick="gateway('status')">查看状态</button><button class="danger" onclick="gateway('disable')">关闭网关规则</button><span class="muted">启用前请确认 LAN/WAN 接口，避免影响现有网络。</span></div><pre id="gatewayOut"></pre></div></section><section id="service" class="view"><div class="title"><h1>服务与组件</h1></div><div class="grid"><div class="card"><h3>ArmWall Web</h3><span class="status">运行中</span><p class="muted">systemd · :8080</p></div><div class="card"><h3>sing-box</h3><p id="coreVersion">检查中</p><button class="primary" onclick="updateCore('sing-box','version')">检查版本</button><button class="primary" onclick="updateCore('sing-box','latest')">更新</button></div><div class="card"><h3>代理服务</h3><button class="primary" onclick="service('start')">启动</button><button class="danger" onclick="service('stop')">停止</button><p id="serviceOut" class="muted"></p></div></div></section><section id="logs" class="view"><div class="title"><h1>运行日志</h1><button class="primary" onclick="service('status')">刷新状态</button></div><pre id="logOut">点击服务状态按钮查看 sing-box 状态。</pre></section><pre id="out" style="margin-top:16px"></pre></main></div><script>
const $=id=>document.getElementById(id);let token=localStorage.armwallToken||'';function api(path,opt={}){opt.headers=Object.assign({},opt.headers,{'Authorization':'Bearer '+token});return fetch(path,opt)}function show(msg){$('out').textContent=typeof msg==='string'?msg:JSON.stringify(msg,null,2)}document.querySelectorAll('aside button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));document.querySelectorAll('aside button').forEach(x=>x.classList.remove('active'));$(b.dataset.tab).classList.add('active');b.classList.add('active')});async function state(){let r=await api('/api/state');if(r.status===401){token=prompt('请输入 ArmWall 管理 Token')||'';localStorage.armwallToken=token;r=await api('/api/state')}let s=await r.json();$('nodeCount').textContent=(s.nodes||[]).length;$('modeText').textContent={bypass_cn:'绕过国内',gfw:'GFW 模式',global:'全局代理'}[s.mode]||s.mode;$('routeMode').value=s.mode;renderNodes(s.nodes||[]);$('badge').textContent='已连接';service('status')}function renderNodes(ns){let b=document.getElementById("nodesTable");b.textContent="";ns.forEach(function(n){let r=b.insertRow();[n.Name||n.name||"未命名",n.Type||n.type,n.Server||n.server,n.Port||n.port].forEach(function(v){r.insertCell().textContent=v});let c=r.insertCell(),x=document.createElement("button");x.className="danger";x.textContent="删除";x.onclick=function(){deleteNode(n.ID||n.id)};c.appendChild(x)})}function esc(x){return String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function service(a){let r=await api('/api/service/'+a,{method:'POST'});let t=await r.text();$('svc').textContent=t.trim()||'已提交';$('serviceOut').textContent=t;$('logOut').textContent=t}async function addNode(){let d={Name:$('nName').value,Type:$('nType').value,Server:$('nServer').value,Port:+$('nPort').value,UUID:$('nSecret').value,TLS:true};let r=await api('/api/node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});show(await r.text());state()}async function importSubscription(){let r=await api('/api/subscription',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({URL:$('subURL').value})});show(await r.text());state()}async function saveRouting(){let r=await api('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Mode:$('routeMode').value})});show(await r.text());state()}async function deleteNode(id){let r=await api('/api/node/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ID:id})});show(await r.text());state()}async function gateway(a){let r=await api("/api/gateway/"+a,{method:a==="status"?"GET":"POST"});document.getElementById("gatewayOut").textContent=await r.text()}async function refreshLogs(){let r=await api("/api/logs");document.getElementById("logOut").textContent=await r.text()}async function updateCore(c,a){let r=await api('/api/core/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Core:c,Action:a})});$('coreVersion').textContent=await r.text()}state();</script></body></html>`
