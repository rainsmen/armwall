package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type Node struct {
	ID, Name, Type, Server, UUID, Password string
	Port                                   int
	TLS                                    bool
}
type Store struct {
	Nodes            []Node   `json:"nodes"`
	SubscriptionURLs []string `json:"subscription_urls"`
	Mode             string   `json:"mode"`
}

var mu sync.Mutex
var dataPath = "/var/lib/armwall/store.json"

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
			o["tls"] = map[string]any{"enabled": true, "server_name": n.Server}
		}
		outs = append(outs, o)
	}
	return map[string]any{"log": map[string]any{"level": "info"}, "inbounds": []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 1080}}, "outbounds": outs, "route": map[string]any{"auto_detect_interface": true, "final": "direct"}}
}
func writeConfig(s Store) error {
	b, _ := json.MarshalIndent(config(s), "", "  ")
	if err := os.MkdirAll("/etc/armwall", 0750); err != nil {
		return err
	}
	return os.WriteFile("/etc/armwall/sing-box.json", b, 0640)
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
	case "/api/mode":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ Mode string }
		json.NewDecoder(r.Body).Decode(&v)
		s.Mode = v.Mode
		save(s)
		writeConfig(s)
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
	http.HandleFunc("/api/", api)
	http.HandleFunc("/", page)
	addr := os.Getenv("ARMWALL_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	log.Printf("armwall listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

var indexHTML = `<!doctype html><html><head><meta charset="utf-8"><title>ArmWall</title><style>body{font:15px sans-serif;max-width:900px;margin:32px auto;padding:0 16px;background:#f5f6f8}section{background:#fff;padding:20px;margin:14px 0;border:1px solid #ddd}input,select,button{padding:8px;margin:4px}button{cursor:pointer}</style></head><body><h1>ArmWall</h1><section><h2>服务</h2><button onclick="svc('start')">启动/重启</button><button onclick="svc('stop')">停止</button><button onclick="svc('status')">状态</button><pre id="out"></pre></section><section><h2>分流模式</h2><select id="mode"><option value="bypass_cn">绕过国内</option><option value="gfw">GFW 模式</option><option value="global">全局代理</option></select><button onclick="mode()">保存</button></section><section><h2>添加节点</h2><input id="name" placeholder="名称"><input id="server" placeholder="服务器"><input id="port" type="number" value="443" placeholder="端口"><input id="uuid" placeholder="UUID"><select id="type"><option>vless</option><option>trojan</option><option>shadowsocks</option></select><button onclick="add()">添加</button></section><section><h2>本机代理</h2><p>SOCKS5/HTTP mixed: <code>Armbian_IP:1080</code></p></section><script>async function svc(x){let r=await fetch('/api/service/'+x,{method:'POST'});out.textContent=await r.text()}async function add(){let d={name:name.value,server:server.value,port:+port.value,uuid:uuid.value,type:type.value,tls:true};let r=await fetch('/api/node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});out.textContent=await r.text()}async function mode(){let r=await fetch('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode.value})});out.textContent=await r.text()}</script></body></html>`
