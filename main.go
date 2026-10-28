package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

type Node struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Server           string `json:"server"`
	UUID             string `json:"uuid"`
	Password         string `json:"password"`
	Port             int    `json:"port"`
	TLS              bool   `json:"tls"`
	ServerName       string `json:"server_name"`
	Insecure         bool   `json:"insecure"`
	Username         string `json:"username"`
	Method           string `json:"method"`
	Security         string `json:"security"`
	AlterID          int    `json:"alter_id"`
	Flow             string `json:"flow"`
	Transport        string `json:"transport"`
	Host             string `json:"host"`
	Path             string `json:"path"`
	ServiceName      string `json:"service_name"`
	ALPN             string `json:"alpn"`
	Fingerprint      string `json:"fingerprint"`
	RealityPublicKey string `json:"reality_public_key"`
	RealityShortID   string `json:"reality_short_id"`
	Obfs             string `json:"obfs"`
	ObfsPassword     string `json:"obfs_password"`
	UpMbps           int    `json:"up_mbps"`
	DownMbps         int    `json:"down_mbps"`
	Plugin           string `json:"plugin"`
	PluginOpts       string `json:"plugin_opts"`
	Group            string `json:"group"`
	SubscriptionID   string `json:"subscription_id"`
	Enabled          bool   `json:"enabled"`
	SortOrder        int    `json:"sort_order"`
}

type StrategyGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	NodeIDs     []string `json:"node_ids"`
	Selected    string   `json:"selected"`
	TestURL     string   `json:"test_url"`
	IntervalSec int      `json:"interval_sec"`
	ToleranceMS int      `json:"tolerance_ms"`
}

type ACLRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	SourceCIDRs []string `json:"source_cidrs"`
	SourceMACs  []string `json:"source_macs"`
	Network     string   `json:"network"`
	PortRanges  []string `json:"port_ranges"`
	Outbound    string   `json:"outbound"`
}

type macACLBinding struct {
	ACLID      string
	Tag        string
	Port       int
	MACs       []string
	Network    string
	PortRanges []string
	Outbound   string
}

type naiveBinding struct {
	Node   Node
	Port   int
	Config string
}

type DNSSettings struct {
	Enabled       bool   `json:"enabled"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
	RemoteServer  string `json:"remote_server"`
	RemoteSNI     string `json:"remote_sni"`
	DirectServer  string `json:"direct_server"`
	Strategy      string `json:"strategy"`
	Hijack        bool   `json:"hijack"`
	FakeIP        bool   `json:"fake_ip"`
}

type RuleUpdateSetting struct {
	BackupURL   string    `json:"backup_url"`
	AutoUpdate  bool      `json:"auto_update"`
	UpdateHours int       `json:"update_hours"`
	LastUpdated time.Time `json:"last_updated"`
}

type Store struct {
	Nodes            []Node                       `json:"nodes"`
	SubscriptionURLs []string                     `json:"subscription_urls"`
	Mode             string                       `json:"mode"`
	ProxyPort        int                          `json:"proxy_port"`
	SelectedNode     string                       `json:"selected_node"`
	UpdateHours      int                          `json:"update_hours"`
	LogLevel         string                       `json:"log_level"`
	RuleUpdateHours  int                          `json:"rule_update_hours"`
	RuleBackups      map[string]string            `json:"rule_backups"`
	RuleSettings     map[string]RuleUpdateSetting `json:"rule_settings"`
	Subscriptions    []Subscription               `json:"subscriptions"`
	StrategyGroups   []StrategyGroup              `json:"strategy_groups"`
	TCPOutbound      string                       `json:"tcp_outbound"`
	UDPOutbound      string                       `json:"udp_outbound"`
	ACLRules         []ACLRule                    `json:"acl_rules"`
	DNS              DNSSettings                  `json:"dns"`
	AdBlockEnabled   *bool                        `json:"ad_block_enabled,omitempty"`
}

func decodeBase64(raw string) ([]byte, bool) {
	raw = strings.TrimSpace(raw)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(raw); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func anyInt(value any) int {
	switch typed := value.(type) {
	case string:
		parsed, _ := strconv.Atoi(typed)
		return parsed
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	default:
		return 0
	}
}

func parseVMessLink(line string) (Node, bool) {
	decoded, ok := decodeBase64(strings.TrimPrefix(line, "vmess://"))
	if !ok {
		return Node{}, false
	}
	var value struct {
		PS, Add, ID, TLS, SNI, Net, Host, Path, Scy, FP, ALPN string
		Port, Aid                                             any
	}
	if json.Unmarshal(decoded, &value) != nil {
		return Node{}, false
	}
	node := Node{
		ID:          fmt.Sprintf("sub-%d", time.Now().UnixNano()),
		Name:        value.PS,
		Type:        "vmess",
		Server:      value.Add,
		Port:        anyInt(value.Port),
		UUID:        value.ID,
		Security:    value.Scy,
		AlterID:     anyInt(value.Aid),
		TLS:         value.TLS != "" && !strings.EqualFold(value.TLS, "none"),
		ServerName:  value.SNI,
		Transport:   value.Net,
		Host:        value.Host,
		Path:        value.Path,
		ServiceName: value.Path,
		ALPN:        value.ALPN,
		Fingerprint: value.FP,
		Enabled:     true,
	}
	if node.Security == "" {
		node.Security = "auto"
	}
	if node.Name == "" {
		node.Name = node.Server
	}
	return node, node.Server != "" && node.Port > 0 && node.UUID != ""
}

func parseShadowsocksLink(line string) (Node, bool) {
	raw := strings.TrimPrefix(line, "ss://")
	raw = strings.TrimPrefix(raw, "shadowsocks://")
	fragment := ""
	if index := strings.Index(raw, "#"); index >= 0 {
		fragment, _ = url.QueryUnescape(raw[index+1:])
		raw = raw[:index]
	}
	if !strings.Contains(raw, "@") {
		encoded := raw
		query := ""
		if index := strings.Index(encoded, "?"); index >= 0 {
			query = encoded[index:]
			encoded = encoded[:index]
		}
		if decoded, ok := decodeBase64(encoded); ok {
			raw = string(decoded) + query
		}
	}
	parsed, err := url.Parse("ss://" + raw)
	if err != nil || parsed.Hostname() == "" || parsed.User == nil {
		return Node{}, false
	}
	method := parsed.User.Username()
	password, hasPassword := parsed.User.Password()
	if !hasPassword {
		if decoded, ok := decodeBase64(method); ok {
			credentials := string(decoded)
			if index := strings.Index(credentials, ":"); index > 0 {
				method, password = credentials[:index], credentials[index+1:]
				hasPassword = true
			}
		}
	}
	port, _ := strconv.Atoi(parsed.Port())
	if !hasPassword || method == "" || password == "" || port == 0 {
		return Node{}, false
	}
	node := Node{ID: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Name: fragment, Type: "shadowsocks", Server: parsed.Hostname(), Port: port, Method: method, Password: password, Enabled: true}
	plugin := parsed.Query().Get("plugin")
	if plugin != "" {
		parts := strings.Split(plugin, ";")
		node.Plugin = parts[0]
		if len(parts) > 1 {
			node.PluginOpts = strings.Join(parts[1:], ";")
		}
	}
	if node.Name == "" {
		node.Name = node.Server
	}
	return node, true
}

func parseSubscription(raw string) []Node {
	if decoded, ok := decodeBase64(raw); ok && strings.Contains(string(decoded), "://") {
		raw = string(decoded)
	}
	var out []Node
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "vmess://") {
			if node, ok := parseVMessLink(line); ok {
				out = append(out, node)
				continue
			}
		}
		if strings.HasPrefix(line, "ss://") || strings.HasPrefix(line, "shadowsocks://") {
			if node, ok := parseShadowsocksLink(line); ok {
				out = append(out, node)
				continue
			}
		}
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if u.Scheme != "vless" && u.Scheme != "trojan" && u.Scheme != "hysteria2" && u.Scheme != "hy2" && u.Scheme != "anytls" && u.Scheme != "naive" && u.Scheme != "naive+https" && u.Scheme != "naive+quic" {
			continue
		}
		nodeType := u.Scheme
		if nodeType == "hy2" {
			nodeType = "hysteria2"
		}
		naiveTransport := ""
		if strings.HasPrefix(nodeType, "naive+") {
			naiveTransport = strings.TrimPrefix(nodeType, "naive+")
			nodeType = "naive"
		}
		tlsEnabled := nodeType == "trojan" || nodeType == "hysteria2" || nodeType == "anytls" || nodeType == "naive"
		security := strings.ToLower(u.Query().Get("security"))
		if security == "tls" || security == "reality" || u.Query().Get("tls") == "1" {
			tlsEnabled = true
		}
		n := Node{ID: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Name: u.Fragment, Type: nodeType, Server: u.Hostname(), TLS: tlsEnabled, Enabled: true, Transport: naiveTransport}
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
		if transport := u.Query().Get("type"); transport != "" {
			n.Transport = transport
		}
		n.Host = u.Query().Get("host")
		n.Path = u.Query().Get("path")
		n.ServiceName = u.Query().Get("serviceName")
		if n.ServiceName == "" {
			n.ServiceName = u.Query().Get("service_name")
		}
		n.Flow = u.Query().Get("flow")
		n.ALPN = u.Query().Get("alpn")
		n.Fingerprint = u.Query().Get("fp")
		n.RealityPublicKey = u.Query().Get("pbk")
		n.RealityShortID = u.Query().Get("sid")
		n.Obfs = u.Query().Get("obfs")
		n.ObfsPassword = u.Query().Get("obfs-password")
		if n.ObfsPassword == "" {
			n.ObfsPassword = u.Query().Get("obfs_password")
		}
		n.UpMbps, _ = strconv.Atoi(u.Query().Get("upmbps"))
		n.DownMbps, _ = strconv.Atoi(u.Query().Get("downmbps"))
		if n.Type == "naive" {
			n.Username = n.UUID
			n.UUID = ""
		}
		if n.Name == "" {
			n.Name = n.Server
		}
		out = append(out, n)
	}
	return out
}

func fetchSubscription(rawURL string) ([]Node, error) {
	if !httpsURL(rawURL) {
		return nil, fmt.Errorf("subscription must use https")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		body, err := downloadResource(rawURL, 4<<20, 20*time.Second)
		if err != nil {
			lastErr = err
		} else if nodes := parseSubscription(string(body)); len(nodes) > 0 {
			return nodes, nil
		} else {
			lastErr = fmt.Errorf("no supported nodes")
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
		}
	}
	return nil, lastErr
}

var fetchSubscriptionFn = fetchSubscription

func updateSubscriptions() error {
	return withStoreFileLock(func() error {
		return updateSubscriptionsWithForceLocked(false)
	})
}

func subscriptionNodeKey(node Node) string {
	node.ID = ""
	node.Name = ""
	node.Group = ""
	node.SubscriptionID = ""
	node.Enabled = false
	node.SortOrder = 0
	payload, _ := json.Marshal(node)
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func reconcileSubscriptionNodes(existing, fetched []Node, sub Subscription) []Node {
	previous := map[string][]Node{}
	usedIDs := map[string]bool{}
	for _, node := range existing {
		usedIDs[node.ID] = true
		if node.SubscriptionID == sub.ID {
			key := subscriptionNodeKey(node)
			previous[key] = append(previous[key], node)
		}
	}
	occurrences := map[string]int{}
	for i := range fetched {
		key := subscriptionNodeKey(fetched[i])
		fetched[i].SubscriptionID = sub.ID
		fetched[i].Group = sub.Name
		if matches := previous[key]; len(matches) > 0 {
			fetched[i].ID = matches[0].ID
			fetched[i].Enabled = matches[0].Enabled
			previous[key] = matches[1:]
			continue
		}
		fetched[i].Enabled = true
		baseID := fmt.Sprintf("sub-%x", sha256.Sum256([]byte(sub.ID+":"+key)))[:24]
		candidate := baseID
		for usedIDs[candidate] {
			occurrences[baseID]++
			candidate = fmt.Sprintf("%s-%d", baseID, occurrences[baseID]+1)
		}
		fetched[i].ID = candidate
		usedIDs[candidate] = true
	}
	return fetched
}

func subscriptionDue(sub Subscription, now time.Time) bool {
	hours := sub.UpdateHours
	if hours < 1 {
		hours = 6
	}
	return sub.LastUpdated.IsZero() || now.Sub(sub.LastUpdated) >= time.Duration(hours)*time.Hour
}

func updateSubscriptionsWithForce(force bool) error {
	return withStoreFileLock(func() error {
		return updateSubscriptionsWithForceLocked(force)
	})
}

func updateSubscriptionsWithForceLocked(force bool) error {
	s, err := loadStore()
	if err != nil {
		return err
	}
	wasRunning := proxyRunningFn()
	if len(s.Subscriptions) == 0 {
		s = migrateLegacy(s)
	}
	fetchedBySub := map[string][]Node{}
	errors := make([]string, 0)
	now := time.Now()
	for i := range s.Subscriptions {
		sub := &s.Subscriptions[i]
		if !sub.Enabled {
			continue
		}
		if !force && !subscriptionDue(*sub, now) {
			continue
		}
		fetched, err := fetchSubscriptionFn(sub.URL)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", sub.Name, err))
			continue
		}
		fetched = reconcileSubscriptionNodes(s.Nodes, fetched, *sub)
		fetchedBySub[sub.ID] = fetched
		sub.LastUpdated = now
	}
	if len(s.Subscriptions) == 0 {
		return fmt.Errorf("no subscriptions configured")
	}
	if len(fetchedBySub) == 0 {
		if len(errors) > 0 {
			return fmt.Errorf("%s", strings.Join(errors, "; "))
		}
		return nil
	}
	kept := make([]Node, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		if _, ok := fetchedBySub[n.SubscriptionID]; !ok {
			kept = append(kept, n)
		}
	}
	for _, sub := range s.Subscriptions {
		kept = append(kept, fetchedBySub[sub.ID]...)
	}
	s.Nodes = kept
	s.SubscriptionURLs = nil
	for _, sub := range s.Subscriptions {
		s.SubscriptionURLs = append(s.SubscriptionURLs, sub.URL)
	}
	if err := writeConfig(s); err != nil {
		return err
	}
	if err := save(s); err != nil {
		return err
	}
	if wasRunning {
		if err := restartProxyFn(); err != nil {
			return err
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

var mu sync.Mutex
var dataPath = "/var/lib/armwall/store.json"
var configPath = "/etc/armwall/sing-box.json"
var macACLPath = "/etc/armwall/mac-acl.tsv"
var naiveConfigDir = "/etc/armwall/naive"
var logDir = "/var/log/armwall"
var gatewayPath = "/usr/local/bin/armwall-gateway"
var gatewayStatePath = "/var/lib/armwall/gateway.state"
var proxyPort = 1080
var tproxyEnabled bool
var tproxyPort = 11081
var naiveProxyPort = 12000
var clashAPISecret string
var clashSecretMu sync.Mutex

const (
	maxAPIJSONBodySize       = 1 << 20
	minAuthTokenLength       = 16
	defaultWebListenLocal    = "127.0.0.1:8080"
	defaultWebListenLAN      = "0.0.0.0:8080"
	defaultWebAllowedPrivate = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
)

type webAccessConfig struct {
	Mode            string
	ListenAddress   string
	AllowedPrefixes []netip.Prefix
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func ensureDefaultBool(value **bool, fallback bool) {
	if *value == nil {
		v := fallback
		*value = &v
	}
}

func storeLockFile() string {
	if path := os.Getenv("ARMWALL_LOCK"); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(dbPath), "armwall.lock")
}

func lockStoreFile() (func(), error) {
	path := storeLockFile()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	unlock := func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
	return unlock, nil
}

func withStoreFileLock(fn func() error) error {
	unlock, err := lockStoreFile()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func clashSecretFile() string {
	if path := os.Getenv("ARMWALL_CLASH_SECRET_FILE"); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(configPath), "clash.secret")
}

func currentClashAPISecret() string {
	if secret := strings.TrimSpace(os.Getenv("ARMWALL_CLASH_SECRET")); secret != "" {
		return secret
	}
	clashSecretMu.Lock()
	defer clashSecretMu.Unlock()
	if clashAPISecret != "" {
		return clashAPISecret
	}
	data, err := os.ReadFile(clashSecretFile())
	if err == nil {
		clashAPISecret = strings.TrimSpace(string(data))
	}
	return clashAPISecret
}

func ensureClashAPISecret() (string, error) {
	if secret := strings.TrimSpace(os.Getenv("ARMWALL_CLASH_SECRET")); secret != "" {
		clashSecretMu.Lock()
		clashAPISecret = secret
		clashSecretMu.Unlock()
		return secret, nil
	}
	clashSecretMu.Lock()
	defer clashSecretMu.Unlock()
	if clashAPISecret != "" {
		return clashAPISecret, nil
	}
	path := clashSecretFile()
	if data, err := os.ReadFile(path); err == nil {
		if secret := strings.TrimSpace(string(data)); secret != "" {
			clashAPISecret = secret
			return secret, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}
	clashAPISecret = hex.EncodeToString(secretBytes)
	if err := writeAtomicFile(path, []byte(clashAPISecret+"\n"), 0600); err != nil {
		clashAPISecret = ""
		return "", err
	}
	return clashAPISecret, nil
}

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

func httpsURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && u.Hostname() != ""
}

func outboundHTTPClients(timeout time.Duration) []*http.Client {
	clients := make([]*http.Client, 0, 2)
	address := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		_ = conn.Close()
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: address})
		clients = append(clients, &http.Client{Transport: transport, Timeout: timeout})
	}
	direct := http.DefaultTransport.(*http.Transport).Clone()
	direct.Proxy = nil
	return append(clients, &http.Client{Transport: direct, Timeout: timeout})
}

func downloadResource(raw string, limit int64, timeout time.Duration) ([]byte, error) {
	if !httpsURL(raw) {
		return nil, fmt.Errorf("download URL must use https")
	}
	var lastErr error
	for _, client := range outboundHTTPClients(timeout) {
		resp, err := client.Get(raw)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("http status %d", resp.StatusCode)
			continue
		}
		if int64(len(body)) > limit {
			lastErr = fmt.Errorf("download exceeds %d bytes", limit)
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("download failed")
	}
	return nil, lastErr
}

func updateRule(tag, backup string) error {
	primary, ok := ruleURLs[tag]
	if !ok {
		return fmt.Errorf("unknown rule")
	}
	backup = strings.TrimSpace(backup)
	if backup != "" && !httpsURL(backup) {
		return fmt.Errorf("backup rule URL must use https")
	}
	urls := []string{primary}
	if backup != "" {
		urls = append(urls, backup)
	}
	var last error
	for _, raw := range urls {
		body, err := downloadResource(raw, 32<<20, 30*time.Second)
		if err != nil || len(body) < 16 {
			if err == nil {
				err = fmt.Errorf("downloaded rule is empty")
			}
			last = fmt.Errorf("%s: %w", raw, err)
			continue
		}
		checkLen := len(body)
		if checkLen > 512 {
			checkLen = 512
		}
		prefix := strings.TrimSpace(string(body[:min(len(body), 64)]))
		if strings.HasPrefix(prefix, "<") || bytes.Contains(body[:checkLen], []byte("<!DOCTYPE html")) || bytes.Contains(body[:checkLen], []byte("<html")) {
			last = fmt.Errorf("%s: downloaded rule returned html error page", raw)
			continue
		}
		dir := "/var/lib/armwall/rules"
		if err = os.MkdirAll(dir, 0750); err != nil {
			return err
		}
		target := filepath.Join(dir, tag+".srs")
		bak := filepath.Join(dir, tag+".srs.bak")
		if prev, readErr := os.ReadFile(target); readErr == nil {
			_ = os.WriteFile(bak, prev, 0640)
		}
		return writeAtomicFile(target, body, 0640)
	}
	return last
}

func restoreRuleBackups(tags []string) {
	dir := "/var/lib/armwall/rules"
	for _, tag := range tags {
		bak := filepath.Join(dir, tag+".srs.bak")
		target := filepath.Join(dir, tag+".srs")
		if _, err := os.Stat(bak); err == nil {
			_ = os.Rename(bak, target)
		}
	}
}

func cleanupRuleBackups(tags []string) {
	dir := "/var/lib/armwall/rules"
	for _, tag := range tags {
		_ = os.Remove(filepath.Join(dir, tag+".srs.bak"))
	}
}

var updateRuleFn = updateRule

func normalizeRuleSettings(s *Store) {
	if s.RuleSettings == nil {
		s.RuleSettings = map[string]RuleUpdateSetting{}
	}
	if s.RuleBackups == nil {
		s.RuleBackups = map[string]string{}
	}
	legacyHours := s.RuleUpdateHours
	if legacyHours < 1 || legacyHours > 168 {
		legacyHours = 6
	}
	for tag := range ruleURLs {
		setting := s.RuleSettings[tag]
		if setting.BackupURL == "" {
			setting.BackupURL = strings.TrimSpace(s.RuleBackups[tag])
		}
		if setting.UpdateHours < 1 || setting.UpdateHours > 168 {
			setting.UpdateHours = legacyHours
		}
		s.RuleSettings[tag] = setting
		s.RuleBackups[tag] = setting.BackupURL
	}
	s.RuleUpdateHours = legacyHours
}

func ruleUpdateDue(setting RuleUpdateSetting, now time.Time) bool {
	if !setting.AutoUpdate {
		return false
	}
	hours := setting.UpdateHours
	if hours < 1 || hours > 168 {
		hours = 6
	}
	return setting.LastUpdated.IsZero() || now.Sub(setting.LastUpdated) >= time.Duration(hours)*time.Hour
}

func updateConfiguredRules(s *Store, force bool, onlyTag string, now time.Time) ([]string, error) {
	normalizeRuleSettings(s)
	if onlyTag != "" {
		if _, ok := ruleURLs[onlyTag]; !ok {
			return nil, fmt.Errorf("unknown rule")
		}
	}
	updated := make([]string, 0, len(ruleURLs))
	errors := make([]string, 0)
	for tag := range ruleURLs {
		if onlyTag != "" && tag != onlyTag {
			continue
		}
		setting := s.RuleSettings[tag]
		if !force && !ruleUpdateDue(setting, now) {
			continue
		}
		if err := updateRuleFn(tag, setting.BackupURL); err != nil {
			errors = append(errors, tag+": "+err.Error())
			continue
		}
		setting.LastUpdated = now
		s.RuleSettings[tag] = setting
		updated = append(updated, tag)
	}
	if len(errors) > 0 {
		return updated, fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return updated, nil
}

func applyScheduledRuleUpdates() (int, error) {
	var count int
	err := withStoreFileLock(func() error {
		updated, updateErr := applyScheduledRuleUpdatesLocked()
		count = updated
		return updateErr
	})
	return count, err
}

func applyScheduledRuleUpdatesLocked() (int, error) {
	s, err := loadStore()
	if err != nil {
		return 0, err
	}
	wasRunning := proxyRunningFn()
	updated, updateErr := updateConfiguredRules(&s, false, "", time.Now())
	if len(updated) == 0 {
		return 0, updateErr
	}
	if err := writeConfig(s); err != nil {
		restoreRuleBackups(updated)
		return 0, err
	}
	if err := save(s); err != nil {
		restoreRuleBackups(updated)
		return 0, err
	}
	if wasRunning {
		if err := restartProxy(); err != nil {
			restoreRuleBackups(updated)
			return 0, err
		}
	}
	cleanupRuleBackups(updated)
	return len(updated), updateErr
}

func loadStore() (Store, error) {
	if _, err := os.Stat(dbPath); err == nil {
		s, err := loadDB()
		if err != nil {
			return Store{}, fmt.Errorf("load SQLite store: %w", err)
		}
		normalizeStore(&s)
		return s, nil
	} else if !os.IsNotExist(err) {
		return Store{}, err
	}
	if _, err := os.Stat(dataPath); err == nil {
		legacy := migrateLegacy(loadJSON())
		normalizeStore(&legacy)
		if err := saveDB(legacy); err != nil {
			return Store{}, fmt.Errorf("migrate legacy JSON store: %w", err)
		}
		return legacy, nil
	} else if !os.IsNotExist(err) {
		return Store{}, err
	}
	s, err := loadDB()
	if err != nil {
		return Store{}, err
	}
	normalizeStore(&s)
	return s, nil
}

func load() Store {
	s, err := loadStore()
	if err != nil {
		log.Printf("cannot load store: %v", err)
		return Store{Mode: "bypass_cn"}
	}
	return s
}
func save(s Store) error {
	if err := saveDB(s); err != nil {
		return err
	}
	if err := saveJSON(s); err != nil {
		log.Printf("SQLite store saved but legacy JSON mirror could not be updated: %v", err)
	}
	return nil
}

func normalizeStore(s *Store) {
	normalizeRuleSettings(s)
	ensureDefaultBool(&s.AdBlockEnabled, true)
	s.SubscriptionURLs = s.SubscriptionURLs[:0]
	for _, sub := range s.Subscriptions {
		s.SubscriptionURLs = append(s.SubscriptionURLs, sub.URL)
	}
	selectedOK := false
	existingNodes := make(map[string]bool, len(s.Nodes))
	for i := range s.Nodes {
		s.Nodes[i].SortOrder = i
		existingNodes[s.Nodes[i].ID] = true
		if s.Nodes[i].ID == s.SelectedNode && s.Nodes[i].Enabled {
			selectedOK = true
		}
	}
	existingOutbounds := map[string]bool{"direct": true}
	for id := range existingNodes {
		existingOutbounds[id] = true
	}
	for i := range s.StrategyGroups {
		group := &s.StrategyGroups[i]
		if group.Type == "fallback" {
			group.Type = "urltest"
		}
		kept := group.NodeIDs[:0]
		seen := map[string]bool{}
		for _, id := range group.NodeIDs {
			if existingNodes[id] && !seen[id] {
				kept = append(kept, id)
				seen[id] = true
			}
		}
		group.NodeIDs = kept
		if !seen[group.Selected] {
			group.Selected = ""
			if len(group.NodeIDs) > 0 {
				group.Selected = group.NodeIDs[0]
			}
		}
		existingOutbounds[group.ID] = true
	}
	if !existingOutbounds[s.TCPOutbound] {
		s.TCPOutbound = ""
	}
	if s.UDPOutbound != "same" && !existingOutbounds[s.UDPOutbound] {
		s.UDPOutbound = ""
	}
	for i := range s.ACLRules {
		if !existingOutbounds[s.ACLRules[i].Outbound] && s.ACLRules[i].Outbound != "block" {
			s.ACLRules[i].Enabled = false
		}
	}
	if selectedOK {
		return
	}
	s.SelectedNode = ""
	for _, node := range s.Nodes {
		if node.Enabled {
			s.SelectedNode = node.ID
			break
		}
	}
}

func persistStore(next Store, reload bool) error {
	previous, err := loadStore()
	if err != nil {
		return err
	}
	wasRunning := proxyRunningFn()
	previousProxyPort := proxyPort
	normalizeStore(&next)
	if !reload {
		return save(next)
	}
	if next.ProxyPort > 0 {
		proxyPort = next.ProxyPort
	}
	prevJSON, _ := json.Marshal(config(previous))
	nextJSON, _ := json.Marshal(config(next))
	prevMAC, _ := macACLData(previous)
	nextMAC, _ := macACLData(next)
	configChanged := !bytes.Equal(prevJSON, nextJSON) || !bytes.Equal(prevMAC, nextMAC) || previousProxyPort != proxyPort

	if err := writeConfig(next); err != nil {
		proxyPort = previousProxyPort
		return err
	}
	if err := save(next); err != nil {
		proxyPort = previousProxyPort
		_ = writeConfig(previous)
		return err
	}
	if wasRunning && configChanged {
		if err := restartProxyFn(); err != nil {
			proxyPort = previousProxyPort
			_ = save(previous)
			_ = writeConfig(previous)
			_ = restartProxyFn()
			return err
		}
		if err := reloadGatewayFn(); err != nil {
			proxyPort = previousProxyPort
			_ = save(previous)
			_ = writeConfig(previous)
			_ = restartProxyFn()
			_ = reloadGatewayFn()
			return err
		}
	}
	return nil
}

func reloadGatewayIfActive() error {
	if _, err := os.Stat(gatewayStatePath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	out, err := exec.Command(gatewayPath, "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("transparent gateway reload failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

var reloadGatewayFn = reloadGatewayIfActive

func proxyRunning() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "armwall-sing-box.service").Run() == nil
}

var proxyRunningFn = proxyRunning

func validateNode(n *Node) error {
	n.Name = strings.TrimSpace(n.Name)
	n.Type = strings.ToLower(strings.TrimSpace(n.Type))
	n.Server = strings.TrimSpace(n.Server)
	n.Group = strings.TrimSpace(n.Group)
	if n.Type == "ss" {
		n.Type = "shadowsocks"
	}
	allowed := map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria2": true, "anytls": true, "naive": true}
	if !allowed[n.Type] {
		return fmt.Errorf("unsupported node type")
	}
	if n.Name == "" || n.Server == "" || n.Port < 1 || n.Port > 65535 {
		return fmt.Errorf("name, server and valid port are required")
	}
	if n.Group == "" {
		n.Group = "手动节点"
	}
	switch n.Type {
	case "vless", "vmess":
		if strings.TrimSpace(n.UUID) == "" {
			return fmt.Errorf("%s node requires uuid", n.Type)
		}
	case "trojan":
		if strings.TrimSpace(n.Password) == "" {
			return fmt.Errorf("trojan node requires password")
		}
		if !n.TLS {
			return fmt.Errorf("trojan node requires TLS")
		}
	case "shadowsocks":
		if strings.TrimSpace(n.Method) == "" || strings.TrimSpace(n.Password) == "" {
			return fmt.Errorf("shadowsocks node requires method and password")
		}
	case "hysteria2":
		if strings.TrimSpace(n.Password) == "" {
			return fmt.Errorf("hysteria2 node requires password")
		}
		if !n.TLS {
			return fmt.Errorf("hysteria2 node requires TLS")
		}
	case "anytls":
		if strings.TrimSpace(n.Password) == "" {
			return fmt.Errorf("anytls node requires password")
		}
		if !n.TLS {
			return fmt.Errorf("anytls node requires TLS")
		}
	}
	if n.Type == "naive" {
		if strings.TrimSpace(n.Username) == "" || strings.TrimSpace(n.Password) == "" {
			return fmt.Errorf("NaiveProxy node requires username and password")
		}
		if n.Transport == "" {
			n.Transport = "https"
		}
		if n.Transport != "https" && n.Transport != "quic" {
			return fmt.Errorf("NaiveProxy transport must be https or quic")
		}
	}
	if n.RealityPublicKey != "" {
		n.TLS = true
		if n.Fingerprint == "" {
			n.Fingerprint = "chrome"
		}
	}
	return nil
}

func validateStrategyGroup(group *StrategyGroup, s Store) error {
	group.Name = strings.TrimSpace(group.Name)
	group.Type = strings.ToLower(strings.TrimSpace(group.Type))
	if group.Type == "fallback" {
		group.Type = "urltest"
	}
	if group.Name == "" || (group.Type != "selector" && group.Type != "urltest") {
		return fmt.Errorf("strategy name and valid type are required")
	}
	existing := make(map[string]bool, len(s.Nodes))
	for _, node := range s.Nodes {
		existing[node.ID] = true
		if node.ID == group.ID {
			return fmt.Errorf("strategy id conflicts with node")
		}
	}
	seen := map[string]bool{}
	members := group.NodeIDs[:0]
	for _, id := range group.NodeIDs {
		if existing[id] && !seen[id] {
			members = append(members, id)
			seen[id] = true
		}
	}
	group.NodeIDs = members
	if len(group.NodeIDs) == 0 {
		return fmt.Errorf("strategy requires at least one node")
	}
	if group.Type != "selector" && len(group.NodeIDs) < 2 {
		return fmt.Errorf("automatic strategy requires at least two nodes")
	}
	if !seen[group.Selected] {
		group.Selected = group.NodeIDs[0]
	}
	if group.TestURL == "" {
		group.TestURL = "https://www.gstatic.com/generate_204"
	}
	if !strings.HasPrefix(group.TestURL, "https://") {
		return fmt.Errorf("test url must use https")
	}
	if group.IntervalSec == 0 {
		group.IntervalSec = 180
	}
	if group.IntervalSec < 10 || group.IntervalSec > 86400 || group.ToleranceMS < 0 || group.ToleranceMS > 10000 {
		return fmt.Errorf("invalid strategy interval or tolerance")
	}
	for _, existingGroup := range s.StrategyGroups {
		if existingGroup.ID != group.ID && existingGroup.Name == group.Name {
			return fmt.Errorf("strategy name already exists")
		}
	}
	return nil
}

func validOutboundTags(s Store) map[string]bool {
	valid := map[string]bool{"direct": true, "block": true}
	for _, node := range s.Nodes {
		valid[node.ID] = true
	}
	for _, group := range s.StrategyGroups {
		valid[group.ID] = true
	}
	return valid
}

func validatePortRange(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	first, err := strconv.Atoi(parts[0])
	if err != nil || first < 1 || first > 65535 {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	last, err := strconv.Atoi(parts[1])
	return err == nil && last >= first && last <= 65535
}

func splitPortMatches(values []string) ([]int, []string) {
	ports := make([]int, 0, len(values))
	ranges := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, ":") {
			ranges = append(ranges, value)
			continue
		}
		port, err := strconv.Atoi(value)
		if err == nil {
			ports = append(ports, port)
		}
	}
	return ports, ranges
}

func validateACLRule(rule *ACLRule, s Store) error {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Network = strings.ToLower(strings.TrimSpace(rule.Network))
	if rule.Name == "" || (rule.Network != "" && rule.Network != "tcp" && rule.Network != "udp") {
		return fmt.Errorf("ACL name and valid network are required")
	}
	if !validOutboundTags(s)[rule.Outbound] {
		return fmt.Errorf("ACL outbound does not exist")
	}
	cidrs := make([]string, 0, len(rule.SourceCIDRs))
	seenCIDR := map[string]bool{}
	for _, raw := range rule.SourceCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			if ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
		if _, _, err := net.ParseCIDR(raw); err != nil {
			return fmt.Errorf("invalid source CIDR: %s", raw)
		}
		if !seenCIDR[raw] {
			cidrs = append(cidrs, raw)
			seenCIDR[raw] = true
		}
	}
	rule.SourceCIDRs = cidrs
	macs := make([]string, 0, len(rule.SourceMACs))
	seenMAC := map[string]bool{}
	for _, raw := range rule.SourceMACs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		mac, err := net.ParseMAC(raw)
		if err != nil {
			return fmt.Errorf("invalid source MAC: %s", raw)
		}
		normalized := strings.ToLower(mac.String())
		if !seenMAC[normalized] {
			macs = append(macs, normalized)
			seenMAC[normalized] = true
		}
	}
	rule.SourceMACs = macs
	if len(rule.SourceCIDRs) == 0 && len(rule.SourceMACs) == 0 {
		return fmt.Errorf("ACL requires a source IP/CIDR or MAC")
	}
	ports := make([]string, 0, len(rule.PortRanges))
	for _, raw := range rule.PortRanges {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !validatePortRange(raw) {
			return fmt.Errorf("invalid destination port range: %s", raw)
		}
		ports = append(ports, raw)
	}
	rule.PortRanges = ports
	return nil
}

func validateDNSSettings(settings *DNSSettings) error {
	if !settings.Enabled {
		return nil
	}
	settings.ListenAddress = strings.TrimSpace(settings.ListenAddress)
	if settings.ListenAddress == "" {
		address, err := detectDNSListenAddress()
		if err != nil {
			return err
		}
		settings.ListenAddress = address
	}
	if net.ParseIP(settings.ListenAddress) == nil {
		return fmt.Errorf("DNS listen address must be an IP address")
	}
	if settings.ListenPort == 0 {
		settings.ListenPort = 53
	}
	if settings.ListenPort < 1 || settings.ListenPort > 65535 {
		return fmt.Errorf("invalid DNS listen port")
	}
	if settings.RemoteServer == "" {
		settings.RemoteServer = "https://1.1.1.1/dns-query"
	}
	if settings.DirectServer == "" {
		settings.DirectServer = "udp://223.5.5.5"
	}
	if settings.Strategy == "" {
		settings.Strategy = "prefer_ipv4"
	}
	validStrategy := map[string]bool{"prefer_ipv4": true, "prefer_ipv6": true, "ipv4_only": true, "ipv6_only": true}
	if !validStrategy[settings.Strategy] {
		return fmt.Errorf("invalid DNS strategy")
	}
	for _, raw := range []string{settings.RemoteServer, settings.DirectServer} {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "tls" && u.Scheme != "udp" && u.Scheme != "tcp") {
			return fmt.Errorf("invalid DNS server: %s", raw)
		}
	}
	if settings.FakeIP {
		settings.Hijack = true
	}
	return nil
}

func detectDNSListenAddress() (string, error) {
	conn, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return "", fmt.Errorf("cannot detect DNS listen address; enter the Armbian LAN IP")
	}
	defer conn.Close()
	address, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil || net.ParseIP(address) == nil {
		return "", fmt.Errorf("cannot detect DNS listen address; enter the Armbian LAN IP")
	}
	return address, nil
}

func dnsServerConfig(tag, raw, serverName, detour string) map[string]any {
	u, _ := url.Parse(raw)
	port, _ := strconv.Atoi(u.Port())
	server := map[string]any{"type": u.Scheme, "tag": tag, "server": u.Hostname()}
	switch u.Scheme {
	case "https":
		if port == 0 {
			port = 443
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/dns-query"
		}
		server["path"] = path
		if serverName == "" {
			serverName = u.Hostname()
		}
		server["tls"] = map[string]any{"enabled": true, "server_name": serverName}
	case "tls":
		if port == 0 {
			port = 853
		}
		if serverName == "" {
			serverName = u.Hostname()
		}
		server["tls"] = map[string]any{"enabled": true, "server_name": serverName}
	default:
		if port == 0 {
			port = 53
		}
	}
	server["server_port"] = port
	if detour != "" {
		server["detour"] = detour
	}
	return server
}

func macACLBindings(s Store) []macACLBinding {
	bindings := make([]macACLBinding, 0)
	for _, acl := range s.ACLRules {
		if !acl.Enabled || len(acl.SourceMACs) == 0 {
			continue
		}
		index := len(bindings) + 1
		bindings = append(bindings, macACLBinding{
			ACLID:      acl.ID,
			Tag:        fmt.Sprintf("acl-mac-%d", index),
			Port:       tproxyPort + index,
			MACs:       append([]string(nil), acl.SourceMACs...),
			Network:    acl.Network,
			PortRanges: append([]string(nil), acl.PortRanges...),
			Outbound:   acl.Outbound,
		})
	}
	return bindings
}

func naiveBindings(s Store) []naiveBinding {
	bindings := make([]naiveBinding, 0)
	for _, node := range s.Nodes {
		if !node.Enabled || node.Type != "naive" {
			continue
		}
		port := naiveProxyPort + len(bindings)
		transport := node.Transport
		if transport != "quic" {
			transport = "https"
		}
		proxy := &url.URL{Scheme: transport, Host: net.JoinHostPort(node.Server, strconv.Itoa(node.Port))}
		if node.Username != "" || node.Password != "" {
			proxy.User = url.UserPassword(node.Username, node.Password)
		}
		configData, _ := json.MarshalIndent(map[string]string{
			"listen": fmt.Sprintf("socks://127.0.0.1:%d", port),
			"proxy":  proxy.String(),
		}, "", "  ")
		bindings = append(bindings, naiveBinding{Node: node, Port: port, Config: string(configData)})
	}
	return bindings
}

func writeNaiveConfigs(s Store) error {
	parent := filepath.Dir(naiveConfigDir)
	if err := os.MkdirAll(parent, 0750); err != nil {
		return err
	}
	candidate, err := os.MkdirTemp(parent, ".naive-candidate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(candidate)
	for i, binding := range naiveBindings(s) {
		path := filepath.Join(candidate, fmt.Sprintf("%04d.json", i+1))
		if err := os.WriteFile(path, []byte(binding.Config+"\n"), 0600); err != nil {
			return err
		}
	}
	previous := naiveConfigDir + ".previous"
	_ = os.RemoveAll(previous)
	if err := os.Rename(naiveConfigDir, previous); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(candidate, naiveConfigDir); err != nil {
		_ = os.Rename(previous, naiveConfigDir)
		return err
	}
	_ = os.RemoveAll(previous)
	return nil
}

func macACLData(s Store) ([]byte, error) {
	var data strings.Builder
	for _, binding := range macACLBindings(s) {
		if binding.Port > 65535 {
			return nil, fmt.Errorf("too many MAC ACL rules for TProxy port %d", tproxyPort)
		}
		network := binding.Network
		if network == "" {
			network = "any"
		}
		ports := strings.Join(binding.PortRanges, ",")
		if ports == "" {
			ports = "any"
		}
		for _, mac := range binding.MACs {
			fmt.Fprintf(&data, "%d\t%s\t%s\t%s\n", binding.Port, mac, network, ports)
		}
	}
	return []byte(data.String()), nil
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func config(s Store) map[string]any {
	outs := []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "block", "tag": "block"}}
	naivePorts := map[string]int{}
	for _, binding := range naiveBindings(s) {
		naivePorts[binding.Node.ID] = binding.Port
	}
	nodeTags := map[string]bool{}
	for _, n := range s.Nodes {
		if !n.Enabled {
			continue
		}
		nodeTags[n.ID] = true
		if n.Type == "naive" {
			outs = append(outs, map[string]any{"type": "socks", "tag": n.ID, "server": "127.0.0.1", "server_port": naivePorts[n.ID]})
			continue
		}
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
		if n.Type == "vmess" {
			security := n.Security
			if security == "" {
				security = "auto"
			}
			o["security"] = security
			if n.AlterID > 0 {
				o["alter_id"] = n.AlterID
			}
		} else if n.Method != "" {
			o["method"] = n.Method
		}
		if n.Type == "shadowsocks" && n.Plugin != "" {
			o["plugin"] = n.Plugin
			if n.PluginOpts != "" {
				o["plugin_opts"] = n.PluginOpts
			}
		}
		if n.Type == "hysteria2" {
			if n.Obfs != "" {
				o["obfs"] = map[string]any{"type": n.Obfs, "password": n.ObfsPassword}
			}
			if n.UpMbps > 0 {
				o["up_mbps"] = n.UpMbps
			}
			if n.DownMbps > 0 {
				o["down_mbps"] = n.DownMbps
			}
		}
		if n.Flow != "" {
			o["flow"] = n.Flow
		}
		if n.Transport != "" {
			tr := map[string]any{"type": n.Transport}
			if n.Transport == "grpc" {
				serviceName := n.ServiceName
				if serviceName == "" {
					serviceName = strings.TrimPrefix(n.Path, "/")
				}
				if serviceName != "" {
					tr["service_name"] = serviceName
				}
			} else if n.Path != "" {
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
			if n.RealityPublicKey != "" {
				if n.Fingerprint == "" {
					tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
				}
				reality := map[string]any{"enabled": true, "public_key": n.RealityPublicKey}
				if n.RealityShortID != "" {
					reality["short_id"] = n.RealityShortID
				}
				tls["reality"] = reality
			}
			o["tls"] = tls
		}
		outs = append(outs, o)
	}
	strategyTags := map[string]bool{}
	for _, group := range s.StrategyGroups {
		if group.ID == "" || group.Name == "" {
			continue
		}
		members := make([]string, 0, len(group.NodeIDs))
		for _, id := range group.NodeIDs {
			if nodeTags[id] {
				members = append(members, id)
			}
		}
		if len(members) == 0 {
			continue
		}
		groupType := group.Type
		if groupType != "selector" && groupType != "urltest" {
			continue
		}
		o := map[string]any{"type": groupType, "tag": group.ID, "outbounds": members}
		if groupType == "selector" {
			selected := group.Selected
			if !nodeTags[selected] {
				selected = members[0]
			}
			o["default"] = selected
		} else {
			testURL := group.TestURL
			if testURL == "" {
				testURL = "https://www.gstatic.com/generate_204"
			}
			interval := group.IntervalSec
			if interval < 10 {
				interval = 180
			}
			o["url"] = testURL
			o["interval"] = fmt.Sprintf("%ds", interval)
			o["tolerance"] = group.ToleranceMS
		}
		outs = append(outs, o)
		strategyTags[group.ID] = true
	}
	proxy := "direct"
	for _, n := range s.Nodes {
		if n.Enabled {
			proxy = n.ID
			break
		}
	}
	if s.SelectedNode != "" {
		for _, n := range s.Nodes {
			if n.ID == s.SelectedNode && n.Enabled {
				proxy = n.ID
				break
			}
		}
	}
	validOutbound := map[string]bool{"direct": true}
	for tag := range nodeTags {
		validOutbound[tag] = true
	}
	for tag := range strategyTags {
		validOutbound[tag] = true
	}
	chooseOutbound := func(value, fallback string) string {
		if value == "" || value == "same" || !validOutbound[value] {
			return fallback
		}
		return value
	}
	tcpOutbound := chooseOutbound(s.TCPOutbound, proxy)
	udpOutbound := chooseOutbound(s.UDPOutbound, tcpOutbound)
	rules := []any{}
	if s.DNS.Enabled {
		rules = append(rules, map[string]any{"inbound": []string{"dns-in"}, "action": "hijack-dns"})
	}
	if s.DNS.Enabled && s.DNS.Hijack {
		rules = append(rules, map[string]any{"protocol": "dns", "action": "hijack-dns"})
	}
	for _, acl := range s.ACLRules {
		if !acl.Enabled {
			continue
		}
		if len(acl.SourceCIDRs) > 0 {
			rule := map[string]any{"outbound": acl.Outbound}
			rule["source_ip_cidr"] = acl.SourceCIDRs
			if acl.Network != "" {
				rule["network"] = []string{acl.Network}
			}
			if len(acl.PortRanges) > 0 {
				ports, ranges := splitPortMatches(acl.PortRanges)
				if len(ports) > 0 {
					rule["port"] = ports
				}
				if len(ranges) > 0 {
					rule["port_range"] = ranges
				}
			}
			rules = append(rules, rule)
		}
	}
	macBindings := macACLBindings(s)
	for _, binding := range macBindings {
		rules = append(rules, map[string]any{"inbound": []string{binding.Tag}, "outbound": binding.Outbound})
	}
	rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct"})
	ruleSets := []any{}
	if boolValue(s.AdBlockEnabled, true) {
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-ads"}, "outbound": "block"})
		ruleSets = append(ruleSets, ruleSet("geosite-ads"))
	}
	final := proxy
	switch s.Mode {
	case "bypass_cn":
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-cn", "geoip-cn"}, "outbound": "direct"})
		if udpOutbound != tcpOutbound {
			rules = append(rules, map[string]any{"network": "udp", "outbound": udpOutbound})
		}
		ruleSets = append(ruleSets, ruleSet("geosite-cn"), ruleSet("geoip-cn"))
	case "gfw":
		if udpOutbound != tcpOutbound {
			rules = append(rules, map[string]any{"rule_set": []string{"geosite-proxy"}, "network": "udp", "outbound": udpOutbound}, map[string]any{"rule_set": []string{"geosite-proxy"}, "network": "tcp", "outbound": tcpOutbound})
		} else {
			rules = append(rules, map[string]any{"rule_set": []string{"geosite-proxy"}, "outbound": tcpOutbound})
		}
		ruleSets = append(ruleSets, ruleSet("geosite-proxy"))
		final = "direct"
	default:
		if udpOutbound != tcpOutbound {
			rules = append(rules, map[string]any{"network": "udp", "outbound": udpOutbound})
		}
	}
	if s.Mode != "gfw" {
		final = tcpOutbound
	}
	listenPort := proxyPort
	if s.ProxyPort > 0 {
		listenPort = s.ProxyPort
	}
	inbounds := []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": listenPort}}
	if s.DNS.Enabled {
		inbounds = append(inbounds, map[string]any{"type": "direct", "tag": "dns-in", "listen": s.DNS.ListenAddress, "listen_port": s.DNS.ListenPort})
	}
	sniffConfig := map[string]any{"enabled": true, "dest_override": []string{"http", "tls"}}
	if tproxyEnabled {
		inbounds = append(inbounds, map[string]any{"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": tproxyPort, "sniff": sniffConfig})
	}
	for _, binding := range macBindings {
		inbounds = append(inbounds, map[string]any{"type": "tproxy", "tag": binding.Tag, "listen": "0.0.0.0", "listen_port": binding.Port, "sniff": sniffConfig})
	}
	level := s.LogLevel
	if level == "" {
		level = "info"
	}
	clashAPI := map[string]any{"external_controller": "127.0.0.1:9090"}
	if secret := currentClashAPISecret(); secret != "" {
		clashAPI["secret"] = secret
	}
	result := map[string]any{"log": map[string]any{"level": level, "output": filepath.Join(logDir, "sing-box.log"), "timestamp": true}, "inbounds": inbounds, "outbounds": outs, "route": map[string]any{"auto_detect_interface": true, "rules": rules, "rule_set": ruleSets, "final": final}, "experimental": map[string]any{"clash_api": clashAPI}}
	if s.DNS.Enabled {
		remoteDetour := tcpOutbound
		if remoteDetour == "direct" {
			remoteDetour = ""
		}
		dnsServers := []any{dnsServerConfig("remote-dns", s.DNS.RemoteServer, s.DNS.RemoteSNI, remoteDetour), dnsServerConfig("direct-dns", s.DNS.DirectServer, "", "")}
		dns := map[string]any{"servers": dnsServers, "rules": []any{map[string]any{"rule_set": []string{"geosite-cn"}, "action": "route", "server": "direct-dns"}}, "final": "remote-dns", "strategy": s.DNS.Strategy, "independent_cache": true}
		if s.DNS.FakeIP {
			dnsServers = append(dnsServers, map[string]any{"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"})
			dns["servers"] = dnsServers
			dns["rules"] = append(dns["rules"].([]any), map[string]any{"query_type": []string{"A", "AAAA"}, "action": "route", "server": "fakeip"})
			dns["reverse_mapping"] = true
		}
		result["dns"] = dns
		route := result["route"].(map[string]any)
		route["default_domain_resolver"] = "direct-dns"
		if s.Mode != "bypass_cn" {
			route["rule_set"] = append(route["rule_set"].([]any), ruleSet("geosite-cn"))
		}
	}
	return result
}
func writeConfig(s Store) error {
	if err := validateDNSSettings(&s.DNS); err != nil {
		return err
	}
	if _, err := ensureClashAPISecret(); err != nil {
		return err
	}
	macData, err := macACLData(s)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(config(s), "", "  ")
	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(configPath), "."+filepath.Base(configPath)+".candidate-*")
	if err != nil {
		return err
	}
	candidate := tmp.Name()
	defer func() {
		if candidate != "" {
			_ = os.Remove(candidate)
		}
	}()
	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	checker, lookErr := exec.LookPath("sing-box")
	if lookErr == nil {
		out, err := exec.Command(checker, "check", "-c", candidate).CombinedOutput()
		if err != nil {
			return fmt.Errorf("invalid sing-box config: %s", strings.TrimSpace(string(out)))
		}
	}
	if err := writeNaiveConfigs(s); err != nil {
		return fmt.Errorf("write NaiveProxy configs: %w", err)
	}
	if err := writeAtomicFile(macACLPath, macData, 0640); err != nil {
		return fmt.Errorf("write MAC ACL bindings: %w", err)
	}
	if err := os.Rename(candidate, configPath); err != nil {
		return err
	}
	candidate = ""
	return nil
}
func run(w http.ResponseWriter, name string, args ...string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(out)
}

func runCoreUpdate(w http.ResponseWriter, args ...string) {
	coreOperationMu.Lock()
	defer coreOperationMu.Unlock()
	cmd := exec.Command(updateCorePath, args...)
	mu.Lock()
	port := proxyPort
	mu.Unlock()
	cmd.Env = append(os.Environ(), fmt.Sprintf("ARMWALL_PROXY_PORT=%d", port))
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}

func loadAPIStoreSnapshot() (Store, error) {
	unlock, err := lockStoreFile()
	if err != nil {
		return Store{}, err
	}
	defer unlock()
	return loadStore()
}

// handleUnlockedAPI handles read-only and externally slow endpoints before the
// write mutex is acquired. Store snapshots are still protected by the
// cross-process file lock, while network, systemctl, and core-update I/O do
// not block unrelated API writes.
func handleUnlockedAPI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/state":
		s, err := loadAPIStoreSnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		json.NewEncoder(w).Encode(s)
		return true
	case "/api/strategy/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return true
		}
		s, err := loadAPIStoreSnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		json.NewEncoder(w).Encode(map[string]any{"groups": strategyRuntimeStatuses(s)})
		return true
	case "/api/strategy/test":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return true
		}
		var request struct{ ID string }
		if decodeJSONBody(r, &request) != nil || request.ID == "" {
			http.Error(w, "strategy id is required", http.StatusBadRequest)
			return true
		}
		s, err := loadAPIStoreSnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		var group *StrategyGroup
		for i := range s.StrategyGroups {
			if s.StrategyGroups[i].ID == request.ID {
				group = &s.StrategyGroups[i]
				break
			}
		}
		if group == nil {
			http.Error(w, "strategy not found", http.StatusNotFound)
			return true
		}
		delay, err := clashDelay(group.ID, group.TestURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return true
		}
		json.NewEncoder(w).Encode(map[string]any{"id": group.ID, "ms": delay})
		return true
	case "/api/service/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return true
		}
		out, _ := exec.Command("systemctl", "is-active", "armwall-sing-box.service").CombinedOutput()
		status := strings.TrimSpace(string(out))
		if status == "" {
			status = "unknown"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(status + "\n"))
		return true
	case "/api/logs":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return true
		}
		path := filepath.Join(logDir, "sing-box.log")
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			return true
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		defer file.Close()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", "attachment; filename=armwall.log")
			_, _ = io.Copy(w, file)
			return true
		}
		if info, statErr := file.Stat(); statErr == nil && info.Size() > 256<<10 {
			_, _ = file.Seek(-(256 << 10), io.SeekEnd)
		}
		_, _ = io.Copy(w, file)
		return true
	case "/api/network/test":
		targets := map[string]string{"google": "https://www.google.com/generate_204", "youtube": "https://www.youtube.com/generate_204", "github": "https://github.com/", "facebook": "https://www.facebook.com/", "baidu": "https://www.baidu.com/", "qq": "https://www.qq.com/", "bilibili": "https://www.bilibili.com/", "microsoft": "https://www.microsoft.com/"}
		name := r.URL.Query().Get("target")
		target, ok := targets[name]
		if !ok {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return true
		}
		mu.Lock()
		port := proxyPort
		mu.Unlock()
		transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)})}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		start := time.Now()
		resp, err := client.Get(target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return true
		}
		resp.Body.Close()
		json.NewEncoder(w).Encode(map[string]any{"target": name, "status": resp.StatusCode, "ms": time.Since(start).Milliseconds()})
		return true
	case "/api/gateway/status":
		run(w, gatewayPath, "status")
		return true
	case "/api/node/test":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return true
		}
		var v struct{ ID string }
		if err := decodeOptionalJSONBody(r, &v); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return true
		}
		if v.ID == "" {
			v.ID = r.URL.Query().Get("id")
		}
		s, err := loadAPIStoreSnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
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
			http.Error(w, "node not found", http.StatusNotFound)
			return true
		}
		method := r.URL.Query().Get("method")
		start := time.Now()
		switch method {
		case "ping":
			if strings.HasPrefix(host, "-") {
				http.Error(w, "invalid host", http.StatusBadRequest)
				return true
			}
			out, err := exec.Command("ping", "-c", "1", "-W", "3", host).CombinedOutput()
			if err != nil {
				http.Error(w, string(out), http.StatusBadGateway)
				return true
			}
			json.NewEncoder(w).Encode(map[string]any{"method": "ping", "ms": time.Since(start).Milliseconds()})
		case "tcp":
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return true
			}
			conn.Close()
			json.NewEncoder(w).Encode(map[string]any{"method": "tcp", "ms": time.Since(start).Milliseconds()})
		case "urltest":
			delay, err := clashDelay(tag, "https://www.google.com/generate_204")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return true
			}
			json.NewEncoder(w).Encode(map[string]any{"method": "urltest", "ms": delay, "delay": delay})
		default:
			http.Error(w, "invalid method", http.StatusBadRequest)
		}
		return true
	case "/api/core/update":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return true
		}
		var v struct{ Core, Action string }
		if decodeJSONBody(r, &v) != nil || (v.Core != "sing-box" && v.Core != "naive") {
			http.Error(w, "invalid core", http.StatusBadRequest)
			return true
		}
		if v.Action != "version" && v.Action != "latest" {
			http.Error(w, "invalid action", http.StatusBadRequest)
			return true
		}
		runCoreUpdate(w, v.Core, v.Action)
		return true
	case "/api/core/upload":
		handleCoreUpload(w, r)
		return true
	}
	return false
}

func restartProxy() error {
	if _, err := exec.LookPath("naive"); err == nil {
		out, restartErr := exec.Command("systemctl", "restart", "armwall-naive.service").CombinedOutput()
		if restartErr != nil {
			return fmt.Errorf("NaiveProxy restart failed: %s", strings.TrimSpace(string(out)))
		}
	}
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

var restartProxyFn = restartProxy

var authFailureMu sync.Mutex
var authFailures = map[string][]time.Time{}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data: https:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
}

func validateAuthToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", fmt.Errorf("ARMWALL_TOKEN is required")
	}
	if len(token) < minAuthTokenLength {
		return "", fmt.Errorf("ARMWALL_TOKEN must be at least %d characters", minAuthTokenLength)
	}
	if strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("ARMWALL_TOKEN must not contain line breaks")
	}
	return token, nil
}

func authorized(token, header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	candidate := strings.TrimPrefix(header, prefix)
	tokenHash := sha256.Sum256([]byte(token))
	candidateHash := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(tokenHash[:], candidateHash[:]) == 1 && len(candidate) == len(token)
}

func authClient(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func recordAuthFailure(remoteAddr string) bool {
	client := authClient(remoteAddr)
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	authFailureMu.Lock()
	defer authFailureMu.Unlock()
	if len(authFailures) > 100 {
		for c, stamps := range authFailures {
			hasRecent := false
			for _, st := range stamps {
				if st.After(cutoff) {
					hasRecent = true
					break
				}
			}
			if !hasRecent {
				delete(authFailures, c)
			}
		}
	}
	kept := authFailures[client][:0]
	for _, stamp := range authFailures[client] {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	kept = append(kept, now)
	authFailures[client] = kept
	return len(kept) > 10
}

func parseWebAllowedCIDRs(raw string) ([]netip.Prefix, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(parts) == 0 {
		return nil, fmt.Errorf("ARMWALL_WEB_ALLOWED_CIDRS is required")
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid ARMWALL_WEB_ALLOWED_CIDRS entry %q: %w", part, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func parseWebListenAddress(addr string) (string, error) {
	host, portRaw, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid ARMWALL_LISTEN %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid ARMWALL_LISTEN port %q", portRaw)
	}
	if host == "localhost" {
		return host, nil
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("ARMWALL_LISTEN host must be an IP address or localhost")
		}
	}
	return host, nil
}

func webListenNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "localhost" {
		return "tcp"
	}
	parsed, err := netip.ParseAddr(host)
	if err == nil && parsed.Is6() {
		return "tcp6"
	}
	return "tcp4"
}

func loadWebAccessConfig() (webAccessConfig, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("ARMWALL_WEB_ACCESS")))
	addr := strings.TrimSpace(os.Getenv("ARMWALL_LISTEN"))
	legacy := false
	if mode == "" {
		if addr == "" {
			mode = "local"
		} else {
			host, err := parseWebListenAddress(addr)
			if err != nil {
				return webAccessConfig{}, err
			}
			ip, _ := netip.ParseAddr(host)
			if host == "localhost" || ip.IsLoopback() {
				mode = "local"
			} else {
				mode = "legacy"
				legacy = true
			}
		}
	}
	switch mode {
	case "local":
		if addr == "" {
			addr = defaultWebListenLocal
		}
	case "lan":
		if addr == "" {
			addr = defaultWebListenLAN
		}
	case "custom", "legacy":
		if addr == "" {
			return webAccessConfig{}, fmt.Errorf("ARMWALL_LISTEN is required for %s web access", mode)
		}
	default:
		return webAccessConfig{}, fmt.Errorf("ARMWALL_WEB_ACCESS must be local, lan, or custom")
	}
	host, err := parseWebListenAddress(addr)
	if err != nil {
		return webAccessConfig{}, err
	}
	parsedHost, _ := netip.ParseAddr(host)
	if mode == "local" && host != "localhost" && !parsedHost.IsLoopback() {
		return webAccessConfig{}, fmt.Errorf("local web access requires a loopback ARMWALL_LISTEN address")
	}
	if mode == "lan" && host != "" && host != "0.0.0.0" {
		return webAccessConfig{}, fmt.Errorf("lan web access requires ARMWALL_LISTEN=0.0.0.0:<port>")
	}

	allowed := strings.TrimSpace(os.Getenv("ARMWALL_WEB_ALLOWED_CIDRS"))
	switch mode {
	case "local":
		allowed = "127.0.0.0/8,::1/128"
	case "lan":
		if allowed == "" {
			allowed = defaultWebAllowedPrivate
		}
	case "legacy":
		allowed = "0.0.0.0/0,::/0"
	}
	prefixes, err := parseWebAllowedCIDRs(allowed)
	if err != nil {
		return webAccessConfig{}, err
	}
	config := webAccessConfig{Mode: mode, ListenAddress: addr, AllowedPrefixes: prefixes}
	if legacy {
		log.Printf("warning: non-loopback ARMWALL_LISTEN without ARMWALL_WEB_ACCESS uses unrestricted legacy access")
	}
	return config, nil
}

func webClientAllowed(remoteAddr string, prefixes []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func webAccessMiddleware(config webAccessConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !webClientAllowed(r.RemoteAddr, config.AllowedPrefixes) {
			log.Printf("web access denied from %s path=%s", r.RemoteAddr, r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authHandler(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(token, r.Header.Get("Authorization")) {
			limited := recordAuthFailure(r.RemoteAddr)
			log.Printf("unauthorized API request from %s path=%s", r.RemoteAddr, r.URL.Path)
			w.Header().Set("WWW-Authenticate", "Bearer")
			if limited {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many authentication failures", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func decodeJSONBody(r *http.Request, dst any) error {
	return decodeJSONPayload(r, dst, false)
}

func decodeOptionalJSONBody(r *http.Request, dst any) error {
	return decodeJSONPayload(r, dst, true)
}

func decodeJSONPayload(r *http.Request, dst any, allowEmpty bool) error {
	data, err := readLimitedBody(r.Body, maxAPIJSONBodySize)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("invalid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid json")
	}
	return nil
}

func api(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if handleUnlockedAPI(w, r) {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	unlock, err := lockStoreFile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer unlock()
	s, err := loadStore()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch r.URL.Path {
	case "/api/node":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var n Node
		if decodeJSONBody(r, &n) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if err := validateNode(&n); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if n.ID == "" {
			n.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
		} else {
			n.ID = strings.TrimSpace(n.ID)
			lowerID := strings.ToLower(n.ID)
			if lowerID == "direct" || lowerID == "block" || lowerID == "dns-in" || lowerID == "tproxy-in" || strings.HasPrefix(lowerID, "tproxy-mac-") {
				http.Error(w, "reserved node id", 400)
				return
			}
			for _, existing := range s.Nodes {
				if existing.ID == n.ID {
					http.Error(w, "duplicate node id", 400)
					return
				}
			}
		}
		n.Enabled = true
		n.SortOrder = len(s.Nodes)
		s.Nodes = append(s.Nodes, n)
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(n)
	case "/api/node/delete":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ID string }
		if err := decodeOptionalJSONBody(r, &v); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if v.ID == "" {
			v.ID = r.URL.Query().Get("id")
		}
		found := false
		for i := range s.Nodes {
			if s.Nodes[i].ID == v.ID {
				s.Nodes = append(s.Nodes[:i], s.Nodes[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "node not found", 404)
			return
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/node/update":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var n Node
		if decodeJSONBody(r, &n) != nil || n.ID == "" {
			http.Error(w, "invalid node", 400)
			return
		}
		index := -1
		for i := range s.Nodes {
			if s.Nodes[i].ID == n.ID {
				index = i
				break
			}
		}
		if index < 0 {
			http.Error(w, "node not found", 404)
			return
		}
		n.SubscriptionID = s.Nodes[index].SubscriptionID
		if strings.TrimSpace(n.Group) == "" {
			n.Group = s.Nodes[index].Group
		}
		n.SortOrder = s.Nodes[index].SortOrder
		if err := validateNode(&n); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.Nodes[index] = n
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(n)
	case "/api/node/copy":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ID string }
		if err := decodeJSONBody(r, &v); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		for _, n := range s.Nodes {
			if n.ID == v.ID {
				n.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
				n.Name += " - 副本"
				n.SubscriptionID = ""
				n.Group = "手动节点"
				n.Enabled = true
				n.SortOrder = len(s.Nodes)
				s.Nodes = append(s.Nodes, n)
				if err := persistStore(s, true); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				json.NewEncoder(w).Encode(n)
				return
			}
		}
		http.Error(w, "node not found", 404)
	case "/api/node/toggle":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct {
			ID      string
			Enabled bool
		}
		if err := decodeJSONBody(r, &v); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		found := false
		for i := range s.Nodes {
			if s.Nodes[i].ID == v.ID {
				s.Nodes[i].Enabled = v.Enabled
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "node not found", 404)
			return
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/node/batch-toggle":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct {
			IDs     []string
			Enabled bool
		}
		if decodeJSONBody(r, &v) != nil || len(v.IDs) == 0 {
			http.Error(w, "node ids are required", 400)
			return
		}
		ids := make(map[string]bool, len(v.IDs))
		for _, id := range v.IDs {
			ids[id] = true
		}
		updated := 0
		for i := range s.Nodes {
			if ids[s.Nodes[i].ID] {
				s.Nodes[i].Enabled = v.Enabled
				updated++
			}
		}
		if updated == 0 {
			http.Error(w, "nodes not found", 404)
			return
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"updated": updated, "enabled": v.Enabled})
	case "/api/node/batch-delete":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ IDs []string }
		if decodeJSONBody(r, &v) != nil || len(v.IDs) == 0 {
			http.Error(w, "node ids are required", 400)
			return
		}
		ids := map[string]bool{}
		for _, id := range v.IDs {
			ids[id] = true
		}
		before := len(s.Nodes)
		kept := s.Nodes[:0]
		for _, n := range s.Nodes {
			if !ids[n.ID] {
				kept = append(kept, n)
			}
		}
		s.Nodes = kept
		if len(s.Nodes) == before {
			http.Error(w, "nodes not found", 404)
			return
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/node/reorder":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ IDs []string }
		if decodeJSONBody(r, &v) != nil || len(v.IDs) == 0 {
			http.Error(w, "node ids are required", 400)
			return
		}
		byID := map[string]Node{}
		for _, n := range s.Nodes {
			byID[n.ID] = n
		}
		ordered := make([]Node, 0, len(s.Nodes))
		for _, id := range v.IDs {
			if n, ok := byID[id]; ok {
				n.SortOrder = len(ordered)
				ordered = append(ordered, n)
				delete(byID, id)
			}
		}
		for _, n := range s.Nodes {
			if rest, ok := byID[n.ID]; ok {
				rest.SortOrder = len(ordered)
				ordered = append(ordered, rest)
			}
		}
		s.Nodes = ordered
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/node/select":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ID string }
		if err := decodeJSONBody(r, &v); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		found := false
		for _, n := range s.Nodes {
			if n.ID == v.ID && n.Enabled {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "node not found", 404)
			return
		}
		s.SelectedNode = v.ID
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/subscription":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct {
			URL, Name   string
			UpdateHours int
		}
		if decodeJSONBody(r, &v) != nil || !strings.HasPrefix(v.URL, "https://") {
			http.Error(w, "invalid url", 400)
			return
		}
		nodes, err := fetchSubscriptionFn(v.URL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if len(nodes) == 0 {
			http.Error(w, "subscription contains no supported nodes", http.StatusUnprocessableEntity)
			return
		}
		var sub *Subscription
		for i := range s.Subscriptions {
			if s.Subscriptions[i].URL == v.URL {
				sub = &s.Subscriptions[i]
				break
			}
		}
		if sub == nil {
			name := strings.TrimSpace(v.Name)
			if name == "" {
				name = fmt.Sprintf("订阅 %d", len(s.Subscriptions)+1)
			}
			hours := v.UpdateHours
			if hours < 1 || hours > 168 {
				hours = 6
			}
			s.Subscriptions = append(s.Subscriptions, Subscription{ID: fmt.Sprintf("subsrc-%d", time.Now().UnixNano()), Name: name, URL: v.URL, UpdateHours: hours, Enabled: true})
			sub = &s.Subscriptions[len(s.Subscriptions)-1]
		}
		nodes = reconcileSubscriptionNodes(s.Nodes, nodes, *sub)
		sub.LastUpdated = time.Now()
		kept := make([]Node, 0, len(s.Nodes))
		for _, n := range s.Nodes {
			if n.SubscriptionID != sub.ID {
				kept = append(kept, n)
			}
		}
		s.Nodes = append(kept, nodes...)
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
	case "/api/subscription/clear":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		kept := s.Nodes[:0]
		for _, n := range s.Nodes {
			if n.SubscriptionID == "" {
				kept = append(kept, n)
			}
		}
		s.Nodes = kept
		s.SubscriptionURLs = nil
		s.Subscriptions = nil
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"cleared": true})
	case "/api/subscription/update":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if err := updateSubscriptionsWithForceLocked(true); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"updated": true})
	case "/api/subscription/update-one":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ID string }
		if decodeJSONBody(r, &v) != nil || v.ID == "" {
			http.Error(w, "subscription id is required", 400)
			return
		}
		var sub *Subscription
		for i := range s.Subscriptions {
			if s.Subscriptions[i].ID == v.ID {
				sub = &s.Subscriptions[i]
				break
			}
		}
		if sub == nil {
			http.Error(w, "subscription not found", 404)
			return
		}
		nodes, err := fetchSubscriptionFn(sub.URL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if len(nodes) == 0 {
			http.Error(w, "subscription contains no supported nodes", http.StatusUnprocessableEntity)
			return
		}
		nodes = reconcileSubscriptionNodes(s.Nodes, nodes, *sub)
		kept := make([]Node, 0, len(s.Nodes))
		for _, n := range s.Nodes {
			if n.SubscriptionID != sub.ID {
				kept = append(kept, n)
			}
		}
		s.Nodes = append(kept, nodes...)
		sub.LastUpdated = time.Now()
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"updated": sub.ID, "nodes": len(nodes)})
	case "/api/subscription/edit":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v Subscription
		if decodeJSONBody(r, &v) != nil || v.ID == "" || !strings.HasPrefix(v.URL, "https://") {
			http.Error(w, "invalid subscription", 400)
			return
		}
		v.Name = strings.TrimSpace(v.Name)
		if v.Name == "" || v.UpdateHours < 1 || v.UpdateHours > 168 {
			http.Error(w, "name and update interval 1-168 are required", 400)
			return
		}
		for _, sub := range s.Subscriptions {
			if sub.ID != v.ID && sub.URL == v.URL {
				http.Error(w, "subscription url already exists", http.StatusConflict)
				return
			}
		}
		found := false
		for i := range s.Subscriptions {
			if s.Subscriptions[i].ID == v.ID {
				oldName := s.Subscriptions[i].Name
				if v.LastUpdated.IsZero() {
					v.LastUpdated = s.Subscriptions[i].LastUpdated
				}
				s.Subscriptions[i] = v
				for j := range s.Nodes {
					if s.Nodes[j].SubscriptionID == v.ID && s.Nodes[j].Group == oldName {
						s.Nodes[j].Group = v.Name
					}
				}
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "subscription not found", 404)
			return
		}
		if err := persistStore(s, false); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(v)
	case "/api/subscription/delete":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ID string }
		if decodeJSONBody(r, &v) != nil || v.ID == "" {
			http.Error(w, "subscription id is required", 400)
			return
		}
		before := len(s.Subscriptions)
		subs := s.Subscriptions[:0]
		for _, sub := range s.Subscriptions {
			if sub.ID != v.ID {
				subs = append(subs, sub)
			}
		}
		s.Subscriptions = subs
		if len(s.Subscriptions) == before {
			http.Error(w, "subscription not found", 404)
			return
		}
		nodes := s.Nodes[:0]
		for _, n := range s.Nodes {
			if n.SubscriptionID != v.ID {
				nodes = append(nodes, n)
			}
		}
		s.Nodes = nodes
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/subscription/toggle":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct {
			ID      string
			Enabled bool
		}
		if decodeJSONBody(r, &v) != nil || v.ID == "" {
			http.Error(w, "subscription id is required", 400)
			return
		}
		found := false
		for i := range s.Subscriptions {
			if s.Subscriptions[i].ID == v.ID {
				s.Subscriptions[i].Enabled = v.Enabled
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "subscription not found", 404)
			return
		}
		if err := persistStore(s, false); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/subscription/schedule":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ Hours int }
		if decodeJSONBody(r, &v) != nil || v.Hours < 1 || v.Hours > 168 {
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
	case "/api/acl":
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
	case "/api/acl/toggle":
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
	case "/api/acl/delete":
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
	case "/api/dns":
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
	case "/api/strategy":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var group StrategyGroup
		if decodeJSONBody(r, &group) != nil {
			http.Error(w, "invalid strategy", 400)
			return
		}
		creating := group.ID == ""
		if creating {
			group.ID = fmt.Sprintf("strategy-%d", time.Now().UnixNano())
		}
		if group.ID == "direct" || group.ID == "block" {
			http.Error(w, "reserved strategy id", 400)
			return
		}
		if err := validateStrategyGroup(&group, s); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if creating {
			s.StrategyGroups = append(s.StrategyGroups, group)
		} else {
			index := -1
			for i := range s.StrategyGroups {
				if s.StrategyGroups[i].ID == group.ID {
					index = i
					break
				}
			}
			if index < 0 {
				http.Error(w, "strategy not found", 404)
				return
			}
			s.StrategyGroups[index] = group
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(group)
	case "/api/strategy/delete":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ID string }
		if decodeJSONBody(r, &v) != nil || v.ID == "" {
			http.Error(w, "strategy id is required", 400)
			return
		}
		before := len(s.StrategyGroups)
		kept := s.StrategyGroups[:0]
		for _, group := range s.StrategyGroups {
			if group.ID != v.ID {
				kept = append(kept, group)
			}
		}
		s.StrategyGroups = kept
		if len(s.StrategyGroups) == before {
			http.Error(w, "strategy not found", 404)
			return
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/strategy/select":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var request struct{ ID, NodeID string }
		if decodeJSONBody(r, &request) != nil || request.ID == "" || request.NodeID == "" {
			http.Error(w, "strategy and node ids are required", http.StatusBadRequest)
			return
		}
		found := false
		for i := range s.StrategyGroups {
			group := &s.StrategyGroups[i]
			if group.ID != request.ID || group.Type != "selector" {
				continue
			}
			for _, member := range group.NodeIDs {
				if member == request.NodeID {
					group.Selected = request.NodeID
					found = true
					break
				}
			}
		}
		if !found {
			http.Error(w, "selector or member not found", http.StatusNotFound)
			return
		}
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/routing":
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
	case "/api/mode":
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
	case "/api/settings":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ ProxyPort int }
		if decodeJSONBody(r, &v) != nil || v.ProxyPort < 1 || v.ProxyPort > 65535 {
			http.Error(w, "invalid port", 400)
			return
		}
		reservedPorts := map[int]string{8080: "web", 9090: "clash api", 11081: "tproxy", 53: "dns", 22: "ssh"}
		if name, conflict := reservedPorts[v.ProxyPort]; conflict {
			http.Error(w, fmt.Sprintf("port %d conflicts with %s", v.ProxyPort, name), 400)
			return
		}
		s.ProxyPort = v.ProxyPort
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/service/start":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
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
		if err := reloadGatewayIfActive(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("active\n"))
	case "/api/service/stop":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		gatewaySuspended := false
		if _, statErr := os.Stat(gatewayStatePath); statErr == nil {
			if gatewayOut, gatewayErr := exec.Command(gatewayPath, "suspend").CombinedOutput(); gatewayErr != nil {
				http.Error(w, string(gatewayOut), 500)
				return
			}
			gatewaySuspended = true
		}
		out, err := exec.Command("systemctl", "stop", "armwall-sing-box.service", "armwall-naive.service").CombinedOutput()
		if err != nil {
			if gatewaySuspended {
				_, _ = exec.Command(gatewayPath, "restore").CombinedOutput()
			}
			http.Error(w, strings.TrimSpace(string(out)), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("inactive\n"))
	case "/api/log/clear":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if err := os.WriteFile(filepath.Join(logDir, "sing-box.log"), nil, 0640); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"cleared": true})
	case "/api/log/level":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ Level string }
		if decodeJSONBody(r, &v) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if v.Level != "trace" && v.Level != "debug" && v.Level != "info" && v.Level != "warn" && v.Level != "error" {
			http.Error(w, "invalid level", 400)
			return
		}
		s.LogLevel = v.Level
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/api/rules":
		json.NewEncoder(w).Encode(map[string]any{"rules": ruleURLs, "settings": s.RuleSettings, "backups": s.RuleBackups, "update_hours": s.RuleUpdateHours, "ad_block_enabled": boolValue(s.AdBlockEnabled, true)})
	case "/api/rules/update":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ Tag string }
		if err := decodeOptionalJSONBody(r, &v); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if v.Tag == "" {
			http.Error(w, "rule tag is required", 400)
			return
		}
		updated, err := updateConfiguredRules(&s, true, v.Tag, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if len(updated) != 1 {
			http.Error(w, "rule was not updated", 500)
			return
		}
		if err := writeConfig(s); err != nil {
			restoreRuleBackups(updated)
			http.Error(w, err.Error(), 500)
			return
		}
		if err := save(s); err != nil {
			restoreRuleBackups(updated)
			http.Error(w, err.Error(), 500)
			return
		}
		wasRunning := proxyRunningFn()
		if wasRunning {
			if err := restartProxy(); err != nil {
				restoreRuleBackups(updated)
				http.Error(w, err.Error(), 500)
				return
			}
		}
		cleanupRuleBackups(updated)
		json.NewEncoder(w).Encode(map[string]any{"updated": v.Tag})
	case "/api/rules/settings":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct {
			Tag            string `json:"tag"`
			Backup         string `json:"backup"`
			Hours          int    `json:"hours"`
			AutoUpdate     bool   `json:"autoUpdate"`
			AdBlockEnabled *bool  `json:"adBlockEnabled"`
		}
		if decodeJSONBody(r, &v) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if _, ok := ruleURLs[v.Tag]; !ok || v.Hours < 1 || v.Hours > 168 {
			http.Error(w, "invalid rule settings", 400)
			return
		}
		v.Backup = strings.TrimSpace(v.Backup)
		if v.Backup != "" && !httpsURL(v.Backup) {
			http.Error(w, "backup rule URL must use https", 400)
			return
		}
		setting := s.RuleSettings[v.Tag]
		setting.BackupURL = v.Backup
		setting.UpdateHours = v.Hours
		setting.AutoUpdate = v.AutoUpdate
		s.RuleSettings[v.Tag] = setting
		s.RuleBackups[v.Tag] = v.Backup
		if v.AdBlockEnabled != nil {
			s.AdBlockEnabled = v.AdBlockEnabled
			if err := persistStore(s, true); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		} else {
			if err := save(s); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		json.NewEncoder(w).Encode(s)
	case "/api/gateway/enable":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ LAN, WAN string }
		if decodeJSONBody(r, &v) != nil || !safeIface(v.LAN) || !safeIface(v.WAN) {
			http.Error(w, "invalid interface", 400)
			return
		}
		cmd := exec.Command(gatewayPath, "enable")
		cmd.Env = append(os.Environ(), "ARMWALL_LAN_IF="+v.LAN, "ARMWALL_WAN_IF="+v.WAN)
		out, err := cmd.CombinedOutput()
		if err != nil {
			http.Error(w, string(out), 500)
			return
		}
		if serviceOut, serviceErr := exec.Command("systemctl", "enable", "--now", "armwall-gateway.service").CombinedOutput(); serviceErr != nil {
			_, _ = exec.Command(gatewayPath, "disable").CombinedOutput()
			http.Error(w, string(serviceOut), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(out)
	case "/api/gateway/disable":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		out, err := exec.Command(gatewayPath, "disable").CombinedOutput()
		if err != nil {
			http.Error(w, string(out), 500)
			return
		}
		if serviceOut, serviceErr := exec.Command("systemctl", "disable", "--now", "armwall-gateway.service").CombinedOutput(); serviceErr != nil {
			http.Error(w, string(serviceOut), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(out)
	case "/api/node/import":
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var v struct{ Links string }
		if decodeJSONBody(r, &v) != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		nodes := parseSubscription(v.Links)
		if len(nodes) == 0 {
			http.Error(w, "no supported links", http.StatusUnprocessableEntity)
			return
		}
		for i := range nodes {
			nodes[i].SubscriptionID = ""
			if err := validateNode(&nodes[i]); err != nil {
				http.Error(w, fmt.Sprintf("invalid imported node: %v", err), http.StatusUnprocessableEntity)
				return
			}
		}
		s.Nodes = append(s.Nodes, nodes...)
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"imported": len(nodes)})
	case "/api/config/export":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		data, err := marshalConfigArchive(s)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=armwall-config.json")
		_, _ = w.Write(data)
	case "/api/config/import":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		data, err := readLimitedBody(r.Body, maxConfigSize)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		imported, err := parseConfigArchive(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := createConfigBackup(s, "pre-import"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := persistStore(imported, true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(imported)
	case "/api/backups":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		backups, err := listConfigBackups()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(backups)
	case "/api/backups/create":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		backup, err := createConfigBackup(s, "armwall-backup")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(backup)
	case "/api/backups/download":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		path, err := configBackupPath(r.URL.Query().Get("name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "backup not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(path))
		_, _ = w.Write(data)
	case "/api/backups/restore":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var request struct{ Name string }
		if decodeJSONBody(r, &request) != nil {
			http.Error(w, "backup name is required", http.StatusBadRequest)
			return
		}
		path, err := configBackupPath(request.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "backup not found", http.StatusNotFound)
			return
		}
		restored, err := parseConfigArchive(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := createConfigBackup(s, "pre-restore"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := persistStore(restored, true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(restored)
	case "/api/backups/delete":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var request struct{ Name string }
		if decodeJSONBody(r, &request) != nil {
			http.Error(w, "backup name is required", http.StatusBadRequest)
			return
		}
		path, err := configBackupPath(request.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := os.Remove(path); err != nil {
			http.Error(w, "backup not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
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
	setSecurityHeaders(w)
	b, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	_, _ = w.Write(b)
}

func securityHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func newHTTPServer(config webAccessConfig, token string, staticFS fs.FS) (*http.Server, error) {
	if _, err := validateAuthToken(token); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", authHandler(token, api))
	if staticFS != nil {
		mux.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))).ServeHTTP(w, r)
		}))
	}
	mux.HandleFunc("/", page)
	return &http.Server{
		Addr:              config.ListenAddress,
		Handler:           securityHeaderMiddleware(webAccessMiddleware(config, mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}, nil
}

//go:embed web/index.html web/styles.css web/app.js
var webFiles embed.FS

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("armwall %s\n", version)
		return
	}
	if v := os.Getenv("ARMWALL_DB"); v != "" {
		dbPath = v
	}
	if v := os.Getenv("ARMWALL_DATA"); v != "" {
		dataPath = v
	}
	if v := os.Getenv("ARMWALL_PROXY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			proxyPort = p
		}
	}
	if stored, err := loadStore(); err != nil {
		log.Fatal(err)
	} else if stored.ProxyPort > 0 && stored.ProxyPort < 65536 {
		proxyPort = stored.ProxyPort
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
	if v := os.Getenv("ARMWALL_LOG_DIR"); v != "" {
		logDir = v
	}
	if len(os.Args) > 1 && os.Args[1] == "--check-config" {
		if _, err := validateAuthToken(os.Getenv("ARMWALL_TOKEN")); err != nil {
			log.Fatal(err)
		}
		if _, err := loadWebAccessConfig(); err != nil {
			log.Fatal(err)
		}
		log.Print("configuration ok")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--write-config" {
		if err := withStoreFileLock(func() error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			if s.Mode == "" {
				s.Mode = "bypass_cn"
			}
			if s.ProxyPort == 0 {
				s.ProxyPort = proxyPort
			}
			normalizeStore(&s)
			if err := writeConfig(s); err != nil {
				return err
			}
			return save(s)
		}); err != nil {
			log.Fatal(err)
		}
		log.Print("configuration generated")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--update-subscriptions" {
		if err := updateSubscriptions(); err != nil {
			log.Fatal(err)
		}
		log.Print("subscriptions updated")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--update-rules" {
		updated, err := applyScheduledRuleUpdates()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("rules updated: %d", updated)
		return
	}
	staticFS, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	webAccess, err := loadWebAccessConfig()
	if err != nil {
		log.Fatal(err)
	}
	token, err := validateAuthToken(os.Getenv("ARMWALL_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("armwall listening on %s web_access=%s", webAccess.ListenAddress, webAccess.Mode)
	server, err := newHTTPServer(webAccess, token, staticFS)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen(webListenNetwork(webAccess.ListenAddress), webAccess.ListenAddress)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.Serve(listener))
}
