package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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

var version = "dev"

type Node struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Server         string `json:"server"`
	UUID           string `json:"uuid"`
	Password       string `json:"password"`
	Port           int    `json:"port"`
	TLS            bool   `json:"tls"`
	ServerName     string `json:"server_name"`
	Insecure       bool   `json:"insecure"`
	Username       string `json:"username"`
	Method         string `json:"method"`
	Flow           string `json:"flow"`
	Transport      string `json:"transport"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	ALPN           string `json:"alpn"`
	Fingerprint    string `json:"fingerprint"`
	Plugin         string `json:"plugin"`
	PluginOpts     string `json:"plugin_opts"`
	Group          string `json:"group"`
	SubscriptionID string `json:"subscription_id"`
	Enabled        bool   `json:"enabled"`
	SortOrder      int    `json:"sort_order"`
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
	Subscriptions    []Subscription    `json:"subscriptions"`
	StrategyGroups   []StrategyGroup   `json:"strategy_groups"`
	TCPOutbound      string            `json:"tcp_outbound"`
	UDPOutbound      string            `json:"udp_outbound"`
	ACLRules         []ACLRule         `json:"acl_rules"`
	DNS              DNSSettings       `json:"dns"`
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
					out = append(out, Node{ID: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Name: v.PS, Type: "vmess", Server: v.Add, Port: p, UUID: v.ID, TLS: v.TLS != "", ServerName: v.SNI, Enabled: true})
					continue
				}
			}
		}
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if u.Scheme != "vless" && u.Scheme != "trojan" && u.Scheme != "shadowsocks" && u.Scheme != "ss" && u.Scheme != "hysteria2" && u.Scheme != "anytls" && u.Scheme != "naive" && u.Scheme != "naive+https" && u.Scheme != "naive+quic" {
			continue
		}
		nodeType := u.Scheme
		naiveTransport := ""
		if strings.HasPrefix(nodeType, "naive+") {
			naiveTransport = strings.TrimPrefix(nodeType, "naive+")
			nodeType = "naive"
		}
		n := Node{ID: fmt.Sprintf("sub-%d", time.Now().UnixNano()), Name: u.Fragment, Type: nodeType, Server: u.Hostname(), TLS: true, Enabled: true, Transport: naiveTransport}
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
	return updateSubscriptionsWithForce(false)
}

func subscriptionDue(sub Subscription, now time.Time) bool {
	hours := sub.UpdateHours
	if hours < 1 {
		hours = 6
	}
	return sub.LastUpdated.IsZero() || now.Sub(sub.LastUpdated) >= time.Duration(hours)*time.Hour
}

func updateSubscriptionsWithForce(force bool) error {
	s := load()
	if len(s.Subscriptions) == 0 {
		s = migrateLegacy(s)
	}
	fetchedBySub := map[string][]Node{}
	now := time.Now()
	for i := range s.Subscriptions {
		sub := &s.Subscriptions[i]
		if !sub.Enabled {
			continue
		}
		if !force && !subscriptionDue(*sub, now) {
			continue
		}
		fetched, err := fetchSubscription(sub.URL)
		if err != nil {
			return fmt.Errorf("%s: %w", sub.URL, err)
		}
		for j := range fetched {
			fetched[j].SubscriptionID = sub.ID
			fetched[j].Group = sub.Name
			fetched[j].Enabled = true
		}
		fetchedBySub[sub.ID] = fetched
		sub.LastUpdated = now
	}
	if len(s.Subscriptions) == 0 {
		return fmt.Errorf("no subscriptions configured")
	}
	if len(fetchedBySub) == 0 {
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
	return restartProxy()
}

var mu sync.Mutex
var dataPath = "/var/lib/armwall/store.json"
var configPath = "/etc/armwall/sing-box.json"
var macACLPath = "/etc/armwall/mac-acl.tsv"
var naiveConfigDir = "/etc/armwall/naive"
var logDir = "/var/log/armwall"
var proxyPort = 1080
var tproxyEnabled bool
var tproxyPort = 11081
var naiveProxyPort = 12000
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
	s, err := loadDB()
	if err == nil {
		return s
	}
	legacy := migrateLegacy(loadJSON())
	_ = saveDB(legacy)
	return legacy
}
func save(s Store) error {
	if err := saveDB(s); err != nil {
		return err
	}
	return saveJSON(s)
}

func normalizeStore(s *Store) {
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
	previous := load()
	previousProxyPort := proxyPort
	normalizeStore(&next)
	if !reload {
		return save(next)
	}
	if next.ProxyPort > 0 {
		proxyPort = next.ProxyPort
	}
	if err := writeConfig(next); err != nil {
		proxyPort = previousProxyPort
		return err
	}
	if err := save(next); err != nil {
		proxyPort = previousProxyPort
		_ = writeConfig(previous)
		return err
	}
	if err := restartProxyFn(); err != nil {
		proxyPort = previousProxyPort
		_ = save(previous)
		_ = writeConfig(previous)
		_ = restartProxyFn()
		return err
	}
	return nil
}

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
	if n.Type == "naive" {
		if n.Transport == "" {
			n.Transport = "https"
		}
		if n.Transport != "https" && n.Transport != "quic" {
			return fmt.Errorf("NaiveProxy transport must be https or quic")
		}
	}
	return nil
}

func validateStrategyGroup(group *StrategyGroup, s Store) error {
	group.Name = strings.TrimSpace(group.Name)
	group.Type = strings.ToLower(strings.TrimSpace(group.Type))
	if group.Name == "" || (group.Type != "selector" && group.Type != "urltest" && group.Type != "fallback") {
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
	return os.Rename(tmpPath, path)
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
		if groupType == "fallback" {
			// sing-box implements health-based failover through URLTest.
			groupType = "urltest"
		}
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
				rule["port_range"] = acl.PortRanges
			}
			rules = append(rules, rule)
		}
	}
	macBindings := macACLBindings(s)
	for _, binding := range macBindings {
		rules = append(rules, map[string]any{"inbound": []string{binding.Tag}, "outbound": binding.Outbound})
	}
	rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct"}, map[string]any{"rule_set": []string{"geosite-ads"}, "outbound": "block"})
	ruleSets := []any{ruleSet("geosite-ads")}
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
	if tproxyEnabled {
		inbounds = append(inbounds, map[string]any{"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": tproxyPort})
	}
	for _, binding := range macBindings {
		inbounds = append(inbounds, map[string]any{"type": "tproxy", "tag": binding.Tag, "listen": "0.0.0.0", "listen_port": binding.Port})
	}
	level := s.LogLevel
	if level == "" {
		level = "info"
	}
	result := map[string]any{"log": map[string]any{"level": level, "output": filepath.Join(logDir, "sing-box.log"), "timestamp": true}, "inbounds": inbounds, "outbounds": outs, "route": map[string]any{"auto_detect_interface": true, "rules": rules, "rule_set": ruleSets, "final": final}, "experimental": map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:9090"}}}
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
	if err := writeNaiveConfigs(s); err != nil {
		_ = os.Remove(candidate)
		return fmt.Errorf("write NaiveProxy configs: %w", err)
	}
	if err := os.Rename(candidate, configPath); err != nil {
		_ = os.Remove(candidate)
		return err
	}
	if err := writeAtomicFile(macACLPath, macData, 0640); err != nil {
		return fmt.Errorf("write MAC ACL bindings: %w", err)
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
		if err := validateNode(&n); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if n.ID == "" {
			n.ID = fmt.Sprintf("node-%d", time.Now().UnixNano())
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
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
			http.Error(w, "method", 405)
			return
		}
		var n Node
		if json.NewDecoder(r.Body).Decode(&n) != nil || n.ID == "" {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
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
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			ID      string
			Enabled bool
		}
		json.NewDecoder(r.Body).Decode(&v)
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
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			IDs     []string
			Enabled bool
		}
		if json.NewDecoder(r.Body).Decode(&v) != nil || len(v.IDs) == 0 {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ IDs []string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || len(v.IDs) == 0 {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ IDs []string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || len(v.IDs) == 0 {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
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
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			URL, Name   string
			UpdateHours int
		}
		if json.NewDecoder(r.Body).Decode(&v) != nil || !strings.HasPrefix(v.URL, "https://") {
			http.Error(w, "invalid url", 400)
			return
		}
		nodes, err := fetchSubscription(v.URL)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		if len(nodes) == 0 {
			http.Error(w, "subscription contains no supported nodes", 422)
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
		for i := range nodes {
			nodes[i].SubscriptionID = sub.ID
			nodes[i].Group = sub.Name
			nodes[i].Enabled = true
		}
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
			http.Error(w, "method", 405)
			return
		}
		kept := s.Nodes[:0]
		for _, n := range s.Nodes {
			if n.SubscriptionID == "" && !strings.HasPrefix(n.ID, "sub-") {
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
			http.Error(w, "method", 405)
			return
		}
		if err := updateSubscriptionsWithForce(true); err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"updated": true})
	case "/api/subscription/update-one":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
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
		nodes, err := fetchSubscription(sub.URL)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		if len(nodes) == 0 {
			http.Error(w, "subscription contains no supported nodes", 422)
			return
		}
		for i := range nodes {
			nodes[i].SubscriptionID = sub.ID
			nodes[i].Group = sub.Name
			nodes[i].Enabled = true
		}
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
			http.Error(w, "method", 405)
			return
		}
		var v Subscription
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID == "" || !strings.HasPrefix(v.URL, "https://") {
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
				http.Error(w, "subscription url already exists", 409)
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		json.NewDecoder(r.Body).Decode(&v)
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
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			ID      string
			Enabled bool
		}
		json.NewDecoder(r.Body).Decode(&v)
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
	case "/api/acl":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var rule ACLRule
		if json.NewDecoder(r.Body).Decode(&rule) != nil {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			ID      string
			Enabled bool
		}
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID == "" {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID == "" {
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
			http.Error(w, "method", 405)
			return
		}
		var settings DNSSettings
		if json.NewDecoder(r.Body).Decode(&settings) != nil {
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
			http.Error(w, "method", 405)
			return
		}
		var group StrategyGroup
		if json.NewDecoder(r.Body).Decode(&group) != nil {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct{ ID string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID == "" {
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
	case "/api/strategy/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"groups": strategyRuntimeStatuses(s)})
	case "/api/strategy/test":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var request struct{ ID string }
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.ID == "" {
			http.Error(w, "strategy id is required", http.StatusBadRequest)
			return
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
			return
		}
		delay, err := clashDelay(group.ID, group.TestURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": group.ID, "ms": delay})
	case "/api/strategy/select":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var request struct{ ID, NodeID string }
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.ID == "" || request.NodeID == "" {
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
			http.Error(w, "method", 405)
			return
		}
		var v struct {
			Mode        string
			TCPOutbound string
			UDPOutbound string
			DNS         *DNSSettings
		}
		if json.NewDecoder(r.Body).Decode(&v) != nil || (v.Mode != "bypass_cn" && v.Mode != "gfw" && v.Mode != "global") {
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
		if err := persistStore(s, true); err != nil {
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
		if err := writeConfig(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		run(w, "systemctl", "restart", "armwall-sing-box.service")
	case "/api/service/stop":
		run(w, "systemctl", "stop", "armwall-sing-box.service")
	case "/api/service/status":
		run(w, "systemctl", "is-active", "armwall-sing-box.service")
	case "/api/logs":
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", "attachment; filename=armwall.log")
		}
		b, err := os.ReadFile(filepath.Join(logDir, "sing-box.log"))
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
		if err := os.WriteFile(filepath.Join(logDir, "sing-box.log"), nil, 0640); err != nil {
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
			delay, err := clashDelay(tag, "https://www.google.com/generate_204")
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"method": "urltest", "ms": delay, "delay": delay})
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
		var v struct{ Core, Action string }
		if json.NewDecoder(r.Body).Decode(&v) != nil || (v.Core != "sing-box" && v.Core != "naive") {
			http.Error(w, "invalid core", 400)
			return
		}
		if v.Action != "version" && v.Action != "latest" {
			http.Error(w, "invalid action", 400)
			return
		}
		args := []string{v.Core, v.Action}
		run(w, updateCorePath, args...)
	case "/api/core/upload":
		handleCoreUpload(w, r)
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
		if json.NewDecoder(r.Body).Decode(&request) != nil {
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
		if json.NewDecoder(r.Body).Decode(&request) != nil {
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
	b, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	_, _ = w.Write(b)
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
	if v := os.Getenv("ARMWALL_LOG_DIR"); v != "" {
		logDir = v
	}
	if len(os.Args) > 1 && os.Args[1] == "--write-config" {
		s := load()
		if s.Mode == "" {
			s.Mode = "bypass_cn"
		}
		if s.ProxyPort == 0 {
			s.ProxyPort = proxyPort
		}
		normalizeStore(&s)
		if err := writeConfig(s); err != nil {
			log.Fatal(err)
		}
		if err := save(s); err != nil {
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
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if token := os.Getenv("ARMWALL_TOKEN"); token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", 401)
			return
		}
		api(w, r)
	})
	staticFS, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))).ServeHTTP(w, r)
	}))
	http.HandleFunc("/", page)
	addr := os.Getenv("ARMWALL_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	log.Printf("armwall listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
