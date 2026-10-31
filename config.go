package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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

type configResourceBackup struct {
	path    string
	backup  string
	existed bool
	isDir   bool
}

func copyConfigResource(src, dst string, info os.FileInfo) error {
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childInfo, err := entry.Info()
			if err != nil {
				return err
			}
			if err := copyConfigResource(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name()), childInfo); err != nil {
				return err
			}
		}
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

func snapshotConfigResource(path, dir string) (configResourceBackup, error) {
	backup := configResourceBackup{path: path, backup: filepath.Join(dir, filepath.Base(path))}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return backup, nil
	}
	if err != nil {
		return backup, err
	}
	backup.existed = true
	backup.isDir = info.IsDir()
	return backup, copyConfigResource(path, backup.backup, info)
}

func restoreConfigResource(backup configResourceBackup) error {
	if err := os.RemoveAll(backup.path); err != nil {
		return err
	}
	if !backup.existed {
		return nil
	}
	info, err := os.Stat(backup.backup)
	if err != nil {
		return err
	}
	return copyConfigResource(backup.backup, backup.path, info)
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
		if n.Transport != "" && n.Transport != "tcp" && n.Transport != "none" {
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
	rules = append(rules, map[string]any{"action": "sniff"})
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
	listenPort := getProxyPort()
	if s.ProxyPort > 0 {
		listenPort = s.ProxyPort
	}
	mixedListen := "0.0.0.0"
	if addr := os.Getenv("ARMWALL_PROXY_LISTEN"); addr != "" {
		mixedListen = addr
	}
	inbounds := []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": mixedListen, "listen_port": listenPort}}
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
	clashAPI := map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", clashAPIPort)}
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
	if err := validateRuntimePorts(s); err != nil {
		return err
	}
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
	backupDir, err := os.MkdirTemp("", "armwall-config-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(backupDir)
	backups := make([]configResourceBackup, 0, 3)
	for _, path := range []string{naiveConfigDir, macACLPath, configPath} {
		backup, backupErr := snapshotConfigResource(path, backupDir)
		if backupErr != nil {
			return backupErr
		}
		backups = append(backups, backup)
	}
	restoreAll := func(cause error) error {
		var restoreErrs []string
		for _, backup := range backups {
			if restoreErr := restoreConfigResource(backup); restoreErr != nil {
				restoreErrs = append(restoreErrs, backup.path+": "+restoreErr.Error())
			}
		}
		if len(restoreErrs) > 0 {
			return fmt.Errorf("%w (resource restore failed: %s)", cause, strings.Join(restoreErrs, "; "))
		}
		return cause
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
		out, err := runCommandTimeout(5*time.Second, checker, "check", "-c", candidate)
		if err != nil {
			return fmt.Errorf("invalid sing-box config: %s", strings.TrimSpace(string(out)))
		}
	}
	if err := writeNaiveConfigs(s); err != nil {
		return restoreAll(fmt.Errorf("write NaiveProxy configs: %w", err))
	}
	if err := writeAtomicFile(macACLPath, macData, 0640); err != nil {
		return restoreAll(fmt.Errorf("write MAC ACL bindings: %w", err))
	}
	if err := os.Rename(candidate, configPath); err != nil {
		return restoreAll(err)
	}
	candidate = ""
	return nil
}
