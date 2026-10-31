package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

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
	} else {
		n.Transport = normalizeTransport(n.Transport)
		if n.Transport != "" {
			validTransports := map[string]bool{"http": true, "ws": true, "quic": true, "grpc": true, "httpupgrade": true}
			if !validTransports[n.Transport] {
				return fmt.Errorf("unsupported transport: %s", n.Transport)
			}
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
