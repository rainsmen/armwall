package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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
	assignNaivePorts(&s)
	bindings := make([]naiveBinding, 0)
	for _, node := range s.Nodes {
		if !node.Enabled || node.Type != "naive" {
			continue
		}
		port := node.NaivePort
		transport := node.Transport
		if transport != "quic" {
			transport = "https"
		}
		config := map[string]string{"listen": fmt.Sprintf("socks://127.0.0.1:%d", port)}
		proxyHost := node.Server
		if sni := naiveServerName(node); sni != "" {
			// NaiveProxy has no separate SNI option: the proxy URL host is used for
			// both SNI and certificate verification. Put the SNI in the URL and map it
			// back to the real server address, as relay links on mobile clients do.
			proxyHost = sni
			config["host-resolver-rules"] = "MAP " + sni + " " + naiveResolverTarget(node.Server)
		}
		proxy := &url.URL{Scheme: transport, Host: net.JoinHostPort(proxyHost, strconv.Itoa(node.Port))}
		if node.Username != "" || node.Password != "" {
			proxy.User = url.UserPassword(node.Username, node.Password)
		}
		config["proxy"] = proxy.String()
		configData, _ := json.MarshalIndent(config, "", "  ")
		bindings = append(bindings, naiveBinding{Node: node, Port: port, Config: string(configData)})
	}
	return bindings
}

// naiveServerName returns the TLS server name that differs from the dial
// address, or "" when the proxy URL host alone is sufficient. Subscription
// refreshes bypass validateNode, so malformed values are dropped here instead
// of being spliced into the resolver rule.
func naiveServerName(node Node) string {
	sni := strings.TrimSpace(node.ServerName)
	if sni == "" || strings.EqualFold(sni, node.Server) || !isDNSHostname(sni) {
		return ""
	}
	if net.ParseIP(node.Server) == nil && !isDNSHostname(node.Server) {
		return ""
	}
	return sni
}

// naiveResolverTarget formats the dial address as a Chromium host resolver
// rule replacement, which requires brackets around IPv6 literals.
func naiveResolverTarget(server string) string {
	if ip := net.ParseIP(server); ip != nil && ip.To4() == nil {
		return "[" + server + "]"
	}
	return server
}

func assignNaivePorts(s *Store) error {
	used := make(map[int]bool)
	used[22] = true           // SSH
	used[53] = true           // DNS
	used[clashAPIPort] = true // Clash API
	if webPort, err := webPortFromAddress(); err == nil && webPort > 0 {
		used[webPort] = true
	}
	if s.DNS.Enabled && s.DNS.ListenPort > 0 {
		used[s.DNS.ListenPort] = true
	}
	proxy := s.ProxyPort
	if proxy <= 0 {
		proxy = getProxyPort()
	}
	if proxy > 0 {
		used[proxy] = true
	}
	if tproxyPort > 0 {
		used[tproxyPort] = true
	}
	for _, binding := range macACLBindings(*s) {
		used[binding.Port] = true
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.Type != "naive" || n.NaivePort == 0 {
			continue
		}
		used[n.NaivePort] = true
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.Type != "naive" || n.NaivePort != 0 {
			continue
		}
		for port := naiveProxyPort; port <= 65535; port++ {
			if !used[port] && validateListenerPort(port, "NaiveProxy") == nil {
				n.NaivePort = port
				used[port] = true
				break
			}
		}
		if n.NaivePort == 0 {
			return fmt.Errorf("no available NaiveProxy port")
		}
	}
	return nil
}

func writeNaiveConfigs(s Store) error {
	if err := assignNaivePorts(&s); err != nil {
		return err
	}
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
