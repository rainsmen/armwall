package main

import (
	"fmt"
	"net"
	"strconv"
)

const clashAPIPort = 9090

func validateListenerPort(port int, name string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid %s port", name)
	}
	return nil
}

func validateProxyPort(port int) error {
	if err := validateListenerPort(port, "proxy"); err != nil {
		return err
	}
	if port == 22 || port == 53 {
		return fmt.Errorf("proxy port %d is reserved", port)
	}
	if port == 11081 {
		return fmt.Errorf("proxy port %d is reserved for tproxy", port)
	}
	return nil
}

func webPortFromAddress() (int, error) {
	web, err := loadWebAccessConfig()
	if err != nil {
		return 0, err
	}
	_, raw, err := net.SplitHostPort(web.ListenAddress)
	if err != nil {
		return 0, fmt.Errorf("invalid web listen address: %w", err)
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid web listen port")
	}
	return port, nil
}

func validateRuntimePorts(s Store) error {
	webPort, err := webPortFromAddress()
	if err != nil {
		return err
	}
	proxy := s.ProxyPort
	if proxy == 0 {
		proxy = getProxyPort()
	}
	listeners := []struct {
		port int
		name string
	}{
		{proxy, "Mixed proxy"},
		{webPort, "Web"},
		{clashAPIPort, "Clash API"},
	}
	listeners = append(listeners, struct {
		port int
		name string
	}{tproxyPort, "TProxy"})
	for _, binding := range macACLBindings(s) {
		listeners = append(listeners, struct {
			port int
			name string
		}{binding.Port, "MAC ACL TProxy"})
	}
	if s.DNS.Enabled {
		port := s.DNS.ListenPort
		if port == 0 {
			port = 53
		}
		listeners = append(listeners, struct {
			port int
			name string
		}{port, "DNS"})
	}
	for _, binding := range naiveBindings(s) {
		listeners = append(listeners, struct {
			port int
			name string
		}{binding.Port, "NaiveProxy"})
	}
	seen := make(map[int]string, len(listeners))
	for _, listener := range listeners {
		if listener.name == "Mixed proxy" {
			if err := validateProxyPort(listener.port); err != nil {
				return err
			}
		} else if err := validateListenerPort(listener.port, listener.name); err != nil {
			return err
		}
		if previous, ok := seen[listener.port]; ok {
			return fmt.Errorf("port %d is used by %s and %s", listener.port, previous, listener.name)
		}
		seen[listener.port] = listener.name
	}
	return nil
}
