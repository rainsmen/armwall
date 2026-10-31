package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
		// Older installs set only ARMWALL_LISTEN. Keep them reachable from the
		// LAN, but never from public addresses unless explicitly configured.
		if allowed == "" {
			allowed = defaultWebAllowedPrivate
		}
	}
	prefixes, err := parseWebAllowedCIDRs(allowed)
	if err != nil {
		return webAccessConfig{}, err
	}
	config := webAccessConfig{Mode: mode, ListenAddress: addr, AllowedPrefixes: prefixes}
	if legacy {
		log.Printf("warning: non-loopback ARMWALL_LISTEN without ARMWALL_WEB_ACCESS; allowing only %s (set ARMWALL_WEB_ACCESS to silence this)", allowed)
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
		WriteTimeout:      180 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}, nil
}

func serveUntilShutdown(ctx context.Context, server *http.Server, listener net.Listener) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		err := <-serveErr
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

//go:embed web/index.html web/styles.css web/js/*.js
var webFiles embed.FS
