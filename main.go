package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var version = "dev"

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
			setProxyPort(p)
		}
	}
	if stored, err := loadStore(); err != nil {
		log.Fatal(err)
	} else if stored.ProxyPort > 0 && stored.ProxyPort < 65536 {
		setProxyPort(stored.ProxyPort)
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
		stored, err := loadStore()
		if err != nil {
			log.Fatal(err)
		}
		if err := validateRuntimePorts(stored); err != nil {
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
			if errors.Is(err, errNoSubscriptions) {
				log.Print("no subscriptions configured")
				return
			}
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
	if len(os.Args) > 1 && os.Args[1] == "--bootstrap-rules" {
		updated, err := bootstrapRules()
		if err != nil {
			log.Fatalf("bootstrap rules failed after %d updates: %v", updated, err)
		}
		log.Printf("bootstrap rules updated: %d", updated)
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveUntilShutdown(ctx, server, listener); err != nil {
		log.Fatal(err)
	}
	closeDB()
}
