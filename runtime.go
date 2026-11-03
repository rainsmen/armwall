package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func runCommandTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func run(w http.ResponseWriter, name string, args ...string) {
	out, err := runCommandTimeout(10*time.Second, name, args...)
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
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, updateCorePath, args...)
	port := getProxyPort()
	cmd.Env = append(os.Environ(), fmt.Sprintf("ARMWALL_PROXY_PORT=%d", port))
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}

func restartNaive() error {
	if _, err := exec.LookPath("naive"); err != nil {
		return nil
	}
	out, restartErr := runCommandTimeout(10*time.Second, "systemctl", "restart", "armwall-naive.service")
	if restartErr != nil {
		return fmt.Errorf("NaiveProxy restart failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func restartSingBox() error {
	out, err := runCommandTimeout(10*time.Second, "systemctl", "restart", "armwall-sing-box.service")
	if err != nil {
		return fmt.Errorf("sing-box restart failed: %s", strings.TrimSpace(string(out)))
	}
	address := fmt.Sprintf("127.0.0.1:%d", getProxyPort())
	for i := 0; i < 80; i++ {
		conn, dialErr := net.DialTimeout("tcp", address, 150*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("sing-box restarted but proxy port %d is not ready", getProxyPort())
}

// restartProxy restarts both proxy services. It is used when the caller cannot
// tell which part changed, such as an explicit service start.
func restartProxy() error {
	if err := restartNaive(); err != nil {
		return err
	}
	return restartSingBox()
}

// reloadProxy restarts only the parts whose configuration changed.
//
// sing-box reads /etc/armwall/sing-box.json once at start and offers no reload
// interface, but that configuration only references the local naive bridges by
// port: changing a naive node's credentials rewrites the naive configuration
// files alone, while routing, DNS, rule or non-naive node changes leave the
// naive configuration untouched. Restarting both on every store change dropped
// every relayed connection for no reason.
func reloadProxy(singBoxChanged, naiveChanged bool) error {
	if !singBoxChanged && !naiveChanged {
		return nil
	}
	if naiveChanged {
		if err := restartNaive(); err != nil {
			return err
		}
	}
	if !singBoxChanged {
		// sing-box reconnects to the restarted bridges lazily, per connection.
		return nil
	}
	return restartSingBox()
}

var restartProxyFn = restartProxy

var reloadProxyFn = reloadProxy
