package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func httpsURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && u.Hostname() != ""
}

func outboundHTTPClients(timeout time.Duration) []*http.Client {
	clients := make([]*http.Client, 0, 2)
	address := fmt.Sprintf("127.0.0.1:%d", getProxyPort())
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
	return downloadResourceContext(context.Background(), raw, limit, timeout)
}

func downloadResourceContext(ctx context.Context, raw string, limit int64, timeout time.Duration) ([]byte, error) {
	if !httpsURL(raw) {
		return nil, fmt.Errorf("download URL must use https")
	}
	var lastErr error
	for _, client := range outboundHTTPClients(timeout) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, lastErr
}
