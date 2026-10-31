package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

func normalizeTransport(t string) string {
	raw := strings.ToLower(strings.TrimSpace(t))
	switch raw {
	case "", "tcp", "none":
		return ""
	case "h2":
		return "http"
	default:
		return raw
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
		Transport:   normalizeTransport(value.Net),
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
			n.Transport = normalizeTransport(transport)
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

func fetchSubscription(ctx context.Context, rawURL string) ([]Node, error) {
	if !httpsURL(rawURL) {
		return nil, fmt.Errorf("subscription must use https")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		body, err := downloadResourceContext(ctx, rawURL, 4<<20, 20*time.Second)
		if err != nil {
			lastErr = err
		} else if nodes := parseSubscription(string(body)); len(nodes) > 0 {
			return nodes, nil
		} else {
			lastErr = fmt.Errorf("no supported nodes")
		}
		if attempt < 2 {
			timer := time.NewTimer(time.Duration(attempt+1) * 2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, lastErr
}

var fetchSubscriptionFn = func(ctx context.Context, rawURL string) ([]Node, error) {
	return fetchSubscription(ctx, rawURL)
}

func updateSubscriptions() error {
	return updateSubscriptionsWithForceContext(context.Background(), false)
}

func subscriptionNodeKey(node Node) string {
	node.ID = ""
	node.Name = ""
	node.Group = ""
	node.NameOverride = ""
	node.GroupOverride = ""
	node.NaivePort = 0
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
			fetched[i].SortOrder = matches[0].SortOrder
			fetched[i].NameOverride = matches[0].NameOverride
			fetched[i].GroupOverride = matches[0].GroupOverride
			fetched[i].NaivePort = matches[0].NaivePort
			if fetched[i].NameOverride != "" {
				fetched[i].Name = fetched[i].NameOverride
			}
			if fetched[i].GroupOverride != "" {
				fetched[i].Group = fetched[i].GroupOverride
			}
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

// replaceSubscriptionNodes swaps a subscription's nodes for fresh ones, keeping
// them at the position of the first old node so manual ordering survives.
func replaceSubscriptionNodes(nodes []Node, subID string, fresh []Node) []Node {
	result := make([]Node, 0, len(nodes)+len(fresh))
	inserted := false
	for _, n := range nodes {
		if n.SubscriptionID != subID {
			result = append(result, n)
			continue
		}
		if !inserted {
			result = append(result, fresh...)
			inserted = true
		}
	}
	if !inserted {
		result = append(result, fresh...)
	}
	return result
}

func subscriptionDue(sub Subscription, now time.Time) bool {
	hours := sub.UpdateHours
	if hours < 1 {
		hours = 6
	}
	return sub.LastUpdated.IsZero() || now.Sub(sub.LastUpdated) >= time.Duration(hours)*time.Hour
}

func updateSubscriptionsWithForce(force bool) error {
	return updateSubscriptionsWithForceContext(context.Background(), force)
}

func updateSubscriptionsWithForceContext(ctx context.Context, force bool) error {
	s, err := loadStore()
	if err != nil {
		return err
	}
	if len(s.Subscriptions) == 0 {
		return errNoSubscriptions
	}
	now := time.Now()
	var subsToFetch []Subscription
	baselineUpdated := make(map[string]time.Time)
	baselineEnabled := make(map[string]bool)
	for _, sub := range s.Subscriptions {
		baselineUpdated[sub.ID] = sub.LastUpdated
		baselineEnabled[sub.ID] = sub.Enabled
		if !sub.Enabled {
			continue
		}
		if force || subscriptionDue(sub, now) {
			subsToFetch = append(subsToFetch, sub)
		}
	}
	if len(subsToFetch) == 0 {
		return nil
	}

	type fetchRes struct {
		subID string
		url   string
		nodes []Node
		err   error
	}
	results := make([]fetchRes, len(subsToFetch))
	var wg sync.WaitGroup
	for i, sub := range subsToFetch {
		wg.Add(1)
		go func(idx int, targetSub Subscription) {
			defer wg.Done()
			nodes, fetchErr := fetchSubscriptionFn(ctx, targetSub.URL)
			results[idx] = fetchRes{subID: targetSub.ID, url: targetSub.URL, nodes: nodes, err: fetchErr}
		}(i, sub)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	return withStoreFileLockContext(ctx, func() error {
		cur, loadErr := loadStore()
		if loadErr != nil {
			return loadErr
		}
		wasRunning := proxyRunningFn()
		fetchedBySub := map[string][]Node{}
		var errs []string
		for _, res := range results {
			var sub Subscription
			for _, item := range cur.Subscriptions {
				if item.ID == res.subID {
					sub = item
					break
				}
			}
			if sub.URL != res.url {
				continue
			}
			if !sub.LastUpdated.Equal(baselineUpdated[res.subID]) || sub.Enabled != baselineEnabled[res.subID] {
				// A newer refresh or a user edit won the race while this fetch ran.
				continue
			}
			if res.err != nil {
				name := sub.Name
				if name == "" {
					name = res.subID
				}
				errs = append(errs, fmt.Sprintf("%s: %v", name, res.err))
				continue
			}
			nodes := reconcileSubscriptionNodes(cur.Nodes, res.nodes, sub)
			fetchedBySub[res.subID] = nodes
			for j := range cur.Subscriptions {
				if cur.Subscriptions[j].ID == res.subID {
					cur.Subscriptions[j].LastUpdated = now
					break
				}
			}
		}
		if len(fetchedBySub) == 0 {
			if len(errs) > 0 {
				return fmt.Errorf("%s", strings.Join(errs, "; "))
			}
			return nil
		}
		for _, sub := range cur.Subscriptions {
			if fresh, ok := fetchedBySub[sub.ID]; ok {
				cur.Nodes = replaceSubscriptionNodes(cur.Nodes, sub.ID, fresh)
			}
		}
		cur.SubscriptionURLs = nil
		for _, sub := range cur.Subscriptions {
			cur.SubscriptionURLs = append(cur.SubscriptionURLs, sub.URL)
		}
		if err := persistStore(cur, wasRunning); err != nil {
			return err
		}
		if len(errs) > 0 {
			return fmt.Errorf("%s", strings.Join(errs, "; "))
		}
		return nil
	})
}

var errNoSubscriptions = errors.New("no subscriptions configured")
