package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Connectivity diagnostics answer the question "is traffic actually reaching
// the proxy, and is it routed the way the administrator expects". Every check
// mirrors a failure mode that has been observed in production: an upstream
// gateway handing over bare IP destinations, a China bypass rule swallowing a
// Google Play download host, a node type that cannot relay UDP, and a host
// resolver that hangs for seconds.
const (
	diagnosticsLogBytes     = 1 << 20
	diagnosticsProbeTimeout = 6 * time.Second
	diagnosticsMaxFailures  = 5
	diagnosticsMaxErrors    = 5
	diagnosticsDomainProbe  = "www.gstatic.com"
)

var (
	diagnosticsInboundRE = regexp.MustCompile(`inbound connection to (\S+)`)
	diagnosticsDirectRE  = regexp.MustCompile(`open connection to (\S+) using outbound/direct\[direct\]`)
	diagnosticsIDRE      = regexp.MustCompile(`^\[\S+ \S+\] `)
)

// diagnosticsResolverLookup is replaced by tests.
var diagnosticsResolverLookup = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

type diagnosticsCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type diagnosticsFailure struct {
	Destination string `json:"destination"`
	Count       int    `json:"count"`
}

type diagnosticsConnections struct {
	Total  int `json:"total"`
	IPv4   int `json:"ipv4"`
	IPv6   int `json:"ipv6"`
	Domain int `json:"domain"`
}

type diagnosticsLog struct {
	Lines          int                    `json:"lines"`
	LogLevel       string                 `json:"log_level"`
	FirstTimestamp string                 `json:"first_timestamp,omitempty"`
	LastTimestamp  string                 `json:"last_timestamp,omitempty"`
	Connections    diagnosticsConnections `json:"connections"`
	UDPSessions    int                    `json:"udp_sessions"`
	UDPBlocked     int                    `json:"udp_blocked"`
	ErrorCount     int                    `json:"error_count"`
	DirectFailures []diagnosticsFailure   `json:"direct_failures,omitempty"`
	RecentErrors   []string               `json:"recent_errors,omitempty"`
}

type diagnosticsSummary struct {
	OK      int    `json:"ok"`
	Failed  int    `json:"failed"`
	Verdict string `json:"verdict"`
}

type diagnosticsOutbound struct {
	TCP        string `json:"tcp"`
	UDP        string `json:"udp"`
	UDPRelay   bool   `json:"udp_relay"`
	UDPBlocked bool   `json:"udp_blocked"`
}

type diagnosticsDNS struct {
	Enabled               bool   `json:"enabled"`
	Remote                string `json:"remote"`
	Direct                string `json:"direct"`
	Strategy              string `json:"strategy"`
	DefaultDomainResolver string `json:"default_domain_resolver"`
}

type diagnosticsRules struct {
	ForceProxySuffixes int  `json:"force_proxy_suffixes"`
	ChinaDirect        bool `json:"china_direct"`
}

type diagnosticsReport struct {
	GeneratedAt    time.Time           `json:"generated_at"`
	Version        string              `json:"version"`
	Mode           string              `json:"mode"`
	ProxyPort      int                 `json:"proxy_port"`
	ProxyRunning   bool                `json:"proxy_running"`
	SingBoxVersion string              `json:"sing_box_version,omitempty"`
	Outbound       diagnosticsOutbound `json:"outbound"`
	DNS            diagnosticsDNS      `json:"dns"`
	Rules          diagnosticsRules    `json:"rules"`
	Log            diagnosticsLog      `json:"log"`
	Checks         []diagnosticsCheck  `json:"checks"`
	Summary        diagnosticsSummary  `json:"summary"`
}

func apiDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Read-only endpoint: it must not mutate the running proxy port.
	json.NewEncoder(w).Encode(buildDiagnostics(r.Context(), s))
}

func buildDiagnostics(ctx context.Context, s Store) diagnosticsReport {
	port := getProxyPort()
	if s.ProxyPort > 0 {
		port = s.ProxyPort
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	report := diagnosticsReport{
		GeneratedAt:    time.Now(),
		Version:        version,
		Mode:           s.Mode,
		ProxyPort:      port,
		ProxyRunning:   proxyRunningFn(),
		SingBoxVersion: singBoxVersion(),
	}
	report.Log = readDiagnosticsLog()
	report.Log.LogLevel = effectiveLogLevel(s)

	tcpOutbound, udpOutbound := resolveOutbounds(s)
	report.Outbound = diagnosticsOutbound{
		TCP:        tcpOutbound,
		UDP:        udpOutbound,
		UDPRelay:   !udpOutboundCannotRelay(s, udpOutbound),
		UDPBlocked: s.Mode != "gfw" && udpOutboundCannotRelay(s, udpOutbound),
	}
	remote, direct, _, strategy := effectiveDNS(s)
	report.DNS = diagnosticsDNS{
		Enabled:               s.DNS.Enabled,
		Remote:                remote,
		Direct:                direct,
		Strategy:              strategy,
		DefaultDomainResolver: "remote-dns",
	}
	report.Rules = diagnosticsRules{ForceProxySuffixes: len(forceProxyDomainSuffixes(s)), ChinaDirect: configHasChinaDirectRule(s)}

	checks := make([]diagnosticsCheck, 0, 10)
	var mu sync.Mutex
	add := func(check diagnosticsCheck) {
		mu.Lock()
		checks = append(checks, check)
		mu.Unlock()
	}
	var wg sync.WaitGroup
	wg.Add(5)
	go func() { defer wg.Done(); add(probePortCheck(address)) }()
	go func() { defer wg.Done(); add(probeDomainCheck(address)) }()
	go func() { defer wg.Done(); add(probeIPModeCheck(address)) }()
	go func() { defer wg.Done(); add(probeUDPCheck(address, report.Outbound)) }()
	go func() { defer wg.Done(); add(probeResolverCheck(ctx)) }()
	wg.Wait()

	checks = append(checks, singBoxConfigCheck(), ipv6Check(report.Log), logLevelCheck(report.Log.LogLevel), udpOutboundCheck(report.Outbound), rulesCheck(report.Rules), proxyRunningCheck(report.ProxyRunning))
	report.Checks = orderDiagnosticsChecks(checks)
	for _, check := range report.Checks {
		if check.OK {
			report.Summary.OK++
			continue
		}
		report.Summary.Failed++
	}
	switch report.Summary.Failed {
	case 0:
		report.Summary.Verdict = "全部检查通过"
	case 1:
		report.Summary.Verdict = "存在 1 项需要关注"
	default:
		report.Summary.Verdict = fmt.Sprintf("存在 %d 项需要关注", report.Summary.Failed)
	}
	return report
}

// diagnosticsCheckOrder is the presentation order of the checks.
var diagnosticsCheckOrder = []string{
	"代理服务",
	"代理端口",
	"sing-box 配置",
	"域名模式探测",
	"IP 模式探测（含 SNI）",
	"强制代理规则",
	"IPv6 流量",
	"UDP 中继",
	"UDP 出站配置",
	"主机解析器",
	"日志级别",
}

func orderDiagnosticsChecks(checks []diagnosticsCheck) []diagnosticsCheck {
	rank := make(map[string]int, len(diagnosticsCheckOrder))
	for i, name := range diagnosticsCheckOrder {
		rank[name] = i
	}
	sort.SliceStable(checks, func(i, j int) bool {
		left, ok := rank[checks[i].Name]
		if !ok {
			left = len(diagnosticsCheckOrder)
		}
		right, ok := rank[checks[j].Name]
		if !ok {
			right = len(diagnosticsCheckOrder)
		}
		return left < right
	})
	return checks
}

func effectiveLogLevel(s Store) string {
	if strings.TrimSpace(s.LogLevel) == "" {
		return "info"
	}
	return strings.ToLower(strings.TrimSpace(s.LogLevel))
}

func configHasChinaDirectRule(s Store) bool {
	route, ok := config(s)["route"].(map[string]any)
	if !ok {
		return false
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return false
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tags, ok := rule["rule_set"].([]string)
		if !ok {
			continue
		}
		for _, tag := range tags {
			if tag == "geosite-cn" || tag == "geoip-cn" {
				return true
			}
		}
	}
	return false
}

func singBoxVersion() string {
	out, err := runCommandTimeout(5*time.Second, "sing-box", "version")
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line)
}

func singBoxConfigCheck() diagnosticsCheck {
	check := diagnosticsCheck{Name: "sing-box 配置"}
	checker, err := exec.LookPath("sing-box")
	if err != nil {
		check.Detail = "未安装 sing-box"
		return check
	}
	out, err := runCommandTimeout(10*time.Second, checker, "check", "-c", configPath)
	if err != nil {
		check.Detail = "校验失败: " + strings.TrimSpace(string(out))
		return check
	}
	check.OK = true
	check.Detail = "配置有效"
	return check
}

func proxyRunningCheck(running bool) diagnosticsCheck {
	check := diagnosticsCheck{Name: "代理服务", OK: running}
	if running {
		check.Detail = "sing-box 服务运行中"
		return check
	}
	check.Detail = "sing-box 服务未运行，以下探测结果不代表路由配置问题"
	return check
}

func probePortCheck(address string) diagnosticsCheck {
	check := diagnosticsCheck{Name: "代理端口"}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		check.Detail = fmt.Sprintf("无法连接 %s: %v", address, err)
		return check
	}
	_ = conn.Close()
	check.OK = true
	check.Detail = fmt.Sprintf("%s 可连接 (%.0f ms)", address, time.Since(start).Seconds()*1000)
	return check
}

// probeDomainCheck sends the hostname to the proxy, which is what a client with
// remote DNS resolution does.
func probeDomainCheck(address string) diagnosticsCheck {
	check := diagnosticsCheck{Name: "域名模式探测"}
	proxyURL := &url.URL{Scheme: "socks5", Host: address}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport, Timeout: diagnosticsProbeTimeout}
	start := time.Now()
	resp, err := client.Get("https://" + diagnosticsDomainProbe + "/generate_204")
	if err != nil {
		check.Detail = fmt.Sprintf("%s 失败: %v", diagnosticsDomainProbe, err)
		return check
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	elapsed := time.Since(start)
	check.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	check.Detail = fmt.Sprintf("%s %d / %.2fs", diagnosticsDomainProbe, resp.StatusCode, elapsed.Seconds())
	return check
}

// probeIPModeCheck resolves the host locally and connects to the bare address
// with the real SNI, which is what an upstream gateway that resolves DNS itself
// (OpenWrt passwall, a router, a SOCKS client without remote resolution) hands
// over. It proves that sniffing plus the forced-proxy rules still pick the
// proxy for an IP destination.
func probeIPModeCheck(address string) diagnosticsCheck {
	check := diagnosticsCheck{Name: "IP 模式探测（含 SNI）"}
	ctx, cancel := context.WithTimeout(context.Background(), diagnosticsProbeTimeout)
	defer cancel()
	source := "本地解析"
	ips, err := diagnosticsResolverLookup(ctx, diagnosticsDomainProbe)
	if err != nil || len(ips) == 0 {
		// An upstream gateway resolves DNS itself and hands over an address, so
		// this probe must answer "does an IP destination reach the proxy" even
		// on a host whose own resolver (or UDP 53 egress) is broken, which is
		// exactly the situation that made this diagnosis hard. Resolve through
		// the proxy instead: a DoH query over the tunnel, then a bare IP
		// destination carrying the real SNI.
		fallback, fallbackErr := resolveThroughProxy(address, diagnosticsDomainProbe, diagnosticsProbeTimeout)
		if fallbackErr != nil {
			check.Detail = fmt.Sprintf("解析 %s 失败（本地: %v；经代理 DoH: %v）", diagnosticsDomainProbe, err, fallbackErr)
			return check
		}
		ips = fallback
		source = "经代理 DoH"
	}
	target := ""
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			target = ip
			break
		}
	}
	if target == "" && len(ips) > 0 {
		target = ips[0]
	}
	if target == "" {
		check.Detail = fmt.Sprintf("%s 没有解析结果", diagnosticsDomainProbe)
		return check
	}
	start := time.Now()
	conn, err := dialSocks5(address, target, 443, diagnosticsProbeTimeout)
	if err != nil {
		check.Detail = fmt.Sprintf("以 %s 连接失败: %v", target, err)
		return check
	}
	defer conn.Close()
	// The certificate is irrelevant here: the probe only checks that the tunnel
	// carries a TLS handshake whose SNI drives the routing decision.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: diagnosticsDomainProbe, InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(diagnosticsProbeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		check.Detail = fmt.Sprintf("以 %s 连接后 TLS 握手失败: %v", target, err)
		return check
	}
	check.OK = true
	check.Detail = fmt.Sprintf("%s:443 经代理完成 TLS 握手 / %.2fs（%s）", target, time.Since(start).Seconds(), source)
	return check
}

func probeUDPCheck(address string, outbound diagnosticsOutbound) diagnosticsCheck {
	check := diagnosticsCheck{Name: "UDP 中继"}
	accepted, replied, detail := probeUDPAssociate(address, diagnosticsProbeTimeout)
	if replied {
		check.OK = true
		check.Detail = detail
		return check
	}
	if outbound.UDPBlocked {
		// Blocking is the intended behaviour for a node that cannot relay UDP:
		// QUIC fails immediately and clients fall back to TCP.
		check.OK = true
		check.Detail = fmt.Sprintf("UDP 出站 %s 不支持中继，已改为 block（QUIC 会回落 TCP）: %s", outbound.UDP, detail)
		return check
	}
	if !accepted {
		check.Detail = detail
		return check
	}
	check.Detail = detail
	return check
}

func ipv6Check(summary diagnosticsLog) diagnosticsCheck {
	check := diagnosticsCheck{Name: "IPv6 流量"}
	switch {
	case summary.Connections.IPv6 > 0:
		check.OK = true
		check.Detail = fmt.Sprintf("最近 %d 条日志中有 %d 个 IPv6 目标", summary.Lines, summary.Connections.IPv6)
	case summary.Connections.Total == 0:
		check.OK = true
		check.Detail = "最近日志没有连接记录（没有流量，或日志级别高于 info），无法判断 IPv6 是否被代理"
	default:
		check.Detail = fmt.Sprintf("最近 %d 个连接中没有 IPv6 目标：上游可能没有代理 IPv6，客户端会优先走 IPv6 并被运营商黑洞", summary.Connections.Total)
	}
	return check
}

// diagnosticsDoHEndpoints are queried over the proxy by literal address, so no
// host resolution or external UDP 53 access is required.
var diagnosticsDoHEndpoints = []struct {
	address string
	sni     string
	query   string
}{
	{address: "1.1.1.1", sni: "cloudflare-dns.com", query: "/dns-query?name=%s&type=A"},
	{address: "8.8.8.8", sni: "dns.google", query: "/resolve?name=%s&type=A"},
	{address: "223.5.5.5", sni: "dns.alidns.com", query: "/resolve?name=%s&type=A"},
}

// resolveThroughProxy asks a DNS-over-HTTPS endpoint reached through the proxy
// for A records.
func resolveThroughProxy(address, host string, timeout time.Duration) ([]string, error) {
	var lastErr error
	for _, endpoint := range diagnosticsDoHEndpoints {
		ips, err := queryDoHThroughProxy(address, endpoint.address, endpoint.sni, fmt.Sprintf(endpoint.query, url.QueryEscape(host)), timeout)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s 没有返回 A 记录", endpoint.sni)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用的 DoH 端点")
	}
	return nil, lastErr
}

func queryDoHThroughProxy(address, dohAddress, sni, path string, timeout time.Duration) ([]string, error) {
	conn, err := dialSocks5(address, dohAddress, 443, timeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sni, err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("%s TLS: %w", sni, err)
	}
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n", path, sni)
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return nil, fmt.Errorf("%s: %w", sni, err)
	}
	payload, err := io.ReadAll(io.LimitReader(tlsConn, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sni, err)
	}
	return parseDoHAnswers(payload)
}

// parseDoHAnswers extracts A records from a DNS-over-HTTPS JSON answer, given
// the raw HTTP response.
func parseDoHAnswers(payload []byte) ([]string, error) {
	if index := bytes.Index(payload, []byte("\r\n\r\n")); index >= 0 {
		payload = payload[index+4:]
	}
	var answer struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(payload, &answer); err != nil {
		return nil, fmt.Errorf("DoH 响应无法解析: %w", err)
	}
	records := make([]string, 0, len(answer.Answer))
	for _, record := range answer.Answer {
		if record.Type != 1 {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(record.Data)); ip != nil && ip.To4() != nil {
			records = append(records, ip.String())
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("DoH 响应没有 A 记录 (status=%d)", answer.Status)
	}
	return records, nil
}

func logLevelCheck(level string) diagnosticsCheck {
	check := diagnosticsCheck{Name: "日志级别", OK: true}
	check.Detail = level
	if level == "warn" || level == "error" {
		check.OK = false
		check.Detail = fmt.Sprintf("日志级别为 %s，连接统计为空；如需统计请在「服务与组件」中临时调为 info", level)
	}
	return check
}

func udpOutboundCheck(outbound diagnosticsOutbound) diagnosticsCheck {
	check := diagnosticsCheck{Name: "UDP 出站配置"}
	check.OK = outbound.UDPRelay && !outbound.UDPBlocked
	check.Detail = fmt.Sprintf("UDP 出站 %s", outbound.UDP)
	if !outbound.UDPRelay {
		check.Detail = fmt.Sprintf("UDP 出站 %s 不能中继 UDP", outbound.UDP)
		if outbound.UDPBlocked {
			check.OK = true
			check.Detail += "，已改为 block（QUIC 立刻失败并回落 TCP）"
		}
	}
	return check
}

func rulesCheck(rules diagnosticsRules) diagnosticsCheck {
	check := diagnosticsCheck{Name: "强制代理规则", OK: rules.ForceProxySuffixes > 0}
	if rules.ChinaDirect {
		check.Detail = fmt.Sprintf("%d 条强制代理后缀规则先于国内直连规则", rules.ForceProxySuffixes)
		return check
	}
	check.Detail = fmt.Sprintf("%d 条强制代理后缀规则（当前模式没有国内直连规则）", rules.ForceProxySuffixes)
	return check
}

func probeResolverCheck(ctx context.Context) diagnosticsCheck {
	check := diagnosticsCheck{Name: "主机解析器"}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	ips, err := diagnosticsResolverLookup(lookupCtx, diagnosticsDomainProbe)
	elapsed := time.Since(start)
	if err != nil {
		check.Detail = fmt.Sprintf("解析 %s 失败（%.1fs）: %v", diagnosticsDomainProbe, elapsed.Seconds(), err)
		return check
	}
	check.OK = true
	check.Detail = fmt.Sprintf("%s 解析到 %d 个地址 / %.0f ms", diagnosticsDomainProbe, len(ips), elapsed.Seconds()*1000)
	return check
}

// readDiagnosticsLog reads the tail of the sing-box log.
func readDiagnosticsLog() diagnosticsLog {
	path := filepath.Join(logDir, "sing-box.log")
	file, err := os.Open(path)
	if err != nil {
		return diagnosticsLog{}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return diagnosticsLog{}
	}
	size := info.Size()
	truncated := size > diagnosticsLogBytes
	if truncated {
		if _, err := file.Seek(size-diagnosticsLogBytes, io.SeekStart); err != nil {
			return diagnosticsLog{}
		}
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return diagnosticsLog{}
	}
	if truncated {
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			data = data[index+1:]
		}
	}
	return summarizeProxyLog(data)
}

// summarizeProxyLog counts connections by destination family, UDP sessions and
// direct-outbound failures in raw sing-box log lines.
func summarizeProxyLog(data []byte) diagnosticsLog {
	summary := diagnosticsLog{}
	failures := map[string]int{}
	recent := make([]string, 0, 8)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		summary.Lines++
		if stamp := logLineTimestamp(line); stamp != "" {
			if summary.FirstTimestamp == "" {
				summary.FirstTimestamp = stamp
			}
			summary.LastTimestamp = stamp
		}
		switch {
		// sing-box reports a blocked datagram twice: an info line
		// ("blocked packet connection to …") and an error line
		// ("listen packet connection using outbound/block …").
		case strings.Contains(line, "outbound/block[block]"):
			summary.UDPBlocked++
			if strings.Contains(line, "ERROR") {
				summary.ErrorCount++
				recent = append(recent, trimLogPrefix(line))
			}
		case strings.Contains(line, "inbound/mixed") && strings.Contains(line, "packet connection"):
			summary.UDPSessions++
		case strings.Contains(line, "inbound connection to "):
			match := diagnosticsInboundRE.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			summary.Connections.Total++
			switch {
			case strings.HasPrefix(match[1], "["):
				summary.Connections.IPv6++
			case isIPv4Destination(match[1]):
				summary.Connections.IPv4++
			default:
				summary.Connections.Domain++
			}
		case strings.Contains(line, "ERROR"):
			summary.ErrorCount++
			if match := diagnosticsDirectRE.FindStringSubmatch(line); match != nil {
				failures[match[1]]++
			} else {
				recent = append(recent, trimLogPrefix(line))
			}
		}
	}
	if len(failures) > 0 {
		destinations := make([]diagnosticsFailure, 0, len(failures))
		for destination, count := range failures {
			destinations = append(destinations, diagnosticsFailure{Destination: destination, Count: count})
		}
		sort.Slice(destinations, func(i, j int) bool {
			if destinations[i].Count != destinations[j].Count {
				return destinations[i].Count > destinations[j].Count
			}
			return destinations[i].Destination < destinations[j].Destination
		})
		if len(destinations) > diagnosticsMaxFailures {
			destinations = destinations[:diagnosticsMaxFailures]
		}
		summary.DirectFailures = destinations
	}
	if len(recent) > diagnosticsMaxErrors {
		recent = recent[len(recent)-diagnosticsMaxErrors:]
	}
	summary.RecentErrors = recent
	return summary
}

func logLineTimestamp(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ""
	}
	offset := fields[0]
	if len(offset) < 5 || !(strings.HasPrefix(offset, "+") || strings.HasPrefix(offset, "-")) {
		return ""
	}
	return fields[1] + " " + fields[2]
}

func trimLogPrefix(line string) string {
	fields := strings.Fields(line)
	if logLineTimestamp(line) != "" && len(fields) > 3 {
		line = strings.Join(fields[3:], " ")
	}
	return diagnosticsIDRE.ReplaceAllString(line, "")
}

func isIPv4Destination(destination string) bool {
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

// dialSocks5 performs a SOCKS5 CONNECT for a host name or a literal address.
func dialSocks5(address, host string, port int, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 认证失败")
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 0x01)
			request = append(request, v4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("主机名过长")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 连接被拒绝 (reply %d)", header[1])
	}
	if _, _, err := readSocks5Address(conn, header[3]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func readSocks5Address(reader io.Reader, atyp byte) (net.IP, int, error) {
	var ip net.IP
	switch atyp {
	case 0x01:
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return nil, 0, err
		}
		ip = net.IP(buffer)
	case 0x04:
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return nil, 0, err
		}
		ip = net.IP(buffer)
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return nil, 0, err
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, host); err != nil {
			return nil, 0, err
		}
	default:
		return nil, 0, fmt.Errorf("未知的 SOCKS5 地址类型 %d", atyp)
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return nil, 0, err
	}
	return ip, int(binary.BigEndian.Uint16(portBytes)), nil
}

// probeUDPAssociate asks the proxy for a UDP relay and sends one DNS query
// through it.
func probeUDPAssociate(address string, timeout time.Duration) (bool, bool, string) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, false, fmt.Sprintf("无法连接 %s: %v", address, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, false, err.Error()
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false, false, err.Error()
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 0x05 {
		return false, false, "SOCKS5 握手失败"
	}
	request := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(request); err != nil {
		return false, false, err.Error()
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false, false, "读取 UDP ASSOCIATE 应答失败"
	}
	relayIP, relayPort, err := readSocks5Address(conn, header[3])
	if header[1] != 0x00 {
		return false, false, fmt.Sprintf("UDP ASSOCIATE 被拒绝 (rep=%d)", header[1])
	}
	if err != nil {
		return false, false, err.Error()
	}
	if relayIP == nil || relayIP.IsUnspecified() {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return true, false, "应答中没有中继地址"
		}
		relayIP = net.ParseIP(host)
	}
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: relayPort})
	if err != nil {
		return true, false, fmt.Sprintf("UDP 套接字创建失败: %v", err)
	}
	defer udpConn.Close()
	if err := udpConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return true, false, err.Error()
	}
	packet := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}
	packet = append(packet, dnsQuery(diagnosticsDomainProbe)...)
	if _, err := udpConn.Write(packet); err != nil {
		return true, false, fmt.Sprintf("UDP 发送失败: %v", err)
	}
	buffer := make([]byte, 1500)
	read, err := udpConn.Read(buffer)
	if err != nil || read == 0 {
		return true, false, "已接受 UDP ASSOCIATE 但没有应答（UDP 未真正中继）"
	}
	return true, true, fmt.Sprintf("UDP 中继可用（返回 %d 字节）", read)
}

func dnsQuery(host string) []byte {
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00, 0x00, 0x01, 0x00, 0x01)
	return query
}
