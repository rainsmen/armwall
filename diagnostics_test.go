package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSummarizeProxyLogCountsConnections(t *testing.T) {
	lines := []string{
		"+0800 2026-11-03 19:00:01 INFO [1 0ms] inbound/mixed[mixed-in]: inbound connection to 142.251.214.99:443",
		"+0800 2026-11-03 19:00:02 INFO [2 1ms] inbound/mixed[mixed-in]: inbound connection to [2001:4860:4844:400::]:443",
		"+0800 2026-11-03 19:00:03 INFO [3 2ms] inbound/mixed[mixed-in]: inbound connection to www.gstatic.com:443",
		"+0800 2026-11-03 19:00:04 INFO [4 1ms] inbound/mixed[mixed-in]: inbound packet connection from 192.168.10.1:5000",
		"+0800 2026-11-03 19:00:05 ERROR [5 6ms] connection: listen packet connection using  using outbound/block[block]: operation not permitted",
		"+0800 2026-11-03 19:00:05 INFO [5 5ms] outbound/block[block]: blocked packet connection to 8.8.8.8:53",
		"+0800 2026-11-03 19:00:06 ERROR [6 5.1s] connection: open connection to 142.251.214.99:443 using outbound/direct[direct]: dial tcp 142.251.214.99:443: i/o timeout",
		"+0800 2026-11-03 19:00:07 INFO [7 3ms] inbound/mixed[mixed-in]: inbound connection from 192.168.10.1:5001",
	}
	summary := summarizeProxyLog([]byte(strings.Join(lines, "\n")))
	if summary.Lines != 8 {
		t.Fatalf("lines=%d", summary.Lines)
	}
	if summary.Connections.Total != 3 || summary.Connections.IPv4 != 1 || summary.Connections.IPv6 != 1 || summary.Connections.Domain != 1 {
		t.Fatalf("unexpected connection counts: %+v", summary.Connections)
	}
	if summary.UDPSessions != 1 {
		t.Fatalf("udp sessions=%d", summary.UDPSessions)
	}
	if summary.UDPBlocked != 2 {
		t.Fatalf("udp blocked=%d", summary.UDPBlocked)
	}
	if summary.ErrorCount != 2 {
		t.Fatalf("error count=%d", summary.ErrorCount)
	}
	if len(summary.DirectFailures) != 1 || summary.DirectFailures[0].Destination != "142.251.214.99:443" || summary.DirectFailures[0].Count != 1 {
		t.Fatalf("unexpected direct failures: %+v", summary.DirectFailures)
	}
	if summary.LastTimestamp != "2026-11-03 19:00:07" || summary.FirstTimestamp != "2026-11-03 19:00:01" {
		t.Fatalf("timestamps: %q .. %q", summary.FirstTimestamp, summary.LastTimestamp)
	}
	if len(summary.RecentErrors) == 0 || strings.HasPrefix(summary.RecentErrors[0], "+0800") {
		t.Fatalf("recent errors must be trimmed: %+v", summary.RecentErrors)
	}
}

func TestDiagnosticsEndpointReportsChecks(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "naive", Type: "naive", Server: "naive.example", Port: 443, Username: "user", Password: "secret", Enabled: true}}})
	if err := os.MkdirAll(logDir, 0750); err != nil {
		t.Fatal(err)
	}
	logLine := "+0800 2026-11-03 19:00:01 INFO [1 0ms] inbound/mixed[mixed-in]: inbound connection to 142.251.214.99:443\n"
	if err := os.WriteFile(filepath.Join(logDir, "sing-box.log"), []byte(logLine), 0640); err != nil {
		t.Fatal(err)
	}
	oldLookup := diagnosticsResolverLookup
	diagnosticsResolverLookup = func(context.Context, string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}
	t.Cleanup(func() { diagnosticsResolverLookup = oldLookup })

	recorder := callAPIGet(t, "/api/diagnostics")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var report diagnosticsReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.ProxyPort != 11080 || report.Mode != "global" {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if report.Log.Connections.IPv4 != 1 || report.Log.Connections.Total != 1 {
		t.Fatalf("unexpected log summary: %+v", report.Log)
	}
	if !report.Outbound.UDPBlocked || report.Outbound.UDPRelay {
		t.Fatalf("naive UDP must be reported as blocked: %+v", report.Outbound)
	}
	if report.Rules.ForceProxySuffixes == 0 {
		t.Fatalf("built-in force proxy suffixes must be reported: %+v", report.Rules)
	}
	checks := map[string]diagnosticsCheck{}
	for _, check := range report.Checks {
		if _, duplicate := checks[check.Name]; duplicate {
			t.Fatalf("duplicate check %s", check.Name)
		}
		checks[check.Name] = check
	}
	for _, name := range []string{"代理服务", "代理端口", "域名模式探测", "IP 模式探测（含 SNI）", "UDP 中继", "UDP 出站配置", "主机解析器", "日志级别", "强制代理规则", "sing-box 配置"} {
		if _, ok := checks[name]; !ok {
			t.Fatalf("missing check %q: %+v", name, report.Checks)
		}
	}
	if !checks["UDP 中继"].OK {
		t.Fatalf("a blocked naive UDP outbound must be reported as expected, not as a failure: %+v", checks["UDP 中继"])
	}
	if report.Summary.OK+report.Summary.Failed != len(report.Checks) {
		t.Fatalf("summary does not match checks: %+v", report.Summary)
	}
	if report.Summary.Verdict == "" {
		t.Fatal("summary verdict is required")
	}
}

func TestDiagnosticsLogLevelWarning(t *testing.T) {
	check := logLevelCheck("warn")
	if check.OK {
		t.Fatalf("a warn log level hides connection statistics and must be reported: %+v", check)
	}
	if !strings.Contains(check.Detail, "info") {
		t.Fatalf("the hint must mention the info level: %+v", check)
	}
	if ok := logLevelCheck("info"); !ok.OK {
		t.Fatalf("info log level should pass: %+v", ok)
	}
}

func TestIPv6CheckWithoutTrafficIsInconclusive(t *testing.T) {
	if check := ipv6Check(diagnosticsLog{}); !check.OK {
		t.Fatalf("no traffic must be inconclusive rather than a failure: %+v", check)
	}
	if check := ipv6Check(diagnosticsLog{Connections: diagnosticsConnections{Total: 5, IPv4: 5}}); check.OK {
		t.Fatalf("IPv4-only traffic must be reported: %+v", check)
	}
	if check := ipv6Check(diagnosticsLog{Connections: diagnosticsConnections{Total: 3, IPv4: 2, IPv6: 1}}); !check.OK {
		t.Fatalf("IPv6 traffic must pass: %+v", check)
	}
}

func TestParseDoHAnswersReadsARecords(t *testing.T) {
	body := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\n\r\n" +
		`{"Status":0,"Answer":[{"name":"www.gstatic.com","type":5,"data":"gstatic.l.google.com"},{"name":"www.gstatic.com","type":1,"data":"142.251.215.163"}]}`)
	records, err := parseDoHAnswers(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0] != "142.251.215.163" {
		t.Fatalf("records=%v", records)
	}
	if _, err := parseDoHAnswers([]byte("HTTP/1.1 200 OK\r\n\r\nnot-json")); err == nil {
		t.Fatal("an unparsable body must be rejected")
	}
	if _, err := parseDoHAnswers([]byte("HTTP/1.1 200 OK\r\n\r\n{\"Status\":3}")); err == nil {
		t.Fatal("a response without A records must be rejected")
	}
}
