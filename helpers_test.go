package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func setupAPITest(t *testing.T, initial Store) {
	t.Helper()
	oldDB, oldData, oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldRuleDataDir := dbPath, dataPath, configPath, macACLPath, naiveConfigDir, logDir, ruleDataDir
	oldRestart, oldFetch, oldReload, oldProxyRunning, oldProxyPort, oldTProxyPort, oldTProxyEnabled := restartProxyFn, fetchSubscriptionFn, reloadGatewayFn, proxyRunningFn, getProxyPort(), tproxyPort, tproxyEnabled
	oldGatewayPath, oldGatewayStatePath := gatewayPath, gatewayStatePath
	oldBackupDir, oldCoreUploadDir, oldUpdateCorePath := backupDir, coreUploadDir, updateCorePath
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	configPath = filepath.Join(dir, "sing-box.json")
	macACLPath = filepath.Join(dir, "mac-acl.tsv")
	naiveConfigDir = filepath.Join(dir, "naive")
	logDir = filepath.Join(dir, "logs")
	ruleDataDir = filepath.Join(dir, "rules")
	backupDir = filepath.Join(dir, "backups")
	coreUploadDir = filepath.Join(dir, "uploads")
	gatewayPath = filepath.Join(dir, "gateway")
	gatewayStatePath = filepath.Join(dir, "gateway.state")
	setProxyPort(11080)
	restartProxyFn = func() error { return nil }
	proxyRunningFn = func() bool { return true }
	t.Cleanup(func() {
		dbPath, dataPath, configPath, macACLPath, naiveConfigDir, logDir, ruleDataDir = oldDB, oldData, oldConfig, oldMACACL, oldNaiveConfigDir, oldLogDir, oldRuleDataDir
		restartProxyFn, fetchSubscriptionFn, reloadGatewayFn, proxyRunningFn, tproxyPort, tproxyEnabled = oldRestart, oldFetch, oldReload, oldProxyRunning, oldTProxyPort, oldTProxyEnabled
		setProxyPort(oldProxyPort)
		gatewayPath, gatewayStatePath = oldGatewayPath, oldGatewayStatePath
		backupDir, coreUploadDir, updateCorePath = oldBackupDir, oldCoreUploadDir, oldUpdateCorePath
	})
	if err := save(initial); err != nil {
		t.Fatal(err)
	}
}

func mustWebPrefixes(t *testing.T, raw string) []netip.Prefix {
	t.Helper()
	prefixes, err := parseWebAllowedCIDRs(raw)
	if err != nil {
		t.Fatal(err)
	}
	return prefixes
}

func callAPIGet(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	api(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

func callAPI(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	api(recorder, req)
	return recorder
}
