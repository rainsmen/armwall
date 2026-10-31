package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuleBackupRestoreHandlesExistingAndNewFiles(t *testing.T) {
	dir := t.TempDir()
	oldRuleDataDir := ruleDataDir
	ruleDataDir = dir
	t.Cleanup(func() { ruleDataDir = oldRuleDataDir })

	oldPath := filepath.Join(dir, "existing.srs")
	if err := os.WriteFile(filepath.Join(dir, "existing.srs.bak"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(dir, "new.srs")
	if err := os.WriteFile(newPath, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath+".bak.absent", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreRuleBackups([]string{"existing", "new"}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(oldPath); err != nil || string(got) != "old" {
		t.Fatalf("existing file restore = %q, %v", got, err)
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatalf("new file remains after rollback, stat error=%v", err)
	}
}

func TestRuleSettingsMigrationAndDue(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	s := Store{RuleUpdateHours: 12, RuleBackups: map[string]string{"geosite-ads": "https://backup.example/ads.srs"}}
	normalizeRuleSettings(&s)
	setting := s.RuleSettings["geosite-ads"]
	if setting.BackupURL != "https://backup.example/ads.srs" || setting.UpdateHours != 12 || setting.AutoUpdate {
		t.Fatalf("legacy rule settings were not migrated: %+v", setting)
	}
	setting.AutoUpdate = true
	setting.LastUpdated = now.Add(-11 * time.Hour)
	if ruleUpdateDue(setting, now) {
		t.Fatal("rule should not be due before its interval")
	}
	setting.LastUpdated = now.Add(-12 * time.Hour)
	if !ruleUpdateDue(setting, now) {
		t.Fatal("rule should be due at its interval")
	}
}

func TestUpdateConfiguredRulesHonorsPerRuleSchedule(t *testing.T) {
	oldUpdateRule := updateRuleFn
	t.Cleanup(func() { updateRuleFn = oldUpdateRule })
	calls := map[string]string{}
	updateRuleFn = func(tag, backup string) (bool, error) {
		calls[tag] = backup
		return true, nil
	}
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	s := Store{RuleSettings: map[string]RuleUpdateSetting{
		"geosite-ads": {BackupURL: "https://backup.example/ads.srs", AutoUpdate: true, UpdateHours: 6, LastUpdated: now.Add(-6 * time.Hour)},
		"geosite-cn":  {AutoUpdate: false, UpdateHours: 1},
	}}
	updated, _, err := updateConfiguredRules(&s, false, "", now)
	if err != nil || len(updated) != 1 || updated[0] != "geosite-ads" || calls["geosite-ads"] != "https://backup.example/ads.srs" {
		t.Fatalf("unexpected scheduled update: updated=%v calls=%v err=%v", updated, calls, err)
	}
	if !s.RuleSettings["geosite-ads"].LastUpdated.Equal(now) {
		t.Fatalf("last update was not recorded: %+v", s.RuleSettings["geosite-ads"])
	}
	updated, _, err = updateConfiguredRules(&s, true, "geosite-cn", now.Add(time.Minute))
	if err != nil || len(updated) != 1 || updated[0] != "geosite-cn" || calls["geosite-cn"] != "" {
		t.Fatalf("unexpected manual update: updated=%v calls=%v err=%v", updated, calls, err)
	}
}

func TestRuleSettingsAPIStoresAutoUpdate(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	recorder := callAPI(t, "/api/rules/settings", `{"tag":"geosite-proxy","backup":"https://backup.example/proxy.srs","hours":24,"autoUpdate":true}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	setting := load().RuleSettings["geosite-proxy"]
	if setting.BackupURL != "https://backup.example/proxy.srs" || setting.UpdateHours != 24 || !setting.AutoUpdate {
		t.Fatalf("unexpected stored rule setting: %+v", setting)
	}
}

func TestRuleSettingsAPITogglesAdBlocking(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}})
	recorder := callAPI(t, "/api/rules/settings", `{"tag":"geosite-ads","hours":6,"autoUpdate":false,"adBlockEnabled":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	got := load()
	if got.AdBlockEnabled == nil || *got.AdBlockEnabled {
		t.Fatalf("ad blocking was not disabled: %+v", got.AdBlockEnabled)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configBytes), "geosite-ads") {
		t.Fatalf("generated config still includes ads rule: %s", configBytes)
	}
}

func TestBootstrapRuleUpdatesIgnoreAutoUpdateOptOut(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080, RuleSettings: map[string]RuleUpdateSetting{}})
	oldUpdateRule := updateRuleFn
	t.Cleanup(func() { updateRuleFn = oldUpdateRule })
	calls := 0
	updateRuleFn = func(_, _ string) (bool, error) { calls++; return true, nil }
	if count, err := applyScheduledRuleUpdates(); err != nil || count != 0 || calls != 0 {
		t.Fatalf("scheduled updates should respect opt-out: count=%d calls=%d err=%v", count, calls, err)
	}
	count, err := applyRuleUpdates(true)
	if err != nil || count != len(ruleURLs) || calls != len(ruleURLs) {
		t.Fatalf("bootstrap should force all rules: count=%d calls=%d err=%v", count, calls, err)
	}
}

func TestValidateSRSRejectsInvalidMagic(t *testing.T) {
	if err := validateSRS([]byte("not-a-valid-rule-set")); err == nil {
		t.Fatal("expected invalid SRS magic to be rejected")
	}
}

func TestUnchangedRuleCheckDoesNotRestartProxy(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080, RuleSettings: map[string]RuleUpdateSetting{}})
	restarts := 0
	restartProxyFn = func() error { restarts++; return nil }
	oldUpdateRule := updateRuleFn
	t.Cleanup(func() { updateRuleFn = oldUpdateRule })
	changed := false
	updateRuleFn = func(_, _ string) (bool, error) { return changed, nil }

	if count, err := applyRuleUpdates(true); err != nil || count != len(ruleURLs) {
		t.Fatalf("unchanged check: count=%d err=%v", count, err)
	}
	if restarts != 0 {
		t.Fatalf("unchanged rule content restarted sing-box %d times", restarts)
	}
	s, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	for tag := range ruleURLs {
		if s.RuleSettings[tag].LastUpdated.IsZero() {
			t.Fatalf("check time for %s was not recorded", tag)
		}
	}
	if recorder := callAPI(t, "/api/rules/update", `{"Tag":"geosite-cn"}`); recorder.Code != http.StatusOK || restarts != 0 {
		t.Fatalf("unchanged API rule update: code=%d restarts=%d body=%s", recorder.Code, restarts, recorder.Body.String())
	}

	changed = true
	if _, err := applyRuleUpdates(true); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 {
		t.Fatalf("changed rule content should restart sing-box once, got %d", restarts)
	}
}
