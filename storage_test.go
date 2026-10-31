package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreRevisionIncrementsAndPersists(t *testing.T) {
	setupAPITest(t, Store{Mode: "global", ProxyPort: 11080})
	initial := load()
	initialRev := initial.Revision
	initial.Mode = "bypass_cn"
	if err := save(initial); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	updated := load()
	if updated.Revision <= initialRev {
		t.Fatalf("expected revision to increment, got initial=%d, updated=%d", initialRev, updated.Revision)
	}
}

func TestSQLiteRoundTrip(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath = oldDB; dataPath = oldData })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	want := Store{Mode: "gfw", ProxyPort: 11080, SelectedNode: "n1", TCPOutbound: "g1", UDPOutbound: "same", DNS: DNSSettings{Enabled: true, RemoteServer: "https://1.1.1.1/dns-query", RemoteSNI: "cloudflare-dns.com", DirectServer: "udp://223.5.5.5", Strategy: "prefer_ipv4", Hijack: true}, RuleSettings: map[string]RuleUpdateSetting{"geosite-ads": {BackupURL: "https://example.com/ads.srs", AutoUpdate: true, UpdateHours: 12, LastUpdated: time.Now().UTC().Truncate(time.Second)}}, ACLRules: []ACLRule{{ID: "a1", Name: "客户端", Enabled: true, SourceCIDRs: []string{"192.168.10.20/32"}, Network: "tcp", PortRanges: []string{"443"}, Outbound: "direct"}}, StrategyGroups: []StrategyGroup{{ID: "g1", Name: "自动选择", Type: "urltest", NodeIDs: []string{"n1"}, Selected: "n1", TestURL: "https://example.com/204", IntervalSec: 180, ToleranceMS: 50}}, Subscriptions: []Subscription{{ID: "s1", Name: "测试订阅", URL: "https://example.com/sub", UpdateHours: 6, Enabled: true}}, Nodes: []Node{{ID: "n1", Name: "节点", NameOverride: "自定义", GroupOverride: "我的分组", NaivePort: 12009, Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true, Group: "测试订阅", SubscriptionID: "s1"}}}
	if err := save(want); err != nil {
		t.Fatal(err)
	}
	got := load()
	if len(got.Nodes) != 1 || len(got.Subscriptions) != 1 || len(got.StrategyGroups) != 1 || len(got.ACLRules) != 1 || !got.DNS.Enabled || got.Nodes[0].SubscriptionID != "s1" || got.Nodes[0].NameOverride != "自定义" || got.Nodes[0].GroupOverride != "我的分组" || got.Nodes[0].NaivePort != 12009 || got.ProxyPort != 11080 || got.TCPOutbound != "g1" || !got.RuleSettings["geosite-ads"].AutoUpdate || got.RuleSettings["geosite-ads"].UpdateHours != 12 {
		t.Fatalf("unexpected round trip: %+v", got)
	}
}

func TestSQLiteSettingsWithoutNodesDoNotFallBackToJSON(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath = oldDB; dataPath = oldData })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := saveDB(Store{Mode: "global", ProxyPort: 12080, LogLevel: "debug", DNS: DNSSettings{Enabled: true, ListenAddress: "192.168.10.1", ListenPort: 53, RemoteServer: "https://1.1.1.1/dns-query", DirectServer: "udp://223.5.5.5"}}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(Store{Mode: "bypass_cn", ProxyPort: 11080}); err != nil {
		t.Fatal(err)
	}
	got := load()
	if got.Mode != "global" || got.ProxyPort != 12080 || got.LogLevel != "debug" || !got.DNS.Enabled {
		t.Fatalf("settings-only database was not used: %+v", got)
	}
}

func TestCorruptSQLiteDoesNotFallBackToJSON(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := os.WriteFile(dbPath, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(Store{Mode: "global", ProxyPort: 12080}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("corrupt SQLite database unexpectedly fell back to JSON")
	}
}

func TestCorruptNodePayloadRefusesLoad(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData; closeDB() })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := save(Store{Mode: "global", Nodes: []Node{{ID: "n1", Type: "anytls", Server: "example.com", Port: 443, Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	db, err := openDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE nodes SET payload = ? WHERE id = ?", "{broken", "n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil || !strings.Contains(err.Error(), "corrupted node payload") {
		t.Fatalf("corrupted node payload was not refused: %v", err)
	}
}

func TestLegacyMigration(t *testing.T) {
	s := migrateLegacy(Store{SubscriptionURLs: []string{"https://example.com/sub"}, Nodes: []Node{{ID: "sub-1", Name: "legacy"}}})
	if len(s.Subscriptions) != 1 || s.Nodes[0].SubscriptionID == "" || !s.Nodes[0].Enabled {
		t.Fatalf("migration failed: %+v", s)
	}
}

func TestLegacyJSONMigrationArchivesSourceAndPersistsSchemaVersion(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData; closeDB() })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	legacy := Store{Mode: "global", ProxyPort: 11080, StrategyGroups: []StrategyGroup{{ID: "g1", Name: "old fallback", Type: "fallback"}}}
	if err := saveJSON(legacy); err != nil {
		t.Fatal(err)
	}
	got, err := loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.StrategyGroups[0].Type != "urltest" {
		t.Fatalf("legacy strategy migration = version %d type %q", got.SchemaVersion, got.StrategyGroups[0].Type)
	}
	if _, err := os.Stat(dataPath); !os.IsNotExist(err) {
		t.Fatalf("legacy credential file was not archived, stat error=%v", err)
	}
	if _, err := os.Stat(dataPath + ".migrated"); err != nil {
		t.Fatalf("legacy archive missing: %v", err)
	}
	got, err = loadStore()
	if err != nil || got.SchemaVersion != 1 || got.StrategyGroups[0].Type != "urltest" {
		t.Fatalf("migrated store did not round trip: %+v err=%v", got, err)
	}
}

func TestLegacyJSONMigrationRefusesCorruptSourceAndArchiveCollision(t *testing.T) {
	oldDB, oldData := dbPath, dataPath
	t.Cleanup(func() { dbPath, dataPath = oldDB, oldData; closeDB() })
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "armwall.db")
	dataPath = filepath.Join(dir, "store.json")
	if err := os.WriteFile(dataPath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("expected corrupt legacy JSON to be rejected")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("corrupt migration created a database: %v", err)
	}
	if err := os.WriteFile(dataPath, []byte(`{"mode":"global"}`), 0600); err != nil {
		t.Fatal(err)
	}
	archivePath := dataPath + ".migrated"
	if err := os.WriteFile(archivePath, []byte("previous archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStore(); err == nil {
		t.Fatal("expected existing migration archive to block overwrite")
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil || string(archive) != "previous archive" {
		t.Fatalf("existing migration archive changed: %q, %v", archive, err)
	}
}
