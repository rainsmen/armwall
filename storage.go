package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Subscription struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	UpdateHours int       `json:"update_hours"`
	Enabled     bool      `json:"enabled"`
	LastUpdated time.Time `json:"last_updated"`
}

var dbPath = "/var/lib/armwall/armwall.db"

var (
	dbInstance     *sql.DB
	dbInstanceMu   sync.Mutex
	dbInstancePath string
)

func openDB() (*sql.DB, error) {
	dbInstanceMu.Lock()
	defer dbInstanceMu.Unlock()
	if dbInstance != nil && dbInstancePath == dbPath {
		return dbInstance, nil
	}
	if dbInstance != nil {
		_ = dbInstance.Close()
		dbInstance = nil
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, update_hours INTEGER NOT NULL DEFAULT 6, enabled INTEGER NOT NULL DEFAULT 1, last_updated TEXT);
CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, subscription_id TEXT, group_name TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL);`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	_, _ = db.Exec(`UPDATE nodes SET group_name = COALESCE((SELECT name FROM subscriptions WHERE subscriptions.id = nodes.subscription_id), '') WHERE group_name = '' AND subscription_id <> ''`)
	dbInstance = db
	dbInstancePath = dbPath
	return dbInstance, nil
}

func closeDB() {
	dbInstanceMu.Lock()
	defer dbInstanceMu.Unlock()
	if dbInstance != nil {
		_ = dbInstance.Close()
		dbInstance = nil
		dbInstancePath = ""
	}
}

func loadJSON() (Store, error) {
	b, err := os.ReadFile(dataPath)
	if err != nil {
		return Store{}, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return Store{}, fmt.Errorf("decode legacy JSON store: %w", err)
	}
	return s, nil
}
func saveJSON(s Store) error {
	if err := os.MkdirAll(filepath.Dir(dataPath), 0750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(dataPath, b, 0600)
}

func loadDB() (Store, error) {
	db, err := openDB()
	if err != nil {
		return Store{}, err
	}
	s := Store{Mode: "bypass_cn"}
	rows, err := db.Query("SELECT key,value FROM settings")
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return s, err
		}
		switch k {
		case "revision":
			s.Revision, _ = strconv.ParseInt(v, 10, 64)
		case "schema_version":
			s.SchemaVersion, _ = strconv.Atoi(v)
		case "mode":
			s.Mode = v
		case "proxy_port":
			s.ProxyPort, _ = strconv.Atoi(v)
		case "selected_node":
			s.SelectedNode = v
		case "update_hours":
			s.UpdateHours, _ = strconv.Atoi(v)
		case "log_level":
			s.LogLevel = v
		case "rule_update_hours":
			s.RuleUpdateHours, _ = strconv.Atoi(v)
		case "rule_backups":
			if err := json.Unmarshal([]byte(v), &s.RuleBackups); err != nil {
				rows.Close()
				return s, err
			}
		case "rule_settings":
			if err := json.Unmarshal([]byte(v), &s.RuleSettings); err != nil {
				rows.Close()
				return s, err
			}
		case "strategy_groups":
			if err := json.Unmarshal([]byte(v), &s.StrategyGroups); err != nil {
				rows.Close()
				return s, err
			}
		case "tcp_outbound":
			s.TCPOutbound = v
		case "udp_outbound":
			s.UDPOutbound = v
		case "acl_rules":
			if err := json.Unmarshal([]byte(v), &s.ACLRules); err != nil {
				rows.Close()
				return s, err
			}
		case "dns":
			if err := json.Unmarshal([]byte(v), &s.DNS); err != nil {
				rows.Close()
				return s, err
			}
		case "ad_block_enabled":
			enabled, err := strconv.ParseBool(v)
			if err != nil {
				rows.Close()
				return s, err
			}
			s.AdBlockEnabled = &enabled
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return s, err
	}
	rows.Close()
	ss, err := db.Query("SELECT id,name,url,update_hours,enabled,last_updated FROM subscriptions ORDER BY name")
	if err != nil {
		return s, err
	}
	for ss.Next() {
		var sub Subscription
		var enabled int
		var stamp sql.NullString
		if err := ss.Scan(&sub.ID, &sub.Name, &sub.URL, &sub.UpdateHours, &enabled, &stamp); err != nil {
			ss.Close()
			return s, err
		}
		sub.Enabled = enabled != 0
		if stamp.Valid {
			sub.LastUpdated, _ = time.Parse(time.RFC3339Nano, stamp.String)
		}
		s.Subscriptions = append(s.Subscriptions, sub)
		s.SubscriptionURLs = append(s.SubscriptionURLs, sub.URL)
	}
	if err := ss.Err(); err != nil {
		ss.Close()
		return s, err
	}
	ss.Close()
	ns, err := db.Query("SELECT id,subscription_id,group_name,enabled,sort_order,payload FROM nodes ORDER BY sort_order,id")
	if err != nil {
		return s, err
	}
	for ns.Next() {
		var n Node
		var subID, group, payload string
		var enabled int
		var order int
		if err := ns.Scan(&n.ID, &subID, &group, &enabled, &order, &payload); err != nil {
			ns.Close()
			return s, err
		}
		if err := json.Unmarshal([]byte(payload), &n); err != nil {
			log.Printf("corrupted node payload refused (id=%s): %v", n.ID, err)
			return s, fmt.Errorf("corrupted node payload %s: %w", n.ID, err)
		}
		n.SubscriptionID = subID
		n.Group = group
		n.Enabled = enabled != 0
		n.SortOrder = order
		s.Nodes = append(s.Nodes, n)
	}
	if err := ns.Err(); err != nil {
		ns.Close()
		return s, err
	}
	ns.Close()
	return s, nil
}

func saveDB(s Store) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM settings"); err != nil {
		return err
	}
	backups, _ := json.Marshal(s.RuleBackups)
	ruleSettings, _ := json.Marshal(s.RuleSettings)
	groups, _ := json.Marshal(s.StrategyGroups)
	aclRules, _ := json.Marshal(s.ACLRules)
	dnsSettings, _ := json.Marshal(s.DNS)
	s.Revision++
	settings := map[string]string{"revision": strconv.FormatInt(s.Revision, 10), "schema_version": strconv.Itoa(s.SchemaVersion), "mode": s.Mode, "proxy_port": strconv.Itoa(s.ProxyPort), "selected_node": s.SelectedNode, "update_hours": strconv.Itoa(s.UpdateHours), "log_level": s.LogLevel, "rule_update_hours": strconv.Itoa(s.RuleUpdateHours), "rule_backups": string(backups), "rule_settings": string(ruleSettings), "strategy_groups": string(groups), "tcp_outbound": s.TCPOutbound, "udp_outbound": s.UDPOutbound, "acl_rules": string(aclRules), "dns": string(dnsSettings), "ad_block_enabled": strconv.FormatBool(boolValue(s.AdBlockEnabled, true))}
	for k, v := range settings {
		if _, err = tx.Exec("INSERT INTO settings(key,value) VALUES(?,?)", k, v); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DELETE FROM subscriptions"); err != nil {
		return err
	}
	for _, sub := range s.Subscriptions {
		enabled := 0
		if sub.Enabled {
			enabled = 1
		}
		if _, err = tx.Exec("INSERT INTO subscriptions(id,name,url,update_hours,enabled,last_updated) VALUES(?,?,?,?,?,?)", sub.ID, sub.Name, sub.URL, sub.UpdateHours, enabled, sub.LastUpdated.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DELETE FROM nodes"); err != nil {
		return err
	}
	for i, n := range s.Nodes {
		payload, err := json.Marshal(n)
		if err != nil {
			return fmt.Errorf("marshal node %s: %w", n.ID, err)
		}
		enabled := 0
		if n.Enabled {
			enabled = 1
		}
		if _, err = tx.Exec("INSERT INTO nodes(id,subscription_id,group_name,enabled,sort_order,payload) VALUES(?,?,?,?,?,?)", n.ID, n.SubscriptionID, n.Group, enabled, i, string(payload)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
