package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

func openDB() (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, update_hours INTEGER NOT NULL DEFAULT 6, enabled INTEGER NOT NULL DEFAULT 1, last_updated TEXT);
CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, subscription_id TEXT, group_name TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	_, _ = db.Exec(`UPDATE nodes SET group_name = COALESCE((SELECT name FROM subscriptions WHERE subscriptions.id = nodes.subscription_id), '') WHERE group_name = '' AND subscription_id <> ''`)
	return db, nil
}

func loadJSON() Store {
	b, err := os.ReadFile(dataPath)
	if err != nil {
		return Store{Mode: "bypass_cn"}
	}
	var s Store
	if json.Unmarshal(b, &s) != nil {
		return Store{Mode: "bypass_cn"}
	}
	return s
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
	defer db.Close()
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
			json.Unmarshal([]byte(v), &s.RuleBackups)
		case "rule_settings":
			json.Unmarshal([]byte(v), &s.RuleSettings)
		case "strategy_groups":
			json.Unmarshal([]byte(v), &s.StrategyGroups)
		case "tcp_outbound":
			s.TCPOutbound = v
		case "udp_outbound":
			s.UDPOutbound = v
		case "acl_rules":
			json.Unmarshal([]byte(v), &s.ACLRules)
		case "dns":
			json.Unmarshal([]byte(v), &s.DNS)
		}
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
			sub.LastUpdated, _ = time.Parse(time.RFC3339, stamp.String)
		}
		s.Subscriptions = append(s.Subscriptions, sub)
		s.SubscriptionURLs = append(s.SubscriptionURLs, sub.URL)
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
		if json.Unmarshal([]byte(payload), &n) != nil {
			continue
		}
		n.SubscriptionID = subID
		n.Group = group
		n.Enabled = enabled != 0
		n.SortOrder = order
		s.Nodes = append(s.Nodes, n)
	}
	ns.Close()
	if len(s.Nodes) == 0 && len(s.Subscriptions) == 0 {
		return s, sql.ErrNoRows
	}
	return s, nil
}

func saveDB(s Store) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
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
	settings := map[string]string{"mode": s.Mode, "proxy_port": strconv.Itoa(s.ProxyPort), "selected_node": s.SelectedNode, "update_hours": strconv.Itoa(s.UpdateHours), "log_level": s.LogLevel, "rule_update_hours": strconv.Itoa(s.RuleUpdateHours), "rule_backups": string(backups), "rule_settings": string(ruleSettings), "strategy_groups": string(groups), "tcp_outbound": s.TCPOutbound, "udp_outbound": s.UDPOutbound, "acl_rules": string(aclRules), "dns": string(dnsSettings)}
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
		if _, err = tx.Exec("INSERT INTO subscriptions(id,name,url,update_hours,enabled,last_updated) VALUES(?,?,?,?,?,?)", sub.ID, sub.Name, sub.URL, sub.UpdateHours, enabled, sub.LastUpdated.Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DELETE FROM nodes"); err != nil {
		return err
	}
	for i, n := range s.Nodes {
		payload, _ := json.Marshal(n)
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

func migrateLegacy(s Store) Store {
	if len(s.Subscriptions) == 0 {
		for i, u := range s.SubscriptionURLs {
			s.Subscriptions = append(s.Subscriptions, Subscription{ID: fmt.Sprintf("subsrc-%d", i+1), Name: fmt.Sprintf("订阅 %d", i+1), URL: u, UpdateHours: 6, Enabled: true})
		}
	}
	for i := range s.Nodes {
		s.Nodes[i].Enabled = true
		if s.Nodes[i].SubscriptionID == "" && len(s.Subscriptions) > 0 && len(s.SubscriptionURLs) > 0 && len(s.Nodes[i].ID) >= 4 && s.Nodes[i].ID[:4] == "sub-" {
			s.Nodes[i].SubscriptionID = s.Subscriptions[0].ID
			s.Nodes[i].Group = s.Subscriptions[0].Name
		}
		s.Nodes[i].SortOrder = i
	}
	return s
}
