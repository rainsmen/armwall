package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func apiRulesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ Tag string }
	if err := decodeOptionalJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if v.Tag == "" {
		http.Error(w, "rule tag is required", 400)
		return
	}
	persistErr := withRuleUpdateLock(func() error {
		s, err := loadAPIStoreSnapshot()
		if err != nil {
			return err
		}
		normalizeRuleSettings(&s)
		setting := s.RuleSettings[v.Tag]
		ruleChanged, err := updateRuleFn(v.Tag, setting.BackupURL)
		if err != nil {
			return fmt.Errorf("download rule: %w", err)
		}
		mu.Lock()
		defer mu.Unlock()
		commitErr := withStoreFileLock(func() error {
			current, loadErr := loadStore()
			if loadErr != nil {
				return loadErr
			}
			normalizeRuleSettings(&current)
			st := current.RuleSettings[v.Tag]
			st.LastUpdated = time.Now()
			current.RuleSettings[v.Tag] = st
			return persistStoreWithRuleChange(current, proxyRunningFn(), ruleChanged)
		})
		if commitErr != nil {
			if restoreErr := restoreRuleBackups([]string{v.Tag}); restoreErr != nil {
				return fmt.Errorf("%v; %w", commitErr, restoreErr)
			}
			return commitErr
		}
		return cleanupRuleBackups([]string{v.Tag})
	})
	if persistErr != nil {
		status := http.StatusInternalServerError
		if strings.HasPrefix(persistErr.Error(), "download rule:") {
			status = http.StatusBadGateway
		}
		http.Error(w, persistErr.Error(), status)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"updated": v.Tag})
}

func apiRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	normalizeRuleSettings(&s)
	json.NewEncoder(w).Encode(map[string]any{"rules": ruleURLs, "settings": s.RuleSettings, "backups": s.RuleBackups, "update_hours": s.RuleUpdateHours, "ad_block_enabled": boolValue(s.AdBlockEnabled, true)})
}

func apiRulesSettings(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		Tag            string `json:"tag"`
		Backup         string `json:"backup"`
		Hours          int    `json:"hours"`
		AutoUpdate     bool   `json:"autoUpdate"`
		AdBlockEnabled *bool  `json:"adBlockEnabled"`
	}
	if decodeJSONBody(r, &v) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if _, ok := ruleURLs[v.Tag]; !ok || v.Hours < 1 || v.Hours > 168 {
		http.Error(w, "invalid rule settings", 400)
		return
	}
	v.Backup = strings.TrimSpace(v.Backup)
	if v.Backup != "" && !httpsURL(v.Backup) {
		http.Error(w, "backup rule URL must use https", 400)
		return
	}
	setting := s.RuleSettings[v.Tag]
	setting.BackupURL = v.Backup
	setting.UpdateHours = v.Hours
	setting.AutoUpdate = v.AutoUpdate
	s.RuleSettings[v.Tag] = setting
	s.RuleBackups[v.Tag] = v.Backup
	if v.AdBlockEnabled != nil {
		s.AdBlockEnabled = v.AdBlockEnabled
		if err := persistStore(s, true); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else {
		if err := save(s); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	json.NewEncoder(w).Encode(s)
}
