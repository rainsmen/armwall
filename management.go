package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	configArchiveFormat = "armwall-config-v1"
	maxConfigSize       = 16 << 20
	maxCoreUploadSize   = 128 << 20
)

type configArchive struct {
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	Store     Store     `json:"store"`
}

type backupInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

var backupDir = "/var/lib/armwall/backups/config"
var coreUploadDir = "/var/lib/armwall/uploads"
var updateCorePath = "/usr/local/bin/armwall-update-core"

func marshalConfigArchive(s Store) ([]byte, error) {
	return json.MarshalIndent(configArchive{Format: configArchiveFormat, CreatedAt: time.Now().UTC(), Store: s}, "", "  ")
}

func parseConfigArchive(data []byte) (Store, error) {
	var envelope struct {
		Format string          `json:"format"`
		Store  json.RawMessage `json:"store"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Store{}, fmt.Errorf("invalid configuration JSON: %w", err)
	}
	var s Store
	if envelope.Format != "" || len(envelope.Store) > 0 {
		if envelope.Format != configArchiveFormat || len(envelope.Store) == 0 {
			return Store{}, fmt.Errorf("unsupported configuration format")
		}
		if err := json.Unmarshal(envelope.Store, &s); err != nil {
			return Store{}, fmt.Errorf("invalid configuration store: %w", err)
		}
	} else if err := json.Unmarshal(data, &s); err != nil {
		return Store{}, fmt.Errorf("invalid configuration store: %w", err)
	}
	if err := validateImportedStore(&s); err != nil {
		return Store{}, err
	}
	return s, nil
}

func validateImportedStore(s *Store) error {
	if len(s.Nodes) > 10000 || len(s.Subscriptions) > 1000 || len(s.StrategyGroups) > 1000 || len(s.ACLRules) > 1000 {
		return fmt.Errorf("configuration contains too many records")
	}
	if s.Mode == "" {
		s.Mode = "bypass_cn"
	}
	if s.Mode != "bypass_cn" && s.Mode != "gfw" && s.Mode != "global" {
		return fmt.Errorf("invalid routing mode")
	}
	if s.ProxyPort == 0 {
		s.ProxyPort = 11080
	}
	if s.ProxyPort < 1 || s.ProxyPort > 65535 {
		return fmt.Errorf("invalid proxy port")
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
	if !map[string]bool{"trace": true, "debug": true, "info": true, "warn": true, "error": true}[s.LogLevel] {
		return fmt.Errorf("invalid log level")
	}
	normalizeRuleSettings(s)
	for tag, setting := range s.RuleSettings {
		if _, ok := ruleURLs[tag]; !ok {
			return fmt.Errorf("unknown rule setting: %s", tag)
		}
		if setting.UpdateHours < 1 || setting.UpdateHours > 168 {
			return fmt.Errorf("invalid update interval for rule %s", tag)
		}
		if setting.BackupURL != "" && !httpsURL(setting.BackupURL) {
			return fmt.Errorf("invalid backup URL for rule %s", tag)
		}
	}
	seenNodes := map[string]bool{}
	for i := range s.Nodes {
		node := &s.Nodes[i]
		if node.ID == "" || node.ID == "direct" || node.ID == "block" || seenNodes[node.ID] {
			return fmt.Errorf("invalid or duplicate node id")
		}
		if err := validateNode(node); err != nil {
			return fmt.Errorf("node %q: %w", node.Name, err)
		}
		seenNodes[node.ID] = true
	}
	seenSubscriptions := map[string]bool{}
	seenURLs := map[string]bool{}
	for i := range s.Subscriptions {
		sub := &s.Subscriptions[i]
		sub.ID = strings.TrimSpace(sub.ID)
		sub.Name = strings.TrimSpace(sub.Name)
		sub.URL = strings.TrimSpace(sub.URL)
		u, err := url.Parse(sub.URL)
		if sub.ID == "" || sub.Name == "" || seenSubscriptions[sub.ID] || seenURLs[sub.URL] || err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return fmt.Errorf("invalid or duplicate subscription")
		}
		if sub.UpdateHours == 0 {
			sub.UpdateHours = 6
		}
		if sub.UpdateHours < 1 || sub.UpdateHours > 168 {
			return fmt.Errorf("invalid subscription update interval")
		}
		seenSubscriptions[sub.ID] = true
		seenURLs[sub.URL] = true
	}
	seenGroups := map[string]bool{}
	for i := range s.StrategyGroups {
		group := &s.StrategyGroups[i]
		if group.ID == "" || group.ID == "direct" || group.ID == "block" || seenNodes[group.ID] || seenGroups[group.ID] {
			return fmt.Errorf("invalid or duplicate strategy id")
		}
		if err := validateStrategyGroup(group, *s); err != nil {
			return fmt.Errorf("strategy %q: %w", group.Name, err)
		}
		seenGroups[group.ID] = true
	}
	for i := range s.ACLRules {
		if s.ACLRules[i].ID == "" {
			return fmt.Errorf("ACL rule id is required")
		}
		if err := validateACLRule(&s.ACLRules[i], *s); err != nil {
			return fmt.Errorf("ACL %q: %w", s.ACLRules[i].Name, err)
		}
	}
	if err := validateDNSSettings(&s.DNS); err != nil {
		return err
	}
	normalizeStore(s)
	return nil
}

func createConfigBackup(s Store, prefix string) (backupInfo, error) {
	if prefix == "" {
		prefix = "armwall-backup"
	}
	data, err := marshalConfigArchive(s)
	if err != nil {
		return backupInfo{}, err
	}
	stamp := time.Now().UTC()
	name := fmt.Sprintf("%s-%s.json", prefix, stamp.Format("20060102-150405.000000000"))
	path := filepath.Join(backupDir, name)
	if err := writeAtomicFile(path, data, 0600); err != nil {
		return backupInfo{}, err
	}
	return backupInfo{Name: name, Size: int64(len(data)), CreatedAt: stamp}, nil
}

func validBackupName(name string) bool {
	if name == "" || filepath.Base(name) != name || !strings.HasSuffix(name, ".json") {
		return false
	}
	if !strings.HasPrefix(name, "armwall-backup-") && !strings.HasPrefix(name, "pre-restore-") && !strings.HasPrefix(name, "pre-import-") {
		return false
	}
	for _, char := range name {
		if !(char == '-' || char == '.' || char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z') {
			return false
		}
	}
	return true
}

func configBackupPath(name string) (string, error) {
	if !validBackupName(name) {
		return "", fmt.Errorf("invalid backup name")
	}
	return filepath.Join(backupDir, name), nil
}

func listConfigBackups() ([]backupInfo, error) {
	entries, err := os.ReadDir(backupDir)
	if os.IsNotExist(err) {
		return []backupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	backups := make([]backupInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && validBackupName(entry.Name()) {
			info, err := entry.Info()
			if err == nil {
				backups = append(backups, backupInfo{Name: entry.Name(), Size: info.Size(), CreatedAt: info.ModTime()})
			}
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("request is too large")
	}
	return data, nil
}

func handleCoreUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCoreUploadSize+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "invalid or oversized upload", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	core := r.FormValue("core")
	if core != "sing-box" && core != "naive" {
		http.Error(w, "invalid core", http.StatusBadRequest)
		return
	}
	source, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "core file is required", http.StatusBadRequest)
		return
	}
	defer source.Close()
	if err := os.MkdirAll(coreUploadDir, 0750); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp, err := os.CreateTemp(coreUploadDir, "."+core+"-upload-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	written, copyErr := io.Copy(tmp, io.LimitReader(source, maxCoreUploadSize+1))
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil || written == 0 || written > maxCoreUploadSize {
		http.Error(w, "invalid or oversized core file", http.StatusBadRequest)
		return
	}
	out, err := exec.Command(updateCorePath, core, "manual", tmpPath).CombinedOutput()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		http.Error(w, strings.TrimSpace(string(out)), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}
