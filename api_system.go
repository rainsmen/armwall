package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func apiState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for i := range s.Nodes {
		if s.Nodes[i].Password != "" {
			s.Nodes[i].Password = "******"
		}
		if s.Nodes[i].UUID != "" {
			s.Nodes[i].UUID = "******"
		}
		if s.Nodes[i].ObfsPassword != "" {
			s.Nodes[i].ObfsPassword = "******"
		}
	}
	json.NewEncoder(w).Encode(s)
}

func apiServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	out, _ := runCommandTimeout(5*time.Second, "systemctl", "is-active", "armwall-sing-box.service")
	status := strings.TrimSpace(string(out))
	if status == "" {
		status = "unknown"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(status + "\n"))
}

func apiLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	path := filepath.Join(logDir, "sing-box.log")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", "attachment; filename=armwall.log")
		_, _ = io.Copy(w, file)
		return
	}
	if info, statErr := file.Stat(); statErr == nil && info.Size() > 256<<10 {
		_, _ = file.Seek(-(256 << 10), io.SeekEnd)
	}
	_, _ = io.Copy(w, file)
}

func apiCoreUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ Core, Action string }
	if decodeJSONBody(r, &v) != nil || (v.Core != "sing-box" && v.Core != "naive") {
		http.Error(w, "invalid core", http.StatusBadRequest)
		return
	}
	if v.Action != "version" && v.Action != "latest" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	runCoreUpdate(w, v.Core, v.Action)
}

func apiCoreUpload(w http.ResponseWriter, r *http.Request) {
	handleCoreUpload(w, r)
}

func apiConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	s, err := loadAPIStoreSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := marshalConfigArchive(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=armwall-config.json")
	_, _ = w.Write(data)
}

func apiBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	backups, err := listConfigBackups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(backups)
}

func apiBackupsDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	path, err := configBackupPath(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(path))
	_, _ = w.Write(data)
}

func apiSettings(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ ProxyPort int }
	if decodeJSONBody(r, &v) != nil || v.ProxyPort < 1 || v.ProxyPort > 65535 {
		http.Error(w, "invalid port", 400)
		return
	}
	reservedPorts := map[int]string{8080: "web", 9090: "clash api", 11081: "tproxy", 53: "dns", 22: "ssh"}
	if name, conflict := reservedPorts[v.ProxyPort]; conflict {
		http.Error(w, fmt.Sprintf("port %d conflicts with %s", v.ProxyPort, name), 400)
		return
	}
	s.ProxyPort = v.ProxyPort
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiServiceStart(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := writeConfig(s); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := restartProxy(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := reloadGatewayIfActive(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("active\n"))
}

func apiServiceStop(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	gatewaySuspended := false
	if _, statErr := os.Stat(gatewayStatePath); statErr == nil {
		if gatewayOut, gatewayErr := runCommandTimeout(5*time.Second, gatewayPath, "suspend"); gatewayErr != nil {
			http.Error(w, string(gatewayOut), 500)
			return
		}
		gatewaySuspended = true
	}
	out, err := runCommandTimeout(10*time.Second, "systemctl", "stop", "armwall-sing-box.service", "armwall-naive.service")
	if err != nil {
		if gatewaySuspended {
			_, _ = runCommandTimeout(5*time.Second, gatewayPath, "restore")
		}
		http.Error(w, strings.TrimSpace(string(out)), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("inactive\n"))
}

func apiLogClear(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := os.WriteFile(filepath.Join(logDir, "sing-box.log"), nil, 0640); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"cleared": true})
}

func apiLogLevel(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct{ Level string }
	if decodeJSONBody(r, &v) != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if v.Level != "trace" && v.Level != "debug" && v.Level != "info" && v.Level != "warn" && v.Level != "error" {
		http.Error(w, "invalid level", 400)
		return
	}
	s.LogLevel = v.Level
	if err := persistStore(s, true); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func apiConfigImport(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	data, err := readLimitedBody(r.Body, maxConfigSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	imported, err := parseConfigArchive(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := createConfigBackup(s, "pre-import"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := persistStore(imported, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(imported)
}

func apiBackupsCreate(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	backup, err := createConfigBackup(s, "armwall-backup")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(backup)
}

func apiBackupsRestore(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var request struct{ Name string }
	if decodeJSONBody(r, &request) != nil {
		http.Error(w, "backup name is required", http.StatusBadRequest)
		return
	}
	path, err := configBackupPath(request.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	restored, err := parseConfigArchive(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := createConfigBackup(s, "pre-restore"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := persistStore(restored, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(restored)
}

func apiBackupsDelete(w http.ResponseWriter, r *http.Request, s Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var request struct{ Name string }
	if decodeJSONBody(r, &request) != nil {
		http.Error(w, "backup name is required", http.StatusBadRequest)
		return
	}
	path, err := configBackupPath(request.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.Remove(path); err != nil {
		http.Error(w, "backup not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
}
