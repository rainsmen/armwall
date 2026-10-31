package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// unlockedAPIRoutes run before the write mutex is acquired; see
// handleUnlockedAPI.
var unlockedAPIRoutes = map[string]func(http.ResponseWriter, *http.Request){
	"/api/state":                   apiState,
	"/api/node/get":                apiNodeGet,
	"/api/strategy/status":         apiStrategyStatus,
	"/api/strategy/test":           apiStrategyTest,
	"/api/service/status":          apiServiceStatus,
	"/api/logs":                    apiLogs,
	"/api/network/test":            apiNetworkTest,
	"/api/gateway/status":          apiGatewayStatus,
	"/api/node/test":               apiNodeTest,
	"/api/node/batch-test":         apiNodeBatchTest,
	"/api/subscription/update":     apiSubscriptionUpdate,
	"/api/subscription/update-one": apiSubscriptionUpdateOne,
	"/api/subscription":            apiSubscription,
	"/api/rules/update":            apiRulesUpdate,
	"/api/core/update":             apiCoreUpdate,
	"/api/core/upload":             apiCoreUpload,
	"/api/rules":                   apiRules,
	"/api/config/export":           apiConfigExport,
	"/api/backups":                 apiBackups,
	"/api/backups/download":        apiBackupsDownload,
}

// lockedAPIRoutes run with mu and the store file lock held, and receive the
// store loaded under that lock.
var lockedAPIRoutes = map[string]func(http.ResponseWriter, *http.Request, Store){
	"/api/node":                  apiNode,
	"/api/node/delete":           apiNodeDelete,
	"/api/node/update":           apiNodeUpdate,
	"/api/node/copy":             apiNodeCopy,
	"/api/node/toggle":           apiNodeToggle,
	"/api/node/batch-toggle":     apiNodeBatchToggle,
	"/api/node/batch-delete":     apiNodeBatchDelete,
	"/api/node/reorder":          apiNodeReorder,
	"/api/node/select":           apiNodeSelect,
	"/api/subscription/clear":    apiSubscriptionClear,
	"/api/subscription/edit":     apiSubscriptionEdit,
	"/api/subscription/delete":   apiSubscriptionDelete,
	"/api/subscription/toggle":   apiSubscriptionToggle,
	"/api/subscription/schedule": apiSubscriptionSchedule,
	"/api/acl":                   apiAcl,
	"/api/acl/toggle":            apiAclToggle,
	"/api/acl/delete":            apiAclDelete,
	"/api/dns":                   apiDns,
	"/api/strategy":              apiStrategy,
	"/api/strategy/delete":       apiStrategyDelete,
	"/api/strategy/select":       apiStrategySelect,
	"/api/routing":               apiRouting,
	"/api/mode":                  apiMode,
	"/api/settings":              apiSettings,
	"/api/service/start":         apiServiceStart,
	"/api/service/stop":          apiServiceStop,
	"/api/log/clear":             apiLogClear,
	"/api/log/level":             apiLogLevel,
	"/api/rules/settings":        apiRulesSettings,
	"/api/gateway/enable":        apiGatewayEnable,
	"/api/gateway/disable":       apiGatewayDisable,
	"/api/node/import":           apiNodeImport,
	"/api/config/import":         apiConfigImport,
	"/api/backups/create":        apiBackupsCreate,
	"/api/backups/restore":       apiBackupsRestore,
	"/api/backups/delete":        apiBackupsDelete,
}

// handleUnlockedAPI handles read-only and externally slow endpoints before the
// write mutex is acquired. Store snapshots are still protected by the
// cross-process file lock, while network, systemctl, and core-update I/O do
// not block unrelated API writes.
func handleUnlockedAPI(w http.ResponseWriter, r *http.Request) bool {
	handler, ok := unlockedAPIRoutes[r.URL.Path]
	if !ok {
		return false
	}
	handler(w, r)
	return true
}

func api(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if handleUnlockedAPI(w, r) {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	unlock, err := lockStoreFile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer unlock()
	s, err := loadStore()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler, ok := lockedAPIRoutes[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	handler(w, r, s)
}

func loadAPIStoreSnapshot() (Store, error) {
	unlock, err := lockStoreFileShared()
	if err != nil {
		return Store{}, err
	}
	defer unlock()
	return loadStore()
}

func decodeJSONBody(r *http.Request, dst any) error {
	return decodeJSONPayload(r, dst, false)
}

func decodeOptionalJSONBody(r *http.Request, dst any) error {
	return decodeJSONPayload(r, dst, true)
}

func decodeJSONPayload(r *http.Request, dst any, allowEmpty bool) error {
	data, err := readLimitedBody(r.Body, maxAPIJSONBodySize)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("invalid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid json")
	}
	return nil
}
