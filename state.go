package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var mu sync.Mutex

var dataPath = "/var/lib/armwall/store.json"

var configPath = "/etc/armwall/sing-box.json"

var macACLPath = "/etc/armwall/mac-acl.tsv"

var naiveConfigDir = "/etc/armwall/naive"

var logDir = "/var/log/armwall"

var gatewayPath = "/usr/local/bin/armwall-gateway"

var gatewayStatePath = "/var/lib/armwall/gateway.state"

var ruleDataDir = "/var/lib/armwall/rules"

var proxyPort = 1080

var proxyPortMu sync.RWMutex

func getProxyPort() int {
	proxyPortMu.RLock()
	defer proxyPortMu.RUnlock()
	return proxyPort
}

func setProxyPort(p int) {
	proxyPortMu.Lock()
	defer proxyPortMu.Unlock()
	proxyPort = p
}

var tproxyEnabled bool

var tproxyPort = 11081

var naiveProxyPort = 12000

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func ensureDefaultBool(value **bool, fallback bool) {
	if *value == nil {
		v := fallback
		*value = &v
	}
}

func storeLockFile() string {
	if path := os.Getenv("ARMWALL_LOCK"); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(dbPath), "armwall.lock")
}

func lockStoreFile() (func(), error) {
	path := storeLockFile()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	unlock := func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
	return unlock, nil
}

func lockStoreFileShared() (func(), error) {
	path := storeLockFile()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		_ = file.Close()
		return nil, err
	}
	unlock := func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
	return unlock, nil
}

func withStoreFileLock(fn func() error) error {
	unlock, err := lockStoreFile()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func withStoreFileLockContext(ctx context.Context, fn func() error) error {
	path := storeLockFile()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			return fn()
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func loadStore() (Store, error) {
	if _, err := os.Stat(dbPath); err == nil {
		s, err := loadDB()
		if err != nil {
			return Store{}, fmt.Errorf("load SQLite store: %w", err)
		}
		normalizeStore(&s)
		return s, nil
	} else if !os.IsNotExist(err) {
		return Store{}, err
	}
	if _, err := os.Stat(dataPath); err == nil {
		legacy, err := loadJSON()
		if err != nil {
			return Store{}, err
		}
		archivePath := dataPath + ".migrated"
		if _, err := os.Lstat(archivePath); err == nil {
			return Store{}, fmt.Errorf("legacy migration archive already exists: %s", archivePath)
		} else if !os.IsNotExist(err) {
			return Store{}, err
		}
		legacy = migrateLegacy(legacy)
		normalizeStore(&legacy)
		if err := saveDB(legacy); err != nil {
			return Store{}, fmt.Errorf("migrate legacy JSON store: %w", err)
		}
		if err := os.Link(dataPath, archivePath); err != nil {
			return Store{}, fmt.Errorf("archive legacy JSON store: %w", err)
		}
		if err := os.Remove(dataPath); err != nil {
			return Store{}, fmt.Errorf("remove migrated legacy JSON store: %w", err)
		}
		return legacy, nil
	} else if !os.IsNotExist(err) {
		return Store{}, err
	}
	s, err := loadDB()
	if err != nil {
		return Store{}, err
	}
	normalizeStore(&s)
	return s, nil
}

func load() Store {
	s, err := loadStore()
	if err != nil {
		log.Printf("cannot load store: %v", err)
		return Store{Mode: "bypass_cn"}
	}
	return s
}

func save(s Store) error {
	return saveDB(s)
}

func persistStore(next Store, reload bool) error {
	return persistStoreWithRuleChange(next, reload, false)
}

// ruleSettingsFingerprint ignores LastUpdated: a completed check alone does not
// change what sing-box loads.
func ruleSettingsFingerprint(settings map[string]RuleUpdateSetting) []byte {
	stripped := make(map[string]RuleUpdateSetting, len(settings))
	for tag, setting := range settings {
		setting.LastUpdated = time.Time{}
		stripped[tag] = setting
	}
	data, _ := json.Marshal(stripped)
	return data
}

// persistStoreWithRuleChange writes the store and runtime config. rulesChanged
// reports that rule-set files were replaced on disk, which sing-box only picks
// up after a restart.
func persistStoreWithRuleChange(next Store, reload, rulesChanged bool) error {
	previous, err := loadStore()
	if err != nil {
		return err
	}
	wasRunning := proxyRunningFn()
	previousProxyPort := getProxyPort()
	normalizeStore(&next)
	if next.ProxyPort <= 0 {
		next.ProxyPort = previousProxyPort
	}
	if next.ProxyPort > 0 {
		setProxyPort(next.ProxyPort)
	}
	if err := validateRuntimePorts(next); err != nil {
		setProxyPort(previousProxyPort)
		return err
	}
	prevJSON, _ := json.Marshal(config(previous))
	nextJSON, _ := json.Marshal(config(next))
	prevMAC, _ := macACLData(previous)
	nextMAC, _ := macACLData(next)
	prevRules := ruleSettingsFingerprint(previous.RuleSettings)
	nextRules := ruleSettingsFingerprint(next.RuleSettings)
	configChanged := rulesChanged || !bytes.Equal(prevJSON, nextJSON) || !bytes.Equal(prevMAC, nextMAC) || !bytes.Equal(prevRules, nextRules) || previousProxyPort != getProxyPort()

	if err := writeConfig(next); err != nil {
		setProxyPort(previousProxyPort)
		return err
	}
	if err := save(next); err != nil {
		setProxyPort(previousProxyPort)
		if rErr := writeConfig(previous); rErr != nil {
			return fmt.Errorf("save store: %w (restore config failed: %v)", err, rErr)
		}
		return err
	}
	if wasRunning && reload && configChanged {
		if err := restartProxyFn(); err != nil {
			setProxyPort(previousProxyPort)
			var rErrs []string
			if rErr := save(previous); rErr != nil {
				rErrs = append(rErrs, "restore db: "+rErr.Error())
			}
			if rErr := writeConfig(previous); rErr != nil {
				rErrs = append(rErrs, "restore config: "+rErr.Error())
			}
			if rErr := restartProxyFn(); rErr != nil {
				rErrs = append(rErrs, "restart proxy: "+rErr.Error())
			}
			if len(rErrs) > 0 {
				return fmt.Errorf("%w (rollback failed: %s)", err, strings.Join(rErrs, "; "))
			}
			return err
		}
		if err := reloadGatewayFn(); err != nil {
			setProxyPort(previousProxyPort)
			var rErrs []string
			if rErr := save(previous); rErr != nil {
				rErrs = append(rErrs, "restore db: "+rErr.Error())
			}
			if rErr := writeConfig(previous); rErr != nil {
				rErrs = append(rErrs, "restore config: "+rErr.Error())
			}
			if rErr := restartProxyFn(); rErr != nil {
				rErrs = append(rErrs, "restart proxy: "+rErr.Error())
			}
			if rErr := reloadGatewayFn(); rErr != nil {
				rErrs = append(rErrs, "reload gateway: "+rErr.Error())
			}
			if len(rErrs) > 0 {
				return fmt.Errorf("%w (rollback failed: %s)", err, strings.Join(rErrs, "; "))
			}
			return err
		}
	}
	return nil
}

func reloadGatewayIfActive() error {
	if _, err := os.Stat(gatewayStatePath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	out, err := runCommandTimeout(5*time.Second, gatewayPath, "reload")
	if err != nil {
		return fmt.Errorf("transparent gateway reload failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

var reloadGatewayFn = reloadGatewayIfActive

func proxyRunning() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "armwall-sing-box.service").Run() == nil
}

var proxyRunningFn = proxyRunning
