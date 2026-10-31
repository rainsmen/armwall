package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var ruleURLs = map[string]string{
	"geosite-ads":   "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
	"geosite-cn":    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
	"geoip-cn":      "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
	"geosite-proxy": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
}

func ruleSet(tag string) map[string]any {
	path := "/var/lib/armwall/rules/" + tag + ".srs"
	if _, err := os.Stat(path); err == nil {
		return map[string]any{"type": "local", "tag": tag, "format": "binary", "path": path}
	}
	return map[string]any{"type": "remote", "tag": tag, "format": "binary", "url": ruleURLs[tag], "download_detour": "direct"}
}

// updateRule refreshes one rule set and reports whether the file on disk
// changed. Unchanged content must not restart sing-box.
func updateRule(tag, backup string) (bool, error) {
	primary, ok := ruleURLs[tag]
	if !ok {
		return false, fmt.Errorf("unknown rule")
	}
	backup = strings.TrimSpace(backup)
	if backup != "" && !httpsURL(backup) {
		return false, fmt.Errorf("backup rule URL must use https")
	}
	urls := []string{primary}
	if backup != "" {
		urls = append(urls, backup)
	}
	target := filepath.Join(ruleDataDir, tag+".srs")
	useLocalAsset := false
	current, currentErr := os.ReadFile(target)
	if os.IsNotExist(currentErr) {
		useLocalAsset = true
	} else if currentErr != nil {
		return false, fmt.Errorf("read existing rule: %w", currentErr)
	} else if validateSRS(current) != nil {
		useLocalAsset = true
	}
	if useLocalAsset {
		if body, asset, assetErr := bundledRule(tag); assetErr == nil {
			if len(current) > 0 && bytes.Equal(current, body) {
				return false, nil
			}
			if err := os.MkdirAll(ruleDataDir, 0750); err != nil {
				return false, err
			}
			if err := backupRuleFile(tag); err != nil {
				return false, err
			}
			if err := writeAtomicFile(target, body, 0640); err != nil {
				return false, fmt.Errorf("install local rule asset %s: %w", asset, err)
			}
			return true, nil
		}
	}
	var last error
	for _, raw := range urls {
		body, err := downloadResource(raw, 32<<20, 30*time.Second)
		if err != nil || len(body) < 16 {
			if err == nil {
				err = fmt.Errorf("downloaded rule is empty")
			}
			last = fmt.Errorf("%s: %w", raw, err)
			continue
		}
		if err := validateSRS(body); err != nil {
			last = fmt.Errorf("%s: %w", raw, err)
			continue
		}
		if err = os.MkdirAll(ruleDataDir, 0750); err != nil {
			return false, err
		}
		if prev, readErr := os.ReadFile(target); readErr == nil && bytes.Equal(prev, body) {
			// Rule content unchanged, avoid redundant disk write and service restart
			return false, nil
		}
		if err := backupRuleFile(tag); err != nil {
			return false, err
		}
		if err := writeAtomicFile(target, body, 0640); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, last
}

// backupRuleFile records the current rule file (or its absence) so that
// restoreRuleBackups can undo a rule write when the store commit fails.
func backupRuleFile(tag string) error {
	target := filepath.Join(ruleDataDir, tag+".srs")
	bak := target + ".bak"
	absent := bak + ".absent"
	prev, err := os.ReadFile(target)
	if os.IsNotExist(err) {
		if err := os.WriteFile(absent, nil, 0600); err != nil {
			return fmt.Errorf("record absent rule: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read existing rule: %w", err)
	}
	if err := os.WriteFile(bak, prev, 0640); err != nil {
		return fmt.Errorf("backup existing rule: %w", err)
	}
	_ = os.Remove(absent)
	return nil
}

func bundledRule(tag string) ([]byte, string, error) {
	assetDir := strings.TrimSpace(os.Getenv("ARMWALL_RULE_ASSET_DIR"))
	if assetDir == "" {
		assetDir = "/usr/share/armwall/rules"
	}
	asset := filepath.Join(assetDir, tag+".srs")
	body, err := os.ReadFile(asset)
	if err != nil {
		return nil, asset, err
	}
	if err := validateSRS(body); err != nil {
		return nil, asset, err
	}
	return body, asset, nil
}

func validateSRS(body []byte) error {
	if len(body) < 4 {
		return fmt.Errorf("SRS rule is too short")
	}
	if !bytes.Equal(body[:3], []byte("SRS")) {
		return fmt.Errorf("invalid SRS magic")
	}
	checker, err := exec.LookPath("sing-box")
	if err != nil {
		return fmt.Errorf("sing-box rule-set validator is unavailable")
	}
	input, err := os.CreateTemp("", "armwall-rule-*.srs")
	if err != nil {
		return err
	}
	inputPath := input.Name()
	defer os.Remove(inputPath)
	if _, err := input.Write(body); err != nil {
		input.Close()
		return err
	}
	if err := input.Close(); err != nil {
		return err
	}
	output, err := os.CreateTemp("", "armwall-rule-*.json")
	if err != nil {
		return err
	}
	outputPath := output.Name()
	if err := output.Close(); err != nil {
		os.Remove(outputPath)
		return err
	}
	defer os.Remove(outputPath)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, checker, "rule-set", "decompile", "--output", outputPath, inputPath)
	if result, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("SRS validation timed out")
		}
		return fmt.Errorf("sing-box rejected SRS: %s", strings.TrimSpace(string(result)))
	}
	decoded, err := os.ReadFile(outputPath)
	if err != nil {
		return fmt.Errorf("read decompiled SRS: %w", err)
	}
	var source struct {
		Version int               `json:"version"`
		Rules   []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(decoded, &source); err != nil || source.Version < 1 || source.Rules == nil {
		return fmt.Errorf("sing-box produced an invalid rule-set source")
	}
	return nil
}

func bootstrapRules() (int, error) {
	count := 0
	var updateErr error
	err := withRuleUpdateLock(func() error {
		s, err := loadStore()
		if err != nil {
			return err
		}
		now := time.Now()
		for tag, setting := range s.RuleSettings {
			if _, ok := ruleURLs[tag]; !ok {
				continue
			}
			path := filepath.Join(ruleDataDir, tag+".srs")
			if body, readErr := os.ReadFile(path); readErr == nil && validateSRS(body) == nil {
				setting.LastUpdated = now
				s.RuleSettings[tag] = setting
			}
		}
		for tag := range ruleURLs {
			path := filepath.Join(ruleDataDir, tag+".srs")
			body, readErr := os.ReadFile(path)
			if readErr == nil && validateSRS(body) == nil {
				continue
			}
			setting := s.RuleSettings[tag]
			if _, err := updateRuleFn(tag, setting.BackupURL); err != nil {
				updateErr = errors.Join(updateErr, fmt.Errorf("%s: %w", tag, err))
				continue
			}
			setting.LastUpdated = now
			s.RuleSettings[tag] = setting
			count++
		}
		if count == 0 && updateErr != nil {
			return updateErr
		}
		if count == 0 {
			return nil
		}
		if err := withStoreFileLock(func() error {
			current, err := loadStore()
			if err != nil {
				return err
			}
			for tag, setting := range s.RuleSettings {
				if setting.LastUpdated.Equal(now) {
					current.RuleSettings[tag] = setting
				}
			}
			return persistStoreWithRuleChange(current, proxyRunningFn(), true)
		}); err != nil {
			updateErr = errors.Join(updateErr, err)
		}
		return nil
	})
	if err != nil {
		return count, err
	}
	return count, updateErr
}

func ruleLockFile() string {
	if path := os.Getenv("ARMWALL_RULE_LOCK"); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(dataPath), "armwall-rules.lock")
}

func withRuleUpdateLock(fn func() error) error {
	path := ruleLockFile()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

func restoreRuleBackups(tags []string) error {
	dir := ruleDataDir
	var errs []string
	for _, tag := range tags {
		bak := filepath.Join(dir, tag+".srs.bak")
		target := filepath.Join(dir, tag+".srs")
		if _, err := os.Stat(bak); err == nil {
			if err := os.Rename(bak, target); err != nil {
				errs = append(errs, tag+": "+err.Error())
			}
		} else if os.IsNotExist(err) {
			if _, markerErr := os.Stat(bak + ".absent"); markerErr == nil {
				if removeErr := os.Remove(target); removeErr != nil && !os.IsNotExist(removeErr) {
					errs = append(errs, tag+": "+removeErr.Error())
				}
			} else if !os.IsNotExist(markerErr) {
				errs = append(errs, tag+": "+markerErr.Error())
			}
		} else if !os.IsNotExist(err) {
			errs = append(errs, tag+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("restore rule backups: %s", strings.Join(errs, "; "))
	}
	return nil
}

func cleanupRuleBackups(tags []string) error {
	dir := ruleDataDir
	var errs []string
	for _, tag := range tags {
		for _, suffix := range []string{".srs.bak", ".srs.bak.absent"} {
			if err := os.Remove(filepath.Join(dir, tag+suffix)); err != nil && !os.IsNotExist(err) {
				errs = append(errs, tag+": "+err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup rule backups: %s", strings.Join(errs, "; "))
	}
	return nil
}

var updateRuleFn = updateRule

func normalizeRuleSettings(s *Store) {
	if s.RuleSettings == nil {
		s.RuleSettings = map[string]RuleUpdateSetting{}
	}
	if s.RuleBackups == nil {
		s.RuleBackups = map[string]string{}
	}
	legacyHours := s.RuleUpdateHours
	if legacyHours < 1 || legacyHours > 168 {
		legacyHours = 6
	}
	for tag := range ruleURLs {
		setting := s.RuleSettings[tag]
		if setting.BackupURL == "" {
			setting.BackupURL = strings.TrimSpace(s.RuleBackups[tag])
		}
		if setting.UpdateHours < 1 || setting.UpdateHours > 168 {
			setting.UpdateHours = legacyHours
		}
		s.RuleSettings[tag] = setting
		s.RuleBackups[tag] = setting.BackupURL
	}
	s.RuleUpdateHours = legacyHours
}

func ruleUpdateDue(setting RuleUpdateSetting, now time.Time) bool {
	if !setting.AutoUpdate {
		return false
	}
	hours := setting.UpdateHours
	if hours < 1 || hours > 168 {
		hours = 6
	}
	return setting.LastUpdated.IsZero() || now.Sub(setting.LastUpdated) >= time.Duration(hours)*time.Hour
}

// updateConfiguredRules checks due rule sets. checked lists every rule whose
// check succeeded (its LastUpdated advances); changed lists only the rules
// whose file content was replaced and therefore need a sing-box restart.
func updateConfiguredRules(s *Store, force bool, onlyTag string, now time.Time) (checked, changed []string, err error) {
	normalizeRuleSettings(s)
	if onlyTag != "" {
		if _, ok := ruleURLs[onlyTag]; !ok {
			return nil, nil, fmt.Errorf("unknown rule")
		}
	}
	checked = make([]string, 0, len(ruleURLs))
	errors := make([]string, 0)
	for tag := range ruleURLs {
		if onlyTag != "" && tag != onlyTag {
			continue
		}
		setting := s.RuleSettings[tag]
		if !force && !ruleUpdateDue(setting, now) {
			continue
		}
		ruleChanged, ruleErr := updateRuleFn(tag, setting.BackupURL)
		if ruleErr != nil {
			errors = append(errors, tag+": "+ruleErr.Error())
			continue
		}
		setting.LastUpdated = now
		s.RuleSettings[tag] = setting
		checked = append(checked, tag)
		if ruleChanged {
			changed = append(changed, tag)
		}
	}
	if len(errors) > 0 {
		return checked, changed, fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return checked, changed, nil
}

func applyRuleUpdates(force bool) (int, error) {
	count := 0
	var updateErr error
	err := withRuleUpdateLock(func() error {
		s, err := loadStore()
		if err != nil {
			return err
		}
		updated, changed, batchErr := updateConfiguredRules(&s, force, "", time.Now())
		updateErr = batchErr
		if len(updated) == 0 {
			return batchErr
		}
		commitErr := withStoreFileLock(func() error {
			current, loadErr := loadStore()
			if loadErr != nil {
				return loadErr
			}
			normalizeRuleSettings(&current)
			for _, tag := range updated {
				setting := current.RuleSettings[tag]
				setting.LastUpdated = s.RuleSettings[tag].LastUpdated
				current.RuleSettings[tag] = setting
			}
			return persistStoreWithRuleChange(current, proxyRunningFn(), len(changed) > 0)
		})
		if commitErr != nil {
			if restoreErr := restoreRuleBackups(updated); restoreErr != nil {
				return fmt.Errorf("%v; %w", commitErr, restoreErr)
			}
			return commitErr
		}
		if cleanupErr := cleanupRuleBackups(updated); cleanupErr != nil {
			return cleanupErr
		}
		count = len(updated)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, updateErr
}

func applyScheduledRuleUpdates() (int, error) {
	return applyRuleUpdates(false)
}
