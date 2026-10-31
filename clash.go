package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var clashAPISecret string

var clashSecretMu sync.Mutex

func clashSecretFile() string {
	if path := os.Getenv("ARMWALL_CLASH_SECRET_FILE"); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(configPath), "clash.secret")
}

func currentClashAPISecret() string {
	if secret := strings.TrimSpace(os.Getenv("ARMWALL_CLASH_SECRET")); secret != "" {
		return secret
	}
	clashSecretMu.Lock()
	defer clashSecretMu.Unlock()
	if clashAPISecret != "" {
		return clashAPISecret
	}
	data, err := os.ReadFile(clashSecretFile())
	if err == nil {
		clashAPISecret = strings.TrimSpace(string(data))
	}
	return clashAPISecret
}

func ensureClashAPISecret() (string, error) {
	if secret := strings.TrimSpace(os.Getenv("ARMWALL_CLASH_SECRET")); secret != "" {
		clashSecretMu.Lock()
		clashAPISecret = secret
		clashSecretMu.Unlock()
		return secret, nil
	}
	clashSecretMu.Lock()
	defer clashSecretMu.Unlock()
	if clashAPISecret != "" {
		return clashAPISecret, nil
	}
	path := clashSecretFile()
	if data, err := os.ReadFile(path); err == nil {
		if secret := strings.TrimSpace(string(data)); secret != "" {
			clashAPISecret = secret
			return secret, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}
	clashAPISecret = hex.EncodeToString(secretBytes)
	if err := writeAtomicFile(path, []byte(clashAPISecret+"\n"), 0600); err != nil {
		clashAPISecret = ""
		return "", err
	}
	return clashAPISecret, nil
}
