package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// authEnvPath is the systemd EnvironmentFile that stores ARMWALL_TOKEN. The
// installer owns the file; the token change endpoint rewrites only the
// ARMWALL_TOKEN line so the next service start reads the new value.
var authEnvPath = "/etc/armwall/armwall.env"

// authTokenAPIPath is served by newHTTPServer directly, not by api(), because
// the handler needs the live token holder.
const authTokenAPIPath = "/api/auth/token"

// tokenSpecialChars are the punctuation characters accepted in a token. Quotes,
// backslash, '$', '#', '`' and whitespace are excluded because systemd's
// EnvironmentFile parser treats them specially, and the token must survive a
// round trip through that file unchanged.
const tokenSpecialChars = "-_.~@%+=:,!^*()[]{}/?"

func validateNewAuthToken(raw string) (string, error) {
	if len(raw) < minAuthTokenLength {
		return "", fmt.Errorf("Token 长度至少 %d 位", minAuthTokenLength)
	}
	if len(raw) > maxAuthTokenLength {
		return "", fmt.Errorf("Token 长度不能超过 %d 位", maxAuthTokenLength)
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(tokenSpecialChars, r):
		default:
			return "", fmt.Errorf("Token 只能包含字母、数字和 %s", tokenSpecialChars)
		}
	}
	return raw, nil
}

func tokensEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

// writeEnvToken replaces every ARMWALL_TOKEN line of the env file with one line
// holding token, at the position of the first occurrence, and keeps all other
// lines. The file is replaced atomically with mode 0600.
func writeEnvToken(path, token string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	written := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "ARMWALL_TOKEN=") {
			if !written {
				out.WriteString("ARMWALL_TOKEN=" + token + "\n")
				written = true
			}
			continue
		}
		out.WriteString(line + "\n")
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !written {
		out.WriteString("ARMWALL_TOKEN=" + token + "\n")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(out.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// apiAuthTokenChange replaces the admin token. The request is already
// authenticated by authHandler; the current token is required again in the
// body so that an unattended, already-authenticated browser tab cannot be used
// to lock the owner out without knowing the token.
func apiAuthTokenChange(w http.ResponseWriter, r *http.Request, holder *authToken) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var v struct {
		Current string `json:"current"`
		Token   string `json:"token"`
	}
	if err := decodeJSONBody(r, &v); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	newToken, err := validateNewAuthToken(v.Token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Hold the write lock across the file write so two concurrent changes
	// cannot leave the file and the in-memory token disagreeing.
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if !tokensEqual(v.Current, holder.value) {
		http.Error(w, "当前 Token 不正确", http.StatusForbidden)
		return
	}
	if tokensEqual(newToken, holder.value) {
		http.Error(w, "新 Token 与当前 Token 相同", http.StatusBadRequest)
		return
	}
	if err := writeEnvToken(authEnvPath, newToken); err != nil {
		log.Printf("admin token change failed: %v", err)
		http.Error(w, "写入 Token 失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	holder.value = newToken
	log.Printf("admin token changed from %s", authClient(r.RemoteAddr))
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
