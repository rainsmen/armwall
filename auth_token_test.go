package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateNewAuthToken(t *testing.T) {
	for _, ok := range []string{"abcd1234", "My-Pass_2026.x", "a@b%c+d=e:f"} {
		if _, err := validateNewAuthToken(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "short7!", "has space1", "quote\"1234", "dollar$1234", "hash#12345", "new\nline123", strings.Repeat("a", 129), "中文密码12345678"} {
		if _, err := validateNewAuthToken(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := validateAuthToken("12345678"); err != nil {
		t.Fatalf("8-character env token rejected: %v", err)
	}
}

func TestWriteEnvTokenKeepsOtherLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "armwall.env")
	content := "ARMWALL_TOKEN=old1234567890abcd\nARMWALL_WEB_ACCESS=lan\n\nARMWALL_TOKEN=dup\nARMWALL_LISTEN=0.0.0.0:8080\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvToken(path, "newtoken1"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := "ARMWALL_TOKEN=newtoken1\nARMWALL_WEB_ACCESS=lan\n\nARMWALL_LISTEN=0.0.0.0:8080\n"
	if string(got) != want {
		t.Fatalf("env file:\n%s\nwant:\n%s", got, want)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode().Perm())
	}
}

func TestAuthTokenChangeEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "armwall.env")
	if err := os.WriteFile(path, []byte("ARMWALL_TOKEN=0123456789abcdef\nARMWALL_WEB_ACCESS=lan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := authEnvPath
	authEnvPath = path
	t.Cleanup(func() { authEnvPath = old })

	holder := newAuthToken("0123456789abcdef")
	handler := authHandler(holder, func(w http.ResponseWriter, r *http.Request) {
		apiAuthTokenChange(w, r, holder)
	})
	call := func(auth, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/token", strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("Authorization", "Bearer "+auth)
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}
	if code := call("0123456789abcdef", `{"current":"wrong","token":"mynewpass"}`); code != http.StatusForbidden {
		t.Fatalf("wrong current token status=%d", code)
	}
	if code := call("0123456789abcdef", `{"current":"0123456789abcdef","token":"short"}`); code != http.StatusBadRequest {
		t.Fatalf("short token status=%d", code)
	}
	if code := call("0123456789abcdef", `{"current":"0123456789abcdef","token":"mynewpass"}`); code != http.StatusOK {
		t.Fatalf("change status=%d", code)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "ARMWALL_TOKEN=mynewpass\nARMWALL_WEB_ACCESS=lan\n" {
		t.Fatalf("env file=%q", got)
	}
	if code := call("0123456789abcdef", `{}`); code != http.StatusUnauthorized {
		t.Fatalf("old token still accepted, status=%d", code)
	}
	if code := call("mynewpass", `{"current":"mynewpass","token":"mynewpass"}`); code != http.StatusBadRequest {
		t.Fatalf("same token status=%d", code)
	}
}

func TestAuthTokenChangeKeepsTokenWhenWriteFails(t *testing.T) {
	old := authEnvPath
	authEnvPath = filepath.Join(t.TempDir(), "missing", "armwall.env")
	t.Cleanup(func() { authEnvPath = old })
	holder := newAuthToken("0123456789abcdef")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/token", strings.NewReader(`{"current":"0123456789abcdef","token":"mynewpass"}`))
	rec := httptest.NewRecorder()
	apiAuthTokenChange(rec, req, holder)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	if holder.get() != "0123456789abcdef" {
		t.Fatal("in-memory token changed although the file write failed")
	}
}
