package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigArchiveAndBackupLifecycle(t *testing.T) {
	dir := t.TempDir()
	oldBackupDir := backupDir
	backupDir = dir
	t.Cleanup(func() { backupDir = oldBackupDir })
	want := Store{Mode: "global", ProxyPort: 11080, LogLevel: "info", SelectedNode: "n1", Nodes: []Node{{ID: "n1", Name: "node", Type: "anytls", Server: "example.com", Port: 443, Password: "secret", TLS: true, Enabled: true}}}
	created, err := createConfigBackup(want, "armwall-backup")
	if err != nil {
		t.Fatal(err)
	}
	if !validBackupName(created.Name) || validBackupName("../"+created.Name) {
		t.Fatalf("unexpected backup name validation for %q", created.Name)
	}
	backups, err := listConfigBackups()
	if err != nil || len(backups) != 1 || backups[0].Name != created.Name {
		t.Fatalf("unexpected backup list: %+v, %v", backups, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, created.Name))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseConfigArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyPort != want.ProxyPort || len(got.Nodes) != 1 || got.Nodes[0].Password != "secret" {
		t.Fatalf("unexpected restored store: %+v", got)
	}
}

func TestCoreUploadUsesManagedTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	oldUploadDir, oldUpdateCorePath := coreUploadDir, updateCorePath
	coreUploadDir = filepath.Join(dir, "uploads")
	updateCorePath = filepath.Join(dir, "fake-update")
	t.Cleanup(func() { coreUploadDir, updateCorePath = oldUploadDir, oldUpdateCorePath })
	script := "#!/bin/sh\n[ \"$1:$2\" = \"naive:manual\" ] || exit 2\n[ -s \"$3\" ] || exit 3\nprintf 'naive uploaded\\n'\n"
	if err := os.WriteFile(updateCorePath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("core", "naive"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", "naive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("test binary")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/core/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	handleCoreUpload(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "naive uploaded") {
		t.Fatalf("upload status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	entries, err := os.ReadDir(coreUploadDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary upload was not removed: %+v, %v", entries, err)
	}
}

func TestCoreUpdateReceivesCurrentProxyPort(t *testing.T) {
	dir := t.TempDir()
	oldUpdateCorePath, oldProxyPort := updateCorePath, proxyPort
	updateCorePath = filepath.Join(dir, "fake-update")
	proxyPort = 12080
	t.Cleanup(func() { updateCorePath, proxyPort = oldUpdateCorePath, oldProxyPort })
	if err := os.WriteFile(updateCorePath, []byte("#!/bin/sh\nprintf '%s' \"$ARMWALL_PROXY_PORT\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runCoreUpdate(recorder, "sing-box", "latest")
	if recorder.Code != http.StatusOK || recorder.Body.String() != "12080" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestLogPreviewIsBoundedAndExportIsComplete(t *testing.T) {
	setupAPITest(t, Store{Mode: "bypass_cn", ProxyPort: 11080})
	if err := os.MkdirAll(logDir, 0750); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("0123456789abcdef"), 20000)
	if err := os.WriteFile(filepath.Join(logDir, "sing-box.log"), content, 0640); err != nil {
		t.Fatal(err)
	}
	previewRequest := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	preview := httptest.NewRecorder()
	api(preview, previewRequest)
	if preview.Code != http.StatusOK || preview.Body.Len() != 256<<10 {
		t.Fatalf("preview status=%d size=%d", preview.Code, preview.Body.Len())
	}
	exportRequest := httptest.NewRequest(http.MethodGet, "/api/logs?download=1", nil)
	export := httptest.NewRecorder()
	api(export, exportRequest)
	if export.Code != http.StatusOK || !bytes.Equal(export.Body.Bytes(), content) || !strings.Contains(export.Header().Get("Content-Disposition"), "armwall.log") {
		t.Fatalf("export status=%d size=%d disposition=%q", export.Code, export.Body.Len(), export.Header().Get("Content-Disposition"))
	}
}
