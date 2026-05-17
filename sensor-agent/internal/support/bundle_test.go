//go:build linux

package support

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

func TestRedactRemovesSensitiveValues(t *testing.T) {
	input := []byte(`{
  "ip": "192.168.10.44",
  "password": "secret-value",
  "Authorization": "Bearer abc.def.ghi",
  "pem": "-----BEGIN EC PRIVATE KEY-----
super-secret
-----END EC PRIVATE KEY-----"
}`)

	output := string(redact(input))
	for _, forbidden := range []string{"192.168.10.44", "secret-value", "abc.def.ghi", "super-secret"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("redacted output still contains %q: %s", forbidden, output)
		}
	}
	for _, want := range []string{"[REDACTED-IP]", `"password": "[REDACTED]"`, "Bearer [REDACTED]", "[REDACTED-PRIVATE-KEY]"} {
		if !strings.Contains(output, want) {
			t.Fatalf("redacted output missing %q: %s", want, output)
		}
	}
}

func TestExtractLogLinesStripsControlBytes(t *testing.T) {
	raw := []byte{0, 1, 2, 'h', 'e', 'l', 'l', 'o', '\n', 0, 'w', 'o', 'r', 'l', 'd'}
	lines := extractLogLines(raw)
	if len(lines) != 2 || lines[0] != "hello" || lines[1] != "world" {
		t.Fatalf("extractLogLines() = %#v", lines)
	}
}

func TestGenerateWritesArchiveWithExpectedSections(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	auditLog, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer auditLog.Close()
	auditLog.Log("support_bundle_requested", "sensor-agent", "success", map[string]any{
		"token": "super-secret-token",
	})

	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "local.rules"), []byte("alert tcp any any -> any any (sid:1;)"), 0600); err != nil {
		t.Fatal(err)
	}

	generator := NewBundleGeneratorWithConfig(auditLog, BundleConfig{
		AuditLogPath:     auditPath,
		CertDir:          filepath.Join(dir, "missing-certs"),
		RulesDir:         rulesDir,
		PcapAlertsDir:    dir,
		PodmanSocketPath: filepath.Join(dir, "missing-podman.sock"),
		OutputDir:        dir,
		AuditTailLines:   10,
	})

	archivePath, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	entries := readBundleEntries(t, archivePath)
	for _, suffix := range []string{
		"container_logs.json",
		"nic_stats.json",
		"af_packet_drops.json",
		"disk_usage.json",
		"rule_versions.json",
		"cert_status.json",
		"audit_log_tail.json",
	} {
		found := false
		for name := range entries {
			if strings.HasSuffix(name, suffix) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("bundle missing %s; entries=%v", suffix, entries)
		}
	}

	for name, body := range entries {
		if strings.Contains(body, "super-secret-token") {
			t.Fatalf("bundle entry %s leaked token: %s", name, body)
		}
	}
}

func readBundleEntries(t *testing.T, archivePath string) map[string]string {
	t.Helper()

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	entries := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries[hdr.Name] = string(data)
	}
	return entries
}
