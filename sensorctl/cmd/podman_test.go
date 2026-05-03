package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareHostInstallsJournaldLimits(t *testing.T) {
	commands := strings.Join(prepareHostCommands(), "\n")

	if !strings.Contains(commands, "deploy/systemd/journald.conf.d/ravenwire.conf") {
		t.Fatal("prepareHost must install the RavenWire journald drop-in")
	}
	if !strings.Contains(commands, "/etc/systemd/journald.conf.d/ravenwire.conf") {
		t.Fatal("prepareHost must install the journald drop-in under /etc/systemd")
	}
	if !strings.Contains(commands, "systemctl restart systemd-journald.service") {
		t.Fatal("prepareHost must restart systemd-journald after installing limits")
	}
	if !strings.Contains(commands, "journalctl --rotate") {
		t.Fatal("prepareHost must rotate the journal before vacuuming existing logs")
	}
	if !strings.Contains(commands, "journalctl --vacuum-size=512M --vacuum-time=7d") {
		t.Fatal("prepareHost must vacuum existing journals to the configured cap")
	}
	if !strings.Contains(commands, "deploy/systemd/logrotate.d/ravenwire") {
		t.Fatal("prepareHost must install the RavenWire logrotate rule")
	}
	if !strings.Contains(commands, "deploy/systemd/libexec/ravenwire-prune-logs") {
		t.Fatal("prepareHost must install the RavenWire log pruning script")
	}
	if !strings.Contains(commands, "systemctl enable --now ravenwire-log-prune.timer") {
		t.Fatal("prepareHost must enable the RavenWire log pruning timer")
	}
	if !strings.Contains(commands, "/var/sensor/support-bundles") {
		t.Fatal("prepareHost must create the support bundle directory")
	}
}

func TestJournaldDropInBoundsJournalStorage(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "journald.conf.d", "ravenwire.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	for _, want := range []string{
		"[Journal]",
		"SystemMaxUse=512M",
		"RuntimeMaxUse=128M",
		"SystemKeepFree=2G",
		"RuntimeKeepFree=512M",
		"MaxRetentionSec=7day",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("journald drop-in missing %q", want)
		}
	}
}

func TestLogPruneTimerBoundsRavenWireHostLogs(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	script, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "libexec", "ravenwire-prune-logs"))
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "system", "ravenwire-log-prune.timer"))
	if err != nil {
		t.Fatal(err)
	}

	scriptText := string(script)
	for _, want := range []string{
		"RAVENWIRE_LOG_RETENTION_DAYS:-2",
		"RAVENWIRE_LOG_MAX_TOTAL_MB:-2048",
		"RAVENWIRE_LOG_MAX_FILE_MB:-512",
		"RAVENWIRE_SUPPORT_BUNDLE_RETENTION_DAYS:-2",
		"RAVENWIRE_PCAP_RETENTION_DAYS:-7",
		"RAVENWIRE_PCAP_MAX_TOTAL_MB:-4096",
		"truncated active oversized log",
		"deleted aged",
	} {
		if !strings.Contains(scriptText, want) {
			t.Fatalf("log prune script missing %q", want)
		}
	}

	timerText := string(timer)
	for _, want := range []string{
		"OnBootSec=5min",
		"OnUnitActiveSec=1h",
		"WantedBy=timers.target",
	} {
		if !strings.Contains(timerText, want) {
			t.Fatalf("log prune timer missing %q", want)
		}
	}
}

func TestLogrotateRuleBoundsRavenWireHostLogs(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "logrotate.d", "ravenwire"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	for _, want := range []string{
		"/var/sensor/logs/suricata/*.json",
		"/var/sensor/logs/zeek/*.log",
		"/var/sensor/audit.log",
		"rotate 2",
		"maxsize 512M",
		"copytruncate",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("logrotate rule missing %q", want)
		}
	}
}

func TestCleanupCommandsRunStoragePruning(t *testing.T) {
	commands := strings.Join(cleanupCommands(cleanupOptions{}), "\n")

	for _, want := range []string{
		"journalctl --vacuum-size=512M --vacuum-time=7d",
		"ravenwire-log-prune.service",
		"logrotate -f /etc/logrotate.d/ravenwire",
		"sensor-support-*.tar.gz",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("cleanup commands missing %q", want)
		}
	}

	withPodman := strings.Join(cleanupCommands(cleanupOptions{podman: true}), "\n")
	if !strings.Contains(withPodman, "podman system prune -f") {
		t.Fatal("cleanup --podman must prune unused Podman artifacts")
	}

	withDocker := strings.Join(cleanupCommands(cleanupOptions{docker: true}), "\n")
	if !strings.Contains(withDocker, "docker system prune -f") {
		t.Fatal("cleanup --docker must prune unused Docker artifacts")
	}
}

func TestSensorCertificateReadyRejectsExpiredCert(t *testing.T) {
	certDir := t.TempDir()
	writeTestCertBundle(t, certDir, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	ok, reason := sensorCertificateReady(certDir, time.Now())
	if ok {
		t.Fatal("expired certificate must require enrollment")
	}
	if !strings.Contains(reason, "expired") {
		t.Fatalf("expected expired reason, got %q", reason)
	}
}

func TestSensorCertificateReadyAcceptsCurrentBundle(t *testing.T) {
	certDir := t.TempDir()
	writeTestCertBundle(t, certDir, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	ok, reason := sensorCertificateReady(certDir, time.Now())
	if !ok {
		t.Fatalf("valid certificate bundle rejected: %s", reason)
	}
}

func TestSensorCertificateReadyRejectsPartialBundle(t *testing.T) {
	certDir := t.TempDir()
	writeTestCertBundle(t, certDir, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := os.Remove(filepath.Join(certDir, "ca-chain.pem")); err != nil {
		t.Fatal(err)
	}

	ok, reason := sensorCertificateReady(certDir, time.Now())
	if ok {
		t.Fatal("partial certificate bundle must require enrollment")
	}
	if !strings.Contains(reason, "missing") {
		t.Fatalf("expected missing-file reason, got %q", reason)
	}
}

func writeTestCertBundle(t *testing.T, certDir string, notBefore, notAfter time.Time) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"sensor.crt":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		"sensor.key":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"ca-chain.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(certDir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
