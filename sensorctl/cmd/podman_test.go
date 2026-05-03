package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
