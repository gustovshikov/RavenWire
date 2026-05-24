package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
	if !strings.Contains(commands, "deploy/systemd/tmpfiles.d/ravenwire.conf") {
		t.Fatal("prepareHost must install the RavenWire tmpfiles rule")
	}
	if !strings.Contains(commands, "systemd-tmpfiles --create /etc/tmpfiles.d/ravenwire.conf") {
		t.Fatal("prepareHost must create tmpfiles-managed runtime directories")
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

func TestDefaultVectorConfigDiscardsNormalizedOutput(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "config", "sensor", "vector.toml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	for _, want := range []string{
		"[sinks.normalized_null]",
		`type = "blackhole"`,
		`fingerprint.strategy = "device_and_inode"`,
		"drop_on_abort = true",
		"drop_on_error = true",
		"reroute_dropped = false",
		"parsed = parse_json",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("default Vector config missing %q", want)
		}
	}
	if strings.Contains(text, "[sinks.normalized_console]") || strings.Contains(text, `type = "console"`) {
		t.Fatal("default Vector config must not write normalized events to console")
	}
	if !strings.Contains(text, "reroute_unmatched = false") {
		t.Fatal("default Vector route transform must disable the unused _unmatched output")
	}
	if strings.Contains(text, "parse_json!") {
		t.Fatal("default Vector config must drop invalid log lines without noisy parse errors")
	}
}

func TestPrepareHostInstallsSuricataStarterRules(t *testing.T) {
	commands := strings.Join(prepareHostCommands(), "\n")

	if !strings.Contains(commands, "config/sensor/suricata/rules/suricata.rules") {
		t.Fatal("prepareHost must install the starter Suricata rules file")
	}
	if strings.Contains(commands, "touch /etc/sensor/suricata/rules/suricata.rules") {
		t.Fatal("prepareHost must not replace starter Suricata rules with an empty file")
	}

	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "config", "sensor", "suricata", "rules", "suricata.rules"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	if !strings.Contains(text, "sid:9000001") || !strings.Contains(text, "alert ") {
		t.Fatal("starter Suricata rules file must contain a loadable low-noise alert rule")
	}
}

func TestConfigureCaptureInterfaceTunesQueuesAndOffloads(t *testing.T) {
	commands := strings.Join(configureCaptureInterfaceCommands("ens16f1"), "\n")

	for _, want := range []string{
		"ip link set dev 'ens16f1' up promisc on",
		"ip link set dev 'ens16f1' txqueuelen 4096",
		"ethtool -K 'ens16f1' gro off lro off",
		"ethtool -G 'ens16f1' rx 4096 tx 4096",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("capture interface setup missing %q", want)
		}
	}
}

func TestSensorAgentQuadletReceivesControlAPIHost(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "deploy", "quadlet", "sensor-pod", "sensor-agent.container"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	if !strings.Contains(text, "Environment=CONTROL_API_HOST=${CONTROL_API_HOST}") {
		t.Fatal("sensor-agent quadlet must pass CONTROL_API_HOST into the container")
	}
}

func TestSensorPodQuadletsLoadPersistentEnvironmentFile(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"sensor-agent.container",
		"pcap-ring-writer.container",
		"zeek.container",
		"suricata.container",
		"vector.container",
	} {
		content, err := os.ReadFile(filepath.Join(root, "deploy", "quadlet", "sensor-pod", name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "EnvironmentFile=-/etc/ravenwire/sensor.env") {
			t.Fatalf("%s must load the persistent sensor environment file", name)
		}
	}
}

func TestConfigManagerQuadletLoadsPersistentManagerEnvironmentFile(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(root, "deploy", "quadlet", "management-pod", "config-manager.container"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	if !strings.Contains(text, "EnvironmentFile=/etc/ravenwire/manager.env") {
		t.Fatal("config-manager quadlet must load the persistent manager environment file")
	}
	if strings.Contains(text, "RAVENWIRE_ADMIN_PASSWORD=RavenWire2026!") {
		t.Fatal("config-manager quadlet must not hardcode the demo admin password")
	}
}

func TestSensorEnvironmentFileCommandWritesStableRootOnlyFile(t *testing.T) {
	command := sensorEnvironmentFileCommand(map[string]string{
		"SENSOR_POD_NAME":    "ravenwire-test",
		"CONFIG_MANAGER_URL": "http://127.0.0.1:4000/api/v1",
		"EMPTY":              "",
	})

	for _, want := range []string{
		"sudo mkdir -p '/etc/ravenwire'",
		"'CONFIG_MANAGER_URL=http://127.0.0.1:4000/api/v1'",
		"'EMPTY='",
		"'SENSOR_POD_NAME=ravenwire-test'",
		"sudo tee '/etc/ravenwire/sensor.env' >/dev/null",
		"sudo chmod 0600 '/etc/ravenwire/sensor.env'",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("sensor env file command missing %q in %q", want, command)
		}
	}
}

func TestManagerEnvironmentFileCommandWritesStableRootOnlyFile(t *testing.T) {
	command := environmentFileCommand(managerEnvFile, map[string]string{
		"RAVENWIRE_ADMIN_USER":     "pilot-admin",
		"SECRET_KEY_BASE":          "secret-key-base",
		"RAVENWIRE_ADMIN_PASSWORD": "pilot-password",
	})

	for _, want := range []string{
		"sudo mkdir -p '/etc/ravenwire'",
		"'RAVENWIRE_ADMIN_PASSWORD=pilot-password'",
		"'RAVENWIRE_ADMIN_USER=pilot-admin'",
		"'SECRET_KEY_BASE=secret-key-base'",
		"sudo tee '/etc/ravenwire/manager.env' >/dev/null",
		"sudo chmod 0600 '/etc/ravenwire/manager.env'",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("manager env file command missing %q in %q", want, command)
		}
	}
}

func TestLabManagerEnvironmentPreservesDemoDefaults(t *testing.T) {
	result, err := managerEnvironment(false, func(string) string {
		return "ignored"
	}, func(int) (string, error) {
		t.Fatal("lab manager environment must not generate secrets")
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.env["SECRET_KEY_BASE"] != demoSecretKeyBase {
		t.Fatal("lab manager environment must preserve the demo secret key base")
	}
	if result.env["RAVENWIRE_ADMIN_USER"] != demoAdminUser {
		t.Fatal("lab manager environment must preserve the demo admin user")
	}
	if result.env["RAVENWIRE_ADMIN_PASSWORD"] != demoAdminPassword {
		t.Fatal("lab manager environment must preserve the demo admin password")
	}
	if _, ok := result.env["RAVENWIRE_SINK_ENCRYPTION_KEY"]; ok {
		t.Fatal("lab manager environment must not set a sink encryption key")
	}
}

func TestPilotManagerEnvironmentUsesExplicitSecrets(t *testing.T) {
	sinkKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	values := map[string]string{
		"SECRET_KEY_BASE":               strings.Repeat("s", 64),
		"RAVENWIRE_SINK_ENCRYPTION_KEY": sinkKey,
		"RAVENWIRE_ADMIN_USER":          "pilot-admin",
		"RAVENWIRE_ADMIN_PASSWORD":      "operator-password",
	}

	result, err := managerEnvironment(true, func(key string) string {
		return values[key]
	}, func(int) (string, error) {
		t.Fatal("explicit pilot manager environment must not generate secrets")
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for key, want := range values {
		if result.env[key] != want {
			t.Fatalf("%s = %q, want %q", key, result.env[key], want)
		}
	}
	if result.env["RAVENWIRE_API_DOCS_REQUIRE_AUTH"] != "true" {
		t.Fatal("pilot hardening must require auth for API docs")
	}
	if result.generatedAdminPassword != "" {
		t.Fatal("explicit admin password must not be reported as generated")
	}
}

func TestPilotManagerEnvironmentGeneratesNonDemoSecrets(t *testing.T) {
	sinkKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	random := func(byteCount int) (string, error) {
		switch byteCount {
		case 48:
			return strings.Repeat("s", 64), nil
		case 32:
			return sinkKey, nil
		case 24:
			return "generated-admin-password", nil
		default:
			t.Fatalf("unexpected random byte count %d", byteCount)
			return "", nil
		}
	}

	result, err := managerEnvironment(true, func(string) string {
		return ""
	}, random)
	if err != nil {
		t.Fatal(err)
	}

	if result.env["SECRET_KEY_BASE"] == "" || result.env["SECRET_KEY_BASE"] == demoSecretKeyBase {
		t.Fatal("pilot hardening must generate a non-demo secret key base")
	}
	if result.env["RAVENWIRE_SINK_ENCRYPTION_KEY"] != sinkKey {
		t.Fatal("pilot hardening must generate a sink encryption key")
	}
	if result.env["RAVENWIRE_ADMIN_USER"] != demoAdminUser {
		t.Fatal("pilot hardening should default the admin username to RavenWire")
	}
	if result.env["RAVENWIRE_ADMIN_PASSWORD"] != "generated-admin-password" {
		t.Fatal("pilot hardening must generate an admin password when none is provided")
	}
	if result.generatedAdminPassword != "generated-admin-password" {
		t.Fatal("generated admin password must be reported for one-time operator capture")
	}
}

func TestPilotManagerEnvironmentRejectsDemoPassword(t *testing.T) {
	sinkKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	values := map[string]string{
		"SECRET_KEY_BASE":               strings.Repeat("s", 64),
		"RAVENWIRE_SINK_ENCRYPTION_KEY": sinkKey,
		"RAVENWIRE_ADMIN_PASSWORD":      demoAdminPassword,
	}

	_, err := managerEnvironment(true, func(key string) string {
		return values[key]
	}, func(int) (string, error) {
		t.Fatal("invalid explicit pilot manager environment must not generate secrets")
		return "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "must not use the bundled demo value") {
		t.Fatalf("expected demo password rejection, got %v", err)
	}
}

func TestDetectControlAPIHostDefaultsLoopbackForSingleNodeInstall(t *testing.T) {
	for _, managerURL := range []string{
		"http://127.0.0.1:4000/api/v1",
		"http://localhost:4000/api/v1",
	} {
		if got := detectControlAPIHost(managerURL); got != "127.0.0.1" {
			t.Fatalf("detectControlAPIHost(%q) = %q, want 127.0.0.1", managerURL, got)
		}
	}
}

func TestContainerImagesAreVersionPinned(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}

	files := []string{
		filepath.Join(root, "config-manager", "Dockerfile"),
		filepath.Join(root, "sensor-agent", "Containerfile"),
		filepath.Join(root, "sensor-agent", "pcap-ring-writer.Containerfile"),
	}

	quadlets, err := filepath.Glob(filepath.Join(root, "deploy", "quadlet", "*", "*.container"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, quadlets...)

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		for lineNo, line := range strings.Split(string(content), "\n") {
			ref, ok := imageReference(line)
			if !ok {
				continue
			}

			if strings.Contains(ref, ":latest") || strings.Contains(ref, "latest-") {
				t.Fatalf("%s:%d uses mutable latest image tag: %s", file, lineNo+1, ref)
			}
			if !imageHasPinnedTag(ref) {
				t.Fatalf("%s:%d image must be pinned to an explicit version tag: %s", file, lineNo+1, ref)
			}
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

func imageReference(line string) (string, bool) {
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "FROM ") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", false
		}
		return fields[1], true
	}

	if strings.HasPrefix(line, "Image=") {
		return strings.TrimSpace(strings.TrimPrefix(line, "Image=")), true
	}

	return "", false
}

func imageHasPinnedTag(ref string) bool {
	if strings.Contains(ref, "@sha256:") {
		return true
	}

	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon <= lastSlash || lastColon == len(ref)-1 {
		return false
	}

	tag := ref[lastColon+1:]
	if strings.HasPrefix(ref, "localhost/") {
		return tag != ""
	}

	for _, r := range tag {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
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
