package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	appUnit              = "app"
	managementTarget     = "management-pod.target"
	sensorTarget         = "sensor-pod.target"
	captureTarget        = "capture-pipeline.target"
	analysisTarget       = "analysis-pipeline.target"
	defaultManagerURL    = "http://127.0.0.1:4000/api/v1"
	defaultManagerHealth = "http://127.0.0.1:4000/"
	sensorEnvFile        = "/etc/ravenwire/sensor.env"
	managerEnvFile       = "/etc/ravenwire/manager.env"
	demoSecretKeyBase    = "demo_secret_key_base_64chars_long_for_dev_only_not_for_prod_use"
	demoAdminUser        = "RavenWire"
	demoAdminPassword    = "RavenWire2026!"
)

type installOptions struct {
	captureIface   string
	podName        string
	managerURL     string
	skipBuild      bool
	pilotHardening bool
}

type cleanupOptions struct {
	podman bool
	docker bool
}

func installCmd() *cobra.Command {
	opts := installOptions{}
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the RavenWire dual-pod deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installApp(opts)
		},
	}
	cmd.Flags().StringVar(&opts.captureIface, "capture-iface", "", "Capture interface for the sensor pod")
	cmd.Flags().StringVar(&opts.podName, "pod-name", "", "Sensor pod name")
	cmd.Flags().StringVar(&opts.managerURL, "manager-url", defaultManagerURL, "Config Manager enrollment API base URL")
	cmd.Flags().BoolVar(&opts.skipBuild, "skip-build", false, "Skip local Podman image builds")
	cmd.Flags().BoolVar(&opts.pilotHardening, "pilot-hardening", false, "Generate a root-only manager env file with non-demo production-pilot secrets")
	return cmd
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [unit]",
		Short: "Start RavenWire or one target/service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAppUnit(args) {
				return startApp()
			}
			unit := defaultUnit(args, "app")
			return runShell("", fmt.Sprintf("sudo systemctl start %s", shellQuote(unit)))
		},
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop [unit]",
		Short: "Stop RavenWire or one target/service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAppUnit(args) {
				return stopApp()
			}
			unit := defaultUnit(args, "app")
			return runShell("", fmt.Sprintf("sudo systemctl stop %s", shellQuote(unit)))
		},
	}
}

func restartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart [unit]",
		Short: "Restart RavenWire or one target/service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAppUnit(args) {
				if err := stopApp(); err != nil {
					return err
				}
				return startApp()
			}
			unit := defaultUnit(args, "app")
			return runShell("", fmt.Sprintf("sudo systemctl restart %s", shellQuote(unit)))
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [unit]",
		Short: "Show RavenWire unit status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAppUnit(args) {
				return runShell("", "sudo systemctl list-units 'sensor-*' 'management-*' 'capture-*' 'analysis-*' 'pcap-*' 'zeek*' 'suricata*' 'vector*' --no-pager")
			}
			unit := normalizeSystemdUnit(args[0])
			return runShell("", fmt.Sprintf("sudo systemctl status %s --no-pager", shellQuote(unit)))
		},
	}
}

func logsCmd() *cobra.Command {
	var lines int

	cmd := &cobra.Command{
		Use:   "logs [unit]",
		Short: "Show RavenWire systemd journal logs",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAppUnit(args) {
				return runShell("", fmt.Sprintf("sudo journalctl -u sensor-pod.target -u management-pod.target -u sensor-agent.service -u pcap-ring-writer.service -u zeek.service -u suricata.service -u vector.service -n %d --no-pager", lines))
			}
			unit := normalizeSystemdUnit(args[0])
			return runShell("", fmt.Sprintf("sudo journalctl -u %s -n %d --no-pager", shellQuote(unit), lines))
		},
	}

	cmd.Flags().IntVarP(&lines, "lines", "n", 200, "Number of journal lines to show")
	return cmd
}

func uninstallCmd() *cobra.Command {
	var purge bool
	var images bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall RavenWire systemd/Quadlet units",
		RunE: func(cmd *cobra.Command, args []string) error {
			return uninstallApp(purge, images)
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "Remove RavenWire host data and generated certs/config")
	cmd.Flags().BoolVar(&images, "images", false, "Remove locally built RavenWire images")
	return cmd
}

func cleanupCmd() *cobra.Command {
	opts := cleanupOptions{}
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Prune RavenWire runtime storage and optional container cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cleanupApp(opts)
		},
	}
	cmd.Flags().BoolVar(&opts.podman, "podman", false, "Also prune unused Podman containers, networks, and images")
	cmd.Flags().BoolVar(&opts.docker, "docker", false, "Also prune unused Docker containers, networks, and images from old lab workflows")
	return cmd
}

func installApp(opts installOptions) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}

	if !opts.skipBuild {
		if err := buildImages(root); err != nil {
			return err
		}
	}

	if err := prepareHost(root); err != nil {
		return err
	}

	if err := installQuadlet(root); err != nil {
		return err
	}

	if err := configureEnvironment(opts); err != nil {
		return err
	}

	fmt.Println("RavenWire installed. Start the dual-pod stack with `sensorctl start`.")
	return nil
}

func buildImages(root string) error {
	commands := []string{
		"sudo podman build --network=host -t localhost/ravenwire/config-manager:test -f config-manager/Dockerfile config-manager",
		"sudo podman build --network=host -t localhost/ravenwire/sensor-agent:test -f sensor-agent/Containerfile sensor-agent",
		"sudo podman build --network=host -t localhost/ravenwire/pcap-ring-writer:test -f sensor-agent/pcap-ring-writer.Containerfile sensor-agent",
	}
	for _, command := range commands {
		if err := runShell(root, command); err != nil {
			return err
		}
	}
	return nil
}

func prepareHost(root string) error {
	for _, command := range prepareHostCommands() {
		if err := runShell(root, command); err != nil {
			return err
		}
	}
	return nil
}

func prepareHostCommands() []string {
	return []string{
		"sudo systemctl enable --now podman.socket",
		"sudo mkdir -p /data/config_manager /data/ca /data/metrics /etc/sensor/certs /etc/sensor/zeek /etc/sensor/suricata/rules /etc/sensor/vector /var/sensor/logs/zeek /var/sensor/logs/suricata /var/sensor/logs/vector /var/sensor/vector-buffer /var/sensor/support-bundles /var/run/sensor /sensor/pcap/alerts",
		"sudo chown -R 0:0 /data/config_manager /data/ca /data/metrics /etc/sensor /var/sensor /var/run/sensor /sensor/pcap",
		"sudo install -D -m 0644 deploy/systemd/journald.conf.d/ravenwire.conf /etc/systemd/journald.conf.d/ravenwire.conf",
		"sudo systemctl restart systemd-journald.service",
		"sudo journalctl --rotate",
		"sudo journalctl --vacuum-size=256M --vacuum-time=3d",
		"sudo install -D -m 0644 deploy/systemd/tmpfiles.d/ravenwire.conf /etc/tmpfiles.d/ravenwire.conf",
		"sudo systemd-tmpfiles --create /etc/tmpfiles.d/ravenwire.conf",
		"sudo install -D -m 0644 deploy/systemd/logrotate.d/ravenwire /etc/logrotate.d/ravenwire",
		"sudo install -D -m 0755 deploy/systemd/libexec/ravenwire-prune-logs /usr/local/libexec/ravenwire-prune-logs",
		"sudo install -D -m 0644 deploy/systemd/system/ravenwire-log-prune.service /etc/systemd/system/ravenwire-log-prune.service",
		"sudo install -D -m 0644 deploy/systemd/system/ravenwire-log-prune.timer /etc/systemd/system/ravenwire-log-prune.timer",
		"sudo systemctl daemon-reload",
		"sudo systemctl enable --now ravenwire-log-prune.timer",
		"sudo systemctl start ravenwire-log-prune.service",
		"sudo install -D -m 0644 config/sensor/bpf_filters.conf /etc/sensor/bpf_filters.conf",
		"sudo install -D -m 0644 config/sensor/capture.conf /etc/sensor/capture.conf",
		"sudo install -D -m 0644 config/sensor/vector.toml /etc/sensor/vector/vector.toml",
		"sudo install -D -m 0644 config/sensor/suricata.yaml /etc/sensor/suricata/suricata.yaml",
		"sudo install -D -m 0644 config/sensor/suricata/classification.config /etc/sensor/suricata/classification.config",
		"sudo install -D -m 0644 config/sensor/suricata/reference.config /etc/sensor/suricata/reference.config",
		"sudo install -D -m 0644 config/sensor/suricata/threshold.config /etc/sensor/suricata/threshold.config",
		"sudo install -D -m 0644 config/sensor/suricata/rules/suricata.rules /etc/sensor/suricata/rules/suricata.rules",
		"sudo install -D -m 0644 config/sensor/zeek/local.zeek /etc/sensor/zeek/local.zeek",
	}
}

func installQuadlet(root string) error {
	src := filepath.Join(root, "deploy", "quadlet")
	quadletDst := "/etc/containers/systemd"
	systemdDst := "/etc/systemd/system"

	commands := []string{
		fmt.Sprintf("sudo mkdir -p %s %s", shellQuote(quadletDst), shellQuote(systemdDst)),
		fmt.Sprintf("find %s -type f \\( -name '*.container' -o -name '*.network' -o -name '*.volume' \\) -exec sudo cp {} %s/ \\;", shellQuote(src), shellQuote(quadletDst)),
		fmt.Sprintf("find %s -type f -name '*.target' -exec sudo cp {} %s/ \\;", shellQuote(src), shellQuote(systemdDst)),
		"sudo systemctl daemon-reload",
	}

	for _, command := range commands {
		if err := runShell(root, command); err != nil {
			return err
		}
	}

	return nil
}

func configureEnvironment(opts installOptions) error {
	iface := opts.captureIface
	if iface == "" {
		iface = os.Getenv("CAPTURE_IFACE")
	}
	if iface == "" {
		var err error
		iface, err = detectCaptureInterface()
		if err != nil {
			return err
		}
	}

	podName := opts.podName
	if podName == "" {
		podName = os.Getenv("SENSOR_POD_NAME")
	}
	if podName == "" {
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		podName = host
	}

	managerURL := opts.managerURL
	if managerURL == "" {
		managerURL = defaultManagerURL
	}
	controlAPIHost := os.Getenv("CONTROL_API_HOST")
	if controlAPIHost == "" {
		controlAPIHost = detectControlAPIHost(managerURL)
	}

	env := map[string]string{
		"CAPTURE_IFACE":       iface,
		"SENSOR_POD_NAME":     podName,
		"CONFIG_MANAGER_URL":  strings.TrimRight(managerURL, "/"),
		"CONTROL_API_HOST":    controlAPIHost,
		"GRPC_ADDR":           "127.0.0.1:9090",
		"SENSOR_SVC_UID":      "0",
		"MIN_DISK_WRITE_MBPS": envOr("MIN_DISK_WRITE_MBPS", "50"),
		"MIN_STORAGE_GB":      envOr("MIN_STORAGE_GB", "10"),
		"VECTOR_METRICS_URL":  envOr("VECTOR_METRICS_URL", "http://127.0.0.1:9598/metrics"),
		"ZEEK_LOG_DIR":        envOr("ZEEK_LOG_DIR", "/var/sensor/logs/zeek"),
		"SURICATA_EVE_PATH":   envOr("SURICATA_EVE_PATH", "/var/sensor/logs/suricata/eve*.json"),
		"SPLUNK_HEC_URL":      "",
		"SPLUNK_HEC_TOKEN":    "",
		"CRIBL_URL":           "",
		"CRIBL_TOKEN":         "",
	}

	assignments := make([]string, 0, len(env))
	for key, value := range env {
		assignments = append(assignments, shellQuote(key+"="+value))
	}

	if err := writeSensorEnvironmentFile(env); err != nil {
		return err
	}
	managerEnv, err := managerEnvironment(opts.pilotHardening, os.Getenv, randomBase64)
	if err != nil {
		return err
	}
	if err := writeManagerEnvironmentFile(managerEnv.env); err != nil {
		return err
	}
	if err := runShell("", "sudo systemctl set-environment "+strings.Join(assignments, " ")); err != nil {
		return err
	}
	if err := configureCaptureInterface(iface); err != nil {
		return err
	}

	fmt.Printf("Configured sensor pod %q on interface %q using manager %s\n", podName, iface, managerURL)
	if controlAPIHost != "" {
		fmt.Printf("Configured Control API host %q for automatic enrollment\n", controlAPIHost)
	}
	printManagerEnvironmentSummary(opts.pilotHardening, managerEnv)
	return nil
}

func writeSensorEnvironmentFile(env map[string]string) error {
	return runShell("", sensorEnvironmentFileCommand(env))
}

func writeManagerEnvironmentFile(env map[string]string) error {
	return runShell("", environmentFileCommand(managerEnvFile, env))
}

func sensorEnvironmentFileCommand(env map[string]string) string {
	return environmentFileCommand(sensorEnvFile, env)
}

func environmentFileCommand(path string, env map[string]string) string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, shellQuote(key+"="+env[key]))
	}

	return fmt.Sprintf(
		"sudo mkdir -p %s && printf '%%s\\n' %s | sudo tee %s >/dev/null && sudo chmod 0600 %s",
		shellQuote(filepath.Dir(path)),
		strings.Join(lines, " "),
		shellQuote(path),
		shellQuote(path),
	)
}

type managerEnvironmentResult struct {
	env                    map[string]string
	generatedAdminPassword string
}

func managerEnvironment(pilotHardening bool, getenv func(string) string, randomString func(int) (string, error)) (managerEnvironmentResult, error) {
	if !pilotHardening {
		return managerEnvironmentResult{
			env: map[string]string{
				"SECRET_KEY_BASE":          demoSecretKeyBase,
				"RAVENWIRE_ADMIN_USER":     demoAdminUser,
				"RAVENWIRE_ADMIN_PASSWORD": demoAdminPassword,
			},
		}, nil
	}

	secretKeyBase, err := pilotSecretKeyBase(getenv, randomString)
	if err != nil {
		return managerEnvironmentResult{}, err
	}
	sinkEncryptionKey, err := pilotSinkEncryptionKey(getenv, randomString)
	if err != nil {
		return managerEnvironmentResult{}, err
	}
	adminUser := getenv("RAVENWIRE_ADMIN_USER")
	if adminUser == "" {
		adminUser = demoAdminUser
	}

	adminPassword := getenv("RAVENWIRE_ADMIN_PASSWORD")
	generatedAdminPassword := ""
	if adminPassword == "" {
		adminPassword, err = randomString(24)
		if err != nil {
			return managerEnvironmentResult{}, fmt.Errorf("generate RAVENWIRE_ADMIN_PASSWORD: %w", err)
		}
		generatedAdminPassword = adminPassword
	}
	if err := validatePilotAdminPassword(adminPassword); err != nil {
		return managerEnvironmentResult{}, err
	}

	return managerEnvironmentResult{
		env: map[string]string{
			"SECRET_KEY_BASE":                 secretKeyBase,
			"RAVENWIRE_ADMIN_USER":            adminUser,
			"RAVENWIRE_ADMIN_PASSWORD":        adminPassword,
			"RAVENWIRE_SINK_ENCRYPTION_KEY":   sinkEncryptionKey,
			"RAVENWIRE_API_DOCS_REQUIRE_AUTH": "true",
		},
		generatedAdminPassword: generatedAdminPassword,
	}, nil
}

func pilotSecretKeyBase(getenv func(string) string, randomString func(int) (string, error)) (string, error) {
	secretKeyBase := getenv("SECRET_KEY_BASE")
	if secretKeyBase == "" {
		generated, err := randomString(48)
		if err != nil {
			return "", fmt.Errorf("generate SECRET_KEY_BASE: %w", err)
		}
		return generated, nil
	}
	if secretKeyBase == demoSecretKeyBase {
		return "", fmt.Errorf("SECRET_KEY_BASE must not use the bundled demo value when --pilot-hardening is enabled")
	}
	if len(secretKeyBase) < 64 {
		return "", fmt.Errorf("SECRET_KEY_BASE must be at least 64 characters when --pilot-hardening is enabled")
	}
	return secretKeyBase, nil
}

func pilotSinkEncryptionKey(getenv func(string) string, randomString func(int) (string, error)) (string, error) {
	sinkEncryptionKey := getenv("RAVENWIRE_SINK_ENCRYPTION_KEY")
	if sinkEncryptionKey == "" {
		generated, err := randomString(32)
		if err != nil {
			return "", fmt.Errorf("generate RAVENWIRE_SINK_ENCRYPTION_KEY: %w", err)
		}
		return generated, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(sinkEncryptionKey)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("RAVENWIRE_SINK_ENCRYPTION_KEY must be a Base64-encoded 32-byte key")
	}
	return sinkEncryptionKey, nil
}

func validatePilotAdminPassword(adminPassword string) error {
	if adminPassword == demoAdminPassword {
		return fmt.Errorf("RAVENWIRE_ADMIN_PASSWORD must not use the bundled demo value when --pilot-hardening is enabled")
	}
	if len(adminPassword) < 12 {
		return fmt.Errorf("RAVENWIRE_ADMIN_PASSWORD must be at least 12 characters when --pilot-hardening is enabled")
	}
	return nil
}

func randomBase64(byteCount int) (string, error) {
	buf := make([]byte, byteCount)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func printManagerEnvironmentSummary(pilotHardening bool, result managerEnvironmentResult) {
	if !pilotHardening {
		fmt.Printf("Configured lab manager defaults in %s\n", managerEnvFile)
		return
	}

	fmt.Printf("Configured production-pilot manager secrets in %s\n", managerEnvFile)
	if result.generatedAdminPassword != "" {
		fmt.Printf("RAVENWIRE_BOOTSTRAP_ADMIN_USER=%s\n", result.env["RAVENWIRE_ADMIN_USER"])
		fmt.Printf("RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD=%s\n", result.generatedAdminPassword)
		fmt.Println("Store this generated admin password securely; it is printed by sensorctl only during this install.")
	}
}

func detectControlAPIHost(managerURL string) string {
	parsed, err := url.Parse(managerURL)
	if err != nil {
		return "127.0.0.1"
	}

	host := parsed.Hostname()
	if host == "" || host == "localhost" {
		return "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "127.0.0.1"
	}

	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		if hostname, hostErr := os.Hostname(); hostErr == nil && hostname != "" {
			return hostname
		}
		return "127.0.0.1"
	}
	defer conn.Close()

	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr.IP != nil {
		return localAddr.IP.String()
	}

	return "127.0.0.1"
}

func configureCaptureInterface(iface string) error {
	for _, command := range configureCaptureInterfaceCommands(iface) {
		if err := runShell("", command); err != nil {
			return err
		}
	}
	return nil
}

func configureCaptureInterfaceCommands(iface string) []string {
	quoted := shellQuote(iface)

	return []string{
		fmt.Sprintf("sudo ip link set dev %s up promisc on", quoted),
		fmt.Sprintf("sudo ip link set dev %s txqueuelen 4096 || true", quoted),
		fmt.Sprintf("if command -v ethtool >/dev/null 2>&1; then sudo ethtool -K %s gro off lro off || true; fi", quoted),
		fmt.Sprintf("if command -v ethtool >/dev/null 2>&1; then sudo ethtool -G %s rx 4096 tx 4096 || sudo ethtool -G %s rx 4096 || true; fi", quoted, quoted),
	}
}

func startApp() error {
	if err := stopSensorUnits(); err != nil {
		return err
	}
	if err := runShell("", "sudo systemctl reset-failed"); err != nil {
		return err
	}

	if err := runShell("", fmt.Sprintf("sudo systemctl start %s", shellQuote(managementTarget))); err != nil {
		return err
	}
	if err := waitForHTTP(defaultManagerHealth, 2*time.Minute); err != nil {
		return err
	}

	certReady, certReason := sensorCertificateReady("/etc/sensor/certs", time.Now())
	needsEnrollment := !certReady
	if needsEnrollment {
		if certReason != "" {
			fmt.Printf("Sensor enrollment required: %s\n", certReason)
		}
		if err := runShell("", "sudo rm -f /etc/sensor/certs/sensor.crt /etc/sensor/certs/sensor.key /etc/sensor/certs/ca-chain.pem"); err != nil {
			return err
		}
		token, err := generateEnrollmentToken()
		if err != nil {
			return err
		}
		if err := runShell("", fmt.Sprintf("sudo systemctl set-environment %s", shellQuote("SENSOR_ENROLLMENT_TOKEN="+token))); err != nil {
			return err
		}
	}

	if err := runShell("", "sudo systemctl start sensor-agent.service"); err != nil {
		return err
	}

	if needsEnrollment {
		if err := waitForSensorCertificate("/etc/sensor/certs", 2*time.Minute); err != nil {
			return err
		}
		if err := runShell("", "sudo systemctl unset-environment SENSOR_ENROLLMENT_TOKEN"); err != nil {
			return err
		}
	}

	if err := runShell("", fmt.Sprintf("sudo systemctl start %s", shellQuote(sensorTarget))); err != nil {
		return err
	}

	fmt.Println("RavenWire started. Use `sensorctl status` and `sensorctl logs` to inspect it.")
	return nil
}

func sensorCertificateReady(certDir string, now time.Time) (bool, string) {
	certPath := filepath.Join(certDir, "sensor.crt")
	keyPath := filepath.Join(certDir, "sensor.key")
	caPath := filepath.Join(certDir, "ca-chain.pem")

	for _, path := range []string{certPath, keyPath, caPath} {
		if !fileExists(path) {
			return false, fmt.Sprintf("certificate bundle is incomplete; missing %s", path)
		}
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read sensor certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, "sensor certificate is not valid PEM"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Sprintf("cannot parse sensor certificate: %v", err)
	}
	if now.Before(cert.NotBefore) {
		return false, fmt.Sprintf("sensor certificate is not valid before %s", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(cert.NotAfter) {
		return false, fmt.Sprintf("sensor certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return true, ""
}

func waitForSensorCertificate(certDir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastReason string
	for time.Now().Before(deadline) {
		if ok, reason := sensorCertificateReady(certDir, time.Now()); ok {
			return nil
		} else {
			lastReason = reason
		}
		time.Sleep(2 * time.Second)
	}
	if lastReason == "" {
		lastReason = "certificate was not written"
	}
	return fmt.Errorf("wait for valid sensor certificate: %s", lastReason)
}

func stopApp() error {
	if err := stopSensorUnits(); err != nil {
		return err
	}
	commands := []string{
		"sudo systemctl stop config-manager.service",
		fmt.Sprintf("sudo systemctl stop %s", shellQuote(managementTarget)),
	}
	for _, command := range commands {
		if err := runShell("", command); err != nil {
			return err
		}
	}
	return nil
}

func stopSensorUnits() error {
	commands := []string{
		"sudo systemctl stop vector.service zeek.service suricata.service pcap-ring-writer.service sensor-agent.service",
		fmt.Sprintf("sudo systemctl stop %s", shellQuote(analysisTarget)),
		fmt.Sprintf("sudo systemctl stop %s", shellQuote(captureTarget)),
		fmt.Sprintf("sudo systemctl stop %s", shellQuote(sensorTarget)),
	}
	for _, command := range commands {
		if err := runShell("", command); err != nil {
			return err
		}
	}
	return nil
}

func cleanupApp(opts cleanupOptions) error {
	for _, command := range cleanupCommands(opts) {
		if err := runShell("", command); err != nil {
			return err
		}
	}

	fmt.Println("RavenWire cleanup complete.")
	return nil
}

func cleanupCommands(opts cleanupOptions) []string {
	commands := []string{
		"sudo journalctl --rotate",
		"sudo journalctl --vacuum-size=256M --vacuum-time=3d",
		"if systemctl list-unit-files ravenwire-log-prune.service >/dev/null 2>&1; then sudo systemctl start ravenwire-log-prune.service; fi",
		"if [ -f /etc/logrotate.d/ravenwire ]; then sudo logrotate -f /etc/logrotate.d/ravenwire; fi",
		"sudo find /tmp /var/sensor/support-bundles -xdev -type f -name 'sensor-support-*.tar.gz' -mtime +2 -delete 2>/dev/null || true",
	}
	if opts.podman {
		commands = append(commands, "if command -v podman >/dev/null 2>&1; then podman system prune -af || true; sudo podman system prune -af; fi")
	}
	if opts.docker {
		commands = append(commands, "if command -v docker >/dev/null 2>&1; then sudo docker system prune -af; fi")
	}
	return commands
}

func uninstallApp(purge, images bool) error {
	if err := stopApp(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: stop failed during uninstall: %v\n", err)
	}

	for _, command := range uninstallCommands(purge, images) {
		if err := runShell("", command); err != nil {
			return err
		}
	}

	fmt.Println("RavenWire uninstalled.")
	return nil
}

func uninstallCommands(purge, images bool) []string {
	quadletDst := "/etc/containers/systemd"
	systemdDst := "/etc/systemd/system"

	files := []string{
		"config-manager.container",
		"pcap-ring-writer.container",
		"sensor-agent.container",
		"suricata.container",
		"vector.container",
		"zeek.container",
	}
	targets := []string{
		"analysis-pipeline.target",
		"capture-pipeline.target",
		managementTarget,
		sensorTarget,
	}

	var commands []string
	commands = append(commands,
		fmt.Sprintf("systemctl --user stop %s || true", shellQuote(managementTarget)),
		fmt.Sprintf("systemctl --user stop %s || true", shellQuote(analysisTarget)),
		fmt.Sprintf("systemctl --user stop %s || true", shellQuote(captureTarget)),
		fmt.Sprintf("systemctl --user stop %s || true", shellQuote(sensorTarget)),
	)

	for _, file := range files {
		commands = append(commands, fmt.Sprintf("sudo rm -f %s", shellQuote(filepath.Join(quadletDst, file))))
		commands = append(commands, fmt.Sprintf("rm -f \"$HOME/.config/containers/systemd/%s\"", file))
	}
	for _, file := range targets {
		commands = append(commands, fmt.Sprintf("sudo rm -f %s", shellQuote(filepath.Join(quadletDst, file))))
		commands = append(commands, fmt.Sprintf("sudo rm -f %s", shellQuote(filepath.Join(systemdDst, file))))
		commands = append(commands, fmt.Sprintf("rm -f \"$HOME/.config/containers/systemd/%s\"", file))
		commands = append(commands, fmt.Sprintf("rm -f \"$HOME/.config/systemd/user/%s\"", file))
	}
	commands = append(commands,
		"sudo systemctl stop ravenwire-log-prune.timer ravenwire-log-prune.service || true",
		"sudo systemctl disable ravenwire-log-prune.timer || true",
		"sudo rm -f /etc/systemd/journald.conf.d/ravenwire.conf",
		"sudo rm -f /etc/logrotate.d/ravenwire",
		"sudo rm -f /usr/local/libexec/ravenwire-prune-logs",
		"sudo rm -f /etc/systemd/system/ravenwire-log-prune.service /etc/systemd/system/ravenwire-log-prune.timer",
		"sudo systemctl restart systemd-journald.service",
		"sudo systemctl daemon-reload",
		"sudo systemctl reset-failed",
		"systemctl --user daemon-reload || true",
		"systemctl --user reset-failed || true",
		"sudo systemctl unset-environment CAPTURE_IFACE SENSOR_POD_NAME SENSOR_ENROLLMENT_TOKEN CONFIG_MANAGER_URL CONTROL_API_HOST GRPC_ADDR SENSOR_SVC_UID MIN_DISK_WRITE_MBPS MIN_STORAGE_GB SPLUNK_HEC_URL SPLUNK_HEC_TOKEN CRIBL_URL CRIBL_TOKEN",
	)

	if purge {
		commands = append(commands, "sudo rm -rf /data/config_manager /data/ca /data/metrics /etc/sensor /etc/ravenwire /var/sensor /var/run/sensor /sensor/pcap")
	}
	if images {
		commands = append(commands,
			"podman rmi -f localhost/ravenwire/config-manager:test localhost/ravenwire/sensor-agent:test localhost/ravenwire/pcap-ring-writer:test || true",
			"sudo podman rmi -f localhost/ravenwire/config-manager:test localhost/ravenwire/sensor-agent:test localhost/ravenwire/pcap-ring-writer:test",
		)
	}

	return commands
}

func generateEnrollmentToken() (string, error) {
	expr := `Application.ensure_all_started(:ecto_sql); {:ok, _} = ConfigManager.Repo.start_link(); {:ok, token} = ConfigManager.Enrollment.generate_token("sensorctl install"); IO.puts("SENSORCTL_TOKEN=" <> token)`
	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error

	for {
		c := exec.Command("sudo", "podman", "exec", "systemd-config-manager", "mix", "run", "--no-start", "-e", expr)
		out, err := c.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("generate enrollment token: %w\n%s", err, string(out))
		} else {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if token, ok := strings.CutPrefix(line, "SENSORCTL_TOKEN="); ok && token != "" {
					return token, nil
				}
			}
			lastErr = fmt.Errorf("generate enrollment token: token not found in output")
		}

		if time.Now().After(deadline) {
			return "", lastErr
		}
		time.Sleep(3 * time.Second)
	}
}

func waitForHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %s", url)
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fileExists(path) {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

func detectCaptureInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		return iface.Name, nil
	}
	return "", fmt.Errorf("capture interface not detected; pass --capture-iface")
}

func isAppUnit(args []string) bool {
	if len(args) == 0 {
		return true
	}
	switch args[0] {
	case appUnit, "all", "ravenwire":
		return true
	default:
		return false
	}
}

func defaultUnit(args []string, fallback string) string {
	if len(args) == 0 {
		return normalizeSystemdUnit(fallback)
	}
	return normalizeSystemdUnit(args[0])
}

func normalizeSystemdUnit(name string) string {
	if name == appUnit || name == "all" || name == "ravenwire" {
		return sensorTarget
	}
	if strings.HasSuffix(name, ".target") || strings.HasSuffix(name, ".service") {
		return name
	}
	return name + ".target"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
