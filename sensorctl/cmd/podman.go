package cmd

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
)

type installOptions struct {
	captureIface string
	podName      string
	managerURL   string
	skipBuild    bool
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
	commands := []string{
		"sudo systemctl enable --now podman.socket",
		"sudo mkdir -p /data/config_manager /data/ca /data/metrics /etc/sensor/certs /etc/sensor/zeek /etc/sensor/suricata/rules /etc/sensor/vector /var/sensor/logs/zeek /var/sensor/logs/suricata /var/sensor/logs/vector /var/sensor/vector-buffer /var/run/sensor /sensor/pcap/alerts",
		"sudo chown -R 0:0 /data/config_manager /data/ca /data/metrics /etc/sensor /var/sensor /var/run/sensor /sensor/pcap",
		"sudo install -D -m 0644 config/sensor/bpf_filters.conf /etc/sensor/bpf_filters.conf",
		"sudo install -D -m 0644 config/sensor/capture.conf /etc/sensor/capture.conf",
		"sudo install -D -m 0644 config/sensor/vector.toml /etc/sensor/vector/vector.toml",
		"sudo install -D -m 0644 config/sensor/suricata.yaml /etc/sensor/suricata/suricata.yaml",
		"sudo install -D -m 0644 config/sensor/suricata/classification.config /etc/sensor/suricata/classification.config",
		"sudo install -D -m 0644 config/sensor/suricata/reference.config /etc/sensor/suricata/reference.config",
		"sudo install -D -m 0644 config/sensor/suricata/threshold.config /etc/sensor/suricata/threshold.config",
		"sudo install -D -m 0644 config/sensor/zeek/local.zeek /etc/sensor/zeek/local.zeek",
		"sudo touch /etc/sensor/suricata/rules/suricata.rules",
	}
	for _, command := range commands {
		if err := runShell(root, command); err != nil {
			return err
		}
	}
	return nil
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

	env := map[string]string{
		"CAPTURE_IFACE":       iface,
		"SENSOR_POD_NAME":     podName,
		"CONFIG_MANAGER_URL":  strings.TrimRight(managerURL, "/"),
		"GRPC_ADDR":           "127.0.0.1:9090",
		"SENSOR_SVC_UID":      "0",
		"MIN_DISK_WRITE_MBPS": envOr("MIN_DISK_WRITE_MBPS", "50"),
		"MIN_STORAGE_GB":      envOr("MIN_STORAGE_GB", "10"),
		"SPLUNK_HEC_URL":      "",
		"SPLUNK_HEC_TOKEN":    "",
		"CRIBL_URL":           "",
		"CRIBL_TOKEN":         "",
	}

	assignments := make([]string, 0, len(env))
	for key, value := range env {
		assignments = append(assignments, shellQuote(key+"="+value))
	}

	if err := runShell("", "sudo systemctl set-environment "+strings.Join(assignments, " ")); err != nil {
		return err
	}
	if err := configureCaptureInterface(iface); err != nil {
		return err
	}

	fmt.Printf("Configured sensor pod %q on interface %q using manager %s\n", podName, iface, managerURL)
	return nil
}

func configureCaptureInterface(iface string) error {
	commands := []string{
		fmt.Sprintf("sudo ip link set dev %s up promisc on", shellQuote(iface)),
		fmt.Sprintf("if command -v ethtool >/dev/null 2>&1; then sudo ethtool -K %s gro off lro off || true; fi", shellQuote(iface)),
	}
	for _, command := range commands {
		if err := runShell("", command); err != nil {
			return err
		}
	}
	return nil
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

	needsEnrollment := !fileExists("/etc/sensor/certs/sensor.crt")
	if needsEnrollment {
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
		if err := waitForFile("/etc/sensor/certs/sensor.crt", 2*time.Minute); err != nil {
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

func uninstallApp(purge, images bool) error {
	if err := stopApp(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: stop failed during uninstall: %v\n", err)
	}

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
	for _, file := range files {
		commands = append(commands, fmt.Sprintf("sudo rm -f %s", shellQuote(filepath.Join(quadletDst, file))))
	}
	for _, file := range targets {
		commands = append(commands, fmt.Sprintf("sudo rm -f %s", shellQuote(filepath.Join(systemdDst, file))))
	}
	commands = append(commands,
		"sudo systemctl daemon-reload",
		"sudo systemctl reset-failed",
		"sudo systemctl unset-environment CAPTURE_IFACE SENSOR_POD_NAME SENSOR_ENROLLMENT_TOKEN CONFIG_MANAGER_URL GRPC_ADDR SENSOR_SVC_UID MIN_DISK_WRITE_MBPS MIN_STORAGE_GB SPLUNK_HEC_URL SPLUNK_HEC_TOKEN CRIBL_URL CRIBL_TOKEN",
	)

	if purge {
		commands = append(commands, "sudo rm -rf /data/config_manager /data/ca /data/metrics /etc/sensor /var/sensor /var/run/sensor /sensor/pcap")
	}
	if images {
		commands = append(commands, "sudo podman rmi -f localhost/ravenwire/config-manager:test localhost/ravenwire/sensor-agent:test localhost/ravenwire/pcap-ring-writer:test")
	}

	for _, command := range commands {
		if err := runShell("", command); err != nil {
			return err
		}
	}

	fmt.Println("RavenWire uninstalled.")
	return nil
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
