package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// bootstrapState mirrors the bootstrap state machine states from
// sensor-agent/internal/bootstrap. Kept as strings to avoid a cross-module
// dependency — sensorctl is a standalone CLI tool.
const (
	bsInstalled       = "installed"
	bsEnrolling       = "enrolling"
	bsPendingApproval = "pending_approval"
	bsConfigReceived  = "config_received"
	bsConfigValidated = "config_validated"
	bsCaptureActive   = "capture_active"
)

// bootstrapStateOrder defines the expected forward progression for display.
var bootstrapStateOrder = []string{
	bsInstalled,
	bsEnrolling,
	bsPendingApproval,
	bsConfigReceived,
	bsConfigValidated,
	bsCaptureActive,
}

// bootstrapStatus is the response from the sensor agent's bootstrap status endpoint.
type bootstrapStatus struct {
	State         string   `json:"state"`
	BlockingErrors []string `json:"blocking_errors,omitempty"`
	PodName       string   `json:"pod_name,omitempty"`
	Uptime        string   `json:"uptime,omitempty"`
}

func enrollCmd() *cobra.Command {
	var manager, token, podName, certDir, sensorURL string
	var statusOnly bool

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this sensor with a Config Manager",
		Long: `Automates the sensor enrollment token configuration step.

When run with --manager and --token, generates a local ECDSA keypair,
submits the enrollment request to the Config Manager, and writes the
issued certificate bundle when approved.

After enrollment (or with --status), displays the current bootstrap
state machine state and any blocking errors so operators can diagnose
enrollment failures without reading log files.

Requirement: 11.7`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if statusOnly {
				return runEnrollStatus(sensorURL)
			}
			if manager == "" {
				return fmt.Errorf("--manager is required (or use --status to check current state)")
			}
			if token == "" {
				return fmt.Errorf("--token is required")
			}
			if podName == "" {
				host, err := os.Hostname()
				if err != nil {
					return err
				}
				podName = host
			}
			return runEnroll(manager, token, podName, certDir, sensorURL)
		},
	}

	cmd.Flags().StringVar(&manager, "manager", "", "Config Manager URL, for example https://manager:8443 or http://127.0.0.1:4000/api/v1")
	cmd.Flags().StringVar(&token, "token", "", "One-time enrollment token")
	cmd.Flags().StringVar(&podName, "pod-name", "", "Sensor pod name (defaults to hostname)")
	cmd.Flags().StringVar(&certDir, "cert-dir", envOr("CERT_DIR", "/etc/sensor/certs"), "Directory for sensor.key, sensor.crt, and ca-chain.pem")
	cmd.Flags().StringVar(&sensorURL, "sensor", envOr("SENSORCTL_SENSOR_URL", ""), "Sensor agent URL for bootstrap state query (e.g. https://sensor-host:9091)")
	cmd.Flags().BoolVar(&statusOnly, "status", false, "Only display the current bootstrap state and blocking errors (no enrollment)")

	return cmd
}

// runEnrollStatus queries and displays the bootstrap state without performing enrollment.
func runEnrollStatus(sensorURL string) error {
	if sensorURL == "" {
		// Try to infer from config or environment
		cfg := loadAgentConfig()
		if cfg.SensorURL != "" {
			sensorURL = cfg.SensorURL
		}
	}

	if sensorURL != "" {
		status, err := fetchBootstrapStatus(sensorURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not query sensor agent: %v\n", err)
			fmt.Println("\nBootstrap state: unknown (sensor agent unreachable)")
			fmt.Println("Possible causes:")
			fmt.Println("  - Sensor agent is not running")
			fmt.Println("  - Incorrect --sensor URL")
			fmt.Println("  - mTLS certificates not configured for sensorctl")
			return nil
		}
		printBootstrapStatus(status)
		return nil
	}

	// No sensor URL — check local cert state to infer bootstrap progress
	return showLocalEnrollmentState()
}

// runEnroll performs the enrollment and then displays the bootstrap state.
func runEnroll(manager, token, podName, certDir, sensorURL string) error {
	fmt.Printf("Enrolling sensor %q with Config Manager at %s\n\n", podName, manager)

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})

	requestBody, err := json.Marshal(map[string]string{
		"token":      token,
		"pod_name":   podName,
		"public_key": string(pubKeyPEM),
	})
	if err != nil {
		return err
	}

	enrollURL := strings.TrimRight(managerAPIBase(manager), "/") + "/enroll"
	fmt.Printf("  POST %s\n", enrollURL)

	resp, err := http.Post(enrollURL, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		printEnrollmentError("enrollment request failed", err)
		return showBootstrapStateAfterError(sensorURL)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusAccepted:
		fmt.Printf("\n  ✓ Enrollment submitted for %s; awaiting operator approval.\n", podName)
		fmt.Println("    The Config Manager will issue certificates once an operator approves this sensor.")
		fmt.Printf("\n  Bootstrap state: %s\n", bsPendingApproval)
		printBootstrapProgress(bsPendingApproval)

	case http.StatusOK:
		if err := writeEnrollmentBundle(resp, privKey, certDir); err != nil {
			printEnrollmentError("failed to write certificate bundle", err)
			return showBootstrapStateAfterError(sensorURL)
		}
		fmt.Printf("\n  ✓ Enrollment approved. Certificate bundle written to %s\n", certDir)
		fmt.Printf("\n  Bootstrap state: %s\n", bsConfigReceived)
		printBootstrapProgress(bsConfigReceived)

	default:
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		errMsg := strings.TrimSpace(body.String())
		fmt.Printf("\n  ✗ Enrollment failed (HTTP %d)\n", resp.StatusCode)
		if errMsg != "" {
			fmt.Printf("    Error: %s\n", errMsg)
		}
		fmt.Printf("\n  Bootstrap state: %s\n", bsEnrolling)
		printBootstrapProgress(bsEnrolling)
		fmt.Println("\n  Blocking errors:")
		fmt.Printf("    - Enrollment request returned HTTP %d: %s\n", resp.StatusCode, errMsg)
		fmt.Println("\n  Troubleshooting:")
		fmt.Println("    - Verify the enrollment token is correct and has not expired")
		fmt.Println("    - Verify the Config Manager URL is reachable")
		fmt.Println("    - Check Config Manager logs for details")
		return fmt.Errorf("enrollment failed with HTTP %d: %s", resp.StatusCode, errMsg)
	}

	// If we have a sensor URL, also query the live bootstrap state
	if sensorURL != "" {
		fmt.Println()
		status, err := fetchBootstrapStatus(sensorURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Note: could not query sensor agent for live state: %v\n", err)
		} else {
			fmt.Println("  Live agent bootstrap state:")
			printBootstrapStatus(status)
		}
	}

	return nil
}

func managerAPIBase(manager string) string {
	manager = strings.TrimRight(manager, "/")
	if strings.HasSuffix(manager, "/api/v1") {
		return manager
	}
	return manager + "/api/v1"
}

func writeEnrollmentBundle(resp *http.Response, privKey *ecdsa.PrivateKey, certDir string) error {
	var certResp struct {
		CertPEM    string `json:"cert_pem"`
		CAChainPEM string `json:"ca_chain_pem"`
		PodID      string `json:"sensor_pod_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("decode enrollment response: %w", err)
	}

	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyDER})

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"sensor.key", privKeyPEM, 0600},
		{"sensor.crt", []byte(certResp.CertPEM), 0644},
		{"ca-chain.pem", []byte(certResp.CAChainPEM), 0644},
	}

	for _, file := range files {
		if err := os.WriteFile(filepath.Join(certDir, file.name), file.data, file.mode); err != nil {
			return fmt.Errorf("write %s: %w", file.name, err)
		}
	}

	fmt.Printf("  Certificates written:\n")
	for _, file := range files {
		fmt.Printf("    %s (%04o)\n", filepath.Join(certDir, file.name), file.mode)
	}

	return nil
}

// fetchBootstrapStatus queries the sensor agent for the current bootstrap state.
func fetchBootstrapStatus(sensorURL string) (*bootstrapStatus, error) {
	cfg := loadAgentConfig()
	cfg.SensorURL = sensorURL

	client, err := buildAgentHTTPClient(cfg, true)
	if err != nil {
		// Fall back to insecure client if mTLS certs aren't available
		client = &http.Client{Timeout: 10 * time.Second}
	}

	url := strings.TrimRight(sensorURL, "/") + "/bootstrap/status"
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET %s returned HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var status bootstrapStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode bootstrap status: %w", err)
	}
	return &status, nil
}

// printBootstrapStatus displays the bootstrap state and any blocking errors.
func printBootstrapStatus(status *bootstrapStatus) {
	fmt.Printf("  State:    %s\n", formatStateName(status.State))
	if status.PodName != "" {
		fmt.Printf("  Pod:      %s\n", status.PodName)
	}
	if status.Uptime != "" {
		fmt.Printf("  Uptime:   %s\n", status.Uptime)
	}

	printBootstrapProgress(status.State)

	if len(status.BlockingErrors) > 0 {
		fmt.Println("\n  Blocking errors:")
		for _, e := range status.BlockingErrors {
			fmt.Printf("    ✗ %s\n", e)
		}
		fmt.Println("\n  Troubleshooting:")
		printTroubleshootingHints(status.State, status.BlockingErrors)
	} else if status.State == bsCaptureActive {
		fmt.Println("\n  No blocking errors. Sensor is fully operational.")
	}
}

// printBootstrapProgress displays a visual progress indicator for the bootstrap state.
func printBootstrapProgress(currentState string) {
	fmt.Println("\n  Bootstrap progress:")
	currentIdx := -1
	for i, s := range bootstrapStateOrder {
		if s == currentState {
			currentIdx = i
			break
		}
	}

	for i, s := range bootstrapStateOrder {
		marker := "  "
		if i < currentIdx {
			marker = "✓ "
		} else if i == currentIdx {
			marker = "→ "
		} else {
			marker = "  "
		}
		fmt.Printf("    %s%s\n", marker, formatStateName(s))
	}
}

// formatStateName returns a human-readable name for a bootstrap state.
func formatStateName(state string) string {
	switch state {
	case bsInstalled:
		return "installed"
	case bsEnrolling:
		return "enrolling"
	case bsPendingApproval:
		return "pending_approval (awaiting operator approval)"
	case bsConfigReceived:
		return "config_received (validating configuration)"
	case bsConfigValidated:
		return "config_validated (running readiness checks)"
	case bsCaptureActive:
		return "capture_active (operational)"
	default:
		return state
	}
}

// printTroubleshootingHints provides context-specific troubleshooting guidance.
func printTroubleshootingHints(state string, errors []string) {
	switch state {
	case bsEnrolling:
		fmt.Println("    - Verify the enrollment token is correct and has not expired")
		fmt.Println("    - Verify the Config Manager URL is reachable from this sensor")
		fmt.Println("    - Check Config Manager logs: sensorctl logs management-pod")
	case bsPendingApproval:
		fmt.Println("    - An operator must approve this sensor in the Config Manager UI")
		fmt.Println("    - Check Config Manager for pending enrollment requests")
	case bsConfigReceived:
		fmt.Println("    - The received configuration bundle failed validation")
		fmt.Println("    - Review the errors above and correct the sensor pool configuration")
		fmt.Println("    - Push a corrected config bundle from the Config Manager")
	case bsConfigValidated:
		fmt.Println("    - Host readiness checks failed; review the errors above")
		fmt.Println("    - Common fixes: disable GRO/LRO, enable promiscuous mode, sync NTP")
		fmt.Println("    - Run: sensorctl test  (for detailed readiness check output)")
	default:
		fmt.Println("    - Check sensor agent logs: sensorctl logs sensor-agent")
	}
}

// showLocalEnrollmentState checks local filesystem state to infer bootstrap progress.
func showLocalEnrollmentState() error {
	certDir := envOr("CERT_DIR", "/etc/sensor/certs")

	fmt.Println("Bootstrap state (inferred from local filesystem):")

	certExists := fileExistsLocal(filepath.Join(certDir, "sensor.crt"))
	keyExists := fileExistsLocal(filepath.Join(certDir, "sensor.key"))
	caExists := fileExistsLocal(filepath.Join(certDir, "ca-chain.pem"))

	if certExists && keyExists && caExists {
		fmt.Printf("  Certificates found in %s\n", certDir)
		fmt.Println("  State: config_received or later (certificates are present)")
		printBootstrapProgress(bsConfigReceived)
		fmt.Println("\n  Use --sensor <url> to query the sensor agent for the exact state.")
	} else if certExists || keyExists || caExists {
		fmt.Printf("  Partial certificates in %s:\n", certDir)
		fmt.Printf("    sensor.crt:  %s\n", existsLabel(certExists))
		fmt.Printf("    sensor.key:  %s\n", existsLabel(keyExists))
		fmt.Printf("    ca-chain.pem: %s\n", existsLabel(caExists))
		fmt.Println("\n  State: enrolling (incomplete certificate set)")
		printBootstrapProgress(bsEnrolling)
		fmt.Println("\n  Blocking errors:")
		fmt.Println("    ✗ Incomplete certificate bundle — enrollment may have been interrupted")
		fmt.Println("\n  Re-run enrollment: sensorctl enroll --manager <url> --token <token>")
	} else {
		fmt.Printf("  No certificates found in %s\n", certDir)
		fmt.Println("  State: installed (enrollment has not been performed)")
		printBootstrapProgress(bsInstalled)
		fmt.Println("\n  To enroll: sensorctl enroll --manager <url> --token <token>")
	}

	return nil
}

// showBootstrapStateAfterError displays bootstrap state context after an enrollment error.
func showBootstrapStateAfterError(sensorURL string) error {
	if sensorURL != "" {
		status, err := fetchBootstrapStatus(sensorURL)
		if err == nil {
			fmt.Println("\n  Current agent bootstrap state:")
			printBootstrapStatus(status)
		}
	}
	return nil
}

// printEnrollmentError formats an enrollment error with context.
func printEnrollmentError(context string, err error) {
	fmt.Printf("\n  ✗ %s: %v\n", context, err)
}

func fileExistsLocal(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func existsLabel(exists bool) string {
	if exists {
		return "present"
	}
	return "missing"
}
