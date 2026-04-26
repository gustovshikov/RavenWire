// sensorctl — internal dev CLI for the Sensor_Agent mTLS control API.
//
// Usage:
//
//	sensorctl enroll --manager <url> --token <token> --name <name>
//	sensorctl status [--sensor <url>]
//	sensorctl show-drops [--sensor <url>]
//	sensorctl collect-support-bundle --sensor <url> --output <path>
//
// mTLS credentials are loaded from environment variables or a config file:
//
//	SENSORCTL_CERT        — path to client cert PEM
//	SENSORCTL_KEY         — path to client key PEM
//	SENSORCTL_CA          — path to CA cert PEM
//	SENSORCTL_SENSOR_URL  — default sensor URL (e.g. https://sensor-host:9091)
//
// Config file locations (first found wins):
//
//	~/.sensorctl/config.yaml
//	./sensorctl.yaml
//
// This is an internal development tool, not a stable public API.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config holds resolved mTLS credentials and default sensor URL.
type config struct {
	CertFile  string
	KeyFile   string
	CAFile    string
	SensorURL string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "enroll":
		runEnroll(args)
	case "status":
		runStatus(args)
	case "show-drops":
		runShowDrops(args)
	case "collect-support-bundle":
		runCollectSupportBundle(args)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "sensorctl: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `sensorctl — internal dev CLI for Sensor_Agent

Commands:
  enroll --manager <url> --token <token> --name <name>
      Trigger Sensor_Agent enrollment by POSTing to the Config_Manager
      enrollment endpoint.

  status [--sensor <url>]
      Print current health snapshot from the Sensor_Agent control API.

  show-drops [--sensor <url>]
      Print per-consumer packet/drop counters from the health snapshot.

  collect-support-bundle --sensor <url> --output <path>
      Trigger support bundle generation and download the archive.

mTLS credentials (env vars or config file):
  SENSORCTL_CERT        path to client cert PEM
  SENSORCTL_KEY         path to client key PEM
  SENSORCTL_CA          path to CA cert PEM
  SENSORCTL_SENSOR_URL  default sensor URL (https://sensor-host:9091)

Config file: ~/.sensorctl/config.yaml or ./sensorctl.yaml`)
}

// ── enroll ────────────────────────────────────────────────────────────────────

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	managerURL := fs.String("manager", "", "Config_Manager URL (e.g. https://manager:8443)")
	token := fs.String("token", "", "One-time enrollment token")
	name := fs.String("name", "", "Sensor pod name")
	fs.Parse(args)

	if *managerURL == "" || *token == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "sensorctl enroll: --manager, --token, and --name are required")
		fs.Usage()
		os.Exit(1)
	}

	// The enroll command talks to Config_Manager (not Sensor_Agent).
	// It does not require mTLS client certs — the token is the auth mechanism.
	// We still load CA if available to verify the server cert.
	cfg := loadConfig()

	client := buildHTTPClient(cfg, false /* no client cert for enroll */)

	payload := fmt.Sprintf(`{"token":%q,"pod_name":%q}`, *token, *name)
	url := strings.TrimRight(*managerURL, "/") + "/enroll"

	fmt.Printf("Enrolling %q with Config_Manager at %s ...\n", *name, url)

	resp, err := client.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		fatalf("enroll: POST failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("Enrollment approved. Certificate issued.")
		printJSON(body)
	case http.StatusAccepted:
		fmt.Println("Enrollment request submitted — awaiting operator approval (202 Accepted).")
		printJSON(body)
	default:
		fmt.Fprintf(os.Stderr, "Enrollment failed (HTTP %d):\n", resp.StatusCode)
		fmt.Fprintln(os.Stderr, string(body))
		os.Exit(1)
	}
}

// ── status ────────────────────────────────────────────────────────────────────

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	sensorURL := fs.String("sensor", "", "Sensor_Agent URL (overrides SENSORCTL_SENSOR_URL)")
	fs.Parse(args)

	cfg := loadConfig()
	if *sensorURL != "" {
		cfg.SensorURL = *sensorURL
	}
	requireSensorURL(cfg)

	client := buildHTTPClient(cfg, true)
	url := strings.TrimRight(cfg.SensorURL, "/") + "/health"

	resp, err := client.Get(url)
	if err != nil {
		fatalf("status: GET /health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fatalf("status: unexpected HTTP %d: %s", resp.StatusCode, body)
	}

	var report healthReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		fatalf("status: failed to decode response: %v", err)
	}

	printHealthReport(report)
}

// ── show-drops ────────────────────────────────────────────────────────────────

func runShowDrops(args []string) {
	fs := flag.NewFlagSet("show-drops", flag.ExitOnError)
	sensorURL := fs.String("sensor", "", "Sensor_Agent URL (overrides SENSORCTL_SENSOR_URL)")
	fs.Parse(args)

	cfg := loadConfig()
	if *sensorURL != "" {
		cfg.SensorURL = *sensorURL
	}
	requireSensorURL(cfg)

	client := buildHTTPClient(cfg, true)
	url := strings.TrimRight(cfg.SensorURL, "/") + "/health"

	resp, err := client.Get(url)
	if err != nil {
		fatalf("show-drops: GET /health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fatalf("show-drops: unexpected HTTP %d: %s", resp.StatusCode, body)
	}

	var report healthReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		fatalf("show-drops: failed to decode response: %v", err)
	}

	printDropCounters(report)
}

// ── collect-support-bundle ────────────────────────────────────────────────────

func runCollectSupportBundle(args []string) {
	fs := flag.NewFlagSet("collect-support-bundle", flag.ExitOnError)
	sensorURL := fs.String("sensor", "", "Sensor_Agent URL (required)")
	outputPath := fs.String("output", "", "Local path to write the support bundle archive")
	fs.Parse(args)

	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "sensorctl collect-support-bundle: --output is required")
		fs.Usage()
		os.Exit(1)
	}

	cfg := loadConfig()
	if *sensorURL != "" {
		cfg.SensorURL = *sensorURL
	}
	requireSensorURL(cfg)

	client := buildHTTPClient(cfg, true)
	triggerURL := strings.TrimRight(cfg.SensorURL, "/") + "/control/support-bundle"

	fmt.Printf("Triggering support bundle generation on %s ...\n", cfg.SensorURL)

	// Step 1: trigger bundle generation
	resp, err := client.Post(triggerURL, "application/json", strings.NewReader("{}"))
	if err != nil {
		fatalf("collect-support-bundle: POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fatalf("collect-support-bundle: trigger failed (HTTP %d): %s", resp.StatusCode, body)
	}

	var triggerResp struct {
		Status string `json:"status"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&triggerResp); err != nil {
		fatalf("collect-support-bundle: failed to decode trigger response: %v", err)
	}

	if triggerResp.Path == "" {
		fatalf("collect-support-bundle: sensor returned empty bundle path")
	}

	fmt.Printf("Bundle generated at sensor path: %s\n", triggerResp.Path)

	// Step 2: download the archive via the same mTLS connection.
	// Convention: GET /control/support-bundle/download?path=<path> returns the archive.
	downloadURL := strings.TrimRight(cfg.SensorURL, "/") +
		"/control/support-bundle/download?path=" + triggerResp.Path

	fmt.Printf("Downloading bundle to %s ...\n", *outputPath)

	dlResp, err := client.Get(downloadURL)
	if err != nil {
		// Download endpoint may not be implemented; print the remote path and exit gracefully.
		fmt.Fprintf(os.Stderr, "Warning: download failed (%v)\n", err)
		fmt.Printf("Bundle is available on the sensor at: %s\n", triggerResp.Path)
		return
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(dlResp.Body)
		// Non-fatal: bundle was generated, just not downloadable via this path.
		fmt.Fprintf(os.Stderr, "Warning: download returned HTTP %d: %s\n", dlResp.StatusCode, body)
		fmt.Printf("Bundle is available on the sensor at: %s\n", triggerResp.Path)
		return
	}

	// Write to output file
	if err := os.MkdirAll(filepath.Dir(*outputPath), 0755); err != nil {
		fatalf("collect-support-bundle: create output dir: %v", err)
	}

	f, err := os.Create(*outputPath)
	if err != nil {
		fatalf("collect-support-bundle: create output file: %v", err)
	}
	defer f.Close()

	n, err := io.Copy(f, dlResp.Body)
	if err != nil {
		fatalf("collect-support-bundle: write output file: %v", err)
	}

	fmt.Printf("Support bundle saved to %s (%d bytes)\n", *outputPath, n)
}

// ── Config loading ────────────────────────────────────────────────────────────

// loadConfig resolves mTLS credentials from env vars, then config file.
func loadConfig() config {
	cfg := config{
		CertFile:  os.Getenv("SENSORCTL_CERT"),
		KeyFile:   os.Getenv("SENSORCTL_KEY"),
		CAFile:    os.Getenv("SENSORCTL_CA"),
		SensorURL: os.Getenv("SENSORCTL_SENSOR_URL"),
	}

	// If any field is missing, try config file
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" || cfg.SensorURL == "" {
		fileCfg := loadConfigFile()
		if cfg.CertFile == "" {
			cfg.CertFile = fileCfg["cert"]
		}
		if cfg.KeyFile == "" {
			cfg.KeyFile = fileCfg["key"]
		}
		if cfg.CAFile == "" {
			cfg.CAFile = fileCfg["ca"]
		}
		if cfg.SensorURL == "" {
			cfg.SensorURL = fileCfg["sensor_url"]
		}
	}

	return cfg
}

// loadConfigFile reads a minimal YAML config file (key: value lines only).
// Supports ~/.sensorctl/config.yaml and ./sensorctl.yaml.
func loadConfigFile() map[string]string {
	candidates := []string{"./sensorctl.yaml"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append([]string{filepath.Join(home, ".sensorctl", "config.yaml")}, candidates...)
	}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()

		result := make(map[string]string)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				result[key] = val
			}
		}
		return result
	}

	return nil
}

// ── HTTP client ───────────────────────────────────────────────────────────────

// buildHTTPClient builds an HTTP client with optional mTLS.
// If withClientCert is false, only the CA (server verification) is configured.
func buildHTTPClient(cfg config, withClientCert bool) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load CA for server cert verification
	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			fatalf("failed to read CA cert %s: %v", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			fatalf("failed to parse CA cert from %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	} else {
		// No CA configured — skip server cert verification (dev convenience)
		tlsCfg.InsecureSkipVerify = true
	}

	// Load client cert for mTLS
	if withClientCert && cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			fatalf("failed to load client cert/key (%s, %s): %v", cfg.CertFile, cfg.KeyFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		Timeout: 30 * time.Second,
	}
}

// ── Health report types (mirrors internal/health/collector.go) ────────────────

type healthReport struct {
	SensorPodID     string            `json:"sensor_pod_id"`
	TimestampUnixMs int64             `json:"timestamp_unix_ms"`
	Containers      []containerHealth `json:"containers"`
	Capture         captureStats      `json:"capture"`
	Storage         storageStats      `json:"storage"`
	Clock           clockStats        `json:"clock"`
}

type containerHealth struct {
	Name          string  `json:"name"`
	State         string  `json:"state"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryBytes   uint64  `json:"memory_bytes"`
}

type captureStats struct {
	Consumers map[string]consumerStats `json:"consumers"`
}

type consumerStats struct {
	PacketsReceived uint64  `json:"packets_received"`
	PacketsDropped  uint64  `json:"packets_dropped"`
	DropPercent     float64 `json:"drop_percent"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

type storageStats struct {
	Path           string  `json:"path"`
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type clockStats struct {
	OffsetMs     int64  `json:"offset_ms"`
	Synchronized bool   `json:"synchronized"`
	Source       string `json:"source"`
}

// ── Output formatting ─────────────────────────────────────────────────────────

func printHealthReport(r healthReport) {
	ts := time.UnixMilli(r.TimestampUnixMs).UTC().Format(time.RFC3339)
	fmt.Printf("Sensor Pod:  %s\n", r.SensorPodID)
	fmt.Printf("Timestamp:   %s\n\n", ts)

	fmt.Println("Containers:")
	if len(r.Containers) == 0 {
		fmt.Println("  (none)")
	}
	for _, c := range r.Containers {
		fmt.Printf("  %-20s  state=%-12s  uptime=%ds  cpu=%.1f%%  mem=%s\n",
			c.Name, c.State, c.UptimeSeconds, c.CPUPercent, formatBytes(c.MemoryBytes))
	}

	fmt.Println("\nCapture consumers:")
	if len(r.Capture.Consumers) == 0 {
		fmt.Println("  (none)")
	}
	for name, cs := range r.Capture.Consumers {
		fmt.Printf("  %-16s  rx=%d  drops=%d  drop%%=%.2f  throughput=%s/s\n",
			name, cs.PacketsReceived, cs.PacketsDropped, cs.DropPercent,
			formatBytes(uint64(cs.ThroughputBps)))
	}

	fmt.Printf("\nStorage (%s):\n", r.Storage.Path)
	fmt.Printf("  used=%s / total=%s (%.1f%%)\n",
		formatBytes(r.Storage.UsedBytes), formatBytes(r.Storage.TotalBytes), r.Storage.UsedPercent)

	syncStr := "yes"
	if !r.Clock.Synchronized {
		syncStr = "NO (DEGRADED)"
	}
	fmt.Printf("\nClock:\n")
	fmt.Printf("  synchronized=%s  offset=%dms  source=%s\n",
		syncStr, r.Clock.OffsetMs, r.Clock.Source)
}

func printDropCounters(r healthReport) {
	ts := time.UnixMilli(r.TimestampUnixMs).UTC().Format(time.RFC3339)
	fmt.Printf("Sensor Pod: %s  (as of %s)\n\n", r.SensorPodID, ts)

	fmt.Printf("%-16s  %12s  %12s  %8s\n", "Consumer", "Received", "Dropped", "Drop%")
	fmt.Println(strings.Repeat("-", 56))

	if len(r.Capture.Consumers) == 0 {
		fmt.Println("  (no consumers)")
		return
	}

	for name, cs := range r.Capture.Consumers {
		fmt.Printf("%-16s  %12d  %12d  %7.2f%%\n",
			name, cs.PacketsReceived, cs.PacketsDropped, cs.DropPercent)
	}
}

// printJSON pretty-prints a JSON body, falling back to raw output on error.
func printJSON(body []byte) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		fmt.Println(string(body))
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func requireSensorURL(cfg config) {
	if cfg.SensorURL == "" {
		fatalf("sensor URL is required: use --sensor <url> or set SENSORCTL_SENSOR_URL")
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sensorctl: "+format+"\n", args...)
	os.Exit(1)
}
