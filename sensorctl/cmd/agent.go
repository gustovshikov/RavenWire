package cmd

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type agentConfig struct {
	CertFile  string
	KeyFile   string
	CAFile    string
	SensorURL string
}

func agentCmd() *cobra.Command {
	agent := &cobra.Command{
		Use:   "agent",
		Short: "Inspect and operate a RavenWire sensor agent",
		Long:  "Agent commands talk to a sensor agent control API over mTLS.",
	}

	agent.AddCommand(agentStatusCmd())
	agent.AddCommand(agentShowDropsCmd())
	agent.AddCommand(agentSupportBundleCmd())

	return agent
}

func agentStatusCmd() *cobra.Command {
	var sensorURL string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print the current sensor health snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := fetchAgentHealth(sensorURL)
			if err != nil {
				return err
			}
			printAgentHealthReport(report)
			return nil
		},
	}

	cmd.Flags().StringVar(&sensorURL, "sensor", "", "Sensor agent URL, for example https://sensor-host:9091")
	return cmd
}

func agentShowDropsCmd() *cobra.Command {
	var sensorURL string

	cmd := &cobra.Command{
		Use:     "show-drops",
		Aliases: []string{"drops"},
		Short:   "Print per-consumer packet and drop counters",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := fetchAgentHealth(sensorURL)
			if err != nil {
				return err
			}
			printAgentDropCounters(report)
			return nil
		},
	}

	cmd.Flags().StringVar(&sensorURL, "sensor", "", "Sensor agent URL, for example https://sensor-host:9091")
	return cmd
}

func agentSupportBundleCmd() *cobra.Command {
	var sensorURL, outputPath string

	cmd := &cobra.Command{
		Use:   "collect-support-bundle",
		Short: "Generate and download a sensor support bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPath == "" {
				return fmt.Errorf("--output is required")
			}
			return collectAgentSupportBundle(sensorURL, outputPath)
		},
	}

	cmd.Flags().StringVar(&sensorURL, "sensor", "", "Sensor agent URL, for example https://sensor-host:9091")
	cmd.Flags().StringVar(&outputPath, "output", "", "Local path to write the support bundle archive")
	return cmd
}

func fetchAgentHealth(sensorURL string) (agentHealthReport, error) {
	cfg := loadAgentConfig()
	if sensorURL != "" {
		cfg.SensorURL = sensorURL
	}
	if cfg.SensorURL == "" {
		return agentHealthReport{}, fmt.Errorf("sensor URL is required: use --sensor or set SENSORCTL_SENSOR_URL")
	}

	client, err := buildAgentHTTPClient(cfg, true)
	if err != nil {
		return agentHealthReport{}, err
	}

	url := strings.TrimRight(cfg.SensorURL, "/") + "/health"
	resp, err := client.Get(url)
	if err != nil {
		return agentHealthReport{}, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return agentHealthReport{}, fmt.Errorf("GET %s returned HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var report agentHealthReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return agentHealthReport{}, fmt.Errorf("decode health response: %w", err)
	}
	return report, nil
}

func collectAgentSupportBundle(sensorURL, outputPath string) error {
	cfg := loadAgentConfig()
	if sensorURL != "" {
		cfg.SensorURL = sensorURL
	}
	if cfg.SensorURL == "" {
		return fmt.Errorf("sensor URL is required: use --sensor or set SENSORCTL_SENSOR_URL")
	}

	client, err := buildAgentHTTPClient(cfg, true)
	if err != nil {
		return err
	}

	triggerURL := strings.TrimRight(cfg.SensorURL, "/") + "/control/support-bundle"
	resp, err := client.Post(triggerURL, "application/json", strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("POST %s: %w", triggerURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("support bundle trigger returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var triggerResp struct {
		Status string `json:"status"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&triggerResp); err != nil {
		return fmt.Errorf("decode support bundle response: %w", err)
	}
	if triggerResp.Path == "" {
		return fmt.Errorf("sensor returned an empty support bundle path")
	}

	downloadURL := strings.TrimRight(cfg.SensorURL, "/") + "/control/support-bundle/download?path=" + triggerResp.Path
	dlResp, err := client.Get(downloadURL)
	if err != nil {
		fmt.Printf("Bundle generated on sensor at %s, but download failed: %v\n", triggerResp.Path, err)
		return nil
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(dlResp.Body)
		fmt.Printf("Bundle generated on sensor at %s, but download returned HTTP %d: %s\n", triggerResp.Path, dlResp.StatusCode, strings.TrimSpace(string(body)))
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	n, err := io.Copy(f, dlResp.Body)
	if err != nil {
		return fmt.Errorf("write support bundle: %w", err)
	}

	fmt.Printf("Support bundle saved to %s (%d bytes)\n", outputPath, n)
	return nil
}

func loadAgentConfig() agentConfig {
	cfg := agentConfig{
		CertFile:  os.Getenv("SENSORCTL_CERT"),
		KeyFile:   os.Getenv("SENSORCTL_KEY"),
		CAFile:    os.Getenv("SENSORCTL_CA"),
		SensorURL: os.Getenv("SENSORCTL_SENSOR_URL"),
	}

	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" || cfg.SensorURL == "" {
		fileCfg := loadAgentConfigFile()
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

func loadAgentConfigFile() map[string]string {
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
			if len(parts) != 2 {
				continue
			}
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
		return result
	}

	return map[string]string{}
}

func buildAgentHTTPClient(cfg agentConfig, withClientCert bool) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true
	}

	if withClientCert && cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}, nil
}

type agentHealthReport struct {
	SensorPodID     string                 `json:"sensor_pod_id"`
	TimestampUnixMs int64                  `json:"timestamp_unix_ms"`
	Containers      []agentContainerHealth `json:"containers"`
	Capture         agentCaptureStats      `json:"capture"`
	Storage         agentStorageStats      `json:"storage"`
	Clock           agentClockStats        `json:"clock"`
}

type agentContainerHealth struct {
	Name          string  `json:"name"`
	State         string  `json:"state"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryBytes   uint64  `json:"memory_bytes"`
}

type agentCaptureStats struct {
	Consumers map[string]agentConsumerStats `json:"consumers"`
}

type agentConsumerStats struct {
	PacketsReceived uint64  `json:"packets_received"`
	PacketsDropped  uint64  `json:"packets_dropped"`
	DropPercent     float64 `json:"drop_percent"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

type agentStorageStats struct {
	Path           string  `json:"path"`
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type agentClockStats struct {
	OffsetMs     int64  `json:"offset_ms"`
	Synchronized bool   `json:"synchronized"`
	Source       string `json:"source"`
}

func printAgentHealthReport(r agentHealthReport) {
	ts := time.UnixMilli(r.TimestampUnixMs).UTC().Format(time.RFC3339)
	fmt.Printf("Sensor Pod:  %s\n", r.SensorPodID)
	fmt.Printf("Timestamp:   %s\n\n", ts)

	fmt.Println("Containers:")
	if len(r.Containers) == 0 {
		fmt.Println("  (none)")
	}
	for _, c := range r.Containers {
		fmt.Printf("  %-20s  state=%-12s  uptime=%ds  cpu=%.1f%%  mem=%s\n",
			c.Name, c.State, c.UptimeSeconds, c.CPUPercent, formatAgentBytes(c.MemoryBytes))
	}

	fmt.Println("\nCapture consumers:")
	if len(r.Capture.Consumers) == 0 {
		fmt.Println("  (none)")
	}
	for name, cs := range r.Capture.Consumers {
		fmt.Printf("  %-16s  rx=%d  drops=%d  drop%%=%.2f  throughput=%s/s\n",
			name, cs.PacketsReceived, cs.PacketsDropped, cs.DropPercent,
			formatAgentBytes(uint64(cs.ThroughputBps)))
	}

	fmt.Printf("\nStorage (%s):\n", r.Storage.Path)
	fmt.Printf("  used=%s / total=%s (%.1f%%)\n",
		formatAgentBytes(r.Storage.UsedBytes), formatAgentBytes(r.Storage.TotalBytes), r.Storage.UsedPercent)

	syncStr := "yes"
	if !r.Clock.Synchronized {
		syncStr = "NO (DEGRADED)"
	}
	fmt.Printf("\nClock:\n")
	fmt.Printf("  synchronized=%s  offset=%dms  source=%s\n", syncStr, r.Clock.OffsetMs, r.Clock.Source)
}

func printAgentDropCounters(r agentHealthReport) {
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

func formatAgentBytes(b uint64) string {
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
