//go:build linux

// Package support implements support bundle generation for the Sensor_Agent.
// A support bundle collects container logs, NIC stats, AF_PACKET drop counters,
// disk usage, rule versions, cert status, and recent audit log entries into a
// timestamped tar.gz archive. Sensitive values (IPs, credentials, keys) are
// redacted by default.
package support

import (
	"archive/tar"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sensor-stack/sensor-agent/internal/audit"
)

// BundleConfig holds paths and settings for bundle collection.
type BundleConfig struct {
	// AuditLogPath is the path to the local audit log file.
	AuditLogPath string
	// CertDir is the directory containing sensor TLS certificates.
	CertDir string
	// RulesDir is the directory containing Suricata rule files.
	RulesDir string
	// PcapAlertsDir is the PCAP alerts storage directory (for disk usage).
	PcapAlertsDir string
	// PodmanSocketPath is the Unix socket path for the Podman API.
	PodmanSocketPath string
	// OutputDir is where the tar.gz archive is written (default: /tmp).
	OutputDir string
	// AuditTailLines is how many recent audit log lines to include (default: 200).
	AuditTailLines int
}

// DefaultBundleConfig returns a BundleConfig populated from environment variables.
func DefaultBundleConfig() BundleConfig {
	return BundleConfig{
		AuditLogPath:     envOrDefault("AUDIT_LOG_PATH", "/var/sensor/audit.log"),
		CertDir:          envOrDefault("CERT_DIR", "/etc/sensor/certs"),
		RulesDir:         envOrDefault("SURICATA_RULES_DIR", "/etc/suricata/rules"),
		PcapAlertsDir:    envOrDefault("PCAP_ALERTS_DIR", "/sensor/pcap/alerts"),
		PodmanSocketPath: envOrDefault("PODMAN_SOCKET_PATH", "/run/podman/podman.sock"),
		OutputDir:        envOrDefault("SUPPORT_BUNDLE_DIR", "/tmp"),
		AuditTailLines:   200,
	}
}

// BundleGenerator collects diagnostic data and writes a support bundle archive.
type BundleGenerator struct {
	auditLog *audit.Logger
	cfg      BundleConfig
}

// NewBundleGenerator creates a new BundleGenerator with default config.
func NewBundleGenerator(auditLog *audit.Logger) *BundleGenerator {
	return &BundleGenerator{
		auditLog: auditLog,
		cfg:      DefaultBundleConfig(),
	}
}

// NewBundleGeneratorWithConfig creates a BundleGenerator with explicit config.
func NewBundleGeneratorWithConfig(auditLog *audit.Logger, cfg BundleConfig) *BundleGenerator {
	return &BundleGenerator{auditLog: auditLog, cfg: cfg}
}

// Generate collects diagnostic data and writes a timestamped tar.gz archive.
// Returns the path to the generated archive.
func (g *BundleGenerator) Generate() (string, error) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	archiveName := fmt.Sprintf("sensor-support-%s.tar.gz", ts)
	archivePath := filepath.Join(g.cfg.OutputDir, archiveName)

	f, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("create support bundle archive %s: %w", archivePath, err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	prefix := fmt.Sprintf("sensor-support-%s/", ts)

	// Collect each section; log but don't abort on individual failures.
	sections := []struct {
		name    string
		collect func() ([]byte, error)
	}{
		{"container_logs.json", g.collectContainerLogs},
		{"nic_stats.json", g.collectNICStats},
		{"af_packet_drops.json", g.collectAFPacketDrops},
		{"disk_usage.json", g.collectDiskUsage},
		{"rule_versions.json", g.collectRuleVersions},
		{"cert_status.json", g.collectCertStatus},
		{"audit_log_tail.json", g.collectAuditLogTail},
	}

	for _, s := range sections {
		data, err := s.collect()
		if err != nil {
			log.Printf("support: collecting %s: %v", s.name, err)
			data = marshalError(s.name, err)
		}
		data = redact(data)
		if err := addFile(tw, prefix+s.name, data); err != nil {
			return "", fmt.Errorf("write %s to archive: %w", s.name, err)
		}
	}

	// Flush writers before returning path
	if err := tw.Close(); err != nil {
		return "", fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("close gzip writer: %w", err)
	}

	log.Printf("support: bundle written to %s", archivePath)
	return archivePath, nil
}

// ── Section collectors ────────────────────────────────────────────────────────

// collectContainerLogs fetches container names and recent log lines via Podman.
func (g *BundleGenerator) collectContainerLogs() ([]byte, error) {
	client := podmanClient(g.cfg.PodmanSocketPath)

	listResp, err := client.Get("http://d/v4.0.0/libpod/containers/json?all=true")
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	defer listResp.Body.Close()

	var containers []struct {
		Names []string `json:"Names"`
		State string   `json:"State"`
		ID    string   `json:"Id"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode container list: %w", err)
	}

	type containerLog struct {
		Name  string   `json:"name"`
		State string   `json:"state"`
		Lines []string `json:"recent_lines"`
		Error string   `json:"error,omitempty"`
	}

	result := make([]containerLog, 0, len(containers))
	for _, ct := range containers {
		name := ""
		if len(ct.Names) > 0 {
			name = ct.Names[0]
		}
		cl := containerLog{Name: name, State: ct.State}

		logsURL := fmt.Sprintf("http://d/v4.0.0/libpod/containers/%s/logs?stdout=true&stderr=true&tail=50", ct.ID)
		logsResp, err := client.Get(logsURL)
		if err != nil {
			cl.Error = err.Error()
		} else {
			raw, _ := io.ReadAll(logsResp.Body)
			logsResp.Body.Close()
			// Podman log stream uses a multiplexed framing; extract printable lines.
			cl.Lines = extractLogLines(raw)
		}
		result = append(result, cl)
	}

	return json.MarshalIndent(result, "", "  ")
}

// collectNICStats reads interface statistics from /proc/net/dev.
func (g *BundleGenerator) collectNICStats() ([]byte, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/dev: %w", err)
	}

	type ifaceStats struct {
		Interface string `json:"interface"`
		RxBytes   string `json:"rx_bytes"`
		RxPackets string `json:"rx_packets"`
		RxDropped string `json:"rx_dropped"`
		TxBytes   string `json:"tx_bytes"`
		TxPackets string `json:"tx_packets"`
		TxDropped string `json:"tx_dropped"`
	}

	var stats []ifaceStats
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") {
			continue
		}
		// Format: iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs tx_drop ...
		parts := strings.Fields(strings.ReplaceAll(line, ":", " "))
		if len(parts) < 17 {
			continue
		}
		stats = append(stats, ifaceStats{
			Interface: parts[0],
			RxBytes:   parts[1],
			RxPackets: parts[2],
			RxDropped: parts[4],
			TxBytes:   parts[9],
			TxPackets: parts[10],
			TxDropped: parts[12],
		})
	}

	return json.MarshalIndent(stats, "", "  ")
}

// collectAFPacketDrops reads per-socket AF_PACKET statistics from /proc/net/packet.
func (g *BundleGenerator) collectAFPacketDrops() ([]byte, error) {
	data, err := os.ReadFile("/proc/net/packet")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/packet: %w", err)
	}

	type socketStats struct {
		RefCount string `json:"ref_count"`
		Type     string `json:"type"`
		Proto    string `json:"proto"`
		Iface    string `json:"iface"`
		RCount   string `json:"r_count"`
		RBytes   string `json:"r_bytes"`
		Drops    string `json:"drops"`
	}

	var sockets []socketStats
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "sk") {
			continue
		}
		// /proc/net/packet columns: sk RefCnt Type Proto Iface R Rmem User Inode
		// Extended format includes drop counter as last field.
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		s := socketStats{
			RefCount: parts[1],
			Type:     parts[2],
			Proto:    parts[3],
			Iface:    parts[4],
			RCount:   parts[5],
		}
		if len(parts) >= 7 {
			s.RBytes = parts[6]
		}
		if len(parts) >= 9 {
			s.Drops = parts[8]
		}
		sockets = append(sockets, s)
	}

	return json.MarshalIndent(sockets, "", "  ")
}

// collectDiskUsage reports disk usage for key sensor paths.
func (g *BundleGenerator) collectDiskUsage() ([]byte, error) {
	paths := []string{
		g.cfg.PcapAlertsDir,
		"/var/sensor",
		"/etc/sensor",
		"/dev/shm",
	}

	type pathUsage struct {
		Path           string  `json:"path"`
		TotalBytes     uint64  `json:"total_bytes"`
		UsedBytes      uint64  `json:"used_bytes"`
		AvailableBytes uint64  `json:"available_bytes"`
		UsedPercent    float64 `json:"used_percent"`
		Error          string  `json:"error,omitempty"`
	}

	result := make([]pathUsage, 0, len(paths))
	for _, p := range paths {
		pu := pathUsage{Path: p}
		var stat syscall.Statfs_t
		if err := syscall.Statfs(p, &stat); err != nil {
			pu.Error = err.Error()
		} else {
			total := stat.Blocks * uint64(stat.Bsize)
			avail := stat.Bavail * uint64(stat.Bsize)
			used := total - avail
			pu.TotalBytes = total
			pu.UsedBytes = used
			pu.AvailableBytes = avail
			if total > 0 {
				pu.UsedPercent = float64(used) / float64(total) * 100
			}
		}
		result = append(result, pu)
	}

	return json.MarshalIndent(result, "", "  ")
}

// collectRuleVersions lists rule files and their sizes/mtimes from the rules directory.
func (g *BundleGenerator) collectRuleVersions() ([]byte, error) {
	type ruleFile struct {
		Name    string `json:"name"`
		SizeB   int64  `json:"size_bytes"`
		ModTime string `json:"mod_time"`
	}

	entries, err := os.ReadDir(g.cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", g.cfg.RulesDir, err)
	}

	var files []ruleFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, ruleFile{
			Name:    e.Name(),
			SizeB:   info.Size(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
		})
	}

	return json.MarshalIndent(map[string]any{
		"rules_dir": g.cfg.RulesDir,
		"files":     files,
	}, "", "  ")
}

// collectCertStatus reads the sensor certificate and reports its metadata (no key material).
func (g *BundleGenerator) collectCertStatus() ([]byte, error) {
	certPath := filepath.Join(g.cfg.CertDir, "sensor.crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", certPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	now := time.Now().UTC()
	remaining := cert.NotAfter.Sub(now)

	status := map[string]any{
		"subject":      cert.Subject.CommonName,
		"issuer":       cert.Issuer.CommonName,
		"serial":       cert.SerialNumber.String(),
		"not_before":   cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after":    cert.NotAfter.UTC().Format(time.RFC3339),
		"remaining":    remaining.String(),
		"expired":      now.After(cert.NotAfter),
		"dns_names":    cert.DNSNames,
		"key_algo":     cert.PublicKeyAlgorithm.String(),
		"sig_algo":     cert.SignatureAlgorithm.String(),
	}

	return json.MarshalIndent(status, "", "  ")
}

// collectAuditLogTail returns the last N entries from the audit log.
func (g *BundleGenerator) collectAuditLogTail() ([]byte, error) {
	entries, err := g.auditLog.ReadLast(g.cfg.AuditTailLines)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return json.MarshalIndent(entries, "", "  ")
}

// ── Redaction ─────────────────────────────────────────────────────────────────

// redactPatterns is the list of regex → replacement pairs applied to bundle content.
var redactPatterns = []*redactRule{
	// IPv4 addresses (preserve structure, replace octets)
	{re: regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`), replacement: "[REDACTED-IP]"},
	// IPv6 addresses
	{re: regexp.MustCompile(`([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}`), replacement: "[REDACTED-IPv6]"},
	// PEM private key blocks
	{re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), replacement: "[REDACTED-PRIVATE-KEY]"},
	// Generic password/secret/token/key JSON fields
	{re: regexp.MustCompile(`(?i)"(password|secret|token|api_key|apikey|credential|auth)["\s]*:\s*"[^"]*"`), replacement: `"$1": "[REDACTED]"`},
	// Bearer tokens in headers
	{re: regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`), replacement: "Bearer [REDACTED]"},
}

type redactRule struct {
	re          *regexp.Regexp
	replacement string
}

// redact applies all redaction patterns to raw JSON bytes.
func redact(data []byte) []byte {
	s := string(data)
	for _, rule := range redactPatterns {
		s = rule.re.ReplaceAllString(s, rule.replacement)
	}
	return []byte(s)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// addFile writes a single file entry into the tar archive.
func addFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0640,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// marshalError returns a JSON-encoded error payload for a failed section.
func marshalError(section string, err error) []byte {
	b, _ := json.MarshalIndent(map[string]string{
		"section": section,
		"error":   err.Error(),
	}, "", "  ")
	return b
}

// podmanClient returns an HTTP client that dials the Podman Unix socket.
func podmanClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// extractLogLines strips Podman's multiplexed stream framing and returns plain lines.
// Podman log streams prefix each frame with an 8-byte header; we skip non-printable
// bytes and split on newlines to recover the text.
func extractLogLines(raw []byte) []string {
	var lines []string
	var current strings.Builder
	for _, b := range raw {
		if b == '\n' {
			if current.Len() > 0 {
				lines = append(lines, current.String())
				current.Reset()
			}
		} else if b >= 0x20 || b == '\t' {
			current.WriteByte(b)
		}
		// skip control bytes (Podman framing headers)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
