package pcap

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sensor-stack/sensor-agent/internal/audit"
)

// CarveRequest is a request to carve a PCAP window.
type CarveRequest struct {
	CommunityID    string `json:"community_id,omitempty"`
	StartTimeMs    int64  `json:"start_time_ms"`
	EndTimeMs      int64  `json:"end_time_ms"`
	PreAlertMs     int64  `json:"pre_alert_ms,omitempty"`
	PostAlertMs    int64  `json:"post_alert_ms,omitempty"`
	OutputPath     string `json:"output_path,omitempty"`
}

// CarveResult is the result of a PCAP carve operation.
type CarveResult struct {
	OutputPath  string `json:"output_path"`
	PacketCount int    `json:"packet_count"`
	StartTimeMs int64  `json:"start_time_ms"`
	EndTimeMs   int64  `json:"end_time_ms"`
	CommunityID string `json:"community_id,omitempty"`
}

// AlertEvent is an alert forwarded from Vector.
type AlertEvent struct {
	CommunityID string  `json:"community_id"`
	Severity    int     `json:"severity"`
	Timestamp   int64   `json:"timestamp_ms"`
	SID         string  `json:"sid,omitempty"`
	Message     string  `json:"message,omitempty"`
}

// Manager controls the pcap_ring_writer and handles alert-driven PCAP carving.
type Manager struct {
	ringSocket      string
	alertsDir       string
	index           *Index
	auditLog        *audit.Logger
	severityThresh  int
	preAlertMs      int64
	postAlertMs     int64
	criticalPct     float64
	lowWaterPct     float64
	mode            string // "alert_driven" or "full_pcap"
}

// NewManager creates a new PCAP Manager.
func NewManager(ringSocket, alertsDir string, index *Index, auditLog *audit.Logger) *Manager {
	return &Manager{
		ringSocket:     ringSocket,
		alertsDir:      alertsDir,
		index:          index,
		auditLog:       auditLog,
		severityThresh: 2,    // default: medium severity and above
		preAlertMs:     5000, // 5 seconds pre-alert window
		postAlertMs:    3000, // 3 seconds post-alert window
		criticalPct:    90.0,
		lowWaterPct:    75.0,
		mode:           "alert_driven",
	}
}

// SwitchMode switches between "alert_driven" and "full_pcap" modes.
func (m *Manager) SwitchMode(mode string) error {
	switch mode {
	case "alert_driven", "full_pcap":
		m.mode = mode
		log.Printf("pcap: switched to mode %q", mode)
		return nil
	default:
		return fmt.Errorf("unknown capture mode %q; valid modes: alert_driven, full_pcap", mode)
	}
}

// HandleAlert processes a qualifying alert event and triggers a PCAP carve.
func (m *Manager) HandleAlert(alert AlertEvent) error {
	if m.mode != "alert_driven" {
		return nil
	}
	if alert.Severity < m.severityThresh {
		return nil
	}

	alertTimeMs := alert.Timestamp
	if alertTimeMs == 0 {
		alertTimeMs = time.Now().UnixMilli()
	}

	preAlertMs := alertTimeMs - m.preAlertMs

	// Mark pre-alert window in ring writer
	if err := m.sendToRing(map[string]interface{}{
		"cmd":          "mark_pre_alert",
		"timestamp_ms": preAlertMs,
	}); err != nil {
		return fmt.Errorf("mark_pre_alert: %w", err)
	}

	// Wait for post-alert window
	time.Sleep(time.Duration(m.postAlertMs) * time.Millisecond)

	postAlertMs := time.Now().UnixMilli()

	// Carve the window
	outputPath := filepath.Join(m.alertsDir,
		fmt.Sprintf("alert_%s_%d.pcap", sanitizeCommunityID(alert.CommunityID), alertTimeMs))

	if err := os.MkdirAll(m.alertsDir, 0755); err != nil {
		return fmt.Errorf("create alerts dir: %w", err)
	}

	result, err := m.carveFromRing(preAlertMs*int64(time.Millisecond), postAlertMs*int64(time.Millisecond), outputPath)
	if err != nil {
		return fmt.Errorf("carve window: %w", err)
	}

	// Index the carved file
	_, err = m.index.Insert(PcapFile{
		FilePath:    outputPath,
		StartTime:   preAlertMs,
		EndTime:     postAlertMs,
		Interface:   os.Getenv("CAPTURE_IFACE"),
		PacketCount: int64(result.PacketCount),
		AlertDriven: true,
		CommunityID: alert.CommunityID,
	})
	if err != nil {
		log.Printf("pcap: failed to index carved file: %v", err)
	}

	m.auditLog.Log("pcap-carve", "system", "success", map[string]any{
		"output":       outputPath,
		"packets":      result.PacketCount,
		"community_id": alert.CommunityID,
	})

	// Check storage and prune if needed
	go m.pruneIfNeeded()

	return nil
}

// Carve executes a PCAP carve request from the Control API.
func (m *Manager) Carve(req CarveRequest) (CarveResult, error) {
	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(m.alertsDir,
			fmt.Sprintf("carve_%d_%d.pcap", req.StartTimeMs, time.Now().UnixMilli()))
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return CarveResult{}, fmt.Errorf("create output dir: %w", err)
	}

	preNs := req.StartTimeMs * int64(time.Millisecond)
	postNs := req.EndTimeMs * int64(time.Millisecond)

	result, err := m.carveFromRing(preNs, postNs, outputPath)
	if err != nil {
		return CarveResult{}, err
	}

	result.CommunityID = req.CommunityID
	return result, nil
}

// carveFromRing sends a carve_window command to pcap_ring_writer.
func (m *Manager) carveFromRing(preAlertNs, postAlertNs int64, outputPath string) (CarveResult, error) {
	var resp map[string]interface{}
	err := m.sendToRingAndReceive(map[string]interface{}{
		"cmd":           "carve_window",
		"pre_alert_ns":  preAlertNs,
		"post_alert_ns": postAlertNs,
		"output_path":   outputPath,
	}, &resp)
	if err != nil {
		return CarveResult{}, fmt.Errorf("carve_window command: %w", err)
	}

	if status, _ := resp["status"].(string); status != "ok" {
		errMsg, _ := resp["error"].(string)
		return CarveResult{}, fmt.Errorf("carve_window failed: %s", errMsg)
	}

	count := 0
	if c, ok := resp["packet_count"].(float64); ok {
		count = int(c)
	}

	return CarveResult{
		OutputPath:  outputPath,
		PacketCount: count,
		StartTimeMs: preAlertNs / int64(time.Millisecond),
		EndTimeMs:   postAlertNs / int64(time.Millisecond),
	}, nil
}

// sendToRing sends a command to pcap_ring_writer without reading the response.
func (m *Manager) sendToRing(cmd map[string]interface{}) error {
	var resp map[string]interface{}
	return m.sendToRingAndReceive(cmd, &resp)
}

// sendToRingAndReceive sends a command and decodes the response.
func (m *Manager) sendToRingAndReceive(cmd map[string]interface{}, resp interface{}) error {
	conn, err := net.DialTimeout("unix", m.ringSocket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial ring socket %s: %w", m.ringSocket, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		return fmt.Errorf("send command: %w", err)
	}
	if err := json.NewDecoder(conn).Decode(resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	return nil
}

// pruneIfNeeded checks storage usage and prunes old PCAP files if above threshold.
func (m *Manager) pruneIfNeeded() {
	usedPct, err := storageUsedPercent(m.alertsDir)
	if err != nil {
		log.Printf("pcap: failed to check storage: %v", err)
		return
	}

	if usedPct < m.criticalPct {
		return
	}

	log.Printf("pcap: storage at %.1f%% (threshold %.1f%%), pruning", usedPct, m.criticalPct)

	timeout := time.After(60 * time.Second)
	for {
		select {
		case <-timeout:
			log.Printf("pcap: CRITICAL: pruning timed out, storage still above threshold")
			return
		default:
		}

		current, err := storageUsedPercent(m.alertsDir)
		if err != nil || current < m.lowWaterPct {
			if err == nil {
				log.Printf("pcap: pruning complete, storage at %.1f%%", current)
			}
			return
		}

		// Get oldest files
		files, err := m.index.OldestFiles(10)
		if err != nil || len(files) == 0 {
			log.Printf("pcap: no files to prune")
			return
		}

		for _, f := range files {
			if err := os.Remove(f.FilePath); err != nil && !os.IsNotExist(err) {
				log.Printf("pcap: failed to delete %s: %v", f.FilePath, err)
				continue
			}
			if err := m.index.DeleteByID(f.ID); err != nil {
				log.Printf("pcap: failed to remove index entry %d: %v", f.ID, err)
			}
			log.Printf("pcap: pruned %s", f.FilePath)
		}
	}
}

// ListenForAlerts starts an HTTP server to receive alert events from Vector.
func (m *Manager) ListenForAlerts(addr string, done <-chan struct{}) {
	// Alert webhook listener — Vector POSTs qualifying Suricata alerts here
	log.Printf("pcap: alert listener starting on %s", addr)
	// Full implementation: HTTP server that receives Vector alert webhooks
	// For MVP, alerts are handled via the Control API carve endpoint
}

func sanitizeCommunityID(id string) string {
	if id == "" {
		return "unknown"
	}
	// Replace characters not safe for filenames
	safe := make([]byte, 0, len(id))
	for _, c := range []byte(id) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			safe = append(safe, c)
		} else {
			safe = append(safe, '_')
		}
	}
	return string(safe)
}

// PruneStats holds the result of a pruning operation for testing.
type PruneStats struct {
	FilesDeleted int
	BytesFreed   int64
	FinalUsedPct float64
}

// PruneToLowWater prunes PCAP files until storage is below the low-water mark.
// Returns stats about what was pruned. Used by tests and the FIFO pruning logic.
func (m *Manager) PruneToLowWater() (PruneStats, error) {
	var stats PruneStats

	timeout := time.After(60 * time.Second)
	for {
		select {
		case <-timeout:
			return stats, fmt.Errorf("pruning timed out")
		default:
		}

		usedPct, err := storageUsedPercent(m.alertsDir)
		if err != nil {
			return stats, fmt.Errorf("check storage: %w", err)
		}
		stats.FinalUsedPct = usedPct

		if usedPct < m.lowWaterPct {
			return stats, nil
		}

		files, err := m.index.OldestFiles(10)
		if err != nil {
			return stats, fmt.Errorf("query oldest files: %w", err)
		}
		if len(files) == 0 {
			return stats, fmt.Errorf("no files to prune but storage still above low-water mark")
		}

		for _, f := range files {
			info, statErr := os.Stat(f.FilePath)
			if statErr == nil {
				stats.BytesFreed += info.Size()
			}

			if err := os.Remove(f.FilePath); err != nil && !os.IsNotExist(err) {
				log.Printf("pcap: prune: failed to delete %s: %v", f.FilePath, err)
				continue
			}
			if err := m.index.DeleteByID(f.ID); err != nil {
				log.Printf("pcap: prune: failed to remove index entry %d: %v", f.ID, err)
			}
			stats.FilesDeleted++
		}
	}
}

// storageUsedPercent returns the percentage of used storage at the given path.
func storageUsedPercent(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	total := stat.Blocks * uint64(stat.Bsize)
	if total == 0 {
		return 0, nil
	}
	avail := stat.Bavail * uint64(stat.Bsize)
	used := total - avail
	return float64(used) / float64(total) * 100, nil
}
