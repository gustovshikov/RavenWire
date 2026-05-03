package pcap

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/podman"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/ringctl"
)

// Container names managed by SwitchMode.
const (
	containerNetsniffNG     = "netsniff-ng"
	containerPcapRingWriter = "pcap_ring_writer"
)

// defaultModeSwitchTimeout is the default timeout for verifying a container
// reaches its target state during a mode switch (Requirement 13.1).
const defaultModeSwitchTimeout = 30 * time.Second

// CarveRequest is a request to carve a PCAP window.
type CarveRequest struct {
	CommunityID string `json:"community_id,omitempty"`
	StartTimeMs int64  `json:"start_time_ms"`
	EndTimeMs   int64  `json:"end_time_ms"`
	OutputPath  string `json:"output_path,omitempty"`
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
	CommunityID string `json:"community_id"`
	Severity    int    `json:"severity"`
	TimestampMs int64  `json:"timestamp_ms"`
	SID         string `json:"sid"`
	Signature   string `json:"signature,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	SrcPort     int    `json:"src_port,omitempty"`
	DstPort     int    `json:"dst_port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	ZeekUID     string `json:"zeek_uid,omitempty"`
}

// Manager controls the pcap_ring_writer and handles alert-driven PCAP carving.
type Manager struct {
	ringSocket     string
	alertsDir      string
	index          *Index
	auditLog       *audit.Logger
	severityThresh int
	preAlertMs     int64
	postAlertMs    int64
	criticalPct    float64
	lowWaterPct    float64
	mode           string // "alert_driven" or "full_pcap"
	listener       *AlertListener
	sensorID       string
	dedup          *dedupCache

	// Podman client for container lifecycle management (Requirement 13).
	podmanClient *podman.Client
	// modeSwitchTimeout is the timeout for verifying container target state.
	modeSwitchTimeout time.Duration
	// pcapStoragePath is the path checked for free space before starting netsniff-ng.
	pcapStoragePath string
	// storageMinFreePct is the minimum free storage percentage required (low-water mark).
	// If free space is below this, switching to full_pcap is rejected.
	storageMinFreePct float64

	// containerStates tracks the last known state of mode-relevant containers.
	// Protected by the caller (SwitchMode is not concurrent-safe by design).
	containerStates map[string]string

	// healthReporter is an optional callback to report failures to Config_Manager.
	healthReporter func(msg string)

	// retentionDuration is the default time carved PCAP artifacts are retained.
	// A zero or negative duration disables default retention.
	retentionDuration time.Duration
}

// NewManager creates a new PCAP Manager.
func NewManager(ringSocket, alertsDir string, index *Index, auditLog *audit.Logger) *Manager {
	return NewManagerWithConfig(ringSocket, alertsDir, index, auditLog, ManagerConfig{})
}

// ManagerConfig holds optional configuration for the PCAP Manager.
type ManagerConfig struct {
	// SensorID is the unique identity of this sensor, used as part of the
	// deduplication key. Defaults to the hostname if empty.
	SensorID string
	// DedupWindow is the time window for alert deduplication. Defaults to 30s.
	DedupWindow time.Duration
	// SeverityThreshold is the maximum severity value that triggers a carve.
	// Suricata severity 1 is highest; alerts with severity <= threshold are carved.
	// Defaults to 2.
	SeverityThreshold int

	// PodmanClient is the Podman REST API client used for container lifecycle
	// management during mode switches. May be nil (mode switches will fail).
	PodmanClient *podman.Client
	// ModeSwitchTimeout is the timeout for verifying a container reaches its
	// target state during a mode switch. Defaults to 30s.
	ModeSwitchTimeout time.Duration
	// PCAPStoragePath is the path checked for free space before starting
	// netsniff-ng in Full_PCAP_Mode. Defaults to alertsDir.
	PCAPStoragePath string
	// StorageMinFreePct is the minimum free storage percentage required before
	// starting netsniff-ng. Defaults to 10.0 (10% free required).
	StorageMinFreePct float64
	// HealthReporter is an optional callback invoked when a mode switch fails,
	// to report the failure to the Config_Manager health stream.
	HealthReporter func(msg string)
	// RetentionPruneInterval is the interval between retention pruning cycles.
	// Defaults to 60s.
	RetentionPruneInterval time.Duration
	// RetentionDuration is the default retention period for carved PCAP files.
	// Defaults to 7 days. Set a negative value to disable default retention.
	RetentionDuration time.Duration
}

// NewManagerWithConfig creates a new PCAP Manager with explicit configuration.
func NewManagerWithConfig(ringSocket, alertsDir string, index *Index, auditLog *audit.Logger, cfg ManagerConfig) *Manager {
	sensorID := cfg.SensorID
	if sensorID == "" {
		if h, err := os.Hostname(); err == nil {
			sensorID = h
		} else {
			sensorID = "unknown"
		}
	}
	dedupWindow := cfg.DedupWindow
	if dedupWindow <= 0 {
		dedupWindow = 30 * time.Second
	}
	severityThresh := cfg.SeverityThreshold
	if severityThresh <= 0 {
		severityThresh = 2
	}
	modeSwitchTimeout := cfg.ModeSwitchTimeout
	if modeSwitchTimeout <= 0 {
		modeSwitchTimeout = defaultModeSwitchTimeout
	}
	pcapStoragePath := cfg.PCAPStoragePath
	if pcapStoragePath == "" {
		pcapStoragePath = alertsDir
	}
	storageMinFreePct := cfg.StorageMinFreePct
	if storageMinFreePct <= 0 {
		storageMinFreePct = 10.0 // require at least 10% free
	}
	retentionDuration := cfg.RetentionDuration
	if retentionDuration == 0 {
		retentionDuration = 7 * 24 * time.Hour
	}
	return &Manager{
		ringSocket:        ringSocket,
		alertsDir:         alertsDir,
		index:             index,
		auditLog:          auditLog,
		severityThresh:    severityThresh,
		preAlertMs:        5000, // 5 seconds pre-alert window
		postAlertMs:       3000, // 3 seconds post-alert window
		criticalPct:       90.0,
		lowWaterPct:       75.0,
		mode:              "alert_driven",
		sensorID:          sensorID,
		dedup:             newDedupCache(dedupWindow),
		podmanClient:      cfg.PodmanClient,
		modeSwitchTimeout: modeSwitchTimeout,
		pcapStoragePath:   pcapStoragePath,
		storageMinFreePct: storageMinFreePct,
		containerStates:   make(map[string]string),
		healthReporter:    cfg.HealthReporter,
		retentionDuration: retentionDuration,
	}
}

// ModeStatus holds the current capture mode and per-container state for health
// reporting (Requirement 13.5).
type ModeStatus struct {
	ActiveMode      string            `json:"active_mode"`
	ContainerStates map[string]string `json:"container_states"`
}

// ModeStatus returns the current active mode and per-container state for
// inclusion in the health report (Requirement 13.5).
func (m *Manager) ModeStatus() ModeStatus {
	states := make(map[string]string, len(m.containerStates))
	for k, v := range m.containerStates {
		states[k] = v
	}
	return ModeStatus{
		ActiveMode:      m.mode,
		ContainerStates: states,
	}
}

// SwitchMode switches between "alert_driven" and "full_pcap" modes by
// starting/stopping the appropriate containers via the Podman REST API.
//
// Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6
func (m *Manager) SwitchMode(mode string) error {
	switch mode {
	case "alert_driven", "full_pcap":
		// valid
	default:
		return fmt.Errorf("unknown capture mode %q; valid modes: alert_driven, full_pcap", mode)
	}

	if m.podmanClient == nil {
		return fmt.Errorf("podman client not configured; cannot switch mode")
	}

	previousMode := m.mode

	switch mode {
	case "full_pcap":
		if err := m.switchToFullPcap(); err != nil {
			// Attempt rollback to previous mode's container states (Requirement 13.4).
			m.rollbackMode(previousMode)
			if m.healthReporter != nil {
				m.healthReporter(fmt.Sprintf("mode switch to full_pcap failed: %v", err))
			}
			return fmt.Errorf("switch to full_pcap: %w", err)
		}
	case "alert_driven":
		if err := m.switchToAlertDriven(); err != nil {
			// Attempt rollback to previous mode's container states (Requirement 13.4).
			m.rollbackMode(previousMode)
			if m.healthReporter != nil {
				m.healthReporter(fmt.Sprintf("mode switch to alert_driven failed: %v", err))
			}
			return fmt.Errorf("switch to alert_driven: %w", err)
		}
	}

	m.mode = mode
	log.Printf("pcap: switched to mode %q", mode)
	return nil
}

// switchToFullPcap starts netsniff-ng and stops pcap_ring_writer.
// Requirements: 13.1, 13.2, 13.6
func (m *Manager) switchToFullPcap() error {
	// Requirement 13.6: Verify sufficient free storage before starting netsniff-ng.
	freePct, err := storageFreePercent(m.pcapStoragePath)
	if err != nil {
		return fmt.Errorf("check storage: %w", err)
	}
	if freePct < m.storageMinFreePct {
		return fmt.Errorf("insufficient free storage: %.1f%% free, minimum %.1f%% required at %s",
			freePct, m.storageMinFreePct, m.pcapStoragePath)
	}

	// Requirement 13.1: Start netsniff-ng and verify running state.
	if _, err := m.podmanClient.StartContainer(containerNetsniffNG, "pcap_manager"); err != nil {
		return fmt.Errorf("start %s: %w", containerNetsniffNG, err)
	}
	if err := m.waitForState(containerNetsniffNG, podman.StateRunning); err != nil {
		return fmt.Errorf("verify %s running: %w", containerNetsniffNG, err)
	}
	m.containerStates[containerNetsniffNG] = string(podman.StateRunning)

	// Requirement 13.2: Stop pcap_ring_writer.
	if _, err := m.podmanClient.StopContainer(containerPcapRingWriter, "pcap_manager"); err != nil {
		return fmt.Errorf("stop %s: %w", containerPcapRingWriter, err)
	}
	if err := m.waitForState(containerPcapRingWriter, podman.StateStopped); err != nil {
		return fmt.Errorf("verify %s stopped: %w", containerPcapRingWriter, err)
	}
	m.containerStates[containerPcapRingWriter] = string(podman.StateStopped)

	return nil
}

// switchToAlertDriven stops netsniff-ng and starts pcap_ring_writer.
// Requirement 13.3
func (m *Manager) switchToAlertDriven() error {
	// Stop netsniff-ng.
	if _, err := m.podmanClient.StopContainer(containerNetsniffNG, "pcap_manager"); err != nil {
		return fmt.Errorf("stop %s: %w", containerNetsniffNG, err)
	}
	if err := m.waitForState(containerNetsniffNG, podman.StateStopped); err != nil {
		return fmt.Errorf("verify %s stopped: %w", containerNetsniffNG, err)
	}
	m.containerStates[containerNetsniffNG] = string(podman.StateStopped)

	// Start pcap_ring_writer.
	if _, err := m.podmanClient.StartContainer(containerPcapRingWriter, "pcap_manager"); err != nil {
		return fmt.Errorf("start %s: %w", containerPcapRingWriter, err)
	}
	if err := m.waitForState(containerPcapRingWriter, podman.StateRunning); err != nil {
		return fmt.Errorf("verify %s running: %w", containerPcapRingWriter, err)
	}
	m.containerStates[containerPcapRingWriter] = string(podman.StateRunning)

	return nil
}

// waitForState polls the Podman API until the container reaches the target
// state or the mode switch timeout expires (Requirement 13.1: 30s default).
func (m *Manager) waitForState(containerName string, target podman.ContainerState) error {
	deadline := time.Now().Add(m.modeSwitchTimeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		state, err := m.podmanClient.GetContainerState(containerName)
		if err != nil {
			log.Printf("pcap: waitForState %q: poll error: %v", containerName, err)
		} else if state == target {
			return nil
		}
		time.Sleep(pollInterval)
	}

	return fmt.Errorf("container %q did not reach state %q within %s", containerName, target, m.modeSwitchTimeout)
}

// rollbackMode attempts to restore the container states for the given mode.
// This is a best-effort operation; errors are logged but not returned
// (Requirement 13.4).
func (m *Manager) rollbackMode(previousMode string) {
	log.Printf("pcap: attempting rollback to mode %q container states", previousMode)

	switch previousMode {
	case "full_pcap":
		// full_pcap: netsniff-ng running, pcap_ring_writer stopped
		if _, err := m.podmanClient.StartContainer(containerNetsniffNG, "pcap_manager_rollback"); err != nil {
			log.Printf("pcap: rollback: failed to start %s: %v", containerNetsniffNG, err)
		} else {
			m.containerStates[containerNetsniffNG] = string(podman.StateRunning)
		}
		if _, err := m.podmanClient.StopContainer(containerPcapRingWriter, "pcap_manager_rollback"); err != nil {
			log.Printf("pcap: rollback: failed to stop %s: %v", containerPcapRingWriter, err)
		} else {
			m.containerStates[containerPcapRingWriter] = string(podman.StateStopped)
		}
	case "alert_driven":
		// alert_driven: pcap_ring_writer running, netsniff-ng stopped
		if _, err := m.podmanClient.StopContainer(containerNetsniffNG, "pcap_manager_rollback"); err != nil {
			log.Printf("pcap: rollback: failed to stop %s: %v", containerNetsniffNG, err)
		} else {
			m.containerStates[containerNetsniffNG] = string(podman.StateStopped)
		}
		if _, err := m.podmanClient.StartContainer(containerPcapRingWriter, "pcap_manager_rollback"); err != nil {
			log.Printf("pcap: rollback: failed to start %s: %v", containerPcapRingWriter, err)
		} else {
			m.containerStates[containerPcapRingWriter] = string(podman.StateRunning)
		}
	default:
		log.Printf("pcap: rollback: unknown previous mode %q, skipping", previousMode)
	}
}

// storageFreePercent returns the percentage of free storage at the given path.
func storageFreePercent(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	total := stat.Blocks * uint64(stat.Bsize)
	if total == 0 {
		return 100, nil // empty filesystem treated as fully free
	}
	avail := stat.Bavail * uint64(stat.Bsize)
	return float64(avail) / float64(total) * 100, nil
}

// HandleAlert processes a qualifying alert event and triggers a PCAP carve.
func (m *Manager) HandleAlert(alert AlertEvent) error {
	if m.mode != "alert_driven" {
		return nil
	}
	if alert.Severity > m.severityThresh {
		return nil
	}

	// Deduplicate: discard if the same (community_id, sid, sensor_id) was seen
	// within the configured dedup window.
	if m.dedup != nil && m.dedup.IsDuplicate(alert.CommunityID, alert.SID, m.sensorID) {
		log.Printf("pcap: dedup: discarding duplicate alert community_id=%q sid=%q", alert.CommunityID, alert.SID)
		return nil
	}

	// Update the health endpoint's dedup cache size counter.
	if m.listener != nil && m.dedup != nil {
		m.listener.SetDedupSize(int64(m.dedup.Size()))
	}

	alertTimeMs := alert.TimestampMs
	if alertTimeMs == 0 {
		alertTimeMs = time.Now().UnixMilli()
	}

	preAlertMs := alertTimeMs - m.preAlertMs

	// Mark pre-alert window in ring writer (timestamp in nanoseconds)
	preAlertNs := preAlertMs * int64(time.Millisecond)
	if err := m.sendToRing(ringctl.MarkPreAlertCmd{
		Cmd:         "mark_pre_alert",
		TimestampNs: preAlertNs,
	}); err != nil {
		return fmt.Errorf("mark_pre_alert: %w", err)
	}

	// Wait for post-alert window
	time.Sleep(time.Duration(m.postAlertMs) * time.Millisecond)

	postAlertNs := time.Now().UnixNano()

	// Carve the window
	outputPath := filepath.Join(m.alertsDir,
		fmt.Sprintf("alert_%s_%d.pcap", sanitizeCommunityID(alert.CommunityID), alertTimeMs))

	if err := os.MkdirAll(m.alertsDir, 0755); err != nil {
		return fmt.Errorf("create alerts dir: %w", err)
	}

	result, err := m.carveFromRing(preAlertNs, postAlertNs, outputPath)
	if err != nil {
		return fmt.Errorf("carve window: %w", err)
	}

	// Compute SHA256 hash of the carved PCAP file (Requirement 9.2).
	fileHash, err := HashFile(outputPath)
	if err != nil {
		log.Printf("pcap: failed to hash carved file %s: %v", outputPath, err)
		fileHash = ""
	}

	// Get file size (Requirement 9.1).
	fileSizeBytes, err := FileSizeBytes(outputPath)
	if err != nil {
		log.Printf("pcap: failed to stat carved file %s: %v", outputPath, err)
		fileSizeBytes = 0
	}

	// Generate Chain_of_Custody_Manifest (Requirement 9.3).
	manifestPath := ManifestPathForPcap(outputPath)
	if err := WriteCreatedManifest(manifestPath, "system", alert.SID, alert.UUID, fileHash); err != nil {
		log.Printf("pcap: failed to write custody manifest for %s: %v", outputPath, err)
		manifestPath = ""
	}

	createdAtMs := time.Now().UnixMilli()

	// Index the carved file
	_, err = m.index.Insert(PcapFile{
		FilePath:                   outputPath,
		StartTime:                  preAlertNs / int64(time.Millisecond),
		EndTime:                    postAlertNs / int64(time.Millisecond),
		Interface:                  os.Getenv("CAPTURE_IFACE"),
		PacketCount:                int64(result.PacketCount),
		AlertDriven:                true,
		CommunityID:                alert.CommunityID,
		SensorID:                   m.sensorID,
		AlertSID:                   alert.SID,
		AlertSignature:             alert.Signature,
		AlertUUID:                  alert.UUID,
		SrcIP:                      alert.SrcIP,
		DstIP:                      alert.DstIP,
		SrcPort:                    alert.SrcPort,
		DstPort:                    alert.DstPort,
		Proto:                      alert.Proto,
		ZeekUID:                    alert.ZeekUID,
		CaptureInterface:           os.Getenv("CAPTURE_IFACE"),
		CarveReason:                "alert",
		RequestedBy:                "system",
		CreatedAtMs:                createdAtMs,
		RetentionExpiresAtMs:       m.retentionExpiresAt(createdAtMs),
		Sha256Hash:                 fileHash,
		FileSizeBytes:              fileSizeBytes,
		ChainOfCustodyManifestPath: manifestPath,
	})
	if err != nil {
		log.Printf("pcap: failed to index carved file: %v", err)
	}

	m.auditLog.Log("pcap-carve", "system", "success", map[string]any{
		"output":       outputPath,
		"packets":      result.PacketCount,
		"community_id": alert.CommunityID,
		"sha256_hash":  fileHash,
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

	// Compute SHA256 hash of the carved PCAP file (Requirement 9.2).
	fileHash, err := HashFile(outputPath)
	if err != nil {
		log.Printf("pcap: failed to hash carved file %s: %v", outputPath, err)
		fileHash = ""
	}

	fileSizeBytes, err := FileSizeBytes(outputPath)
	if err != nil {
		log.Printf("pcap: failed to stat carved file %s: %v", outputPath, err)
		fileSizeBytes = 0
	}

	// Generate Chain_of_Custody_Manifest (Requirement 9.3).
	manifestPath := ManifestPathForPcap(outputPath)
	if err := WriteCreatedManifest(manifestPath, "api", "", "", fileHash); err != nil {
		log.Printf("pcap: failed to write custody manifest for %s: %v", outputPath, err)
		manifestPath = ""
	}

	createdAtMs := time.Now().UnixMilli()
	if _, err := m.index.Insert(PcapFile{
		FilePath:                   outputPath,
		StartTime:                  result.StartTimeMs,
		EndTime:                    result.EndTimeMs,
		Interface:                  os.Getenv("CAPTURE_IFACE"),
		PacketCount:                int64(result.PacketCount),
		ByteCount:                  fileSizeBytes,
		AlertDriven:                false,
		CommunityID:                req.CommunityID,
		SensorID:                   m.sensorID,
		CaptureInterface:           os.Getenv("CAPTURE_IFACE"),
		CarveReason:                "api",
		RequestedBy:                "api",
		CreatedAtMs:                createdAtMs,
		RetentionExpiresAtMs:       m.retentionExpiresAt(createdAtMs),
		Sha256Hash:                 fileHash,
		FileSizeBytes:              fileSizeBytes,
		ChainOfCustodyManifestPath: manifestPath,
	}); err != nil {
		log.Printf("pcap: failed to index carved file: %v", err)
	}

	go m.pruneIfNeeded()

	result.CommunityID = req.CommunityID
	return result, nil
}

func (m *Manager) retentionExpiresAt(createdAtMs int64) int64 {
	if m.retentionDuration <= 0 {
		return 0
	}
	return createdAtMs + int64(m.retentionDuration/time.Millisecond)
}

// AccessPcap records an access event in the Chain_of_Custody_Manifest for the
// given PCAP file. actor identifies who is accessing the file, and purpose
// describes why (e.g. "investigation", "export"). This should be called
// whenever a PCAP file is accessed via the carve API (Requirement 9.4).
func (m *Manager) AccessPcap(pcapFilePath, actor, purpose string) error {
	// Look up the index entry to find the manifest path.
	manifestPath := ""

	// Try to find the manifest path from the index by matching file path.
	files, err := m.index.QueryByFilePath(pcapFilePath)
	if err == nil && len(files) > 0 && files[0].ChainOfCustodyManifestPath != "" {
		manifestPath = files[0].ChainOfCustodyManifestPath
	}

	// Fall back to the conventional manifest path if not in the index.
	if manifestPath == "" {
		manifestPath = ManifestPathForPcap(pcapFilePath)
	}

	if err := AppendAccessEvent(manifestPath, actor, purpose); err != nil {
		return fmt.Errorf("append access event to manifest: %w", err)
	}

	m.auditLog.Log("pcap-access", actor, "success", map[string]any{
		"file":    pcapFilePath,
		"purpose": purpose,
	})

	return nil
}

// AccessPcapByID records an access event for a PCAP file looked up by its
// index ID. Returns the PcapFile record for the caller to serve.
func (m *Manager) AccessPcapByID(id int64, actor, purpose string) (*PcapFile, error) {
	file, err := m.index.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("lookup pcap file %d: %w", id, err)
	}

	manifestPath := file.ChainOfCustodyManifestPath
	if manifestPath == "" {
		manifestPath = ManifestPathForPcap(file.FilePath)
	}

	// Only append if the manifest file exists (it won't for pre-existing files
	// carved before this feature was added).
	if _, statErr := os.Stat(manifestPath); statErr == nil {
		if err := AppendAccessEvent(manifestPath, actor, purpose); err != nil {
			log.Printf("pcap: failed to append access event to manifest %s: %v", manifestPath, err)
		}
	}

	m.auditLog.Log("pcap-access", actor, "success", map[string]any{
		"file_id": id,
		"file":    file.FilePath,
		"purpose": purpose,
	})

	return file, nil
}

// carveFromRing sends a carve_window command to pcap_ring_writer.
func (m *Manager) carveFromRing(preAlertNs, postAlertNs int64, outputPath string) (CarveResult, error) {
	resp, err := ringctl.DialAndSend(m.ringSocket, ringctl.CarveWindowCmd{
		Cmd:         "carve_window",
		PreAlertNs:  preAlertNs,
		PostAlertNs: postAlertNs,
		OutputPath:  outputPath,
	})
	if err != nil {
		return CarveResult{}, fmt.Errorf("carve_window command: %w", err)
	}

	if resp.Status != "ok" {
		return CarveResult{}, fmt.Errorf("carve_window failed: %s", resp.Error)
	}

	return CarveResult{
		OutputPath:  outputPath,
		PacketCount: resp.PacketCount,
		StartTimeMs: preAlertNs / int64(time.Millisecond),
		EndTimeMs:   postAlertNs / int64(time.Millisecond),
	}, nil
}

// sendToRing sends a command to pcap_ring_writer without using the response.
func (m *Manager) sendToRing(cmd interface{}) error {
	_, err := ringctl.DialAndSend(m.ringSocket, cmd)
	return err
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

// ListenForAlerts starts the Alert_Listener HTTP server and begins draining
// the alert queue in the background. addr defaults to ":9092" if empty.
// The listener runs until done is closed.
func (m *Manager) ListenForAlerts(addr string, done <-chan struct{}) {
	m.listener = NewAlertListener(addr, 0, m)
	m.listener.Start()

	go func() {
		for {
			select {
			case <-done:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := m.listener.Shutdown(ctx); err != nil {
					log.Printf("pcap: alert listener shutdown error: %v", err)
				}
				return
			case alert := <-m.listener.Queue():
				if err := m.HandleAlert(alert); err != nil {
					log.Printf("pcap: handle alert error: %v", err)
				}
			}
		}
	}()
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

// RetentionPruneStats holds the result of a retention pruning cycle.
type RetentionPruneStats struct {
	FilesDeleted   int
	EntriesDeleted int
	Errors         int
}

// PruneExpiredRetention deletes PCAP files and their index entries when
// retention_expires_at_ms is set and the current time exceeds it.
// nowMs is accepted as a parameter for testability (Requirement 9.5).
func (m *Manager) PruneExpiredRetention(nowMs int64) RetentionPruneStats {
	var stats RetentionPruneStats

	expired, err := m.index.QueryByRetentionExpired(nowMs)
	if err != nil {
		log.Printf("pcap: retention prune: failed to query expired entries: %v", err)
		stats.Errors++
		return stats
	}

	for _, f := range expired {
		// Delete the PCAP file from disk.
		if err := os.Remove(f.FilePath); err != nil && !os.IsNotExist(err) {
			log.Printf("pcap: retention prune: failed to delete file %s: %v", f.FilePath, err)
			stats.Errors++
			continue
		}
		if err == nil || os.IsNotExist(err) {
			stats.FilesDeleted++
		}

		// Delete the chain-of-custody manifest file if it exists.
		manifestPath := f.ChainOfCustodyManifestPath
		if manifestPath == "" {
			manifestPath = ManifestPathForPcap(f.FilePath)
		}
		if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
			log.Printf("pcap: retention prune: failed to delete manifest %s: %v", manifestPath, err)
		}

		// Delete the index entry.
		if err := m.index.DeleteByID(f.ID); err != nil {
			log.Printf("pcap: retention prune: failed to delete index entry %d: %v", f.ID, err)
			stats.Errors++
			continue
		}
		stats.EntriesDeleted++

		log.Printf("pcap: retention prune: deleted expired file %s (id=%d, expired_at=%d)",
			f.FilePath, f.ID, f.RetentionExpiresAtMs)
	}

	return stats
}

// StartRetentionPruner starts a background goroutine that runs
// PruneExpiredRetention on a configurable interval. The pruner stops when
// the provided context is cancelled.
func (m *Manager) StartRetentionPruner(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	log.Printf("pcap: retention pruner started (interval=%s)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("pcap: retention pruner stopped")
				return
			case <-ticker.C:
				stats := m.PruneExpiredRetention(time.Now().UnixMilli())
				if stats.FilesDeleted > 0 || stats.Errors > 0 {
					log.Printf("pcap: retention prune cycle: files_deleted=%d entries_deleted=%d errors=%d",
						stats.FilesDeleted, stats.EntriesDeleted, stats.Errors)
				}
			}
		}
	}()
}
