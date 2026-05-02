//go:build linux

package capture

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/podman"
	"golang.org/x/sys/unix"
)

// AuditLogger is the interface used by Manager to emit audit log entries.
// The real implementation is *audit.Logger; tests may inject a stub.
type AuditLogger interface {
	Log(action, actor, result string, detail map[string]any)
}

// BPFCompileFunc is the signature for a BPF filter compilation function.
// The default implementation is CompileBPF; tests may inject a stub that
// simulates compilation failures.
type BPFCompileFunc func(filter string) ([]unix.SockFilter, error)

// Manager manages the AF_PACKET capture configuration and BPF filter lifecycle.
type Manager struct {
	cfg            *CaptureConfig
	bpfFilterPath  string
	pcapRingSocket string
	eventCh        chan ReloadEvent
	podmanClient   *podman.Client
	auditLog       AuditLogger
	// bpfCompiler is the function used to compile BPF filters. Defaults to
	// CompileBPF; tests may override this to inject compilation failures.
	bpfCompiler BPFCompileFunc
	// restartTimeout is the timeout for container restart polling (default 30s).
	restartTimeout time.Duration
	// bpfRestartPending tracks per-consumer whether a BPF filter change has been
	// validated and written but the container restart has not yet completed.
	// Req 4.7: exposed to Config_Manager via the health report.
	bpfRestartMu      sync.RWMutex
	bpfRestartPending map[string]bool
}

// ReloadEvent describes a BPF filter reload result for a single consumer.
type ReloadEvent struct {
	Consumer        string    `json:"consumer"`
	Applied         bool      `json:"applied"`
	LiveReload      bool      `json:"live_reload"`      // true = applied live; false = required restart
	RestartRequired bool      `json:"restart_required"` // true = consumer required a container restart
	Error           string    `json:"error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// ManagerConfig holds optional dependencies for the Manager.
type ManagerConfig struct {
	PodmanClient   *podman.Client
	AuditLog       AuditLogger
	RestartTimeout time.Duration
	BPFCompiler    BPFCompileFunc
}

// NewManager creates a new Capture Manager.
func NewManager(cfg *CaptureConfig, bpfFilterPath, pcapRingSocket string) *Manager {
	return NewManagerWithConfig(cfg, bpfFilterPath, pcapRingSocket, ManagerConfig{})
}

// NewManagerWithConfig creates a new Capture Manager with optional dependencies.
func NewManagerWithConfig(cfg *CaptureConfig, bpfFilterPath, pcapRingSocket string, mcfg ManagerConfig) *Manager {
	timeout := mcfg.RestartTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	compiler := mcfg.BPFCompiler
	if compiler == nil {
		compiler = CompileBPF
	}
	return &Manager{
		cfg:               cfg,
		bpfFilterPath:     bpfFilterPath,
		pcapRingSocket:    pcapRingSocket,
		eventCh:           make(chan ReloadEvent, 32),
		podmanClient:      mcfg.PodmanClient,
		auditLog:          mcfg.AuditLog,
		bpfCompiler:       compiler,
		restartTimeout:    timeout,
		bpfRestartPending: make(map[string]bool),
	}
}

// Events returns the channel on which reload events are published.
func (m *Manager) Events() <-chan ReloadEvent {
	return m.eventCh
}

// Config returns the current CaptureConfig.
func (m *Manager) Config() *CaptureConfig {
	return m.cfg
}

// BPFRestartPending returns a copy of the per-consumer BPF restart pending state.
// A consumer has bpf_restart_pending=true when a BPF filter change has been
// validated and written but the container restart has not yet completed (Req 4.7).
func (m *Manager) BPFRestartPending() map[string]bool {
	m.bpfRestartMu.RLock()
	defer m.bpfRestartMu.RUnlock()
	result := make(map[string]bool, len(m.bpfRestartPending))
	for k, v := range m.bpfRestartPending {
		result[k] = v
	}
	return result
}

// WatchBPFFilter watches the BPF filter file for changes using inotify and
// triggers a reload on each modification. Blocks until done is closed.
func (m *Manager) WatchBPFFilter(done <-chan struct{}) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	defer unix.Close(fd)

	wd, err := unix.InotifyAddWatch(fd, m.bpfFilterPath,
		unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO)
	if err != nil {
		return fmt.Errorf("inotify_add_watch %s: %w", m.bpfFilterPath, err)
	}
	defer unix.InotifyRmWatch(fd, uint32(wd))

	log.Printf("capture: watching BPF filter file %s for changes", m.bpfFilterPath)

	buf := make([]byte, unix.SizeofInotifyEvent*16+unix.NAME_MAX+1)
	for {
		select {
		case <-done:
			return nil
		default:
		}

		tv := unix.Timeval{Sec: 1, Usec: 0}
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return fmt.Errorf("inotify read: %w", err)
		}
		if n < unix.SizeofInotifyEvent {
			continue
		}

		log.Printf("capture: BPF filter file changed, reloading")
		if err := m.ReloadBPFFilter(); err != nil {
			log.Printf("capture: BPF filter reload failed: %v", err)
		}
	}
}

// ReloadBPFFilter reads the current BPF filter file and applies it to all consumers.
// For Zeek and Suricata, this executes the safe restart sequence (Req 4.1, 4.4).
// For pcap_ring_writer, it sends the configure command (Req 4.6).
// Emits an audit log entry for every change (Req 4.8).
func (m *Manager) ReloadBPFFilter() error {
	return m.ApplyBPFFilter("")
}

// ApplyBPFFilter applies the given BPF filter text to all consumers.
// If filterText is empty, it reads from the configured bpfFilterPath.
// This is the main entry point for BPF filter changes.
func (m *Manager) ApplyBPFFilter(filterText string) error {
	// Read previous filter for audit log
	prevFilter, _ := m.readCurrentFilter()
	prevHash := filterHash(prevFilter)

	if filterText == "" {
		var err error
		filterText, err = LoadBPFFile(m.bpfFilterPath)
		if err != nil {
			return fmt.Errorf("load BPF filter: %w", err)
		}
	}

	newHash := filterHash(filterText)

	// Req 4.2: Validate the new BPF filter by compiling it to bytecode before
	// writing to any config file or initiating any restart sequence.
	_, err := m.bpfCompiler(filterText)
	if err != nil {
		// Req 4.3: Reject the change, log the compilation error, leave state unchanged.
		log.Printf("capture: BPF filter compilation failed, rejecting change: %v", err)
		m.emitAuditLog(prevHash, newHash, nil, err)
		return fmt.Errorf("invalid BPF filter: %w", err)
	}

	// Collect per-consumer results for audit log.
	// Fields are exported so JSON serialization includes them in the audit entry.
	type consumerResult struct {
		Name            string `json:"name"`
		RestartRequired bool   `json:"restart_required"`
		Error           string `json:"error,omitempty"`
	}
	var results []consumerResult

	for _, consumer := range m.cfg.Consumers {
		var event ReloadEvent
		event.Consumer = consumer.Name
		event.Timestamp = time.Now()

		switch consumer.Name {
		case "pcap_ring_writer":
			// Req 4.6: Send updated filter via configure command on Ring_Control_Protocol socket.
			// Live reload — no restart required.
			err := m.sendBPFToPcapRingWriter(filterText)
			if err != nil {
				event.Applied = false
				event.Error = err.Error()
				log.Printf("capture: failed to send BPF to pcap_ring_writer: %v", err)
			} else {
				event.Applied = true
				event.LiveReload = true
				event.RestartRequired = false
			}
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			results = append(results, consumerResult{Name: consumer.Name, RestartRequired: false, Error: errStr})

		case "zeek":
			// Req 4.1: Zeek BPF changes are restart-required; do NOT send SIGHUP.
			event.RestartRequired = true
			// Req 4.7: Mark restart pending before attempting restart.
			m.bpfRestartMu.Lock()
			m.bpfRestartPending[consumer.Name] = true
			m.bpfRestartMu.Unlock()
			err := m.safeRestartWithBPF(consumer.Name, filterText,
				zeekBPFPath, zeekContainerName)
			if err != nil {
				event.Applied = false
				event.Error = err.Error()
				log.Printf("capture: failed to apply BPF to zeek: %v", err)
				// Leave bpfRestartPending=true on failure
			} else {
				event.Applied = true
				event.LiveReload = false
				// Restart succeeded — clear pending flag.
				m.bpfRestartMu.Lock()
				m.bpfRestartPending[consumer.Name] = false
				m.bpfRestartMu.Unlock()
			}
			zeekErrStr := ""
			if err != nil {
				zeekErrStr = err.Error()
			}
			results = append(results, consumerResult{Name: consumer.Name, RestartRequired: true, Error: zeekErrStr})

		case "suricata":
			// Req 4.1: Suricata BPF changes are restart-required; do NOT send SIGUSR2.
			event.RestartRequired = true
			// Req 4.7: Mark restart pending before attempting restart.
			m.bpfRestartMu.Lock()
			m.bpfRestartPending[consumer.Name] = true
			m.bpfRestartMu.Unlock()
			err := m.safeRestartWithBPF(consumer.Name, filterText,
				suricataBPFPath, suricataContainerName)
			if err != nil {
				event.Applied = false
				event.Error = err.Error()
				log.Printf("capture: failed to apply BPF to suricata: %v", err)
				// Leave bpfRestartPending=true on failure
			} else {
				event.Applied = true
				event.LiveReload = false
				// Restart succeeded — clear pending flag.
				m.bpfRestartMu.Lock()
				m.bpfRestartPending[consumer.Name] = false
				m.bpfRestartMu.Unlock()
			}
			suricataErrStr := ""
			if err != nil {
				suricataErrStr = err.Error()
			}
			results = append(results, consumerResult{Name: consumer.Name, RestartRequired: true, Error: suricataErrStr})

		default:
			event.Applied = false
			event.Error = fmt.Sprintf("unknown consumer %q; BPF reload not implemented", consumer.Name)
			results = append(results, consumerResult{Name: consumer.Name, Error: fmt.Sprintf("unknown consumer %q; BPF reload not implemented", consumer.Name)})
		}

		select {
		case m.eventCh <- event:
		default:
			log.Printf("capture: event channel full, dropping reload event for %s", consumer.Name)
		}
	}

	// Req 4.8: Emit audit log entry for every BPF filter change.
	m.emitAuditLog(prevHash, newHash, results, nil)

	return nil
}

// BPF config paths and container names.
const (
	zeekBPFPath          = "/etc/sensor/zeek/af_packet_bpf.filter"
	zeekContainerName    = "zeek"
	suricataBPFPath      = "/etc/sensor/suricata/bpf_filter.bpf"
	suricataContainerName = "suricata"
)

// safeRestartWithBPF implements the safe restart sequence for Zeek/Suricata (Req 4.4, 4.5):
//  1. Write new filter config to staging path
//  2. Request container restart via Podman REST API
//  3. Poll until running or timeout (30s)
//  4. On timeout: restore previous filter, retry once
//  5. On second failure: log critical, report to Config_Manager health stream
func (m *Manager) safeRestartWithBPF(consumerName, filterText, configPath, containerName string) error {
	// Read previous filter for rollback
	prevFilter, prevReadErr := readFileContents(configPath)

	// Step 1: Write new filter config to staging path (Req 4.4)
	stagingPath := configPath + ".staging"
	if err := os.WriteFile(stagingPath, []byte(filterText), 0644); err != nil {
		return fmt.Errorf("write staging BPF filter for %s: %w", consumerName, err)
	}
	// Atomically move staging to live path
	if err := os.Rename(stagingPath, configPath); err != nil {
		os.Remove(stagingPath)
		return fmt.Errorf("rename staging BPF filter for %s: %w", consumerName, err)
	}

	log.Printf("capture: wrote new BPF filter for %s, requesting container restart", consumerName)

	// Step 2 & 3: Request restart and poll until running or timeout (Req 4.4)
	if err := m.restartAndWait(containerName); err != nil {
		// Step 4: On timeout, restore previous filter and retry once (Req 4.5)
		log.Printf("capture: container %s restart timed out, attempting rollback and retry", containerName)

		if prevReadErr == nil {
			if writeErr := os.WriteFile(configPath, []byte(prevFilter), 0644); writeErr != nil {
				log.Printf("capture: CRITICAL: failed to restore previous BPF filter for %s: %v", consumerName, writeErr)
			} else {
				log.Printf("capture: restored previous BPF filter for %s, retrying restart", consumerName)
			}
		}

		if retryErr := m.restartAndWait(containerName); retryErr != nil {
			// Step 5: Second failure — log critical and report to health stream (Req 4.5)
			log.Printf("capture: CRITICAL: container %s failed to restart after BPF filter change and rollback: %v", containerName, retryErr)
			m.reportCriticalFailure(consumerName, containerName, retryErr)
			return fmt.Errorf("container %s failed to restart after BPF change (with rollback): %w", containerName, retryErr)
		}

		// Retry succeeded but with old filter
		return fmt.Errorf("container %s restarted with previous BPF filter after timeout: %w", containerName, err)
	}

	log.Printf("capture: container %s restarted successfully with new BPF filter", containerName)
	return nil
}

// restartAndWait requests a container restart via Podman and polls until running
// or the configured timeout expires (Req 4.4).
func (m *Manager) restartAndWait(containerName string) error {
	if m.podmanClient == nil {
		return fmt.Errorf("no Podman client configured; cannot restart container %s", containerName)
	}

	_, err := m.podmanClient.RestartContainer(containerName, "capture-manager")
	if err != nil {
		return fmt.Errorf("restart container %s: %w", containerName, err)
	}

	// Poll until running or timeout
	deadline := time.Now().Add(m.restartTimeout)
	for time.Now().Before(deadline) {
		state, err := m.podmanClient.GetContainerState(containerName)
		if err == nil && state == podman.StateRunning {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("container %s did not reach running state within %s", containerName, m.restartTimeout)
}

// reportCriticalFailure logs a critical error and reports to the Config_Manager health stream.
func (m *Manager) reportCriticalFailure(consumerName, containerName string, err error) {
	log.Printf("capture: CRITICAL: BPF filter change failure for consumer %s (container %s): %v",
		consumerName, containerName, err)
	if m.auditLog != nil {
		m.auditLog.Log("bpf-filter-critical-failure", "capture-manager", "failure", map[string]any{
			"consumer":  consumerName,
			"container": containerName,
			"error":     err.Error(),
		})
	}
	// TODO: report to Config_Manager health stream via gRPC when health stream client is wired in
}

// sendBPFToPcapRingWriter sends a configure command with the new BPF filter
// to pcap_ring_writer via its Unix socket control interface (Req 4.6).
func (m *Manager) sendBPFToPcapRingWriter(filterText string) error {
	conn, err := net.DialTimeout("unix", m.pcapRingSocket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial pcap_ring_writer socket %s: %w", m.pcapRingSocket, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	cmd := map[string]interface{}{
		"cmd":        "configure",
		"bpf_filter": filterText,
	}
	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		return fmt.Errorf("send configure command: %w", err)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("read configure response: %w", err)
	}

	if status, _ := resp["status"].(string); status != "ok" {
		errMsg, _ := resp["error"].(string)
		return fmt.Errorf("pcap_ring_writer configure failed: %s", errMsg)
	}

	return nil
}

// emitAuditLog emits an audit log entry for a BPF filter change (Req 4.8).
// results may be nil for rejected (invalid) changes.
func (m *Manager) emitAuditLog(prevHash, newHash string, results interface{}, compilationErr error) {
	if m.auditLog == nil {
		return
	}

	detail := map[string]any{
		"prev_filter_hash": prevHash,
		"new_filter_hash":  newHash,
	}
	if compilationErr != nil {
		detail["compilation_error"] = compilationErr.Error()
		detail["rejected"] = true
	}
	if results != nil {
		detail["consumers"] = results
	}

	m.auditLog.Log("bpf-filter-change", "capture-manager", "applied", detail)
}

// readCurrentFilter reads the current BPF filter from the configured path.
func (m *Manager) readCurrentFilter() (string, error) {
	return LoadBPFFile(m.bpfFilterPath)
}

// readFileContents reads raw file contents (for rollback).
func readFileContents(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// filterHash returns the hex-encoded SHA-256 hash of a BPF filter string.
func filterHash(filter string) string {
	h := sha256.Sum256([]byte(filter))
	return fmt.Sprintf("%x", h)
}

// ConsumerStats holds per-consumer packet statistics.
type ConsumerStats struct {
	Name            string  `json:"name"`
	PacketsReceived uint64  `json:"packets_received"`
	PacketsDropped  uint64  `json:"packets_dropped"`
	DropPercent     float64 `json:"drop_percent"`
}

// ReadPacketStats reads per-consumer packet/drop counters.
func ReadPacketStats(cfg *CaptureConfig) (map[string]ConsumerStats, error) {
	stats := make(map[string]ConsumerStats)

	for _, c := range cfg.Consumers {
		received, dropped, err := readPacketStatsForIface(c.Interface)
		if err != nil {
			stats[c.Name] = ConsumerStats{Name: c.Name}
			continue
		}
		dropPct := 0.0
		if received+dropped > 0 {
			dropPct = float64(dropped) / float64(received+dropped) * 100
		}
		stats[c.Name] = ConsumerStats{
			Name:            c.Name,
			PacketsReceived: received,
			PacketsDropped:  dropped,
			DropPercent:     dropPct,
		}
	}

	return stats, nil
}

// readPacketStatsForIface reads aggregate RX packet and drop counters for
// a network interface from /sys/class/net/<iface>/statistics/.
func readPacketStatsForIface(iface string) (received, dropped uint64, err error) {
	if iface == "" {
		return 0, 0, fmt.Errorf("empty interface name")
	}

	rxPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface)
	dropPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_dropped", iface)
	missedPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_missed_errors", iface)

	rxData, err := os.ReadFile(rxPath)
	if err != nil {
		return 0, 0, fmt.Errorf("read rx_packets for %s: %w", iface, err)
	}
	fmt.Sscanf(string(rxData), "%d", &received)

	var dropped1, dropped2 uint64
	if dropData, e := os.ReadFile(dropPath); e == nil {
		fmt.Sscanf(string(dropData), "%d", &dropped1)
	}
	if missedData, e := os.ReadFile(missedPath); e == nil {
		fmt.Sscanf(string(missedData), "%d", &dropped2)
	}
	dropped = dropped1 + dropped2

	return received, dropped, nil
}

// SendSignalByName is kept for backward compatibility but is no longer used
// for BPF filter changes (Zeek/Suricata now use safe restart sequence).
func SendSignalByName(name string, sig interface{}) error {
	return fmt.Errorf("SendSignalByName: direct signal delivery for BPF changes is not supported; use safe restart sequence")
}
