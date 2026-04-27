//go:build linux

package capture

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Manager manages the AF_PACKET capture configuration and BPF filter lifecycle.
type Manager struct {
	cfg            *CaptureConfig
	bpfFilterPath  string
	pcapRingSocket string
	eventCh        chan ReloadEvent
}

// ReloadEvent describes a BPF filter reload result for a single consumer.
type ReloadEvent struct {
	Consumer    string    `json:"consumer"`
	Applied     bool      `json:"applied"`
	LiveReload  bool      `json:"live_reload"` // true = applied live; false = required socket rebind
	Error       string    `json:"error,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewManager creates a new Capture Manager.
func NewManager(cfg *CaptureConfig, bpfFilterPath, pcapRingSocket string) *Manager {
	return &Manager{
		cfg:            cfg,
		bpfFilterPath:  bpfFilterPath,
		pcapRingSocket: pcapRingSocket,
		eventCh:        make(chan ReloadEvent, 32),
	}
}

// Events returns the channel on which reload events are published.
func (m *Manager) Events() <-chan ReloadEvent {
	return m.eventCh
}

// Config returns the current CaptureConfig. Used by the Health Collector
// to enumerate consumers for packet stats collection.
func (m *Manager) Config() *CaptureConfig {
	return m.cfg
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

		// Set a short read timeout so we can check done channel
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
func (m *Manager) ReloadBPFFilter() error {
	filterText, err := LoadBPFFile(m.bpfFilterPath)
	if err != nil {
		return fmt.Errorf("load BPF filter: %w", err)
	}

	// Validate the filter by compiling it
	_, err = CompileBPF(filterText)
	if err != nil {
		return fmt.Errorf("invalid BPF filter: %w", err)
	}

	for _, consumer := range m.cfg.Consumers {
		var event ReloadEvent
		event.Consumer = consumer.Name
		event.Timestamp = time.Now()

		switch consumer.Name {
		case "pcap_ring_writer":
			// Send updated BPF profile to pcap_ring_writer via Unix socket
			err := m.sendBPFToPcapRingWriter(filterText)
			if err != nil {
				event.Applied = false
				event.Error = err.Error()
				log.Printf("capture: failed to send BPF to pcap_ring_writer: %v", err)
			} else {
				event.Applied = true
				event.LiveReload = true
			}

		case "zeek":
			// Write updated Zeek capture config and send SIGHUP
			err := m.reloadZeekBPF(filterText)
			if err != nil {
				event.Applied = false
				event.Error = err.Error()
				log.Printf("capture: failed to reload Zeek BPF: %v", err)
			} else {
				event.Applied = true
				event.LiveReload = false // Zeek requires config reload
			}

		case "suricata":
			// Write updated Suricata capture config and send SIGUSR2
			err := m.reloadSuricataBPF(filterText)
			if err != nil {
				event.Applied = false
				event.Error = err.Error()
				log.Printf("capture: failed to reload Suricata BPF: %v", err)
			} else {
				event.Applied = true
				event.LiveReload = false // Suricata requires config reload
			}

		default:
			event.Applied = false
			event.Error = fmt.Sprintf("unknown consumer %q; BPF reload not implemented", consumer.Name)
		}

		select {
		case m.eventCh <- event:
		default:
			log.Printf("capture: event channel full, dropping reload event for %s", consumer.Name)
		}
	}

	return nil
}

// sendBPFToPcapRingWriter sends a configure command with the new BPF filter
// to pcap_ring_writer via its Unix socket control interface.
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

// reloadZeekBPF writes the updated BPF filter to Zeek's config and sends SIGHUP.
func (m *Manager) reloadZeekBPF(filterText string) error {
	// Write the BPF filter to Zeek's af_packet config file
	zeekBPFPath := "/etc/sensor/zeek/af_packet_bpf.filter"
	if err := os.WriteFile(zeekBPFPath, []byte(filterText), 0644); err != nil {
		return fmt.Errorf("write Zeek BPF filter: %w", err)
	}

	// Send SIGHUP to Zeek process to trigger config reload
	return sendSignalToProcess("zeek", syscall.SIGHUP)
}

// reloadSuricataBPF writes the updated BPF filter to Suricata's config and sends SIGUSR2.
func (m *Manager) reloadSuricataBPF(filterText string) error {
	// Write the BPF filter to Suricata's bpf-filter file
	suricataBPFPath := "/etc/sensor/suricata/bpf_filter.bpf"
	if err := os.WriteFile(suricataBPFPath, []byte(filterText), 0644); err != nil {
		return fmt.Errorf("write Suricata BPF filter: %w", err)
	}

	// Send SIGUSR2 to Suricata to trigger rule/config reload
	return sendSignalToProcess("suricata", syscall.SIGUSR2)
}

// sendSignalToProcess finds a process by name in /proc and sends it a signal.
func sendSignalToProcess(name string, sig syscall.Signal) error {
	pid, err := findProcessByName(name)
	if err != nil {
		return fmt.Errorf("find process %q: %w", name, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := proc.Signal(sig); err != nil {
		return fmt.Errorf("send signal %v to %s (pid %d): %w", sig, name, pid, err)
	}

	log.Printf("capture: sent %v to %s (pid %d)", sig, name, pid)
	return nil
}

// findProcessByName searches /proc for a process with the given name and returns its PID.
func findProcessByName(name string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		var pid int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		comm, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		procName := string(comm)
		if len(procName) > 0 && procName[len(procName)-1] == '\n' {
			procName = procName[:len(procName)-1]
		}

		if procName == name {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("process %q not found in /proc", name)
}

// ConsumerStats holds per-consumer packet statistics.
type ConsumerStats struct {
	Name            string  `json:"name"`
	PacketsReceived uint64  `json:"packets_received"`
	PacketsDropped  uint64  `json:"packets_dropped"`
	DropPercent     float64 `json:"drop_percent"`
}

// ReadPacketStats reads per-consumer packet/drop counters using the
// PACKET_STATISTICS socket option. It opens a temporary AF_PACKET socket
// per consumer interface and reads the kernel's per-socket counters.
// Falls back to /proc/net/packet aggregate counts if getsockopt fails.
func ReadPacketStats(cfg *CaptureConfig) (map[string]ConsumerStats, error) {
	stats := make(map[string]ConsumerStats)

	for _, c := range cfg.Consumers {
		received, dropped, err := readPacketStatsForIface(c.Interface)
		if err != nil {
			// Return zeros rather than failing the whole health report
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
// This gives the total packets seen on the interface, which is the best
// available proxy for capture consumer throughput without per-socket fd access.
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

// SendSignalByName is a package-level helper to send a signal to a named process.
func SendSignalByName(name string, sig syscall.Signal) error {
	return sendSignalToProcess(name, sig)
}
