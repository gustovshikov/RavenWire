// Package ringctl defines the JSON-over-Unix-socket Ring_Control_Protocol
// shared between PCAP_Manager (internal/pcap) and pcap_ring_writer.
// Both binaries import this package exclusively; neither defines protocol
// fields independently.
//
// All timestamp fields use Unix nanoseconds.
package ringctl

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"
)

// ── Command structs ───────────────────────────────────────────────────────────

// MarkPreAlertCmd instructs pcap_ring_writer to record the pre-alert boundary.
type MarkPreAlertCmd struct {
	Cmd         string `json:"cmd"`          // "mark_pre_alert"
	TimestampNs int64  `json:"timestamp_ns"` // Unix nanoseconds
}

// CarveWindowCmd instructs pcap_ring_writer to carve a PCAP window.
type CarveWindowCmd struct {
	Cmd         string `json:"cmd"`           // "carve_window"
	PreAlertNs  int64  `json:"pre_alert_ns"`  // Unix nanoseconds
	PostAlertNs int64  `json:"post_alert_ns"` // Unix nanoseconds
	OutputPath  string `json:"output_path"`
}

// ConfigureCmd sends a new BPF filter to pcap_ring_writer.
type ConfigureCmd struct {
	Cmd       string `json:"cmd"`        // "configure"
	BPFFilter string `json:"bpf_filter"`
}

// StatusCmd requests runtime statistics from pcap_ring_writer.
type StatusCmd struct {
	Cmd string `json:"cmd"` // "status"
}

// ── Response struct ───────────────────────────────────────────────────────────

// RingResponse is the JSON response returned by pcap_ring_writer for every command.
type RingResponse struct {
	Status                 string `json:"status"` // "ok" | "error"
	Error                  string `json:"error,omitempty"`
	PacketCount            int    `json:"packet_count,omitempty"`
	OutputPath             string `json:"output_path,omitempty"`
	PacketsWritten         uint64 `json:"packets_written,omitempty"`
	BytesWritten           uint64 `json:"bytes_written,omitempty"`
	WrapCount              uint64 `json:"wrap_count,omitempty"`
	SocketDrops            uint64 `json:"socket_drops,omitempty"`
	SocketFreezeQueueDrops uint64 `json:"socket_freeze_queue_drops,omitempty"`
}

// ── DialAndSend ───────────────────────────────────────────────────────────────

const (
	// sensorSvcUID is the UID of the sensor-svc user that owns the control socket.
	sensorSvcUID = 10000
	// requiredSocketPerm is the required permission bits for the control socket.
	requiredSocketPerm fs.FileMode = 0600
)

// DialAndSend verifies that socketPath is owned by UID 10000 (sensor-svc) or
// root (UID 0) and has permissions 0600, then dials the Unix socket, sends cmd
// as JSON, and decodes the JSON response into a RingResponse.
//
// Returns an error if the ownership or permission check fails, or if any
// network or encoding operation fails.
func DialAndSend(socketPath string, cmd interface{}) (RingResponse, error) {
	if err := verifySocket(socketPath); err != nil {
		return RingResponse{}, fmt.Errorf("ringctl: socket security check failed: %w", err)
	}

	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return RingResponse{}, fmt.Errorf("ringctl: dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return RingResponse{}, fmt.Errorf("ringctl: set deadline: %w", err)
	}

	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		return RingResponse{}, fmt.Errorf("ringctl: send command: %w", err)
	}

	var resp RingResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return RingResponse{}, fmt.Errorf("ringctl: read response: %w", err)
	}

	return resp, nil
}

// verifySocket checks that the socket file is owned by UID 10000 or root and
// has permissions exactly 0600.
func verifySocket(socketPath string) error {
	info, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", socketPath, err)
	}

	// Check permissions: must be exactly 0600.
	perm := info.Mode().Perm()
	if perm != requiredSocketPerm {
		return fmt.Errorf("socket %s has permissions %04o, want %04o",
			socketPath, perm, requiredSocketPerm)
	}

	// Check ownership: must be UID 10000 (sensor-svc) or 0 (root).
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine ownership of %s", socketPath)
	}
	uid := int(stat.Uid)
	if uid != 0 && uid != sensorSvcUID {
		return fmt.Errorf("socket %s is owned by UID %d, want %d (sensor-svc) or 0 (root)",
			socketPath, uid, sensorSvcUID)
	}

	return nil
}
