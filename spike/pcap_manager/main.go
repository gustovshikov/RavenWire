// pcap_manager — simulates an alert event and triggers a PCAP carve via pcap_ring_writer.
//
// Spike implementation: validates the alert → carve workflow end-to-end.
//
// Environment variables:
//   ALERT_DELAY_SECONDS       — seconds to wait before simulating alert (default: 10)
//   PRE_ALERT_WINDOW_SECONDS  — seconds before alert to include in carve (default: 5)
//   POST_ALERT_WINDOW_SECONDS — seconds after alert to wait before carving (default: 3)
//   CONTROL_SOCK              — path to pcap_ring_writer Unix socket (default: /var/run/pcap_ring.sock)
//
// Exit codes:
//   0 — success (carved PCAP written)
//   1 — failure

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// ── Control protocol (mirrors pcap_ring_writer) ───────────────────────────────

type controlCmd struct {
	Cmd         string `json:"cmd"`
	TimestampMs int64  `json:"timestamp_ms,omitempty"`
	PreAlertMs  int64  `json:"pre_alert_ms,omitempty"`
	PostAlertMs int64  `json:"post_alert_ms,omitempty"`
	OutputPath  string `json:"output_path,omitempty"`
}

type controlResp struct {
	Status      string                 `json:"status"`
	Error       string                 `json:"error,omitempty"`
	PacketCount int                    `json:"packet_count,omitempty"`
	OutputPath  string                 `json:"output_path,omitempty"`
	Stats       map[string]interface{} `json:"stats,omitempty"`
}

// sendCmd sends a single command to pcap_ring_writer and returns the response.
func sendCmd(sockPath string, cmd controlCmd) (controlResp, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return controlResp{}, fmt.Errorf("dial %s: %w", sockPath, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(cmd); err != nil {
		return controlResp{}, fmt.Errorf("encode cmd: %w", err)
	}

	var resp controlResp
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return controlResp{}, fmt.Errorf("decode resp: %w", err)
	}
	return resp, nil
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	controlSock := envOrDefault("CONTROL_SOCK", "/var/run/pcap_ring.sock")
	alertDelay := envIntOrDefault("ALERT_DELAY_SECONDS", 10)
	preWindow := envIntOrDefault("PRE_ALERT_WINDOW_SECONDS", 5)
	postWindow := envIntOrDefault("POST_ALERT_WINDOW_SECONDS", 3)

	log.Printf("pcap_manager: alert in %ds, pre-window=%ds, post-window=%ds",
		alertDelay, preWindow, postWindow)

	// Step 1: Wait for the simulated alert delay
	log.Printf("Waiting %d seconds before simulated alert...", alertDelay)
	time.Sleep(time.Duration(alertDelay) * time.Second)

	alertTime := time.Now()
	alertTimeMs := alertTime.UnixMilli()
	preAlertMs := alertTimeMs - int64(preWindow)*1000

	log.Printf("Simulated alert fired at %s", alertTime.Format(time.RFC3339))

	// Step 2: Send mark_pre_alert to pcap_ring_writer
	log.Printf("Sending mark_pre_alert (timestamp_ms=%d)...", preAlertMs)
	resp, err := sendCmd(controlSock, controlCmd{
		Cmd:         "mark_pre_alert",
		TimestampMs: preAlertMs,
	})
	if err != nil {
		log.Fatalf("mark_pre_alert failed: %v", err)
	}
	if resp.Status != "ok" {
		log.Fatalf("mark_pre_alert error: %s", resp.Error)
	}
	log.Println("Pre-alert mark acknowledged")

	// Step 3: Wait for post-alert window
	log.Printf("Waiting %d seconds for post-alert window...", postWindow)
	time.Sleep(time.Duration(postWindow) * time.Second)

	postAlertMs := time.Now().UnixMilli()

	// Step 4: Send carve_window
	outputPath := fmt.Sprintf("/tmp/alert_carve_%d.pcap", alertTimeMs)
	log.Printf("Sending carve_window: pre=%d post=%d output=%s", preAlertMs, postAlertMs, outputPath)

	resp, err = sendCmd(controlSock, controlCmd{
		Cmd:         "carve_window",
		PreAlertMs:  preAlertMs,
		PostAlertMs: postAlertMs,
		OutputPath:  outputPath,
	})
	if err != nil {
		log.Fatalf("carve_window failed: %v", err)
	}
	if resp.Status != "ok" {
		log.Fatalf("carve_window error: %s", resp.Error)
	}

	// Step 5: Report results
	fmt.Printf("carved_pcap_path=%s\n", resp.OutputPath)
	fmt.Printf("packet_count=%d\n", resp.PacketCount)
	log.Printf("Success: carved %d packets to %s", resp.PacketCount, resp.OutputPath)

	// Step 6: Query ring stats for verification
	statsResp, err := sendCmd(controlSock, controlCmd{Cmd: "status"})
	if err != nil {
		log.Printf("status query failed: %v", err)
	} else {
		statsJSON, _ := json.MarshalIndent(statsResp.Stats, "", "  ")
		log.Printf("Ring stats:\n%s", statsJSON)
	}

	os.Exit(0)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
