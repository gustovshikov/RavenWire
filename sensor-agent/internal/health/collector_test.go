//go:build linux

package health

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/capture"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/ringctl"
)

// --- Test helpers ---

// mockRingStatus returns a RingStatusFunc that returns the given response.
func mockRingStatus(resp ringctl.RingResponse, err error) RingStatusFunc {
	return func(socketPath string) (ringctl.RingResponse, error) {
		return resp, err
	}
}

// mockReadFile returns a readFile func that returns content for known paths.
func mockReadFile(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if content, ok := files[name]; ok {
			return []byte(content), nil
		}
		return nil, fmt.Errorf("file not found: %s", name)
	}
}

// mockReadDir returns a readDir func that returns entries for known directories.
func mockReadDir(dirs map[string][]os.DirEntry) func(string) ([]os.DirEntry, error) {
	return func(name string) ([]os.DirEntry, error) {
		if entries, ok := dirs[name]; ok {
			return entries, nil
		}
		return nil, fmt.Errorf("dir not found: %s", name)
	}
}

// mockStat returns a stat func that returns info for known paths.
func mockStat(infos map[string]os.FileInfo) func(string) (os.FileInfo, error) {
	return func(name string) (os.FileInfo, error) {
		if info, ok := infos[name]; ok {
			return info, nil
		}
		return nil, fmt.Errorf("stat not found: %s", name)
	}
}

// mockHTTPGet returns an httpGet func that returns a response with the given body.
func mockHTTPGet(body string, statusCode int, err error) func(string) (*http.Response, error) {
	return func(url string) (*http.Response, error) {
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
}

// --- Drop Alert Tests ---

func TestComputeDropAlert_AboveThreshold(t *testing.T) {
	c := &Collector{dropAlertThreshPct: 1.0}

	if !c.computeDropAlert("test-consumer", 1.5) {
		t.Error("expected DropAlert=true when dropPercent (1.5) > threshold (1.0)")
	}
}

func TestComputeDropAlert_AtThreshold(t *testing.T) {
	c := &Collector{dropAlertThreshPct: 1.0}

	// At exactly the threshold, should NOT trigger (> not >=)
	if c.computeDropAlert("test-consumer", 1.0) {
		t.Error("expected DropAlert=false when dropPercent (1.0) == threshold (1.0)")
	}
}

func TestComputeDropAlert_BelowThreshold(t *testing.T) {
	c := &Collector{dropAlertThreshPct: 1.0}

	if c.computeDropAlert("test-consumer", 0.5) {
		t.Error("expected DropAlert=false when dropPercent (0.5) < threshold (1.0)")
	}
}

func TestComputeDropAlert_ZeroDrops(t *testing.T) {
	c := &Collector{dropAlertThreshPct: 1.0}

	if c.computeDropAlert("test-consumer", 0.0) {
		t.Error("expected DropAlert=false when dropPercent is 0")
	}
}

func TestComputeDropAlert_CustomThreshold(t *testing.T) {
	c := &Collector{dropAlertThreshPct: 5.0}

	if c.computeDropAlert("test-consumer", 3.0) {
		t.Error("expected DropAlert=false when dropPercent (3.0) < threshold (5.0)")
	}
	if !c.computeDropAlert("test-consumer", 6.0) {
		t.Error("expected DropAlert=true when dropPercent (6.0) > threshold (5.0)")
	}
}

// --- Throughput Calculation Tests ---

func TestComputeThroughput_FirstInterval(t *testing.T) {
	c := &Collector{
		prevState: make(map[string]prevConsumerState),
	}

	now := time.Now()
	bps := c.computeThroughput("test", 1000, now)
	if bps != 0 {
		t.Errorf("expected 0 bps on first interval, got %f", bps)
	}
}

func TestComputeThroughput_SecondInterval(t *testing.T) {
	now := time.Now()
	c := &Collector{
		prevState: map[string]prevConsumerState{
			"test": {
				BytesWritten: 1000,
				Timestamp:    now.Add(-10 * time.Second),
			},
		},
	}

	// 2000 bytes delta over 10 seconds = 200 bytes/sec = 1600 bits/sec
	bps := c.computeThroughput("test", 3000, now)
	expected := float64(2000) * 8 / 10.0
	if bps != expected {
		t.Errorf("expected %f bps, got %f", expected, bps)
	}
}

func TestComputeThroughput_ZeroElapsed(t *testing.T) {
	now := time.Now()
	c := &Collector{
		prevState: map[string]prevConsumerState{
			"test": {
				BytesWritten: 1000,
				Timestamp:    now,
			},
		},
	}

	bps := c.computeThroughput("test", 2000, now)
	if bps != 0 {
		t.Errorf("expected 0 bps when elapsed is 0, got %f", bps)
	}
}

// --- Overwrite Risk Tests ---

func TestOverwriteRisk_WrapDeltaGreaterThanOne(t *testing.T) {
	c := &Collector{
		prevState: map[string]prevConsumerState{
			"pcap_ring_writer": {
				WrapCount: 5,
				Timestamp: time.Now().Add(-10 * time.Second),
			},
		},
		pcapRingSocket: "/tmp/test.sock",
		ringStatusFn: mockRingStatus(ringctl.RingResponse{
			Status:         "ok",
			PacketsWritten: 1000,
			BytesWritten:   50000,
			WrapCount:      8, // delta = 3 > 1
			SocketDrops:    10,
		}, nil),
		dropAlertThreshPct: 1.0,
		timeNow:            time.Now,
	}

	cs := &ConsumerStats{}
	c.scrapePcapRingWriterStats(cs)

	if !cs.OverwriteRisk {
		t.Error("expected OverwriteRisk=true when wrap_count delta (3) > 1")
	}
}

func TestOverwriteRisk_WrapDeltaExactlyOne(t *testing.T) {
	c := &Collector{
		prevState: map[string]prevConsumerState{
			"pcap_ring_writer": {
				WrapCount: 5,
				Timestamp: time.Now().Add(-10 * time.Second),
			},
		},
		pcapRingSocket: "/tmp/test.sock",
		ringStatusFn: mockRingStatus(ringctl.RingResponse{
			Status:         "ok",
			PacketsWritten: 1000,
			BytesWritten:   50000,
			WrapCount:      6, // delta = 1, not > 1
			SocketDrops:    0,
		}, nil),
		dropAlertThreshPct: 1.0,
		timeNow:            time.Now,
	}

	cs := &ConsumerStats{}
	c.scrapePcapRingWriterStats(cs)

	if cs.OverwriteRisk {
		t.Error("expected OverwriteRisk=false when wrap_count delta (1) == 1")
	}
}

func TestOverwriteRisk_NoPreviousState(t *testing.T) {
	c := &Collector{
		prevState:      make(map[string]prevConsumerState),
		pcapRingSocket: "/tmp/test.sock",
		ringStatusFn: mockRingStatus(ringctl.RingResponse{
			Status:         "ok",
			PacketsWritten: 1000,
			BytesWritten:   50000,
			WrapCount:      5,
			SocketDrops:    0,
		}, nil),
		dropAlertThreshPct: 1.0,
		timeNow:            time.Now,
	}

	cs := &ConsumerStats{}
	c.scrapePcapRingWriterStats(cs)

	if cs.OverwriteRisk {
		t.Error("expected OverwriteRisk=false when no previous state exists")
	}
}

// --- pcap_ring_writer Stats Tests ---

func TestScrapePcapRingWriterStats_Success(t *testing.T) {
	c := &Collector{
		prevState:      make(map[string]prevConsumerState),
		pcapRingSocket: "/tmp/test.sock",
		ringStatusFn: mockRingStatus(ringctl.RingResponse{
			Status:                 "ok",
			PacketsWritten:         5000,
			BytesWritten:           250000,
			WrapCount:              3,
			SocketDrops:            50,
			SocketFreezeQueueDrops: 5,
		}, nil),
		dropAlertThreshPct: 1.0,
		timeNow:            time.Now,
	}

	cs := &ConsumerStats{}
	c.scrapePcapRingWriterStats(cs)

	if cs.PacketsWritten != 5000 {
		t.Errorf("expected PacketsWritten=5000, got %d", cs.PacketsWritten)
	}
	if cs.BytesWritten != 250000 {
		t.Errorf("expected BytesWritten=250000, got %d", cs.BytesWritten)
	}
	if cs.WrapCount != 3 {
		t.Errorf("expected WrapCount=3, got %d", cs.WrapCount)
	}
	if cs.SocketDrops != 50 {
		t.Errorf("expected SocketDrops=50, got %d", cs.SocketDrops)
	}
	if cs.SocketFreezeQueueDrops != 5 {
		t.Errorf("expected SocketFreezeQueueDrops=5, got %d", cs.SocketFreezeQueueDrops)
	}
	if cs.PacketsReceived != 5000 {
		t.Errorf("expected PacketsReceived=5000, got %d", cs.PacketsReceived)
	}
	if cs.PacketsDropped != 50 {
		t.Errorf("expected PacketsDropped=50, got %d", cs.PacketsDropped)
	}
}

func TestScrapePcapRingWriterStats_NoSocket(t *testing.T) {
	c := &Collector{
		prevState:      make(map[string]prevConsumerState),
		pcapRingSocket: "", // no socket configured
	}

	cs := &ConsumerStats{}
	c.scrapePcapRingWriterStats(cs)

	if cs.PacketsWritten != 0 {
		t.Errorf("expected PacketsWritten=0 when no socket, got %d", cs.PacketsWritten)
	}
}

func TestScrapePcapRingWriterStats_Error(t *testing.T) {
	c := &Collector{
		prevState:      make(map[string]prevConsumerState),
		pcapRingSocket: "/tmp/test.sock",
		ringStatusFn:   mockRingStatus(ringctl.RingResponse{}, fmt.Errorf("connection refused")),
	}

	cs := &ConsumerStats{}
	c.scrapePcapRingWriterStats(cs)

	if cs.PacketsWritten != 0 {
		t.Errorf("expected PacketsWritten=0 on error, got %d", cs.PacketsWritten)
	}
}

// --- Suricata Stats Tests ---

func TestScrapeSuricataStats_Success(t *testing.T) {
	eveContent := `{"event_type":"alert","src_ip":"1.2.3.4"}
{"event_type":"stats","stats":{"capture":{"kernel_packets":100000,"kernel_drops":50,"kernel_ifdrops":5}}}
{"event_type":"alert","src_ip":"5.6.7.8"}
{"event_type":"stats","stats":{"capture":{"kernel_packets":200000,"kernel_drops":100,"kernel_ifdrops":10}}}
`
	c := &Collector{
		suricataEVEPath: "/var/log/suricata/eve.json",
		readFile:        mockReadFile(map[string]string{"/var/log/suricata/eve.json": eveContent}),
	}

	cs := &ConsumerStats{}
	c.scrapeSuricataStats(cs)

	// Should use the LAST stats event
	if cs.KernelPackets != 200000 {
		t.Errorf("expected KernelPackets=200000, got %d", cs.KernelPackets)
	}
	if cs.KernelDrops != 100 {
		t.Errorf("expected KernelDrops=100, got %d", cs.KernelDrops)
	}
	if cs.KernelIfdrops != 10 {
		t.Errorf("expected KernelIfdrops=10, got %d", cs.KernelIfdrops)
	}
}

func TestScrapeSuricataStats_NoStatsEvent(t *testing.T) {
	eveContent := `{"event_type":"alert","src_ip":"1.2.3.4"}
{"event_type":"alert","src_ip":"5.6.7.8"}
`
	c := &Collector{
		suricataEVEPath: "/var/log/suricata/eve.json",
		readFile:        mockReadFile(map[string]string{"/var/log/suricata/eve.json": eveContent}),
	}

	cs := &ConsumerStats{}
	c.scrapeSuricataStats(cs)

	// Should remain zero when no stats event found
	if cs.KernelPackets != 0 {
		t.Errorf("expected KernelPackets=0, got %d", cs.KernelPackets)
	}
}

func TestScrapeSuricataStats_NoPath(t *testing.T) {
	c := &Collector{
		suricataEVEPath: "",
	}

	cs := &ConsumerStats{}
	c.scrapeSuricataStats(cs)

	if cs.KernelPackets != 0 {
		t.Errorf("expected KernelPackets=0 when no path, got %d", cs.KernelPackets)
	}
}

// --- Vector Stats Tests ---

func TestScrapeVectorStats_Success(t *testing.T) {
	metricsBody := `{
		"components_received_events_total": [
			{"name": "source_zeek", "value": 1000},
			{"name": "source_suricata", "value": 500}
		],
		"sinks": [
			{"name": "splunk_hec", "connected": true},
			{"name": "cribl_http", "connected": false}
		],
		"disk_buffer_usage": {
			"used_bytes": 500000,
			"total_bytes": 1000000
		}
	}`

	c := &Collector{
		vectorMetricsURL: "http://localhost:9598/metrics",
		httpGet:          mockHTTPGet(metricsBody, 200, nil),
		interval:         10 * time.Second,
	}

	consumers := map[string]ConsumerStats{
		"vector": {},
	}
	c.scrapeVectorStats(consumers)

	cs := consumers["vector"]
	// 1500 total events / 10 seconds = 150 per sec
	if cs.RecordsIngestedPerSec != 150.0 {
		t.Errorf("expected RecordsIngestedPerSec=150.0, got %f", cs.RecordsIngestedPerSec)
	}
	if cs.SinkConnectivity["splunk_hec"] != "connected" {
		t.Errorf("expected splunk_hec=connected, got %s", cs.SinkConnectivity["splunk_hec"])
	}
	if cs.SinkConnectivity["cribl_http"] != "disconnected" {
		t.Errorf("expected cribl_http=disconnected, got %s", cs.SinkConnectivity["cribl_http"])
	}
	if cs.DiskBufferUtilPct != 50.0 {
		t.Errorf("expected DiskBufferUtilPct=50.0, got %f", cs.DiskBufferUtilPct)
	}
}

func TestScrapeVectorStats_NoURL(t *testing.T) {
	c := &Collector{
		vectorMetricsURL: "",
	}

	consumers := map[string]ConsumerStats{}
	c.scrapeVectorStats(consumers)

	if _, ok := consumers["vector"]; ok {
		t.Error("expected no vector entry when URL is empty")
	}
}

// --- ToProto Tests ---

func TestToProto_MapsNewFields(t *testing.T) {
	report := HealthReport{
		SensorPodID:     "test-pod",
		TimestampUnixMs: 1700000000000,
		Capture: CaptureStats{
			Consumers: map[string]ConsumerStats{
				"pcap_ring_writer": {
					PacketsReceived:        5000,
					PacketsDropped:         50,
					DropPercent:            0.99,
					ThroughputBps:          8000000,
					BpfRestartPending:      false,
					PacketsWritten:         5000,
					BytesWritten:           250000,
					WrapCount:              3,
					SocketDrops:            50,
					SocketFreezeQueueDrops: 5,
					OverwriteRisk:          true,
					DropAlert:              false,
				},
			},
		},
	}

	pb := report.ToProto()
	cs := pb.Capture.Consumers["pcap_ring_writer"]

	if cs.PacketsWritten != 5000 {
		t.Errorf("proto PacketsWritten: expected 5000, got %d", cs.PacketsWritten)
	}
	if cs.BytesWritten != 250000 {
		t.Errorf("proto BytesWritten: expected 250000, got %d", cs.BytesWritten)
	}
	if cs.WrapCount != 3 {
		t.Errorf("proto WrapCount: expected 3, got %d", cs.WrapCount)
	}
	if cs.SocketDrops != 50 {
		t.Errorf("proto SocketDrops: expected 50, got %d", cs.SocketDrops)
	}
	if cs.SocketFreezeQueueDrops != 5 {
		t.Errorf("proto SocketFreezeQueueDrops: expected 5, got %d", cs.SocketFreezeQueueDrops)
	}
	if !cs.OverwriteRisk {
		t.Error("proto OverwriteRisk: expected true")
	}
	if cs.DropAlert {
		t.Error("proto DropAlert: expected false")
	}
	if cs.ThroughputBps != 8000000 {
		t.Errorf("proto ThroughputBps: expected 8000000, got %f", cs.ThroughputBps)
	}
}

// --- NewCollectorWithConfig Tests ---

func TestNewCollectorWithConfig_SetsFields(t *testing.T) {
	cfg := CollectorConfig{
		PcapRingSocket:     "/var/run/sensor/pcap_ring.sock",
		DropAlertThreshPct: 2.5,
		SuricataEVEPath:    "/var/log/suricata/eve.json",
		ZeekLogDir:         "/var/log/zeek",
		VectorMetricsURL:   "http://localhost:9598/metrics",
	}

	c := NewCollectorWithConfig(nil, nil, cfg)

	if c.pcapRingSocket != "/var/run/sensor/pcap_ring.sock" {
		t.Errorf("expected pcapRingSocket=/var/run/sensor/pcap_ring.sock, got %s", c.pcapRingSocket)
	}
	if c.dropAlertThreshPct != 2.5 {
		t.Errorf("expected dropAlertThreshPct=2.5, got %f", c.dropAlertThreshPct)
	}
	if c.suricataEVEPath != "/var/log/suricata/eve.json" {
		t.Errorf("expected suricataEVEPath=/var/log/suricata/eve.json, got %s", c.suricataEVEPath)
	}
	if c.zeekLogDir != "/var/log/zeek" {
		t.Errorf("expected zeekLogDir=/var/log/zeek, got %s", c.zeekLogDir)
	}
	if c.vectorMetricsURL != "http://localhost:9598/metrics" {
		t.Errorf("expected vectorMetricsURL=http://localhost:9598/metrics, got %s", c.vectorMetricsURL)
	}
}

func TestNewCollectorWithConfig_DefaultThreshold(t *testing.T) {
	cfg := CollectorConfig{}
	c := NewCollectorWithConfig(nil, nil, cfg)

	if c.dropAlertThreshPct != 1.0 {
		t.Errorf("expected default dropAlertThreshPct=1.0, got %f", c.dropAlertThreshPct)
	}
}

// --- JSON Serialization Test ---

func TestConsumerStats_JSONRoundTrip(t *testing.T) {
	original := ConsumerStats{
		PacketsReceived:        5000,
		PacketsDropped:         50,
		DropPercent:            0.99,
		ThroughputBps:          8000000,
		BpfRestartPending:      true,
		PacketsWritten:         5000,
		BytesWritten:           250000,
		WrapCount:              3,
		SocketDrops:            50,
		SocketFreezeQueueDrops: 5,
		OverwriteRisk:          true,
		KernelPackets:          100000,
		KernelDrops:            100,
		KernelIfdrops:          10,
		UptimeSeconds:          3600,
		LogWriteLagMs:          500,
		Degraded:               false,
		RecordsIngestedPerSec:  150.0,
		SinkConnectivity:       map[string]string{"splunk": "connected"},
		DiskBufferUtilPct:      50.0,
		DropAlert:              true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ConsumerStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.PacketsWritten != original.PacketsWritten {
		t.Errorf("PacketsWritten mismatch: %d != %d", decoded.PacketsWritten, original.PacketsWritten)
	}
	if decoded.OverwriteRisk != original.OverwriteRisk {
		t.Errorf("OverwriteRisk mismatch: %v != %v", decoded.OverwriteRisk, original.OverwriteRisk)
	}
	if decoded.DropAlert != original.DropAlert {
		t.Errorf("DropAlert mismatch: %v != %v", decoded.DropAlert, original.DropAlert)
	}
	if decoded.KernelPackets != original.KernelPackets {
		t.Errorf("KernelPackets mismatch: %d != %d", decoded.KernelPackets, original.KernelPackets)
	}
	if decoded.RecordsIngestedPerSec != original.RecordsIngestedPerSec {
		t.Errorf("RecordsIngestedPerSec mismatch: %f != %f", decoded.RecordsIngestedPerSec, original.RecordsIngestedPerSec)
	}
}

// --- Property-Based Tests ---

// Property 12: Health report drop alert flag accuracy
//
// For any capture consumer whose drop_percent exceeds drop_alert_thresh_pct,
// the health report SHALL include drop_alert: true for that consumer;
// consumers below the threshold SHALL have drop_alert: false.
//
// **Validates: Requirements 7.7**

// TestProperty12_HealthReportDropAlertFlagAccuracy tests the computeDropAlert
// function directly with randomly generated drop percentages and thresholds.
func TestProperty12_HealthReportDropAlertFlagAccuracy(t *testing.T) {
	t.Run("direct_computeDropAlert", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			consumerName := rapid.StringMatching(`[a-z_]{1,32}`).Draw(t, "consumer_name")
			dropPercent := rapid.Float64Range(0.0, 100.0).Draw(t, "drop_percent")
			threshold := rapid.Float64Range(0.01, 100.0).Draw(t, "threshold")

			c := &Collector{dropAlertThreshPct: threshold}
			result := c.computeDropAlert(consumerName, dropPercent)

			if dropPercent > threshold {
				if !result {
					t.Fatalf("expected DropAlert=true when dropPercent (%.6f) > threshold (%.6f), got false",
						dropPercent, threshold)
				}
			} else {
				if result {
					t.Fatalf("expected DropAlert=false when dropPercent (%.6f) <= threshold (%.6f), got true",
						dropPercent, threshold)
				}
			}
		})
	})

	t.Run("integration_scrapeCaptureStats", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			packetsWritten := rapid.Uint64Range(0, 1_000_000).Draw(t, "packets_written")
			socketDrops := rapid.Uint64Range(0, 1_000_000).Draw(t, "socket_drops")
			threshold := rapid.Float64Range(0.01, 100.0).Draw(t, "threshold")

			// Compute expected drop percent using the same formula as the production code
			var expectedDropPercent float64
			totalPackets := packetsWritten + socketDrops
			if totalPackets > 0 {
				expectedDropPercent = float64(socketDrops) / float64(totalPackets) * 100
			}
			expectedDropAlert := expectedDropPercent > threshold

			cfg := &capture.CaptureConfig{
				Consumers: []capture.ConsumerConfig{
					{Name: "pcap_ring_writer", Interface: "eth_test"},
				},
			}
			mgr := capture.NewManager(cfg, "", "")

			c := &Collector{
				captureMgr:         mgr,
				pcapRingSocket:     "/tmp/test_prop12.sock",
				dropAlertThreshPct: threshold,
				prevState:          make(map[string]prevConsumerState),
				timeNow:            time.Now,
				ringStatusFn: mockRingStatus(ringctl.RingResponse{
					Status:         "ok",
					PacketsWritten: packetsWritten,
					BytesWritten:   packetsWritten * 100, // arbitrary bytes
					WrapCount:      0,
					SocketDrops:    socketDrops,
				}, nil),
			}

			stats := c.scrapeCaptureStats()

			cs, ok := stats.Consumers["pcap_ring_writer"]
			if !ok {
				t.Fatal("expected pcap_ring_writer in consumers map")
			}

			if cs.DropAlert != expectedDropAlert {
				t.Fatalf("DropAlert mismatch: got %v, want %v (dropPercent=%.6f, threshold=%.6f)",
					cs.DropAlert, expectedDropAlert, cs.DropPercent, threshold)
			}
		})
	})
}
