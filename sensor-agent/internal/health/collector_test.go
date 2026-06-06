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

type testDirEntry struct {
	name string
	dir  bool
}

func (e testDirEntry) Name() string { return e.name }
func (e testDirEntry) IsDir() bool  { return e.dir }
func (e testDirEntry) Type() os.FileMode {
	if e.dir {
		return os.ModeDir
	}
	return 0
}
func (e testDirEntry) Info() (os.FileInfo, error) { return testFileInfo{name: e.name, dir: e.dir}, nil }

type testFileInfo struct {
	name  string
	dir   bool
	mtime time.Time
}

func (i testFileInfo) Name() string { return i.name }
func (i testFileInfo) Size() int64  { return 0 }
func (i testFileInfo) Mode() os.FileMode {
	if i.dir {
		return os.ModeDir
	}
	return 0
}
func (i testFileInfo) ModTime() time.Time { return i.mtime }
func (i testFileInfo) IsDir() bool        { return i.dir }
func (i testFileInfo) Sys() any           { return nil }

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

func TestComputeThroughput_CounterReset(t *testing.T) {
	now := time.Now()
	c := &Collector{
		prevState: map[string]prevConsumerState{
			"test": {
				BytesWritten: 5000,
				Timestamp:    now.Add(-10 * time.Second),
			},
		},
	}

	bps := c.computeThroughput("test", 1000, now)
	if bps != 0 {
		t.Errorf("expected 0 bps when byte counter resets, got %f", bps)
	}
}

func TestMergeInterfacePacketStatsReturnsBytesForThroughput(t *testing.T) {
	cs := &ConsumerStats{}
	bytesReceived := mergeInterfacePacketStats(cs, capture.ConsumerStats{
		PacketsReceived: 42,
		PacketsDropped:  2,
		BytesReceived:   123456,
		DropPercent:     4.5,
	})

	if bytesReceived != 123456 {
		t.Fatalf("bytesReceived = %d, want 123456", bytesReceived)
	}
	if cs.PacketsReceived != 42 {
		t.Fatalf("PacketsReceived = %d, want 42", cs.PacketsReceived)
	}
	if cs.PacketsDropped != 2 {
		t.Fatalf("PacketsDropped = %d, want 2", cs.PacketsDropped)
	}
	if cs.DropPercent != 4.5 {
		t.Fatalf("DropPercent = %f, want 4.5", cs.DropPercent)
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

func TestParseSuricataEVEStats_ExtractsDecoderAndNewestGlob(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	oldPath := "/var/log/suricata/eve-old.json"
	newPath := "/var/log/suricata/eve-new.json"
	oldContent := `{"timestamp":"1970-01-01T00:02:00.000000Z","event_type":"stats","stats":{"decoder":{"bytes":100,"pkts":10},"capture":{"kernel_packets":10,"kernel_drops":1,"kernel_ifdrops":0}}}`
	newContent := `{"event_type":"alert","src_ip":"1.2.3.4"}
{"timestamp":"1970-01-01T00:03:10.000000Z","event_type":"stats","stats":{"decoder":{"bytes":3000,"pkts":200},"capture":{"kernel_packets":200,"kernel_drops":4,"kernel_ifdrops":1}}}
`

	c := &Collector{
		readDir: mockReadDir(map[string][]os.DirEntry{
			"/var/log/suricata": {
				testDirEntry{name: "eve-old.json"},
				testDirEntry{name: "eve-new.json"},
			},
		}),
		readFile: mockReadFile(map[string]string{
			oldPath: oldContent,
			newPath: newContent,
		}),
		stat: mockStat(map[string]os.FileInfo{
			oldPath: testFileInfo{name: "eve-old.json", mtime: now.Add(-2 * time.Minute)},
			newPath: testFileInfo{name: "eve-new.json", mtime: now.Add(-10 * time.Second)},
		}),
		timeNow: func() time.Time { return now },
	}

	stats, err := c.parseSuricataEVEStats("/var/log/suricata/eve*.json")
	if err != nil {
		t.Fatalf("parseSuricataEVEStats: %v", err)
	}

	if stats.Stats.Decoder.Bytes != 3000 {
		t.Fatalf("Decoder.Bytes = %d, want 3000", stats.Stats.Decoder.Bytes)
	}
	if stats.Stats.Decoder.Pkts != 200 {
		t.Fatalf("Decoder.Pkts = %d, want 200", stats.Stats.Decoder.Pkts)
	}
	if stats.Stats.Capture.KernelDrops != 4 {
		t.Fatalf("KernelDrops = %d, want 4", stats.Stats.Capture.KernelDrops)
	}
	if stats.Stats.Capture.KernelIfdrops != 1 {
		t.Fatalf("KernelIfdrops = %d, want 1", stats.Stats.Capture.KernelIfdrops)
	}
	if !stats.Timestamp.Equal(time.Unix(190, 0).UTC()) {
		t.Fatalf("Timestamp = %s, want %s", stats.Timestamp, time.Unix(190, 0).UTC())
	}
}

func TestScrapeSuricataStats_ProcessRatesFirstSampleDeltaAndReset(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	body := `{"timestamp":"1970-01-01T00:03:10.000000Z","event_type":"stats","stats":{"decoder":{"bytes":1000,"pkts":100},"capture":{"kernel_packets":100,"kernel_drops":2,"kernel_ifdrops":1}}}`
	c := &Collector{
		suricataEVEPath:  "/var/log/suricata/eve.json",
		readFile:         func(string) ([]byte, error) { return []byte(body), nil },
		timeNow:          func() time.Time { return now },
		interval:         10 * time.Second,
		prevProcessState: make(map[string]prevProcessInputState),
	}

	first := &ConsumerStats{}
	c.scrapeSuricataStats(first)
	if first.ProcessTelemetrySource != "suricata eve stats" {
		t.Fatalf("first ProcessTelemetrySource = %q", first.ProcessTelemetrySource)
	}
	if first.ProcessThroughputBps != 0 || first.ProcessPacketsPerSec != 0 || first.ProcessDropPercent != 0 {
		t.Fatalf("first process rates should be zero, got bps=%f pps=%f drop=%f",
			first.ProcessThroughputBps, first.ProcessPacketsPerSec, first.ProcessDropPercent)
	}

	body = `{"timestamp":"1970-01-01T00:03:20.000000Z","event_type":"stats","stats":{"decoder":{"bytes":3000,"pkts":180},"capture":{"kernel_packets":180,"kernel_drops":4,"kernel_ifdrops":1}}}`
	second := &ConsumerStats{}
	c.scrapeSuricataStats(second)
	if second.ProcessThroughputBps != 1600 {
		t.Fatalf("ProcessThroughputBps = %f, want 1600", second.ProcessThroughputBps)
	}
	if second.ProcessPacketsPerSec != 8 {
		t.Fatalf("ProcessPacketsPerSec = %f, want 8", second.ProcessPacketsPerSec)
	}
	expectedDrop := float64(2) / float64(82) * 100
	if second.ProcessDropPercent != expectedDrop {
		t.Fatalf("ProcessDropPercent = %f, want %f", second.ProcessDropPercent, expectedDrop)
	}

	body = `{"timestamp":"1970-01-01T00:03:30.000000Z","event_type":"stats","stats":{"decoder":{"bytes":10,"pkts":5},"capture":{"kernel_packets":5,"kernel_drops":0,"kernel_ifdrops":0}}}`
	reset := &ConsumerStats{}
	c.scrapeSuricataStats(reset)
	if reset.ProcessThroughputBps != 0 || reset.ProcessPacketsPerSec != 0 || reset.ProcessDropPercent != 0 {
		t.Fatalf("reset process rates should be zero, got bps=%f pps=%f drop=%f",
			reset.ProcessThroughputBps, reset.ProcessPacketsPerSec, reset.ProcessDropPercent)
	}
}

func TestScrapeSuricataStats_StaleProcessTelemetryLeavesProcessFieldsEmpty(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	c := &Collector{
		suricataEVEPath: "/var/log/suricata/eve.json",
		readFile: mockReadFile(map[string]string{
			"/var/log/suricata/eve.json": `{"timestamp":"1970-01-01T00:01:00.000000Z","event_type":"stats","stats":{"decoder":{"bytes":1000,"pkts":100},"capture":{"kernel_packets":100,"kernel_drops":2,"kernel_ifdrops":1}}}`,
		}),
		timeNow:          func() time.Time { return now },
		interval:         10 * time.Second,
		prevProcessState: make(map[string]prevProcessInputState),
	}

	cs := &ConsumerStats{}
	c.scrapeSuricataStats(cs)
	if cs.ProcessTelemetrySource != "" {
		t.Fatalf("stale telemetry should not set source, got %q", cs.ProcessTelemetrySource)
	}
}

// --- Zeek Stats Tests ---

func TestParseZeekStatsLogAndApplyProcessRates(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	statsPath := "/var/log/zeek/stats.log"
	content := `{"ts":185.0,"bytes_recv":1000,"pkts_proc":50,"pkts_dropped":5}
{"ts":190.0,"bytes_recv":2000,"pkts_proc":80,"pkts_dropped":20}
`
	c := &Collector{
		zeekLogDir: "/var/log/zeek",
		readDir: mockReadDir(map[string][]os.DirEntry{
			"/var/log/zeek": {testDirEntry{name: "stats.log"}},
		}),
		readFile: mockReadFile(map[string]string{statsPath: content}),
		stat: mockStat(map[string]os.FileInfo{
			statsPath: testFileInfo{name: "stats.log", mtime: now.Add(-10 * time.Second)},
		}),
		timeNow:  func() time.Time { return now },
		interval: 10 * time.Second,
	}

	stats, err := c.parseZeekStatsLog("/var/log/zeek")
	if err != nil {
		t.Fatalf("parseZeekStatsLog: %v", err)
	}

	cs := &ConsumerStats{}
	c.applyZeekProcessStats(cs, stats)
	if cs.ProcessTelemetrySource != "zeek stats.log" {
		t.Fatalf("ProcessTelemetrySource = %q", cs.ProcessTelemetrySource)
	}
	if cs.ProcessThroughputBps != 1600 {
		t.Fatalf("ProcessThroughputBps = %f, want 1600", cs.ProcessThroughputBps)
	}
	if cs.ProcessPacketsPerSec != 8 {
		t.Fatalf("ProcessPacketsPerSec = %f, want 8", cs.ProcessPacketsPerSec)
	}
	expectedDrop := float64(20) / float64(100) * 100
	if cs.ProcessDropPercent != expectedDrop {
		t.Fatalf("ProcessDropPercent = %f, want %f", cs.ProcessDropPercent, expectedDrop)
	}
}

func TestParseZeekStatsLog_InvalidRowsProduceNoProcessTelemetry(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	statsPath := "/var/log/zeek/stats.log"
	c := &Collector{
		zeekLogDir: "/var/log/zeek",
		readDir: mockReadDir(map[string][]os.DirEntry{
			"/var/log/zeek": {testDirEntry{name: "stats.log"}},
		}),
		readFile: mockReadFile(map[string]string{
			statsPath: `{"ts":"not-a-time","bytes_recv":1000,"pkts_proc":10}`,
		}),
		stat: mockStat(map[string]os.FileInfo{
			statsPath: testFileInfo{name: "stats.log", mtime: now.Add(-10 * time.Second)},
		}),
		timeNow:  func() time.Time { return now },
		interval: 10 * time.Second,
	}

	if _, err := c.parseZeekStatsLog("/var/log/zeek"); err == nil {
		t.Fatal("expected invalid Zeek stats rows to return an error")
	}
}

func TestApplyZeekProcessStats_StaleTelemetryIgnored(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	c := &Collector{
		timeNow:  func() time.Time { return now },
		interval: 10 * time.Second,
	}

	cs := &ConsumerStats{}
	c.applyZeekProcessStats(cs, &zeekStatsRow{
		Timestamp:        now.Add(-2 * time.Minute),
		BytesRecv:        2000,
		PacketsProcessed: 80,
	})

	if cs.ProcessTelemetrySource != "" {
		t.Fatalf("stale telemetry should not set source, got %q", cs.ProcessTelemetrySource)
	}
}

// --- Vector Stats Tests ---

func TestScrapeVectorStats_Success(t *testing.T) {
	firstBody := `# HELP component_received_events_total Events received
vector_component_received_events_total{component_id="parse_zeek",component_type="transform"} 1000
vector_component_received_events_total{component_id="parse_suricata",component_type="transform"} 500
component_received_events_total{component_id="normalize",component_type="transform"} 999
disk_buffer_utilization_ratio 0.5
sink_connected{component_id="splunk_hec"} 1
sink_connected{component_id="cribl_http"} 0
`
	secondBody := `vector_component_received_events_total{component_id="parse_zeek",component_type="transform"} 1250
vector_component_received_events_total{component_id="parse_suricata",component_type="transform"} 700
disk_buffer_utilization_ratio 0.5
sink_connected{component_id="splunk_hec"} 1
sink_connected{component_id="cribl_http"} 0
`
	body := firstBody
	now := time.Unix(100, 0)
	c := &Collector{
		vectorMetricsURL: "http://localhost:9598/metrics",
		httpGet:          func(string) (*http.Response, error) { return mockHTTPGet(body, 200, nil)("ignored") },
		timeNow:          func() time.Time { return now },
	}

	first := c.scrapeVectorStats()
	if first.InputRecordsPerSec["zeek"] != 0 {
		t.Errorf("first sample should report zeek=0 rec/s, got %f", first.InputRecordsPerSec["zeek"])
	}
	if first.InputRecordsPerSec["suricata"] != 0 {
		t.Errorf("first sample should report suricata=0 rec/s, got %f", first.InputRecordsPerSec["suricata"])
	}
	if first.DiskBufferUtilPct != 50.0 {
		t.Errorf("expected DiskBufferUtilPct=50.0, got %f", first.DiskBufferUtilPct)
	}
	if first.SinkConnectivity["splunk_hec"] != "connected" {
		t.Errorf("expected splunk_hec=connected, got %s", first.SinkConnectivity["splunk_hec"])
	}
	if first.SinkConnectivity["cribl_http"] != "disconnected" {
		t.Errorf("expected cribl_http=disconnected, got %s", first.SinkConnectivity["cribl_http"])
	}

	body = secondBody
	now = now.Add(10 * time.Second)
	second := c.scrapeVectorStats()

	if second.InputRecordsPerSec["zeek"] != 25.0 {
		t.Errorf("expected zeek=25.0 rec/s, got %f", second.InputRecordsPerSec["zeek"])
	}
	if second.InputRecordsPerSec["suricata"] != 20.0 {
		t.Errorf("expected suricata=20.0 rec/s, got %f", second.InputRecordsPerSec["suricata"])
	}
	if second.TotalRecordsPerSec != 45.0 {
		t.Errorf("expected total=45.0 rec/s, got %f", second.TotalRecordsPerSec)
	}
}

func TestScrapeVectorStats_NoURL(t *testing.T) {
	c := &Collector{
		vectorMetricsURL: "",
	}

	stats := c.scrapeVectorStats()

	if vectorStatsPresent(stats) {
		t.Fatal("expected absent VectorStats when URL is empty")
	}
}

func TestScrapeVectorStats_ResetReportsZero(t *testing.T) {
	body := `vector_component_received_events_total{component_id="parse_zeek"} 1000`
	now := time.Unix(100, 0)
	c := &Collector{
		vectorMetricsURL: "http://localhost:9598/metrics",
		httpGet:          func(string) (*http.Response, error) { return mockHTTPGet(body, 200, nil)("ignored") },
		timeNow:          func() time.Time { return now },
	}

	_ = c.scrapeVectorStats()
	body = `vector_component_received_events_total{component_id="parse_zeek"} 10`
	now = now.Add(10 * time.Second)

	stats := c.scrapeVectorStats()
	if stats.InputRecordsPerSec["zeek"] != 0 {
		t.Errorf("counter reset should report zeek=0 rec/s, got %f", stats.InputRecordsPerSec["zeek"])
	}
}

func TestScrapeVectorStats_MissingEndpointIsAbsent(t *testing.T) {
	c := &Collector{
		vectorMetricsURL: "http://localhost:9598/metrics",
		httpGet:          mockHTTPGet("", 500, nil),
	}

	stats := c.scrapeVectorStats()
	if vectorStatsPresent(stats) {
		t.Fatal("expected absent VectorStats when scrape fails")
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
					ProcessThroughputBps:   1600,
					ProcessPacketsPerSec:   8,
					ProcessDropPercent:     2.5,
					ProcessTelemetrySource: "suricata eve stats",
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
		Vector: VectorStats{
			InputRecordsPerSec: map[string]float64{"zeek": 25, "suricata": 0},
			TotalRecordsPerSec: 25,
			DiskBufferUtilPct:  12.5,
			SinkConnectivity:   map[string]string{"splunk_hec": "connected"},
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
	if cs.ProcessThroughputBps != 1600 {
		t.Errorf("proto ProcessThroughputBps: expected 1600, got %f", cs.ProcessThroughputBps)
	}
	if cs.ProcessPacketsPerSec != 8 {
		t.Errorf("proto ProcessPacketsPerSec: expected 8, got %f", cs.ProcessPacketsPerSec)
	}
	if cs.ProcessDropPercent != 2.5 {
		t.Errorf("proto ProcessDropPercent: expected 2.5, got %f", cs.ProcessDropPercent)
	}
	if cs.ProcessTelemetrySource != "suricata eve stats" {
		t.Errorf("proto ProcessTelemetrySource: expected suricata eve stats, got %s", cs.ProcessTelemetrySource)
	}
	if pb.Vector == nil {
		t.Fatal("expected proto VectorStats")
	}
	if pb.Vector.InputRecordsPerSec["zeek"] != 25 {
		t.Errorf("proto Vector zeek rate: expected 25, got %f", pb.Vector.InputRecordsPerSec["zeek"])
	}
	if pb.Vector.InputRecordsPerSec["suricata"] != 0 {
		t.Errorf("proto Vector suricata rate: expected 0, got %f", pb.Vector.InputRecordsPerSec["suricata"])
	}
	if pb.Vector.TotalRecordsPerSec != 25 {
		t.Errorf("proto Vector total rate: expected 25, got %f", pb.Vector.TotalRecordsPerSec)
	}
	if pb.Vector.DiskBufferUtilPct != 12.5 {
		t.Errorf("proto Vector disk buffer: expected 12.5, got %f", pb.Vector.DiskBufferUtilPct)
	}
	if pb.Vector.SinkConnectivity["splunk_hec"] != "connected" {
		t.Errorf("proto Vector sink connectivity: expected connected, got %s", pb.Vector.SinkConnectivity["splunk_hec"])
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
		ProcessThroughputBps:   1600,
		ProcessPacketsPerSec:   8,
		ProcessDropPercent:     2.5,
		ProcessTelemetrySource: "suricata eve stats",
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
	if decoded.ProcessTelemetrySource != original.ProcessTelemetrySource {
		t.Errorf("ProcessTelemetrySource mismatch: %s != %s", decoded.ProcessTelemetrySource, original.ProcessTelemetrySource)
	}
	if decoded.ProcessThroughputBps != original.ProcessThroughputBps {
		t.Errorf("ProcessThroughputBps mismatch: %f != %f", decoded.ProcessThroughputBps, original.ProcessThroughputBps)
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

func TestContainerUptimeSecondsUsesStartedAtWallClock(t *testing.T) {
	now := time.Unix(1_700_000_300, 0)
	ct := podmanContainerInspect{
		State:     "running",
		StartedAt: 1_700_000_000,
	}

	if got := containerUptimeSeconds(ct, now); got != 300 {
		t.Fatalf("container uptime = %d, want 300", got)
	}
}

func TestContainerUptimeSecondsFallsBackToCreatedTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 3, 16, 10, 0, 0, time.UTC)
	ct := podmanContainerInspect{
		State:   "running",
		Created: "2026-05-03T16:06:30.000000000Z",
	}

	if got := containerUptimeSeconds(ct, now); got != 210 {
		t.Fatalf("container uptime = %d, want 210", got)
	}
}

func TestReadHostCPUPercentUsesProcStatDelta(t *testing.T) {
	reads := 0
	c := &Collector{
		readFile: func(name string) ([]byte, error) {
			if name != "/proc/stat" {
				return nil, fmt.Errorf("unexpected path %s", name)
			}
			reads++
			if reads == 1 {
				return []byte("cpu  100 0 100 800 0 0 0 0 0 0\n"), nil
			}
			return []byte("cpu  150 0 150 900 0 0 0 0 0 0\n"), nil
		},
	}

	if got, err := c.readHostCPUPercent(); err != nil || got != 0 {
		t.Fatalf("first CPU sample = %.2f, %v; want 0, nil", got, err)
	}

	got, err := c.readHostCPUPercent()
	if err != nil {
		t.Fatalf("second CPU sample returned error: %v", err)
	}
	if got != 50 {
		t.Fatalf("second CPU sample = %.2f, want 50.00", got)
	}
}

func TestReadMemoryStatsUsesMemAvailable(t *testing.T) {
	c := &Collector{
		readFile: mockReadFile(map[string]string{
			"/proc/meminfo": strings.Join([]string{
				"MemTotal:        2048 kB",
				"MemFree:          512 kB",
				"MemAvailable:    1024 kB",
				"",
			}, "\n"),
		}),
	}

	total, available, err := c.readMemoryStats()
	if err != nil {
		t.Fatalf("readMemoryStats returned error: %v", err)
	}
	if total != 2_097_152 || available != 1_048_576 {
		t.Fatalf("memory stats = total %d available %d, want 2097152 and 1048576", total, available)
	}
}

func TestDeriveSystemHealthThresholds(t *testing.T) {
	if got := deriveSystemHealth(SystemStats{CPUCount: 4, DiskUsedPercent: 63, MemoryUsedPercent: 40, Load1: 1}); got != "ok" {
		t.Fatalf("healthy system = %q, want ok", got)
	}
	if got := deriveSystemHealth(SystemStats{CPUCount: 4, DiskUsedPercent: 86, MemoryUsedPercent: 40, Load1: 1}); got != "warning" {
		t.Fatalf("warning system = %q, want warning", got)
	}
	if got := deriveSystemHealth(SystemStats{CPUCount: 4, DiskUsedPercent: 96, MemoryUsedPercent: 40, Load1: 1}); got != "critical" {
		t.Fatalf("critical system = %q, want critical", got)
	}
}
