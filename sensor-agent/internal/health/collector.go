//go:build linux

package health

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/capture"
	healthpb "github.com/ravenwire/ravenwire/sensor-agent/internal/health/proto"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/ringctl"
	"golang.org/x/sys/unix"
)

// HealthReport is the assembled health snapshot for a Sensor_Pod.
// This is the internal Go struct used by the Collector; the gRPC layer
// converts it to the protobuf HealthReport via ToProto().
type HealthReport struct {
	SensorPodID     string            `json:"sensor_pod_id"`
	TimestampUnixMs int64             `json:"timestamp_unix_ms"`
	Containers      []ContainerHealth `json:"containers"`
	Capture         CaptureStats      `json:"capture"`
	Storage         StorageStats      `json:"storage"`
	Clock           ClockStats        `json:"clock"`
	System          SystemStats       `json:"system"`
}

// ContainerHealth holds per-container health metrics.
type ContainerHealth struct {
	Name          string  `json:"name"`
	State         string  `json:"state"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryBytes   uint64  `json:"memory_bytes"`
}

// CaptureStats holds per-consumer AF_PACKET statistics.
type CaptureStats struct {
	Consumers map[string]ConsumerStats `json:"consumers"`
}

// ConsumerStats holds per-consumer packet counters and health metrics.
type ConsumerStats struct {
	PacketsReceived   uint64  `json:"packets_received"`
	PacketsDropped    uint64  `json:"packets_dropped"`
	DropPercent       float64 `json:"drop_percent"`
	ThroughputBps     float64 `json:"throughput_bps"`
	BpfRestartPending bool    `json:"bpf_restart_pending"` // Req 4.7

	// pcap_ring_writer specific (Req 7.1, 7.2)
	PacketsWritten         uint64 `json:"packets_written"`
	BytesWritten           uint64 `json:"bytes_written"`
	WrapCount              uint64 `json:"wrap_count"`
	SocketDrops            uint64 `json:"socket_drops"`
	SocketFreezeQueueDrops uint64 `json:"socket_freeze_queue_drops"`
	OverwriteRisk          bool   `json:"overwrite_risk"` // true when wrap_count delta > 1 since last interval

	// Suricata specific (Req 7.3)
	KernelPackets uint64 `json:"kernel_packets,omitempty"`
	KernelDrops   uint64 `json:"kernel_drops,omitempty"`
	KernelIfdrops uint64 `json:"kernel_ifdrops,omitempty"`

	// Zeek specific (Req 7.4)
	UptimeSeconds int64 `json:"uptime_seconds,omitempty"`
	LogWriteLagMs int64 `json:"log_write_lag_ms,omitempty"`
	Degraded      bool  `json:"degraded,omitempty"`

	// Vector specific (Req 7.5)
	RecordsIngestedPerSec float64           `json:"records_ingested_per_sec,omitempty"`
	SinkConnectivity      map[string]string `json:"sink_connectivity,omitempty"` // sink_name -> "connected"/"disconnected"
	DiskBufferUtilPct     float64           `json:"disk_buffer_util_pct,omitempty"`

	// Common (Req 7.7)
	DropAlert bool `json:"drop_alert"` // true when drop_percent > drop_alert_thresh_pct
}

// StorageStats holds PCAP storage usage.
type StorageStats struct {
	Path           string  `json:"path"`
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

// ClockStats holds clock synchronization status.
type ClockStats struct {
	OffsetMs     int64  `json:"offset_ms"`
	Synchronized bool   `json:"synchronized"`
	Source       string `json:"source"`
}

// SystemStats holds host-level health metrics for the sensor host.
type SystemStats struct {
	UptimeSeconds        int64   `json:"uptime_seconds"`
	CPUPercent           float64 `json:"cpu_percent"`
	CPUCount             int32   `json:"cpu_count"`
	MemoryTotalBytes     uint64  `json:"memory_total_bytes"`
	MemoryUsedBytes      uint64  `json:"memory_used_bytes"`
	MemoryAvailableBytes uint64  `json:"memory_available_bytes"`
	MemoryUsedPercent    float64 `json:"memory_used_percent"`
	DiskPath             string  `json:"disk_path"`
	DiskTotalBytes       uint64  `json:"disk_total_bytes"`
	DiskUsedBytes        uint64  `json:"disk_used_bytes"`
	DiskAvailableBytes   uint64  `json:"disk_available_bytes"`
	DiskUsedPercent      float64 `json:"disk_used_percent"`
	Load1                float64 `json:"load1"`
	Load5                float64 `json:"load5"`
	Load15               float64 `json:"load15"`
	Health               string  `json:"health"`
	KernelRelease        string  `json:"kernel_release"`
	CaptureInterface     string  `json:"capture_interface"`
	NICDriver            string  `json:"nic_driver"`
	AFPacketAvailable    bool    `json:"af_packet_available"`
}

// ToProto converts the internal HealthReport to the protobuf representation
// for transmission over the gRPC health stream.
func (r *HealthReport) ToProto() *healthpb.HealthReport {
	pb := &healthpb.HealthReport{
		SensorPodId:     r.SensorPodID,
		TimestampUnixMs: r.TimestampUnixMs,
	}

	for _, c := range r.Containers {
		pb.Containers = append(pb.Containers, &healthpb.ContainerHealth{
			Name:          c.Name,
			State:         c.State,
			UptimeSeconds: c.UptimeSeconds,
			CpuPercent:    c.CPUPercent,
			MemoryBytes:   c.MemoryBytes,
		})
	}

	consumers := make(map[string]*healthpb.ConsumerStats, len(r.Capture.Consumers))
	for name, cs := range r.Capture.Consumers {
		consumers[name] = &healthpb.ConsumerStats{
			PacketsReceived:        cs.PacketsReceived,
			PacketsDropped:         cs.PacketsDropped,
			DropPercent:            cs.DropPercent,
			ThroughputBps:          cs.ThroughputBps,
			BpfRestartPending:      cs.BpfRestartPending,
			DropAlert:              cs.DropAlert,
			PacketsWritten:         cs.PacketsWritten,
			BytesWritten:           cs.BytesWritten,
			WrapCount:              cs.WrapCount,
			SocketDrops:            cs.SocketDrops,
			SocketFreezeQueueDrops: cs.SocketFreezeQueueDrops,
			OverwriteRisk:          cs.OverwriteRisk,
		}
	}
	pb.Capture = &healthpb.CaptureStats{Consumers: consumers}

	pb.Storage = &healthpb.StorageStats{
		Path:           r.Storage.Path,
		TotalBytes:     r.Storage.TotalBytes,
		UsedBytes:      r.Storage.UsedBytes,
		AvailableBytes: r.Storage.AvailableBytes,
		UsedPercent:    r.Storage.UsedPercent,
	}

	pb.Clock = &healthpb.ClockStats{
		OffsetMs:     r.Clock.OffsetMs,
		Synchronized: r.Clock.Synchronized,
		Source:       r.Clock.Source,
	}

	pb.System = &healthpb.SystemStats{
		UptimeSeconds:        r.System.UptimeSeconds,
		CpuPercent:           r.System.CPUPercent,
		CpuCount:             r.System.CPUCount,
		MemoryTotalBytes:     r.System.MemoryTotalBytes,
		MemoryUsedBytes:      r.System.MemoryUsedBytes,
		MemoryAvailableBytes: r.System.MemoryAvailableBytes,
		MemoryUsedPercent:    r.System.MemoryUsedPercent,
		DiskPath:             r.System.DiskPath,
		DiskTotalBytes:       r.System.DiskTotalBytes,
		DiskUsedBytes:        r.System.DiskUsedBytes,
		DiskAvailableBytes:   r.System.DiskAvailableBytes,
		DiskUsedPercent:      r.System.DiskUsedPercent,
		Load1:                r.System.Load1,
		Load5:                r.System.Load5,
		Load15:               r.System.Load15,
		Health:               r.System.Health,
		KernelRelease:        r.System.KernelRelease,
		CaptureInterface:     r.System.CaptureInterface,
		NicDriver:            r.System.NICDriver,
		AfPacketAvailable:    r.System.AFPacketAvailable,
	}

	return pb
}

// prevConsumerState tracks per-consumer state between collection intervals
// for computing deltas (throughput, overwrite risk).
type prevConsumerState struct {
	BytesWritten uint64
	WrapCount    uint64
	Timestamp    time.Time
}

type cpuSample struct {
	Idle  uint64
	Total uint64
}

// CollectorConfig holds configuration for the health Collector.
type CollectorConfig struct {
	PcapRingSocket     string  // path to pcap_ring_writer control socket
	DropAlertThreshPct float64 // drop percentage threshold for DropAlert flag (default 1.0)
	SuricataEVEPath    string  // path to Suricata EVE JSON log
	ZeekLogDir         string  // path to Zeek log directory
	VectorMetricsURL   string  // URL for Vector internal metrics endpoint
}

// RingStatusFunc is a function that queries pcap_ring_writer status via the
// Ring_Control_Protocol socket. This is injectable for testing.
type RingStatusFunc func(socketPath string) (ringctl.RingResponse, error)

// defaultRingStatusFunc uses ringctl.DialAndSend to query pcap_ring_writer status.
func defaultRingStatusFunc(socketPath string) (ringctl.RingResponse, error) {
	return ringctl.DialAndSend(socketPath, ringctl.StatusCmd{Cmd: "status"})
}

// Collector scrapes health metrics from all sources and assembles HealthReports.
type Collector struct {
	podID        string
	captureMgr   *capture.Manager
	captureCfg   *capture.CaptureConfig
	podmanSock   string
	pcapPath     string
	hostDiskPath string
	auditLog     *audit.Logger
	interval     time.Duration

	// Per-consumer data source configuration (Req 7.x)
	pcapRingSocket     string
	dropAlertThreshPct float64
	suricataEVEPath    string
	zeekLogDir         string
	vectorMetricsURL   string

	// Previous state for delta calculations
	prevStateMu sync.Mutex
	prevState   map[string]prevConsumerState
	prevCPUMu   sync.Mutex
	prevCPU     cpuSample

	// Injectable functions for testing
	ringStatusFn RingStatusFunc
	timeNow      func() time.Time
	httpGet      func(url string) (*http.Response, error)
	readDir      func(name string) ([]os.DirEntry, error)
	readFile     func(name string) ([]byte, error)
	stat         func(name string) (os.FileInfo, error)
}

// NewCollector creates a new health Collector with default settings.
func NewCollector(capMgr *capture.Manager, auditLog *audit.Logger) *Collector {
	return &Collector{
		podID:              os.Getenv("SENSOR_POD_NAME"),
		captureMgr:         capMgr,
		podmanSock:         envOrDefault("PODMAN_SOCKET_PATH", "/run/podman/podman.sock"),
		pcapPath:           envOrDefault("PCAP_ALERTS_DIR", "/sensor/pcap"),
		hostDiskPath:       envOrDefault("HOST_DISK_PATH", envOrDefault("PCAP_ALERTS_DIR", "/sensor/pcap")),
		auditLog:           auditLog,
		interval:           10 * time.Second,
		dropAlertThreshPct: 1.0,
		prevState:          make(map[string]prevConsumerState),
		ringStatusFn:       defaultRingStatusFunc,
		timeNow:            time.Now,
		httpGet:            http.Get,
		readDir:            os.ReadDir,
		readFile:           os.ReadFile,
		stat:               os.Stat,
	}
}

// NewCollectorWithConfig creates a new health Collector with explicit configuration
// for per-consumer data sources.
func NewCollectorWithConfig(capMgr *capture.Manager, auditLog *audit.Logger, cfg CollectorConfig) *Collector {
	c := NewCollector(capMgr, auditLog)
	if cfg.PcapRingSocket != "" {
		c.pcapRingSocket = cfg.PcapRingSocket
	}
	if cfg.DropAlertThreshPct > 0 {
		c.dropAlertThreshPct = cfg.DropAlertThreshPct
	}
	if cfg.SuricataEVEPath != "" {
		c.suricataEVEPath = cfg.SuricataEVEPath
	}
	if cfg.ZeekLogDir != "" {
		c.zeekLogDir = cfg.ZeekLogDir
	}
	if cfg.VectorMetricsURL != "" {
		c.vectorMetricsURL = cfg.VectorMetricsURL
	}
	return c
}

// SetInterval overrides the default collection interval.
func (c *Collector) SetInterval(d time.Duration) {
	c.interval = d
}

// Collect assembles a HealthReport from all sources.
func (c *Collector) Collect() HealthReport {
	report := HealthReport{
		SensorPodID:     c.podID,
		TimestampUnixMs: c.timeNow().UnixMilli(),
	}

	report.Containers = c.scrapeContainers()
	report.Capture = c.scrapeCaptureStats()
	report.Storage = c.scrapeStorage()
	report.Clock = c.scrapeClock()
	report.System = c.scrapeSystem()

	return report
}

// dockerContainer is the Docker API container list response format.
type dockerContainer struct {
	Names  []string `json:"Names"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
	ID     string   `json:"Id"`
}

// dockerContainerStats is the Docker API stats response format.
type dockerContainerStats struct {
	Name     string `json:"name"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
	} `json:"memory_stats"`
}

// scrapeContainers queries the Docker/Podman socket for container stats.
func (c *Collector) scrapeContainers() []ContainerHealth {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return net.Dial("unix", c.podmanSock)
			},
		},
		Timeout: 5 * time.Second,
	}

	// Prefer Podman's native libpod API. The Docker-compatible endpoint does
	// not expose wall-clock uptime and its CPU deltas can be misleading on Podman.
	containers := c.fetchContainersPodman(client)
	if containers == nil {
		containers = c.fetchContainersDocker(client)
	}
	return containers
}

// fetchContainersDocker uses the Docker-compatible API (/containers/json).
func (c *Collector) fetchContainersDocker(client *http.Client) []ContainerHealth {
	listResp, err := client.Get("http://d/containers/json?all=true")
	if err != nil {
		return nil
	}
	defer listResp.Body.Close()

	var containers []dockerContainer
	if err := json.NewDecoder(listResp.Body).Decode(&containers); err != nil {
		return nil
	}

	result := make([]ContainerHealth, 0, len(containers))
	for _, ct := range containers {
		name := ""
		if len(ct.Names) > 0 {
			name = ct.Names[0]
			// Docker prefixes names with "/"
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}
		ch := ContainerHealth{
			Name:  name,
			State: ct.State,
		}
		// Fetch per-container stats (non-streaming)
		if s := c.fetchDockerStats(client, ct.ID); s != nil {
			cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage - s.PreCPUStats.CPUUsage.TotalUsage)
			sysDelta := float64(s.CPUStats.SystemCPUUsage - s.PreCPUStats.SystemCPUUsage)
			if sysDelta > 0 && s.CPUStats.OnlineCPUs > 0 {
				ch.CPUPercent = (cpuDelta / sysDelta) * float64(s.CPUStats.OnlineCPUs) * 100.0
			}
			ch.MemoryBytes = s.MemoryStats.Usage
		}
		result = append(result, ch)
	}
	return result
}

// fetchDockerStats fetches stats for a single container by ID.
func (c *Collector) fetchDockerStats(client *http.Client, id string) *dockerContainerStats {
	resp, err := client.Get("http://d/containers/" + id + "/stats?stream=false")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var s dockerContainerStats
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil
	}
	return &s
}

// podmanContainerInspect is the subset of Podman's container inspect response we need.
type podmanContainerInspect struct {
	Names     []string `json:"Names"`
	State     string   `json:"State"`
	Status    string   `json:"Status"`
	StartedAt int64    `json:"StartedAt"`
	Created   string   `json:"Created"`
}

// podmanContainerStats is the subset of Podman's /stats response we need.
type podmanContainerStats struct {
	Name     string  `json:"Name"`
	CPU      float64 `json:"CPU"`
	AvgCPU   float64 `json:"AvgCPU"`
	MemUsage uint64  `json:"MemUsage"`
}

// fetchContainersPodman uses the Podman libpod API.
func (c *Collector) fetchContainersPodman(client *http.Client) []ContainerHealth {
	listResp, err := client.Get("http://d/v4.0.0/libpod/containers/json?all=true")
	if err != nil {
		return nil
	}
	defer listResp.Body.Close()

	var containers []podmanContainerInspect
	if err := json.NewDecoder(listResp.Body).Decode(&containers); err != nil {
		return nil
	}

	statsMap := c.scrapePodmanStats(client)
	result := make([]ContainerHealth, 0, len(containers))
	for _, ct := range containers {
		name := ""
		if len(ct.Names) > 0 {
			name = ct.Names[0]
		}
		ch := ContainerHealth{
			Name:          name,
			State:         ct.State,
			UptimeSeconds: containerUptimeSeconds(ct, c.timeNow()),
		}
		if s, ok := statsMap[name]; ok {
			ch.CPUPercent = s.CPU
			if ch.CPUPercent == 0 {
				ch.CPUPercent = s.AvgCPU
			}
			ch.MemoryBytes = s.MemUsage
		}
		result = append(result, ch)
	}
	return result
}

func containerUptimeSeconds(ct podmanContainerInspect, now time.Time) int64 {
	if ct.State != "running" {
		return 0
	}
	if ct.StartedAt > 0 {
		uptime := now.Unix() - ct.StartedAt
		if uptime > 0 {
			return uptime
		}
		return 0
	}
	if ct.Created != "" {
		if created, err := time.Parse(time.RFC3339Nano, ct.Created); err == nil {
			uptime := now.Sub(created).Seconds()
			if uptime > 0 {
				return int64(uptime)
			}
		}
	}
	return 0
}

// scrapePodmanStats fetches per-container CPU/memory stats from Podman.
func (c *Collector) scrapePodmanStats(client *http.Client) map[string]podmanContainerStats {
	resp, err := client.Get("http://d/v4.0.0/libpod/containers/stats?stream=false")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var body struct {
		Stats []podmanContainerStats `json:"Stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	m := make(map[string]podmanContainerStats, len(body.Stats))
	for _, s := range body.Stats {
		m[s.Name] = s
	}
	return m
}

// scrapeCaptureStats reads per-consumer statistics from actual capture processes
// rather than interface-level counters (Req 7.1).
func (c *Collector) scrapeCaptureStats() CaptureStats {
	stats := CaptureStats{
		Consumers: make(map[string]ConsumerStats),
	}

	if c.captureMgr == nil {
		return stats
	}

	cfg := c.captureMgr.Config()
	if cfg == nil {
		return stats
	}

	// Req 4.7: Merge BPF restart pending flags into consumer stats.
	bpfPending := c.captureMgr.BPFRestartPending()

	// Also read interface-level stats as a baseline for consumers that don't
	// have a dedicated stats source.
	rawStats, err := capture.ReadPacketStats(cfg)
	if err != nil {
		log.Printf("health: failed to read packet stats: %v", err)
	}

	now := c.timeNow()

	for _, consumer := range cfg.Consumers {
		name := consumer.Name
		cs := ConsumerStats{
			BpfRestartPending: bpfPending[name],
		}

		switch name {
		case "pcap_ring_writer":
			c.scrapePcapRingWriterStats(&cs)
		case "suricata":
			c.scrapeSuricataStats(&cs)
			// Also merge interface-level stats as baseline
			if rs, ok := rawStats[name]; ok {
				cs.PacketsReceived = rs.PacketsReceived
				cs.PacketsDropped = rs.PacketsDropped
				cs.DropPercent = rs.DropPercent
			}
		case "zeek":
			c.scrapeZeekStats(&cs)
			// Also merge interface-level stats as baseline
			if rs, ok := rawStats[name]; ok {
				cs.PacketsReceived = rs.PacketsReceived
				cs.PacketsDropped = rs.PacketsDropped
				cs.DropPercent = rs.DropPercent
			}
		default:
			// Fall back to interface-level stats
			if rs, ok := rawStats[name]; ok {
				cs.PacketsReceived = rs.PacketsReceived
				cs.PacketsDropped = rs.PacketsDropped
				cs.DropPercent = rs.DropPercent
			}
		}

		// Compute throughput from byte count deltas (Req 7.6)
		cs.ThroughputBps = c.computeThroughput(name, cs.BytesWritten, now)

		// Update previous wrap count for pcap_ring_writer after overwrite risk
		// has been computed and throughput has updated prevState.
		if name == "pcap_ring_writer" {
			c.updatePrevWrapCount(name, cs.WrapCount)
		}

		// Compute drop alert flag (Req 7.7)
		cs.DropAlert = c.computeDropAlert(name, cs.DropPercent)

		stats.Consumers[name] = cs
	}

	// Collect Vector metrics if configured (Req 7.5)
	c.scrapeVectorStats(stats.Consumers)

	return stats
}

// scrapePcapRingWriterStats queries pcap_ring_writer via the Ring_Control_Protocol
// socket status command (Req 7.1, 7.2).
func (c *Collector) scrapePcapRingWriterStats(cs *ConsumerStats) {
	if c.pcapRingSocket == "" {
		return
	}

	resp, err := c.ringStatusFn(c.pcapRingSocket)
	if err != nil {
		log.Printf("health: failed to query pcap_ring_writer status: %v", err)
		return
	}

	if resp.Status != "ok" {
		log.Printf("health: pcap_ring_writer status error: %s", resp.Error)
		return
	}

	cs.PacketsWritten = resp.PacketsWritten
	cs.BytesWritten = resp.BytesWritten
	cs.WrapCount = resp.WrapCount
	cs.SocketDrops = resp.SocketDrops
	cs.SocketFreezeQueueDrops = resp.SocketFreezeQueueDrops

	// Use packets_written as packets_received for pcap_ring_writer
	cs.PacketsReceived = resp.PacketsWritten
	// Drops are socket_drops for pcap_ring_writer
	cs.PacketsDropped = resp.SocketDrops
	if cs.PacketsReceived+cs.PacketsDropped > 0 {
		cs.DropPercent = float64(cs.PacketsDropped) / float64(cs.PacketsReceived+cs.PacketsDropped) * 100
	}

	// Derive overwrite_risk: true when wrap_count has incremented more than once
	// since the last interval (Req 7.2).
	c.prevStateMu.Lock()
	prev, hasPrev := c.prevState["pcap_ring_writer"]
	if hasPrev {
		wrapDelta := cs.WrapCount - prev.WrapCount
		cs.OverwriteRisk = wrapDelta > 1
	}
	c.prevStateMu.Unlock()
}

// suricataEVEStats represents the capture stats from a Suricata EVE stats event.
type suricataEVEStats struct {
	EventType string `json:"event_type"`
	Stats     struct {
		Capture struct {
			KernelPackets uint64 `json:"kernel_packets"`
			KernelDrops   uint64 `json:"kernel_drops"`
			KernelIfdrops uint64 `json:"kernel_ifdrops"`
		} `json:"capture"`
	} `json:"stats"`
}

// scrapeSuricataStats collects Suricata capture stats from the EVE JSON stats
// event stream (Req 7.3).
func (c *Collector) scrapeSuricataStats(cs *ConsumerStats) {
	if c.suricataEVEPath == "" {
		return
	}

	stats, err := c.parseSuricataEVEStats(c.suricataEVEPath)
	if err != nil {
		log.Printf("health: failed to read Suricata EVE stats: %v", err)
		return
	}

	cs.KernelPackets = stats.Stats.Capture.KernelPackets
	cs.KernelDrops = stats.Stats.Capture.KernelDrops
	cs.KernelIfdrops = stats.Stats.Capture.KernelIfdrops
}

// parseSuricataEVEStats reads the Suricata EVE JSON log and finds the last
// stats event to extract capture statistics.
func (c *Collector) parseSuricataEVEStats(evePath string) (*suricataEVEStats, error) {
	data, err := c.readFile(evePath)
	if err != nil {
		return nil, fmt.Errorf("read EVE log %s: %w", evePath, err)
	}

	// Scan lines in reverse to find the last stats event
	var lastStats *suricataEVEStats
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, `"event_type":"stats"`) {
			continue
		}
		var evt suricataEVEStats
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue
		}
		if evt.EventType == "stats" {
			lastStats = &evt
		}
	}

	if lastStats == nil {
		return nil, fmt.Errorf("no stats event found in EVE log")
	}
	return lastStats, nil
}

// scrapeZeekStats collects Zeek process health metrics (Req 7.4):
// - uptime from /proc/<pid>/stat
// - log write lag from file mtime
// - degraded state flag
func (c *Collector) scrapeZeekStats(cs *ConsumerStats) {
	pid := c.findProcessPID("zeek")
	if pid <= 0 {
		cs.Degraded = true
		return
	}

	// Read uptime from /proc/<pid>/stat
	uptime, err := c.readProcessUptime(pid)
	if err != nil {
		log.Printf("health: failed to read Zeek uptime: %v", err)
		cs.Degraded = true
	} else {
		cs.UptimeSeconds = uptime
	}

	// Check log write lag from Zeek log directory mtime
	if c.zeekLogDir != "" {
		lag, err := c.computeLogWriteLag(c.zeekLogDir)
		if err != nil {
			log.Printf("health: failed to compute Zeek log write lag: %v", err)
		} else {
			cs.LogWriteLagMs = lag
		}
	}

	// Degraded if uptime is very low (just restarted) or log lag is excessive (>60s)
	if cs.LogWriteLagMs > 60000 {
		cs.Degraded = true
	}
}

// findProcessPID scans /proc for a process with the given name and returns its PID.
func (c *Collector) findProcessPID(name string) int {
	entries, err := c.readDir("/proc")
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		comm, err := c.readFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		procName := strings.TrimSpace(string(comm))
		if procName == name {
			return pid
		}
	}
	return 0
}

// readProcessUptime reads the process uptime in seconds from /proc/<pid>/stat.
// Field 22 (starttime) is the time the process started after system boot, in clock ticks.
func (c *Collector) readProcessUptime(pid int) (int64, error) {
	statData, err := c.readFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/stat: %w", pid, err)
	}

	// Parse starttime (field 22, 1-indexed). The comm field (field 2) may contain
	// spaces and parentheses, so find the last ')' to skip it.
	content := string(statData)
	idx := strings.LastIndex(content, ")")
	if idx < 0 {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(content[idx+1:])
	// After the closing ')', fields are indexed from 0 = field 3 in the original.
	// starttime is field 22 in the original, so index 22-3 = 19 in our slice.
	if len(fields) < 20 {
		return 0, fmt.Errorf("not enough fields in /proc/%d/stat", pid)
	}
	starttime, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse starttime: %w", err)
	}

	// Read system uptime
	uptimeData, err := c.readFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("read /proc/uptime: %w", err)
	}
	var systemUptime float64
	fmt.Sscanf(string(uptimeData), "%f", &systemUptime)

	// Clock ticks per second (typically 100 on Linux)
	clkTck := int64(100)
	processStartSec := starttime / clkTck
	processUptime := int64(systemUptime) - processStartSec

	if processUptime < 0 {
		processUptime = 0
	}
	return processUptime, nil
}

// computeLogWriteLag finds the most recently modified file in the log directory
// and returns the lag in milliseconds since that modification.
func (c *Collector) computeLogWriteLag(logDir string) (int64, error) {
	entries, err := c.readDir(logDir)
	if err != nil {
		return 0, fmt.Errorf("read log dir %s: %w", logDir, err)
	}

	var latestMtime time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := c.stat(filepath.Join(logDir, entry.Name()))
		if err != nil {
			continue
		}
		if info.ModTime().After(latestMtime) {
			latestMtime = info.ModTime()
		}
	}

	if latestMtime.IsZero() {
		return 0, fmt.Errorf("no files found in %s", logDir)
	}

	lag := c.timeNow().Sub(latestMtime)
	return lag.Milliseconds(), nil
}

// vectorMetricsResponse represents the subset of Vector's internal metrics
// endpoint response that we need (Req 7.5).
type vectorMetricsResponse struct {
	ComponentsReceivedEventsTotal []struct {
		Name  string  `json:"name"`
		Value float64 `json:"value"`
	} `json:"components_received_events_total,omitempty"`
	Sinks []struct {
		Name      string `json:"name"`
		Connected bool   `json:"connected"`
	} `json:"sinks,omitempty"`
	DiskBufferUsage struct {
		UsedBytes  uint64 `json:"used_bytes"`
		TotalBytes uint64 `json:"total_bytes"`
	} `json:"disk_buffer_usage,omitempty"`
}

// scrapeVectorStats collects Vector internal metrics (Req 7.5).
// If a "vector" consumer exists in the consumers map, it enriches it;
// otherwise it creates a new entry.
func (c *Collector) scrapeVectorStats(consumers map[string]ConsumerStats) {
	if c.vectorMetricsURL == "" {
		return
	}

	resp, err := c.httpGet(c.vectorMetricsURL)
	if err != nil {
		log.Printf("health: failed to query Vector metrics: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("health: Vector metrics returned status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("health: failed to read Vector metrics response: %v", err)
		return
	}

	var metrics vectorMetricsResponse
	if err := json.Unmarshal(body, &metrics); err != nil {
		log.Printf("health: failed to parse Vector metrics: %v", err)
		return
	}

	cs := consumers["vector"]

	// Records ingested per second: sum of all component received events / interval
	var totalEvents float64
	for _, comp := range metrics.ComponentsReceivedEventsTotal {
		totalEvents += comp.Value
	}
	if c.interval > 0 {
		cs.RecordsIngestedPerSec = totalEvents / c.interval.Seconds()
	}

	// Sink connectivity status
	cs.SinkConnectivity = make(map[string]string)
	for _, sink := range metrics.Sinks {
		if sink.Connected {
			cs.SinkConnectivity[sink.Name] = "connected"
		} else {
			cs.SinkConnectivity[sink.Name] = "disconnected"
		}
	}

	// Disk buffer utilization percentage
	if metrics.DiskBufferUsage.TotalBytes > 0 {
		cs.DiskBufferUtilPct = float64(metrics.DiskBufferUsage.UsedBytes) / float64(metrics.DiskBufferUsage.TotalBytes) * 100
	}

	consumers["vector"] = cs
}

// computeThroughput calculates bits per second from successive byte count deltas
// for a given consumer (Req 7.6).
func (c *Collector) computeThroughput(name string, currentBytes uint64, now time.Time) float64 {
	c.prevStateMu.Lock()
	defer c.prevStateMu.Unlock()

	prev, hasPrev := c.prevState[name]

	// Update previous state for next interval
	newState := prevConsumerState{
		BytesWritten: currentBytes,
		Timestamp:    now,
	}
	// Preserve WrapCount from existing state if present
	if existing, ok := c.prevState[name]; ok {
		newState.WrapCount = existing.WrapCount
	}
	c.prevState[name] = newState

	if !hasPrev || prev.Timestamp.IsZero() || currentBytes == 0 {
		return 0
	}

	elapsed := now.Sub(prev.Timestamp).Seconds()
	if elapsed <= 0 {
		return 0
	}

	bytesDelta := currentBytes - prev.BytesWritten
	// Convert bytes to bits
	return float64(bytesDelta) * 8 / elapsed
}

// computeDropAlert checks if the drop percentage exceeds the configured threshold
// and logs a warning if so (Req 7.7).
func (c *Collector) computeDropAlert(name string, dropPercent float64) bool {
	if dropPercent > c.dropAlertThreshPct {
		log.Printf("health: WARNING: consumer %s drop percentage %.2f%% exceeds threshold %.2f%%",
			name, dropPercent, c.dropAlertThreshPct)
		return true
	}
	return false
}

// updatePrevWrapCount updates the previous wrap count for pcap_ring_writer
// after computing overwrite risk. Called at the end of scrapeCaptureStats.
func (c *Collector) updatePrevWrapCount(name string, wrapCount uint64) {
	c.prevStateMu.Lock()
	defer c.prevStateMu.Unlock()
	if state, ok := c.prevState[name]; ok {
		state.WrapCount = wrapCount
		c.prevState[name] = state
	}
}

// scrapeStorage reads disk usage for the PCAP storage path.
func (c *Collector) scrapeStorage() StorageStats {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(c.pcapPath, &stat); err != nil {
		return StorageStats{Path: c.pcapPath}
	}

	total := stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := total - avail
	usedPct := 0.0
	if total > 0 {
		usedPct = float64(used) / float64(total) * 100
	}

	return StorageStats{
		Path:           c.pcapPath,
		TotalBytes:     total,
		UsedBytes:      used,
		AvailableBytes: avail,
		UsedPercent:    usedPct,
	}
}

// scrapeSystem reads host-level CPU, memory, load, uptime, and disk usage.
func (c *Collector) scrapeSystem() SystemStats {
	stats := SystemStats{
		CPUCount:         int32(runtime.NumCPU()),
		DiskPath:         c.hostDiskPath,
		Health:           "ok",
		CaptureInterface: envOrDefault("CAPTURE_IFACE", "eth0"),
	}

	if uptime, err := c.readSystemUptime(); err == nil {
		stats.UptimeSeconds = uptime
	}
	if cpu, err := c.readHostCPUPercent(); err == nil {
		stats.CPUPercent = cpu
	}
	if total, available, err := c.readMemoryStats(); err == nil {
		stats.MemoryTotalBytes = total
		stats.MemoryAvailableBytes = available
		if total >= available {
			stats.MemoryUsedBytes = total - available
		}
		if total > 0 {
			stats.MemoryUsedPercent = float64(stats.MemoryUsedBytes) / float64(total) * 100
		}
	}
	if load1, load5, load15, err := c.readLoadAverage(); err == nil {
		stats.Load1 = load1
		stats.Load5 = load5
		stats.Load15 = load15
	}
	if kernel, err := c.readKernelRelease(); err == nil {
		stats.KernelRelease = kernel
	}
	if stats.CaptureInterface != "" {
		stats.NICDriver = c.readNICDriver(stats.CaptureInterface)
	}
	stats.AFPacketAvailable = c.afPacketAvailable()

	var disk syscall.Statfs_t
	if err := syscall.Statfs(c.hostDiskPath, &disk); err == nil {
		total := disk.Blocks * uint64(disk.Bsize)
		avail := disk.Bavail * uint64(disk.Bsize)
		used := total - avail
		stats.DiskTotalBytes = total
		stats.DiskAvailableBytes = avail
		stats.DiskUsedBytes = used
		if total > 0 {
			stats.DiskUsedPercent = float64(used) / float64(total) * 100
		}
	}

	stats.Health = deriveSystemHealth(stats)
	return stats
}

func (c *Collector) readKernelRelease() (string, error) {
	data, err := c.readFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (c *Collector) readNICDriver(iface string) string {
	driverPath := fmt.Sprintf("/sys/class/net/%s/device/driver", iface)
	target, err := os.Readlink(driverPath)
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func (c *Collector) afPacketAvailable() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func (c *Collector) readSystemUptime() (int64, error) {
	data, err := c.readFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return int64(uptime), nil
}

func (c *Collector) readHostCPUPercent() (float64, error) {
	sample, err := c.readCPUSample()
	if err != nil {
		return 0, err
	}

	c.prevCPUMu.Lock()
	defer c.prevCPUMu.Unlock()

	prev := c.prevCPU
	c.prevCPU = sample
	if prev.Total == 0 || sample.Total <= prev.Total || sample.Idle < prev.Idle {
		return 0, nil
	}

	totalDelta := sample.Total - prev.Total
	idleDelta := sample.Idle - prev.Idle
	if totalDelta == 0 || idleDelta > totalDelta {
		return 0, nil
	}
	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100, nil
}

func (c *Collector) readCPUSample() (cpuSample, error) {
	data, err := c.readFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	if !scanner.Scan() {
		return cpuSample{}, fmt.Errorf("empty /proc/stat")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("malformed cpu line in /proc/stat")
	}

	var values []uint64
	for _, raw := range fields[1:] {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return cpuSample{}, err
		}
		values = append(values, v)
	}

	var total uint64
	for _, v := range values {
		total += v
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return cpuSample{Idle: idle, Total: total}, nil
}

func (c *Collector) readMemoryStats() (uint64, uint64, error) {
	data, err := c.readFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}

	var totalKB, availableKB uint64
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			totalKB = value
		case "MemAvailable":
			availableKB = value
		}
	}
	if totalKB == 0 {
		return 0, 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
	}
	return totalKB * 1024, availableKB * 1024, nil
}

func (c *Collector) readLoadAverage() (float64, float64, float64, error) {
	data, err := c.readFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("malformed /proc/loadavg")
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	load5, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	load15, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	return load1, load5, load15, nil
}

func deriveSystemHealth(stats SystemStats) string {
	cpuCount := float64(stats.CPUCount)
	if cpuCount < 1 {
		cpuCount = 1
	}
	loadPerCPU := stats.Load1 / cpuCount

	if stats.DiskUsedPercent >= 95 || stats.MemoryUsedPercent >= 95 || loadPerCPU >= 2 {
		return "critical"
	}
	if stats.DiskUsedPercent >= 85 || stats.MemoryUsedPercent >= 90 || loadPerCPU >= 1 {
		return "warning"
	}
	return "ok"
}

// scrapeClock reads the system clock offset via adjtimex.
func (c *Collector) scrapeClock() ClockStats {
	var timex unix.Timex
	state, err := unix.Adjtimex(&timex)
	if err != nil {
		return ClockStats{Synchronized: false}
	}

	// TIME_ERROR (5) means the clock is not synchronized.
	synchronized := state != 5
	offsetMs := timex.Offset / int64(time.Millisecond)
	if offsetMs < 0 {
		offsetMs = -offsetMs
	}

	return ClockStats{
		OffsetMs:     offsetMs,
		Synchronized: synchronized,
	}
}

// Run starts the health collector loop, publishing reports at the configured interval.
func (c *Collector) Run(done <-chan struct{}, out chan<- HealthReport) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			select {
			case out <- c.Collect():
			default:
				log.Printf("health: collector output channel full, dropping report")
			}
		}
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// StorageUsedPercent returns the current used percentage for the PCAP storage path.
func StorageUsedPercent(path string) (float64, error) {
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
