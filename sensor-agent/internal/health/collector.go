//go:build linux

package health

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	"github.com/ravenwire/ravenwire/sensor-agent/internal/capture"
	healthpb "github.com/ravenwire/ravenwire/sensor-agent/internal/health/proto"
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

// ConsumerStats holds per-consumer packet counters.
type ConsumerStats struct {
	PacketsReceived uint64  `json:"packets_received"`
	PacketsDropped  uint64  `json:"packets_dropped"`
	DropPercent     float64 `json:"drop_percent"`
	ThroughputBps   float64 `json:"throughput_bps"`
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
			PacketsReceived: cs.PacketsReceived,
			PacketsDropped:  cs.PacketsDropped,
			DropPercent:     cs.DropPercent,
			ThroughputBps:   cs.ThroughputBps,
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

	return pb
}

// Collector scrapes health metrics from all sources and assembles HealthReports.
type Collector struct {
	podID      string
	captureMgr *capture.Manager
	captureCfg *capture.CaptureConfig
	podmanSock string
	pcapPath   string
	auditLog   *audit.Logger
	interval   time.Duration
}

// NewCollector creates a new health Collector.
func NewCollector(capMgr *capture.Manager, auditLog *audit.Logger) *Collector {
	return &Collector{
		podID:      os.Getenv("SENSOR_POD_NAME"),
		captureMgr: capMgr,
		podmanSock: envOrDefault("PODMAN_SOCKET_PATH", "/run/podman/podman.sock"),
		pcapPath:   envOrDefault("PCAP_ALERTS_DIR", "/sensor/pcap"),
		auditLog:   auditLog,
		interval:   10 * time.Second,
	}
}

// SetInterval overrides the default collection interval.
func (c *Collector) SetInterval(d time.Duration) {
	c.interval = d
}

// Collect assembles a HealthReport from all sources.
func (c *Collector) Collect() HealthReport {
	report := HealthReport{
		SensorPodID:     c.podID,
		TimestampUnixMs: time.Now().UnixMilli(),
	}

	report.Containers = c.scrapeContainers()
	report.Capture = c.scrapeCaptureStats()
	report.Storage = c.scrapeStorage()
	report.Clock = c.scrapeClock()

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

	// Try Docker API first, fall back to Podman libpod API
	containers := c.fetchContainersDocker(client)
	if containers == nil {
		containers = c.fetchContainersPodman(client)
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
	Names  []string `json:"Names"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

// podmanContainerStats is the subset of Podman's /stats response we need.
type podmanContainerStats struct {
	Name       string  `json:"Name"`
	CPUPercent float64 `json:"CPUPercent"`
	MemUsage   uint64  `json:"MemUsage"`
	UpTime     uint64  `json:"UpTime"` // nanoseconds
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
		ch := ContainerHealth{Name: name, State: ct.State}
		if s, ok := statsMap[name]; ok {
			ch.CPUPercent = s.CPUPercent
			ch.MemoryBytes = s.MemUsage
			ch.UptimeSeconds = int64(s.UpTime / uint64(time.Second))
		}
		result = append(result, ch)
	}
	return result
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

// scrapeCaptureStats reads per-consumer packet/drop counters via capture.ReadPacketStats.
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

	rawStats, err := capture.ReadPacketStats(cfg)
	if err != nil {
		log.Printf("health: failed to read packet stats: %v", err)
		return stats
	}

	for name, rs := range rawStats {
		stats.Consumers[name] = ConsumerStats{
			PacketsReceived: rs.PacketsReceived,
			PacketsDropped:  rs.PacketsDropped,
			DropPercent:     rs.DropPercent,
		}
	}
	return stats
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
