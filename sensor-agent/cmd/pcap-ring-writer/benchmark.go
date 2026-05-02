//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ── Benchmark configuration ───────────────────────────────────────────────────

const (
	// Default ring parameters for benchmarking.
	benchRingSizeMB   = 64
	benchMaxPackets   = 65536
	benchPacketSize   = 1024 // representative mixed-traffic packet size
	benchDurationSecs = 10

	// Bits per byte.
	bitsPerByte = 8
)

// BenchmarkProfile defines a single traffic profile to benchmark.
type BenchmarkProfile struct {
	Name       string  `json:"name"`
	TargetGbps float64 `json:"target_gbps"`
	PacketSize int     `json:"packet_size_bytes"`
	DurationS  int     `json:"duration_seconds"`
}

// BenchmarkResult holds the measured results for a single profile run.
type BenchmarkResult struct {
	Name            string  `json:"name"`
	TargetGbps      float64 `json:"target_gbps"`
	TargetPPS       uint64  `json:"target_pps"`
	DurationSeconds float64 `json:"duration_seconds"`
	AchievedPPS     uint64  `json:"achieved_pps"`
	AchievedGbps    float64 `json:"achieved_gbps"`
	PacketsWritten  uint64  `json:"packets_written"`
	BytesWritten    uint64  `json:"bytes_written"`
	WrapCount       uint64  `json:"wrap_count"`
	DropPercentage  float64 `json:"drop_percentage"`
	TargetAchieved  bool    `json:"target_achieved"`
}

// BenchmarkReport is the top-level JSON report written to disk.
type BenchmarkReport struct {
	Timestamp       string            `json:"timestamp"`
	RingSizeMB      int               `json:"ring_size_mb"`
	MaxPackets      int               `json:"max_packets"`
	PacketSizeBytes int               `json:"packet_size_bytes"`
	GoVersion       string            `json:"go_version"`
	NumCPU          int               `json:"num_cpu"`
	GOOS            string            `json:"goos"`
	GOARCH          string            `json:"goarch"`
	Profiles        []BenchmarkResult `json:"profiles"`
}

// defaultProfiles returns the three standard traffic profiles.
func defaultProfiles() []BenchmarkProfile {
	return []BenchmarkProfile{
		{Name: "1Gbps", TargetGbps: 1.0, PacketSize: benchPacketSize, DurationS: benchDurationSecs},
		{Name: "10Gbps", TargetGbps: 10.0, PacketSize: benchPacketSize, DurationS: benchDurationSecs},
		{Name: "25Gbps", TargetGbps: 25.0, PacketSize: benchPacketSize, DurationS: benchDurationSecs},
	}
}

// targetPPS calculates the packets-per-second needed to achieve targetGbps
// with the given packet size.
func targetPPS(targetGbps float64, packetSize int) uint64 {
	bitsPerPacket := float64(packetSize) * bitsPerByte
	bitsPerSecond := targetGbps * 1e9
	return uint64(bitsPerSecond / bitsPerPacket)
}

// ── Profile runner ────────────────────────────────────────────────────────────

// runProfile creates a fresh Ring, injects packets at the target rate for the
// configured duration, and returns the measured results.
func runProfile(profile BenchmarkProfile) (BenchmarkResult, error) {
	// Create a temp file for the ring.
	tmpDir, err := os.MkdirTemp("", "pcap_bench_*")
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	ringPath := filepath.Join(tmpDir, "bench_ring")
	ring, err := newRing(ringPath, benchRingSizeMB, benchMaxPackets)
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("create ring: %w", err)
	}

	tgtPPS := targetPPS(profile.TargetGbps, profile.PacketSize)
	duration := time.Duration(profile.DurationS) * time.Second

	// Pre-allocate a representative packet payload.
	pkt := make([]byte, profile.PacketSize)
	for i := range pkt {
		pkt[i] = byte(i % 256)
	}

	// Calculate batch parameters for rate control.
	// At high rates, per-packet sleeps are too coarse. Instead, write packets
	// in batches and sleep between batches to approximate the target rate.
	const batchSize = 1000
	batchInterval := time.Duration(float64(time.Second) * float64(batchSize) / float64(tgtPPS))

	log.Printf("  profile=%s target_gbps=%.1f target_pps=%d batch_interval=%v duration=%v",
		profile.Name, profile.TargetGbps, tgtPPS, batchInterval, duration)

	var packetsWritten uint64
	tsNs := time.Now().UnixNano()

	start := time.Now()
	deadline := start.Add(duration)
	batchStart := time.Now()

	for time.Now().Before(deadline) {
		// Write a batch of packets.
		for i := 0; i < batchSize; i++ {
			ring.writePacket(tsNs, pkt)
			packetsWritten++
			tsNs++ // increment timestamp to simulate distinct packets
		}

		// Rate limiting: if we're ahead of schedule, busy-wait until the
		// batch interval has elapsed. time.Sleep is too coarse for high
		// rates, so we spin on time.Now() for sub-millisecond precision.
		elapsed := time.Since(batchStart)
		if elapsed < batchInterval {
			for time.Since(batchStart) < batchInterval {
				runtime.Gosched()
			}
		}
		batchStart = time.Now()

		// Check if we've already exceeded the target total packets.
		if packetsWritten >= tgtPPS*uint64(profile.DurationS) {
			break
		}
	}

	actualDuration := time.Since(start)

	// Collect ring stats.
	stats := ring.stats()
	wrapCount, _ := stats["wrap_count"].(uint64)
	bytesWritten, _ := stats["bytes_written"].(uint64)

	achievedPPS := uint64(float64(packetsWritten) / actualDuration.Seconds())
	achievedGbps := float64(bytesWritten) * bitsPerByte / actualDuration.Seconds() / 1e9

	// Drop percentage: compare achieved PPS to target PPS.
	// If we wrote fewer packets than the target, the difference is "drops"
	// (i.e., the ring write path couldn't keep up).
	totalTarget := tgtPPS * uint64(profile.DurationS)
	var dropPct float64
	if packetsWritten < totalTarget {
		dropPct = float64(totalTarget-packetsWritten) / float64(totalTarget) * 100.0
	}

	// Target is achieved if we reached >= 95% of the target PPS.
	targetAchieved := float64(achievedPPS) >= float64(tgtPPS)*0.95

	result := BenchmarkResult{
		Name:            profile.Name,
		TargetGbps:      profile.TargetGbps,
		TargetPPS:       tgtPPS,
		DurationSeconds: actualDuration.Seconds(),
		AchievedPPS:     achievedPPS,
		AchievedGbps:    achievedGbps,
		PacketsWritten:  packetsWritten,
		BytesWritten:    bytesWritten,
		WrapCount:       wrapCount,
		DropPercentage:  dropPct,
		TargetAchieved:  targetAchieved,
	}

	log.Printf("  result: achieved_pps=%d achieved_gbps=%.2f packets=%d wraps=%d drop_pct=%.2f%% target_met=%v",
		achievedPPS, achievedGbps, packetsWritten, wrapCount, dropPct, targetAchieved)

	return result, nil
}

// ── Benchmark entry point ─────────────────────────────────────────────────────

// runBenchmark runs all traffic profiles and writes a JSON report.
func runBenchmark() {
	outputPath := benchmarkOutputPath()

	log.Printf("pcap_ring_writer benchmark: ring_size=%dMB max_packets=%d packet_size=%d",
		benchRingSizeMB, benchMaxPackets, benchPacketSize)
	log.Printf("pcap_ring_writer benchmark: output=%s", outputPath)

	profiles := defaultProfiles()
	report := BenchmarkReport{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		RingSizeMB:      benchRingSizeMB,
		MaxPackets:      benchMaxPackets,
		PacketSizeBytes: benchPacketSize,
		GoVersion:       runtime.Version(),
		NumCPU:          runtime.NumCPU(),
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		Profiles:        make([]BenchmarkResult, 0, len(profiles)),
	}

	for _, p := range profiles {
		log.Printf("pcap_ring_writer benchmark: running profile %s", p.Name)
		result, err := runProfile(p)
		if err != nil {
			log.Printf("pcap_ring_writer benchmark: profile %s failed: %v", p.Name, err)
			continue
		}
		report.Profiles = append(report.Profiles, result)
	}

	// Write JSON report.
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("pcap_ring_writer benchmark: marshal report: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Fatalf("pcap_ring_writer benchmark: write report: %v", err)
	}

	log.Printf("pcap_ring_writer benchmark: report written to %s", outputPath)

	// Also print a summary to stdout.
	fmt.Println(string(data))
}

// benchmarkOutputPath returns the path for the benchmark JSON report.
// Checks --benchmark-output flag (next arg after --benchmark), then
// BENCHMARK_OUTPUT env var, then defaults to benchmark_report.json.
func benchmarkOutputPath() string {
	// Check for --benchmark-output in args.
	for i, arg := range os.Args {
		if arg == "--benchmark-output" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}

	if v := os.Getenv("BENCHMARK_OUTPUT"); v != "" {
		return v
	}

	return "benchmark_report.json"
}
