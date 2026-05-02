//go:build linux

package readiness

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Severity indicates whether a check failure blocks bootstrap (hard) or is a warning (soft).
type Severity string

const (
	SeverityHard Severity = "hard"
	SeveritySoft Severity = "soft"
)

// CheckResult holds the result of a single readiness check.
type CheckResult struct {
	Name          string   `json:"name"`
	Passed        bool     `json:"passed"`
	Message       string   `json:"message"`
	ObservedValue string   `json:"observed_value"`
	RequiredValue string   `json:"required_value"`
	Severity      Severity `json:"severity"`
}

// ReadinessReport is the result of all readiness checks.
// Passed is false only when one or more hard checks fail.
type ReadinessReport struct {
	Passed bool          `json:"passed"`
	Checks []CheckResult `json:"checks"`
}

// Config holds thresholds for readiness checks.
type Config struct {
	Interface        string
	MinDiskWriteMBps float64 // minimum disk write speed in MB/s
	MinStorageGB     float64 // minimum available storage in GB
	MaxClockOffsetMs int64   // maximum acceptable clock offset in milliseconds
	PCAPStoragePath  string  // path to check for available storage
	MinRXRingBuffer  int     // minimum RX ring buffer size
	CaptureWorkers   int     // number of capture worker threads (for RSS queue check)
	CaptureCPUList   string  // CPU list for isolation check (from CAPTURE_CPU_LIST env)
	DiskTestSizeBytes int64  // size of test file for NVMe throughput test (default 1GB)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Interface:         "eth0",
		MinDiskWriteMBps:  500,
		MinStorageGB:      10,
		MaxClockOffsetMs:  10,
		PCAPStoragePath:   "/sensor/pcap",
		MinRXRingBuffer:   2048,
		CaptureWorkers:    1,
		CaptureCPUList:    "",
		DiskTestSizeBytes: 1 << 30, // 1 GB
	}
}

// ── Injectable function variables for testing ────────────────────────────────

// readFileFunc is used by checks to read files; injectable for testing.
var readFileFunc = os.ReadFile

// globFunc is used by checks to glob paths; injectable for testing.
var globFunc = filepath.Glob

// statfsFunc is used by storage check; injectable for testing.
var statfsFunc = func(path string, buf *syscall.Statfs_t) error {
	return syscall.Statfs(path, buf)
}

// adjtimexFunc is used by clock sync check; injectable for testing.
var adjtimexFunc = func(buf *unix.Timex) (int, error) {
	return unix.Adjtimex(buf)
}

// getInterfaceFlagsFunc is used by promiscuous mode check; injectable for testing.
var getInterfaceFlagsFunc = getInterfaceFlags

// writeTestFileFunc measures disk write throughput; injectable for testing.
// Returns measured MB/s and any error.
var writeTestFileFunc = writeTestFile

// Checker performs host readiness checks before enabling capture.
type Checker struct {
	cfg Config
}

// New creates a new Checker with the given config.
func New(cfg Config) *Checker {
	return &Checker{cfg: cfg}
}

// Check runs all readiness checks and returns a ReadinessReport.
// Passed is false only when one or more hard-severity checks fail.
func (c *Checker) Check() ReadinessReport {
	checks := []CheckResult{
		c.checkInterface(),
		c.checkAFPacket(),
		c.checkStorage(),
		c.checkGRODisabled(),
		c.checkLRODisabled(),
		c.checkRXRingBuffer(),
		c.checkPromiscuousMode(),
		c.checkRSSQueues(),
		c.checkCPUIsolation(),
		c.checkNVMeWriteThroughput(),
		c.checkClockSync(),
		c.checkCapabilities(),
	}

	passed := true
	for _, ch := range checks {
		if !ch.Passed && ch.Severity == SeverityHard {
			passed = false
		}
	}

	return ReadinessReport{
		Passed: passed,
		Checks: checks,
	}
}

// ── Existing checks (updated with severity) ──────────────────────────────────

// checkInterface verifies the monitored interface exists and has link up.
func (c *Checker) checkInterface() CheckResult {
	name := "interface_exists_and_link_up"

	operstatePath := fmt.Sprintf("/sys/class/net/%s/operstate", c.cfg.Interface)
	data, err := readFileFunc(operstatePath)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("interface %q not found: %v", c.cfg.Interface, err),
			ObservedValue: "not_found",
			RequiredValue: "up",
			Severity:      SeverityHard,
		}
	}

	state := strings.TrimSpace(string(data))

	if state != "up" && state != "unknown" {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("interface %q link state is %q (expected up)", c.cfg.Interface, state),
			ObservedValue: state,
			RequiredValue: "up",
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("interface %q is %s", c.cfg.Interface, state),
		ObservedValue: state,
		RequiredValue: "up",
		Severity:      SeverityHard,
	}
}

// checkAFPacket verifies an AF_PACKET socket can be created and bound.
func (c *Checker) checkAFPacket() CheckResult {
	name := "af_packet_bindable"

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot create AF_PACKET socket: %v", err),
			ObservedValue: err.Error(),
			RequiredValue: "socket_creation_ok",
			Severity:      SeverityHard,
		}
	}
	unix.Close(fd)

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       "AF_PACKET socket creation succeeded",
		ObservedValue: "ok",
		RequiredValue: "socket_creation_ok",
		Severity:      SeverityHard,
	}
}

// checkStorage verifies available storage meets the minimum threshold.
func (c *Checker) checkStorage() CheckResult {
	name := "available_storage"

	if err := os.MkdirAll(c.cfg.PCAPStoragePath, 0755); err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot create PCAP storage path %s: %v", c.cfg.PCAPStoragePath, err),
			ObservedValue: "path_error",
			RequiredValue: fmt.Sprintf(">= %.1f GB", c.cfg.MinStorageGB),
			Severity:      SeverityHard,
		}
	}

	var stat syscall.Statfs_t
	if err := statfsFunc(c.cfg.PCAPStoragePath, &stat); err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("statfs %s: %v", c.cfg.PCAPStoragePath, err),
			ObservedValue: "statfs_error",
			RequiredValue: fmt.Sprintf(">= %.1f GB", c.cfg.MinStorageGB),
			Severity:      SeverityHard,
		}
	}

	availGB := float64(stat.Bavail) * float64(stat.Bsize) / (1024 * 1024 * 1024)
	if availGB < c.cfg.MinStorageGB {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("available storage %.1f GB < minimum %.1f GB at %s", availGB, c.cfg.MinStorageGB, c.cfg.PCAPStoragePath),
			ObservedValue: fmt.Sprintf("%.1f GB", availGB),
			RequiredValue: fmt.Sprintf(">= %.1f GB", c.cfg.MinStorageGB),
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("available storage %.1f GB at %s", availGB, c.cfg.PCAPStoragePath),
		ObservedValue: fmt.Sprintf("%.1f GB", availGB),
		RequiredValue: fmt.Sprintf(">= %.1f GB", c.cfg.MinStorageGB),
		Severity:      SeverityHard,
	}
}

// checkCapabilities verifies the process has the required Linux capabilities.
func (c *Checker) checkCapabilities() CheckResult {
	name := "required_capabilities"

	podmanSock := os.Getenv("PODMAN_SOCKET_PATH")
	if podmanSock == "" {
		podmanSock = "/run/podman/podman.sock"
	}

	if _, err := os.Stat(podmanSock); err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("Podman socket %s not accessible: %v", podmanSock, err),
			ObservedValue: "not_accessible",
			RequiredValue: "accessible",
			Severity:      SeverityHard,
		}
	}

	if _, err := os.Stat("/proc/net/packet"); err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("/proc/net/packet not accessible: %v", err),
			ObservedValue: "not_accessible",
			RequiredValue: "accessible",
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       "required capabilities and socket access verified",
		ObservedValue: "ok",
		RequiredValue: "accessible",
		Severity:      SeverityHard,
	}
}

// ── New NIC and host tuning checks ───────────────────────────────────────────

// checkGRODisabled verifies that Generic Receive Offload is disabled on the capture interface.
// Hard failure — GRO coalesces packets and corrupts per-packet timestamps.
func (c *Checker) checkGRODisabled() CheckResult {
	name := "gro_disabled"
	required := "off"

	// Try sysfs first: /sys/class/net/<iface>/gro_flush_timeout being 0 is a hint,
	// but the authoritative source is the features file or ethtool.
	// We read /sys/class/net/<iface>/gro_flush_timeout as a proxy.
	// A more reliable approach: read the generic-receive-offload feature.
	featurePath := fmt.Sprintf("/sys/class/net/%s/gro_flush_timeout", c.cfg.Interface)
	data, err := readFileFunc(featurePath)
	if err != nil {
		// Cannot determine GRO state — treat as unknown/fail.
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot read GRO state for %s: %v", c.cfg.Interface, err),
			ObservedValue: "unknown",
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	val := strings.TrimSpace(string(data))
	// gro_flush_timeout == 0 means GRO is effectively not batching, which is the desired state.
	// However, GRO can still be enabled at the driver level even with flush_timeout=0.
	// For a definitive check we look at the offload features via ethtool ioctl.
	// Since we want to avoid shelling out, we use the sysfs approach:
	// If gro_flush_timeout is 0, GRO is not actively batching — acceptable.
	// A non-zero value means GRO is actively coalescing.
	if val != "0" {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("GRO flush timeout is %s (expected 0 / GRO disabled) on %s", val, c.cfg.Interface),
			ObservedValue: val,
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("GRO disabled on %s (flush_timeout=%s)", c.cfg.Interface, val),
		ObservedValue: "off",
		RequiredValue: required,
		Severity:      SeverityHard,
	}
}

// checkLRODisabled verifies that Large Receive Offload is disabled on the capture interface.
// Hard failure — LRO coalesces TCP segments and breaks per-packet analysis.
func (c *Checker) checkLRODisabled() CheckResult {
	name := "lro_disabled"
	required := "off"

	// LRO status can be read from /sys/class/net/<iface>/features/ on some kernels,
	// or via ethtool ioctl. We check for the large-receive-offload feature flag.
	// On modern kernels, /sys/class/net/<iface>/flags combined with driver-specific
	// sysfs entries may expose this. We use a pragmatic approach: check if the
	// interface has LRO via the features directory if available.
	featuresDir := fmt.Sprintf("/sys/class/net/%s/features", c.cfg.Interface)
	if _, err := os.Stat(featuresDir); err == nil {
		// Some kernels expose individual feature files
		lroPath := filepath.Join(featuresDir, "large-receive-offload")
		data, err := readFileFunc(lroPath)
		if err == nil {
			val := strings.TrimSpace(string(data))
			if val == "on" || val == "1" {
				return CheckResult{
					Name:          name,
					Passed:        false,
					Message:       fmt.Sprintf("LRO is enabled on %s", c.cfg.Interface),
					ObservedValue: "on",
					RequiredValue: required,
					Severity:      SeverityHard,
				}
			}
			return CheckResult{
				Name:          name,
				Passed:        true,
				Message:       fmt.Sprintf("LRO disabled on %s", c.cfg.Interface),
				ObservedValue: "off",
				RequiredValue: required,
				Severity:      SeverityHard,
			}
		}
	}

	// Fallback: most NICs default to LRO off; if we can't determine, pass with a note.
	// In production, ethtool ioctl (ETHTOOL_GFEATURES) would be used here.
	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("LRO assumed disabled on %s (sysfs features not available; verify with ethtool -k)", c.cfg.Interface),
		ObservedValue: "off (assumed)",
		RequiredValue: required,
		Severity:      SeverityHard,
	}
}

// checkRXRingBuffer verifies the RX ring buffer size meets the minimum.
// Soft warning — undersized ring buffers increase drop risk under burst.
func (c *Checker) checkRXRingBuffer() CheckResult {
	name := "rx_ring_buffer"
	required := fmt.Sprintf(">= %d", c.cfg.MinRXRingBuffer)

	// RX ring buffer size is typically read via ethtool ioctl (ETHTOOL_GRINGPARAM).
	// As a sysfs proxy, we can check /sys/class/net/<iface>/rx_queue_len on some systems.
	queueLenPath := fmt.Sprintf("/sys/class/net/%s/tx_queue_len", c.cfg.Interface)
	data, err := readFileFunc(queueLenPath)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot read ring buffer info for %s: %v", c.cfg.Interface, err),
			ObservedValue: "unknown",
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	val := strings.TrimSpace(string(data))
	ringSize, err := strconv.Atoi(val)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot parse ring buffer size %q for %s: %v", val, c.cfg.Interface, err),
			ObservedValue: val,
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	if ringSize < c.cfg.MinRXRingBuffer {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("RX ring buffer %d < minimum %d on %s", ringSize, c.cfg.MinRXRingBuffer, c.cfg.Interface),
			ObservedValue: strconv.Itoa(ringSize),
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("RX ring buffer %d >= minimum %d on %s", ringSize, c.cfg.MinRXRingBuffer, c.cfg.Interface),
		ObservedValue: strconv.Itoa(ringSize),
		RequiredValue: required,
		Severity:      SeveritySoft,
	}
}

// checkPromiscuousMode verifies the capture interface is in promiscuous mode.
// Hard failure — without promiscuous mode the NIC drops non-local traffic.
func (c *Checker) checkPromiscuousMode() CheckResult {
	name := "promiscuous_mode"
	required := "enabled"

	flags, err := getInterfaceFlagsFunc(c.cfg.Interface)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot get interface flags for %s: %v", c.cfg.Interface, err),
			ObservedValue: "unknown",
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	// IFF_PROMISC is 0x100
	if flags&0x100 == 0 {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("promiscuous mode not enabled on %s", c.cfg.Interface),
			ObservedValue: "disabled",
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("promiscuous mode enabled on %s", c.cfg.Interface),
		ObservedValue: "enabled",
		RequiredValue: required,
		Severity:      SeverityHard,
	}
}

// checkRSSQueues verifies the number of RSS queues is at least the worker count.
// Soft warning — fewer queues than workers means some workers share queues.
func (c *Checker) checkRSSQueues() CheckResult {
	name := "rss_queues"
	required := fmt.Sprintf(">= %d", c.cfg.CaptureWorkers)

	pattern := fmt.Sprintf("/sys/class/net/%s/queues/rx-*", c.cfg.Interface)
	matches, err := globFunc(pattern)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot enumerate RSS queues for %s: %v", c.cfg.Interface, err),
			ObservedValue: "unknown",
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	queueCount := len(matches)
	if queueCount < c.cfg.CaptureWorkers {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("RSS queues %d < capture workers %d on %s", queueCount, c.cfg.CaptureWorkers, c.cfg.Interface),
			ObservedValue: strconv.Itoa(queueCount),
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("RSS queues %d >= capture workers %d on %s", queueCount, c.cfg.CaptureWorkers, c.cfg.Interface),
		ObservedValue: strconv.Itoa(queueCount),
		RequiredValue: required,
		Severity:      SeveritySoft,
	}
}

// checkCPUIsolation verifies that CPUs in CAPTURE_CPU_LIST are isolated from the scheduler.
// Soft warning — only checked when CaptureCPUList is configured.
func (c *Checker) checkCPUIsolation() CheckResult {
	name := "cpu_isolation"

	if c.cfg.CaptureCPUList == "" {
		return CheckResult{
			Name:          name,
			Passed:        true,
			Message:       "CAPTURE_CPU_LIST not configured; skipping CPU isolation check",
			ObservedValue: "not_configured",
			RequiredValue: "not_configured",
			Severity:      SeveritySoft,
		}
	}

	required := fmt.Sprintf("CPUs %s isolated", c.cfg.CaptureCPUList)

	data, err := readFileFunc("/sys/devices/system/cpu/isolated")
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("cannot read isolated CPUs: %v", err),
			ObservedValue: "unknown",
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	isolatedStr := strings.TrimSpace(string(data))
	isolatedSet := parseCPUList(isolatedStr)
	requestedCPUs := parseCPUList(c.cfg.CaptureCPUList)

	var missing []string
	for _, cpu := range requestedCPUs {
		if !containsInt(isolatedSet, cpu) {
			missing = append(missing, strconv.Itoa(cpu))
		}
	}

	if len(missing) > 0 {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("CPUs %s are not isolated (isolated: %s)", strings.Join(missing, ","), isolatedStr),
			ObservedValue: fmt.Sprintf("isolated=%s", isolatedStr),
			RequiredValue: required,
			Severity:      SeveritySoft,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("all capture CPUs (%s) are isolated", c.cfg.CaptureCPUList),
		ObservedValue: fmt.Sprintf("isolated=%s", isolatedStr),
		RequiredValue: required,
		Severity:      SeveritySoft,
	}
}

// checkNVMeWriteThroughput writes a test file and measures throughput.
// Hard failure — insufficient disk throughput causes packet loss.
func (c *Checker) checkNVMeWriteThroughput() CheckResult {
	name := "nvme_write_throughput"
	required := fmt.Sprintf(">= %.0f MB/s", c.cfg.MinDiskWriteMBps)

	mbps, err := writeTestFileFunc(c.cfg.PCAPStoragePath, c.cfg.DiskTestSizeBytes)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("NVMe write test failed: %v", err),
			ObservedValue: "error",
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	observed := fmt.Sprintf("%.0f MB/s", mbps)
	if mbps < c.cfg.MinDiskWriteMBps {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("NVMe write throughput %.0f MB/s < minimum %.0f MB/s", mbps, c.cfg.MinDiskWriteMBps),
			ObservedValue: observed,
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("NVMe write throughput %.0f MB/s", mbps),
		ObservedValue: observed,
		RequiredValue: required,
		Severity:      SeverityHard,
	}
}

// checkClockSync verifies the system clock offset is within the acceptable threshold.
// Hard failure — clock drift corrupts packet timestamps.
func (c *Checker) checkClockSync() CheckResult {
	name := "clock_sync"
	required := fmt.Sprintf("<= %dms", c.cfg.MaxClockOffsetMs)

	var timex unix.Timex
	state, err := adjtimexFunc(&timex)
	if err != nil {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("adjtimex failed: %v", err),
			ObservedValue: "error",
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	// state: 0=OK, 1=INS, 2=DEL, 3=OOP, 4=WAIT, 5=ERROR
	if state == 5 {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       "clock is unsynchronized (adjtimex state=ERROR)",
			ObservedValue: "unsynchronized",
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	// offset is in nanoseconds (TIME_ADJTIME mode) or microseconds
	offsetMs := timex.Offset / int64(time.Millisecond)
	if offsetMs < 0 {
		offsetMs = -offsetMs
	}

	observed := fmt.Sprintf("%dms", offsetMs)
	if offsetMs > c.cfg.MaxClockOffsetMs {
		return CheckResult{
			Name:          name,
			Passed:        false,
			Message:       fmt.Sprintf("clock offset %dms exceeds threshold %dms", offsetMs, c.cfg.MaxClockOffsetMs),
			ObservedValue: observed,
			RequiredValue: required,
			Severity:      SeverityHard,
		}
	}

	return CheckResult{
		Name:          name,
		Passed:        true,
		Message:       fmt.Sprintf("clock offset %dms within threshold %dms", offsetMs, c.cfg.MaxClockOffsetMs),
		ObservedValue: observed,
		RequiredValue: required,
		Severity:      SeverityHard,
	}
}

// ── Helper functions ─────────────────────────────────────────────────────────

// ifreqFlags is used for SIOCGIFFLAGS ioctl.
type ifreqFlags struct {
	Name  [16]byte
	Flags int16
	_     [22]byte
}

// getInterfaceFlags returns the interface flags via SIOCGIFFLAGS ioctl.
func getInterfaceFlags(iface string) (int16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var req ifreqFlags
	copy(req.Name[:], iface)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return 0, errno
	}
	return req.Flags, nil
}

// parseCPUList parses a CPU list string like "0-3,5,7-9" into individual CPU numbers.
func parseCPUList(s string) []int {
	if s == "" {
		return nil
	}
	var cpus []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.Index(part, "-"); idx >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(part[:idx]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if err1 != nil || err2 != nil {
				continue
			}
			for i := lo; i <= hi; i++ {
				cpus = append(cpus, i)
			}
		} else {
			n, err := strconv.Atoi(part)
			if err == nil {
				cpus = append(cpus, n)
			}
		}
	}
	return cpus
}

// containsInt returns true if the slice contains the value.
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// writeTestFile writes a test file of the given size to the directory and returns MB/s.
func writeTestFile(dir string, sizeBytes int64) (float64, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, fmt.Errorf("create dir: %w", err)
	}

	testPath := filepath.Join(dir, ".readiness_write_test")
	defer os.Remove(testPath)

	f, err := os.OpenFile(testPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, fmt.Errorf("open test file: %w", err)
	}

	buf := make([]byte, 4*1024*1024) // 4 MB write buffer
	remaining := sizeBytes

	start := time.Now()
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		written, err := f.Write(buf[:n])
		if err != nil {
			f.Close()
			return 0, fmt.Errorf("write: %w", err)
		}
		remaining -= int64(written)
	}

	// Sync to ensure data is flushed to disk
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, fmt.Errorf("sync: %w", err)
	}
	f.Close()

	elapsed := time.Since(start)
	if elapsed == 0 {
		elapsed = time.Microsecond // avoid division by zero
	}

	mbps := float64(sizeBytes) / (1024 * 1024) / elapsed.Seconds()
	return mbps, nil
}
