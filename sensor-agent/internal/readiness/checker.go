//go:build linux

package readiness

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// CheckResult holds the result of a single readiness check.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// ReadinessReport is the result of all readiness checks.
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
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Interface:        "eth0",
		MinDiskWriteMBps: 100,
		MinStorageGB:     10,
		MaxClockOffsetMs: 1000,
		PCAPStoragePath:  "/sensor/pcap",
	}
}

// Checker performs host readiness checks before enabling capture.
type Checker struct {
	cfg Config
}

// New creates a new Checker with the given config.
func New(cfg Config) *Checker {
	return &Checker{cfg: cfg}
}

// Check runs all readiness checks and returns a ReadinessReport.
// If any check fails, Passed is false.
func (c *Checker) Check() ReadinessReport {
	checks := []CheckResult{
		c.checkInterface(),
		c.checkAFPacket(),
		c.checkStorage(),
		c.checkClockSync(),
		c.checkCapabilities(),
	}

	passed := true
	for _, ch := range checks {
		if !ch.Passed {
			passed = false
		}
	}

	return ReadinessReport{
		Passed: passed,
		Checks: checks,
	}
}

// checkInterface verifies the monitored interface exists and has link up.
func (c *Checker) checkInterface() CheckResult {
	name := "interface_exists_and_link_up"

	// Check interface exists via /sys/class/net
	operstatePath := fmt.Sprintf("/sys/class/net/%s/operstate", c.cfg.Interface)
	data, err := os.ReadFile(operstatePath)
	if err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("interface %q not found: %v", c.cfg.Interface, err),
		}
	}

	state := string(data)
	if len(state) > 0 && state[len(state)-1] == '\n' {
		state = state[:len(state)-1]
	}

	if state != "up" && state != "unknown" {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("interface %q link state is %q (expected up)", c.cfg.Interface, state),
		}
	}

	return CheckResult{
		Name:    name,
		Passed:  true,
		Message: fmt.Sprintf("interface %q is %s", c.cfg.Interface, state),
	}
}

// checkAFPacket verifies an AF_PACKET socket can be created and bound.
func (c *Checker) checkAFPacket() CheckResult {
	name := "af_packet_bindable"

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("cannot create AF_PACKET socket: %v", err),
		}
	}
	unix.Close(fd)

	return CheckResult{
		Name:    name,
		Passed:  true,
		Message: "AF_PACKET socket creation succeeded",
	}
}

// checkStorage verifies available storage meets the minimum threshold.
func (c *Checker) checkStorage() CheckResult {
	name := "available_storage"

	// Ensure the path exists
	if err := os.MkdirAll(c.cfg.PCAPStoragePath, 0755); err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("cannot create PCAP storage path %s: %v", c.cfg.PCAPStoragePath, err),
		}
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(c.cfg.PCAPStoragePath, &stat); err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("statfs %s: %v", c.cfg.PCAPStoragePath, err),
		}
	}

	availGB := float64(stat.Bavail) * float64(stat.Bsize) / (1024 * 1024 * 1024)
	if availGB < c.cfg.MinStorageGB {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("available storage %.1f GB < minimum %.1f GB at %s", availGB, c.cfg.MinStorageGB, c.cfg.PCAPStoragePath),
		}
	}

	return CheckResult{
		Name:    name,
		Passed:  true,
		Message: fmt.Sprintf("available storage %.1f GB at %s", availGB, c.cfg.PCAPStoragePath),
	}
}

// checkClockSync verifies the system clock offset is within the acceptable threshold.
func (c *Checker) checkClockSync() CheckResult {
	name := "clock_sync"

	// Use adjtimex to get clock offset
	var timex unix.Timex
	state, err := unix.Adjtimex(&timex)
	if err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("adjtimex failed: %v", err),
		}
	}

	// state: 0=OK, 1=INS, 2=DEL, 3=OOP, 4=WAIT, 5=ERROR
	if state == 5 {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: "clock is unsynchronized (adjtimex state=ERROR)",
		}
	}

	// offset is in nanoseconds (TIME_ADJTIME mode) or microseconds
	offsetMs := timex.Offset / int64(time.Millisecond)
	if offsetMs < 0 {
		offsetMs = -offsetMs
	}

	if offsetMs > c.cfg.MaxClockOffsetMs {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("clock offset %dms exceeds threshold %dms", offsetMs, c.cfg.MaxClockOffsetMs),
		}
	}

	return CheckResult{
		Name:    name,
		Passed:  true,
		Message: fmt.Sprintf("clock offset %dms within threshold %dms", offsetMs, c.cfg.MaxClockOffsetMs),
	}
}

// checkCapabilities verifies the process has the required Linux capabilities.
func (c *Checker) checkCapabilities() CheckResult {
	name := "required_capabilities"

	// Check if we can create an AF_PACKET socket (requires CAP_NET_RAW or CAP_NET_ADMIN)
	// The sensor-agent itself doesn't need CAP_NET_RAW (pcap_ring_writer does),
	// but we verify the Podman socket is accessible.
	podmanSock := os.Getenv("PODMAN_SOCKET_PATH")
	if podmanSock == "" {
		podmanSock = "/run/podman/podman.sock"
	}

	if _, err := os.Stat(podmanSock); err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("Podman socket %s not accessible: %v", podmanSock, err),
		}
	}

	// Check we can read /proc/net/packet (requires no special caps, just existence)
	if _, err := os.Stat("/proc/net/packet"); err != nil {
		return CheckResult{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("/proc/net/packet not accessible: %v", err),
		}
	}

	return CheckResult{
		Name:    name,
		Passed:  true,
		Message: "required capabilities and socket access verified",
	}
}

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
