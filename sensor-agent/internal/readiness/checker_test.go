//go:build linux

package readiness

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

// stubReadFile returns a readFileFunc that serves files from a map.
func stubReadFile(files map[string]string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if content, ok := files[path]; ok {
			return []byte(content), nil
		}
		return nil, fmt.Errorf("stubbed: file not found: %s", path)
	}
}

// stubGlob returns a globFunc that returns the given matches.
func stubGlob(matches []string) func(string) ([]string, error) {
	return func(_ string) ([]string, error) {
		return matches, nil
	}
}

// stubAdjtimex returns an adjtimexFunc with the given state and offset.
func stubAdjtimex(state int, offsetNs int64, err error) func(*unix.Timex) (int, error) {
	return func(buf *unix.Timex) (int, error) {
		if err != nil {
			return 0, err
		}
		buf.Offset = offsetNs
		return state, nil
	}
}

// stubWriteTestFile returns a writeTestFileFunc with the given throughput.
func stubWriteTestFile(mbps float64, err error) func(string, int64) (float64, error) {
	return func(_ string, _ int64) (float64, error) {
		return mbps, err
	}
}

// stubInterfaceFlags returns a getInterfaceFlagsFunc with the given flags.
func stubInterfaceFlags(flags int16, err error) func(string) (int16, error) {
	return func(_ string) (int16, error) {
		return flags, err
	}
}

// stubStatfs returns a statfsFunc with the given available space.
func stubStatfs(bavail uint64, bsize int64) func(string, *syscall.Statfs_t) error {
	return func(_ string, buf *syscall.Statfs_t) error {
		buf.Bavail = bavail
		buf.Bsize = bsize
		return nil
	}
}

// saveAndRestore saves the current injectable functions and returns a cleanup func.
func saveAndRestore() func() {
	origRead := readFileFunc
	origGlob := globFunc
	origStatfs := statfsFunc
	origAdjtimex := adjtimexFunc
	origFlags := getInterfaceFlagsFunc
	origWrite := writeTestFileFunc
	return func() {
		readFileFunc = origRead
		globFunc = origGlob
		statfsFunc = origStatfs
		adjtimexFunc = origAdjtimex
		getInterfaceFlagsFunc = origFlags
		writeTestFileFunc = origWrite
	}
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestCheckResult_SeverityField(t *testing.T) {
	// Verify that CheckResult has the expected severity values.
	hard := CheckResult{Severity: SeverityHard}
	soft := CheckResult{Severity: SeveritySoft}
	if hard.Severity != "hard" {
		t.Errorf("expected SeverityHard = %q, got %q", "hard", hard.Severity)
	}
	if soft.Severity != "soft" {
		t.Errorf("expected SeveritySoft = %q, got %q", "soft", soft.Severity)
	}
}

func TestCheckGRODisabled_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/gro_flush_timeout": "0\n",
	})

	c := New(DefaultConfig())
	result := c.checkGRODisabled()

	if !result.Passed {
		t.Errorf("expected GRO check to pass, got: %s", result.Message)
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
	if result.Name != "gro_disabled" {
		t.Errorf("expected name gro_disabled, got %s", result.Name)
	}
}

func TestCheckGRODisabled_Fail(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/gro_flush_timeout": "250000\n",
	})

	c := New(DefaultConfig())
	result := c.checkGRODisabled()

	if result.Passed {
		t.Error("expected GRO check to fail when flush_timeout is non-zero")
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
	if result.ObservedValue == "" {
		t.Error("expected non-empty observed value")
	}
}

func TestCheckLRODisabled_Pass_NoFeatures(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	// When sysfs features dir doesn't exist, LRO is assumed off.
	readFileFunc = stubReadFile(map[string]string{})

	c := New(DefaultConfig())
	result := c.checkLRODisabled()

	if !result.Passed {
		t.Errorf("expected LRO check to pass (assumed off), got: %s", result.Message)
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
}

func TestCheckRXRingBuffer_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/tx_queue_len": "4096\n",
	})

	cfg := DefaultConfig()
	cfg.MinRXRingBuffer = 2048
	c := New(cfg)
	result := c.checkRXRingBuffer()

	if !result.Passed {
		t.Errorf("expected RX ring buffer check to pass, got: %s", result.Message)
	}
	if result.Severity != SeveritySoft {
		t.Errorf("expected severity soft, got %s", result.Severity)
	}
	if result.ObservedValue != "4096" {
		t.Errorf("expected observed value 4096, got %s", result.ObservedValue)
	}
}

func TestCheckRXRingBuffer_Fail(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/tx_queue_len": "512\n",
	})

	cfg := DefaultConfig()
	cfg.MinRXRingBuffer = 2048
	c := New(cfg)
	result := c.checkRXRingBuffer()

	if result.Passed {
		t.Error("expected RX ring buffer check to fail when below minimum")
	}
	if result.Severity != SeveritySoft {
		t.Errorf("expected severity soft, got %s", result.Severity)
	}
}

func TestCheckPromiscuousMode_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	// IFF_PROMISC = 0x100
	getInterfaceFlagsFunc = stubInterfaceFlags(0x100, nil)

	c := New(DefaultConfig())
	result := c.checkPromiscuousMode()

	if !result.Passed {
		t.Errorf("expected promiscuous mode check to pass, got: %s", result.Message)
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
}

func TestCheckPromiscuousMode_Fail(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	getInterfaceFlagsFunc = stubInterfaceFlags(0x0, nil)

	c := New(DefaultConfig())
	result := c.checkPromiscuousMode()

	if result.Passed {
		t.Error("expected promiscuous mode check to fail when not set")
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
	if result.ObservedValue != "disabled" {
		t.Errorf("expected observed value 'disabled', got %s", result.ObservedValue)
	}
}

func TestCheckRSSQueues_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	globFunc = stubGlob([]string{
		"/sys/class/net/eth0/queues/rx-0",
		"/sys/class/net/eth0/queues/rx-1",
		"/sys/class/net/eth0/queues/rx-2",
		"/sys/class/net/eth0/queues/rx-3",
	})

	cfg := DefaultConfig()
	cfg.CaptureWorkers = 4
	c := New(cfg)
	result := c.checkRSSQueues()

	if !result.Passed {
		t.Errorf("expected RSS queues check to pass, got: %s", result.Message)
	}
	if result.Severity != SeveritySoft {
		t.Errorf("expected severity soft, got %s", result.Severity)
	}
}

func TestCheckRSSQueues_Fail(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	globFunc = stubGlob([]string{
		"/sys/class/net/eth0/queues/rx-0",
	})

	cfg := DefaultConfig()
	cfg.CaptureWorkers = 4
	c := New(cfg)
	result := c.checkRSSQueues()

	if result.Passed {
		t.Error("expected RSS queues check to fail when fewer queues than workers")
	}
	if result.ObservedValue != "1" {
		t.Errorf("expected observed value '1', got %s", result.ObservedValue)
	}
}

func TestCheckCPUIsolation_Skipped(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	cfg := DefaultConfig()
	cfg.CaptureCPUList = "" // not configured
	c := New(cfg)
	result := c.checkCPUIsolation()

	if !result.Passed {
		t.Error("expected CPU isolation check to pass when not configured")
	}
	if result.Severity != SeveritySoft {
		t.Errorf("expected severity soft, got %s", result.Severity)
	}
}

func TestCheckCPUIsolation_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/devices/system/cpu/isolated": "2-5\n",
	})

	cfg := DefaultConfig()
	cfg.CaptureCPUList = "2,3,4"
	c := New(cfg)
	result := c.checkCPUIsolation()

	if !result.Passed {
		t.Errorf("expected CPU isolation check to pass, got: %s", result.Message)
	}
}

func TestCheckCPUIsolation_Fail(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/devices/system/cpu/isolated": "2-3\n",
	})

	cfg := DefaultConfig()
	cfg.CaptureCPUList = "2,3,6"
	c := New(cfg)
	result := c.checkCPUIsolation()

	if result.Passed {
		t.Error("expected CPU isolation check to fail when CPU 6 is not isolated")
	}
}

func TestCheckNVMeWriteThroughput_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	writeTestFileFunc = stubWriteTestFile(1000.0, nil)

	cfg := DefaultConfig()
	cfg.MinDiskWriteMBps = 500
	c := New(cfg)
	result := c.checkNVMeWriteThroughput()

	if !result.Passed {
		t.Errorf("expected NVMe write check to pass, got: %s", result.Message)
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
}

func TestCheckNVMeWriteThroughput_Fail(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	writeTestFileFunc = stubWriteTestFile(200.0, nil)

	cfg := DefaultConfig()
	cfg.MinDiskWriteMBps = 500
	c := New(cfg)
	result := c.checkNVMeWriteThroughput()

	if result.Passed {
		t.Error("expected NVMe write check to fail when below minimum")
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
}

func TestCheckClockSync_Pass(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	// offset 5ms in nanoseconds = 5_000_000
	adjtimexFunc = stubAdjtimex(0, 5_000_000, nil)

	cfg := DefaultConfig()
	cfg.MaxClockOffsetMs = 10
	c := New(cfg)
	result := c.checkClockSync()

	if !result.Passed {
		t.Errorf("expected clock sync check to pass, got: %s", result.Message)
	}
	if result.Severity != SeverityHard {
		t.Errorf("expected severity hard, got %s", result.Severity)
	}
}

func TestCheckClockSync_Fail_Offset(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	// offset 50ms in nanoseconds = 50_000_000
	adjtimexFunc = stubAdjtimex(0, 50_000_000, nil)

	cfg := DefaultConfig()
	cfg.MaxClockOffsetMs = 10
	c := New(cfg)
	result := c.checkClockSync()

	if result.Passed {
		t.Error("expected clock sync check to fail when offset exceeds threshold")
	}
}

func TestCheckClockSync_Fail_Unsynchronized(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	adjtimexFunc = stubAdjtimex(5, 0, nil) // state 5 = ERROR

	c := New(DefaultConfig())
	result := c.checkClockSync()

	if result.Passed {
		t.Error("expected clock sync check to fail when state is ERROR")
	}
}

func TestCheck_HardFailureBlocksBootstrap(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	// Stub everything to pass except promiscuous mode (hard failure)
	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/operstate":         "up\n",
		"/sys/class/net/eth0/gro_flush_timeout":  "0\n",
		"/sys/class/net/eth0/tx_queue_len":       "4096\n",
	})
	globFunc = stubGlob([]string{"/sys/class/net/eth0/queues/rx-0"})
	adjtimexFunc = stubAdjtimex(0, 0, nil)
	writeTestFileFunc = stubWriteTestFile(1000.0, nil)
	getInterfaceFlagsFunc = stubInterfaceFlags(0x0, nil) // no promisc = hard fail
	statfsFunc = stubStatfs(100*1024*1024, 1024)         // ~100 GB

	c := New(DefaultConfig())
	report := c.Check()

	if report.Passed {
		t.Error("expected report.Passed to be false when a hard check fails")
	}

	// Find the promiscuous mode check
	found := false
	for _, ch := range report.Checks {
		if ch.Name == "promiscuous_mode" {
			found = true
			if ch.Passed {
				t.Error("expected promiscuous_mode check to fail")
			}
			if ch.Severity != SeverityHard {
				t.Errorf("expected severity hard, got %s", ch.Severity)
			}
		}
	}
	if !found {
		t.Error("promiscuous_mode check not found in report")
	}
}

func TestCheck_SoftFailureDoesNotBlockBootstrap(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	// Stub everything to pass except RSS queues (soft failure)
	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/operstate":         "up\n",
		"/sys/class/net/eth0/gro_flush_timeout":  "0\n",
		"/sys/class/net/eth0/tx_queue_len":       "4096\n",
	})
	globFunc = stubGlob([]string{"/sys/class/net/eth0/queues/rx-0"}) // 1 queue < 4 workers
	adjtimexFunc = stubAdjtimex(0, 0, nil)
	writeTestFileFunc = stubWriteTestFile(1000.0, nil)
	getInterfaceFlagsFunc = stubInterfaceFlags(0x100, nil) // promisc on
	statfsFunc = stubStatfs(100*1024*1024, 1024)           // ~100 GB

	cfg := DefaultConfig()
	cfg.CaptureWorkers = 4 // more workers than queues → soft fail
	c := New(cfg)
	report := c.Check()

	if !report.Passed {
		t.Error("expected report.Passed to be true when only soft checks fail")
	}

	// Verify the RSS check did fail
	for _, ch := range report.Checks {
		if ch.Name == "rss_queues" {
			if ch.Passed {
				t.Error("expected rss_queues check to fail")
			}
			if ch.Severity != SeveritySoft {
				t.Errorf("expected severity soft, got %s", ch.Severity)
			}
		}
	}
}

func TestParseCPUList(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
	}{
		{"", nil},
		{"0", []int{0}},
		{"0,1,2", []int{0, 1, 2}},
		{"0-3", []int{0, 1, 2, 3}},
		{"0-2,5,7-9", []int{0, 1, 2, 5, 7, 8, 9}},
		{"  1 , 3 ", []int{1, 3}},
	}

	for _, tt := range tests {
		result := parseCPUList(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseCPUList(%q) = %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("parseCPUList(%q)[%d] = %d, want %d", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

func TestWriteTestFile_Integration(t *testing.T) {
	// Test the actual writeTestFile function with a small file.
	dir := t.TempDir()
	mbps, err := writeTestFile(dir, 1024*1024) // 1 MB
	if err != nil {
		t.Fatalf("writeTestFile failed: %v", err)
	}
	if mbps <= 0 {
		t.Errorf("expected positive throughput, got %.2f MB/s", mbps)
	}

	// Verify the test file was cleaned up.
	testPath := filepath.Join(dir, ".readiness_write_test")
	if _, err := os.Stat(testPath); !os.IsNotExist(err) {
		t.Error("expected test file to be cleaned up")
	}
}

func TestCheckResult_FieldsPopulated(t *testing.T) {
	cleanup := saveAndRestore()
	defer cleanup()

	readFileFunc = stubReadFile(map[string]string{
		"/sys/class/net/eth0/gro_flush_timeout": "0\n",
	})

	c := New(DefaultConfig())
	result := c.checkGRODisabled()

	// Verify all fields are populated per requirement 12.6
	if result.Name == "" {
		t.Error("expected non-empty Name")
	}
	if result.ObservedValue == "" {
		t.Error("expected non-empty ObservedValue")
	}
	if result.RequiredValue == "" {
		t.Error("expected non-empty RequiredValue")
	}
	if result.Severity == "" {
		t.Error("expected non-empty Severity")
	}
}
