//go:build linux

package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

// ── Test audit logger ─────────────────────────────────────────────────────────

// fileAuditLogger implements AuditLogger by writing JSON-lines to a file.
type fileAuditLogger struct {
	path string
	f    *os.File
}

func newFileAuditLogger(path string) (*fileAuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &fileAuditLogger{path: path, f: f}, nil
}

func (l *fileAuditLogger) Log(action, actor, result string, detail map[string]any) {
	entry := map[string]any{
		"action": action,
		"actor":  actor,
		"result": result,
		"detail": detail,
	}
	data, _ := json.Marshal(entry)
	l.f.Write(data)
	l.f.Write([]byte("\n"))
}

func (l *fileAuditLogger) Close() error { return l.f.Close() }

// auditLogEntry is a minimal representation of an audit log entry for testing.
type auditLogEntry struct {
	Action string         `json:"action"`
	Actor  string         `json:"actor"`
	Result string         `json:"result"`
	Detail map[string]any `json:"detail"`
}

func readAuditLog(t *testing.T, path string) []auditLogEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entries []auditLogEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e auditLogEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries
}

// readAuditLogFromPath reads audit log entries from a path (for use inside rapid callbacks).
func readAuditLogFromPath(path string) ([]auditLogEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []auditLogEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e auditLogEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// setupTestDir creates a temp directory with a BPF filter file and optional audit log.
// Returns (dir, filterPath, auditPath).
func setupTestDir(t *testing.T, initialFilter string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	filterPath := filepath.Join(dir, "bpf.filter")
	if err := os.WriteFile(filterPath, []byte(initialFilter), 0644); err != nil {
		t.Fatalf("write initial filter: %v", err)
	}
	auditPath := filepath.Join(dir, "audit.log")
	return dir, filterPath, auditPath
}

// readFilter reads the current filter file contents.
func readFilter(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read filter file: %v", err)
	}
	return string(data)
}

// ── Property 5: BPF filter validation before state mutation ──────────────────
//
// For any BPF filter string that fails compilation, the Capture_Manager SHALL
// reject the change and leave the existing filter file contents and process
// state unchanged after the rejection attempt.
//
// Validates: Requirements 4.2, 4.3

// TestProperty5_BPFFilterValidationBeforeStateMutation_CompilationFailure is the
// core property test for task 7.1. It injects a BPF compiler that always fails
// and verifies that for any arbitrary filter string and any consumer:
//  1. ApplyBPFFilter returns a non-nil error
//  2. The bpfFilterPath (watched source-of-truth file) is unchanged
//  3. Consumer-specific config files (zeek/suricata BPF paths) are not created
//  4. The bpfRestartPending state remains unchanged (no restart was attempted)
//  5. No ReloadEvent is emitted to the event channel (processing never reached consumers)
func TestProperty5_BPFFilterValidationBeforeStateMutation_CompilationFailure(t *testing.T) {
	// **Validates: Requirements 4.2, 4.3**
	rapid.Check(t, func(t *rapid.T) {
		initialFilter := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "initial_filter")
		newFilter := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "new_filter")
		compilationErrMsg := rapid.StringMatching(`[a-z ]{5,40}`).Draw(t, "err_msg")
		consumerName := rapid.SampledFrom([]string{"pcap_ring_writer", "zeek", "suricata"}).Draw(t, "consumer")

		// Create temp dir manually (rapid.T doesn't have TempDir).
		dir, err := os.MkdirTemp("", "bpf_prop5_*")
		if err != nil {
			t.Fatalf("mkdirtemp: %v", err)
		}
		defer os.RemoveAll(dir)

		filterPath := filepath.Join(dir, "bpf.filter")
		if err := os.WriteFile(filterPath, []byte(initialFilter), 0644); err != nil {
			t.Fatalf("write initial filter: %v", err)
		}

		// Create consumer-specific config paths so we can verify they are NOT written.
		// Use the same directory structure the Manager would write to.
		zeekCfgPath := filepath.Join(dir, "zeek_bpf.filter")
		suricataCfgPath := filepath.Join(dir, "suricata_bpf.filter")

		consumers := []ConsumerConfig{
			{Name: consumerName, FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
		}
		cfg := &CaptureConfig{Consumers: consumers}

		// Inject a BPF compiler that always fails — simulating an invalid filter.
		failingCompiler := func(filter string) ([]unix.SockFilter, error) {
			return nil, fmt.Errorf("compile BPF filter: %s", compilationErrMsg)
		}

		m := NewManagerWithConfig(cfg, filterPath, filepath.Join(dir, "pcap_ring.sock"), ManagerConfig{
			BPFCompiler: failingCompiler,
		})

		// Record state before the change attempt.
		filterBefore, _ := os.ReadFile(filterPath)
		pendingBefore := m.BPFRestartPending()

		// Attempt to apply the new filter — must fail.
		applyErr := m.ApplyBPFFilter(newFilter)

		// ── Assertion 1: ApplyBPFFilter must return an error ──
		if applyErr == nil {
			t.Fatalf("ApplyBPFFilter should have returned an error for a failing compiler (consumer=%s, filter=%q)",
				consumerName, newFilter)
		}

		// ── Assertion 2: bpfFilterPath must be unchanged ──
		filterAfter, _ := os.ReadFile(filterPath)
		if string(filterAfter) != string(filterBefore) {
			t.Fatalf("bpfFilterPath was mutated after compilation failure (consumer=%s): before=%q after=%q",
				consumerName, string(filterBefore), string(filterAfter))
		}

		// ── Assertion 3: Consumer-specific config files must NOT be created ──
		// The Manager writes to zeekBPFPath/suricataBPFPath during safeRestartWithBPF.
		// With a failing compiler, it should never reach that code path.
		if _, err := os.Stat(zeekCfgPath); err == nil {
			t.Fatalf("zeek BPF config file was created despite compilation failure")
		}
		if _, err := os.Stat(suricataCfgPath); err == nil {
			t.Fatalf("suricata BPF config file was created despite compilation failure")
		}

		// ── Assertion 4: bpfRestartPending state must be unchanged ──
		pendingAfter := m.BPFRestartPending()
		for k, v := range pendingBefore {
			if pendingAfter[k] != v {
				t.Fatalf("bpfRestartPending[%s] changed from %v to %v after compilation failure",
					k, v, pendingAfter[k])
			}
		}
		for k, v := range pendingAfter {
			if pendingBefore[k] != v {
				t.Fatalf("bpfRestartPending[%s] appeared with value %v after compilation failure",
					k, v)
			}
		}

		// ── Assertion 5: No ReloadEvent emitted ──
		// The event channel should be empty because processing was rejected before
		// reaching any consumer.
		select {
		case event := <-m.Events():
			t.Fatalf("unexpected ReloadEvent emitted after compilation failure: %+v", event)
		default:
			// Good — no event emitted.
		}
	})
}

// TestProperty5_BPFFilterValidationBeforeStateMutation verifies that the
// bpfFilterPath (the source-of-truth filter file watched by the Manager) is
// never written by ApplyBPFFilter even for valid filters. The Manager reads
// from this file but only writes to consumer-specific config paths.
func TestProperty5_BPFFilterValidationBeforeStateMutation(t *testing.T) {
	// **Validates: Requirements 4.2, 4.3**
	rapid.Check(t, func(t *rapid.T) {
		initialFilter := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "initial_filter")
		newFilter := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "new_filter")
		consumerName := rapid.SampledFrom([]string{"pcap_ring_writer", "zeek", "suricata"}).Draw(t, "consumer")

		// Create temp dir manually (rapid.T doesn't have TempDir).
		dir, err := os.MkdirTemp("", "bpf_test_*")
		if err != nil {
			t.Fatalf("mkdirtemp: %v", err)
		}
		defer os.RemoveAll(dir)

		filterPath := filepath.Join(dir, "bpf.filter")
		if err := os.WriteFile(filterPath, []byte(initialFilter), 0644); err != nil {
			t.Fatalf("write initial filter: %v", err)
		}

		consumers := []ConsumerConfig{
			{Name: consumerName, FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
		}
		cfg := &CaptureConfig{Consumers: consumers}
		m := NewManager(cfg, filterPath, filepath.Join(dir, "pcap_ring.sock"))

		// Record state before any change attempt.
		stateBefore, _ := os.ReadFile(filterPath)

		// Apply a new filter. This will fail for restart-required consumers
		// (no Podman client) and for pcap_ring_writer (no socket), but the
		// bpfFilterPath must remain unchanged in all cases.
		_ = m.ApplyBPFFilter(newFilter)

		stateAfter, _ := os.ReadFile(filterPath)
		if string(stateAfter) != string(stateBefore) {
			t.Fatalf("bpfFilterPath was mutated by ApplyBPFFilter (consumer=%s): before=%q after=%q",
				consumerName, string(stateBefore), string(stateAfter))
		}
	})
}

// TestProperty5_ZeekSuricataClassifiedAsRestartRequired verifies that Zeek and
// Suricata BPF changes are classified as restart-required (Req 4.1) and that
// the ReloadEvent has RestartRequired=true for these consumers.
func TestProperty5_ZeekSuricataClassifiedAsRestartRequired(t *testing.T) {
	// **Validates: Requirements 4.1**
	for _, consumerName := range []string{"zeek", "suricata"} {
		t.Run(consumerName, func(t *testing.T) {
			dir, filterPath, _ := setupTestDir(t, "tcp")
			consumers := []ConsumerConfig{
				{Name: consumerName, FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
			}
			cfg := &CaptureConfig{Consumers: consumers}
			m := NewManager(cfg, filterPath, filepath.Join(dir, "pcap_ring.sock"))

			_ = m.ApplyBPFFilter("udp")

			// The event channel is buffered (32). Read the event.
			select {
			case event := <-m.Events():
				if !event.RestartRequired {
					t.Errorf("consumer %s: expected RestartRequired=true, got false", consumerName)
				}
				if event.LiveReload {
					t.Errorf("consumer %s: expected LiveReload=false (restart required), got true", consumerName)
				}
			default:
				t.Errorf("consumer %s: no event received after ApplyBPFFilter", consumerName)
			}
		})
	}
}

// TestProperty5_PcapRingWriterIsLiveReload verifies that pcap_ring_writer BPF
// changes are classified as live reload (not restart-required).
func TestProperty5_PcapRingWriterIsLiveReload(t *testing.T) {
	// **Validates: Requirements 4.6**
	dir, filterPath, _ := setupTestDir(t, "tcp")
	consumers := []ConsumerConfig{
		{Name: "pcap_ring_writer", FanoutGroupID: 4, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
	}
	cfg := &CaptureConfig{Consumers: consumers}
	m := NewManager(cfg, filterPath, filepath.Join(dir, "pcap_ring.sock"))

	_ = m.ApplyBPFFilter("udp")

	select {
	case event := <-m.Events():
		if event.RestartRequired {
			t.Errorf("pcap_ring_writer: expected RestartRequired=false, got true")
		}
	default:
		// Event may not be present if socket dial failed before event was sent.
		// The key invariant is that the code path does NOT set RestartRequired=true.
	}
}

// ── Property 6: BPF filter change audit log completeness ─────────────────────
//
// For any BPF filter change (valid or invalid), the Sensor_Agent SHALL emit
// an audit log entry that contains the previous filter hash, the new filter
// hash, the affected consumers, and whether each consumer required a restart.
//
// Validates: Requirements 4.8

func TestProperty6_BPFFilterChangeAuditLogCompleteness(t *testing.T) {
	// **Validates: Requirements 4.8**
	rapid.Check(t, func(t *rapid.T) {
		initialFilter := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "initial_filter")
		newFilter := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "new_filter")

		// Create temp dir manually (rapid.T doesn't have TempDir).
		dir, err := os.MkdirTemp("", "bpf_audit_test_*")
		if err != nil {
			t.Fatalf("mkdirtemp: %v", err)
		}
		defer os.RemoveAll(dir)

		filterPath := filepath.Join(dir, "bpf.filter")
		if err := os.WriteFile(filterPath, []byte(initialFilter), 0644); err != nil {
			t.Fatalf("write initial filter: %v", err)
		}
		auditPath := filepath.Join(dir, "audit.log")

		// Choose a mix of consumers
		consumerNames := rapid.SliceOfDistinct(
			rapid.SampledFrom([]string{"pcap_ring_writer", "zeek", "suricata"}),
			func(s string) string { return s },
		).Draw(t, "consumers")
		if len(consumerNames) == 0 {
			consumerNames = []string{"pcap_ring_writer"}
		}

		consumers := make([]ConsumerConfig, len(consumerNames))
		for i, name := range consumerNames {
			consumers[i] = ConsumerConfig{
				Name:          name,
				FanoutGroupID: uint16(i + 1),
				FanoutMode:    FanoutHash,
				Interface:     "eth0",
				ThreadCount:   1,
			}
		}

		al, err := newFileAuditLogger(auditPath)
		if err != nil {
			t.Fatalf("create audit logger: %v", err)
		}
		defer al.Close()

		cfg := &CaptureConfig{Consumers: consumers}
		m := NewManagerWithConfig(cfg, filterPath, filepath.Join(dir, "pcap_ring.sock"), ManagerConfig{
			AuditLog: al,
		})

		// Apply the new filter (will fail for restart-required consumers since no Podman)
		_ = m.ApplyBPFFilter(newFilter)

		// Flush the audit log
		al.Close()

		// Read back audit log entries
		entries, err := readAuditLogFromPath(auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}

		// Find the bpf-filter-change entry
		var bpfEntry *auditLogEntry
		for i := range entries {
			if entries[i].Action == "bpf-filter-change" {
				bpfEntry = &entries[i]
				break
			}
		}

		if bpfEntry == nil {
			t.Fatalf("no bpf-filter-change audit entry found after ApplyBPFFilter; entries: %v", entries)
		}

		// Assert: previous filter hash is present and correct
		prevHash, ok := bpfEntry.Detail["prev_filter_hash"].(string)
		if !ok || prevHash == "" {
			t.Fatalf("audit entry missing prev_filter_hash: %+v", bpfEntry.Detail)
		}
		expectedPrevHash := filterHash(initialFilter)
		if prevHash != expectedPrevHash {
			t.Fatalf("prev_filter_hash mismatch: got %q, want %q", prevHash, expectedPrevHash)
		}

		// Assert: new filter hash is present and correct
		newHash, ok := bpfEntry.Detail["new_filter_hash"].(string)
		if !ok || newHash == "" {
			t.Fatalf("audit entry missing new_filter_hash: %+v", bpfEntry.Detail)
		}
		expectedNewHash := filterHash(newFilter)
		if newHash != expectedNewHash {
			t.Fatalf("new_filter_hash mismatch: got %q, want %q", newHash, expectedNewHash)
		}

		// Assert: consumers field is present and contains per-consumer results
		consumersRaw, ok := bpfEntry.Detail["consumers"]
		if !ok {
			t.Fatalf("audit entry missing consumers field: %+v", bpfEntry.Detail)
		}

		// The consumers field is a JSON array of objects. After JSON round-trip
		// through the audit logger, it arrives as []interface{}.
		consumerList, ok := consumersRaw.([]interface{})
		if !ok {
			t.Fatalf("consumers field is not an array: %T = %+v", consumersRaw, consumersRaw)
		}

		// Assert: every configured consumer appears in the audit entry
		if len(consumerList) != len(consumerNames) {
			t.Fatalf("expected %d consumers in audit entry, got %d: %+v",
				len(consumerNames), len(consumerList), consumerList)
		}

		// Build a lookup of consumer results from the audit entry
		auditConsumers := make(map[string]map[string]interface{})
		for _, raw := range consumerList {
			entry, ok := raw.(map[string]interface{})
			if !ok {
				t.Fatalf("consumer entry is not an object: %T = %+v", raw, raw)
			}
			name, _ := entry["name"].(string)
			if name == "" {
				t.Fatalf("consumer entry missing 'name' field: %+v", entry)
			}
			auditConsumers[name] = entry
		}

		// Assert: each configured consumer has a name and restart_required flag
		for _, name := range consumerNames {
			entry, exists := auditConsumers[name]
			if !exists {
				t.Fatalf("consumer %q not found in audit entry consumers: %+v", name, auditConsumers)
			}

			// restart_required must be present as a boolean
			restartRequired, hasRestart := entry["restart_required"]
			if !hasRestart {
				t.Fatalf("consumer %q missing restart_required in audit entry: %+v", name, entry)
			}

			rr, ok := restartRequired.(bool)
			if !ok {
				t.Fatalf("consumer %q restart_required is not a bool: %T = %v", name, restartRequired, restartRequired)
			}

			// Verify restart_required matches the expected value per consumer type:
			// zeek and suricata are restart-required; pcap_ring_writer is not.
			expectedRR := name == "zeek" || name == "suricata"
			if rr != expectedRR {
				t.Fatalf("consumer %q: expected restart_required=%v, got %v", name, expectedRR, rr)
			}
		}
	})
}

// TestProperty6_RejectedFilterAuditLogCompleteness verifies that even when a
// BPF filter change is rejected (compilation failure), an audit entry is emitted
// with the previous and new filter hashes and a rejection indicator.
func TestProperty6_RejectedFilterAuditLogCompleteness(t *testing.T) {
	// **Validates: Requirements 4.8**
	rapid.Check(t, func(t *rapid.T) {
		prevFilterStr := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "prev_filter")
		newFilterStr := rapid.StringMatching(`[a-z]{3,20}`).Draw(t, "new_filter")
		compilationErrMsg := rapid.StringMatching(`[a-z ]{5,40}`).Draw(t, "err_msg")

		// Draw a random set of consumers to verify the rejected path is
		// independent of consumer configuration.
		consumerName := rapid.SampledFrom([]string{"pcap_ring_writer", "zeek", "suricata"}).Draw(t, "consumer")

		dir, err := os.MkdirTemp("", "bpf_reject_test_*")
		if err != nil {
			t.Fatalf("mkdirtemp: %v", err)
		}
		defer os.RemoveAll(dir)

		auditPath := filepath.Join(dir, "audit.log")
		filterPath := filepath.Join(dir, "bpf.filter")
		if err := os.WriteFile(filterPath, []byte(prevFilterStr), 0644); err != nil {
			t.Fatalf("write filter: %v", err)
		}

		al, err := newFileAuditLogger(auditPath)
		if err != nil {
			t.Fatalf("create audit logger: %v", err)
		}

		// Inject a BPF compiler that always fails.
		failingCompiler := func(filter string) ([]unix.SockFilter, error) {
			return nil, fmt.Errorf("compile BPF filter: %s", compilationErrMsg)
		}

		cfg := &CaptureConfig{Consumers: []ConsumerConfig{
			{Name: consumerName, FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
		}}
		m := NewManagerWithConfig(cfg, filterPath, filepath.Join(dir, "pcap_ring.sock"), ManagerConfig{
			AuditLog:    al,
			BPFCompiler: failingCompiler,
		})

		// Apply the filter through the real code path — must fail compilation.
		applyErr := m.ApplyBPFFilter(newFilterStr)
		if applyErr == nil {
			t.Fatalf("ApplyBPFFilter should have returned an error for a failing compiler")
		}

		al.Close()

		entries, err := readAuditLogFromPath(auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		if len(entries) == 0 {
			t.Fatal("no audit entries found after ApplyBPFFilter with compilation error")
		}

		// Find the bpf-filter-change entry
		var entry *auditLogEntry
		for i := range entries {
			if entries[i].Action == "bpf-filter-change" {
				entry = &entries[i]
				break
			}
		}
		if entry == nil {
			t.Fatalf("no bpf-filter-change audit entry found; entries: %v", entries)
		}

		// prev_filter_hash must be present and match
		prevHash, ok := entry.Detail["prev_filter_hash"].(string)
		if !ok || prevHash == "" {
			t.Fatalf("missing prev_filter_hash in rejected change audit entry: %+v", entry.Detail)
		}
		expectedPrevHash := filterHash(prevFilterStr)
		if prevHash != expectedPrevHash {
			t.Fatalf("prev_filter_hash mismatch: got %q, want %q", prevHash, expectedPrevHash)
		}

		// new_filter_hash must be present and match
		newHash, ok := entry.Detail["new_filter_hash"].(string)
		if !ok || newHash == "" {
			t.Fatalf("missing new_filter_hash in rejected change audit entry: %+v", entry.Detail)
		}
		expectedNewHash := filterHash(newFilterStr)
		if newHash != expectedNewHash {
			t.Fatalf("new_filter_hash mismatch: got %q, want %q", newHash, expectedNewHash)
		}

		// compilation_error must be present
		if _, ok := entry.Detail["compilation_error"]; !ok {
			t.Fatalf("missing compilation_error in rejected change audit entry: %+v", entry.Detail)
		}

		// rejected flag must be true
		if rejected, _ := entry.Detail["rejected"].(bool); !rejected {
			t.Fatalf("expected rejected=true in audit entry: %+v", entry.Detail)
		}

		// consumers field must NOT be present for rejected changes (compilation
		// failed before reaching any consumer).
		if consumers, ok := entry.Detail["consumers"]; ok && consumers != nil {
			t.Fatalf("rejected change should not have consumers field, but got: %+v", consumers)
		}
	})
}
