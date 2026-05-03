package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	"pgregory.net/rapid"
)

// ── Unit tests ────────────────────────────────────────────────────────────────

func TestIndex_InsertAndQuery(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	file := PcapFile{
		FilePath:    "/sensor/pcap/alerts/test.pcap",
		StartTime:   1000,
		EndTime:     2000,
		Interface:   "eth0",
		PacketCount: 100,
		ByteCount:   50000,
		AlertDriven: true,
		CommunityID: "1:abc123",
	}

	id, err := idx.Insert(file)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	files, err := idx.QueryByTimeRange(500, 1500)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
	if files[0].CommunityID != "1:abc123" {
		t.Errorf("expected community_id 1:abc123, got %s", files[0].CommunityID)
	}
}

func TestIndex_DeleteByID(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	id, err := idx.Insert(PcapFile{
		FilePath: "/tmp/test.pcap", StartTime: 1000, EndTime: 2000,
		Interface: "eth0", PacketCount: 10, ByteCount: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := idx.DeleteByID(id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	files, err := idx.QueryByTimeRange(0, 9999)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files after delete, got %d", len(files))
	}
}

func TestManager_DefaultRetentionDuration(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{})
	createdAtMs := time.Now().UnixMilli()
	expiresAtMs := m.retentionExpiresAt(createdAtMs)

	if expiresAtMs <= createdAtMs {
		t.Fatalf("expected default retention expiration after creation time, got created=%d expires=%d", createdAtMs, expiresAtMs)
	}

	want := createdAtMs + int64((7*24*time.Hour)/time.Millisecond)
	if expiresAtMs != want {
		t.Fatalf("default retention mismatch: got %d, want %d", expiresAtMs, want)
	}
}

func TestManager_RetentionCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{
		RetentionDuration: -1,
	})

	if got := m.retentionExpiresAt(time.Now().UnixMilli()); got != 0 {
		t.Fatalf("expected disabled retention expiration 0, got %d", got)
	}
}

// ── Property tests ────────────────────────────────────────────────────────────

// Property 3: Severity filter correctness
// For any alert severity (1, 2, 3) and any configured threshold, assert
// HandleAlert triggers a carve iff severity <= threshold and discards iff
// severity > threshold.
// **Validates: Requirements 3.1, 3.2**
func TestProperty3_SeverityFilterCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := rapid.IntRange(1, 3).Draw(t, "severity")
		threshold := rapid.IntRange(1, 3).Draw(t, "threshold")

		// Set up a temp directory for the index DB and audit log.
		dir, err := os.MkdirTemp("", "pcap-prop3-sev-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		auditLogger, err := audit.New(filepath.Join(dir, "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		defer auditLogger.Close()

		// Manager with an invalid ring socket path. HandleAlert will:
		// - return nil immediately when severity > threshold (discard)
		// - attempt to dial the socket and fail when severity <= threshold (carve)
		m := &Manager{
			ringSocket:     filepath.Join(dir, "nonexistent.sock"),
			alertsDir:      filepath.Join(dir, "alerts"),
			index:          idx,
			auditLog:       auditLogger,
			severityThresh: threshold,
			mode:           "alert_driven",
			preAlertMs:     10,
			postAlertMs:    10,
			sensorID:       "test-sensor",
			dedup:          newDedupCache(30 * time.Second),
		}
		defer m.dedup.stop()

		alert := AlertEvent{
			CommunityID: fmt.Sprintf("1:test-%d-%d", severity, threshold),
			Severity:    severity,
			TimestampMs: time.Now().UnixMilli(),
			SID:         fmt.Sprintf("100%d", rapid.IntRange(0, 9).Draw(t, "sid_suffix")),
		}

		err = m.HandleAlert(alert)

		shouldDiscard := severity > threshold
		if shouldDiscard {
			// Discarded alerts return nil (early return before any socket interaction).
			if err != nil {
				t.Fatalf("severity=%d threshold=%d: expected nil (discard), got error: %v",
					severity, threshold, err)
			}
			// Verify no index entry was created.
			count, countErr := idx.Count()
			if countErr != nil {
				t.Fatalf("severity=%d threshold=%d: failed to count index entries: %v",
					severity, threshold, countErr)
			}
			if count != 0 {
				t.Fatalf("severity=%d threshold=%d: expected 0 index entries after discard, got %d",
					severity, threshold, count)
			}
		} else {
			// Carve-eligible alerts pass the severity filter and attempt to dial
			// the ring socket. Since the socket doesn't exist, HandleAlert returns
			// a non-nil error, proving the alert was NOT discarded.
			if err == nil {
				t.Fatalf("severity=%d threshold=%d: expected socket error (carve attempted), got nil",
					severity, threshold)
			}
		}
	})
}

// Property 4: Alert-Driven Pre-Alert Window Preservation
// For any alert event, the carved PCAP must contain packets spanning
// from at least (alert_time - pre_alert_window) to at least (alert_time + post_alert_window).
// Validates: Requirements 5.3, 5.4
func TestProperty4_PreAlertWindowPreservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		preWindowMs := int64(rapid.IntRange(1000, 30000).Draw(t, "pre_window_ms"))
		postWindowMs := int64(rapid.IntRange(1000, 10000).Draw(t, "post_window_ms"))

		alertTimeMs := int64(rapid.IntRange(60000, 3600000).Draw(t, "alert_time_ms"))
		preAlertMs := alertTimeMs - preWindowMs
		postAlertMs := alertTimeMs + postWindowMs

		dir, err := os.MkdirTemp("", "pcap-prop4-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		pcapPath := filepath.Join(dir, "test.pcap")

		// Write a mock PCAP with packets at preAlertMs, alertTimeMs, and postAlertMs
		writeMockPCAP(t, pcapPath, []int64{preAlertMs, alertTimeMs, postAlertMs})

		minTs, maxTs := readPCAPTimestamps(t, pcapPath)

		if minTs > preAlertMs {
			t.Fatalf("PCAP min timestamp %d > pre-alert time %d: pre-alert window not preserved",
				minTs, preAlertMs)
		}
		if maxTs < postAlertMs {
			t.Fatalf("PCAP max timestamp %d < post-alert time %d: post-alert window not preserved",
				maxTs, postAlertMs)
		}
	})
}

// Property 3: PCAP Storage FIFO Pruning Invariant
// After pruning, the index must be consistent:
// no index entries reference deleted files, no files exist without index entries.
// Validates: Requirements 5.7
func TestProperty3_FIFOPruningInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "pcap-prop3-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		dbPath := filepath.Join(dir, "pcap.db")

		idx, err := OpenIndex(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		numFiles := rapid.IntRange(5, 20).Draw(t, "num_files")
		var insertedPaths []string

		for i := 0; i < numFiles; i++ {
			path := filepath.Join(dir, fmt.Sprintf("alert_%d.pcap", i))
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			f.Write(make([]byte, rapid.IntRange(100, 10000).Draw(t, "file_size")))
			f.Close()

			startTime := int64(i * 1000)
			_, err = idx.Insert(PcapFile{
				FilePath:    path,
				StartTime:   startTime,
				EndTime:     startTime + 999,
				Interface:   "eth0",
				PacketCount: 10,
				ByteCount:   1000,
				AlertDriven: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			insertedPaths = append(insertedPaths, path)
		}

		// Prune half the files
		pruneCount := numFiles / 2
		files, err := idx.OldestFiles(pruneCount)
		if err != nil {
			t.Fatal(err)
		}

		deletedPaths := make(map[string]bool)
		for _, f := range files {
			os.Remove(f.FilePath)
			idx.DeleteByID(f.ID)
			deletedPaths[f.FilePath] = true
		}

		// Invariant 1: No index entries reference deleted files
		remaining, err := idx.QueryByTimeRange(0, int64(numFiles*1000))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range remaining {
			if deletedPaths[f.FilePath] {
				t.Fatalf("index still references deleted file %s", f.FilePath)
			}
		}

		// Invariant 2: No files exist without index entries
		indexedPaths := make(map[string]bool)
		for _, f := range remaining {
			indexedPaths[f.FilePath] = true
		}
		for _, path := range insertedPaths {
			if _, err := os.Stat(path); err == nil {
				if !indexedPaths[path] {
					t.Fatalf("file %s exists but has no index entry", path)
				}
			}
		}
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// writeMockPCAP writes a minimal PCAP file with packets at the given timestamps (ms).
func writeMockPCAP(t *rapid.T, path string, timestampsMs []int64) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Global header (24 bytes)
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(gh[4:], 2)          // major
	binary.LittleEndian.PutUint16(gh[6:], 4)          // minor
	binary.LittleEndian.PutUint32(gh[16:], 65535)     // snaplen
	binary.LittleEndian.PutUint32(gh[20:], 1)         // link type (Ethernet)
	f.Write(gh)

	pktData := []byte{0x00, 0x01, 0x02, 0x03}
	for _, tsMs := range timestampsMs {
		tsSec := uint32(tsMs / 1000)
		tsUsec := uint32((tsMs % 1000) * 1000)

		ph := make([]byte, 16)
		binary.LittleEndian.PutUint32(ph[0:], tsSec)
		binary.LittleEndian.PutUint32(ph[4:], tsUsec)
		binary.LittleEndian.PutUint32(ph[8:], uint32(len(pktData)))
		binary.LittleEndian.PutUint32(ph[12:], uint32(len(pktData)))
		f.Write(ph)
		f.Write(pktData)
	}
}

// readPCAPTimestamps reads a PCAP file and returns the min and max packet timestamps in ms.
func readPCAPTimestamps(t *rapid.T, path string) (minMs, maxMs int64) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 24 {
		t.Fatal("PCAP file too small")
	}

	offset := 24
	minMs = int64(^uint64(0) >> 1)
	maxMs = 0

	for offset+16 <= len(data) {
		tsSec := int64(binary.LittleEndian.Uint32(data[offset:]))
		tsUsec := int64(binary.LittleEndian.Uint32(data[offset+4:]))
		inclLen := int(binary.LittleEndian.Uint32(data[offset+8:]))

		tsMs := tsSec*1000 + tsUsec/1000
		if tsMs < minMs {
			minMs = tsMs
		}
		if tsMs > maxMs {
			maxMs = tsMs
		}
		offset += 16 + inclLen
	}

	if minMs == int64(^uint64(0)>>1) {
		minMs = 0
	}
	return
}

// Suppress unused import warnings
var _ = time.Now

// ── Property 1: Alert payload validation ─────────────────────────────────────

// Property 1: Alert payload validation rejects any payload missing required fields
// For any HTTP POST payload missing one or more required fields, assert the
// listener returns HTTP 400 and the alert is not enqueued.
// Validates: Requirements 1.3
func TestProperty1_AlertPayloadValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		communityID := rapid.StringMatching(`[a-z0-9:]{3,20}`).Draw(t, "community_id")
		severity := rapid.IntRange(1, 3).Draw(t, "severity")
		timestampMs := rapid.Int64Range(1, 9999999999999).Draw(t, "timestamp_ms")
		sid := rapid.StringMatching(`[0-9]{4,10}`).Draw(t, "sid")

		// Decide which required fields to blank (at least one must be blank).
		blankCommunityID := rapid.Bool().Draw(t, "blank_community_id")
		blankSeverity := rapid.Bool().Draw(t, "blank_severity")
		blankTimestampMs := rapid.Bool().Draw(t, "blank_timestamp_ms")
		blankSID := rapid.Bool().Draw(t, "blank_sid")

		// Ensure at least one field is missing.
		if !blankCommunityID && !blankSeverity && !blankTimestampMs && !blankSID {
			blankCommunityID = true
		}

		event := AlertEvent{
			CommunityID: communityID,
			Severity:    severity,
			TimestampMs: timestampMs,
			SID:         sid,
		}
		if blankCommunityID {
			event.CommunityID = ""
		}
		if blankSeverity {
			event.Severity = 0
		}
		if blankTimestampMs {
			event.TimestampMs = 0
		}
		if blankSID {
			event.SID = ""
		}

		// Create a listener with a small queue.
		al := NewAlertListener("", 10, nil)
		queueBefore := al.QueueDepth()

		body, _ := json.Marshal(event)
		req := httptest.NewRequest(http.MethodPost, "/alerts", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		al.handlePostAlerts(rr, req)

		// Must return 400.
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected HTTP 400 for invalid payload %+v, got %d", event, rr.Code)
		}
		// Queue must not have grown.
		if al.QueueDepth() != queueBefore {
			t.Fatalf("queue grew after invalid payload: before=%d after=%d", queueBefore, al.QueueDepth())
		}
	})
}

// TestAlertListener_ValidPayloadAccepted verifies that a complete valid payload
// returns 202 and is enqueued.
func TestAlertListener_ValidPayloadAccepted(t *testing.T) {
	al := NewAlertListener("", 10, nil)

	event := AlertEvent{
		CommunityID: "1:abc123",
		Severity:    2,
		TimestampMs: 1700000000000,
		SID:         "2100498",
	}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/alerts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	al.handlePostAlerts(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	if al.QueueDepth() != 1 {
		t.Fatalf("expected 1 item in queue, got %d", al.QueueDepth())
	}
}

// TestAlertListener_QueueFull verifies that a full queue returns 429 and drops the alert.
func TestAlertListener_QueueFull(t *testing.T) {
	al := NewAlertListener("", 1, nil)

	event := AlertEvent{
		CommunityID: "1:abc123",
		Severity:    2,
		TimestampMs: 1700000000000,
		SID:         "2100498",
	}

	// Fill the queue.
	body, _ := json.Marshal(event)
	req := httptest.NewRequest(http.MethodPost, "/alerts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	al.handlePostAlerts(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("first request: expected 202, got %d", rr.Code)
	}

	// Second request should be dropped.
	body2, _ := json.Marshal(event)
	req2 := httptest.NewRequest(http.MethodPost, "/alerts", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	al.handlePostAlerts(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", rr2.Code)
	}
}

// TestAlertListener_Health verifies the health endpoint returns queue depth and dedup size.
func TestAlertListener_Health(t *testing.T) {
	al := NewAlertListener("", 10, nil)
	al.SetDedupSize(5)

	req := httptest.NewRequest(http.MethodGet, "/alerts/health", nil)
	rr := httptest.NewRecorder()
	al.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		QueueDepth     int   `json:"queue_depth"`
		DedupCacheSize int64 `json:"dedup_cache_size"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if resp.QueueDepth != 0 {
		t.Errorf("expected queue_depth 0, got %d", resp.QueueDepth)
	}
	if resp.DedupCacheSize != 5 {
		t.Errorf("expected dedup_cache_size 5, got %d", resp.DedupCacheSize)
	}
}

// ── Deduplication tests ───────────────────────────────────────────────────────

// TestDedupCache_BasicDedup verifies that a second identical alert within the
// window is detected as a duplicate.
func TestDedupCache_BasicDedup(t *testing.T) {
	dc := newDedupCache(30 * time.Second)
	defer dc.stop()

	if dc.IsDuplicate("1:abc", "1001", "sensor-1") {
		t.Fatal("first occurrence should not be a duplicate")
	}
	if !dc.IsDuplicate("1:abc", "1001", "sensor-1") {
		t.Fatal("second occurrence within window should be a duplicate")
	}
}

// TestDedupCache_DifferentKeyNotDuplicate verifies that alerts with different
// keys are not considered duplicates of each other.
func TestDedupCache_DifferentKeyNotDuplicate(t *testing.T) {
	dc := newDedupCache(30 * time.Second)
	defer dc.stop()

	dc.IsDuplicate("1:abc", "1001", "sensor-1")

	// Different community_id
	if dc.IsDuplicate("1:xyz", "1001", "sensor-1") {
		t.Error("different community_id should not be a duplicate")
	}
	// Different sid
	if dc.IsDuplicate("1:abc", "9999", "sensor-1") {
		t.Error("different sid should not be a duplicate")
	}
	// Different sensor_id
	if dc.IsDuplicate("1:abc", "1001", "sensor-2") {
		t.Error("different sensor_id should not be a duplicate")
	}
}

// TestDedupCache_ExpiredEntryNotDuplicate verifies that an entry is no longer
// considered a duplicate after the TTL expires.
func TestDedupCache_ExpiredEntryNotDuplicate(t *testing.T) {
	dc := newDedupCache(50 * time.Millisecond)
	defer dc.stop()

	dc.IsDuplicate("1:abc", "1001", "sensor-1")
	time.Sleep(100 * time.Millisecond)

	if dc.IsDuplicate("1:abc", "1001", "sensor-1") {
		t.Fatal("entry should have expired and not be a duplicate")
	}
}

// TestDedupCache_SweepReducesSize verifies that the background sweep removes
// expired entries and reduces the cache size.
func TestDedupCache_SweepReducesSize(t *testing.T) {
	dc := newDedupCache(50 * time.Millisecond)
	defer dc.stop()

	dc.IsDuplicate("1:a", "1001", "s1")
	dc.IsDuplicate("1:b", "1002", "s1")
	if dc.Size() != 2 {
		t.Fatalf("expected size 2, got %d", dc.Size())
	}

	// Wait for entries to expire and sweep to run.
	time.Sleep(200 * time.Millisecond)
	dc.sweep() // force a sweep in case the ticker hasn't fired yet

	if dc.Size() != 0 {
		t.Fatalf("expected size 0 after sweep, got %d", dc.Size())
	}
}

// TestDedupCache_PropertyRoundTrip verifies the dedup cache layer in isolation:
// for any (community_id, sid, sensor_id) tuple, the first call to IsDuplicate
// returns false and the second call within the window returns true.
func TestDedupCache_PropertyRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		communityID := rapid.StringMatching(`[a-z0-9:]{3,20}`).Draw(t, "community_id")
		sid := rapid.StringMatching(`[0-9]{4,10}`).Draw(t, "sid")
		sensorID := rapid.StringMatching(`[a-z0-9-]{3,20}`).Draw(t, "sensor_id")

		// Use a generous window so both calls happen well within it.
		dc := newDedupCache(30 * time.Second)
		defer dc.stop()

		// First occurrence: not a duplicate — should trigger a carve.
		firstIsDup := dc.IsDuplicate(communityID, sid, sensorID)
		if firstIsDup {
			t.Fatalf("first alert (community_id=%q sid=%q sensor_id=%q) should not be a duplicate",
				communityID, sid, sensorID)
		}

		// Second occurrence within the window: must be a duplicate — carve discarded.
		secondIsDup := dc.IsDuplicate(communityID, sid, sensorID)
		if !secondIsDup {
			t.Fatalf("second alert (community_id=%q sid=%q sensor_id=%q) within window should be a duplicate",
				communityID, sid, sensorID)
		}
	})
}

// Property 4: Alert deduplication within the time window
// For any alert event, sending the same alert twice within the dedup window
// results in exactly one carve attempt; the second is discarded by HandleAlert.
// **Validates: Requirements 1.6**
func TestProperty4_AlertDeduplicationWithinWindow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		communityID := rapid.StringMatching(`[a-z0-9:]{3,20}`).Draw(t, "community_id")
		sid := rapid.StringMatching(`[0-9]{4,10}`).Draw(t, "sid")
		// Severity 1 or 2 so it passes the default threshold of 2.
		severity := rapid.IntRange(1, 2).Draw(t, "severity")

		// Set up a temp directory for the index DB and audit log.
		dir, err := os.MkdirTemp("", "pcap-prop4-dedup-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		auditLogger, err := audit.New(filepath.Join(dir, "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		defer auditLogger.Close()

		// Manager with threshold=2, mode="alert_driven", invalid ring socket,
		// and a dedup cache with a 30s window.
		// HandleAlert will:
		// - pass severity check (severity <= 2)
		// - first call: pass dedup check, attempt to dial socket → non-nil error (carve attempted)
		// - second call: fail dedup check, return nil (discarded)
		m := &Manager{
			ringSocket:     filepath.Join(dir, "nonexistent.sock"),
			alertsDir:      filepath.Join(dir, "alerts"),
			index:          idx,
			auditLog:       auditLogger,
			severityThresh: 2,
			mode:           "alert_driven",
			preAlertMs:     10,
			postAlertMs:    0, // zero to avoid sleep in tests
			sensorID:       "test-sensor",
			dedup:          newDedupCache(30 * time.Second),
		}
		defer m.dedup.stop()

		alert := AlertEvent{
			CommunityID: communityID,
			Severity:    severity,
			TimestampMs: time.Now().UnixMilli(),
			SID:         sid,
		}

		// First HandleAlert call: should pass dedup and attempt carve.
		// The invalid socket causes a non-nil error, proving the carve was attempted.
		err1 := m.HandleAlert(alert)
		if err1 == nil {
			t.Fatalf("first HandleAlert(community_id=%q sid=%q severity=%d): expected non-nil error (carve attempted via invalid socket), got nil",
				communityID, sid, severity)
		}

		// Second HandleAlert call with the SAME alert: should be deduplicated.
		// Dedup returns true → HandleAlert returns nil without attempting the socket.
		err2 := m.HandleAlert(alert)
		if err2 != nil {
			t.Fatalf("second HandleAlert(community_id=%q sid=%q severity=%d): expected nil (deduplicated), got error: %v",
				communityID, sid, severity, err2)
		}

		// Verify the index has 0 entries (no carve completed for either call,
		// since the socket was invalid for the first and the second was deduped).
		count, countErr := idx.Count()
		if countErr != nil {
			t.Fatalf("failed to count index entries: %v", countErr)
		}
		if count != 0 {
			t.Fatalf("expected 0 index entries (no carve completed), got %d", count)
		}
	})
}

// ── Retention pruning tests ───────────────────────────────────────────────────

// TestRetentionPruning_DeletesExpiredFiles verifies that PruneExpiredRetention
// deletes expired PCAP files and their index entries while leaving non-expired
// and no-policy entries intact.
func TestRetentionPruning_DeletesExpiredFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pcap.db")

	idx, err := OpenIndex(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	nowMs := time.Now().UnixMilli()

	// Entry 1: expired retention (past time)
	expiredPath := filepath.Join(dir, "expired.pcap")
	if err := os.WriteFile(expiredPath, []byte("expired-pcap-data"), 0644); err != nil {
		t.Fatal(err)
	}
	expiredID, err := idx.Insert(PcapFile{
		FilePath:             expiredPath,
		StartTime:            1000,
		EndTime:              2000,
		Interface:            "eth0",
		PacketCount:          10,
		ByteCount:            1000,
		RetentionExpiresAtMs: nowMs - 60000, // expired 60s ago
	})
	if err != nil {
		t.Fatal(err)
	}

	// Entry 2: not yet expired (future time)
	futurePath := filepath.Join(dir, "future.pcap")
	if err := os.WriteFile(futurePath, []byte("future-pcap-data"), 0644); err != nil {
		t.Fatal(err)
	}
	futureID, err := idx.Insert(PcapFile{
		FilePath:             futurePath,
		StartTime:            3000,
		EndTime:              4000,
		Interface:            "eth0",
		PacketCount:          20,
		ByteCount:            2000,
		RetentionExpiresAtMs: nowMs + 3600000, // expires in 1 hour
	})
	if err != nil {
		t.Fatal(err)
	}

	// Entry 3: no retention policy (RetentionExpiresAtMs = 0)
	noPolicyPath := filepath.Join(dir, "nopolicy.pcap")
	if err := os.WriteFile(noPolicyPath, []byte("nopolicy-pcap-data"), 0644); err != nil {
		t.Fatal(err)
	}
	noPolicyID, err := idx.Insert(PcapFile{
		FilePath:             noPolicyPath,
		StartTime:            5000,
		EndTime:              6000,
		Interface:            "eth0",
		PacketCount:          30,
		ByteCount:            3000,
		RetentionExpiresAtMs: 0, // no retention policy
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a minimal manager with just the index and alertsDir.
	m := &Manager{
		index:     idx,
		alertsDir: dir,
	}

	stats := m.PruneExpiredRetention(nowMs)

	// Verify stats.
	if stats.FilesDeleted != 1 {
		t.Errorf("expected 1 file deleted, got %d", stats.FilesDeleted)
	}
	if stats.EntriesDeleted != 1 {
		t.Errorf("expected 1 entry deleted, got %d", stats.EntriesDeleted)
	}
	if stats.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", stats.Errors)
	}

	// Expired file should be gone from disk.
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Errorf("expired file should have been deleted from disk")
	}

	// Expired entry should be gone from index.
	_, err = idx.GetByID(expiredID)
	if err == nil {
		t.Errorf("expired entry (id=%d) should have been deleted from index", expiredID)
	}

	// Future file should still exist on disk.
	if _, err := os.Stat(futurePath); err != nil {
		t.Errorf("future file should still exist on disk: %v", err)
	}

	// Future entry should still exist in index.
	f, err := idx.GetByID(futureID)
	if err != nil {
		t.Errorf("future entry (id=%d) should still exist in index: %v", futureID, err)
	}
	if f.FilePath != futurePath {
		t.Errorf("future entry file path mismatch: got %s, want %s", f.FilePath, futurePath)
	}

	// No-policy file should still exist on disk.
	if _, err := os.Stat(noPolicyPath); err != nil {
		t.Errorf("no-policy file should still exist on disk: %v", err)
	}

	// No-policy entry should still exist in index.
	f, err = idx.GetByID(noPolicyID)
	if err != nil {
		t.Errorf("no-policy entry (id=%d) should still exist in index: %v", noPolicyID, err)
	}
	if f.FilePath != noPolicyPath {
		t.Errorf("no-policy entry file path mismatch: got %s, want %s", f.FilePath, noPolicyPath)
	}
}

// TestRetentionPruning_DeletesManifestFiles verifies that PruneExpiredRetention
// also deletes the chain-of-custody manifest file alongside the PCAP file.
func TestRetentionPruning_DeletesManifestFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pcap.db")

	idx, err := OpenIndex(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	nowMs := time.Now().UnixMilli()

	// Create an expired PCAP file with a manifest.
	pcapPath := filepath.Join(dir, "expired_with_manifest.pcap")
	if err := os.WriteFile(pcapPath, []byte("pcap-data"), 0644); err != nil {
		t.Fatal(err)
	}

	manifestPath := ManifestPathForPcap(pcapPath)
	if err := WriteCreatedManifest(manifestPath, "system", "2100498", "test-uuid", "sha256:abc123"); err != nil {
		t.Fatal(err)
	}

	// Verify manifest was created.
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest file should exist after creation: %v", err)
	}

	_, err = idx.Insert(PcapFile{
		FilePath:                   pcapPath,
		StartTime:                  1000,
		EndTime:                    2000,
		Interface:                  "eth0",
		PacketCount:                10,
		ByteCount:                  1000,
		RetentionExpiresAtMs:       nowMs - 60000, // expired
		ChainOfCustodyManifestPath: manifestPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a second expired entry without an explicit manifest path
	// (should use the conventional path).
	pcapPath2 := filepath.Join(dir, "expired_no_explicit_manifest.pcap")
	if err := os.WriteFile(pcapPath2, []byte("pcap-data-2"), 0644); err != nil {
		t.Fatal(err)
	}
	manifestPath2 := ManifestPathForPcap(pcapPath2)
	if err := WriteCreatedManifest(manifestPath2, "system", "2100499", "test-uuid-2", "sha256:def456"); err != nil {
		t.Fatal(err)
	}

	_, err = idx.Insert(PcapFile{
		FilePath:             pcapPath2,
		StartTime:            3000,
		EndTime:              4000,
		Interface:            "eth0",
		PacketCount:          20,
		ByteCount:            2000,
		RetentionExpiresAtMs: nowMs - 30000, // expired
		// ChainOfCustodyManifestPath intentionally empty
	})
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		index:     idx,
		alertsDir: dir,
	}

	stats := m.PruneExpiredRetention(nowMs)

	if stats.FilesDeleted != 2 {
		t.Errorf("expected 2 files deleted, got %d", stats.FilesDeleted)
	}
	if stats.EntriesDeleted != 2 {
		t.Errorf("expected 2 entries deleted, got %d", stats.EntriesDeleted)
	}

	// Both PCAP files should be gone.
	if _, err := os.Stat(pcapPath); !os.IsNotExist(err) {
		t.Errorf("first PCAP file should have been deleted")
	}
	if _, err := os.Stat(pcapPath2); !os.IsNotExist(err) {
		t.Errorf("second PCAP file should have been deleted")
	}

	// Both manifest files should be gone.
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Errorf("first manifest file should have been deleted")
	}
	if _, err := os.Stat(manifestPath2); !os.IsNotExist(err) {
		t.Errorf("second manifest file should have been deleted")
	}
}

// Property 10: Retention pruning removes expired entries
//
// For any set of PCAP index entries where some have retention_expires_at_ms set
// and the current time exceeds it, the pruning cycle (PruneExpiredRetention)
// deletes the PCAP file from disk and the index entry for expired entries, while
// non-expired entries (future expiration or no retention policy) remain untouched.
//
// **Validates: Requirements 9.5**
func TestProperty10_RetentionPruningRemovesExpiredEntries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "pcap-prop10-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		// Generate a random "now" time in milliseconds.
		nowMs := rapid.Int64Range(1600000000000, 1800000000000).Draw(t, "now_ms")

		// Generate a random number of entries (1-10).
		numEntries := rapid.IntRange(1, 10).Draw(t, "num_entries")

		type entryInfo struct {
			id           int64
			pcapPath     string
			manifestPath string
			category     string // "expired", "not_expired", "no_policy"
			hasManifest  bool
		}
		var entries []entryInfo

		for i := 0; i < numEntries; i++ {
			// Randomly choose a category for this entry.
			category := rapid.SampledFrom([]string{"expired", "not_expired", "no_policy"}).Draw(t, fmt.Sprintf("category_%d", i))

			// Create a PCAP file on disk.
			pcapPath := filepath.Join(dir, fmt.Sprintf("entry_%d.pcap", i))
			pcapContent := rapid.SliceOfN(rapid.Byte(), 24, 512).Draw(t, fmt.Sprintf("pcap_content_%d", i))
			if err := os.WriteFile(pcapPath, pcapContent, 0644); err != nil {
				t.Fatal(err)
			}

			// Optionally create a manifest file.
			hasManifest := rapid.Bool().Draw(t, fmt.Sprintf("has_manifest_%d", i))
			manifestPath := ""
			if hasManifest {
				manifestPath = ManifestPathForPcap(pcapPath)
				if err := WriteCreatedManifest(manifestPath, "system", fmt.Sprintf("sid_%d", i), fmt.Sprintf("uuid_%d", i), "sha256:abc"); err != nil {
					t.Fatal(err)
				}
			}

			// Determine retention_expires_at_ms based on category.
			var retentionExpiresAtMs int64
			switch category {
			case "expired":
				// Expired: retention time is in the past relative to nowMs.
				retentionExpiresAtMs = nowMs - rapid.Int64Range(1, 1000000000).Draw(t, fmt.Sprintf("expired_offset_%d", i))
			case "not_expired":
				// Not yet expired: retention time is in the future relative to nowMs.
				retentionExpiresAtMs = nowMs + rapid.Int64Range(1, 1000000000).Draw(t, fmt.Sprintf("future_offset_%d", i))
			case "no_policy":
				// No retention policy.
				retentionExpiresAtMs = 0
			}

			startTime := rapid.Int64Range(1000, 9999999).Draw(t, fmt.Sprintf("start_time_%d", i))
			id, err := idx.Insert(PcapFile{
				FilePath:                   pcapPath,
				StartTime:                  startTime,
				EndTime:                    startTime + 1000,
				Interface:                  "eth0",
				PacketCount:                10,
				ByteCount:                  1000,
				RetentionExpiresAtMs:       retentionExpiresAtMs,
				ChainOfCustodyManifestPath: manifestPath,
			})
			if err != nil {
				t.Fatal(err)
			}

			entries = append(entries, entryInfo{
				id:           id,
				pcapPath:     pcapPath,
				manifestPath: manifestPath,
				category:     category,
				hasManifest:  hasManifest,
			})
		}

		// Count expected expired entries.
		expectedExpired := 0
		for _, e := range entries {
			if e.category == "expired" {
				expectedExpired++
			}
		}

		// Run the pruning cycle.
		m := &Manager{
			index:     idx,
			alertsDir: dir,
		}
		stats := m.PruneExpiredRetention(nowMs)

		// Assert stats match expectations.
		if stats.FilesDeleted != expectedExpired {
			t.Fatalf("expected FilesDeleted=%d, got %d", expectedExpired, stats.FilesDeleted)
		}
		if stats.EntriesDeleted != expectedExpired {
			t.Fatalf("expected EntriesDeleted=%d, got %d", expectedExpired, stats.EntriesDeleted)
		}
		if stats.Errors != 0 {
			t.Fatalf("expected 0 errors, got %d", stats.Errors)
		}

		// Assert per-entry invariants.
		for _, e := range entries {
			_, fileErr := os.Stat(e.pcapPath)
			_, indexErr := idx.GetByID(e.id)

			switch e.category {
			case "expired":
				// PCAP file must be deleted from disk.
				if !os.IsNotExist(fileErr) {
					t.Fatalf("expired entry (id=%d): PCAP file %s should have been deleted from disk", e.id, e.pcapPath)
				}
				// Index entry must be deleted.
				if indexErr == nil {
					t.Fatalf("expired entry (id=%d): index entry should have been deleted", e.id)
				}
				// Manifest file must be deleted (if it existed).
				if e.hasManifest {
					if _, mErr := os.Stat(e.manifestPath); !os.IsNotExist(mErr) {
						t.Fatalf("expired entry (id=%d): manifest %s should have been deleted", e.id, e.manifestPath)
					}
				}

			case "not_expired":
				// PCAP file must still exist on disk.
				if fileErr != nil {
					t.Fatalf("not_expired entry (id=%d): PCAP file %s should still exist: %v", e.id, e.pcapPath, fileErr)
				}
				// Index entry must still exist.
				if indexErr != nil {
					t.Fatalf("not_expired entry (id=%d): index entry should still exist: %v", e.id, indexErr)
				}
				// Manifest file must still exist (if it was created).
				if e.hasManifest {
					if _, mErr := os.Stat(e.manifestPath); mErr != nil {
						t.Fatalf("not_expired entry (id=%d): manifest %s should still exist: %v", e.id, e.manifestPath, mErr)
					}
				}

			case "no_policy":
				// PCAP file must still exist on disk.
				if fileErr != nil {
					t.Fatalf("no_policy entry (id=%d): PCAP file %s should still exist: %v", e.id, e.pcapPath, fileErr)
				}
				// Index entry must still exist.
				if indexErr != nil {
					t.Fatalf("no_policy entry (id=%d): index entry should still exist: %v", e.id, indexErr)
				}
				// Manifest file must still exist (if it was created).
				if e.hasManifest {
					if _, mErr := os.Stat(e.manifestPath); mErr != nil {
						t.Fatalf("no_policy entry (id=%d): manifest %s should still exist: %v", e.id, e.manifestPath, mErr)
					}
				}
			}
		}
	})
}
