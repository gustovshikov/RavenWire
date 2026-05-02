package pcap

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Unit tests for SHA256 hashing ─────────────────────────────────────────────

func TestHashFile_CorrectHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	content := []byte("hello world pcap data")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	expected := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	if got != expected {
		t.Fatalf("hash mismatch: got %s, want %s", got, expected)
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")

	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	expected := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte{}))
	if got != expected {
		t.Fatalf("hash mismatch for empty file: got %s, want %s", got, expected)
	}
}

func TestHashFile_NonexistentFile(t *testing.T) {
	_, err := HashFile("/nonexistent/path/file.pcap")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ── Unit tests for FileSizeBytes ──────────────────────────────────────────────

func TestFileSizeBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	content := []byte("some pcap content here")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	size, err := FileSizeBytes(path)
	if err != nil {
		t.Fatalf("FileSizeBytes: %v", err)
	}
	if size != int64(len(content)) {
		t.Fatalf("size mismatch: got %d, want %d", size, len(content))
	}
}

// ── Unit tests for ManifestPathForPcap ────────────────────────────────────────

func TestManifestPathForPcap(t *testing.T) {
	got := ManifestPathForPcap("/sensor/pcap/alerts/alert_1_abc.pcap")
	want := "/sensor/pcap/alerts/alert_1_abc.pcap.custody.jsonl"
	if got != want {
		t.Fatalf("ManifestPathForPcap: got %s, want %s", got, want)
	}
}

// ── Unit tests for Chain_of_Custody_Manifest ──────────────────────────────────

func TestWriteCreatedManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "test.pcap.custody.jsonl")

	err := WriteCreatedManifest(manifestPath, "system", "2100498", "uuid-123", "sha256:abc123")
	if err != nil {
		t.Fatalf("WriteCreatedManifest: %v", err)
	}

	events, err := ReadManifest(manifestPath)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Event != CustodyEventCreated {
		t.Errorf("expected event type %q, got %q", CustodyEventCreated, ev.Event)
	}
	if ev.Actor != "system" {
		t.Errorf("expected actor %q, got %q", "system", ev.Actor)
	}
	if ev.AlertSID != "2100498" {
		t.Errorf("expected alert_sid %q, got %q", "2100498", ev.AlertSID)
	}
	if ev.AlertUUID != "uuid-123" {
		t.Errorf("expected alert_uuid %q, got %q", "uuid-123", ev.AlertUUID)
	}
	if ev.FileHash != "sha256:abc123" {
		t.Errorf("expected file_hash %q, got %q", "sha256:abc123", ev.FileHash)
	}
	if ev.TimestampMs <= 0 {
		t.Errorf("expected positive timestamp_ms, got %d", ev.TimestampMs)
	}
}

func TestAppendAccessEvent(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "test.pcap.custody.jsonl")

	// Create the initial manifest.
	if err := WriteCreatedManifest(manifestPath, "system", "2100498", "uuid-123", "sha256:abc"); err != nil {
		t.Fatal(err)
	}

	// Append an access event.
	if err := AppendAccessEvent(manifestPath, "analyst@mgmt", "investigation"); err != nil {
		t.Fatalf("AppendAccessEvent: %v", err)
	}

	events, err := ReadManifest(manifestPath)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// First event is "created".
	if events[0].Event != CustodyEventCreated {
		t.Errorf("first event: expected %q, got %q", CustodyEventCreated, events[0].Event)
	}

	// Second event is "accessed".
	acc := events[1]
	if acc.Event != CustodyEventAccessed {
		t.Errorf("second event: expected %q, got %q", CustodyEventAccessed, acc.Event)
	}
	if acc.Actor != "analyst@mgmt" {
		t.Errorf("expected actor %q, got %q", "analyst@mgmt", acc.Actor)
	}
	if acc.Purpose != "investigation" {
		t.Errorf("expected purpose %q, got %q", "investigation", acc.Purpose)
	}
	if acc.TimestampMs <= 0 {
		t.Errorf("expected positive timestamp_ms, got %d", acc.TimestampMs)
	}
}

func TestAppendMultipleAccessEvents(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "test.pcap.custody.jsonl")

	if err := WriteCreatedManifest(manifestPath, "system", "1001", "", "sha256:def"); err != nil {
		t.Fatal(err)
	}

	// Append several access events.
	for i := 0; i < 5; i++ {
		actor := fmt.Sprintf("user-%d@mgmt", i)
		if err := AppendAccessEvent(manifestPath, actor, "review"); err != nil {
			t.Fatalf("AppendAccessEvent %d: %v", i, err)
		}
	}

	events, err := ReadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	// 1 created + 5 accessed = 6 total.
	if len(events) != 6 {
		t.Fatalf("expected 6 events, got %d", len(events))
	}
	for i := 1; i < 6; i++ {
		if events[i].Event != CustodyEventAccessed {
			t.Errorf("event %d: expected %q, got %q", i, CustodyEventAccessed, events[i].Event)
		}
		expectedActor := fmt.Sprintf("user-%d@mgmt", i-1)
		if events[i].Actor != expectedActor {
			t.Errorf("event %d: expected actor %q, got %q", i, expectedActor, events[i].Actor)
		}
	}
}

// ── Integration test: SHA256 hash + manifest + index ──────────────────────────

func TestHashAndManifest_EndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Create a fake PCAP file.
	pcapPath := filepath.Join(dir, "alert_test.pcap")
	pcapContent := []byte("fake pcap global header and packets")
	if err := os.WriteFile(pcapPath, pcapContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Hash the file.
	hash, err := HashFile(pcapPath)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("hash should start with 'sha256:', got %s", hash)
	}

	// Get file size.
	size, err := FileSizeBytes(pcapPath)
	if err != nil {
		t.Fatalf("FileSizeBytes: %v", err)
	}
	if size != int64(len(pcapContent)) {
		t.Fatalf("size mismatch: got %d, want %d", size, len(pcapContent))
	}

	// Write the manifest.
	manifestPath := ManifestPathForPcap(pcapPath)
	if err := WriteCreatedManifest(manifestPath, "system", "2100498", "uuid-abc", hash); err != nil {
		t.Fatalf("WriteCreatedManifest: %v", err)
	}

	// Open the index and insert.
	idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	id, err := idx.Insert(PcapFile{
		FilePath:                   pcapPath,
		StartTime:                  1000,
		EndTime:                    2000,
		Interface:                  "eth0",
		PacketCount:                42,
		AlertDriven:                true,
		CommunityID:                "1:test123",
		SensorID:                   "sensor-1",
		AlertSID:                   "2100498",
		AlertUUID:                  "uuid-abc",
		Sha256Hash:                 hash,
		FileSizeBytes:              size,
		ChainOfCustodyManifestPath: manifestPath,
		CarveReason:                "alert",
		RequestedBy:                "system",
		CreatedAtMs:                1700000000000,
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Query back and verify.
	file, err := idx.GetByID(id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if file.Sha256Hash != hash {
		t.Errorf("sha256_hash mismatch: got %s, want %s", file.Sha256Hash, hash)
	}
	if file.FileSizeBytes != size {
		t.Errorf("file_size_bytes mismatch: got %d, want %d", file.FileSizeBytes, size)
	}
	if file.ChainOfCustodyManifestPath != manifestPath {
		t.Errorf("manifest path mismatch: got %s, want %s", file.ChainOfCustodyManifestPath, manifestPath)
	}

	// Simulate an access event.
	if err := AppendAccessEvent(manifestPath, "analyst@mgmt", "investigation"); err != nil {
		t.Fatalf("AppendAccessEvent: %v", err)
	}

	// Verify the manifest has both events.
	events, err := ReadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 manifest events, got %d", len(events))
	}
	if events[0].Event != CustodyEventCreated {
		t.Errorf("first event should be 'created', got %q", events[0].Event)
	}
	if events[0].FileHash != hash {
		t.Errorf("created event file_hash mismatch: got %s, want %s", events[0].FileHash, hash)
	}
	if events[1].Event != CustodyEventAccessed {
		t.Errorf("second event should be 'accessed', got %q", events[1].Event)
	}
	if events[1].Actor != "analyst@mgmt" {
		t.Errorf("access event actor mismatch: got %s, want %s", events[1].Actor, "analyst@mgmt")
	}
	if events[1].Purpose != "investigation" {
		t.Errorf("access event purpose mismatch: got %s, want %s", events[1].Purpose, "investigation")
	}
}

// ── Test GetByID and QueryByFilePath ──────────────────────────────────────────

func TestIndex_GetByID(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	id, err := idx.Insert(PcapFile{
		FilePath:    "/tmp/test.pcap",
		StartTime:   1000,
		EndTime:     2000,
		Interface:   "eth0",
		PacketCount: 10,
		ByteCount:   1000,
		CommunityID: "1:abc",
		Sha256Hash:  "sha256:deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}

	file, err := idx.GetByID(id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if file.FilePath != "/tmp/test.pcap" {
		t.Errorf("file_path mismatch: got %s", file.FilePath)
	}
	if file.Sha256Hash != "sha256:deadbeef" {
		t.Errorf("sha256_hash mismatch: got %s", file.Sha256Hash)
	}
}

func TestIndex_GetByID_NotFound(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	_, err = idx.GetByID(99999)
	if err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
}

func TestIndex_QueryByFilePath(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	_, err = idx.Insert(PcapFile{
		FilePath:    "/sensor/pcap/alert_1.pcap",
		StartTime:   1000,
		EndTime:     2000,
		Interface:   "eth0",
		PacketCount: 10,
		ByteCount:   1000,
	})
	if err != nil {
		t.Fatal(err)
	}

	files, err := idx.QueryByFilePath("/sensor/pcap/alert_1.pcap")
	if err != nil {
		t.Fatalf("QueryByFilePath: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].FilePath != "/sensor/pcap/alert_1.pcap" {
		t.Errorf("file_path mismatch: got %s", files[0].FilePath)
	}

	// Query for nonexistent path.
	files, err = idx.QueryByFilePath("/nonexistent.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 files for nonexistent path, got %d", len(files))
	}
}
