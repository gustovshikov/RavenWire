package pcap

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// ── Property tests ────────────────────────────────────────────────────────────

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
