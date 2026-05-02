package pcap

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

// Property 8: PCAP index entry completeness and round-trip fidelity
//
// For any carved PCAP file, assert the index entry contains all required fields,
// the stored sha256_hash matches the SHA256 of the actual file contents, and
// querying by community_id returns a record with identical field values to those
// inserted.
//
// **Validates: Requirements 9.1, 9.2, 9.6**
func TestProperty8_PcapIndexCompletenessAndRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "pcap-prop8-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		// Open a fresh index.
		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		// Generate random PCAP file content and write to disk.
		pcapContent := rapid.SliceOfN(rapid.Byte(), 24, 4096).Draw(t, "pcap_content")
		pcapPath := filepath.Join(dir, "carved.pcap")
		if err := os.WriteFile(pcapPath, pcapContent, 0644); err != nil {
			t.Fatal(err)
		}

		// Compute the actual SHA256 hash of the file.
		actualHash, err := HashFile(pcapPath)
		if err != nil {
			t.Fatalf("HashFile: %v", err)
		}

		// Compute expected file size.
		actualSize, err := FileSizeBytes(pcapPath)
		if err != nil {
			t.Fatalf("FileSizeBytes: %v", err)
		}

		// Generate the chain-of-custody manifest.
		manifestPath := ManifestPathForPcap(pcapPath)

		// Generate random but non-empty values for all evidence-grade fields.
		communityID := rapid.StringMatching(`1:[a-f0-9]{6,16}`).Draw(t, "community_id")
		sensorID := rapid.StringMatching(`sensor-[a-z0-9]{3,10}`).Draw(t, "sensor_id")
		alertSID := rapid.StringMatching(`[0-9]{5,10}`).Draw(t, "alert_sid")
		alertSignature := rapid.StringMatching(`ET [A-Z]{3,10} [a-z ]{5,30}`).Draw(t, "alert_signature")
		alertUUID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(t, "alert_uuid")
		srcIP := rapid.StringMatching(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`).Draw(t, "src_ip")
		dstIP := rapid.StringMatching(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`).Draw(t, "dst_ip")
		srcPort := rapid.IntRange(1, 65535).Draw(t, "src_port")
		dstPort := rapid.IntRange(1, 65535).Draw(t, "dst_port")
		proto := rapid.SampledFrom([]string{"TCP", "UDP", "ICMP", "SCTP"}).Draw(t, "proto")
		zeekUID := rapid.StringMatching(`C[a-zA-Z0-9]{10,18}`).Draw(t, "zeek_uid")
		captureInterface := rapid.SampledFrom([]string{"eth0", "eth1", "ens192", "bond0"}).Draw(t, "capture_interface")
		carveReason := rapid.SampledFrom([]string{"alert", "manual", "scheduled"}).Draw(t, "carve_reason")
		requestedBy := rapid.StringMatching(`[a-z]+@[a-z]+`).Draw(t, "requested_by")
		startTime := rapid.Int64Range(1000000, 9999999999).Draw(t, "start_time")
		endTime := startTime + rapid.Int64Range(1000, 60000).Draw(t, "duration")
		packetCount := rapid.Int64Range(1, 100000).Draw(t, "packet_count")
		byteCount := rapid.Int64Range(100, 10000000).Draw(t, "byte_count")
		createdAtMs := rapid.Int64Range(1600000000000, 1800000000000).Draw(t, "created_at_ms")
		retentionExpiresAtMs := rapid.Int64Range(1800000000000, 2000000000000).Draw(t, "retention_expires_at_ms")

		// Write the chain-of-custody manifest.
		if err := WriteCreatedManifest(manifestPath, requestedBy, alertSID, alertUUID, actualHash); err != nil {
			t.Fatalf("WriteCreatedManifest: %v", err)
		}

		// Build the PcapFile with all required fields populated.
		inserted := PcapFile{
			FilePath:                   pcapPath,
			StartTime:                  startTime,
			EndTime:                    endTime,
			Interface:                  captureInterface,
			PacketCount:                packetCount,
			ByteCount:                  byteCount,
			AlertDriven:                true,
			CommunityID:                communityID,
			Sha256Hash:                 actualHash,
			FileSizeBytes:              actualSize,
			SensorID:                   sensorID,
			AlertSID:                   alertSID,
			AlertSignature:             alertSignature,
			AlertUUID:                  alertUUID,
			SrcIP:                      srcIP,
			DstIP:                      dstIP,
			SrcPort:                    srcPort,
			DstPort:                    dstPort,
			Proto:                      proto,
			ZeekUID:                    zeekUID,
			CaptureInterface:           captureInterface,
			CarveReason:                carveReason,
			RequestedBy:                requestedBy,
			CreatedAtMs:                createdAtMs,
			RetentionExpiresAtMs:       retentionExpiresAtMs,
			ChainOfCustodyManifestPath: manifestPath,
		}

		// Insert into the index.
		id, err := idx.Insert(inserted)
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}
		if id <= 0 {
			t.Fatalf("expected positive ID, got %d", id)
		}

		// ── Invariant 1: Query by community_id returns the record ──────────

		files, err := idx.QueryByCommunityID(communityID)
		if err != nil {
			t.Fatalf("QueryByCommunityID(%q): %v", communityID, err)
		}
		if len(files) != 1 {
			t.Fatalf("expected 1 result for community_id=%q, got %d", communityID, len(files))
		}
		queried := files[0]

		// ── Invariant 2: All required fields round-trip identically ────────

		assertStringField(t, "FilePath", inserted.FilePath, queried.FilePath)
		assertInt64Field(t, "StartTime", inserted.StartTime, queried.StartTime)
		assertInt64Field(t, "EndTime", inserted.EndTime, queried.EndTime)
		assertStringField(t, "Interface", inserted.Interface, queried.Interface)
		assertInt64Field(t, "PacketCount", inserted.PacketCount, queried.PacketCount)
		assertInt64Field(t, "ByteCount", inserted.ByteCount, queried.ByteCount)
		assertBoolField(t, "AlertDriven", inserted.AlertDriven, queried.AlertDriven)
		assertStringField(t, "CommunityID", inserted.CommunityID, queried.CommunityID)
		assertStringField(t, "Sha256Hash", inserted.Sha256Hash, queried.Sha256Hash)
		assertInt64Field(t, "FileSizeBytes", inserted.FileSizeBytes, queried.FileSizeBytes)
		assertStringField(t, "SensorID", inserted.SensorID, queried.SensorID)
		assertStringField(t, "AlertSID", inserted.AlertSID, queried.AlertSID)
		assertStringField(t, "AlertSignature", inserted.AlertSignature, queried.AlertSignature)
		assertStringField(t, "AlertUUID", inserted.AlertUUID, queried.AlertUUID)
		assertStringField(t, "SrcIP", inserted.SrcIP, queried.SrcIP)
		assertStringField(t, "DstIP", inserted.DstIP, queried.DstIP)
		assertIntField(t, "SrcPort", inserted.SrcPort, queried.SrcPort)
		assertIntField(t, "DstPort", inserted.DstPort, queried.DstPort)
		assertStringField(t, "Proto", inserted.Proto, queried.Proto)
		assertStringField(t, "ZeekUID", inserted.ZeekUID, queried.ZeekUID)
		assertStringField(t, "CaptureInterface", inserted.CaptureInterface, queried.CaptureInterface)
		assertStringField(t, "CarveReason", inserted.CarveReason, queried.CarveReason)
		assertStringField(t, "RequestedBy", inserted.RequestedBy, queried.RequestedBy)
		assertInt64Field(t, "CreatedAtMs", inserted.CreatedAtMs, queried.CreatedAtMs)
		assertInt64Field(t, "RetentionExpiresAtMs", inserted.RetentionExpiresAtMs, queried.RetentionExpiresAtMs)
		assertStringField(t, "ChainOfCustodyManifestPath", inserted.ChainOfCustodyManifestPath, queried.ChainOfCustodyManifestPath)

		// ── Invariant 3: Stored sha256_hash matches actual file hash ───────

		// Re-hash the file on disk to confirm the stored hash is correct.
		verifyHash, err := HashFile(pcapPath)
		if err != nil {
			t.Fatalf("re-hash file: %v", err)
		}
		if queried.Sha256Hash != verifyHash {
			t.Fatalf("stored sha256_hash %q does not match actual file hash %q",
				queried.Sha256Hash, verifyHash)
		}

		// Also verify the hash format is "sha256:<64 hex chars>".
		if len(queried.Sha256Hash) != 7+sha256.Size*2 {
			t.Fatalf("sha256_hash has unexpected length %d (expected %d): %q",
				len(queried.Sha256Hash), 7+sha256.Size*2, queried.Sha256Hash)
		}

		// ── Invariant 4: FileSizeBytes matches actual file size ────────────

		verifySize, err := FileSizeBytes(pcapPath)
		if err != nil {
			t.Fatalf("re-stat file: %v", err)
		}
		if queried.FileSizeBytes != verifySize {
			t.Fatalf("stored file_size_bytes %d does not match actual file size %d",
				queried.FileSizeBytes, verifySize)
		}
	})
}

// ── Assertion helpers ─────────────────────────────────────────────────────────

func assertStringField(t *rapid.T, name, expected, actual string) {
	t.Helper()
	if expected != actual {
		t.Fatalf("%s mismatch: inserted=%q, queried=%q", name, expected, actual)
	}
}

func assertInt64Field(t *rapid.T, name string, expected, actual int64) {
	t.Helper()
	if expected != actual {
		t.Fatalf("%s mismatch: inserted=%d, queried=%d", name, expected, actual)
	}
}

func assertIntField(t *rapid.T, name string, expected, actual int) {
	t.Helper()
	if expected != actual {
		t.Fatalf("%s mismatch: inserted=%d, queried=%d", name, expected, actual)
	}
}

func assertBoolField(t *rapid.T, name string, expected, actual bool) {
	t.Helper()
	if expected != actual {
		t.Fatalf("%s mismatch: inserted=%v, queried=%v", name, expected, actual)
	}
}

// Suppress unused import warning.
var _ = fmt.Sprintf
