package pcap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
	"pgregory.net/rapid"
)

// Property 9: Chain_of_Custody_Manifest access event append
//
// For any PCAP file access via the carve API, assert an access event is
// appended to the manifest containing accessor identity, timestamp, and purpose.
//
// **Validates: Requirements 9.4**

// TestProperty9_CustodyManifestAccessEventAppend_ViaFilePath tests that
// AccessPcap (file-path based access) appends a correctly formed "accessed"
// event to the manifest for every access, regardless of actor or purpose.
func TestProperty9_CustodyManifestAccessEventAppend_ViaFilePath(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "pcap-prop9-path-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		// Create a fake PCAP file.
		pcapPath := filepath.Join(dir, "alert_test.pcap")
		pcapContent := rapid.SliceOfN(rapid.Byte(), 24, 1024).Draw(t, "pcap_content")
		if err := os.WriteFile(pcapPath, pcapContent, 0644); err != nil {
			t.Fatal(err)
		}

		// Compute hash and write the initial "created" manifest.
		fileHash, err := HashFile(pcapPath)
		if err != nil {
			t.Fatalf("HashFile: %v", err)
		}
		manifestPath := ManifestPathForPcap(pcapPath)
		alertSID := rapid.StringMatching(`[0-9]{5,10}`).Draw(t, "alert_sid")
		alertUUID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}`).Draw(t, "alert_uuid")
		if err := WriteCreatedManifest(manifestPath, "system", alertSID, alertUUID, fileHash); err != nil {
			t.Fatalf("WriteCreatedManifest: %v", err)
		}

		// Open an index and insert the PCAP entry so AccessPcap can find it.
		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		_, err = idx.Insert(PcapFile{
			FilePath:                   pcapPath,
			StartTime:                  1000,
			EndTime:                    2000,
			Interface:                  "eth0",
			PacketCount:                1,
			CommunityID:                "1:test",
			ChainOfCustodyManifestPath: manifestPath,
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}

		// Create audit logger and Manager.
		auditLog, err := audit.New(filepath.Join(dir, "audit.log"))
		if err != nil {
			t.Fatalf("audit.New: %v", err)
		}
		defer auditLog.Close()

		mgr := NewManager(filepath.Join(dir, "ring.sock"), dir, idx, auditLog)

		// Generate random access parameters.
		actor := rapid.StringMatching(`[a-z]{3,12}@[a-z]{3,10}`).Draw(t, "actor")
		purpose := rapid.SampledFrom([]string{
			"investigation", "export", "review", "compliance_audit",
			"incident_response", "forensic_analysis", "training",
		}).Draw(t, "purpose")

		// Record the number of events before the access.
		eventsBefore, err := ReadManifest(manifestPath)
		if err != nil {
			t.Fatalf("ReadManifest before access: %v", err)
		}
		countBefore := len(eventsBefore)

		// Perform the access via AccessPcap (file-path based).
		if err := mgr.AccessPcap(pcapPath, actor, purpose); err != nil {
			t.Fatalf("AccessPcap: %v", err)
		}

		// Read the manifest after the access.
		eventsAfter, err := ReadManifest(manifestPath)
		if err != nil {
			t.Fatalf("ReadManifest after access: %v", err)
		}

		// ── Invariant 1: Exactly one new event was appended ────────────────
		if len(eventsAfter) != countBefore+1 {
			t.Fatalf("expected %d events after access, got %d", countBefore+1, len(eventsAfter))
		}

		// ── Invariant 2: The new event is an "accessed" event ──────────────
		accessEvent := eventsAfter[len(eventsAfter)-1]
		if accessEvent.Event != CustodyEventAccessed {
			t.Fatalf("expected event type %q, got %q", CustodyEventAccessed, accessEvent.Event)
		}

		// ── Invariant 3: Actor identity matches ────────────────────────────
		if accessEvent.Actor != actor {
			t.Fatalf("actor mismatch: expected %q, got %q", actor, accessEvent.Actor)
		}

		// ── Invariant 4: Timestamp is positive (valid Unix ms) ─────────────
		if accessEvent.TimestampMs <= 0 {
			t.Fatalf("expected positive timestamp_ms, got %d", accessEvent.TimestampMs)
		}

		// ── Invariant 5: Purpose matches ───────────────────────────────────
		if accessEvent.Purpose != purpose {
			t.Fatalf("purpose mismatch: expected %q, got %q", purpose, accessEvent.Purpose)
		}

		// ── Invariant 6: Previous events are unchanged ─────────────────────
		for i := 0; i < countBefore; i++ {
			if eventsAfter[i].Event != eventsBefore[i].Event {
				t.Fatalf("event %d type changed: was %q, now %q", i, eventsBefore[i].Event, eventsAfter[i].Event)
			}
			if eventsAfter[i].Actor != eventsBefore[i].Actor {
				t.Fatalf("event %d actor changed: was %q, now %q", i, eventsBefore[i].Actor, eventsAfter[i].Actor)
			}
		}
	})
}

// TestProperty9_CustodyManifestAccessEventAppend_ViaID tests that
// AccessPcapByID (index-ID based access) appends a correctly formed "accessed"
// event to the manifest for every access.
func TestProperty9_CustodyManifestAccessEventAppend_ViaID(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "pcap-prop9-id-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		// Create a fake PCAP file.
		pcapPath := filepath.Join(dir, "alert_test.pcap")
		pcapContent := rapid.SliceOfN(rapid.Byte(), 24, 1024).Draw(t, "pcap_content")
		if err := os.WriteFile(pcapPath, pcapContent, 0644); err != nil {
			t.Fatal(err)
		}

		// Compute hash and write the initial "created" manifest.
		fileHash, err := HashFile(pcapPath)
		if err != nil {
			t.Fatalf("HashFile: %v", err)
		}
		manifestPath := ManifestPathForPcap(pcapPath)
		alertSID := rapid.StringMatching(`[0-9]{5,10}`).Draw(t, "alert_sid")
		alertUUID := rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}`).Draw(t, "alert_uuid")
		if err := WriteCreatedManifest(manifestPath, "system", alertSID, alertUUID, fileHash); err != nil {
			t.Fatalf("WriteCreatedManifest: %v", err)
		}

		// Open an index and insert the PCAP entry.
		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		insertedID, err := idx.Insert(PcapFile{
			FilePath:                   pcapPath,
			StartTime:                  1000,
			EndTime:                    2000,
			Interface:                  "eth0",
			PacketCount:                1,
			CommunityID:                "1:test",
			ChainOfCustodyManifestPath: manifestPath,
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}

		// Create audit logger and Manager.
		auditLog, err := audit.New(filepath.Join(dir, "audit.log"))
		if err != nil {
			t.Fatalf("audit.New: %v", err)
		}
		defer auditLog.Close()

		mgr := NewManager(filepath.Join(dir, "ring.sock"), dir, idx, auditLog)

		// Generate random access parameters.
		actor := rapid.StringMatching(`[a-z]{3,12}@[a-z]{3,10}`).Draw(t, "actor")
		purpose := rapid.SampledFrom([]string{
			"investigation", "export", "review", "compliance_audit",
			"incident_response", "forensic_analysis", "training",
		}).Draw(t, "purpose")

		// Record the number of events before the access.
		eventsBefore, err := ReadManifest(manifestPath)
		if err != nil {
			t.Fatalf("ReadManifest before access: %v", err)
		}
		countBefore := len(eventsBefore)

		// Perform the access via AccessPcapByID (index-ID based).
		returnedFile, err := mgr.AccessPcapByID(insertedID, actor, purpose)
		if err != nil {
			t.Fatalf("AccessPcapByID: %v", err)
		}

		// Verify the returned file matches the inserted path.
		if returnedFile.FilePath != pcapPath {
			t.Fatalf("returned file path mismatch: expected %q, got %q", pcapPath, returnedFile.FilePath)
		}

		// Read the manifest after the access.
		eventsAfter, err := ReadManifest(manifestPath)
		if err != nil {
			t.Fatalf("ReadManifest after access: %v", err)
		}

		// ── Invariant 1: Exactly one new event was appended ────────────────
		if len(eventsAfter) != countBefore+1 {
			t.Fatalf("expected %d events after access, got %d", countBefore+1, len(eventsAfter))
		}

		// ── Invariant 2: The new event is an "accessed" event ──────────────
		accessEvent := eventsAfter[len(eventsAfter)-1]
		if accessEvent.Event != CustodyEventAccessed {
			t.Fatalf("expected event type %q, got %q", CustodyEventAccessed, accessEvent.Event)
		}

		// ── Invariant 3: Actor identity matches ────────────────────────────
		if accessEvent.Actor != actor {
			t.Fatalf("actor mismatch: expected %q, got %q", actor, accessEvent.Actor)
		}

		// ── Invariant 4: Timestamp is positive (valid Unix ms) ─────────────
		if accessEvent.TimestampMs <= 0 {
			t.Fatalf("expected positive timestamp_ms, got %d", accessEvent.TimestampMs)
		}

		// ── Invariant 5: Purpose matches ───────────────────────────────────
		if accessEvent.Purpose != purpose {
			t.Fatalf("purpose mismatch: expected %q, got %q", purpose, accessEvent.Purpose)
		}

		// ── Invariant 6: Previous events are unchanged ─────────────────────
		for i := 0; i < countBefore; i++ {
			if eventsAfter[i].Event != eventsBefore[i].Event {
				t.Fatalf("event %d type changed: was %q, now %q", i, eventsBefore[i].Event, eventsAfter[i].Event)
			}
			if eventsAfter[i].Actor != eventsBefore[i].Actor {
				t.Fatalf("event %d actor changed: was %q, now %q", i, eventsBefore[i].Actor, eventsAfter[i].Actor)
			}
		}
	})
}

// TestProperty9_CustodyManifestAccessEventAppend_MultipleAccesses tests that
// multiple sequential accesses each append their own event, preserving all
// previous events and maintaining correct ordering.
func TestProperty9_CustodyManifestAccessEventAppend_MultipleAccesses(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dir, err := os.MkdirTemp("", "pcap-prop9-multi-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		// Create a fake PCAP file.
		pcapPath := filepath.Join(dir, "alert_test.pcap")
		pcapContent := rapid.SliceOfN(rapid.Byte(), 24, 512).Draw(t, "pcap_content")
		if err := os.WriteFile(pcapPath, pcapContent, 0644); err != nil {
			t.Fatal(err)
		}

		// Write the initial "created" manifest.
		fileHash, err := HashFile(pcapPath)
		if err != nil {
			t.Fatalf("HashFile: %v", err)
		}
		manifestPath := ManifestPathForPcap(pcapPath)
		if err := WriteCreatedManifest(manifestPath, "system", "12345", "uuid-abc", fileHash); err != nil {
			t.Fatalf("WriteCreatedManifest: %v", err)
		}

		// Open an index and insert the PCAP entry.
		idx, err := OpenIndex(filepath.Join(dir, "pcap.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()

		_, err = idx.Insert(PcapFile{
			FilePath:                   pcapPath,
			StartTime:                  1000,
			EndTime:                    2000,
			Interface:                  "eth0",
			PacketCount:                1,
			CommunityID:                "1:test",
			ChainOfCustodyManifestPath: manifestPath,
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}

		// Create audit logger and Manager.
		auditLog, err := audit.New(filepath.Join(dir, "audit.log"))
		if err != nil {
			t.Fatalf("audit.New: %v", err)
		}
		defer auditLog.Close()

		mgr := NewManager(filepath.Join(dir, "ring.sock"), dir, idx, auditLog)

		// Generate a random number of accesses (2-8).
		numAccesses := rapid.IntRange(2, 8).Draw(t, "num_accesses")

		type accessRecord struct {
			actor   string
			purpose string
		}
		var accesses []accessRecord

		for i := 0; i < numAccesses; i++ {
			actor := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}`).Draw(t, "actor")
			purpose := rapid.SampledFrom([]string{
				"investigation", "export", "review", "compliance_audit",
			}).Draw(t, "purpose")

			if err := mgr.AccessPcap(pcapPath, actor, purpose); err != nil {
				t.Fatalf("AccessPcap %d: %v", i, err)
			}
			accesses = append(accesses, accessRecord{actor: actor, purpose: purpose})
		}

		// Read the final manifest.
		events, err := ReadManifest(manifestPath)
		if err != nil {
			t.Fatalf("ReadManifest: %v", err)
		}

		// ── Invariant 1: Total events = 1 created + numAccesses ────────────
		expectedCount := 1 + numAccesses
		if len(events) != expectedCount {
			t.Fatalf("expected %d events, got %d", expectedCount, len(events))
		}

		// ── Invariant 2: First event is still "created" ────────────────────
		if events[0].Event != CustodyEventCreated {
			t.Fatalf("first event should be %q, got %q", CustodyEventCreated, events[0].Event)
		}

		// ── Invariant 3: Each access event matches in order ────────────────
		for i, acc := range accesses {
			ev := events[1+i]
			if ev.Event != CustodyEventAccessed {
				t.Fatalf("event %d: expected %q, got %q", 1+i, CustodyEventAccessed, ev.Event)
			}
			if ev.Actor != acc.actor {
				t.Fatalf("event %d: actor mismatch: expected %q, got %q", 1+i, acc.actor, ev.Actor)
			}
			if ev.Purpose != acc.purpose {
				t.Fatalf("event %d: purpose mismatch: expected %q, got %q", 1+i, acc.purpose, ev.Purpose)
			}
			if ev.TimestampMs <= 0 {
				t.Fatalf("event %d: expected positive timestamp_ms, got %d", 1+i, ev.TimestampMs)
			}
		}

		// ── Invariant 4: Timestamps are non-decreasing ─────────────────────
		for i := 1; i < len(events); i++ {
			if events[i].TimestampMs < events[i-1].TimestampMs {
				t.Fatalf("timestamp decreased at event %d: %d < %d",
					i, events[i].TimestampMs, events[i-1].TimestampMs)
			}
		}
	})
}
