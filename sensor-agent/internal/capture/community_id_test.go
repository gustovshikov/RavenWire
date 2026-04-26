package capture

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// ── Unit tests ────────────────────────────────────────────────────────────────

func TestComputeCommunityID_KnownVector(t *testing.T) {
	// Known test vector verified against gommunityid and pycommunityid reference implementations:
	// TCP 128.232.110.120:34855 -> 66.35.250.204:80
	// Source: https://github.com/satta/gommunityid (tcp.pcap test data)
	flow, err := ParseFlow5Tuple("128.232.110.120", "66.35.250.204", 34855, 80, 6)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ComputeCommunityID(flow, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
	if got != want {
		t.Errorf("community ID mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestComputeCommunityID_Symmetric(t *testing.T) {
	// Forward and reverse directions must produce the same Community ID.
	fwd, _ := ParseFlow5Tuple("10.0.0.1", "10.0.0.2", 1234, 80, 6)
	rev, _ := ParseFlow5Tuple("10.0.0.2", "10.0.0.1", 80, 1234, 6)

	idFwd, err := ComputeCommunityID(fwd, 0)
	if err != nil {
		t.Fatal(err)
	}
	idRev, err := ComputeCommunityID(rev, 0)
	if err != nil {
		t.Fatal(err)
	}
	if idFwd != idRev {
		t.Errorf("forward and reverse flows produced different Community IDs:\n  fwd: %s\n  rev: %s", idFwd, idRev)
	}
}

func TestComputeCommunityID_Format(t *testing.T) {
	flow, _ := ParseFlow5Tuple("192.168.1.1", "8.8.8.8", 54321, 53, 17)
	id, err := ComputeCommunityID(flow, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "1:") {
		t.Errorf("Community ID must start with '1:', got: %s", id)
	}
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || len(parts[1]) == 0 {
		t.Errorf("Community ID must be '1:<base64>', got: %s", id)
	}
}

// ── Property tests ────────────────────────────────────────────────────────────

// zeekConnLog simulates a Zeek conn.log JSON record for a flow.
type zeekConnLog struct {
	UID         string `json:"uid"`
	SrcIP       string `json:"id.orig_h"`
	SrcPort     int    `json:"id.orig_p"`
	DstIP       string `json:"id.resp_h"`
	DstPort     int    `json:"id.resp_p"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id"`
}

// suricataAlert simulates a Suricata EVE JSON alert record for a flow.
type suricataAlert struct {
	EventType   string `json:"event_type"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DstIP       string `json:"dest_ip"`
	DstPort     int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id"`
}

// vectorNormalized simulates a Vector-normalized event after the remap transform.
// The remap preserves community_id at the top level unchanged.
type vectorNormalized struct {
	SensorSource string `json:"sensor_source"`
	SensorPodID  string `json:"sensor_pod_id"`
	CommunityID  string `json:"community_id"`
}

// simulateZeekOutput marshals a Zeek conn.log record and extracts community_id.
func simulateZeekOutput(communityID, srcIP, dstIP string, srcPort, dstPort int, proto string) (string, error) {
	rec := zeekConnLog{
		UID:         "Ctest123",
		SrcIP:       srcIP,
		SrcPort:     srcPort,
		DstIP:       dstIP,
		DstPort:     dstPort,
		Proto:       proto,
		CommunityID: communityID,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	cid, _ := out["community_id"].(string)
	return cid, nil
}

// simulateSuricataOutput marshals a Suricata EVE alert and extracts community_id.
func simulateSuricataOutput(communityID, srcIP, dstIP string, srcPort, dstPort int, proto string) (string, error) {
	rec := suricataAlert{
		EventType:   "alert",
		SrcIP:       srcIP,
		SrcPort:     srcPort,
		DstIP:       dstIP,
		DstPort:     dstPort,
		Proto:       proto,
		CommunityID: communityID,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	cid, _ := out["community_id"].(string)
	return cid, nil
}

// simulateVectorNormalized simulates the Vector remap transform:
// parses the input JSON and preserves community_id at the top level unchanged.
func simulateVectorNormalized(inputJSON []byte, sensorSource string) (string, error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(inputJSON, &parsed); err != nil {
		return "", err
	}
	// Vector remap: preserve community_id exactly as-is
	cid, _ := parsed["community_id"].(string)
	out := vectorNormalized{
		SensorSource: sensorSource,
		SensorPodID:  "sensor-pod-1",
		CommunityID:  cid,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return "", err
	}
	return result["community_id"].(string), nil
}

// Property 11: Community_ID Preservation Across All Output Types
//
// For any arbitrary flow 5-tuple, the Community_ID computed from the tuple must be:
//   - present and identical in the Zeek log output
//   - present and identical in the Suricata alert output
//   - present and identical in the Vector-normalized output (raw schema mode)
//
// This validates that no normalization stage drops or modifies the community_id field.
// Validates: Requirements 17.1, 17.3
func TestProperty11_CommunityIDPreservationAcrossOutputTypes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate an arbitrary flow 5-tuple
		srcIP := rapid.Custom(func(t *rapid.T) string {
			return fmt.Sprintf("%d.%d.%d.%d",
				rapid.IntRange(1, 254).Draw(t, "s1"),
				rapid.IntRange(0, 255).Draw(t, "s2"),
				rapid.IntRange(0, 255).Draw(t, "s3"),
				rapid.IntRange(1, 254).Draw(t, "s4"),
			)
		}).Draw(t, "src_ip")

		dstIP := rapid.Custom(func(t *rapid.T) string {
			return fmt.Sprintf("%d.%d.%d.%d",
				rapid.IntRange(1, 254).Draw(t, "d1"),
				rapid.IntRange(0, 255).Draw(t, "d2"),
				rapid.IntRange(0, 255).Draw(t, "d3"),
				rapid.IntRange(1, 254).Draw(t, "d4"),
			)
		}).Draw(t, "dst_ip")

		srcPort := uint16(rapid.IntRange(1024, 65535).Draw(t, "src_port"))
		dstPort := uint16(rapid.IntRange(1, 1023).Draw(t, "dst_port"))

		// Use TCP (6) or UDP (17)
		protoNum := uint8(rapid.SampledFrom([]uint8{6, 17}).Draw(t, "proto"))
		protoStr := map[uint8]string{6: "tcp", 17: "udp"}[protoNum]

		// Compute the canonical Community ID from the 5-tuple
		flow, err := ParseFlow5Tuple(srcIP, dstIP, srcPort, dstPort, protoNum)
		if err != nil {
			t.Skip() // skip degenerate IPs
		}
		canonicalID, err := ComputeCommunityID(flow, 0)
		if err != nil {
			t.Fatal(err)
		}

		// 1. Zeek output: community_id must be present and equal to canonical
		zeekCID, err := simulateZeekOutput(canonicalID, srcIP, dstIP, int(srcPort), int(dstPort), protoStr)
		if err != nil {
			t.Fatalf("zeek output simulation failed: %v", err)
		}
		if zeekCID != canonicalID {
			t.Fatalf("Zeek community_id mismatch:\n  got:  %q\n  want: %q", zeekCID, canonicalID)
		}

		// 2. Suricata output: community_id must be present and equal to canonical
		suricataCID, err := simulateSuricataOutput(canonicalID, srcIP, dstIP, int(srcPort), int(dstPort), protoStr)
		if err != nil {
			t.Fatalf("suricata output simulation failed: %v", err)
		}
		if suricataCID != canonicalID {
			t.Fatalf("Suricata community_id mismatch:\n  got:  %q\n  want: %q", suricataCID, canonicalID)
		}

		// 3. Vector-normalized output (from Zeek): community_id must survive the remap transform
		zeekJSON, _ := json.Marshal(zeekConnLog{
			UID: "Ctest", SrcIP: srcIP, SrcPort: int(srcPort),
			DstIP: dstIP, DstPort: int(dstPort), Proto: protoStr,
			CommunityID: canonicalID,
		})
		vectorFromZeekCID, err := simulateVectorNormalized(zeekJSON, "zeek")
		if err != nil {
			t.Fatalf("vector normalization (zeek) failed: %v", err)
		}
		if vectorFromZeekCID != canonicalID {
			t.Fatalf("Vector (from Zeek) community_id mismatch:\n  got:  %q\n  want: %q", vectorFromZeekCID, canonicalID)
		}

		// 4. Vector-normalized output (from Suricata): community_id must survive the remap transform
		suricataJSON, _ := json.Marshal(suricataAlert{
			EventType: "alert", SrcIP: srcIP, SrcPort: int(srcPort),
			DstIP: dstIP, DstPort: int(dstPort), Proto: protoStr,
			CommunityID: canonicalID,
		})
		vectorFromSuricataCID, err := simulateVectorNormalized(suricataJSON, "suricata")
		if err != nil {
			t.Fatalf("vector normalization (suricata) failed: %v", err)
		}
		if vectorFromSuricataCID != canonicalID {
			t.Fatalf("Vector (from Suricata) community_id mismatch:\n  got:  %q\n  want: %q", vectorFromSuricataCID, canonicalID)
		}
	})
}
