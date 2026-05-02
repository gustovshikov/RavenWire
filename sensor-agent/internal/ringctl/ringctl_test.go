package ringctl_test

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/ringctl"
)

// Property 2: Ring_Control_Protocol serialization round-trip
//
// For any valid Ring_Control_Protocol command struct (MarkPreAlertCmd,
// CarveWindowCmd, ConfigureCmd), encoding the struct using the PCAP_Manager
// serializer and decoding it using the pcap_ring_writer deserializer SHALL
// produce a struct with identical field values, with all timestamp fields
// preserved as nanoseconds without unit conversion error.
//
// Validates: Requirements 2.1, 2.3, 2.4
func TestProperty2_RingControlProtocolRoundTrip(t *testing.T) {
	t.Run("MarkPreAlertCmd", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			original := ringctl.MarkPreAlertCmd{
				Cmd:         "mark_pre_alert",
				TimestampNs: rapid.Int64().Draw(t, "timestamp_ns"),
			}

			// Encode (PCAP_Manager serializer side)
			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("marshal MarkPreAlertCmd: %v", err)
			}

			// Decode (pcap_ring_writer deserializer side)
			var decoded ringctl.MarkPreAlertCmd
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal MarkPreAlertCmd: %v", err)
			}

			if decoded.Cmd != original.Cmd {
				t.Fatalf("Cmd mismatch: got %q, want %q", decoded.Cmd, original.Cmd)
			}
			if decoded.TimestampNs != original.TimestampNs {
				t.Fatalf("TimestampNs mismatch: got %d, want %d (unit conversion error)",
					decoded.TimestampNs, original.TimestampNs)
			}
		})
	})

	t.Run("CarveWindowCmd", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			original := ringctl.CarveWindowCmd{
				Cmd:         "carve_window",
				PreAlertNs:  rapid.Int64().Draw(t, "pre_alert_ns"),
				PostAlertNs: rapid.Int64().Draw(t, "post_alert_ns"),
				OutputPath:  rapid.StringMatching(`[a-z0-9/_.-]{1,64}`).Draw(t, "output_path"),
			}

			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("marshal CarveWindowCmd: %v", err)
			}

			var decoded ringctl.CarveWindowCmd
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal CarveWindowCmd: %v", err)
			}

			if decoded.Cmd != original.Cmd {
				t.Fatalf("Cmd mismatch: got %q, want %q", decoded.Cmd, original.Cmd)
			}
			if decoded.PreAlertNs != original.PreAlertNs {
				t.Fatalf("PreAlertNs mismatch: got %d, want %d (unit conversion error)",
					decoded.PreAlertNs, original.PreAlertNs)
			}
			if decoded.PostAlertNs != original.PostAlertNs {
				t.Fatalf("PostAlertNs mismatch: got %d, want %d (unit conversion error)",
					decoded.PostAlertNs, original.PostAlertNs)
			}
			if decoded.OutputPath != original.OutputPath {
				t.Fatalf("OutputPath mismatch: got %q, want %q", decoded.OutputPath, original.OutputPath)
			}
		})
	})

	t.Run("ConfigureCmd", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			original := ringctl.ConfigureCmd{
				Cmd:       "configure",
				BPFFilter: rapid.StringMatching(`[a-z0-9 ]{0,128}`).Draw(t, "bpf_filter"),
			}

			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("marshal ConfigureCmd: %v", err)
			}

			var decoded ringctl.ConfigureCmd
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal ConfigureCmd: %v", err)
			}

			if decoded.Cmd != original.Cmd {
				t.Fatalf("Cmd mismatch: got %q, want %q", decoded.Cmd, original.Cmd)
			}
			if decoded.BPFFilter != original.BPFFilter {
				t.Fatalf("BPFFilter mismatch: got %q, want %q", decoded.BPFFilter, original.BPFFilter)
			}
		})
	})

	t.Run("RingResponse", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			original := ringctl.RingResponse{
				Status:                 rapid.SampledFrom([]string{"ok", "error"}).Draw(t, "status"),
				Error:                  rapid.StringMatching(`[a-z ]{0,64}`).Draw(t, "error"),
				PacketCount:            rapid.IntRange(0, 1<<20).Draw(t, "packet_count"),
				OutputPath:             rapid.StringMatching(`[a-z0-9/_.-]{0,64}`).Draw(t, "output_path"),
				PacketsWritten:         uint64(rapid.Uint64().Draw(t, "packets_written")),
				BytesWritten:           uint64(rapid.Uint64().Draw(t, "bytes_written")),
				WrapCount:              uint64(rapid.Uint64().Draw(t, "wrap_count")),
				SocketDrops:            uint64(rapid.Uint64().Draw(t, "socket_drops")),
				SocketFreezeQueueDrops: uint64(rapid.Uint64().Draw(t, "socket_freeze_queue_drops")),
			}

			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("marshal RingResponse: %v", err)
			}

			var decoded ringctl.RingResponse
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal RingResponse: %v", err)
			}

			if decoded.Status != original.Status {
				t.Fatalf("Status mismatch: got %q, want %q", decoded.Status, original.Status)
			}
			if decoded.PacketsWritten != original.PacketsWritten {
				t.Fatalf("PacketsWritten mismatch: got %d, want %d", decoded.PacketsWritten, original.PacketsWritten)
			}
			if decoded.BytesWritten != original.BytesWritten {
				t.Fatalf("BytesWritten mismatch: got %d, want %d", decoded.BytesWritten, original.BytesWritten)
			}
			if decoded.WrapCount != original.WrapCount {
				t.Fatalf("WrapCount mismatch: got %d, want %d", decoded.WrapCount, original.WrapCount)
			}
			if decoded.SocketDrops != original.SocketDrops {
				t.Fatalf("SocketDrops mismatch: got %d, want %d", decoded.SocketDrops, original.SocketDrops)
			}
			if decoded.SocketFreezeQueueDrops != original.SocketFreezeQueueDrops {
				t.Fatalf("SocketFreezeQueueDrops mismatch: got %d, want %d",
					decoded.SocketFreezeQueueDrops, original.SocketFreezeQueueDrops)
			}
		})
	})
}
