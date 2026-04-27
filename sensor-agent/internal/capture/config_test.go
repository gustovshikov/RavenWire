//go:build linux

package capture

import (
	"testing"

	"pgregory.net/rapid"
)

// ── Unit tests ────────────────────────────────────────────────────────────────

func TestValidateConfig_Valid(t *testing.T) {
	cfg := &CaptureConfig{
		Consumers: []ConsumerConfig{
			{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
			{Name: "suricata", FanoutGroupID: 2, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
			{Name: "pcap_ring_writer", FanoutGroupID: 4, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
		},
	}
	errs := cfg.Validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid config, got: %v", errs)
	}
}

func TestValidateConfig_DuplicateFanoutGroupID(t *testing.T) {
	cfg := &CaptureConfig{
		Consumers: []ConsumerConfig{
			{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
			{Name: "suricata", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4}, // duplicate
		},
	}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Error("expected error for duplicate fanout group ID, got none")
	}
}

func TestValidateConfig_EmptyInterface(t *testing.T) {
	cfg := &CaptureConfig{
		Consumers: []ConsumerConfig{
			{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "", ThreadCount: 4},
		},
	}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Error("expected error for empty interface, got none")
	}
}

func TestValidateConfig_ZeroThreadCount(t *testing.T) {
	cfg := &CaptureConfig{
		Consumers: []ConsumerConfig{
			{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 0},
		},
	}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Error("expected error for zero thread count, got none")
	}
}

func TestValidateConfig_InvalidFanoutMode(t *testing.T) {
	cfg := &CaptureConfig{
		Consumers: []ConsumerConfig{
			{Name: "zeek", FanoutGroupID: 1, FanoutMode: "INVALID_MODE", Interface: "eth0", ThreadCount: 4},
		},
	}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Error("expected error for invalid fanout mode, got none")
	}
}

func TestValidateConfig_EmptyConsumers(t *testing.T) {
	cfg := &CaptureConfig{Consumers: []ConsumerConfig{}}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Error("expected error for empty consumers, got none")
	}
}

func TestOverrideInterface(t *testing.T) {
	cfg := &CaptureConfig{
		Consumers: []ConsumerConfig{
			{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
			{Name: "suricata", FanoutGroupID: 2, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
			{Name: "pcap_ring_writer", FanoutGroupID: 4, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 1},
		},
	}

	cfg.OverrideInterface("ens16f1")

	for _, consumer := range cfg.Consumers {
		if consumer.Interface != "ens16f1" {
			t.Fatalf("expected %s interface to be overridden, got %q", consumer.Name, consumer.Interface)
		}
	}
}

// ── Property tests ────────────────────────────────────────────────────────────

// consumerGen generates a valid ConsumerConfig with a unique fanout group ID.
func consumerGen(groupID uint16) *rapid.Generator[ConsumerConfig] {
	return rapid.Custom(func(t *rapid.T) ConsumerConfig {
		modes := []FanoutMode{FanoutHash, FanoutRoundRobin, FanoutCPU, FanoutRollover}
		mode := modes[rapid.IntRange(0, len(modes)-1).Draw(t, "mode")]
		iface := rapid.StringMatching(`eth[0-9]`).Draw(t, "iface")
		threads := rapid.IntRange(1, 16).Draw(t, "threads")
		name := rapid.StringMatching(`[a-z][a-z0-9_]{2,15}`).Draw(t, "name")
		return ConsumerConfig{
			Name:          name,
			FanoutGroupID: groupID,
			FanoutMode:    mode,
			Interface:     iface,
			ThreadCount:   threads,
		}
	})
}

// Property 1: Capture Consumer Fanout Group Uniqueness
// For any valid config with 2–3 consumers, all fanout group IDs must be distinct.
// Validates: Requirements 2.2
func TestProperty1_FanoutGroupUniqueness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate 2–3 consumers with distinct fanout group IDs
		numConsumers := rapid.IntRange(2, 3).Draw(t, "num_consumers")

		// Pick distinct group IDs
		allIDs := rapid.SliceOfNDistinct(
			rapid.Uint16Range(1, 255),
			numConsumers, numConsumers,
			func(id uint16) uint16 { return id },
		).Draw(t, "group_ids")

		consumers := make([]ConsumerConfig, numConsumers)
		for i := 0; i < numConsumers; i++ {
			consumers[i] = ConsumerConfig{
				Name:          []string{"zeek", "suricata", "pcap_ring_writer"}[i%3],
				FanoutGroupID: allIDs[i],
				FanoutMode:    FanoutHash,
				Interface:     "eth0",
				ThreadCount:   rapid.IntRange(1, 8).Draw(t, "threads"),
			}
		}

		cfg := &CaptureConfig{Consumers: consumers}
		errs := cfg.Validate()

		// Check that no duplicate fanout group ID errors are present
		for _, err := range errs {
			if containsStr(err.Message, "already used by consumer") {
				t.Fatalf("unexpected duplicate fanout group ID error for distinct IDs: %v", err)
			}
		}

		// Verify all IDs are indeed distinct
		seen := make(map[uint16]bool)
		for _, c := range consumers {
			if seen[c.FanoutGroupID] {
				t.Fatalf("generated duplicate fanout group ID %d", c.FanoutGroupID)
			}
			seen[c.FanoutGroupID] = true
		}
	})
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Property 2: Invalid Capture Configuration Rejection
//
// For any CaptureConfig that contains at least one invalid field — duplicate
// fanout group ID, zero/negative thread count, empty interface name, unknown
// fanout mode, or empty consumer name — Validate() must:
//
//  1. Return at least one ValidationError (non-empty slice).
//  2. Each returned error must carry a non-empty Field and a non-empty Message,
//     so that callers can surface descriptive diagnostics.
//
// The test generates configs by:
//   - Picking a random number of otherwise-valid consumers (1–3).
//   - Randomly choosing one of five fault classes to inject into the config.
//   - For per-consumer faults, injecting the fault into a randomly selected consumer.
//   - For the duplicate-fanout-ID fault, forcing two consumers to share the same group ID.
//
// Validates: Requirements 2.3
func TestProperty2_InvalidConfigRejection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numConsumers := rapid.IntRange(1, 3).Draw(t, "num_consumers")

		// Assign distinct group IDs to all consumers up front.
		groupIDs := rapid.SliceOfNDistinct(
			rapid.Uint16Range(1, 255),
			numConsumers, numConsumers,
			func(id uint16) uint16 { return id },
		).Draw(t, "group_ids")

		// Build a base of valid consumers.
		consumers := make([]ConsumerConfig, numConsumers)
		for i := 0; i < numConsumers; i++ {
			consumers[i] = ConsumerConfig{
				Name:          []string{"zeek", "suricata", "pcap_ring_writer"}[i%3],
				FanoutGroupID: groupIDs[i],
				FanoutMode:    FanoutHash,
				Interface:     "eth0",
				ThreadCount:   rapid.IntRange(1, 8).Draw(t, "base_threads"),
			}
		}

		// Five fault classes (0–4).
		faultClass := rapid.IntRange(0, 4).Draw(t, "fault_class")

		// Index of the consumer that will receive the per-consumer fault.
		targetIdx := rapid.IntRange(0, numConsumers-1).Draw(t, "target_idx")

		switch faultClass {
		case 0: // duplicate fanout group ID — force two consumers to share a group ID
			if numConsumers < 2 {
				// Only one consumer: reuse its own group ID by adding a second consumer with the same ID.
				consumers = append(consumers, ConsumerConfig{
					Name:          "extra",
					FanoutGroupID: consumers[0].FanoutGroupID,
					FanoutMode:    FanoutHash,
					Interface:     "eth0",
					ThreadCount:   1,
				})
			} else {
				consumers[1].FanoutGroupID = consumers[0].FanoutGroupID
			}

		case 1: // zero or negative thread count
			consumers[targetIdx].ThreadCount = rapid.IntRange(-64, 0).Draw(t, "bad_threads")

		case 2: // empty interface name
			consumers[targetIdx].Interface = ""

		case 3: // unknown fanout mode — generate a string that is not a valid mode
			badMode := FanoutMode(rapid.StringMatching(`[A-Z_]{4,20}`).Draw(t, "bad_mode"))
			for validFanoutModes[badMode] {
				badMode = FanoutMode(rapid.StringMatching(`[A-Z_]{4,20}`).Draw(t, "bad_mode_retry"))
			}
			consumers[targetIdx].FanoutMode = badMode

		case 4: // empty consumer name
			consumers[targetIdx].Name = ""
		}

		cfg := &CaptureConfig{Consumers: consumers}
		errs := cfg.Validate()

		// Assertion 1: at least one error must be returned.
		if len(errs) == 0 {
			t.Fatalf(
				"Validate() returned no errors for an invalid config (fault_class=%d, target=%d): %+v",
				faultClass, targetIdx, consumers,
			)
		}

		// Assertion 2: every returned error must have a non-empty Field and Message,
		// ensuring callers receive actionable diagnostic information.
		for i, e := range errs {
			if e.Field == "" {
				t.Errorf("error[%d] has empty Field (fault_class=%d): %+v", i, faultClass, e)
			}
			if e.Message == "" {
				t.Errorf("error[%d] has empty Message (fault_class=%d): %+v", i, faultClass, e)
			}
		}
	})
}
