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
// For any config with at least one invalid field, Validate() must return at least one error.
// Validates: Requirements 2.3
func TestProperty2_InvalidConfigRejection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Choose which kind of invalid field to inject
		invalidKind := rapid.IntRange(0, 3).Draw(t, "invalid_kind")

		var cfg CaptureConfig

		switch invalidKind {
		case 0: // duplicate fanout group ID
			cfg = CaptureConfig{
				Consumers: []ConsumerConfig{
					{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
					{Name: "suricata", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 4},
				},
			}
		case 1: // zero thread count
			cfg = CaptureConfig{
				Consumers: []ConsumerConfig{
					{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "eth0", ThreadCount: 0},
				},
			}
		case 2: // empty interface
			cfg = CaptureConfig{
				Consumers: []ConsumerConfig{
					{Name: "zeek", FanoutGroupID: 1, FanoutMode: FanoutHash, Interface: "", ThreadCount: 4},
				},
			}
		case 3: // invalid fanout mode
			cfg = CaptureConfig{
				Consumers: []ConsumerConfig{
					{Name: "zeek", FanoutGroupID: 1, FanoutMode: "BOGUS_MODE", Interface: "eth0", ThreadCount: 4},
				},
			}
		}

		errs := cfg.Validate()
		if len(errs) == 0 {
			t.Fatalf("expected at least one validation error for invalid config (kind=%d), got none", invalidKind)
		}
	})
}
