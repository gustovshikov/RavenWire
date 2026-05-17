//go:build linux

package main

import "testing"

func TestDefaultProfilesCoverSupportedTargets(t *testing.T) {
	profiles := defaultProfiles()
	if len(profiles) != 3 {
		t.Fatalf("defaultProfiles returned %d profiles, want 3", len(profiles))
	}

	want := []struct {
		name string
		gbps float64
	}{
		{"1Gbps", 1.0},
		{"10Gbps", 10.0},
		{"25Gbps", 25.0},
	}

	for i, expected := range want {
		if profiles[i].Name != expected.name || profiles[i].TargetGbps != expected.gbps {
			t.Fatalf("profile %d = %#v, want %s %.1fGbps", i, profiles[i], expected.name, expected.gbps)
		}
		if profiles[i].PacketSize != benchPacketSize || profiles[i].DurationS != benchDurationSecs {
			t.Fatalf("profile %d does not use default packet size/duration: %#v", i, profiles[i])
		}
	}
}

func TestTargetPPS(t *testing.T) {
	if got, want := targetPPS(1.0, 1000), uint64(125000); got != want {
		t.Fatalf("targetPPS(1Gbps, 1000B) = %d, want %d", got, want)
	}
	if got, want := targetPPS(10.0, 1024), uint64(1220703); got != want {
		t.Fatalf("targetPPS(10Gbps, 1024B) = %d, want %d", got, want)
	}
}
