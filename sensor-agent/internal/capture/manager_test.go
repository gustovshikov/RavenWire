//go:build linux

package capture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPacketStatsForIfaceReadsRxBytes(t *testing.T) {
	root := t.TempDir()
	statsDir := filepath.Join(root, "eth-test", "statistics")
	if err := os.MkdirAll(statsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"rx_packets":       "1234\n",
		"rx_bytes":         "987654\n",
		"rx_dropped":       "5\n",
		"rx_missed_errors": "7\n",
	}

	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(statsDir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	received, dropped, bytesReceived, err := readPacketStatsForIfaceRoot(root, "eth-test")
	if err != nil {
		t.Fatalf("readPacketStatsForIfaceRoot: %v", err)
	}

	if received != 1234 {
		t.Fatalf("received = %d, want 1234", received)
	}
	if dropped != 12 {
		t.Fatalf("dropped = %d, want 12", dropped)
	}
	if bytesReceived != 987654 {
		t.Fatalf("bytesReceived = %d, want 987654", bytesReceived)
	}
}
