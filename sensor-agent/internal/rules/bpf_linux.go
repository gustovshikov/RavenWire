//go:build linux

package rules

import (
	"github.com/sensor-stack/sensor-agent/internal/capture"
)

// compileBPFDryRun validates a BPF filter by compiling it via SO_ATTACH_FILTER
// on a temporary AF_PACKET socket. Returns nil if valid or empty.
func compileBPFDryRun(filter string) error {
	_, err := capture.CompileBPF(filter)
	return err
}
