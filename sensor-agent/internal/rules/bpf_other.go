//go:build !linux

package rules

// compileBPFDryRun is a no-op on non-Linux platforms.
// BPF filter validation requires an AF_PACKET socket, which is Linux-only.
func compileBPFDryRun(filter string) error {
	return nil
}
