// sensorctl — Network Sensor Stack development and operations CLI
//
// Phase 1 internal dev tool. Not a stable public API.
// Full public CLI is Phase 5.
//
// Usage:
//   sensorctl <command> [flags]
//
// Commands:
//   env up        — boot the Vagrant dev VM
//   env down      — halt the Vagrant dev VM
//   env status    — show VM status
//   env ssh       — SSH into the VM
//   env provision — re-run provisioner
//   test spike    — run the full spike test suite (spin up, traffic, verify, report)
//   test verify   — run verify-spike.sh against a running VM (no traffic gen)

package main

import (
	"fmt"
	"os"

	"github.com/sensor-stack/sensorctl/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
