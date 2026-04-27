// sensorctl — RavenWire operations CLI
//
// Phase 1 operations tool. Not a stable public API.
//
// Usage:
//   sensorctl <command> [flags]
//
// Commands:
//   install  — install Quadlet units
//   start    — start the sensor pod
//   status   — show unit status
//   logs     — show systemd journal logs
//   enroll   — enroll a sensor with the manager
//   test     — run local RavenWire checks

package main

import (
	"fmt"
	"os"

	"github.com/ravenwire/ravenwire/sensorctl/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
