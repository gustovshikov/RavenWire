package cmd

import (
	"github.com/spf13/cobra"
)

// Root returns the root cobra command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "sensorctl",
		Short: "Network Sensor Stack development and operations CLI",
		Long: `sensorctl manages the sensor stack development environment and test suite.

Phase 1 internal dev tool — not a stable public API.`,
	}

	root.AddCommand(envCmd())
	root.AddCommand(testCmd())
	root.AddCommand(remoteCmd())

	return root
}
