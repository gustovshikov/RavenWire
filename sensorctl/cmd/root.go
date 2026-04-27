package cmd

import (
	"github.com/spf13/cobra"
)

// Root returns the root cobra command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "sensorctl",
		Short: "Network Sensor Stack development and operations CLI",
		Long: `sensorctl manages RavenWire development, enrollment, and Podman deployment workflows.

Phase 1 internal dev tool — not a stable public API.`,
	}

	root.AddCommand(devCmd())
	root.AddCommand(envCmd())
	root.AddCommand(enrollCmd())
	root.AddCommand(podmanCmd())
	root.AddCommand(runtimeCmd())
	root.AddCommand(testCmd())
	root.AddCommand(remoteCmd())

	return root
}
