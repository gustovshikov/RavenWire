package cmd

import (
	"github.com/spf13/cobra"
)

// Root returns the root cobra command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "sensorctl",
		Short: "RavenWire operations CLI",
		Long:  "sensorctl installs, starts, enrolls, and inspects RavenWire Podman/Quadlet sensor stacks.",
	}

	root.AddCommand(agentCmd())
	root.AddCommand(enrollCmd())
	root.AddCommand(installCmd())
	root.AddCommand(startCmd())
	root.AddCommand(stopCmd())
	root.AddCommand(restartCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(logsCmd())
	root.AddCommand(testCmd())

	return root
}
