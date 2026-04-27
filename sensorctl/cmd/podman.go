package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func podmanCmd() *cobra.Command {
	podman := &cobra.Command{
		Use:   "podman",
		Short: "Manage Podman/Quadlet deployment units",
		Long:  "Podman commands target the production-ish local path: Podman containers managed by systemd Quadlet units.",
	}

	podman.AddCommand(podmanInstallCmd())
	podman.AddCommand(podmanStartCmd())
	podman.AddCommand(podmanStatusCmd())

	return podman
}

func podmanInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install Quadlet units into the user systemd container directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installQuadlet()
		},
	}
}

func podmanStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <unit>",
		Short: "Start a Quadlet target or service, such as sensor-pod",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			unit := normalizeSystemdUnit(args[0])
			return runShell("", fmt.Sprintf("systemctl --user start %s", shellQuote(unit)))
		},
	}
}

func podmanStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [unit]",
		Short: "Show Podman systemd status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return runShell("", "systemctl --user list-units 'sensor-*' 'management-*' 'capture-*' 'analysis-*' --no-pager")
			}
			unit := normalizeSystemdUnit(args[0])
			return runShell("", fmt.Sprintf("systemctl --user status %s --no-pager", shellQuote(unit)))
		},
	}
}

func installQuadlet() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	src := filepath.Join(root, "deploy", "quadlet")
	dst := filepath.Join(home, ".config", "containers", "systemd")

	commands := []string{
		fmt.Sprintf("mkdir -p %s", shellQuote(dst)),
		fmt.Sprintf("find %s -type f \\( -name '*.container' -o -name '*.target' -o -name '*.network' -o -name '*.volume' \\) -exec cp {} %s/ \\;", shellQuote(src), shellQuote(dst)),
		"systemctl --user daemon-reload",
	}

	for _, command := range commands {
		if err := runShell(root, command); err != nil {
			return err
		}
	}

	fmt.Println("Quadlet units installed. Try `sensorctl podman start sensor-pod`.")
	return nil
}

func normalizeSystemdUnit(name string) string {
	if strings.HasSuffix(name, ".target") || strings.HasSuffix(name, ".service") {
		return name
	}
	return name + ".target"
}
