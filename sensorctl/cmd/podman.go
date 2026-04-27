package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func installCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install RavenWire Quadlet units",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installQuadlet()
		},
	}
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [unit]",
		Short: "Start a RavenWire target or service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			unit := defaultUnit(args, "sensor-pod")
			return runShell("", fmt.Sprintf("systemctl --user start %s", shellQuote(unit)))
		},
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop [unit]",
		Short: "Stop a RavenWire target or service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			unit := defaultUnit(args, "sensor-pod")
			return runShell("", fmt.Sprintf("systemctl --user stop %s", shellQuote(unit)))
		},
	}
}

func restartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart [unit]",
		Short: "Restart a RavenWire target or service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			unit := defaultUnit(args, "sensor-pod")
			return runShell("", fmt.Sprintf("systemctl --user restart %s", shellQuote(unit)))
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [unit]",
		Short: "Show RavenWire unit status",
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

func logsCmd() *cobra.Command {
	var lines int

	cmd := &cobra.Command{
		Use:   "logs [unit]",
		Short: "Show RavenWire systemd journal logs",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return runShell("", fmt.Sprintf("journalctl --user -u sensor-pod.target -u management-pod.target -n %d --no-pager", lines))
			}
			unit := normalizeSystemdUnit(args[0])
			return runShell("", fmt.Sprintf("journalctl --user -u %s -n %d --no-pager", shellQuote(unit), lines))
		},
	}

	cmd.Flags().IntVarP(&lines, "lines", "n", 200, "Number of journal lines to show")
	return cmd
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
	quadletDst := filepath.Join(home, ".config", "containers", "systemd")
	systemdDst := filepath.Join(home, ".config", "systemd", "user")

	commands := []string{
		fmt.Sprintf("mkdir -p %s %s", shellQuote(quadletDst), shellQuote(systemdDst)),
		fmt.Sprintf("find %s -type f \\( -name '*.container' -o -name '*.network' -o -name '*.volume' \\) -exec cp {} %s/ \\;", shellQuote(src), shellQuote(quadletDst)),
		fmt.Sprintf("find %s -type f -name '*.target' -exec cp {} %s/ \\;", shellQuote(src), shellQuote(systemdDst)),
		"systemctl --user daemon-reload",
	}

	for _, command := range commands {
		if err := runShell(root, command); err != nil {
			return err
		}
	}

	fmt.Println("Quadlet units installed. Try `sensorctl start sensor-pod`.")
	return nil
}

func defaultUnit(args []string, fallback string) string {
	if len(args) == 0 {
		return normalizeSystemdUnit(fallback)
	}
	return normalizeSystemdUnit(args[0])
}

func normalizeSystemdUnit(name string) string {
	if strings.HasSuffix(name, ".target") || strings.HasSuffix(name, ".service") {
		return name
	}
	return name + ".target"
}
