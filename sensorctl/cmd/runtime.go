package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

func runtimeCmd() *cobra.Command {
	runtime := &cobra.Command{
		Use:   "runtime",
		Short: "Detect and select container runtimes",
	}

	runtime.AddCommand(runtimeDetectCmd())
	runtime.AddCommand(runtimeSpecificCmd("docker"))
	runtime.AddCommand(runtimeSpecificCmd("podman"))

	return runtime
}

func runtimeDetectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Show available container runtimes and Compose commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, candidate := range []string{"docker", "podman"} {
				if path, err := exec.LookPath(candidate); err == nil {
					fmt.Printf("%-6s %s\n", candidate, path)
				} else {
					fmt.Printf("%-6s not found\n", candidate)
				}
			}

			for _, candidate := range []string{"docker compose", "podman compose", "docker-compose", "podman-compose"} {
				if commandExists(candidate) {
					fmt.Printf("compose %-16s available\n", candidate)
				}
			}
			return nil
		},
	}
}

func runtimeSpecificCmd(runtime string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   runtime,
		Short: fmt.Sprintf("Run workflows using %s", runtime),
	}

	cmd.AddCommand(runtimeTestSpikeCmd(runtime))
	if runtime == "podman" {
		cmd.AddCommand(runtimeInstallQuadletCmd())
	}

	return cmd
}

func runtimeTestSpikeCmd(runtime string) *cobra.Command {
	cmd := testSpikeCmd()
	cmd.Use = "test-spike"
	cmd.Short = fmt.Sprintf("Run the spike test with %s-compatible commands", runtime)
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runSpikeForRuntime(cmd, args, runtime)
	}
	return cmd
}

func runSpikeForRuntime(cmd *cobra.Command, args []string, runtime string) error {
	captureIface, _ := cmd.Flags().GetString("iface")
	ringSizeMB, _ := cmd.Flags().GetInt("ring-size")
	alertDelaySecs, _ := cmd.Flags().GetInt("alert-delay")
	preWindowSecs, _ := cmd.Flags().GetInt("pre-window")
	postWindowSecs, _ := cmd.Flags().GetInt("post-window")
	trafficDurationSecs, _ := cmd.Flags().GetInt("traffic-duration")
	skipVMBoot, _ := cmd.Flags().GetBool("skip-boot")
	keepRunning, _ := cmd.Flags().GetBool("keep-running")

	return runSpikeTest(spikeTestConfig{
		captureIface:        captureIface,
		ringSizeMB:          ringSizeMB,
		alertDelaySecs:      alertDelaySecs,
		preWindowSecs:       preWindowSecs,
		postWindowSecs:      postWindowSecs,
		trafficDurationSecs: trafficDurationSecs,
		skipVMBoot:          skipVMBoot,
		keepRunning:         keepRunning,
		containerRuntime:    runtimeCommand(runtime),
		composeCommand:      composeCommand(runtime),
	})
}

func runtimeInstallQuadletCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-quadlet",
		Short: "Install Podman Quadlet units from deploy/quadlet",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installQuadlet()
		},
	}
}

func runtimeCommand(runtime string) string {
	if value := strings.TrimSpace(envOr("CONTAINER_RUNTIME", "")); value != "" {
		return value
	}
	return runtime
}

func composeCommand(runtime string) string {
	if value := strings.TrimSpace(envOr("COMPOSE", "")); value != "" {
		return value
	}
	if runtime == "podman" {
		return "podman compose"
	}
	return "docker compose"
}

func commandExists(command string) bool {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}
	if _, err := exec.LookPath(parts[0]); err != nil {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	c := exec.Command(parts[0], parts[1:]...)
	return c.Run() == nil
}
