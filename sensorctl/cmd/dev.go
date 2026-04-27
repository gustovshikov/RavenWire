package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func devCmd() *cobra.Command {
	dev := &cobra.Command{
		Use:   "dev",
		Short: "Run Docker/Compose development workflows",
		Long:  "Development commands use Docker and Compose for fast local iteration. Podman/Quadlet remains the production deployment target.",
	}

	dev.AddCommand(devUpCmd())
	dev.AddCommand(devTestSpikeCmd())

	return dev
}

func devUpCmd() *cobra.Command {
	var detached bool

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start the development Compose stack",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}
			compose := envOr("COMPOSE", "docker compose")
			composeArgs := "up"
			if detached {
				composeArgs += " -d"
			}
			return runShell(root, fmt.Sprintf("%s -f deploy/compose/compose.dev.yml %s", compose, composeArgs))
		},
	}

	cmd.Flags().BoolVarP(&detached, "detach", "d", true, "Run the stack in the background")
	return cmd
}

func devTestSpikeCmd() *cobra.Command {
	cmd := testSpikeCmd()
	cmd.Use = "test-spike"
	cmd.Short = "Run the Docker/Compose spike test in the development VM"
	return cmd
}

func runShell(dir, command string) error {
	c := exec.Command("sh", "-c", command)
	c.Dir = dir
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	fmt.Printf("-> %s\n", command)
	return c.Run()
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
