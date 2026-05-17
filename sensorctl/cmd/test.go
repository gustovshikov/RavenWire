package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

type repositoryCheck struct {
	name string
	dir  string
	env  []string
	args []string
}

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run RavenWire repository and deployment-definition checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			for _, check := range repositoryChecks(root) {
				if err := runRepositoryCheck(check); err != nil {
					return err
				}
			}

			fmt.Println("RavenWire checks passed.")
			return nil
		},
	}
}

func repositoryChecks(root string) []repositoryCheck {
	return []repositoryCheck{
		{
			name: "sensorctl Go tests",
			dir:  filepath.Join(root, "sensorctl"),
			args: []string{"go", "test", "./..."},
		},
		{
			name: "sensor-agent Go tests",
			dir:  filepath.Join(root, "sensor-agent"),
			args: []string{"go", "test", "./..."},
		},
		sensorAgentLinuxCompileCheck(root),
	}
}

func sensorAgentLinuxCompileCheck(root string) repositoryCheck {
	return repositoryCheck{
		name: "sensor-agent Linux compile check",
		dir:  filepath.Join(root, "sensor-agent"),
		env:  []string{"GOOS=linux"},
		args: []string{"go", "test", "-exec=/usr/bin/true", "./..."},
	}
}

func runRepositoryCheck(check repositoryCheck) error {
	return runCheck(check.name, check.dir, check.env, check.args...)
}

func runCheck(name, dir string, env []string, args ...string) error {
	fmt.Printf("\n==> %s\n", name)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}
