package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run RavenWire repository and deployment-definition checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := repoRoot()
			if err != nil {
				return err
			}

			checks := []struct {
				name string
				dir  string
				env  []string
				args []string
			}{
				{"sensorctl Go tests", filepath.Join(root, "sensorctl"), nil, []string{"go", "test", "./..."}},
				{"sensor-agent Go tests", filepath.Join(root, "sensor-agent"), nil, []string{"go", "test", "./..."}},
				{"pcap ring writer Linux build check", filepath.Join(root, "sensor-agent"), []string{"GOOS=linux"}, []string{"go", "test", "./cmd/pcap-ring-writer"}},
				{"lab carve simulator Go tests", filepath.Join(root, "tools", "lab", "pcap-carve-simulator"), nil, []string{"go", "test", "./..."}},
			}

			for _, check := range checks {
				if err := runCheck(check.name, check.dir, check.env, check.args...); err != nil {
					return err
				}
			}

			if podmanComposeAvailable() {
				composeFile := filepath.Join(root, "tools", "lab", "compose.capture-test.yml")
				if err := runCheck("lab compose definition", root, nil, "podman", "compose", "-f", composeFile, "config"); err != nil {
					return err
				}
			} else {
				fmt.Println("skip lab compose definition: podman compose not found")
			}

			fmt.Println("RavenWire checks passed.")
			return nil
		},
	}
}

func podmanComposeAvailable() bool {
	if _, err := exec.LookPath("podman"); err != nil {
		return false
	}
	return exec.Command("podman", "compose", "version").Run() == nil
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
