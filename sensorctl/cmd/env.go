package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func envCmd() *cobra.Command {
	env := &cobra.Command{
		Use:   "env",
		Short: "Manage the Vagrant development VM",
	}

	env.AddCommand(envUpCmd())
	env.AddCommand(envDownCmd())
	env.AddCommand(envStatusCmd())
	env.AddCommand(envSSHCmd())
	env.AddCommand(envProvisionCmd())
	env.AddCommand(envDestroyCmd())

	return env
}

// repoRoot returns the directory containing the Vagrantfile.
// Walks up from the sensorctl binary location.
func repoRoot() (string, error) {
	// Try CWD first, then walk up
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "Vagrantfile")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("Vagrantfile not found — run sensorctl from the repo root")
}

// vagrant runs a vagrant command in the repo root, streaming output to stdout/stderr.
func vagrant(args ...string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}

	cmd := exec.Command("vagrant", args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("→ vagrant %s\n", strings.Join(args, " "))
	return cmd.Run()
}

// vagrantOutput runs a vagrant command and returns its stdout as a string.
func vagrantOutput(args ...string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}

	cmd := exec.Command("vagrant", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func envUpCmd() *cobra.Command {
	var provision bool

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Boot the development VM",
		Long:  "Starts the Vagrant VM. Provisions on first boot automatically.",
		RunE: func(cmd *cobra.Command, args []string) error {
			vagrantArgs := []string{"up"}
			if provision {
				vagrantArgs = append(vagrantArgs, "--provision")
			}
			return vagrant(vagrantArgs...)
		},
	}

	cmd.Flags().BoolVar(&provision, "provision", false, "Force re-provisioning even if already provisioned")
	return cmd
}

func envDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Halt the development VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			return vagrant("halt")
		},
	}
}

func envStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show VM status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return vagrant("status")
		},
	}
}

func envSSHCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh",
		Short: "SSH into the development VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			return vagrant("ssh")
		},
	}
}

func envProvisionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "provision",
		Short: "Re-run the VM provisioner",
		RunE: func(cmd *cobra.Command, args []string) error {
			return vagrant("provision")
		},
	}
}

func envDestroyCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Destroy the development VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			if force {
				return vagrant("destroy", "--force")
			}
			return vagrant("destroy")
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")
	return cmd
}
