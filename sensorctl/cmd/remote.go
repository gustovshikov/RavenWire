package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

func remoteCmd() *cobra.Command {
	remote := &cobra.Command{
		Use:   "remote",
		Short: "Run operations on a remote Linux sensor server over SSH",
		Long: `Manages the remote Linux server used for testing on real x86 hardware.
The remote server pulls from GitHub and runs the spike/tests directly
(no Vagrant needed — the server IS the Linux environment).`,
	}

	remote.AddCommand(remoteSetupCmd())
	remote.AddCommand(remoteSyncCmd())
	remote.AddCommand(remoteTestCmd())
	remote.AddCommand(remoteSSHCmd())
	remote.AddCommand(remoteStatusCmd())

	return remote
}

// ── SSH helpers ───────────────────────────────────────────────────────────────

// sshRun runs a command on the remote server, streaming output.
func sshRun(host, user, keyFile, command string) error {
	args := buildSSHArgs(host, user, keyFile)
	args = append(args, command)

	cmd := exec.Command("ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("→ ssh %s@%s %q\n", user, host, command)
	return cmd.Run()
}

// sshOutput runs a command on the remote server and returns stdout.
func sshOutput(host, user, keyFile, command string) (string, error) {
	args := buildSSHArgs(host, user, keyFile)
	args = append(args, command)

	cmd := exec.Command("ssh", args...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func buildSSHArgs(host, user, keyFile string) []string {
	args := []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
	}
	if keyFile != "" {
		args = append(args, "-i", keyFile)
	}
	args = append(args, fmt.Sprintf("%s@%s", user, host))
	return args
}

// ── Commands ──────────────────────────────────────────────────────────────────

func remoteSetupCmd() *cobra.Command {
	var host, user, keyFile, repoURL string

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Provision the remote server: install deps, clone repo, build binaries",
		Long: `One-time setup for a fresh CentOS Stream 10 (or any RHEL-family) server.
Installs Docker, Go, git, tcpdump, sets up veth pair, clones the repo,
and builds the spike binaries.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoteSetup(host, user, keyFile, repoURL)
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Remote server hostname or IP (required)")
	cmd.Flags().StringVar(&user, "user", "root", "SSH user")
	cmd.Flags().StringVar(&keyFile, "key", "", "Path to SSH private key (uses ssh-agent if not set)")
	cmd.Flags().StringVar(&repoURL, "repo", "git@github.com:gustovshikov/RavenWire.git", "Git repo URL")
	cmd.MarkFlagRequired("host")

	return cmd
}

func remoteSyncCmd() *cobra.Command {
	var host, user, keyFile string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Push local changes to GitHub then pull on the remote server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoteSync(host, user, keyFile)
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Remote server hostname or IP (required)")
	cmd.Flags().StringVar(&user, "user", "root", "SSH user")
	cmd.Flags().StringVar(&keyFile, "key", "", "Path to SSH private key")
	cmd.MarkFlagRequired("host")

	return cmd
}

func remoteTestCmd() *cobra.Command {
	var (
		host, user, keyFile string
		captureIface        string
		alertDelaySecs      int
		trafficDurationSecs int
		skipSync            bool
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Sync repo to remote server and run the full spike test suite",
		Long: `Pushes to GitHub, pulls on the remote server, then runs:
  1. docker-compose up (spike stack)
  2. gen-traffic.sh (traffic on veth1)
  3. verify-spike.sh (all 4 goals)
Results are streamed back over SSH.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoteTest(remoteTestConfig{
				host:                host,
				user:                user,
				keyFile:             keyFile,
				captureIface:        captureIface,
				alertDelaySecs:      alertDelaySecs,
				trafficDurationSecs: trafficDurationSecs,
				skipSync:            skipSync,
			})
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Remote server hostname or IP (required)")
	cmd.Flags().StringVar(&user, "user", "root", "SSH user")
	cmd.Flags().StringVar(&keyFile, "key", "", "Path to SSH private key")
	cmd.Flags().StringVar(&captureIface, "iface", "veth0", "Capture interface on remote server")
	cmd.Flags().IntVar(&alertDelaySecs, "alert-delay", 15, "Seconds before simulated alert fires")
	cmd.Flags().IntVar(&trafficDurationSecs, "traffic-duration", 30, "Seconds to generate traffic")
	cmd.Flags().BoolVar(&skipSync, "skip-sync", false, "Skip git push/pull (use current remote state)")
	cmd.MarkFlagRequired("host")

	return cmd
}

func remoteSSHCmd() *cobra.Command {
	var host, user, keyFile string

	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Open an interactive SSH session to the remote server",
		RunE: func(cmd *cobra.Command, args []string) error {
			sshArgs := buildSSHArgs(host, user, keyFile)
			// Remove BatchMode for interactive session
			filtered := []string{}
			skip := false
			for _, a := range sshArgs {
				if a == "BatchMode=yes" {
					skip = true
					continue
				}
				if skip {
					skip = false
					continue
				}
				filtered = append(filtered, a)
			}
			c := exec.Command("ssh", filtered...)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			c.Stdin = os.Stdin
			return c.Run()
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Remote server hostname or IP (required)")
	cmd.Flags().StringVar(&user, "user", "root", "SSH user")
	cmd.Flags().StringVar(&keyFile, "key", "", "Path to SSH private key")
	cmd.MarkFlagRequired("host")

	return cmd
}

func remoteStatusCmd() *cobra.Command {
	var host, user, keyFile string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show remote server status: docker, veth, ring buffer, disk",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := []struct {
				label string
				cmd   string
			}{
				{"Docker", "docker info --format '{{.ServerVersion}}' 2>/dev/null || echo 'not running'"},
				{"Veth pair", "ip link show veth0 veth1 2>/dev/null | grep -E 'veth|state' || echo 'not found'"},
				{"Ring buffer (/dev/shm)", "df -h /dev/shm | tail -1"},
				{"Repo", "cd ~/RavenWire && git log --oneline -3 2>/dev/null || echo 'not cloned'"},
				{"Spike stack", "cd ~/RavenWire/spike && docker-compose ps 2>/dev/null || echo 'not running'"},
				{"Carved PCAPs", "ls -lh /tmp/alert_carve_*.pcap 2>/dev/null || echo 'none'"},
			}

			for _, check := range checks {
				fmt.Printf("\n── %s ──\n", check.label)
				_ = sshRun(host, user, keyFile, check.cmd)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Remote server hostname or IP (required)")
	cmd.Flags().StringVar(&user, "user", "root", "SSH user")
	cmd.Flags().StringVar(&keyFile, "key", "", "Path to SSH private key")
	cmd.MarkFlagRequired("host")

	return cmd
}

// ── Implementation ────────────────────────────────────────────────────────────

const remoteRepoDir = "~/RavenWire"

// remoteProvisionScript is the one-time setup script for CentOS Stream 10.
const remoteProvisionScript = `
set -euo pipefail

echo "==> Updating system"
dnf update -y -q

echo "==> Installing dependencies"
dnf install -y -q \
  git curl wget \
  tcpdump wireshark-cli \
  iproute net-tools \
  jq nmap-ncat \
  make gcc

# Docker
if ! command -v docker &>/dev/null; then
  echo "==> Installing Docker"
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  dnf install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
fi

# Go
GO_VERSION="1.22.4"
if ! command -v go &>/dev/null; then
  echo "==> Installing Go ${GO_VERSION}"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
  export PATH=$PATH:/usr/local/go/bin
fi

# veth pair (persistent)
echo "==> Setting up veth pair"
ip link add veth0 type veth peer name veth1 2>/dev/null || true
ip link set veth0 up
ip link set veth1 up
ip addr add 10.99.0.1/24 dev veth1 2>/dev/null || true

# Persist veth across reboots
cat > /etc/systemd/system/veth-pair.service <<'EOF'
[Unit]
Description=Create veth pair for sensor testing
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "ip link add veth0 type veth peer name veth1 2>/dev/null || true; ip link set veth0 up; ip link set veth1 up; ip addr add 10.99.0.1/24 dev veth1 2>/dev/null || true"

[Install]
WantedBy=multi-user.target
EOF
systemctl enable veth-pair.service

# /dev/shm sizing
mount -o remount,size=2g /dev/shm 2>/dev/null || true

# Kernel tuning
cat > /etc/sysctl.d/99-sensor.conf <<'EOF'
net.core.rmem_max = 134217728
net.core.rmem_default = 134217728
net.core.netdev_max_backlog = 250000
net.core.bpf_jit_enable = 1
EOF
sysctl -p /etc/sysctl.d/99-sensor.conf 2>/dev/null || true

echo "==> Remote server provisioned"
`

func runRemoteSetup(host, user, keyFile, repoURL string) error {
	fmt.Printf("Setting up remote server %s@%s\n", user, host)
	fmt.Println(strings.Repeat("─", 60))

	// Step 1: Test connectivity
	fmt.Println("\n[1] Testing SSH connectivity...")
	if err := sshRun(host, user, keyFile, "echo 'SSH OK' && uname -a"); err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	// Step 2: Install system dependencies
	fmt.Println("\n[2] Installing system dependencies...")
	if err := sshRun(host, user, keyFile, remoteProvisionScript); err != nil {
		return fmt.Errorf("provisioning failed: %w", err)
	}

	// Step 3: Clone or update repo
	fmt.Println("\n[3] Cloning repository...")
	cloneCmd := fmt.Sprintf(`
		export PATH=$PATH:/usr/local/go/bin
		if [ -d %s ]; then
			echo "Repo already exists, pulling..."
			cd %s && git pull
		else
			git clone %s %s
		fi
	`, remoteRepoDir, remoteRepoDir, repoURL, remoteRepoDir)
	if err := sshRun(host, user, keyFile, cloneCmd); err != nil {
		return fmt.Errorf("repo clone failed: %w", err)
	}

	// Step 4: Build binaries
	fmt.Println("\n[4] Building spike binaries...")
	buildCmd := fmt.Sprintf(`
		export PATH=$PATH:/usr/local/go/bin
		cd %s/spike/pcap_ring_writer && go mod tidy && go build -o /usr/local/bin/pcap_ring_writer .
		cd %s/spike/pcap_manager && go mod tidy && go build -o /usr/local/bin/pcap_manager .
		cd %s/sensorctl && go mod tidy && go build -o /usr/local/bin/sensorctl .
		echo "Binaries built successfully"
	`, remoteRepoDir, remoteRepoDir, remoteRepoDir)
	if err := sshRun(host, user, keyFile, buildCmd); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Printf("  Remote server %s is ready\n", host)
	fmt.Println(strings.Repeat("═", 60))
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  sensorctl remote test --host %s\n", host)
	return nil
}

func runRemoteSync(host, user, keyFile string) error {
	// Push to GitHub
	fmt.Println("→ Pushing to GitHub...")
	pushCmd := exec.Command("git", "push", "origin", "main")
	pushCmd.Stdout = os.Stdout
	pushCmd.Stderr = os.Stderr
	if err := pushCmd.Run(); err != nil {
		// Try pushing current branch
		branchCmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
		branch, _ := branchCmd.Output()
		pushCmd2 := exec.Command("git", "push", "origin", strings.TrimSpace(string(branch)))
		pushCmd2.Stdout = os.Stdout
		pushCmd2.Stderr = os.Stderr
		if err2 := pushCmd2.Run(); err2 != nil {
			return fmt.Errorf("git push failed: %w", err)
		}
	}

	// Pull on remote
	fmt.Println("→ Pulling on remote server...")
	pullCmd := fmt.Sprintf("cd %s && git pull && echo 'Pull complete'", remoteRepoDir)
	return sshRun(host, user, keyFile, pullCmd)
}

type remoteTestConfig struct {
	host                string
	user                string
	keyFile             string
	captureIface        string
	alertDelaySecs      int
	trafficDurationSecs int
	skipSync            bool
}

func runRemoteTest(cfg remoteTestConfig) error {
	fmt.Printf("Running spike test on %s@%s\n", cfg.user, cfg.host)
	fmt.Println(strings.Repeat("─", 60))

	// Step 1: Sync
	if !cfg.skipSync {
		fmt.Println("\n[1] Syncing repo to remote...")
		if err := runRemoteSync(cfg.host, cfg.user, cfg.keyFile); err != nil {
			return fmt.Errorf("sync failed: %w", err)
		}
	} else {
		fmt.Println("\n[1] Skipping sync (--skip-sync)")
	}

	// Step 2: Rebuild binaries (fast if nothing changed)
	fmt.Println("\n[2] Building binaries on remote...")
	buildCmd := fmt.Sprintf(`
		export PATH=$PATH:/usr/local/go/bin
		cd %s/spike/pcap_ring_writer && go build -o /usr/local/bin/pcap_ring_writer . 2>&1
		cd %s/spike/pcap_manager && go build -o /usr/local/bin/pcap_manager . 2>&1
		echo "Build complete"
	`, remoteRepoDir, remoteRepoDir)
	if err := sshRun(cfg.host, cfg.user, cfg.keyFile, buildCmd); err != nil {
		fmt.Println("  Warning: build step had errors, continuing...")
	}

	// Step 3: Start spike stack
	fmt.Println("\n[3] Starting spike stack...")
	startCmd := fmt.Sprintf(`
		cd %s/spike
		CAPTURE_IFACE=%s ALERT_DELAY_SECONDS=%d PRE_ALERT_WINDOW_SECONDS=5 POST_ALERT_WINDOW_SECONDS=3 \
		docker compose up -d 2>&1
		echo "Stack started"
	`, remoteRepoDir, cfg.captureIface, cfg.alertDelaySecs)
	if err := sshRun(cfg.host, cfg.user, cfg.keyFile, startCmd); err != nil {
		return fmt.Errorf("failed to start spike stack: %w", err)
	}

	// Step 4: Generate traffic in background
	fmt.Printf("\n[4] Generating traffic for %ds...\n", cfg.trafficDurationSecs)
	trafficCmd := fmt.Sprintf(
		"DURATION=%d TRAFFIC_IFACE=veth1 bash %s/dev-env/gen-traffic.sh > /tmp/traffic.log 2>&1 &",
		cfg.trafficDurationSecs, remoteRepoDir,
	)
	_ = sshRun(cfg.host, cfg.user, cfg.keyFile, trafficCmd)

	// Step 5: Wait for alert + carve
	totalWait := cfg.alertDelaySecs + 3 + 5
	fmt.Printf("\n[5] Waiting %ds for alert and PCAP carve...\n", totalWait)
	waitCmd := fmt.Sprintf("sleep %d && echo 'Wait complete'", totalWait)
	_ = sshRun(cfg.host, cfg.user, cfg.keyFile, waitCmd)

	// Step 6: Run verification
	fmt.Println("\n[6] Running verification...")
	verifyCmd := fmt.Sprintf("bash %s/dev-env/verify-spike.sh", remoteRepoDir)
	verifyErr := sshRun(cfg.host, cfg.user, cfg.keyFile, verifyCmd)

	// Step 7: Collect diagnostics on failure
	if verifyErr != nil {
		fmt.Println("\n[7] Collecting diagnostics...")
		diagCmd := fmt.Sprintf(`
			echo "=== docker compose logs ===" && cd %s/spike && docker compose logs --tail=30 2>&1
			echo "=== ring stats ===" && echo '{"cmd":"status"}' | nc -U -w 2 /var/run/pcap_ring.sock 2>/dev/null | python3 -m json.tool || echo "unavailable"
			echo "=== carved pcaps ===" && ls -lh /tmp/alert_carve_*.pcap 2>/dev/null || echo "none"
		`, remoteRepoDir)
		_ = sshRun(cfg.host, cfg.user, cfg.keyFile, diagCmd)
	}

	// Step 8: Stop stack
	fmt.Println("\n[8] Stopping spike stack...")
	stopCmd := fmt.Sprintf("cd %s/spike && docker compose down 2>&1", remoteRepoDir)
	_ = sshRun(cfg.host, cfg.user, cfg.keyFile, stopCmd)

	// Result
	fmt.Println()
	fmt.Println(strings.Repeat("═", 60))
	if verifyErr == nil {
		fmt.Println("  ✓  REMOTE SPIKE TEST PASSED")
	} else {
		fmt.Println("  ✗  REMOTE SPIKE TEST FAILED")
	}
	fmt.Println(strings.Repeat("═", 60))

	return verifyErr
}
