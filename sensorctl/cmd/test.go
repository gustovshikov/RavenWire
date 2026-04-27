package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func testCmd() *cobra.Command {
	test := &cobra.Command{
		Use:   "test",
		Short: "Run test suites against the development VM",
	}

	test.AddCommand(testSpikeCmd())
	test.AddCommand(testVerifyCmd())

	return test
}

// vmSSH runs a command inside the Vagrant VM and streams output.
func vmSSH(command string) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}

	cmd := exec.Command("vagrant", "ssh", "--", command)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// vmSSHOutput runs a command inside the VM and returns stdout.
func vmSSHOutput(command string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}

	cmd := exec.Command("vagrant", "ssh", "--", command)
	cmd.Dir = root
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// isVMRunning returns true if the Vagrant VM is in a running state.
func isVMRunning() bool {
	out, err := vagrantOutput("status", "--machine-readable")
	if err != nil {
		return false
	}
	return strings.Contains(out, "state,running")
}

func testSpikeCmd() *cobra.Command {
	var (
		captureIface        string
		ringSizeMB          int
		alertDelaySecs      int
		preWindowSecs       int
		postWindowSecs      int
		trafficDurationSecs int
		skipVMBoot          bool
		keepRunning         bool
	)

	cmd := &cobra.Command{
		Use:   "spike",
		Short: "Full automated spike test: boot VM, start stack, generate traffic, verify",
		Long: `Runs the complete Phase 0.5 spike validation:

  1. Boot the Vagrant VM (if not already running)
  2. Start the spike Compose stack
  3. Generate test traffic on veth1
  4. Wait for pcap_manager to fire a simulated alert and carve a PCAP
  5. Run verify-spike.sh and report results
  6. Halt the VM (unless --keep-running)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSpikeTest(spikeTestConfig{
				captureIface:        captureIface,
				ringSizeMB:          ringSizeMB,
				alertDelaySecs:      alertDelaySecs,
				preWindowSecs:       preWindowSecs,
				postWindowSecs:      postWindowSecs,
				trafficDurationSecs: trafficDurationSecs,
				skipVMBoot:          skipVMBoot,
				keepRunning:         keepRunning,
				containerRuntime:    runtimeCommand("docker"),
				composeCommand:      composeCommand("docker"),
			})
		},
	}

	cmd.Flags().StringVar(&captureIface, "iface", "veth0", "Capture interface inside the VM")
	cmd.Flags().IntVar(&ringSizeMB, "ring-size", 512, "pcap_ring_writer ring size in MB")
	cmd.Flags().IntVar(&alertDelaySecs, "alert-delay", 15, "Seconds before simulated alert fires")
	cmd.Flags().IntVar(&preWindowSecs, "pre-window", 5, "Pre-alert PCAP window in seconds")
	cmd.Flags().IntVar(&postWindowSecs, "post-window", 3, "Post-alert PCAP window in seconds")
	cmd.Flags().IntVar(&trafficDurationSecs, "traffic-duration", 30, "Seconds to generate traffic")
	cmd.Flags().BoolVar(&skipVMBoot, "skip-boot", false, "Skip VM boot (assume already running)")
	cmd.Flags().BoolVar(&keepRunning, "keep-running", false, "Leave VM running after test")

	return cmd
}

func testVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Run verify-spike.sh against a running VM (no traffic generation)",
		Long:  "Assumes the spike stack is already running. Just runs the verification script.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isVMRunning() {
				return fmt.Errorf("VM is not running — run `sensorctl env up` first")
			}
			fmt.Println("→ Running spike verification...")
			return vmSSH("bash /vagrant/dev-env/verify-spike.sh")
		},
	}
}

// ── Spike test runner ─────────────────────────────────────────────────────────

type spikeTestConfig struct {
	captureIface        string
	ringSizeMB          int
	alertDelaySecs      int
	preWindowSecs       int
	postWindowSecs      int
	trafficDurationSecs int
	skipVMBoot          bool
	keepRunning         bool
	containerRuntime    string
	composeCommand      string
}

func runSpikeTest(cfg spikeTestConfig) error {
	start := time.Now()
	step := 0

	printStep := func(msg string) {
		step++
		fmt.Printf("\n[%d] %s\n", step, msg)
		fmt.Println(strings.Repeat("─", 60))
	}

	printResult := func(passed bool, duration time.Duration) {
		fmt.Println()
		fmt.Println(strings.Repeat("═", 60))
		if passed {
			fmt.Printf("  ✓  SPIKE TEST PASSED  (%.1fs)\n", duration.Seconds())
		} else {
			fmt.Printf("  ✗  SPIKE TEST FAILED  (%.1fs)\n", duration.Seconds())
		}
		fmt.Println(strings.Repeat("═", 60))
	}

	// ── Step 1: Boot VM ──────────────────────────────────────────────────────
	if !cfg.skipVMBoot {
		printStep("Booting development VM")
		if isVMRunning() {
			fmt.Println("  VM already running — skipping boot")
		} else {
			if err := vagrant("up"); err != nil {
				return fmt.Errorf("VM boot failed: %w", err)
			}
		}
	} else {
		fmt.Println("  --skip-boot set, assuming VM is running")
		if !isVMRunning() {
			return fmt.Errorf("VM is not running — remove --skip-boot or run `sensorctl env up`")
		}
	}

	// ── Step 2: Build spike binaries inside VM ───────────────────────────────
	printStep("Building spike binaries inside VM")
	buildCmds := []string{
		"cd /vagrant/spike/pcap_ring_writer && go build -o /usr/local/bin/pcap_ring_writer . 2>&1",
		"cd /vagrant/spike/pcap_manager && go build -o /usr/local/bin/pcap_manager . 2>&1",
	}
	for _, buildCmd := range buildCmds {
		if err := vmSSH(buildCmd); err != nil {
			fmt.Printf("  Warning: build step failed: %v\n", err)
			fmt.Println("  (Continuing — binaries may already be built)")
		}
	}

	// ── Step 3: Start spike stack ────────────────────────────────────────────
	printStep("Starting spike Compose stack")
	composeEnv := fmt.Sprintf(
		"CAPTURE_IFACE=%s RING_SIZE_MB=%d ALERT_DELAY_SECONDS=%d PRE_ALERT_WINDOW_SECONDS=%d POST_ALERT_WINDOW_SECONDS=%d",
		cfg.captureIface, cfg.ringSizeMB, cfg.alertDelaySecs, cfg.preWindowSecs, cfg.postWindowSecs,
	)
	compose := cfg.composeCommand
	if strings.TrimSpace(compose) == "" {
		compose = vmComposeCommand()
	}
	spikeFile := "/vagrant/deploy/compose/docker-compose.spike.yml"
	startCmd := fmt.Sprintf("cd /vagrant && %s %s -p spike -f %s up -d 2>&1", composeEnv, compose, spikeFile)
	if err := vmSSH(startCmd); err != nil {
		return fmt.Errorf("failed to start spike stack: %w", err)
	}

	// Give containers a moment to initialize
	fmt.Println("  Waiting 5s for containers to initialize...")
	time.Sleep(5 * time.Second)

	// ── Step 4: Generate traffic ─────────────────────────────────────────────
	printStep(fmt.Sprintf("Generating test traffic on veth1 (%ds)", cfg.trafficDurationSecs))
	trafficCmd := fmt.Sprintf(
		"DURATION=%d TRAFFIC_IFACE=veth1 sudo -E bash /vagrant/dev-env/gen-traffic.sh &",
		cfg.trafficDurationSecs,
	)
	if err := vmSSH(trafficCmd); err != nil {
		fmt.Printf("  Warning: traffic generation returned error: %v\n", err)
		fmt.Println("  (Continuing — some traffic may have been generated)")
	}

	// ── Step 5: Wait for alert + carve ───────────────────────────────────────
	totalWait := cfg.alertDelaySecs + cfg.postWindowSecs + 5 // extra buffer
	printStep(fmt.Sprintf("Waiting %ds for simulated alert and PCAP carve", totalWait))

	for i := 0; i < totalWait; i++ {
		time.Sleep(1 * time.Second)
		if (i+1)%5 == 0 {
			fmt.Printf("  %ds elapsed...\n", i+1)
		}
	}

	// ── Step 6: Run verification ─────────────────────────────────────────────
	printStep("Running spike verification")
	verifyErr := vmSSH(fmt.Sprintf("CONTAINER_RUNTIME=%s COMPOSE=%q bash /vagrant/dev-env/verify-spike.sh", shellQuote(runtimeOrDefault(cfg.containerRuntime)), compose))

	// ── Step 7: Collect logs on failure ─────────────────────────────────────
	if verifyErr != nil {
		printStep("Collecting diagnostic logs")
		diagCmds := []string{
			fmt.Sprintf("cd /vagrant && %s -p spike -f %s logs --tail=50 2>&1", compose, spikeFile),
			"echo '---ring-stats---' && echo '{\"cmd\":\"status\"}' | nc -U -w 2 /var/run/pcap_ring.sock 2>/dev/null | jq . || echo 'control socket unavailable'",
			"echo '---carved-pcaps---' && ls -lh /tmp/alert_carve_*.pcap 2>/dev/null || echo 'none found'",
			"echo '---veth-status---' && ip link show veth0 veth1 2>&1",
		}
		for _, diagCmd := range diagCmds {
			_ = vmSSH(diagCmd)
		}
	}

	// ── Step 8: Stop stack ───────────────────────────────────────────────────
	printStep("Stopping spike stack")
	_ = vmSSH(fmt.Sprintf("cd /vagrant && %s -p spike -f %s down 2>&1", compose, spikeFile))

	// ── Step 9: Halt VM (unless --keep-running) ──────────────────────────────
	if !cfg.keepRunning {
		printStep("Halting VM")
		_ = vagrant("halt")
	} else {
		fmt.Println("\n  --keep-running set, VM left running")
		fmt.Println("  Run `sensorctl env down` to halt when done")
	}

	// ── Result ───────────────────────────────────────────────────────────────
	passed := verifyErr == nil
	printResult(passed, time.Since(start))

	if !passed {
		return fmt.Errorf("spike test failed: %w", verifyErr)
	}

	// Print next steps on success
	root, _ := repoRoot()
	fmt.Printf("\nNext: run Phase 1 tasks\n")
	fmt.Printf("  cd %s\n", root)
	fmt.Printf("  sensorctl env up\n")
	fmt.Printf("  # then proceed with task 1 in tasks.md\n")

	return nil
}

func vmComposeCommand() string {
	if compose := strings.TrimSpace(os.Getenv("COMPOSE")); compose != "" {
		return compose
	}
	return "docker compose"
}

func runtimeOrDefault(runtime string) string {
	if strings.TrimSpace(runtime) != "" {
		return runtime
	}
	if runtime := strings.TrimSpace(os.Getenv("CONTAINER_RUNTIME")); runtime != "" {
		return runtime
	}
	return "docker"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// writeTestReport writes a simple text report to a file.
func writeTestReport(path string, passed bool, output string, duration time.Duration) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	status := "PASSED"
	if !passed {
		status = "FAILED"
	}

	fmt.Fprintf(f, "Network Sensor Stack — Spike Test Report\n")
	fmt.Fprintf(f, "Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "Duration:  %.1fs\n", duration.Seconds())
	fmt.Fprintf(f, "Result:    %s\n\n", status)
	fmt.Fprintf(f, "Output:\n%s\n", output)

	return nil
}

// findRepoRoot is a helper used in tests.
func findRepoRoot() (string, error) {
	return repoRoot()
}

// vagrantSSHCommand returns the full vagrant ssh command for a given shell command.
// Used for constructing commands in tests.
func vagrantSSHCommand(root, shellCmd string) *exec.Cmd {
	cmd := exec.Command("vagrant", "ssh", "--", shellCmd)
	cmd.Dir = root
	return cmd
}

// resolveScriptPath returns the absolute path to a dev-env script.
func resolveScriptPath(scriptName string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "dev-env", scriptName), nil
}
