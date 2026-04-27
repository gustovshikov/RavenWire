package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if isRepoRoot(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("RavenWire repo root not found; run sensorctl from inside the repository")
}

func isRepoRoot(dir string) bool {
	required := []string{
		filepath.Join("deploy", "quadlet"),
		filepath.Join("sensor-agent", "go.mod"),
		filepath.Join("sensorctl", "go.mod"),
	}
	for _, path := range required {
		if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
			return false
		}
	}
	return true
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

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
