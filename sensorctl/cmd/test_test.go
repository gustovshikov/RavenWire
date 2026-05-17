package cmd

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRepositoryChecksCompileLinuxSensorAgentPackagesWithoutExecuting(t *testing.T) {
	checks := repositoryChecks("/repo")

	var linuxCheck *repositoryCheck
	for i := range checks {
		if checks[i].name == "sensor-agent Linux compile check" {
			linuxCheck = &checks[i]
			break
		}
	}
	if linuxCheck == nil {
		t.Fatal("missing sensor-agent Linux compile check")
	}

	if linuxCheck.dir != filepath.Join("/repo", "sensor-agent") {
		t.Fatalf("dir = %q, want sensor-agent under repo root", linuxCheck.dir)
	}
	if !slices.Contains(linuxCheck.env, "GOOS=linux") {
		t.Fatalf("env = %#v, want GOOS=linux", linuxCheck.env)
	}
	if !slices.Contains(linuxCheck.args, "-exec=/usr/bin/true") {
		t.Fatalf("args = %#v, want exec wrapper that avoids running Linux binaries on macOS", linuxCheck.args)
	}
	if !slices.Contains(linuxCheck.args, "./...") {
		t.Fatalf("args = %#v, want all sensor-agent packages", linuxCheck.args)
	}
	if strings.Join(linuxCheck.args, " ") == "go test ./cmd/pcap-ring-writer" {
		t.Fatal("Linux check must not execute a cross-compiled Linux test binary on macOS")
	}
}
