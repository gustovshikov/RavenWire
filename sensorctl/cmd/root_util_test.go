package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootRegistersTopLevelCommands(t *testing.T) {
	root := Root()
	for _, name := range []string{
		"agent",
		"enroll",
		"install",
		"start",
		"stop",
		"restart",
		"status",
		"logs",
		"cleanup",
		"uninstall",
		"test",
	} {
		if found, _, err := root.Find([]string{name}); err != nil || found == nil || found.Name() != name {
			t.Fatalf("root command missing %q: found=%v err=%v", name, found, err)
		}
	}
}

func TestIsRepoRootRequiresDeploymentAndGoModules(t *testing.T) {
	dir := t.TempDir()
	if isRepoRoot(dir) {
		t.Fatal("empty directory must not be treated as repo root")
	}

	for _, path := range []string{
		filepath.Join("deploy", "quadlet"),
		filepath.Join("sensor-agent"),
		filepath.Join("sensorctl"),
	} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{
		filepath.Join("sensor-agent", "go.mod"),
		filepath.Join("sensorctl", "go.mod"),
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte("module test\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if !isRepoRoot(dir) {
		t.Fatal("directory with deployment tree and both Go modules should be repo root")
	}
}

func TestRepoRootWalksUpFromNestedDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{
		filepath.Join("deploy", "quadlet"),
		filepath.Join("sensor-agent"),
		filepath.Join("sensorctl"),
		filepath.Join("sensorctl", "cmd"),
	} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{
		filepath.Join("sensor-agent", "go.mod"),
		filepath.Join("sensorctl", "go.mod"),
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte("module test\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Chdir(filepath.Join(dir, "sensorctl", "cmd")); err != nil {
		t.Fatal(err)
	}

	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	got, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("repoRoot() = %q, want %q", root, dir)
	}
}

func TestEnvOrAndShellQuote(t *testing.T) {
	t.Setenv("RAVENWIRE_TEST_VALUE", "configured")
	if got := envOr("RAVENWIRE_TEST_VALUE", "fallback"); got != "configured" {
		t.Fatalf("envOr configured = %q", got)
	}
	t.Setenv("RAVENWIRE_EMPTY_VALUE", "")
	if got := envOr("RAVENWIRE_EMPTY_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envOr fallback = %q", got)
	}

	if got, want := shellQuote("it's here"), `'it'"'"'s here'`; got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}
