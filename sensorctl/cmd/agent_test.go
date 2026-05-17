package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentCommandRegistersExpectedSubcommands(t *testing.T) {
	cmd := agentCmd()
	for _, name := range []string{"status", "show-drops", "collect-support-bundle"} {
		if found, _, err := cmd.Find([]string{name}); err != nil || found == nil || found.Name() != name {
			t.Fatalf("agent command missing %q: found=%v err=%v", name, found, err)
		}
	}
}

func TestLoadAgentConfigPrefersEnvironmentOverConfigFile(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".sensorctl"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".sensorctl", "config.yaml"), []byte(`
cert: file-cert.pem
key: file-key.pem
ca: file-ca.pem
sensor_url: https://file-sensor:9091
`), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)
	t.Setenv("SENSORCTL_CERT", "env-cert.pem")
	t.Setenv("SENSORCTL_KEY", "env-key.pem")
	t.Setenv("SENSORCTL_CA", "env-ca.pem")
	t.Setenv("SENSORCTL_SENSOR_URL", "https://env-sensor:9091")

	cfg := loadAgentConfig()
	if cfg.CertFile != "env-cert.pem" || cfg.KeyFile != "env-key.pem" ||
		cfg.CAFile != "env-ca.pem" || cfg.SensorURL != "https://env-sensor:9091" {
		t.Fatalf("loadAgentConfig() = %#v, want environment values", cfg)
	}
}

func TestLoadAgentConfigFileReadsSimpleYamlLikeKeys(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".sensorctl"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".sensorctl", "config.yaml"), []byte(`
# comments and blank lines are ignored
cert: /cert.pem
key: /key.pem
ca: /ca.pem
sensor_url: https://sensor.example:9091
ignored line without separator
`), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)

	cfg := loadAgentConfigFile()
	if cfg["cert"] != "/cert.pem" || cfg["key"] != "/key.pem" ||
		cfg["ca"] != "/ca.pem" || cfg["sensor_url"] != "https://sensor.example:9091" {
		t.Fatalf("loadAgentConfigFile() = %#v", cfg)
	}
	if _, ok := cfg["ignored line without separator"]; ok {
		t.Fatalf("loadAgentConfigFile() should ignore malformed lines: %#v", cfg)
	}
}

func TestFetchAgentHealthUsesConfiguredSensorURL(t *testing.T) {
	report := agentHealthReport{
		SensorPodID:     "sensor-01",
		TimestampUnixMs: 1_700_000_000_000,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("content-type", "application/json")
		if err := json.NewEncoder(w).Encode(report); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	t.Setenv("SENSORCTL_SENSOR_URL", server.URL)
	t.Setenv("SENSORCTL_CERT", "")
	t.Setenv("SENSORCTL_KEY", "")
	t.Setenv("SENSORCTL_CA", "")

	got, err := fetchAgentHealth("")
	if err != nil {
		t.Fatalf("fetchAgentHealth: %v", err)
	}
	if got.SensorPodID != report.SensorPodID || got.TimestampUnixMs != report.TimestampUnixMs {
		t.Fatalf("fetchAgentHealth() = %#v, want %#v", got, report)
	}
}

func TestFetchAgentHealthRequiresSensorURL(t *testing.T) {
	t.Setenv("SENSORCTL_SENSOR_URL", "")
	t.Setenv("SENSORCTL_CERT", "")
	t.Setenv("SENSORCTL_KEY", "")
	t.Setenv("SENSORCTL_CA", "")

	if _, err := fetchAgentHealth(""); err == nil {
		t.Fatal("fetchAgentHealth should require a sensor URL")
	}
}

func TestFormatAgentBytes(t *testing.T) {
	tests := map[uint64]string{
		0:          "0B",
		1023:       "1023B",
		1024:       "1.0KiB",
		1048576:    "1.0MiB",
		1073741824: "1.0GiB",
	}

	for input, want := range tests {
		if got := formatAgentBytes(input); got != want {
			t.Fatalf("formatAgentBytes(%d) = %q, want %q", input, got, want)
		}
	}
}
