package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollCmd_RequiresManagerFlag(t *testing.T) {
	root := Root()
	root.SetArgs([]string{"enroll", "--token", "abc123"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --manager is missing")
	}
}

func TestEnrollCmd_RequiresTokenFlag(t *testing.T) {
	root := Root()
	root.SetArgs([]string{"enroll", "--manager", "http://localhost:4000"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --token is missing")
	}
}

func TestRunEnroll_ImmediateApproval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req["token"] != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem":      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			"ca_chain_pem":  "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
			"sensor_pod_id": "pod-001",
		})
	}))
	defer server.Close()

	certDir := t.TempDir()
	err := runEnroll(server.URL, "test-token", "test-pod", certDir, "")
	if err != nil {
		t.Fatalf("runEnroll failed: %v", err)
	}

	// Verify cert files were written
	for _, name := range []string{"sensor.key", "sensor.crt", "ca-chain.pem"} {
		path := filepath.Join(certDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}

	// Verify key file permissions
	info, err := os.Stat(filepath.Join(certDir, "sensor.key"))
	if err != nil {
		t.Fatalf("stat sensor.key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("sensor.key permissions: expected 0600, got %04o", perm)
	}
}

func TestRunEnroll_PendingApproval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}))
	defer server.Close()

	certDir := t.TempDir()
	err := runEnroll(server.URL, "test-token", "test-pod", certDir, "")
	if err != nil {
		t.Fatalf("runEnroll failed: %v", err)
	}

	// No cert files should be written for pending enrollment
	for _, name := range []string{"sensor.crt", "ca-chain.pem"} {
		path := filepath.Join(certDir, name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("expected %s to NOT exist for pending enrollment", name)
		}
	}
}

func TestRunEnroll_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	certDir := t.TempDir()
	err := runEnroll(server.URL, "test-token", "test-pod", certDir, "")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestRunEnroll_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid token"))
	}))
	defer server.Close()

	certDir := t.TempDir()
	err := runEnroll(server.URL, "bad-token", "test-pod", certDir, "")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestManagerAPIBase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://manager:8443", "https://manager:8443/api/v1"},
		{"https://manager:8443/", "https://manager:8443/api/v1"},
		{"http://127.0.0.1:4000/api/v1", "http://127.0.0.1:4000/api/v1"},
		{"http://127.0.0.1:4000/api/v1/", "http://127.0.0.1:4000/api/v1"},
	}

	for _, tt := range tests {
		got := managerAPIBase(tt.input)
		if got != tt.expected {
			t.Errorf("managerAPIBase(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestFormatStateName(t *testing.T) {
	tests := []struct {
		state    string
		contains string
	}{
		{bsInstalled, "installed"},
		{bsEnrolling, "enrolling"},
		{bsPendingApproval, "pending_approval"},
		{bsConfigReceived, "config_received"},
		{bsConfigValidated, "config_validated"},
		{bsCaptureActive, "capture_active"},
		{"unknown_state", "unknown_state"},
	}

	for _, tt := range tests {
		got := formatStateName(tt.state)
		if got == "" {
			t.Errorf("formatStateName(%q) returned empty string", tt.state)
		}
		// The formatted name should contain the raw state name
		if !containsSubstring(got, tt.contains) {
			t.Errorf("formatStateName(%q) = %q, expected to contain %q", tt.state, got, tt.contains)
		}
	}
}

func TestBootstrapStateOrder_AllStatesPresent(t *testing.T) {
	expected := []string{
		bsInstalled,
		bsEnrolling,
		bsPendingApproval,
		bsConfigReceived,
		bsConfigValidated,
		bsCaptureActive,
	}

	if len(bootstrapStateOrder) != len(expected) {
		t.Fatalf("expected %d states, got %d", len(expected), len(bootstrapStateOrder))
	}

	for i, s := range expected {
		if bootstrapStateOrder[i] != s {
			t.Errorf("bootstrapStateOrder[%d]: expected %q, got %q", i, s, bootstrapStateOrder[i])
		}
	}
}

func TestFetchBootstrapStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bootstrap/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bootstrapStatus{
			State:          bsCaptureActive,
			BlockingErrors: nil,
			PodName:        "sensor-pod-01",
		})
	}))
	defer server.Close()

	// Clear env vars that might interfere with the test
	origCert := os.Getenv("SENSORCTL_CERT")
	origKey := os.Getenv("SENSORCTL_KEY")
	origCA := os.Getenv("SENSORCTL_CA")
	os.Setenv("SENSORCTL_CERT", "")
	os.Setenv("SENSORCTL_KEY", "")
	os.Setenv("SENSORCTL_CA", "")
	defer func() {
		os.Setenv("SENSORCTL_CERT", origCert)
		os.Setenv("SENSORCTL_KEY", origKey)
		os.Setenv("SENSORCTL_CA", origCA)
	}()

	status, err := fetchBootstrapStatus(server.URL)
	if err != nil {
		t.Fatalf("fetchBootstrapStatus failed: %v", err)
	}

	if status.State != bsCaptureActive {
		t.Errorf("expected state %q, got %q", bsCaptureActive, status.State)
	}
	if status.PodName != "sensor-pod-01" {
		t.Errorf("expected pod name %q, got %q", "sensor-pod-01", status.PodName)
	}
	if len(status.BlockingErrors) != 0 {
		t.Errorf("expected no blocking errors, got %v", status.BlockingErrors)
	}
}

func TestFetchBootstrapStatus_WithBlockingErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bootstrap/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bootstrapStatus{
			State: bsConfigValidated,
			BlockingErrors: []string{
				"GRO is enabled on eth0 (must be disabled)",
				"Clock offset 150ms exceeds 10ms threshold",
			},
			PodName: "sensor-pod-02",
		})
	}))
	defer server.Close()

	origCert := os.Getenv("SENSORCTL_CERT")
	origKey := os.Getenv("SENSORCTL_KEY")
	origCA := os.Getenv("SENSORCTL_CA")
	os.Setenv("SENSORCTL_CERT", "")
	os.Setenv("SENSORCTL_KEY", "")
	os.Setenv("SENSORCTL_CA", "")
	defer func() {
		os.Setenv("SENSORCTL_CERT", origCert)
		os.Setenv("SENSORCTL_KEY", origKey)
		os.Setenv("SENSORCTL_CA", origCA)
	}()

	status, err := fetchBootstrapStatus(server.URL)
	if err != nil {
		t.Fatalf("fetchBootstrapStatus failed: %v", err)
	}

	if status.State != bsConfigValidated {
		t.Errorf("expected state %q, got %q", bsConfigValidated, status.State)
	}
	if len(status.BlockingErrors) != 2 {
		t.Errorf("expected 2 blocking errors, got %d", len(status.BlockingErrors))
	}
}

func TestFetchBootstrapStatus_ServerDown(t *testing.T) {
	// Use a URL that won't connect
	_, err := fetchBootstrapStatus("http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

func TestShowLocalEnrollmentState_NoCerts(t *testing.T) {
	// Set CERT_DIR to a temp dir with no certs
	tmpDir := t.TempDir()
	origCertDir := os.Getenv("CERT_DIR")
	os.Setenv("CERT_DIR", tmpDir)
	defer os.Setenv("CERT_DIR", origCertDir)

	// Should not error — just prints state info
	err := showLocalEnrollmentState()
	if err != nil {
		t.Fatalf("showLocalEnrollmentState failed: %v", err)
	}
}

func TestShowLocalEnrollmentState_WithCerts(t *testing.T) {
	tmpDir := t.TempDir()
	origCertDir := os.Getenv("CERT_DIR")
	os.Setenv("CERT_DIR", tmpDir)
	defer os.Setenv("CERT_DIR", origCertDir)

	// Create cert files
	for _, name := range []string{"sensor.crt", "sensor.key", "ca-chain.pem"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("test"), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	err := showLocalEnrollmentState()
	if err != nil {
		t.Fatalf("showLocalEnrollmentState failed: %v", err)
	}
}

func TestExistsLabel(t *testing.T) {
	if got := existsLabel(true); got != "present" {
		t.Errorf("existsLabel(true) = %q, want %q", got, "present")
	}
	if got := existsLabel(false); got != "missing" {
		t.Errorf("existsLabel(false) = %q, want %q", got, "missing")
	}
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
