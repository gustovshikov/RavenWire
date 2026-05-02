package pcap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/podman"
)

// ── SwitchMode unit tests ─────────────────────────────────────────────────────

// mockPodmanServer creates a test HTTP server that simulates the Podman REST API
// for start/stop/inspect operations. It tracks container states internally.
type mockPodmanServer struct {
	mu     sync.Mutex
	states map[string]string // container name → state ("running", "exited")
	srv    *httptest.Server
}

func newMockPodmanServer(initialStates map[string]string) *mockPodmanServer {
	m := &mockPodmanServer{
		states: make(map[string]string),
	}
	for k, v := range initialStates {
		m.states[k] = v
	}

	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		path := r.URL.Path
		parts := strings.Split(strings.Trim(path, "/"), "/")

		// Expected paths:
		// /v4.0.0/containers/{name}/start
		// /v4.0.0/containers/{name}/stop
		// /v4.0.0/containers/{name}/json (inspect)
		if len(parts) < 4 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		containerName := parts[2]
		action := parts[3]

		switch action {
		case "start":
			m.states[containerName] = "running"
			w.WriteHeader(http.StatusNoContent)
		case "stop":
			m.states[containerName] = "exited"
			w.WriteHeader(http.StatusNoContent)
		case "json":
			state, ok := m.states[containerName]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"State": map[string]any{
					"Status": state,
					"Error":  "",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	return m
}

func (m *mockPodmanServer) close() {
	m.srv.Close()
}

func (m *mockPodmanServer) getState(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[name]
}

// podmanClientWithTestServer creates a podman.Client that routes requests to
// the given test server, with the specified allowlist.
func podmanClientWithTestServer(srv *httptest.Server, allowlist map[string]string) *podman.Client {
	transport := &rewriteTransport{
		base:    srv.Client().Transport,
		baseURL: srv.URL,
	}
	cfg := podman.Config{
		SocketPath: "/fake/podman.sock",
		Allowlist:  allowlist,
		Timeout:    10 * time.Second,
	}
	c := podman.NewForTest(cfg, &http.Client{Transport: transport})
	return c
}

// rewriteTransport rewrites the scheme+host of every request to a fixed base URL.
type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := strings.TrimRight(t.baseURL, "/")
	newURL := base + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return t.base.RoundTrip(newReq)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestSwitchMode_FullPcap verifies that switching to full_pcap starts netsniff-ng
// and stops pcap_ring_writer (Requirements 13.1, 13.2).
func TestSwitchMode_FullPcap(t *testing.T) {
	mock := newMockPodmanServer(map[string]string{
		"netsniff-ng":      "exited",
		"pcap_ring_writer": "running",
	})
	defer mock.close()

	allowlist := map[string]string{
		"netsniff-ng":      "",
		"pcap_ring_writer": "",
	}
	pc := podmanClientWithTestServer(mock.srv, allowlist)

	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{
		PodmanClient:      pc,
		ModeSwitchTimeout: 5 * time.Second,
		PCAPStoragePath:   dir,
		StorageMinFreePct: 1.0, // very low threshold so test passes
	})

	if err := m.SwitchMode("full_pcap"); err != nil {
		t.Fatalf("SwitchMode(full_pcap): %v", err)
	}

	// Verify container states.
	if mock.getState("netsniff-ng") != "running" {
		t.Errorf("expected netsniff-ng running, got %s", mock.getState("netsniff-ng"))
	}
	if mock.getState("pcap_ring_writer") != "exited" {
		t.Errorf("expected pcap_ring_writer exited, got %s", mock.getState("pcap_ring_writer"))
	}

	// Verify mode status.
	status := m.ModeStatus()
	if status.ActiveMode != "full_pcap" {
		t.Errorf("expected active mode full_pcap, got %s", status.ActiveMode)
	}
	if status.ContainerStates["netsniff-ng"] != "running" {
		t.Errorf("expected netsniff-ng state running in health, got %s", status.ContainerStates["netsniff-ng"])
	}
	if status.ContainerStates["pcap_ring_writer"] != "stopped" {
		t.Errorf("expected pcap_ring_writer state stopped in health, got %s", status.ContainerStates["pcap_ring_writer"])
	}
}

// TestSwitchMode_AlertDriven verifies that switching to alert_driven stops
// netsniff-ng and starts pcap_ring_writer (Requirement 13.3).
func TestSwitchMode_AlertDriven(t *testing.T) {
	mock := newMockPodmanServer(map[string]string{
		"netsniff-ng":      "running",
		"pcap_ring_writer": "exited",
	})
	defer mock.close()

	allowlist := map[string]string{
		"netsniff-ng":      "",
		"pcap_ring_writer": "",
	}
	pc := podmanClientWithTestServer(mock.srv, allowlist)

	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{
		PodmanClient:      pc,
		ModeSwitchTimeout: 5 * time.Second,
		PCAPStoragePath:   dir,
	})
	// Start in full_pcap mode.
	m.mode = "full_pcap"

	if err := m.SwitchMode("alert_driven"); err != nil {
		t.Fatalf("SwitchMode(alert_driven): %v", err)
	}

	// Verify container states.
	if mock.getState("netsniff-ng") != "exited" {
		t.Errorf("expected netsniff-ng exited, got %s", mock.getState("netsniff-ng"))
	}
	if mock.getState("pcap_ring_writer") != "running" {
		t.Errorf("expected pcap_ring_writer running, got %s", mock.getState("pcap_ring_writer"))
	}

	// Verify mode status.
	status := m.ModeStatus()
	if status.ActiveMode != "alert_driven" {
		t.Errorf("expected active mode alert_driven, got %s", status.ActiveMode)
	}
}

// TestSwitchMode_InvalidMode verifies that an invalid mode is rejected.
func TestSwitchMode_InvalidMode(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{})

	if err := m.SwitchMode("invalid"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

// TestSwitchMode_NoPodmanClient verifies that switching mode without a Podman
// client returns an error.
func TestSwitchMode_NoPodmanClient(t *testing.T) {
	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{})

	if err := m.SwitchMode("full_pcap"); err == nil {
		t.Fatal("expected error when podman client is nil")
	}
}

// TestSwitchMode_InsufficientStorage verifies that switching to full_pcap is
// rejected when storage is below the low-water mark (Requirement 13.6).
func TestSwitchMode_InsufficientStorage(t *testing.T) {
	mock := newMockPodmanServer(map[string]string{
		"netsniff-ng":      "exited",
		"pcap_ring_writer": "running",
	})
	defer mock.close()

	allowlist := map[string]string{
		"netsniff-ng":      "",
		"pcap_ring_writer": "",
	}
	pc := podmanClientWithTestServer(mock.srv, allowlist)

	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{
		PodmanClient:      pc,
		ModeSwitchTimeout: 5 * time.Second,
		PCAPStoragePath:   dir,
		StorageMinFreePct: 99.99, // impossibly high threshold
	})

	err = m.SwitchMode("full_pcap")
	if err == nil {
		t.Fatal("expected error for insufficient storage")
	}
	if !strings.Contains(err.Error(), "insufficient free storage") {
		t.Errorf("expected storage error, got: %v", err)
	}
}

// TestSwitchMode_RollbackOnFailure verifies that on failure, the previous mode's
// container states are restored (Requirement 13.4).
func TestSwitchMode_RollbackOnFailure(t *testing.T) {
	// Create a server that fails the start of netsniff-ng.
	failStart := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) < 4 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		containerName := parts[2]
		action := parts[3]

		switch action {
		case "start":
			if containerName == "netsniff-ng" && failStart {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "stop":
			w.WriteHeader(http.StatusNoContent)
		case "json":
			// After rollback, pcap_ring_writer should be running (alert_driven mode).
			state := "exited"
			if containerName == "pcap_ring_writer" {
				state = "running"
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"State": map[string]any{"Status": state, "Error": ""},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	allowlist := map[string]string{
		"netsniff-ng":      "",
		"pcap_ring_writer": "",
	}
	pc := podmanClientWithTestServer(srv, allowlist)

	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	var healthMsg string
	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{
		PodmanClient:      pc,
		ModeSwitchTimeout: 2 * time.Second,
		PCAPStoragePath:   dir,
		StorageMinFreePct: 1.0,
		HealthReporter: func(msg string) {
			healthMsg = msg
		},
	})

	// Start in alert_driven mode.
	m.mode = "alert_driven"

	err = m.SwitchMode("full_pcap")
	if err == nil {
		t.Fatal("expected error when netsniff-ng start fails")
	}

	// Verify health reporter was called (Requirement 13.4).
	if healthMsg == "" {
		t.Error("expected health reporter to be called on failure")
	}
	if !strings.Contains(healthMsg, "full_pcap") {
		t.Errorf("expected health message to mention full_pcap, got: %s", healthMsg)
	}

	// Mode should remain alert_driven since the switch failed.
	if m.mode != "alert_driven" {
		t.Errorf("expected mode to remain alert_driven after failure, got %s", m.mode)
	}
}

// TestSwitchMode_ModeStatusExposure verifies that ModeStatus returns the
// current mode and container states (Requirement 13.5).
func TestSwitchMode_ModeStatusExposure(t *testing.T) {
	mock := newMockPodmanServer(map[string]string{
		"netsniff-ng":      "exited",
		"pcap_ring_writer": "running",
	})
	defer mock.close()

	allowlist := map[string]string{
		"netsniff-ng":      "",
		"pcap_ring_writer": "",
	}
	pc := podmanClientWithTestServer(mock.srv, allowlist)

	dir := t.TempDir()
	idx, err := OpenIndex(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	m := NewManagerWithConfig("", dir, idx, nil, ManagerConfig{
		PodmanClient:      pc,
		ModeSwitchTimeout: 5 * time.Second,
		PCAPStoragePath:   dir,
		StorageMinFreePct: 1.0,
	})

	// Initial state.
	status := m.ModeStatus()
	if status.ActiveMode != "alert_driven" {
		t.Errorf("expected initial mode alert_driven, got %s", status.ActiveMode)
	}

	// Switch to full_pcap.
	if err := m.SwitchMode("full_pcap"); err != nil {
		t.Fatalf("SwitchMode: %v", err)
	}

	status = m.ModeStatus()
	if status.ActiveMode != "full_pcap" {
		t.Errorf("expected mode full_pcap, got %s", status.ActiveMode)
	}
	if len(status.ContainerStates) != 2 {
		t.Errorf("expected 2 container states, got %d", len(status.ContainerStates))
	}

	// Switch back to alert_driven.
	if err := m.SwitchMode("alert_driven"); err != nil {
		t.Fatalf("SwitchMode: %v", err)
	}

	status = m.ModeStatus()
	if status.ActiveMode != "alert_driven" {
		t.Errorf("expected mode alert_driven, got %s", status.ActiveMode)
	}
	if status.ContainerStates["netsniff-ng"] != "stopped" {
		t.Errorf("expected netsniff-ng stopped, got %s", status.ContainerStates["netsniff-ng"])
	}
	if status.ContainerStates["pcap_ring_writer"] != "running" {
		t.Errorf("expected pcap_ring_writer running, got %s", status.ContainerStates["pcap_ring_writer"])
	}
}
