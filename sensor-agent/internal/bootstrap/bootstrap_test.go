package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

// stubValidator implements ConfigValidator for testing.
type stubValidator struct {
	errors []string
	calls  int
}

func (v *stubValidator) ValidateBundle(configJSON string) []string {
	v.calls++
	return v.errors
}

// stubReadiness implements ReadinessChecker for testing.
type stubReadiness struct {
	passed   bool
	failures []string
}

func (r *stubReadiness) CheckHardFailures() (bool, []string) {
	return r.passed, r.failures
}

// stubWriter implements ConfigWriter for testing.
type stubWriter struct {
	called bool
	bundle ConfigBundle
	err    error
}

func (w *stubWriter) WriteConfigAndStartCapture(bundle ConfigBundle) error {
	w.called = true
	w.bundle = bundle
	return w.err
}

// stubReporter implements HealthReporter for testing.
type stubReporter struct {
	mu     sync.Mutex
	errors [][]string
	states []State
}

func (r *stubReporter) ReportError(state State, errors []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, state)
	r.errors = append(r.errors, errors)
}

// noSleep is a sleep function that doesn't actually sleep (for fast tests).
func noSleep(d time.Duration) {}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestNewMachine_StartsInInstalledState(t *testing.T) {
	m := NewMachine(Config{})
	if m.State() != StateInstalled {
		t.Errorf("expected state %q, got %q", StateInstalled, m.State())
	}
}

func TestTransition_ForwardOnly(t *testing.T) {
	m := NewMachine(Config{})

	// Forward transition should work
	if err := m.transition(StateEnrolling); err != nil {
		t.Fatalf("forward transition failed: %v", err)
	}
	if m.State() != StateEnrolling {
		t.Errorf("expected state %q, got %q", StateEnrolling, m.State())
	}

	// Same-state transition should work (retry loop)
	if err := m.transition(StateEnrolling); err != nil {
		t.Fatalf("same-state transition failed: %v", err)
	}

	// Backward transition should fail
	if err := m.transition(StateInstalled); err == nil {
		t.Error("expected error for backward transition, got nil")
	}

	// Skip transition should fail
	if err := m.transition(StateConfigReceived); err == nil {
		t.Error("expected error for skip transition, got nil")
	}
}

func TestTransition_LogsStateChange(t *testing.T) {
	m := NewMachine(Config{})

	if err := m.transition(StateEnrolling); err != nil {
		t.Fatalf("transition failed: %v", err)
	}
	if m.State() != StateEnrolling {
		t.Errorf("expected %q, got %q", StateEnrolling, m.State())
	}
}

func TestRun_ImmediateApproval(t *testing.T) {
	// Set up a mock Config_Manager that immediately approves enrollment.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enroll":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(EnrollmentResponse{
				Status:     "approved",
				CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				CAChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
				ConfigJSON: `{"severity_threshold": 2}`,
				PodID:      "pod-001",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	certDir := t.TempDir()
	writer := &stubWriter{}

	m := NewMachine(Config{
		ConfigManagerURL: server.URL,
		EnrollmentToken:  "test-token",
		PodName:          "test-pod",
		CertDir:          certDir,
		Validator:        &stubValidator{errors: nil},
		Readiness:        &stubReadiness{passed: true},
		Writer:           writer,
		Sleep:            noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if m.State() != StateCaptureActive {
		t.Errorf("expected state %q, got %q", StateCaptureActive, m.State())
	}

	if !writer.called {
		t.Error("expected config writer to be called")
	}

	// Verify certs were written
	if _, err := os.Stat(certDir + "/sensor.crt"); err != nil {
		t.Errorf("expected sensor.crt to exist: %v", err)
	}
	if _, err := os.Stat(certDir + "/sensor.key"); err != nil {
		t.Errorf("expected sensor.key to exist: %v", err)
	}
	if _, err := os.Stat(certDir + "/ca-chain.pem"); err != nil {
		t.Errorf("expected ca-chain.pem to exist: %v", err)
	}
}

func TestRun_PendingApproval(t *testing.T) {
	// First call returns 202 (pending), second call to /enroll/status returns 200.
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enroll":
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
		case "/enroll/status":
			callCount++
			if callCount >= 2 {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(EnrollmentResponse{
					Status:     "approved",
					CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					CAChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
					ConfigJSON: `{"severity_threshold": 2}`,
					PodID:      "pod-002",
				})
			} else {
				w.WriteHeader(http.StatusAccepted)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	m := NewMachine(Config{
		ConfigManagerURL: server.URL,
		EnrollmentToken:  "test-token",
		PodName:          "test-pod",
		CertDir:          t.TempDir(),
		Validator:        &stubValidator{errors: nil},
		Readiness:        &stubReadiness{passed: true},
		Writer:           &stubWriter{},
		Sleep:            noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if m.State() != StateCaptureActive {
		t.Errorf("expected state %q, got %q", StateCaptureActive, m.State())
	}
}

func TestRun_EnrollmentRetryWithBackoff(t *testing.T) {
	// Track retry intervals to verify exponential backoff.
	var mu sync.Mutex
	var sleepDurations []time.Duration

	failCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enroll":
			failCount++
			if failCount <= 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(EnrollmentResponse{
				Status:     "approved",
				CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				ConfigJSON: `{}`,
				PodID:      "pod-003",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	m := NewMachine(Config{
		ConfigManagerURL:     server.URL,
		EnrollmentToken:      "test-token",
		PodName:              "test-pod",
		CertDir:              t.TempDir(),
		EnrollInitialBackoff: 5 * time.Second,
		EnrollMaxBackoff:     60 * time.Second,
		Validator:            &stubValidator{errors: nil},
		Readiness:            &stubReadiness{passed: true},
		Writer:               &stubWriter{},
		Sleep: func(d time.Duration) {
			mu.Lock()
			sleepDurations = append(sleepDurations, d)
			mu.Unlock()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// We expect 3 retries before success: 5s, 10s, 20s
	if len(sleepDurations) < 3 {
		t.Fatalf("expected at least 3 sleep calls, got %d", len(sleepDurations))
	}

	// Verify exponential backoff: 5s, 10s, 20s
	expected := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
	for i, exp := range expected {
		if i >= len(sleepDurations) {
			break
		}
		if sleepDurations[i] != exp {
			t.Errorf("sleep[%d]: expected %s, got %s", i, exp, sleepDurations[i])
		}
	}
}

func TestRun_ConfigValidationFailure(t *testing.T) {
	// Validator fails on first call, succeeds on second.
	validator := &stubValidator{}
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			Status:     "approved",
			CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ConfigJSON: `{"severity_threshold": 2}`,
			PodID:      "pod-004",
		})
	}))
	defer server.Close()

	reporter := &stubReporter{}

	// Custom validator that fails first, then succeeds
	customValidator := &dynamicValidator{
		fn: func(configJSON string) []string {
			callCount++
			if callCount <= 1 {
				return []string{"invalid BPF filter", "missing sink config"}
			}
			return nil
		},
	}
	_ = validator // unused, using customValidator instead

	m := NewMachine(Config{
		ConfigManagerURL: server.URL,
		EnrollmentToken:  "test-token",
		PodName:          "test-pod",
		CertDir:          t.TempDir(),
		Validator:        customValidator,
		Readiness:        &stubReadiness{passed: true},
		Writer:           &stubWriter{},
		Reporter:         reporter,
		Sleep:            noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if m.State() != StateCaptureActive {
		t.Errorf("expected state %q, got %q", StateCaptureActive, m.State())
	}

	// Verify errors were reported to Config_Manager
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.errors) == 0 {
		t.Error("expected validation errors to be reported")
	}
}

func TestRun_ReadinessCheckFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			Status:     "approved",
			CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ConfigJSON: `{}`,
			PodID:      "pod-005",
		})
	}))
	defer server.Close()

	certDir := t.TempDir()
	m := NewMachine(Config{
		ConfigManagerURL: server.URL,
		EnrollmentToken:  "test-token",
		PodName:          "test-pod",
		CertDir:          certDir,
		Validator:        &stubValidator{errors: nil},
		Readiness:        &stubReadiness{passed: false, failures: []string{"GRO enabled", "clock unsynchronized"}},
		Writer:           &stubWriter{},
		Sleep:            noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Run(ctx)
	if err == nil {
		t.Fatal("expected error from readiness check failure, got nil")
	}

	// Machine should be stuck at config_validated (readiness failed)
	if m.State() != StateConfigValidated {
		t.Errorf("expected state %q, got %q", StateConfigValidated, m.State())
	}
	if _, statErr := os.Stat(filepath.Join(certDir, "sensor.crt")); statErr != nil {
		t.Fatalf("expected enrolled cert to be written before readiness failure: %v", statErr)
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	// Server that never approves
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	m := NewMachine(Config{
		ConfigManagerURL:     server.URL,
		EnrollmentToken:      "test-token",
		PodName:              "test-pod",
		CertDir:              t.TempDir(),
		EnrollInitialBackoff: time.Millisecond,
		EnrollMaxBackoff:     time.Millisecond,
		Sleep:                noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := m.Run(ctx)
	if err == nil {
		t.Fatal("expected error from context cancellation, got nil")
	}
}

func TestRun_NoValidatorSkipsValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			Status:     "approved",
			CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ConfigJSON: `{}`,
			PodID:      "pod-006",
		})
	}))
	defer server.Close()

	m := NewMachine(Config{
		ConfigManagerURL: server.URL,
		EnrollmentToken:  "test-token",
		PodName:          "test-pod",
		CertDir:          t.TempDir(),
		Validator:        nil, // no validator
		Readiness:        &stubReadiness{passed: true},
		Writer:           &stubWriter{},
		Sleep:            noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if m.State() != StateCaptureActive {
		t.Errorf("expected state %q, got %q", StateCaptureActive, m.State())
	}
}

func TestRun_WriterFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			Status:     "approved",
			CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ConfigJSON: `{}`,
			PodID:      "pod-007",
		})
	}))
	defer server.Close()

	m := NewMachine(Config{
		ConfigManagerURL: server.URL,
		EnrollmentToken:  "test-token",
		PodName:          "test-pod",
		CertDir:          t.TempDir(),
		Validator:        &stubValidator{errors: nil},
		Readiness:        &stubReadiness{passed: true},
		Writer:           &stubWriter{err: fmt.Errorf("disk full")},
		Sleep:            noSleep,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.Run(ctx)
	if err == nil {
		t.Fatal("expected error from writer failure, got nil")
	}
}

func TestStateOrder_AllStatesPresent(t *testing.T) {
	expected := []State{
		StateInstalled,
		StateEnrolling,
		StatePendingApproval,
		StateConfigReceived,
		StateConfigValidated,
		StateCaptureActive,
	}

	if len(stateOrder) != len(expected) {
		t.Fatalf("expected %d states, got %d", len(expected), len(stateOrder))
	}

	for i, s := range expected {
		if stateOrder[i] != s {
			t.Errorf("stateOrder[%d]: expected %q, got %q", i, s, stateOrder[i])
		}
	}
}

func TestEnrollmentBackoff_CapsAt60s(t *testing.T) {
	var mu sync.Mutex
	var sleepDurations []time.Duration
	failCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		if failCount <= 10 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(EnrollmentResponse{
			Status:     "approved",
			CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			ConfigJSON: `{}`,
			PodID:      "pod-cap",
		})
	}))
	defer server.Close()

	m := NewMachine(Config{
		ConfigManagerURL:     server.URL,
		EnrollmentToken:      "test-token",
		PodName:              "test-pod",
		CertDir:              t.TempDir(),
		EnrollInitialBackoff: 5 * time.Second,
		EnrollMaxBackoff:     60 * time.Second,
		Validator:            &stubValidator{errors: nil},
		Readiness:            &stubReadiness{passed: true},
		Writer:               &stubWriter{},
		Sleep: func(d time.Duration) {
			mu.Lock()
			sleepDurations = append(sleepDurations, d)
			mu.Unlock()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify no sleep exceeds 60s
	for i, d := range sleepDurations {
		if d > 60*time.Second {
			t.Errorf("sleep[%d] = %s exceeds max backoff of 60s", i, d)
		}
	}

	// Verify the backoff sequence: 5, 10, 20, 40, 60, 60, 60, 60, 60, 60
	expectedBackoffs := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		60 * time.Second, // capped
		60 * time.Second,
		60 * time.Second,
		60 * time.Second,
		60 * time.Second,
		60 * time.Second,
	}
	for i, exp := range expectedBackoffs {
		if i >= len(sleepDurations) {
			break
		}
		if sleepDurations[i] != exp {
			t.Errorf("sleep[%d]: expected %s, got %s", i, exp, sleepDurations[i])
		}
	}
}

// dynamicValidator is a ConfigValidator with a configurable function.
type dynamicValidator struct {
	fn func(configJSON string) []string
}

func (v *dynamicValidator) ValidateBundle(configJSON string) []string {
	return v.fn(configJSON)
}
