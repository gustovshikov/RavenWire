package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// stateGen draws a random bootstrap state from the defined state order.
func stateGen() *rapid.Generator[State] {
	return rapid.Custom(func(t *rapid.T) State {
		idx := rapid.IntRange(0, len(stateOrder)-1).Draw(t, "state_index")
		return stateOrder[idx]
	})
}

// TestProperty14_BootstrapStateMachineForwardOnlyTransitions verifies that the
// bootstrap state machine enforces forward-only transitions:
//   - Transitions that advance exactly one step forward always succeed.
//   - Same-state transitions (retry loops for enrolling and config_received) always succeed.
//   - Backward transitions are always rejected.
//   - Transitions that skip one or more states are always rejected.
//
// Property 14: Bootstrap state machine forward-only transitions
// Validates: Requirements 11.1
func TestProperty14_BootstrapStateMachineForwardOnlyTransitions(t *testing.T) {
	t.Run("forward_step_always_succeeds", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Pick any state except the last one (capture_active has no forward step).
			fromIdx := rapid.IntRange(0, len(stateOrder)-2).Draw(t, "from_index")
			from := stateOrder[fromIdx]
			to := stateOrder[fromIdx+1]

			m := &Machine{state: from}
			err := m.transition(to)

			if err != nil {
				t.Fatalf("forward transition %q → %q should succeed, got error: %v", from, to, err)
			}
			if m.state != to {
				t.Fatalf("after forward transition, expected state %q, got %q", to, m.state)
			}
		})
	})

	t.Run("same_state_retry_always_succeeds", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Same-state transitions are used for retry loops. The machine
			// allows them for every state (the design specifically uses them
			// for enrolling and config_received, but the implementation
			// permits same-state for any state since toIdx == fromIdx is not < fromIdx).
			state := stateGen().Draw(t, "state")

			m := &Machine{state: state}
			err := m.transition(state)

			if err != nil {
				t.Fatalf("same-state transition %q → %q should succeed (retry loop), got error: %v", state, state, err)
			}
			if m.state != state {
				t.Fatalf("after same-state transition, expected state %q, got %q", state, m.state)
			}
		})
	})

	t.Run("backward_transition_always_rejected", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Pick a from state that is not the first (installed has no backward target).
			fromIdx := rapid.IntRange(1, len(stateOrder)-1).Draw(t, "from_index")
			// Pick a target state strictly before the from state.
			toIdx := rapid.IntRange(0, fromIdx-1).Draw(t, "to_index")

			from := stateOrder[fromIdx]
			to := stateOrder[toIdx]

			m := &Machine{state: from}
			originalState := m.state
			err := m.transition(to)

			if err == nil {
				t.Fatalf("backward transition %q → %q should be rejected, but succeeded", from, to)
			}
			// State must remain unchanged after a rejected transition.
			if m.state != originalState {
				t.Fatalf("state mutated after rejected backward transition: expected %q, got %q", originalState, m.state)
			}
		})
	})

	t.Run("skip_transition_always_rejected", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Pick a from state that has at least two states ahead of it.
			fromIdx := rapid.IntRange(0, len(stateOrder)-3).Draw(t, "from_index")
			// Pick a target state that skips at least one state (fromIdx+2 or beyond).
			toIdx := rapid.IntRange(fromIdx+2, len(stateOrder)-1).Draw(t, "to_index")

			from := stateOrder[fromIdx]
			to := stateOrder[toIdx]

			m := &Machine{state: from}
			originalState := m.state
			err := m.transition(to)

			if err == nil {
				t.Fatalf("skip transition %q → %q should be rejected, but succeeded", from, to)
			}
			// State must remain unchanged after a rejected transition.
			if m.state != originalState {
				t.Fatalf("state mutated after rejected skip transition: expected %q, got %q", originalState, m.state)
			}
		})
	})

	t.Run("unknown_state_always_rejected", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			from := stateGen().Draw(t, "from_state")
			unknownState := State("unknown_" + rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "suffix"))

			m := &Machine{state: from}
			originalState := m.state
			err := m.transition(unknownState)

			if err == nil {
				t.Fatalf("transition to unknown state %q should be rejected, but succeeded", unknownState)
			}
			if m.state != originalState {
				t.Fatalf("state mutated after rejected unknown-state transition: expected %q, got %q", originalState, m.state)
			}
		})
	})

	t.Run("full_forward_sequence_succeeds", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Simulate a complete bootstrap sequence with optional retry loops
			// at enrolling and config_received states.
			enrollRetries := rapid.IntRange(0, 5).Draw(t, "enroll_retries")
			configRetries := rapid.IntRange(0, 5).Draw(t, "config_retries")

			m := &Machine{state: StateInstalled}

			// installed → enrolling
			if err := m.transition(StateEnrolling); err != nil {
				t.Fatalf("installed → enrolling failed: %v", err)
			}

			// Retry loops at enrolling
			for i := 0; i < enrollRetries; i++ {
				if err := m.transition(StateEnrolling); err != nil {
					t.Fatalf("enrolling retry %d failed: %v", i, err)
				}
			}

			// enrolling → pending_approval
			if err := m.transition(StatePendingApproval); err != nil {
				t.Fatalf("enrolling → pending_approval failed: %v", err)
			}

			// pending_approval → config_received
			if err := m.transition(StateConfigReceived); err != nil {
				t.Fatalf("pending_approval → config_received failed: %v", err)
			}

			// Retry loops at config_received
			for i := 0; i < configRetries; i++ {
				if err := m.transition(StateConfigReceived); err != nil {
					t.Fatalf("config_received retry %d failed: %v", i, err)
				}
			}

			// config_received → config_validated
			if err := m.transition(StateConfigValidated); err != nil {
				t.Fatalf("config_received → config_validated failed: %v", err)
			}

			// config_validated → capture_active
			if err := m.transition(StateCaptureActive); err != nil {
				t.Fatalf("config_validated → capture_active failed: %v", err)
			}

			if m.state != StateCaptureActive {
				t.Fatalf("expected final state %q, got %q", StateCaptureActive, m.state)
			}
		})
	})
}

// TestProperty15_EnrollmentRetryExponentialBackoff verifies that for any
// sequence of consecutive enrollment failures, the retry intervals follow
// exponential backoff: starting at the configured initial backoff, doubling
// each attempt, and capping at the configured max backoff.
//
// Property 15: Enrollment retry exponential backoff
// **Validates: Requirements 11.2**
func TestProperty15_EnrollmentRetryExponentialBackoff(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random parameters to test the property universally.
		numFailures := rapid.IntRange(1, 15).Draw(t, "num_failures")
		initialBackoffSec := rapid.IntRange(1, 10).Draw(t, "initial_backoff_sec")
		maxBackoffSec := rapid.IntRange(initialBackoffSec*2, 120).Draw(t, "max_backoff_sec")

		initialBackoff := time.Duration(initialBackoffSec) * time.Second
		maxBackoff := time.Duration(maxBackoffSec) * time.Second

		// Track enrollment request count and sleep durations.
		var mu sync.Mutex
		var sleepDurations []time.Duration
		requestCount := 0

		// Set up an HTTP server that returns 500 for the first N requests,
		// then returns 200 with a valid enrollment response.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requestCount++
			current := requestCount
			mu.Unlock()

			if current <= numFailures {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(EnrollmentResponse{
				Status:     "approved",
				CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
				CAChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
				ConfigJSON: `{"severity_threshold": 2}`,
				PodID:      "pod-prop15",
			})
		}))
		defer server.Close()

		certDir, err := os.MkdirTemp("", "prop15-certs-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		defer os.RemoveAll(certDir)

		m := NewMachine(Config{
			ConfigManagerURL:     server.URL,
			EnrollmentToken:      "test-token",
			PodName:              "test-pod",
			CertDir:              certDir,
			EnrollInitialBackoff: initialBackoff,
			EnrollMaxBackoff:     maxBackoff,
			Validator:            &stubValidator{errors: nil},
			Readiness:            &stubReadiness{passed: true},
			Writer:               &stubWriter{},
			Sleep: func(d time.Duration) {
				mu.Lock()
				sleepDurations = append(sleepDurations, d)
				mu.Unlock()
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := m.Run(ctx); err != nil {
			t.Fatalf("Run failed: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()

		// The number of sleep calls must equal the number of failures.
		if len(sleepDurations) != numFailures {
			t.Fatalf("expected %d sleep calls (one per failure), got %d", numFailures, len(sleepDurations))
		}

		// The first sleep must be exactly the initial backoff.
		if sleepDurations[0] != initialBackoff {
			t.Fatalf("first sleep: expected %s, got %s", initialBackoff, sleepDurations[0])
		}

		// Verify each sleep duration matches the exponential backoff formula:
		// sleep[i] = min(initialBackoff * 2^i, maxBackoff)
		for i, got := range sleepDurations {
			expected := time.Duration(math.Min(
				float64(initialBackoff)*(math.Pow(2, float64(i))),
				float64(maxBackoff),
			))
			if got != expected {
				t.Fatalf("sleep[%d]: expected %s, got %s (initial=%s, max=%s)",
					i, expected, got, initialBackoff, maxBackoff)
			}
		}

		// No sleep duration may exceed maxBackoff.
		for i, d := range sleepDurations {
			if d > maxBackoff {
				t.Fatalf("sleep[%d] = %s exceeds max backoff %s", i, d, maxBackoff)
			}
		}

		// Each subsequent sleep is exactly double the previous (until capped).
		for i := 1; i < len(sleepDurations); i++ {
			prev := sleepDurations[i-1]
			curr := sleepDurations[i]
			expectedDouble := time.Duration(math.Min(float64(prev*2), float64(maxBackoff)))
			if curr != expectedDouble {
				t.Fatalf("sleep[%d] = %s, expected double of sleep[%d] = %s (capped at %s)",
					i, curr, i-1, expectedDouble, maxBackoff)
			}
		}
	})
}

// TestProperty16_ConfigValidationBeforeFileWrite verifies that for any config
// bundle received in config_received state:
//   - Rule_Validator and Capture_Manager validation (via ConfigValidator) is
//     always invoked before any config file is written to disk.
//   - If validation fails, no files are written (ConfigWriter is never called).
//   - If validation succeeds, files are written (ConfigWriter is called).
//
// Property 16: Config validation before file write
// Validates: Requirements 11.4
func TestProperty16_ConfigValidationBeforeFileWrite(t *testing.T) {
	t.Run("validation_failure_prevents_file_write", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Generate a random number of validation errors (at least 1).
			numErrors := rapid.IntRange(1, 10).Draw(t, "num_errors")
			var validationErrors []string
			for i := 0; i < numErrors; i++ {
				validationErrors = append(validationErrors,
					rapid.StringMatching(`[a-z_ ]{5,40}`).Draw(t, fmt.Sprintf("error_%d", i)))
			}

			// Generate a random config JSON payload.
			configJSON := rapid.StringMatching(`\{"severity_threshold":\s*[123]\}`).Draw(t, "config_json")

			// Track the order of operations: validation calls and write calls.
			var mu sync.Mutex
			var opLog []string
			validatorCalls := 0
			writerCalls := 0

			validator := &dynamicValidator{
				fn: func(cfg string) []string {
					mu.Lock()
					defer mu.Unlock()
					validatorCalls++
					opLog = append(opLog, "validate")
					// First call fails; if the machine retries, second call succeeds
					// to let the test terminate. But we only care about the first
					// iteration: validation failed → no write.
					if validatorCalls <= 1 {
						return validationErrors
					}
					return nil
				},
			}

			writer := &trackingWriter{
				mu:    &mu,
				opLog: &opLog,
			}

			reporter := &stubReporter{}

			// Set up a server that immediately approves enrollment.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(EnrollmentResponse{
					Status:     "approved",
					CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					CAChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
					ConfigJSON: configJSON,
					PodID:      "pod-prop16",
				})
			}))
			defer server.Close()

			certDir, err := os.MkdirTemp("", "prop16-*")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			defer os.RemoveAll(certDir)

			m := NewMachine(Config{
				ConfigManagerURL: server.URL,
				EnrollmentToken:  "test-token",
				PodName:          "test-pod",
				CertDir:          certDir,
				Validator:        validator,
				Readiness:        &stubReadiness{passed: true},
				Writer:           writer,
				Reporter:         reporter,
				Sleep:            noSleep,
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := m.Run(ctx); err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()

			// The validator must have been called at least once.
			if validatorCalls == 0 {
				t.Fatal("validator was never called — validation must be invoked before any file write")
			}

			// The first operation must always be "validate", never "write".
			if len(opLog) == 0 {
				t.Fatal("no operations recorded")
			}
			if opLog[0] != "validate" {
				t.Fatalf("first operation was %q, expected \"validate\" — validation must precede any file write", opLog[0])
			}

			// After the first validation failure, no write should have occurred
			// before the second validation call.
			firstWriteIdx := -1
			secondValidateIdx := -1
			for i, op := range opLog {
				if op == "write" && firstWriteIdx == -1 {
					firstWriteIdx = i
				}
				if op == "validate" && i > 0 && secondValidateIdx == -1 {
					secondValidateIdx = i
				}
			}

			// If a write occurred, it must be after a successful validation.
			if firstWriteIdx != -1 && firstWriteIdx < secondValidateIdx {
				t.Fatalf("file write (opLog[%d]) occurred before second validation (opLog[%d]) — "+
					"validation failure must prevent file writes", firstWriteIdx, secondValidateIdx)
			}

			// Verify errors were reported to Config_Manager on the first failure.
			reporter.mu.Lock()
			defer reporter.mu.Unlock()
			if len(reporter.errors) == 0 {
				t.Fatal("validation errors were not reported to Config_Manager")
			}
			if len(reporter.errors[0]) != numErrors {
				t.Fatalf("expected %d reported errors, got %d", numErrors, len(reporter.errors[0]))
			}

			// Writer must not have been called before the second (successful) validation.
			if writerCalls > 0 && validatorCalls < 2 {
				t.Fatal("writer was called despite validation never succeeding")
			}
			_ = writerCalls // used via writer.calls
		})
	})

	t.Run("validation_success_allows_file_write", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Generate a random config JSON payload.
			configJSON := rapid.StringMatching(`\{"severity_threshold":\s*[123]\}`).Draw(t, "config_json")

			var mu sync.Mutex
			var opLog []string
			validatorCalls := 0

			validator := &dynamicValidator{
				fn: func(cfg string) []string {
					mu.Lock()
					defer mu.Unlock()
					validatorCalls++
					opLog = append(opLog, "validate")
					return nil // validation always succeeds
				},
			}

			writer := &trackingWriter{
				mu:    &mu,
				opLog: &opLog,
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(EnrollmentResponse{
					Status:     "approved",
					CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					CAChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
					ConfigJSON: configJSON,
					PodID:      "pod-prop16-ok",
				})
			}))
			defer server.Close()

			certDir, err := os.MkdirTemp("", "prop16-ok-*")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			defer os.RemoveAll(certDir)

			m := NewMachine(Config{
				ConfigManagerURL: server.URL,
				EnrollmentToken:  "test-token",
				PodName:          "test-pod",
				CertDir:          certDir,
				Validator:        validator,
				Readiness:        &stubReadiness{passed: true},
				Writer:           writer,
				Sleep:            noSleep,
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := m.Run(ctx); err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()

			// Validation must have been called.
			if validatorCalls == 0 {
				t.Fatal("validator was never called")
			}

			// Writer must have been called (validation succeeded → files written).
			if writer.calls == 0 {
				t.Fatal("writer was not called despite validation succeeding — files should be written after successful validation")
			}

			// The operation log must show validate before write.
			validateSeen := false
			for _, op := range opLog {
				if op == "validate" {
					validateSeen = true
				}
				if op == "write" && !validateSeen {
					t.Fatal("file write occurred before validation — validation must always precede file writes")
				}
			}

			// Final state must be capture_active.
			if m.State() != StateCaptureActive {
				t.Fatalf("expected state %q, got %q", StateCaptureActive, m.State())
			}
		})
	})

	t.Run("validation_always_precedes_write_for_any_error_count", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			// Generate a random number of consecutive validation failures before success.
			failuresBeforeSuccess := rapid.IntRange(0, 8).Draw(t, "failures_before_success")

			// Generate random error messages for each failure round.
			errorSets := make([][]string, failuresBeforeSuccess)
			for i := 0; i < failuresBeforeSuccess; i++ {
				numErrs := rapid.IntRange(1, 5).Draw(t, fmt.Sprintf("num_errors_%d", i))
				errs := make([]string, numErrs)
				for j := 0; j < numErrs; j++ {
					errs[j] = rapid.StringMatching(`[a-z]{3,20}`).Draw(t, fmt.Sprintf("err_%d_%d", i, j))
				}
				errorSets[i] = errs
			}

			configJSON := rapid.StringMatching(`\{"severity_threshold":\s*[123]\}`).Draw(t, "config_json")

			var mu sync.Mutex
			var opLog []string
			validatorCalls := 0

			validator := &dynamicValidator{
				fn: func(cfg string) []string {
					mu.Lock()
					defer mu.Unlock()
					call := validatorCalls
					validatorCalls++
					opLog = append(opLog, "validate")
					if call < failuresBeforeSuccess {
						return errorSets[call]
					}
					return nil
				},
			}

			writer := &trackingWriter{
				mu:    &mu,
				opLog: &opLog,
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(EnrollmentResponse{
					Status:     "approved",
					CertPEM:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					CAChainPEM: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
					ConfigJSON: configJSON,
					PodID:      "pod-prop16-multi",
				})
			}))
			defer server.Close()

			certDir, err := os.MkdirTemp("", "prop16-multi-*")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			defer os.RemoveAll(certDir)

			m := NewMachine(Config{
				ConfigManagerURL: server.URL,
				EnrollmentToken:  "test-token",
				PodName:          "test-pod",
				CertDir:          certDir,
				Validator:        validator,
				Readiness:        &stubReadiness{passed: true},
				Writer:           writer,
				Reporter:         &stubReporter{},
				Sleep:            noSleep,
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := m.Run(ctx); err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()

			// Total validator calls = failures + 1 successful call.
			expectedValidatorCalls := failuresBeforeSuccess + 1
			if validatorCalls != expectedValidatorCalls {
				t.Fatalf("expected %d validator calls, got %d", expectedValidatorCalls, validatorCalls)
			}

			// Writer must have been called exactly once (after the successful validation).
			if writer.calls != 1 {
				t.Fatalf("expected exactly 1 writer call, got %d", writer.calls)
			}

			// Verify ordering: no "write" appears before the last "validate".
			// The last validate is the successful one; write must come after it.
			lastValidateIdx := -1
			firstWriteIdx := -1
			for i, op := range opLog {
				if op == "validate" {
					lastValidateIdx = i
				}
				if op == "write" && firstWriteIdx == -1 {
					firstWriteIdx = i
				}
			}

			if firstWriteIdx == -1 {
				t.Fatal("no write operation recorded despite successful validation")
			}
			if lastValidateIdx == -1 {
				t.Fatal("no validate operation recorded")
			}
			if firstWriteIdx < lastValidateIdx {
				t.Fatalf("write (opLog[%d]) occurred before final validation (opLog[%d]) — "+
					"validation must always complete successfully before any file write", firstWriteIdx, lastValidateIdx)
			}

			// Verify no writes occurred during the failure rounds.
			// Count writes before the successful validation index.
			successValidateIdx := -1
			validateCount := 0
			for i, op := range opLog {
				if op == "validate" {
					validateCount++
					if validateCount == expectedValidatorCalls {
						successValidateIdx = i
					}
				}
			}
			for i, op := range opLog {
				if op == "write" && i < successValidateIdx {
					t.Fatalf("write at opLog[%d] occurred before successful validation at opLog[%d]", i, successValidateIdx)
				}
			}
		})
	})
}

// trackingWriter implements ConfigWriter and records write operations in a shared opLog.
type trackingWriter struct {
	mu    *sync.Mutex
	opLog *[]string
	calls int
}

func (w *trackingWriter) WriteConfigAndStartCapture(bundle ConfigBundle) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	*w.opLog = append(*w.opLog, "write")
	return nil
}
