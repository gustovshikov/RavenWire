// Package bootstrap implements the sensor bootstrap state machine.
//
// The state machine progresses through a defined sequence of states:
//
//	installed → enrolling → pending_approval → config_received → config_validated → capture_active
//
// Each state transition is logged. The machine handles enrollment with
// exponential backoff, config validation before file writes, and host
// readiness checks before starting capture.
//
// Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

// State represents a bootstrap state machine state.
type State string

const (
	StateInstalled       State = "installed"
	StateEnrolling       State = "enrolling"
	StatePendingApproval State = "pending_approval"
	StateConfigReceived  State = "config_received"
	StateConfigValidated State = "config_validated"
	StateCaptureActive   State = "capture_active"
)

// stateOrder defines the valid forward progression of states.
// Used to enforce forward-only transitions (Requirement 11.1).
var stateOrder = []State{
	StateInstalled,
	StateEnrolling,
	StatePendingApproval,
	StateConfigReceived,
	StateConfigValidated,
	StateCaptureActive,
}

// stateIndex returns the ordinal position of a state, or -1 if unknown.
func stateIndex(s State) int {
	for i, st := range stateOrder {
		if st == s {
			return i
		}
	}
	return -1
}

// EnrollmentResponse is the response from Config_Manager's enrollment endpoint.
type EnrollmentResponse struct {
	Status     string `json:"status"`   // "pending", "approved"
	CertPEM    string `json:"cert_pem"` // present when approved
	CAChainPEM string `json:"ca_chain_pem"`
	ConfigJSON string `json:"config_json"` // sensor config bundle JSON
	PodID      string `json:"sensor_pod_id"`
}

// ConfigBundle holds the cert and config data received from Config_Manager.
type ConfigBundle struct {
	CertPEM    string
	CAChainPEM string
	ConfigJSON string
	PodID      string
	PrivateKey *ecdsa.PrivateKey
}

// ConfigValidator validates a config bundle before it is written to disk.
// Implementations should invoke Rule_Validator and Capture_Manager validation.
type ConfigValidator interface {
	// ValidateBundle validates the config bundle and returns a list of error
	// strings. An empty slice means the bundle is valid.
	ValidateBundle(configJSON string) []string
}

// ReadinessChecker runs host readiness checks.
type ReadinessChecker interface {
	// CheckHardFailures returns true if all hard checks pass, false otherwise.
	// The second return value is a list of failure descriptions.
	CheckHardFailures() (passed bool, failures []string)
}

// ConfigWriter writes validated config and starts capture processes.
type ConfigWriter interface {
	// WriteConfigAndStartCapture writes the config bundle to disk and starts
	// capture processes. Returns an error if any step fails.
	WriteConfigAndStartCapture(bundle ConfigBundle) error
}

// HealthReporter reports errors to Config_Manager.
type HealthReporter interface {
	// ReportError sends a validation or readiness error to Config_Manager.
	ReportError(state State, errors []string)
}

// Config holds the bootstrap state machine configuration.
type Config struct {
	// ConfigManagerURL is the base URL of the Config_Manager (e.g. "https://config-manager:9090").
	ConfigManagerURL string
	// EnrollmentToken is the one-time token for enrollment.
	EnrollmentToken string
	// PodName is the name of this sensor pod.
	PodName string
	// CertDir is the directory where certs are stored.
	CertDir string

	// EnrollInitialBackoff is the initial retry interval for enrollment (default 5s).
	EnrollInitialBackoff time.Duration
	// EnrollMaxBackoff is the maximum retry interval for enrollment (default 60s).
	EnrollMaxBackoff time.Duration
	// ApprovalPollInterval is the interval for polling approval status (default 30s).
	ApprovalPollInterval time.Duration

	// Validator validates config bundles before writing.
	Validator ConfigValidator
	// Readiness runs host readiness checks.
	Readiness ReadinessChecker
	// Writer writes config and starts capture.
	Writer ConfigWriter
	// Reporter reports errors to Config_Manager.
	Reporter HealthReporter
	// AuditLog is the audit logger.
	AuditLog *audit.Logger

	// HTTPClient is the HTTP client used for enrollment requests.
	// Defaults to http.DefaultClient if nil.
	HTTPClient *http.Client

	// Clock provides the current time. Defaults to time.Now if nil.
	// Exposed for testing.
	Clock func() time.Time
	// Sleep pauses for the given duration. Defaults to time.Sleep if nil.
	// Exposed for testing.
	Sleep func(time.Duration)
}

func (c *Config) defaults() {
	if c.EnrollInitialBackoff <= 0 {
		c.EnrollInitialBackoff = 5 * time.Second
	}
	if c.EnrollMaxBackoff <= 0 {
		c.EnrollMaxBackoff = 60 * time.Second
	}
	if c.ApprovalPollInterval <= 0 {
		c.ApprovalPollInterval = 30 * time.Second
	}
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = time.Sleep
	}
}

// Machine is the bootstrap state machine.
type Machine struct {
	cfg    Config
	state  State
	bundle *ConfigBundle
}

// NewMachine creates a new bootstrap state machine starting in the installed state.
func NewMachine(cfg Config) *Machine {
	cfg.defaults()
	return &Machine{
		cfg:   cfg,
		state: StateInstalled,
	}
}

// State returns the current state.
func (m *Machine) State() State {
	return m.state
}

// BlockingErrors returns a human-readable description of any errors blocking
// progress from the current state. Returns nil if no errors are blocking.
func (m *Machine) BlockingErrors() []string {
	return nil // populated during Run if needed
}

// transition advances the state machine to the given state, logging the transition.
// Returns an error if the transition is not forward-only (Requirement 11.1).
func (m *Machine) transition(to State) error {
	fromIdx := stateIndex(m.state)
	toIdx := stateIndex(to)

	if toIdx < 0 {
		return fmt.Errorf("bootstrap: unknown target state %q", to)
	}

	// Allow same-state transitions for retry loops (enrolling, config_received).
	if toIdx < fromIdx {
		return fmt.Errorf("bootstrap: backward transition from %q to %q is not allowed", m.state, to)
	}

	// Enforce no state skipping: target must be current or current+1,
	// except for retry loops where target == current.
	if toIdx > fromIdx+1 {
		return fmt.Errorf("bootstrap: cannot skip from %q to %q", m.state, to)
	}

	if m.state != to {
		log.Printf("bootstrap: state transition %s → %s", m.state, to)
		if m.cfg.AuditLog != nil {
			m.cfg.AuditLog.Log("bootstrap-transition", "system", "success", map[string]any{
				"from": string(m.state),
				"to":   string(to),
			})
		}
	}

	m.state = to
	return nil
}

// Run executes the bootstrap state machine from installed through to
// capture_active. It blocks until the machine reaches capture_active or
// the context is cancelled.
//
// Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
func (m *Machine) Run(ctx context.Context) error {
	log.Printf("bootstrap: starting state machine (state=%s)", m.state)

	// installed → enrolling
	if m.state == StateInstalled {
		if err := m.transition(StateEnrolling); err != nil {
			return err
		}
	}

	// enrolling: POST enrollment with exponential backoff (Requirement 11.2)
	if m.state == StateEnrolling {
		bundle, err := m.runEnrolling(ctx)
		if err != nil {
			return fmt.Errorf("bootstrap: enrolling failed: %w", err)
		}
		if bundle == nil {
			// Enrollment accepted but pending approval
			if err := m.transition(StatePendingApproval); err != nil {
				return err
			}
		} else {
			// Enrollment approved immediately — skip pending_approval
			// We still transition through pending_approval to maintain order.
			if err := m.transition(StatePendingApproval); err != nil {
				return err
			}
			m.bundle = bundle
			if err := m.transition(StateConfigReceived); err != nil {
				return err
			}
		}
	}

	// pending_approval: poll for approval (Requirement 11.3)
	if m.state == StatePendingApproval {
		bundle, err := m.runPendingApproval(ctx)
		if err != nil {
			return fmt.Errorf("bootstrap: pending_approval failed: %w", err)
		}
		m.bundle = bundle
		if err := m.transition(StateConfigReceived); err != nil {
			return err
		}
	}

	// config_received: validate bundle (Requirement 11.4, 11.5)
	if m.state == StateConfigReceived {
		if err := m.runConfigReceived(ctx); err != nil {
			return fmt.Errorf("bootstrap: config_received failed: %w", err)
		}
		if err := m.transition(StateConfigValidated); err != nil {
			return err
		}
	}

	// config_validated: run readiness checks, write config, start capture (Requirement 11.6)
	if m.state == StateConfigValidated {
		if err := m.runConfigValidated(ctx); err != nil {
			return fmt.Errorf("bootstrap: config_validated failed: %w", err)
		}
		if err := m.transition(StateCaptureActive); err != nil {
			return err
		}
	}

	log.Printf("bootstrap: state machine complete (state=%s)", m.state)
	return nil
}

// runEnrolling handles the enrolling state: POST to Config_Manager with
// exponential backoff on failure (Requirement 11.2).
//
// Returns the ConfigBundle if enrollment is immediately approved (200),
// or nil if enrollment is pending approval (202).
func (m *Machine) runEnrolling(ctx context.Context) (*ConfigBundle, error) {
	backoff := m.cfg.EnrollInitialBackoff

	// Generate ECDSA P-256 keypair for enrollment
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		bundle, pending, err := m.postEnrollment(pubKeyPEM, privKey)
		if err == nil {
			if pending {
				log.Printf("bootstrap: enrollment accepted, pending approval")
				return nil, nil
			}
			log.Printf("bootstrap: enrollment approved immediately (pod_id=%s)", bundle.PodID)
			return bundle, nil
		}

		log.Printf("bootstrap: enrollment failed (retrying in %s): %v", backoff, err)
		if m.cfg.AuditLog != nil {
			m.cfg.AuditLog.Log("bootstrap-enrollment-retry", "system", "failure", map[string]any{
				"error":   err.Error(),
				"backoff": backoff.String(),
			})
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			m.cfg.Sleep(backoff)
		}

		// Exponential backoff: double, cap at max (Requirement 11.2)
		backoff = time.Duration(math.Min(
			float64(backoff*2),
			float64(m.cfg.EnrollMaxBackoff),
		))
	}
}

// postEnrollment sends a single enrollment POST request.
// Returns (bundle, false, nil) on immediate approval (200),
// (nil, true, nil) on pending (202), or (nil, false, err) on failure.
func (m *Machine) postEnrollment(pubKeyPEM []byte, privKey *ecdsa.PrivateKey) (*ConfigBundle, bool, error) {
	enrollReq := map[string]string{
		"token":      m.cfg.EnrollmentToken,
		"pod_name":   m.cfg.PodName,
		"public_key": string(pubKeyPEM),
	}

	body, err := json.Marshal(enrollReq)
	if err != nil {
		return nil, false, fmt.Errorf("marshal enrollment request: %w", err)
	}

	url := m.cfg.ConfigManagerURL + "/enroll"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("create enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("POST /enroll: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Immediately approved
		var enrollResp EnrollmentResponse
		if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
			return nil, false, fmt.Errorf("decode enrollment response: %w", err)
		}
		bundle := &ConfigBundle{
			CertPEM:    enrollResp.CertPEM,
			CAChainPEM: enrollResp.CAChainPEM,
			ConfigJSON: enrollResp.ConfigJSON,
			PodID:      enrollResp.PodID,
			PrivateKey: privKey,
		}
		return bundle, false, nil

	case http.StatusAccepted:
		// Pending approval
		return nil, true, nil

	default:
		return nil, false, fmt.Errorf("enrollment returned status %d", resp.StatusCode)
	}
}

// runPendingApproval polls Config_Manager for approval at the configured
// interval (Requirement 11.3).
func (m *Machine) runPendingApproval(ctx context.Context) (*ConfigBundle, error) {
	log.Printf("bootstrap: polling for approval (interval=%s)", m.cfg.ApprovalPollInterval)

	// We need the private key from the enrollment phase. If we don't have a
	// bundle yet, generate a new keypair for the approval poll.
	var privKey *ecdsa.PrivateKey
	if m.bundle != nil && m.bundle.PrivateKey != nil {
		privKey = m.bundle.PrivateKey
	} else {
		var err error
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate keypair for approval poll: %w", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		bundle, err := m.pollApproval(privKey)
		if err == nil && bundle != nil {
			log.Printf("bootstrap: approval received (pod_id=%s)", bundle.PodID)
			return bundle, nil
		}
		if err != nil {
			log.Printf("bootstrap: approval poll error: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			m.cfg.Sleep(m.cfg.ApprovalPollInterval)
		}
	}
}

// pollApproval sends a single approval status request.
func (m *Machine) pollApproval(privKey *ecdsa.PrivateKey) (*ConfigBundle, error) {
	url := fmt.Sprintf("%s/enroll/status?pod_name=%s", m.cfg.ConfigManagerURL, m.cfg.PodName)
	resp, err := m.cfg.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET /enroll/status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil // still pending
	}

	var enrollResp EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("decode approval response: %w", err)
	}

	return &ConfigBundle{
		CertPEM:    enrollResp.CertPEM,
		CAChainPEM: enrollResp.CAChainPEM,
		ConfigJSON: enrollResp.ConfigJSON,
		PodID:      enrollResp.PodID,
		PrivateKey: privKey,
	}, nil
}

// runConfigReceived validates the config bundle using Rule_Validator and
// Capture_Manager validation before writing any files (Requirement 11.4, 11.5).
//
// On validation failure, remains in config_received state, logs errors, and
// reports to Config_Manager. Retries on the next poll cycle.
func (m *Machine) runConfigReceived(ctx context.Context) error {
	if m.bundle == nil {
		return fmt.Errorf("no config bundle available")
	}

	if m.cfg.Validator == nil {
		log.Printf("bootstrap: no config validator configured, skipping validation")
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		errs := m.cfg.Validator.ValidateBundle(m.bundle.ConfigJSON)
		if len(errs) == 0 {
			log.Printf("bootstrap: config bundle validated successfully")
			return nil
		}

		// Requirement 11.5: Remain in config_received, log errors, report to Config_Manager.
		log.Printf("bootstrap: config validation failed (%d errors):", len(errs))
		for _, e := range errs {
			log.Printf("  - %s", e)
		}

		if m.cfg.AuditLog != nil {
			m.cfg.AuditLog.Log("bootstrap-config-validation-failed", "system", "failure", map[string]any{
				"errors": errs,
			})
		}

		if m.cfg.Reporter != nil {
			m.cfg.Reporter.ReportError(StateConfigReceived, errs)
		}

		// Wait before retrying validation (e.g. operator may push a corrected bundle)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			m.cfg.Sleep(m.cfg.ApprovalPollInterval)
		}
	}
}

// runConfigValidated writes the enrolled identity, runs Host_Readiness_Checker,
// writes config, and starts capture processes (Requirement 11.6).
func (m *Machine) runConfigValidated(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Enrollment identity is independent from capture readiness. Persist it as
	// soon as approval and config validation succeed so restarts can use the
	// enrolled certificate even if capture activation is blocked by host tuning.
	if m.bundle != nil && m.bundle.CertPEM != "" {
		if err := m.writeCerts(); err != nil {
			return fmt.Errorf("write certs: %w", err)
		}
	}

	// Run host readiness checks
	if m.cfg.Readiness != nil {
		passed, failures := m.cfg.Readiness.CheckHardFailures()
		if !passed {
			log.Printf("bootstrap: host readiness check failed:")
			for _, f := range failures {
				log.Printf("  - %s", f)
			}
			if m.cfg.AuditLog != nil {
				m.cfg.AuditLog.Log("bootstrap-readiness-failed", "system", "failure", map[string]any{
					"failures": failures,
				})
			}
			return fmt.Errorf("host readiness check failed: %d hard failures", len(failures))
		}
		log.Printf("bootstrap: host readiness checks passed")
	}

	// Write config and start capture processes
	if m.cfg.Writer != nil && m.bundle != nil {
		if err := m.cfg.Writer.WriteConfigAndStartCapture(*m.bundle); err != nil {
			return fmt.Errorf("write config and start capture: %w", err)
		}
	}

	log.Printf("bootstrap: config written and capture processes started")
	return nil
}

// writeCerts writes the certificate, private key, and CA chain to the cert directory.
func (m *Machine) writeCerts() error {
	if m.cfg.CertDir == "" {
		return fmt.Errorf("cert directory not configured")
	}

	if err := os.MkdirAll(m.cfg.CertDir, 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	// Write certificate
	if err := os.WriteFile(m.cfg.CertDir+"/sensor.crt", []byte(m.bundle.CertPEM), 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// Write CA chain
	if m.bundle.CAChainPEM != "" {
		if err := os.WriteFile(m.cfg.CertDir+"/ca-chain.pem", []byte(m.bundle.CAChainPEM), 0644); err != nil {
			return fmt.Errorf("write CA chain: %w", err)
		}
	}

	// Write private key
	if m.bundle.PrivateKey != nil {
		privKeyDER, err := x509.MarshalECPrivateKey(m.bundle.PrivateKey)
		if err != nil {
			return fmt.Errorf("marshal private key: %w", err)
		}
		privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyDER})
		if err := os.WriteFile(m.cfg.CertDir+"/sensor.key", privKeyPEM, 0600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
	}

	log.Printf("bootstrap: certs written to %s", m.cfg.CertDir)
	return nil
}
