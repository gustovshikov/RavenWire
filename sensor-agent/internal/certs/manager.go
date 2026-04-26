package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sensor-stack/sensor-agent/internal/audit"
)

// Manager handles certificate enrollment, storage, and rotation.
type Manager struct {
	certDir          string
	configManagerURL string
	podName          string
	enrollmentToken  string
	auditLog         *audit.Logger

	cert    *tls.Certificate
	privKey *ecdsa.PrivateKey
}

// NewManager creates a new Certificate Manager.
func NewManager(certDir, configManagerURL, podName, enrollmentToken string, auditLog *audit.Logger) *Manager {
	return &Manager{
		certDir:          certDir,
		configManagerURL: configManagerURL,
		podName:          podName,
		enrollmentToken:  enrollmentToken,
		auditLog:         auditLog,
	}
}

// Enroll performs the enrollment flow:
// 1. Generate ECDSA P-256 keypair
// 2. POST /enroll to Config_Manager
// 3. Poll for approval (202) or receive cert (200)
// 4. Store cert + CA chain to certDir
func (m *Manager) Enroll() error {
	if err := os.MkdirAll(m.certDir, 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	// Generate ECDSA P-256 keypair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	m.privKey = privKey

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})

	// POST /enroll
	enrollReq := map[string]string{
		"token":      m.enrollmentToken,
		"pod_name":   m.podName,
		"public_key": string(pubKeyPEM),
	}

	body, _ := json.Marshal(enrollReq)
	resp, err := http.Post(m.configManagerURL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST /enroll: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusAccepted: // 202 — pending operator approval
		log.Printf("certs: enrollment pending operator approval for pod %q", m.podName)
		m.auditLog.Log("enrollment-pending", "system", "pending", map[string]any{"pod_name": m.podName})
		// Poll for approval
		return m.pollForApproval(privKey)

	case http.StatusOK: // 200 — cert issued immediately
		return m.handleCertResponse(resp, privKey)

	default:
		return fmt.Errorf("enrollment failed with status %d", resp.StatusCode)
	}
}

// pollForApproval polls Config_Manager for enrollment approval.
func (m *Manager) pollForApproval(privKey *ecdsa.PrivateKey) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	timeout := time.After(24 * time.Hour)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("enrollment approval timed out after 24h")
		case <-ticker.C:
			resp, err := http.Get(m.configManagerURL + "/enroll/status?pod_name=" + m.podName)
			if err != nil {
				log.Printf("certs: poll enrollment status failed: %v", err)
				continue
			}

			if resp.StatusCode == http.StatusOK {
				err := m.handleCertResponse(resp, privKey)
				resp.Body.Close()
				return err
			}
			resp.Body.Close()
			log.Printf("certs: enrollment still pending (status=%d)", resp.StatusCode)
		}
	}
}

// handleCertResponse parses a 200 enrollment response and stores the cert.
func (m *Manager) handleCertResponse(resp *http.Response, privKey *ecdsa.PrivateKey) error {
	var certResp struct {
		CertPEM    string `json:"cert_pem"`
		CAChainPEM string `json:"ca_chain_pem"`
		PodID      string `json:"sensor_pod_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("decode cert response: %w", err)
	}

	// Store private key
	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyDER})

	if err := os.WriteFile(m.certDir+"/sensor.key", privKeyPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(m.certDir+"/sensor.crt", []byte(certResp.CertPEM), 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(m.certDir+"/ca-chain.pem", []byte(certResp.CAChainPEM), 0644); err != nil {
		return fmt.Errorf("write CA chain: %w", err)
	}

	// Load the cert into memory
	cert, err := tls.X509KeyPair([]byte(certResp.CertPEM), privKeyPEM)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}
	m.cert = &cert

	log.Printf("certs: enrolled successfully (pod_id=%s)", certResp.PodID)
	m.auditLog.Log("enrollment-complete", "system", "success", map[string]any{"pod_id": certResp.PodID})
	return nil
}

// LoadExisting loads an existing cert from certDir.
func (m *Manager) LoadExisting() error {
	certFile := m.certDir + "/sensor.crt"
	keyFile := m.certDir + "/sensor.key"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load existing cert: %w", err)
	}
	m.cert = &cert
	log.Printf("certs: loaded existing cert from %s", m.certDir)
	return nil
}

// Rotate requests a new certificate from Config_Manager.
func (m *Manager) Rotate() error {
	if m.configManagerURL == "" {
		return fmt.Errorf("Config_Manager URL not configured")
	}

	resp, err := http.Post(m.configManagerURL+"/api/v1/certs/rotate",
		"application/json", bytes.NewReader([]byte(`{"pod_name":"`+m.podName+`"}`)))
	if err != nil {
		return fmt.Errorf("POST /api/v1/certs/rotate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cert rotation failed with status %d", resp.StatusCode)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate new keypair: %w", err)
	}

	return m.handleCertResponse(resp, privKey)
}

// MonitorExpiry monitors cert expiry and triggers rotation when ≤6h remain.
func (m *Manager) MonitorExpiry(done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if m.cert == nil {
				continue
			}

			leaf, err := x509.ParseCertificate(m.cert.Certificate[0])
			if err != nil {
				log.Printf("certs: failed to parse cert for expiry check: %v", err)
				continue
			}

			remaining := time.Until(leaf.NotAfter)
			if remaining <= 6*time.Hour {
				log.Printf("certs: cert expires in %v, initiating rotation", remaining)
				if err := m.Rotate(); err != nil {
					log.Printf("certs: rotation failed: %v", err)
					m.auditLog.Log("cert-rotation-failed", "system", "failure",
						map[string]any{"error": err.Error(), "expires_in": remaining.String()})
				}
			}
		}
	}
}

// TLSCertificate returns the current TLS certificate for use in connections.
func (m *Manager) TLSCertificate() *tls.Certificate {
	return m.cert
}
