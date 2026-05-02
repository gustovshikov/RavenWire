package api

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
)

// CRLChecker checks client certificate serials against a Certificate Revocation List.
type CRLChecker struct {
	mu      sync.RWMutex
	revoked map[string]bool // serial number hex → true
}

// NewCRLChecker creates a new CRLChecker. If crlPath is non-empty, the CRL is
// loaded from that file. If the file does not exist or is empty, the checker
// starts with an empty revocation set (no certificates revoked).
func NewCRLChecker(crlPath string) (*CRLChecker, error) {
	c := &CRLChecker{
		revoked: make(map[string]bool),
	}
	if crlPath == "" {
		return c, nil
	}
	if err := c.LoadFromFile(crlPath); err != nil {
		// If the file doesn't exist, start with empty CRL — not an error.
		if os.IsNotExist(err) {
			log.Printf("api/crl: CRL file %s not found; starting with empty revocation list", crlPath)
			return c, nil
		}
		return nil, err
	}
	return c, nil
}

// LoadFromFile loads a PEM-encoded CRL from the given file path.
func (c *CRLChecker) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return c.LoadFromPEM(data)
}

// LoadFromPEM parses a PEM-encoded CRL and populates the revoked serial set.
func (c *CRLChecker) LoadFromPEM(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("crl: no PEM block found")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("crl: parse revocation list: %w", err)
	}

	revoked := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		revoked[entry.SerialNumber.Text(16)] = true
	}

	c.mu.Lock()
	c.revoked = revoked
	c.mu.Unlock()

	log.Printf("api/crl: loaded CRL with %d revoked certificate(s)", len(revoked))
	return nil
}

// IsRevoked returns true if the given certificate serial number is in the CRL.
func (c *CRLChecker) IsRevoked(serial *big.Int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revoked[serial.Text(16)]
}

// VerifyPeerCertificate returns a callback suitable for tls.Config.VerifyPeerCertificate.
// It checks each presented certificate's serial against the loaded CRL and rejects
// the connection if any certificate is revoked.
func (c *CRLChecker) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("crl: parse certificate: %w", err)
		}
		if c.IsRevoked(cert.SerialNumber) {
			log.Printf("api/crl: REJECTED connection: certificate serial %s is revoked (CN=%s)",
				cert.SerialNumber.Text(16), cert.Subject.CommonName)
			return fmt.Errorf("certificate serial %s is revoked", cert.SerialNumber.Text(16))
		}
	}
	return nil
}
