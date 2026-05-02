package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// generateTestCRL creates a PEM-encoded CRL with the given revoked serial numbers.
func generateTestCRL(t *testing.T, revokedSerials []*big.Int) []byte {
	t.Helper()

	// Generate a CA key and cert for signing the CRL.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// Build revoked entries.
	var revokedEntries []x509.RevocationListEntry
	for _, serial := range revokedSerials {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-1 * time.Hour),
		})
	}

	crlTemplate := &x509.RevocationList{
		RevokedCertificateEntries: revokedEntries,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-1 * time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
}

func TestCRLChecker_EmptyPath(t *testing.T) {
	checker, err := NewCRLChecker("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No certificates should be revoked.
	if checker.IsRevoked(big.NewInt(42)) {
		t.Fatal("expected serial 42 to not be revoked with empty CRL")
	}
}

func TestCRLChecker_NonExistentFile(t *testing.T) {
	checker, err := NewCRLChecker("/nonexistent/path/crl.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should start with empty revocation list.
	if checker.IsRevoked(big.NewInt(42)) {
		t.Fatal("expected serial 42 to not be revoked with missing CRL file")
	}
}

func TestCRLChecker_LoadAndCheck(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	crlPEM := generateTestCRL(t, revokedSerials)

	checker, err := NewCRLChecker("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := checker.LoadFromPEM(crlPEM); err != nil {
		t.Fatalf("LoadFromPEM: %v", err)
	}

	// Revoked serials should be detected.
	for _, serial := range revokedSerials {
		if !checker.IsRevoked(serial) {
			t.Errorf("expected serial %s to be revoked", serial.Text(10))
		}
	}

	// Non-revoked serial should not be detected.
	if checker.IsRevoked(big.NewInt(999)) {
		t.Error("expected serial 999 to not be revoked")
	}
}

func TestCRLChecker_LoadFromFile(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(42)}
	crlPEM := generateTestCRL(t, revokedSerials)

	tmpFile, err := os.CreateTemp(t.TempDir(), "crl-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmpFile.Write(crlPEM); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
	tmpFile.Close()

	checker, err := NewCRLChecker(tmpFile.Name())
	if err != nil {
		t.Fatalf("NewCRLChecker: %v", err)
	}

	if !checker.IsRevoked(big.NewInt(42)) {
		t.Error("expected serial 42 to be revoked")
	}
	if checker.IsRevoked(big.NewInt(43)) {
		t.Error("expected serial 43 to not be revoked")
	}
}

func TestCRLChecker_VerifyPeerCertificate_Revoked(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(555)}
	crlPEM := generateTestCRL(t, revokedSerials)

	checker, err := NewCRLChecker("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := checker.LoadFromPEM(crlPEM); err != nil {
		t.Fatalf("LoadFromPEM: %v", err)
	}

	// Create a self-signed cert with serial 555.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(555),
		Subject:      pkix.Name{CommonName: "revoked-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	err = checker.VerifyPeerCertificate([][]byte{certDER}, nil)
	if err == nil {
		t.Fatal("expected error for revoked certificate, got nil")
	}
}

func TestCRLChecker_VerifyPeerCertificate_NotRevoked(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(555)}
	crlPEM := generateTestCRL(t, revokedSerials)

	checker, err := NewCRLChecker("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := checker.LoadFromPEM(crlPEM); err != nil {
		t.Fatalf("LoadFromPEM: %v", err)
	}

	// Create a self-signed cert with serial 999 (not revoked).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "valid-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	err = checker.VerifyPeerCertificate([][]byte{certDER}, nil)
	if err != nil {
		t.Fatalf("expected no error for valid certificate, got: %v", err)
	}
}
