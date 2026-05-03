package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

func TestBundleReadyRejectsExpiredCertificate(t *testing.T) {
	certDir := t.TempDir()
	writeCertBundle(t, certDir, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	ok, reason := BundleReady(
		filepath.Join(certDir, "sensor.crt"),
		filepath.Join(certDir, "sensor.key"),
		filepath.Join(certDir, "ca-chain.pem"),
		time.Now(),
	)
	if ok {
		t.Fatal("expired certificate must not be ready")
	}
	if !strings.Contains(reason, "expired") {
		t.Fatalf("expected expired reason, got %q", reason)
	}
}

func TestBundleReadyAcceptsCurrentCertificate(t *testing.T) {
	certDir := t.TempDir()
	writeCertBundle(t, certDir, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	ok, reason := BundleReady(
		filepath.Join(certDir, "sensor.crt"),
		filepath.Join(certDir, "sensor.key"),
		filepath.Join(certDir, "ca-chain.pem"),
		time.Now(),
	)
	if !ok {
		t.Fatalf("valid certificate bundle rejected: %s", reason)
	}
}

func TestRotateSendsFreshPublicKeyAndStoresReturnedBundle(t *testing.T) {
	certDir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certs/rotate" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var req struct {
			PodName   string `json:"pod_name"`
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.PodName != "rotate-test" {
			t.Fatalf("unexpected pod name %q", req.PodName)
		}
		block, _ := pem.Decode([]byte(req.PublicKey))
		if block == nil {
			t.Fatal("rotation request did not include a PEM public key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected ECDSA public key, got %T", pub)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, ecdsaPub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem":      string(certPEM),
			"ca_chain_pem":  string(certPEM),
			"sensor_pod_id": "pod-id",
		})
	}))
	defer server.Close()

	auditLog, err := audit.New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()

	manager := NewManager(certDir, server.URL, "rotate-test", "", auditLog)
	if err := manager.Rotate(); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	ok, reason := BundleReady(
		filepath.Join(certDir, "sensor.crt"),
		filepath.Join(certDir, "sensor.key"),
		filepath.Join(certDir, "ca-chain.pem"),
		time.Now(),
	)
	if !ok {
		t.Fatalf("rotated certificate bundle rejected: %s", reason)
	}
}

func writeCertBundle(t *testing.T, certDir string, notBefore, notAfter time.Time) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"sensor.crt":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		"sensor.key":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"ca-chain.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(certDir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
