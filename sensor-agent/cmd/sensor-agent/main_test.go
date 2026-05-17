//go:build linux

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActorFromUsesClientCertificateCommonName(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/control", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "sensor-01"}},
		},
	}

	if got := actorFrom(req); got != "sensor-01" {
		t.Fatalf("actorFrom() = %q, want sensor-01", got)
	}
	if got := actorFrom(httptest.NewRequest(http.MethodPost, "/control", nil)); got != "unknown" {
		t.Fatalf("actorFrom() without cert = %q, want unknown", got)
	}
}

func TestWriteJSONAndWriteErr(t *testing.T) {
	okRecorder := httptest.NewRecorder()
	writeOK(okRecorder)

	if okRecorder.Code != http.StatusOK {
		t.Fatalf("writeOK status = %d", okRecorder.Code)
	}
	if okRecorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("writeOK content type = %q", okRecorder.Header().Get("Content-Type"))
	}
	var okBody map[string]string
	if err := json.Unmarshal(okRecorder.Body.Bytes(), &okBody); err != nil {
		t.Fatal(err)
	}
	if okBody["status"] != "ok" {
		t.Fatalf("writeOK body = %#v", okBody)
	}

	errRecorder := httptest.NewRecorder()
	writeErr(errRecorder, http.StatusBadRequest, "bad request")
	if errRecorder.Code != http.StatusBadRequest {
		t.Fatalf("writeErr status = %d", errRecorder.Code)
	}
	if !strings.Contains(errRecorder.Body.String(), "bad request") {
		t.Fatalf("writeErr body = %s", errRecorder.Body.String())
	}
}

func TestDecodeBody(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	if err := decodeBody(strings.NewReader(`{"name":"sensor"}`), &dst); err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if dst.Name != "sensor" {
		t.Fatalf("decoded name = %q", dst.Name)
	}
	if err := decodeBody(strings.NewReader(`{`), &dst); err == nil {
		t.Fatal("decodeBody should reject invalid JSON")
	}
}

func TestEnvironmentHelpers(t *testing.T) {
	t.Setenv("TEST_SENSOR_AGENT_VALUE", "configured")
	if got := envOrDefault("TEST_SENSOR_AGENT_VALUE", "fallback"); got != "configured" {
		t.Fatalf("envOrDefault configured = %q", got)
	}
	t.Setenv("TEST_SENSOR_AGENT_VALUE", "")
	if got := envOrDefault("TEST_SENSOR_AGENT_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envOrDefault fallback = %q", got)
	}

	t.Setenv("TEST_SENSOR_AGENT_FLOAT", "12.5")
	if got, ok := envFloat("TEST_SENSOR_AGENT_FLOAT"); !ok || got != 12.5 {
		t.Fatalf("envFloat valid = %v %v", got, ok)
	}
	t.Setenv("TEST_SENSOR_AGENT_FLOAT", "nope")
	if got, ok := envFloat("TEST_SENSOR_AGENT_FLOAT"); ok || got != 0 {
		t.Fatalf("envFloat invalid = %v %v", got, ok)
	}

	t.Setenv("TEST_SENSOR_AGENT_DURATION", "15m")
	if got := envDurationOrDefault("TEST_SENSOR_AGENT_DURATION", time.Second); got != 15*time.Minute {
		t.Fatalf("envDurationOrDefault valid = %s", got)
	}
	t.Setenv("TEST_SENSOR_AGENT_DURATION", "bad")
	if got := envDurationOrDefault("TEST_SENSOR_AGENT_DURATION", time.Second); got != time.Second {
		t.Fatalf("envDurationOrDefault invalid = %s", got)
	}
}

func TestFileExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exists")
	if fileExists(path) {
		t.Fatal("fileExists should be false before file is created")
	}
	if err := os.WriteFile(path, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if !fileExists(path) {
		t.Fatal("fileExists should be true after file is created")
	}
}
