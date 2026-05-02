package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

// allowedRoutes is the exact set of (method, path) pairs the Control API accepts.
// Any request not in this set is rejected with HTTP 403.
var allowedRoutes = map[string]string{
	"POST /control/reload/zeek":            "reload-zeek",
	"POST /control/reload/suricata":        "reload-suricata",
	"POST /control/restart/vector":         "restart-vector",
	"POST /control/capture-mode":           "switch-capture-mode",
	"POST /control/config":                 "apply-pool-config",
	"POST /control/cert/rotate":            "rotate-cert",
	"GET /health":                          "report-health",
	"POST /control/pcap/carve":             "carve-pcap",
	"POST /control/config/validate":        "validate-config",
	"POST /control/support-bundle":         "support-bundle",
	"GET /control/support-bundle/download": "download-support-bundle",
}

// Handler is a function that handles a specific control action.
type Handler func(w http.ResponseWriter, r *http.Request)

// Server is the mTLS REST control API server.
type Server struct {
	addr     string
	tlsCfg   *tls.Config
	audit    *audit.Logger
	handlers map[string]Handler
}

// New creates a new Server.
func New(addr string, tlsCfg *tls.Config, auditLog *audit.Logger) *Server {
	return &Server{
		addr:     addr,
		tlsCfg:   tlsCfg,
		audit:    auditLog,
		handlers: make(map[string]Handler),
	}
}

// Register registers a handler for a specific action name.
func (s *Server) Register(action string, h Handler) {
	s.handlers[action] = h
}

// ListenAndServe starts the mTLS HTTP server.
// Every response includes an X-Request-ID header and the request ID is
// stored in the request context for use by handlers and audit logging.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dispatch)

	// Wrap with X-Request-ID middleware (Requirement 6.5).
	handler := requestIDMiddleware(mux)

	srv := &http.Server{
		Addr:      s.addr,
		Handler:   handler,
		TLSConfig: s.tlsCfg,
	}

	if s.tlsCfg == nil {
		log.Printf("api: control API listening on %s (plain HTTP — dev mode)", s.addr)
		return srv.ListenAndServe()
	}
	log.Printf("api: control API listening on %s (mTLS)", s.addr)
	return srv.ListenAndServeTLS("", "")
}

// dispatch routes requests to registered handlers, enforcing the allowlist.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	action, allowed := allowedRoutes[key]

	// Extract actor identity from mTLS client cert CN
	actor := "unknown"
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		actor = r.TLS.PeerCertificates[0].Subject.CommonName
	}

	// Extract request ID from context (set by requestIDMiddleware).
	requestID := RequestIDFromContext(r.Context())

	if !allowed {
		s.audit.Log("control_api_rejected", actor, "failure", map[string]any{
			"method":     r.Method,
			"path":       r.URL.Path,
			"reason":     "not in allowlist",
			"request_id": requestID,
		})
		writeError(w, http.StatusForbidden, "FORBIDDEN",
			fmt.Sprintf("action %s %s is not permitted", r.Method, r.URL.Path))
		return
	}

	h, registered := s.handlers[action]
	if !registered {
		// Action is in allowlist but no handler registered yet
		s.audit.Log(action, actor, "failure", map[string]any{
			"reason":     "handler not implemented",
			"request_id": requestID,
		})
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED",
			fmt.Sprintf("action %q is not yet implemented", action))
		return
	}

	s.audit.Log(action, actor, "accepted", map[string]any{
		"request_id": requestID,
	})
	h(w, r)
}

// writeError writes a structured JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// writeJSON writes a JSON response with status 200.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// NewMTLSConfig builds a tls.Config for mTLS using the cert/key/CA at the given paths.
func NewMTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", caFile, err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert from %s", caFile)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	// Load CRL if available (Requirement 6.6).
	// Check CRL_PATH env var first, then look for crl.pem in the cert directory.
	crlPath := os.Getenv("CRL_PATH")
	if crlPath == "" {
		crlPath = filepath.Join(filepath.Dir(certFile), "crl.pem")
	}
	crlChecker, err := NewCRLChecker(crlPath)
	if err != nil {
		return nil, fmt.Errorf("load CRL: %w", err)
	}
	tlsCfg.VerifyPeerCertificate = crlChecker.VerifyPeerCertificate

	return tlsCfg, nil
}

// AllowedRoutes returns a copy of the allowlist for testing.
func AllowedRoutes() map[string]string {
	out := make(map[string]string, len(allowedRoutes))
	for k, v := range allowedRoutes {
		out[k] = v
	}
	return out
}
