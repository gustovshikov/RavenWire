package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"pgregory.net/rapid"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	auditLog, err := audit.New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditLog.Close() })

	srv := New(":9091", nil, auditLog)
	// Register a no-op handler for all allowed actions
	for _, action := range AllowedRoutes() {
		action := action
		srv.Register(action, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"status": "ok", "action": action})
		})
	}
	return srv
}

// Unit tests for specific allowlist cases

func TestAllowedRoute_Health(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	srv.dispatch(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /health: expected 200, got %d", rr.Code)
	}
}

func TestAllowedRoute_ReloadZeek(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/control/reload/zeek", nil)
	rr := httptest.NewRecorder()
	srv.dispatch(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("POST /control/reload/zeek: expected 200, got %d", rr.Code)
	}
}

func TestForbiddenRoute_ArbitraryPath(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/etc/passwd", nil)
	rr := httptest.NewRecorder()
	srv.dispatch(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("GET /etc/passwd: expected 403, got %d", rr.Code)
	}
}

func TestForbiddenRoute_WrongMethod(t *testing.T) {
	srv := newTestServer(t)
	// /health is GET only; POST should be forbidden
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()
	srv.dispatch(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("POST /health: expected 403, got %d", rr.Code)
	}
}

// Property 7: Sensor_Agent Action Allowlist Enforcement
// For any HTTP method + path combination, only the 9 allowlisted pairs return non-403.
// All others must return HTTP 403.
// Validates: Requirements 11.4, 15.7
func TestProperty7_AllowlistEnforcement(t *testing.T) {
	srv := newTestServer(t)
	allowed := AllowedRoutes()

	rapid.Check(t, func(t *rapid.T) {
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		method := methods[rapid.IntRange(0, len(methods)-1).Draw(t, "method")]
		path := "/" + rapid.StringMatching(`[a-z/]{1,40}`).Draw(t, "path")

		key := method + " " + path
		_, isAllowed := allowed[key]

		req := httptest.NewRequest(method, path, nil)
		rr := httptest.NewRecorder()
		srv.dispatch(rr, req)

		if isAllowed {
			// Allowed routes should return 200 (handler registered) or 501 (not implemented)
			if rr.Code == http.StatusForbidden {
				t.Fatalf("allowed route %s returned 403", key)
			}
		} else {
			// Non-allowed routes must return 403
			if rr.Code != http.StatusForbidden {
				t.Fatalf("non-allowed route %s returned %d (expected 403)", key, rr.Code)
			}
		}
	})
}
