package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateRequestID_Unique(t *testing.T) {
	ids := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := GenerateRequestID()
		if id == "" {
			t.Fatal("GenerateRequestID returned empty string")
		}
		if ids[id] {
			t.Fatalf("duplicate request ID: %s", id)
		}
		ids[id] = true
	}
}

func TestRequestIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	if id := RequestIDFromContext(ctx); id != "" {
		t.Fatalf("expected empty string, got %q", id)
	}
}

func TestContextWithRequestID_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "test-id-123")
	if id := RequestIDFromContext(ctx); id != "test-id-123" {
		t.Fatalf("expected test-id-123, got %q", id)
	}
}

func TestRequestIDMiddleware_SetsHeader(t *testing.T) {
	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := requestIDMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Check the response header is set.
	headerID := rr.Header().Get("X-Request-ID")
	if headerID == "" {
		t.Fatal("X-Request-ID header not set on response")
	}

	// Check the context value matches the header.
	if capturedID != headerID {
		t.Fatalf("context ID %q != header ID %q", capturedID, headerID)
	}
}

func TestRequestIDMiddleware_UniquePerRequest(t *testing.T) {
	var ids []string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids = append(ids, rr(r))
		w.WriteHeader(http.StatusOK)
	})

	handler := requestIDMiddleware(inner)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate request ID across requests: %s", id)
		}
		seen[id] = true
	}
}

// rr extracts request ID from context (helper for test).
func rr(r *http.Request) string {
	return RequestIDFromContext(r.Context())
}
