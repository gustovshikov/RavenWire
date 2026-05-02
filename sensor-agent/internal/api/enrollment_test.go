package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollmentListener_PostEnroll(t *testing.T) {
	called := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}

	el := NewEnrollmentListener(":0", handler)

	req := httptest.NewRequest(http.MethodPost, "/enroll", nil)
	rr := httptest.NewRecorder()
	el.dispatch(rr, req)

	if !called {
		t.Fatal("expected enroll handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestEnrollmentListener_GetEnroll_Returns404(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for GET /enroll")
	}

	el := NewEnrollmentListener(":0", handler)

	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	rr := httptest.NewRecorder()
	el.dispatch(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for GET /enroll, got %d", rr.Code)
	}
}

func TestEnrollmentListener_OtherPaths_Return404(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for non-enroll paths")
	}

	el := NewEnrollmentListener(":0", handler)

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodGet, "/health"},
		{http.MethodPost, "/control/reload/zeek"},
		{http.MethodPost, "/api/v1/config"},
		{http.MethodDelete, "/enroll"},
		{http.MethodPut, "/enroll"},
		{http.MethodGet, "/enroll/status"},
	}

	for _, tc := range paths {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		el.dispatch(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s: expected 404, got %d", tc.method, tc.path, rr.Code)
		}
	}
}
