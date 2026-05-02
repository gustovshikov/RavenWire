package api

import (
	"log"
	"net/http"
)

// EnrollHandler is a function that handles the POST /enroll request.
type EnrollHandler func(w http.ResponseWriter, r *http.Request)

// EnrollmentListener is a minimal HTTP server that binds on a separate port
// and accepts ONLY POST /enroll. All other paths return HTTP 404.
// This listener runs without mTLS (used before certificates are issued).
type EnrollmentListener struct {
	addr    string
	handler EnrollHandler
}

// NewEnrollmentListener creates a new enrollment listener on the given address.
func NewEnrollmentListener(addr string, handler EnrollHandler) *EnrollmentListener {
	return &EnrollmentListener{
		addr:    addr,
		handler: handler,
	}
}

// ListenAndServe starts the enrollment HTTP server (plain HTTP, no mTLS).
func (el *EnrollmentListener) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", el.dispatch)

	srv := &http.Server{
		Addr:    el.addr,
		Handler: mux,
	}

	log.Printf("api: enrollment listener on %s (plain HTTP, POST /enroll only)", el.addr)
	return srv.ListenAndServe()
}

// dispatch routes requests: only POST /enroll is accepted; everything else is 404.
func (el *EnrollmentListener) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/enroll" {
		el.handler(w, r)
		return
	}
	http.NotFound(w, r)
}
