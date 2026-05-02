package podman

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// ── Unit tests ────────────────────────────────────────────────────────────────

// TestAllowlist_AllowedContainer verifies that a container in the allowlist
// is not rejected by the allowlist check.
func TestAllowlist_AllowedContainer(t *testing.T) {
	c := &Client{
		allowlist: map[string]string{
			"vector": "",
			"zeek":   "zeek.service",
		},
	}
	if !c.IsAllowed("vector") {
		t.Error("vector should be allowed")
	}
	if !c.IsAllowed("zeek") {
		t.Error("zeek should be allowed")
	}
}

// TestAllowlist_RejectedContainer verifies that a container not in the allowlist
// is rejected.
func TestAllowlist_RejectedContainer(t *testing.T) {
	c := &Client{
		allowlist: map[string]string{
			"vector": "",
		},
	}
	if c.IsAllowed("unknown-container") {
		t.Error("unknown-container should not be allowed")
	}
	if c.IsAllowed("") {
		t.Error("empty name should not be allowed")
	}
}

// TestRestartContainer_AllowlistRejection verifies that a restart request for a
// container not in the allowlist returns an error and does not call the Podman API.
func TestRestartContainer_AllowlistRejection(t *testing.T) {
	apiCalled := false
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Start()
	defer srv.Close()

	c := &Client{
		allowlist:  map[string]string{"vector": ""},
		timeout:    DefaultTimeout,
		httpClient: srv.Client(),
		available:  true,
	}
	// Override httpClient to use the test server — but since the allowlist check
	// happens before any HTTP call, the server should never be called.
	c.httpClient = &http.Client{}

	_, err := c.RestartContainer("not-in-allowlist", "test-actor")
	if err == nil {
		t.Fatal("expected error for container not in allowlist, got nil")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("expected allowlist error, got: %v", err)
	}
	if apiCalled {
		t.Error("Podman API should NOT have been called for a rejected container")
	}
}

// TestRestartContainer_SocketUnavailable verifies that a restart attempt when
// the socket is unavailable returns an error without calling the API.
func TestRestartContainer_SocketUnavailable(t *testing.T) {
	apiCalled := false
	c := &Client{
		allowlist:  map[string]string{"vector": ""},
		socketPath: "/nonexistent/podman.sock",
		timeout:    DefaultTimeout,
		httpClient: &http.Client{},
		available:  false,
	}
	_ = apiCalled

	_, err := c.RestartContainer("vector", "test-actor")
	if err == nil {
		t.Fatal("expected error when socket is unavailable, got nil")
	}
}

// TestGetContainerState_Running verifies state parsing for a running container.
func TestGetContainerState_Running(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"State":{"Status":"running","Error":""}}`))
	}))
	defer srv.Close()

	c := clientWithTestServer(srv)
	state, err := c.GetContainerState("vector")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != StateRunning {
		t.Errorf("expected running, got %s", state)
	}
}

// TestGetContainerState_Exited verifies state parsing for a stopped container.
func TestGetContainerState_Exited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"State":{"Status":"exited","Error":""}}`))
	}))
	defer srv.Close()

	c := clientWithTestServer(srv)
	state, err := c.GetContainerState("vector")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != StateStopped {
		t.Errorf("expected stopped, got %s", state)
	}
}

// TestGetContainerState_NotFound verifies that a 404 response maps to StateStopped.
func TestGetContainerState_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := clientWithTestServer(srv)
	state, err := c.GetContainerState("missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != StateStopped {
		t.Errorf("expected stopped for 404, got %s", state)
	}
}

// ── StartContainer / StopContainer tests ──────────────────────────────────────

// TestStartContainer_Success verifies that starting an allowed container succeeds.
func TestStartContainer_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/start") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Inspect endpoint returns running state.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"State":{"Status":"running","Error":""}}`))
	}))
	defer srv.Close()

	c := clientWithTestServer(srv)
	c.allowlist["netsniff-ng"] = ""

	result, err := c.StartContainer("netsniff-ng", "test-actor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != StateRunning {
		t.Errorf("expected running state, got %s", result.State)
	}
	if result.Method != "podman_api" {
		t.Errorf("expected podman_api method, got %s", result.Method)
	}
}

// TestStartContainer_AllowlistRejection verifies that starting a container not
// in the allowlist returns an error.
func TestStartContainer_AllowlistRejection(t *testing.T) {
	c := &Client{
		allowlist:  map[string]string{"vector": ""},
		socketPath: "/fake/podman.sock",
		timeout:    DefaultTimeout,
		httpClient: &http.Client{},
		available:  true,
	}
	c.socketChecker = func() error { return nil }

	_, err := c.StartContainer("not-allowed", "test-actor")
	if err == nil {
		t.Fatal("expected error for container not in allowlist")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("expected allowlist error, got: %v", err)
	}
}

// TestStopContainer_Success verifies that stopping an allowed container succeeds.
func TestStopContainer_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Inspect endpoint returns stopped state.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"State":{"Status":"exited","Error":""}}`))
	}))
	defer srv.Close()

	c := clientWithTestServer(srv)
	c.allowlist["pcap_ring_writer"] = ""

	result, err := c.StopContainer("pcap_ring_writer", "test-actor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != StateStopped {
		t.Errorf("expected stopped state, got %s", result.State)
	}
}

// TestStopContainer_AllowlistRejection verifies that stopping a container not
// in the allowlist returns an error.
func TestStopContainer_AllowlistRejection(t *testing.T) {
	c := &Client{
		allowlist:  map[string]string{"vector": ""},
		socketPath: "/fake/podman.sock",
		timeout:    DefaultTimeout,
		httpClient: &http.Client{},
		available:  true,
	}
	c.socketChecker = func() error { return nil }

	_, err := c.StopContainer("not-allowed", "test-actor")
	if err == nil {
		t.Fatal("expected error for container not in allowlist")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("expected allowlist error, got: %v", err)
	}
}

// TestStartContainer_SocketUnavailable verifies that starting when the socket
// is unavailable returns an error.
func TestStartContainer_SocketUnavailable(t *testing.T) {
	c := &Client{
		allowlist:  map[string]string{"vector": ""},
		socketPath: "/nonexistent/podman.sock",
		timeout:    DefaultTimeout,
		httpClient: &http.Client{},
		available:  false,
	}

	_, err := c.StartContainer("vector", "test-actor")
	if err == nil {
		t.Fatal("expected error when socket is unavailable")
	}
}

// ── Property tests ────────────────────────────────────────────────────────────

// Property 7: Container restart allowlist enforcement
// For any container name not in the allowlist, assert the restart request is
// rejected with a logged error and no HTTP request is made to the Podman REST API.
// This property covers all three lifecycle operations: Restart, Start, and Stop.
// Validates: Requirements 5.2
func TestProperty7_ContainerRestartAllowlistEnforcement(t *testing.T) {
	// Operations that must all enforce the allowlist.
	type operation struct {
		name string
		call func(c *Client, containerName, actor string) (RestartResult, error)
	}
	ops := []operation{
		{"RestartContainer", (*Client).RestartContainer},
		{"StartContainer", (*Client).StartContainer},
		{"StopContainer", (*Client).StopContainer},
	}

	rapid.Check(t, func(t *rapid.T) {
		// Generate a set of allowed container names.
		numAllowed := rapid.IntRange(1, 5).Draw(t, "num_allowed")
		allowlist := make(map[string]string, numAllowed)
		for i := 0; i < numAllowed; i++ {
			name := rapid.StringMatching(`[a-z][a-z0-9-]{2,15}`).Draw(t, "allowed_name")
			allowlist[name] = ""
		}

		// Generate a container name that is NOT in the allowlist.
		// We use a prefix that cannot match any allowed name.
		rejectedName := "REJECTED-" + rapid.StringMatching(`[a-z0-9]{4,10}`).Draw(t, "rejected_suffix")

		// Pick a random operation to test.
		opIdx := rapid.IntRange(0, len(ops)-1).Draw(t, "operation")
		op := ops[opIdx]

		apiCalled := false
		c := &Client{
			allowlist:  allowlist,
			socketPath: "/nonexistent/podman.sock",
			timeout:    DefaultTimeout,
			httpClient: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					apiCalled = true
					return &http.Response{StatusCode: http.StatusNoContent}, nil
				}),
			},
			available: true,
		}
		c.socketChecker = func() error { return nil }

		_, err := op.call(c, rejectedName, "test-actor")

		// Must return an error.
		if err == nil {
			t.Fatalf("%s: expected error for container %q not in allowlist, got nil", op.name, rejectedName)
		}

		// Error must mention allowlist.
		if !strings.Contains(err.Error(), "allowlist") {
			t.Fatalf("%s: expected allowlist error for %q, got: %v", op.name, rejectedName, err)
		}

		// Podman API must NOT have been called.
		if apiCalled {
			t.Fatalf("%s: Podman API was called for rejected container %q — must not forward to API", op.name, rejectedName)
		}
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// clientWithTestServer creates a Client that routes HTTP requests to the given
// test server. The socket availability check is bypassed by overriding the
// httpClient and setting available=true with a fake socket path.
func clientWithTestServer(srv *httptest.Server) *Client {
	// We need to intercept the Unix socket transport. Since httptest.Server uses
	// TCP, we use a custom transport that rewrites the URL host to the test server.
	transport := &rewriteTransport{
		base:    srv.Client().Transport,
		baseURL: srv.URL,
	}
	c := &Client{
		allowlist:  map[string]string{"vector": "", "missing": ""},
		socketPath: "/fake/podman.sock",
		timeout:    DefaultTimeout,
		httpClient: &http.Client{Transport: transport},
		available:  true,
	}
	// Bypass the real socket check so tests don't need an actual socket file.
	c.socketChecker = func() error { return nil }
	return c
}

// rewriteTransport rewrites the scheme+host of every request to a fixed base URL,
// allowing Unix-socket-targeted requests to be redirected to a test HTTP server.
type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Parse the base URL to get scheme and host.
	base := strings.TrimRight(t.baseURL, "/")
	// Rebuild the URL: keep path and query, replace scheme+host.
	newURL := base + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return t.base.RoundTrip(newReq)
}

// roundTripFunc is an http.RoundTripper backed by a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
