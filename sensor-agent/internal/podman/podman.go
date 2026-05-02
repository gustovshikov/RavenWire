// Package podman provides a client for the Podman REST API over a Unix socket,
// used by Sensor_Agent to manage container lifecycle.
//
// The client enforces an explicit allowlist of container names, prefers
// systemctl restart on Quadlet-generated systemd units, and falls back to
// the Podman REST API when no unit can be resolved.
package podman

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ravenwire/ravenwire/sensor-agent/internal/audit"
)

// DefaultTimeout is the default timeout for Podman API requests.
const DefaultTimeout = 60 * time.Second

// ContainerState represents the running state of a container.
type ContainerState string

const (
	StateRunning ContainerState = "running"
	StateStopped ContainerState = "stopped"
	StateError   ContainerState = "error"
	StateUnknown ContainerState = "unknown"
)

// RestartResult holds the outcome of a container restart operation.
type RestartResult struct {
	ContainerName string         `json:"container_name"`
	State         ContainerState `json:"state"`
	Method        string         `json:"method"` // "systemctl" or "podman_api"
}

// Client is a Podman REST API client that operates over a Unix socket.
type Client struct {
	socketPath    string
	allowlist     map[string]string // container name → quadlet unit name (empty if none)
	timeout       time.Duration
	auditLog      *audit.Logger
	httpClient    *http.Client
	available     bool // whether the socket was accessible at startup
	socketChecker func() error // injectable for testing; defaults to checkSocket
}

// Config holds configuration for the Podman client.
type Config struct {
	// SocketPath is the path to the Podman Unix socket.
	// Defaults to /run/podman/podman.sock.
	SocketPath string

	// Allowlist maps container names to their Quadlet unit names.
	// A container name with an empty unit name will use the Podman API directly.
	// Only containers in this map may be restarted.
	Allowlist map[string]string

	// Timeout is the timeout for Podman API requests. Defaults to DefaultTimeout.
	Timeout time.Duration

	// AuditLog is the audit logger. May be nil (no audit logging).
	AuditLog *audit.Logger
}

// New creates a new Podman client and checks socket accessibility at startup.
// If the socket is not accessible, a warning is logged and the client is
// returned in a degraded state; restart attempts will return errors until
// the socket becomes accessible.
func New(cfg Config) *Client {
	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = "/run/podman/podman.sock"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	allowlist := cfg.Allowlist
	if allowlist == nil {
		allowlist = make(map[string]string)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	httpClient := &http.Client{Transport: transport}

	c := &Client{
		socketPath: socketPath,
		allowlist:  allowlist,
		timeout:    timeout,
		auditLog:   cfg.AuditLog,
		httpClient: httpClient,
	}
	c.socketChecker = c.checkSocket

	// Check socket accessibility at startup (Requirement 5.7).
	if err := c.checkSocket(); err != nil {
		log.Printf("podman: WARNING: Podman socket %s is not accessible at startup: %v", socketPath, err)
		log.Printf("podman: container restart actions will return errors until the socket becomes accessible")
		c.available = false
	} else {
		log.Printf("podman: Podman socket %s is accessible", socketPath)
		c.available = true
	}

	return c
}

// NewForTest creates a Podman client for testing with an injected HTTP client
// and the socket check bypassed. The client is always marked as available.
func NewForTest(cfg Config, httpClient *http.Client) *Client {
	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = "/run/podman/podman.sock"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	allowlist := cfg.Allowlist
	if allowlist == nil {
		allowlist = make(map[string]string)
	}

	c := &Client{
		socketPath: socketPath,
		allowlist:  allowlist,
		timeout:    timeout,
		auditLog:   cfg.AuditLog,
		httpClient: httpClient,
		available:  true,
	}
	c.socketChecker = func() error { return nil }
	return c
}

// checkSocket verifies the Podman socket is accessible by attempting a stat.
func (c *Client) checkSocket() error {
	info, err := os.Stat(c.socketPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", c.socketPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", c.socketPath)
	}
	return nil
}

// isSocketAvailable re-checks socket accessibility on each call.
func (c *Client) isSocketAvailable() bool {
	checker := c.socketChecker
	if checker == nil {
		checker = c.checkSocket
	}
	if err := checker(); err != nil {
		return false
	}
	return true
}

// RestartContainer restarts the named container.
//
// It enforces the allowlist (Requirement 5.2), prefers systemctl restart on
// the Quadlet unit when one is configured (Requirement 5.6), falls back to
// the Podman REST API, queries the post-restart state (Requirement 5.4), and
// logs audit events with the requesting actor identity (Requirement 5.5).
func (c *Client) RestartContainer(containerName, actor string) (RestartResult, error) {
	// Allowlist check (Requirement 5.2).
	unitName, allowed := c.allowlist[containerName]
	if !allowed {
		log.Printf("podman: REJECTED restart request for container %q: not in allowlist (actor=%s)", containerName, actor)
		if c.auditLog != nil {
			c.auditLog.Log("container-restart-rejected", actor, "failure", map[string]any{
				"container": containerName,
				"reason":    "not in allowlist",
			})
		}
		return RestartResult{}, fmt.Errorf("container %q is not in the restart allowlist", containerName)
	}

	// Socket availability check (Requirement 5.7).
	if !c.isSocketAvailable() {
		log.Printf("podman: ERROR: Podman socket %s is not accessible; cannot restart %q", c.socketPath, containerName)
		if c.auditLog != nil {
			c.auditLog.Log("container-restart-attempted", actor, "failure", map[string]any{
				"container": containerName,
				"reason":    "podman socket not accessible",
			})
		}
		return RestartResult{}, fmt.Errorf("podman socket %s is not accessible", c.socketPath)
	}

	// Log the restart request (Requirement 5.5).
	log.Printf("podman: restart requested for container %q by actor %q", containerName, actor)
	if c.auditLog != nil {
		c.auditLog.Log("container-restart-requested", actor, "accepted", map[string]any{
			"container": containerName,
		})
	}

	var (
		result RestartResult
		err    error
	)
	result.ContainerName = containerName

	// Prefer systemctl restart on Quadlet unit (Requirement 5.6).
	if unitName != "" {
		result, err = c.restartViaSystemctl(containerName, unitName, actor)
	} else {
		result, err = c.restartViaPodmanAPI(containerName, actor)
	}

	if err != nil {
		if c.auditLog != nil {
			c.auditLog.Log("container-restart-completed", actor, "failure", map[string]any{
				"container": containerName,
				"error":     err.Error(),
			})
		}
		return result, err
	}

	// Query post-restart state (Requirement 5.4).
	state, stateErr := c.GetContainerState(containerName)
	if stateErr != nil {
		log.Printf("podman: WARNING: could not query state of %q after restart: %v", containerName, stateErr)
		state = StateUnknown
	}
	result.State = state

	// Log the resulting state (Requirement 5.5).
	log.Printf("podman: container %q restarted via %s; post-restart state: %s (actor=%s)",
		containerName, result.Method, state, actor)
	if c.auditLog != nil {
		c.auditLog.Log("container-restart-completed", actor, "success", map[string]any{
			"container": containerName,
			"method":    result.Method,
			"state":     string(state),
		})
	}

	return result, nil
}

// restartViaSystemctl issues `systemctl restart <unit>` (Requirement 5.6).
// Falls back to the Podman API if systemctl fails.
func (c *Client) restartViaSystemctl(containerName, unitName, actor string) (RestartResult, error) {
	log.Printf("podman: restarting %q via systemctl unit %q", containerName, unitName)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "restart", unitName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("podman: systemctl restart %q failed: %v (%s); falling back to Podman API", unitName, err, strings.TrimSpace(string(out)))
		// Fall back to Podman API (Requirement 5.6).
		return c.restartViaPodmanAPI(containerName, actor)
	}

	return RestartResult{
		ContainerName: containerName,
		Method:        "systemctl",
	}, nil
}

// restartViaPodmanAPI issues a POST /containers/{name}/restart to the Podman REST API
// over the configured Unix socket (Requirement 5.1).
func (c *Client) restartViaPodmanAPI(containerName, actor string) (RestartResult, error) {
	log.Printf("podman: restarting %q via Podman REST API", containerName)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	url := fmt.Sprintf("http://d/v4.0.0/containers/%s/restart", containerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return RestartResult{}, fmt.Errorf("build restart request: %w", err)
	}

	// Include X-Request-ID for correlation (Requirement 6.5).
	req.Header.Set("X-Request-ID", c.generateRequestID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return RestartResult{}, fmt.Errorf("podman restart %q: %w", containerName, err)
	}
	defer resp.Body.Close()

	// Podman returns 204 No Content on success.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return RestartResult{}, fmt.Errorf("podman restart %q: unexpected status %d", containerName, resp.StatusCode)
	}

	return RestartResult{
		ContainerName: containerName,
		Method:        "podman_api",
	}, nil
}

// generateRequestID creates a unique request ID for outbound Podman API calls
// (Requirement 6.5). Uses timestamp + random bytes for uniqueness.
func (c *Client) generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%d-%x", time.Now().UnixNano(), b)
}

// podmanContainerInspect is the subset of the Podman inspect response we care about.
type podmanContainerInspect struct {
	State struct {
		Status string `json:"Status"`
		Error  string `json:"Error"`
	} `json:"State"`
}

// GetContainerState queries the Podman API for the current state of a container
// (Requirement 5.4). Returns StateUnknown if the container cannot be inspected.
func (c *Client) GetContainerState(containerName string) (ContainerState, error) {
	if !c.isSocketAvailable() {
		return StateUnknown, fmt.Errorf("podman socket not accessible")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	url := fmt.Sprintf("http://d/v4.0.0/containers/%s/json", containerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return StateUnknown, fmt.Errorf("build inspect request: %w", err)
	}

	// Include X-Request-ID for correlation (Requirement 6.5).
	req.Header.Set("X-Request-ID", c.generateRequestID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return StateUnknown, fmt.Errorf("podman inspect %q: %w", containerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return StateStopped, nil
	}
	if resp.StatusCode != http.StatusOK {
		return StateUnknown, fmt.Errorf("podman inspect %q: unexpected status %d", containerName, resp.StatusCode)
	}

	var info podmanContainerInspect
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return StateUnknown, fmt.Errorf("decode inspect response: %w", err)
	}

	switch strings.ToLower(info.State.Status) {
	case "running":
		return StateRunning, nil
	case "exited", "stopped", "dead":
		return StateStopped, nil
	case "error":
		return StateError, nil
	default:
		return StateUnknown, nil
	}
}

// StartContainer starts the named container via the Podman REST API.
//
// It enforces the allowlist, verifies socket availability, and logs audit events.
// Returns the post-start container state.
func (c *Client) StartContainer(containerName, actor string) (RestartResult, error) {
	// Allowlist check.
	_, allowed := c.allowlist[containerName]
	if !allowed {
		log.Printf("podman: REJECTED start request for container %q: not in allowlist (actor=%s)", containerName, actor)
		if c.auditLog != nil {
			c.auditLog.Log("container-start-rejected", actor, "failure", map[string]any{
				"container": containerName,
				"reason":    "not in allowlist",
			})
		}
		return RestartResult{}, fmt.Errorf("container %q is not in the restart allowlist", containerName)
	}

	// Socket availability check.
	if !c.isSocketAvailable() {
		log.Printf("podman: ERROR: Podman socket %s is not accessible; cannot start %q", c.socketPath, containerName)
		if c.auditLog != nil {
			c.auditLog.Log("container-start-attempted", actor, "failure", map[string]any{
				"container": containerName,
				"reason":    "podman socket not accessible",
			})
		}
		return RestartResult{}, fmt.Errorf("podman socket %s is not accessible", c.socketPath)
	}

	log.Printf("podman: start requested for container %q by actor %q", containerName, actor)
	if c.auditLog != nil {
		c.auditLog.Log("container-start-requested", actor, "accepted", map[string]any{
			"container": containerName,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	url := fmt.Sprintf("http://d/v4.0.0/containers/%s/start", containerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return RestartResult{}, fmt.Errorf("build start request: %w", err)
	}

	// Include X-Request-ID for correlation (Requirement 6.5).
	req.Header.Set("X-Request-ID", c.generateRequestID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return RestartResult{}, fmt.Errorf("podman start %q: %w", containerName, err)
	}
	defer resp.Body.Close()

	// Podman returns 204 on success, 304 if already started.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return RestartResult{}, fmt.Errorf("podman start %q: unexpected status %d", containerName, resp.StatusCode)
	}

	// Query post-start state.
	state, stateErr := c.GetContainerState(containerName)
	if stateErr != nil {
		log.Printf("podman: WARNING: could not query state of %q after start: %v", containerName, stateErr)
		state = StateUnknown
	}

	result := RestartResult{
		ContainerName: containerName,
		State:         state,
		Method:        "podman_api",
	}

	log.Printf("podman: container %q started; post-start state: %s (actor=%s)", containerName, state, actor)
	if c.auditLog != nil {
		c.auditLog.Log("container-start-completed", actor, "success", map[string]any{
			"container": containerName,
			"state":     string(state),
		})
	}

	return result, nil
}

// StopContainer stops the named container via the Podman REST API.
//
// It enforces the allowlist, verifies socket availability, and logs audit events.
// Returns the post-stop container state.
func (c *Client) StopContainer(containerName, actor string) (RestartResult, error) {
	// Allowlist check.
	_, allowed := c.allowlist[containerName]
	if !allowed {
		log.Printf("podman: REJECTED stop request for container %q: not in allowlist (actor=%s)", containerName, actor)
		if c.auditLog != nil {
			c.auditLog.Log("container-stop-rejected", actor, "failure", map[string]any{
				"container": containerName,
				"reason":    "not in allowlist",
			})
		}
		return RestartResult{}, fmt.Errorf("container %q is not in the restart allowlist", containerName)
	}

	// Socket availability check.
	if !c.isSocketAvailable() {
		log.Printf("podman: ERROR: Podman socket %s is not accessible; cannot stop %q", c.socketPath, containerName)
		if c.auditLog != nil {
			c.auditLog.Log("container-stop-attempted", actor, "failure", map[string]any{
				"container": containerName,
				"reason":    "podman socket not accessible",
			})
		}
		return RestartResult{}, fmt.Errorf("podman socket %s is not accessible", c.socketPath)
	}

	log.Printf("podman: stop requested for container %q by actor %q", containerName, actor)
	if c.auditLog != nil {
		c.auditLog.Log("container-stop-requested", actor, "accepted", map[string]any{
			"container": containerName,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	url := fmt.Sprintf("http://d/v4.0.0/containers/%s/stop", containerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return RestartResult{}, fmt.Errorf("build stop request: %w", err)
	}

	// Include X-Request-ID for correlation (Requirement 6.5).
	req.Header.Set("X-Request-ID", c.generateRequestID())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return RestartResult{}, fmt.Errorf("podman stop %q: %w", containerName, err)
	}
	defer resp.Body.Close()

	// Podman returns 204 on success, 304 if already stopped.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return RestartResult{}, fmt.Errorf("podman stop %q: unexpected status %d", containerName, resp.StatusCode)
	}

	// Query post-stop state.
	state, stateErr := c.GetContainerState(containerName)
	if stateErr != nil {
		log.Printf("podman: WARNING: could not query state of %q after stop: %v", containerName, stateErr)
		state = StateUnknown
	}

	result := RestartResult{
		ContainerName: containerName,
		State:         state,
		Method:        "podman_api",
	}

	log.Printf("podman: container %q stopped; post-stop state: %s (actor=%s)", containerName, state, actor)
	if c.auditLog != nil {
		c.auditLog.Log("container-stop-completed", actor, "success", map[string]any{
			"container": containerName,
			"state":     string(state),
		})
	}

	return result, nil
}

// IsAllowed returns true if the container name is in the allowlist.
func (c *Client) IsAllowed(containerName string) bool {
	_, ok := c.allowlist[containerName]
	return ok
}

// SocketPath returns the configured socket path.
func (c *Client) SocketPath() string {
	return c.socketPath
}
