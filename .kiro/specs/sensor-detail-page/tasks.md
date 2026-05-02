# Implementation Plan: Sensor Detail Page

## Overview

This plan implements a dedicated Sensor Pod detail page at `/sensors/:id` for the RavenWire Config Manager. The implementation builds incrementally: first the pure formatting module, then the Health Registry PubSub extension, then the SensorAgentClient extensions, then the LiveView with section components, then the router and dashboard wiring, and finally the action dispatch logic. Each step produces testable, integrated code.

## Tasks

- [ ] 1. Implement the Formatters module
  - [ ] 1.1 Create `lib/config_manager_web/formatters.ex` with pure formatting functions
    - Implement `format_bytes/1` (nil → "—", 0 → "0 B", scales through KB/MB/GB/TB)
    - Implement `format_throughput/1` (nil → "—", scales through bps/Kbps/Mbps/Gbps)
    - Implement `format_utc/1` and `format_utc_from_unix_ms/1` (nil → "—", DateTime → "YYYY-MM-DD HH:MM:SS UTC")
    - Implement `format_relative_age/1` (nil → "—", past DateTime → "N seconds/minutes/hours/days ago")
    - Implement `cert_status/1` (nil → :unknown, expired/expiring_soon/valid classification with 30-day threshold)
    - Implement `format_uptime/1` (nil → "—", seconds → "Xd Yh Zm" format)
    - Implement `display/1` (nil or "" → "—", otherwise string representation)
    - _Requirements: 2.2, 2.3, 2.4, 2.6, 5.5, 6.2_

  - [ ]* 1.2 Write property tests for Formatters (PropCheck)
    - **Property 1: Byte formatting produces valid human-readable output**
    - **Property 2: Throughput formatting produces valid human-readable output**
    - **Property 3: Certificate status classification is correct and complete**
    - **Property 4: Nil-safe display returns dash for absent values**
    - **Property 5: UTC timestamp formatting always includes timezone indicator**
    - **Property 6: Relative age produces human-readable past-tense text**
    - Create `test/config_manager_web/formatters_prop_test.exs`
    - **Validates: Requirements 2.2, 2.3, 2.4, 2.6, 5.5, 6.2**

  - [ ]* 1.3 Write unit tests for Formatters
    - Create `test/config_manager_web/formatters_test.exs`
    - Test specific edge cases: 0 bytes, boundary values (1024, 1_048_576), negative throughput, nil inputs
    - Test format_uptime with 0s, 59s, 3600s, 86400s, nil
    - Test cert_status with expired, 29-day, 31-day, nil
    - _Requirements: 14.7_

- [ ] 2. Extend Health Registry with pod-scoped PubSub
  - [ ] 2.1 Add pod-scoped PubSub broadcasts to `lib/config_manager/health/registry.ex`
    - Add `pod_topic/1` function: `"sensor_pod:#{health_key}"`
    - Update `handle_cast({:update, ...})` to broadcast `{:pod_updated, health_key}` to both `"sensor_pods"` and `pod_topic(health_key)`
    - Update degradation checks (`check_clock_drift`, `check_bpf_restart_pending`) to broadcast `{:pod_degraded, ...}` and `{:pod_recovered, ...}` to both topics
    - Expose `get_degraded_pods/0` or `get_degradation_reasons/1` for initial page load
    - _Requirements: 9.1, 9.2, 9.5, 11.1, 11.3_

  - [ ]* 2.2 Write unit tests for pod-scoped PubSub
    - Test that updating a pod broadcasts to both fleet-wide and pod-specific topics
    - Test that degradation/recovery events broadcast to pod-specific topic
    - Test that subscribing to pod_topic only receives messages for that pod
    - **Property 15: Pod-scoped PubSub ignores unrelated updates**
    - **Validates: Requirements 9.1, 9.2, 9.5, 14.3**

- [ ] 3. Extend SensorAgentClient with new action functions
  - [ ] 3.1 Add new control API functions to `lib/config_manager/sensor_agent_client.ex`
    - Implement `validate_config/1` — POST `/control/config/validate`
    - Implement `reload_zeek/1` — POST `/control/reload/zeek`
    - Implement `reload_suricata/1` — POST `/control/reload/suricata`
    - Implement `restart_vector/1` — POST `/control/restart/vector`
    - Follow existing pattern: check `control_api_host`, build Finch request, handle response codes, decode JSON, return sanitized error tuples
    - Return `{:error, :no_control_api_host}` when `control_api_host` is nil
    - _Requirements: 10.4, 10.14_

  - [ ]* 3.2 Write unit tests for new SensorAgentClient functions
    - Test success path for each new function
    - Test HTTP error handling
    - Test `no_control_api_host` error when control_api_host is nil
    - _Requirements: 14.4_

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement the SensorDetailLive LiveView and section components
  - [ ] 5.1 Create `lib/config_manager_web/live/sensor_detail_live.ex` — main LiveView
    - Implement `mount/3`: load SensorPod from DB by ID, handle 404, derive `health_key` from `pod.name`, read health from Registry, read degradation reasons, subscribe to `pod_topic(health_key)` when connected
    - Implement `handle_info({:pod_updated, _}, socket)`: re-read health from Registry, update assigns
    - Implement `handle_info({:pod_degraded, _, reason, _}, socket)` and `handle_info({:pod_recovered, _, reason}, socket)`: update degradation_reasons assign
    - Implement `render/1`: delegate to section components in stable order (degradation, identity, host readiness, containers, capture, storage, clock, forwarding, actions)
    - Define `@action_permissions` and `@action_audit_names` module attributes
    - Assign `stale_threshold_sec` (default 60) and `action_timeout_ms` (default 30_000)
    - _Requirements: 1.1, 1.2, 1.3, 9.1, 9.2, 9.3, 9.4, 9.5, 12.1, 12.2, 13.1_

  - [ ] 5.2 Create `lib/config_manager_web/live/sensor_detail_live/degradation_component.ex`
    - Render degradation summary banner when `degradation_reasons` is non-empty
    - Hide banner when no active degradation reasons
    - Group duplicate reasons and show most recent timestamp
    - Use semantic HTML with `aria-label`
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 13.3, 13.4_

  - [ ] 5.3 Create `lib/config_manager_web/live/sensor_detail_live/identity_component.ex`
    - Display: name, UUID, pool_id, cert_serial, cert_expires_at, enrolled_at, enrolled_by, last_seen_at, status, control_api_host
    - Apply cert expiration highlighting (expired = red, expiring_soon = yellow) using `cert_status/1`
    - Display timestamps with `format_utc/1` and relative age with `format_relative_age/1`
    - Use `display/1` for nil-safe field rendering
    - Never render secret fields (PEM, keys, tokens)
    - _Requirements: 1.7, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 13.3, 13.4_

  - [ ] 5.4 Create `lib/config_manager_web/live/sensor_detail_live/host_readiness_component.ex`
    - When host readiness data present: display interface name, NIC driver, kernel version, AF_PACKET support, disk capacity, time sync state
    - When absent: display "Host readiness data is not yet available from the Sensor Agent"
    - Highlight AF_PACKET unavailable as warning
    - Display individual readiness checks with name, severity, observed/required values, pass/fail
    - Include hard check failures in degradation summary data
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 13.3, 13.4_

  - [ ] 5.5 Create `lib/config_manager_web/live/sensor_detail_live/container_component.ex`
    - Render a row per container: name, state (color-coded badge), uptime, CPU%, memory
    - Color badges: green=running, red=error, yellow=restarting, gray=stopped
    - Highlight CPU > 90% as warning
    - Show "No container data is available" when no container data
    - Always show expected containers (zeek, suricata, vector, pcap_ring_writer); mark as "missing" if absent from HealthReport
    - Conditionally show optional containers (strelka, netsniff-ng) only when present
    - Use semantic table with `<th>`/`<td>` and `aria-label`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 13.3, 13.4_

  - [ ] 5.6 Create `lib/config_manager_web/live/sensor_detail_live/capture_component.ex`
    - Render a row per capture consumer: name, packets received, packets dropped, drop%, throughput (formatted), BPF restart pending
    - Highlight drop% > 5% as critical
    - Show BPF restart pending indicator when true
    - Show "No capture data is available" when no capture data
    - Format throughput with `format_throughput/1`
    - Never show negative rates
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 13.3, 13.4_

  - [ ] 5.7 Create `lib/config_manager_web/live/sensor_detail_live/storage_component.ex`
    - Display PCAP path, total/used/available bytes (formatted), used%
    - Format bytes with `format_bytes/1`
    - Highlight used% > 85% as warning, > 95% as critical
    - Show "No storage data is available" when no health storage data
    - Always display DB PCAP config: ring_size_mb, pre_alert_window_sec, post_alert_window_sec, alert_severity_threshold
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 13.3, 13.4_

  - [ ] 5.8 Create `lib/config_manager_web/live/sensor_detail_live/clock_component.ex`
    - Display clock offset (ms), NTP sync status, NTP/PTP source
    - Highlight offset exceeding drift threshold (default 100ms) as degraded
    - Highlight NTP sync false as warning
    - Show "Clock data is not available" when no clock data
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 13.3, 13.4_

  - [ ] 5.9 Create `lib/config_manager_web/live/sensor_detail_live/forwarding_component.ex`
    - Display Vector sink status, queue/buffer usage, destination health
    - Show "Forwarding data is not yet available from the Sensor Agent" when absent
    - Highlight unhealthy/disconnected sinks as critical
    - Redact secrets/tokens/credentials; display non-secret destination labels
    - Highlight buffer > 85% as warning, > 95% as critical
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 13.3, 13.4_

  - [ ] 5.10 Create `lib/config_manager_web/live/sensor_detail_live/actions_component.ex`
    - Render action buttons: Validate Config, Reload Zeek, Reload Suricata, Restart Vector, Generate Support Bundle, Revoke Sensor
    - Show buttons only when user has required permission (pass `current_user` and `action_permissions` as assigns)
    - Disable Control API buttons when `control_api_host` is nil; show "Sensor agent is not reachable" message
    - Hide entire Actions section when pod status is "revoked"
    - Hide Control API buttons when pod status is "pending"
    - Show loading indicator and disable button when action is in-flight
    - Revoke button triggers confirmation dialog before dispatch
    - All buttons have accessible names (`aria-label`)
    - _Requirements: 10.1, 10.2, 10.5, 10.7, 10.11, 10.14, 10.15, 12.3, 12.4, 13.3_

- [ ] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement action dispatch and audit logging in SensorDetailLive
  - [ ] 7.1 Implement `handle_event("action", ...)` in SensorDetailLive
    - Server-side RBAC check via `AuthHelpers.authorize(socket, permission)` before any dispatch
    - On RBAC denial: flash error, create `permission_denied` audit entry, no dispatch
    - On RBAC success: mark action as in-flight, dispatch via `start_async/3` or Task.Supervisor with configurable timeout
    - Map action names to SensorAgentClient functions (validate_config, reload_zeek, reload_suricata, restart_vector, support_bundle)
    - Handle revoke action locally: update SensorPod status to "revoked", update CRL, audit log — no Control API call
    - _Requirements: 10.4, 10.5, 10.6, 10.14, 10.15_

  - [ ] 7.2 Implement async result handling in SensorDetailLive
    - Implement `handle_async/3` (or Task result handlers): clear in-flight state, flash success/error
    - On success: flash success with action name and sanitized result, create audit entry with canonical name and `result: "success"`
    - On failure: flash error with action name and sanitized error reason, create audit entry with canonical name and `result: "failure"`
    - On timeout (30s default): treat as failure with "Action timed out" message
    - Sanitize results: strip secrets, PEM headers, tokens from flash and audit detail
    - _Requirements: 10.7, 10.8, 10.9, 10.10, 10.12, 10.13_

  - [ ] 7.3 Implement revoke confirmation flow
    - `handle_event("action", %{"action" => "revoke"}, socket)` sets a `confirm_revoke` assign to show confirmation dialog
    - `handle_event("confirm_revoke", _, socket)` performs the actual revocation
    - `handle_event("cancel_revoke", _, socket)` clears the confirmation state
    - Revoke updates `sensor_pods.status` to "revoked" in DB, does NOT call SensorAgentClient
    - Audit entry with `sensor_revoke` canonical name
    - _Requirements: 10.11, 10.14, 10.15_

- [ ] 8. Wire up router and dashboard navigation
  - [ ] 8.1 Add `/sensors/:id` route to `lib/config_manager_web/router.ex`
    - Add `live "/sensors/:id", SensorDetailLive, :show` inside the authenticated `live_session` block
    - Set `private: %{required_permission: "sensors:view"}` for route-level RBAC
    - Ensure all authenticated users can access (sensors:view is available to all roles)
    - _Requirements: 1.1, 1.6_

  - [ ] 8.2 Update dashboard with clickable sensor links
    - Modify `lib/config_manager_web/live/dashboard_live.ex` to include clickable links on each pod row
    - Link navigates to `/sensors/:id` using the database UUID
    - Add `aria-label` for accessibility on each link
    - _Requirements: 1.4_

  - [ ] 8.3 Add back-navigation link in SensorDetailLive
    - Include a link back to the dashboard (`/`) in the detail page layout
    - _Requirements: 1.5_

- [ ] 9. Implement offline sensor and stale data handling
  - [ ] 9.1 Add status banners and stale data warnings to SensorDetailLive
    - When Health Registry has no HealthReport: show "not currently reporting health data" banner
    - When HealthReport timestamp > stale_threshold_sec old: show stale data warning with time since last report
    - When pod status is "revoked": show revoked banner, hide Actions section
    - When pod status is "pending": show pending enrollment banner, hide Control API action buttons
    - Display timestamp of most recent HealthReport for freshness indication
    - _Requirements: 9.4, 9.6, 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Write LiveView integration tests
  - [ ]* 11.1 Write route and rendering tests
    - Create `test/config_manager_web/live/sensor_detail_live_test.exs`
    - Test existing pod returns 200 with identity data
    - Test non-existent pod returns 404
    - Test pending, enrolled, revoked pods all render with appropriate banners
    - Test dashboard contains clickable link to `/sensors/:id`
    - Test detail page contains back link to dashboard
    - Test sections render in stable order
    - Test empty states for each section when health data is nil
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 12.1, 12.3, 12.4, 13.1, 14.1, 14.4**

  - [ ]* 11.2 Write PubSub and real-time update tests
    - Test page subscribes to pod-specific PubSub topic on mount
    - Test page updates health sections when matching PubSub message received
    - Test page ignores PubSub messages for other pods
    - Test degradation banner appears/disappears with PubSub events
    - Test stale data warning appears when HealthReport timestamp exceeds threshold
    - **Property 15: Pod-scoped PubSub ignores unrelated updates**
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.5, 11.3, 14.2, 14.3**

  - [ ]* 11.3 Write RBAC and action tests
    - Test each action button visible only when user has required permission
    - Test each action event rejected server-side when user lacks permission
    - Test `permission_denied` audit entry created on RBAC denial
    - Test action success creates audit entry with canonical name
    - Test action failure creates audit entry with canonical name and failure result
    - Test action timeout handling (30s)
    - Test revoke confirmation dialog flow
    - Test revoke does not call SensorAgentClient
    - Test Control API buttons disabled when no control_api_host
    - **Property 8: RBAC enforcement is consistent between UI visibility and server-side checks**
    - **Property 9: Every authorized action dispatch produces a structurally complete audit entry**
    - **Validates: Requirements 10.1–10.15, 14.5, 14.6**

  - [ ]* 11.4 Write property tests for LiveView rendering
    - Create `test/config_manager_web/live/sensor_detail_live_prop_test.exs`
    - **Property 7: Secret fields are never present in rendered detail page HTML**
    - **Property 9a: Revoke does not require Control API reachability**
    - **Property 10: Storage and buffer threshold highlighting is correct**
    - **Property 11: Container section renders all expected containers and flags missing ones**
    - **Property 12: Capture consumer section renders all consumers with correct drop highlighting**
    - **Property 13: Degradation banner displays all active reasons**
    - **Property 14: Stale health data triggers a warning based on configurable threshold**
    - **Validates: Requirements 1.7, 4.1, 4.6, 5.1, 5.2, 6.3, 6.4, 8.5, 11.1, 11.2, 12.2, 14.4, 14.7, 14.8**

  - [ ]* 11.5 Write accessibility tests
    - Verify all action buttons have accessible names (aria-label or visible text)
    - Verify warning/critical states include text indicators (not color alone)
    - Verify semantic table structure with `<th>`/`<td>`
    - Verify sections have `aria-label` attributes
    - **Validates: Requirements 13.2, 13.3, 13.4, 13.5, 14.8**

- [ ] 12. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design uses Elixir/Phoenix LiveView — all code examples use Elixir
- No new dependencies are needed (PropCheck, Floki, Phoenix.LiveViewTest already available)
- No database schema changes are required
