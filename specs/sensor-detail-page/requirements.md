# Requirements Document: Sensor Detail Page

## Introduction

The RavenWire Config Manager dashboard currently lists all connected Sensor Pods with container state, uptime, CPU/memory, capture consumer packet/drop stats, and clock status. This fleet-level view answers "what is unhealthy?" but does not answer "why is it unhealthy?" There is no way to click into a single sensor and see its full identity, host readiness, per-container detail, capture pipeline state, storage health, forwarding status, or trigger operational actions.

This feature adds a dedicated Sensor Pod detail page at `/sensors/:id` that consolidates all available information about a single sensor into one view. The page combines persisted identity data from the `sensor_pods` database table with real-time health data from the in-memory Health Registry (fed by the gRPC health stream). It also provides action buttons for common operational tasks dispatched to the Sensor Agent control API. The page is accessible to all authenticated users for read-only viewing, with action buttons gated by RBAC permissions from the auth-rbac-audit spec.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Pod**: A deployed sensor instance with an identity record in the `sensor_pods` database table and real-time health state in the Health_Registry.
- **Health_Registry**: The in-memory ETS-backed GenServer (`ConfigManager.Health.Registry`) that stores the latest `HealthReport` for each connected Sensor_Pod.
- **HealthReport**: A protobuf message streamed from the Sensor_Agent to the Config_Manager via gRPC, containing container health, capture stats, storage stats, and clock stats.
- **Sensor_Agent**: The Go process running on each sensor host that streams health data and accepts control commands via its control API.
- **Control_API**: The HTTP API exposed by each Sensor_Agent for receiving operational commands (reload, restart, validate, bundle generation).
- **Detail_Page**: The LiveView page at `/sensors/:id` that displays all information about a single Sensor_Pod.
- **Identity_Section**: The portion of the Detail_Page showing persisted Sensor_Pod fields: name, UUID, pool, certificate serial, certificate expiration, enrollment time, and last seen timestamp.
- **Container_Section**: The portion of the Detail_Page showing per-container health: name, state, uptime, CPU percent, and memory usage for Zeek, Suricata, Vector, pcap_ring_writer, Strelka submitter, and netsniff-ng.
- **Capture_Section**: The portion of the Detail_Page showing capture pipeline state: per-consumer packet/drop counters, drop percentage, throughput, and BPF restart pending status.
- **Storage_Section**: The portion of the Detail_Page showing storage health: PCAP path, total/used/available bytes, and used percentage.
- **Forwarding_Section**: The portion of the Detail_Page showing Vector sink status, queue/buffer usage, and destination health.
- **Actions_Section**: The portion of the Detail_Page containing operational action buttons dispatched to the Sensor_Agent Control_API.
- **Action_Permission_Map**: The mapping from each Detail_Page action to the RBAC Permission required to execute it.
- **Stale_HealthReport**: A HealthReport whose timestamp is older than the configured freshness threshold, defaulting to 60 seconds.
- **RBAC_Gate**: The runtime permission check that compares the current user's role permissions against the permission required by a route or action, as defined in the auth-rbac-audit spec.

## Requirements

### Requirement 1: Sensor Detail Route and Navigation

**User Story:** As a sensor operator, I want to click on a sensor in the dashboard and navigate to a dedicated detail page, so that I can see everything about that sensor in one place.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Detail_Page at the route `/sensors/:id` where `:id` is the Sensor_Pod database identifier.
2. WHEN an authenticated user navigates to `/sensors/:id` for an existing Sensor_Pod with status pending, enrolled, or revoked, THE Detail_Page SHALL render with all available identity and health data for that Sensor_Pod.
3. WHEN an authenticated user navigates to `/sensors/:id` for a non-existent Sensor_Pod identifier, THE Detail_Page SHALL display a 404 Not Found page with a message indicating the sensor was not found.
4. THE Config_Manager SHALL add a clickable link on each Sensor_Pod row in the dashboard that navigates to `/sensors/:id` for that pod.
5. THE Detail_Page SHALL include a navigation link back to the dashboard.
6. THE Detail_Page SHALL be accessible to all authenticated users regardless of role for read-only viewing.
7. THE Detail_Page SHALL NOT expose raw certificate PEM, private keys, enrollment tokens, API tokens, or other secret values in any rendered section.

### Requirement 2: Identity Section

**User Story:** As a sensor operator, I want to see the full identity and enrollment details of a sensor, so that I can verify its certificate status and pool membership.

#### Acceptance Criteria

1. THE Identity_Section SHALL display the following fields from the Sensor_Pod database record: name, database identifier (UUID), pool identifier, certificate serial number, certificate expiration timestamp, enrollment timestamp, enrolled-by value, and last-seen timestamp.
2. WHEN the Sensor_Pod certificate expiration timestamp is in the past, THE Identity_Section SHALL visually highlight the expiration field as expired.
3. WHEN the Sensor_Pod certificate expiration timestamp is within 30 days of the current time, THE Identity_Section SHALL visually highlight the expiration field as expiring soon.
4. WHEN a field value is not available (nil or empty), THE Identity_Section SHALL display a placeholder dash character instead of blank space.
5. THE Identity_Section SHALL display the Sensor_Pod enrollment status (pending, enrolled, or revoked).
6. THE Identity_Section SHALL display timestamps in UTC with an unambiguous format and SHALL include relative age text where useful (for example, "last seen 42 seconds ago").
7. THE Identity_Section SHALL display the Sensor_Pod control API host when configured, or a placeholder dash when not configured.

### Requirement 3: Host Readiness Section

**User Story:** As a sensor operator, I want to see the host-level readiness state of a sensor, so that I can diagnose issues with the underlying host before investigating container problems.

#### Acceptance Criteria

1. WHEN the HealthReport for the Sensor_Pod includes host readiness data, THE Detail_Page SHALL display a Host Readiness section showing: capture interface name, NIC driver, kernel version, AF_PACKET support status, disk capacity, and time synchronization state.
2. WHEN the HealthReport does not include host readiness data, THE Detail_Page SHALL display the Host Readiness section with a message indicating that host readiness data is not yet available from the Sensor_Agent.
3. WHEN AF_PACKET support is reported as unavailable, THE Detail_Page SHALL visually highlight the AF_PACKET field as a warning condition.
4. WHEN host readiness includes individual hard or soft readiness checks, THE Detail_Page SHALL display each check with name, severity, observed value, required value, and pass/fail state.
5. WHEN any hard readiness check fails, THE Detail_Page SHALL include that failure in the Degradation Summary.

### Requirement 4: Container Health Section

**User Story:** As a sensor operator, I want to see the health of every container running on a sensor, so that I can identify which component is causing a problem.

#### Acceptance Criteria

1. THE Container_Section SHALL display a row for each container reported in the HealthReport, showing: container name, state, uptime, CPU percentage, and memory usage.
2. THE Container_Section SHALL display container state using color-coded badges: green for running, red for error, yellow for restarting, and gray for stopped.
3. WHEN a container CPU percentage exceeds 90 percent, THE Container_Section SHALL visually highlight that value as a warning condition.
4. WHEN the HealthReport contains no container data, THE Container_Section SHALL display a message indicating that no container data is available.
5. THE Container_Section SHALL display the expected RavenWire containers (Zeek, Suricata, Vector, pcap_ring_writer) and conditionally display optional containers (Strelka submitter, netsniff-ng) only when they are present in the HealthReport.
6. WHEN an expected RavenWire container is absent from the HealthReport, THE Container_Section SHALL display that container as missing rather than silently omitting it.

### Requirement 5: Capture Pipeline Section

**User Story:** As a sensor operator, I want to see the capture pipeline state including packet counters and drop rates per consumer, so that I can diagnose packet loss and BPF issues.

#### Acceptance Criteria

1. THE Capture_Section SHALL display a row for each capture consumer reported in the HealthReport, showing: consumer name, packets received, packets dropped, drop percentage, throughput in bits per second, and BPF restart pending status.
2. WHEN a capture consumer drop percentage exceeds 5 percent, THE Capture_Section SHALL visually highlight that value as a critical condition.
3. WHEN a capture consumer has BPF restart pending set to true, THE Capture_Section SHALL display a visible indicator that a BPF filter restart is required.
4. WHEN the HealthReport contains no capture data, THE Capture_Section SHALL display a message indicating that no capture data is available.
5. THE Capture_Section SHALL format throughput values in human-readable units (bps, Kbps, Mbps, Gbps) based on magnitude.
6. WHEN packet/drop counters are unavailable or reset between HealthReports, THE Capture_Section SHALL display the latest absolute counters and SHALL avoid showing negative rates.

### Requirement 6: Storage Section

**User Story:** As a sensor operator, I want to see the PCAP storage health of a sensor, so that I can detect low disk space before capture data is lost.

#### Acceptance Criteria

1. THE Storage_Section SHALL display the following fields from the HealthReport storage stats: PCAP path, total bytes, used bytes, available bytes, and used percentage.
2. THE Storage_Section SHALL format byte values in human-readable units (KB, MB, GB, TB) based on magnitude.
3. WHEN the storage used percentage exceeds 85 percent, THE Storage_Section SHALL visually highlight the used percentage as a warning condition.
4. WHEN the storage used percentage exceeds 95 percent, THE Storage_Section SHALL visually highlight the used percentage as a critical condition.
5. WHEN the HealthReport contains no storage data, THE Storage_Section SHALL display a message indicating that no storage data is available.
6. THE Storage_Section SHALL display the Sensor_Pod PCAP configuration from the database record: ring size (MB), pre-alert window (seconds), post-alert window (seconds), and alert severity threshold.
7. WHEN a PCAP prune or retention error is reported by the Sensor_Agent, THE Storage_Section SHALL display the error as a critical condition and include it in the Degradation Summary.

### Requirement 7: Clock and Time Synchronization Section

**User Story:** As a sensor operator, I want to see the clock synchronization state of a sensor, so that I can ensure accurate timestamps for correlation across sensors.

#### Acceptance Criteria

1. THE Detail_Page SHALL display a Clock section showing: clock offset in milliseconds, NTP synchronization status, and NTP/PTP source.
2. WHEN the clock offset exceeds the configured drift threshold (default 100ms, configurable by the Config_Manager), THE Detail_Page SHALL visually highlight the offset value as a degraded condition.
3. WHEN NTP synchronization is reported as false, THE Detail_Page SHALL visually highlight the synchronization status as a warning condition.
4. WHEN the HealthReport contains no clock data, THE Detail_Page SHALL display the Clock section with a message indicating that clock data is not available.

### Requirement 8: Forwarding Section

**User Story:** As a sensor operator, I want to see the Vector forwarding status of a sensor, so that I can diagnose log delivery failures to downstream destinations like Splunk or Cribl.

#### Acceptance Criteria

1. WHEN the HealthReport for the Sensor_Pod includes forwarding data, THE Forwarding_Section SHALL display: Vector sink status, queue or buffer usage, and destination health indicators.
2. WHEN the HealthReport does not include forwarding data, THE Forwarding_Section SHALL display a message indicating that forwarding data is not yet available from the Sensor_Agent.
3. WHEN a Vector sink reports an unhealthy or disconnected state, THE Forwarding_Section SHALL visually highlight that sink as a critical condition.
4. THE Forwarding_Section SHALL redact sink secrets, tokens, credentials, and sensitive headers while still displaying non-secret destination labels or hostnames when available.
5. WHEN Vector buffer usage exceeds 85 percent, THE Forwarding_Section SHALL visually highlight the buffer as a warning condition; when it exceeds 95 percent, it SHALL highlight the buffer as a critical condition.

### Requirement 9: Real-Time Updates

**User Story:** As a sensor operator, I want the detail page to update in real time as new health data arrives, so that I do not need to manually refresh the page while troubleshooting.

#### Acceptance Criteria

1. WHEN the Detail_Page is mounted and the LiveView WebSocket is connected, THE Detail_Page SHALL subscribe to PubSub updates for the displayed Sensor_Pod.
2. WHEN a new HealthReport arrives for the displayed Sensor_Pod, THE Detail_Page SHALL update all health-derived sections (containers, capture, storage, clock, forwarding) within 2 seconds of the report arriving at the Health_Registry.
3. WHEN the displayed Sensor_Pod transitions to or from a degraded state, THE Detail_Page SHALL update the degradation indicators without requiring a page reload.
4. THE Detail_Page SHALL display the timestamp of the most recent HealthReport to indicate data freshness.
5. THE Detail_Page SHALL ignore PubSub updates for other Sensor_Pods.
6. WHEN the LiveView WebSocket disconnects, THE Detail_Page SHALL show a reconnecting or stale-data indication using standard Phoenix LiveView behavior and SHALL preserve the last rendered data until the connection recovers or the page is refreshed.

### Requirement 10: Operational Actions

**User Story:** As a sensor operator, I want to trigger common operational actions from the sensor detail page, so that I can respond to issues without switching to a terminal or separate tool.

#### Acceptance Criteria

1. THE Actions_Section SHALL display the following action buttons when permitted: Validate Config, Reload Zeek, Reload Suricata, Restart Vector, Generate Support Bundle, and Revoke Sensor.
2. THE Config_Manager SHALL define the following Action_Permission_Map:
   - Validate Config: `sensor:operate`.
   - Reload Zeek: `sensor:operate`.
   - Reload Suricata: `sensor:operate`.
   - Restart Vector: `sensor:operate`.
   - Generate Support Bundle: `bundle:download`.
   - Revoke Sensor: `enrollment:manage`.
3. THE auth-rbac-audit role-to-permission mapping SHALL include `sensor:operate` for `sensor-operator`, `rule-manager`, and `platform-admin` roles before these actions are exposed.
4. WHEN an authenticated user with the required Permission clicks an action button, THE Config_Manager SHALL dispatch the corresponding command to the Sensor_Agent Control_API for that Sensor_Pod.
5. WHEN an authenticated user without the required Permission views the Detail_Page, THE Actions_Section SHALL hide action buttons that the user's role does not permit.
6. THE RBAC_Gate SHALL enforce permission checks server-side on each action event before dispatching the command, regardless of whether the button is hidden in the UI.
7. WHEN an action is dispatched, THE Detail_Page SHALL display a loading indicator on the triggered button and disable it until the action completes or times out.
8. WHEN an action does not complete within 30 seconds, configurable by the Config_Manager, THE Detail_Page SHALL treat the action as failed with a timeout message.
9. WHEN an action completes successfully, THE Detail_Page SHALL display a success flash message with the action name and sanitized result.
10. WHEN an action fails, THE Detail_Page SHALL display an error flash message with the action name and sanitized error reason.
11. WHEN the Revoke Sensor action is triggered, THE Detail_Page SHALL display a confirmation dialog before dispatching the revocation command.
12. WHEN an action is dispatched, THE Config_Manager SHALL record an Audit_Entry with a canonical action name, the Sensor_Pod identifier, the acting user or API token, the required Permission, and the result.
13. THE canonical Audit_Entry action names SHALL be: `sensor_validate_config`, `sensor_reload_zeek`, `sensor_reload_suricata`, `sensor_restart_vector`, `sensor_support_bundle_generate`, and `sensor_revoke`.
14. IF the Sensor_Pod has no Control_API host configured, THEN THE Actions_Section SHALL disable Control_API-backed action buttons and display a message indicating that the sensor agent is not reachable.
15. THE Revoke Sensor action SHALL remain available only when the user has `enrollment:manage`, because revocation is handled by Config_Manager identity state and certificate revocation, not by the Sensor_Agent Control_API.

### Requirement 11: Degradation Summary

**User Story:** As a sensor operator, I want to see a summary of all active degradation reasons for a sensor at the top of the detail page, so that I can immediately understand what is wrong.

#### Acceptance Criteria

1. WHEN the displayed Sensor_Pod has one or more active degradation reasons (clock drift, BPF restart pending, or other reasons tracked by the Health_Registry), THE Detail_Page SHALL display a degradation summary banner at the top of the page listing each active reason.
2. WHEN the displayed Sensor_Pod has no active degradation reasons, THE Detail_Page SHALL NOT display the degradation summary banner.
3. THE degradation summary banner SHALL update in real time as degradation reasons are added or removed via PubSub events.
4. THE degradation summary banner SHALL group duplicate reasons and SHALL display the most recent timestamp for each reason when available.

### Requirement 12: Offline Sensor Handling

**User Story:** As a sensor operator, I want the detail page to clearly indicate when a sensor is offline or has stale data, so that I do not mistake old data for current state.

#### Acceptance Criteria

1. WHEN the Health_Registry has no HealthReport for the displayed Sensor_Pod, THE Detail_Page SHALL display the Identity_Section from the database record and show a prominent banner indicating that the sensor is not currently reporting health data.
2. WHEN the most recent HealthReport timestamp for the displayed Sensor_Pod is older than 60 seconds, THE Detail_Page SHALL display a stale data warning indicating the time since the last report.
3. WHEN the Sensor_Pod status in the database is "revoked", THE Detail_Page SHALL display a revoked status banner and hide the Actions_Section.
4. WHEN the Sensor_Pod status in the database is "pending", THE Detail_Page SHALL display a pending enrollment banner and hide Control_API-backed action buttons.
5. THE stale-data threshold SHALL default to 60 seconds and SHALL be configurable by the Config_Manager.

### Requirement 13: Layout, Accessibility, and Responsiveness

**User Story:** As an operator using the detail page from different devices and assistive technologies, I want the page to remain readable, accessible, and usable.

#### Acceptance Criteria

1. THE Detail_Page SHALL render all sections in a stable order: degradation summary, identity, host readiness, containers, capture pipeline, storage, clock, forwarding, and actions.
2. THE Detail_Page SHALL be usable at desktop and mobile widths without overlapping text, clipped labels, or horizontal scrolling for ordinary field values.
3. THE Detail_Page SHALL provide accessible names for all action buttons and SHALL NOT rely on color alone to communicate warning or critical states.
4. THE Detail_Page SHALL use semantic tables or lists for repeated status rows so that screen readers can identify row labels and values.
5. THE Detail_Page SHALL display loading, empty, stale, and error states in each section without causing layout shifts that obscure other sections.

### Requirement 14: Tests and Verification

**User Story:** As an engineer implementing the detail page, I want explicit test expectations, so that route behavior, real-time updates, permissions, and edge cases are verified.

#### Acceptance Criteria

1. THE Config_Manager SHALL include route tests for `/sensors/:id` covering existing, pending, enrolled, revoked, and non-existent Sensor_Pod identifiers.
2. THE Config_Manager SHALL include LiveView tests verifying that the Detail_Page subscribes to the displayed Sensor_Pod and updates when a matching PubSub message is received.
3. THE Config_Manager SHALL include tests verifying that PubSub messages for other Sensor_Pods do not change the displayed Detail_Page.
4. THE Config_Manager SHALL include rendering tests for missing HealthReport data, stale HealthReport data, missing optional containers, missing expected containers, and unavailable Control_API host.
5. THE Config_Manager SHALL include RBAC tests proving each action button is hidden and server-rejected when the current user lacks the required Permission.
6. THE Config_Manager SHALL include audit tests proving each operational action records the canonical Audit_Entry action name for success and failure paths.
7. THE Config_Manager SHALL include formatting tests for byte units, throughput units, UTC timestamps, certificate expiration status, and clock drift status.
8. THE Config_Manager SHALL include accessibility-oriented tests or assertions verifying action button labels and non-color indicators for degraded, warning, and critical states.
