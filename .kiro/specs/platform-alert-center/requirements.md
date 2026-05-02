# Requirements Document: Platform Alert Center

## Introduction

The Platform Alert Center adds a centralized alerting subsystem to the RavenWire Config Manager web UI. This feature derives platform-level alerts from health telemetry and system events — not from network traffic analysis (SIEM). Alerts cover conditions such as sensor offline, high packet drops, clock drift, disk critical, Vector sink down, rule deployment failure, certificate expiration, BPF validation failure, and PCAP prune failure.

The system consists of three parts: (1) an alert rule engine that evaluates configurable conditions against incoming health telemetry and system events, (2) a persistent alert store for historical review and acknowledgment workflows, and (3) LiveView pages at `/alerts`, `/alerts/rules`, and `/alerts/notifications` for viewing, managing, and configuring alerts in real time.

Notification channels (email, webhook) are deferred to a later phase. This spec focuses on the alert UI, rule engine, alert persistence, and acknowledgment/resolution workflows.

## Glossary

- **Alert_Engine**: The GenServer process that evaluates alert rules against incoming health telemetry and system events, firing or auto-resolving alerts when conditions are met or cleared.
- **Alert_Rule**: A configurable definition specifying what condition triggers an alert, at what severity, and with what threshold values. Alert rules are persisted in SQLite.
- **Alert**: A persisted record representing a specific alert instance fired by the Alert_Engine when an Alert_Rule condition is met for a specific Sensor_Pod.
- **Alert_Severity**: One of `critical`, `warning`, or `info`, indicating the urgency of an alert.
- **Alert_Status**: One of `firing`, `acknowledged`, or `resolved`, representing the lifecycle state of an alert.
- **Alert_Type**: A string identifier for the category of condition being monitored (e.g., `sensor_offline`, `packet_drops_high`, `clock_drift`, `disk_critical`, `vector_sink_down`, `rule_deploy_failed`, `cert_expiring`, `bpf_validation_failed`, `pcap_prune_failed`).
- **Health_Registry**: The existing in-memory ETS-based registry (`ConfigManager.Health.Registry`) that stores the latest health snapshot for each connected Sensor_Pod.
- **Health_Report**: The protobuf message streamed from Sensor_Agents containing container health, capture statistics, storage statistics, and clock statistics.
- **Config_Manager**: The Phoenix/Elixir LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Pod**: An enrolled sensor node managed by the Config_Manager.
- **PubSub**: The existing Phoenix PubSub system used for real-time UI updates and inter-process messaging.
- **Acknowledgment**: An operator action that marks a firing alert as seen and being investigated, without resolving the underlying condition.
- **Resolution**: The transition of an alert to resolved status, either automatically when the condition clears or manually by an operator.

## Requirements

### Requirement 1: Alert Rule Management

**User Story:** As a platform administrator, I want to define and configure alert rules with customizable thresholds, so that the alert system monitors the conditions relevant to my deployment.

#### Acceptance Criteria

1. THE Config_Manager SHALL provide a default set of alert rules on first startup, covering all nine Alert_Types: `sensor_offline`, `packet_drops_high`, `clock_drift`, `disk_critical`, `vector_sink_down`, `rule_deploy_failed`, `cert_expiring`, `bpf_validation_failed`, and `pcap_prune_failed`.
2. WHEN an operator navigates to `/alerts/rules`, THE Config_Manager SHALL display all configured alert rules with their Alert_Type, description, severity, enabled status, and threshold values.
3. WHEN an operator edits an alert rule, THE Config_Manager SHALL allow modification of the severity, enabled status, and threshold value for that rule.
4. THE Config_Manager SHALL validate that threshold values are numeric and within the allowed range for each Alert_Type (e.g., drop percent between 0 and 100, disk percent between 0 and 100, clock offset in milliseconds greater than 0, offline timeout in seconds greater than 0).
5. WHEN an operator saves an alert rule change, THE Config_Manager SHALL persist the updated rule to the database and write an audit log entry recording the change.
6. WHEN an operator disables an alert rule, THE Alert_Engine SHALL stop evaluating that rule against incoming telemetry until the rule is re-enabled.
7. THE Config_Manager SHALL prevent deletion of built-in alert rules; operators may only disable or modify them.
8. IF an operator submits an alert rule with an invalid threshold value, THEN THE Config_Manager SHALL display a validation error and retain the form state.

### Requirement 2: Alert Rule Default Thresholds

**User Story:** As a platform administrator, I want sensible default thresholds for all alert types, so that the alert system works out of the box without manual configuration.

#### Acceptance Criteria

1. THE Config_Manager SHALL seed the `sensor_offline` rule with a default threshold of 60 seconds and severity `critical`.
2. THE Config_Manager SHALL seed the `packet_drops_high` rule with a default threshold of 5.0 percent and severity `warning`.
3. THE Config_Manager SHALL seed the `clock_drift` rule with a default threshold of 100 milliseconds and severity `warning`.
4. THE Config_Manager SHALL seed the `disk_critical` rule with a default threshold of 90.0 percent and severity `critical`.
5. THE Config_Manager SHALL seed the `vector_sink_down` rule with a default threshold of 0 (boolean condition: any sink reported down) and severity `critical`.
6. THE Config_Manager SHALL seed the `rule_deploy_failed` rule with a default threshold of 0 (boolean condition: any deployment failure) and severity `warning`.
7. THE Config_Manager SHALL seed the `cert_expiring` rule with a default threshold of 72 hours before expiration and severity `warning`.
8. THE Config_Manager SHALL seed the `bpf_validation_failed` rule with a default threshold of 0 (boolean condition: any BPF validation failure) and severity `warning`.
9. THE Config_Manager SHALL seed the `pcap_prune_failed` rule with a default threshold of 0 (boolean condition: any prune failure) and severity `critical`.

### Requirement 3: Health Telemetry Alert Evaluation

**User Story:** As a platform operator, I want the system to automatically detect unhealthy conditions from sensor health telemetry, so that I am alerted before problems escalate.

#### Acceptance Criteria

1. WHEN the Health_Registry receives a Health_Report with a clock offset exceeding the `clock_drift` rule threshold, THE Alert_Engine SHALL fire a `clock_drift` alert for that Sensor_Pod.
2. WHEN the Health_Registry receives a Health_Report with any capture consumer drop percent exceeding the `packet_drops_high` rule threshold, THE Alert_Engine SHALL fire a `packet_drops_high` alert for that Sensor_Pod.
3. WHEN the Health_Registry receives a Health_Report with storage used percent exceeding the `disk_critical` rule threshold, THE Alert_Engine SHALL fire a `disk_critical` alert for that Sensor_Pod.
4. WHEN no Health_Report is received from a Sensor_Pod for a duration exceeding the `sensor_offline` rule threshold, THE Alert_Engine SHALL fire a `sensor_offline` alert for that Sensor_Pod.
5. WHEN a previously alerting condition returns to within the acceptable threshold, THE Alert_Engine SHALL auto-resolve the corresponding alert by setting its status to `resolved` and recording the resolution timestamp.
6. THE Alert_Engine SHALL evaluate only enabled alert rules; disabled rules SHALL produce no alerts.
7. THE Alert_Engine SHALL not fire duplicate alerts for the same Alert_Type and Sensor_Pod combination while an existing alert for that combination is in `firing` or `acknowledged` status.

### Requirement 4: System Event Alert Evaluation

**User Story:** As a platform operator, I want the system to generate alerts from operational events like deployment failures and certificate issues, so that I have a single place to see all platform problems.

#### Acceptance Criteria

1. WHEN a rule deployment returns a failure result for a Sensor_Pod, THE Alert_Engine SHALL fire a `rule_deploy_failed` alert for that Sensor_Pod.
2. WHEN a BPF filter validation fails during a deployment attempt, THE Alert_Engine SHALL fire a `bpf_validation_failed` alert for that Sensor_Pod.
3. WHEN a Sensor_Pod certificate is within the `cert_expiring` threshold of its expiration time, THE Alert_Engine SHALL fire a `cert_expiring` alert for that Sensor_Pod.
4. WHEN a PCAP storage prune operation fails for a Sensor_Pod, THE Alert_Engine SHALL fire a `pcap_prune_failed` alert for that Sensor_Pod.
5. WHEN the Health_Report indicates a Vector sink is unreachable or in error state, THE Alert_Engine SHALL fire a `vector_sink_down` alert for that Sensor_Pod.
6. WHEN a system event alert condition is resolved (e.g., certificate renewed, successful re-deployment), THE Alert_Engine SHALL auto-resolve the corresponding alert.

### Requirement 5: Alert Persistence and History

**User Story:** As a platform operator, I want alerts to be persisted in the database, so that I can review historical alert activity and track patterns over time.

#### Acceptance Criteria

1. WHEN the Alert_Engine fires an alert, THE Config_Manager SHALL persist the alert record to the database with the Alert_Type, Sensor_Pod identifier, severity, status (`firing`), a human-readable message, the threshold value that was exceeded, the observed value that triggered the alert, and the fired-at timestamp.
2. THE Config_Manager SHALL retain resolved alerts in the database for historical querying.
3. WHEN an alert transitions from one status to another, THE Config_Manager SHALL update the alert record with the new status and the timestamp of the transition.
4. THE Config_Manager SHALL record the actor (operator username) who acknowledged or manually resolved an alert.
5. WHEN an alert is fired, acknowledged, or resolved, THE Config_Manager SHALL write an audit log entry recording the action, the alert identifier, and the actor.

### Requirement 6: Alert Dashboard

**User Story:** As a platform operator, I want a centralized alert dashboard, so that I can see all active and recent alerts across the sensor fleet at a glance.

#### Acceptance Criteria

1. WHEN an operator navigates to `/alerts`, THE Config_Manager SHALL display a list of alerts sorted by fired-at timestamp in descending order, with the most recent alerts first.
2. THE Config_Manager SHALL display each alert with its severity, Alert_Type, Sensor_Pod name, status, human-readable message, and fired-at timestamp.
3. THE Config_Manager SHALL provide filter controls to filter alerts by severity, Alert_Type, status, and Sensor_Pod name.
4. THE Config_Manager SHALL provide a text search field that filters alerts by message content or Sensor_Pod name.
5. THE Config_Manager SHALL paginate the alert list with a configurable page size defaulting to 25 alerts per page.
6. THE Config_Manager SHALL display a summary bar showing counts of alerts in each status: firing, acknowledged, and resolved.
7. WHEN a new alert is fired or an existing alert changes status, THE Config_Manager SHALL update the alert dashboard in real time via PubSub without requiring a page refresh.
8. THE Config_Manager SHALL visually distinguish alert severities using color coding: `critical` in red, `warning` in amber, and `info` in blue.
9. WHEN an operator clicks a Sensor_Pod name in the alert list, THE Config_Manager SHALL navigate to the sensor detail page for that Sensor_Pod.

### Requirement 7: Alert Acknowledgment and Resolution

**User Story:** As a platform operator, I want to acknowledge and resolve alerts, so that my team can track which problems are being investigated and which are fixed.

#### Acceptance Criteria

1. WHEN an operator clicks the acknowledge action on a firing alert, THE Config_Manager SHALL transition the alert status from `firing` to `acknowledged` and record the operator username and acknowledgment timestamp.
2. WHEN an operator clicks the resolve action on a firing or acknowledged alert, THE Config_Manager SHALL transition the alert status to `resolved` and record the operator username and resolution timestamp.
3. THE Config_Manager SHALL allow bulk acknowledgment of multiple selected alerts in a single action.
4. THE Config_Manager SHALL allow bulk resolution of multiple selected alerts in a single action.
5. THE Config_Manager SHALL not allow transitioning a resolved alert back to firing or acknowledged; resolved is a terminal manual state.
6. WHEN an operator acknowledges or resolves an alert, THE Config_Manager SHALL broadcast the status change via PubSub so all connected alert dashboard sessions update in real time.
7. WHEN an operator adds a note while acknowledging or resolving an alert, THE Config_Manager SHALL persist the note text with the alert record.

### Requirement 8: Real-Time Alert Delivery

**User Story:** As a platform operator, I want to see new alerts appear immediately in the UI, so that I can respond to platform issues without delay.

#### Acceptance Criteria

1. WHEN the Alert_Engine fires a new alert, THE Config_Manager SHALL broadcast the alert via PubSub to the `alerts` topic.
2. WHEN the Alert_Engine auto-resolves an alert, THE Config_Manager SHALL broadcast the resolution via PubSub to the `alerts` topic.
3. WHEN a LiveView client is subscribed to the `alerts` topic, THE Config_Manager SHALL push the alert event to the client within 2 seconds of the alert being fired.
4. THE Config_Manager SHALL broadcast alert events to a sensor-scoped topic `alert:sensor:{sensor_pod_id}` so that the sensor detail page can display alerts relevant to that sensor.

### Requirement 9: Alert Notification Configuration Page

**User Story:** As a platform administrator, I want a notification configuration page, so that the system is prepared for future notification channel integrations.

#### Acceptance Criteria

1. WHEN an operator navigates to `/alerts/notifications`, THE Config_Manager SHALL display a placeholder page indicating that notification channels (email, webhook) are planned for a future release.
2. THE Config_Manager SHALL include navigation links between `/alerts`, `/alerts/rules`, and `/alerts/notifications` as a tab bar or sub-navigation.

### Requirement 10: Sensor Offline Detection

**User Story:** As a platform operator, I want to be alerted when a sensor stops reporting health data, so that I can investigate connectivity or hardware issues.

#### Acceptance Criteria

1. THE Alert_Engine SHALL maintain a last-seen timestamp for each Sensor_Pod based on received Health_Reports.
2. WHEN the elapsed time since the last Health_Report from a Sensor_Pod exceeds the `sensor_offline` rule threshold, THE Alert_Engine SHALL fire a `sensor_offline` alert for that Sensor_Pod.
3. THE Alert_Engine SHALL check for offline sensors at a periodic interval no greater than 15 seconds.
4. WHEN a previously offline Sensor_Pod resumes sending Health_Reports, THE Alert_Engine SHALL auto-resolve the `sensor_offline` alert for that Sensor_Pod.

### Requirement 11: Alert Integration with Existing Pages

**User Story:** As a platform operator, I want to see alert indicators on the dashboard and sensor detail pages, so that I have contextual awareness of problems without navigating to the alert center.

#### Acceptance Criteria

1. THE Config_Manager SHALL display an alert badge in the main navigation bar showing the count of firing alerts, updated in real time.
2. WHEN the firing alert count is zero, THE Config_Manager SHALL display the alert navigation link without a count badge.
3. WHEN the sensor detail page is displayed for a Sensor_Pod with active (firing or acknowledged) alerts, THE Config_Manager SHALL display an alert summary section listing those alerts.
4. THE Config_Manager SHALL include a link from the sensor detail alert summary to the alert dashboard filtered by that Sensor_Pod.

### Requirement 12: RBAC Integration

**User Story:** As a platform administrator, I want alert management actions to respect the role-based access control system, so that only authorized operators can acknowledge, resolve, or configure alerts.

#### Acceptance Criteria

1. THE Config_Manager SHALL allow all authenticated users with `sensors:view` permission to view the alert dashboard at `/alerts`.
2. THE Config_Manager SHALL require `alerts:manage` permission to acknowledge or resolve alerts.
3. THE Config_Manager SHALL require `alerts:manage` permission to modify alert rules at `/alerts/rules`.
4. THE Config_Manager SHALL verify that the canonical `alerts:manage` permission from the auth-rbac-audit spec is granted to the `sensor-operator`, `rule-manager`, and `platform-admin` roles in the Policy module.
5. THE Config_Manager SHALL treat `alerts:view` as a display alias for `sensors:view` for alert dashboard access, maintaining consistency with the canonical auth-rbac-audit permission model.
6. IF an operator without `alerts:manage` permission attempts to acknowledge or resolve an alert, THEN THE Config_Manager SHALL display the alert dashboard in read-only mode with action buttons hidden.
