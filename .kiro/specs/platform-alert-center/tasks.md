# Tasks: Platform Alert Center

## Task 1: Database Migrations and Ecto Schemas

- [ ] 1.1 Create migration for `alert_rules` table with columns: id (binary_id PK), alert_type (text, unique), description (text), severity (text), enabled (boolean), threshold_value (real), threshold_unit (text), builtin (boolean), timestamps
- [ ] 1.2 Create migration for `alerts` table with columns: id (binary_id PK), alert_type (text), sensor_pod_id (text), sensor_pod_db_id (binary_id), severity (text), status (text), message (text), threshold_value (real), observed_value (real), fired_at (utc_datetime), acknowledged_at (utc_datetime), acknowledged_by (text), resolved_at (utc_datetime), resolved_by (text), note (text), timestamps; add indexes on alert_type, sensor_pod_id, status, fired_at, severity, and composite (alert_type, sensor_pod_id, status)
- [ ] 1.3 Create `ConfigManager.Alerts.AlertRule` Ecto schema with changeset validation: severity in [critical, warning, info], threshold range validation per alert_type (0-100 for percent, >0 for time-based), alert_type in the 9 defined types
- [ ] 1.4 Create `ConfigManager.Alerts.Alert` Ecto schema with `fire_changeset/2`, `acknowledge_changeset/2`, and `resolve_changeset/2` including status transition validation (firing→acknowledged, firing→resolved, acknowledged→resolved; resolved is terminal)
- [ ] 1.5 Write property test for alert rule threshold validation (Property 1): generate random {alert_type, threshold_value} pairs, verify changeset accepts values within range and rejects values outside range

## Task 2: Alert Context Module — Core CRUD and Queries

- [ ] 2.1 Implement `ConfigManager.Alerts.seed_default_rules/0` to insert all 9 default rules with thresholds from Requirement 2 (sensor_offline: 60s/critical, packet_drops_high: 5%/warning, clock_drift: 100ms/warning, disk_critical: 90%/critical, vector_sink_down: 0/critical, rule_deploy_failed: 0/warning, cert_expiring: 72h/warning, bpf_validation_failed: 0/warning, pcap_prune_failed: 0/critical); skip if rules already exist
- [ ] 2.2 Implement `ConfigManager.Alerts.list_rules/0` returning all rules ordered by alert_type
- [ ] 2.3 Implement `ConfigManager.Alerts.update_rule/3` that updates severity, enabled, threshold_value within an Ecto.Multi that also appends an audit entry via `Audit.append_multi/2`; broadcast `{:rules_updated}` on `"alert_rules"` PubSub topic
- [ ] 2.4 Implement `ConfigManager.Alerts.fire_alert/1` that checks for existing active alert (firing/acknowledged) for the same {alert_type, sensor_pod_id}, returns `{:error, :duplicate}` if found, otherwise inserts the alert and broadcasts to `"alerts"` and `"alert:sensor:{sensor_pod_id}"` topics
- [ ] 2.5 Implement `ConfigManager.Alerts.acknowledge_alert/3` and `resolve_alert/3` using Ecto.Multi with audit entry; validate status transitions; broadcast updates to PubSub topics
- [ ] 2.6 Implement `ConfigManager.Alerts.auto_resolve_alert/1` that sets resolved_by="system", resolved_at=now, broadcasts to PubSub
- [ ] 2.7 Implement `ConfigManager.Alerts.bulk_acknowledge/2` and `bulk_resolve/2` that process multiple alert IDs in a single transaction with audit entries for each
- [ ] 2.8 Implement `ConfigManager.Alerts.list_alerts/2` with filtering (severity, alert_type, status, sensor_pod_id), text search (message or sensor_pod_id LIKE), sorting by fired_at desc, and pagination (page, page_size with default 25); return `{alerts, meta}` tuple
- [ ] 2.9 Implement `ConfigManager.Alerts.alert_status_counts/0`, `firing_alert_count/0`, `active_alerts_for_sensor/1`, and `active_alert_index/0`
- [ ] 2.10 Write property test for alert lifecycle transitions (Property 11): generate random alert states and transition attempts, verify valid transitions succeed and invalid ones fail
- [ ] 2.11 Write property test for alert query filtering (Property 13): generate random alert sets with varying attributes, apply random filter combinations, verify all returned alerts match all predicates
- [ ] 2.12 Write property test for alert query pagination (Property 14): generate random alert sets, verify page slices are correct and sorted by fired_at desc
- [ ] 2.13 Write property test for status summary counts (Property 15): generate random alert sets, verify counts match actual per-status counts
- [ ] 2.14 Write property test for alert rule update round-trip (Property 2): generate valid rule changes, verify persisted values match and audit entry exists
- [ ] 2.15 Write unit tests for seed defaults: verify all 9 rules exist with exact threshold values and severities after seeding; verify idempotency (running seed twice doesn't duplicate)

## Task 3: Alert Engine GenServer

- [ ] 3.1 Create `ConfigManager.Alerts.AlertEngine` GenServer with init that loads enabled rules into state, rebuilds active alert index from DB, initializes last_seen map from Health Registry, subscribes to `"sensor_pods"`, `"system_events"`, and `"alert_rules"` PubSub topics, and schedules periodic check at 10-second interval
- [ ] 3.2 Implement `handle_info({:pod_updated, pod_id}, state)` that reads health from Registry and evaluates health-telemetry rules (clock_drift, packet_drops_high, disk_critical) using pure evaluation functions; update last_seen timestamp; fire or auto-resolve alerts as needed
- [ ] 3.3 Implement pure evaluation functions: `evaluate_health_rule/3` returns :fire, :resolve, or :noop based on rule type, threshold, and health report values; `check_offline/3` compares elapsed time to threshold; `check_cert_expiring/3` compares cert expiry to threshold hours
- [ ] 3.4 Implement `handle_info({:system_event, event_type, pod_id, detail}, state)` for rule_deploy_failed, bpf_validation_failed, pcap_prune_failed, and vector_sink_down events; fire alerts when enabled rules match
- [ ] 3.5 Implement `handle_info(:check_periodic, state)` that iterates all known sensors for offline detection (last_seen > threshold) and cert expiration checks; fire or auto-resolve alerts; reschedule timer
- [ ] 3.6 Implement `handle_info({:rules_updated}, state)` to reload rule cache from DB
- [ ] 3.7 Implement deduplication logic: before firing, check `active_alerts` MapSet for `{alert_type, sensor_pod_id}`; after firing, add to set; after resolving, remove from set
- [ ] 3.8 Add Alert Engine to application supervision tree in `ConfigManager.Application`, after Health.Registry; call `Alerts.seed_default_rules()` during startup
- [ ] 3.9 Write property test for health telemetry alert firing (Property 4): generate random health reports with metrics above/below thresholds, verify evaluate_health_rule returns correct result
- [ ] 3.10 Write property test for disabled rules produce no alerts (Property 3): generate health reports that would trigger alerts, disable the rule, verify no alert fires
- [ ] 3.11 Write property test for auto-resolve (Property 5): generate scenarios where condition clears, verify alert transitions to resolved with system actor
- [ ] 3.12 Write property test for deduplication (Property 6): generate sequences of triggering reports for same pod, verify only one active alert exists
- [ ] 3.13 Write property test for sensor offline detection (Property 9): generate random last_seen timestamps and thresholds, verify correct fire/resolve behavior
- [ ] 3.14 Write property test for cert expiring detection (Property 8): generate random cert_expires_at values and thresholds, verify correct fire/resolve behavior
- [ ] 3.15 Write property test for system event alert firing (Property 7): generate random system events with enabled/disabled rules, verify correct firing behavior

## Task 4: System Event Broadcasting

- [ ] 4.1 Extend `ConfigManager.RuleDeployer.deploy_to_pool/3` to broadcast `{:system_event, :rule_deploy_failed, pod_id, detail}` on `"system_events"` PubSub topic when a deployment fails, and `{:system_event, :rule_deploy_success, pod_id, detail}` on success
- [ ] 4.2 Add PubSub broadcast for BPF validation failures at the appropriate call site (during deployment validation)
- [ ] 4.3 Add PubSub broadcast for PCAP prune failures at the appropriate call site
- [ ] 4.4 Add PubSub broadcast for Vector sink down detection from health report processing (in Alert Engine's health evaluation, since vector sink status comes from HealthReport)
- [ ] 4.5 Write unit tests verifying system event broadcasts are sent with correct topic, event type, pod_id, and detail payload

## Task 5: RBAC Integration

- [ ] 5.1 Verify `"alerts:manage"` is present in `Policy.canonical_permissions/0` and granted to `sensor-operator`, `rule-manager`, and `platform-admin`
- [ ] 5.2 Configure alert dashboard route (`/alerts`) with `required_permission: "sensors:view"` and alert rules route (`/alerts/rules`) with `required_permission: "alerts:manage"`
- [ ] 5.3 Add server-side RBAC checks in AlertDashboardLive `handle_event` callbacks for acknowledge, resolve, bulk_acknowledge, and bulk_resolve using `AuthHelpers.authorize(socket, "alerts:manage")`
- [ ] 5.4 Add server-side RBAC check in AlertRulesLive `handle_event` callbacks for save and toggle_enabled
- [ ] 5.5 Write property test for RBAC enforcement (Property 17): generate random {role, action} pairs, verify action succeeds iff role has alerts:manage
- [ ] 5.6 Write unit tests verifying alerts:manage is present in sensor-operator, rule-manager, and platform-admin roles; verify sensors:view grants dashboard access

## Task 6: Alert Dashboard LiveView (`/alerts`)

- [ ] 6.1 Create `ConfigManagerWeb.AlertDashboardLive` with mount that subscribes to `"alerts"` PubSub topic, loads initial alerts with default pagination (page 1, size 25), and loads status counts
- [ ] 6.2 Implement alert list rendering with severity badge (color-coded: critical=red, warning=amber, info=blue), alert_type, sensor_pod_id (linked to `/sensors/:db_id`), status badge, message, and fired_at timestamp; sorted by fired_at descending
- [ ] 6.3 Implement filter controls: dropdowns for severity, alert_type, and status; text input for sensor_pod_id; text search field for message/pod name filtering
- [ ] 6.4 Implement pagination controls with configurable page size (default 25), page navigation, and total count display
- [ ] 6.5 Implement status summary bar showing counts of firing, acknowledged, and resolved alerts
- [ ] 6.6 Implement real-time PubSub handlers: `handle_info({:alert_fired, alert})`, `handle_info({:alert_updated, alert})`, `handle_info({:alert_resolved, alert})` that update the alert list and status counts without page refresh
- [ ] 6.7 Implement single alert acknowledge and resolve actions with RBAC check, flash feedback, and PubSub broadcast
- [ ] 6.8 Implement checkbox selection for alerts and bulk acknowledge/resolve actions
- [ ] 6.9 Implement note input for acknowledge and resolve actions (optional text field in a confirmation modal or inline)
- [ ] 6.10 Conditionally hide ack/resolve/bulk action buttons when current user lacks `alerts:manage` permission (read-only mode)
- [ ] 6.11 Add sub-navigation tabs linking to `/alerts`, `/alerts/rules`, and `/alerts/notifications`
- [ ] 6.12 Write property test for severity color mapping (Property 16): verify CSS classes for each severity value
- [ ] 6.13 Write unit test for PubSub real-time update: subscribe, fire alert, verify dashboard receives and displays the new alert
- [ ] 6.14 Write unit test for sensor pod name link: verify alert row contains link to `/sensors/:db_id`

## Task 7: Alert Rules LiveView (`/alerts/rules`)

- [ ] 7.1 Create `ConfigManagerWeb.AlertRulesLive` with mount that loads all rules; display table with alert_type, description, severity, enabled toggle, threshold value and unit
- [ ] 7.2 Implement inline edit form for severity (dropdown), enabled (toggle), and threshold_value (numeric input); validate on submit using AlertRule changeset
- [ ] 7.3 Implement save handler that calls `Alerts.update_rule/3` with current_user as actor; display validation errors on invalid input; flash success on save
- [ ] 7.4 Implement enabled/disabled toggle that calls `update_rule/3` with only the enabled field changed
- [ ] 7.5 Prevent deletion of built-in rules (no delete button rendered; if attempted via event, reject with flash error)
- [ ] 7.6 Add sub-navigation tabs consistent with alert dashboard
- [ ] 7.7 Write unit test for rule edit form: edit threshold, save, verify DB updated and audit entry created
- [ ] 7.8 Write unit test for invalid threshold: submit out-of-range value, verify validation error displayed

## Task 8: Alert Notifications Placeholder (`/alerts/notifications`)

- [ ] 8.1 Create `ConfigManagerWeb.AlertNotificationsLive` with mount that renders a placeholder page indicating notification channels (email, webhook) are planned for a future release
- [ ] 8.2 Include sub-navigation tabs consistent with other alert pages
- [ ] 8.3 Write unit test verifying placeholder content is rendered and navigation tabs are present

## Task 9: Alert Integration with Existing Pages

- [ ] 9.1 Create `ConfigManagerWeb.Components.AlertNavBadge` function component that accepts a firing alert count and renders a badge on the Alerts nav link; hide badge when count is zero
- [ ] 9.2 Add the alert nav badge to the root layout navigation bar; use a LiveView hook or assign to keep the count updated in real time via PubSub subscription to `"alerts"` topic
- [ ] 9.3 Add alert summary section to the sensor detail page (`SensorDetailLive`) that queries `Alerts.active_alerts_for_sensor/1` and displays firing/acknowledged alerts for that sensor; subscribe to `"alert:sensor:{sensor_pod_id}"` for real-time updates
- [ ] 9.4 Add a link from the sensor detail alert summary to `/alerts?sensor_pod_id={sensor_pod_id}` for filtered dashboard view
- [ ] 9.5 Add `/alerts` link to the dashboard navigation bar (alongside Enrollment, PCAP Config, Rules, Support Bundles)
- [ ] 9.6 Write property test for nav badge count (Property 19): generate random alert sets, verify badge count equals firing alert count and badge hidden when zero
- [ ] 9.7 Write property test for sensor detail alert summary (Property 20): generate alerts for multiple sensors, verify only active alerts for the target sensor are shown
- [ ] 9.8 Write unit test for filtered dashboard link from sensor detail page

## Task 10: Router and Navigation Updates

- [ ] 10.1 Add routes to the authenticated live_session in `ConfigManagerWeb.Router`: `/alerts` → AlertDashboardLive with `required_permission: "sensors:view"`, `/alerts/rules` → AlertRulesLive with `required_permission: "alerts:manage"`, `/alerts/notifications` → AlertNotificationsLive with `required_permission: "sensors:view"`
- [ ] 10.2 Write unit test verifying all three alert routes are accessible with correct permissions and return 403 for unauthorized roles

## Task 11: Alert Audit Logging

- [ ] 11.1 Ensure all alert lifecycle events use `Audit.append_multi/2` within Ecto.Multi transactions: `alert_fired` (actor="system"), `alert_acknowledged` (actor=operator), `alert_resolved` (actor=operator or "system"), `alert_rule_updated` (actor=operator)
- [ ] 11.2 Write property test for audit entries (Property 18): generate random alert lifecycle events, verify each produces an audit entry with correct action, target_id, target_type="alert", and non-empty actor
- [ ] 11.3 Write unit test verifying audit entry detail field contains relevant context (threshold_value, observed_value for fires; note for ack/resolve)

## Task 12: End-to-End Integration Tests

- [ ] 12.1 Write integration test for full alert flow: send health report with metric exceeding threshold → verify alert fired in DB → verify PubSub broadcast → verify dashboard shows alert
- [ ] 12.2 Write integration test for auto-resolve flow: fire alert → send clearing health report → verify alert resolved → verify PubSub broadcast
- [ ] 12.3 Write integration test for ack/resolve with audit: acknowledge alert → verify DB state + audit entry + PubSub broadcast; resolve alert → verify same
- [ ] 12.4 Write integration test for bulk operations: select multiple alerts → bulk ack → verify all transitioned → bulk resolve → verify all resolved
- [ ] 12.5 Write integration test for sensor offline detection: simulate no health reports for > threshold → verify offline alert fired → simulate reconnect → verify auto-resolve
