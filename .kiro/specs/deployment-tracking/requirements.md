# Requirements Document: Deployment Tracking and Drift Detection

## Introduction

The RavenWire Config Manager allows operators to configure sensor pools with capture settings, BPF filter profiles, forwarding sinks, and Suricata rules. Each of these configuration domains has its own versioning system (pool `config_version`, `forwarding_config_version`, BPF `bpf_profile.version`), but there is currently no unified deployment orchestration layer that tracks what was pushed to sensors, when, by whom, and whether it succeeded. The existing rule deployment page dispatches commands to individual sensors via the Sensor Agent Client but does not record per-sensor results, provide rollback capability, or detect configuration drift.

This feature adds a deployment tracking and drift detection system to the Config Manager. It introduces a `deployments` table and `deployment_results` table that record the full lifecycle of every configuration push: pending → validating → deploying → per-sensor results → successful/failed/cancelled/rolled_back. It provides fleet-wide and pool-scoped deployment list pages (`/deployments`, `/deployments/:id`), per-sensor result tracking, configuration diff display, one-click rollback to the previous successful deployment, and drift detection that compares each sensor's last-deployed configuration version against the pool's current desired state.

Deployments target pools and push configuration bundles (capture config, BPF filters, forwarding sinks, Suricata rules) to all deployable enrolled sensors in the pool. Enrolled sensors that cannot receive a control API push are tracked as skipped results. The deployment orchestrator dispatches commands to sensors via the existing Sensor Agent Client over mTLS, collects per-sensor results asynchronously, and transitions the deployment through its lifecycle states. This feature creates the "explicit deployment" layer that the pool management, BPF filter editor, and Vector forwarding specs reference when they say "deployment remains an explicit operator action."

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Pool**: A named grouping of Sensor_Pods that share a common configuration profile. Stored in the `sensor_pools` table.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager. Each Sensor_Pod has an optional `pool_id` foreign key referencing a Sensor_Pool.
- **Deployment**: A tracked configuration push from the Config_Manager to a target Sensor_Pool. Each Deployment records the target pool, configuration snapshot, operator, lifecycle status, and per-sensor results for enrolled sensors in that pool.
- **Deployment_Status**: The lifecycle state of a Deployment. One of: `pending` (created, not yet started), `validating` (pre-flight checks in progress), `deploying` (actively pushing to sensors), `successful` (all deployable targeted sensors accepted the configuration), `failed` (one or more deployable targeted sensors rejected the configuration or were unreachable), `cancelled` (an operator cancelled the deployment before it reached a normal terminal state), `rolled_back` (a later rollback Deployment successfully restored an earlier configuration after this Deployment).
- **Deployment_Result**: A per-sensor outcome record within a Deployment, tracking whether each Sensor_Pod in the target pool accepted, rejected, was unreachable, or was skipped during the push.
- **Sensor_Result_Status**: The outcome for a single sensor within a Deployment. One of: `pending` (not yet attempted), `pushing` (command dispatched, awaiting response), `success` (sensor accepted the configuration), `failed` (sensor rejected or returned an error), `unreachable` (sensor did not respond within the timeout), `skipped` (enrolled sensor was excluded from this deployment, for example because it has no control API host).
- **Configuration_Bundle**: The set of configuration artifacts pushed during a Deployment, including capture config, BPF filter expression, forwarding sink configuration, and Suricata rules from the immutable Configuration_Snapshot.
- **Configuration_Snapshot**: A JSON representation of the full configuration state at the time of deployment, stored on the Deployment record for diff display and rollback reference.
- **Deployment_Diff**: A human-readable comparison between the configuration being deployed and the previously deployed configuration, showing what changed.
- **Drift**: The condition where a Sensor_Pod's last successfully deployed configuration version does not match the Sensor_Pool's current desired configuration version. Drift indicates the sensor is running an outdated or different configuration than what the pool specifies.
- **Drift_Detection**: The process of comparing each sensor's last-deployed configuration version against the pool's current desired version to identify sensors that are out of sync.
- **Rollback**: The act of creating a new Deployment that restores the configuration from the most recent successful Deployment for the same pool before the Deployment being rolled back, effectively reverting a bad push.
- **Deployment_Orchestrator**: The Elixir module that manages the deployment lifecycle: creates the deployment record, runs pre-flight validation, dispatches configuration to sensors via the Sensor Agent Client, collects results, and transitions the deployment through its status states.
- **Sensor_Agent_Client**: The existing mTLS HTTP client module (`ConfigManager.SensorAgentClient`) used to dispatch control commands to Sensor_Agent instances on individual sensors.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that enforces role-based access on routes and LiveView events.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who performed what action, when, on which target, and whether it succeeded.
- **Health_Registry**: The existing module that tracks sensor health state, including degraded conditions and last-seen timestamps.
- **Deployment_Context**: The Elixir context module (`ConfigManager.Deployments`) that provides the public API for deployment CRUD, orchestration, drift detection, and rollback operations.

## Requirements

### Requirement 1: Deployment List Page

**User Story:** As a sensor operator, I want a fleet-wide deployment list page, so that I can see the history and current status of all configuration pushes across all pools.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a deployment list page at `/deployments` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display a paginated table of Deployments ordered by creation timestamp descending, showing for each Deployment: target Sensor_Pool name (linked to the pool detail page), deployed configuration versions, Deployment_Status, operator identity (username or API_Token name), start timestamp, end timestamp (if completed), and a count summary of per-sensor results (e.g., "8 success, 1 failed, 1 unreachable").
3. THE Config_Manager SHALL provide filter controls on the deployment list page allowing Users to filter by: target Sensor_Pool, Deployment_Status, operator, and date range.
4. THE Config_Manager SHALL visually distinguish Deployment_Status values using color-coded badges: `pending` (gray), `validating` (blue), `deploying` (blue with animation), `successful` (green), `failed` (red), `cancelled` (gray), `rolled_back` (amber).
5. WHEN a Deployment is in the `deploying` state, THE Config_Manager SHALL update the deployment row in real time via PubSub as per-sensor results arrive, without requiring a page refresh.
6. THE Config_Manager SHALL display a "New Deployment" button on the deployment list page, visible only to Users whose Role includes the `deployments:manage` Permission.

### Requirement 2: Deployment Detail Page

**User Story:** As a sensor operator, I want a deployment detail page, so that I can see the full context of a specific deployment including per-sensor results, what changed, and rollback options.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a deployment detail page at `/deployments/:id` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display the following deployment metadata on the detail page: target Sensor_Pool name (linked), deployed configuration versions, Deployment_Status, operator identity, operator type (user or API token), start timestamp, end timestamp, and total duration.
3. THE Config_Manager SHALL display a per-sensor results table showing each targeted Sensor_Pod's name (linked to the sensor detail page), Sensor_Result_Status, response message (if any), and timestamp of the result.
4. THE Config_Manager SHALL display a Deployment_Diff section showing the configuration changes between the deployed version and the previously deployed version for the same pool. THE diff SHALL cover capture config fields, BPF filter expression, forwarding sink configuration, and Suricata rule changes.
5. THE Config_Manager SHALL display a "Rollback" button on the detail page for Deployments with status `successful` or `failed` when a previous successful Deployment exists for the same pool, visible only to Users whose Role includes the `deployments:manage` Permission.
6. THE Config_Manager SHALL display a "Cancel" button on the detail page for Deployments with status `pending`, `validating`, or `deploying`, visible only to Users whose Role includes the `deployments:manage` Permission.
7. WHEN a Deployment is in the `deploying` state, THE Config_Manager SHALL update per-sensor results in real time via PubSub as each sensor responds.
8. THE Config_Manager SHALL display the Configuration_Snapshot stored on the Deployment record, allowing the operator to inspect the exact configuration that was pushed.

### Requirement 3: Deployment Creation

**User Story:** As a sensor operator, I want to create a new deployment targeting a pool, so that I can push the pool's current desired configuration to all sensors in the pool.

#### Acceptance Criteria

1. THE Config_Manager SHALL allow Users with the `deployments:manage` Permission to create a new Deployment targeting a specific Sensor_Pool.
2. WHEN a User creates a Deployment, THE Config_Manager SHALL snapshot the pool's current configuration state (capture config, BPF filter profile and compiled expression, forwarding sinks and schema mode, Suricata rules) into a Configuration_Snapshot stored on the Deployment record.
3. WHEN a User creates a Deployment, THE Config_Manager SHALL record the configuration versions being deployed: pool `config_version`, `forwarding_config_version`, and BPF profile `version`.
4. THE Config_Manager SHALL set the initial Deployment_Status to `pending` and record the creating User as the operator.
5. THE Config_Manager SHALL record an Audit_Entry with action `deployment_created` containing the target pool name, configuration versions, and operator identity.
6. THE Config_Manager SHALL prevent creating a new Deployment for a pool that already has a Deployment in `pending`, `validating`, or `deploying` status. IF a User attempts to create a Deployment while one is in progress, THEN THE Config_Manager SHALL return an error indicating a deployment is already active for the pool.
7. WHEN a Deployment is created, THE Config_Manager SHALL identify all Sensor_Pods assigned to the target pool and create a Deployment_Result record for each enrolled Sensor_Pod.
8. WHEN an enrolled Sensor_Pod has a non-null `control_api_host`, THE Config_Manager SHALL create its Deployment_Result with status `pending`; WHEN an enrolled Sensor_Pod lacks a `control_api_host`, THE Config_Manager SHALL create its Deployment_Result with status `skipped` and a message explaining why it cannot be deployed.
9. IF the target Sensor_Pool has no enrolled sensors with a non-null `control_api_host`, THEN THE Config_Manager SHALL reject the Deployment creation with an error indicating no deployable sensors exist in the pool.

### Requirement 4: Deployment Lifecycle Orchestration

**User Story:** As a sensor operator, I want deployments to progress through a defined lifecycle with pre-flight validation and per-sensor tracking, so that I have full visibility into the deployment process and can identify failures quickly.

#### Acceptance Criteria

1. WHEN a Deployment transitions from `pending` to `validating`, THE Deployment_Orchestrator SHALL perform pre-flight checks: verify the target pool exists, verify at least one enrolled sensor with a non-null `control_api_host` is assigned to the pool, and verify the Configuration_Snapshot is complete and well-formed.
2. WHEN pre-flight validation succeeds, THE Deployment_Orchestrator SHALL transition the Deployment to `deploying` status and begin dispatching configuration to sensors.
3. WHEN pre-flight validation fails, THE Deployment_Orchestrator SHALL transition the Deployment to `failed` status with a detail message explaining the validation failure, and SHALL record an Audit_Entry with action `deployment_validation_failed`.
4. WHILE the Deployment is in `deploying` status, THE Deployment_Orchestrator SHALL dispatch the Configuration_Bundle to each targeted Sensor_Pod whose Deployment_Result is `pending` via the Sensor_Agent_Client, updating each Deployment_Result as responses arrive.
5. THE Deployment_Orchestrator SHALL dispatch to sensors concurrently with a configurable concurrency limit (default 5 concurrent sensor pushes) to avoid overwhelming the Config_Manager or the sensor fleet.
6. WHEN a sensor responds successfully, THE Deployment_Orchestrator SHALL update the corresponding Deployment_Result to `success` and broadcast the update via PubSub.
7. WHEN a sensor responds with an error, THE Deployment_Orchestrator SHALL update the corresponding Deployment_Result to `failed` with the error message and broadcast the update via PubSub.
8. WHEN a sensor does not respond within a configurable timeout (default 30 seconds), THE Deployment_Orchestrator SHALL update the corresponding Deployment_Result to `unreachable` and broadcast the update via PubSub.
9. WHEN all Deployment_Results have reached a terminal state (success, failed, unreachable, or skipped), THE Deployment_Orchestrator SHALL transition the Deployment to `successful` if all non-skipped results are `success`, or to `failed` if any non-skipped result is `failed` or `unreachable`.
10. WHEN a Deployment completes (transitions to `successful` or `failed`), THE Deployment_Orchestrator SHALL record the end timestamp and record an Audit_Entry with action `deployment_completed` containing the final status and a summary of per-sensor results.
11. THE Deployment_Orchestrator SHALL run asynchronously under a supervised process so that the initiating LiveView remains responsive during deployment execution.
12. WHEN a Deployment completes with status `successful`, THE Deployment_Orchestrator SHALL update pool-level deployed-version markers for any fully deployed domains, including the BPF_Profile `last_deployed_version` defined in the BPF filter editor spec.
13. WHEN a User with the `deployments:manage` Permission cancels a Deployment in `pending`, `validating`, or `deploying` status, THE Deployment_Orchestrator SHALL stop dispatching new sensor pushes, mark any remaining `pending` Deployment_Results as `skipped` with a cancellation message, transition the Deployment to `cancelled` after any in-flight pushes finish or time out, record the end timestamp, broadcast the status change, and record an Audit_Entry with action `deployment_cancelled`.
14. THE Config_Manager SHALL NOT update any last-deployed version fields or pool-level deployed-version markers for a Deployment that ends in `cancelled` status.

### Requirement 5: Per-Sensor Deployment Results

**User Story:** As a sensor operator, I want to see per-sensor deployment results, so that I can identify exactly which sensors accepted or rejected a configuration push and troubleshoot individual failures.

#### Acceptance Criteria

1. THE Config_Manager SHALL create a Deployment_Result record for each enrolled Sensor_Pod in the target pool when a Deployment is created, with initial Sensor_Result_Status of `pending` for deployable sensors and `skipped` for enrolled sensors that cannot receive a control API push.
2. THE Config_Manager SHALL update each Deployment_Result with the Sensor_Result_Status, response message, and completion timestamp as the Deployment_Orchestrator receives responses from sensors.
3. WHEN an enrolled Sensor_Pod lacks a `control_api_host` at deployment time, THE Config_Manager SHALL set the Deployment_Result to `skipped` with a message explaining why the sensor was excluded. Sensor_Pods that are not enrolled SHALL NOT receive Deployment_Result records for new deployments.
4. THE Config_Manager SHALL store the error message or response body from failed sensor pushes on the Deployment_Result record for troubleshooting, truncating excessively long messages to a configurable maximum length (default 2048 characters).
5. THE Config_Manager SHALL display per-sensor results on the deployment detail page grouped by Sensor_Result_Status, with failed and unreachable sensors displayed first for quick identification.

### Requirement 6: Configuration Diff Display

**User Story:** As a sensor operator, I want to see what changed between deployments, so that I can review the impact of a configuration push before and after it happens.

#### Acceptance Criteria

1. THE Config_Manager SHALL compute and display a Deployment_Diff on the deployment detail page comparing the Configuration_Snapshot of the current Deployment against the Configuration_Snapshot of the most recent previous successful Deployment for the same pool.
2. THE Deployment_Diff SHALL cover the following configuration domains: capture config fields (capture_mode, PCAP settings), BPF filter expression and composition mode, forwarding sinks (added, removed, modified) and schema mode, and Suricata rule changes (added, removed, modified rule files).
3. THE Config_Manager SHALL present the diff in a human-readable format with added items highlighted in green, removed items highlighted in red, and modified items showing old and new values side by side.
4. WHEN no previous successful Deployment exists for the pool, THE Config_Manager SHALL display the full Configuration_Snapshot as "initial deployment" without a diff comparison.
5. THE Config_Manager SHALL NOT include Sink_Secret plaintext values in the Deployment_Diff or Configuration_Snapshot. Secret fields SHALL be represented as "configured" or "not configured" in the diff.

### Requirement 7: Rollback

**User Story:** As a sensor operator, I want to roll back a deployment to the previous successful configuration, so that I can quickly recover when a configuration push breaks sensors.

#### Acceptance Criteria

1. WHEN a User with the `deployments:manage` Permission clicks "Rollback" on a Deployment detail page, THE Config_Manager SHALL create a new Deployment that restores the Configuration_Snapshot from the most recent successful Deployment for the same pool whose `inserted_at` is earlier than the Deployment being rolled back.
2. THE rollback Deployment SHALL follow the same lifecycle as a normal Deployment (pending → validating → deploying → per-sensor results → successful/failed), using the restored Configuration_Snapshot as the configuration to push.
3. THE Config_Manager SHALL record the rollback Deployment with a `rollback_of_deployment_id` field referencing the Deployment being rolled back, and a `source_deployment_id` field referencing the Deployment whose Configuration_Snapshot is being restored.
4. WHEN a rollback Deployment completes successfully, THE Config_Manager SHALL update the Deployment being rolled back to status `rolled_back` without modifying the successful source Deployment being restored.
5. THE Config_Manager SHALL record an Audit_Entry with action `deployment_rollback_initiated` containing the original deployment ID, the source deployment ID, the target pool, and the operator identity.
6. IF no previous successful Deployment exists for the pool, THEN THE Config_Manager SHALL disable the Rollback button and display a tooltip explaining that no previous successful deployment is available to restore.
7. THE Config_Manager SHALL prevent rollback of a Deployment that is already in `rolled_back` status or that has an active rollback Deployment in progress.

### Requirement 8: Drift Detection

**User Story:** As a sensor operator, I want to see which sensors are not running the pool's current desired configuration, so that I can identify drift and decide whether to deploy.

#### Acceptance Criteria

1. THE Config_Manager SHALL track the last successfully deployed configuration versions per sensor by updating `last_deployed_config_version`, `last_deployed_forwarding_version`, and `last_deployed_bpf_version` fields on each Sensor_Pod when a Deployment succeeds for that sensor.
2. THE Config_Manager SHALL compute drift by comparing each sensor's last-deployed versions against the pool's current desired versions (`config_version`, `forwarding_config_version`, and BPF profile `version`).
3. THE Config_Manager SHALL display a drift summary on the pool detail page showing: the number of sensors in sync, the number of sensors with drift, and the number of sensors that have never been deployed to.
4. THE Config_Manager SHALL display a drift detail view accessible from the pool detail page, listing each sensor in the pool with its drift status: "in sync," "drift detected" (with which configuration domains are out of date), or "never deployed."
5. WHEN drift is detected for one or more sensors in a pool, THE Config_Manager SHALL display a visual indicator (badge or icon) on the pool's entry in the pool list page and on the pool detail page navigation.
6. THE Config_Manager SHALL update drift status in real time when a Deployment completes, reflecting the new deployment state without requiring a page refresh.
7. THE Config_Manager SHALL treat sensors that have never received a successful deployment as "never deployed" rather than "in sync," even if the pool's configuration versions are at their initial values.

### Requirement 9: Deployment Data Model

**User Story:** As an engineer implementing deployment tracking, I want a well-defined data model for deployments and per-sensor results, so that the deployment lifecycle is stored reliably and supports querying, diffing, and rollback.

#### Acceptance Criteria

1. THE Config_Manager SHALL create a `deployments` table via an Ecto migration with the following columns: `id` (binary_id primary key), `pool_id` (binary_id foreign key to `sensor_pools`, on_delete cascade), `status` (text, not null, default `pending`), `operator` (text, not null), `operator_type` (text, not null), `config_version` (integer, not null), `forwarding_config_version` (integer), `bpf_version` (integer), `config_snapshot` (map/jsonb, not null, Configuration_Snapshot), `diff_summary` (map/jsonb, nullable, Deployment_Diff), `rollback_of_deployment_id` (binary_id, nullable, self-referencing foreign key), `source_deployment_id` (binary_id, nullable, self-referencing foreign key), `started_at` (utc_datetime_usec, nullable), `completed_at` (utc_datetime_usec, nullable), `failure_reason` (text, nullable), `inserted_at` (utc_datetime_usec), `updated_at` (utc_datetime_usec).
2. THE Config_Manager SHALL create a `deployment_results` table via an Ecto migration with the following columns: `id` (binary_id primary key), `deployment_id` (binary_id foreign key to `deployments`, on_delete cascade), `sensor_pod_id` (binary_id foreign key to `sensor_pods`, on_delete cascade), `status` (text, not null, default `pending`), `message` (text, nullable), `started_at` (utc_datetime_usec, nullable), `completed_at` (utc_datetime_usec, nullable), `inserted_at` (utc_datetime_usec), `updated_at` (utc_datetime_usec).
3. THE Config_Manager SHALL create indexes on `deployments` for: `pool_id`, `status`, `inserted_at`, and the composite `(pool_id, status)` for active deployment checks.
4. THE Config_Manager SHALL create indexes on `deployment_results` for: `deployment_id`, `sensor_pod_id`, and `status`.
5. THE Config_Manager SHALL validate `status` values on the `deployments` table against the allowed set: `pending`, `validating`, `deploying`, `successful`, `failed`, `cancelled`, `rolled_back`.
6. THE Config_Manager SHALL validate `status` values on the `deployment_results` table against the allowed set: `pending`, `pushing`, `success`, `failed`, `unreachable`, `skipped`.
7. THE Config_Manager SHALL cascade-delete Deployments and Deployment_Results when their parent Sensor_Pool is deleted.

### Requirement 10: Drift Tracking Data Model

**User Story:** As an engineer implementing drift detection, I want per-sensor version tracking fields, so that drift can be computed efficiently without scanning all historical deployment results.

#### Acceptance Criteria

1. THE Config_Manager SHALL add the following fields to the `sensor_pods` table via migration: `last_deployed_config_version` (integer, nullable), `last_deployed_forwarding_version` (integer, nullable), `last_deployed_bpf_version` (integer, nullable), `last_deployed_at` (utc_datetime_usec, nullable), `last_deployment_id` (binary_id, nullable, foreign key to `deployments`).
2. WHEN a Deployment_Result for a Sensor_Pod transitions to `success`, THE Config_Manager SHALL update the sensor's last-deployed version fields to match the Deployment's configuration versions and set `last_deployed_at` to the current timestamp.
3. WHEN a Deployment_Result for a Sensor_Pod transitions to `success`, THE Config_Manager SHALL set the sensor's `last_deployment_id` to the successful Deployment's ID.
4. THE Config_Manager SHALL NOT update last-deployed version fields when a Deployment_Result is `failed`, `unreachable`, or `skipped`.
5. THE Config_Manager SHALL compute drift by comparing `sensor_pod.last_deployed_config_version` against `sensor_pool.config_version`, `sensor_pod.last_deployed_forwarding_version` against `sensor_pool.forwarding_config_version`, and `sensor_pod.last_deployed_bpf_version` against the pool's BPF profile `version`.

### Requirement 11: RBAC Integration

**User Story:** As a platform admin, I want deployment actions protected by role-based access control, so that only authorized users can initiate deployments and rollbacks.

#### Acceptance Criteria

1. THE Config_Manager SHALL use the canonical `deployments:manage` Permission from the auth-rbac-audit spec for deployment write operations (create deployment, initiate rollback, cancel deployment).
2. THE Config_Manager SHALL verify that the auth-rbac-audit Policy grants `deployments:manage` to the `sensor-operator`, `rule-manager`, and `platform-admin` Roles, consistent with the `pools:manage` and `forwarding:manage` Permission grant patterns.
3. THE Config_Manager SHALL grant read-only deployment access (`sensors:view`) to all authenticated Roles, allowing viewing of the deployment list, deployment details, per-sensor results, diffs, and drift status.
4. WHEN a User without the `deployments:manage` Permission attempts a deployment write action via LiveView event, THE RBAC_Gate SHALL deny the action, display an error flash, and record an Audit_Entry with action `permission_denied`.
5. THE Config_Manager SHALL hide deployment write UI elements (New Deployment button, Rollback button, Cancel button) from Users whose Role does not include the `deployments:manage` Permission.
6. THE Config_Manager SHALL enforce RBAC on every LiveView `handle_event` callback for deployment write actions, regardless of whether the UI element is hidden.

### Requirement 12: Audit Logging for Deployment Actions

**User Story:** As an auditor, I want all deployment actions recorded in the audit log, so that every configuration push, rollback, and failure is traceable and attributable.

#### Acceptance Criteria

1. THE Config_Manager SHALL record an Audit_Entry for each of the following deployment actions: `deployment_created`, `deployment_started`, `deployment_validation_failed`, `deployment_completed`, `deployment_rollback_initiated`, `deployment_cancelled`.
2. EACH deployment-related Audit_Entry SHALL contain: the actor identity (username or API_Token name), the actor type, the action name, `target_type` set to `deployment`, `target_id` set to the Deployment's ID, the result (`success` or `failure`), and a JSON detail field with action-specific context including the target pool name and configuration versions.
3. THE Config_Manager SHALL write deployment-related Audit_Entries within the same database transaction as the deployment state change when possible, so that if the audit write fails, the state change is rolled back.
4. THE Config_Manager SHALL NOT include Sink_Secret values in any deployment-related Audit_Entry detail field or Configuration_Snapshot. Secret fields SHALL be represented as "configured" or "not configured."
5. WHEN a Deployment completes, THE Audit_Entry detail SHALL include a summary of per-sensor results: counts of success, failed, unreachable, and skipped sensors.

### Requirement 13: Real-Time Updates

**User Story:** As a sensor operator, I want deployment progress and drift status to update in real time, so that I can monitor active deployments without refreshing the page.

#### Acceptance Criteria

1. THE Config_Manager SHALL broadcast deployment status changes to a `"deployment:#{deployment_id}"` PubSub topic, allowing the deployment detail page to update in real time.
2. THE Config_Manager SHALL broadcast per-sensor result updates to the `"deployment:#{deployment_id}"` PubSub topic as each sensor responds during a deployment.
3. THE Config_Manager SHALL broadcast deployment lifecycle events (created, completed, cancelled, rolled back) to a `"pool:#{pool_id}:deployments"` PubSub topic, allowing the pool deployment history and drift views to update in real time.
4. THE Config_Manager SHALL broadcast drift status changes to the `"pool:#{pool_id}:drift"` PubSub topic when a deployment completes, allowing drift views to reflect the new state.
5. THE Config_Manager SHALL subscribe the deployment list page to a `"deployments"` fleet-wide PubSub topic for new deployment creation and completion events.

### Requirement 14: Navigation and UI Integration

**User Story:** As a sensor operator, I want deployment tracking and drift detection integrated into the existing navigation, so that I can access deployment information from the places I already work.

#### Acceptance Criteria

1. THE Config_Manager SHALL add a "Deployments" link to the main navigation bar, linking to `/deployments`, visible to all authenticated Users.
2. THE Config_Manager SHALL add a "Deployments" tab to the pool detail page navigation, linking to a pool-scoped deployment history view showing only deployments for that pool.
3. THE Config_Manager SHALL add a "Drift" tab or section to the pool detail page showing the drift summary and per-sensor drift status for the pool.
4. THE Config_Manager SHALL display the sensor's last-deployed configuration version and drift status on the sensor detail page's identity or configuration section.
5. WHEN a pool has sensors with detected drift, THE Config_Manager SHALL display a drift indicator badge on the pool's row in the pool list page.
6. THE Config_Manager SHALL display a "Deploy Now" action on the pool detail page when the pool's current configuration versions are ahead of the last successful deployment, visible only to Users with the `deployments:manage` Permission.

### Requirement 15: Configuration Snapshot Integrity

**User Story:** As a sensor operator, I want deployment configuration snapshots to be complete and immutable, so that I can always see exactly what was deployed and use it for rollback.

#### Acceptance Criteria

1. THE Config_Manager SHALL capture a complete Configuration_Snapshot at deployment creation time, including: all pool config fields (capture_mode, PCAP settings), the BPF profile's compiled expression and composition mode, all enabled forwarding sinks with their non-secret configuration and schema mode, and all Suricata rule file contents.
2. THE Config_Manager SHALL NOT modify a Configuration_Snapshot after the Deployment record is created. The snapshot is immutable for the lifetime of the Deployment record.
3. THE Config_Manager SHALL NOT include Sink_Secret plaintext or ciphertext values in the Configuration_Snapshot. Secret fields SHALL be represented as a boolean indicating whether the secret is configured.
4. THE Config_Manager SHALL store the Configuration_Snapshot as structured JSON data on the Deployment record, ensuring it can be decoded and displayed on the deployment detail page.
5. FOR ALL Configuration_Snapshots, encoding the snapshot to JSON and then decoding it SHALL produce an equivalent data structure (round-trip property).
