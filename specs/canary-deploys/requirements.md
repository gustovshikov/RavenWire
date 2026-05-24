# Requirements Document: Canary Deployment Workflow

## Introduction

The RavenWire Config Manager's deployment-tracking spec provides a deployment orchestration system that pushes configuration bundles to all enrolled sensors in a pool simultaneously. While this approach is efficient, it carries risk: a bad configuration change (broken BPF filter, incompatible Suricata rules, misconfigured forwarding sink) can impact every sensor in a pool at once, potentially causing fleet-wide capture loss or data pipeline failure.

This feature adds a canary deployment workflow that deploys configuration changes to a small subset of pool members first, monitors the canary sensor(s) for a configurable observation period, and then either auto-promotes the deployment to the full pool (if the canary is healthy) or auto-rolls back (if the canary shows degradation). This provides a safety net for configuration changes by catching problems on one or a few sensors before they affect the entire fleet.

The canary workflow integrates with the existing deployment lifecycle from the deployment-tracking spec. A canary deployment is a standard Deployment record with additional canary-specific metadata (canary sensor selection, observation period, health evaluation criteria). The deployment progresses through the standard lifecycle states but adds a `canary_observing` phase between the canary sensor push and the full pool rollout.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Canary_Deployment**: A Deployment that targets a subset of pool members first (the canary group), observes their health for a configurable period, and then either promotes to the full pool or rolls back based on health evaluation.
- **Canary_Group**: The subset of Sensor_Pods in a pool selected to receive the configuration change first. May be a single sensor or a configurable percentage of the pool.
- **Canary_Selection_Strategy**: The method used to choose which sensors form the Canary_Group. Options: `single` (one sensor, operator-selected or auto-selected), `percentage` (a configurable percentage of pool members, rounded up to at least one).
- **Observation_Period**: The duration (in minutes) after the canary sensor(s) successfully receive the configuration during which the Config_Manager monitors their health before deciding to promote or rollback. Default: 10 minutes.
- **Health_Evaluation**: The process of comparing canary sensor health metrics during the Observation_Period against pre-deployment baselines and configured thresholds to determine whether the canary is healthy.
- **Canary_Health_Criteria**: The set of health conditions that must be met for a canary to be considered healthy: no new platform alerts fired, packet drop rate not increased beyond threshold, all containers running, forwarding sinks operational.
- **Auto_Promote**: The automatic progression of a Canary_Deployment from the canary group to the remaining pool members after the Observation_Period completes with a healthy canary evaluation.
- **Auto_Rollback**: The automatic rollback of a Canary_Deployment when the canary health evaluation detects degradation during the Observation_Period.
- **Deployment**: A tracked configuration push from the Config_Manager to a target Sensor_Pool, from the deployment-tracking spec.
- **Deployment_Status**: The lifecycle state of a Deployment. Extended with `canary_deploying` and `canary_observing` states for canary deployments.
- **Sensor_Result_Status**: The per-sensor deployment result state from the deployment-tracking spec. Extended with `awaiting_canary` for non-canary sensors that are intentionally held until the canary phase is promoted.
- **Deployment_Orchestrator**: The module that manages the deployment lifecycle, extended to support canary phases.
- **Sensor_Pool**: A named grouping of Sensor_Pods from the sensor-pool-management spec.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager.
- **Health_Registry**: The existing in-memory health store that tracks per-sensor health state.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec.
- **Audit_Entry**: An append-only record in the `audit_log` table.

## Requirements

### Requirement 1: Canary Deployment Creation

**User Story:** As a sensor operator, I want to create a canary deployment that targets a subset of pool members first, so that I can test configuration changes on a small group before rolling out to the full pool.

#### Acceptance Criteria

1. WHEN a User with the `deployments:manage` Permission creates a new Deployment, THE Config_Manager SHALL offer a "Canary Deployment" option alongside the existing "Full Deployment" option.
2. WHEN the User selects "Canary Deployment," THE Config_Manager SHALL present canary configuration options: Canary_Selection_Strategy (`single` or `percentage`), specific sensor selection (when strategy is `single`), percentage value (when strategy is `percentage`, default 10%, minimum 1 sensor), and Observation_Period in minutes (default 10, minimum 1, maximum 60).
3. THE Config_Manager SHALL store canary configuration on the Deployment record: `deployment_type` (`full` or `canary`), `canary_strategy`, `canary_percentage`, `canary_sensor_ids` (list of selected canary Sensor_Pod IDs), and `observation_period_minutes`.
4. WHEN the Canary_Selection_Strategy is `percentage`, THE Config_Manager SHALL auto-select canary sensors by choosing the configured percentage of deployable enrolled pool members (rounded up to at least one), preferring sensors with the longest uptime.
5. THE Config_Manager SHALL record an Audit_Entry with action `canary_deployment_created` containing the canary configuration, target pool, and selected canary sensor IDs.
6. THE Config_Manager SHALL prevent creating a Canary_Deployment for a pool with fewer than 2 deployable sensors, since a canary requires at least one canary sensor and one remaining sensor.

### Requirement 2: Canary Deployment Lifecycle

**User Story:** As a sensor operator, I want the canary deployment to progress through defined phases, so that I have full visibility into the canary test and subsequent rollout.

#### Acceptance Criteria

1. THE Deployment_Orchestrator SHALL extend the Deployment lifecycle with two additional states for canary deployments: `canary_deploying` (pushing configuration to canary sensors only) and `canary_observing` (monitoring canary health during the Observation_Period).
2. A Canary_Deployment SHALL progress through the following lifecycle: `pending` → `validating` → `canary_deploying` → `canary_observing` → `deploying` (remaining pool members) → `successful`/`failed`, with `cancelled` and `rolled_back` as terminal states reachable according to the deployment-tracking spec.
3. WHEN the Canary_Deployment enters `canary_deploying`, THE Deployment_Orchestrator SHALL push the Configuration_Bundle only to the Canary_Group sensors, setting canary sensor Deployment_Result records to `pending` and remaining deployable sensor Deployment_Result records to `awaiting_canary`.
4. WHEN all canary sensor Deployment_Results reach a terminal state, THE Deployment_Orchestrator SHALL evaluate the canary results: if all canary sensors succeeded, transition to `canary_observing`; if any canary sensor failed or was unreachable, mark remaining `awaiting_canary` results as `skipped` and transition to `failed`.
5. WHEN the Canary_Deployment enters `canary_observing`, THE Deployment_Orchestrator SHALL start a timer for the configured Observation_Period and begin Health_Evaluation of the canary sensors.
6. THE Config_Manager SHALL broadcast canary lifecycle state changes to the deployment PubSub topics for real-time UI updates.
7. THE Config_Manager SHALL record an Audit_Entry for each canary lifecycle transition: `canary_deploy_started`, `canary_observation_started`, `canary_observation_completed`, `canary_promoted`, `canary_rollback_initiated`.
8. THE Config_Manager SHALL validate Deployment status values against the deployment-tracking statuses plus `canary_deploying` and `canary_observing`.
9. THE Config_Manager SHALL validate Deployment_Result status values against the deployment-tracking result statuses plus `awaiting_canary`.

### Requirement 3: Canary Health Evaluation

**User Story:** As a sensor operator, I want the canary sensor health automatically evaluated during the observation period, so that degradation is detected without manual monitoring.

#### Acceptance Criteria

1. DURING the Observation_Period, THE Config_Manager SHALL periodically evaluate the Canary_Health_Criteria for each canary sensor at a configurable interval (default every 30 seconds).
2. THE Canary_Health_Criteria SHALL include: no new platform alerts fired for the canary sensor since the canary deployment started, packet drop rate has not increased by more than a configurable threshold (default 2 percentage points) compared to the pre-deployment baseline, all expected containers are in running state, and forwarding sinks are operational (no new sink-down conditions).
3. THE Config_Manager SHALL capture a pre-deployment health baseline for each canary sensor immediately before the canary push begins, recording: current packet drop rate, container states, forwarding sink states, and active platform alert count.
4. WHEN any Canary_Health_Criteria check fails during the Observation_Period, THE Config_Manager SHALL immediately trigger Auto_Rollback without waiting for the full Observation_Period to elapse.
5. THE Config_Manager SHALL broadcast health evaluation results to the deployment PubSub topic so the deployment detail page can display canary health status in real time.
6. THE Config_Manager SHALL log each health evaluation result at the `:debug` level and log health failures at the `:warning` level.

### Requirement 4: Auto-Promote to Full Pool

**User Story:** As a sensor operator, I want the canary deployment to automatically promote to the full pool when the canary is healthy, so that successful changes roll out without manual intervention.

#### Acceptance Criteria

1. WHEN the Observation_Period completes and all Canary_Health_Criteria checks have passed throughout the period, THE Deployment_Orchestrator SHALL automatically transition the Canary_Deployment from `canary_observing` to `deploying` and push the Configuration_Bundle to the remaining pool members.
2. THE Config_Manager SHALL update the Deployment_Result records for remaining sensors from `awaiting_canary` to `pending` before dispatching configuration to them.
3. THE Config_Manager SHALL record an Audit_Entry with action `canary_promoted` containing the canary sensor IDs, observation duration, and health evaluation summary.
4. AFTER promotion, THE remaining pool deployment SHALL follow the standard deployment lifecycle (concurrent dispatch, per-sensor results, final status determination) from the deployment-tracking spec.
5. THE Config_Manager SHALL display a "Canary Passed — Promoting to Full Pool" status message on the deployment detail page during promotion.

### Requirement 5: Auto-Rollback on Canary Degradation

**User Story:** As a sensor operator, I want the canary deployment to automatically roll back when the canary shows degradation, so that bad configuration changes are reverted before affecting the full pool.

#### Acceptance Criteria

1. WHEN a Canary_Health_Criteria check fails during the Observation_Period, THE Deployment_Orchestrator SHALL initiate Auto_Rollback: push the previous successful configuration to the canary sensors and transition the Canary_Deployment to `failed` with a failure reason describing the health degradation.
2. THE Auto_Rollback SHALL restore the Configuration_Snapshot from the most recent successful Deployment for the same pool, consistent with the rollback mechanism from the deployment-tracking spec.
3. THE Config_Manager SHALL record an Audit_Entry with action `canary_rollback_initiated` containing the failed health criteria, canary sensor IDs, and the source deployment being restored.
4. THE Config_Manager SHALL mark remaining (non-canary) sensor Deployment_Results as `skipped` with a message indicating the canary failed, since they never received the new configuration.
5. THE Config_Manager SHALL display a "Canary Failed — Rolling Back" status message on the deployment detail page with details of which health criteria failed.
6. WHEN the Auto_Rollback push to canary sensors completes successfully, THE Config_Manager SHALL update the canary sensors' last-deployed version fields to reflect the restored configuration and SHALL NOT update last-deployed fields for remaining sensors that never received the canary configuration.
7. IF no previous successful Deployment exists for the same pool, THEN THE Config_Manager SHALL mark remaining sensor Deployment_Results as `skipped`, transition the Canary_Deployment to `failed`, and display that automatic rollback could not be performed because no restore point exists.

### Requirement 6: Manual Canary Override

**User Story:** As a sensor operator, I want to manually promote or abort a canary deployment during the observation period, so that I can override the automatic decision when I have additional context.

#### Acceptance Criteria

1. DURING the `canary_observing` phase, THE Config_Manager SHALL display "Promote Now" and "Abort Canary" buttons on the deployment detail page, visible only to Users with the `deployments:manage` Permission.
2. WHEN a User clicks "Promote Now," THE Deployment_Orchestrator SHALL skip the remaining Observation_Period and immediately promote the deployment to the full pool, following the same promotion flow as Auto_Promote.
3. WHEN a User clicks "Abort Canary," THE Deployment_Orchestrator SHALL initiate rollback of the canary sensors and transition the Deployment to `cancelled`, following the same rollback flow as Auto_Rollback.
4. THE Config_Manager SHALL record an Audit_Entry with action `canary_manual_promote` or `canary_manual_abort` containing the operator identity and the reason (if provided).

### Requirement 7: Canary Deployment UI

**User Story:** As a sensor operator, I want the deployment detail page to show canary-specific information, so that I can monitor the canary test progress and health evaluation results.

#### Acceptance Criteria

1. THE Config_Manager SHALL display canary deployment metadata on the deployment detail page: canary strategy, selected canary sensors, observation period, and current observation elapsed time.
2. THE Config_Manager SHALL display a canary health dashboard section during the `canary_observing` phase showing: per-canary-sensor health status (healthy/degraded), pre-deployment baseline values, current metric values, and health criteria pass/fail indicators.
3. THE Config_Manager SHALL visually distinguish canary sensors from remaining sensors in the per-sensor results table using a "canary" badge or icon.
4. THE Config_Manager SHALL display a progress indicator showing the elapsed time versus total Observation_Period during the `canary_observing` phase.
5. THE Config_Manager SHALL display canary deployment status badges using distinct colors: `canary_deploying` (blue), `canary_observing` (amber with animation), alongside the existing deployment status colors.
6. THE Config_Manager SHALL update canary health evaluation results in real time via PubSub without requiring a page refresh.

### Requirement 8: Canary Deployment on Deployment List

**User Story:** As a sensor operator, I want canary deployments clearly identified on the deployment list page, so that I can distinguish them from full deployments.

#### Acceptance Criteria

1. THE Config_Manager SHALL display a "Canary" badge on canary deployments in the deployment list page.
2. THE Config_Manager SHALL include `canary_deploying` and `canary_observing` in the deployment status filter options on the deployment list page.
3. THE Config_Manager SHALL display the canary observation progress (e.g., "Observing: 4m / 10m") in the deployment list row for deployments in `canary_observing` status.

### Requirement 9: Audit Logging

**User Story:** As an auditor, I want all canary deployment actions recorded in the audit log, so that canary decisions and health evaluations are traceable.

#### Acceptance Criteria

1. THE Config_Manager SHALL record Audit_Entries for: `canary_deployment_created`, `canary_deploy_started`, `canary_observation_started`, `canary_observation_completed`, `canary_promoted`, `canary_manual_promote`, `canary_rollback_initiated`, `canary_manual_abort`, and `canary_health_degradation_detected`.
2. EACH canary-related Audit_Entry SHALL contain: the actor identity, the action name, the deployment ID, the target pool, and a JSON detail field with canary-specific context (canary sensor IDs, health criteria results, observation duration).
3. THE `canary_health_degradation_detected` Audit_Entry SHALL include the specific health criteria that failed, the baseline values, and the observed values at the time of failure.

### Requirement 10: Canary Data Model

**User Story:** As an engineer implementing canary deployments, I want the deployment schema extensions defined, so that canary metadata and result states are stored consistently.

#### Acceptance Criteria

1. THE Config_Manager SHALL extend the `deployments` table with nullable canary metadata fields: `deployment_type` (text, not null, default `full`), `canary_strategy` (text, nullable), `canary_percentage` (integer, nullable), `canary_sensor_ids` (array/jsonb of Sensor_Pod IDs, nullable), `observation_period_minutes` (integer, nullable), `canary_started_at` (utc_datetime_usec, nullable), and `canary_observation_ends_at` (utc_datetime_usec, nullable).
2. THE Config_Manager SHALL validate `deployment_type` values against `full` and `canary`.
3. THE Config_Manager SHALL validate `canary_strategy` values against `single` and `percentage` when `deployment_type` is `canary`.
4. THE Config_Manager SHALL store canary health evaluation summaries in the Deployment's existing `diff_summary` or a dedicated structured JSON field so the deployment detail page can render historical canary results after completion.

### Requirement 11: Deferred Capabilities

**User Story:** As a product owner, I want deferred canary deployment capabilities documented, so that the team knows what is planned for future enhancements.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement multi-stage canary rollouts (e.g., 10% → 25% → 50% → 100%) in this feature. Only single-stage canary (canary group → full pool) is supported. Multi-stage rollout is deferred to a future enhancement.
2. THE Config_Manager SHALL NOT implement canary deployment for detection content independently of full configuration deployment in this feature. Canary applies to the entire Configuration_Bundle. Per-domain canary is deferred.
3. THE Config_Manager SHALL NOT implement automated canary scheduling (e.g., "deploy canary at 2 AM") in this feature. Canary deployments are operator-initiated. Scheduling is deferred.
4. THE Config_Manager SHALL NOT implement canary traffic comparison (comparing canary sensor alert output against non-canary sensors) in this feature. Traffic-level comparison is deferred to a future analytics enhancement.
