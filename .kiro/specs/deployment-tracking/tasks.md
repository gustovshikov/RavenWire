# Implementation Plan: Deployment Tracking and Drift Detection

## Overview

This plan implements a deployment orchestration, tracking, and drift detection system for the RavenWire Config Manager. The implementation proceeds bottom-up: database migrations and schemas first, then context logic (snapshot, diff, drift, orchestration), then LiveView UI, and finally integration wiring. Each task builds on the previous, ensuring no orphaned code.

## Tasks

- [ ] 1. Create database migrations and Ecto schemas
  - [ ] 1.1 Create the `deployments` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_deployments.exs`
    - Add all columns: `id` (binary_id PK), `pool_id` (FK to sensor_pools, on_delete cascade), `status` (text, not null, default "pending"), `operator`, `operator_type`, `config_version`, `forwarding_config_version`, `bpf_version`, `config_snapshot` (map, not null), `diff_summary` (map), `rollback_of_deployment_id` (self-ref FK), `source_deployment_id` (self-ref FK), `started_at`, `completed_at`, `failure_reason`, timestamps
    - Create indexes: `pool_id`, `status`, `inserted_at`, composite `(pool_id, status)`
    - _Requirements: 9.1, 9.3_

  - [ ] 1.2 Create the `deployment_results` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_deployment_results.exs`
    - Add all columns: `id` (binary_id PK), `deployment_id` (FK to deployments, on_delete cascade), `sensor_pod_id` (FK to sensor_pods, on_delete cascade), `status` (text, not null, default "pending"), `message` (text), `started_at`, `completed_at`, timestamps
    - Create indexes: `deployment_id`, `sensor_pod_id`, `status`
    - _Requirements: 9.2, 9.4, 9.7_

  - [ ] 1.3 Create the drift tracking fields migration for `sensor_pods`
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_add_drift_fields_to_sensor_pods.exs`
    - Add columns: `last_deployed_config_version` (integer), `last_deployed_forwarding_version` (integer), `last_deployed_bpf_version` (integer), `last_deployed_at` (utc_datetime_usec), `last_deployment_id` (FK to deployments, on_delete nilify_all)
    - _Requirements: 10.1_

  - [ ] 1.4 Create the `Deployment` Ecto schema
    - Create `lib/config_manager/deployments/deployment.ex`
    - Define schema with all fields, belongs_to/has_many associations
    - Implement `create_changeset/2` with required field validation and operator_type inclusion check
    - Implement `status_changeset/3` with status inclusion validation and transition validation
    - Define `@valid_transitions` map enforcing: pending→{validating,cancelled}, validating→{deploying,failed,cancelled}, deploying→{successful,failed,cancelled}, successful→{rolled_back}, failed→{rolled_back}, cancelled→{}, rolled_back→{}
    - _Requirements: 9.5_

  - [ ] 1.5 Create the `DeploymentResult` Ecto schema
    - Create `lib/config_manager/deployments/deployment_result.ex`
    - Define schema with all fields and belongs_to associations
    - Implement `create_changeset/2` and `update_changeset/2` with status validation
    - Implement message truncation to 2048 characters in changesets
    - _Requirements: 9.6, 5.4_

  - [ ] 1.6 Extend the `SensorPod` schema with drift tracking fields
    - Add `last_deployed_config_version`, `last_deployed_forwarding_version`, `last_deployed_bpf_version`, `last_deployed_at`, `last_deployment_id` fields to the existing `SensorPod` schema
    - Add `deployment_success_changeset/2` for updating last-deployed version fields
    - _Requirements: 10.1, 8.1_

  - [ ]* 1.7 Write property tests for Deployment schema status validation and transitions
    - **Property 13: Deployment and result status validation** — generate random strings, verify changeset accepts only valid status values
    - **Property 14: Deployment status transitions follow valid paths** — generate all status pairs, verify transition validity against the defined transition map
    - **Validates: Requirements 9.5, 9.6, 4.1, 4.2, 4.3, 4.9, 4.13**

  - [ ]* 1.8 Write property test for DeploymentResult message truncation
    - **Property 15: Error message truncation** — generate random strings of varying lengths, verify messages are truncated to at most 2048 characters and messages at or below 2048 are stored unchanged
    - **Validates: Requirements 5.4**

- [ ] 2. Checkpoint — Run migrations and verify schemas compile
  - Run `mix ecto.migrate` to verify all three migrations apply cleanly
  - Run `mix compile` to verify schemas compile without errors
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Implement configuration snapshot and diff modules
  - [ ] 3.1 Implement `Deployments.Snapshot` module
    - Create `lib/config_manager/deployments/snapshot.ex`
    - Implement `capture/1` that reads pool config (capture config, BPF profile with rules, forwarding sinks with schema mode, Suricata rules) and builds the snapshot map with `captured_at` timestamp
    - Implement `sanitize_sink/1` to replace secret values with boolean presence indicators
    - Implement `validate/1` to check snapshot completeness (all four domains present)
    - Ensure no secret plaintext/ciphertext values appear in snapshots
    - _Requirements: 3.2, 15.1, 15.2, 15.3, 6.5_

  - [ ] 3.2 Implement `Deployments.Diff` module
    - Create `lib/config_manager/deployments/diff.ex`
    - Implement `compute/2` that compares two snapshots, returns nil when previous is nil
    - Implement `diff_capture/2` for capture config field changes (old/new values)
    - Implement `diff_bpf/2` for BPF expression and rule changes
    - Implement `diff_forwarding/2` for forwarding sink additions/removals/modifications and schema mode changes
    - Implement `diff_rules/2` for Suricata rule file additions/removals/modifications
    - _Requirements: 6.1, 6.2, 6.4_

  - [ ]* 3.3 Write property tests for snapshot and diff
    - **Property 1: Configuration snapshot JSON round-trip** — generate random snapshot maps, verify `Jason.decode!(Jason.encode!(snapshot))` produces equivalent structure
    - **Property 3: Secret exclusion from snapshots and diffs** — generate sinks with random secret configurations, verify no secret values appear in snapshot or diff output
    - **Property 10: Diff computation identifies all changes between snapshots** — generate random snapshot pairs, verify diff captures all changed fields across all domains
    - **Validates: Requirements 15.4, 15.5, 6.5, 12.4, 15.3, 6.1, 6.2**

- [ ] 4. Implement drift detection module
  - [ ] 4.1 Implement `Deployments.DriftDetector` module
    - Create `lib/config_manager/deployments/drift_detector.ex`
    - Implement `compute/1` that loads pool and its sensors, compares per-sensor `last_deployed_*_version` fields against pool's current versions (`config_version`, `forwarding_config_version`, BPF profile `version`)
    - Return per-sensor drift results: `%{sensor: sensor, status: :in_sync | :drift_detected | :never_deployed, domains: [atom()]}`
    - Treat sensors with all nil `last_deployed_*_version` fields as `:never_deployed`
    - Skip BPF domain comparison when pool has no BPF profile
    - Implement `summary/1` returning counts of in_sync, drift_detected, never_deployed, total
    - Implement `sensor_drift/1` for single-sensor drift computation
    - _Requirements: 8.1, 8.2, 8.7, 10.5_

  - [ ]* 4.2 Write property test for drift computation
    - **Property 9: Drift computation correctness** — generate random sensor/pool version tuples including nil values, verify drift status classification matches the specification
    - **Validates: Requirements 8.2, 8.7, 10.5**

- [ ] 5. Implement the Deployments context module (CRUD, creation, rollback)
  - [ ] 5.1 Implement deployment CRUD and creation in `ConfigManager.Deployments`
    - Create `lib/config_manager/deployments.ex`
    - Implement `list_deployments/1` with pagination, filtering (pool, status, operator, date range), and descending insertion order
    - Implement `list_pool_deployments/2` for pool-scoped listing with pagination
    - Implement `get_deployment/1` and `get_deployment!/1` with preloaded results and pool
    - Implement `create_deployment/3`: check for active deployments, capture snapshot via `Snapshot.capture/1`, compute diff via `Diff.compute/2`, use `Ecto.Multi` to insert deployment + deployment_results for each enrolled sensor + audit entry (`deployment_created`), broadcast to PubSub topics, kick off orchestration
    - Create deployment_result records: `pending` for sensors with `control_api_host`, `skipped` for sensors without
    - Reject creation if no deployable sensors exist (`:no_deployable_sensors`)
    - Reject creation if active deployment exists (`:active_deployment_exists`)
    - Implement `has_active_deployment?/1`, `last_successful_deployment/1`, `last_deployment/1`
    - _Requirements: 1.1, 1.2, 1.3, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 12.1, 12.2, 12.3_

  - [ ] 5.2 Implement cancellation in `ConfigManager.Deployments`
    - Implement `cancel_deployment/2`: validate deployment is in cancellable state (pending/validating/deploying), mark remaining pending results as skipped, transition to cancelled, write audit entry (`deployment_cancelled`), broadcast via PubSub
    - _Requirements: 4.13, 4.14, 12.1_

  - [ ] 5.3 Implement rollback in `ConfigManager.Deployments`
    - Implement `rollback_deployment/2`: find most recent successful deployment before target, create new deployment using source snapshot, set `rollback_of_deployment_id` and `source_deployment_id`, write audit entry (`deployment_rollback_initiated`), follow normal deployment lifecycle
    - Implement `previous_successful_deployment/1`
    - Guard: reject if target is already `rolled_back`, if active rollback in progress, if no previous successful deployment exists
    - On successful rollback completion: update original deployment status to `rolled_back`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [ ] 5.4 Implement drift detection public API in `ConfigManager.Deployments`
    - Implement `compute_drift/1`, `drift_summary/1`, `pool_has_drift?/1` delegating to `DriftDetector`
    - _Requirements: 8.2, 8.3, 8.4, 8.5_

  - [ ] 5.5 Implement deployment result helpers in `ConfigManager.Deployments`
    - Implement `list_deployment_results/1` grouped by status with failed/unreachable first
    - Implement `result_summary/1` returning counts per status
    - _Requirements: 2.3, 5.5_

  - [ ]* 5.6 Write property tests for deployment creation and guards
    - **Property 4: Deployment creation records correct versions and initial state** — generate random pools with varying versions, verify deployment fields match pool state
    - **Property 5: Concurrent deployment prevention** — generate pools with deployments in various statuses, verify guard rejects when active deployment exists and allows when terminal
    - **Property 6: Deployment result records match enrolled sensors** — generate pools with varying sensor counts and control_api_host presence, verify correct result record counts and statuses
    - **Validates: Requirements 3.3, 3.4, 3.6, 3.7, 3.8, 3.9, 5.1, 5.3**

  - [ ]* 5.7 Write property tests for rollback guards
    - **Property 12: Rollback guard conditions** — generate deployments in various states, verify rollback is rejected for already rolled_back, active rollback in progress, and no previous successful deployment
    - **Validates: Requirements 7.7**

  - [ ]* 5.8 Write property test for deployment list filtering
    - **Property 17: Deployment list filtering returns correct results** — generate random deployments and filter criteria, verify filtered results match all criteria and are ordered by inserted_at descending
    - **Validates: Requirements 1.3**

- [ ] 6. Checkpoint — Verify context module and core logic
  - Run `mix compile` and `mix test` to verify all context modules compile and pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement the deployment orchestrator
  - [ ] 7.1 Add `Task.Supervisor` to the application supervision tree
    - Add `{Task.Supervisor, name: ConfigManager.Deployments.TaskSupervisor}` to the children list in `ConfigManager.Application`
    - Place it before the Phoenix endpoint in the supervision tree
    - _Requirements: 4.11_

  - [ ] 7.2 Implement `Deployments.Orchestrator` module
    - Create `lib/config_manager/deployments/orchestrator.ex`
    - Implement `start/2` that spawns an async task under `ConfigManager.Deployments.TaskSupervisor`
    - Implement validation phase: transition to `validating`, run pre-flight checks (pool exists, deployable sensors, snapshot well-formed), transition to `failed` with audit entry on validation failure
    - Implement deployment phase: transition to `deploying`, record `started_at`, write audit entry (`deployment_started`), dispatch to sensors via `Task.async_stream` with `max_concurrency: 5` and `timeout: 30_000`
    - For each sensor: call appropriate `SensorAgentClient` functions, update deployment_result status (`pushing` → `success`/`failed`/`unreachable`), broadcast `{:result_updated, result}` via PubSub
    - Implement finalization: determine final status (successful if all non-skipped are success, failed otherwise), record `completed_at`, write audit entry (`deployment_completed`), broadcast completion
    - On success: update per-sensor `last_deployed_*_version` fields via `SensorPod.deployment_success_changeset/2`, broadcast `{:drift_updated, pool_id}`
    - Implement `cancel/1` to signal cancellation to the orchestrator process
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 4.11, 4.12, 4.13, 4.14, 10.2, 10.3, 10.4, 13.1, 13.2_

  - [ ]* 7.3 Write property tests for orchestrator logic
    - **Property 7: Final deployment status determination** — generate random combinations of per-sensor result statuses, verify final deployment status is `successful` iff all non-skipped results are `success`
    - **Property 8: Version fields updated only on successful deployment results** — generate random result status transitions, verify version fields are updated only for `success` results and never for cancelled deployments
    - **Validates: Requirements 4.9, 8.1, 10.2, 10.3, 10.4, 4.14**

- [ ] 8. Checkpoint — Verify orchestrator and full deployment lifecycle
  - Run `mix compile` and `mix test` to verify orchestrator compiles and lifecycle tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement RBAC policy verification and audit integration
  - [ ] 9.1 Verify canonical `deployments:manage` permission in the RBAC policy
    - Verify `deployments:manage` is present in `Policy.canonical_permissions/0`
    - Verify the Policy module's role-permission mapping grants `deployments:manage` to `sensor-operator`, `rule-manager`, and `platform-admin` roles
    - Verify `viewer`, `analyst`, and `auditor` roles do NOT receive `deployments:manage`
    - _Requirements: 11.1, 11.2, 11.3_

  - [ ]* 9.2 Write property test for RBAC enforcement
    - **Property 16: RBAC enforcement for deployment write actions** — generate random users with varying roles, verify deployment write actions are denied for users without `deployments:manage` and allowed for users with it
    - **Validates: Requirements 3.1, 11.4, 11.6**

- [ ] 10. Implement LiveView modules for deployment UI
  - [ ] 10.1 Implement `DeploymentLive.ListLive` — fleet-wide deployment list page
    - Create `lib/config_manager_web/live/deployment_live/list_live.ex`
    - Mount: load paginated deployments, subscribe to `"deployments"` PubSub topic
    - Display paginated table: pool name (linked), config versions, status badge (color-coded), operator, start/end timestamps, per-sensor result summary
    - Implement filter controls: pool, status, operator, date range
    - Implement "New Deployment" button visible only to users with `deployments:manage`
    - Handle PubSub: `{:deployment_created, deployment}` prepend to list, `{:deployment_completed, deployment}` update row
    - Implement real-time row updates during `deploying` state
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 13.5_

  - [ ] 10.2 Implement `DeploymentLive.DetailLive` — deployment detail page
    - Create `lib/config_manager_web/live/deployment_live/detail_live.ex`
    - Mount: load deployment with results and pool, subscribe to `"deployment:#{id}"` PubSub topic
    - Display deployment metadata: pool name (linked), config versions, status badge, operator, operator type, start/end timestamps, duration
    - Display per-sensor results table: sensor name (linked), result status, message, timestamp — grouped by status with failed/unreachable first
    - Display diff section: capture config changes, BPF changes, forwarding sink changes, Suricata rule changes — with green/red/side-by-side formatting
    - Display "initial deployment" message when no previous deployment exists
    - Display configuration snapshot viewer
    - Implement "Rollback" button: visible for successful/failed deployments with previous successful deployment, requires `deployments:manage`
    - Implement "Cancel" button: visible for pending/validating/deploying, requires `deployments:manage`
    - RBAC: enforce `deployments:manage` in `handle_event` for rollback and cancel actions
    - Handle PubSub: `{:result_updated, result}` update per-sensor row, `{:deployment_status_changed, deployment}` update header
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5, 7.6, 11.4, 11.5, 11.6, 13.1, 13.2_

  - [ ] 10.3 Implement `PoolLive.DriftLive` — pool drift view
    - Create `lib/config_manager_web/live/pool_live/drift_live.ex`
    - Mount: load pool, compute drift via `Deployments.compute_drift/1`, subscribe to `"pool:#{pool_id}:drift"` PubSub topic
    - Display drift summary cards: in_sync count, drift_detected count, never_deployed count
    - Display per-sensor drift table: sensor name, drift status, drifted domains
    - Handle PubSub: `{:drift_updated, pool_id}` recompute drift
    - _Requirements: 8.3, 8.4, 8.6, 13.4_

  - [ ] 10.4 Update existing LiveViews for deployment integration
    - Update `PoolDeploymentsLive` (or create if not existing) at `/pools/:id/deployments` to show pool-scoped deployment history
    - Update `PoolShowLive`: add "Deployments" tab, "Drift" tab, "Deploy Now" button (visible when config versions ahead of last deployment, requires `deployments:manage`), drift indicator badge
    - Update `PoolIndexLive`: add drift indicator badge on pool rows where drift is detected
    - Update `SensorDetailLive`: add last-deployed configuration versions and drift status section (in sync / drift detected with domains / never deployed)
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 8.5_

- [ ] 11. Add deployment routes and navigation
  - [ ] 11.1 Add deployment routes to the router
    - Add `live "/deployments", DeploymentLive.ListLive, :index` to the browser scope
    - Add `live "/deployments/:id", DeploymentLive.DetailLive, :show` to the browser scope
    - Add `live "/pools/:id/deployments", PoolLive.DeploymentsLive, :index` to the browser scope
    - Add `live "/pools/:id/drift", PoolLive.DriftLive, :index` to the browser scope
    - _Requirements: 1.1, 2.1, 14.2, 14.3_

  - [ ] 11.2 Add "Deployments" link to the main navigation bar
    - Update the root layout or navigation component to include a "Deployments" link to `/deployments`, visible to all authenticated users
    - _Requirements: 14.1_

- [ ] 12. Checkpoint — Verify full UI and routing
  - Run `mix compile` and `mix test` to verify all LiveView modules compile and route correctly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Wire PubSub broadcasts and real-time updates
  - [ ] 13.1 Implement PubSub broadcast helpers in the Deployments context
    - Add private broadcast functions for all PubSub topics: `"deployment:#{id}"`, `"pool:#{pool_id}:deployments"`, `"pool:#{pool_id}:drift"`, `"deployments"`
    - Wire broadcasts into `create_deployment/3`, `cancel_deployment/2`, rollback completion, and orchestrator status transitions
    - Ensure deployment detail page receives `{:deployment_status_changed, deployment}` and `{:result_updated, result}`
    - Ensure pool deployment list receives `{:deployment_created, deployment}`, `{:deployment_completed, deployment}`, `{:deployment_cancelled, deployment}`
    - Ensure drift views receive `{:drift_updated, pool_id}` on successful deployment completion
    - Ensure fleet-wide list receives `{:deployment_created, deployment}` and `{:deployment_completed, deployment}`
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 8.6_

- [ ] 14. Implement rollback completion callback
  - [ ] 14.1 Wire rollback status update on successful rollback deployment
    - When a rollback deployment completes with status `successful`, update the original deployment (referenced by `rollback_of_deployment_id`) to status `rolled_back`
    - Broadcast `{:deployment_rolled_back, deployment}` to `"pool:#{pool_id}:deployments"`
    - Write audit entry for the status change
    - Ensure the source deployment's status remains unchanged
    - _Requirements: 7.4, 13.3_

  - [ ]* 14.2 Write property test for rollback integrity
    - **Property 11: Rollback deployment uses source snapshot and records references** — generate deployment histories, verify rollback uses correct source snapshot, sets correct reference IDs, and on success transitions original to rolled_back without modifying source
    - **Validates: Requirements 7.1, 7.3, 7.4**

- [ ] 15. Final checkpoint — Full integration verification
  - Run `mix compile` and `mix test` to verify the complete feature compiles and all tests pass
  - Verify deployment creation → orchestration → per-sensor results → completion lifecycle
  - Verify rollback lifecycle and drift detection
  - Verify PubSub real-time updates reach LiveView subscribers
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using PropCheck (already a project dependency)
- Unit tests validate specific examples and edge cases
- The design uses Elixir throughout — no language selection was needed
- All 17 correctness properties from the design document are covered by property test tasks
- All 15 requirements are covered by implementation tasks
