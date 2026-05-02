# Implementation Plan: Canary Deployment Workflow

## Overview

This plan implements the canary deployment workflow for the RavenWire Config Manager. The implementation extends the existing deployment-tracking system with canary-specific schema fields, lifecycle states, health evaluation, auto-promote/rollback logic, manual override controls, and UI enhancements. The implementation proceeds bottom-up: database migration and schema extensions first, then canary health evaluation logic, then orchestrator extensions, then UI updates, and finally integration wiring.

## Tasks

- [ ] 1. Create database migration and extend Ecto schemas
  - [ ] 1.1 Create the canary fields migration for `deployments` and `deployment_results`
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_add_canary_fields_to_deployments.exs`
    - Add columns to `deployments`: `deployment_type` (text, not null, default "full"), `canary_strategy` (text, nullable), `canary_percentage` (integer, nullable), `canary_sensor_ids` (map/JSON, nullable), `observation_period_minutes` (integer, nullable), `canary_started_at` (utc_datetime_usec, nullable), `canary_observation_ends_at` (utc_datetime_usec, nullable), `canary_health_baseline` (map/JSON, nullable), `canary_health_log` (map/JSON, nullable)
    - Add column to `deployment_results`: `is_canary` (boolean, default false)
    - Create index on `deployments(deployment_type)`
    - _Requirements: 10.1_

  - [ ] 1.2 Extend the `Deployment` Ecto schema with canary fields and states
    - Add canary fields to `lib/config_manager/deployments/deployment.ex`: `deployment_type`, `canary_strategy`, `canary_percentage`, `canary_sensor_ids`, `observation_period_minutes`, `canary_started_at`, `canary_observation_ends_at`, `canary_health_baseline`, `canary_health_log`
    - Extend `@valid_statuses` to include `canary_deploying` and `canary_observing`
    - Add `@valid_deployment_types ~w(full canary)` and `@valid_canary_strategies ~w(single percentage)`
    - Implement `canary_create_changeset/2` with canary-specific validations: deployment_type inclusion, conditional canary_strategy/percentage/sensor_ids/observation_period validation
    - Extend `@valid_transitions` map: `validating → {canary_deploying, deploying, failed, cancelled}`, `canary_deploying → {canary_observing, failed, cancelled}`, `canary_observing → {deploying, failed, cancelled}`
    - Update `status_changeset/3` to accept canary-specific attrs (`canary_started_at`, `canary_observation_ends_at`, `canary_health_baseline`, `canary_health_log`)
    - _Requirements: 2.1, 2.2, 2.8, 10.2, 10.3_

  - [ ] 1.3 Extend the `DeploymentResult` Ecto schema with canary fields
    - Add `is_canary` boolean field (default false) to `lib/config_manager/deployments/deployment_result.ex`
    - Extend `@valid_statuses` to include `awaiting_canary`
    - Update `create_changeset/2` to accept `is_canary` in cast fields
    - _Requirements: 2.3, 2.9_

  - [ ]* 1.4 Write property tests for extended status and type validation
    - **Property 4: Extended deployment and result status validation** — generate random strings, verify deployment changeset accepts only the 9 valid statuses (including canary_deploying, canary_observing), deployment_type accepts only {full, canary}, canary_strategy accepts only {single, percentage} when type is canary, result changeset accepts only the 7 valid statuses (including awaiting_canary)
    - Tag: `# Feature: canary-deploys, Property 4: Extended deployment and result status validation`
    - **Validates: Requirements 2.1, 2.8, 2.9, 10.2, 10.3**

  - [ ]* 1.5 Write property test for canary deployment state transitions
    - **Property 5: Canary deployment state transitions follow valid paths** — generate all (status, target_status) pairs for the extended transition map, verify only valid transitions are accepted by the changeset
    - Tag: `# Feature: canary-deploys, Property 5: Canary deployment state transitions follow valid paths`
    - **Validates: Requirements 2.2**

- [ ] 2. Checkpoint — Run migration and verify schemas compile
  - Run `mix ecto.migrate` to verify the canary fields migration applies cleanly
  - Run `mix compile` to verify extended schemas compile without errors
  - Ensure all existing tests still pass

- [ ] 3. Implement canary health evaluation modules
  - [ ] 3.1 Implement `Deployments.CanaryHealth` module
    - Create `lib/config_manager/deployments/canary_health.ex`
    - Implement `capture_baseline/1` that reads current health state from `Health.Registry` ETS table for each canary sensor ID: packet drop rate, container states, forwarding sink states; queries Platform Alert Center for active alert count per sensor; returns `%{sensor_id => %{drop_rate, containers, sinks, alert_count, captured_at}}`
    - Implement `evaluate/3` that compares a single sensor's current health against its baseline: check no new alerts (current alert_count <= baseline alert_count), drop rate not increased beyond threshold (default 2pp), all baseline containers still running, all baseline sinks still operational; returns `{:ok, %{status: :healthy, metrics: map}}` or `{:error, %{status: :degraded, failed_criteria: [...], metrics: map}}`
    - Implement `evaluate_all/3` that evaluates all canary sensors and returns aggregate result
    - Implement `format_for_audit/1` that formats evaluation results for audit entry detail fields
    - Make drop rate threshold configurable via application config (default 2.0)
    - _Requirements: 3.1, 3.2, 3.3_

  - [ ]* 3.2 Write property tests for health evaluation
    - **Property 8: Health evaluation criteria correctness** — generate random baselines and current health states, verify: alert criterion fails iff current_count > baseline_count, drop rate criterion fails iff current - baseline > threshold, container criterion fails iff any baseline-running container is no longer running, sink criterion fails iff any baseline-operational sink is no longer operational, overall is degraded iff any criterion fails
    - Tag: `# Feature: canary-deploys, Property 8: Health evaluation criteria correctness`
    - **Validates: Requirements 3.2**

  - [ ]* 3.3 Write property test for baseline capture completeness
    - **Property 9: Health baseline capture completeness** — generate random sensor health data in ETS, capture baseline, verify every canary sensor has an entry with all required fields (drop_rate as number, containers as map, sinks as map, alert_count as non-negative integer, captured_at as timestamp)
    - Tag: `# Feature: canary-deploys, Property 9: Health baseline capture completeness`
    - **Validates: Requirements 3.3**

- [ ] 4. Implement canary monitor GenServer
  - [ ] 4.1 Implement `Deployments.CanaryMonitor` module
    - Create `lib/config_manager/deployments/canary_monitor.ex`
    - Implement as a GenServer started under `ConfigManager.Deployments.TaskSupervisor` via `start_link/1`
    - Accept options: `deployment_id`, `canary_sensor_ids`, `baseline`, `observation_ends_at`, `check_interval_ms` (default 30_000)
    - Register process via `Registry` or `via` tuple keyed by deployment_id for lookup
    - On init: schedule first health check via `Process.send_after(self(), :check_health, check_interval_ms)`
    - On `:check_health`: read health from `Health.Registry` ETS for each canary sensor, query alert center, call `CanaryHealth.evaluate_all/3`, broadcast `{:canary_health_update, result}` to `"deployment:#{id}"` PubSub topic, append result to deployment's `canary_health_log` field, log at `:debug` level (`:warning` on failure)
    - If any criterion fails: stop timer, call `Orchestrator.rollback_canary/2` with failure details
    - If observation_ends_at reached and all healthy: stop timer, call `Orchestrator.promote_canary/1`
    - Otherwise: schedule next check
    - Implement `stop/1` for clean shutdown on manual override
    - _Requirements: 3.1, 3.4, 3.5, 3.6, 2.5_

- [ ] 5. Checkpoint — Verify health evaluation and monitor compile
  - Run `mix compile` to verify CanaryHealth and CanaryMonitor compile
  - Run `mix test` to verify property tests pass
  - Ensure all tests pass

- [ ] 6. Extend Deployments context with canary creation and override functions
  - [ ] 6.1 Implement canary deployment creation in `ConfigManager.Deployments`
    - Extend `create_deployment/3` to handle `deployment_type: "canary"` option
    - Validate pool has >= 2 deployable sensors for canary (return `{:error, :insufficient_sensors_for_canary}` otherwise)
    - For `percentage` strategy: implement `select_canary_sensors/2` that selects `max(1, ceil(N * P / 100))` sensors preferring longest uptime, ensuring selected count < total deployable count
    - For `single` strategy: validate operator-selected sensor is a deployable member of the pool
    - Create `DeploymentResult` records: canary sensors get `status: "pending", is_canary: true`, remaining deployable sensors get `status: "awaiting_canary", is_canary: false`, non-deployable sensors get `status: "skipped", is_canary: false`
    - Write `canary_deployment_created` audit entry with canary config details
    - Broadcast creation to PubSub topics
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

  - [ ] 6.2 Implement canary manual override functions
    - Implement `promote_canary/2`: validate deployment is in `canary_observing`, stop CanaryMonitor, delegate to `Orchestrator.promote_canary/1`, write `canary_manual_promote` audit entry
    - Implement `abort_canary/2`: validate deployment is in `canary_observing`, stop CanaryMonitor, delegate to `Orchestrator.rollback_canary/2` with manual abort reason, transition to `cancelled`, write `canary_manual_abort` audit entry
    - Both require `deployments:manage` permission (checked by LiveView caller)
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [ ] 6.3 Implement canary query helpers
    - Implement `canary_deployment?/1` returning `deployment.deployment_type == "canary"`
    - Implement `canary_sensor_ids/1` returning the canary sensor ID list from deployment
    - Implement `canary_health_log/1` returning the health log array from deployment
    - Implement `canary_health_baseline/1` returning the baseline map from deployment
    - _Requirements: 7.1_

  - [ ]* 6.4 Write property tests for canary creation and guards
    - **Property 1: Canary metadata persistence round-trip** — generate random valid canary configs, create deployment, retrieve, verify all canary fields match input; also generate health log entries, append and retrieve, verify round-trip integrity
    - Tag: `# Feature: canary-deploys, Property 1: Canary metadata persistence round-trip`
    - **Property 3: Minimum deployable sensors guard** — generate pools with 0, 1, 2, and N deployable sensors, attempt canary creation, verify failure for < 2 and success for >= 2
    - Tag: `# Feature: canary-deploys, Property 3: Minimum deployable sensors guard for canary`
    - **Validates: Requirements 1.3, 1.6, 10.4**

  - [ ]* 6.5 Write property test for canary sensor auto-selection
    - **Property 2: Canary sensor auto-selection count and ordering** — generate pools with 2-20 sensors with random uptimes and percentages 1-50, verify selection count equals `max(1, ceil(N * P / 100))`, all selected are deployable pool members, selected count < total, and sensors are ordered by longest uptime
    - Tag: `# Feature: canary-deploys, Property 2: Canary sensor auto-selection count and ordering`
    - **Validates: Requirements 1.4**

  - [ ]* 6.6 Write property test for canary result record partitioning
    - **Property 6: Canary result record partitioning invariants** — generate pools with varying sensor counts and canary selections, verify at creation: C results with is_canary=true/status=pending and (N-C) with is_canary=false/status=awaiting_canary; on promotion: all awaiting_canary become pending; on rollback: all awaiting_canary become skipped
    - Tag: `# Feature: canary-deploys, Property 6: Canary result record partitioning invariants`
    - **Validates: Requirements 2.3, 4.2, 5.4**

- [ ] 7. Extend the deployment orchestrator for canary lifecycle
  - [ ] 7.1 Implement canary deployment phases in `Deployments.Orchestrator`
    - Extend `start/2` to detect canary deployments and route to canary lifecycle
    - Implement canary validation phase: same as standard validation
    - Implement `canary_deploy/1`: transition to `canary_deploying`, capture health baseline via `CanaryHealth.capture_baseline/1`, store baseline on deployment record, dispatch config to canary sensors only via `Task.async_stream`, write `canary_deploy_started` audit entry
    - Implement canary result evaluation: if all canary results are `success` → call `start_canary_observation/1`; if any `failed`/`unreachable` → mark all `awaiting_canary` as `skipped`, transition to `failed`
    - Implement `start_canary_observation/1`: transition to `canary_observing`, compute `canary_observation_ends_at`, start `CanaryMonitor` GenServer, write `canary_observation_started` audit entry, broadcast `{:canary_observation_started, deployment}`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 3.3_

  - [ ] 7.2 Implement canary promote and rollback in orchestrator
    - Implement `promote_canary/1`: transition from `canary_observing` to `deploying`, update all `awaiting_canary` results to `pending`, dispatch config to remaining sensors (standard concurrent dispatch), write `canary_promoted` audit entry (or `canary_observation_completed` + `canary_promoted`), finalize per standard lifecycle
    - Implement `rollback_canary/2`: find previous successful deployment's snapshot, push restored config to canary sensors only, mark all `awaiting_canary` results as `skipped` with message "Canary failed", transition to `failed` (auto-rollback) or `cancelled` (manual abort), update canary sensors' `last_deployed_*_version` fields to restored config versions, write `canary_rollback_initiated` audit entry
    - Handle edge case: no previous successful deployment → mark remaining as `skipped`, transition to `failed` with message "No restore point available"
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 5.6, 5.7_

  - [ ]* 7.3 Write property tests for canary orchestrator logic
    - **Property 7: Canary phase final status determination** — generate random combinations of canary sensor result statuses, verify: all success → canary_observing, any failed/unreachable → failed with awaiting_canary marked skipped
    - Tag: `# Feature: canary-deploys, Property 7: Canary phase final status determination`
    - **Property 10: Canary rollback uses correct source deployment** — generate deployment histories with varying success/failure patterns, verify rollback uses the most recent successful deployment's snapshot before the canary deployment
    - Tag: `# Feature: canary-deploys, Property 10: Canary rollback uses correct source deployment`
    - **Property 11: Version field updates scoped to canary sensors on rollback** — generate canary deployments with varying sensor splits, trigger rollback, verify only canary sensor version fields are updated and non-canary sensors are unchanged
    - Tag: `# Feature: canary-deploys, Property 11: Version field updates scoped to canary sensors on rollback`
    - **Validates: Requirements 2.4, 5.2, 5.6, 5.7**

- [ ] 8. Checkpoint — Verify canary orchestrator and lifecycle
  - Run `mix compile` and `mix test` to verify orchestrator extensions compile and canary lifecycle tests pass
  - Ensure all tests pass

- [ ] 9. Implement canary deployment UI extensions
  - [ ] 9.1 Extend `DeploymentLive.DetailLive` for canary deployments
    - Add canary metadata display section: canary strategy, selected canary sensors (linked), observation period, elapsed time
    - Add canary health dashboard section (visible during `canary_observing`): render `CanaryHealthComponent` with per-sensor health status, baseline vs current metrics, criteria pass/fail indicators
    - Add progress indicator showing elapsed time vs total observation period during `canary_observing`
    - Add "Promote Now" button: visible during `canary_observing` for users with `deployments:manage`, calls `Deployments.promote_canary/2`
    - Add "Abort Canary" button: visible during `canary_observing` for users with `deployments:manage`, calls `Deployments.abort_canary/2`
    - Add canary status badges: `canary_deploying` (blue), `canary_observing` (amber with pulse animation)
    - Add "canary" badge/icon on canary sensor rows in the per-sensor results table (where `is_canary: true`)
    - Display status messages: "Canary Passed — Promoting to Full Pool" during promotion, "Canary Failed — Rolling Back" with failed criteria details during rollback
    - Handle new PubSub messages: `{:canary_health_update, result}` update health dashboard, `{:canary_promoted, deployment}` update status, `{:canary_rollback, deployment, reason}` show failure details
    - Add `:tick` timer (every 1 second) during `canary_observing` to update elapsed time display
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 4.5, 5.5_

  - [ ] 9.2 Implement `CanaryHealthComponent` LiveComponent
    - Create `lib/config_manager_web/live/components/canary_health_component.ex`
    - Accept assigns: `canary_health` (list of per-sensor results), `canary_baseline` (baseline map), `observation_progress` (elapsed/total/percentage), `deployment_status`
    - Render progress bar showing elapsed vs total observation time
    - Render per-sensor health cards: sensor name, healthy/degraded badge, drop rate (baseline → current with pass/fail), container count (pass/fail), sink count (pass/fail), alert count (pass/fail)
    - Use green/red color coding for pass/fail indicators
    - _Requirements: 7.2, 7.4_

  - [ ] 9.3 Extend `DeploymentLive.ListLive` for canary deployments
    - Add "Canary" badge on deployment list rows where `deployment_type == "canary"`
    - Add `canary_deploying` and `canary_observing` to the status filter dropdown options
    - Display observation progress ("Observing: 4m / 10m") in the list row for deployments in `canary_observing` status
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ] 9.4 Extend deployment creation form for canary options
    - Update the deployment creation flow (modal or form) to offer "Full Deployment" and "Canary Deployment" options
    - When "Canary Deployment" is selected, show: strategy selector (single/percentage), sensor picker (for single strategy — dropdown of deployable pool sensors), percentage input (for percentage strategy, default 10%, range 1-50), observation period input (default 10 minutes, range 1-60)
    - Validate minimum 2 deployable sensors for canary option; disable canary option with explanation if fewer than 2
    - On submit: call `Deployments.create_deployment/3` with canary options
    - _Requirements: 1.1, 1.2_

- [ ] 10. Checkpoint — Verify canary UI
  - Run `mix compile` and `mix test` to verify all LiveView extensions compile
  - Ensure all tests pass

- [ ] 11. Implement canary audit logging
  - [ ] 11.1 Wire canary audit entries throughout the lifecycle
    - Ensure `canary_deployment_created` audit entry is written in `create_deployment/3` with canary config details (strategy, percentage, sensor IDs, observation period, pool name)
    - Ensure `canary_deploy_started` audit entry is written when transitioning to `canary_deploying`
    - Ensure `canary_observation_started` audit entry is written when transitioning to `canary_observing` with baseline summary and observation_ends_at
    - Ensure `canary_observation_completed` audit entry is written when observation period completes
    - Ensure `canary_promoted` audit entry is written on auto-promote with health summary
    - Ensure `canary_manual_promote` audit entry is written on manual promote with operator identity
    - Ensure `canary_rollback_initiated` audit entry is written on auto-rollback with failed criteria, baseline values, observed values, source deployment ID
    - Ensure `canary_manual_abort` audit entry is written on manual abort with operator identity
    - Ensure `canary_health_degradation_detected` audit entry is written when health check fails with specific failed criteria, baseline values, and observed values
    - All audit entries use `Ecto.Multi` with `Audit.append_multi/2` for transactional writes
    - _Requirements: 9.1, 9.2, 9.3, 2.7_

  - [ ]* 11.2 Write property test for canary audit completeness
    - **Property 12: Canary audit entry completeness and structure** — generate canary deployments through lifecycle paths, verify each transition produces an audit entry with correct action name, non-nil actor, actor_type, target_type "deployment", target_id matching deployment ID, and detail containing pool_name and canary_sensor_ids; verify canary_health_degradation_detected contains failed_criteria, baseline_values, observed_values
    - Tag: `# Feature: canary-deploys, Property 12: Canary audit entry completeness and structure`
    - **Validates: Requirements 1.5, 2.7, 9.1, 9.2, 9.3**

- [ ] 12. Wire PubSub broadcasts for canary events
  - [ ] 12.1 Implement canary-specific PubSub broadcasts
    - Broadcast `{:canary_observation_started, deployment}` to `"deployment:#{id}"` when entering canary_observing
    - Broadcast `{:canary_health_update, %{sensor_results: [...], timestamp: DateTime}}` to `"deployment:#{id}"` on each health check
    - Broadcast `{:canary_promoted, deployment}` to `"deployment:#{id}"` on promotion
    - Broadcast `{:canary_rollback, deployment, %{reason: string, failed_criteria: [...]}}` to `"deployment:#{id}"` on rollback
    - Ensure existing deployment PubSub topics (`"pool:#{pool_id}:deployments"`, `"deployments"`) receive canary deployment events (creation, completion) using existing message types
    - _Requirements: 2.6, 3.5, 7.6_

- [ ] 13. Final checkpoint — Full integration verification
  - Run `mix compile` and `mix test` to verify the complete canary feature compiles and all tests pass
  - Verify canary deployment creation with both single and percentage strategies
  - Verify canary lifecycle: create → canary_deploy → observe → promote → deploy remaining → successful
  - Verify canary rollback: create → canary_deploy → observe → health failure → auto-rollback → failed
  - Verify manual override: Promote Now and Abort Canary during observation
  - Verify canary UI: badges, health dashboard, progress indicator, status colors
  - Verify audit trail: all 9 canary action types recorded with correct detail fields
  - Verify PubSub: real-time health updates reach deployment detail page
  - Ensure all tests pass

## Notes

- Tasks marked with `*` are optional property-based test tasks and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using PropCheck (`propcheck ~> 1.4`, already a project dependency)
- All 12 correctness properties from the design document are covered by property test tasks
- All 11 requirements (including deferred capabilities in Req 11) are covered by implementation tasks
- The canary feature extends existing deployment-tracking modules rather than creating parallel structures
- Deferred capabilities (Requirement 11) are explicitly NOT implemented: no multi-stage rollout, no per-domain canary, no scheduling, no traffic comparison
