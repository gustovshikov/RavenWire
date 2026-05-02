# Implementation Plan: Sensor Pool Management

## Overview

This plan implements the complete pool management workflow for the RavenWire Config Manager: schema extension with PCAP config fields, a dedicated `ConfigManager.Pools` context module, six LiveView pages (index, form, show, sensors, config, deployments), router integration with RBAC, PubSub real-time updates, transactional audit logging, and navigation integration with existing pages. Each task builds incrementally on the previous, ending with full wiring and verification.

## Tasks

- [ ] 1. Database migration and schema extension
  - [ ] 1.1 Create the Ecto migration to add pool config fields
    - Create migration file `priv/repo/migrations/YYYYMMDDHHMMSS_add_pool_config_fields.exs`
    - Add columns: `description` (text), `pcap_ring_size_mb` (integer, default 4096), `pre_alert_window_sec` (integer, default 60), `post_alert_window_sec` (integer, default 30), `alert_severity_threshold` (integer, default 2)
    - Drop existing `sensor_pools_name_index` and create `sensor_pools_name_nocase_index` with `COLLATE NOCASE`
    - Implement explicit `up/down` functions (not `change`) with raw SQL `execute` for the COLLATE NOCASE index
    - _Requirements: 13.1, 13.2, 13.4, 13.6_

  - [ ] 1.2 Extend the `ConfigManager.SensorPool` Ecto schema
    - Add new fields: `:description`, `:pcap_ring_size_mb`, `:pre_alert_window_sec`, `:post_alert_window_sec`, `:alert_severity_threshold`
    - Add `@name_format` regex `~r/^[a-zA-Z0-9._-]+$/`
    - Implement `create_changeset/3` with name normalization (trim), format validation, PCAP field validation, unique constraint on `:sensor_pools_name_nocase_index`, and actor metadata
    - Implement `metadata_changeset/2` for name/description edits without touching config_version
    - Implement `config_update_changeset/3` with `maybe_version_and_metadata/2` that increments config_version only when config fields change
    - Add private helpers: `normalize_name/1`, `validate_pcap_fields/1`, `maybe_version_and_metadata/2`, `now_utc/0`
    - _Requirements: 13.5, 2.3, 4.2, 8.4, 8.7_

  - [ ]* 1.3 Write property tests for name normalization and case-insensitive uniqueness
    - **Property 1: Name normalization is idempotent and preserves validity**
    - **Property 2: Case-insensitive name uniqueness**
    - **Validates: Requirements 2.3, 4.2, 4.3, 13.4**

  - [ ]* 1.4 Write property tests for pool creation defaults and Config_Version invariant
    - **Property 3: Pool creation initializes all defaults correctly**
    - **Property 4: Config_Version increments only on config profile changes**
    - **Validates: Requirements 2.2, 8.3, 8.7, 13.6**

- [ ] 2. Implement `ConfigManager.Pools` context module — CRUD operations
  - [ ] 2.1 Create `lib/config_manager/pools.ex` with pool CRUD functions
    - Implement `list_pools/1` returning pools with member counts, default alphabetical sort
    - Implement `get_pool/1` and `get_pool!/1`
    - Implement `create_pool/2` using `Ecto.Multi` with `Audit.append_multi/2` for transactional audit
    - Implement `update_pool/3` using `metadata_changeset/2` with audit entry
    - Implement `delete_pool/2` that nilifies member sensors, writes audit with affected_sensor_count
    - Broadcast PubSub messages to `"pools"` topic on create/update/delete
    - _Requirements: 1.3, 2.2, 4.1, 5.2, 11.1, 11.4_

  - [ ]* 2.2 Write property test for pool deletion nilification
    - **Property 5: Pool deletion nilifies all member sensors**
    - **Validates: Requirements 5.2**

  - [ ]* 2.3 Write property test for default sort order
    - **Property 14: Default pool list sort order is alphabetical by name**
    - **Validates: Requirements 1.3**

- [ ] 3. Implement `ConfigManager.Pools` context module — sensor assignment and removal
  - [ ] 3.1 Implement sensor assignment and removal functions
    - Implement `list_pool_sensors/1` returning sensors for a pool
    - Implement `list_unassigned_sensors/0` returning enrolled sensors with nil pool_id
    - Implement `list_other_pool_sensors/1` returning enrolled sensors in other pools
    - Implement `assign_sensors/4` with `allow_reassign?` option, per-sensor audit entries + pool summary, race condition detection (reject and roll back entire operation)
    - Implement `remove_sensors/3` with per-sensor audit entries + pool summary
    - Broadcast PubSub messages to `"pools"`, `"pool:#{pool_id}"`, and `"sensor_pod:#{health_key}"` topics
    - _Requirements: 6.3, 6.4, 6.5, 6.7, 7.1, 11.3, 11.4_

  - [ ]* 3.2 Write property tests for sensor assignment round-trip and assignable sensor filtering
    - **Property 6: Sensor assignment round-trip**
    - **Property 7: Assignable sensor list contains only unassigned enrolled sensors**
    - **Validates: Requirements 6.3, 6.4, 7.1**

  - [ ]* 3.3 Write property test for bulk audit entry counts
    - **Property 10: Bulk operations produce per-sensor audit entries plus pool summary**
    - **Validates: Requirements 11.3**

- [ ] 4. Implement `ConfigManager.Pools` context module — config profile and queries
  - [ ] 4.1 Implement pool config update and query functions
    - Implement `update_pool_config/3` using `config_update_changeset/3` with audit entry containing old/new values
    - Implement `member_count/1`, `pool_name/1`, `pool_name_map/0`
    - Implement `list_pool_deployments/2` querying audit_log for deployment actions filtered by pool
    - Broadcast `{:pool_config_updated, pool_id}` to `"pool:#{pool_id}"` on config update
    - _Requirements: 8.3, 8.5, 8.6, 8.7, 9.3, 9.6, 12.3_

  - [ ]* 4.2 Write property test for pool config validation equivalence
    - **Property 12: Pool config validation matches per-pod PCAP validation rules**
    - **Validates: Requirements 8.4**

  - [ ]* 4.3 Write property test for deployment history filtering
    - **Property 13: Deployment history contains only deployment actions for the target pool**
    - **Validates: Requirements 9.2, 9.3, 9.6**

- [ ] 5. Checkpoint — Ensure all context tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Router and RBAC integration
  - [ ] 6.1 Add pool routes to the router with permission metadata
    - Add all 7 pool routes to the authenticated `live_session` block in `router.ex`
    - Set `private: %{required_permission: ...}` on each route per the design
    - Read-only pages use `sensors:view`; write pages use `pools:manage`
    - _Requirements: 10.1, 10.2, 10.3, 1.1, 2.1, 3.1, 6.1, 8.1, 9.1_

  - [ ]* 6.2 Write property test for RBAC enforcement on pool write operations
    - **Property 8: RBAC enforcement is consistent for pool write operations**
    - **Validates: Requirements 10.1, 10.4, 10.5, 10.6**

- [ ] 7. Implement Pool LiveView pages — list and form
  - [ ] 7.1 Implement `PoolLive.IndexLive` — pool list page
    - Create `lib/config_manager_web/live/pool_live/index_live.ex`
    - Mount: load pools with counts via `Pools.list_pools/1`, subscribe to `"pools"` PubSub topic
    - Render sortable table with pool rows (name, capture mode, member count, config version, last update)
    - Handle sort events, PubSub handlers for pool changes
    - Show "Create Pool" button only for users with `pools:manage` permission
    - Display empty state when no pools exist
    - Row click navigates to `/pools/:id`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

  - [ ] 7.2 Implement `PoolLive.FormLive` — pool create/edit form
    - Create `lib/config_manager_web/live/pool_live/form_live.ex`
    - Mount: for `:new` — empty changeset with `alert_driven` default; for `:edit` — load pool
    - Handle `"validate"` event for live validation, `"save"` event for submission
    - Call `Pools.create_pool/2` or `Pools.update_pool/3` on save
    - Display changeset errors inline (name uniqueness, format, length)
    - Redirect to `/pools/:id` on success
    - RBAC: `pools:manage` required (enforced by route + handle_event)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 4.1, 4.2, 4.3, 4.4_

- [ ] 8. Implement Pool LiveView pages — detail and sensors
  - [ ] 8.1 Implement `PoolLive.ShowLive` — pool detail page
    - Create `lib/config_manager_web/live/pool_live/show_live.ex`
    - Mount: load pool by ID, subscribe to `"pool:#{id}"` and `"pools"` topics
    - Render pool info: name, description, capture mode, config version, timestamps, member count
    - Navigation links to config, sensors, deployments sub-pages
    - Show Edit/Delete buttons only for `pools:manage` users
    - Handle `"delete"` event with confirmation, redirect to `/pools` on success
    - Handle PubSub updates for pool changes and deletion
    - Render 404 page if pool not found
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 5.1, 5.2, 5.3_

  - [ ] 8.2 Implement `PoolLive.SensorsLive` — pool sensors page
    - Create `lib/config_manager_web/live/pool_live/sensors_live.ex`
    - Mount: load pool, list pool sensors, subscribe to `"pool:#{id}"`
    - Render sensor list with name, status, last seen, link to sensor detail
    - Implement "Assign Sensors" modal showing unassigned enrolled sensors
    - Implement "Move from another pool" option showing other-pool sensors with confirmation
    - Implement "Remove from Pool" with confirmation dialog
    - Handle PubSub updates for assignment/removal broadcasts
    - Show assign/remove buttons only for `pools:manage` users
    - Display notice that assignment changes desired state only (no auto-push)
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 7.1, 7.2, 7.3, 7.4_

- [ ] 9. Implement Pool LiveView pages — config and deployments
  - [ ] 9.1 Implement `PoolLive.ConfigLive` — pool config page
    - Create `lib/config_manager_web/live/pool_live/config_live.ex`
    - Mount: load pool, build config form changeset, subscribe to `"pool:#{id}"`
    - Render config fields: capture mode, PCAP ring size, pre/post alert windows, severity threshold
    - Display Config_Version and last update metadata
    - Handle `"validate"` for live validation, `"save"` for submission
    - Call `Pools.update_pool_config/3` on save
    - Display no-auto-push notice
    - Read-only view for `sensors:view` users; save enabled for `pools:manage` users
    - Handle PubSub `{:pool_config_updated, pool_id}` to refresh display
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

  - [ ] 9.2 Implement `PoolLive.DeploymentsLive` — pool deployment history page
    - Create `lib/config_manager_web/live/pool_live/deployments_live.ex`
    - Mount: load pool, query deployment audit entries via `Pools.list_pool_deployments/2`
    - Render deployment entries: timestamp, actor, action, result, summary
    - Implement pagination with default page size of 25
    - Display empty state when no deployment history exists
    - Filter to deployment action names only (not CRUD or config-save entries)
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

- [ ] 10. Checkpoint — Ensure all LiveView pages render and pass tests
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Navigation integration and existing page updates
  - [ ] 11.1 Add "Pools" link to main navigation bar
    - Update the root layout or nav component to include a "Pools" link to `/pools`
    - Visible to all authenticated users
    - _Requirements: 12.1_

  - [ ] 11.2 Update sensor detail page with pool name link
    - In `SensorDetailLive`, when `pod.pool_id` is non-nil, query `Pools.pool_name/1` and render as a link to `/pools/:pool_id`
    - Handle `{:pool_assignment_changed, sensor_id, pool_id}` PubSub message to update pool name without full reload
    - _Requirements: 12.2, 12.4_

  - [ ] 11.3 Update rule deployment page with pool names in dropdown
    - In `RuleDeploymentLive`, call `Pools.pool_name_map/0` on mount
    - Replace raw pool UUID display with human-readable pool names in the deployment target dropdown
    - _Requirements: 12.3_

- [ ] 12. Audit logging and transactional integrity
  - [ ] 12.1 Verify and wire audit entry patterns for all pool mutations
    - Ensure all context functions use `Ecto.Multi` with `Audit.append_multi/2`
    - Verify audit entries match the patterns defined in the design: `pool_created`, `pool_updated`, `pool_deleted`, `pool_config_updated`, `sensor_assigned_to_pool`, `sensor_removed_from_pool`
    - Verify bulk operations produce per-sensor entries + pool summary entry
    - Verify failure audit entries are written when actor and target can be identified
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

  - [ ]* 12.2 Write property test for audit entry structural completeness
    - **Property 9: Every pool mutation produces a structurally complete audit entry**
    - **Validates: Requirements 11.1, 11.2**

  - [ ]* 12.3 Write property test for transactional audit integrity
    - **Property 11: Audit writes are transactional with pool mutations**
    - **Validates: Requirements 11.4**

- [ ] 13. PubSub real-time updates and UI quality
  - [ ] 13.1 Wire PubSub broadcasts and handlers across all LiveView modules
    - Verify all context functions broadcast to correct topics per the design
    - Ensure `IndexLive` handles `{:pool_created, _}`, `{:pool_updated, _}`, `{:pool_deleted, _}`, `{:pool_membership_changed, _}`
    - Ensure `ShowLive` handles pool-scoped messages and redirects on deletion
    - Ensure `SensorsLive` handles `{:sensors_assigned, _, _}` and `{:sensors_removed, _, _}`
    - Ensure `ConfigLive` handles `{:pool_config_updated, _}`
    - Ensure messages for unrelated pool IDs are ignored
    - _Requirements: 14.1, 14.2_

  - [ ] 13.2 Add accessible labels, confirmation text, and responsive layout
    - Add ARIA labels to all pool forms, buttons, and interactive controls
    - Ensure confirmation dialogs have clear text and keyboard-reachable controls
    - Verify pool pages render without horizontal overflow at common widths
    - _Requirements: 14.3, 14.4_

- [ ] 14. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design uses Elixir (Phoenix/LiveView) throughout — no language selection needed
- No new dependencies are required; `propcheck ~> 1.4` is already in `mix.exs`
