# Implementation Plan: BPF Filter Editor

## Overview

This plan implements a pool-level BPF Filter Editor for the RavenWire Config Manager. The implementation proceeds in layers: database migrations → Ecto schemas → parameter validation → expression generation → BPF compiler → context module → RBAC extension → LiveView editor → pool navigation integration. Each step builds on the previous, ensuring no orphaned code. The design uses Elixir with Phoenix LiveView, Ecto/SQLite, and PropCheck for property-based testing.

## Tasks

- [ ] 1. Database migrations
  - [ ] 1.1 Create the `bpf_profiles` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_bpf_profiles.exs`
    - Define columns: `id` (binary_id PK), `pool_id` (binary_id FK to sensor_pools, on_delete: delete_all, not null), `version` (integer, not null, default 1), `last_deployed_version` (integer, nullable), `raw_expression` (text, nullable), `composition_mode` (text, not null, default "append"), `compiled_expression` (text, nullable), `updated_by` (text, nullable), timestamps (utc_datetime_usec)
    - Create unique index on `[:pool_id]`
    - _Requirements: 11.1, 11.2_

  - [ ] 1.2 Create the `bpf_filter_rules` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_bpf_filter_rules.exs`
    - Define columns: `id` (binary_id PK), `bpf_profile_id` (binary_id FK to bpf_profiles, on_delete: delete_all, not null), `rule_type` (text, not null), `params` (text, not null — JSON-encoded), `label` (text, nullable), `enabled` (boolean, not null, default true), `position` (integer, not null), timestamps (utc_datetime_usec)
    - Create index on `[:bpf_profile_id, :position]`
    - _Requirements: 11.3, 11.4_

  - [ ] 1.3 Create the `bpf_profile_versions` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_bpf_profile_versions.exs`
    - Define columns: `id` (binary_id PK), `bpf_profile_id` (binary_id FK to bpf_profiles, on_delete: delete_all, not null), `version` (integer, not null), `raw_expression` (text, nullable), `composition_mode` (text, not null), `compiled_expression` (text, nullable), `rules_snapshot` (text, not null — JSON-encoded), `created_by` (text, nullable), `inserted_at` (utc_datetime_usec, updated_at: false)
    - Create unique index on `[:bpf_profile_id, :version]`
    - _Requirements: 11.9, 11.10_

  - [ ] 1.4 Run migrations and verify schema
    - Run `mix ecto.migrate` to apply all three migrations
    - Verify tables, columns, indexes, and foreign key constraints are created correctly
    - Verify cascade delete from sensor_pools → bpf_profiles → bpf_filter_rules and bpf_profile_versions
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.7, 11.9, 11.10_

- [ ] 2. Ecto schemas and parameter validation
  - [ ] 2.1 Implement the `BpfProfile` Ecto schema
    - Create `lib/config_manager/bpf/bpf_profile.ex`
    - Define schema with all fields: `pool_id`, `version`, `last_deployed_version`, `raw_expression`, `composition_mode`, `compiled_expression`, `updated_by`
    - Define `has_many :rules` and `has_many :versions` associations
    - Implement `create_changeset/2` with pool_id required, composition_mode validation against `~w(append replace)`, unique constraint on pool_id
    - Implement `save_changeset/3` for updating raw_expression, composition_mode, compiled_expression with actor
    - Implement `increment_version_changeset/1` to bump version by 1
    - Implement `reset_changeset/2` to clear raw_expression, set composition_mode to "append", clear compiled_expression
    - Implement `deploy_changeset/2` to set last_deployed_version
    - _Requirements: 11.1, 11.5, 11.6_

  - [ ] 2.2 Implement the `BpfFilterRule` Ecto schema
    - Create `lib/config_manager/bpf/bpf_filter_rule.ex`
    - Define schema with all fields: `bpf_profile_id`, `rule_type`, `params`, `label`, `enabled`, `position`
    - Implement `changeset/2` with required fields validation, rule_type inclusion in `~w(elephant_flow cidr_pair port_exclusion)`, label max length 255, params validation via `RuleParams.validate/2`
    - _Requirements: 11.3, 11.5, 11.8_

  - [ ] 2.3 Implement the `BpfProfileVersion` Ecto schema
    - Create `lib/config_manager/bpf/bpf_profile_version.ex`
    - Define schema with all fields: `bpf_profile_id`, `version`, `raw_expression`, `composition_mode`, `compiled_expression`, `rules_snapshot`, `created_by`
    - Implement `changeset/2` with required fields, unique constraint on `[:bpf_profile_id, :version]`
    - Use `timestamps(type: :utc_datetime_usec, updated_at: false)` for insert-only records
    - _Requirements: 11.9, 11.10_

  - [ ] 2.4 Implement `ConfigManager.Bpf.RuleParams` — type-specific parameter validation
    - Create `lib/config_manager/bpf/rule_params.ex`
    - Implement `validate/2` dispatching on rule_type:
      - `elephant_flow`: require at least one of src_cidr, dst_cidr, port; validate CIDRs, ports, protocol
      - `cidr_pair`: require both src_cidr and dst_cidr; validate CIDRs
      - `port_exclusion`: require port; validate port, optional port_end (must be >= port), protocol
      - Unknown rule types: return error
    - Implement `validate_cidr/1` for IPv4 and IPv6 CIDR notation
    - Implement `validate_port/1` for range 1–65535
    - Implement `validate_port_range/2` for start <= end, both valid ports
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 11.8_

  - [ ]* 2.5 Write property test for rule parameter validation (Property 1)
    - **Property 1: Rule parameter validation enforces type-specific constraints**
    - Generate random rule types and parameter maps, verify acceptance/rejection matches type-specific constraints
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**

  - [ ]* 2.6 Write property test for CIDR and port validation (Property 2)
    - **Property 2: CIDR and port validation**
    - Generate random strings for CIDR validation, random integers for port validation, random pairs for port range validation
    - Verify acceptance iff valid IPv4/IPv6 CIDR, port in 1–65535, start <= end
    - **Validates: Requirements 2.5, 2.6**

- [ ] 3. Expression generation
  - [ ] 3.1 Implement `ConfigManager.Bpf.ExpressionGenerator`
    - Create `lib/config_manager/bpf/expression_generator.ex`
    - Implement `generate/3` taking rules list, raw_expression, composition_mode:
      - "append" mode: join enabled rule clauses with ` and `, append ` and (<raw>)` if raw is non-empty
      - "replace" mode: return raw_expression if non-empty, else return ""
      - No enabled rules and no raw expression: return ""
    - Implement `rule_to_clause/1` for each rule type:
      - `elephant_flow`: `not (` + predicates (`src net`, `dst net`, `port`/`portrange`, `tcp`/`udp`) joined with ` and ` + `)`
      - `cidr_pair`: `not (src net <src> and dst net <dst>)`
      - `port_exclusion`: `not (` + port predicate + optional protocol + `)`
    - Filter only enabled rules, maintain position order
    - _Requirements: 5.1, 5.2, 5.4, 3.2, 3.4, 3.6, 3.7_

  - [ ]* 3.2 Write property test for expression generation respecting enabled state and order (Property 3)
    - **Property 3: Expression generation respects enabled state and rule order**
    - Generate rule lists with mixed enabled/disabled states, verify only enabled rules produce clauses, in position order
    - **Validates: Requirements 2.7, 2.8, 5.1**

  - [ ]* 3.3 Write property test for composition mode behavior (Property 4)
    - **Property 4: Composition mode determines expression structure**
    - Generate rule lists and raw expressions, verify append vs replace mode behavior
    - **Validates: Requirements 3.2, 3.4, 3.6, 3.7**

  - [ ]* 3.4 Write property test for clause generation syntax (Property 6)
    - **Property 6: Clause generation produces correct BPF syntax per rule type**
    - Generate valid parameters for each rule type, verify clause matches expected BPF pattern
    - **Validates: Requirements 5.2**

- [ ] 4. BPF compiler
  - [ ] 4.1 Implement `ConfigManager.Bpf.Compiler`
    - Create `lib/config_manager/bpf/compiler.ex`
    - Implement `compile/2` with async execution under `Task.Supervisor` with configurable timeout (default 5s)
    - Implement `compile_sync/1` using `System.cmd("tcpdump", ["-d", expression], stderr_to_stdout: true)` — no shell
    - Parse output: count lines for instruction count on success, capture error message on non-zero exit
    - Handle empty expression: return `{:ok, %{instruction_count: 0}}` without invoking tcpdump
    - Handle timeout: `Task.yield/2` + `Task.shutdown/1`, return `{:error, %{message: "..."}}`
    - _Requirements: 4.1, 4.4, 4.5, 4.6, 4.7, 4.9, 4.10_

  - [ ]* 4.2 Write property test for expression round-trip compilation (Property 5)
    - **Property 5: Expression generation round-trip — generated expressions compile successfully**
    - Generate valid rule combinations, produce expression via ExpressionGenerator, compile with Compiler, verify success
    - Skip empty expressions (no-filter state)
    - **Validates: Requirements 5.5**

- [ ] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. BPF context module
  - [ ] 6.1 Implement `ConfigManager.Bpf` context — profile CRUD
    - Create `lib/config_manager/bpf.ex`
    - Implement `get_profile_for_pool/1`, `get_profile/1`
    - Implement `create_profile/2` with Ecto.Multi: insert profile with defaults → create version 1 snapshot → append audit entry (`bpf_profile_created`) → broadcast PubSub `{:bpf_profile_created, pool_id}` to `"pool:#{pool_id}:bpf"`
    - Return `{:error, :profile_exists}` if pool already has a profile
    - _Requirements: 7.1, 7.2, 9.1, 9.2, 9.5_

  - [ ] 6.2 Implement `ConfigManager.Bpf` context — save profile
    - Implement `save_profile/3` with Ecto.Multi: generate expression → compile via Compiler → reject on compilation failure/timeout → detect if configuration changed → if changed: update profile (version, expression, composition mode) + delete old rules + insert new rules + create version snapshot + audit (`bpf_profile_updated`) → broadcast PubSub `{:bpf_profile_updated, pool_id}`
    - If no changes detected, return success without version increment
    - Include old/new version, rule change summary, compiled_expression in audit detail
    - _Requirements: 7.3, 6.2, 6.5, 9.1, 9.3, 9.4, 9.5, 4.2, 4.3_

  - [ ] 6.3 Implement `ConfigManager.Bpf` context — reset, validate, rules, versions, queries
    - Implement `reset_profile/2` with Ecto.Multi: clear rules, reset profile fields, increment version, create version snapshot, audit (`bpf_profile_reset`), broadcast PubSub `{:bpf_profile_reset, pool_id}`
    - Implement `validate_expression/1` delegating to Compiler.compile/2
    - Implement `list_rules/1` ordered by position
    - Implement `generate_expression/3` delegating to ExpressionGenerator.generate/3
    - Implement `list_versions/2` newest first, `get_version/2`
    - Implement `bpf_summary/1` returning profile status, version, rule counts, pending deployment
    - Implement `bpf_restart_pending_sensors/1` querying Health Registry for pool sensors with bpf_restart_pending
    - _Requirements: 7.4, 4.8, 6.3, 12.1, 12.2, 10.3, 1.4_

  - [ ]* 6.4 Write property test for profile creation defaults (Property 7)
    - **Property 7: Profile creation initializes correct defaults**
    - Create profiles for random valid pools, verify version=1, nil raw_expression, "append" mode, nil compiled_expression, 0 rules
    - **Validates: Requirements 6.1, 7.2**

  - [ ]* 6.5 Write property test for version increment behavior (Property 8)
    - **Property 8: Version increments only on configuration changes**
    - Save with changed config → verify version N+1; save with identical config → verify version unchanged; validate-only → verify version unchanged
    - **Validates: Requirements 6.2, 6.4**

  - [ ]* 6.6 Write property test for immutable version snapshots (Property 9)
    - **Property 9: Every version increment creates an immutable snapshot**
    - Perform multiple saves, verify each version has a snapshot with correct compiled_expression, rules_snapshot, composition_mode, created_by; verify prior snapshots unchanged
    - **Validates: Requirements 6.5, 11.9, 11.10**

  - [ ]* 6.7 Write property test for reset behavior (Property 10)
    - **Property 10: Reset clears all state and increments version**
    - Create profile with rules and raw expression, reset, verify 0 rules, nil raw_expression, "append" mode, nil compiled_expression, version V+1, snapshot created
    - **Validates: Requirements 7.4**

  - [ ]* 6.8 Write property test for cascade delete (Property 11)
    - **Property 11: Pool deletion cascades to BPF profile and rules**
    - Create pools with profiles, rules, and versions, delete pool, verify all BPF data removed
    - **Validates: Requirements 7.5, 11.7**

  - [ ]* 6.9 Write property test for transactional audit integrity (Property 14)
    - **Property 14: Audit writes are transactional with BPF mutations**
    - Simulate audit write failure during create/save/reset, verify BPF data unchanged (rolled back)
    - **Validates: Requirements 7.3, 9.4**

  - [ ]* 6.10 Write property test for audit entry structure (Property 13)
    - **Property 13: Every BPF mutation produces a structurally complete audit entry**
    - Perform random BPF mutations, verify audit entries have non-nil id, timestamp, actor, action, target_type="bpf_profile", target_id, result="success", valid JSON detail
    - **Validates: Requirements 9.1, 9.2**

  - [ ]* 6.11 Write property test for pending deployment detection (Property 15)
    - **Property 15: Pending deployment detection**
    - Generate profiles with various version/last_deployed_version combinations, verify pending indicator logic
    - **Validates: Requirements 10.3, 13.3**

- [ ] 7. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. RBAC policy verification
  - [ ] 8.1 Verify canonical `bpf:manage` permission in the Policy module
    - Verify `"bpf:manage"` is present in `Policy.canonical_permissions/0`
    - Verify `sensor-operator` and `rule-manager` role permission lists include `"bpf:manage"`
    - Verify `platform-admin` has `:all` (covers bpf:manage)
    - Verify `viewer`, `analyst`, `auditor` do NOT have `bpf:manage`
    - All authenticated roles retain `sensors:view` for read access to the BPF editor page
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ]* 8.2 Write property test for RBAC enforcement (Property 12)
    - **Property 12: RBAC enforcement is consistent for BPF write operations**
    - For random roles and BPF write events, verify permit/deny matches policy; verify bpf:manage granted to exactly sensor-operator, rule-manager, platform-admin
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.6**

- [ ] 9. Router and Task.Supervisor setup
  - [ ] 9.1 Add BPF route to the router and configure Task.Supervisor
    - Add `live "/pools/:id/bpf", BpfLive.EditorLive, :index` with `sensors:view` permission to the authenticated live_session block
    - Add `ConfigManager.Bpf.TaskSupervisor` to the application supervision tree in `application.ex`
    - _Requirements: 1.1, 4.4, 4.5_

- [ ] 10. LiveView — BPF Editor page
  - [ ] 10.1 Implement `BpfLive.EditorLive` — mount, assigns, and PubSub
    - Create `lib/config_manager_web/live/bpf_live/editor_live.ex`
    - Implement `mount/3`: load pool via `Pools.get_pool!/1`, load BPF profile via `Bpf.get_profile_for_pool/1`, load rules, generate compiled expression preview, query Health Registry for bpf_restart_pending sensors, subscribe to `"pool:#{pool_id}:bpf"` and `"sensor_pods"` PubSub topics
    - Set assigns: pool, profile (nil for empty state), rules, raw_expression, composition_mode, compiled_expression, validation_result, validating, restart_pending_sensors, restart_pending_count, pending_deployment, current_user, dirty, rule_form, show_reset_confirm
    - Implement `handle_info` for PubSub messages: `{:bpf_profile_created, _}`, `{:bpf_profile_updated, _}`, `{:bpf_profile_reset, _}` → reload profile and rules; `{:pod_degraded, _, :bpf_restart_pending, _}` and `{:pod_recovered, _, :bpf_restart_pending}` → update restart pending count
    - _Requirements: 1.1, 1.2, 1.4, 1.6, 12.1, 12.3_

  - [ ] 10.2 Implement `BpfLive.EditorLive` — write event handlers
    - Implement `handle_event` callbacks with `bpf:manage` RBAC check on each:
      - `"create_profile"` — call `Bpf.create_profile/2`
      - `"add_rule"` / `"edit_rule"` — open rule form modal in assigns
      - `"save_rule"` — validate and add/update rule in in-memory list, regenerate preview
      - `"delete_rule"` — remove rule from in-memory list, regenerate preview
      - `"toggle_rule"` — toggle enabled state in-memory, regenerate preview
      - `"reorder_rules"` — update positions in-memory, regenerate preview
      - `"update_raw_expression"` — update raw expression in assigns, regenerate preview
      - `"update_composition_mode"` — switch append/replace, regenerate preview
      - `"validate"` — generate expression, call `Bpf.validate_expression/1`, display result with instruction count or error
      - `"save"` — call `Bpf.save_profile/3`, display success/error flash with "saved but not deployed" notice
      - `"reset"` / `"confirm_reset"` / `"cancel_reset"` — confirmation flow, call `Bpf.reset_profile/2`
    - Deny unauthorized events with error flash and `permission_denied` audit entry
    - _Requirements: 2.1–2.11, 3.1–3.7, 4.2, 4.3, 4.8, 7.3, 7.4, 8.4, 8.5, 8.6, 10.2_

  - [ ] 10.3 Implement `BpfLive.EditorLive` — template/render
    - Render empty state with "Create Profile" button when no profile exists
    - Render filter rule list/table: rule type icon/label, parameter summary, enabled/disabled toggle, edit/delete controls, drag-and-drop reorder
    - Render raw BPF expression text area with composition mode selector (append/replace)
    - Render compiled expression preview in read-only monospace area, updated in real time
    - Render "Validate" and "Save" buttons with loading indicator during compilation
    - Render version metadata: current version, last-modified timestamp and actor
    - Render "saved but not deployed" notice and pending deployment indicator
    - Render BPF restart pending warning banner with sensor count and links to sensor detail pages
    - Render green status indicator when no sensors have bpf_restart_pending
    - Render reset confirmation dialog
    - Render replace mode warning when structured rules exist
    - Render no-filter warning when compiled expression is empty
    - Hide write controls (add rule, save, reset, validate, edit/delete/toggle/reorder, raw expression textarea) for users without `bpf:manage`
    - _Requirements: 1.2, 1.3, 1.4, 1.5, 2.7, 2.10, 2.11, 3.1, 3.3, 4.4, 4.8, 4.9, 5.3, 5.4, 6.3, 8.5, 10.1, 10.2, 10.3, 12.2, 12.4_

- [ ] 11. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12. Pool navigation integration
  - [ ] 12.1 Add BPF Filters tab to pool detail page navigation
    - Update `PoolShowLive` (or equivalent pool detail page) to add "BPF Filters" navigation link to the tab bar alongside Config, Sensors, Forwarding, and Deployments
    - Display BPF summary on the pool detail/show page: profile exists, current version, enabled rule count, has raw expression
    - Show "pending deployment" badge on the BPF tab when `version > last_deployed_version`
    - Use `Bpf.bpf_summary/1` for summary data
    - _Requirements: 13.1, 13.2, 13.3_

- [ ] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (15 properties total)
- Unit tests validate specific examples and edge cases
- No new Elixir dependencies — uses existing `System.cmd/3` for tcpdump compilation and existing `propcheck ~> 1.4` for property tests
- BPF configuration does NOT auto-deploy to sensors; deployment is a separate explicit action through the existing deployment workflow
- All rule editing happens in-memory in the LiveView; changes are only persisted on "Save"
- The `bpf:manage` permission follows the same grant pattern as `pools:manage` and `forwarding:manage`
