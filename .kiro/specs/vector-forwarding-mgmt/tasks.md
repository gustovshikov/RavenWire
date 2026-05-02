# Implementation Plan: Vector Forwarding Sink Management

## Overview

This plan implements pool-level Vector forwarding sink management for the RavenWire Config Manager. The implementation proceeds in layers: database migrations → Ecto schemas → encryption module → validation modules → context module → LiveView UI → integration wiring. Each step builds on the previous, ensuring no orphaned code.

## Tasks

- [ ] 1. Database migrations and schema foundations
  - [ ] 1.1 Create the `forwarding_sinks` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_forwarding_sinks.exs`
    - Define columns: `id` (binary_id PK), `pool_id` (binary_id FK to sensor_pools, on_delete: delete_all), `name` (text, not null), `normalized_name` (text, not null), `sink_type` (text, not null), `config` (text, not null), `enabled` (boolean, default true), `last_test_result` (text, nullable), `last_test_at` (utc_datetime_usec, nullable), timestamps
    - Create unique index on `[:pool_id, :normalized_name]`
    - Create index on `[:pool_id]`
    - _Requirements: 13.1, 13.2_

  - [ ] 1.2 Create the `sink_secrets` table migration
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_sink_secrets.exs`
    - Define columns: `id` (binary_id PK), `forwarding_sink_id` (binary_id FK to forwarding_sinks, on_delete: delete_all), `secret_name` (text, not null), `ciphertext` (text, not null), `last_four` (text, nullable), timestamps
    - Create unique index on `[:forwarding_sink_id, :secret_name]`
    - Create index on `[:forwarding_sink_id]`
    - _Requirements: 13.3, 13.9, 13.10_

  - [ ] 1.3 Create the migration to add forwarding fields to `sensor_pools`
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_add_forwarding_fields_to_sensor_pools.exs`
    - Add columns: `schema_mode` (text, not null, default "raw"), `forwarding_config_version` (integer, not null, default 0), `forwarding_config_updated_at` (utc_datetime_usec, nullable), `forwarding_config_updated_by` (text, nullable)
    - _Requirements: 13.4, 13.5_

  - [ ] 1.4 Run migrations and verify schema
    - Run `mix ecto.migrate` to apply all three migrations
    - Verify tables, columns, indexes, and constraints are created correctly
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.9, 13.10_

- [ ] 2. Ecto schemas
  - [ ] 2.1 Implement the `ForwardingSink` Ecto schema
    - Create `lib/config_manager/forwarding/forwarding_sink.ex`
    - Define schema with all fields, `has_many :secrets` association
    - Implement `create_changeset/2` with name validation, format validation, `put_normalized_name/1`, unique constraint, JSON config validation
    - Implement `update_changeset/2` with same validations (excluding pool_id/sink_type changes)
    - Implement `toggle_changeset/1` and `test_result_changeset/3`
    - Validate `sink_type` against `~w(splunk_hec http syslog kafka s3 file)`
    - _Requirements: 2.3, 13.1, 13.7_

  - [ ] 2.2 Implement the `SinkSecret` Ecto schema
    - Create `lib/config_manager/forwarding/sink_secret.ex`
    - Define schema with `forwarding_sink_id`, `secret_name`, `ciphertext`, `last_four`
    - Implement `changeset/2` with required field validation and unique constraint
    - _Requirements: 13.3, 13.9, 13.10_

  - [ ] 2.3 Extend the `SensorPool` schema with forwarding fields
    - Add `schema_mode`, `forwarding_config_version`, `forwarding_config_updated_at`, `forwarding_config_updated_by` fields
    - Add `has_many :forwarding_sinks` association
    - Implement `schema_mode_changeset/3` with validation against `~w(raw ecs ocsf splunk_cim)`
    - Implement `increment_forwarding_version_changeset/2` for version bumps
    - _Requirements: 7.1, 13.4, 13.5, 15.3_

  - [ ]* 2.4 Write property tests for sink name normalization (Property 2)
    - **Property 2: Case-insensitive sink name uniqueness within a pool**
    - Generate random sink names with case variants, verify uniqueness constraint
    - **Validates: Requirements 2.3, 13.2**

  - [ ]* 2.5 Write property test for schema mode validation (Property 13)
    - **Property 13: Schema mode validation against allowed set**
    - Generate random strings, verify acceptance iff in `["raw", "ecs", "ocsf", "splunk_cim"]`
    - **Validates: Requirements 7.1, 13.5**

- [ ] 3. Encryption module
  - [ ] 3.1 Implement `ConfigManager.Forwarding.Encryption`
    - Create `lib/config_manager/forwarding/encryption.ex`
    - Implement `encrypt/1` using AES-256-GCM with random 12-byte IV, 16-byte tag, AAD `"ravenwire_sink_secret_v1"`
    - Implement `decrypt/1` to decode Base64, extract IV/tag/ciphertext, decrypt
    - Implement `last_four/1` to extract last 4 characters (or fewer for short strings)
    - Implement `mask/1` to return dots + last 4 chars
    - Implement `key_available?/0` to check env var presence
    - Key source: `RAVENWIRE_SINK_ENCRYPTION_KEY` env var (Base64-decoded, 32 bytes); dev/test fallback from `secret_key_base`
    - _Requirements: 6.1, 6.3_

  - [ ]* 3.2 Write property test for encryption round-trip (Property 3)
    - **Property 3: Secret encryption round-trip**
    - Generate random binary strings (1–1000 bytes), verify encrypt→decrypt produces original
    - Verify ciphertext ≠ plaintext, two encryptions produce different ciphertexts
    - **Validates: Requirements 6.1, 13.3**

  - [ ]* 3.3 Write property test for secret masking (Property 12)
    - **Property 12: Secret masking shows only last 4 characters**
    - Generate random strings of varying lengths, verify masking behavior
    - **Validates: Requirements 6.3**

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Validation modules
  - [ ] 5.1 Implement `ConfigManager.Forwarding.SinkConfigSchema`
    - Create `lib/config_manager/forwarding/sink_config_schema.ex`
    - Implement `validate/2` for each sink type with required/optional field definitions
    - Implement `secret_fields/1` returning secret field names per type
    - Implement `required_fields/1` returning required non-secret fields per type
    - Implement `sensitive_headers/0` returning `["Authorization", "Cookie", "X-API-Key"]`
    - Validate endpoint URLs, host:port formats, bootstrap server lists per type
    - _Requirements: 2.2, 2.7, 2.8, 13.8_

  - [ ] 5.2 Implement `ConfigManager.Forwarding.DestinationValidator`
    - Create `lib/config_manager/forwarding/destination_validator.ex`
    - Implement `validate/3` for URL/host validation per sink type
    - Implement `allow_private?/0` checking `ALLOW_PRIVATE_DESTINATIONS` env var
    - Implement `resolve_and_check/1` for IP resolution and range checking
    - Block loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7) unless lab mode
    - _Requirements: 8.9_

  - [ ]* 5.3 Write property test for destination validation (Property 9)
    - **Property 9: Destination validation rejects blocked network addresses**
    - Generate random IPs from loopback/link-local/private/public ranges
    - Verify rejection/acceptance based on `ALLOW_PRIVATE_DESTINATIONS` setting
    - **Validates: Requirements 8.9**

- [ ] 6. Connection tester module
  - [ ] 6.1 Implement `ConfigManager.Forwarding.ConnectionTester`
    - Create `lib/config_manager/forwarding/connection_tester.ex`
    - Implement `test_async/3` dispatching via `Task.Supervisor` with concurrency limit (default 5)
    - Implement `test_sync/2` with per-type test logic (HTTP for splunk_hec/http, TCP for syslog/kafka, HEAD for s3)
    - Implement `active_test_count/0` for concurrency tracking
    - Return `{:error, :file_sink}` for file type, `{:error, :concurrent_limit}` when at capacity
    - Configurable timeout (default 10s)
    - Sanitize error messages (strip tokens, passwords, query strings)
    - _Requirements: 8.1, 8.2, 8.5, 8.6, 8.7, 8.8_

  - [ ]* 6.2 Write property test for concurrency limiting (Property 14)
    - **Property 14: Connection test concurrency limiting**
    - Dispatch concurrent test requests exceeding limit, verify excess rejected
    - **Validates: Requirements 8.8**

- [ ] 7. Forwarding context module
  - [ ] 7.1 Implement `ConfigManager.Forwarding` context — CRUD operations
    - Create `lib/config_manager/forwarding.ex`
    - Implement `list_sinks/1`, `get_sink/1`, `get_sink_for_pool/2` (cross-pool check)
    - Implement `create_sink/3` with Ecto.Multi: validate config schema → create sink → encrypt and insert secrets → increment forwarding_config_version → append audit entry → broadcast PubSub
    - Implement `update_sink/4` with secret preservation logic (sentinel/empty = keep existing)
    - Implement `delete_sink/3` with Ecto.Multi: verify pool ownership → delete sink (cascade secrets) → increment version → audit → broadcast
    - Implement `toggle_sink/3` with Ecto.Multi: toggle enabled → increment version → audit → broadcast
    - _Requirements: 2.4, 3.3, 3.4, 3.5, 3.6, 3.7, 4.2, 4.4, 5.2, 14.1_

  - [ ] 7.2 Implement `ConfigManager.Forwarding` context — schema mode and connection testing
    - Implement `update_schema_mode/3` with Ecto.Multi: validate mode → update pool → increment version → audit → broadcast
    - Implement `test_connection/3` with destination validation → dispatch async test → store result (no version increment)
    - Implement `masked_secrets/1` and `forwarding_summary/1` query functions
    - Implement `get_schema_mode/1`
    - _Requirements: 7.3, 8.1, 8.2, 8.10, 15.4_

  - [ ]* 7.3 Write property test for config version increment (Property 5)
    - **Property 5: Forwarding_Config_Version increments exactly on configuration changes**
    - Perform random sequences of mutations, verify version increments by 1 each time
    - Verify connection test does NOT increment version
    - **Validates: Requirements 2.4, 3.5, 4.2, 5.2, 7.3, 8.10, 15.3, 15.4**

  - [ ]* 7.4 Write property test for cross-pool access denial (Property 6)
    - **Property 6: Cross-pool sink access denial**
    - Create sinks in pool A, attempt access via pool B, verify :not_found
    - **Validates: Requirements 3.7, 4.4, 16.5**

  - [ ]* 7.5 Write property test for secret preservation on unchanged edit (Property 11)
    - **Property 11: Secret preservation on unchanged edit**
    - Create sinks with secrets, edit non-secret fields, verify ciphertext unchanged
    - **Validates: Requirements 3.3**

  - [ ]* 7.6 Write property test for transactional audit integrity (Property 8)
    - **Property 8: Transactional audit integrity**
    - Simulate audit insert failure, verify forwarding mutation rolled back
    - **Validates: Requirements 12.4**

- [ ] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. RBAC policy verification
  - [ ] 9.1 Verify canonical `forwarding:manage` permission in the Policy module
    - Verify `"forwarding:manage"` is present in `Policy.canonical_permissions/0`
    - Verify `sensor-operator` and `rule-manager` role permission lists include `"forwarding:manage"`
    - Verify `platform-admin` has `:all` (covers forwarding:manage)
    - Verify `viewer`, `analyst`, `auditor` do NOT have `forwarding:manage`
    - _Requirements: 11.1, 11.2, 11.3_

  - [ ]* 9.2 Write property test for RBAC enforcement (Property 1)
    - **Property 1: RBAC enforcement for forwarding actions**
    - For random roles and forwarding write actions, verify permit/deny matches policy
    - **Validates: Requirements 1.1, 2.1, 3.1, 11.1, 11.2, 11.3, 11.4, 11.6**

- [ ] 10. Router and navigation
  - [ ] 10.1 Add forwarding routes to the router
    - Add `live "/pools/:id/forwarding"` with `sensors:view` permission
    - Add `live "/pools/:id/forwarding/sinks/new"` with `forwarding:manage` permission
    - Add `live "/pools/:id/forwarding/sinks/:sink_id/edit"` with `forwarding:manage` permission
    - Add "Forwarding" navigation link to pool sub-navigation
    - _Requirements: 16.1, 16.2, 16.3, 11.7_

- [ ] 11. LiveView — Forwarding Overview page
  - [ ] 11.1 Implement `ForwardingLive.OverviewLive`
    - Create `lib/config_manager_web/live/forwarding_live/overview_live.ex`
    - Implement `mount/3`: load pool, list sinks, get forwarding summary, subscribe to PubSub topic `"pool:#{pool_id}:forwarding"`
    - Implement `handle_event` callbacks: `toggle_sink`, `delete_sink`, `confirm_delete`, `cancel_delete`, `test_connection`, `update_schema_mode`, `reveal_secret` — each with RBAC check for `forwarding:manage`
    - Implement `handle_info` callbacks for PubSub messages and `{:connection_test_result, ...}`
    - _Requirements: 1.1, 1.2, 1.3, 1.5, 1.6, 1.7, 4.1, 4.3, 5.1, 5.3, 17.1_

  - [ ] 11.2 Create the overview page template/render
    - Render sink summary cards: name, type, endpoint, enabled/disabled status, last test result
    - Render schema mode selector with descriptions for each mode
    - Render "Add Sink" button (visible only with `forwarding:manage`)
    - Render empty state when no sinks configured
    - Render forwarding telemetry placeholder section ("Forwarding telemetry not yet available — requires HealthReport protobuf extension")
    - Render forwarding_config_version and metadata (timestamp, actor)
    - Render deployment notice ("Saved configuration changes require explicit deployment")
    - Render delete confirmation dialog
    - Render loading indicators for async operations
    - Visually distinguish disabled sinks (muted/grayed-out)
    - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 5.3, 9.1, 9.2, 9.4, 15.2, 17.2, 17.3, 17.4_

- [ ] 12. LiveView — Sink Form (Create/Edit)
  - [ ] 12.1 Implement `ForwardingLive.SinkFormLive`
    - Create `lib/config_manager_web/live/forwarding_live/sink_form_live.ex`
    - Implement `mount/3` for `:new` (empty form with type selector) and `:edit` (pre-populate from sink, mask secrets, cross-pool check)
    - Implement `handle_event("select_type", ...)` to switch type-specific fields
    - Implement `handle_event("validate", ...)` for live validation
    - Implement `handle_event("save", ...)` calling `Forwarding.create_sink/3` or `Forwarding.update_sink/4`
    - Implement `handle_event("test_connection", ...)` for edit mode
    - Redirect to overview on success
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 8.1_

  - [ ] 12.2 Create the sink form template/render
    - Render sink type selector with all 6 types
    - Render type-specific fields per design (splunk_hec, http, syslog, kafka, s3, file)
    - Render secret fields with masked placeholders on edit
    - Render field-level validation errors
    - Render "Test Connection" button on edit (not for file type)
    - Accessible labels, keyboard-reachable controls
    - _Requirements: 2.2, 2.7, 2.8, 3.2, 6.3, 8.1, 17.2_

- [ ] 13. Sensor detail page forwarding section
  - [ ] 13.1 Update `SensorDetailLive` forwarding section
    - When sensor belongs to a pool with sinks: show pool name (linked to `/pools/:pool_id/forwarding`), schema mode, enabled sink count, sink name/type list
    - When sensor has no pool: show "No pool assigned" message with link to pool list
    - When sensor's pool has no sinks: show "No forwarding sinks configured" with link to pool forwarding page
    - Show "Forwarding telemetry not yet available" placeholder for per-sensor telemetry
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

- [ ] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 15. Audit and secret sanitization integration
  - [ ] 15.1 Verify audit entry sanitization across all forwarding actions
    - Ensure `sink_created` audit includes name, sink_type, pool_id, pool_name
    - Ensure `sink_updated` audit includes changed fields with old/new values, `secrets_changed` list (names only, no values)
    - Ensure `sink_deleted` audit includes name, sink_type, pool_id
    - Ensure `sink_toggled` audit includes name and new enabled state
    - Ensure `schema_mode_changed` audit includes old_mode and new_mode
    - Ensure `sink_connection_tested` audit includes sanitized endpoint (no query params, no credentials)
    - Ensure `permission_denied` audit includes required_permission and event_or_route
    - Verify no secret values appear in any audit detail field
    - _Requirements: 12.1, 12.2, 12.3, 12.6, 12.7_

  - [ ]* 15.2 Write property test for audit completeness and sanitization (Property 7)
    - **Property 7: Audit entry completeness and sanitization**
    - Perform random forwarding mutations, verify audit entries have all required fields
    - Verify no secrets in detail JSON, verify URL sanitization
    - **Validates: Requirements 8.4, 8.11, 12.1, 12.2, 12.6, 12.7**

  - [ ]* 15.3 Write property test for secret leak prevention (Property 4)
    - **Property 4: Secrets never leak to responses, audit entries, or PubSub**
    - Create sinks with random secrets, verify absence in config field, audit, PubSub payloads
    - **Validates: Requirements 3.6, 6.2, 6.6, 12.3, 13.8**

- [ ] 16. PubSub integration and real-time updates
  - [ ] 16.1 Wire PubSub broadcasts in the Forwarding context
    - Broadcast `{:sink_created, sink}`, `{:sink_updated, sink}`, `{:sink_deleted, sink_id}`, `{:sink_toggled, sink}`, `{:schema_mode_changed, schema_mode}` to `"pool:#{pool_id}:forwarding"`
    - Ensure PubSub payloads do NOT contain secret values
    - Verify overview page handles all PubSub messages and updates UI without full reload
    - _Requirements: 6.6, 17.1_

- [ ] 17. Cascade delete and pool integration
  - [ ] 17.1 Verify cascade delete behavior
    - Confirm that deleting a pool cascades to all forwarding_sinks and their sink_secrets
    - Confirm sinks/secrets in other pools are unaffected
    - _Requirements: 13.6, 14.1_

  - [ ]* 17.2 Write property test for cascade delete (Property 10)
    - **Property 10: Pool cascade deletes all associated sinks and secrets**
    - Create pools with random numbers of sinks and secrets, delete pool, verify cleanup
    - **Validates: Requirements 13.6**

- [ ] 18. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design specifies no new Elixir dependencies — uses existing `:crypto` for AES-256-GCM and existing `propcheck ~> 1.4` for property tests
- Telemetry display is placeholder-only in this feature; actual telemetry requires a future HealthReport protobuf extension
- Forwarding configuration does NOT auto-deploy to sensors; deployment is a separate explicit action
