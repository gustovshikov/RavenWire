# Implementation Plan: Detection Content Lifecycle Management

## Overview

This plan implements detection content lifecycle management for all three RavenWire detection engines (Suricata, Zeek, YARA) with unified content versioning, content validation, and full audit/RBAC integration. Tasks are ordered so each step builds on the previous: database migrations first, then Ecto schemas, context modules, validation, LiveView UI, router wiring, and finally integration with existing deployment and pool detail pages.

## Tasks

- [ ] 1. Create Ecto migrations for Zeek packages, YARA rules, and detection content version fields
  - [ ] 1.1 Create migration `CreateZeekPackages` for `zeek_packages` and `zeek_pool_packages` tables
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_zeek_packages.exs`
    - `zeek_packages`: id (binary_id PK), name (string, not null, unique), description (text), version (string), author (string), source_url (string), tags (text, default "[]"), timestamps
    - `zeek_pool_packages`: id (binary_id PK), pool_id (references sensor_pools, on_delete: delete_all), package_id (references zeek_packages, on_delete: delete_all), enabled (boolean, default true), installed_by (string, not null), timestamps
    - Unique index on `[:pool_id, :package_id]`, index on `[:pool_id]`
    - _Requirements: 10.4, 2.3_

  - [ ] 1.2 Create migration `CreateYaraRulesTables` for `yara_rules`, `yara_rulesets`, `yara_ruleset_rules`, and `pool_yara_ruleset_assignments` tables
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_yara_rules_tables.exs`
    - `yara_rules`: id (binary_id PK), name (string, not null, unique), description (text), raw_text (text, not null), tags (text, default "[]"), enabled (boolean, default true), uploaded_by (string, not null), source_filename (string), timestamps
    - `yara_rulesets`: id (binary_id PK), name (string, not null), description (text), version (integer, default 1), updated_by (string, not null), timestamps; case-insensitive unique index via raw SQL
    - `yara_ruleset_rules`: id (binary_id PK), ruleset_id (references yara_rulesets, on_delete: delete_all), rule_id (references yara_rules, on_delete: delete_all), timestamps; unique index on `[:ruleset_id, :rule_id]`
    - `pool_yara_ruleset_assignments`: id (binary_id PK), pool_id (references sensor_pools, on_delete: delete_all), ruleset_id (references yara_rulesets, on_delete: delete_all), assigned_by (string, not null), timestamps; unique index on `[:pool_id]`
    - Use `up/down` functions for the raw SQL index on yara_rulesets
    - _Requirements: 10.4, 10.5_

  - [ ] 1.3 Create migration `AddDetectionContentVersion` for new fields on existing tables
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_add_detection_content_version.exs`
    - `sensor_pools`: add `detection_content_version` (integer, not null, default 1)
    - `sensor_pods`: add `last_deployed_detection_content_version` (integer, nullable)
    - `deployments`: add `detection_content_version` (integer, nullable) — guard with `if table_exists?` or ensure deployment-tracking migration runs first
    - _Requirements: 10.1, 10.2, 10.3_

- [ ] 2. Create Ecto schemas for Zeek packages
  - [ ] 2.1 Create `ZeekPackage` schema at `lib/config_manager/zeek_packages/zeek_package.ex`
    - Define schema for `zeek_packages` table with all fields from migration
    - Implement `changeset/2` with required name validation, length constraint, unique constraint
    - Tags stored as JSON-encoded text string for SQLite compatibility
    - _Requirements: 1.3, 10.4_

  - [ ] 2.2 Create `ZeekPoolPackage` schema at `lib/config_manager/zeek_packages/zeek_pool_package.ex`
    - Define schema for `zeek_pool_packages` table with pool_id, package_id, enabled, installed_by
    - Implement `changeset/2` with required fields, unique constraint on `[:pool_id, :package_id]`, foreign key constraints
    - Implement `toggle_changeset/1` that flips the `enabled` field
    - `belongs_to` associations for pool and package with `define_field: false`
    - _Requirements: 2.3, 10.4_

- [ ] 3. Create Ecto schemas for YARA rules
  - [ ] 3.1 Create `YaraRule` schema at `lib/config_manager/yara_rules/yara_rule.ex`
    - Define schema for `yara_rules` table with all fields from migration
    - Implement `changeset/2` with required name/raw_text/uploaded_by, length constraint, unique constraint
    - Implement `toggle_changeset/1` that flips the `enabled` field
    - Tags stored as JSON-encoded text string for SQLite compatibility
    - _Requirements: 3.2, 3.3, 10.4_

  - [ ] 3.2 Create `YaraRuleset` schema at `lib/config_manager/yara_rules/yara_ruleset.ex`
    - Define schema for `yara_rulesets` table with name, description, version, updated_by
    - Implement `create_changeset/3` with name format validation (`^[a-zA-Z0-9._-]+$`), unique constraint (nocase index), version defaults to 1
    - Implement `update_changeset/4` that increments version when membership changes
    - `has_many` associations for `ruleset_rules` and `rules` (through)
    - _Requirements: 4.1, 10.5_

  - [ ] 3.3 Create `YaraRulesetRule` schema at `lib/config_manager/yara_rules/yara_ruleset_rule.ex`
    - Define schema for `yara_ruleset_rules` join table
    - Implement `changeset/2` with required ruleset_id/rule_id, unique constraint, foreign key constraints
    - `belongs_to` associations with `define_field: false`
    - _Requirements: 4.1_

  - [ ] 3.4 Create `PoolYaraRulesetAssignment` schema at `lib/config_manager/yara_rules/pool_yara_ruleset_assignment.ex`
    - Define schema for `pool_yara_ruleset_assignments` table
    - Implement `changeset/2` with required pool_id/ruleset_id/assigned_by, unique constraint on pool_id, foreign key constraints
    - `belongs_to` associations with `define_field: false`
    - _Requirements: 4.2, 4.3_

- [ ] 4. Update existing schemas with detection content version fields
  - [ ] 4.1 Add `detection_content_version` field to `ConfigManager.SensorPool` schema
    - Add `field :detection_content_version, :integer, default: 1` to the schema
    - Add a `detection_content_version_changeset/1` or helper function that increments the version
    - Do not add `detection_content_version` to the general `changeset/2` cast list — it should only be incremented by detection content mutations
    - _Requirements: 5.1, 10.1_

  - [ ] 4.2 Add `last_deployed_detection_content_version` field to `ConfigManager.SensorPod` schema
    - Add `field :last_deployed_detection_content_version, :integer` to the schema
    - _Requirements: 5.4, 10.3_

- [ ] 5. Checkpoint — Run migrations and verify schemas compile
  - Ensure `mix ecto.migrate` succeeds and all new schemas compile without errors. Ask the user if questions arise.

- [ ] 6. Implement YARA syntax validator
  - [ ] 6.1 Create `ConfigManager.YaraRules.Validator` at `lib/config_manager/yara_rules/validator.ex`
    - Implement `validate_syntax/1` — checks matching rule blocks (`rule name { ... }`), valid rule names (alphanumeric + underscore, starting with letter/underscore), required `condition:` section, balanced braces and parentheses
    - Implement `parse_metadata/1` — extracts rule names, descriptions (from `meta:` section), and tags from rule text; returns `{:ok, [%{name, description, tags}]}` or `{:error, message}`
    - Implement `valid_extension?/1` — checks `.yar` or `.yara` extension
    - Return structured errors with line numbers: `{:error, [%{line: integer, message: string}]}`
    - _Requirements: 3.4, 3.5, 6.3_

  - [ ]* 6.2 Write property tests for YARA validator (Properties 4 and 5)
    - **Property 4: YARA rule upload preserves raw text** — generate valid YARA rule text, upload and retrieve, verify byte-identical raw_text and correct parsed name
    - **Property 5: YARA syntax validation accepts valid rules and rejects invalid rules** — generate well-formed rules (validator returns :ok) and malformed rules with unbalanced braces/missing condition/invalid names (validator returns {:error, errors})
    - **Validates: Requirements 3.3, 3.4, 3.5**

  - [ ]* 6.3 Write unit tests for YARA validator edge cases
    - Test empty file, single rule, multi-rule file, nested braces, comments, imports, rules with meta section, rules with tags
    - Test invalid: missing condition, unbalanced braces, invalid rule name characters, empty rule body
    - Test `valid_extension?/1` with .yar, .yara, .txt, .rules, no extension
    - _Requirements: 3.4, 3.5_

- [ ] 7. Implement `ConfigManager.ZeekPackages` context module
  - [ ] 7.1 Create `lib/config_manager/zeek_packages.ex` with registry query functions
    - Implement `list_packages/1` with search, sort (default: name asc), and pagination (default: 25 per page)
    - Implement `list_packages_with_pool_state/2` that annotates packages with per-pool installation state
    - Implement `get_package/1` and `search_packages/2`
    - Implement `installed_count/1` and `enabled_count/1`
    - All list functions return `%{entries, page, total_pages, total_count}` pagination struct
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [ ] 7.2 Implement per-pool Zeek package state functions with Ecto.Multi and audit
    - Implement `install_package/3` — creates `zeek_pool_packages` record, increments pool `detection_content_version`, writes audit entry (`zeek_package_installed`), broadcasts PubSub; all in one `Ecto.Multi` transaction
    - Implement `uninstall_package/3` — removes record, increments version, writes audit, broadcasts; returns `{:error, :not_installed}` if not found
    - Implement `toggle_package/3` — flips enabled state, increments version, writes audit (`zeek_package_toggled`), broadcasts
    - Implement `list_pool_packages/1` — returns installed packages with enabled state
    - Implement `verify_pool_packages/1` — checks all installed packages exist in registry (used by ContentValidation)
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6, 2.7, 8.1, 8.2, 8.3_

  - [ ]* 7.3 Write property tests for Zeek packages (Properties 1, 2, 3)
    - **Property 1: Zeek package install/uninstall round-trip preserves pool isolation** — install for pool A, verify record exists, uninstall, verify removed, verify pool B unchanged
    - **Property 2: Zeek package toggle is self-inverse** — toggle twice returns to original enabled state
    - **Property 3: Zeek package search returns only matching results** — generate random packages and queries, verify all results contain query substring in name or description
    - **Validates: Requirements 1.4, 2.1, 2.2, 2.3, 2.4**

  - [ ]* 7.4 Write unit tests for Zeek package context
    - Test pagination boundary conditions (page 0, beyond last page, exact page boundary)
    - Test search with empty query returns all, special characters, case-insensitive matching
    - Test install already-installed returns `{:error, :already_installed}`
    - Test uninstall not-installed returns `{:error, :not_installed}`
    - Test audit entry structure for each Zeek action type
    - _Requirements: 1.4, 1.6, 1.7, 2.1, 2.4, 8.1, 8.2_

- [ ] 8. Implement `ConfigManager.YaraRules` context module
  - [ ] 8.1 Create `lib/config_manager/yara_rules.ex` with rule CRUD functions
    - Implement `list_rules/1` with search, sort, and pagination
    - Implement `get_rule/1`
    - Implement `upload_rules/2` — validates syntax via Validator, parses metadata, inserts records, writes audit (`yara_rule_uploaded`), broadcasts; rejects entire batch on any validation failure
    - Implement `toggle_rule/2` — toggles global enabled state, updates affected rulesets (removes rule, increments version), increments affected pools' `detection_content_version`, writes audit (`yara_rule_toggled`), broadcasts
    - Implement `delete_rule/2` — removes rule, updates affected rulesets and pool versions, writes audit (`yara_rule_deleted`), broadcasts
    - Implement `affected_pools_for_rule/1` — finds pools whose assigned rulesets include the given rule
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 8.1, 8.2, 8.3_

  - [ ] 8.2 Implement YARA ruleset management functions
    - Implement `list_rulesets/0` with rule counts and pool assignment info
    - Implement `get_ruleset/1` and `get_ruleset!/1` with preloaded rules
    - Implement `create_ruleset/3` — validates all rule_ids are enabled, creates ruleset and membership records, writes audit; returns `{:error, :disabled_rules_included}` if any rule is disabled
    - Implement `update_ruleset/4` — updates metadata/membership, increments version on membership change, validates enabled-only, writes audit
    - Implement `delete_ruleset/2` — deletes ruleset and cascade assignments, writes audit
    - Implement `effective_rules/1` — returns enabled rules for a pool's assigned ruleset
    - _Requirements: 4.1, 10.5_

  - [ ] 8.3 Implement YARA ruleset pool assignment functions
    - Implement `assign_ruleset_to_pool/3` — replaces any existing assignment (at most one per pool), increments pool `detection_content_version`, writes audit (`yara_ruleset_assigned_to_pool`), broadcasts
    - Implement `unassign_ruleset_from_pool/2` — removes assignment, increments version, writes audit (`yara_ruleset_unassigned_from_pool`), broadcasts
    - Implement `pool_assignment/1`, `pool_ruleset/1`
    - All mutations use `Ecto.Multi` with `Audit.append_multi/2`
    - _Requirements: 4.2, 4.3, 4.5, 4.6, 8.1, 8.2, 8.3_

  - [ ]* 8.4 Write property tests for YARA rules (Properties 6 and 7)
    - **Property 6: YARA ruleset composition includes only enabled rules** — create rulesets with mixed enabled/disabled rules, verify only enabled accepted; disable a rule in an assigned ruleset, verify ruleset updated and pool version incremented
    - **Property 7: At most one YARA ruleset per pool** — assign multiple rulesets to same pool sequentially, verify only one assignment exists after each
    - **Validates: Requirements 4.1, 4.2, 10.5**

  - [ ]* 8.5 Write unit tests for YARA rules context
    - Test upload with valid single file, valid multi-rule file, invalid syntax file, invalid extension
    - Test bulk upload partial failure rejects entire batch
    - Test toggle rule affecting assigned rulesets updates pool versions
    - Test delete rule affecting assigned rulesets updates pool versions
    - Test create ruleset with disabled rule returns `:disabled_rules_included`
    - Test duplicate rule name on upload returns uniqueness error
    - Test audit entry structure for each YARA action type
    - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 8.1, 8.2_

- [ ] 9. Checkpoint — Verify context modules compile and pass tests
  - Ensure all context modules compile, `mix test` passes. Ask the user if questions arise.

- [ ] 10. Implement unified detection content version tracking
  - [ ] 10.1 Create shared version increment helper
    - Add a helper function (in `ZeekPackages` or a shared module) that increments `sensor_pools.detection_content_version` within an `Ecto.Multi` pipeline
    - Ensure the helper is used consistently by `ZeekPackages.install_package/3`, `uninstall_package/3`, `toggle_package/3`, `YaraRules.assign_ruleset_to_pool/3`, `unassign_ruleset_from_pool/2`, and YARA rule toggle/delete when affecting assigned rulesets
    - _Requirements: 5.1, 2.7, 4.3, 4.6_

  - [ ]* 10.2 Write property test for unified version increment (Property 8)
    - **Property 8: Unified detection_content_version increments on any content change** — generate random sequences of Zeek install/uninstall/toggle, YARA assign/unassign, YARA rule toggle affecting assigned rulesets; verify version increments by exactly 1 for each operation and is monotonically increasing
    - **Validates: Requirements 2.7, 4.3, 4.6, 5.1**

  - [ ]* 10.3 Write property test for drift detection (Property 9)
    - **Property 9: Detection content drift detection correctness** — generate pools with sensors at various deployed versions, verify drift detected iff `last_deployed_detection_content_version != detection_content_version`, nil classified as `:never_deployed`
    - **Validates: Requirements 5.3, 5.4, 5.6**

- [ ] 11. Implement `ConfigManager.ContentValidation` module
  - [ ] 11.1 Create `lib/config_manager/content_validation.ex`
    - Implement `validate_pool/1` — orchestrates validation across Suricata (via existing `Rules.Parser`), YARA (via `YaraRules.Validator`), and Zeek (via `ZeekPackages.verify_pool_packages/1`)
    - Implement `validate_suricata/1`, `validate_yara/1`, `validate_zeek/1` as individual engine validators
    - Implement `record_validation_result/3` — writes audit entry with action `content_validation_passed` or `content_validation_failed`
    - All engines validated independently; result contains errors from all failing engines
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 8.1_

  - [ ]* 11.2 Write property test for content validation (Property 11)
    - **Property 11: Content validation catches inconsistent Zeek package states** — generate pool package states with some packages missing from registry, verify validator returns `:ok` when consistent and `{:error, issues}` when inconsistent
    - **Validates: Requirements 6.4**

  - [ ]* 11.3 Write unit tests for content validation
    - Test validate_pool with all engines passing
    - Test validate_pool with Suricata failure only, YARA failure only, Zeek failure only, multiple failures
    - Test audit entry written for passed and failed validations
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.6_

- [ ] 12. Checkpoint — Verify all context modules and validation pass tests
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Implement `ZeekPackagesLive` LiveView
  - [ ] 13.1 Create `lib/config_manager_web/live/rules_live/zeek_packages_live.ex`
    - Implement `mount/3` — load pools for selector, load paginated packages with default sort (name asc), subscribe to PubSub topic
    - Implement pool selector dropdown (`handle_event("select_pool", ...)`) — reload package states for selected pool
    - Implement search (`handle_event("search", ...)`) — filter packages by name/description substring
    - Implement sort (`handle_event("sort", ...)`) — change sort column
    - Implement pagination (`handle_event("page", ...)`) — 25 per page default
    - Display each package row: name, description, version, author, source_url, per-pool status (available/installed/enabled/disabled)
    - Display empty state message when no packages match search
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [ ] 13.2 Implement Zeek package management actions in `ZeekPackagesLive`
    - Implement `handle_event("install", ...)` — calls `ZeekPackages.install_package/3`, requires `rules:manage`
    - Implement `handle_event("uninstall", ...)` — calls `ZeekPackages.uninstall_package/3`, requires `rules:manage`
    - Implement `handle_event("toggle", ...)` — calls `ZeekPackages.toggle_package/3`, requires `rules:manage`
    - Show Install/Uninstall/Enable/Disable buttons only to users with `rules:manage` permission
    - Handle PubSub messages to refresh package states in real-time
    - Display notice that changes are not automatically deployed
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6, 7.1, 7.3, 7.4_

- [ ] 14. Implement `YaraRulesLive` LiveView
  - [ ] 14.1 Create `lib/config_manager_web/live/rules_live/yara_rules_live.ex` with rules tab
    - Implement `mount/3` — load paginated YARA rules, subscribe to `yara_rules` and `yara_rulesets` PubSub topics
    - Implement tab switching (`handle_event("tab", ...)`) between `:rules` and `:rulesets`
    - Rules tab: display rule rows (name, description, tags, enabled/disabled, upload timestamp, uploaded by)
    - Implement search, pagination for rules
    - Implement file upload via `Phoenix.LiveView.Upload` for `.yar`/`.yara` files, supporting bulk upload
    - Implement `handle_event("upload", ...)` — calls `YaraRules.upload_rules/2`, displays validation errors inline on failure
    - Implement `handle_event("toggle", ...)` — calls `YaraRules.toggle_rule/2`, displays affected pools
    - Implement `handle_event("delete", ...)` — calls `YaraRules.delete_rule/2` with confirmation
    - Show Upload/Toggle/Delete buttons only to users with `rules:manage` permission
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 7.1, 7.3, 7.4_

  - [ ] 14.2 Implement rulesets tab in `YaraRulesLive`
    - Rulesets tab: display rulesets with rule count and assigned pool info
    - Implement `handle_event("create_ruleset", ...)` — calls `YaraRules.create_ruleset/3`
    - Implement `handle_event("update_ruleset", ...)` — calls `YaraRules.update_ruleset/4`
    - Implement `handle_event("delete_ruleset", ...)` — calls `YaraRules.delete_ruleset/2`
    - Implement `handle_event("assign_pool", ...)` — pool selector dropdown, calls `YaraRules.assign_ruleset_to_pool/3`
    - Implement `handle_event("unassign_pool", ...)` — calls `YaraRules.unassign_ruleset_from_pool/2`
    - Handle PubSub messages to refresh rulesets in real-time
    - Show ruleset management actions only to users with `rules:manage` permission
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 4.6, 7.1, 7.3, 7.4_

- [ ] 15. Add routes and navigation integration
  - [ ] 15.1 Add new routes to `ConfigManagerWeb.Router`
    - Add `live "/rules/zeek-packages", RulesLive.ZeekPackagesLive, :index` to the browser scope
    - Add `live "/rules/yara", RulesLive.YaraRulesLive, :index` to the browser scope
    - Both routes require `sensors:view` permission (write actions check `rules:manage` in handle_event)
    - _Requirements: 1.1, 3.1, 7.1, 7.3_

  - [ ] 15.2 Update navigation to include Zeek Packages and YARA Rules sub-links
    - Add "Zeek Packages" (`/rules/zeek-packages`) and "YARA Rules" (`/rules/yara`) sub-links to the existing "Rules" navigation section
    - Ensure navigation highlights the active sub-link
    - _Requirements: 9.1_

- [ ] 16. Integrate detection content into pool detail and deployment pages
  - [ ] 16.1 Update pool detail page with detection content summary
    - Display detection content summary section: Suricata ruleset name/version, Zeek packages installed/enabled count, YARA ruleset name/version, unified `detection_content_version`
    - Add "Validate Content" button that calls `ContentValidation.validate_pool/1` and displays results inline
    - Display drift indicator when any member sensor's `last_deployed_detection_content_version` differs from pool's `detection_content_version`
    - Display currently assigned YARA ruleset alongside Suricata ruleset assignment
    - _Requirements: 4.4, 5.2, 5.3, 6.7, 9.2_

  - [ ] 16.2 Update deployment integration for detection content version
    - Ensure deployment snapshot builder includes `detection_content_version`, enabled Zeek packages, and assigned YARA ruleset info
    - Ensure deployment orchestrator's `validating` phase calls `ContentValidation.validate_pool/1`; transition to `failed` on validation failure with error details
    - Ensure successful `Deployment_Result` updates `sensor_pods.last_deployed_detection_content_version`
    - Display `detection_content_version` on deployment detail page
    - _Requirements: 5.5, 5.6, 6.1, 6.5, 9.3_

- [ ] 17. Implement audit logging for all detection content actions
  - [ ] 17.1 Wire audit entries for all 10 action types
    - Verify all context module mutations write audit entries via `Ecto.Multi` with `Audit.append_multi/2`
    - Verify each audit entry contains: actor, actor_type, action, target_type, target_id, result, and JSON detail field with action-specific context per the design's audit entry patterns table
    - Verify audit entries for: `zeek_package_installed`, `zeek_package_toggled`, `zeek_package_uninstalled`, `yara_rule_uploaded`, `yara_rule_toggled`, `yara_rule_deleted`, `yara_ruleset_assigned_to_pool`, `yara_ruleset_unassigned_from_pool`, `content_validation_passed`, `content_validation_failed`
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ]* 17.2 Write property test for audit completeness (Property 10)
    - **Property 10: Audit entries are complete and transactional** — generate random detection content mutations, verify each successful mutation has exactly one audit entry with correct action name and non-nil required fields; verify rolled-back transactions produce no audit entry
    - **Validates: Requirements 8.1, 8.2, 8.3**

- [ ] 18. Final checkpoint — Full test suite and compilation verification
  - Run `mix compile --warnings-as-errors` and `mix test` to verify everything compiles and all tests pass. Ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after major milestones
- Property tests validate the 11 correctness properties defined in the design document using PropCheck
- Unit tests validate specific examples, edge cases, and integration points
- All mutations use `Ecto.Multi` with transactional audit writes per the project's established pattern
- Tags fields use JSON-encoded text strings for SQLite compatibility
- No new Elixir dependencies are required — PropCheck is already in the project
