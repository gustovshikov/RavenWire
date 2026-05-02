# Implementation Plan: Rule Store Management

## Overview

This plan implements the full Suricata Rule Store for the RavenWire Config Manager. The implementation builds incrementally: first the Suricata rule parser module, then the database schemas and migration, then the Rules context module with CRUD and repository management, then the ruleset composition and compilation logic, then the LiveView pages, and finally the navigation wiring and integration tests. Each step produces testable, integrated code.

## Tasks

- [ ] 1. Implement Suricata rule parser module
  - [ ] 1.1 Create `lib/config_manager/rules/parser.ex` with rule parsing functions
    - Implement `parse_rule/1` — takes a single rule line string, extracts SID, message, revision, classtype via regex, returns `{:ok, map}` or `{:error, reason}`
    - Implement `extract_sid/1` — regex for `sid:\s*(\d+)\s*;` pattern
    - Implement `extract_message/1` — regex for `msg:\s*"([^"]+)"\s*;` pattern
    - Implement `extract_revision/1` — regex for `rev:\s*(\d+)\s*;` pattern, default 1
    - Implement `extract_classtype/1` — regex for `classtype:\s*([^;]+)\s*;` pattern
    - Implement `category_from_filename/1` — strips path prefix and `.rules` extension
    - Implement `parse_files/1` — takes `[{filename, content}]`, parses each line, skips comments and blank lines, returns `{:ok, [rule_data]}`
    - Implement `format_rule/1` — reconstructs a rule line from parsed data (for round-trip testing)
    - Handle edge cases: commented-out rules (lines starting with `#`), disabled rules (lines starting with `# alert` or `#alert`), multi-line rules (backslash continuation)
    - _Requirements: 5.1, 5.2, 5.4_

  - [ ]* 1.2 Write property tests for Suricata rule parser (PropCheck)
    - **Property 1: Suricata rule parsing round-trip**
    - Create `test/config_manager/rules/parser_prop_test.exs`
    - Generate random valid Suricata rule lines with random SIDs (1..999999), messages, revisions, classtypes
    - Verify parse_rule/1 extracts correct SID for all generated rules
    - Verify format_rule/1 then parse_rule/1 produces equivalent SID and message
    - Verify category_from_filename strips path and extension correctly for random filenames
    - Verify parse_files/1 skips comment lines and blank lines
    - **Validates: Requirements 5.1, 5.2**

  - [ ]* 1.3 Write unit tests for parser with known Suricata rules
    - Create `test/config_manager/rules/parser_test.exs`
    - Test with real ET Open rule examples (emerging-malware, emerging-exploit categories)
    - Test SID extraction edge cases: SID at end of options, SID with spaces
    - Test message extraction with special characters and escaped quotes
    - Test revision extraction with missing rev (default to 1)
    - Test classtype extraction with missing classtype (nil)
    - Test category_from_filename with paths like `rules/emerging-malware.rules`
    - Test parse_files with mixed valid/invalid/comment lines
    - Test format_rule produces valid Suricata syntax
    - _Requirements: 5.1, 5.2, 5.4_

- [ ] 2. Implement database schemas and migration
  - [ ] 2.1 Create migration for all rule store tables
    - Create migration file `priv/repo/migrations/YYYYMMDDHHMMSS_create_rule_store_tables.exs`
    - Create `suricata_rules` table with: id (binary_id PK), sid (integer, unique), message (text), raw_text (text, not null), category (string, not null), classtype (string), severity (integer, default 2), revision (integer, default 1), enabled (boolean, default true), repository_id (binary_id), repository_name (string), timestamps
    - Create `rule_repositories` table with: id (binary_id PK), name (string, not null, case-insensitive unique), url (text, not null), repo_type (string, default "custom"), last_updated_at (utc_datetime), last_update_status (string, default "never_updated"), last_update_error (text), rule_count (integer, default 0), timestamps
    - Create `rulesets` table with: id (binary_id PK), name (string, not null, case-insensitive unique), description (text), version (integer, default 1), categories (text, default "[]"), updated_by (string), timestamps
    - Create `ruleset_rules` table with: id (binary_id PK), ruleset_id (references rulesets, on_delete: delete_all), sid (integer, not null), action (string, not null), timestamps; unique index on [ruleset_id, sid]
    - Create `pool_ruleset_assignments` table with: id (binary_id PK), pool_id (references sensor_pools, on_delete: delete_all), ruleset_id (references rulesets, on_delete: delete_all), assigned_by (string, not null), deployed_rule_version (integer), timestamps; unique index on pool_id
    - Add all indexes from design document
    - _Requirements: 6.1, 6.4, 7.1, 7.2_

  - [ ] 2.2 Create migration to add `last_deployed_rule_version` to `sensor_pods`
    - Create migration file `priv/repo/migrations/YYYYMMDDHHMMSS_add_rule_version_to_sensor_pods.exs`
    - Add `last_deployed_rule_version` integer column (nullable) to `sensor_pods`
    - _Requirements: 9.1, 9.2_

  - [ ] 2.3 Create Ecto schemas for all rule store tables
    - Create `lib/config_manager/rules/suricata_rule.ex` with changeset and toggle_changeset
    - Create `lib/config_manager/rules/rule_repository.ex` with changeset and update_status_changeset
    - Create `lib/config_manager/rules/ruleset.ex` with create_changeset and update_changeset (version increment logic)
    - Create `lib/config_manager/rules/ruleset_rule.ex` with changeset
    - Create `lib/config_manager/rules/pool_ruleset_assignment.ex` with changeset
    - Update `lib/config_manager/sensor_pod.ex` to add `last_deployed_rule_version` field
    - _Requirements: 2.1, 4.4, 6.4, 7.2_

  - [ ]* 2.4 Write schema validation tests
    - Create `test/config_manager/rules/schemas_test.exs`
    - Test SuricataRule changeset: valid attrs, missing sid, invalid severity, duplicate sid
    - Test RuleRepository changeset: valid attrs, invalid URL, duplicate name (case-insensitive)
    - Test Ruleset create_changeset: valid attrs, invalid name format, duplicate name
    - Test Ruleset update_changeset: version increment on category change, no increment on name-only change
    - Test RulesetRule changeset: valid include/exclude, invalid action, duplicate [ruleset_id, sid]
    - Test PoolRulesetAssignment changeset: valid attrs, duplicate pool_id
    - _Requirements: 2.1, 4.4, 6.4, 7.2_

- [ ] 3. Implement Rules context module — core CRUD
  - [ ] 3.1 Create `lib/config_manager/rules.ex` with rule CRUD and category operations
    - Implement `list_rules/1` with search (SID prefix, message substring), category filter, repo filter, sorting, pagination
    - Implement `get_rule/1`, `get_rule_by_sid/1`
    - Implement `toggle_rule/2` — flips enabled, writes audit entry in Ecto.Multi, broadcasts PubSub
    - Implement `bulk_toggle_rules/3` — bulk update enabled for list of IDs, writes summary audit entry
    - Implement `list_categories/0` — aggregates rules by category with enabled/disabled counts
    - Implement `toggle_category/3` — updates all rules in category, writes audit entry, broadcasts PubSub
    - All mutations use `Ecto.Multi` with `Audit.append_multi/2`
    - _Requirements: 1.1-1.8, 2.1-2.5, 3.1-3.6, 12.1-12.4_

  - [ ]* 3.2 Write property tests for rule toggle and category toggle (PropCheck)
    - **Property 3: Rule toggle is its own inverse**
    - **Property 4: Category toggle affects exactly the rules in that category**
    - Create `test/config_manager/rules/toggle_prop_test.exs`
    - Generate random rules, toggle, verify state flip; toggle again, verify original state
    - Generate random categories with rules, toggle category, verify all rules in category affected
    - Verify rules in other categories unchanged after category toggle
    - **Validates: Requirements 2.1, 2.2, 3.3, 3.4, 3.5**

  - [ ]* 3.3 Write unit tests for rule CRUD and category operations
    - Create `test/config_manager/rules/rules_context_test.exs`
    - Test list_rules with various search/filter combinations
    - Test list_rules pagination (page 1, page 2, out of range)
    - Test toggle_rule creates audit entry
    - Test bulk_toggle_rules with empty list, single rule, multiple rules
    - Test list_categories returns correct counts
    - Test toggle_category enables/disables all rules in category
    - Test toggle_category does not affect other categories
    - _Requirements: 1.1-1.8, 2.1-2.5, 3.1-3.6_

- [ ] 4. Implement repository management
  - [ ] 4.1 Create `lib/config_manager/rules/fetcher.ex` with HTTP fetch and archive extraction
    - Implement `fetch/1` — HTTP GET via Finch with 60s timeout, returns `{:ok, binary}` or `{:error, reason}`
    - Implement `extract/1` — uses `:erl_tar.extract/2` with `:compressed` and `:memory` options to extract `.rules` files from `.tar.gz`
    - Implement `fetch_and_parse/1` — pipeline: fetch → extract → Parser.parse_files
    - Handle errors: network timeout, non-200 status, invalid archive format, empty archive
    - _Requirements: 4.6, 5.6_

  - [ ] 4.2 Add repository CRUD and async update to Rules context
    - Implement `list_repositories/0`, `get_repository/1`
    - Implement `create_repository/2` — validates, creates, writes audit entry
    - Implement `delete_repository/2` — deletes repo record (preserves rules), writes audit entry
    - Implement `update_repository/2` — sets status to "updating", spawns async task under `ConfigManager.Rules.TaskSupervisor`
    - Implement `bulk_upsert_rules/3` — upserts by SID (insert new, update if rev >= stored, preserve enabled state), writes audit entry with counts
    - Add `ConfigManager.Rules.TaskSupervisor` to application supervision tree
    - Async task: calls `Fetcher.fetch_and_parse/1`, then `bulk_upsert_rules/3`, updates repo status, broadcasts PubSub
    - _Requirements: 4.1-4.10, 5.1-5.6, 12.1_

  - [ ]* 4.3 Write property tests for SID-based upsert (PropCheck)
    - **Property 2: SID-based upsert preserves enabled state and is idempotent**
    - **Property 11: Repository deletion preserves imported rules**
    - Create `test/config_manager/rules/upsert_prop_test.exs`
    - Generate random rules, insert, then upsert same SIDs with same/higher revision
    - Verify enabled state preserved after upsert
    - Verify upserting same data twice is idempotent (same DB state)
    - Verify rule count after upsert equals previous + new unique SIDs
    - Verify deleting repository preserves all imported rules
    - **Validates: Requirements 4.9, 5.3, 5.5**

  - [ ]* 4.4 Write unit tests for repository management
    - Create `test/config_manager/rules/repository_test.exs`
    - Test create_repository with valid/invalid attrs
    - Test create_repository with duplicate name (case-insensitive)
    - Test delete_repository preserves rules
    - Test bulk_upsert_rules: new rules inserted, existing rules updated when rev >= stored
    - Test bulk_upsert_rules: existing rules NOT updated when rev < stored
    - Test bulk_upsert_rules: enabled state preserved
    - Test audit entries created for all repository operations
    - _Requirements: 4.1-4.10, 5.1-5.6_

- [ ] 5. Checkpoint — Ensure all tests pass
  - Run `mix test` and verify all property and unit tests pass
  - Ask the user if questions arise

- [ ] 6. Implement ruleset management and compilation
  - [ ] 6.1 Add ruleset CRUD to Rules context
    - Implement `list_rulesets/0` — returns rulesets with effective rule counts and assigned pool counts
    - Implement `get_ruleset/1`, `get_ruleset!/1` — with preloaded overrides
    - Implement `create_ruleset/2` — validates name, creates with version 1, writes audit entry
    - Implement `update_ruleset/3` — validates, increments version on content change, writes audit entry
    - Implement `delete_ruleset/2` — deletes ruleset and cascade-deletes assignments, writes audit entry
    - Implement `effective_rules/1` — computes effective rule set per composition model
    - Implement `effective_rule_count/1`
    - _Requirements: 6.1-6.8_

  - [ ] 6.2 Add SID override management to Rules context
    - Implement adding/removing SID overrides (include/exclude) on a ruleset
    - Override changes increment ruleset version
    - Validate SID exists in rule store for includes
    - Write audit entries for override changes
    - _Requirements: 6.3, 6.5, 6.6_

  - [ ] 6.3 Create `lib/config_manager/rules/compiler.ex` with ruleset compilation
    - Implement `compile/1` — takes ruleset_id, computes effective rules, groups by category, produces `%{filename => content}` map
    - Each category produces a `<category>.rules` file with one rule per line
    - Explicit SID includes not in any included category go into `local-overrides.rules`
    - Explicit SID excludes are omitted from their category files
    - Disabled rules are omitted
    - Returns `{:ok, rule_map}` or `{:error, :empty_ruleset}`
    - _Requirements: 8.1_

  - [ ]* 6.4 Write property tests for ruleset composition and compilation (PropCheck)
    - **Property 5: Ruleset effective rule computation matches composition model**
    - **Property 6: Ruleset name uniqueness is case-insensitive**
    - **Property 7: Ruleset version increments only on content changes**
    - **Property 9: Ruleset compilation produces valid rule file map**
    - Create `test/config_manager/rules/ruleset_prop_test.exs`
    - Generate random rulesets with categories and overrides
    - Verify effective rules match composition model
    - Verify compilation produces valid file map with correct SID count
    - Verify no SID appears in more than one compiled file
    - Verify name uniqueness is case-insensitive
    - Verify version increment behavior
    - **Validates: Requirements 6.4, 6.5, 6.6, 8.1**

  - [ ]* 6.5 Write unit tests for ruleset management
    - Create `test/config_manager/rules/ruleset_test.exs`
    - Test create_ruleset with valid/invalid attrs
    - Test create_ruleset with duplicate name (case-insensitive)
    - Test update_ruleset increments version on category change
    - Test update_ruleset does NOT increment version on name-only change
    - Test delete_ruleset cascade-deletes assignments
    - Test effective_rules with categories only, with includes, with excludes, with mixed
    - Test effective_rule_count matches effective_rules length
    - Test compiler produces correct file map
    - Test compiler with empty ruleset returns error
    - Test audit entries for all ruleset operations
    - _Requirements: 6.1-6.8, 8.1_

- [ ] 7. Implement pool assignment and deployment
  - [ ] 7.1 Add pool assignment operations to Rules context
    - Implement `assign_ruleset_to_pool/3` — creates or replaces assignment, writes audit entry
    - Implement `unassign_ruleset_from_pool/2` — deletes assignment, writes audit entry
    - Implement `pool_assignment/1`, `pool_ruleset/1` — query helpers
    - Enforce one-ruleset-per-pool constraint via unique index on pool_id
    - _Requirements: 7.1-7.6_

  - [ ] 7.2 Add rule deployment to Rules context
    - Implement `deploy_ruleset_to_pool/3`:
      1. Load pool assignment, verify ruleset exists
      2. Compile ruleset via `Compiler.compile/1`
      3. Call `RuleDeployer.deploy_to_pool/3` with compiled rule map
      4. On per-sensor success: update `last_deployed_rule_version` on sensor_pod
      5. Update `deployed_rule_version` on pool_ruleset_assignment
      6. Write audit entry with per-sensor results
      7. Broadcast `{:rules_deployed, pool_id, version}` to `"rulesets"` topic
    - Implement `deployed_rule_version/1` — reads from pool_ruleset_assignment
    - Implement `list_rule_deployments/1`, `list_pool_rule_deployments/2` — query audit_log
    - _Requirements: 8.1-8.6, 9.1-9.4_

  - [ ] 7.3 Add out-of-sync detection to Rules context
    - Implement `out_of_sync_count/1` — counts sensors where last_deployed_rule_version != assigned ruleset version
    - Implement `sensor_sync_statuses/1` — returns per-sensor sync status list
    - Handle edge cases: no assignment (all sensors are "no ruleset assigned"), sensor never deployed (NULL version)
    - _Requirements: 10.1-10.5_

  - [ ]* 7.4 Write property tests for pool assignment and drift detection (PropCheck)
    - **Property 8: One ruleset per pool invariant**
    - **Property 10: Out-of-sync detection is correct**
    - Create `test/config_manager/rules/assignment_prop_test.exs`
    - Generate random pools and rulesets, assign/reassign, verify at most one assignment per pool
    - Generate random sensors with various deployed versions, verify out-of-sync classification
    - **Validates: Requirements 7.2, 10.1, 10.2, 10.3**

  - [ ]* 7.5 Write unit tests for pool assignment and deployment
    - Create `test/config_manager/rules/deployment_test.exs`
    - Test assign_ruleset_to_pool creates assignment
    - Test assign_ruleset_to_pool replaces existing assignment
    - Test unassign_ruleset_from_pool deletes assignment
    - Test deploy_ruleset_to_pool compiles and deploys (mock SensorAgentClient)
    - Test deploy_ruleset_to_pool updates last_deployed_rule_version on success
    - Test deploy_ruleset_to_pool with no assignment returns error
    - Test out_of_sync_count with mixed sync states
    - Test sensor_sync_statuses returns correct per-sensor status
    - Test audit entries for all assignment and deployment operations
    - _Requirements: 7.1-7.6, 8.1-8.6, 9.1-9.4, 10.1-10.5_

- [ ] 8. Checkpoint — Ensure all tests pass
  - Run `mix test` and verify all property and unit tests pass
  - Ask the user if questions arise

- [ ] 9. Implement Rule Store LiveView page
  - [ ] 9.1 Create `lib/config_manager_web/live/rules_live/store_live.ex` — Rule Store browse/search
    - Mount: check `sensors:view` permission, load paginated rules with default sort (SID asc), load categories and repositories for filter dropdowns, subscribe to `"rules"` PubSub topic
    - Render searchable, filterable, paginated rule table with columns: SID, message, category, source, revision, severity, enabled toggle
    - Implement `phx-change` on search input for real-time filtering
    - Implement category dropdown filter and repository dropdown filter
    - Implement column sort (SID, message, category, revision, severity)
    - Implement pagination controls
    - Implement enable/disable toggle per rule (check `rules:manage` in handle_event)
    - Implement bulk select (checkboxes) and bulk enable/disable action
    - Handle PubSub `{:rules_updated, _}` to refresh after repository imports
    - Empty state: "No rules found" when search returns nothing; "No rules in store" when store is empty
    - RBAC: hide toggle controls from users without `rules:manage`
    - _Requirements: 1.1-1.8, 2.1-2.5, 11.5_

  - [ ] 9.2 Create `lib/config_manager_web/live/rules_live/categories_live.ex` — Categories page
    - Mount: check `sensors:view` permission, load categories with counts
    - Render category table: name, total rules, enabled count, disabled count, toggle
    - Implement category toggle (check `rules:manage` in handle_event)
    - Subscribe to `"rules"` topic for updates after toggles
    - RBAC: hide toggle from users without `rules:manage`
    - _Requirements: 3.1-3.6, 11.5_

- [ ] 10. Implement Repository management LiveView
  - [ ] 10.1 Create `lib/config_manager_web/live/rules_live/repositories_live.ex` — Repositories page
    - Mount: check `sensors:view` permission, load repositories, subscribe to `"rule_repositories"` topic
    - Render repository table: name, URL, type, last updated, rule count, status
    - Implement "Add Repository" form (inline or modal) with name, URL, type fields (check `rules:manage`)
    - Implement "Update Now" button per repository (check `rules:manage`)
    - Show spinner/progress indicator during async update via PubSub
    - Implement "Delete" button with confirmation (check `rules:manage`)
    - Handle PubSub messages: updating, updated, update_failed
    - Display error message when update fails
    - RBAC: hide management actions from users without `rules:manage`
    - _Requirements: 4.1-4.10, 11.5_

- [ ] 11. Implement Ruleset management LiveViews
  - [ ] 11.1 Create `lib/config_manager_web/live/rules_live/rulesets_live.ex` — Rulesets list page
    - Mount: check `sensors:view` permission, load rulesets with effective counts and pool counts
    - Render ruleset table: name, description, version, effective rule count, assigned pools, last modified
    - "Create Ruleset" button (visible only with `rules:manage`)
    - Click row navigates to `/rules/rulesets/:id`
    - Subscribe to `"rulesets"` topic for updates
    - _Requirements: 6.1, 6.2, 6.8, 11.5_

  - [ ] 11.2 Create `lib/config_manager_web/live/rules_live/ruleset_detail_live.ex` — Ruleset detail/edit page
    - Mount: load ruleset with overrides, effective rule count, pool assignments, all pools list
    - For `:new` action: empty changeset, category selector, SID override inputs
    - For `:show` action: display ruleset info, categories, overrides, effective rule count, pool assignments
    - For `:edit` action: editable form with category multi-select, SID override management
    - Category selector: multi-select from all known categories with rule counts
    - SID override management: add include/exclude SIDs, remove overrides
    - Pool assignment section: list all pools with current assignment status, assign/unassign buttons
    - "Deploy Rules" button per assigned pool (check `rules:deploy` in handle_event)
    - "Delete Ruleset" button with confirmation (check `rules:manage`)
    - Events: save, delete, assign_pool, unassign_pool, deploy_to_pool, add_override, remove_override
    - RBAC: hide write actions from users without `rules:manage`; hide deploy from users without `rules:deploy`
    - _Requirements: 6.1-6.8, 7.1-7.6, 8.5, 8.6, 11.5_

  - [ ] 11.3 Create `lib/config_manager_web/live/rules_live/deployments_live.ex` — Rule Deployments history page
    - Mount: check `sensors:view` permission, load rule deployment audit entries
    - Render deployment history table: timestamp, operator, pool, ruleset, version, result summary
    - Paginate with 25 per page default
    - Highlight pools with out-of-sync sensors
    - Query audit_log for actions: `rules_deployed`, `adhoc_rules_deployed`
    - Empty state when no deployments exist
    - _Requirements: 9.4, 10.5_

- [ ] 12. Update existing pages and navigation
  - [ ] 12.1 Update router with rule store routes
    - Add all rule store LiveView routes inside authenticated live_session block:
      - `live "/rules/store", RulesLive.StoreLive, :index`
      - `live "/rules/categories", RulesLive.CategoriesLive, :index`
      - `live "/rules/repositories", RulesLive.RepositoriesLive, :index`
      - `live "/rules/rulesets", RulesLive.RulesetsLive, :index`
      - `live "/rules/rulesets/new", RulesLive.RulesetDetailLive, :new`
      - `live "/rules/rulesets/:id", RulesLive.RulesetDetailLive, :show`
      - `live "/rules/rulesets/:id/edit", RulesLive.RulesetDetailLive, :edit`
      - `live "/rules/deployments", RulesLive.DeploymentsLive, :index`
    - Preserve existing `live "/rules", RuleDeploymentLive, :index`
    - Set appropriate `required_permission` private metadata on each route
    - _Requirements: 13.1, 13.2_

  - [ ] 12.2 Update navigation to include Rules section with sub-links
    - Update navigation template/component to expand "Rules" into a section with sub-links:
      Rule Store, Categories, Repositories, Rulesets, Deployments, Quick Deploy
    - Show sub-links based on user permissions
    - _Requirements: 13.1, 13.2_

  - [ ] 12.3 Update existing rule deployment page (`RuleDeploymentLive`)
    - Add banner/link at top: "Looking for managed rulesets? Go to Rule Store →"
    - Update pool dropdown to show pool names instead of raw UUIDs (use `Pools.pool_name_map/0`)
    - Add audit entry with action `adhoc_rules_deployed` on successful deploy
    - Label page as "Quick Deploy" in navigation
    - _Requirements: 14.1-14.4_

  - [ ] 12.4 Update pool detail page to show assigned ruleset and sync status
    - Display assigned Ruleset name (linked to `/rules/rulesets/:id`) on pool detail page
    - Display sync status badge (in-sync / out-of-sync / no ruleset)
    - Display out-of-sync sensor count
    - Show "Deploy Rules" button when ruleset is assigned and user has `rules:deploy`
    - _Requirements: 9.1, 9.3, 10.3, 13.3_

  - [ ] 12.5 Update sensor detail page to show deployed rule version
    - Display `last_deployed_rule_version` in the sensor identity or detection section
    - Show "never deployed" when value is NULL
    - _Requirements: 9.2, 13.4_

  - [ ] 12.6 Add `ConfigManager.Rules.TaskSupervisor` to application supervision tree
    - Add `{Task.Supervisor, name: ConfigManager.Rules.TaskSupervisor}` to the application children list
    - _Requirements: 4.6_

- [ ] 13. Checkpoint — Ensure all tests pass
  - Run `mix test` and verify all tests pass
  - Ask the user if questions arise

- [ ] 14. Write integration tests
  - [ ]* 14.1 Write LiveView integration tests for Rule Store page
    - Create `test/config_manager_web/live/rules_live/store_live_test.exs`
    - Test page renders with rules sorted by SID
    - Test search filters rules by SID prefix and message substring
    - Test category and repository dropdown filters
    - Test pagination
    - Test enable/disable toggle creates audit entry
    - Test bulk toggle
    - Test RBAC: toggle hidden for users without `rules:manage`
    - Test empty state messages
    - **Validates: Requirements 1.1-1.8, 2.1-2.5, 11.5**

  - [ ]* 14.2 Write LiveView integration tests for Categories page
    - Create `test/config_manager_web/live/rules_live/categories_live_test.exs`
    - Test page renders categories with correct counts
    - Test category toggle updates all rules in category
    - Test RBAC: toggle hidden for users without `rules:manage`
    - **Validates: Requirements 3.1-3.6**

  - [ ]* 14.3 Write LiveView integration tests for Repositories page
    - Create `test/config_manager_web/live/rules_live/repositories_live_test.exs`
    - Test page renders repositories
    - Test add repository form validation
    - Test add repository with duplicate name rejected
    - Test delete repository preserves rules
    - Test RBAC: management actions hidden for users without `rules:manage`
    - **Validates: Requirements 4.1-4.10**

  - [ ]* 14.4 Write LiveView integration tests for Rulesets pages
    - Create `test/config_manager_web/live/rules_live/rulesets_live_test.exs`
    - Test rulesets list page renders with effective counts
    - Test create ruleset form validation
    - Test ruleset detail page shows categories, overrides, pool assignments
    - Test assign/unassign pool
    - Test deploy rules button triggers deployment
    - Test RBAC: write actions hidden for users without `rules:manage`
    - Test RBAC: deploy button hidden for users without `rules:deploy`
    - **Validates: Requirements 6.1-6.8, 7.1-7.6, 8.5, 8.6**

  - [ ]* 14.5 Write end-to-end integration test for full rule lifecycle
    - Create `test/config_manager/rules/integration_test.exs`
    - Test full lifecycle: add repository → update (mock HTTP) → browse rules → create ruleset → assign to pool → deploy (mock SensorAgentClient) → verify deployed version → verify sync status
    - Verify audit entries at each step
    - **Validates: Requirements 4.6, 5.1-5.6, 6.1-6.8, 7.1-7.6, 8.1-8.6, 9.1-9.4, 10.1-10.5, 12.1-12.4**

  - [ ]* 14.6 Write property test for audit entry completeness (PropCheck)
    - **Property 12: Every rule store mutation produces an audit entry**
    - Create `test/config_manager/rules/audit_prop_test.exs`
    - Generate random rule store mutations (toggle, category toggle, repo add/delete, ruleset create/update/delete, assign, deploy)
    - Verify each mutation produces at least one audit entry with correct action name and non-empty detail
    - **Validates: Requirements 12.1, 12.2, 12.3**

- [ ] 15. Final checkpoint — Ensure all tests pass
  - Run `mix test` and verify all property and unit tests pass
  - Ask the user if questions arise

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design uses Elixir/Phoenix LiveView — all code examples use Elixir
- PropCheck (~> 1.4) is already in mix.exs
- New dependencies: none required (`:erl_tar` is part of Erlang/OTP for archive extraction, Finch is already available for HTTP)
- New database tables: `suricata_rules`, `rule_repositories`, `rulesets`, `ruleset_rules`, `pool_ruleset_assignments` (one migration) + `last_deployed_rule_version` on `sensor_pods` (second migration)
- The existing `RuleDeployer` module and `SensorAgentClient.push_rule_bundle/3` are reused, not replaced
- YARA and Zeek package management are explicitly deferred to Phase D
- Scheduled repository polling is deferred — updates are manual-only via "Update Now"
- The existing paste-and-deploy page at `/rules` is preserved as "Quick Deploy"
