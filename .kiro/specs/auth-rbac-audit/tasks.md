# Implementation Plan: Authentication, RBAC, and Audit Log

## Overview

This plan implements local authentication, role-based access control, scoped API tokens, and audit logging for the RavenWire Config Manager. Tasks are ordered to build foundational layers first (dependencies, schemas, migrations), then core auth logic, then RBAC enforcement, then API tokens, then audit log features, and finally integration wiring. Each task builds incrementally on previous work.

## Tasks

- [ ] 1. Add dependency and set up project structure
  - [x] 1.1 Add `argon2_elixir` dependency and configure test environment
    - Add `{:argon2_elixir, "~> 4.1"}` to `mix.exs` deps
    - Configure Argon2id defaults in `config/config.exs`
    - Add low-cost Argon2id parameters to `config/test.exs` for fast test hashing
    - Run `mix deps.get` to fetch the new dependency
    - _Requirements: 1.3_

  - [ ] 1.2 Create directory structure for auth modules
    - Create `lib/config_manager/auth/` directory with empty module files
    - Create `lib/config_manager_web/plugs/` directory
    - Create `lib/config_manager_web/live/auth_live/` directory
    - Create `lib/config_manager_web/live/admin_live/` directory
    - Create `lib/config_manager_web/live/audit_live/` directory
    - Create `lib/config_manager_web/controllers/api/` directory
    - _Requirements: 13.1, 13.2_
    - Status: partially complete for the MVP auth modules and plugs; planned LiveView admin/auth/API directories still need to be added when those pages/controllers are implemented.

- [ ] 2. Create database migrations and Ecto schemas
  - [x] 2.1 Create migration for `users` table
    - Create migration with fields: id (binary_id), username (unique), password_hash, display_name, role (default "viewer"), active (default true), must_change_password (default false), timestamps
    - Add unique index on username and index on role
    - _Requirements: 1.1, 1.2, 13.1_

  - [x] 2.2 Create migration for `sessions` table
    - Create migration with fields: id (binary_id), user_id (references users, on_delete cascade), token_hash, last_active_at, expires_at, inserted_at
    - Add indexes on user_id, token_hash, and expires_at
    - _Requirements: 3.2, 11.3_

  - [x] 2.3 Create migration for `api_tokens` table
    - Create migration with fields: id (binary_id), name, token_hash (unique), user_id (references users, on_delete cascade), permissions (text/JSON array), expires_at (nullable), revoked_at (nullable), timestamps
    - Add unique index on token_hash and index on user_id
    - _Requirements: 6.2, 6.3_

  - [x] 2.4 Create compatibility migration for existing `audit_log` table
    - Verify existing audit_log table schema and add any missing columns (actor_type, target_type, target_id) or indexes
    - Ensure `detail` column stores JSON text and `timestamp` supports microsecond precision
    - _Requirements: 7.2, 7.3_

  - [ ] 2.5 Implement Ecto schemas for User, Session, ApiToken, and AuditEntry
    - Create `ConfigManager.Auth.User` schema with virtual `:password` field (redacted), changesets for create/update/password
    - Create `ConfigManager.Auth.Session` schema with belongs_to user
    - Create `ConfigManager.Auth.ApiToken` schema with belongs_to user, permissions as `{:array, :string}`
    - Create `ConfigManager.Auth.AuditEntry` schema mapping to `audit_log` table with JSON detail field
    - _Requirements: 1.1, 7.2, 6.3, 11.3_
    - Status: MVP schemas exist for User, Session, ApiToken, and AuditEntry; this remains open because ApiToken permissions are currently stored as JSON text/string and AuditEntry is `ConfigManager.AuditEntry`, not `ConfigManager.Auth.AuditEntry`.

  - [ ]* 2.6 Write migration and schema verification tests
    - Assert all tables, columns, indexes, and constraints exist after migration
    - Assert schema changesets enforce required fields and constraints
    - _Requirements: 12.1_

- [ ] 3. Implement Policy module and password utilities
  - [x] 3.1 Implement `ConfigManager.Auth.Policy` module
    - Define `@roles_permissions` map with all six roles and their exact permission sets as specified in design
    - Define `@canonical_permissions` containing every permission identifier introduced by downstream specs
    - Implement `has_permission?/2`, `permissions_for/1`, `canonical_permissions/0`, `roles/0`, `role_display_name/1`, `permission_display_name/1`
    - Treat `alerts:view` as a UI label alias for `sensors:view`, never as a stored permission
    - Use `platform-admin` mapping to `:all` for full access
    - Ensure role identifiers are exact strings: `viewer`, `analyst`, `sensor-operator`, `rule-manager`, `platform-admin`, `auditor`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 13.1, 13.2_

  - [ ]* 3.2 Write property test for role-permission mapping (Property 5)
    - **Property 5: Role-permission mapping is complete and correct**
    - Verify each role returns exactly the specified permission set
    - Verify hierarchical roles are strict supersets (viewer ⊂ analyst ⊂ sensor-operator ⊂ rule-manager)
    - Verify auditor has no write, admin, system management, or PCAP retrieval permissions
    - Verify every API token scope option is present in `canonical_permissions/0`
    - **Validates: Requirements 4.1, 4.2, 13.1**

  - [x] 3.3 Implement `ConfigManager.Auth.Password` module
    - Implement `hash_password/1` using Argon2id
    - Implement `verify_password/2` for constant-time comparison
    - Implement `validate_password/2` enforcing: minimum 12 characters, not matching username
    - Implement `generate_random_password/0` producing 24-character random string
    - _Requirements: 1.3, 10.1, 10.2_

  - [ ]* 3.4 Write property test for password validation (Property 14)
    - **Property 14: Password validation enforces security policy**
    - Generate random strings < 12 chars → all rejected
    - Generate (username, password) where password == username → rejected
    - Generate valid passwords (≥ 12 chars, != username) → accepted
    - **Validates: Requirements 10.1, 10.2**

  - [ ]* 3.5 Write property test for password hashing (Property 1)
    - **Property 1: Password hashing preserves no plaintext**
    - For random valid passwords, verify stored hash is valid Argon2id
    - Verify plaintext does not appear in the hash string
    - **Validates: Requirements 1.3**

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement Auth context and session management
  - [ ] 5.1 Implement `ConfigManager.Auth` context module — user CRUD operations
    - Implement `create_user/2`, `update_user/3`, `disable_user/2`, `enable_user/2`, `delete_user/2`
    - `disable_user` must invalidate all sessions and reject all API tokens for that user
    - `delete_user` must revoke all API tokens and invalidate all sessions (cascade handles DB cleanup)
    - Implement `get_user!/1`, `get_user_by_username/1`, `list_users/0`
    - Implement `change_password/4` (requires current password verification) and `admin_reset_password/3`
    - All mutating operations record audit entries via `Audit.append_multi/2`
    - _Requirements: 1.1–1.9, 7.1_
    - Status: basic create/update/list/get/authenticate helpers are implemented; disable/enable/delete/password-change/token invalidation and transactional audit writes remain.

  - [ ]* 5.2 Write property test for user deactivation (Property 2)
    - **Property 2: User deactivation invalidates all credentials**
    - Create user with random number of sessions (0–10) and tokens (0–5)
    - Disable user → verify all sessions invalid, all tokens rejected
    - Delete user → verify same plus records removed
    - **Validates: Requirements 1.4, 1.5, 1.8, 6.8**

  - [ ] 5.3 Implement session management in `ConfigManager.Auth`
    - Implement `authenticate/3` — verify credentials, check rate limits, create session, set cookie attributes
    - Implement `validate_session/1` — look up by token_hash, check inactivity timeout (30 min default, configurable via `RAVENWIRE_SESSION_TIMEOUT_MIN`), check absolute lifetime (24 hr default, configurable via `RAVENWIRE_SESSION_MAX_LIFETIME_HR`), touch `last_active_at`
    - Implement `destroy_session/1`, `invalidate_user_sessions/1`
    - Implement `prune_expired_sessions/0` for periodic and opportunistic cleanup
    - Session token is regenerated on successful authentication (prevent fixation)
    - _Requirements: 3.1–3.9, 11.1–11.4_
    - Status: server-side session create/validate/destroy/invalidate/prune is implemented; rate-limit-aware `authenticate/3`, IP handling, and full periodic cleanup wiring remain.

  - [ ]* 5.4 Write property test for authentication error indistinguishability (Property 3)
    - **Property 3: Authentication error messages are indistinguishable**
    - Generate login attempts with various failure reasons (bad username, bad password, disabled, rate-limited)
    - Verify all produce identical user-facing message "Invalid username or password"
    - Verify specific reason only appears in audit detail field
    - **Validates: Requirements 3.3, 3.8, 10.7**

- [ ] 6. Implement rate limiter
  - [ ] 6.1 Implement `ConfigManager.Auth.RateLimiter` GenServer
    - Create ETS table for per-username counters (max 5 failures in 15 minutes)
    - Create ETS table for per-IP counters (configurable threshold)
    - Implement `check_username/1`, `record_failure/1`, `check_ip/1`, `record_ip_failure/1`
    - Implement periodic `prune_expired/0` via `Process.send_after`
    - Fail closed: if ETS is unavailable, reject the attempt with generic message
    - _Requirements: 10.4, 10.5, 10.6_

  - [ ]* 6.2 Write property test for rate limiting (Property 15)
    - **Property 15: Rate limiting enforces attempt thresholds**
    - For random usernames, after exactly 5 failures the 6th is rejected
    - For random IPs, after exceeding threshold further attempts are throttled
    - Each rate-limit rejection produces an audit entry
    - **Validates: Requirements 10.4, 10.5, 10.6**

- [ ] 7. Implement Audit context
  - [ ] 7.1 Implement `ConfigManager.Audit` context module
    - Implement `log/1` for standalone audit writes (login attempts, permission denials)
    - Implement `append_multi/2` for transactional audit writes (user CRUD, token operations, config changes)
    - Implement `list_entries/2` with filtering (date range, actor, action, target_type, target_id, result) and pagination (default 50)
    - Implement `count_entries/1` for pagination metadata
    - Implement `export_entries/2` supporting CSV and JSON formats with 100K record limit
    - Ensure entries are always returned in reverse chronological order
    - _Requirements: 7.1–7.5, 8.1–8.5, 9.1–9.5_
    - Status: append-only `log/1` and reverse-chronological paged `list_entries/1` exist; `append_multi/2`, filters, count metadata, CSV/JSON export, and export limits remain.

  - [ ]* 7.2 Write property test for audit entry structure (Property 11)
    - **Property 11: Audit entries are structurally complete**
    - Generate random audit params covering all action types
    - Verify each written entry has: non-nil UUID id, microsecond UTC timestamp, non-empty actor, valid actor_type, non-empty action, valid result, valid JSON detail
    - **Validates: Requirements 7.2**

  - [ ]* 7.3 Write property test for audit query ordering and pagination (Property 12)
    - **Property 12: Audit log queries return entries in reverse chronological order with correct pagination**
    - Insert random sets of 10–200 entries, query with random page sizes
    - Verify descending timestamp order, correct page count, no duplicates across pages
    - **Validates: Requirements 8.2, 8.4**

  - [ ]* 7.4 Write property test for audit filter correctness (Property 13)
    - **Property 13: Audit log filters return only matching entries**
    - Insert random entries, apply random filter combinations
    - Verify every returned entry matches ALL filters, no matching entry excluded
    - **Validates: Requirements 8.3, 9.2**

- [ ] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement authentication plugs and LiveView hooks
  - [x] 9.1 Implement `ConfigManagerWeb.Plugs.RequireAuth` plug
    - Read session_id from conn session, validate via `Auth.validate_session/1`
    - If valid: assign `:current_user` to conn
    - If invalid/expired: redirect to `/login` with appropriate flash message
    - Touch session `last_active_at` on each valid request
    - _Requirements: 3.7, 3.5, 11.2_

  - [ ]* 9.2 Write property test for unauthenticated redirect (Property 4)
    - **Property 4: Unauthenticated requests redirect to login**
    - For all protected route paths, request without valid session → redirect to `/login`
    - Verify no protected page content leaks in response
    - **Validates: Requirements 3.7**

  - [x] 9.3 Implement `ConfigManagerWeb.Plugs.RequirePermission` plug
    - Read required permission from plug init arg or `conn.private.required_permission`
    - Get current_user or current_token from conn.assigns
    - Check `Policy.has_permission?/2`
    - If denied: render 403 page, record audit entry with `permission_denied`
    - _Requirements: 5.1, 5.7_

  - [ ] 9.4 Implement `ConfigManagerWeb.Plugs.ApiTokenAuth` plug
    - Extract `Authorization: Bearer <token>` header
    - SHA-256 hash the token, look up in api_tokens table
    - Validate: not expired, not revoked, creating user active
    - Assign `:current_token` with scoped permissions
    - If invalid: return 401 Unauthorized JSON response
    - _Requirements: 6.4, 6.5, 6.6, 6.8_

  - [ ] 9.5 Implement `ConfigManagerWeb.Plugs.RequirePasswordChange` plug
    - If `current_user.must_change_password == true` and path is not `/password/change` or `/logout`: redirect to `/password/change`
    - _Requirements: 10.3_

  - [ ]* 9.6 Write property test for forced password change blocking (Property 16)
    - **Property 16: Forced password change blocks all other routes**
    - For user with `must_change_password = true`, all routes except `/password/change` and `/logout` redirect
    - After password change, `must_change_password` is false and routes are accessible
    - **Validates: Requirements 10.3**

  - [x] 9.7 Implement `ConfigManagerWeb.AuthHelpers` for LiveView
    - Implement `on_mount(:require_auth, ...)` — load user from session, assign to socket or redirect
    - Implement `on_mount({:require_permission, permission}, ...)` — check permission or redirect to 403
    - Implement `authorize/2` helper for `handle_event` callbacks — returns `:ok` or `{:error, :forbidden}`
    - _Requirements: 5.4, 5.1_

- [ ] 10. Implement initial admin seeder
  - [x] 10.1 Implement `ConfigManager.Auth.AdminSeeder`
    - If any User exists: do nothing
    - Read username from `RAVENWIRE_ADMIN_USER` env var (default: `RavenWire`)
    - Read password from `RAVENWIRE_ADMIN_PASSWORD` env var
    - If env password set: validate ≥ 12 chars (refuse to start if shorter), create admin with `must_change_password = false`
    - If env password not set: generate random 24-char password, create admin with `must_change_password = true`, print `RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD=<password>` to stdout exactly once
    - Never write plaintext password to audit log or database
    - Wire into application startup (after migrations)
    - _Requirements: 2.1–2.5_

  - [ ]* 10.2 Write unit tests for AdminSeeder
    - Test seeding with env var set (valid and too-short password)
    - Test seeding with no env var (random password generated, printed once)
    - Test no-op when users already exist
    - _Requirements: 2.1–2.5, 12.1_

- [ ] 11. Implement router restructuring and session controller
  - [ ] 11.1 Restructure the Phoenix router
    - Add unauthenticated scope for `/login`
    - Add authenticated scope with `require_auth`, `require_password_change_check`, and `require_permission` plugs
    - Add `live_session :authenticated` with `on_mount` hook for existing and planned operational pages from Requirement 5.2
    - Add admin scope with `live_session :admin` for `/admin/users`, `/admin/roles`, `/admin/api-tokens`, `/admin/bundles`, and `/admin/ha` with `required_permission` metadata
    - Add audit export scope for `/audit/export` with `audit:export` permission
    - Add session management routes: `POST /login`, `DELETE /logout`
    - Add Public API scope under `/api/v1` with `api_token_auth` and `require_permission` plugs for all API routes with correct permission metadata
    - Preserve existing mTLS routes unchanged
    - _Requirements: 5.2, 5.5, 5.6, 6.10, 6.11, 3.7_
    - Status: current browser routes are split into unauthenticated/authenticated scopes with permission plugs, and mTLS routes are preserved. Admin scopes, audit export, password-change route, and token-authenticated public API scopes remain.

  - [x] 11.2 Implement `ConfigManagerWeb.SessionController`
    - `create` action: authenticate credentials, create session, set secure cookie (Secure, HttpOnly, SameSite=Strict), redirect to dashboard
    - `delete` action: destroy session, clear cookie, redirect to `/login`
    - Record audit entries for login success, login failure, and logout
    - _Requirements: 3.1, 3.2, 3.6, 7.1, 11.1_

  - [ ]* 11.3 Write property test for RBAC enforcement consistency (Property 6)
    - **Property 6: RBAC enforcement is consistent across all access paths**
    - For all (role, route) pairs, access granted iff `Policy.has_permission?` returns true
    - Verify consistency across browser, LiveView, and API paths
    - Verify all authenticated users can access `/` and `/audit`
    - **Validates: Requirements 5.1, 5.2, 5.4, 5.5, 6.7, 6.10**

  - [ ]* 11.4 Write property test for permission denial audit (Property 7)
    - **Property 7: Permission denial always produces an audit entry**
    - For random (role, route) pairs where role lacks permission
    - Verify audit entry created with action `permission_denied`, result `failure`, detail contains required permission and route/event
    - **Validates: Requirements 5.7, 6.11, 7.5**

- [ ] 12. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Implement API token management
  - [ ] 13.1 Implement API token operations in `ConfigManager.Auth`
    - `create_api_token/2`: generate 32+ byte random token, store SHA-256 hash, return raw token once
    - `revoke_api_token/2`: set `revoked_at` timestamp, record audit entry
    - `authenticate_api_token/1`: hash provided token, look up, validate (not expired, not revoked, user active)
    - `list_api_tokens/0`: return tokens without hash or raw values
    - All operations record audit entries via `Audit.append_multi/2`
    - _Requirements: 6.1–6.9_

  - [ ]* 13.2 Write property test for API token storage security (Property 8)
    - **Property 8: API token storage never leaks secrets**
    - Create tokens, inspect DB records and API responses
    - Verify only SHA-256 hash stored, raw token never in list/show responses
    - **Validates: Requirements 6.2, 6.9**

  - [ ]* 13.3 Write property test for API token authentication round-trip (Property 9)
    - **Property 9: API token authentication round-trip**
    - Create token, authenticate with raw value → success
    - Authenticate with any other value → failure
    - **Validates: Requirements 6.4**

  - [ ]* 13.4 Write property test for expired/revoked token rejection (Property 10)
    - **Property 10: Expired and revoked tokens are rejected**
    - Tokens with past expiry → 401
    - Tokens with non-null revoked_at → 401
    - Checks performed on every attempt, not cached
    - **Validates: Requirements 6.5, 6.6**

- [ ] 14. Implement LiveView pages — Authentication
  - [ ] 14.1 Implement `LoginLive` at `/login`
    - Render login form with username and password fields
    - On submit: call `Auth.authenticate/3`, handle success (redirect to dashboard) and failure (generic error message)
    - Display session expired message when redirected from expired session
    - Do not reveal whether username or password was incorrect
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.8_
    - Status: implemented as `SessionController` HTML, not LiveView.

  - [ ] 14.2 Implement `PasswordChangeLive` at `/password/change`
    - For self-service: require current password before accepting new password
    - Validate new password against policy (≥ 12 chars, not matching username)
    - On success: clear `must_change_password` flag, redirect to dashboard
    - Record audit entry for password change
    - _Requirements: 1.7, 10.1, 10.2, 10.3_

- [ ] 15. Implement LiveView pages — Admin
  - [ ] 15.1 Implement `AdminLive.UsersLive` at `/admin/users`
    - List all users with username, display name, role, active status
    - Create user form: username, display name, password, role selection
    - Edit user: change display name, role, active status
    - Disable/enable user actions with immediate session invalidation
    - Delete user action with confirmation
    - Admin password reset action (generates temp password or requires new entry, marks must_change_password)
    - All actions record audit entries
    - _Requirements: 1.1–1.9, 4.5_

  - [ ] 15.2 Implement `AdminLive.RolesLive` at `/admin/roles`
    - Display each role with its associated permissions in a reference table
    - Read-only page showing role-permission mapping from Policy module
    - _Requirements: 4.4_

  - [ ] 15.3 Implement `AdminLive.ApiTokensLive` at `/admin/api-tokens`
    - List existing tokens (name, creating user, permissions, expiry, status) without showing hashes
    - Create token form: name, permission selection (checkboxes), optional expiry
    - Display raw token exactly once after creation with copy-to-clipboard
    - Revoke token action with confirmation
    - All actions record audit entries
    - _Requirements: 6.1–6.3, 6.6, 6.9_

- [ ] 16. Implement LiveView pages — Audit Log
  - [ ] 16.1 Implement `AuditLive.AuditLogLive` at `/audit`
    - Display entries in reverse chronological order: timestamp, actor, action, target, result
    - Filter controls: date range, actor, action type, target type, target identifier, result
    - Pagination with default page size of 50
    - Expandable detail panel showing full JSON on row click
    - Accessible to all authenticated users
    - _Requirements: 8.1–8.5, 5.5_
    - Status: basic `/audit` LiveView exists with reverse-chronological entries and human-readable user labels; filters, visible pagination controls, and expandable detail remain.

  - [ ] 16.2 Implement `AuditLive.AuditExportLive` at `/audit/export`
    - Same filter controls as audit log view
    - Format selection: CSV or JSON
    - Export button triggers download
    - Reject exports exceeding 100,000 records with instructive message
    - Record audit entry for each export with filters and format
    - Accessible only to platform-admin and auditor roles
    - _Requirements: 9.1–9.5_

- [ ] 17. Implement API controllers
  - [ ] 17.1 Implement JSON API controllers for all protected endpoints
    - Place all Public API controllers under `/api/v1`; do not add new unversioned `/api/...` public routes
    - `EnrollmentApiController`: approve/deny actions with `enrollment:manage` permission
    - `PcapApiController`: config update with `pcap:configure`, carve/search/detail/manifest with `pcap:search`, download with `pcap:download`
    - `RulesApiController`, `RulesetsApiController`, and repository APIs: read with `sensors:view`, write with `rules:manage`, deploy with `rules:deploy`
    - `DeploymentsApiController`: read with `sensors:view`, create/cancel/rollback with `deployments:manage`
    - `BundleApiController`: create action with `bundle:download` permission
    - `AuditApiController`: list with `audit:view`, export with `audit:export`
    - `UsersApiController`: create action with `users:manage` permission
    - `TokensApiController`: create action with `tokens:manage` permission
    - All controllers record audit entries for their actions
    - Return proper JSON error responses (401, 403) for auth/permission failures
    - _Requirements: 6.10, 6.11, 6.12, 7.1_

- [ ] 18. Implement UI element visibility based on role
  - [ ] 18.1 Add permission-based UI element hiding across all LiveView pages
    - Hide action buttons, links, and form controls for actions the current user's role does not permit
    - Enrollment page: hide approve/deny buttons for users without `enrollment:manage`
    - PCAP config page: hide write controls for users without `pcap:configure`
    - Rules page: hide deploy button for users without `rules:deploy`
    - Support bundle page: hide download button for users without `bundle:download`
    - PCAP pages: hide download controls for users without `pcap:download`
    - Deployment pages: hide create/cancel/rollback/promote/abort controls for users without `deployments:manage`
    - Rule store and detection content pages: hide write controls for users without `rules:manage`
    - Pool forwarding and BPF pages: hide write controls for users without `forwarding:manage` or `bpf:manage`
    - Alert pages: hide acknowledge/resolve/configuration controls for users without `alerts:manage`
    - Navigation: hide admin links for non-platform-admin users
    - Server-side enforcement remains regardless of UI hiding
    - _Requirements: 5.3_

- [ ] 19. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 20. Wire existing LiveView pages into RBAC
  - [ ] 20.1 Add permission checks to existing LiveView `handle_event` callbacks
    - `EnrollmentLive`: check `enrollment:manage` before approve/deny events
    - `PcapConfigLive`: check `pcap:configure` before save/update events
    - `RuleDeploymentLive`: check `rules:deploy` before deploy events
    - `SupportBundleLive`: check `bundle:download` before download events
    - Use `AuthHelpers.authorize/2` in each handler, return error flash if denied
    - Record audit entries for permission denials and successful actions
    - _Requirements: 5.4, 5.7, 7.1_

  - [ ] 20.2 Add audit logging to existing state-changing operations
    - Record `enrollment_approved` / `enrollment_denied` audit entries
    - Record `pcap_config_changed` audit entries
    - Record `rule_deployed` audit entries
    - Record `support_bundle_downloaded` audit entries
    - Use `Audit.append_multi/2` for transactional writes where applicable
    - _Requirements: 7.1_

- [ ] 21. Integration tests
  - [ ]* 21.1 Write route protection integration tests
    - Test every protected browser route redirects unauthenticated users
    - Test every protected browser route allows authenticated users with correct permissions
    - Test every protected browser route returns 403 for users without required permission
    - Test all API routes return 401 without token and 403 without required scope
    - _Requirements: 12.2, 12.3_
    - Status: basic browser auth redirect, allowed login, forbidden role, and audit display tests exist; full route/API matrix coverage remains.

  - [ ]* 21.2 Write audit coverage integration tests
    - Test each audited action category produces correct audit entry for both success and failure paths
    - Verify audit entries contain all required fields with correct values
    - _Requirements: 12.4_

  - [ ]* 21.3 Write security-specific integration tests
    - Test API token plaintext and hashes never returned after creation
    - Test disabled users cannot log in
    - Test API tokens created by disabled users are rejected
    - Test CSRF protection on browser write actions
    - Test session cookie attributes (Secure, HttpOnly, SameSite=Strict)
    - Test session ID regeneration on login (fixation prevention)
    - _Requirements: 12.5, 12.6, 12.7, 11.1, 11.2, 11.5_

- [ ] 22. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The only new dependency is `argon2_elixir ~> 4.1`; PropCheck is already available
- Existing mTLS routes for sensor agents remain unchanged throughout
- All audit writes for security-sensitive mutations use `Audit.append_multi/2` (fail-closed transactional pattern)
