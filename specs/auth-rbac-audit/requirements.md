# Requirements Document: Authentication, RBAC, and Audit Log

## Introduction

The RavenWire Config Manager web UI currently exposes all browser routes (`/`, `/enrollment`, `/pcap-config`, `/rules`, `/support-bundle`) without any authentication pipeline, session enforcement, role check, or permission gate. Any user who can reach the network port can deploy rules, change PCAP configuration, approve sensor enrollments, and download support bundles.

This feature adds local authentication, role-based access control (RBAC) with six defined roles, scoped API tokens for automation, and a queryable audit log that records every security-relevant action. The scope is limited to local credential authentication and RBAC enforcement; OIDC/SAML federation is deferred to a later phase.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages RavenWire sensor fleet configuration.
- **Auth_Pipeline**: A Plug pipeline in the Phoenix router that enforces session authentication on browser routes.
- **Session**: A server-side session record tied to a browser cookie, created at login and destroyed at logout or expiry.
- **User**: A local account record with a username, hashed password, assigned role, and active/disabled status.
- **Role**: A named set of permissions. One of: `viewer`, `analyst`, `sensor-operator`, `rule-manager`, `platform-admin`, `auditor`.
- **Permission**: A granular capability string (e.g., `rules:deploy`, `pcap:configure`) that a Role grants.
- **RBAC_Gate**: A runtime check that compares the current User's Role permissions against the permission required by a route or action.
- **API_Token**: A bearer token with a name, scoped permissions, optional expiry, and association to a creating User.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who did what, when, to which target, and whether it succeeded.
- **Password_Hash**: The Argon2id-hashed representation of a User's password, stored in the database. Plaintext passwords are never persisted.
- **Initial_Admin**: The first `platform-admin` User, seeded automatically when the database contains zero User records.

## Requirements

### Requirement 1: User Account Management

**User Story:** As a platform admin, I want to create, edit, disable, and delete local user accounts, so that I can control who has access to the Config Manager.

#### Acceptance Criteria

1. THE Config_Manager SHALL store User records with fields: username, Password_Hash, display name, Role, active status, and timestamps.
2. THE Config_Manager SHALL enforce unique usernames across all User records.
3. WHEN a platform admin creates a User, THE Config_Manager SHALL hash the password using Argon2id before storing the Password_Hash, using memory-hard parameters no weaker than the configured RavenWire defaults.
4. WHEN a platform admin disables a User, THE Config_Manager SHALL immediately invalidate all active Sessions for that User.
5. WHEN a platform admin deletes a User, THE Config_Manager SHALL revoke all API_Tokens associated with that User and invalidate all active Sessions.
6. THE Config_Manager SHALL expose a user management page at `/admin/users` accessible only to Users with the `platform-admin` Role.
7. WHEN a User attempts to change their own password, THE Config_Manager SHALL require the current password before accepting the new password.
8. WHEN a platform admin disables a User, THE Config_Manager SHALL immediately reject all API_Tokens created by that User until the User is re-enabled or the tokens are revoked.
9. WHEN a platform admin initiates a password reset for another User, THE Config_Manager SHALL either generate a temporary password or require a new password entry, mark the account as requiring a password change on next login, invalidate all active Sessions for that User, and record an Audit_Entry.

### Requirement 2: Initial Admin Seeding

**User Story:** As an operator deploying RavenWire for the first time, I want an initial admin account created automatically, so that I can log in and configure the system without manual database manipulation.

#### Acceptance Criteria

1. WHEN the Config_Manager starts and the User table contains zero records, THE Config_Manager SHALL create an Initial_Admin User with the `platform-admin` Role.
2. THE Config_Manager SHALL read the Initial_Admin username from the `RAVENWIRE_ADMIN_USER` environment variable, defaulting to `RavenWire` when the variable is not set.
3. THE Config_Manager SHALL read the Initial_Admin password from the `RAVENWIRE_ADMIN_PASSWORD` environment variable, defaulting to a generated random 24-character password when the variable is not set.
4. WHEN the Config_Manager generates a default Initial_Admin password because `RAVENWIRE_ADMIN_PASSWORD` is not set, THE Config_Manager SHALL log the generated password exactly once to stdout at startup, clearly mark it as first-startup bootstrap output, SHALL NOT write the plaintext password to the audit log or database, and SHALL mark the account as requiring a password change on first login.
5. IF the `RAVENWIRE_ADMIN_PASSWORD` environment variable contains fewer than 12 characters, THEN THE Config_Manager SHALL refuse to start and log an error stating the minimum password length requirement.

### Requirement 3: Session Authentication

**User Story:** As a user, I want to log in with my username and password, so that I can access the Config Manager securely.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a login page at `/login` that accepts a username and password.
2. WHEN a User submits valid credentials on the login page, THE Config_Manager SHALL create a Session, set a secure HTTP-only cookie, and redirect the User to the dashboard.
3. WHEN a User submits invalid credentials, THE Config_Manager SHALL display a generic error message "Invalid username or password" without revealing whether the username or password was incorrect.
4. THE Config_Manager SHALL enforce a Session inactivity timeout of 30 minutes, configurable via the `RAVENWIRE_SESSION_TIMEOUT_MIN` environment variable.
5. WHEN a Session expires due to inactivity, THE Config_Manager SHALL redirect the User to the login page with a message indicating the session has expired.
6. WHEN a User clicks the logout action, THE Config_Manager SHALL destroy the Session, clear the session cookie, and redirect to the login page.
7. THE Auth_Pipeline SHALL reject unauthenticated requests to all browser routes except `/login` and redirect them to `/login`.
8. IF a disabled User attempts to log in, THEN THE Config_Manager SHALL reject the login with the same generic error message used for invalid credentials.
9. THE Config_Manager SHALL periodically prune expired Session records from server-side storage and SHALL also delete expired Session records opportunistically when they are encountered during request authentication.

### Requirement 4: Role Definitions and Permission Model

**User Story:** As a platform admin, I want a predefined set of roles with specific permissions, so that I can assign appropriate access levels to each user.

#### Acceptance Criteria

1. THE Config_Manager SHALL define the following Roles with their associated Permissions:
   - `viewer`: `dashboard:view`, `sensors:view`, `audit:view`.
   - `analyst`: viewer permissions plus `pcap:search` and `pcap:download`.
   - `sensor-operator`: analyst permissions plus `sensor:operate`, `enrollment:manage`, `pcap:configure`, `pools:manage`, `deployments:manage`, `forwarding:manage`, `bpf:manage`, `alerts:manage`, and `bundle:download`.
   - `rule-manager`: sensor-operator permissions plus `rules:deploy` and `rules:manage`.
   - `platform-admin`: all permissions including `users:manage`, `roles:view`, `tokens:manage`, `audit:export`, and `system:manage`.
   - `auditor`: `dashboard:view`, `sensors:view`, `audit:view`, and `audit:export`; no write, configuration, PCAP retrieval, admin, or system management permissions.
2. THE Config_Manager SHALL treat the following Permission identifiers as the canonical RBAC source of truth across all specs, code, fixtures, route policy declarations, API token scopes, and tests: `dashboard:view`, `sensors:view`, `sensor:operate`, `enrollment:manage`, `pcap:configure`, `pcap:search`, `pcap:download`, `pools:manage`, `deployments:manage`, `rules:deploy`, `rules:manage`, `forwarding:manage`, `bpf:manage`, `alerts:manage`, `bundle:download`, `audit:view`, `audit:export`, `users:manage`, `roles:view`, `tokens:manage`, and `system:manage`.
3. THE Config_Manager SHALL treat `alerts:view` as a display alias for `sensors:view` only; it SHALL NOT be stored as a separate permission identifier.
4. THE Config_Manager SHALL store the Role-to-Permission mapping in application code, not in the database, to prevent privilege escalation through database manipulation.
5. WHEN a User's Role is changed, THE Config_Manager SHALL apply the new permissions on the next request without requiring the User to log out and log back in.
6. THE Config_Manager SHALL expose a role reference page at `/admin/roles` accessible to Users with the `platform-admin` Role, displaying each Role and its associated Permissions.
7. THE Config_Manager SHALL require `platform-admin` for admin pages that manage local security state, including `/admin/users`, `/admin/roles`, and `/admin/api-tokens`; the `auditor` Role SHALL NOT grant read-only access to those admin pages unless a later requirement explicitly adds separate read-only admin views.

### Requirement 5: RBAC Enforcement on Browser Routes

**User Story:** As a platform admin, I want the UI to enforce role-based access on every page and action, so that users can only perform operations their role permits.

#### Acceptance Criteria

1. WHEN an authenticated User navigates to a route requiring a Permission the User's Role does not include, THE Config_Manager SHALL display a 403 Forbidden page with a message indicating insufficient permissions.
2. THE RBAC_Gate SHALL protect the following browser routes with the specified minimum Permissions:
   - `/`: `dashboard:view`.
   - `/audit`: `audit:view`.
   - `/audit/export`: `audit:export`.
   - `/enrollment`: `enrollment:manage`.
   - `/pcap-config`: `sensors:view` for read access; `pcap:configure` for write events.
   - `/rules`: `sensors:view` for page access; `rules:deploy` for quick deploy events.
   - `/support-bundle`: `sensors:view` for page access; `bundle:download` for generation or download actions.
   - `/sensors/:id`, `/sensors/:id/pipeline`, `/sensors/:id/metrics`, and `/sensors/:id/baselines`: `sensors:view`.
   - `/pools`, `/pools/:id`, `/pools/:id/sensors`, `/pools/:id/config`, `/pools/:id/deployments`, `/pools/:id/drift`, `/pools/:id/pipeline`, `/pools/:id/metrics`, `/pools/:id/baselines`, `/pools/:id/bpf`, and `/pools/:id/forwarding`: `sensors:view` for read access.
   - `/pools/new`, `/pools/:id/edit`, `/pools/:id/sensors` write events, and `/pools/:id/config` write events: `pools:manage`.
   - `/pools/:id/bpf` write events: `bpf:manage`.
   - `/pools/:id/forwarding/sinks/new`, `/pools/:id/forwarding/sinks/:sink_id/edit`, and forwarding write events: `forwarding:manage`.
   - `/deployments`, `/deployments/:id`, and `/pools/:id/deployments`: `sensors:view`; deployment create, cancel, rollback, promote, and abort events: `deployments:manage`.
   - `/pcap`, `/pcap/search`, `/pcap/requests`, `/pcap/requests/:id`, `/pcap/requests/:id/manifest`, and `/pcap/requests/:id/manifest/export`: `pcap:search`; `/pcap/requests/:id/download`: `pcap:download`.
   - `/rules/store`, `/rules/categories`, `/rules/repositories`, `/rules/rulesets`, `/rules/deployments`, `/rules/zeek-packages`, and `/rules/yara`: `sensors:view` for read access; rule store and detection content write events: `rules:manage`; deployment events that push content to sensors: `deployments:manage` or `rules:deploy` as specified by the feature route.
   - `/alerts` and `/alerts/notifications`: `sensors:view`; `/alerts/rules` and alert acknowledge/resolve/configuration events: `alerts:manage`.
   - `/admin/users`: `users:manage`.
   - `/admin/roles`: `roles:view`.
   - `/admin/api-tokens`: `tokens:manage`.
   - `/admin/bundles`, `/admin/bundles/import`, `/admin/bundles/export`, `/admin/ha`, and `/admin/ha/status`: `system:manage`.
   - `/api/docs` and `/api/v1/openapi.json`: publicly readable by default, unless hardened deployment configuration requires authentication.
3. THE Config_Manager SHALL hide UI elements (buttons, links, form controls) for actions the current User's Role does not permit, in addition to server-side enforcement.
4. WHEN a LiveView action is invoked via WebSocket, THE RBAC_Gate SHALL verify the User's Permission before executing the action and return an error if the Permission is missing.
5. THE Config_Manager SHALL allow all authenticated Users read access to the dashboard (`/`) and the audit log view (`/audit`).
6. WHEN a browser form post, controller write action, or LiveView event mutates state, THE Config_Manager SHALL enforce Phoenix CSRF protections in addition to authentication and RBAC.
7. WHEN the RBAC_Gate rejects a browser route or LiveView action, THE Config_Manager SHALL record an Audit_Entry with action `permission_denied`, result `failure`, and details containing the required Permission and requested route or event.

### Requirement 6: API Token Management

**User Story:** As a platform admin, I want to create scoped API tokens for automation tools like Splunk workflow actions, so that external systems can interact with the Config Manager API without using a user session.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose an API token management page at `/admin/api-tokens` accessible only to Users with the `platform-admin` Role.
2. WHEN a platform admin creates an API_Token, THE Config_Manager SHALL generate a cryptographically random token of at least 32 bytes, display it exactly once, and store only a SHA-256 hash of the token in the database.
3. THE Config_Manager SHALL associate each API_Token with the creating User, a human-readable name, a set of scoped Permissions, and an optional expiry timestamp.
4. WHEN an API request includes a bearer token in the `Authorization` header, THE Config_Manager SHALL authenticate the request by hashing the provided token and comparing it against stored API_Token hashes.
5. WHEN an API_Token has an expiry timestamp that has passed, THE Config_Manager SHALL reject requests using that token with a 401 Unauthorized response.
6. WHEN a platform admin revokes an API_Token, THE Config_Manager SHALL immediately reject all subsequent requests using that token.
7. THE RBAC_Gate SHALL enforce the API_Token's scoped Permissions on API requests identically to how it enforces User Role Permissions on browser requests.
8. WHEN the creating User for an API_Token is disabled or deleted, THE Config_Manager SHALL reject requests using that API_Token with a 401 Unauthorized response.
9. THE Config_Manager SHALL NOT return stored token hashes or full bearer token values from any API or page after the one-time creation display.
10. THE RBAC_Gate SHALL protect all Public_API routes under `/api/v1/` with the same canonical Permission identifiers used for browser routes; no new unversioned `/api/...` Public_API routes SHALL be introduced.
11. THE RBAC_Gate SHALL protect the following initial Public_API endpoints with the specified minimum Permissions:
   - `POST /api/v1/enrollments/:id/approve`: `enrollment:manage`.
   - `POST /api/v1/enrollments/:id/deny`: `enrollment:manage`.
   - `POST /api/v1/pcap-config`: `pcap:configure`.
   - `GET /api/v1/pcap/requests`, `GET /api/v1/pcap/requests/:id`, `GET /api/v1/pcap/requests/:id/manifest`, and `POST /api/v1/pcap/carve`: `pcap:search`.
   - `GET /api/v1/pcap/requests/:id/download`: `pcap:download`.
   - `POST /api/v1/rules/deploy`: `rules:deploy`.
   - `GET /api/v1/rules`, `GET /api/v1/rulesets`, and `GET /api/v1/repositories`: `sensors:view`.
   - `POST /api/v1/rules`, `POST /api/v1/rulesets`, and `POST /api/v1/repositories`: `rules:manage`.
   - `GET /api/v1/deployments` and `GET /api/v1/deployments/:id`: `sensors:view`.
   - `POST /api/v1/deployments`, `POST /api/v1/deployments/:id/cancel`, and `POST /api/v1/deployments/:id/rollback`: `deployments:manage`.
   - `POST /api/v1/support-bundles`: `bundle:download`.
   - `GET /api/v1/audit`: `audit:view`.
   - `GET /api/v1/audit/export`: `audit:export`.
   - `POST /api/v1/admin/users`: `users:manage`.
   - `POST /api/v1/admin/api-tokens`: `tokens:manage`.
   - Future forwarding and BPF API write endpoints: `forwarding:manage` and `bpf:manage` respectively.
12. WHEN the RBAC_Gate rejects an API request due to missing token scope or User Role Permission, THE Config_Manager SHALL return 403 Forbidden and record an Audit_Entry with action `permission_denied`.

### Requirement 7: Audit Logging

**User Story:** As an auditor, I want every security-relevant action recorded in an immutable audit log, so that I can investigate incidents and demonstrate compliance.

#### Acceptance Criteria

1. THE Config_Manager SHALL record an Audit_Entry for each of the following actions: user login, user logout, failed login attempt, login rate limit, permission denied, user creation, user modification, user deletion, user disabled, password reset, role change, API token creation, API token revocation, enrollment approval, enrollment denial, PCAP configuration change, pool management action, rule deployment, sensor operational action, support bundle download, and audit log export.
2. EACH Audit_Entry SHALL contain: a unique identifier, a microsecond-precision UTC timestamp, the actor identity (username or API_Token name), the actor type (`user`, `api_token`, or `system`), the action performed, the target type, the target identifier, the result (`success` or `failure`), and a JSON detail field with action-specific context.
3. THE Config_Manager SHALL write Audit_Entries to the existing `audit_log` database table in an append-only manner.
4. THE Config_Manager SHALL NOT provide any interface or API to modify or delete Audit_Entries.
5. WHEN an audited action fails due to a permission check, THE Config_Manager SHALL still record the Audit_Entry with action `permission_denied`, a result of `failure`, and include the missing Permission in the detail field.

### Requirement 8: Audit Log Viewing

**User Story:** As an auditor or admin, I want to browse and filter the audit log in the web UI, so that I can quickly find relevant events during an investigation.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose an audit log page at `/audit` accessible to all authenticated Users.
2. THE Config_Manager SHALL display Audit_Entries in reverse chronological order with columns: timestamp, actor, action, target, and result.
3. WHEN a User applies filters on the audit log page, THE Config_Manager SHALL support filtering by: date range, actor, action type, target type, target identifier, and result.
4. THE Config_Manager SHALL paginate audit log results with a default page size of 50 entries.
5. WHEN a User clicks on an Audit_Entry row, THE Config_Manager SHALL display the full detail JSON in an expandable panel.

### Requirement 9: Audit Log Export

**User Story:** As an auditor, I want to export filtered audit log data as CSV or JSON, so that I can include it in incident reports and compliance documentation.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose an audit export page at `/audit/export` accessible only to Users with the `platform-admin` or `auditor` Role.
2. WHEN a User requests an export, THE Config_Manager SHALL apply the same filters available on the audit log view page to the exported data.
3. THE Config_Manager SHALL support export in CSV and JSON formats, selectable by the User before initiating the export.
4. WHEN an export is initiated, THE Config_Manager SHALL record an Audit_Entry with action `audit_export` capturing the applied filters and the export format.
5. IF an export request would produce more than 100,000 records, THEN THE Config_Manager SHALL reject the request with a message instructing the User to narrow the date range or filters.

### Requirement 10: Password Security Policy

**User Story:** As a platform admin, I want password security policies enforced on all accounts, so that weak credentials do not compromise the platform.

#### Acceptance Criteria

1. THE Config_Manager SHALL require passwords to be at least 12 characters long.
2. THE Config_Manager SHALL reject passwords that match the username.
3. WHEN a User's account is marked as requiring a password change, THE Config_Manager SHALL redirect the User to a password change page immediately after login and block access to all other routes until the password is changed.
4. THE Config_Manager SHALL rate-limit login attempts to a maximum of 5 failed attempts per username within a 15-minute window.
5. WHEN the login rate limit is exceeded for a username, THE Config_Manager SHALL reject further login attempts for that username for 15 minutes and record an Audit_Entry with action `login_rate_limited`.
6. THE Config_Manager SHALL also apply IP-based login throttling to reduce username enumeration and distributed guessing.
7. WHEN any login rate limit is exceeded, THE Config_Manager SHALL show the same generic login failure message used for invalid credentials while recording the specific rate-limit reason internally in the Audit_Entry detail field.

### Requirement 11: Secure Session and Cookie Handling

**User Story:** As a security-conscious operator, I want sessions and cookies handled securely, so that session hijacking and fixation attacks are mitigated.

#### Acceptance Criteria

1. THE Config_Manager SHALL set the `Secure`, `HttpOnly`, and `SameSite=Strict` attributes on all session cookies.
2. WHEN a User successfully authenticates, THE Config_Manager SHALL regenerate the session identifier to prevent session fixation.
3. THE Config_Manager SHALL store session data server-side and transmit only an opaque session identifier in the cookie.
4. THE Config_Manager SHALL enforce a maximum absolute session lifetime of 24 hours regardless of activity, configurable via the `RAVENWIRE_SESSION_MAX_LIFETIME_HR` environment variable.
5. THE Config_Manager SHALL verify that session cookies include the required `Secure`, `HttpOnly`, and `SameSite=Strict` attributes in automated tests.

### Requirement 12: Test Coverage and Verification

**User Story:** As an engineer implementing authentication and RBAC, I want explicit test expectations, so that security behavior is verified and regressions are caught before deployment.

#### Acceptance Criteria

1. THE Config_Manager SHALL include migration tests or schema assertions verifying that required auth, session, API token, and audit log tables and indexes are created.
2. THE Config_Manager SHALL include route tests proving that every protected browser route redirects unauthenticated Users and allows authenticated Users with sufficient Permissions.
3. THE Config_Manager SHALL include allow/deny tests for every permission-gated browser action, LiveView event, and API route listed in this document.
4. THE Config_Manager SHALL include audit tests for both success and failure paths for each audited action category.
5. THE Config_Manager SHALL include tests proving API token plaintext and token hashes are never returned after token creation.
6. THE Config_Manager SHALL include tests proving disabled Users cannot log in and API_Tokens created by disabled Users are rejected.
7. THE Config_Manager SHALL include CSRF tests for browser write actions where Phoenix CSRF protection applies.

### Requirement 13: Naming and Implementation Consistency

**User Story:** As an engineer implementing RBAC, I want stable role and permission identifiers, so that policy checks, fixtures, database constraints, and tests use the same names.

#### Acceptance Criteria

1. THE Config_Manager SHALL use the exact Role identifiers `viewer`, `analyst`, `sensor-operator`, `rule-manager`, `platform-admin`, and `auditor` consistently in application code, fixtures, migrations, tests, and policy modules.
2. THE Config_Manager SHALL define Permission identifiers as stable strings in application code and SHALL reuse those constants in route policy declarations and tests.
3. THE Config_Manager SHALL document any display labels separately from Role and Permission identifiers so UI wording changes do not alter authorization behavior.
