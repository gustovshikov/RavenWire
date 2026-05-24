# Requirements Document: Vector Forwarding Sink Management

## Introduction

The RavenWire sensor stack uses Vector as the sole log-forwarding egress path. Every Zeek log, Suricata alert, and normalized event flows through Vector before reaching external destinations such as Splunk, Cribl, syslog collectors, Kafka brokers, or S3 buckets. Today the Config Manager has no UI for managing Vector forwarding sinks, selecting schema transformation modes, viewing buffer health, or testing sink connectivity. The sensor detail page's forwarding section currently displays "data not yet available," and the HealthReport protobuf contains no forwarding telemetry fields.

This feature adds pool-level Vector forwarding sink management to the Config Manager web UI: CRUD operations on forwarding sinks with type-specific configuration forms, secret handling for HEC tokens and API keys, schema mode selection (raw, ECS, OCSF, Splunk CIM), sink connection testing, buffer and retry/drop counter display (gracefully degraded until forwarding telemetry is added to the HealthReport protobuf), and integration with the existing RBAC, audit logging, and pool management systems.

Sink configurations are pool-scoped — all sensors in a pool share the same forwarding configuration. Saving a sink configuration does NOT automatically push it to sensors; deployment remains an explicit operator action through the existing deployment workflow. This is a configuration management feature, not a deployment feature.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Pool**: A named grouping of Sensor_Pods that share a common configuration profile, including forwarding sink configuration. Stored in the `sensor_pools` table.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager. Each Sensor_Pod has an optional `pool_id` foreign key referencing a Sensor_Pool.
- **Forwarding_Sink**: A configured Vector output destination (e.g., Splunk HEC, Cribl HTTP, syslog, Kafka, S3, generic HTTP, or file). Each Forwarding_Sink belongs to a Sensor_Pool and defines the connection parameters, authentication credentials, and delivery settings for one egress path.
- **Sink_Type**: The category of a Forwarding_Sink, determining which configuration fields are required. Supported types: `splunk_hec`, `http` (covers Cribl and generic HTTP), `syslog`, `kafka`, `s3`, `file`.
- **Schema_Mode**: The log transformation schema applied by Vector before forwarding. One of `raw` (no transformation), `ecs` (Elastic Common Schema), `ocsf` (Open Cybersecurity Schema Framework), or `splunk_cim` (Splunk Common Information Model).
- **Sink_Secret**: A sensitive credential stored with a Forwarding_Sink, such as a Splunk HEC token, HTTP bearer token, API key, or password. Sink_Secrets are encrypted at rest and never displayed in full after submission.
- **Connection_Test**: A lightweight, bounded reachability check initiated by the Config_Manager server that validates a Forwarding_Sink's endpoint is accessible and accepts authentication without deploying the full Vector configuration to sensors.
- **Buffer_Stats**: Telemetry data about a Forwarding_Sink's in-memory or disk-backed buffer usage, including current size, capacity, and overflow policy. Depends on forwarding telemetry fields not yet present in the HealthReport protobuf.
- **Retry_Drop_Counters**: Telemetry counters tracking the number of events retried and dropped per Forwarding_Sink due to delivery failures. Depends on forwarding telemetry fields not yet present in the HealthReport protobuf.
- **Forwarding_Context**: The Elixir context module (`ConfigManager.Forwarding`) that provides the public API for sink CRUD, connection testing, schema mode management, and forwarding telemetry queries.
- **Pool_Context**: The existing Elixir context module (`ConfigManager.Pools`) for pool CRUD and sensor assignment.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that enforces role-based access on routes and LiveView events.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who performed what action, when, on which target, and whether it succeeded.
- **Forwarding_Config_Version**: An integer on the Sensor_Pool record that increments each time the pool's forwarding configuration (sinks or schema mode) changes, providing a monotonic version counter separate from the capture/PCAP config version.
- **Forwarding_Config_Metadata**: The timestamp and actor identifier for the last forwarding configuration change, stored on the Sensor_Pool alongside the Forwarding_Config_Version.

## Requirements

### Requirement 1: Forwarding Overview Page

**User Story:** As a sensor operator, I want a forwarding overview page for each pool, so that I can see all configured sinks, the active schema mode, and forwarding health at a glance.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a forwarding overview page at `/pools/:id/forwarding` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display a summary card for each Forwarding_Sink configured for the pool, showing: sink name, Sink_Type, primary endpoint or destination, enabled/disabled status, and the most recent Connection_Test result if available.
3. THE Config_Manager SHALL display the pool's current Schema_Mode selection on the forwarding overview page.
4. THE Config_Manager SHALL display a "Forwarding Telemetry" section showing Buffer_Stats and Retry_Drop_Counters per sink. WHILE forwarding telemetry fields are absent from the HealthReport protobuf, THE Config_Manager SHALL display a placeholder message stating "Forwarding telemetry not yet available — requires HealthReport protobuf extension" instead of counters.
5. THE Config_Manager SHALL display an "Add Sink" button on the forwarding overview page, visible only to Users whose Role includes the `forwarding:manage` Permission.
6. WHEN no Forwarding_Sinks are configured for a pool, THE Config_Manager SHALL display an empty state message indicating no sinks have been configured and prompting the User to add one.
7. THE Config_Manager SHALL display the Forwarding_Config_Version and last forwarding config update metadata (timestamp and actor) on the overview page.

### Requirement 2: Sink Creation

**User Story:** As a sensor operator, I want to add forwarding sinks to a pool, so that Vector can deliver logs to my SIEM, log aggregator, or storage destination.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a sink creation page at `/pools/:id/forwarding/sinks/new` accessible only to Users whose Role includes the `forwarding:manage` Permission.
2. WHEN a User selects a Sink_Type on the creation form, THE Config_Manager SHALL display type-specific configuration fields appropriate for that sink type:
   - **splunk_hec**: endpoint URL, HEC token (Sink_Secret), index name (optional), source type (optional), TLS verification toggle, acknowledgements toggle.
   - **http**: endpoint URL, method (POST or PUT), authentication type (none, bearer token, basic auth), authentication credentials (Sink_Secret), custom headers (key-value pairs), TLS verification toggle.
   - **syslog**: host, port, protocol (TCP or UDP), format (RFC 3164 or RFC 5424), TLS toggle (TCP only), TLS verification toggle.
   - **kafka**: bootstrap servers (comma-separated), topic name, SASL mechanism (none, PLAIN, SCRAM-SHA-256, SCRAM-SHA-512), SASL credentials (Sink_Secret), TLS toggle, TLS verification toggle, compression (none, gzip, snappy, lz4, zstd).
   - **s3**: bucket name, region, endpoint URL (optional, for S3-compatible stores), access key ID (Sink_Secret), secret access key (Sink_Secret), prefix (optional), compression (none, gzip), encoding (json, ndjson).
   - **file**: path template, encoding (json, ndjson, text).
3. THE Config_Manager SHALL require a case-insensitive unique sink name within the pool, validate that the name is between 1 and 255 characters, and contains only alphanumeric characters, hyphens, underscores, and periods.
4. WHEN a User submits the sink creation form with valid parameters, THE Config_Manager SHALL create a new Forwarding_Sink record associated with the pool, encrypt and store any Sink_Secrets, increment the Forwarding_Config_Version on the Sensor_Pool, update the Forwarding_Config_Metadata, and record an Audit_Entry with action `sink_created`.
5. THE Config_Manager SHALL default new sinks to an enabled state.
6. WHEN sink creation succeeds, THE Config_Manager SHALL redirect the User to the forwarding overview page for the pool.
7. THE Config_Manager SHALL validate type-specific required fields before accepting the form submission and display field-level validation errors for missing or invalid values.
8. THE Config_Manager SHALL reject endpoint URLs or destination fields that are malformed for the selected Sink_Type before storing the Forwarding_Sink.

### Requirement 3: Sink Editing

**User Story:** As a sensor operator, I want to edit existing forwarding sinks, so that I can update endpoints, rotate credentials, or adjust delivery settings without recreating the sink.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a sink edit page at `/pools/:id/forwarding/sinks/:sink_id/edit` accessible only to Users whose Role includes the `forwarding:manage` Permission.
2. THE Config_Manager SHALL pre-populate the edit form with the current sink configuration, except that Sink_Secret fields SHALL display a masked placeholder (e.g., "••••••••") instead of the actual secret value.
3. WHEN a User submits the edit form without modifying a Sink_Secret field, THE Config_Manager SHALL preserve the existing encrypted secret value unchanged.
4. WHEN a User enters a new value in a Sink_Secret field, THE Config_Manager SHALL encrypt and store the new secret, replacing the previous value.
5. WHEN a User submits a valid sink edit, THE Config_Manager SHALL update the Forwarding_Sink record, increment the Forwarding_Config_Version on the Sensor_Pool, update the Forwarding_Config_Metadata, and record an Audit_Entry with action `sink_updated` containing the changed fields with old and new values, excluding secret values from the audit detail.
6. THE Config_Manager SHALL NOT include plaintext or encrypted Sink_Secret values in Audit_Entry detail fields. The audit detail SHALL record only that a secret field was changed, not its value.
7. THE Config_Manager SHALL verify that `sink_id` belongs to the pool identified by `:id`; attempts to edit a sink through the wrong pool route SHALL return not found or forbidden and SHALL NOT expose sink details.

### Requirement 4: Sink Deletion

**User Story:** As a sensor operator, I want to delete forwarding sinks that are no longer needed, so that the pool's forwarding configuration stays clean and reflects the current egress topology.

#### Acceptance Criteria

1. WHEN a User with the `forwarding:manage` Permission requests deletion of a Forwarding_Sink, THE Config_Manager SHALL display a confirmation dialog stating the sink name, Sink_Type, and a warning that the sink will be permanently removed from the pool's forwarding configuration.
2. WHEN the User confirms deletion, THE Config_Manager SHALL delete the Forwarding_Sink record, delete the associated encrypted Sink_Secrets, increment the Forwarding_Config_Version on the Sensor_Pool, update the Forwarding_Config_Metadata, and record an Audit_Entry with action `sink_deleted`.
3. WHEN sink deletion succeeds, THE Config_Manager SHALL update the forwarding overview page to reflect the removal without a full page reload.
4. THE Config_Manager SHALL verify that the Forwarding_Sink belongs to the displayed Sensor_Pool before deletion; attempts to delete a sink through the wrong pool SHALL be denied and audited as a failure when an actor can be identified.

### Requirement 5: Sink Enable/Disable Toggle

**User Story:** As a sensor operator, I want to enable or disable individual sinks without deleting them, so that I can temporarily stop forwarding to a destination during maintenance or troubleshooting.

#### Acceptance Criteria

1. THE Config_Manager SHALL display an enable/disable toggle for each Forwarding_Sink on the forwarding overview page, visible only to Users whose Role includes the `forwarding:manage` Permission.
2. WHEN a User toggles a sink's enabled state, THE Config_Manager SHALL update the Forwarding_Sink record, increment the Forwarding_Config_Version on the Sensor_Pool, update the Forwarding_Config_Metadata, and record an Audit_Entry with action `sink_toggled` containing the sink name and the new enabled state.
3. THE Config_Manager SHALL visually distinguish disabled sinks from enabled sinks on the forwarding overview page using a muted or grayed-out presentation.
4. WHEN a sink is disabled, THE future deployment/config-push feature SHALL exclude the sink from generated Vector configuration. THE Config_Manager SHALL NOT remove the sink's stored configuration or secrets.

### Requirement 6: Secret Handling

**User Story:** As a sensor operator, I want HEC tokens, API keys, and passwords stored securely and never displayed in full after submission, so that sensitive credentials are protected from accidental exposure.

#### Acceptance Criteria

1. THE Config_Manager SHALL encrypt Sink_Secret values before storing them in the database, using application-level encryption with a dedicated encryption key configured via environment variable; deriving this key from `secret_key_base` SHALL NOT be the default production behavior.
2. THE Config_Manager SHALL never return the full plaintext value of a Sink_Secret in any HTTP response, LiveView render, API response, or log output after the user submits the form.
3. WHEN displaying a Forwarding_Sink that contains Sink_Secrets, THE Config_Manager SHALL show only a masked representation (e.g., last 4 characters preceded by dots) for each secret field.
4. THE Config_Manager SHALL provide a "Reveal" action that shows the last 4 characters of a Sink_Secret for identification purposes, accessible only to Users whose Role includes the `forwarding:manage` Permission. THE Config_Manager SHALL NOT provide any action to reveal the full secret value.
5. IF the encryption key is unavailable or decryption fails for a stored Sink_Secret, THEN THE Config_Manager SHALL display an error indicator on the affected sink and log a warning, without exposing the raw encrypted value.
6. THE Config_Manager SHALL NOT include Sink_Secret values in Audit_Entry detail fields, PubSub broadcast payloads, or application log messages.
7. THE Config_Manager SHALL redact sensitive custom headers such as `Authorization`, `Cookie`, `X-API-Key`, and any header configured as secret from renders, audit details, PubSub payloads, and logs.

### Requirement 7: Schema Mode Selection

**User Story:** As a sensor operator, I want to select a schema transformation mode for each pool's forwarding pipeline, so that logs are formatted to match the destination SIEM's expected schema before delivery.

#### Acceptance Criteria

1. THE Config_Manager SHALL store a Schema_Mode field on each Sensor_Pool record, with allowed values: `raw`, `ecs`, `ocsf`, and `splunk_cim`, defaulting to `raw`.
2. THE Config_Manager SHALL display a schema mode selector on the forwarding overview page, editable by Users whose Role includes the `forwarding:manage` Permission and read-only for other authenticated Users.
3. WHEN a User changes the Schema_Mode, THE Config_Manager SHALL update the Sensor_Pool record, increment the Forwarding_Config_Version, update the Forwarding_Config_Metadata, and record an Audit_Entry with action `schema_mode_changed` containing the old and new schema mode values.
4. THE Config_Manager SHALL display a brief description of each Schema_Mode option in the selector to help operators understand the transformation:
   - **raw**: No transformation; logs forwarded as produced by Zeek and Suricata.
   - **ecs**: Elastic Common Schema field mapping for Elasticsearch/OpenSearch destinations.
   - **ocsf**: Open Cybersecurity Schema Framework mapping for OCSF-compatible destinations.
   - **splunk_cim**: Splunk Common Information Model field mapping for Splunk destinations.
5. WHEN the Schema_Mode is changed, THE Config_Manager SHALL NOT automatically push the new schema configuration to sensors. Schema mode changes take effect only when the forwarding configuration is explicitly deployed.

### Requirement 8: Sink Connection Testing

**User Story:** As a sensor operator, I want to test a sink's connectivity before deploying the configuration to sensors, so that I can catch endpoint errors, authentication failures, and TLS issues without blind config pushes.

#### Acceptance Criteria

1. THE Config_Manager SHALL provide a "Test Connection" button on each Forwarding_Sink's detail or edit view, accessible to Users whose Role includes the `forwarding:manage` Permission.
2. WHEN a User clicks "Test Connection," THE Config_Manager SHALL perform a lightweight connectivity check from the Config_Manager server to the sink's configured endpoint, validating: network reachability, TLS handshake (if TLS is enabled), and authentication acceptance (if credentials are configured).
3. THE Config_Manager SHALL display the Connection_Test result inline on the page, indicating success or failure with a descriptive message (e.g., "Connection successful," "TLS handshake failed: certificate expired," "Authentication rejected: 401 Unauthorized").
4. THE Config_Manager SHALL record an Audit_Entry with action `sink_connection_tested` containing the sink name, Sink_Type, and test result (success or failure with error category), excluding any Sink_Secret values from the audit detail.
5. IF the Connection_Test fails due to a network timeout, THEN THE Config_Manager SHALL display a message indicating the endpoint was unreachable within the configured timeout period.
6. THE Config_Manager SHALL execute Connection_Tests asynchronously so that the LiveView remains responsive during the test. THE Config_Manager SHALL display a loading indicator while the test is in progress.
7. THE Config_Manager SHALL support Connection_Tests for all Sink_Types except `file`, which has no remote endpoint to test.
8. THE Config_Manager SHALL bound Connection_Tests with a configurable timeout, defaulting to 10 seconds, and SHALL limit concurrent tests to prevent one User from exhausting server resources.
9. THE Config_Manager SHALL validate Connection_Test destinations against the selected Sink_Type and SHALL reject unsupported URL schemes, malformed hosts, loopback/link-local destinations, and private network destinations unless an explicit allow-private-destinations configuration is enabled for lab deployments.
10. THE Config_Manager SHALL store the most recent Connection_Test result and timestamp on the Forwarding_Sink but SHALL NOT increment Forwarding_Config_Version for a Connection_Test because the forwarding configuration did not change.
11. THE Config_Manager SHALL redact credentials, tokens, sensitive headers, and full endpoint query strings from Connection_Test error messages before displaying them, auditing them, or logging them.

### Requirement 9: Buffer and Telemetry Display

**User Story:** As a sensor operator, I want to view buffer usage, retry counts, and drop counters for each forwarding sink, so that I can detect downstream outages and troubleshoot delivery failures.

#### Acceptance Criteria

1. THE Config_Manager SHALL display a forwarding telemetry section on the forwarding overview page showing per-sink Buffer_Stats (current buffer size, buffer capacity, buffer usage percentage, overflow policy) and Retry_Drop_Counters (events retried, events dropped).
2. WHILE the HealthReport protobuf does not include forwarding telemetry fields, THE Config_Manager SHALL display a placeholder panel for each sink stating "Forwarding telemetry not yet available" with a brief explanation that the HealthReport protobuf extension is required.
3. WHEN forwarding telemetry fields are added to the HealthReport protobuf in a future update, THE Config_Manager SHALL render actual telemetry data in place of the placeholder without requiring changes to the forwarding UI page structure.
4. THE Config_Manager SHALL design the forwarding telemetry display components to accept telemetry data as optional assigns, rendering placeholder content when the data is nil and actual metrics when the data is present.
5. THE Config_Manager SHALL display buffer and counter data per sink, not aggregated across all sinks, so operators can identify which specific destination is experiencing issues.

### Requirement 10: Forwarding Section on Sensor Detail Page

**User Story:** As a sensor operator, I want the sensor detail page's forwarding section to show the pool's forwarding configuration and per-sensor forwarding health, so that I can understand each sensor's egress state without navigating to the pool page.

#### Acceptance Criteria

1. WHEN a Sensor_Pod belongs to a Sensor_Pool that has Forwarding_Sinks configured, THE Config_Manager SHALL display a summary of the pool's forwarding configuration in the sensor detail page's forwarding section, including: pool name (linked to `/pools/:pool_id/forwarding`), Schema_Mode, number of enabled sinks, and a list of sink names with their Sink_Types.
2. WHEN a Sensor_Pod does not belong to any Sensor_Pool, THE Config_Manager SHALL display a message in the forwarding section stating "No pool assigned — forwarding configuration is managed at the pool level" with a link to the pool list page.
3. WHEN a Sensor_Pod belongs to a Sensor_Pool that has no Forwarding_Sinks configured, THE Config_Manager SHALL display a message stating "No forwarding sinks configured for pool [pool_name]" with a link to the pool's forwarding page.
4. WHILE forwarding telemetry is unavailable in the HealthReport protobuf, THE Config_Manager SHALL display "Forwarding telemetry not yet available" in the per-sensor forwarding health area, replacing the current "data not yet available" placeholder.

### Requirement 11: RBAC Integration

**User Story:** As a platform admin, I want forwarding management actions protected by role-based access control, so that only authorized users can create, modify, or delete sinks and change schema modes.

#### Acceptance Criteria

1. THE Config_Manager SHALL use the canonical `forwarding:manage` Permission from the auth-rbac-audit spec for forwarding write operations (create sink, edit sink, delete sink, toggle sink, change schema mode, test connection).
2. THE Config_Manager SHALL verify that the auth-rbac-audit Policy grants `forwarding:manage` to the `sensor-operator`, `rule-manager`, and `platform-admin` Roles, consistent with the `pools:manage` Permission grant pattern.
3. THE Config_Manager SHALL grant read-only forwarding access (`sensors:view`) to all authenticated Roles, allowing viewing of the forwarding overview, sink configurations (with masked secrets), schema mode, and telemetry data.
4. WHEN a User without the `forwarding:manage` Permission attempts a forwarding write action via LiveView event, THE RBAC_Gate SHALL deny the action, display an error flash, and record an Audit_Entry with action `permission_denied`.
5. THE Config_Manager SHALL hide forwarding write UI elements (Add Sink button, Edit/Delete actions, enable/disable toggle, schema mode save, Test Connection button) from Users whose Role does not include the `forwarding:manage` Permission.
6. THE Config_Manager SHALL enforce RBAC on every LiveView `handle_event` callback for forwarding write actions, regardless of whether the UI element is hidden.
7. THE route map and RBAC policy declarations SHALL include `/pools/:id/forwarding` with `sensors:view` and `/pools/:id/forwarding/sinks/new`, `/pools/:id/forwarding/sinks/:sink_id/edit`, and forwarding write events with `forwarding:manage`.
8. WHEN forwarding management is exposed through an API in the future, THE API token scope model SHALL use the same `forwarding:manage` Permission for write actions and SHALL record `permission_denied` audit entries on denied requests.

### Requirement 12: Audit Logging for Forwarding Actions

**User Story:** As an auditor, I want all forwarding management actions recorded in the audit log, so that changes to the organization's log egress path are traceable and attributable.

#### Acceptance Criteria

1. THE Config_Manager SHALL record an Audit_Entry for each of the following forwarding actions: `sink_created`, `sink_updated`, `sink_deleted`, `sink_toggled`, `schema_mode_changed`, and `sink_connection_tested`.
2. EACH forwarding-related Audit_Entry SHALL contain: the actor identity (username or API_Token name), the actor type, the action name, `target_type` set to `forwarding_sink` (for sink actions) or `pool` (for schema mode changes), `target_id` set to the Forwarding_Sink's ID or Sensor_Pool's ID, the result (`success` or `failure`), and a JSON detail field with action-specific context.
3. THE Config_Manager SHALL NOT include Sink_Secret values (plaintext or encrypted) in any Audit_Entry detail field. For secret field changes, the audit detail SHALL record only that the field was modified.
4. THE Config_Manager SHALL write forwarding-related Audit_Entries within the same database transaction as the forwarding mutation, so that if the audit write fails, the forwarding mutation is rolled back.
5. WHEN a forwarding mutation fails validation, THE Config_Manager SHALL record a failure Audit_Entry when an actor and target can be identified.
6. THE Config_Manager SHALL include the required Permission and LiveView event or route name in `permission_denied` audit details for denied forwarding actions.
7. THE Config_Manager SHALL sanitize Audit_Entry detail fields for Connection_Tests so endpoint URLs do not include credentials or sensitive query parameters.

### Requirement 13: Forwarding Data Model

**User Story:** As an engineer implementing forwarding sink management, I want a well-defined data model for sinks and secrets, so that the forwarding configuration is stored reliably and secrets are protected.

#### Acceptance Criteria

1. THE Config_Manager SHALL create a `forwarding_sinks` table via an Ecto migration with the following columns: `id` (binary_id primary key), `pool_id` (binary_id foreign key to `sensor_pools`, on_delete cascade), `name` (text, not null), `normalized_name` (text, not null), `sink_type` (text, not null), `config` (text, not null, JSON-encoded type-specific non-secret configuration), `enabled` (boolean, default true), `last_test_result` (text, nullable, JSON-encoded sanitized test result), `last_test_at` (utc_datetime_usec, nullable), `inserted_at` (utc_datetime_usec), `updated_at` (utc_datetime_usec).
2. THE Config_Manager SHALL create a unique index on `(pool_id, normalized_name)` in the `forwarding_sinks` table to enforce case-insensitive sink name uniqueness within a pool.
3. THE Config_Manager SHALL store Sink_Secret values in a separate `sink_secrets` table linked to `forwarding_sinks`, using application-level encryption. THE Config_Manager SHALL NOT store plaintext secrets in the database.
4. THE Config_Manager SHALL add `schema_mode` (text, default `raw`), `forwarding_config_version` (integer, default 0), `forwarding_config_updated_at` (utc_datetime_usec, nullable), and `forwarding_config_updated_by` (text or binary_id actor reference, nullable) fields to the `sensor_pools` table via migration.
5. THE Config_Manager SHALL validate `schema_mode` values against the allowed set: `raw`, `ecs`, `ocsf`, `splunk_cim`.
6. THE Config_Manager SHALL cascade-delete Forwarding_Sinks when their parent Sensor_Pool is deleted, consistent with the pool deletion behavior defined in the sensor-pool-management spec.
7. THE Config_Manager SHALL validate `sink_type` values against the allowed set: `splunk_hec`, `http`, `syslog`, `kafka`, `s3`, `file`.
8. THE Config_Manager SHALL ensure the JSON `config` field never contains plaintext Sink_Secret values or sensitive header values.
9. THE Config_Manager SHALL create a `sink_secrets` table with at least: `id` (binary_id primary key), `forwarding_sink_id` (binary_id foreign key to `forwarding_sinks`, on_delete cascade), `secret_name` (text, not null), `ciphertext` (text, not null), `last_four` (text, nullable), `inserted_at` (utc_datetime_usec), and `updated_at` (utc_datetime_usec).
10. THE Config_Manager SHALL create a unique index on `(forwarding_sink_id, secret_name)` in the `sink_secrets` table so each sink has at most one current value for each secret field.

### Requirement 14: Forwarding Configuration is Pool-Scoped

**User Story:** As a sensor operator, I want forwarding configuration managed at the pool level, so that all sensors in a pool share the same egress topology and I avoid per-sensor configuration snowflakes.

#### Acceptance Criteria

1. THE Config_Manager SHALL associate each Forwarding_Sink with exactly one Sensor_Pool via the `pool_id` foreign key.
2. THE Config_Manager SHALL NOT provide per-sensor forwarding sink configuration. All forwarding configuration is inherited from the Sensor_Pod's assigned Sensor_Pool.
3. WHEN a Sensor_Pod is assigned to a Sensor_Pool, THE Config_Manager SHALL NOT automatically push the pool's forwarding configuration to the sensor. Forwarding configuration deployment remains an explicit operator action.
4. WHEN a Sensor_Pod is not assigned to any Sensor_Pool, THE Config_Manager SHALL treat the sensor as having no forwarding configuration.

### Requirement 15: No Automatic Deployment on Save

**User Story:** As a sensor operator, I want saving forwarding configuration to be separate from deploying it, so that I can review and validate changes before they affect live sensors.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT automatically push forwarding configuration to sensors when a Forwarding_Sink is created, edited, deleted, toggled, or when the Schema_Mode is changed.
2. THE Config_Manager SHALL display a notice on the forwarding overview page stating that saved configuration changes require explicit deployment to take effect on sensors.
3. THE Config_Manager SHALL increment the Forwarding_Config_Version on the Sensor_Pool each time the forwarding configuration changes (sink CRUD, toggle, or schema mode change), providing operators a version indicator to compare against deployed state.
4. THE Config_Manager SHALL NOT increment the Forwarding_Config_Version when only a Connection_Test result is recorded, because test results are operational telemetry rather than desired forwarding configuration.

### Requirement 16: Navigation and Route Integration

**User Story:** As a user, I want forwarding management integrated into the existing pool navigation, so that I can easily access forwarding pages from the pool detail view.

#### Acceptance Criteria

1. THE Config_Manager SHALL add a "Forwarding" navigation link on the pool detail page and pool sub-navigation, linking to `/pools/:id/forwarding`.
2. THE Config_Manager SHALL add routes for forwarding pages within the authenticated scope: `/pools/:id/forwarding` (overview), `/pools/:id/forwarding/sinks/new` (create), `/pools/:id/forwarding/sinks/:sink_id/edit` (edit).
3. THE Config_Manager SHALL display the forwarding overview page as a tab or section within the pool management navigation, alongside the existing Config, Sensors, and Deployments links.
4. WHEN the sensor detail page's forwarding section displays pool forwarding information, THE Config_Manager SHALL link the pool name to `/pools/:pool_id/forwarding` so operators can navigate directly to the forwarding configuration.
5. THE Config_Manager SHALL return a 404 or permission-safe error when the pool ID or sink ID in a forwarding route does not exist, without revealing whether an inaccessible sink exists in another pool.

### Requirement 17: Realtime Behavior and UI Quality

**User Story:** As an operator managing forwarding sinks during active configuration, I want pages to stay current and controls to be accessible, so that I can trust the displayed state.

#### Acceptance Criteria

1. THE Config_Manager SHALL update the forwarding overview page through LiveView PubSub messages after sink creation, editing, deletion, toggle, schema mode change, and connection test completion, without requiring a full page reload.
2. THE Config_Manager SHALL provide accessible labels, confirmation text, and keyboard-reachable controls for sink create, edit, delete, toggle, schema mode selection, and connection test forms.
3. THE Config_Manager SHALL render the forwarding overview, sink forms, and telemetry sections without horizontal overflow at common desktop widths.
4. THE Config_Manager SHALL display loading indicators during asynchronous operations (connection testing, sink creation/deletion) so operators know the system is processing their request.

### Requirement 18: Test Coverage and Verification

**User Story:** As an engineer implementing forwarding sink management, I want explicit test expectations, so that forwarding behavior is verified and regressions are caught before deployment.

#### Acceptance Criteria

1. THE Config_Manager SHALL include migration tests proving the `forwarding_sinks` table, `sink_secrets` table, `schema_mode` field, Forwarding_Config_Version fields, Forwarding_Config_Metadata fields, and all indexes and constraints are present and correct.
2. THE Config_Manager SHALL include CRUD tests for sink creation, editing, deletion, and validation failures, including sink name uniqueness within a pool and type-specific field validation.
3. THE Config_Manager SHALL include tests proving Sink_Secret values are encrypted before storage and that no API response, LiveView render, or audit entry contains plaintext secret values.
4. THE Config_Manager SHALL include tests proving Forwarding_Config_Version increments on sink CRUD, toggle, and schema mode changes, and does not increment on unrelated pool metadata changes.
5. THE Config_Manager SHALL include allow/deny tests for every route and LiveView event protected by `forwarding:manage`.
6. THE Config_Manager SHALL include connection test tests validating success and failure paths for at least Splunk HEC and generic HTTP sink types.
7. THE Config_Manager SHALL include tests proving the forwarding overview page renders placeholder telemetry content when HealthReport forwarding data is absent.
8. THE Config_Manager SHALL include tests proving Connection_Test destination validation rejects malformed URLs, unsupported schemes, and blocked loopback/link-local/private destinations unless lab allow-list configuration is enabled.
9. THE Config_Manager SHALL include tests proving forwarding route access cannot edit, delete, toggle, or test a sink through the wrong pool ID.
10. THE Config_Manager SHALL include tests proving Forwarding_Config_Metadata is updated on configuration changes and not updated by Connection_Test result writes.

### Requirement 19: Deferred Capabilities

**User Story:** As a product owner, I want deferred forwarding capabilities documented, so that the team knows what is planned for future phases without overloading the current implementation.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement Vector configuration generation or rendering (converting Forwarding_Sink records into a `vector.toml` file) in this feature. Vector config generation is deferred to the deployment/config-push feature.
2. THE Config_Manager SHALL NOT implement forwarding telemetry collection from sensors in this feature. Forwarding telemetry requires extending the HealthReport protobuf and the Sensor_Agent's health reporting, which is deferred to a future HealthReport extension spec.
3. THE Config_Manager SHALL NOT implement per-sensor forwarding sink overrides in this feature. All forwarding configuration is pool-scoped.
4. THE Config_Manager SHALL NOT implement sink ordering or priority in this feature. All enabled sinks in a pool receive the same events.
5. THE Config_Manager SHALL NOT implement automatic sink failover or load balancing across sinks in this feature.
