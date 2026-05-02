# Requirements Document: Offline Update Bundle Import

## Introduction

The RavenWire Config Manager is designed to manage sensor fleets that may operate in air-gapped or restricted network environments where sensors and the Config Manager itself cannot reach external networks. The rule-store-management spec's repository update feature requires HTTP access to external rule sources (ET Open, Snort Community), and the detection-content-lifecycle spec's Zeek package management requires access to the Zeek Package Manager repository. In air-gapped deployments, these features cannot function.

This feature adds an offline update bundle system that allows operators to generate a downloadable bundle on an internet-connected Config Manager instance (or build one manually), transfer it to an air-gapped Config Manager instance via removable media or secure file transfer, and import the bundle to update detection content and configuration artifacts. The bundle contains: Suricata rule repository archives, Zeek packages, YARA rules, BPF profiles, and forwarding configuration templates.

Bundle integrity is verified using a SHA-256 manifest that lists every file in the bundle with its hash. The import process validates the manifest before applying any content, ensuring that corrupted bundles are rejected. When bundle signing is configured, the import process also verifies the manifest signature to reject tampered bundles. New LiveView pages at `/admin/bundles`, `/admin/bundles/import`, and `/admin/bundles/export` provide the management interface.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Update_Bundle**: A compressed archive (`.tar.gz`) containing detection content, configuration artifacts, and a SHA-256 integrity manifest, designed for transfer between Config Manager instances.
- **Bundle_Manifest**: A JSON file (`manifest.json`) inside the Update_Bundle that lists every included file with its SHA-256 hash, the bundle version, creation timestamp, source Config Manager identity, content type metadata, and a description.
- **Bundle_Signature**: An optional detached signature for `manifest.json`, used to verify bundle authenticity when a trusted signing key is configured.
- **Bundle_Version**: A monotonically increasing integer assigned to each generated Update_Bundle, allowing operators to track which bundle version has been imported.
- **Air_Gapped_Deployment**: A Config Manager instance operating on a network with no external internet access, requiring offline content updates.
- **Bundle_Export**: The process of generating an Update_Bundle from the current Config Manager's detection content and configuration state.
- **Bundle_Import**: The process of uploading an Update_Bundle to an air-gapped Config Manager, verifying its integrity, and applying its contents to the local detection content stores.
- **Content_Application**: The process of merging imported bundle content into the local Rule_Store, Zeek package registry, YARA rule store, and configuration templates.
- **Rule_Store**: The database-backed Suricata rule collection from the rule-store-management spec.
- **Sensor_Pool**: A named grouping of Sensor_Pods from the sensor-pool-management spec.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec.
- **Audit_Entry**: An append-only record in the `audit_log` table.

## Requirements

### Requirement 1: Bundle Export

**User Story:** As a platform administrator, I want to generate a downloadable update bundle from my Config Manager, so that I can transfer detection content to air-gapped instances.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a bundle export page at `/admin/bundles/export` accessible only to Users with the `system:manage` Permission (`platform-admin` Role only).
2. WHEN a User initiates a bundle export, THE Config_Manager SHALL present options to select which content types to include: Suricata rule archives, Zeek packages, YARA rules, BPF profile templates, and forwarding configuration templates.
3. THE Config_Manager SHALL generate an Update_Bundle as a `.tar.gz` archive containing the selected content types and a Bundle_Manifest.
4. THE Bundle_Manifest SHALL be a JSON file named `manifest.json` at the root of the archive containing: `bundle_version` (integer), `created_at` (ISO 8601 timestamp), `created_by` (operator identity), `source_instance` (Config Manager hostname or identifier), `description` (operator-provided text), `content_types` (array of included content type identifiers), and `files` (array of objects with `path`, `sha256`, `size_bytes`, and `content_type` for each file in the bundle).
5. THE Config_Manager SHALL compute a SHA-256 hash for each file included in the bundle and record it in the Bundle_Manifest.
6. THE Config_Manager SHALL assign a monotonically increasing Bundle_Version to each generated bundle and record the export in the database.
7. THE Config_Manager SHALL record an Audit_Entry with action `bundle_exported` containing the Bundle_Version, included content types, file count, total size, and operator identity.
8. THE Config_Manager SHALL make the generated bundle available for download via a time-limited download link (default: 24 hours).
9. IF bundle signing is configured, THEN THE Config_Manager SHALL generate a detached signature for `manifest.json` and include it in the archive as `manifest.sig`.

### Requirement 2: Bundle Import

**User Story:** As a platform administrator on an air-gapped instance, I want to import an update bundle, so that I can update detection content without internet access.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a bundle import page at `/admin/bundles/import` accessible only to Users with the `system:manage` Permission (`platform-admin` Role only).
2. THE Config_Manager SHALL accept Update_Bundle uploads via the LiveView file upload mechanism with a configurable maximum file size (default: 500 MB).
3. WHEN a User uploads an Update_Bundle, THE Config_Manager SHALL extract the archive to a temporary directory and locate the `manifest.json` file.
4. IF the uploaded file is not a valid `.tar.gz` archive or does not contain a `manifest.json`, THEN THE Config_Manager SHALL reject the import and display an error message.
5. THE Config_Manager SHALL display the Bundle_Manifest metadata (version, creation timestamp, source instance, description, file count) to the User for review before applying the content.
6. THE Config_Manager SHALL provide a "Review & Apply" workflow where the User can review the bundle contents and confirm the import before any content is applied.
7. THE Config_Manager SHALL record an Audit_Entry with action `bundle_imported` containing the Bundle_Version, source instance, content types applied, and import results.
8. THE Config_Manager SHALL clean up temporary files after import completes or fails.

### Requirement 3: Bundle Integrity Verification

**User Story:** As a platform administrator, I want bundle integrity verified before import, so that corrupted bundles are rejected and tampered bundles are rejected when signing is configured.

#### Acceptance Criteria

1. BEFORE applying any content from an imported Update_Bundle, THE Config_Manager SHALL verify the SHA-256 hash of every file listed in the Bundle_Manifest against the actual file contents in the archive.
2. IF any file's computed SHA-256 hash does not match the hash recorded in the Bundle_Manifest, THEN THE Config_Manager SHALL reject the entire import, display which files failed verification, and record an Audit_Entry with action `bundle_integrity_failed`.
3. IF the Bundle_Manifest lists files that are not present in the archive, THEN THE Config_Manager SHALL reject the import with an error indicating missing files.
4. IF the archive contains files not listed in the Bundle_Manifest, THE Config_Manager SHALL ignore the unlisted files and log a warning.
5. THE Config_Manager SHALL display the integrity verification result (pass/fail with details) to the User before proceeding with content application.
6. THE Config_Manager SHALL verify the Bundle_Manifest JSON structure is well-formed and contains all required fields before proceeding with file hash verification.
7. THE Config_Manager SHALL reject archive entries with absolute paths, parent-directory traversal (`..`), or paths that would extract outside the temporary import directory.
8. IF a trusted bundle signing key is configured, THEN THE Config_Manager SHALL verify `manifest.sig` before applying content and SHALL reject the import if the signature is missing or invalid.
9. IF no trusted bundle signing key is configured, THEN THE Config_Manager SHALL display a warning during import review that SHA-256 verification detects corruption but does not prove bundle authenticity.

### Requirement 4: Content Application

**User Story:** As a platform administrator, I want imported bundle content applied to the local detection content stores, so that the air-gapped instance has up-to-date detection content.

#### Acceptance Criteria

1. WHEN applying Suricata rule content from a bundle, THE Config_Manager SHALL use the same SID-based upsert logic from the rule-store-management spec: updating rules with newer revisions, inserting new SIDs, and preserving per-rule enabled/disabled state for existing SIDs.
2. WHEN applying Zeek package content from a bundle, THE Config_Manager SHALL add new packages to the local Zeek package registry as available (not automatically installed or enabled).
3. WHEN applying YARA rule content from a bundle, THE Config_Manager SHALL add new YARA rules to the local YARA rule store as disabled by default, preserving existing rules and their enabled/disabled state.
4. THE Config_Manager SHALL apply all selected content types within a single database transaction when possible so that a failure during application rolls back the entire import. IF filesystem writes are required, THEN THE Config_Manager SHALL stage them before the database transaction and only promote them after database changes succeed.
5. THE Config_Manager SHALL display an import results summary showing: rules added, rules updated, rules unchanged, Zeek packages added, YARA rules added, and any errors encountered.
6. THE Config_Manager SHALL record an Audit_Entry with action `bundle_content_applied` containing per-content-type results (added, updated, unchanged counts).
7. THE Config_Manager SHALL NOT automatically deploy imported content to sensors. Deployment remains an explicit operator action through the deployment-tracking workflow.
8. THE Config_Manager SHALL increment relevant desired-state versions, such as `detection_content_version`, only for content types that are actually applied and change local desired state.

### Requirement 5: Bundle History

**User Story:** As a platform administrator, I want to see a history of exported and imported bundles, so that I can track which content versions have been transferred between instances.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a bundle history page at `/admin/bundles` accessible only to Users with the `system:manage` Permission (`platform-admin` Role only).
2. THE Config_Manager SHALL display a table of bundle operations (exports and imports) showing: Bundle_Version, operation type (export/import), timestamp, operator, source instance (for imports), content types, file count, total size, and status (success/failed).
3. THE Config_Manager SHALL retain bundle operation records in the database for audit purposes, even after the bundle file itself is no longer available for download.
4. THE Config_Manager SHALL provide a download link for exported bundles that are still within the download expiry window.

### Requirement 6: Bundle Content Selection

**User Story:** As a platform administrator, I want to select which content types to include in an export bundle and which to apply during import, so that I can transfer only the content I need.

#### Acceptance Criteria

1. DURING bundle export, THE Config_Manager SHALL allow the User to select individual content types to include: Suricata rules (all rules from the Rule_Store), Zeek packages (all known packages), YARA rules (all YARA rules), BPF profile templates (all BPF profiles), and forwarding configuration templates (all forwarding sink configurations with secrets excluded).
2. DURING bundle import, THE Config_Manager SHALL allow the User to select which content types from the bundle to apply, defaulting to all available content types.
3. THE Config_Manager SHALL display the content type breakdown from the Bundle_Manifest during import review, showing the count and size of each content type.
4. THE Config_Manager SHALL NOT include secret values (API tokens, HEC tokens, sink credentials) in exported bundles. Forwarding configuration templates SHALL include sink structure and non-secret settings only.

### Requirement 7: RBAC and Audit Integration

**User Story:** As a platform admin, I want bundle operations restricted to administrators and fully audited, so that offline content updates are controlled and traceable.

#### Acceptance Criteria

1. THE Config_Manager SHALL restrict all bundle operations (export, import, history viewing) to Users with the `system:manage` Permission (`platform-admin` Role only).
2. THE Config_Manager SHALL record Audit_Entries for: `bundle_exported`, `bundle_imported`, `bundle_integrity_failed`, `bundle_content_applied`, and `bundle_download`.
3. EACH bundle-related Audit_Entry SHALL contain: the actor identity, the action name, the Bundle_Version, and a JSON detail field with operation-specific context.
4. WHEN a User without `system:manage` attempts to access bundle pages or invoke bundle LiveView events, THE Config_Manager SHALL return a 403 Forbidden response or event error and record an Audit_Entry with action `permission_denied`.

### Requirement 8: Deferred Capabilities

**User Story:** As a product owner, I want deferred offline bundle capabilities documented, so that the team knows what is planned for future enhancements.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement automatic bundle generation on a schedule in this feature. Bundle export is operator-initiated only. Scheduled exports are deferred.
2. THE Config_Manager SHALL NOT implement bundle differential updates (only changes since last export) in this feature. Each bundle is a full snapshot of the selected content types. Differential bundles are deferred.
3. THE Config_Manager SHALL NOT implement bundle payload encryption in this feature. Bundles are integrity-verified and may be signed for authenticity, but content confidentiality is deferred to a future security enhancement.
4. THE Config_Manager SHALL NOT implement bundle transfer via USB device auto-detection or network sync between Config Manager instances in this feature. Transfer is manual (file upload). Automated transfer is deferred.
