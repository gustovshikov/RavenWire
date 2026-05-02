# Requirements Document: Detection Content Lifecycle Management

## Introduction

The RavenWire Config Manager's rule-store-management spec provides a full Suricata Rule Store with SID-indexed storage, category management, repository polling, named ruleset composition, pool assignment, and managed deployment. However, the current detection content management is limited to Suricata rules only. The todo-notes roadmap explicitly defers Zeek package management and YARA rule management to Phase D.

This feature extends the detection content management system to cover all three detection engines in the RavenWire sensor stack: Suricata rules (already managed by the rule-store-management spec), Zeek packages (installed and managed via the Zeek Package Manager), and YARA rules (uploaded and assigned to sensor pools for Strelka file analysis). It adds unified content versioning across all three engines so operators can track which detection content version is deployed to each pool, and it adds content validation/testing before deployment to catch errors before they reach production sensors.

New LiveView pages at `/rules/zeek-packages` and `/rules/yara` provide management interfaces for Zeek packages and YARA rules respectively. The existing Rules navigation section is extended with these sub-links. All operations integrate with the existing RBAC, audit logging, and deployment tracking systems from the auth-rbac-audit and deployment-tracking specs.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Detection_Content**: The collective term for all detection logic deployed to sensors: Suricata rules, Zeek packages, and YARA rules.
- **Zeek_Package**: A Zeek script package installable via the Zeek Package Manager (`zkg`). Packages provide additional protocol analyzers, detection scripts, and log generators.
- **Zeek_Package_Registry**: The list of available Zeek packages known to the Config_Manager, sourced from the official Zeek Package Manager repository or custom package sources.
- **YARA_Rule**: A YARA pattern-matching rule used by Strelka for file analysis. Stored as the raw rule text with parsed metadata (rule name, description, tags).
- **YARA_Ruleset**: A named collection of YARA rules assigned to a Sensor_Pool, analogous to a Suricata Ruleset.
- **Content_Version**: A unified version number per pool that increments whenever any detection content (Suricata ruleset, Zeek package set, or YARA ruleset) changes for that pool.
- **Last_Deployed_Detection_Content_Version**: The most recent Content_Version successfully deployed to a Sensor_Pod or Sensor_Pool through the deployment-tracking workflow.
- **Content_Validation**: A pre-deployment check that verifies detection content is syntactically correct and compatible with the target engine version before pushing to sensors.
- **Sensor_Pool**: A named grouping of Sensor_Pods that share a common configuration profile, from the sensor-pool-management spec.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that enforces role-based access on routes and LiveView events.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who performed what action, when, on which target, and whether it succeeded.
- **Deployment**: A tracked configuration push from the Config_Manager to a target Sensor_Pool, from the deployment-tracking spec.
- **Rule_Store**: The existing database-backed Suricata rule collection from the rule-store-management spec.

## Requirements

### Requirement 1: Zeek Package Browsing and Search

**User Story:** As a rule manager, I want to browse and search available Zeek packages, so that I can discover and evaluate packages for deployment to my sensor fleet.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Zeek Packages page at `/rules/zeek-packages` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL provide a Sensor_Pool selector on the Zeek Packages page so Users can view and manage package state for a specific pool.
3. THE Config_Manager SHALL display each known Zeek_Package as a row containing: package name, description, version, author, source URL, and current status for the selected pool (available, installed, enabled, disabled).
4. THE Config_Manager SHALL provide a search input that filters packages by name (substring match) and description (substring match).
5. WHEN the Zeek Packages page loads, THE Config_Manager SHALL display packages sorted by name in ascending order as the default.
6. THE Config_Manager SHALL paginate the package list with a default page size of 25 packages per page.
7. WHEN no packages match the search criteria, THE Config_Manager SHALL display an empty state message indicating no matching packages were found.

### Requirement 2: Zeek Package Install, Enable, and Disable

**User Story:** As a rule manager, I want to install, enable, and disable Zeek packages per pool, so that I can control which Zeek detection scripts run on each sensor group.

#### Acceptance Criteria

1. WHEN a User with the `rules:manage` Permission clicks "Install" on an available Zeek_Package, THE Config_Manager SHALL record the package as installed for the selected Sensor_Pool and record an Audit_Entry with action `zeek_package_installed`.
2. WHEN a User with the `rules:manage` Permission toggles a Zeek_Package's enabled status for a pool, THE Config_Manager SHALL update the package state and record an Audit_Entry with action `zeek_package_toggled` containing the package name, pool name, and new state.
3. THE Config_Manager SHALL track Zeek_Package installation and enabled state per Sensor_Pool, allowing different pools to run different package configurations.
4. WHEN a User with the `rules:manage` Permission uninstalls a Zeek_Package from a pool, THE Config_Manager SHALL remove the package association and record an Audit_Entry with action `zeek_package_uninstalled`.
5. THE Config_Manager SHALL display package management actions (Install, Enable, Disable, Uninstall) only to Users whose Role includes the `rules:manage` Permission.
6. THE Config_Manager SHALL NOT automatically deploy Zeek package changes to sensors. Deployment remains an explicit operator action through the deployment-tracking workflow.
7. WHEN a Zeek_Package association is installed, uninstalled, enabled, or disabled for a pool, THE Config_Manager SHALL increment that pool's `detection_content_version`.

### Requirement 3: YARA Rule Management

**User Story:** As a rule manager, I want to upload, browse, enable, and disable YARA rules, so that I can manage file analysis detection content for Strelka.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a YARA Rules page at `/rules/yara` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display each YARA_Rule as a row containing: rule name, description, tags, enabled/disabled status, upload timestamp, and uploaded by actor.
3. WHEN a User with the `rules:manage` Permission uploads a YARA rule file (`.yar` or `.yara` extension), THE Config_Manager SHALL parse the file to extract rule names and metadata, store the raw rule text, and record an Audit_Entry with action `yara_rule_uploaded`.
4. THE Config_Manager SHALL validate uploaded YARA rule files for basic syntax correctness (matching rule blocks, valid rule names) before accepting the upload.
5. IF a YARA rule file fails syntax validation, THEN THE Config_Manager SHALL reject the upload and display the validation error to the User.
6. WHEN a User with the `rules:manage` Permission toggles a YARA_Rule's enabled status, THE Config_Manager SHALL update the global rule availability state and record an Audit_Entry with action `yara_rule_toggled`.
7. THE Config_Manager SHALL support bulk upload of multiple YARA rule files in a single operation.
8. THE Config_Manager SHALL display YARA rule management actions (Upload, Enable, Disable, Delete) only to Users whose Role includes the `rules:manage` Permission.
9. THE Config_Manager SHALL NOT automatically deploy uploaded, toggled, or deleted YARA_Rules to sensors. Deployment remains an explicit operator action.

### Requirement 4: YARA Ruleset Assignment to Pools

**User Story:** As a rule manager, I want to assign YARA rulesets to sensor pools, so that each pool runs the appropriate file analysis detection content.

#### Acceptance Criteria

1. THE Config_Manager SHALL allow a User with the `rules:manage` Permission to compose a YARA_Ruleset from enabled YARA_Rules and assign it to a Sensor_Pool.
2. THE Config_Manager SHALL allow at most one YARA_Ruleset assigned to a Sensor_Pool at any time, consistent with the Suricata ruleset assignment model.
3. WHEN a YARA_Ruleset is assigned to a pool, THE Config_Manager SHALL increment the pool's `detection_content_version` and record an Audit_Entry with action `yara_ruleset_assigned_to_pool`.
4. THE Config_Manager SHALL display the currently assigned YARA_Ruleset on the pool detail page alongside the Suricata ruleset assignment.
5. THE Config_Manager SHALL NOT automatically deploy YARA ruleset changes to sensors. Deployment remains an explicit operator action.
6. WHEN a YARA_Ruleset is unassigned from a pool, THE Config_Manager SHALL increment the pool's `detection_content_version` and record an Audit_Entry with action `yara_ruleset_unassigned_from_pool`.

### Requirement 5: Unified Content Versioning

**User Story:** As a sensor operator, I want a unified version number that tracks all detection content changes for a pool, so that I can quickly determine whether a pool's detection content is current.

#### Acceptance Criteria

1. THE Config_Manager SHALL maintain a `detection_content_version` integer on each Sensor_Pool that increments whenever any detection content assignment changes: Suricata ruleset version change, Zeek package set change, or YARA ruleset version change.
2. THE Config_Manager SHALL display the `detection_content_version` on the pool detail page alongside the individual engine-specific versions.
3. WHEN the `detection_content_version` does not match the last deployed detection content version for a pool, THE Config_Manager SHALL display a visual indicator on the pool list page and pool detail page indicating detection content drift.
4. THE Config_Manager SHALL track the last deployed `detection_content_version` per sensor for drift detection, extending the existing drift tracking fields from the deployment-tracking spec with `last_deployed_detection_content_version`.
5. THE Config_Manager SHALL include the `detection_content_version` in Deployment records and Configuration_Snapshots.
6. WHEN a Deployment_Result for a Sensor_Pod transitions to `success`, THE Config_Manager SHALL update that sensor's `last_deployed_detection_content_version` to the Deployment's `detection_content_version`.

### Requirement 6: Content Validation Before Deployment

**User Story:** As a sensor operator, I want detection content validated before deployment, so that syntax errors and compatibility issues are caught before they reach production sensors.

#### Acceptance Criteria

1. WHEN a User initiates a Deployment that includes detection content, THE Deployment_Orchestrator SHALL run content validation as part of the `validating` phase before transitioning to `deploying`.
2. THE Config_Manager SHALL validate Suricata rules by checking for syntax errors using the Suricata rule parser (consistent with the existing rule import parsing from the rule-store-management spec).
3. THE Config_Manager SHALL validate YARA rules by checking for syntax errors before including them in a deployment bundle.
4. THE Config_Manager SHALL validate Zeek package configurations by verifying that all referenced packages are in the installed state for the target pool.
5. IF content validation fails, THEN THE Deployment_Orchestrator SHALL transition the Deployment to `failed` status with a detail message listing the validation errors, and SHALL NOT push any content to sensors.
6. THE Config_Manager SHALL record an Audit_Entry with action `content_validation_failed` containing the validation errors and the detection content types that failed.
7. THE Config_Manager SHALL provide a "Validate Content" button on the pool detail page that runs content validation without creating a Deployment, allowing operators to check content before committing to a deployment.

### Requirement 7: RBAC Integration

**User Story:** As a platform admin, I want detection content management actions protected by role-based access control, so that only authorized users can modify Zeek packages and YARA rules.

#### Acceptance Criteria

1. THE Config_Manager SHALL use the existing `rules:manage` Permission for Zeek package and YARA rule write operations, consistent with the Suricata rule management permission model.
2. THE Config_Manager SHALL use the `deployments:manage` Permission from the deployment-tracking spec for deployment operations that push detection content to sensors.
3. THE Config_Manager SHALL grant read-only detection content access (`sensors:view`) to all authenticated Roles.
4. WHEN a User without the `rules:manage` Permission attempts a detection content write action via LiveView event, THE RBAC_Gate SHALL deny the action, display an error flash, and record an Audit_Entry with action `permission_denied`.

### Requirement 8: Audit Logging

**User Story:** As an auditor, I want all detection content management actions recorded in the audit log, so that changes to Zeek packages and YARA rules are traceable.

#### Acceptance Criteria

1. THE Config_Manager SHALL record an Audit_Entry for each of the following actions: `zeek_package_installed`, `zeek_package_toggled`, `zeek_package_uninstalled`, `yara_rule_uploaded`, `yara_rule_toggled`, `yara_rule_deleted`, `yara_ruleset_assigned_to_pool`, `yara_ruleset_unassigned_from_pool`, `content_validation_failed`, and `content_validation_passed`.
2. EACH detection-content-related Audit_Entry SHALL contain: the actor identity, the actor type, the action name, the target type and target ID, the result, and a JSON detail field with action-specific context.
3. THE Config_Manager SHALL write detection-content-related Audit_Entries within the same database transaction as the mutation.

### Requirement 9: Navigation Integration

**User Story:** As a user, I want Zeek package and YARA rule management integrated into the existing Rules navigation, so that all detection content is accessible from one place.

#### Acceptance Criteria

1. THE Config_Manager SHALL add "Zeek Packages" (`/rules/zeek-packages`) and "YARA Rules" (`/rules/yara`) sub-links to the existing "Rules" navigation section.
2. THE Config_Manager SHALL display detection content summary (Suricata ruleset, Zeek packages, YARA ruleset) on the pool detail page.
3. THE Config_Manager SHALL display the unified `detection_content_version` and per-engine versions on the deployment detail page.

### Requirement 10: Detection Content Data Model

**User Story:** As an engineer implementing detection content lifecycle management, I want the required persistence fields defined, so that versioning and drift detection work consistently.

#### Acceptance Criteria

1. THE Config_Manager SHALL add `detection_content_version` (integer, not null, default 1) to the `sensor_pools` table.
2. THE Config_Manager SHALL add `detection_content_version` (integer, nullable) to the `deployments` table.
3. THE Config_Manager SHALL add `last_deployed_detection_content_version` (integer, nullable) to the `sensor_pods` table.
4. THE Config_Manager SHALL create tables for pool-scoped Zeek package state and YARA ruleset assignment with foreign keys to `sensor_pools` and cascade behavior consistent with existing pool-scoped configuration.
5. THE Config_Manager SHALL validate that YARA_Rulesets assigned to pools include only YARA_Rules whose global availability state is enabled.

### Requirement 11: Deferred Capabilities

**User Story:** As a product owner, I want deferred detection content capabilities documented, so that the team knows what is planned for future phases.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement automatic Zeek package updates from the official package manager repository in this feature. Package updates are manual-only. Automatic polling is deferred to a future enhancement.
2. THE Config_Manager SHALL NOT implement YARA rule compilation or performance profiling in this feature. These are deferred to a future Strelka advanced configuration spec.
3. THE Config_Manager SHALL NOT implement detection content A/B testing or gradual rollout in this feature. Canary deployment of detection content is covered by the canary-deploys spec.
4. THE Config_Manager SHALL NOT implement Zeek package dependency resolution in this feature. Operators are responsible for ensuring package compatibility.
