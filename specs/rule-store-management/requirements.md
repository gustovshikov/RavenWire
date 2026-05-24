# Requirements Document: Rule Store Management

## Introduction

The RavenWire Config Manager currently provides a simple rule deployment page at `/rules` that allows operators to paste Suricata rules into a text area and deploy them to a specific pod or all pods in a pool. This paste-and-deploy workflow is useful for quick ad-hoc rule pushes but does not support browsing, searching, organizing, enabling/disabling, or versioning rules. The `RuleDeployer` module pushes raw rule file maps directly to Sensor Agents via `SensorAgentClient.push_rule_bundle/3`.

This feature adds a full Rule Store to the Config Manager: a database-backed repository of Suricata rules organized by SID, category, and source repository. Operators can browse and search rules, enable or disable individual rules and entire categories, compose named rulesets from enabled rules, assign rulesets to pools, and deploy rulesets through the existing deployment lifecycle. External rule repositories (ET Open, Snort Community, custom URLs) can be registered and polled for updates. The existing paste-and-deploy page is preserved as a quick-action but the Rule Store becomes the primary rule management interface.

YARA rule management and Zeek package management are explicitly deferred to Phase D. This spec does not include them.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Rule_Store**: The database-backed collection of all Suricata rules known to the Config_Manager, indexed by SID, name, category, and source repository.
- **Suricata_Rule**: A single Suricata IDS/IPS rule identified by a unique SID (Signature ID). Stored as the raw rule text along with parsed metadata (SID, message, category, revision, classtype, severity).
- **SID**: Signature ID — the unique integer identifier for a Suricata rule (the `sid` keyword value).
- **Rule_Category**: A Suricata rule category string (e.g., `emerging-malware`, `emerging-exploit`, `emerging-policy`) used for bulk enable/disable operations. Categories are derived from rule file names or explicit `classtype` metadata.
- **Rule_Repository**: An external source of Suricata rules that can be registered in the Config_Manager and polled for updates. Examples include ET Open, Snort Community, and custom HTTP/HTTPS URLs serving tarballed rule archives.
- **Ruleset**: A named, operator-defined collection of rules composed from individually enabled rules and enabled categories. A Ruleset is the unit of assignment to a Sensor_Pool for deployment.
- **Ruleset_Version**: An integer on the Ruleset record that increments each time the Ruleset's effective rule membership changes (rules added/removed, categories toggled, individual rules toggled).
- **Pool_Ruleset_Assignment**: The association between a Sensor_Pool and a Ruleset, defining which detection content the pool's sensors should run.
- **Rule_Deployment**: The act of pushing a Ruleset's compiled rule files to all sensors in an assigned pool via the existing deployment lifecycle from the deployment-tracking spec.
- **Deployed_Rule_Version**: The Ruleset_Version that was last successfully deployed to a given pool, tracked per pool for drift detection.
- **Out_Of_Sync_Sensor**: A sensor whose last-deployed Ruleset_Version does not match the pool's currently assigned Ruleset's version, indicating rule drift.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that enforces role-based access on routes and LiveView events.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who performed what action, when, on which target, and whether it succeeded.
- **Sensor_Pool**: A named grouping of Sensor_Pods that share a common configuration profile, from the sensor-pool-management spec.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager.

## Requirements

### Requirement 1: Rule Store Browse and Search

**User Story:** As a rule manager, I want to browse and search all Suricata rules in the Rule Store, so that I can find specific rules by SID, name, category, or source repository.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Rule Store page at `/rules/store` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display each Suricata_Rule as a row containing: SID, rule message (msg field), Rule_Category, source Rule_Repository name, revision number, enabled/disabled status, and severity.
3. WHEN the Rule Store page loads, THE Config_Manager SHALL sort rules by SID in ascending order as the default.
4. THE Config_Manager SHALL provide a search input that filters rules by SID (exact or prefix match), message text (substring match), Rule_Category (exact match from dropdown), and source Rule_Repository name (exact match from dropdown).
5. WHEN a User enters a search query, THE Config_Manager SHALL filter the displayed rules in real time using LiveView events without a full page reload.
6. THE Config_Manager SHALL paginate the rule list with a default page size of 50 rules per page.
7. WHEN no rules match the search criteria, THE Config_Manager SHALL display an empty state message indicating no matching rules were found.
8. WHEN the Rule Store contains no rules at all, THE Config_Manager SHALL display an empty state message prompting the User to add a Rule_Repository or import rules.

### Requirement 2: Individual Rule Enable/Disable

**User Story:** As a rule manager, I want to enable or disable individual Suricata rules, so that I can fine-tune detection content without removing rules from the store.

#### Acceptance Criteria

1. THE Config_Manager SHALL display an enable/disable toggle for each Suricata_Rule on the Rule Store page, visible only to Users whose Role includes the `rules:manage` Permission.
2. WHEN a User with the `rules:manage` Permission toggles a rule's enabled status, THE Config_Manager SHALL update the rule's `enabled` field in the database and record an Audit_Entry with action `rule_toggled` containing the SID, previous state, and new state.
3. THE Config_Manager SHALL default all newly imported rules to enabled status.
4. WHEN a rule is disabled, THE Config_Manager SHALL exclude the rule from any Ruleset that includes the rule's category, unless the rule is explicitly added to the Ruleset by SID override.
5. THE Config_Manager SHALL support bulk enable/disable by allowing Users to select multiple rules and apply a single toggle action, recording one Audit_Entry per affected rule.

### Requirement 3: Category Enable/Disable

**User Story:** As a rule manager, I want to enable or disable entire rule categories, so that I can quickly include or exclude broad classes of detection content.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Rule Categories page at `/rules/categories` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display each Rule_Category as a row containing: category name, total rule count in the category, enabled rule count, disabled rule count, and a category-level enabled/disabled toggle.
3. WHEN a User with the `rules:manage` Permission toggles a category's enabled status, THE Config_Manager SHALL update the `enabled` field on all Suricata_Rules in that category and record an Audit_Entry with action `category_toggled` containing the category name, affected rule count, and new state.
4. WHEN a category is disabled, THE Config_Manager SHALL set all rules in that category to disabled, overriding any individually enabled rules within the category.
5. WHEN a category is re-enabled, THE Config_Manager SHALL set all rules in that category to enabled, restoring the category to its default state.
6. THE Config_Manager SHALL display the category toggle only to Users whose Role includes the `rules:manage` Permission.

### Requirement 4: Rule Repository Management

**User Story:** As a rule manager, I want to register external rule repositories and update them on demand, so that the Rule Store stays current with community and commercial rule sources.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Rule Repositories page at `/rules/repositories` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display each Rule_Repository as a row containing: repository name, URL, repository type (ET Open, Snort Community, or custom), last update timestamp, rule count from the repository, and update status.
3. WHEN a User with the `rules:manage` Permission submits a new repository with a name and URL, THE Config_Manager SHALL create a Rule_Repository record and record an Audit_Entry with action `repository_added`.
4. THE Config_Manager SHALL validate that the repository URL is a valid HTTP or HTTPS URL and that the repository name is unique (case-insensitive).
5. IF a User submits a repository name that already exists, THEN THE Config_Manager SHALL display a validation error and reject the creation.
6. WHEN a User with the `rules:manage` Permission clicks "Update Now" on a repository, THE Config_Manager SHALL fetch the rule archive from the repository URL, parse the contained Suricata rule files, and upsert rules into the Rule Store by SID (updating existing rules with newer revisions, inserting new rules, and preserving per-rule enabled/disabled state for existing SIDs).
7. WHEN a repository update completes, THE Config_Manager SHALL record an Audit_Entry with action `repository_updated` containing the repository name, rules added count, rules updated count, and rules unchanged count.
8. IF a repository update fails due to network error, invalid archive format, or parse error, THEN THE Config_Manager SHALL record the failure in the repository's `last_update_status` field and record an Audit_Entry with action `repository_update_failed` containing the error reason.
9. WHEN a User with the `rules:manage` Permission deletes a repository, THE Config_Manager SHALL remove the Rule_Repository record but SHALL NOT delete the Suricata_Rules that were imported from it, preserving them in the Rule Store with their source marked as the deleted repository name.
10. THE Config_Manager SHALL display repository management actions (Add, Update Now, Delete) only to Users whose Role includes the `rules:manage` Permission.

### Requirement 5: Rule Import and Parsing

**User Story:** As a rule manager, I want rules imported from repositories to be correctly parsed and indexed, so that I can search, filter, and manage them by their metadata.

#### Acceptance Criteria

1. WHEN importing rules from a repository archive, THE Config_Manager SHALL parse each Suricata rule file and extract: SID, message (msg keyword), revision (rev keyword), classtype, and the raw rule text.
2. THE Config_Manager SHALL derive the Rule_Category from the rule file name (e.g., rules in `emerging-malware.rules` belong to category `emerging-malware`).
3. WHEN a rule with an existing SID is encountered during import, THE Config_Manager SHALL update the rule only if the imported revision is greater than or equal to the stored revision, preserving the existing enabled/disabled state.
4. IF a rule line cannot be parsed, THEN THE Config_Manager SHALL skip the unparseable line, log a warning, and continue processing remaining rules.
5. THE Config_Manager SHALL track the source Rule_Repository for each imported rule so that operators can filter rules by source.
6. THE Config_Manager SHALL support importing rules from `.tar.gz` archives containing `.rules` files, which is the standard distribution format for ET Open and Snort Community rulesets.

### Requirement 6: Ruleset Composition

**User Story:** As a rule manager, I want to compose named rulesets from enabled rules and categories, so that I can define different detection profiles for different sensor pools.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Rulesets page at `/rules/rulesets` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display each Ruleset as a row containing: ruleset name, description, Ruleset_Version, effective rule count (total enabled rules included), assigned pool count, last modified timestamp, and last modified by actor.
3. WHEN a User with the `rules:manage` Permission creates a new Ruleset, THE Config_Manager SHALL accept a name, optional description, a list of included Rule_Categories, and a list of individual SID overrides (explicit includes or excludes), and record an Audit_Entry with action `ruleset_created`.
4. THE Config_Manager SHALL validate that the Ruleset name is unique (case-insensitive), between 1 and 255 characters, and contains only alphanumeric characters, hyphens, underscores, and periods.
5. THE Config_Manager SHALL compute the effective rule set for a Ruleset as: all enabled rules in the included categories, plus any explicitly included SIDs not already in those categories, minus any explicitly excluded SIDs.
6. WHEN a User with the `rules:manage` Permission modifies a Ruleset's category list or SID overrides, THE Config_Manager SHALL increment the Ruleset_Version, update the last modified metadata, and record an Audit_Entry with action `ruleset_updated` containing the changes.
7. WHEN a User with the `rules:manage` Permission deletes a Ruleset, THE Config_Manager SHALL remove the Ruleset record and any Pool_Ruleset_Assignments referencing it, and record an Audit_Entry with action `ruleset_deleted`.
8. THE Config_Manager SHALL display ruleset management actions (Create, Edit, Delete) only to Users whose Role includes the `rules:manage` Permission.

### Requirement 7: Ruleset Assignment to Pools

**User Story:** As a rule manager, I want to assign rulesets to sensor pools, so that each pool runs the appropriate detection content.

#### Acceptance Criteria

1. THE Config_Manager SHALL allow a User with the `rules:manage` Permission to assign a Ruleset to a Sensor_Pool, creating a Pool_Ruleset_Assignment, and record an Audit_Entry with action `ruleset_assigned_to_pool`.
2. THE Config_Manager SHALL allow at most one Ruleset assigned to a Sensor_Pool at any time. Assigning a new Ruleset SHALL replace the previous assignment.
3. WHEN a Ruleset is assigned to a pool, THE Config_Manager SHALL NOT automatically deploy the rules to the pool's sensors. Deployment remains an explicit operator action.
4. THE Config_Manager SHALL display the currently assigned Ruleset on the pool detail page and on the Rulesets page.
5. WHEN a User with the `rules:manage` Permission removes a Ruleset assignment from a pool, THE Config_Manager SHALL delete the Pool_Ruleset_Assignment and record an Audit_Entry with action `ruleset_unassigned_from_pool`.
6. THE Config_Manager SHALL provide a pool assignment interface on the Ruleset detail page showing all pools and their current assignment status.

### Requirement 8: Rule Deployment from Rulesets

**User Story:** As a rule manager, I want to deploy a pool's assigned ruleset to its sensors, so that detection content changes take effect on the network.

#### Acceptance Criteria

1. WHEN a User with the `rules:deploy` Permission initiates a rule deployment for a pool, THE Config_Manager SHALL compile the pool's assigned Ruleset into Suricata rule files (one file per included category, plus an override file for explicit SID includes/excludes).
2. THE Config_Manager SHALL deploy the compiled rule files to all enrolled sensors in the pool using the existing `SensorAgentClient.push_rule_bundle/3` function.
3. WHEN a rule deployment succeeds for a sensor, THE Config_Manager SHALL update the sensor's `last_deployed_rule_version` to the Ruleset_Version that was deployed.
4. THE Config_Manager SHALL record an Audit_Entry with action `rules_deployed` containing the pool name, Ruleset name, Ruleset_Version, and per-sensor results.
5. THE Config_Manager SHALL display a "Deploy Rules" button on the pool detail page and on the Ruleset detail page, visible only to Users whose Role includes the `rules:deploy` Permission.
6. WHEN no Ruleset is assigned to a pool, THE Config_Manager SHALL disable the "Deploy Rules" button and display a message indicating no ruleset is assigned.

### Requirement 9: Deployed Rule Version Tracking

**User Story:** As a rule manager, I want to see which rule version is deployed to each pool and sensor, so that I can verify detection content is current.

#### Acceptance Criteria

1. THE Config_Manager SHALL display the Deployed_Rule_Version on the pool detail page alongside the currently assigned Ruleset_Version.
2. THE Config_Manager SHALL display the Deployed_Rule_Version on the sensor detail page for each sensor that has received a rule deployment.
3. WHEN the Deployed_Rule_Version does not match the assigned Ruleset_Version for a pool, THE Config_Manager SHALL display a visual indicator (badge or icon) on the pool list page and pool detail page indicating the pool's rules are out of sync.
4. THE Config_Manager SHALL expose a rule deployments page at `/rules/deployments` accessible to all authenticated Users with the `sensors:view` Permission, showing a history of rule deployments with: timestamp, operator, pool name, Ruleset name, Ruleset_Version, and per-sensor result summary.

### Requirement 10: Out-of-Sync Sensor Detection

**User Story:** As a rule manager, I want to detect sensors whose deployed rules do not match the pool's current ruleset version, so that I can identify and remediate rule drift.

#### Acceptance Criteria

1. THE Config_Manager SHALL compare each sensor's `last_deployed_rule_version` against the pool's assigned Ruleset_Version to determine sync status.
2. WHEN a sensor's `last_deployed_rule_version` is NULL or does not match the pool's assigned Ruleset_Version, THE Config_Manager SHALL classify the sensor as an Out_Of_Sync_Sensor.
3. THE Config_Manager SHALL display out-of-sync sensor counts on the pool detail page and pool list page.
4. THE Config_Manager SHALL display per-sensor sync status on the pool sensors page, showing each sensor's deployed rule version and whether it matches the assigned Ruleset_Version.
5. WHEN a User views the rule deployments page, THE Config_Manager SHALL highlight pools with out-of-sync sensors.

### Requirement 11: RBAC Integration

**User Story:** As a platform admin, I want rule store management actions protected by role-based access control, so that only authorized users can modify detection content.

#### Acceptance Criteria

1. THE Config_Manager SHALL use the existing `rules:manage` Permission for rule store write operations (toggle rules, toggle categories, manage repositories, manage rulesets, assign rulesets to pools).
2. THE Config_Manager SHALL use the existing `rules:deploy` Permission for rule deployment operations.
3. THE Config_Manager SHALL grant read-only rule store access (`sensors:view`) to all authenticated Roles, consistent with the existing permission model.
4. WHEN a User without the `rules:manage` Permission attempts a rule store write action via LiveView event, THE RBAC_Gate SHALL deny the action, display an error flash, and record an Audit_Entry with action `permission_denied`.
5. THE Config_Manager SHALL hide rule store write UI elements from Users whose Role does not include the `rules:manage` Permission.
6. THE Config_Manager SHALL enforce RBAC on every LiveView `handle_event` callback for rule store write actions, regardless of whether the UI element is hidden.

### Requirement 12: Audit Logging

**User Story:** As an auditor, I want all rule store management actions recorded in the audit log, so that detection content changes are traceable and attributable.

#### Acceptance Criteria

1. THE Config_Manager SHALL record an Audit_Entry for each of the following actions: `rule_toggled`, `category_toggled`, `repository_added`, `repository_updated`, `repository_update_failed`, `repository_deleted`, `ruleset_created`, `ruleset_updated`, `ruleset_deleted`, `ruleset_assigned_to_pool`, `ruleset_unassigned_from_pool`, and `rules_deployed`.
2. EACH rule-store-related Audit_Entry SHALL contain: the actor identity, the actor type, the action name, the target type and target ID, the result, and a JSON detail field with action-specific context.
3. THE Config_Manager SHALL write rule-store-related Audit_Entries within the same database transaction as the mutation, so that if the audit write fails, the mutation is rolled back.
4. WHEN a bulk operation affects multiple rules (category toggle, bulk enable/disable), THE Config_Manager SHALL record a single summary Audit_Entry containing the total affected count rather than one entry per rule.

### Requirement 13: Navigation Integration

**User Story:** As a user, I want rule store management integrated into the existing navigation, so that I can easily access rule management pages from the Config Manager.

#### Acceptance Criteria

1. THE Config_Manager SHALL add a "Rules" section to the main navigation with sub-links to: Rule Store (`/rules/store`), Categories (`/rules/categories`), Repositories (`/rules/repositories`), Rulesets (`/rules/rulesets`), and Deployments (`/rules/deployments`).
2. THE Config_Manager SHALL preserve the existing paste-and-deploy page at `/rules` as a "Quick Deploy" action accessible from the Rules navigation section.
3. THE Config_Manager SHALL display the assigned Ruleset name and sync status on the pool detail page.
4. THE Config_Manager SHALL display the deployed rule version on the sensor detail page.

### Requirement 14: Existing Paste-and-Deploy Preservation

**User Story:** As a rule manager, I want the existing paste-and-deploy workflow preserved, so that I can still quickly push ad-hoc rules without going through the full ruleset workflow.

#### Acceptance Criteria

1. THE Config_Manager SHALL preserve the existing rule deployment page at `/rules` with its current paste-and-deploy functionality.
2. THE Config_Manager SHALL update the rule deployment page to display pool names instead of raw pool UUIDs in the target dropdown.
3. WHEN a User deploys rules via the paste-and-deploy page, THE Config_Manager SHALL record an Audit_Entry with action `adhoc_rules_deployed` containing the target, filename, and rule count.
4. THE Config_Manager SHALL label the paste-and-deploy page as "Quick Deploy" in the navigation to distinguish it from the managed ruleset deployment workflow.

### Requirement 15: Deferred Capabilities

**User Story:** As a product owner, I want deferred rule management capabilities documented, so that the team knows what is planned for Phase D.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement YARA rule management in this feature. YARA support is deferred to Phase D.
2. THE Config_Manager SHALL NOT implement Zeek package management in this feature. Zeek package support is deferred to Phase D.
3. THE Config_Manager SHALL NOT implement automatic scheduled repository polling in this feature. Repository updates are manual-only via the "Update Now" button. Scheduled polling is deferred to a future enhancement.
4. THE Config_Manager SHALL NOT implement rule suppression or threshold editing in this feature. These are deferred to a future Suricata advanced configuration spec.
