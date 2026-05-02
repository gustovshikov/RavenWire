# Requirements Document: Sensor Pool Management

## Introduction

The RavenWire Config Manager has a `sensor_pools` table and a `SensorPool` Ecto schema, and the `sensor_pods` table references pools via a `pool_id` foreign key. The rule deployment page can target "all pods in pool," but there is no web UI for creating pools, assigning sensors to pools, viewing pool membership, or managing pool-level configuration profiles. Pool IDs shown in the rule deployment dropdown are raw UUIDs extracted from enrolled pods, with no human-readable context.

This feature adds a complete pool management workflow to the Config Manager web UI: CRUD operations on pools, sensor-to-pool assignment and removal, pool-level configuration profiles (capture mode and PCAP settings), pool detail views with member sensor listings, and pool-scoped deployment history. The feature integrates with the existing RBAC system from the auth-rbac-audit spec and links to the sensor detail page from the sensor-detail-page spec.

Canary rollout, automated rollback, and drift detection are recognized as valuable capabilities but are deferred to the Versioned Configuration Management spec or Phase B. This spec references them as future work without including them as requirements.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Pool**: A named grouping of Sensor_Pods that share a common configuration profile. Stored in the `sensor_pools` table.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager. Stored in the `sensor_pods` table. Each Sensor_Pod has an optional `pool_id` foreign key referencing a Sensor_Pool.
- **Pool_Config_Profile**: The set of configuration fields on a Sensor_Pool record that define the desired state for all member Sensor_Pods: capture mode, PCAP ring size, pre-alert window, post-alert window, and alert severity threshold.
- **Pool_Context**: The Elixir context module (`ConfigManager.Pools`) that provides the public API for pool CRUD, sensor assignment, and pool queries.
- **Capture_Mode**: The operational mode for a Sensor_Pod's packet capture pipeline. One of `alert_driven` (capture around alerts only) or `full_pcap` (continuous full packet capture).
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that enforces role-based access on routes and LiveView events.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who performed what action, when, on which target, and whether it succeeded.
- **Unassigned_Sensor**: A Sensor_Pod whose `pool_id` is `NULL`, meaning it does not belong to any Sensor_Pool.
- **Pool_Member_Count**: The count of Sensor_Pods whose `pool_id` references a given Sensor_Pool, regardless of enrollment status. UI views may also show enrolled, pending, and revoked breakdowns for operator clarity.
- **Config_Version**: An integer on the Sensor_Pool record that increments each time the Pool_Config_Profile is updated, providing a simple monotonic version counter.

## Requirements

### Requirement 1: Pool List Page

**User Story:** As a sensor operator, I want to see all sensor pools in a single list view, so that I can understand how the fleet is organized and navigate to individual pools.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a pool list page at `/pools` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display each Sensor_Pool as a row containing: pool name, capture mode, Pool_Member_Count, Config_Version, last config update timestamp, and last config update actor.
3. WHEN the pool list page loads, THE Config_Manager SHALL sort Sensor_Pools alphabetically by name as the default order.
4. THE Config_Manager SHALL display a "Create Pool" button on the pool list page, visible only to Users whose Role includes the `pools:manage` Permission.
5. WHEN a User clicks a Sensor_Pool row on the list page, THE Config_Manager SHALL navigate to the pool detail page at `/pools/:id`.
6. WHEN no Sensor_Pools exist, THE Config_Manager SHALL display an empty state message indicating no pools have been created and prompting the User to create one.

### Requirement 2: Pool Creation

**User Story:** As a sensor operator, I want to create new sensor pools, so that I can organize sensors into logical groups for fleet management.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a pool creation page at `/pools/new` accessible only to Users whose Role includes the `pools:manage` Permission.
2. WHEN a User submits the pool creation form with a valid pool name and capture mode, THE Config_Manager SHALL create a new Sensor_Pool record with Config_Version set to 1, initialize the pool configuration defaults, set config update metadata to the creating actor and timestamp, and record an Audit_Entry with action `pool_created`.
3. THE Config_Manager SHALL trim leading and trailing whitespace from the pool name and validate that the normalized pool name is between 1 and 255 characters, contains only alphanumeric characters, hyphens, underscores, and periods, and is unique across all Sensor_Pools using a case-insensitive comparison.
4. IF a User submits a pool name that already exists, THEN THE Config_Manager SHALL display a validation error indicating the name is already taken without creating a duplicate record.
5. THE Config_Manager SHALL default the capture mode to `alert_driven` on the creation form.
6. WHEN pool creation succeeds, THE Config_Manager SHALL redirect the User to the new pool's detail page at `/pools/:id`.

### Requirement 3: Pool Detail Page

**User Story:** As a sensor operator, I want a dedicated detail page for each pool, so that I can see pool configuration, member sensors, and navigate to pool-specific management views.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a pool detail page at `/pools/:id` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display the following pool information on the detail page: pool name, capture mode, Config_Version, config last updated timestamp, config last updated by actor, creation timestamp, and Pool_Member_Count.
3. THE Config_Manager SHALL display navigation links on the pool detail page to: pool configuration (`/pools/:id/config`), pool sensors (`/pools/:id/sensors`), and pool deployments (`/pools/:id/deployments`).
4. IF the requested pool ID does not exist, THEN THE Config_Manager SHALL render a 404 page with a "Pool not found" message.
5. THE Config_Manager SHALL display an "Edit Pool" button on the detail page, visible only to Users whose Role includes the `pools:manage` Permission.
6. THE Config_Manager SHALL display a "Delete Pool" button on the detail page, visible only to Users whose Role includes the `pools:manage` Permission.

### Requirement 4: Pool Editing

**User Story:** As a sensor operator, I want to edit a pool's name and basic settings, so that I can rename pools or correct configuration as the fleet evolves.

#### Acceptance Criteria

1. WHEN a User with the `pools:manage` Permission submits an edit to a Sensor_Pool's name or description, THE Config_Manager SHALL update the basic pool metadata and record an Audit_Entry with action `pool_updated` containing the old and new values.
2. THE Config_Manager SHALL apply the same name normalization and validation rules on edit as on creation: trimmed name, 1-255 characters, alphanumeric plus hyphens, underscores, and periods, and case-insensitive uniqueness across all Sensor_Pools.
3. IF a User submits an edit that changes the pool name to one already used by another Sensor_Pool, THEN THE Config_Manager SHALL display a validation error and reject the change.
4. WHEN a pool edit succeeds, THE Config_Manager SHALL redirect the User back to the pool detail page.

### Requirement 5: Pool Deletion

**User Story:** As a sensor operator, I want to delete a pool that is no longer needed, so that the pool list stays clean and reflects the current fleet organization.

#### Acceptance Criteria

1. WHEN a User with the `pools:manage` Permission requests deletion of a Sensor_Pool, THE Config_Manager SHALL display a confirmation dialog stating the pool name and the number of Sensor_Pods currently assigned to the pool, including a warning that member sensors will become unassigned.
2. WHEN the User confirms deletion, THE Config_Manager SHALL delete the Sensor_Pool record, set the `pool_id` to NULL on all Sensor_Pods that referenced the deleted pool (as enforced by the existing `on_delete: :nilify_all` foreign key constraint), and record an Audit_Entry with action `pool_deleted` containing the affected sensor count.
3. WHEN pool deletion succeeds, THE Config_Manager SHALL redirect the User to the pool list page at `/pools`.
4. THE Config_Manager SHALL NOT allow deletion of a Sensor_Pool while a deployment to that pool is actively in progress, if deployment tracking is available from the rule deployment system.

### Requirement 6: Sensor Assignment to Pool

**User Story:** As a sensor operator, I want to assign sensors to a pool, so that newly enrolled sensors join the correct fleet group and inherit the pool's desired configuration profile for future explicit deployment.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a pool sensors page at `/pools/:id/sensors` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display a list of all Sensor_Pods currently assigned to the pool, showing: sensor name, enrollment status, last seen timestamp, and a link to the sensor detail page at `/sensors/:sensor_id`.
3. WHEN a User with the `pools:manage` Permission clicks "Assign Sensors," THE Config_Manager SHALL display a selection interface listing all Unassigned_Sensors (Sensor_Pods with a NULL `pool_id`) that have a status of `enrolled`.
4. WHEN a User selects one or more Unassigned_Sensors and confirms assignment, THE Config_Manager SHALL update each selected Sensor_Pod's `pool_id` to the current Sensor_Pool's ID and record an Audit_Entry with action `sensor_assigned_to_pool` for each sensor, including the sensor name, previous pool ID, new pool ID, and pool name in the detail field.
5. IF the UI offers a "Move from another pool" option, THEN THE Config_Manager SHALL list enrolled Sensor_Pods currently assigned to other pools separately from Unassigned_Sensors and require explicit confirmation before changing their `pool_id`.
6. THE Config_Manager SHALL display an "Assign Sensors" button on the pool sensors page, visible only to Users whose Role includes the `pools:manage` Permission.
7. WHEN a Sensor_Pod is assigned or moved to a pool, THE Config_Manager SHALL NOT automatically push the pool configuration to that Sensor_Pod. The UI SHALL indicate that assignment changes desired state only and that deployment remains an explicit operator action.

### Requirement 7: Sensor Removal from Pool

**User Story:** As a sensor operator, I want to remove sensors from a pool, so that I can reorganize the fleet or decommission sensors from a group without deleting the pool.

#### Acceptance Criteria

1. WHEN a User with the `pools:manage` Permission selects one or more Sensor_Pods on the pool sensors page and clicks "Remove from Pool," THE Config_Manager SHALL set the `pool_id` to NULL on each selected Sensor_Pod and record an Audit_Entry with action `sensor_removed_from_pool` for each sensor, including the previous pool ID and pool name.
2. THE Config_Manager SHALL display a confirmation dialog before removing sensors, stating the number of sensors being removed and the pool name.
3. WHEN sensor removal succeeds, THE Config_Manager SHALL update the pool sensors list to reflect the removal without a full page reload.
4. THE Config_Manager SHALL display a "Remove from Pool" action for each sensor row or as a bulk action, visible only to Users whose Role includes the `pools:manage` Permission.

### Requirement 8: Pool Configuration Profile

**User Story:** As a sensor operator, I want to define a configuration profile at the pool level, so that all sensors in the pool share consistent capture and PCAP settings instead of requiring per-sensor configuration.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a pool configuration page at `/pools/:id/config` accessible to Users with the `pools:manage` Permission for write actions and `sensors:view` Permission for read-only viewing.
2. THE Config_Manager SHALL display the current Pool_Config_Profile fields on the configuration page: capture mode (`alert_driven` or `full_pcap`), PCAP ring size in MB, pre-alert window in seconds, post-alert window in seconds, and alert severity threshold (1=low, 2=medium, 3=high).
3. WHEN a User with the `pools:manage` Permission submits a configuration change, THE Config_Manager SHALL update the Sensor_Pool record, increment the Config_Version, set the `config_updated_at` timestamp and `config_updated_by` actor, and record an Audit_Entry with action `pool_config_updated` containing the changed fields with old and new values.
4. THE Config_Manager SHALL validate pool configuration values using the same rules as the existing per-pod PCAP configuration: PCAP ring size greater than 0, pre-alert and post-alert windows greater than or equal to 0, alert severity threshold in {1, 2, 3}, and capture mode in {`alert_driven`, `full_pcap`}.
5. WHEN a pool configuration change is saved, THE Config_Manager SHALL NOT automatically push the new configuration to member Sensor_Pods. Configuration deployment is a separate explicit action performed through the existing rule deployment workflow or a future versioned configuration deployment system.
6. THE Config_Manager SHALL display the Config_Version and last update metadata on the configuration page so operators can see when the profile was last changed and by whom.
7. THE Config_Manager SHALL increment Config_Version only when the Pool_Config_Profile fields change, not when basic metadata such as pool name or description changes.

### Requirement 9: Pool Deployment History View

**User Story:** As a sensor operator, I want to see a history of deployments targeting a pool, so that I can understand what configuration and rules have been pushed to the pool's sensors over time.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a pool deployments page at `/pools/:id/deployments` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display deployment-related Audit_Entries filtered to the current pool, showing: timestamp, actor, action type, result, and a summary of the deployment target and outcome.
3. THE Config_Manager SHALL query the `audit_log` table for entries where `target_type` is `pool` and `target_id` matches the current Sensor_Pool's ID, sorted in reverse chronological order.
4. THE Config_Manager SHALL paginate the deployment history with a default page size of 25 entries.
5. WHEN no deployment history exists for a pool, THE Config_Manager SHALL display an empty state message indicating no deployments have been recorded for the pool.
6. THE Config_Manager SHALL limit this view to deployment action names, including `rule_deployed` and future explicit pool configuration deployment actions, and SHALL NOT mix routine pool CRUD or saved-but-not-deployed configuration changes into the deployment history.

### Requirement 10: RBAC Integration

**User Story:** As a platform admin, I want pool management actions protected by role-based access control, so that only authorized users can create, modify, or delete pools and assign sensors.

#### Acceptance Criteria

1. THE Config_Manager SHALL use the canonical `pools:manage` Permission from the auth-rbac-audit spec for pool write operations (create, edit, delete, assign sensors, remove sensors, update pool configuration).
2. THE Config_Manager SHALL verify that the auth-rbac-audit Policy grants `pools:manage` to the `sensor-operator`, `rule-manager`, and `platform-admin` Roles.
3. THE Config_Manager SHALL grant read-only pool access (`sensors:view`) to all authenticated Roles, consistent with the existing sensor viewing permission model.
4. WHEN a User without the `pools:manage` Permission navigates to `/pools/new` or attempts a pool write action via LiveView event, THE RBAC_Gate SHALL deny the action, display a 403 page or error flash, and record an Audit_Entry with action `permission_denied`.
5. THE Config_Manager SHALL hide pool write UI elements (Create Pool button, Edit Pool button, Delete Pool button, Assign Sensors button, Remove from Pool action, configuration save button) from Users whose Role does not include the `pools:manage` Permission.
6. THE Config_Manager SHALL enforce RBAC on every LiveView `handle_event` callback for pool write actions, regardless of whether the UI element is hidden.

### Requirement 11: Audit Logging for Pool Actions

**User Story:** As an auditor, I want all pool management actions recorded in the audit log, so that fleet organization changes are traceable and attributable.

#### Acceptance Criteria

1. THE Config_Manager SHALL record an Audit_Entry for each of the following pool actions: `pool_created`, `pool_updated`, `pool_deleted`, `pool_config_updated`, `sensor_assigned_to_pool`, and `sensor_removed_from_pool`.
2. EACH pool-related Audit_Entry SHALL contain: the actor identity (username or API_Token name), the actor type, the action name, `target_type` set to `pool`, `target_id` set to the Sensor_Pool's ID, the result (`success` or `failure`), and a JSON detail field with action-specific context including affected field values.
3. WHEN a sensor assignment or removal action affects multiple Sensor_Pods, THE Config_Manager SHALL record a separate Audit_Entry for each affected Sensor_Pod, with `target_type` set to `sensor_pod` and `target_id` set to the Sensor_Pod's ID, in addition to a summary entry for the pool.
4. THE Config_Manager SHALL write pool-related Audit_Entries within the same database transaction as the pool mutation, so that if the audit write fails, the pool mutation is rolled back.
5. WHEN a pool mutation fails validation or cannot complete, THE Config_Manager SHALL record a failure Audit_Entry when an actor and target can be identified, without exposing sensitive internal error details in the user-facing message.

### Requirement 12: Navigation Integration

**User Story:** As a user, I want pool management integrated into the existing navigation, so that I can easily find and access pool pages from anywhere in the Config Manager.

#### Acceptance Criteria

1. THE Config_Manager SHALL add a "Pools" link to the main navigation bar, visible to all authenticated Users, linking to `/pools`.
2. THE Config_Manager SHALL display the pool name as a link on the sensor detail page's identity section when the Sensor_Pod has a non-NULL `pool_id`, linking to `/pools/:pool_id`.
3. THE Config_Manager SHALL display pool names instead of raw pool UUIDs in the rule deployment target dropdown, by querying Sensor_Pool records to resolve names.
4. WHEN a Sensor_Pod's pool assignment changes, THE Config_Manager SHALL broadcast a pool assignment update for the affected Sensor_Pod so the sensor detail page can reflect the updated pool name without requiring a full page reload.

### Requirement 13: Pool Schema Extension

**User Story:** As an engineer implementing pool management, I want the Sensor_Pool schema extended with PCAP configuration fields, so that the pool configuration profile can define the desired PCAP settings for all member sensors.

#### Acceptance Criteria

1. THE Config_Manager SHALL add the following fields to the `sensor_pools` table via a new Ecto migration: `pcap_ring_size_mb` (integer, default 4096), `pre_alert_window_sec` (integer, default 60), `post_alert_window_sec` (integer, default 30), and `alert_severity_threshold` (integer, default 2).
2. THE Config_Manager SHALL add an optional `description` text field to the `sensor_pools` table for operators to document the pool's purpose.
3. THE Config_Manager SHALL preserve the existing `config_version`, `config_updated_at`, and `config_updated_by` fields and SHALL use them as the Pool_Config_Profile metadata displayed throughout the pool UI.
4. THE Config_Manager SHALL enforce case-insensitive uniqueness for Sensor_Pool names at the database layer, either by using a normalized name column or a database-supported case-insensitive unique index.
5. THE Config_Manager SHALL update the `SensorPool` Ecto schema to include the new fields with appropriate changesets and validations matching the existing per-pod PCAP validation rules.
6. THE Config_Manager SHALL preserve backward compatibility with existing Sensor_Pool records by using column defaults for all new fields and a migration that backfills missing config metadata where needed.

### Requirement 14: Realtime Behavior and UI Quality

**User Story:** As an operator using pool management during active testing, I want pages to stay current and usable, so that I can trust what I see without manually refreshing every view.

#### Acceptance Criteria

1. THE Config_Manager SHALL update pool list member counts, pool sensors membership, and sensor detail pool identity through LiveView state updates or PubSub messages after assignment, removal, deletion, or pool rename actions.
2. THE Config_Manager SHALL ignore pool update messages for unrelated pool IDs or Sensor_Pod IDs so that open LiveViews do not display stale cross-pool data.
3. THE Config_Manager SHALL provide accessible labels, confirmation text, and keyboard-reachable controls for pool create, edit, delete, assignment, removal, and configuration forms.
4. THE Config_Manager SHALL render pool list, detail, sensors, and configuration pages without horizontal overflow at common desktop and mobile widths.

### Requirement 15: Test Coverage and Verification

**User Story:** As an engineer implementing pool management, I want explicit test expectations, so that pool behavior is verified and regressions are caught before deployment.

#### Acceptance Criteria

1. THE Config_Manager SHALL include migration or schema tests proving the new `sensor_pools` fields, defaults, constraints, and indexes are present.
2. THE Config_Manager SHALL include allow/deny tests for every route and LiveView event protected by `pools:manage`.
3. THE Config_Manager SHALL include CRUD tests for pool creation, edit, deletion, and validation failures, including case-insensitive name uniqueness.
4. THE Config_Manager SHALL include sensor assignment, reassignment, and removal tests proving `pool_id` changes and Audit_Entries are written in the same transaction.
5. THE Config_Manager SHALL include tests proving pool configuration updates increment Config_Version and basic metadata updates do not.
6. THE Config_Manager SHALL include LiveView tests proving membership changes update the relevant open views without a full page reload.

### Requirement 16: Deferred Capabilities

**User Story:** As a product owner, I want deferred pool capabilities documented, so that the team knows what is planned for future phases without overloading the current implementation.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement canary rollout (deploying configuration to a subset of pool members before full rollout) in this feature. Canary rollout is deferred to the Versioned Configuration Management spec or Phase B.
2. THE Config_Manager SHALL NOT implement automated rollback (reverting pool configuration to a previous version on failure) in this feature. Rollback is deferred to the Versioned Configuration Management spec or Phase B.
3. THE Config_Manager SHALL NOT implement drift detection (comparing each Sensor_Pod's actual running configuration against the pool's desired Pool_Config_Profile) in this feature. Drift detection is deferred to Phase B.
4. THE Config_Manager SHALL NOT implement automatic configuration push on pool config save. Deploying pool configuration to member sensors remains an explicit operator action through the existing deployment workflow.
