# Requirements Document: Multi-Manager High Availability Status

## Introduction

The RavenWire Config Manager currently operates as a single instance. In production deployments, operators may run multiple Config Manager instances behind a load balancer for high availability. However, the current system provides no visibility into whether multiple instances are running, which instance is the primary (leader), whether configuration state is synchronized between instances, or whether failover is functioning correctly.

This feature adds high availability status visibility and monitoring to the Config Manager. It does not implement the HA architecture itself (leader election, state replication, failover mechanisms) — those are infrastructure-level concerns that depend on the deployment topology (active-passive, active-active, shared database, replicated database). Instead, this feature provides the UI and monitoring layer that surfaces HA status information, assuming the underlying HA infrastructure reports its state through a defined interface.

New LiveView pages at `/admin/ha` and `/admin/ha/status` display HA cluster status, leader election state, configuration sync status, and failover health. Platform alerts are generated when HA conditions degrade (split-brain detected, sync lag exceeded, failover unhealthy). This feature depends on status reported by a configured provider; it does not create HA guarantees by itself.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **HA_Cluster**: The set of Config Manager instances operating together for high availability. May consist of 2 or more instances.
- **Instance**: A single running Config Manager process, identified by a unique Instance_ID (hostname or configured identifier).
- **Leader**: The Config Manager instance currently responsible for write operations, deployment orchestration, and sensor communication. In an active-passive topology, only the leader handles mutations.
- **Follower**: A Config Manager instance that is running but not currently the leader. Followers may serve read-only UI requests or remain on standby.
- **Leader_Election**: The process by which the HA_Cluster determines which instance is the leader. The election mechanism is outside the scope of this spec.
- **Sync_Status**: The state of configuration data synchronization between instances. One of: `in_sync`, `syncing`, `lag_detected`, `sync_failed`, `unknown`.
- **Sync_Lag**: The delay between a write on the leader and its replication to a follower, measured in seconds or number of pending operations.
- **Failover**: The process of promoting a follower to leader when the current leader becomes unavailable.
- **Split_Brain**: A condition where multiple instances believe they are the leader simultaneously, risking conflicting writes.
- **HA_Status_Provider**: An Elixir behaviour module that the HA infrastructure implements to report cluster status to the Config Manager UI. This spec defines the behaviour contract; the implementation is deferred.
- **Sensor_Pool**: A named grouping of Sensor_Pods from the sensor-pool-management spec.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager.
- **Alert_Engine**: The GenServer from the platform-alert-center spec that evaluates alert conditions.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec.
- **Audit_Entry**: An append-only record in the `audit_log` table.

## Requirements

### Requirement 1: HA Status Dashboard

**User Story:** As a platform administrator, I want to see the high availability status of my Config Manager cluster, so that I can verify all instances are healthy and synchronized.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose an HA status page at `/admin/ha` accessible only to Users with the `system:manage` Permission (`platform-admin` Role only).
2. THE Config_Manager SHALL display a cluster overview showing: number of instances in the HA_Cluster, current leader Instance_ID, this instance's role (leader or follower), cluster health status (healthy, degraded, critical), and last status update timestamp.
3. THE Config_Manager SHALL display a table of all known instances showing: Instance_ID, role (leader/follower), status (online/offline/unknown), last heartbeat timestamp, uptime, and Sync_Status.
4. WHEN the Config_Manager is running as a single instance (no HA configured), THE Config_Manager SHALL display a "Single Instance" status page indicating HA is not configured, with guidance on enabling HA.
5. THE Config_Manager SHALL update the HA status display in real time via PubSub as instance status changes are reported.
6. THE Config_Manager SHALL display the HA status page even when the current instance is a follower, showing read-only cluster status.
7. THE Config_Manager SHALL expose `/admin/ha/status` as either an alias of `/admin/ha` or a focused status endpoint/page using the same `system:manage` authorization and HA_Status_Provider data.

### Requirement 2: Leader Election Visibility

**User Story:** As a platform administrator, I want to see which instance is the current leader and when the last election occurred, so that I can verify leader election is functioning correctly.

#### Acceptance Criteria

1. THE Config_Manager SHALL display the current leader's Instance_ID, the timestamp of the last leader election, and the reason for the last election (initial startup, previous leader timeout, manual failover, or network partition recovery).
2. THE Config_Manager SHALL display a leader election history showing the last 10 elections with: timestamp, previous leader, new leader, and election reason.
3. WHEN the HA_Status_Provider reports a leader election that has not previously been recorded by this Config_Manager instance, THE Config_Manager SHALL record an Audit_Entry with action `ha_leader_elected` containing the new leader Instance_ID, previous leader Instance_ID, and election reason.
4. WHEN the current instance transitions from follower to leader, THE Config_Manager SHALL display a prominent banner indicating the role change.
5. THE Config_Manager SHALL display a warning when no leader has been elected (cluster in startup or recovery state).

### Requirement 3: Configuration Sync Monitoring

**User Story:** As a platform administrator, I want to see the synchronization status between Config Manager instances, so that I can verify all instances have consistent configuration data.

#### Acceptance Criteria

1. THE Config_Manager SHALL display the Sync_Status for each follower instance: `in_sync` (all data replicated), `syncing` (replication in progress), `lag_detected` (replication delayed beyond threshold), `sync_failed` (replication error), or `unknown` (status not reported).
2. THE Config_Manager SHALL display the Sync_Lag for each follower instance as a duration (seconds) and/or operation count.
3. WHEN the Sync_Lag for any follower exceeds a configurable threshold (default: 30 seconds), THE Config_Manager SHALL display a warning indicator on the HA status page.
4. THE Config_Manager SHALL display the last successful sync timestamp for each follower instance.
5. THE Config_Manager SHALL display which data domains are being synchronized: sensor enrollment, pool configuration, detection content, forwarding configuration, BPF profiles, and audit log.
6. WHEN the configured HA_Status_Provider cannot report Sync_Status for a follower, THE Config_Manager SHALL display `unknown` rather than assuming the follower is healthy or unhealthy.

### Requirement 4: Failover Monitoring and Alerting

**User Story:** As a platform administrator, I want to be alerted when HA conditions degrade, so that I can take corrective action before a failover failure.

#### Acceptance Criteria

1. THE Config_Manager SHALL register the following HA-related Alert_Types in the Alert_Engine: `ha_instance_offline` (an instance has not sent a heartbeat within the configured timeout), `ha_sync_lag_exceeded` (a follower's sync lag exceeds the threshold), `ha_split_brain_detected` (multiple instances report as leader), and `ha_failover_failed` (a failover attempt did not complete successfully).
2. THE Config_Manager SHALL create default Alert_Rules for each HA Alert_Type: `ha_instance_offline` (severity `critical`, threshold 60 seconds), `ha_sync_lag_exceeded` (severity `warning`, threshold 30 seconds), `ha_split_brain_detected` (severity `critical`), `ha_failover_failed` (severity `critical`).
3. WHEN a split-brain condition is detected (multiple instances reporting as leader), THE Config_Manager SHALL display a critical banner on the HA status page and fire a `ha_split_brain_detected` alert.
4. THE Config_Manager SHALL auto-resolve HA alerts when the condition clears (instance comes back online, sync lag drops below threshold, split-brain resolved).
5. THE Config_Manager SHALL display active HA alerts on the HA status page alongside the cluster overview.
6. THE Config_Manager SHALL evaluate HA alert conditions from HA_Status_Provider data on a configurable interval (default: every 30 seconds), and SHALL not fire HA alerts when the SingleInstanceProvider is active.

### Requirement 5: HA Status Provider Contract

**User Story:** As an engineer implementing the HA architecture, I want a defined interface for reporting HA status to the Config Manager UI, so that the monitoring layer is decoupled from the HA implementation.

#### Acceptance Criteria

1. THE Config_Manager SHALL define an Elixir behaviour module `ConfigManager.HA.StatusProvider` with callbacks for: `cluster_status/0` (returns cluster overview), `instances/0` (returns list of instance statuses), `leader/0` (returns current leader info), `sync_status/1` (returns sync status for a specific instance), and `election_history/1` (returns recent elections with limit).
2. THE Config_Manager SHALL provide a default `ConfigManager.HA.SingleInstanceProvider` implementation that returns single-instance status for deployments without HA configured.
3. THE Config_Manager SHALL read the HA_Status_Provider module from application configuration under `:config_manager, :ha_status_provider`, defaulting to `ConfigManager.HA.SingleInstanceProvider`.
4. THE HA status pages SHALL call the configured HA_Status_Provider to retrieve cluster status, decoupling the UI from the HA implementation.
5. THE Config_Manager SHALL define the data structures returned by the HA_Status_Provider callbacks as typed structs with documentation.

### Requirement 6: HA Status on Dashboard

**User Story:** As a platform administrator, I want a quick HA health indicator on the main dashboard, so that I can see cluster status without navigating to the HA page.

#### Acceptance Criteria

1. WHEN HA is configured (more than one instance detected), THE Config_Manager SHALL display an HA status badge on the main dashboard showing: cluster health (healthy/degraded/critical), instance count, and current role of this instance.
2. THE HA status badge SHALL link to the full HA status page at `/admin/ha`.
3. WHEN HA is not configured, THE Config_Manager SHALL NOT display the HA status badge on the dashboard.
4. THE HA status badge SHALL update in real time via PubSub as cluster status changes.

### Requirement 7: Deferred Capabilities

**User Story:** As a product owner, I want deferred HA capabilities documented, so that the team knows what is planned for future phases.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement the actual HA infrastructure (leader election algorithm, state replication, automatic failover) in this feature. This spec provides the monitoring and UI layer only. The HA architecture is deferred to a dedicated infrastructure spec.
2. THE Config_Manager SHALL NOT implement manual failover triggers from the UI in this feature. Manual failover requires the HA infrastructure to be in place. Manual failover UI is deferred.
3. THE Config_Manager SHALL NOT implement cross-instance audit log replication in this feature. Audit log synchronization depends on the HA replication strategy. It is deferred to the HA infrastructure spec.
4. THE Config_Manager SHALL NOT implement instance-level configuration overrides (e.g., different settings per instance) in this feature. All instances are expected to share the same configuration. Per-instance configuration is deferred.
5. THE Config_Manager SHALL NOT implement geographic distribution or multi-region HA in this feature. The HA model assumes co-located instances. Multi-region HA is deferred to a future enhancement.
6. THE Config_Manager SHALL NOT implement automated HA testing or chaos engineering features in this feature. HA validation tooling is deferred.
