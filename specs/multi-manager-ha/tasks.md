# Implementation Plan: Multi-Manager High Availability Status

## Overview

Build a read-only HA status layer driven by a pluggable provider. Do not implement leader election, replication, failover, or manual promotion controls in this feature.

## Tasks

- [ ] 1. Define HA provider contract and data structs
  - [ ] 1.1 Create `ConfigManager.HA.StatusProvider` behaviour
  - [ ] 1.2 Create typed structs for cluster, instance, leader, sync, and election data
  - [ ] 1.3 Add enum validation helpers for health, role, status, sync status, and election reason
  - _Requirements: 5.1, 5.5_

- [ ] 2. Implement default single-instance provider
  - [ ] 2.1 Create `ConfigManager.HA.SingleInstanceProvider`
  - [ ] 2.2 Read instance ID from `RAVENWIRE_INSTANCE_ID` or hostname
  - [ ] 2.3 Return deterministic single-instance status with no sync lag and no election history
  - [ ] 2.4 Add unit tests proving single-instance status is stable and well-formed
  - _Requirements: 1.4, 5.2, 5.3_

- [ ] 3. Add election event persistence
  - [ ] 3.1 Create `ha_election_events` migration and schema
  - [ ] 3.2 Implement idempotent insert by provider event ID or deterministic event key
  - [ ] 3.3 Append `ha_leader_elected` audit entries only for newly inserted events
  - [ ] 3.4 Add property test for election audit idempotence
  - _Requirements: 2.2, 2.3_

- [ ] 4. Implement `ConfigManager.HA.Monitor`
  - [ ] 4.1 Supervise monitor under the application tree
  - [ ] 4.2 Poll configured provider every `RAVENWIRE_HA_STATUS_INTERVAL_MS` (default 30 seconds)
  - [ ] 4.3 Cache the latest snapshot and expose a read API for LiveViews
  - [ ] 4.4 Broadcast `{:ha_status_updated, snapshot}` on `"ha:status"`
  - [ ] 4.5 Handle provider errors without crashing
  - _Requirements: 1.5, 2.4, 3.6, 5.3, 5.4_

- [ ] 5. Integrate HA alert evaluation
  - [ ] 5.1 Register HA alert types and default rules
  - [ ] 5.2 Detect offline instances, sync lag, split brain, and failed failover
  - [ ] 5.3 Auto-resolve HA alerts when conditions clear
  - [ ] 5.4 Suppress all HA alerts for `SingleInstanceProvider`
  - [ ] 5.5 Add property tests for split-brain detection and single-instance suppression
  - _Requirements: 4.1-4.6_

- [ ] 6. Implement HA LiveView pages
  - [ ] 6.1 Create `HALive.StatusLive` for `/admin/ha`
  - [ ] 6.2 Support `/admin/ha/status` as an alias or focused view
  - [ ] 6.3 Render single-instance state, cluster overview, instance table, leader history, sync status, and active HA alerts
  - [ ] 6.4 Subscribe to `"ha:status"` for real-time updates
  - [ ] 6.5 Show follower-to-leader banner when the local role changes
  - _Requirements: 1.1-1.7, 2.1-2.5, 3.1-3.6_

- [ ] 7. Add dashboard HA badge
  - [ ] 7.1 Add compact badge to DashboardLive when HA is configured
  - [ ] 7.2 Hide badge for single-instance deployments
  - [ ] 7.3 Link badge to `/admin/ha`
  - [ ] 7.4 Update badge through PubSub
  - _Requirements: 6.1-6.4_

- [ ] 8. Wire routes and RBAC
  - [ ] 8.1 Add `/admin/ha` and `/admin/ha/status` routes with `system:manage`
  - [ ] 8.2 Verify `system:manage` is platform-admin only in auth-rbac-audit Policy
  - [ ] 8.3 Add LiveView tests for unauthorized access
  - _Requirements: 1.1, 1.7_

- [ ] 9. Final verification
  - [ ] 9.1 Run formatter
  - [ ] 9.2 Run HA unit, property, and LiveView tests
  - [ ] 9.3 Run alert integration tests
  - [ ] 9.4 Confirm no manual failover or HA infrastructure behavior was added
  - _Requirements: 7.1-7.6_

## Notes

- This feature is a monitoring surface only.
- Any real HA provider must implement `ConfigManager.HA.StatusProvider` in a later infrastructure spec.
