# Implementation Plan: Interface Switching

## Overview

Extend the Sensor_Agent (Go) with a `switch-interface` control action, an Interface Monitor sub-module, and coordinated rebind orchestration in the Capture Manager. Extend the Config_Manager (Elixir/Phoenix LiveView) with an interface selector UI, health-stream switch event handling, a `desired_interface` database field, and drift detection. All 14 correctness properties from the design are covered by property-based tests using `rapid` (Go) and `PropCheck` (Elixir).

---

## Tasks

- [ ] 1. Extend gRPC protobuf schema for interface inventory and switch events
  - Add `InterfaceInfo`, `InterfaceInventory`, and `SwitchEvent` messages to the existing protobuf schema
  - Add `interfaces` (field 7) and `switch_event` (field 8) to the `HealthReport` message
  - Regenerate Go stubs; update Elixir protobuf decoders in Config_Manager
  - _Requirements: 1.1, 1.2, 3.5, 3.6_

- [ ] 2. Implement Interface Monitor sub-module in Sensor_Agent (Go)
  - [ ] 2.1 Implement interface enumeration and inventory builder
    - Use `net.Interfaces()` to enumerate all host interfaces
    - Check link state via `SIOCGIFFLAGS`; probe AF_PACKET support via a short-lived probe socket bind
    - Populate `InterfaceInfo` fields: `Name`, `LinkUp`, `AFPacketOK`, `IsLoopback`, `IsActive`
    - Return a complete `InterfaceInventory` with `ActiveIface` and `LastRefreshed`
    - _Requirements: 1.1, 1.2_

  - [ ]* 2.2 Write property test for interface inventory completeness (Property 1)
    - **Property 1: Interface Inventory Completeness**
    - Generate arbitrary lists of mock interface descriptors; assert the built inventory contains an entry for every interface with all required fields (`Name`, `LinkUp`, `AFPacketOK`, `IsLoopback`) non-zero/non-nil
    - **Validates: Requirements 1.1, 1.2**

  - [ ] 2.3 Wire Interface Monitor into the health report assembly loop
    - Poll at configurable interval (default 30s); include `InterfaceInventory` in every `HealthReport`
    - On inventory change between polls, emit an updated health report immediately
    - _Requirements: 1.3, 1.4, 1.5_

- [ ] 3. Implement `switch-interface` control action handler in Sensor_Agent (Go)
  - [ ] 3.1 Add `switch-interface` to the control API allowlist
    - Register `POST /control/switch-interface` as the 10th allowlisted route
    - Parse `{"target_interface": "<name>"}` request body
    - Return 202 on validation pass (async); return 400/409/422 on synchronous rejection
    - _Requirements: 2.1_

  - [ ] 3.2 Implement interface name validation
    - Accept names that are non-empty, ≤15 characters, and composed only of alphanumeric characters, hyphens, underscores, or dots
    - Reject loopback interfaces with `INVALID_INTERFACE / loopback`
    - Reject names identical to the current active interface with `SAME_INTERFACE`
    - _Requirements: 2.2, 2.3, 6.3, 6.4_

  - [ ]* 3.3 Write property test for interface name validation (Property 3)
    - **Property 3: Interface Name Validation**
    - Generate arbitrary strings; assert `ValidateInterfaceName` accepts if and only if the string is non-empty, ≤15 chars, and matches `[a-zA-Z0-9._-]+`; assert all non-conforming names are rejected with a descriptive error
    - **Validates: Requirements 6.2, 6.3**

  - [ ] 3.4 Implement busy flag check and Host_Readiness_Check invocation
    - Check `operationInProgress` mutex before any state-mutating work; return HTTP 409 `BUSY` if set
    - Set the busy flag; invoke the existing `HostReadinessChecker` for the target interface
    - On readiness failure, clear the busy flag and return HTTP 422 with the specific failed check
    - _Requirements: 2.4, 2.5, 6.1_

  - [ ]* 3.5 Write property test for validation-precedes-rebind (Property 2)
    - **Property 2: Validation Precedes Rebind**
    - Generate invalid/ineligible target interface descriptors (non-existent, link down, no AF_PACKET, loopback, same as current); assert `HandleSwitchInterface` returns a structured error AND `mockCapture.RebindCallCount == 0` for every generated case
    - **Validates: Requirements 2.2, 2.3, 2.4, 2.5**

  - [ ]* 3.6 Write property test for busy flag mutual exclusion (Property 9)
    - **Property 9: Busy Flag Mutual Exclusion**
    - Generate concurrent control operation types (BPF reload, config apply, cert rotation, capture mode switch, interface switch); set the busy flag, then send a `switch-interface` request; assert HTTP 409 `BUSY` is returned and `RebindCallCount == 0`
    - **Validates: Requirements 6.1**

  - [ ] 3.7 Log every switch request to the local audit log
    - Write a JSON-lines audit entry for every `switch-interface` request: timestamp, actor CN from mTLS cert, target interface, outcome (accepted/rejected/completed/rolled_back)
    - _Requirements: 2.6_

  - [ ]* 3.8 Write property test for switch audit log completeness (Property 10)
    - **Property 10: Switch Audit Log Completeness**
    - Generate arbitrary switch request outcomes (accepted, rejected, completed, rolled back); assert the audit log contains an entry for every request with actor identity, target interface, and outcome fields present
    - **Validates: Requirements 2.6, 5.8**

- [ ] 4. Implement coordinated rebind orchestrator in Capture Manager (Go)
  - [ ] 4.1 Implement `RebindAll(targetIface string) error` in Capture Manager
    - Stop Zeek (SIGTERM, wait up to 10s; force-kill on timeout), Suricata (same), pcap_ring_writer (Unix socket `stop`, wait up to 5s)
    - For each consumer: create new AF_PACKET socket on `targetIface`, apply existing BPF filter profile, join existing fanout group ID
    - On any bind failure, immediately invoke rollback; return error with `failed_consumer` and `failure_reason`
    - Start consumers in order: pcap_ring_writer → Suricata → Zeek
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [ ]* 4.2 Write property test for stop-all-before-start-any ordering (Property 4)
    - **Property 4: Stop-All-Before-Start-Any Ordering**
    - Instrument mock consumers with event logs; generate valid switch scenarios; assert that in the recorded event sequence, all `stop` events for every consumer precede any `start` event on the new interface
    - **Validates: Requirements 3.2, 3.4**

  - [ ]* 4.3 Write property test for capture parameter preservation (Property 5)
    - **Property 5: Capture Parameter Preservation Across Switch and Rollback**
    - Generate arbitrary `CaptureParams` (BPF profile + fanout group map); set them on the agent; execute a switch; assert `mockCapture.LastAppliedParams().BPFProfile` and `FanoutGroups` are identical to the originals on both success and rollback paths
    - **Validates: Requirements 3.3, 4.2**

  - [ ] 4.4 Implement rollback logic in `RebindAll`
    - On bind failure: attempt to rebind every consumer (including those that succeeded) back to `previous_iface` using the same BPF profile and fanout groups
    - On successful rollback: start all successfully rebound consumers; emit `switch_failed` health stream event with `ROLLED_BACK` outcome
    - On rollback failure: halt all consumers; emit `ROLLBACK_FAILED` health stream event; log critical error
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ]* 4.5 Write property test for partial failure triggers full rollback (Property 7)
    - **Property 7: Partial Failure Triggers Rollback for All Consumers**
    - Generate switch scenarios where exactly one consumer fails to bind; assert that all consumers (including those that succeeded) are rolled back to the previous interface, and no consumer remains on the target interface
    - **Validates: Requirements 4.1**

  - [ ]* 4.6 Write property test for double failure halts all consumers (Property 8)
    - **Property 8: Double Failure Halts All Consumers**
    - Generate scenarios where both the forward switch and the rollback fail; assert all consumers are halted and a `ROLLBACK_FAILED` event is emitted with no consumer left in an indeterminate bind state
    - **Validates: Requirements 4.4**

  - [ ] 4.7 Handle active PCAP carve before rebind
    - Before initiating the stop sequence, check if pcap_ring_writer has an active carve in progress
    - Wait up to the configured post-alert window duration for the carve to complete; abort if it exceeds the timeout
    - _Requirements: 6.5_

- [ ] 5. Persist active interface in Sensor_Agent (Go)
  - [ ] 5.1 Add `active_interface` field to `last-known-config.json` read/write
    - Write `active_interface` to `/etc/sensor/last-known-config.json` immediately after a successful `RebindAll`
    - On startup, read `active_interface` from the file and run `HostReadinessChecker` against it before binding any consumer
    - If the startup readiness check fails, log a critical error and halt capture startup without binding to any fallback
    - _Requirements: 7.1, 7.5_

  - [ ]* 5.2 Write property test for startup halt on bad persisted interface (Property 14)
    - **Property 14: Startup Halt on Bad Persisted Interface**
    - Generate `last-known-config.json` values with interface names that fail the Host_Readiness_Check; assert Sensor_Agent logs a critical error and halts capture startup without binding any consumer to a fallback interface
    - **Validates: Requirements 7.5**

  - [ ] 5.3 Include active interface in reconnection health report
    - Ensure the `InterfaceInventory.active_interface` field is populated in the first health report sent after a reconnect
    - _Requirements: 7.2_

- [ ] 6. Checkpoint — Sensor_Agent interface switching complete
  - Ensure all Sensor_Agent unit tests and property tests pass
  - Verify `switch-interface` appears in the allowlist and unknown actions still return 403
  - Verify busy flag correctly serializes concurrent control operations
  - Ask the user if questions arise.

- [ ] 7. Add `desired_interface` migration and schema update in Config_Manager (Elixir)
  - [ ] 7.1 Write Ecto migration to add `desired_interface` column to `sensor_pods`
    - `alter table(:sensor_pods) do add :desired_interface, :string end`
    - _Requirements: 5.7_

  - [ ] 7.2 Update `SensorPod` Ecto schema to include `desired_interface` field
    - Add `field :desired_interface, :string` to the schema
    - Update changesets to permit the new field
    - _Requirements: 5.7_

- [ ] 8. Extend Config_Manager Health Aggregator for switch events (Elixir)
  - [ ] 8.1 Deserialize `InterfaceInventory` and `SwitchEvent` from incoming `HealthReport` protobuf messages
    - Update the gRPC health stream server to decode the new fields 7 and 8
    - Update the in-memory Sensor Registry state per pod with the latest inventory and any switch event
    - _Requirements: 1.3, 3.5_

  - [ ] 8.2 Handle `switch_complete` event
    - On `SwitchEvent.outcome == SUCCESS`: update the pod's displayed active interface, clear `switch_state = :in_progress`, persist `desired_interface` to the database
    - _Requirements: 5.5, 5.7_

  - [ ] 8.3 Handle `switch_failed` and `switch_rolled_back` events
    - On `FAILED` or `ROLLED_BACK`: clear `switch_state`, surface failure reason and restored interface in the LiveView assign
    - On `ROLLBACK_FAILED`: mark pod as degraded; do not re-enable the switch control until the pod recovers
    - _Requirements: 4.5, 5.6_

  - [ ]* 8.4 Write property test for LiveView state transitions on switch events (Property 12)
    - **Property 12: LiveView State Transitions on Switch Events**
    - Generate arbitrary `switch_complete`, `switch_failed`, and `switch_rolled_back` events; assert that after processing each event the LiveView assigns reflect the correct active interface, in-progress state, and error message per the event type
    - **Validates: Requirements 5.5, 5.6**

- [ ] 9. Implement drift detection on reconnection (Elixir)
  - [ ] 9.1 Compare reported `active_interface` against `desired_interface` on reconnect
    - When a reconnection health report arrives, compare `InterfaceInventory.active_interface` with `sensor_pods.desired_interface`
    - If they differ, set a `drift_detected` flag in the LiveView assign and surface the discrepancy in the UI
    - Do NOT send a `switch-interface` command automatically
    - _Requirements: 7.3, 7.4_

  - [ ]* 9.2 Write property test for drift detection without auto-remediation (Property 13)
    - **Property 13: Drift Detection Without Automatic Remediation**
    - Generate pairs of `{reported_interface, desired_interface}` where the two values differ; assert `drift_detected == true` and `switch_commands_sent == 0` after processing the reconnection report
    - **Validates: Requirements 7.3, 7.4**

- [ ] 10. Implement interface selector LiveView component in Config_Manager (Elixir)
  - [ ] 10.1 Add active interface display to the per-pod health dashboard entry
    - Show the currently active `Monitored_Interface` label on each pod's dashboard card
    - Show drift warning badge when `drift_detected` is true
    - _Requirements: 5.1_

  - [ ] 10.2 Implement interface selection dropdown and switch button
    - Render a dropdown populated from `InterfaceInventory.interfaces` for the pod
    - Disable (but show) interfaces where `link_up == false`, `af_packet_ok == false`, or `is_loopback == true`
    - Disable the dropdown and button while `switch_state == :in_progress`; show a spinner
    - Show a confirmation modal before dispatching the `switch-interface` action
    - _Requirements: 5.2, 5.3, 5.4_

  - [ ]* 10.3 Write property test for in-progress state disables duplicate requests (Property 11)
    - **Property 11: In-Progress State Prevents Duplicate Requests**
    - Generate LiveView socket assigns with `switch_state == :in_progress`; assert the rendered HTML contains `disabled` on both the dropdown and the switch button for that pod
    - **Validates: Requirements 5.4**

  - [ ] 10.4 Implement client-side interface name validation before dispatch
    - Validate the selected interface name is non-empty and matches Linux IFNAMSIZ constraints before sending the action
    - Display an inline validation error without sending to the Sensor_Agent on failure
    - _Requirements: 6.2_

  - [ ] 10.5 Implement switch outcome display
    - On `switch_complete`: update the active interface label via LiveView push; clear spinner
    - On `switch_failed` / `switch_rolled_back`: show error banner with failure reason and restored interface name; re-enable the control
    - On `ROLLBACK_FAILED`: show critical error banner; keep control disabled
    - On `BUSY` response from Sensor_Agent: show "Another operation is in progress, please retry"; re-enable immediately
    - _Requirements: 5.5, 5.6, 4.5_

  - [ ] 10.6 Write audit log entry for every switch attempt in Config_Manager
    - Record operator identity, source interface, target interface, and outcome for every switch attempt
    - _Requirements: 5.8_

- [ ] 11. Checkpoint — end-to-end interface switching complete
  - Ensure all Config_Manager unit tests and property tests pass
  - Verify the interface selector renders correctly for pods with populated inventories
  - Verify `desired_interface` is persisted after a successful switch and survives a Config_Manager restart
  - Verify drift detection surfaces a discrepancy without sending an auto-switch command
  - Verify the full switch flow: select interface → confirm → in-progress spinner → success update
  - Verify rollback flow: mock consumer bind failure → rollback → error banner → control re-enabled
  - Ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster build
- Property tests use [rapid](https://github.com/flyingmutant/rapid) (Go) for Sensor_Agent properties and [PropCheck](https://github.com/alfert/propcheck) (Elixir) for Config_Manager properties
- Each property test is tagged `// Feature: interface-switching, Property N: <title>` for traceability
- The Config_Manager must never access the Podman socket directly; all consumer lifecycle operations go through the Sensor_Agent control API
- The `switch-interface` action is asynchronous: the 202 response confirms validation passed; completion is reported via the health stream
- The busy flag serializes all control operations — BPF reload, config apply, cert rotation, capture mode switch, and interface switch cannot interleave
