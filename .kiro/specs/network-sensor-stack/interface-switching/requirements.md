# Requirements Document: Interface Switching

## Introduction

This feature extends the Network Sensor Stack to allow an operator to view and change the monitored network interface for a Sensor_Pod directly from the Config_Manager web UI, without requiring manual environment variable edits, pod restarts, or SSH access to the host. The monitored interface is the mirror/TAP port from which Zeek, Suricata, and pcap_ring_writer each bind their own AF_PACKET socket. Changing the interface requires all three capture consumers to rebind their sockets to the new interface; the Sensor_Agent mediates this operation through its existing narrow control API.

The feature must preserve the Sensor_Stack's core security invariant: the Config_Manager never accesses the Podman socket directly, and all container lifecycle operations are mediated exclusively through the Sensor_Agent's control API.

---

## Glossary

- **Monitored_Interface**: The network interface (mirror/TAP port) to which all AF_PACKET capture consumers in a Sensor_Pod bind their sockets. Currently set via environment variable at pod startup.
- **Interface_Switch**: The operation of changing the Monitored_Interface for a running Sensor_Pod from one interface name to another, coordinated by the Sensor_Agent.
- **Capture_Consumer**: Any process in the Sensor_Pod that holds an AF_PACKET socket bound to the Monitored_Interface: Zeek, Suricata, and pcap_ring_writer.
- **switch-interface**: The new Sensor_Agent control API action that orchestrates an Interface_Switch across all active Capture_Consumers.
- **Interface_Inventory**: The set of network interfaces available on the Sensor_Pod host that are eligible for use as a Monitored_Interface, as reported by the Sensor_Agent.
- **Config_Manager**: The Elixir/Phoenix LiveView web application running in the Management_Pod, providing real-time health visibility and configuration management for all Sensor_Pods.
- **Sensor_Agent**: The Go binary running in each Sensor_Pod that is the sole process with Podman socket access and the sole mediator of all container lifecycle and configuration operations.
- **Sensor_Pod**: The Podman pod hosting Zeek, Suricata, Vector, Sensor_Agent, and pcap_ring_writer for a single monitored network segment.
- **mTLS**: Mutual TLS — the transport security mode used for all pod-to-pod communication in the Sensor_Stack.
- **AF_PACKET socket**: The Linux kernel socket type used by each Capture_Consumer to receive raw packets from the Monitored_Interface.
- **Fanout_Group**: A PACKET_FANOUT group ID assigned to a Capture_Consumer's AF_PACKET socket for intra-tool worker scaling. Each consumer has a distinct, validated group ID.
- **BPF_Filter**: A Berkeley Packet Filter program applied per AF_PACKET socket to drop elephant flows before packets reach userspace.
- **Host_Readiness_Check**: The pre-capture validation performed by the Sensor_Agent to confirm that a target interface exists, has link state, and supports AF_PACKET before binding any consumer socket.

---

## Requirements

### Requirement 1: Interface Inventory Discovery

**User Story:** As a network security engineer, I want the Config_Manager to display the available network interfaces on each Sensor_Pod, so that I can select a valid target interface before initiating a switch.

#### Acceptance Criteria

1. THE Sensor_Agent SHALL enumerate all network interfaces present on the host and report the Interface_Inventory to the Config_Manager as part of its health report.
2. THE Interface_Inventory SHALL include, for each interface: the interface name, link state (up/down), and whether the interface currently supports AF_PACKET socket binding.
3. THE Config_Manager SHALL display the Interface_Inventory for each Sensor_Pod in the management UI, updated within 2 seconds of any change in the reported inventory without a page refresh.
4. WHEN an interface in the Interface_Inventory transitions from up to down or becomes unavailable, THE Config_Manager SHALL reflect the updated state in the UI within 2 seconds.
5. THE Sensor_Agent SHALL refresh the Interface_Inventory at a configurable polling interval (default 30 seconds) and report changes to the Config_Manager via the existing health stream.

---

### Requirement 2: Interface Switch Control Action

**User Story:** As a network security engineer, I want the Sensor_Agent to expose a dedicated interface-switch control action, so that the Config_Manager can request an interface change through the existing narrow control API without requiring any new privileged access paths.

#### Acceptance Criteria

1. THE Sensor_Agent SHALL add `switch-interface` to its permitted control API action list, accepting a payload containing the target interface name.
2. WHEN the Config_Manager sends a `switch-interface` action, THE Sensor_Agent SHALL validate the target interface name before performing any rebind operation.
3. THE Sensor_Agent SHALL reject a `switch-interface` request with a descriptive error if the target interface: does not exist on the host, has no link (is down), does not support AF_PACKET socket binding, or is identical to the currently active Monitored_Interface.
4. THE Sensor_Agent SHALL perform the Host_Readiness_Check for the target interface — validating interface existence, link state, NIC driver AF_PACKET compatibility, and required Linux capabilities — before initiating any Capture_Consumer rebind.
5. IF the Host_Readiness_Check for the target interface fails, THEN THE Sensor_Agent SHALL return a structured error to the Config_Manager identifying which check failed, and SHALL leave all Capture_Consumers bound to the current Monitored_Interface without interruption.
6. THE Sensor_Agent SHALL log every `switch-interface` request (accepted or rejected) to the local audit log, including the requesting actor identity (from the mTLS certificate CN), the requested target interface, and the outcome.

---

### Requirement 3: Coordinated Capture Consumer Rebind

**User Story:** As a network security engineer, I want the interface switch to rebind all capture consumers atomically and in a defined order, so that no consumer is left bound to the old interface while others are already capturing from the new one.

#### Acceptance Criteria

1. WHEN a `switch-interface` action is validated and approved, THE Sensor_Agent SHALL orchestrate the rebind of all active Capture_Consumers (Zeek, Suricata, pcap_ring_writer) to the target interface in a defined sequence.
2. THE Sensor_Agent SHALL stop all active Capture_Consumers before rebinding any of them to the new interface, ensuring no consumer captures from the old interface while another is already bound to the new one.
3. THE Sensor_Agent SHALL apply the existing BPF_Filter profile and Fanout_Group assignments to each Capture_Consumer's new AF_PACKET socket on the target interface, preserving all validated capture parameters.
4. THE Sensor_Agent SHALL start all Capture_Consumers on the new interface only after all consumers have successfully released their sockets on the old interface.
5. WHEN all Capture_Consumers have successfully rebound to the new interface, THE Sensor_Agent SHALL update the active Monitored_Interface record and report the completed switch to the Config_Manager via the health stream.
6. THE total elapsed time from receiving a valid `switch-interface` request to all Capture_Consumers actively capturing on the new interface SHALL be reported by the Sensor_Agent in the switch completion event.

---

### Requirement 4: Switch Failure Handling and Rollback

**User Story:** As a network security engineer, I want the interface switch to roll back to the previous interface if any step fails, so that a failed switch attempt does not leave the Sensor_Pod in a state where no capture is occurring.

#### Acceptance Criteria

1. IF any Capture_Consumer fails to bind its AF_PACKET socket to the target interface during a switch, THEN THE Sensor_Agent SHALL attempt to rebind all Capture_Consumers to the previously active Monitored_Interface.
2. WHEN a rollback is initiated, THE Sensor_Agent SHALL attempt to restore all Capture_Consumers to the previous interface using the same BPF_Filter profile and Fanout_Group assignments that were active before the switch was attempted.
3. WHEN a rollback completes successfully, THE Sensor_Agent SHALL report the rollback outcome to the Config_Manager, including which consumer failed and the reason, and SHALL resume normal health reporting on the restored interface.
4. IF the rollback also fails (the previous interface is no longer available), THEN THE Sensor_Agent SHALL log a critical error, report the degraded state to the Config_Manager, and halt all Capture_Consumers rather than leaving any consumer in an indeterminate bind state.
5. THE Config_Manager SHALL surface a switch failure or rollback event in the management UI as a distinct error condition on the affected Sensor_Pod, with the failure reason visible to the operator.

---

### Requirement 5: Config_Manager Interface Switch UI

**User Story:** As a network security engineer, I want a dedicated interface switching control in the Config_Manager web UI, so that I can change the monitored interface for any Sensor_Pod without leaving the browser or editing configuration files.

#### Acceptance Criteria

1. THE Config_Manager SHALL display the currently active Monitored_Interface for each Sensor_Pod on the health dashboard.
2. THE Config_Manager SHALL provide a per-Sensor_Pod interface selection control that presents the Interface_Inventory reported by that pod's Sensor_Agent, allowing the operator to select a target interface from the available options.
3. WHEN an operator selects a target interface and confirms the switch, THE Config_Manager SHALL send a `switch-interface` action to the affected Sensor_Agent over the mTLS control API.
4. THE Config_Manager SHALL display the in-progress switch state on the affected Sensor_Pod's dashboard entry while the Sensor_Agent is executing the rebind sequence, preventing duplicate switch requests to the same pod.
5. WHEN the Sensor_Agent reports a successful switch, THE Config_Manager SHALL update the displayed active Monitored_Interface and clear the in-progress state without a page refresh.
6. WHEN the Sensor_Agent reports a switch failure or rollback, THE Config_Manager SHALL display the failure reason and the restored interface name, and SHALL re-enable the interface selection control for a subsequent attempt.
7. THE Config_Manager SHALL persist the last successfully applied Monitored_Interface per Sensor_Pod in its database so that the value survives a Config_Manager container restart.
8. THE Config_Manager SHALL record every interface switch attempt (successful or failed) in the audit log, including the operator identity, the source interface, the target interface, and the outcome.

---

### Requirement 6: Interface Switch Validation and Safety Constraints

**User Story:** As a network security engineer, I want the system to enforce safety constraints before and during an interface switch, so that operators cannot accidentally switch to an interface that would break capture or create a security gap.

#### Acceptance Criteria

1. THE Sensor_Agent SHALL reject a `switch-interface` request if the Sensor_Pod is currently executing another control operation (e.g., a BPF filter reload, a config apply, or a certificate rotation), returning a descriptive busy error to the Config_Manager.
2. THE Config_Manager SHALL validate that the selected target interface name is non-empty and contains only characters valid for Linux interface names before sending the `switch-interface` action to the Sensor_Agent.
3. THE Sensor_Agent SHALL validate that the target interface name contains only characters valid for Linux interface names (alphanumeric, hyphen, underscore, dot; maximum 15 characters per IFNAMSIZ constraint) and reject names that do not conform.
4. THE Sensor_Agent SHALL verify that the target interface is not a loopback interface and SHALL reject any request to switch to a loopback interface with a descriptive error.
5. WHERE the Sensor_Pod is operating in Alert_Driven_Mode with an active Rolling_PCAP_Ring carve in progress, THE Sensor_Agent SHALL complete or abort the in-progress carve before initiating the Capture_Consumer rebind sequence.
6. THE Sensor_Agent SHALL re-validate all existing Fanout_Group IDs and BPF_Filter profiles against the target interface before starting any Capture_Consumer on the new interface, applying the same validation rules used at initial startup.

---

### Requirement 7: Persistence and Reconciliation

**User Story:** As a platform engineer, I want the active monitored interface to be persisted and reconciled on reconnection, so that a temporary loss of connectivity between the Sensor_Agent and Config_Manager does not result in configuration drift.

#### Acceptance Criteria

1. THE Sensor_Agent SHALL persist the active Monitored_Interface name to its last-known-config file (`/etc/sensor/last-known-config.json`) immediately after a successful Interface_Switch, so that the correct interface is used if the Sensor_Agent restarts.
2. WHEN the Sensor_Agent reconnects to the Config_Manager after a period of disconnection, THE Sensor_Agent SHALL include the currently active Monitored_Interface in its reconnection health report.
3. WHEN the Config_Manager receives a reconnection health report, THE Config_Manager SHALL compare the reported active Monitored_Interface against its persisted desired interface for that Sensor_Pod and SHALL surface any discrepancy to the operator in the UI.
4. THE Config_Manager SHALL NOT automatically re-issue a `switch-interface` command to resolve a discrepancy detected on reconnection; resolution SHALL require explicit operator action.
5. WHEN the Sensor_Agent starts and the last-known-config specifies a Monitored_Interface that fails the Host_Readiness_Check, THE Sensor_Agent SHALL log a critical error and halt capture startup rather than binding to a fallback interface silently.
