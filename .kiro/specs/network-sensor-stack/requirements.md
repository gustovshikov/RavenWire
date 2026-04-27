# Requirements Document

## Introduction

RavenWire is a containerized (Podman) network monitoring and analysis system for standing up and managing sensor pods. The MVP integrates Zeek, Suricata, Vector, Sensor_Agent, and pcap_ring_writer into a strict capture and analysis architecture. Each capture consumer attaches independently to the monitored interface using its own AF_PACKET socket and fanout group, with PACKET_FANOUT used for intra-tool scaling rather than inter-tool duplication.

The baseline deployment consists of two pod types: a **Management Pod** hosting the Config Manager, and one or more **Sensor Pods** each handling packet capture and analysis for a monitored network segment. Alert-Driven PCAP Mode is the MVP path. Full PCAP mode, Strelka, Arkime, and specialized capture engines are roadmap extensions.

> **Capture Architecture Note:** Each capture consumer (Zeek, Suricata, netsniff-ng) binds its own AF_PACKET socket to the monitored interface with a distinct fanout group ID. PACKET_FANOUT distributes traffic across each tool's internal worker threads for intra-tool scaling — it does not duplicate the stream between tools. All consumers receive the full traffic stream independently from the same mirrored/TAP interface. BPF filters are applied per-socket to shed elephant flows before packets reach userspace.

> **Alert-Driven PCAP Note:** Alert-Driven Mode uses a rolling pre/post-alert packet buffer rather than a simple flush-on-alert model. The Sensor_Pod maintains a configurable rolling packet history via a dedicated `pcap_ring_writer` process; on a qualifying alert, a configurable pre-alert and post-alert window is preserved and carved to disk, ensuring the full attack context including activity before the alert fired is captured.

> **Reference Implementation Note:** All forwarding destinations and storage backends are intentionally generic to support portability across deployments. The validated reference implementation targets Cribl Stream as the log pipeline intermediary forwarding to Splunk, and TrueNAS (NFS/iSCSI mount) as the bulk PCAP storage backend. Any compliant sink or storage target may be substituted.

> **Release Phasing:** Requirements are labeled with their target release phase: **[MVP]** (Phases 0–1), **[v1]** (Phase 2–3), **[v1.5]** (Phase 4), **[v2]** (Phase 5), **[future]** (Phase 6+). See the design document for the full release roadmap.

---

## Glossary

- **RavenWire**: The complete containerized network monitoring system described in this document.
- **Management_Pod**: The Podman pod hosting the Config_Manager. Runs once per deployment and serves all Sensor_Pods.
- **Sensor_Pod**: The Podman pod hosting Zeek, Suricata, Vector, and optionally netsniff-ng for a single monitored network segment. One or more Sensor_Pods connect to a shared Management_Pod.
- **Capture_Pipeline**: The subsystem responsible for receiving raw packets from the network interface via AF_PACKET and distributing them to analysis tools within a Sensor_Pod.
- **Analysis_Pipeline**: The subsystem comprising Zeek, Suricata, and Vector log processing in the MVP.
- **AF_PACKET socket/ring**: The Linux kernel AF_PACKET socket and associated ring buffer. Each capture consumer binds its own socket with a distinct fanout group ID; PACKET_FANOUT distributes traffic across that tool's internal worker threads. The term "AF_PACKET socket/ring" is used throughout to emphasize that each consumer has its own independent socket, not a shared ring.
- **BPF_Filter**: A Berkeley Packet Filter program applied per AF_PACKET socket to drop elephant flows in the kernel before packets are copied to userspace.
- **Elephant_Flow**: A high-volume, low-security-value traffic class (e.g., storage replication, encrypted media streams, trusted bulk transfers) that is a candidate for BPF_Filter exclusion.
- **Community_ID**: A standardized network flow hash (community-id spec) computed from the 5-tuple, used as a universal correlation key across Zeek logs, Suricata alerts, Strelka results, PCAP carve metadata, and downstream SIEM events.
- **Sensor_Agent**: A lightweight process running in each Sensor_Pod responsible for health reporting, local config application, Podman/systemd control, BPF validation, ruleset validation, PCAP carve execution, and certificate rotation. The Sensor_Agent is the only process with local Podman socket access.
- **Rolling_PCAP_Ring**: A fixed-size local packet history maintained by the Sensor_Pod in Alert-Driven Mode, used to preserve a configurable pre-alert and post-alert window when a qualifying alert fires.
- **Zeek**: The network protocol analysis engine responsible for generating connection logs and metadata.
- **Suricata**: The signature-based intrusion detection engine responsible for alert generation and, in Alert-Driven Mode, conditional PCAP capture.
- **Strelka**: The file extraction and analysis engine. Runs in the Management_Pod as a shared service for all Sensor_Pods.
- **Vector**: The log aggregation and routing agent running in each Sensor_Pod, responsible for collecting, transforming, and forwarding logs to downstream sinks.
- **netsniff-ng**: The dedicated full-packet capture tool, optionally active within a Sensor_Pod in Full PCAP Mode.
- **Config_Manager**: The Elixir/Phoenix LiveView web application running in the Management_Pod, providing real-time health visibility and configuration management for all Sensor_Pods.
- **Full_PCAP_Mode**: The operational mode in which netsniff-ng is active in a Sensor_Pod and writes all packets to storage; Suricata's internal PCAP engine is disabled.
- **Alert_Driven_Mode**: The operational mode in which netsniff-ng is inactive and the Sensor_Pod maintains a Rolling_PCAP_Ring; qualifying alerts trigger preservation of a pre/post-alert packet window to disk.
- **Node**: A single physical or virtual host running either a Management_Pod or a Sensor_Pod.
- **Sensor_Pool**: A named logical grouping of one or more Sensor_Pods that share a common configuration profile, including Suricata rulesets, Strelka scanner policies, BPF filter rules, and capture mode.
- **Rule_Repository**: A remote source of Suricata rules, Strelka YARA rules, or Zeek packages, identified by a URL and access credentials, polled on a configurable schedule by the Management_Pod.
- **Rule_Store**: The persistent, deduplicated local store of all Suricata rules, Strelka YARA rules, and Zeek packages managed by the Config_Manager in the Management_Pod.
- **PCAP_Carve**: A targeted extraction of packets from stored PCAP files matching a specific time range and 5-tuple, returned to a requesting client over HTTPS.
- **mTLS**: Mutual TLS — a transport security mode in which both client and server present certificates for authentication, used for all pod-to-pod communication in RavenWire.

---

## Requirements

### Requirement 1: Dual-Pod Baseline Deployment [MVP]

**User Story:** As a platform engineer, I want the stack to deploy as a Management Pod and one or more Sensor Pods from day one, so that shared services are always isolated from capture workloads and additional sensor pods can be added without architectural changes.

#### Acceptance Criteria

1. RavenWire SHALL deploy as exactly two pod types: one Management_Pod and one or more Sensor_Pods.
2. THE Management_Pod SHALL contain the Config_Manager container.
3. Each Sensor_Pod SHALL contain Sensor_Agent, Zeek, Suricata, Vector, and pcap_ring_writer containers.
4. THE Management_Pod and Sensor_Pods SHALL communicate over a defined network interface; all endpoints SHALL be configurable via environment variables or mounted configuration.
5. RavenWire SHALL define deployment container configurations as Podman Quadlet units that can be replicated across multiple Nodes without modification to container images.
6. All per-Node configuration (interface name, storage paths, forwarding destinations, Config_Manager address) SHALL be exposed exclusively through environment variables or mounted configuration files with no hardcoded Node-specific values in container images.
7. WHEN a new Sensor_Pod is provisioned with the same declarative configuration pointing at the existing Management_Pod, RavenWire SHALL begin operating on that Node without requiring changes to any existing Node's configuration.

---

### Requirement 2: AF_PACKET Capture with Per-Consumer Fanout and BPF Filtering [MVP]

**User Story:** As a network security engineer, I want each capture consumer in a Sensor Pod to attach independently to the monitored interface with its own AF_PACKET socket and BPF filter, so that PACKET_FANOUT scales each tool's internal workers without inter-tool coupling, and elephant flows are shed in the kernel before reaching any consumer.

#### Acceptance Criteria

1. THE Sensor_Pod SHALL expose a monitored interface capture policy allowing each authorized capture consumer (Zeek, Suricata, pcap_ring_writer, and netsniff-ng when enabled) to attach to the same interface using its own independent AF_PACKET socket configuration.
2. THE Sensor_Pod SHALL ensure all active capture consumers use distinct fanout group identifiers when PACKET_FANOUT is enabled. The default fanout group assignments are: Zeek = group 1, Suricata = group 2, netsniff-ng = group 3, pcap_ring_writer = group 4. All group IDs are configurable but must be distinct.
3. THE Sensor_Pod SHALL validate fanout group IDs, fanout modes, interface names, BPF filters, and capture thread counts for all consumers before starting any capture process; invalid configurations SHALL halt startup with a descriptive error.
4. WHEN the Sensor_Pod starts, THE Capture_Pipeline SHALL apply a configurable BPF_Filter to each consumer's AF_PACKET socket to drop Elephant_Flow traffic classes in the kernel before packets are copied to userspace.
5. THE BPF_Filter ruleset SHALL be configurable via a mounted filter file and SHALL support at minimum:
   - Storage replication protocols (iSCSI, NFS) between configurable trusted host pairs
   - Encrypted media streams identified by destination IP/port ranges
   - Configurable trusted internal bulk transfer flows by source/destination CIDR
6. WHEN the BPF_Filter file is updated, THE Sensor_Agent SHALL validate the new filter profile and apply it as follows: for pcap_ring_writer-owned sockets, the filter SHALL be applied or reloaded through the pcap_ring_writer control interface; for Zeek and Suricata, the Sensor_Agent SHALL write the updated tool-specific capture configuration and trigger a controlled capture reload. THE Sensor_Agent SHALL report whether each filter was applied live or required a socket rebind, and SHALL report the event to the Config_Manager.
7. **[MVP]** THE Sensor_Agent SHALL report capture validation status, active fanout group assignments, active BPF profile, and per-consumer packet/drop counters to the Config_Manager. **[v1]** THE Capture_Pipeline SHALL sustain packet processing at a throughput of at least 10Gbps without dropping security-relevant packets under nominal load on validated hardware. **[v2]** RavenWire SHALL validate 25Gbps operation on hardware meeting the 25Gbps benchmark profile.

---

### Requirement 3: Strict Pipeline Separation [MVP]

**User Story:** As a network security engineer, I want the Capture Pipeline and Analysis Pipeline to be strictly separated, so that a failure or resource spike in one does not degrade the other.

#### Acceptance Criteria

1. THE Sensor_Pod SHALL deploy the Capture_Pipeline and Analysis_Pipeline as distinct container groups with no shared writable volumes except explicitly defined handoff paths.
2. WHEN a container in the Analysis_Pipeline terminates unexpectedly, THE Sensor_Pod SHALL continue operating the Capture_Pipeline without interruption.
3. WHEN a container in the Capture_Pipeline terminates unexpectedly, THE Sensor_Pod SHALL log the failure and attempt to restart the affected container without restarting Analysis_Pipeline containers.
4. THE Sensor_Pod SHALL enforce resource limits (CPU and memory) on Analysis_Pipeline containers independently of Capture_Pipeline containers.

---

### Requirement 4: Full PCAP Mode [v1.5]

**User Story:** As a network security engineer, I want a dedicated full-packet capture mode, so that I can record all traffic to storage for forensic analysis without burdening the analysis tools.

#### Acceptance Criteria

1. WHEN Full_PCAP_Mode is active, THE Sensor_Pod SHALL deploy the netsniff-ng container consuming packets from the monitored network interface.
2. WHEN Full_PCAP_Mode is active, THE netsniff-ng container SHALL write captured packets to a designated high-capacity storage path in PCAP format, following a three-tier storage hierarchy:
   - Tier 0: local NVMe-backed ring buffer as the primary high-rate write target
   - Tier 1: local retained PCAP storage for indexed access
   - Tier 2: optional async replication to remote bulk storage (TrueNAS/S3/NFS/iSCSI) for archival and overflow; at 25Gbps, remote storage is not the primary capture target
3. WHEN Full_PCAP_Mode is active, THE Suricata container SHALL operate with its internal pcap-log module disabled.
4. WHEN Full_PCAP_Mode is active, THE Suricata container SHALL perform signature matching and produce JSON alert output only.
5. WHEN available storage at the designated PCAP path reaches a configurable critical threshold (default 90%), THE Sensor_Pod SHALL automatically delete the oldest PCAP files in FIFO order until storage drops below a configurable low-water mark, without halting the capture pipeline.
6. IF the FIFO pruning cannot reclaim sufficient space within a configurable timeout, THEN THE Sensor_Pod SHALL log a critical error and THE Config_Manager SHALL surface the condition in the management UI with the affected Sensor_Pod identified.
7. THE BPF_Filter SHALL be applied consistently to each active capture consumer socket so that Elephant_Flow traffic excluded from analysis is also excluded from PCAP storage.

---

### Requirement 5: Alert-Driven PCAP Mode [MVP]

**User Story:** As a network security engineer, I want a lightweight PCAP mode that preserves full attack context around alerts, so that I can run the sensor stack with reduced storage overhead while still capturing the packets before and after a qualifying alert fires.

#### Acceptance Criteria

1. WHEN Alert_Driven_Mode is active, THE Sensor_Pod SHALL ensure the netsniff-ng container is not running.
2. WHEN Alert_Driven_Mode is active, THE Sensor_Pod SHALL maintain a Rolling_PCAP_Ring — a fixed-size local packet history with a configurable retention window (default 60 seconds).
3. WHEN a qualifying alert fires, THE Sensor_Pod SHALL preserve a configurable pre-alert window and post-alert window of packets from the Rolling_PCAP_Ring and write them to disk as a PCAP file associated with the triggering alert, 5-tuple, and Community_ID.
4. THE preserved PCAP file SHALL contain packets from before the alert fired, ensuring attack context that preceded the detection is not lost.
5. WHEN no qualifying alert fires, THE Rolling_PCAP_Ring SHALL continuously overwrite the oldest packets without writing to disk.
6. THE Config_Manager SHALL allow an operator to configure the alert severity threshold, pre-alert window duration, post-alert window duration, and Rolling_PCAP_Ring size.
7. WHEN available storage for alert-driven PCAP files reaches a configurable critical threshold, THE Sensor_Pod SHALL automatically delete the oldest alert PCAP files in FIFO order until storage drops below a configurable low-water mark.

---

### Requirement 6: Zeek Protocol Analysis [MVP]

**User Story:** As a network security analyst, I want Zeek to generate structured connection and protocol logs, so that I can perform network traffic analysis and threat hunting.

#### Acceptance Criteria

1. WHEN the Sensor_Pod is running, THE Zeek container SHALL attach to the monitored interface using its configured AF_PACKET socket and Zeek-specific fanout group and produce structured JSON logs for all supported protocol analyzers.
2. THE Zeek container SHALL write logs to a path accessible to the Vector container for collection and forwarding.
3. IF the Zeek container loses access to its AF_PACKET socket, THEN THE Zeek container SHALL log the error and attempt reconnection at a configurable interval without exiting.

---

### Requirement 7: Suricata Signature Matching [MVP]

**User Story:** As a network security analyst, I want Suricata to perform signature-based detection, so that I can receive alerts on known threats traversing the monitored network.

#### Acceptance Criteria

1. WHEN the Sensor_Pod is running, THE Suricata container SHALL attach to the monitored interface using its configured AF_PACKET socket and Suricata-specific fanout group and evaluate packets against a loaded ruleset.
2. WHEN a packet matches a loaded rule, THE Suricata container SHALL emit a JSON alert record to a path accessible to the Vector container.
3. THE Suricata container SHALL load rules from a configurable rules directory mounted into the container.
4. WHEN the rules directory is updated, THE Suricata container SHALL reload rules without requiring a full container restart.

---

### Requirement 8: Strelka File Analysis with Cross-Sensor Sighting Tracking [v1]

**User Story:** As a network security analyst, I want Strelka to analyze each unique file once and record every sensor sighting separately, so that I get deduplicated analysis results without losing visibility into which network segments saw the same file.

#### Acceptance Criteria

1. WHEN Zeek or Suricata extracts a file from network traffic, THE Sensor_Pod SHALL submit the file to the Strelka frontend endpoint in the Management_Pod, configurable via environment variable.
2. WHEN a file is submitted, THE Strelka frontend SHALL deduplicate analysis by SHA256 hash within a configurable TTL window — if the file has been analyzed recently, the cached analysis result SHALL be returned without re-processing.
3. THE Strelka frontend SHALL record every sensor sighting of a deduplicated file separately, including the submitting Sensor_Pod identifier, flow 5-tuple, Community_ID, and submission timestamp, so that analysts can see all network segments where the file appeared.
4. WHEN a file is submitted, THE Strelka frontend SHALL return a structured analysis result (cached or fresh) within a configurable timeout.
5. IF THE Strelka frontend does not return a result within the configured timeout, THEN THE Sensor_Pod SHALL log the timeout and discard the pending submission without blocking further analysis.
6. THE Strelka frontend SHALL make analysis results and per-sighting metadata available to the Vector container on the submitting Sensor_Pod.
7. THE Strelka backend SHALL scale horizontally within the Management_Pod by running multiple worker containers consuming from a shared work queue.

---

### Requirement 9: Log Aggregation and Forwarding via Vector [MVP]

**User Story:** As a security operations engineer, I want all pipeline logs centralized and forwarded by Vector, so that I have a single, consistent data path to downstream SIEM or storage systems.

#### Acceptance Criteria

1. **[MVP]** THE Vector container in each Sensor_Pod SHALL collect log output from Zeek and Suricata. **[v1]** THE Vector container SHALL additionally collect Strelka result streams when Strelka is enabled.
2. THE Vector container SHALL apply a configurable transformation pipeline to normalize log formats before forwarding.
3. WHEN a downstream forwarding destination is unavailable, THE Vector container SHALL buffer log records locally up to a configurable size limit and resume forwarding when the destination becomes available.
4. IF the local buffer reaches its size limit, THEN THE Vector container SHALL drop the oldest records and emit a warning log.
5. THE Vector container SHALL expose a configurable set of forwarding sinks (e.g., syslog, HTTP, file) selectable via the Config_Manager.

---

### Requirement 10: Configuration Management Web Interface [MVP → v1]

**User Story:** As a network security engineer, I want a web-based interface that shows real-time health, live data flow, and full tool configuration for all sensor pods, so that I can monitor and manage the entire stack from a single interface without touching config files directly.

#### Acceptance Criteria

**[MVP] Basic Dashboard**

1. THE Config_Manager SHALL be implemented as an Elixir/Phoenix application using Phoenix LiveView for all real-time UI updates, running in the Management_Pod.
2. THE Config_Manager SHALL provide a web interface accessible on a configurable port and SHALL require authentication before allowing any configuration changes.
3. THE Config_Manager SHALL present a dashboard view showing all connected Sensor_Pods with their current operational status (running, stopped, error, restarting), updated via LiveView within 2 seconds of any state change without a page refresh.
4. THE Config_Manager SHALL display the following live health metrics per container across all Sensor_Pods, updated continuously via LiveView:
   - Container state and uptime
   - CPU and memory utilization
   - For Zeek and Suricata: packets received, packets dropped, and drop percentage from the AF_PACKET ring
   - For Vector: log records ingested per second and forwarding sink connectivity status
5. **[MVP]** THE Config_Manager SHALL display the active capture mode per Sensor_Pod and allow an operator to configure Alert-Driven PCAP settings (ring size, pre-alert window, post-alert window, alert severity threshold). **[v1.5]** THE Config_Manager SHALL allow switching any Sensor_Pod between Full_PCAP_Mode and Alert_Driven_Mode without a full pod restart.
6. WHEN an operator applies a mode change, THE Config_Manager SHALL send the mode change instruction to the Sensor_Agent on the affected Sensor_Pod; THE Sensor_Agent SHALL apply the change locally via its restricted control interface.
7. THE Config_Manager SHALL NOT have direct access to the Podman socket; all container lifecycle operations SHALL be mediated exclusively through the Sensor_Agent's narrow control API.

**[v1] Full Tool Configuration and Data Flow**

8. THE Config_Manager SHALL provide a live data flow visualization showing the active pipeline path: network interface → AF_PACKET ring → Zeek / Suricata → Strelka (when enabled) → Vector → forwarding sink, with live throughput or record rate on each segment.
9. WHEN a pipeline segment is degraded or a container is in error state, THE data flow visualization SHALL highlight the affected segment distinctly.
10. THE Config_Manager SHALL display additional live health metrics when the relevant components are enabled:
    - For Strelka: submission queue depth, active worker count, and deduplication cache hit rate
    - For netsniff-ng (when active): capture rate and available PCAP storage remaining
11. THE Config_Manager SHALL provide a per-Sensor_Pod configuration editor for each analysis tool, supporting at minimum:
    - Zeek: script policy selection, protocol analyzer enable/disable, log output path
    - Suricata: ruleset selection, alert severity threshold, Rolling_PCAP_Ring size, pre-alert window, and post-alert window
    - Strelka: file type scanner enable/disable, submission timeout, deduplication TTL
    - Vector: forwarding sink selection and endpoint configuration
    - BPF_Filter: elephant flow exclusion rules (add, remove, view active ruleset)
12. WHEN an operator saves a tool configuration change, THE Config_Manager SHALL persist the desired configuration state and send the change to the affected Sensor_Agent over the mTLS control API; THE Sensor_Agent SHALL write the updated configuration to the appropriate local config path, validate it, and signal the affected service to reload.
13. THE Config_Manager SHALL display the currently active configuration for each tool alongside the editable form so operators can compare running state to proposed changes.
14. IF a configuration change results in an invalid state (e.g., enabling both netsniff-ng and Suricata pcap-log simultaneously on the same Sensor_Pod), THEN THE Config_Manager SHALL reject the change and display a descriptive error to the operator.

---

### Requirement 11: Sensor Agent [MVP]

**User Story:** As a platform engineer, I want a dedicated Sensor Agent running in each Sensor Pod to mediate all local control operations, so that the Management Pod never requires direct host or Podman socket access and a compromised web UI cannot become a host-compromise path.

#### Acceptance Criteria

1. Each Sensor_Pod SHALL run a Sensor_Agent process responsible for: health metric collection and reporting, local config application, Podman/systemd container control, BPF filter validation and reload, ruleset validation and reload, PCAP carve execution, local storage reporting, certificate rotation, and local audit logging.
2. THE Sensor_Agent SHALL expose a narrow mTLS-authenticated control API to the Config_Manager accepting only explicitly defined actions: reload-zeek, reload-suricata, restart-vector, switch-capture-mode, apply-pool-config, rotate-cert, report-health, carve-pcap, validate-config.
3. THE Sensor_Agent SHALL be the only process in the Sensor_Pod with access to the local Podman socket; no other container SHALL mount or access the Podman socket.
4. WHEN the Config_Manager sends a control action, THE Sensor_Agent SHALL validate the action against its permitted action list and reject any action not in the list with a logged error.
5. THE Sensor_Agent SHALL stream health metrics to the Config_Manager using a persistent mTLS-authenticated WebSocket or gRPC stream; all config and lifecycle control operations SHALL use the mTLS REST control API.
6. WHEN the Management_Pod is unreachable, THE Sensor_Agent SHALL continue local capture operations using the last known valid configuration and SHALL buffer health metrics locally for reconciliation when connectivity is restored.
7. THE Sensor_Agent SHALL perform a host readiness check before enabling capture, validating: monitored interface existence and link state, NIC driver compatibility, disk write speed, available storage, time synchronization status, required Linux capabilities, and kernel AF_PACKET support.
8. THE Sensor_Agent SHALL be composed of the following internal functional modules: Control API, Health Collector, Config Applier, Capture Manager, PCAP Manager, Rule Validator, Certificate Manager, Local Audit Logger, and Host Readiness Checker.

---

### Requirement 12: Sensor Pool Management [v1]

**User Story:** As a network security engineer, I want to group Sensor_Pods into named pools with distinct configuration profiles, so that I can apply different Suricata rulesets, Strelka policies, and capture settings to different network segments without managing each sensor individually.

#### Acceptance Criteria

1. THE Config_Manager SHALL allow an operator to define named Sensor_Pools, each representing a logical grouping of one or more Sensor_Pods.
2. Each Sensor_Pod SHALL belong to exactly one Sensor_Pool at any given time; pool membership SHALL be assignable and reassignable via the Config_Manager without restarting the affected Sensor_Pod.
3. Each Sensor_Pool SHALL maintain an independent configuration profile containing at minimum:
   - Suricata ruleset selection and enabled rule categories
   - Suricata alert severity threshold
   - Strelka file type scanner enable/disable policy and submission timeout
   - BPF_Filter elephant flow exclusion ruleset
   - Active capture mode (Full_PCAP_Mode or Alert_Driven_Mode)
   - Zeek script policy selection
4. WHEN a pool-level configuration change is applied, THE Config_Manager SHALL propagate the updated configuration to all Sensor_Pods in that pool and signal each affected container to reload without a full restart.
5. THE Config_Manager SHALL display all Sensor_Pools on the dashboard, with per-pool aggregate health metrics and the list of member Sensor_Pods.
6. THE Config_Manager SHALL allow an operator to view and edit the configuration profile of any Sensor_Pool and SHALL display the currently active profile alongside the editable form.
7. IF a Sensor_Pod is moved between pools, THE Config_Manager SHALL apply the destination pool's configuration profile to that pod immediately upon reassignment.
8. THE Config_Manager SHALL support a default pool that newly provisioned Sensor_Pods are assigned to automatically if no explicit pool assignment is provided.
9. Pool configuration profiles SHALL be stored persistently in the Management_Pod so that they survive a Config_Manager container restart.

---

### Requirement 13: Rule Management for Suricata, Strelka (YARA), and Zeek [v1]

**User Story:** As a network security engineer, I want a centralized rule management system for Suricata signatures and Strelka YARA rules, so that I can maintain a deduplicated local rule store, pull updates from remote repositories on a schedule, and push specific rulesets to sensor pools without manually editing files on each node.

#### Acceptance Criteria

**Local Rule Store**

1. THE Management_Pod SHALL maintain a persistent Rule_Store containing all Suricata rules and Strelka YARA rules managed by RavenWire.
2. THE Rule_Store SHALL deduplicate rules by a stable rule identifier (Suricata SID for signatures, rule name/hash for YARA) so that the same rule sourced from multiple repositories is stored exactly once.
3. THE Config_Manager SHALL provide a UI view of all rules in the Rule_Store, filterable by type (Suricata / YARA), source repository, category, and enabled/disabled state.
4. THE Config_Manager SHALL allow an operator to manually upload individual Suricata rule files or YARA rule files directly into the Rule_Store.
5. THE Config_Manager SHALL allow an operator to enable, disable, or delete individual rules or entire rule categories within the Rule_Store without affecting rules sourced from other repositories.

**Remote Repository Management**

6. THE Config_Manager SHALL allow an operator to configure one or more named Rule_Repositories for each rule type (Suricata and YARA), specifying at minimum: URL, authentication credentials (stored securely), update schedule, and enabled/disabled state.
7. Supported Suricata Rule_Repository sources SHALL include at minimum: Emerging Threats (ET Open/Pro), Snort community rules, and arbitrary HTTP/HTTPS URLs returning a rules archive.
8. Supported YARA Rule_Repository sources SHALL include at minimum: arbitrary Git repositories and HTTP/HTTPS URLs returning a YARA rules archive.
9. THE Config_Manager SHALL support Zeek package management via zkg, allowing an operator to configure one or more Zeek package repositories (including the official Zeek package repository and arbitrary Git URLs) as Rule_Repository sources.
10. THE Config_Manager SHALL allow an operator to browse, install, enable, disable, and remove Zeek packages from the Rule_Store, and assign installed packages to Sensor_Pools as part of the pool configuration profile.
11. WHEN a Zeek package is added or updated, THE Config_Manager SHALL distribute the package to all Sensor_Pods in pools where it is assigned and signal Zeek to reload without a full container restart.
12. THE Config_Manager SHALL poll each enabled Rule_Repository on its configured schedule and merge newly fetched rules into the Rule_Store, deduplicating against existing entries.
13. WHEN a remote Rule_Repository fetch fails, THE Config_Manager SHALL log the failure, retain the previously fetched rules, and surface the error in the management UI without disrupting active sensor operations.
14. THE Config_Manager SHALL allow an operator to trigger an immediate manual update from any configured Rule_Repository.
15. THE Config_Manager SHALL record the last successful fetch timestamp and rule count delta for each Rule_Repository and display this in the UI.

**Ruleset Assignment and Distribution**

16. THE Config_Manager SHALL allow an operator to compose named rulesets by selecting subsets of rules from the Rule_Store, and assign each named ruleset to one or more Sensor_Pools as part of the pool configuration profile (per Requirement 12).
17. WHEN a ruleset is updated (via remote fetch, manual upload, or rule enable/disable), THE Config_Manager SHALL identify all Sensor_Pools using that ruleset and propagate the updated rules to all member Sensor_Pods, signaling each container to reload rules without a full restart.
18. THE Suricata container SHALL reload rules on receiving a signal without dropping active connections or restarting the capture pipeline.
19. THE Config_Manager SHALL display the currently deployed ruleset version and rule count per Sensor_Pool, and indicate when a pool's deployed rules are out of sync with the current Rule_Store state.

---

### Requirement 14: PCAP Retrieval API (Splunk Pivot) [v1]

**User Story:** As a security analyst, I want to retrieve the raw packets for a specific alert directly from Splunk via a workflow action, so that I can pivot from an alert to full packet context without logging into the sensor node or navigating a separate UI.

#### Acceptance Criteria

1. THE Sensor_Pod SHALL maintain a local PCAP index recording for each stored PCAP file: start time, end time, interface, packet count, byte count, and flow identifiers (5-tuple and Community_ID where available).
2. THE Config_Manager SHALL expose an authenticated REST API endpoint accepting a PCAP_Carve request containing at minimum: Sensor_Pod identifier, start timestamp, end timestamp, and one or more of: 5-tuple, Community_ID, Suricata alert ID, or Zeek UID.
3. WHEN a valid PCAP_Carve request is received, THE Config_Manager SHALL instruct the Sensor_Agent on the identified Sensor_Pod to use the PCAP index to locate candidate files, extract matching packets, and return the result as a downloadable PCAP file over HTTPS.
4. THE PCAP retrieval API SHALL require token-based authentication; unauthenticated requests SHALL be rejected with HTTP 401.
5. IF no matching packets are found, THE API SHALL return HTTP 404 with a descriptive message.
6. IF the requested Sensor_Pod is unreachable, THE API SHALL return HTTP 503 with the pod identifier and last known status.
7. THE Config_Manager SHALL log all PCAP_Carve requests including requesting identity, query parameters, Sensor_Pod, and result status for audit purposes.
8. THE Config_Manager UI SHALL document the API endpoint URL and token generation process so operators can configure Splunk workflow actions.

---

### Requirement 15: Zero-Trust Pod-to-Pod Communication [MVP]

**User Story:** As a platform security engineer, I want all communication between Sensor_Pods and the Management_Pod to use mutual TLS and run under least-privilege OS identities, so that a compromised container cannot pivot to root on the host or intercept traffic between pods in plaintext.

#### Acceptance Criteria

1. ALL network communication between Sensor_Pods and the Management_Pod — including Strelka file submissions, health streaming, PCAP carve requests, and config distribution — SHALL be encrypted with mTLS, with both client and server presenting certificates for mutual authentication.
2. RavenWire SHALL include a certificate management mechanism that provisions and rotates mTLS certificates for all pods; certificate configuration SHALL be managed via the Config_Manager.
3. IF a pod presents an invalid or expired certificate, THE receiving service SHALL reject the connection and log the rejection with the presenting pod's identity.
4. ALL containers in both the Management_Pod and Sensor_Pods SHALL run as a dedicated non-root OS user (e.g., `sensor-svc`); no container in RavenWire SHALL run as root unless a specific capability cannot be achieved otherwise, in which case the exception SHALL be explicitly documented with justification.
5. Container definitions SHALL explicitly drop all Linux capabilities not required for operation and SHALL not use `--privileged` mode.
6. THE Zeek and Suricata containers SHALL use only the minimum capabilities required for AF_PACKET socket access (`CAP_NET_RAW`, `CAP_NET_ADMIN`) and SHALL drop all others.
7. THE Sensor_Agent SHALL maintain an explicit allowlist of manageable containers and permitted actions; any request outside the allowlist SHALL be rejected and logged.
8. THE Sensor_Agent SHALL not expose arbitrary container start, exec, or image-pull functionality.
9. RavenWire SHOULD apply SELinux or AppArmor profiles to all containers; Podman with SELinux is the recommended configuration.

---

### Requirement 16: Health Metric History [v1]

**User Story:** As a network security engineer, I want at least 72 hours of historical health metrics retained and viewable in the Config_Manager, so that I can investigate packet drop spikes, CPU saturation events, or storage anomalies that occurred outside of active monitoring hours.

#### Acceptance Criteria

1. THE Config_Manager SHALL persist health metrics for all Sensor_Pod containers to a lightweight embedded time-series store in the Management_Pod at a configurable scrape interval (default 30 seconds).
2. THE time-series store SHALL retain at minimum 72 hours of metric history per container per Sensor_Pod.
3. THE Config_Manager UI SHALL provide a historical metric view per Sensor_Pod and per container, displaying time-series graphs for at minimum: CPU utilization, memory utilization, AF_PACKET drop rate, and packets received per second.
4. THE historical metric view SHALL allow an operator to select an arbitrary time range within the retained history window.
5. WHEN a metric exceeds a configurable threshold (e.g., drop rate > 5%), THE Config_Manager SHALL record a timestamped annotation in the time-series store so that threshold breach events are visible on the historical graph.
6. IF the time-series store reaches a configurable size limit, THE Config_Manager SHALL prune the oldest metric records to stay within the limit while retaining the most recent 72 hours.

---

### Requirement 17: Community ID Correlation [MVP]

**User Story:** As a security analyst, I want Community ID preserved across every data type the stack produces, so that I can pivot between a Suricata alert, Zeek connection log, Strelka file result, and raw PCAP using a single correlation key in Splunk or any other tool.

#### Acceptance Criteria

1. RavenWire SHALL compute and attach Community_ID to all Zeek logs, Suricata alerts, Strelka file results, Vector-normalized events, PCAP carve metadata, and downstream forwarding outputs.
2. THE Config_Manager SHALL expose Community_ID as a primary pivot field in the PCAP carve API and UI.
3. THE Vector transformation pipeline SHALL preserve Community_ID through all normalization and forwarding stages without modification.

---

### Requirement 18: Log Schema Normalization [v1]

**User Story:** As a security operations engineer, I want Vector to normalize all log output into a selectable common schema, so that the platform integrates cleanly with Splunk, Elastic, OpenSearch, Cribl, and data lake pipelines without custom parsing work.

#### Acceptance Criteria

1. THE Vector container SHALL support configurable output schema modes including at minimum: raw (native Zeek/Suricata/Strelka JSON), Elastic Common Schema (ECS), Open Cybersecurity Schema Framework (OCSF), and Splunk Common Information Model (CIM).
2. THE active output schema SHALL be selectable per forwarding sink via the Config_Manager without restarting Vector.
3. Community_ID SHALL be preserved in all schema output modes.
4. THE Config_Manager SHALL allow operators to define custom Vector remap profiles for deployments requiring non-standard schema mappings.

---

### Requirement 19: Sensor Enrollment and Identity Lifecycle [MVP]

**User Story:** As a platform engineer, I want a formal sensor enrollment workflow with certificate-based identity, so that new sensor pods join the deployment securely and compromised or decommissioned sensors can be revoked without affecting the rest of the fleet.

#### Acceptance Criteria

1. THE Config_Manager SHALL generate one-time enrollment tokens that a new Sensor_Pod presents to request a unique sensor identity and mTLS certificate.
2. THE Config_Manager SHALL provide an operator approval workflow for new sensor enrollment; a Sensor_Pod SHALL not be granted full operational status until an operator approves its enrollment request.
3. THE Config_Manager SHALL allow operators to: approve, deny, revoke, rename, and reassign enrolled Sensor_Pods.
4. THE Config_Manager SHALL maintain a certificate revocation list and THE Sensor_Agent SHALL reject connections from revoked Sensor_Pod identities.
5. THE Config_Manager SHALL support automated certificate rotation before expiry; rotation SHALL not interrupt active capture operations.
6. The enrollment token and cluster node name SHALL be configurable exclusively via environment variables with no hardcoded values in any container image.

---

### Requirement 20: Config Versioning, Validation, and Rollback [v1]

**User Story:** As a network security engineer, I want all configuration changes versioned, validated before deployment, and rollback-capable, so that a bad ruleset or BPF filter cannot permanently degrade a sensor pool without a recovery path.

#### Acceptance Criteria

1. THE Config_Manager SHALL version every Sensor_Pool configuration change with a timestamp, operator identity, and change summary.
2. THE Config_Manager SHALL validate Suricata rules (syntax and SID conflict), YARA rules (compile check), Zeek packages (compatibility check), BPF filters (syntax validation), and capture mode configurations before deploying any change.
3. IF validation fails, THE Config_Manager SHALL reject the deployment and display the specific validation errors to the operator without applying any partial changes.
4. THE Config_Manager SHALL support canary deployment: applying a configuration change to a single designated Sensor_Pod in a pool before rolling it out to all members.
5. WHEN a canary deployment results in elevated packet drop rate, container failure, or ruleset validation errors within a configurable observation window, THE Config_Manager SHALL automatically roll back the canary pod to the previous known-good configuration and halt the pool-wide rollout.
6. THE Config_Manager SHALL allow an operator to manually roll back any Sensor_Pool to any previous versioned configuration.
7. THE Config_Manager SHALL display the configuration version history per Sensor_Pool with diff view between versions.

---

### Requirement 21: Detection Testing [v1.5]

**User Story:** As a network security engineer, I want to test Suricata rules, YARA rules, Zeek packages, and BPF filters against uploaded PCAP files before deploying them to any sensor pool, so that I can validate detection coverage and catch performance regressions before they affect production.

#### Acceptance Criteria

1. THE Config_Manager SHALL allow operators to upload a PCAP file and run it through a selected ruleset (Suricata rules, YARA rules, Zeek packages, or BPF filter) in an isolated test environment.
2. THE test result SHALL show: matched rules with alert details, generated Zeek log output, processing errors, estimated performance cost, and expected Vector output.
3. WHEN a Suricata rule produces no matches against a provided test PCAP, THE Config_Manager SHALL surface a warning indicating the rule may not be effective against the provided traffic sample.
4. WHEN a BPF filter would drop more than a configurable percentage of packets in the test PCAP, THE Config_Manager SHALL surface a warning before the operator proceeds with deployment.
5. Test results SHALL be retained in the Config_Manager for a configurable period and associated with the rule version tested.

---

### Requirement 22: Time Synchronization [MVP]

**User Story:** As a security analyst, I want all sensor nodes and the management node to maintain synchronized clocks, so that PCAP timestamps, Zeek logs, Suricata alerts, and Splunk events can be correlated accurately across sensors and time zones.

#### Acceptance Criteria

1. All Sensor_Nodes and the Management_Node SHALL synchronize time using NTP or PTP; the time source SHALL be configurable via environment variable.
2. THE Sensor_Agent SHALL monitor clock offset on its Node and report it to the Config_Manager as a health metric.
3. IF clock drift on any Sensor_Node exceeds a configurable threshold (default 100ms), THE Config_Manager SHALL mark the affected Sensor_Pod as degraded in the UI and surface a descriptive alert.
4. For deployments requiring sub-millisecond precision (e.g., multi-sensor PCAP correlation), PTP hardware timestamping support SHALL be documented as an optional host configuration.

---

### Requirement 23: Performance Benchmark Profiles [v1]

**User Story:** As a platform engineer, I want defined benchmark profiles for each supported throughput tier, so that "25Gbps support" is an engineering specification with measurable acceptance criteria rather than a marketing claim.

#### Acceptance Criteria

1. RavenWire SHALL include benchmark profiles for 1Gbps, 10Gbps, and 25Gbps operation.
2. Each benchmark profile SHALL define: average and minimum packet size, flows per second, new connections per second, protocol mix, Suricata ruleset size, Zeek package set, file extraction enabled/disabled, PCAP mode, disk write target, CPU/NIC/RAM baseline, and acceptable packet loss threshold.
3. RavenWire SHALL include a benchmark execution tool that runs a defined profile against a Sensor_Pod and reports measured throughput, packet drop rate, CPU utilization, and memory utilization.
4. THE 25Gbps benchmark profile SHALL document that Full_PCAP_Mode at line rate requires local NVMe-backed storage as the primary write target; remote NFS/iSCSI as the sole write target is not supported at this throughput tier.

---

### Requirement 24: RBAC, SSO, and Audit Logging [v1 → v1.5]

**User Story:** As a platform security engineer, I want role-based access control, SSO integration, and comprehensive audit logging in the Config Manager, so that every action is attributable to an authenticated identity and access is scoped to operational need.

#### Acceptance Criteria

1. THE Config_Manager SHALL implement role-based access control with at minimum the following roles: viewer, analyst, sensor-operator, rule-manager, platform-admin, and auditor.
2. THE Config_Manager SHALL support local authentication for lab use and OIDC/SAML integration for enterprise SSO deployments.
3. THE Config_Manager SHALL support MFA for all authentication methods where the identity provider supports it.
4. THE Config_Manager SHALL support API tokens with configurable scopes, expiration, and rotation.
5. THE Config_Manager SHALL produce an immutable audit log recording at minimum: login, failed login, config change, rule change, mode switch, PCAP carve request, PCAP download, sensor enrollment, certificate rotation, and failed mTLS connection — each entry including timestamp, actor identity, action, target, and result.
6. THE audit log SHALL be accessible to users with the auditor role and SHALL be exportable in a standard format.

---

### Requirement 25: Operational Resilience and Support Bundles [v1]

**User Story:** As a platform engineer, I want the sensor stack to continue operating during Management Pod outages and to generate one-click support bundles for troubleshooting, so that production capture is never dependent on management plane availability and community support is practical.

#### Acceptance Criteria

1. WHEN the Management_Pod is unreachable, each Sensor_Pod SHALL continue packet capture, local logging, and local metric buffering using the last known valid configuration without operator intervention.
2. WHEN Management_Pod connectivity is restored, THE Sensor_Agent SHALL reconcile buffered health metrics and confirm configuration state with the Config_Manager.
3. THE Config_Manager SHALL support backup and restore of all persistent state: pool configurations, rule store, enrollment records, certificate authority, metric history, and audit log.
4. THE Config_Manager SHALL provide a one-click support bundle generator that produces a sanitized archive containing: container logs, host tuning parameters, NIC stats, packet drop counters, Vector buffer status, Suricata stats, Zeek stats, disk usage, rule versions, certificate status, and recent configuration change history — with all sensitive values (IPs, credentials, keys) redacted by default.
5. RavenWire SHALL expose Prometheus-compatible metrics endpoints on both the Management_Pod and each Sensor_Pod for integration with external monitoring systems.
6. RavenWire SHALL expose health check, readiness, and liveness endpoints on all pod services for integration with container orchestration and monitoring tooling.

---

### Requirement 26: Optional Arkime Session Indexing [v2]

**User Story:** As a security analyst, I want an optional indexed session search and PCAP retrieval layer, so that I can search and retrieve packets by session without relying solely on time-range and 5-tuple queries.

#### Acceptance Criteria

1. WHERE Arkime is enabled for a Sensor_Pool, RavenWire SHALL deploy Arkime as a first-class indexed session search and PCAP retrieval layer.
2. WHEN Arkime is enabled, THE Arkime instance SHALL index sessions from the Sensor_Pod's capture stream.
3. RavenWire SHALL preserve correlation links between Arkime session IDs, Zeek UIDs, Suricata alert IDs, Community_ID, and PCAP carve metadata.
4. THE Config_Manager SHALL allow operators to enable or disable Arkime per Sensor_Pool.
5. WHEN Arkime is enabled, THE Config_Manager SHALL expose Arkime session links in the PCAP carve API response.

---

### Requirement 27: Detection-as-Code and GitOps Workflow [v1.5]

**User Story:** As a detection engineer, I want Git-backed detection repositories with automated validation, so that rule changes go through a controlled review and validation pipeline before reaching any sensor.

#### Acceptance Criteria

1. THE Config_Manager SHALL support Git-backed detection repositories as sources for Suricata rules, YARA rules, Zeek scripts, Vector transforms, and BPF filter profiles.
2. THE Config_Manager SHALL support signed rule bundles and version pinning for all Git-backed detection repositories.
3. WHEN rules are pushed to a configured branch, THE Config_Manager SHALL automatically validate them (syntax check, compile check, SID conflict check, YARA compile check) before making them eligible for deployment to any Sensor_Pool.
4. IF validation fails, THE Config_Manager SHALL block deployment and surface the specific validation errors to the operator.

---

### Requirement 28: Supply Chain Security [v2]

**User Story:** As a platform security engineer, I want all container images and release artifacts to be signed and accompanied by an SBOM, so that operators can verify the integrity and provenance of every component they deploy.

#### Acceptance Criteria

1. RavenWire SHALL publish a Software Bill of Materials (SBOM) for all released container images.
2. Container images and release artifacts SHALL be signed; RavenWire SHALL document the verification procedure.
3. RavenWire SHALL support vulnerability scanning of bundled images and dependencies.
4. THE Config_Manager SHALL display running component versions and surface known update availability.

---

### Requirement 29: Air-Gapped Operation [v2]

**User Story:** As a platform engineer, I want the sensor stack to install and operate fully without internet access, so that it can be deployed in classified or isolated network environments.

#### Acceptance Criteria

1. RavenWire SHALL support fully air-gapped installation and operation with no runtime dependency on external network connectivity.
2. RavenWire SHALL provide offline bundles containing: container images, rule updates, Zeek packages, YARA repositories, and documentation.
3. THE Config_Manager SHALL support importing offline update bundles through both the UI and CLI.

---

### Requirement 30: CLI and Public API [v2]

**User Story:** As a platform engineer, I want a CLI tool and a fully documented public API, so that I can automate all platform operations and integrate the sensor stack into existing operational workflows.

#### Acceptance Criteria

1. RavenWire SHALL provide a CLI tool (`sensorctl`) covering all platform operations.
2. `sensorctl` SHALL support at minimum the following commands: install, start, stop, restart, status, logs, enroll, test, agent status, agent show-drops, and agent collect-support-bundle.
3. RavenWire SHALL provide a fully documented public REST API covering all platform operations.
4. THE Config_Manager UI SHALL be built on top of the same public REST API that operators can automate against.

---

### Requirement 31: PCAP Data Governance and Chain of Custody [v1]

**User Story:** As a security operations manager, I want role-based controls and a chain-of-custody manifest for every PCAP export, so that access to raw packet data is auditable and defensible.

#### Acceptance Criteria

1. THE Config_Manager SHALL enforce role-based permissions for PCAP carve and PCAP download actions.
2. THE Config_Manager SHALL optionally require a justification field for PCAP export requests.
3. RavenWire SHALL calculate a SHA256 hash for every exported PCAP file.
4. RavenWire SHALL generate a chain-of-custody manifest for every PCAP export containing: requesting user identity, request timestamp, Sensor_Pod ID, query parameters, file hash, and result status.

---

### Requirement 32: Management Pod High Availability [v1.5]

**User Story:** As a platform engineer, I want documented and supported Management Pod deployment models including HA and backup/restore, so that the management plane can be made resilient without requiring custom engineering.

#### Acceptance Criteria

1. RavenWire SHALL document and support three Management_Pod deployment models: single-node, active/passive HA, and restore-from-backup.
2. WHEN the Management_Pod is unavailable, Sensor_Pods SHALL continue operating using the last known valid configuration.
3. WHEN Management_Pod connectivity is restored after an outage, THE Sensor_Agent SHALL verify the integrity and recency of any configuration updates received and SHALL reject stale or unsigned configuration pushes.
