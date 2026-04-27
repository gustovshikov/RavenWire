# Requirements Document

## Introduction

The sensor stack has proven the core concept: Zeek, Suricata, Vector, pcap_ring_writer, and Sensor_Agent run together, share log volumes, and exercise alert-driven PCAP carving. This spec covers the work required to take that spike to a production-grade distributed sensor — reliable, secure, observable, and capable of sustaining high-throughput capture.

The work is organized into four phases:

- **Phase 1 — Reliability**: Fix the broken alert-to-PCAP path, the control protocol field mismatch, and the severity logic inversion. Add end-to-end integration tests.
- **Phase 2 — Manageability**: Real Podman/systemd container lifecycle control, safe BPF restart sequences, config rollback, templated Vector config, and Podman/Quadlet deployment.
- **Phase 3 — Throughput**: TPACKET_V3 mmap capture, kernel timestamps, per-socket drop counters, configurable ring sizing, and benchmark harness.
- **Phase 4 — Analyst Utility**: Expanded PCAP index metadata, Community_ID and time-range retrieval API, PCAP hashing and chain-of-custody manifests, and Strelka/file extraction integration.

---

## Glossary

- **Sensor_Agent**: The Go binary running in each Sensor_Pod responsible for health reporting, config application, container lifecycle control, BPF management, PCAP carving, and certificate rotation.
- **pcap_ring_writer**: The dedicated Go binary that owns the AF_PACKET socket and maintains the rolling PCAP ring buffer in Alert_Driven_Mode.
- **PCAP_Manager**: The internal module within Sensor_Agent (`internal/pcap`) that controls pcap_ring_writer, handles alert events, manages the PCAP index, and executes carve operations.
- **Capture_Manager**: The internal module within Sensor_Agent (`internal/capture`) that manages BPF filter lifecycle and reports per-consumer packet statistics.
- **Alert_Listener**: The HTTP server within PCAP_Manager that receives qualifying Suricata alert events forwarded by Vector.
- **Ring_Control_Protocol**: The JSON-over-Unix-socket protocol used by PCAP_Manager to send commands to pcap_ring_writer (mark_pre_alert, carve_window, configure, status).
- **Community_ID**: A standardized network flow hash computed from the 5-tuple, used as a universal correlation key across Zeek logs, Suricata alerts, PCAP carve metadata, and downstream SIEM events.
- **Alert_Driven_Mode**: The operational mode in which pcap_ring_writer maintains a rolling ring buffer and qualifying Suricata alerts trigger a pre/post-alert PCAP carve.
- **Full_PCAP_Mode**: The operational mode in which a dedicated full-packet capture process writes all traffic to storage.
- **BPF_Filter**: A Berkeley Packet Filter program applied per AF_PACKET socket to drop elephant flows in the kernel before packets reach userspace.
- **TPACKET_V3**: The Linux kernel block-based AF_PACKET ring buffer mode that reduces syscall overhead compared to recvfrom()-based capture.
- **Podman_REST_API**: The HTTP API exposed by Podman over a Unix socket, used by Sensor_Agent to manage container lifecycle.
- **Quadlet**: The Podman mechanism that generates systemd units from container definitions, enabling native systemd supervision.
- **mTLS**: Mutual TLS — both client and server present certificates for authentication, used for all pod-to-pod communication.
- **PCAP_Index**: The per-Sensor_Pod SQLite database that records metadata for all carved and stored PCAP files.
- **Chain_of_Custody_Manifest**: A signed, append-only record of all access and transfer events for a PCAP file, required for evidence-grade handling.
- **Severity_Threshold**: The Suricata alert severity value at or below which an alert qualifies for PCAP carving. Suricata severity 1 is highest, 3 is lowest.
- **Vector**: The log aggregation and routing agent running in each Sensor_Pod, responsible for collecting Zeek and Suricata output and forwarding qualifying alerts to the Alert_Listener.
- **Sensor_Pool**: A named logical grouping of Sensor_Pods sharing a common configuration profile.
- **Config_Manager**: The Elixir/Phoenix application in the Management_Pod providing centralized configuration, enrollment, and health visibility.
- **SO_ATTACH_FILTER**: The Linux socket option used to attach a compiled BPF program to an AF_PACKET socket.
- **PACKET_FANOUT**: The Linux kernel mechanism that distributes packets across multiple sockets within a fanout group for intra-tool worker scaling.

---

## Requirements

### Requirement 1: Alert Listener Implementation

**User Story:** As a network security engineer, I want the Sensor_Agent to receive qualifying Suricata alerts from Vector and automatically trigger PCAP carves, so that the alert-to-PCAP path is fully operational end-to-end.

#### Acceptance Criteria

1. THE Alert_Listener SHALL implement an HTTP server that accepts POST requests containing Suricata EVE JSON alert payloads forwarded by Vector.
2. WHEN Sensor_Agent starts, THE Alert_Listener SHALL bind to a configurable address and begin accepting alert events before the control API is declared ready.
3. WHEN an alert payload is received, THE Alert_Listener SHALL validate that the payload contains at minimum: `community_id`, `severity`, `timestamp_ms`, and `sid` fields; invalid payloads SHALL be rejected with HTTP 400 and logged.
4. WHEN a valid alert is received, THE Alert_Listener SHALL enqueue the alert for processing; THE Alert_Listener SHALL return HTTP 202 to Vector immediately without waiting for the carve to complete.
5. THE Alert_Listener SHALL maintain an internal bounded queue for pending alert events; WHEN the queue is full, THE Alert_Listener SHALL drop the incoming alert, log a warning with the dropped alert's `community_id` and `sid`, and return HTTP 429 to Vector.
6. THE PCAP_Manager SHALL deduplicate alert events by the combination of `community_id`, `sid`, and sensor identity within a configurable time window (default 30 seconds); duplicate alerts within the window SHALL be discarded without triggering a second carve.
7. THE Alert_Listener SHALL expose a `/alerts/health` endpoint returning HTTP 200 with queue depth and deduplication cache size so that Vector can verify the listener is reachable before routing alerts.
8. WHEN a Suricata EVE alert traverses the Vector pipeline and the Alert_Listener is running, THE Sensor_Agent SHALL produce a carved PCAP file on disk and a corresponding PCAP_Index entry within the post-alert window duration plus a configurable processing timeout (default 10 seconds).

---

### Requirement 2: Ring Control Protocol Standardization

**User Story:** As a platform engineer, I want the control protocol between PCAP_Manager and pcap_ring_writer to use a single consistent time unit, so that carve windows are computed correctly and packet counts are non-zero on valid alerts.

#### Acceptance Criteria

1. THE Ring_Control_Protocol SHALL use nanoseconds as the sole time unit for all timestamp fields in all commands; fields named `pre_alert_ms` and `post_alert_ms` SHALL be renamed to `pre_alert_ns` and `post_alert_ns` throughout both PCAP_Manager and pcap_ring_writer.
2. THE Ring_Control_Protocol SHALL be defined in a shared Go package (`internal/ringctl`) containing the command and response struct definitions, field names, and unit documentation; both PCAP_Manager and pcap_ring_writer SHALL import this package rather than defining protocol fields independently.
3. THE shared `internal/ringctl` package SHALL include a contract test that encodes a command using the PCAP_Manager serializer and decodes it using the pcap_ring_writer deserializer, asserting that all field values round-trip without loss or unit conversion error.
4. WHEN PCAP_Manager sends a `carve_window` command, THE pcap_ring_writer SHALL interpret `pre_alert_ns` and `post_alert_ns` as Unix nanosecond timestamps and include only packets whose `TimestampNs` falls within that range.
5. FOR ALL valid alert events with a non-empty ring buffer, THE end-to-end integration test SHALL assert that the carved PCAP file contains a packet count greater than zero.
6. THE `mark_pre_alert` command SHALL accept a `timestamp_ns` field (Unix nanoseconds); the existing `timestamp_ms` field in the `mark_pre_alert` handler SHALL be removed.

---

### Requirement 3: Alert Severity Logic Correction

**User Story:** As a network security engineer, I want the alert severity threshold to correctly pass high-severity alerts (severity 1) through to PCAP carving, so that the most critical detections are never silently dropped.

#### Acceptance Criteria

1. THE PCAP_Manager SHALL treat Suricata severity as a priority scale where 1 is highest and 3 is lowest; an alert qualifies for carving WHEN its severity value is less than or equal to the configured `severity_threshold`.
2. THE `HandleAlert` method SHALL discard an alert and return nil WHEN `alert.Severity > m.severityThresh`; the current inverted condition (`alert.Severity < m.severityThresh`) SHALL be corrected.
3. THE severity threshold SHALL be explicitly documented in the Sensor_Agent configuration schema with the note that lower numeric values represent higher severity (Suricata convention).
4. THE Vector routing rule that forwards alerts where Suricata severity is `<= 2` SHALL be consistent with the PCAP_Manager threshold default of 2; both values SHALL be sourced from the same configuration field in the sensor config bundle.
5. WHEN the severity threshold is set to 1, THE PCAP_Manager SHALL carve only severity-1 alerts and discard severity-2 and severity-3 alerts.
6. WHEN the severity threshold is set to 3, THE PCAP_Manager SHALL carve all alerts regardless of severity.

---

### Requirement 4: BPF Filter Change Handling

**User Story:** As a platform engineer, I want BPF filter changes to be applied safely without leaving the sensor in an inconsistent capture state, so that filter updates do not silently fail or cause Zeek and Suricata to capture with a stale filter.

#### Acceptance Criteria

1. WHEN a BPF filter change is requested for Zeek or Suricata, THE Capture_Manager SHALL classify the change as restart-required and SHALL NOT send SIGHUP or SIGUSR2 to those processes as a live BPF update mechanism, because neither Zeek nor Suricata supports live AF_PACKET BPF replacement via signal.
2. THE Capture_Manager SHALL validate the new BPF filter by compiling it to BPF bytecode before writing it to any config file or initiating any restart sequence.
3. IF BPF filter compilation fails, THEN THE Capture_Manager SHALL reject the change, log the compilation error, and leave the existing filter and process state unchanged.
4. WHEN a validated BPF filter change requires a Zeek or Suricata restart, THE Capture_Manager SHALL execute a safe restart sequence: write the new filter config, request a controlled container restart via the Podman_REST_API, and verify the container returns to running state within a configurable timeout (default 30 seconds).
5. IF the container does not return to running state within the timeout, THEN THE Capture_Manager SHALL attempt to restore the previous filter config and retry the restart once; IF the retry also fails, THEN THE Capture_Manager SHALL log a critical error and report the failure to the Config_Manager health stream.
6. WHEN a BPF filter change is applied to pcap_ring_writer, THE Capture_Manager SHALL send the updated filter via the `configure` command on the Ring_Control_Protocol Unix socket; this path SHALL implement `SO_ATTACH_FILTER` reattachment in pcap_ring_writer rather than returning a stub `ok` response.
7. THE Config_Manager UI SHALL display a "restart required" indicator for any Sensor_Pod where a BPF filter change is pending but has not yet been applied via a container restart.
8. WHEN a BPF filter change is applied, THE Sensor_Agent SHALL emit an audit log entry recording the previous filter hash, the new filter hash, the affected consumers, and whether each consumer required a restart.

---

### Requirement 5: Podman Container Lifecycle Control

**User Story:** As a platform engineer, I want the Sensor_Agent to perform real container restarts via the Podman REST API, so that the `restart-vector` and future restart actions have actual effect rather than silently succeeding.

#### Acceptance Criteria

1. THE `restartContainerViaPodman` function SHALL implement a real HTTP request to the Podman REST API over the configured Unix socket path, using the `/containers/{name}/restart` endpoint.
2. THE Sensor_Agent SHALL maintain an explicit allowlist of container names that may be restarted; restart requests for containers not in the allowlist SHALL be rejected with a logged error and SHALL NOT be forwarded to the Podman API.
3. WHEN a restart is requested, THE Sensor_Agent SHALL set a configurable timeout on the Podman API request (default 60 seconds) and return an error if the request does not complete within that timeout.
4. WHEN a restart completes, THE Sensor_Agent SHALL query the Podman API for the container's current state and return the actual post-restart state (running, stopped, error) in the response.
5. THE Sensor_Agent SHALL log both the restart request and the resulting container state as audit events, including the requesting actor identity from the mTLS client certificate.
6. WHERE Podman/Quadlet deployment is active, THE Sensor_Agent SHALL prefer issuing `systemctl restart` on the corresponding Quadlet-generated systemd unit over direct Podman API calls, falling back to the Podman API if the systemd unit name cannot be resolved.
7. IF the Podman socket is not accessible at startup, THEN THE Sensor_Agent SHALL log a warning and continue operating; container restart actions SHALL return an error until the socket becomes accessible.

---

### Requirement 6: Control-Plane Security Hardening

**User Story:** As a security engineer, I want the Sensor_Agent control plane to enforce mTLS strictly and apply least-privilege socket permissions, so that a misconfigured or compromised deployment cannot fall back to unauthenticated communication.

#### Acceptance Criteria

1. THE Sensor_Agent SHALL NOT start the control API in plain HTTP mode unless the environment variable `SENSOR_DEV_MODE=true` is explicitly set; absent this variable, missing certificates SHALL cause the Sensor_Agent to log a fatal error and exit rather than falling back to plain HTTP.
2. WHERE `SENSOR_DEV_MODE=true` is set, THE Sensor_Agent SHALL log a prominent warning on every startup indicating that mTLS is disabled and the deployment is not production-safe.
3. THE pcap_ring_writer control socket SHALL be created with permissions `0600` and owned by the `sensor-svc` user (UID 10000); the Sensor_Agent SHALL verify socket ownership and permissions before sending any command and SHALL refuse to connect if they do not match.
4. THE Sensor_Agent SHALL NOT mount or expose `/var/run` broadly; the Podman socket path and the pcap_ring_writer socket path SHALL each be mounted as individual named volumes or bind mounts targeting only the specific socket file.
5. THE Sensor_Agent SHALL include a unique request ID in every outbound Podman API call and every inbound control API response; request IDs SHALL be recorded in audit log entries to enable correlation.
6. WHEN a certificate is presented for mTLS authentication, THE Sensor_Agent SHALL check the certificate serial against the Config_Manager's current CRL before accepting the connection; connections presenting revoked certificates SHALL be rejected at the TLS handshake layer.
7. THE enrollment-only HTTP listener (used before certificates are issued) SHALL bind to a separate port from the mTLS control API and SHALL accept only the `/enroll` endpoint; all other paths on the enrollment port SHALL return HTTP 404.

---

### Requirement 7: Health Metrics Accuracy

**User Story:** As a platform engineer, I want health metrics to reflect actual per-process capture statistics rather than interface-level aggregates, so that I can detect per-consumer drops and throughput degradation accurately.

#### Acceptance Criteria

1. THE Capture_Manager SHALL report per-consumer packet statistics sourced from the actual capture process rather than from `/sys/class/net` interface-level counters; for pcap_ring_writer, statistics SHALL be retrieved via the `status` command on the Ring_Control_Protocol socket.
2. THE health report SHALL include the following pcap_ring_writer statistics: `packets_written`, `bytes_written`, `wrap_count`, and a derived `overwrite_risk` indicator that is true when the ring has wrapped more than once since the last health report interval.
3. THE Sensor_Agent SHALL collect Suricata capture statistics from Suricata's `stats.log` or EVE stats event stream, including `capture.kernel_packets`, `capture.kernel_drops`, and `capture.kernel_ifdrops`.
4. THE Sensor_Agent SHALL collect Zeek process health metrics including process uptime, log write lag (time since last log file write), and whether the Zeek process is in a degraded state.
5. THE Sensor_Agent SHALL collect Vector internal metrics including records ingested per second, sink connectivity status, and disk buffer utilization percentage.
6. THE health report SHALL include a throughput calculation in bits per second for each active capture consumer, derived from the bytes reported in successive health intervals.
7. WHEN a capture consumer reports a drop percentage exceeding a configurable threshold (default 1%), THE Sensor_Agent SHALL include a `drop_alert` flag in the health report for that consumer and log a warning.

---

### Requirement 8: Vector Configuration Templating

**User Story:** As a platform engineer, I want Vector's configuration to be generated from the validated sensor config bundle rather than relying on hardcoded environment variable defaults, so that only configured sinks are active and the config is consistent with the rest of the sensor's applied configuration.

#### Acceptance Criteria

1. THE Sensor_Agent Config_Applier SHALL generate the Vector configuration file from the sensor config bundle when applying a pool configuration; Vector SHALL NOT be started with a static config file that predates the applied bundle.
2. THE generated Vector config SHALL enable only the sinks that are explicitly configured in the sensor config bundle; Splunk HEC and Cribl HTTP sinks SHALL NOT appear in the generated config if they are not present in the bundle.
3. THE generated Vector config SHALL include the Alert_Listener sink routing qualifying Suricata alerts (severity <= configured threshold) to the Alert_Listener address; this routing SHALL use the same severity threshold value as the PCAP_Manager.
4. THE Sensor_Agent SHALL validate the generated Vector config by running `vector validate` before writing it to disk; IF validation fails, THEN the Config_Applier SHALL reject the bundle and return a validation error without modifying the running Vector config.
5. WHEN a downstream sink is unreachable, THE Vector config SHALL include a local file dead-letter sink that captures records that cannot be forwarded; the dead-letter file path and maximum size SHALL be configurable in the sensor config bundle.
6. THE Vector config SHALL support the following schema modes selectable per sink: `raw` (unmodified source JSON), `ecs` (Elastic Common Schema), `ocsf` (Open Cybersecurity Schema Framework), and `splunk_cim` (Splunk Common Information Model); the active schema mode SHALL be specified in the sensor config bundle.
7. WHEN Vector is reloaded after a config change, THE Sensor_Agent SHALL verify that Vector's internal health endpoint returns healthy within a configurable timeout (default 15 seconds); IF Vector does not become healthy, THE Sensor_Agent SHALL restore the previous config and reload Vector again.

---

### Requirement 9: PCAP Index Evidence-Grade Metadata

**User Story:** As a security analyst, I want carved PCAP files to be indexed with complete evidence-grade metadata, so that I can verify file integrity, trace the chain of custody, and pivot from an alert to the corresponding PCAP without ambiguity.

#### Acceptance Criteria

1. THE PCAP_Index SHALL store the following fields for every carved PCAP file: `sha256_hash`, `file_size_bytes`, `sensor_id`, `alert_sid`, `alert_signature`, `alert_uuid`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `community_id`, `zeek_uid`, `capture_interface`, `carve_reason`, `requested_by`, `created_at_ms`, `retention_expires_at_ms`, and `chain_of_custody_manifest_path`.
2. THE PCAP_Manager SHALL compute the SHA256 hash of each carved PCAP file after the carve completes and before writing the index entry; the hash SHALL be computed over the complete file contents including the PCAP global header.
3. THE PCAP_Manager SHALL generate a Chain_of_Custody_Manifest for each carved file at the time of creation; the manifest SHALL record the carve event, the requesting actor, the alert that triggered the carve, and the file hash.
4. WHEN a PCAP file is accessed via the carve API, THE PCAP_Manager SHALL append an access event to the Chain_of_Custody_Manifest for that file, recording the accessor identity, timestamp, and purpose.
5. THE PCAP_Index SHALL enforce a retention policy: WHEN `retention_expires_at_ms` is set and the current time exceeds it, THE PCAP_Manager SHALL delete the file and its index entry during the next pruning cycle.
6. FOR ALL carved PCAP files, THE round-trip property SHALL hold: inserting a `PcapFile` record into the index and then querying by `community_id` SHALL return a record with identical field values to the inserted record.
7. THE PCAP_Index schema migration SHALL be backward-compatible; existing index entries without the new fields SHALL be readable and SHALL have null values for the new fields rather than causing query errors.

---

### Requirement 10: TPACKET_V3 Capture Engine

**User Story:** As a platform engineer, I want pcap_ring_writer to use TPACKET_V3 block-based capture instead of recvfrom(), so that it can sustain higher packet rates with lower CPU overhead and accurate kernel timestamps.

#### Acceptance Criteria

1. THE pcap_ring_writer SHALL use `TPACKET_V3` (block-based AF_PACKET ring) for packet capture instead of `recvfrom()`; the TPACKET_V3 ring SHALL be memory-mapped and polled via `poll()` rather than blocking syscalls.
2. THE pcap_ring_writer SHALL use kernel-provided packet timestamps from the TPACKET_V3 block header (`tp_sec`, `tp_nsec`) rather than userspace `time.Now()` as the primary timestamp source.
3. THE TPACKET_V3 block size and ring frame count SHALL be configurable via environment variables `TPACKET_BLOCK_SIZE_MB` and `TPACKET_FRAME_COUNT`; default values SHALL match the 1Gbps tier (block size 4MB, frame count 2048).
4. THE pcap_ring_writer SHALL expose per-socket drop counters retrieved via `PACKET_STATISTICS` getsockopt; these counters SHALL be included in the `status` command response as `socket_drops` and `socket_freeze_queue_drops`.
5. THE pcap_ring_writer SHALL support a configurable number of capture worker goroutines (`RING_WORKERS`, default 1) that each poll a separate TPACKET_V3 block and write to the shared ring buffer under a mutex.
6. THE pcap_ring_writer SHALL include a benchmark harness that measures sustained packet rate and drop percentage at 1Gbps, 10Gbps, and 25Gbps traffic profiles using a replay tool; benchmark results SHALL be written to a structured JSON report.
7. WHEN the TPACKET_V3 ring is initialized, THE pcap_ring_writer SHALL log the configured block size, frame count, and total ring memory allocation so that operators can verify the configuration matches the intended throughput tier.

---

### Requirement 11: Sensor Bootstrap and First-Boot Flow

**User Story:** As a platform engineer, I want a clean, validated first-boot sequence for a new sensor node, so that a sensor goes from installation to active capture in a defined sequence of steps without manual intervention beyond initial token configuration.

#### Acceptance Criteria

1. THE Sensor_Agent SHALL implement a defined bootstrap state machine with the following states in order: `installed` → `enrolling` → `pending_approval` → `config_received` → `config_validated` → `capture_active`; the agent SHALL log each state transition.
2. WHEN in `enrolling` state, THE Sensor_Agent SHALL POST to the Config_Manager enrollment endpoint with the one-time token, pod name, and public key; IF the enrollment request fails, THE Sensor_Agent SHALL retry with exponential backoff (initial 5s, max 60s) until the token expires or enrollment succeeds.
3. WHEN in `pending_approval` state, THE Sensor_Agent SHALL poll the Config_Manager for approval status at a configurable interval (default 30 seconds) and transition to `config_received` when the Config_Manager issues a certificate and initial config bundle.
4. WHEN in `config_received` state, THE Sensor_Agent SHALL validate the received config bundle using the Rule_Validator and Capture_Manager validation logic before writing any config files to disk.
5. IF config validation fails, THEN THE Sensor_Agent SHALL remain in `config_received` state, log the validation errors, and report them to the Config_Manager; THE Sensor_Agent SHALL NOT start capture with an invalid config.
6. WHEN in `config_validated` state, THE Sensor_Agent SHALL run the Host_Readiness_Checker; IF all checks pass, THE Sensor_Agent SHALL write the validated config, start capture processes, and transition to `capture_active`.
7. THE `sensorctl enroll` command SHALL automate the token configuration step and display the current bootstrap state and any blocking errors so that operators can diagnose enrollment failures without reading log files.

---

### Requirement 12: NIC and Host Tuning Validation

**User Story:** As a platform engineer, I want the Host_Readiness_Checker to validate NIC and host tuning settings required for high-throughput capture, so that a misconfigured host is detected before capture starts rather than silently dropping packets.

#### Acceptance Criteria

1. THE Host_Readiness_Checker SHALL validate the following NIC settings on the capture interface: GRO (Generic Receive Offload) disabled, LRO (Large Receive Offload) disabled, RX ring buffer size at or above a configurable minimum, and promiscuous mode enabled.
2. THE Host_Readiness_Checker SHALL validate that the number of RSS (Receive Side Scaling) queues on the capture interface is at least equal to the configured number of capture worker threads.
3. THE Host_Readiness_Checker SHALL validate CPU isolation: WHEN `CAPTURE_CPU_LIST` is configured, THE checker SHALL verify that the listed CPUs are isolated from the kernel scheduler (present in `/sys/devices/system/cpu/isolated`).
4. THE Host_Readiness_Checker SHALL measure NVMe write throughput by writing a configurable test file (default 1GB) to the PCAP storage path and SHALL fail the check IF the measured throughput is below a configurable minimum (default 500 MB/s for 1Gbps tier, 2000 MB/s for 10Gbps tier).
5. THE Host_Readiness_Checker SHALL validate that the system clock is synchronized (NTP or PTP offset within configurable bounds, default 10ms) and SHALL report the current offset and sync source in the readiness report.
6. WHEN any Host_Readiness_Checker validation fails, THE Sensor_Agent SHALL include the specific failing check name, the observed value, and the required value in the readiness report so that operators can take targeted corrective action.
7. THE Host_Readiness_Checker SHALL distinguish between hard failures (capture cannot start) and soft warnings (capture can start but performance may be degraded); hard failures SHALL block the bootstrap sequence while soft warnings SHALL be logged and reported without blocking.

---

### Requirement 13: Full PCAP Mode Process Management

**User Story:** As a platform engineer, I want switching to Full_PCAP_Mode to actually start and stop the appropriate capture processes, so that the mode switch has real effect rather than only updating an internal string.

#### Acceptance Criteria

1. WHEN `SwitchMode("full_pcap")` is called, THE PCAP_Manager SHALL request a start of the netsniff-ng container via the Podman_REST_API and SHALL verify the container reaches running state within a configurable timeout (default 30 seconds).
2. WHEN `SwitchMode("full_pcap")` is called, THE PCAP_Manager SHALL request a stop of the pcap_ring_writer container via the Podman_REST_API, as the rolling ring buffer is not used in Full_PCAP_Mode.
3. WHEN `SwitchMode("alert_driven")` is called, THE PCAP_Manager SHALL request a stop of the netsniff-ng container and a start of the pcap_ring_writer container, verifying each reaches its target state within the configured timeout.
4. IF a container fails to reach its target state during a mode switch, THEN THE PCAP_Manager SHALL attempt to restore the previous mode's container states and SHALL report the failure to the Config_Manager health stream with the specific container and error.
5. THE PCAP_Manager SHALL expose the current active mode and the state of each mode-relevant container (pcap_ring_writer, netsniff-ng) in the health report so that the Config_Manager can display accurate mode status.
6. WHEN switching to Full_PCAP_Mode, THE PCAP_Manager SHALL verify that the PCAP storage path has sufficient free space (above the low-water mark) before starting netsniff-ng; IF storage is insufficient, THE mode switch SHALL be rejected with a descriptive error.

