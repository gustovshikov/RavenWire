# Implementation Plan: Sensor Stack Production Hardening

## Overview

Incremental implementation across four phases: reliability (alert-to-PCAP path, protocol fixes, severity logic), manageability (container lifecycle, BPF restart, Vector config templating), throughput (TPACKET_V3 capture engine), and analyst utility (evidence-grade PCAP metadata). Each task builds on the previous, ending with full integration.

## Tasks

- [ ] 1. Create `internal/ringctl` shared protocol package
  - Create `sensor-agent/internal/ringctl/ringctl.go` defining `MarkPreAlertCmd`, `CarveWindowCmd`, `ConfigureCmd`, `StatusCmd`, and `RingResponse` structs with all fields using nanosecond timestamps (`timestamp_ns`, `pre_alert_ns`, `post_alert_ns`)
  - Export a `DialAndSend` helper that verifies socket ownership (UID 10000 or root) and permissions (0600) before connecting
  - Remove all independently-defined protocol field structs from `internal/pcap` and `cmd/pcap-ring-writer`; update both to import `internal/ringctl`
  - _Requirements: 2.1, 2.2, 6.3_

  - [ ]* 1.1 Write property test for Ring_Control_Protocol serialization round-trip
    - **Property 2: Ring_Control_Protocol serialization round-trip**
    - For any valid command struct, encode with PCAP_Manager serializer and decode with pcap_ring_writer deserializer; assert all field values are identical and timestamps are preserved as nanoseconds
    - **Validates: Requirements 2.1, 2.3, 2.4**

- [ ] 2. Fix alert severity logic and `mark_pre_alert` timestamp field
  - In `internal/pcap`, correct `HandleAlert` so it discards when `alert.Severity > m.severityThresh` (fix the inverted condition)
  - Rename the `timestamp_ms` field in the `mark_pre_alert` handler to `timestamp_ns` using the new `ringctl.MarkPreAlertCmd` struct
  - Update the `SensorConfig` schema comment to document that lower numeric severity = higher priority (Suricata convention)
  - Add `SeverityThreshold` to `SensorConfig` as the single source of truth; ensure the Vector config template (task 10) reads this same field for the alert routing rule so both PCAP_Manager and Vector use the same threshold value
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 2.6_

  - [ ]* 2.1 Write property test for severity filter correctness
    - **Property 3: Severity filter correctness**
    - For any alert severity (1, 2, 3) and any configured threshold, assert `HandleAlert` triggers a carve iff `severity <= threshold` and discards iff `severity > threshold`
    - **Validates: Requirements 3.1, 3.2**

- [ ] 3. Implement Alert_Listener HTTP server and extend AlertEvent struct
  - In `internal/pcap`, extend the `AlertEvent` struct to include `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `signature`, `uuid`, and `zeek_uid` fields (matching the design's `AlertEvent` definition) so these values flow through to the PCAP index
  - Implement the `Alert_Listener` HTTP server binding on a configurable address (default `:9092`)
  - Implement `POST /alerts`: validate required fields (`community_id`, `severity`, `timestamp_ms`, `sid`); return 400 on invalid, 202 on accepted, 429 when bounded queue is full (log dropped alert's `community_id` and `sid`)
  - Implement `GET /alerts/health`: return 200 with queue depth and deduplication cache size
  - Ensure the listener starts before the control API is declared ready
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7_

  - [ ]* 3.1 Write property test for alert payload validation
    - **Property 1: Alert payload validation rejects any payload missing required fields**
    - For any HTTP POST payload missing one or more required fields, assert the listener returns HTTP 400 and the alert is not enqueued
    - **Validates: Requirements 1.3**

- [ ] 4. Implement alert deduplication
  - In `internal/pcap`, implement in-memory deduplication keyed on `(community_id, sid, sensor_id)` with TTL equal to the configured dedup window (default 30s)
  - Add a background goroutine to sweep expired entries
  - _Requirements: 1.6_

  - [ ]* 4.1 Write property test for alert deduplication within the time window
    - **Property 4: Alert deduplication within the time window**
    - For any alert event, sending the same alert twice within the dedup window results in exactly one carve; the second is discarded
    - **Validates: Requirements 1.6**

- [ ] 5. Checkpoint — Phase 1 reliability
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement real Podman container lifecycle control
  - In `internal/pcap` and `internal/capture`, implement `restartContainerViaPodman` as a real HTTP request to the Podman REST API over the configured Unix socket using `/containers/{name}/restart`
  - Implement the container name allowlist; reject and log requests for names not in the list without calling the Podman API
  - Set a configurable timeout on Podman API requests (default 60s); query container state after restart and return actual state
  - Log restart request and resulting state as audit events including requesting actor identity from mTLS client cert
  - Prefer `systemctl restart <quadlet-unit>` when Quadlet unit name can be resolved; fall back to Podman API
  - Log a warning at startup if the Podman socket is not accessible; return errors on restart attempts until accessible
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [ ]* 6.1 Write property test for container restart allowlist enforcement
    - **Property 7: Container restart allowlist enforcement**
    - For any container name not in the allowlist, assert the restart request is rejected with a logged error and no HTTP request is made to the Podman REST API
    - **Validates: Requirements 5.2**

- [ ] 7. Implement safe BPF filter change handling
  - In `internal/capture`, classify Zeek and Suricata BPF changes as restart-required (no SIGHUP/SIGUSR2)
  - Implement BPF bytecode compilation validation before any config write; reject and log on failure, leave state unchanged
  - Implement the safe restart sequence: write new filter to staging path → request container restart via Podman API → poll until running or timeout (30s) → on timeout restore previous filter and retry once → on second failure log critical and report to Config_Manager health stream
  - Implement `SO_ATTACH_FILTER` reattachment in pcap_ring_writer for the `configure` command path (replace stub `ok` response)
  - Emit audit log entry on every BPF filter change: previous filter hash, new filter hash, affected consumers, restart required per consumer
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.8_

  - [ ]* 7.1 Write property test for BPF filter validation before state mutation
    - **Property 5: BPF filter validation before state mutation**
    - For any BPF filter string that fails compilation, assert the Capture_Manager rejects the change and leaves existing filter file contents and process state unchanged
    - **Validates: Requirements 4.2, 4.3**

  - [ ]* 7.2 Write property test for BPF filter change audit log completeness
    - **Property 6: BPF filter change audit log completeness**
    - For any BPF filter change (valid or invalid), assert the audit log entry contains previous filter hash, new filter hash, affected consumers, and restart-required flag per consumer
    - **Validates: Requirements 4.8**

- [ ] 8. Implement `SwitchMode` container orchestration
  - In `internal/pcap`, extend `SwitchMode("full_pcap")` to start netsniff-ng and stop pcap_ring_writer via Podman REST API, verifying each reaches target state within timeout (30s)
  - Extend `SwitchMode("alert_driven")` to stop netsniff-ng and start pcap_ring_writer, verifying target states
  - On failure, attempt to restore previous mode's container states and report failure to Config_Manager health stream
  - Verify sufficient free storage before starting netsniff-ng in Full_PCAP_Mode; reject with descriptive error if below low-water mark
  - Expose current active mode and per-container state in the health report
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6_

- [ ] 9. Checkpoint — Phase 2 manageability (container lifecycle)
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Implement Vector configuration templating
  - In `internal/config`, extend `applyPoolConfig` to generate the Vector config from the sensor config bundle using a template engine
  - Generated config enables only sinks present in the bundle; omit Splunk HEC and Cribl HTTP sinks if not configured
  - Include Alert_Listener sink routing qualifying Suricata alerts using the same severity threshold as PCAP_Manager
  - Include dead-letter file sink when `dead_letter_path` is configured in the bundle
  - Apply the selected schema transform (`raw`/`ecs`/`ocsf`/`splunk_cim`) per sink
  - Run `vector validate` on the generated config before writing to disk; reject bundle and return validation error on failure
  - After Vector reload, poll Vector's internal health endpoint until healthy within timeout (default 15s); restore previous config and reload if not healthy
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

  - [ ]* 10.1 Write property test for Vector config sink isolation
    - **Property 11: Vector config sink isolation**
    - For any sensor config bundle specifying a subset of sinks, assert the generated Vector config contains exactly those sinks and no others
    - **Validates: Requirements 8.2**

- [ ] 11. Harden control-plane security
  - In `internal/api`, fail startup with a fatal error if certs are absent and `SENSOR_DEV_MODE` is not set; log a prominent warning on every startup when `SENSOR_DEV_MODE=true`
  - Add `X-Request-ID` header to every control API response; include request ID in all outbound Podman API calls and audit log entries
  - Implement CRL check at TLS handshake via a custom `VerifyPeerCertificate` callback; reject connections presenting revoked certificates
  - Bind the enrollment listener on a separate port (default `:9090`) accepting only `POST /enroll`; return 404 for all other paths on that port
  - Verify pcap_ring_writer socket ownership (UID 10000 or root) and permissions (0600) in `ringctl.DialAndSend` before connecting
  - Update Quadlet/Compose container definitions to mount only the specific socket files (`/var/run/podman/podman.sock` and `/var/run/sensor/pcap_ring.sock`) as individual bind mounts rather than the broad `/var/run` directory
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

- [ ] 12. Checkpoint — Phase 2 manageability (security + config)
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 12.5. Expose BPF "restart required" status to Config_Manager
  - In `internal/capture`, track a per-consumer `bpf_restart_pending` flag that is set when a BPF filter change has been validated and written but the container restart has not yet completed
  - Include `bpf_restart_pending` per consumer in the health report streamed to Config_Manager
  - In the Config_Manager (Elixir), surface the `bpf_restart_pending` flag as a "restart required" indicator in the sensor detail view for any Sensor_Pod reporting it
  - _Requirements: 4.7_

- [ ] 13. Rewrite pcap_ring_writer capture loop to TPACKET_V3
  - In `cmd/pcap-ring-writer`, replace the `recvfrom()`-based capture loop with a TPACKET_V3 block-based AF_PACKET ring
  - Implement: create AF_PACKET socket → set `TPACKET_V3` via `PACKET_VERSION` setsockopt → configure block size (`TPACKET_BLOCK_SIZE_MB`, default 4MB) and frame count (`TPACKET_FRAME_COUNT`, default 2048) → `mmap` the ring → spawn `RING_WORKERS` goroutines (default 1) each polling a TPACKET_V3 block via `poll()`
  - Use `tp_sec`/`tp_nsec` from the block header as the packet timestamp (not `time.Now()`)
  - Expose `socket_drops` and `socket_freeze_queue_drops` via `PACKET_STATISTICS` getsockopt in the `status` command response
  - Log configured block size, frame count, and total ring memory allocation at initialization
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.7_

- [ ] 14. Add pcap_ring_writer benchmark harness
  - In `cmd/pcap-ring-writer`, implement a benchmark harness that measures sustained packet rate and drop percentage at 1Gbps, 10Gbps, and 25Gbps traffic profiles using a replay tool
  - Write benchmark results to a structured JSON report
  - _Requirements: 10.6_

- [ ] 15. Checkpoint — Phase 3 throughput
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 16. Extend PCAP index schema and `PcapFile` model
  - In `internal/pcap`, update the `PcapFile` struct to include all required fields: `sha256_hash`, `file_size_bytes`, `sensor_id`, `alert_sid`, `alert_signature`, `alert_uuid`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `community_id`, `zeek_uid`, `capture_interface`, `carve_reason`, `requested_by`, `created_at_ms`, `retention_expires_at_ms`, `chain_of_custody_manifest_path`
  - Write a backward-compatible SQLite schema migration adding new columns with `DEFAULT NULL`
  - _Requirements: 9.1, 9.7_

  - [ ]* 16.1 Write property test for PCAP index entry completeness and round-trip fidelity
    - **Property 8: PCAP index entry completeness and round-trip fidelity**
    - For any carved PCAP file, assert the index entry contains all required fields, the stored `sha256_hash` matches the SHA256 of the actual file contents, and querying by `community_id` returns a record with identical field values to those inserted
    - **Validates: Requirements 9.1, 9.2, 9.6**

- [ ] 17. Implement SHA256 hashing and Chain_of_Custody_Manifest
  - In `internal/pcap`, compute SHA256 hash of each carved PCAP file after carve completes and before writing the index entry
  - Generate a Chain_of_Custody_Manifest (JSON Lines file) at carve time recording: carve event, requesting actor, triggering alert, and file hash
  - Append an access event to the manifest whenever a PCAP file is accessed via the carve API, recording accessor identity, timestamp, and purpose
  - _Requirements: 9.2, 9.3, 9.4_

  - [ ]* 17.1 Write property test for Chain_of_Custody_Manifest access event append
    - **Property 9: Chain_of_Custody_Manifest access event append**
    - For any PCAP file access via the carve API, assert an access event is appended to the manifest containing accessor identity, timestamp, and purpose
    - **Validates: Requirements 9.4**

- [ ] 18. Implement PCAP retention pruning
  - In `internal/pcap`, implement a pruning cycle that deletes PCAP files and their index entries when `retention_expires_at_ms` is set and the current time exceeds it
  - _Requirements: 9.5_

  - [ ]* 18.1 Write property test for retention pruning
    - **Property 10: Retention pruning removes expired entries**
    - For any index entry where `retention_expires_at_ms` is set and current time exceeds it, assert the pruning cycle deletes both the file from disk and the index entry
    - **Validates: Requirements 9.5**

- [ ] 19. Extend health collector with per-consumer statistics
  - In `internal/health`, source pcap_ring_writer stats via the `status` command on the Ring_Control_Protocol socket: `packets_written`, `bytes_written`, `wrap_count`, `socket_drops`, `socket_freeze_queue_drops`; derive `overwrite_risk` when `wrap_count` has incremented more than once since the last interval
  - Collect Suricata capture stats from EVE stats event stream or `stats.log`: `capture.kernel_packets`, `capture.kernel_drops`, `capture.kernel_ifdrops`
  - Collect Zeek process health: uptime from `/proc/<pid>/stat`, log write lag from file mtime, degraded state flag
  - Collect Vector internal metrics: records ingested per second, sink connectivity status, disk buffer utilization percentage
  - Add `ThroughputBps` per consumer derived from successive byte count deltas; add `DropAlert` flag when drop percentage exceeds `drop_alert_thresh_pct` (default 1%) and log a warning
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [ ]* 19.1 Write property test for health report drop alert flag accuracy
    - **Property 12: Health report drop alert flag accuracy**
    - For any capture consumer whose `drop_percent` exceeds `drop_alert_thresh_pct`, assert `drop_alert: true`; consumers below the threshold assert `drop_alert: false`
    - **Validates: Requirements 7.7**

- [ ] 20. Checkpoint — Phase 4 analyst utility
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 21. Implement Host_Readiness_Checker NIC and host tuning validation
  - In `internal/readiness`, implement checks: GRO disabled (hard), LRO disabled (hard), RX ring buffer >= minimum (soft), promiscuous mode enabled (hard), RSS queues >= worker count (soft), CPU isolation when `CAPTURE_CPU_LIST` configured (soft), NVMe write throughput >= minimum (hard), clock sync within bounds via `adjtimex` (hard)
  - Each check result includes `name`, `passed`, `observed_value`, `required_value`, `severity` (hard/soft)
  - Hard failures block the bootstrap sequence; soft warnings are logged and reported without blocking
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

  - [ ]* 21.1 Write property test for readiness checker failure report completeness
    - **Property 13: Readiness checker failure report completeness**
    - For any failing readiness check, assert the report includes check name, observed value, and required value; hard failures have `severity: "hard"`, soft warnings have `severity: "soft"`
    - **Validates: Requirements 12.6, 12.7**

- [ ] 22. Implement bootstrap state machine
  - In `cmd/sensor-agent`, implement the bootstrap state machine with states: `installed` → `enrolling` → `pending_approval` → `config_received` → `config_validated` → `capture_active`; log each state transition
  - In `enrolling` state: POST to Config_Manager enrollment endpoint with one-time token, pod name, and public key; retry with exponential backoff (initial 5s, max 60s) on failure
  - In `pending_approval` state: poll Config_Manager for approval at configurable interval (default 30s); transition to `config_received` when cert and config bundle are issued
  - In `config_received` state: validate bundle using Rule_Validator and Capture_Manager validation before writing any files; remain in state and report errors to Config_Manager on failure
  - In `config_validated` state: run Host_Readiness_Checker; on all hard checks passing, write config, start capture processes, transition to `capture_active`
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [ ]* 22.1 Write property test for bootstrap state machine forward-only transitions
    - **Property 14: Bootstrap state machine forward-only transitions**
    - For any valid bootstrap sequence, assert transitions only advance forward through the defined sequence; no transition skips a state or moves backward except the defined retry loops for `enrolling` and `config_received`
    - **Validates: Requirements 11.1**

  - [ ]* 22.2 Write property test for enrollment retry exponential backoff
    - **Property 15: Enrollment retry exponential backoff**
    - For any sequence of consecutive enrollment failures, assert retry intervals follow exponential backoff starting at 5s, doubling each attempt, capping at 60s
    - **Validates: Requirements 11.2**

  - [ ]* 22.3 Write property test for config validation before file write
    - **Property 16: Config validation before file write**
    - For any config bundle received in `config_received` state, assert Rule_Validator and Capture_Manager validation are invoked before any config file is written; if validation fails, assert no files are written
    - **Validates: Requirements 11.4**

- [ ] 23. Implement `sensorctl enroll` command
  - In `cmd/sensorctl`, implement the `enroll` subcommand that automates token configuration and displays the current bootstrap state and any blocking errors
  - _Requirements: 11.7_

- [ ] 24. Wire all components and final integration
  - Ensure `internal/ringctl` is the sole source of protocol structs for both `sensor-agent` and `cmd/pcap-ring-writer`
  - Ensure `SensorConfig.SeverityThreshold` is the single source of truth used by both PCAP_Manager and the generated Vector config (verify no hardcoded threshold values remain)
  - Ensure the Alert_Listener, deduplication, carve path, SHA256 hashing, manifest creation, and index write are all connected end-to-end
  - Ensure the bootstrap state machine invokes Host_Readiness_Checker, Config_Applier (with Vector config generation), and capture process startup in the correct order
  - Ensure `AlertEvent` fields (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `zeek_uid`) flow through from the Alert_Listener into the PCAP index entry
  - _Requirements: 1.8, 3.4, 8.3_

- [ ] 25. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Property tests use `pgregory.net/rapid`, already a dependency in `sensor-agent/go.mod`
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at phase boundaries
- Property tests validate universal correctness properties; unit tests validate specific examples and edge cases
