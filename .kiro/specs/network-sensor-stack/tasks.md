# Implementation Plan: Network Sensor Stack (MVP — Phases 0–1)

## Overview

Implement the MVP sensor stack in two phases. Phase 0 delivers a proof-of-capture: Zeek and Suricata running with distinct AF_PACKET fanout groups, BPF filter validation, Vector log forwarding, and basic packet/drop metrics. Phase 1 delivers the full Sensor MVP: Sensor_Agent with all 9 internal modules, pcap_ring_writer, Config_Manager basic UI (enrollment + health dashboard + mode switching), mTLS enrollment, Community ID, local PCAP file index, Alert-Driven PCAP mode, Splunk/Cribl forwarding, basic rule deployment, support bundle generation, time synchronization monitoring, and host readiness check.

All code is Go (Sensor_Agent, pcap_ring_writer) and Elixir/Phoenix (Config_Manager) unless otherwise noted. Container definitions use Podman Quadlet.

---

## Tasks

- [x] 0. Phase 0.5 spike — validate hardest MVP assumptions early
  - [x] 0.1 Zeek and Suricata attach to the same mirror interface with separate fanout groups
    - Verify both tools start, receive packets, and produce logs simultaneously without interference
    - Confirm fanout group IDs are distinct and validated at startup
  - [x] 0.2 Vector forwards Zeek and Suricata events to a local file or Cribl/Splunk endpoint
    - Confirm Community ID is present in both Zeek conn.log and Suricata EVE JSON output
    - Confirm Community ID is preserved through Vector normalization
  - [x] 0.3 pcap_ring_writer captures to a memory-mapped ring
    - Confirm ring writer starts, binds AF_PACKET socket with fanout group 4, and writes packets to `/dev/shm/sensor_pcap_ring`
    - Confirm ring wraps correctly under sustained traffic without corruption
  - [x] 0.4 A simulated alert event triggers a pre/post-alert PCAP carve
    - Inject a fake alert event; confirm PCAP Manager carves the correct time window
    - Confirm carved PCAP opens correctly in Wireshark and contains packets from before the alert timestamp
    - Confirm Community ID is present in the carved PCAP metadata
  - [x] 0.5 Document spike findings
    - Record any ring wraparound edge cases, timestamp alignment issues, or tool-specific BPF reload constraints discovered
    - Update design notes if implementation details need adjustment before full Phase 1 build
    - _This spike validates the project's highest-risk assumptions before the full platform depends on them_

- [x] 1. Sensor_Pod container definitions and base infrastructure
  - [x] 1.1 Write Podman Quadlet container unit files for Zeek, Suricata, Vector, sensor_agent, and pcap_ring_writer
    - Define `sensor-svc` (UID 10000) as the run user for all containers
    - Grant only `CAP_NET_RAW` and `CAP_NET_ADMIN` to Zeek, Suricata, and pcap_ring_writer; drop all others
    - Define shared volume mounts: log handoff paths, config paths, Podman socket (sensor_agent only)
    - No hardcoded Node-specific values; all interface names, storage paths, and endpoints via environment variables
    - _Requirements: 1.3, 1.5, 1.6, 15.4, 15.5, 15.6_

  - [x] 1.2 Write Management_Pod Quadlet unit files for config_manager
    - Same `sensor-svc` non-root user; no capabilities required
    - Persistent volume mounts for SQLite DB, RocksDB metric store, enrollment CA
    - All endpoints configurable via environment variables
    - _Note: Strelka frontend/backend containers are added in v1 (Phase 2). MVP Management_Pod contains Config_Manager only._
    - _Requirements: 1.1, 1.2, 1.4, 1.6_

  - [x] 1.3 Implement startup dependency ordering and pipeline separation
    - Zeek, Suricata, Vector start only after sensor_agent readiness check passes
    - Analysis pipeline containers (Zeek, Suricata, Vector) defined in a separate systemd target from the capture infrastructure
    - Verify that a crash in one analysis container does not restart others
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 2. AF_PACKET capture configuration and BPF filter validation (Phase 0)
  - [x] 2.1 Implement capture configuration schema and parser (Go)
    - Define `CaptureConfig` struct: per-consumer fanout group ID, fanout mode, interface name, BPF filter path, thread count
    - Authorized consumers: Zeek (group 1), Suricata (group 2), netsniff-ng (group 3, v1.5), pcap_ring_writer (group 4)
    - Parse from mounted config file (`/etc/sensor/capture.conf`)
    - Return structured validation errors for each invalid field; duplicate fanout group IDs across any consumers are an error
    - _Requirements: 2.1, 2.2, 2.3_

  - [x]* 2.2 Write property test for capture configuration validation (Property 1)
    - **Property 1: Capture Consumer Fanout Group Uniqueness**
    - Generate arbitrary valid configs with 2–3 consumers; assert all fanout group IDs are distinct
    - **Validates: Requirements 2.2**

  - [x]* 2.3 Write property test for invalid configuration rejection (Property 2)
    - **Property 2: Invalid Capture Configuration Rejection**
    - Generate configs with at least one invalid field (duplicate fanout ID, bad BPF, zero thread count, unknown interface); assert Sensor_Agent rejects and returns descriptive error without starting any capture process
    - **Validates: Requirements 2.3**

  - [x] 2.4 Implement BPF filter compilation and socket attachment (Go)
    - Compile BPF filter text to bytecode using `SO_ATTACH_FILTER`
    - Apply per-consumer socket before fanout group join
    - Support elephant flow exclusion classes: iSCSI (TCP/3260), NFS (TCP/UDP 2049), configurable CIDR pairs
    - Return compilation error with line/token detail on invalid filter syntax
    - _Requirements: 2.4, 2.5_

  - [x] 2.5 Implement BPF filter reload in Sensor_Agent Capture Manager (Go)
    - Watch `/etc/sensor/bpf_filters.conf` for changes (inotify)
    - For pcap_ring_writer: recompile filter and send updated filter to pcap_ring_writer via its Unix socket control interface (`configure` command with new BPF profile)
    - For Zeek and Suricata: validate the new BPF profile, write the updated tool-specific capture config (e.g., Zeek's `af_packet.bpf_filter`, Suricata's `bpf-filter`), and trigger a controlled capture reload (SIGHUP/SIGUSR2)
    - Report per-consumer whether filter was applied live or required a socket rebind; report event to Config_Manager
    - _Note: Sensor_Agent does not directly attach filters to Zeek/Suricata sockets — those tools own their own sockets. Filter changes go through each tool's config reload path._
    - _Requirements: 2.6_

  - [x] 2.6 Expose per-consumer packet receive and drop counters
    - Read `/proc/net/packet` or `PACKET_STATISTICS` socket option per consumer
    - Expose counters via Sensor_Agent health report
    - _Requirements: 2.7, 10.4_

- [x] 3. Sensor_Agent core — Control API and module skeleton (Phase 1)
  - [x] 3.1 Implement Sensor_Agent binary entry point and module wiring (Go)
    - Static binary; initialize all 9 modules: Control API, Health Collector, Config Applier, Capture Manager, PCAP Manager, Rule Validator, Certificate Manager, Local Audit Logger, Host Readiness Checker
    - Each module exposes a well-defined internal interface; no cross-module direct calls outside defined interfaces
    - MVP module scope: Control API (full), Health Collector (full), Config Applier (basic — Zeek/Suricata/Vector/BPF), Capture Manager (validation + pcap_ring_writer control), PCAP Manager (alert-driven only), Rule Validator (Suricata + BPF only), Certificate Manager (enrollment + basic rotation), Local Audit Logger (JSON lines), Host Readiness Checker (core checks: interface, capabilities, disk, clock, AF_PACKET)
    - _Requirements: 11.1, 11.8_

  - [x] 3.2 Implement Control API module — mTLS REST server with action allowlist (Go)
    - Listen on port 9091 (mTLS)
    - Implement all 9 allowlisted routes: `POST /control/reload/zeek`, `POST /control/reload/suricata`, `POST /control/restart/vector`, `POST /control/capture-mode`, `POST /control/config`, `POST /control/cert/rotate`, `GET /health`, `POST /control/pcap/carve`, `POST /control/config/validate`
    - Reject any request not matching the allowlist with HTTP 403 and a local audit log entry
    - _Requirements: 11.2, 11.3, 11.4_

  - [x]* 3.3 Write property test for Sensor_Agent action allowlist enforcement (Property 7)
    - **Property 7: Sensor_Agent Action Allowlist Enforcement**
    - Generate arbitrary HTTP method + path combinations; assert that only the 9 allowlisted (method, path) pairs are accepted and all others return HTTP 403 with a logged error and no container operation is performed
    - **Validates: Requirements 11.4, 15.7**

  - [x] 3.4 Implement Local Audit Logger module (Go)
    - Append-only JSON-lines log at `/var/sensor/audit.log`
    - Log every control action received (accepted or rejected), with timestamp, action, actor identity (from mTLS cert CN), and result
    - _Requirements: 11.1_

  - [x] 3.5 Implement Host Readiness Checker module (Go)
    - Validate before enabling capture: monitored interface existence and link state, NIC driver compatibility (AF_PACKET support), disk write speed (configurable minimum), available storage, time synchronization status (clock offset within threshold), required Linux capabilities, kernel AF_PACKET support
    - Return structured readiness report; block capture start on any failed check
    - _Requirements: 11.7_

- [x] 4. Sensor_Agent — Health Collector and gRPC health stream (Phase 1)
  - [x] 4.1 Define gRPC protobuf schema for health streaming
    - Implement `HealthReport`, `ContainerHealth`, `CaptureStats`, `ConsumerStats`, `StorageStats`, `ClockStats` messages as defined in the design
    - Generate Go stubs
    - _Requirements: 11.5_

  - [x] 4.2 Implement Health Collector module (Go)
    - Scrape container stats (CPU, memory, state, uptime) from Podman socket at configurable interval
    - Collect AF_PACKET drop counters per consumer (from task 2.6)
    - Collect disk usage for PCAP storage paths
    - Collect clock offset via `adjtimex` or NTP query
    - Assemble `HealthReport` protobuf message
    - _Requirements: 10.4, 11.1, 22.2_

  - [x] 4.3 Implement gRPC health stream client (Go)
    - Establish persistent bidirectional gRPC stream to Config_Manager on port 9090 (mTLS)
    - Stream `HealthReport` at configured interval
    - On disconnect: buffer reports to `/var/sensor/health-buffer.bin` (configurable max size); reconnect with exponential backoff (1s → 60s max); replay buffer on reconnect
    - _Requirements: 11.5, 11.6, 25.1_

- [x] 5. Sensor_Agent — Config Applier and offline operation (Phase 1)
  - [x] 5.1 Implement Config Applier module (Go)
    - Accept `apply-pool-config` action payload; write config files to appropriate paths for Zeek, Suricata, Vector, BPF filter
    - Signal each service to reload (SIGHUP/SIGUSR2) after writing
    - Persist last-known config to `/etc/sensor/last-known-config.json`
    - _Requirements: 10.12, 11.1, 11.6_

  - [x] 5.2 Implement offline operation — continue on Management_Pod unreachable
    - On startup, load last-known config if Config_Manager is unreachable
    - Continue all capture operations; buffer health metrics locally
    - On reconnect: replay buffered metrics and perform config state reconciliation
    - _Requirements: 11.6, 25.1, 25.2_

- [x] 6. Sensor_Agent — Rule Validator module (Phase 1)
  - [x] 6.1 Implement Rule Validator module (Go)
    - Validate Suricata rule syntax (invoke `suricata -T` in a subprocess or use a Go rule parser)
    - Validate BPF filter syntax (compile via `SO_ATTACH_FILTER` dry-run)
    - Validate YARA rules (invoke `yara --compile-rules` or equivalent)
    - Return structured validation errors per rule/filter
    - _Requirements: 11.1, 2.3_

- [x] 7. Sensor_Agent — Certificate Manager and mTLS enrollment (Phase 1)
  - [x] 7.1 Implement Certificate Manager module (Go)
    - On first start with `SENSOR_ENROLLMENT_TOKEN` set: POST `/enroll` to Config_Manager with token, pod name, and ECDSA P-256 public key
    - Handle 202 (pending approval) and 200 (approved + cert issued) responses
    - Store issued cert and CA chain to `/etc/sensor/certs/`
    - Load cert for all outbound mTLS connections
    - _Requirements: 19.1, 19.2, 15.1_

  - [x] 7.2 Implement automated certificate rotation (Go)
    - Monitor cert expiry; trigger rotation when ≤6h remain on a 24h cert
    - POST `/control/cert/rotate` to Config_Manager; load new cert into memory; drain old connections naturally
    - _Requirements: 19.5_

- [x] 8. pcap_ring_writer process — Alert-Driven rolling ring buffer (Phase 1)
  - [x] 8.1 Implement pcap_ring_writer binary (Go)
    - Static Go binary; bind AF_PACKET socket with fanout group 4 (`CAP_NET_RAW`)
    - Write raw packets to memory-mapped ring at `/dev/shm/sensor_pcap_ring` (configurable size, default 4GB)
    - Expose Unix socket control interface at `/var/run/pcap_ring.sock` for Sensor_Agent PCAP Manager
    - Control commands: `configure`, `mark_pre_alert`, `carve_window`, `status`
    - _Requirements: 5.2, 11.1_

  - [x] 8.2 Implement PCAP Manager module in Sensor_Agent (Go)
    - Control pcap_ring_writer lifecycle (start/stop/configure) via Unix socket
    - Listen for qualifying alert events forwarded from Vector (configurable severity threshold)
    - On qualifying alert: instruct ring writer to mark pre-alert window start; wait for post-alert window; instruct carve to disk
    - Write carved PCAP to `/sensor/pcap/alerts/alert_{community_id}_{timestamp}.pcap`
    - Update SQLite PCAP index with carved file metadata
    - _Requirements: 5.2, 5.3, 5.4, 5.5_

  - [x]* 8.3 Write property test for alert-driven pre-alert window preservation (Property 4)
    - **Property 4: Alert-Driven Pre-Alert Window Preservation**
    - Generate arbitrary alert events with varying pre/post-alert window configs; assert carved PCAP timestamps span from at least `(alert_time - pre_alert_window)` to at least `(alert_time + post_alert_window)`
    - **Validates: Requirements 5.3, 5.4**

  - [x] 8.4 Implement FIFO pruning for alert PCAP storage
    - Monitor `/sensor/pcap/alerts/` storage usage
    - When usage exceeds critical threshold (default 90%): delete oldest alert PCAPs by `start_time` from SQLite index in FIFO order until below low-water mark (default 75%)
    - Log critical error and notify Config_Manager if pruning cannot reclaim space within timeout
    - _Requirements: 5.7_

  - [x]* 8.5 Write property test for PCAP storage FIFO pruning invariant (Property 3)
    - **Property 3: PCAP Storage FIFO Pruning Invariant**
    - Generate arbitrary alert PCAP storage states above the critical threshold; assert that after pruning: used capacity is below the low-water mark, no SQLite index entries reference deleted files, and no files exist without index entries
    - _Note: This test covers alert-driven PCAP pruning (Req 5.7). Full PCAP Mode pruning (Req 4.5) is tested in v1.5._
    - **Validates: Requirements 5.7**

- [x] 9. Local PCAP file index — SQLite Tier 1 (Phase 1)
  - [x] 9.1 Implement SQLite PCAP index (Go)
    - Create `pcap_files` table (Tier 1) with WAL mode: `file_path`, `start_time`, `end_time`, `interface`, `packet_count`, `byte_count`, `alert_driven`
    - Create index `idx_file_time_range` on `(start_time, end_time)`
    - Implement insert, time-range query, and delete-by-id operations
    - _Requirements: 14.1_

- [x] 10. Community ID computation and preservation (Phase 1)
  - [x] 10.1 Integrate Community ID computation into Sensor_Agent and Vector pipeline
    - Implement or import Community ID v1 computation from flow 5-tuple (src_ip, dst_ip, src_port, dst_port, proto) per the community-id spec
    - Ensure Zeek is configured to emit `community_id` field in conn.log and all protocol logs
    - Ensure Suricata EVE JSON includes `community_id` field (enable `community-id: yes` in suricata.yaml)
    - _Requirements: 17.1_

  - [x] 10.2 Configure Vector transformation pipeline to preserve Community ID
    - Write Vector config that reads Zeek log directory (file source) and Suricata EVE JSON (unix socket source)
    - Add remap transform that preserves `community_id` field through all normalization stages without modification
    - Forward to configurable sink (Splunk HEC or Cribl HTTP endpoint, configured via environment variable)
    - _Requirements: 17.1, 17.3, 9.1, 9.2, 9.5_

  - [ ]* 10.3 Write property test for Community ID preservation across output types (Property 11)
    - **Property 11: Community_ID Preservation Across All Output Types**
    - Generate arbitrary flow events; assert that the Community_ID computed from the 5-tuple is present and identical in Zeek log output, Suricata alert output, and Vector-normalized output (raw schema mode at minimum for MVP)
    - **Validates: Requirements 17.1, 17.3**

- [x] 11. Vector log forwarding — Splunk/Cribl sink (Phase 1)
  - [x] 11.1 Implement Vector configuration for Splunk HEC and Cribl HTTP forwarding
    - Write Vector TOML config with: Zeek file source, Suricata unix socket source, Splunk HEC sink and/or HTTP sink (Cribl)
    - Disk-backed buffer (default 1GB); FIFO drop on overflow with warning log
    - All sink endpoints and credentials via environment variables
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [x] 11.2 Implement Vector config hot-reload via Sensor_Agent Config Applier
    - Config Applier writes updated Vector TOML to `/etc/vector/vector.toml`
    - Sends SIGHUP to Vector process to reload without restart
    - _Requirements: 10.13_

- [x] 12. Config_Manager — Elixir/Phoenix application skeleton (Phase 1)
  - [x] 12.1 Scaffold Phoenix LiveView application
    - Mix project with dependencies: Phoenix, Phoenix LiveView, Ecto, Ecto SQLite3, Mint/Finch, x509 (Erlang), Prometheus.ex
    - Configure Ecto repo with SQLite (WAL mode) for enrollment records, pool configs, audit log
    - Configure mTLS on the Phoenix endpoint (port 8443)
    - _Requirements: 10.1, 10.2, 1.2_

  - [x] 12.2 Implement Sensor_Pod enrollment data model and Ecto schema
    - `sensor_pods` schema: id (UUID), name, pool_id, status (enrolled/pending/revoked), cert_serial, cert_expires_at, last_seen_at, enrolled_at, enrolled_by
    - `sensor_pools` schema: id, name, capture_mode, config_version, config_updated_at, config_updated_by
    - Migrations for both tables
    - _Requirements: 19.1, 19.3_

  - [x] 12.3 Implement enrollment CA — ECDSA P-256 certificate authority (Elixir)
    - Generate Intermediate CA keypair on first boot (stored in persistent volume)
    - Implement `POST /enroll` endpoint: validate one-time token, store pending enrollment, return 202
    - On operator approval: issue 24h ECDSA P-256 leaf cert signed by Intermediate CA; return cert + CA chain to Sensor_Agent
    - Mark token as consumed (single-use) after first use regardless of approval outcome
    - _Requirements: 19.1, 19.2, 15.2_

  - [ ]* 12.4 Write property test for enrollment token single-use enforcement (Property 13)
    - **Property 13: Enrollment Token Single-Use Enforcement**
    - Generate arbitrary sequences of enrollment attempts using the same token; assert the token is accepted exactly once and all subsequent uses are rejected regardless of approval state
    - **Validates: Requirements 19.1**

  - [x] 12.5 Implement CRL management and certificate rejection (Elixir)
    - Maintain CRL in Config_Manager; distribute to Sensor_Agents via health stream or dedicated endpoint
    - Reject TLS connections from revoked or expired certs at the Phoenix endpoint
    - Log rejection with presenting identity
    - _Requirements: 19.4, 15.3_

  - [ ]* 12.6 Write property test for certificate rejection (Property 14)
    - **Property 14: Certificate Rejection for Invalid, Expired, or Revoked Identities**
    - Generate TLS connection attempts with (a) syntactically invalid cert, (b) expired cert, (c) cert signed by untrusted CA, (d) cert listed in CRL; assert all four cases are rejected at the TLS handshake layer with a logged rejection
    - **Validates: Requirements 15.3, 19.4**

- [x] 13. Config_Manager — Health dashboard LiveView (Phase 1)
  - [x] 13.1 Implement gRPC health stream server (Elixir)
    - Accept persistent bidirectional gRPC streams from Sensor_Agents on port 9090 (mTLS)
    - Deserialize `HealthReport` protobuf messages
    - Update in-memory Sensor Registry state per pod
    - _Requirements: 11.5, 10.3_

  - [x] 13.2 Implement health dashboard LiveView page
    - Display all connected Sensor_Pods with current operational status (running/stopped/error/restarting)
    - Update via LiveView within 2 seconds of any state change without page refresh
    - Show per-container: state, uptime, CPU%, memory bytes
    - Show per-consumer: packets received, packets dropped, drop percentage
    - _Requirements: 10.3, 10.4_

  - [x] 13.3 Implement clock drift monitoring and degraded pod marking
    - Config_Manager reads `ClockStats.offset_ms` from health reports
    - If offset exceeds configured threshold (default 100ms): mark pod as degraded in UI
    - _Requirements: 22.2, 22.3_

- [x] 14. Config_Manager — Enrollment UI and mode switching (Phase 1)
  - [x] 14.1 Implement enrollment approval LiveView page
    - List pending enrollment requests with pod name and public key fingerprint
    - Approve / Deny actions; approved pods transition to `enrolled` status and receive cert
    - _Requirements: 19.2, 19.3_

  - [x] 14.2 Implement Alert-Driven PCAP configuration UI and mode control dispatch
    - Per-Sensor_Pod Alert-Driven PCAP configuration controls in LiveView: ring size, pre-alert window, post-alert window, alert severity threshold
    - On operator action: POST `switch-capture-mode` to Sensor_Agent control API via mTLS
    - Config_Manager does NOT access Podman socket directly; all lifecycle ops via Sensor_Agent
    - _Note: Full PCAP Mode UI (netsniff-ng controls, NVMe storage config) is added in v1.5 (Phase 4)._
    - _Requirements: 10.5, 10.6, 10.7_

- [x] 15. Basic rule deployment — Suricata rules push to sensor (Phase 1)
  - [x] 15.1 Implement rule bundle delivery via Sensor_Agent apply-pool-config action
    - Config_Manager packages Suricata rules into a bundle and POSTs to `POST /control/config` on the target Sensor_Agent
    - Sensor_Agent Config Applier writes rules to `/etc/suricata/rules/` and sends SIGUSR2 to Suricata
    - Suricata reloads rules without container restart
    - _Requirements: 7.3, 7.4_

  - [x] 15.2 Implement rule validation before deployment (Sensor_Agent Rule Validator)
    - Before writing rules to disk, invoke Rule Validator to check Suricata rule syntax
    - On validation failure: return error to Config_Manager; do not write partial rules
    - _Requirements: 7.3_

- [x] 16. Support bundle generation (Phase 1)
  - [x] 16.1 Implement support bundle generator in Sensor_Agent (Go)
    - On `POST /control/support-bundle` (add to allowlist): collect container logs, NIC stats, AF_PACKET drop counters, disk usage, rule versions, cert status, recent audit log entries
    - Redact sensitive values (IPs, credentials, keys) by default
    - Write to a timestamped tar.gz archive; return path to Config_Manager
    - _Requirements: 25.4_

  - [x] 16.2 Implement support bundle trigger in Config_Manager UI
    - Per-Sensor_Pod "Generate Support Bundle" button in LiveView
    - Download resulting archive via Config_Manager
    - _Requirements: 25.4_

- [x] 17. Internal dev CLI — sensorctl (Phase 1)
  - [x] 17.1 Implement minimal sensorctl binary (Go)
    - `sensorctl enroll --manager <url> --token <token> --name <name>` — trigger Sensor_Agent enrollment
    - `sensorctl status [--sensor <id>]` — print current health snapshot from Sensor_Agent
    - `sensorctl show-drops [--sensor <id>]` — print per-consumer packet/drop counters
    - `sensorctl collect-support-bundle --sensor <id> --output <path>` — trigger support bundle and download
    - All commands use the Sensor_Agent mTLS control API; credentials via env vars or config file
    - _Note: This is an internal development tool, not a stable public API. Full public CLI is Phase 5._
    - _Requirements: 30.1, 30.2 (internal subset)_

- [x] 18. Checkpoint — Phase 0 integration validation
  - Spike (task 0) findings documented and any design adjustments applied
  - Zeek and Suricata start with distinct fanout group IDs validated by Sensor_Agent
  - pcap_ring_writer starts with fanout group 4 and writes to memory-mapped ring
  - BPF filter is applied per-consumer via the correct reload path for each tool
  - Vector forwards logs to configured sink with Community ID present in all events
  - Per-consumer packet/drop counters visible in Sensor_Agent health report
  - Ensure all tests pass; ask the user if questions arise.

- [x] 19. Checkpoint — Phase 1 integration validation
  - Ensure Sensor_Agent enrolls with Config_Manager via one-time token and operator approval
  - Ensure mTLS is enforced on all pod-to-pod communication
  - Ensure Alert-Driven PCAP ring captures pre/post-alert windows and indexes carved files
  - Ensure health dashboard updates within 2 seconds of state changes
  - Ensure mode switching (Alert-Driven ↔ mode config) works without pod restart
  - Ensure support bundle generation produces a sanitized archive
  - Ensure sensorctl dev commands work against a running Sensor_Agent
  - Ensure all tests pass; ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP build
- Property tests use [rapid](https://github.com/flyingmutant/rapid) (Go) for Sensor_Agent properties and [PropCheck](https://github.com/alfert/propcheck) (Elixir) for Config_Manager properties
- Each property test is tagged with its design document property number for traceability
- All Node-specific values (interface names, storage paths, forwarding endpoints) must be environment variables — no hardcoded values in any container image
- The Config_Manager must never access the Podman socket directly; all container lifecycle operations go through the Sensor_Agent control API
- Phase 0 tasks (1–2, 10–11) can be validated independently before Phase 1 work begins
- Full PCAP Mode (netsniff-ng + NVMe Tier 0) is Phase 4 (v1.5) — not in these MVP tasks
- 25Gbps throughput validation is Phase 5 (v2) — MVP targets correct AF_PACKET behavior and measurable drop counters, not line-rate benchmarks
- Strelka integration is Phase 2–3 (v1) — Vector collects only Zeek and Suricata logs in MVP
