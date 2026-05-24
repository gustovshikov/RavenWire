# Requirements Document: PCAP Search and Retrieval

## Introduction

The RavenWire Config Manager currently provides Alert-Driven PCAP configuration (ring size, pre/post-alert windows, severity threshold) but has no UI for actually searching, carving, or downloading packet captures from sensors. An analyst who receives a Suricata alert or Zeek log entry today has no way to retrieve the corresponding raw packets through the Config Manager — the core "alert-driven packet evidence" workflow is incomplete.

This feature adds a full PCAP search and retrieval workflow to the Config Manager web UI. Analysts can search for packets by time range, Community ID, 5-tuple, Suricata alert ID, or Zeek UID. The Config Manager dispatches carve requests to the appropriate Sensor Agent, tracks request lifecycle, proxies PCAP file downloads, enforces download permission checks, and maintains a chain-of-custody manifest for evidentiary integrity. Community ID is exposed as the primary pivot field because it is a deterministic hash of the 5-tuple plus protocol, providing a single correlation key across Zeek, Suricata, and Splunk.

The Config Manager does not perform PCAP carving itself. It dispatches carve requests to Sensor Agents via the existing mTLS control API, polls or receives status updates, and proxies the resulting PCAP file back to the analyst's browser. All requests and downloads are recorded in the chain-of-custody manifest and the audit log.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Agent**: The agent process running on each sensor host that performs local operations including PCAP carving.
- **PCAP_Search**: A query submitted by an analyst specifying criteria (time range, Community ID, 5-tuple, alert ID, or Zeek UID) to locate relevant packets on one or more sensors.
- **Carve_Request**: A request dispatched from the Config_Manager to a Sensor_Agent to extract a PCAP file matching the search criteria from the sensor's packet ring buffer.
- **Community_ID**: A deterministic hash (version 1) of the network 5-tuple (source IP, destination IP, source port, destination port, protocol) that produces a stable correlation key across Zeek, Suricata, and Splunk. Format: `1:<base64-encoded-SHA-256>`.
- **Five_Tuple**: The combination of source IP address, destination IP address, source port, destination port, and transport protocol (TCP/UDP/ICMP/etc.) that identifies a network flow.
- **PCAP_File**: A packet capture file in pcap or pcapng format produced by the Sensor_Agent's carve operation.
- **Chain_of_Custody_Manifest**: An immutable record documenting who requested a PCAP, when, with what search criteria, which sensor produced it, the file's SHA-256 hash, file size, and every subsequent download event.
- **Request_History**: A persistent log of all Carve_Requests submitted through the Config_Manager, enabling re-download of previously carved PCAPs without re-carving.
- **Analyst**: A User with the `analyst` Role (or higher) who has `pcap:search` and `pcap:download` Permissions as defined in the auth-rbac-audit spec.
- **Audit_Entry**: An append-only record in the `audit_log` table capturing who did what, when, to which target, and whether it succeeded (from auth-rbac-audit spec).
- **Health_Registry**: The in-memory ETS-backed registry tracking sensor health state, used to determine which sensors are online and reachable.

## Requirements

### Requirement 1: PCAP Search Interface

**User Story:** As an analyst, I want to search for packet captures using multiple criteria types, so that I can quickly locate the raw packets relevant to an investigation.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a PCAP search page at `/pcap/search` accessible to Users with the `pcap:search` Permission.
2. THE Config_Manager SHALL provide the following search modes, selectable by the Analyst:
   - Time range search: sensor selection plus start and end UTC timestamps.
   - Community ID search: a Community_ID string plus optional time range.
   - 5-tuple search: source IP, destination IP, source port, destination port, and protocol, plus optional time range.
   - Alert ID search: a Suricata signature ID (SID) and alert timestamp, plus optional sensor selection.
   - Zeek UID search: a Zeek connection UID string, plus optional sensor selection.
3. WHEN an Analyst selects Community ID search mode, THE Config_Manager SHALL display the Community_ID field as the primary input with prominent placement and helper text explaining its role as a cross-tool correlation key.
4. THE Config_Manager SHALL validate all search inputs before dispatching a Carve_Request:
   - Community_ID values SHALL match the format `1:<base64-string>`.
   - IP addresses SHALL be valid IPv4 or IPv6 addresses.
   - Port numbers SHALL be integers between 0 and 65535.
   - Time ranges SHALL have a start time before the end time.
   - Time ranges SHALL not exceed 24 hours to prevent excessively large carve operations.
5. IF an Analyst submits a search with invalid inputs, THEN THE Config_Manager SHALL display field-level validation errors without submitting a Carve_Request.
6. THE Config_Manager SHALL allow the Analyst to select one or more target sensors from a list of enrolled sensors with online status from the Health_Registry.
7. WHEN no specific sensor is selected, THE Config_Manager SHALL default to searching all enrolled sensors that are currently online.
8. THE Config_Manager SHALL display sensor online/offline status indicators next to each sensor in the selection list, derived from the Health_Registry.

### Requirement 2: Community ID as Primary Pivot

**User Story:** As an analyst, I want Community ID exposed as the primary search pivot, so that I can correlate a single flow across Zeek logs, Suricata alerts, and Splunk events using one identifier.

#### Acceptance Criteria

1. THE Config_Manager SHALL display Community ID search mode as the default selected search mode on the PCAP search page.
2. THE Config_Manager SHALL provide a Community ID calculator tool on the search page that computes a Community_ID from a user-supplied 5-tuple (source IP, destination IP, source port, destination port, protocol).
3. WHEN an Analyst enters a 5-tuple in the calculator, THE Config_Manager SHALL compute the Community_ID using the Community ID v1 algorithm and populate the Community_ID search field with the result.
4. THE Config_Manager SHALL display explanatory text on the search page describing Community ID as a deterministic hash shared by Zeek, Suricata, and Splunk for the same network flow.
5. WHEN an Analyst performs a 5-tuple search, THE Config_Manager SHALL also compute and display the corresponding Community_ID for reference.

### Requirement 3: Carve Request Lifecycle

**User Story:** As an analyst, I want to track the status of my PCAP carve requests from submission through completion, so that I know when results are ready for download.

#### Acceptance Criteria

1. WHEN an Analyst submits a valid PCAP search, THE Config_Manager SHALL create a Carve_Request record with status `pending` and dispatch the carve command to the selected Sensor_Agent(s) via the existing mTLS control API.
2. THE Config_Manager SHALL track each Carve_Request through the following status lifecycle: `pending` → `dispatched` → `carving` → `completed` → `expired`, with an additional `failed` status reachable from `dispatched` or `carving`.
3. WHILE a Carve_Request is in `dispatched` or `carving` status, THE Config_Manager SHALL poll the Sensor_Agent for status updates at a configurable interval (default 5 seconds).
4. WHEN the Sensor_Agent reports that carving is complete, THE Config_Manager SHALL update the Carve_Request status to `completed` and record the PCAP_File metadata (file path on sensor, file size, SHA-256 hash, packet count, time span covered).
5. IF the Sensor_Agent reports a carve failure, THEN THE Config_Manager SHALL update the Carve_Request status to `failed` and record the error reason in the Carve_Request detail field.
6. IF a Carve_Request remains in `dispatched` status for longer than 5 minutes without a status update, THEN THE Config_Manager SHALL mark the request as `failed` with reason `timeout`.
7. THE Config_Manager SHALL display real-time status updates for in-progress Carve_Requests on the search results page using LiveView push updates.
8. WHEN a search targets multiple sensors, THE Config_Manager SHALL create one Carve_Request per sensor and display individual status for each.

### Requirement 4: PCAP Download with Permission Checks

**User Story:** As an analyst, I want to download carved PCAP files through the Config Manager, so that I can analyze raw packets in Wireshark or other tools without direct sensor access.

#### Acceptance Criteria

1. WHEN a Carve_Request reaches `completed` status, THE Config_Manager SHALL display a download button for the PCAP_File.
2. WHEN an Analyst clicks the download button, THE Config_Manager SHALL verify that the Analyst has the `pcap:download` Permission before initiating the download.
3. IF an Analyst without the `pcap:download` Permission attempts to download a PCAP_File, THEN THE Config_Manager SHALL reject the request with a 403 response and record an Audit_Entry with action `permission_denied`.
4. THE Config_Manager SHALL proxy the PCAP_File download from the Sensor_Agent to the Analyst's browser, streaming the file through the Config_Manager rather than exposing direct sensor access.
5. THE Config_Manager SHALL set the `Content-Disposition` header to `attachment` with a descriptive filename including the sensor name, search criteria summary, and timestamp.
6. THE Config_Manager SHALL set the `Content-Type` header to `application/vnd.tcpdump.pcap` for pcap files or `application/octet-stream` for pcapng files.
7. WHEN a PCAP_File download completes, THE Config_Manager SHALL record a download event in the Chain_of_Custody_Manifest including the downloading User, timestamp, and client IP address.
8. WHEN a PCAP_File download completes, THE Config_Manager SHALL record an Audit_Entry with action `pcap_download`, the Carve_Request ID as target, and the file SHA-256 hash in the detail field.

### Requirement 5: PCAP Request History

**User Story:** As an analyst, I want to view my past PCAP requests and re-download previously carved files, so that I can revisit evidence without re-carving from the sensor.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a PCAP request history page at `/pcap/requests` accessible to Users with the `pcap:search` Permission.
2. THE Config_Manager SHALL display all Carve_Requests in reverse chronological order with columns: request timestamp, requesting User, search criteria summary, target sensor(s), status, and file size (when completed).
3. WHEN an Analyst views the request history, THE Config_Manager SHALL show only requests submitted by the current User, unless the User has the `platform-admin` Role, in which case all requests are visible.
4. THE Config_Manager SHALL support filtering request history by: date range, status, sensor name, and search type (Community ID, 5-tuple, time range, alert ID, Zeek UID).
5. WHEN a completed Carve_Request's PCAP_File is still available on the sensor, THE Config_Manager SHALL display a re-download button that initiates a download without re-carving.
6. WHEN a completed Carve_Request's PCAP_File is no longer available on the sensor (expired or pruned), THE Config_Manager SHALL display the request as `expired` and offer a "Re-submit" button that creates a new Carve_Request with the same search criteria.
7. THE Config_Manager SHALL paginate request history results with a default page size of 25 entries.

### Requirement 6: Chain-of-Custody Manifest

**User Story:** As an analyst or auditor, I want a tamper-evident chain-of-custody record for every PCAP file, so that packet evidence can be used in incident reports and legal proceedings.

#### Acceptance Criteria

1. WHEN a Carve_Request reaches `completed` status, THE Config_Manager SHALL create a Chain_of_Custody_Manifest record containing:
   - The Carve_Request identifier.
   - The requesting User's username and display name.
   - The request timestamp (UTC, microsecond precision).
   - The search criteria used (type, parameters, time range).
   - The target sensor name and identifier.
   - The PCAP_File SHA-256 hash.
   - The PCAP_File size in bytes.
   - The packet count and time span covered by the PCAP_File.
2. WHEN a PCAP_File is downloaded, THE Config_Manager SHALL append a download event to the Chain_of_Custody_Manifest containing: the downloading User's username, the download timestamp, and the client IP address.
3. THE Config_Manager SHALL NOT provide any interface or API to modify or delete Chain_of_Custody_Manifest records.
4. THE Config_Manager SHALL expose a manifest view page at `/pcap/requests/:id/manifest` accessible to Users with the `pcap:search` Permission, displaying the full chain-of-custody timeline for a Carve_Request.
5. THE Config_Manager SHALL provide a downloadable manifest export in JSON format, including all custody events, suitable for inclusion in incident reports.
6. WHEN a manifest is exported, THE Config_Manager SHALL record an Audit_Entry with action `pcap_manifest_export` and the Carve_Request ID as target.
7. THE Config_Manager SHALL compute and display a manifest integrity hash (SHA-256 of the serialized manifest content) that can be independently verified.

### Requirement 7: Carve Request Dispatch via Sensor Agent

**User Story:** As a system operator, I want PCAP carve requests dispatched through the existing Sensor Agent control API, so that the Config Manager never needs direct access to sensor storage.

#### Acceptance Criteria

1. THE Config_Manager SHALL dispatch Carve_Requests to the Sensor_Agent via `POST /control/pcap/carve` on the mTLS control API, following the same pattern as existing `SensorAgentClient` functions.
2. THE Config_Manager SHALL include the following fields in the carve request payload: search type, search parameters (Community ID, 5-tuple fields, alert ID, or Zeek UID), start timestamp, end timestamp, and a request identifier for correlation.
3. THE Config_Manager SHALL poll the Sensor_Agent for carve status via `GET /control/pcap/carve/:request_id` at the configured polling interval.
4. THE Config_Manager SHALL download completed PCAP files from the Sensor_Agent via `GET /control/pcap/download/:request_id`, streaming the response to the Analyst's browser.
5. IF the target Sensor_Agent is unreachable (no `control_api_host` or connection failure), THEN THE Config_Manager SHALL mark the Carve_Request as `failed` with reason `sensor_unreachable` and display an error to the Analyst.
6. IF the Sensor_Agent returns a validation error (HTTP 422) for the carve request, THEN THE Config_Manager SHALL mark the Carve_Request as `failed` and display the Sensor_Agent's error message to the Analyst.

### Requirement 8: PCAP Search and Download Audit Logging

**User Story:** As an auditor, I want all PCAP search, carve, and download actions recorded in the audit log, so that access to raw packet data is fully attributable.

#### Acceptance Criteria

1. WHEN an Analyst submits a PCAP search, THE Config_Manager SHALL record an Audit_Entry with action `pcap_search` containing the search type, search parameters, and target sensor(s).
2. WHEN a Carve_Request is dispatched to a Sensor_Agent, THE Config_Manager SHALL record an Audit_Entry with action `pcap_carve_dispatch` containing the Carve_Request ID, sensor name, and search criteria.
3. WHEN a Carve_Request completes successfully, THE Config_Manager SHALL record an Audit_Entry with action `pcap_carve_complete` containing the Carve_Request ID, file size, and SHA-256 hash.
4. WHEN a Carve_Request fails, THE Config_Manager SHALL record an Audit_Entry with action `pcap_carve_failed` containing the Carve_Request ID and failure reason.
5. WHEN a PCAP_File is downloaded, THE Config_Manager SHALL record an Audit_Entry with action `pcap_download` containing the Carve_Request ID, downloading User, file SHA-256 hash, and client IP address.
6. WHEN a Chain_of_Custody_Manifest is exported, THE Config_Manager SHALL record an Audit_Entry with action `pcap_manifest_export` containing the Carve_Request ID and export format.
7. WHEN a permission check denies a PCAP search or download action, THE Config_Manager SHALL record an Audit_Entry with action `permission_denied` following the pattern established in the auth-rbac-audit spec.

### Requirement 9: PCAP File Expiration and Cleanup

**User Story:** As a system operator, I want PCAP carve results to expire after a configurable retention period, so that sensor disk space is not consumed indefinitely by carved files.

#### Acceptance Criteria

1. THE Config_Manager SHALL track a `expires_at` timestamp on each completed Carve_Request, set to the completion time plus a configurable retention period (default 72 hours, configurable via `RAVENWIRE_PCAP_RETENTION_HOURS` environment variable).
2. WHEN a Carve_Request's `expires_at` timestamp has passed, THE Config_Manager SHALL update the request status to `expired` and SHALL NOT attempt to download the file from the sensor.
3. THE Config_Manager SHALL NOT delete PCAP files from the sensor; file cleanup is the responsibility of the Sensor_Agent's local storage management.
4. WHEN an Analyst attempts to download an expired Carve_Request, THE Config_Manager SHALL display a message indicating the file has expired and offer a "Re-submit" button to create a new Carve_Request with the same search criteria.

### Requirement 10: Navigation and Route Structure

**User Story:** As an analyst, I want a clear navigation structure for PCAP operations, so that I can quickly access search, active requests, and request history.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose the following routes for PCAP operations:
   - `/pcap` — PCAP landing page with navigation to search, active requests, and history.
   - `/pcap/search` — PCAP search form and results.
   - `/pcap/requests` — PCAP request history.
   - `/pcap/requests/:id` — Individual Carve_Request detail with status and download.
   - `/pcap/requests/:id/manifest` — Chain-of-custody manifest for a Carve_Request.
2. THE Config_Manager SHALL protect all `/pcap/*` routes with the `pcap:search` Permission, except that the download action within `/pcap/requests/:id` SHALL additionally require the `pcap:download` Permission.
3. THE Config_Manager SHALL add a "PCAP" navigation link to the main application navigation bar, visible only to Users whose Role includes the `pcap:search` Permission.
4. THE Config_Manager SHALL display active (non-terminal) Carve_Request count as a badge on the PCAP navigation link when the Analyst has in-progress requests.

### Requirement 11: Sensor Agent PCAP Carve API Contract

**User Story:** As an engineer implementing the carve dispatch, I want a clear API contract between the Config Manager and Sensor Agent, so that both sides can be implemented and tested independently.

#### Acceptance Criteria

1. THE Config_Manager SHALL send carve requests as JSON payloads to `POST /control/pcap/carve` with the following structure:
   - `request_id`: UUID string for correlation.
   - `search_type`: one of `time_range`, `community_id`, `five_tuple`, `alert_id`, `zeek_uid`.
   - `params`: object containing search-type-specific fields.
   - `start_time`: ISO 8601 UTC timestamp.
   - `end_time`: ISO 8601 UTC timestamp.
2. THE Config_Manager SHALL expect carve status responses from `GET /control/pcap/carve/:request_id` with the following structure:
   - `request_id`: UUID string.
   - `status`: one of `queued`, `carving`, `completed`, `failed`.
   - `file_path`: string (present when `completed`).
   - `file_size_bytes`: integer (present when `completed`).
   - `sha256`: string (present when `completed`).
   - `packet_count`: integer (present when `completed`).
   - `time_span_start`: ISO 8601 UTC timestamp (present when `completed`).
   - `time_span_end`: ISO 8601 UTC timestamp (present when `completed`).
   - `error`: string (present when `failed`).
3. THE Config_Manager SHALL download PCAP files from `GET /control/pcap/download/:request_id` and expect the response body to be the raw PCAP file content with appropriate content-type headers.

### Requirement 12: Community ID Computation

**User Story:** As an engineer implementing Community ID search, I want the Community ID computation to follow the published specification, so that IDs match those generated by Zeek, Suricata, and Splunk.

#### Acceptance Criteria

1. THE Config_Manager SHALL compute Community ID version 1 hashes using the algorithm defined in the Community ID specification: SHA-256 hash of (seed + source IP + destination IP + protocol + padding + source port + destination port) with canonical ordering of source and destination.
2. THE Config_Manager SHALL format Community ID values as `1:<base64-encoded-hash>` where the prefix `1` indicates version 1.
3. THE Config_Manager SHALL use a default seed value of 0, consistent with the default used by Zeek, Suricata, and Splunk.
4. THE Config_Manager SHALL canonically order the source and destination by comparing IP addresses (and ports for equal IPs) to ensure the same Community_ID is produced regardless of traffic direction.
5. THE Config_Manager SHALL validate that user-supplied Community_ID values match the expected format before using them in search queries.
