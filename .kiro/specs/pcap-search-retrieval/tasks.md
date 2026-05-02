# Implementation Plan: PCAP Search and Retrieval

## Overview

This plan implements the full PCAP search, carve, download, and chain-of-custody workflow for the RavenWire Config Manager. The implementation builds incrementally: first the pure Community ID module, then the data layer (schemas, migrations, context), then the SensorAgentClient extensions, then the status poller, then the LiveView pages and download controller, and finally the navigation and audit wiring. Each step produces testable, integrated code.

## Tasks

- [ ] 1. Implement Community ID v1 computation module
  - [ ] 1.1 Create `lib/config_manager/pcap/community_id.ex` with pure Community ID v1 functions
    - Implement `compute/2` — takes a 5-tuple map and optional seed (default 0), returns `"1:<base64-sha256>"`
    - Implement canonical ordering: compare IPs numerically, then ports for equal IPs, to ensure direction-independence
    - Implement IP packing: IPv4 as 4 bytes, IPv6 as 16 bytes
    - Implement binary packing: `<<seed::16, src_ip::binary, dst_ip::binary, protocol::8, 0::8, src_port::16, dst_port::16>>`
    - Implement `valid_format?/1` — validates `"1:<base64>"` format
    - Implement `parse_ip/1` — parses IPv4/IPv6 string to `:inet.ip_address()`
    - Implement `protocol_number/1` — maps protocol name strings to numbers ("tcp" → 6, "udp" → 17, "icmp" → 1, etc.)
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

  - [ ]* 1.2 Write property tests for Community ID (PropCheck)
    - **Property 2: Community ID v1 computation produces correctly formatted output**
    - **Property 3: Community ID canonical ordering is direction-independent**
    - **Property 4: Community ID format validation accepts only well-formed IDs**
    - Create `test/config_manager/pcap/community_id_prop_test.exs`
    - Generate random valid 5-tuples (IPv4/IPv6, ports 0..65535, protocol 0..255)
    - Verify output format `1:<base64>` with 32-byte decoded hash
    - Verify compute(src, dst) == compute(dst, src) for all generated tuples
    - Verify valid_format? returns true for all computed IDs
    - Verify valid_format? returns false for random non-matching strings
    - **Validates: Requirements 12.1, 12.2, 12.4, 12.5, 2.3**

  - [ ]* 1.3 Write unit tests for Community ID with known test vectors
    - Create `test/config_manager/pcap/community_id_test.exs`
    - Test against published Community ID spec test vectors (TCP, UDP, ICMP flows)
    - Test IPv4 and IPv6 addresses
    - Test default seed = 0
    - Test parse_ip with valid/invalid IP strings
    - Test protocol_number with known and unknown protocols
    - Test valid_format? with edge cases: empty string, missing prefix, invalid base64
    - _Requirements: 12.1, 12.2, 12.3_

- [ ] 2. Implement search parameter validation module
  - [ ] 2.1 Create `lib/config_manager/pcap/search_params.ex` with input validation
    - Define `SearchParams` struct with all search fields
    - Implement `validate/1` — validates raw params map, returns `{:ok, t()}` or `{:error, errors}`
    - Validate Community ID format via `CommunityId.valid_format?/1`
    - Validate IP addresses via `:inet.parse_address/1`
    - Validate port numbers as integers 0..65535
    - Validate time range: start_time < end_time, duration ≤ 24 hours
    - Validate search_type is one of the five valid types
    - Validate at least one search criterion is present per search type
    - Implement `to_carve_payload/1` — converts validated params to Sensor Agent API payload
    - _Requirements: 1.4, 1.5, 7.2, 11.1_

  - [ ]* 2.2 Write property tests for SearchParams (PropCheck)
    - **Property 1: Search input validation correctly accepts valid inputs and rejects invalid inputs**
    - **Property 13: Carve payload contains all required API contract fields**
    - Create `test/config_manager/pcap/search_params_prop_test.exs`
    - Generate random valid search params (valid IPs, ports, time ranges, Community IDs)
    - Verify validate/1 returns {:ok, _} for valid params
    - Generate random invalid params (bad IPs, ports > 65535, reversed time ranges, time range > 24h)
    - Verify validate/1 returns {:error, _} with non-empty error list
    - Verify to_carve_payload/1 output contains all required fields
    - **Validates: Requirements 1.4, 1.5, 7.2, 11.1**

  - [ ]* 2.3 Write unit tests for SearchParams edge cases
    - Create `test/config_manager/pcap/search_params_test.exs`
    - Test each search type with minimal valid params
    - Test Community ID format edge cases
    - Test time range exactly 24 hours (valid) and 24h + 1s (invalid)
    - Test IPv6 addresses
    - Test port boundary values (0, 65535, 65536)
    - _Requirements: 1.4, 1.5_

- [ ] 3. Implement database schemas and migration
  - [ ] 3.1 Create migration for `pcap_carve_requests` and `pcap_custody_events` tables
    - Create migration file in `priv/repo/migrations/`
    - Create `pcap_carve_requests` table with all fields from design (id, user_id, search_type, search_params, community_id, sensor_pod_id, sensor_name, status, error_reason, file metadata fields, timestamps)
    - Create `pcap_custody_events` table with all fields (id, carve_request_id, event_type, actor_username, actor_display_name, timestamp, detail)
    - Add indexes: user_id, status, sensor_pod_id, expires_at, inserted_at on carve_requests; carve_request_id, timestamp on custody_events
    - _Requirements: 3.1, 3.2, 6.1_

  - [ ] 3.2 Create `lib/config_manager/pcap/carve_request.ex` Ecto schema
    - Define schema matching migration columns
    - Implement `create_changeset/2` with required field validation and search_type inclusion check
    - Implement `status_changeset/3` with status transition validation (valid transitions map)
    - Implement `terminal?/1` helper for checking completed/failed/expired
    - Define `@valid_statuses` and `@valid_search_types` module attributes
    - _Requirements: 3.1, 3.2_

  - [ ] 3.3 Create `lib/config_manager/pcap/custody_event.ex` Ecto schema
    - Define schema matching migration columns
    - Implement `changeset/2` with required field validation and event_type inclusion check
    - Define `@valid_event_types` — created, downloaded, manifest_exported
    - _Requirements: 6.1, 6.2_

  - [ ]* 3.4 Write property tests for CarveRequest status transitions (PropCheck)
    - **Property 5: Carve request status transitions follow the valid state machine**
    - Create `test/config_manager/pcap/carve_request_prop_test.exs`
    - Generate all (from_status, to_status) pairs
    - Verify valid transitions produce valid changesets
    - Verify invalid transitions produce changeset errors
    - **Validates: Requirements 3.2**

- [ ] 4. Implement PCAP context module
  - [ ] 4.1 Create `lib/config_manager/pcap.ex` context module
    - Implement `submit_search/3` — validates params, resolves sensors (default to all online if none selected), creates N CarveRequests, records pcap_search audit entry
    - Implement `dispatch_carve/1` — calls SensorAgentClient.request_pcap_carve, updates status to dispatched, records pcap_carve_dispatch audit entry
    - Implement `update_status/3` — applies status_changeset, handles completion (set expires_at, create custody manifest, record audit), handles failure (record audit)
    - Implement `expire_completed_requests/0` — bulk update completed requests past expires_at to expired
    - Implement `get_request!/1`, `list_requests/2`, `list_user_requests/3` with filtering and pagination
    - Implement `create_custody_manifest/1` — creates "created" custody event with all required fields from CarveRequest
    - Implement `append_download_event/2` — creates "downloaded" custody event
    - Implement `get_manifest/1` — returns all custody events for a request ordered by timestamp
    - Implement `export_manifest_json/1` — serializes manifest to JSON, computes SHA-256 integrity hash, returns {json, hash}
    - Implement `compute_community_id/1` — delegates to CommunityId module
    - Implement `download_filename/1` — generates descriptive filename from CarveRequest fields
    - Implement `stream_pcap_download/2` — delegates to SensorAgentClient for streaming
    - _Requirements: 3.1, 3.4, 3.5, 3.8, 4.5, 4.7, 5.2, 5.3, 5.4, 6.1, 6.2, 6.5, 6.7, 8.1, 8.2, 8.3, 8.4, 9.1_

  - [ ]* 4.2 Write property tests for PCAP context (PropCheck)
    - **Property 6: Multi-sensor search creates exactly one request per target sensor**
    - **Property 7: Completed and failed status updates record correct metadata**
    - **Property 12: Manifest integrity hash is deterministic and verifiable**
    - **Property 14: Every PCAP lifecycle action produces a structurally complete audit entry**
    - **Property 15: User-scoped request visibility enforces ownership**
    - **Property 16: Request history filtering returns only matching results**
    - **Property 17: Expiration lifecycle correctly blocks downloads after retention period**
    - Create `test/config_manager/pcap/pcap_context_prop_test.exs`
    - **Validates: Requirements 3.1, 3.4, 3.5, 3.8, 5.2, 5.3, 5.4, 6.7, 8.1-8.4, 9.1, 9.2**

  - [ ]* 4.3 Write unit tests for PCAP context
    - Create `test/config_manager/pcap/pcap_context_test.exs`
    - Test submit_search with single and multiple sensors
    - Test status transitions through full lifecycle: pending → dispatched → carving → completed → expired
    - Test failed status from dispatched and carving
    - Test custody manifest creation with all required fields
    - Test download event appending
    - Test manifest JSON export structure and integrity hash
    - Test download_filename format
    - Test user-scoped vs admin request listing
    - Test expiration: request at boundary of retention period
    - Test expire_completed_requests bulk operation
    - _Requirements: 3.1, 3.2, 3.4, 3.5, 5.3, 6.1, 6.2, 6.5, 6.7, 9.1, 9.2_

- [ ] 5. Checkpoint — Ensure all tests pass
  - Run `mix test` and verify all property and unit tests pass
  - Ask the user if questions arise

- [ ] 6. Extend SensorAgentClient with PCAP functions
  - [ ] 6.1 Add PCAP carve, status, and download functions to `lib/config_manager/sensor_agent_client.ex`
    - Implement `request_pcap_carve/2` — POST `/control/pcap/carve` with JSON payload, follows existing mTLS/Finch pattern
    - Implement `get_pcap_carve_status/2` — GET `/control/pcap/carve/:request_id`, returns parsed status response
    - Implement `stream_pcap_download/3` — GET `/control/pcap/download/:request_id`, streams response body to Plug.Conn via chunk/2
    - Handle error cases: no_control_api_host, connection failure, HTTP 422 (validation error), HTTP 5xx
    - Use `@pcap_download_timeout_ms 120_000` for download streaming
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 11.1, 11.2, 11.3_

  - [ ]* 6.2 Write unit tests for new SensorAgentClient PCAP functions
    - Create or extend `test/config_manager/sensor_agent_client_test.exs`
    - Test request_pcap_carve success and error paths
    - Test get_pcap_carve_status with each possible status response
    - Test stream_pcap_download success path
    - Test no_control_api_host error for all three functions
    - Test HTTP 422 handling for carve request
    - _Requirements: 7.1-7.6_

- [ ] 7. Implement status poller
  - [ ] 7.1 Create `lib/config_manager/pcap/status_poller.ex` for carve status polling
    - Implement as a Task spawned under Task.Supervisor
    - Poll `SensorAgentClient.get_pcap_carve_status/2` at configurable interval (default 5s)
    - On status change: update CarveRequest via `Pcap.update_status/3`, broadcast via PubSub to `"pcap_request:#{request_id}"`
    - On completed: stop polling, broadcast final status
    - On failed: stop polling, broadcast final status
    - On timeout (dispatched > 5 min): mark failed with reason `timeout`, stop polling
    - Handle Sensor Agent unreachable: log warning, retry on next interval
    - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.7_

  - [ ]* 7.2 Write unit tests for StatusPoller
    - Create `test/config_manager/pcap/status_poller_test.exs`
    - Mock SensorAgentClient responses
    - Test polling loop with status progression: dispatched → carving → completed
    - Test failure handling
    - Test timeout after 5 minutes in dispatched
    - Test PubSub broadcast on status change
    - _Requirements: 3.3, 3.4, 3.5, 3.6_

- [ ] 8. Checkpoint — Ensure all tests pass
  - Run `mix test` and verify all tests pass
  - Ask the user if questions arise

- [ ] 9. Implement PCAP search LiveView
  - [ ] 9.1 Create `lib/config_manager_web/live/pcap_live/components/search_form_component.ex`
    - Render search mode selector (tabs or radio buttons): Community ID (default), Time Range, 5-Tuple, Alert ID, Zeek UID
    - Render mode-specific input fields with labels and validation error display
    - Community ID mode: Community ID input field with prominent placement, optional time range
    - Time Range mode: sensor selector, start/end UTC datetime inputs
    - 5-Tuple mode: src_ip, dst_ip, src_port, dst_port, protocol selector, optional time range
    - Alert ID mode: Suricata SID input, alert timestamp, optional sensor selector
    - Zeek UID mode: Zeek UID input, optional sensor selector
    - Client-side validation feedback (phx-change events)
    - _Requirements: 1.2, 1.3, 1.4, 1.5, 2.1_

  - [ ] 9.2 Create `lib/config_manager_web/live/pcap_live/components/community_id_calculator.ex`
    - Render 5-tuple input form (src_ip, dst_ip, src_port, dst_port, protocol)
    - On submit: compute Community ID via `CommunityId.compute/1`, populate search field
    - Display computed Community ID with copy-to-clipboard button
    - Display explanatory text about Community ID as cross-tool correlation key
    - _Requirements: 2.2, 2.3, 2.4_

  - [ ] 9.3 Create `lib/config_manager_web/live/pcap_live/components/sensor_selector_component.ex`
    - Render list of enrolled sensors with online/offline status from Health Registry
    - Support multi-select (checkboxes)
    - Display sensor name and status indicator (green dot = online, gray = offline)
    - Default: all online sensors selected when no explicit selection
    - _Requirements: 1.6, 1.7, 1.8_

  - [ ] 9.4 Create `lib/config_manager_web/live/pcap_live/components/request_status_component.ex`
    - Render status badge with color coding: pending (gray), dispatched (blue), carving (yellow), completed (green), failed (red), expired (gray)
    - Display progress indicator for non-terminal statuses
    - Display error reason for failed requests
    - Display download button for completed requests
    - Display file metadata (size, packet count) for completed requests
    - _Requirements: 3.7, 4.1_

  - [ ] 9.5 Create `lib/config_manager_web/live/pcap_live/search_live.ex` — main search LiveView
    - Mount: check pcap:search permission, load online sensors from Health Registry
    - Render search form component with default Community ID mode
    - Render Community ID calculator panel
    - Handle `phx-change` for live validation
    - Handle `phx-submit` for search submission: validate via SearchParams, call Pcap.submit_search/3, dispatch carves, start pollers
    - On 5-tuple search: compute and display corresponding Community ID
    - Subscribe to `"pcap_request:#{id}"` PubSub topics for each created request
    - Handle PubSub status updates: re-render request status cards
    - Display per-sensor request status cards below search form
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.7, 3.8_

- [ ] 10. Implement PCAP request history LiveView
  - [ ] 10.1 Create `lib/config_manager_web/live/pcap_live/requests_live.ex` — request history
    - Mount: check pcap:search permission, load user's requests (or all for platform-admin)
    - Render table: request timestamp, requesting user, search criteria summary, target sensor(s), status badge, file size
    - Implement filters: date range picker, status dropdown, sensor name, search type
    - Implement pagination with 25 per page default
    - Re-download button for completed + non-expired requests
    - Re-submit button for expired requests (creates new search with same params)
    - User-scoped visibility: non-admin sees only own requests
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [ ] 10.2 Create `lib/config_manager_web/live/pcap_live/request_detail_live.ex` — request detail
    - Mount: load CarveRequest by ID, check pcap:search permission, check ownership (or admin)
    - Display full request detail: search criteria, target sensor, status timeline
    - Subscribe to PubSub for real-time status updates
    - Download button when completed (visible only with pcap:download permission)
    - Link to manifest page
    - Display file metadata when completed
    - Display error reason when failed
    - Display expiration info when completed (time remaining or expired)
    - _Requirements: 3.7, 4.1, 10.1_

- [ ] 11. Implement chain-of-custody manifest LiveView
  - [ ] 11.1 Create `lib/config_manager_web/live/pcap_live/manifest_live.ex` — manifest view
    - Mount: load CarveRequest and all CustodyEvents, check pcap:search permission
    - Display chain-of-custody timeline: creation event, all download events
    - Display each event: type, actor, timestamp, detail
    - Display manifest integrity hash (SHA-256)
    - Export JSON button: triggers download of manifest JSON file
    - _Requirements: 6.1, 6.4, 6.5, 6.7_

- [ ] 12. Implement PCAP download controller
  - [ ] 12.1 Create `lib/config_manager_web/controllers/pcap_download_controller.ex`
    - Implement `download/2` action:
      - Check pcap:download permission (403 + audit on denial)
      - Load CarveRequest, verify completed and not expired
      - Load SensorPod for control_api_host
      - Set Content-Disposition: attachment with descriptive filename from `Pcap.download_filename/1`
      - Set Content-Type: application/vnd.tcpdump.pcap
      - Stream PCAP via `SensorAgentClient.stream_pcap_download/3`
      - On completion: append custody download event, record pcap_download audit entry
    - Implement `export_manifest/2` action:
      - Check pcap:search permission
      - Call `Pcap.export_manifest_json/1`
      - Set Content-Disposition: attachment with manifest filename
      - Set Content-Type: application/json
      - Record pcap_manifest_export audit entry
    - Handle errors: 404 for missing request, redirect for expired, 502 for sensor unreachable
    - _Requirements: 4.1-4.8, 6.5, 6.6, 8.5, 8.6_

  - [ ]* 12.2 Write property tests for download permission and filename (PropCheck)
    - **Property 8: PCAP permission enforcement is consistent across all access paths**
    - **Property 9: Download filename contains sensor name, search criteria, and timestamp**
    - **Property 10: Every completed download appends a custody event with required fields**
    - Create `test/config_manager_web/pcap_download_prop_test.exs`
    - Generate random user roles and verify permission enforcement
    - Generate random CarveRequests and verify filename format
    - **Validates: Requirements 4.2, 4.3, 4.5, 4.7, 8.7, 10.2**

  - [ ]* 12.3 Write unit tests for download controller
    - Create `test/config_manager_web/controllers/pcap_download_controller_test.exs`
    - Test successful download flow with mocked Sensor Agent
    - Test 403 for unauthorized user
    - Test 404 for missing request
    - Test redirect for expired request
    - Test manifest export with integrity hash verification
    - Test audit entries created for download and manifest export
    - _Requirements: 4.1-4.8, 6.5, 6.6_

- [ ] 13. Checkpoint — Ensure all tests pass
  - Run `mix test` and verify all tests pass
  - Ask the user if questions arise

- [ ] 14. Wire up router, navigation, and audit logging
  - [ ] 14.1 Update `lib/config_manager_web/router.ex` with PCAP routes
    - Add PCAP LiveView routes inside authenticated live_session block:
      - `live "/pcap", PcapLive.SearchLive, :index`
      - `live "/pcap/search", PcapLive.SearchLive, :search`
      - `live "/pcap/requests", PcapLive.RequestsLive, :index`
      - `live "/pcap/requests/:id", PcapLive.RequestDetailLive, :show`
      - `live "/pcap/requests/:id/manifest", PcapLive.ManifestLive, :show`
    - Add controller routes for streaming:
      - `get "/pcap/requests/:id/download", PcapDownloadController, :download`
      - `get "/pcap/requests/:id/manifest/export", PcapDownloadController, :export_manifest`
    - Set `private: %{required_permission: "pcap:search"}` on all PCAP routes
    - Set `private: %{required_permission: "pcap:download"}` on download route
    - _Requirements: 10.1, 10.2_

  - [ ] 14.2 Add PCAP navigation link to main navigation
    - Update navigation template/component to include "PCAP" link
    - Show link only when current user has pcap:search permission
    - Display badge with count of active (non-terminal) CarveRequests for current user
    - _Requirements: 10.3, 10.4_

  - [ ] 14.3 Implement PCAP file expiration scheduled task
    - Add periodic task (e.g., via `Task` in Application supervisor or `:timer.send_interval`)
    - Call `Pcap.expire_completed_requests/0` every hour
    - Read retention period from `RAVENWIRE_PCAP_RETENTION_HOURS` env var (default 72)
    - _Requirements: 9.1, 9.2_

- [ ] 15. Write integration tests
  - [ ]* 15.1 Write LiveView integration tests for search page
    - Create `test/config_manager_web/live/pcap_live/search_live_test.exs`
    - Test page renders with Community ID as default mode
    - Test mode switching renders correct fields
    - Test Community ID calculator computes and populates field
    - Test sensor selector shows online/offline status
    - Test form validation displays field-level errors
    - Test successful search creates CarveRequests
    - Test real-time status updates via PubSub
    - Test 5-tuple search displays computed Community ID
    - **Validates: Requirements 1.1-1.8, 2.1-2.5, 3.1, 3.7, 3.8**

  - [ ]* 15.2 Write LiveView integration tests for request history
    - Create `test/config_manager_web/live/pcap_live/requests_live_test.exs`
    - Test page renders request list in reverse chronological order
    - Test user-scoped visibility (non-admin sees only own requests)
    - Test platform-admin sees all requests
    - Test filtering by date range, status, sensor, search type
    - Test pagination with 25 per page
    - Test re-download button for completed requests
    - Test re-submit button for expired requests
    - **Validates: Requirements 5.1-5.7**

  - [ ]* 15.3 Write LiveView integration tests for request detail and manifest
    - Create `test/config_manager_web/live/pcap_live/request_detail_live_test.exs`
    - Test request detail renders all fields
    - Test real-time status updates
    - Test download button visibility based on permission
    - Test manifest page renders custody timeline
    - Test manifest integrity hash display
    - Test manifest JSON export
    - **Validates: Requirements 3.7, 4.1, 6.1, 6.4, 6.5, 6.7, 10.1**

  - [ ]* 15.4 Write end-to-end integration test
    - Create `test/config_manager/pcap/integration_test.exs`
    - Test full lifecycle: search → dispatch → poll → complete → download → custody manifest
    - Mock SensorAgentClient HTTP calls
    - Verify all audit entries created at each step
    - Verify custody manifest contains all events
    - Verify manifest integrity hash
    - **Validates: Requirements 3.1-3.5, 4.7, 4.8, 6.1, 6.2, 8.1-8.5**

  - [ ]* 15.5 Write custody manifest property tests (PropCheck)
    - **Property 11: Custody manifest records are immutable and append-only**
    - Create `test/config_manager/pcap/custody_prop_test.exs`
    - Generate random custody events, verify no update/delete operations exist
    - Verify append operations only insert new records
    - **Validates: Requirements 6.3**

- [ ] 16. Final checkpoint — Ensure all tests pass
  - Run `mix test` and verify all property and unit tests pass
  - Ask the user if questions arise

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design uses Elixir/Phoenix LiveView — all code examples use Elixir
- PropCheck (~> 1.4) is already in mix.exs
- New dependencies: none required
- New database tables: `pcap_carve_requests`, `pcap_custody_events` (one migration)
- The SensorAgentClient is extended, not replaced
- PCAP file streaming uses Finch — no files stored on Config Manager disk
- Expiration is handled by a periodic task, not by the Sensor Agent
