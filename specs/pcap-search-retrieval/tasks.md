# Implementation Plan: PCAP Search and Retrieval

## Overview

PCAP search/retrieval is implemented for the single-site pilot MVP. The carve
request and custody schemas, migration, context, API controller, SensorAgentClient
PCAP calls, browser search/history/detail/manifest/download workflow, and
full-profile test-server E2E coverage exist. Remaining unchecked items are
targeted hardening tests, not blockers for the validated pilot workflow.

## Tasks

- [x] 1. Add persistent PCAP request storage foundation
  - [x] Create `pcap_carve_requests` and `pcap_custody_events` migrations.
  - [x] Create `ConfigManager.Pcap.CarveRequest` with lifecycle status validation.
  - [x] Create `ConfigManager.Pcap.CustodyEvent` for append-only manifest events.
  - [x] Add context tests for request creation, completion, manifest, download, and validation.

- [x] 2. Implement Community ID v1 calculation
  - [x] Create `ConfigManager.Pcap.CommunityId` as a pure module.
  - [x] Implement direction-independent canonical ordering for IPv4 and IPv6 flows.
  - [x] Implement protocol normalization and Community ID format validation.
  - [x] Add unit tests for format, invalid inputs, IPv6, and reversed-flow stability.
  - [x] Add property tests for generated valid/invalid flows.

- [x] 3. Extract PCAP search parameter validation
  - [x] Create `ConfigManager.Pcap.SearchParams`.
  - [x] Move existing inline validation out of `ConfigManager.Pcap`.
  - [x] Preserve validation for time range, Community ID, five-tuple, alert ID, and Zeek UID searches.
  - [x] Add conversion to the Sensor Agent carve payload contract.
  - [x] Add unit tests for valid and invalid search inputs.
  - [x] Add property tests for generated valid/invalid search inputs.

- [x] 4. Add SensorAgentClient PCAP carve plumbing
  - [x] Dispatch carve requests via `POST /control/pcap/carve`.
  - [x] Fetch status via `GET /control/pcap/carve/:request_id`.
  - [x] Download PCAP bytes via `GET /control/pcap/download/:request_id`.
  - [ ] Add focused client tests for PCAP no-host and validation-error paths.

- [x] 5. Adapt PCAP context for browser search workflows
  - [x] Add `submit_search/3` that validates once and creates one request per target sensor.
  - [x] Default to all enrolled sensors currently online in the Health Registry when no sensor is selected.
  - [x] Keep API-compatible single-sensor `submit_carve/3`.
  - [x] Add actor-scoped list/detail helpers for request history and detail pages.
  - [x] Ensure lifecycle audit entries and custody events remain complete.
  - [x] Add tests for multi-sensor fanout plus existing lifecycle, expiration, and manifest export paths.
  - [ ] Add deeper actor visibility/property tests for non-admin request history filtering.

- [x] 6. Implement PCAP status polling
  - [x] Add `ConfigManager.Pcap.StatusPoller` under a supervised task supervisor.
  - [x] Poll Sensor Agent status for non-terminal requests.
  - [x] Broadcast status changes to `pcap_request:<id>` PubSub topics.
  - [x] Mark stale dispatched requests failed with reason `timeout`.
  - [ ] Add tests for terminal transitions, failure, and PubSub broadcasts.

- [x] 7. Implement browser PCAP workflow
  - [x] Add routes for `/pcap`, `/pcap/search`, `/pcap/requests`, `/pcap/requests/:id`, and `/pcap/requests/:id/manifest`.
  - [x] Add a regular browser controller for `/pcap/requests/:id/download` and manifest JSON export.
  - [x] Add a PCAP nav link visible only to users with `pcap:search`.
  - [x] Build the search page with Community ID default mode, sensor selector, validation errors, and current submission status cards.
  - [x] Build request history, request detail, and manifest pages.
  - [x] Enforce `pcap:search` for pages and `pcap:download` for download.

- [x] 8. Add browser and E2E coverage
  - [x] Add route guard tests for the new PCAP browser routes.
  - [x] Add LiveView/controller route tests for search rendering, history/detail/manifest rendering, and RBAC.
  - [x] Add full-profile Playwright coverage against the test server for PCAP search/history/detail/manifest/download behavior.
  - [x] Run the new full-profile Playwright coverage against the deployed test server.
  - [x] Verify no lingering `e2e-` PCAP records remain after E2E runs.

- [x] 9. Release gate
  - [x] Run focused PCAP unit/LiveView/API tests.
  - [x] Run full Config Manager test suite locally.
  - [x] Run `sensorctl test` if Sensor Agent or shared PCAP protocol code changes.
  - [x] Deploy to the test server and run the full E2E profile.
  - [x] Update operator docs once the browser workflow is verified on the test server.
