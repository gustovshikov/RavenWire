# Implementation Plan: Live Data-Flow Visualization

## Overview

This plan implements the live data-flow visualization feature for the RavenWire Config Manager. The implementation follows a bottom-up approach: first building the pure derivation module (fully testable without LiveView), then the reusable rendering component, then the LiveView pages, and finally wiring navigation and routes together. Property-based tests validate the derivation logic at each step.

## Current Reconciliation

- Start this branch from the validated `main` state after Platform Alert Center, Historical Metrics, and Health Baselines have been merged.
- Use `ConfigManager.Health.Registry.pod_topic/1` for pod-scoped subscriptions and `"sensor_pods"` for fleet-wide health updates.
- Use `HealthReport.vector.input_records_per_sec` when present to animate Zeek/Suricata-to-Vector paths from real Vector ingress event-rate telemetry. Missing `vector` stats must keep those connector paths unknown.
- Keep forwarding sink runtime health as `no_data`; forwarding configuration may label the single aggregate Forwarding Sinks node with counts, badges, and tooltip rows, but it is not delivery telemetry and must not create additional sink topology nodes in v1.
- Use current HealthReport system telemetry for the NIC/capture-interface segment only where it is actually meaningful: capture interface name, NIC driver, and AF_PACKET availability. Do not infer physical mirror/SPAN link health.
- Use current PCAP ring-writer counters where available, but do not infer active Alert Driven PCAP flush/carve state until HealthReport exposes it explicitly.
- Keep the feature browser/UI focused. Do not add `/api/v1` endpoints in this pass.
- Use semantic HTML plus lightweight SVG connectors; do not add D3, canvas, or a new frontend build pipeline.
- E2E coverage should focus on route rendering, missing telemetry placeholders, basic live update behavior, table fallback/accessibility, and permission behavior.

## Tasks

- [x] 0. Follow-up slice — add Vector ingress flow telemetry
  - [x] Extend HealthReport protobuf with `VectorStats` on field 8 and update Go/Elixir generated protobuf structs
  - [x] Add Vector internal metrics plus local Prometheus exporter to generated `vector.toml`
  - [x] Default and persist `VECTOR_METRICS_URL=http://127.0.0.1:9598/metrics` for sensor-agent installs/quadlets
  - [x] Replace the old JSON-style Vector scrape with Prometheus text parsing for `component_received_events_total` / `vector_component_received_events_total`
  - [x] Map Vector ingress component aliases (`zeek_logs`/`parse_zeek -> zeek`, `suricata_eve`/`parse_suricata -> suricata`), compute record-rate deltas, and omit `VectorStats` when the endpoint is unavailable
  - [x] Derive Zeek/Suricata-to-Vector connector labels and animation from `rec/s` record rates while keeping byte throughput on AF_PACKET paths
  - [x] Show Vector total ingress record rate on the node graph node when present
  - [x] Add Go, derivation, component, and LiveView tests for Vector ingress record-rate behavior

- [x] 0.5 Follow-up slice — add app-native Zeek/Suricata process input telemetry
  - [x] Extend `ConsumerStats` protobuf with `process_throughput_bps`, `process_packets_per_sec`, `process_drop_percent`, and `process_telemetry_source`
  - [x] Enable Zeek `policy/misc/stats` with a 10-second stats interval
  - [x] Parse newest Zeek `stats*.log` rows and derive process input bps, packets/sec, and drop percent from interval counters
  - [x] Parse newest Suricata EVE `stats` events, extract decoder byte/packet totals plus capture kernel drops, and compute process deltas
  - [x] Preserve existing NIC/fallback `throughput_bps` and use `process_telemetry_source` as the presence marker for real process telemetry
  - [x] Prefer process throughput/drop values for AF_PACKET-to-Zeek and AF_PACKET-to-Suricata connector labels, animation state, segment metrics, and analysis-tool degradation
  - [x] Keep NIC/capture-interface ingest deduplicated from existing capture throughput, not the sum of process rates
  - [x] Add Go, derivation, protobuf, and graph component tests for process telemetry and fallback behavior

- [x] 1. Create the pure derivation module with segment state logic
  - [x] 1.1 Create `lib/config_manager/pipeline/derivation.ex` with module structure, types, and constants
    - Define the module with `@moduledoc`, type specs for `segment_state`, `connector_flow_state`, `speed_tier`, `segment`, `connector`, `pipeline_state`, `aggregate_segment`, `aggregate_pipeline_state`
    - Define threshold constants: `@drop_percent_threshold 5.0`, `@cpu_percent_threshold 90.0`, `@storage_warning_threshold 85.0`, `@storage_critical_threshold 95.0`
    - Define `@canonical_segment_ids` and `@expected_containers` alias maps aligned with current `SensorDetailLive` aliases (`zeek`/`systemd-zeek`, `suricata`/`systemd-suricata`, `pcap_ring_writer`/`pcap-ring-writer`/`systemd-pcap-ring-writer`, `vector`/`systemd-vector`)
    - _Requirements: 14.4, 14.6_

  - [x] 1.2 Implement `derive_mirror_port/1`
    - Healthy when `system.capture_interface` is present and `system.af_packet_available == true`
    - Degraded when `system.capture_interface` is present and `system.af_packet_available == false`
    - No Data when system telemetry is missing or `system.capture_interface` is blank
    - Never return Failed from current system fields; failed remains reserved for future explicit link/carrier/capture failure telemetry
    - Include accessible_summary with capture interface, NIC driver when available, and AF_PACKET availability
    - Make clear in tooltip text that physical mirror/SPAN source health is not proven by current telemetry
    - _Requirements: 2.7, 4.7_

  - [x] 1.3 Implement `derive_af_packet/1` with capture stats derivation
    - Healthy: ≥1 consumer, no `drop_percent > 5.0`, no `bpf_restart_pending == true`
    - Degraded: any consumer has `drop_percent > 5.0`
    - Pending Reload: any consumer has `bpf_restart_pending == true` (and no drops > 5.0)
    - No Data: no capture data present (nil input)
    - Build tooltip with aggregate throughput, per-consumer packet counts, drop percentages, BPF status
    - Build accessible_summary including state, consumer count, throughput
    - _Requirements: 4.1, 12.3_

  - [x] 1.4 Implement `derive_analysis_tool/4` for Zeek, Suricata, PCAP Ring
    - Healthy: container "running", CPU ≤ 90%, consumer drop ≤ 5.0%
    - Degraded: container "running" + CPU > 90% or consumer drop > 5.0%, container "restarting", or unknown non-running container state
    - Failed: container state "error" or "stopped"
    - Disabled: component intentionally disabled (from opts)
    - No Data: no expected container alias present in HealthReport
    - Build tooltip with container state, uptime, CPU%, memory, packets received/dropped, drop%
    - For PCAP Ring, include `packets_written`, `bytes_written`, `wrap_count`, `socket_drops`, and `overwrite_risk` when present
    - _Requirements: 4.2, 6.5, 12.2, 12.4_

  - [x] 1.5 Implement `derive_vector/2` with current container logic and future forwarding-buffer extension point
    - Healthy: container "running" when forwarding buffer data is unavailable
    - Degraded: future-only container "running" + buffer > 85% once HealthReport exposes buffer telemetry, container "restarting", or unknown non-running container state
    - Failed: container state "error" or "stopped"
    - No Data: container not present
    - Build tooltip with container state, uptime, CPU%, memory, buffer usage
    - _Requirements: 4.3, 12.5_

  - [x] 1.6 Implement `derive_forwarding_sinks/2`
    - Always return one aggregate segment with canonical ID `forwarding_sinks`
    - When forwarding configuration is available: expose configured sink names, enabled count, disabled count, and safe destination labels as metrics, badges, and tooltip rows on the aggregate segment
    - Keep enabled sink runtime state as `:no_data` until HealthReport exposes forwarding runtime telemetry
    - Represent disabled sink configurations as configuration detail; use aggregate `:disabled` only when all configured sinks are disabled
    - Keep connection status, latency, error count, and delivery health as future-only tooltip fields until HealthReport exposes runtime sink telemetry
    - _Requirements: 4.4, 9.1, 12.6_

  - [x] 1.7 Implement `derive_storage_warnings/1` for PCAP Ring storage badges
    - `:none` when `used_percent ≤ 85.0`
    - `:warning` when `85.0 < used_percent ≤ 95.0`
    - `:critical` when `used_percent > 95.0`
    - `:no_data` when storage stats are nil
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 1.8 Implement `format_throughput/1` and `format_packet_count/2`
    - `nil` → "—" (missing telemetry)
    - `0` → "0 bps" (real zero, not missing)
    - Positive → scaled to bps/Kbps/Mbps/Gbps
    - Packet count: nil → "—", integer → comma-formatted, with optional rate annotation
    - Keep formatting in `ConfigManager.Pipeline.Derivation` or a non-web pure helper; do not alias `ConfigManagerWeb.Formatters` from the core derivation module
    - _Requirements: 5.1, 5.5, 5.6, 5.7_

  - [x] 1.9 Implement `check_staleness/2`
    - Returns `{is_stale, age_seconds}` based on timestamp vs required `:now` and `:stale_threshold_sec` options
    - Nil, zero, negative, or invalid timestamp → `{true, nil}`
    - Future timestamp → `{false, 0}`
    - Default threshold is assigned by the caller as 60 seconds; the pure derivation module must not call `DateTime.utc_now/0`
    - _Requirements: 4.5, 13.1, 13.6_

  - [x] 1.10 Implement `worst_state/1` for pool aggregation
    - Priority: `:failed` > `:degraded` > `:pending_reload` > `:healthy` > `:disabled`
    - `:no_data` does not override reporting members
    - Empty list → `:no_data`
    - _Requirements: 7.5_

  - [x] 1.11 Implement connector flow derivation helpers
    - Derive `flow_state` from source segment state, target segment state, stale status, throughput, capture mode, and PCAP branch telemetry when available
    - Treat capture mode as context only; do not animate the PCAP connector as flowing from Full PCAP mode alone
    - Derive `speed_tier` from numeric `throughput_bps`, not formatted throughput labels
    - Return `:stopped` when either endpoint is failed or disabled
    - Return `:degraded` when either endpoint is degraded, trusted stale data applies, or drop pressure affects the path
    - Return `:idle` for zero throughput and Alert Driven PCAP paths without active flush telemetry
    - Return `:unknown` for missing telemetry or `:no_data` endpoints
    - Use AF_PACKET capture throughput for AF_PACKET-to-consumer connectors
    - Render Zeek/Suricata/PCAP Ring/dynamic-consumer-to-Vector connectors with `:unknown` flow and "—" throughput unless future structured output-rate telemetry exists
    - Render Vector-to-Forwarding Sinks with `:unknown` flow and "—" throughput until future aggregate forwarding telemetry exists
    - _Requirements: 3.5, 3.6, 5.8, 5.9, 5.10, 14.7, 14.9_

  - [x] 1.12 Implement `derive_sensor_pipeline/3` — the main public API
    - Orchestrate all segment derivations from HealthReport + SensorPod + opts
    - Require opts contract containing `:now`, `:stale_threshold_sec`, `:forwarding_sinks`, `:forwarding_summary`, `:capture_mode`, and `:degradation_reasons`
    - Do not call wall-clock time inside the pure derivation module; LiveViews pass `:now`
    - Build connectors with `throughput_bps`, formatted labels, `flow_state`, `speed_tier`, and accessible summaries
    - Handle dynamic capture consumers as extra parallel branches with deterministic IDs `capture_consumer:<sanitized-name>`, stable normalized-name sorting, generic labels, and tooltips from consumer stats
    - Keep `forwarding_sinks` as a single aggregate terminal node; configured sinks must stay inside aggregate segment metrics, badges, and tooltip rows in v1
    - Compute staleness, build status_banners for pending/revoked/offline sensors
    - For revoked sensors, render available or stale telemetry plus a revoked banner; do not override derived segment states to `:disabled`
    - Build summary_rows for screen-reader table
    - Ensure stable, deterministic segment and connector IDs
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.4, 5.2, 5.3, 5.4, 9.2, 9.3, 9.4, 9.5, 9.6, 13.3, 13.4, 13.5, 14.6, 14.7_

  - [x] 1.13 Implement `aggregate_pool_pipeline/1`
    - Accept list of `{sensor_id, sensor_name, pipeline_state}` tuples
    - For each canonical segment: count states across all members, compute worst_state
    - Build aggregate segments with `state_counts`, `overall_state`, badges (no_data count)
    - Compute `total_members` and `reporting_members` from HealthReport-backed reporting markers or non-`:no_data` health-derived segments; configuration-only Forwarding Sinks details must not count as reporting
    - Build summary_rows for screen-reader table
    - _Requirements: 7.3, 7.4, 7.5, 7.6, 7.7_

  - [x] 1.14 Write property tests for derivation module — topology and structure (Properties 1, 2)
    - **Property 1: Canonical topology structure invariant**
    - **Property 2: Derivation output structural completeness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 3.1, 14.6**

  - [x] 1.15 Write property tests for AF_PACKET derivation (Property 3)
    - **Property 3: AF_PACKET segment state derivation**
    - Generate random capture stats with varying consumer counts, drop percentages, BPF flags
    - **Validates: Requirements 4.1**

  - [x] 1.16 Write property tests for analysis-tool derivation (Property 4)
    - **Property 4: Analysis-tool segment state derivation**
    - Generate random container health states, CPU percentages, consumer drop percentages
    - **Validates: Requirements 4.2**

  - [x] 1.17 Write property tests for Vector derivation (Property 5)
    - **Property 5: Vector segment state derivation**
    - Generate random container states and buffer usage values
    - **Validates: Requirements 4.3**

  - [x] 1.18 Write property tests for missing telemetry (Property 6) and zero throughput (Property 7)
    - **Property 6: Missing telemetry produces no_data state**
    - **Property 7: Zero throughput does not produce failed state**
    - **Validates: Requirements 3.4, 4.6, 9.1, 9.2, 9.4**

  - [x] 1.19 Write property tests for throughput formatting (Property 8) and storage thresholds (Property 9)
    - **Property 8: Throughput formatting with zero/nil distinction**
    - **Property 9: Storage threshold classification**
    - **Validates: Requirements 5.5, 5.7, 6.2, 6.3**

  - [x] 1.20 Write property tests for staleness (Property 10), aggregate counts (Property 11), worst-state (Property 12)
    - **Property 10: Staleness detection**
    - **Property 11: Aggregate state count correctness**
    - **Property 12: Worst-state aggregation logic**
    - **Validates: Requirements 4.5, 7.3, 7.4, 7.5, 13.1**

  - [x] 1.21 Write property tests for determinism (Property 13), tooltips (Property 14), secrets (Property 15), accessibility (Property 16)
    - **Property 13: Derivation is deterministic with stable IDs**
    - **Property 14: Tooltip data completeness per segment type**
    - **Property 15: No secrets in tooltip or accessible summary data**
    - **Property 16: Accessible summaries and summary table rows**
    - **Validates: Requirements 10.1, 10.2, 10.5, 12.1–12.6, 12.9, 15.3**

  - [x] 1.22 Write property tests for connector flow and speed tiers (Properties 17, 18)
    - **Property 17: Connector flow state derivation**
    - **Property 18: Speed tier classification from structured throughput**
    - Verify failed targets stop animation, degraded endpoints produce degraded flow, Alert Driven PCAP without flush telemetry is idle, and formatted labels are never parsed for behavior
    - **Validates: Requirements 3.5, 3.6, 5.8, 5.9, 5.10, 16.13–16.16**

  - [x] 1.23 Write property tests for NIC/capture-interface derivation (Property 19)
    - Generate system telemetry with present/blank capture interface, NIC driver, and AF_PACKET availability
    - Verify current system fields can derive healthy/degraded/no_data but never failed
    - Verify summaries do not claim physical mirror/SPAN source health
    - **Validates: Requirements 2.7, 4.7, 16.17**

- [x] 2. Checkpoint — Derivation module complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Create the reusable PipelineComponent for rendering
  - [x] 3.1 Create `lib/config_manager_web/components/pipeline_component.ex` with module structure
    - Define the module with `use Phoenix.Component`
    - Define `@state_styles` map with Visual State Palette (colors, local icon keys or text glyphs, labels, border styles for all 6 states)
    - Do not add a frontend icon package for v1; render icons with local inline SVG or accessible text glyphs
    - Define component attributes: `pipeline_state`, `mode`, `stale`, `stale_age_seconds`, `sensor_status`, `pool_member_links`
    - _Requirements: 14.1, 14.2, 14.3_

  - [x] 3.2 Implement `pipeline_visualization/1` — main render function
    - In `:sensor` mode: render segments with individual state indicators and throughput annotations
    - In `:pool` mode: render segments with aggregate state counts and worst-state coloring
    - Use stable DOM IDs from segment/connector IDs for efficient LiveView diffs
    - Render left-to-right layout with parallel branches for analysis stage on wide screens
    - Render a top-to-bottom layout or table-first fallback on narrow screens without overlapping labels, badges, or tooltips
    - _Requirements: 2.6, 2.10, 3.2, 14.2, 15.3_

  - [x] 3.3 Implement `segment_node/1` — individual segment rendering
    - Render icon, label, state text, metrics, warnings, storage annotation per segment
    - Apply Visual State Palette styles based on segment state
    - Add `aria-label` with segment name, state, and key metrics
    - Support keyboard focus (`tabindex="0"`)
    - In pool mode: render state count summary instead of individual metrics
    - Add stale overlay (reduced opacity or clock badge) when stale flag is set
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 10.1, 10.3, 10.4, 13.2, 15.4_

  - [x] 3.4 Implement `segment_connector/1` — SVG connector rendering
    - Render a static SVG base path between source and target segments
    - Render an optional animated overlay path only for derived `flow_state` values that allow animation
    - Display throughput label on connector
    - Display secondary label (packet count) when available
    - [x] Define base CSS `@keyframes` for `stroke-dashoffset` in `assets/css/app.css` under `@layer components`
    - [x] Create discrete CSS utility classes for connector flow states: `flow-state-flowing`, `flow-state-degraded`, `flow-state-idle`, `flow-state-stopped`, and `flow-state-unknown`
    - [x] Create discrete CSS utility classes for speed magnitude: `flow-speed-gbps` (for example, 0.5s duration), `flow-speed-mbps` (1.5s duration), and `flow-speed-kbps` (3s duration)
    - [x] Implement logic in `segment_connector/1` to append CSS classes from derived `flow_state` and `speed_tier` fields without parsing formatted throughput labels
    - [x] Do not use JavaScript animation loops or LiveView hooks for connector animation
    - Add `aria-label` with source, destination, and throughput
    - _Requirements: 2.2, 2.8, 2.9, 3.5, 3.6, 5.1, 5.2, 5.4, 5.8, 5.9, 5.10, 10.2, 15.4_

  - [x] 3.5 Implement `segment_tooltip/1` — tooltip/popover rendering
    - Show detailed metrics on hover/focus
    - Dismissible via Escape key or focus loss
    - Content accessible to screen readers (appropriate ARIA attributes)
    - Do not expose secrets, tokens, or certificates
    - _Requirements: 12.1, 12.7, 12.8, 12.9_

  - [x] 3.6 Implement `summary_table/1` — screen-reader accessible table
    - Render HTML table with segment name, state, key metrics
    - Always render the table for screen readers; allow the same summary data to become visible in narrow table-first layouts
    - One row per segment from `summary_rows` data
    - _Requirements: 10.5, 10.6_

  - [x] 3.7 Implement `status_banner/1` — status banners
    - Stale data warning banner with time since last report
    - Revoked sensor banner
    - Pending enrollment banner
    - Sensor not reporting banner (no HealthReport)
    - Pool empty state message
    - _Requirements: 13.1, 13.3, 13.4, 13.5, 7.9_

  - [x] 3.8 Write unit tests for PipelineComponent rendering
    - Test each segment state renders correct Visual State Palette (icon, color, label, border)
    - Test sensor mode vs pool mode rendering differences
    - Test stale overlay rendering
    - Test status banner rendering for each scenario
    - Test accessibility attributes (aria-labels) are present and correct
    - Test summary table presence and content
    - _Requirements: 3.2, 3.3, 10.1, 10.2, 10.5, 13.2_

- [x] 4. Checkpoint — Component rendering complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement original SensorPipelineLive page (superseded by graph in task 13.7)
  - [x] 5.1 Create `lib/config_manager_web/live/pipeline_live/sensor_pipeline_live.ex`
    - Implement `mount/3`: load SensorPod by ID from DB, handle 404, derive health_key, read health from Registry, derive pipeline state, subscribe to PubSub when connected
    - Build and pass the required derivation opts, including current time, stale threshold, forwarding config/summary, capture mode, and degradation reasons
    - Implement `handle_info/2` for `:pod_updated`, `:pod_degraded`, `:pod_recovered` — re-derive pipeline state on matching health_key only
    - Subscribe to `"pool:#{pool_id}:forwarding"` when the sensor belongs to a pool and re-derive configured sink labels on forwarding config changes
    - Ignore PubSub messages for non-matching health_keys
    - Assign: pod, health_key, pipeline_state, not_found, current_user
    - _Requirements: 1.1, 1.2, 1.3, 8.1, 8.2, 8.3, 8.4, 8.8, 8.11_

  - [x] 5.2 Create the template/render for SensorPipelineLive
    - Render 404 page when `not_found` is true
    - Render breadcrumb navigation: link to sensor detail, link to pool pipeline (when applicable)
    - Render page header with sensor name and last report timestamp
    - Render `PipelineComponent.pipeline_visualization` with `mode=:sensor` and derived pipeline state
    - Render segment click navigation (data attributes for segment → sensor detail section linking)
    - _Requirements: 1.1, 1.5, 8.4, 11.3, 11.5, 14.7_

  - [x] 5.3 Write LiveView tests for SensorPipelineLive
    - Test mount with existing sensor renders pipeline visualization
    - Test mount with non-existent sensor renders 404
    - Test PubSub subscription on connected mount
    - Test `:pod_updated` message triggers re-render with updated data
    - Test unrelated PubSub messages do not change state
    - Test forwarding config PubSub update refreshes configured sink labels without changing runtime sink state from `no_data`
    - Test stale data banner appears when HealthReport is old
    - Test revoked/pending sensor banners, including revoked sensors retaining available/stale telemetry instead of overriding derived states to disabled
    - Test sensor with no HealthReport shows all health-derived segments as `no_data` while preserving safe Forwarding Sinks configuration labels/details
    - Test missing PCAP storage stats add only a storage no-data annotation/badge and do not override PCAP Ring segment state
    - _Requirements: 1.2, 1.3, 8.1, 8.2, 8.8, 8.11, 13.1, 13.3, 13.4, 13.5, 16.3, 16.5, 16.6, 16.11_

  - [x] 5.4 Align dashboard freshness labeling with pipeline staleness
    - Ensure stale HealthReports remain visible on the dashboard for operator context
    - Label stale dashboard rows and their host/capture/management summaries as `stale` instead of `running` or current
    - Add route-level regression coverage proving stale dashboard rows are not presented as current health
    - _Requirements: 13.6, 13.8_

- [x] 6. Implement PoolPipelineLive page
  - [x] 6.1 Create `lib/config_manager_web/live/pipeline_live/pool_pipeline_live.ex`
    - Implement `mount/3`: load pool from DB, handle 404, load member sensors, derive per-sensor pipeline states, aggregate via `Derivation.aggregate_pool_pipeline/1`, subscribe to pool topic and per-member pod topics
    - Build and pass the required derivation opts for each member using fixed `now` per re-derive pass
    - Subscribe to `"pool:#{pool_id}:forwarding"` and re-derive configured sink labels on forwarding config changes
    - Implement debounced re-derivation: `schedule_rederive/1` with `Process.send_after/3`, token-based timer cancellation
    - Handle `:pod_updated` — only process if health_key is in `member_health_keys` MapSet
    - Handle `:sensors_assigned` and `:sensors_removed` — reload members, update subscriptions, re-aggregate
    - Handle `:rederive` with token matching to ignore stale timers
    - _Requirements: 7.1, 7.3, 7.4, 7.5, 7.6, 7.9, 7.10, 8.5, 8.6, 8.7, 8.9, 8.10, 8.11_

  - [x] 6.2 Create the template/render for PoolPipelineLive
    - Render 404 page when `not_found` is true
    - Render empty state when pool has zero members
    - Render breadcrumb navigation: link to pool detail page
    - Render page header with pool name, total members, reporting members count
    - Render `PipelineComponent.pipeline_visualization` with `mode=:pool` and aggregate state
    - Render links to each member sensor's pipeline page
    - _Requirements: 7.1, 7.7, 7.8, 7.9, 7.10, 11.4, 11.6_

  - [x] 6.3 Write LiveView tests for PoolPipelineLive
    - Test mount with existing pool renders aggregate pipeline
    - Test mount with non-existent pool renders 404
    - Test empty pool renders empty state message
    - Test PubSub subscription for pool topic and member pod topics
    - Test health update for member sensor triggers debounced re-aggregate
    - Test health update for non-member sensor is ignored
    - Test membership change (sensors_assigned/removed) updates aggregate
    - Test forwarding config PubSub update refreshes configured sink labels without changing runtime sink state from `no_data`
    - Test aggregate Forwarding Sinks remains one segment and no additional sink terminal nodes are rendered
    - Test debounce coalesces rapid updates
    - Test member count and reporting count display
    - _Requirements: 7.1, 7.9, 7.10, 8.5, 8.6, 8.7, 8.9, 8.10, 8.11, 16.4, 16.12_

- [x] 7. Checkpoint — LiveView pages complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Add routes, RBAC, and navigation integration
  - [x] 8.1 Add pipeline routes to the router
    - Add the original `live "/sensors/:id/pipeline"` and `live "/pools/:id/pipeline"` routes
    - Superseded for sensors in task 13.7: `/sensors/:id/pipeline` is now an authenticated redirect to `/sensors/:id/pipeline/graph`
    - Place in the existing `:sensor_pages` live session under the authenticated scope that already uses the `:sensors_view` permission pipeline
    - Do not create a new live session unless the existing route grouping changes before implementation
    - _Requirements: 1.1, 1.4, 7.1, 7.2, 11.7_

  - [x] 8.2 Add navigation links to existing pages
    - Add "Pipeline" link on sensor detail page linking to the sensor pipeline route; superseded in task 13.7 to point directly to `/sensors/:id/pipeline/graph`
    - Add "Pipeline" link on pool detail page linking to `/pools/:id/pipeline`
    - _Requirements: 11.1, 11.2_

  - [x] 8.3 Write RBAC and routing tests
    - Test that `/sensors/:id/pipeline` requires `sensors:view` permission
    - Test that `/pools/:id/pipeline` requires `sensors:view` permission
    - Test that unauthenticated users are redirected
    - _Requirements: 1.4, 7.2, 11.7, 16.9_

- [x] 9. Accessibility and reduced-motion compliance
  - [x] 9.1 Ensure reduced-motion support in PipelineComponent
    - Add `prefers-reduced-motion` media query to disable any connector animations
    - [x] Ensure the `@media (prefers-reduced-motion: reduce)` CSS block explicitly targets the SVG connector lines and sets `animation: none !important;` to completely stop the flowing packets for users who require it
    - Ensure the static base topology, labels, icons, and badges remain fully understandable when animation is disabled
    - Ensure state-change transitions are brief and non-essential
    - Verify WCAG AA contrast for all text and icon outlines in the Visual State Palette
    - _Requirements: 10.7, 15.4, 15.5_

  - [x] 9.2 Write accessibility tests
    - Test each segment has `aria-label` with segment name and state
    - Test each connector has `aria-label` with source, destination, throughput
    - Test summary table is present with correct data
    - Test tooltip content is accessible (ARIA attributes)
    - Test keyboard navigation between segments
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 16.7_

- [x] 10. Add E2E coverage and deployed validation
  - [x] 10.1 Add full-profile Playwright coverage
    - Create `e2e/tests/pipeline.spec.ts`
    - Log in as admin and open the built-in test sensor pipeline route
    - Verify canonical segments, connector labels, missing-telemetry placeholders, NIC local-interface wording, and PCAP active-flush-safe wording
    - Create or reuse an `e2e-` pool fixture and verify the pool pipeline route renders aggregate counts and member links
    - Verify a limited user with `sensors:view` can read the routes and an unauthenticated browser is redirected to login
    - Clean up any `e2e-` pool or sensor fixtures using the existing guarded cleanup helpers
    - _Requirements: 1.1, 1.2, 7.1, 7.3, 9.1, 9.4, 10.5, 16.18_

  - [x] 10.2 Run the deployed validation gate
    - Run `mix test`
    - Run `sensorctl test`
    - Deploy to the test server
    - Run `cd e2e && npm run preflight && E2E_ALLOW_DB_CLEANUP=true npm run test:full`
    - Verify service health and zero lingering `e2e-` pools, users, sensors, rulesets, repositories, forwarding sinks, alerts, PCAP requests, metric fixtures, baseline fixtures, or pipeline fixtures
    - _Requirements: 16.18_

- [x] 11. Final checkpoint — All features integrated and validated
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Fix interface-backed capture throughput telemetry
  - [x] 12.1 Add capture-interface `rx_bytes` to Sensor_Agent capture stats
    - Read `/sys/class/net/<iface>/statistics/rx_bytes` alongside `rx_packets`, `rx_dropped`, and `rx_missed_errors`
    - Preserve packet/drop/drop-percent behavior for existing capture consumers
    - _Requirements: 5.12_

  - [x] 12.2 Compute Zeek and Suricata throughput from interface byte deltas
    - Use interface `rx_bytes` as the byte source for interface-backed consumers that do not expose consumer-specific byte counters
    - Keep `pcap_ring_writer` throughput based on its ring writer `bytes_written` telemetry
    - Treat first intervals and counter resets as `0 bps` instead of underflowing
    - _Requirements: 5.12_

  - [x] 12.3 Add Go regression coverage for the runtime telemetry fix
    - Test `rx_bytes` parsing from the capture interface statistics tree
    - Test interface packet/drop stats are merged while returning bytes for throughput computation
    - Test byte-counter reset handling produces `0 bps`
    - _Requirements: 16.19_

  - [x] 12.4 Prevent UI double-counting of AF_PACKET fan-out throughput
    - Use the largest numeric capture-consumer throughput as the v1 deduplicated NIC-to-AF_PACKET ingress estimate
    - Keep per-consumer fan-out throughput on the AF_PACKET-to-consumer branch connectors
    - Add derivation regression coverage for Zeek and Suricata reporting the same interface-backed throughput
    - _Requirements: 5.13, 16.20_

- [x] 13. Add adjacent sensor node graph test page
  - [x] 13.1 Create `SensorPipelineGraphLive` at `/sensors/:id/pipeline/graph`
    - Reuse existing sensor pipeline derivation, Health Registry lookup, pod-scoped PubSub subscription, forwarding context, and stale threshold behavior
    - Keep `/sensors/:id/pipeline` available during validation and link to the graph page for side-by-side testing; superseded by task 13.7 after the graph became canonical
    - Preserve selected-node state across live updates when the selected segment still exists
    - _Requirements: 1.1, 1.4, 2.1, 13.3_

  - [x] 13.2 Create `PipelineGraphComponent`
    - Render semantic node buttons over SVG connector paths using deterministic left-to-right columns
    - Use flexible columns for NIC/capture interface, AF_PACKET, Analysis consumers, Vector, and Forwarding Sinks so available graph space favors connector visibility
    - Distribute nodes vertically within each column using the agreed 1/2/3/4+ node spacing rules
    - Render compact node boxes with name and throughput; do not render throughput, branch, or secondary packet labels on connector paths
    - Clicking a node opens its detail drawer, clicking the same node again closes it, and clicking a different node while open swaps the drawer content without closing
    - _Requirements: 2.6, 3.2, 5.2, 10.1_

  - [x] 13.3 Add graph-specific RavenWire theme CSS
    - Scope styles under `.pipeline-node-*`
    - Use RavenWire theme variables for health state colors
    - Animate connector flow as square blocks from derived `flow_state` and `speed_tier`
    - Respect `prefers-reduced-motion`
    - _Requirements: 3.5, 5.8, 10.7, 15.4_

  - [x] 13.4 Add component, LiveView, and RBAC route tests
    - Verify graph nodes, health classes, selected-node panel, node-click open/close/swap behavior, keyboard/focus attributes, unlabeled connector paths, route rendering, missing sensor handling, live update rendering, and `sensors:view` route coverage
    - _Requirements: 10.1, 10.3, 10.5, 11.7, 16.7_

  - [x] 13.5 Add visible connector readout and summary below the graph
    - Render connector source/target names, throughput or record-rate labels, and secondary packet-count labels below the graph so connector paths remain uncluttered
    - Render the segment summary table visibly on the graph page as the sensor-page replacement for the linear pipeline summary
    - Keep the linear route in place during validation; superseded by task 13.7 after navigation moved directly to the graph view
    - _Requirements: 4.1, 5.2, 10.1, 11.2_

  - [x] 13.6 Align summary metrics with graph telemetry semantics
    - Show Vector summary throughput as total ingress record rate (`rec/s`) when Vector stats are present
    - Show NIC/capture-interface summary throughput as NIC receive ingest using the de-duplicated capture-interface receive estimate
    - Keep NIC/capture-interface wording clear that this is local NIC receive telemetry, not physical mirror/SPAN source health
    - _Requirements: 2.7, 4.1, 5.13, 16.20_

  - [x] 13.7 Promote the sensor graph and remove the linear sensor page
    - Remove `SensorPipelineLive` and its `/sensors/:id/pipeline` LiveView route
    - Keep `/sensors/:id/pipeline` as an authenticated compatibility redirect to `/sensors/:id/pipeline/graph`
    - Point the sensor detail Pipeline link and pool member sensor links directly to `/sensors/:id/pipeline/graph`
    - Remove the graph page's "Linear Pipeline" back-link
    - Keep the pool aggregate pipeline page on the current linear component until the future pool graph/tab slice is implemented
    - Add regression coverage for the redirect, canonical graph rendering, missing sensor behavior, and updated navigation
    - _Requirements: 1.1, 1.4, 7.8, 11.1, 11.7_

## Notes

- Derivation, component, LiveView, RBAC, accessibility, and deployed E2E verification tasks are required for feature completion
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The derivation module is built first because it has zero dependencies and is the foundation for all other components
- The design uses Elixir/Phoenix LiveView — no language selection was needed
- No new database tables or dependencies are required
- PropCheck (`propcheck ~> 1.4`) is already available in the project
