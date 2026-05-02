# Implementation Plan: Live Data-Flow Visualization

## Overview

This plan implements the live data-flow visualization feature for the RavenWire Config Manager. The implementation follows a bottom-up approach: first building the pure derivation module (fully testable without LiveView), then the reusable rendering component, then the LiveView pages, and finally wiring navigation and routes together. Property-based tests validate the derivation logic at each step.

## Tasks

- [ ] 1. Create the pure derivation module with segment state logic
  - [ ] 1.1 Create `lib/config_manager/pipeline/derivation.ex` with module structure, types, and constants
    - Define the module with `@moduledoc`, type specs for `segment_state`, `segment`, `connector`, `pipeline_state`, `aggregate_segment`, `aggregate_pipeline_state`
    - Define threshold constants: `@drop_percent_threshold 5.0`, `@cpu_percent_threshold 90.0`, `@storage_warning_threshold 85.0`, `@storage_critical_threshold 95.0`
    - Define `@canonical_segment_ids` and `@expected_containers` maps
    - _Requirements: 14.4, 14.6_

  - [ ] 1.2 Implement `derive_mirror_port/1`
    - Always returns a segment with state `:no_data` since host interface telemetry is not available in the current HealthReport schema
    - Include accessible_summary: "Mirror Port: No Data. Host interface telemetry not available."
    - _Requirements: 2.7, 4.1_

  - [ ] 1.3 Implement `derive_af_packet/1` with capture stats derivation
    - Healthy: ≥1 consumer, no `drop_percent > 5.0`, no `bpf_restart_pending == true`
    - Degraded: any consumer has `drop_percent > 5.0`
    - Pending Reload: any consumer has `bpf_restart_pending == true` (and no drops > 5.0)
    - No Data: no capture data present (nil input)
    - Build tooltip with aggregate throughput, per-consumer packet counts, drop percentages, BPF status
    - Build accessible_summary including state, consumer count, throughput
    - _Requirements: 4.1, 12.3_

  - [ ] 1.4 Implement `derive_analysis_tool/4` for Zeek, Suricata, PCAP Ring
    - Healthy: container "running", CPU ≤ 90%, consumer drop ≤ 5.0%
    - Degraded: container "running" + CPU > 90% or consumer drop > 5.0%
    - Failed: container state "error" or "stopped"
    - Disabled: component intentionally disabled (from opts)
    - No Data: container not present in HealthReport
    - Build tooltip with container state, uptime, CPU%, memory, packets received/dropped, drop%
    - _Requirements: 4.2, 12.2_

  - [ ] 1.5 Implement `derive_vector/2` with container and forwarding buffer logic
    - Healthy: container "running", buffer ≤ 85% (or buffer data unavailable)
    - Degraded: container "running" + buffer > 85%
    - Failed: container state "error" or "stopped"
    - No Data: container not present
    - Build tooltip with container state, uptime, CPU%, memory, buffer usage
    - _Requirements: 4.3, 12.5_

  - [ ] 1.6 Implement `derive_forwarding_sinks/1`
    - When forwarding data available: one segment per configured sink with appropriate state
    - When forwarding data nil: single "Forwarding Sinks" segment with `:no_data` state
    - Build tooltip per sink with destination, connection status, latency, error count
    - _Requirements: 4.4, 9.1, 12.6_

  - [ ] 1.7 Implement `derive_storage_warnings/1` for PCAP Ring storage badges
    - `:none` when `used_percent ≤ 85.0`
    - `:warning` when `85.0 < used_percent ≤ 95.0`
    - `:critical` when `used_percent > 95.0`
    - `:no_data` when storage stats are nil
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [ ] 1.8 Implement `format_throughput/1` and `format_packet_count/2`
    - `nil` → "—" (missing telemetry)
    - `0` → "0 bps" (real zero, not missing)
    - Positive → scaled to bps/Kbps/Mbps/Gbps
    - Packet count: nil → "—", integer → comma-formatted, with optional rate annotation
    - _Requirements: 5.1, 5.5, 5.6, 5.7_

  - [ ] 1.9 Implement `check_staleness/2`
    - Returns `{is_stale, age_seconds}` based on timestamp vs threshold
    - Nil timestamp → `{true, nil}`
    - Default threshold: 60 seconds
    - _Requirements: 4.5, 13.1, 13.6_

  - [ ] 1.10 Implement `worst_state/1` for pool aggregation
    - Priority: `:failed` > `:degraded` > `:pending_reload` > `:healthy` > `:disabled`
    - `:no_data` does not override reporting members
    - Empty list → `:no_data`
    - _Requirements: 7.5_

  - [ ] 1.11 Implement `derive_sensor_pipeline/3` — the main public API
    - Orchestrate all segment derivations from HealthReport + SensorPod + opts
    - Build connectors with throughput annotations between segments
    - Handle dynamic capture consumers (extra parallel branches)
    - Compute staleness, build status_banners for pending/revoked/offline sensors
    - Build summary_rows for screen-reader table
    - Ensure stable, deterministic segment and connector IDs
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.4, 5.2, 5.3, 5.4, 9.2, 9.3, 9.4, 9.5, 9.6, 13.3, 13.4, 13.5, 14.6_

  - [ ] 1.12 Implement `aggregate_pool_pipeline/1`
    - Accept list of `{sensor_id, sensor_name, pipeline_state}` tuples
    - For each canonical segment: count states across all members, compute worst_state
    - Build aggregate segments with `state_counts`, `overall_state`, badges (no_data count)
    - Compute `total_members` and `reporting_members`
    - Build summary_rows for screen-reader table
    - _Requirements: 7.3, 7.4, 7.5, 7.6, 7.7_

  - [ ]* 1.13 Write property tests for derivation module — topology and structure (Properties 1, 2)
    - **Property 1: Canonical topology structure invariant**
    - **Property 2: Derivation output structural completeness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 3.1, 14.6**

  - [ ]* 1.14 Write property tests for AF_PACKET derivation (Property 3)
    - **Property 3: AF_PACKET segment state derivation**
    - Generate random capture stats with varying consumer counts, drop percentages, BPF flags
    - **Validates: Requirements 4.1**

  - [ ]* 1.15 Write property tests for analysis-tool derivation (Property 4)
    - **Property 4: Analysis-tool segment state derivation**
    - Generate random container health states, CPU percentages, consumer drop percentages
    - **Validates: Requirements 4.2**

  - [ ]* 1.16 Write property tests for Vector derivation (Property 5)
    - **Property 5: Vector segment state derivation**
    - Generate random container states and buffer usage values
    - **Validates: Requirements 4.3**

  - [ ]* 1.17 Write property tests for missing telemetry (Property 6) and zero throughput (Property 7)
    - **Property 6: Missing telemetry produces no_data state**
    - **Property 7: Zero throughput does not produce failed state**
    - **Validates: Requirements 3.4, 4.6, 9.1, 9.2, 9.4**

  - [ ]* 1.18 Write property tests for throughput formatting (Property 8) and storage thresholds (Property 9)
    - **Property 8: Throughput formatting with zero/nil distinction**
    - **Property 9: Storage threshold classification**
    - **Validates: Requirements 5.5, 5.7, 6.2, 6.3**

  - [ ]* 1.19 Write property tests for staleness (Property 10), aggregate counts (Property 11), worst-state (Property 12)
    - **Property 10: Staleness detection**
    - **Property 11: Aggregate state count correctness**
    - **Property 12: Worst-state aggregation logic**
    - **Validates: Requirements 4.5, 7.3, 7.4, 7.5, 13.1**

  - [ ]* 1.20 Write property tests for determinism (Property 13), tooltips (Property 14), secrets (Property 15), accessibility (Property 16)
    - **Property 13: Derivation is deterministic with stable IDs**
    - **Property 14: Tooltip data completeness per segment type**
    - **Property 15: No secrets in tooltip or accessible summary data**
    - **Property 16: Accessible summaries and summary table rows**
    - **Validates: Requirements 10.1, 10.2, 10.5, 12.1–12.6, 12.9, 15.3**

- [ ] 2. Checkpoint — Derivation module complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Create the reusable PipelineComponent for rendering
  - [ ] 3.1 Create `lib/config_manager_web/components/pipeline_component.ex` with module structure
    - Define the module with `use Phoenix.Component`
    - Define `@state_styles` map with Visual State Palette (colors, icons, labels, border styles for all 6 states)
    - Define component attributes: `pipeline_state`, `mode`, `stale`, `stale_age_seconds`, `sensor_status`, `pool_member_links`
    - _Requirements: 14.1, 14.2, 14.3_

  - [ ] 3.2 Implement `pipeline_visualization/1` — main render function
    - In `:sensor` mode: render segments with individual state indicators and throughput annotations
    - In `:pool` mode: render segments with aggregate state counts and worst-state coloring
    - Use stable DOM IDs from segment/connector IDs for efficient LiveView diffs
    - Render left-to-right layout with parallel branches for analysis stage
    - _Requirements: 2.6, 3.2, 14.2, 15.3_

  - [ ] 3.3 Implement `segment_node/1` — individual segment rendering
    - Render icon, label, state text, metrics, warnings, storage annotation per segment
    - Apply Visual State Palette styles based on segment state
    - Add `aria-label` with segment name, state, and key metrics
    - Support keyboard focus (`tabindex="0"`)
    - In pool mode: render state count summary instead of individual metrics
    - Add stale overlay (reduced opacity or clock badge) when stale flag is set
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 10.1, 10.3, 10.4, 13.2, 15.4_

  - [ ] 3.4 Implement `segment_connector/1` — SVG connector rendering
    - Render SVG path between source and target segments
    - Display throughput label on connector
    - Display secondary label (packet count) when available
    - Add `aria-label` with source, destination, and throughput
    - _Requirements: 2.2, 5.1, 5.2, 5.4, 10.2_

  - [ ] 3.5 Implement `segment_tooltip/1` — tooltip/popover rendering
    - Show detailed metrics on hover/focus
    - Dismissible via Escape key or focus loss
    - Content accessible to screen readers (appropriate ARIA attributes)
    - Do not expose secrets, tokens, or certificates
    - _Requirements: 12.1, 12.7, 12.8, 12.9_

  - [ ] 3.6 Implement `summary_table/1` — screen-reader accessible table
    - Render HTML table with segment name, state, key metrics
    - Visually hidden (`sr-only` class) but accessible to screen readers
    - One row per segment from `summary_rows` data
    - _Requirements: 10.5, 10.6_

  - [ ] 3.7 Implement `status_banner/1` — status banners
    - Stale data warning banner with time since last report
    - Revoked sensor banner
    - Pending enrollment banner
    - Sensor not reporting banner (no HealthReport)
    - Pool empty state message
    - _Requirements: 13.1, 13.3, 13.4, 13.5, 7.9_

  - [ ]* 3.8 Write unit tests for PipelineComponent rendering
    - Test each segment state renders correct Visual State Palette (icon, color, label, border)
    - Test sensor mode vs pool mode rendering differences
    - Test stale overlay rendering
    - Test status banner rendering for each scenario
    - Test accessibility attributes (aria-labels) are present and correct
    - Test summary table presence and content
    - _Requirements: 3.2, 3.3, 10.1, 10.2, 10.5, 13.2_

- [ ] 4. Checkpoint — Component rendering complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement SensorPipelineLive page
  - [ ] 5.1 Create `lib/config_manager_web/live/pipeline_live/sensor_pipeline_live.ex`
    - Implement `mount/3`: load SensorPod by ID from DB, handle 404, derive health_key, read health from Registry, derive pipeline state, subscribe to PubSub when connected
    - Implement `handle_info/2` for `:pod_updated`, `:pod_degraded`, `:pod_recovered` — re-derive pipeline state on matching health_key only
    - Ignore PubSub messages for non-matching health_keys
    - Assign: pod, health_key, pipeline_state, not_found, current_user
    - _Requirements: 1.1, 1.2, 1.3, 8.1, 8.2, 8.3, 8.4, 8.8_

  - [ ] 5.2 Create the template/render for SensorPipelineLive
    - Render 404 page when `not_found` is true
    - Render breadcrumb navigation: link to sensor detail, link to pool pipeline (when applicable)
    - Render page header with sensor name and last report timestamp
    - Render `PipelineComponent.pipeline_visualization` with `mode=:sensor` and derived pipeline state
    - Render segment click navigation (data attributes for segment → sensor detail section linking)
    - _Requirements: 1.1, 1.5, 8.4, 11.3, 11.5, 14.7_

  - [ ]* 5.3 Write LiveView tests for SensorPipelineLive
    - Test mount with existing sensor renders pipeline visualization
    - Test mount with non-existent sensor renders 404
    - Test PubSub subscription on connected mount
    - Test `:pod_updated` message triggers re-render with updated data
    - Test unrelated PubSub messages do not change state
    - Test stale data banner appears when HealthReport is old
    - Test revoked/pending sensor banners
    - Test sensor with no HealthReport shows all no_data segments
    - _Requirements: 1.2, 1.3, 8.1, 8.2, 8.8, 13.1, 13.3, 13.4, 13.5, 16.3, 16.5, 16.6, 16.11_

- [ ] 6. Implement PoolPipelineLive page
  - [ ] 6.1 Create `lib/config_manager_web/live/pipeline_live/pool_pipeline_live.ex`
    - Implement `mount/3`: load pool from DB, handle 404, load member sensors, derive per-sensor pipeline states, aggregate via `Derivation.aggregate_pool_pipeline/1`, subscribe to pool topic and per-member pod topics
    - Implement debounced re-derivation: `schedule_rederive/1` with `Process.send_after/3`, token-based timer cancellation
    - Handle `:pod_updated` — only process if health_key is in `member_health_keys` MapSet
    - Handle `:sensors_assigned` and `:sensors_removed` — reload members, update subscriptions, re-aggregate
    - Handle `:rederive` with token matching to ignore stale timers
    - _Requirements: 7.1, 7.3, 7.4, 7.5, 7.6, 7.9, 7.10, 8.5, 8.6, 8.7, 8.9, 8.10_

  - [ ] 6.2 Create the template/render for PoolPipelineLive
    - Render 404 page when `not_found` is true
    - Render empty state when pool has zero members
    - Render breadcrumb navigation: link to pool detail page
    - Render page header with pool name, total members, reporting members count
    - Render `PipelineComponent.pipeline_visualization` with `mode=:pool` and aggregate state
    - Render links to each member sensor's pipeline page
    - _Requirements: 7.1, 7.7, 7.8, 7.9, 7.10, 11.4, 11.6_

  - [ ]* 6.3 Write LiveView tests for PoolPipelineLive
    - Test mount with existing pool renders aggregate pipeline
    - Test mount with non-existent pool renders 404
    - Test empty pool renders empty state message
    - Test PubSub subscription for pool topic and member pod topics
    - Test health update for member sensor triggers debounced re-aggregate
    - Test health update for non-member sensor is ignored
    - Test membership change (sensors_assigned/removed) updates aggregate
    - Test debounce coalesces rapid updates
    - Test member count and reporting count display
    - _Requirements: 7.1, 7.9, 7.10, 8.5, 8.6, 8.7, 8.9, 8.10, 16.4, 16.12_

- [ ] 7. Checkpoint — LiveView pages complete
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Add routes, RBAC, and navigation integration
  - [ ] 8.1 Add pipeline routes to the router
    - Add `live "/sensors/:id/pipeline"` and `live "/pools/:id/pipeline"` routes
    - Place in authenticated scope with `sensors:view` permission enforcement
    - If no authenticated live_session exists yet, create one with appropriate on_mount hooks
    - _Requirements: 1.1, 1.4, 7.1, 7.2, 11.7_

  - [ ] 8.2 Add navigation links to existing pages
    - Add "Pipeline" link on sensor detail page (`DashboardLive` or sensor detail) linking to `/sensors/:id/pipeline`
    - Add "Pipeline" link on pool detail page linking to `/pools/:id/pipeline`
    - _Requirements: 11.1, 11.2_

  - [ ]* 8.3 Write RBAC and routing tests
    - Test that `/sensors/:id/pipeline` requires `sensors:view` permission
    - Test that `/pools/:id/pipeline` requires `sensors:view` permission
    - Test that unauthenticated users are redirected
    - _Requirements: 1.4, 7.2, 11.7, 16.9_

- [ ] 9. Accessibility and reduced-motion compliance
  - [ ] 9.1 Ensure reduced-motion support in PipelineComponent
    - Add `prefers-reduced-motion` media query to disable any connector animations
    - Ensure state-change transitions are brief and non-essential
    - Verify WCAG AA contrast for all text and icon outlines in the Visual State Palette
    - _Requirements: 10.7, 15.4, 15.5_

  - [ ]* 9.2 Write accessibility tests
    - Test each segment has `aria-label` with segment name and state
    - Test each connector has `aria-label` with source, destination, throughput
    - Test summary table is present with correct data
    - Test tooltip content is accessible (ARIA attributes)
    - Test keyboard navigation between segments
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 16.7_

- [ ] 10. Final checkpoint — All features integrated
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The derivation module is built first because it has zero dependencies and is the foundation for all other components
- The design uses Elixir/Phoenix LiveView — no language selection was needed
- No new database tables or dependencies are required
- PropCheck (`propcheck ~> 1.4`) is already available in the project
