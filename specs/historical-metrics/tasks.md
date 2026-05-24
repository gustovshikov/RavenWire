# Implementation Plan: Historical Metrics

## Overview

This plan implements historical metrics persistence and time-series charting for the RavenWire Config Manager. The implementation proceeds bottom-up: database schema and context module first, then the Sampler GenServer, followed by LiveView pages and chart components, and finally navigation integration and wiring. Each step builds on the previous, ensuring no orphaned code.

## Tasks

- [ ] 1. Create database migration and MetricSnapshot schema
  - [ ] 1.1 Create the Ecto migration for the `metric_snapshots` table
    - Create `priv/repo/migrations/YYYYMMDDHHMMSS_create_metric_snapshots.exs`
    - Define table with columns: `id` (binary_id PK), `sensor_pod_id` (binary_id FK to sensor_pods, on_delete: delete_all), `metric_type` (string, not null), `series_key` (string, not null, default "default"), `value` (float, not null), `recorded_at` (utc_datetime_usec, not null), `metadata` (text, nullable)
    - Create index on `[:recorded_at]` for pruning
    - Create index on `[:metric_type, :recorded_at]` for pool/aggregate queries
    - Create unique index on `[:sensor_pod_id, :metric_type, :series_key, :recorded_at]` named `:metric_snapshots_unique_sample_index`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.8_

  - [ ] 1.2 Implement the `ConfigManager.Metrics.MetricSnapshot` Ecto schema
    - Create `lib/config_manager/metrics/metric_snapshot.ex`
    - Define schema fields matching migration columns
    - Implement `changeset/2` with validations: metric_type inclusion, series_key format (no whitespace, non-empty), finite value check, metadata JSON object validation, foreign key constraint, unique constraint
    - Implement `valid_metric_types/0` public function
    - Implement helper functions: `put_default_series_key/1`, `validate_finite_value/1`, `validate_metadata_json/1`
    - _Requirements: 1.1, 1.6, 1.7, 1.9_

  - [ ]* 1.3 Write property test for changeset validation (Property 1)
    - **Property 1: Changeset validation rejects invalid inputs and accepts valid ones**
    - Generate random attrs with valid/invalid metric_types, series_keys with/without whitespace, finite/non-finite values, valid/invalid JSON metadata
    - **Validates: Requirements 1.6**

  - [ ]* 1.4 Write property test for timestamp microsecond round-trip (Property 2)
    - **Property 2: Recorded timestamp microsecond round-trip**
    - Generate random DateTimes with microsecond precision, write and read back, verify identical
    - **Validates: Requirements 1.7**

- [ ] 2. Implement the Metrics context module (query and write API)
  - [ ] 2.1 Create `ConfigManager.Metrics` context module with write and pruning functions
    - Create `lib/config_manager/metrics.ex`
    - Implement `write_snapshots/1` — batch insert with on_conflict: :nothing for duplicate handling, returns `{:ok, inserted_count}`
    - Implement `prune_before/2` — delete snapshots older than cutoff in configurable batch size, return total deleted count
    - Implement `parse_time_range/1` — validate time range string, return `{:ok, {start, end}}` or `{:error, :invalid_range}`
    - Implement `protobuf_available?/1`, `protobuf_available_types/0`, `future_types/0`, `valid_time_ranges/0`
    - _Requirements: 12.5, 12.6, 12.7_

  - [ ] 2.2 Implement query functions in the Metrics context
    - Implement `list_snapshots/4` — query by sensor_pod_id, metric_type, time_range with ascending order, support series_key filter, metadata_filter, and downsampling via time-bucket averaging when exceeding chart point limit
    - Implement `list_snapshots_for_pool/4` — query for all sensors in a pool, grouped by sensor_pod_id and series_key, ordered ascending
    - Implement `available_metric_types/1` — distinct metric types with data for a sensor
    - Implement `latest_snapshot/3` and `latest_snapshots/3` — most recent snapshot(s) for a sensor/metric
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.8, 4.10_

  - [ ]* 2.3 Write property test for pruning correctness (Property 9)
    - **Property 9: Pruning deletes exactly the expired rows regardless of batch size**
    - Generate random snapshot sets with timestamps spanning a cutoff, vary batch sizes, verify all expired deleted and all non-expired preserved
    - **Validates: Requirements 3.1, 3.3, 12.6**

  - [ ]* 2.4 Write property test for time range validation (Property 12)
    - **Property 12: Time range queries are always bounded**
    - Generate random strings including valid ranges, empty strings, and arbitrary text; verify parse_time_range returns valid bounded tuple or error
    - **Validates: Requirements 6.7, 12.7**

  - [ ]* 2.5 Write property test for list_snapshots in-range results (Property 13)
    - **Property 13: list_snapshots returns only in-range results in ascending order**
    - Generate snapshots spanning before/during/after a time range, verify only in-range returned in ascending order
    - **Validates: Requirements 12.1**

  - [ ]* 2.6 Write property test for pool member filtering (Property 14)
    - **Property 14: list_snapshots_for_pool returns only pool member data**
    - Generate pools with members and non-members all having snapshots, verify only member data returned
    - **Validates: Requirements 12.2**

  - [ ]* 2.7 Write property test for downsampling bounds (Property 11)
    - **Property 11: Downsampling preserves time range bounds and respects point limit**
    - Generate large snapshot sets exceeding chart point limit, verify downsampled result respects limit and preserves time bounds
    - **Validates: Requirements 4.10, 8.11, 12.8**

- [ ] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement the Metrics Sampler GenServer
  - [ ] 4.1 Create `ConfigManager.Metrics.Sampler` GenServer with lifecycle and configuration
    - Create `lib/config_manager/metrics/sampler.ex`
    - Implement `start_link/1`, `init/1` reading config from application environment with defaults
    - Implement `validated_retention_hours/0` enforcing 72h floor outside test env
    - Implement timer scheduling for `:sample` and `:prune` messages
    - Implement `handle_info(:prune, state)` calling `Metrics.prune_before/2` with logging
    - Add error handling: log and continue on failures, never crash
    - _Requirements: 2.1, 2.2, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 14.1, 14.2, 14.3, 14.5_

  - [ ] 4.2 Implement sampling logic: metric extraction and rate computation
    - Implement `handle_info(:sample, state)` and `do_sample/1`
    - Map Health Registry entries to SensorPod records by matching `HealthReport.sensor_pod_id` to `SensorPod.name`
    - Extract single-value metrics: `pcap_disk_used_percent` from storage, `clock_offset_ms` from clock
    - Extract per-container metrics: `cpu_percent` and `memory_bytes` with `series_key = "container:<sanitized_name>"`
    - Implement `compute_packets_received_rate/3` from consecutive report deltas with skip conditions (first sample, counter reset, non-advancing timestamp, zero/negative elapsed)
    - Implement `compute_aggregate_drop_percent/1` with weighted (raw counters) and unweighted (per-consumer values) paths
    - Implement `series_key/2` helper for stable, whitespace-free container key derivation
    - Use HealthReport timestamp as `recorded_at` when valid; fall back to sampler UTC time with metadata annotation
    - Skip unavailable metric types (vector_records_per_sec, sink_buffer_used_percent)
    - Write batch via `Metrics.write_snapshots/1`, broadcast PubSub on success
    - Track previous reports in GenServer state, evict stale entries
    - _Requirements: 2.3, 2.4, 2.5, 2.6, 2.8, 2.9, 2.10, 2.11, 2.12, 2.13, 2.14, 13.1, 13.5_

  - [ ] 4.3 Add Sampler to application supervision tree
    - Add `ConfigManager.Metrics.Sampler` as a child in the application supervisor
    - Ensure it starts after the Repo and Health Registry
    - _Requirements: 2.1_

  - [ ]* 4.4 Write property test for sampler metadata never contains secrets (Property 3)
    - **Property 3: Sampler metadata never contains secrets**
    - Generate HealthReports paired with SensorPods containing PEM fields, verify no PEM headers or cert material in metadata
    - **Validates: Requirements 1.9**

  - [ ]* 4.5 Write property test for sampler extraction correctness (Property 4)
    - **Property 4: Sampler produces snapshots only for matched sensors and available metrics**
    - Generate random Health Registry states and SensorPod sets with varying overlap, verify only matched sensors get snapshots and only available metric types are written
    - **Validates: Requirements 2.3, 2.4, 2.6**

  - [ ]* 4.6 Write property test for aggregate drop_percent (Property 5)
    - **Property 5: Aggregate drop_percent uses weighted formula when counters are available**
    - Generate random consumer maps with varying packet counts and drop_percent values, verify weighted vs unweighted computation
    - **Validates: Requirements 2.5**

  - [ ]* 4.7 Write property test for rate computation (Property 6)
    - **Property 6: Rate computation skips on counter reset, non-advancing timestamp, or first sample**
    - Generate pairs of HealthReports with increasing/decreasing/equal counters and timestamps, verify skip conditions and correct rate
    - **Validates: Requirements 2.9, 2.10**

  - [ ]* 4.8 Write property test for timestamp source selection (Property 7)
    - **Property 7: Timestamp source selection**
    - Generate HealthReports with valid, nil, zero, and negative timestamp_unix_ms values, verify correct recorded_at and metadata
    - **Validates: Requirements 2.11**

  - [ ]* 4.9 Write property test for series_key determinism (Property 8)
    - **Property 8: Series_key determinism and stability**
    - Generate random container name strings, verify deterministic output, no whitespace, correct prefix
    - **Validates: Requirements 2.12, 13.1, 13.5**

  - [ ]* 4.10 Write property test for retention floor enforcement (Property 10)
    - **Property 10: Retention floor enforcement**
    - Generate random retention_hours values including values below 72, verify effective retention is always >= 72 in non-test env
    - **Validates: Requirements 3.7, 14.5**

- [ ] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement the Chart.js hook and ChartComponent
  - [ ] 6.1 Add Chart.js dependency and create the LiveView hook
    - Add Chart.js to `assets/package.json` (pinned version)
    - Create `assets/js/hooks/chart_hook.js` implementing the LiveView hook
    - Initialize Chart.js line chart on `mounted()` with time x-axis, metric-specific y-axis unit, threshold annotation lines/zones, tooltip config
    - Respect `prefers-reduced-motion` by disabling animations
    - Handle `chart_update_${id}` event for incremental point appending and time window shifting
    - Handle `updated()` for full data replacement on time range change
    - Handle `destroyed()` for Chart.js instance cleanup
    - Register hook in `assets/js/app.js`
    - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.6, 8.8, 8.9, 8.10, 7.4_

  - [ ] 6.2 Implement `ConfigManagerWeb.Components.ChartComponent` function component
    - Create `lib/config_manager_web/live/components/chart_component.ex`
    - Implement `chart/1` function component rendering canvas with hook, data attributes, and `aria-label`
    - Implement `chart_placeholder/1` for unavailable (`:unavailable`) and no-data (`:no_data`) states with distinct messages and styling
    - Implement `data_table/1` for accessible table fallback sorted by timestamp descending
    - Include threshold text labels and patterns in addition to color
    - Support multi-series rendering with legend for pool view and per-container charts
    - Include downsampled note when applicable
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 8.10, 8.11, 9.1, 9.2, 9.3, 11.1, 11.2, 11.3, 11.5, 11.6, 11.7_

- [ ] 7. Implement the Sensor Metrics LiveView page
  - [ ] 7.1 Create `ConfigManagerWeb.MetricsLive.SensorMetricsLive`
    - Create `lib/config_manager_web/live/metrics_live/sensor_metrics_live.ex`
    - Implement `mount/3`: load SensorPod by ID, handle 404, subscribe to PubSub topic `"sensor_metrics:#{sensor_pod_id}"` when connected
    - Implement `handle_params/3`: parse time range from URL query string `?range=`, validate, re-query on change
    - Query `Metrics.list_snapshots/4` for each metric type in chart order
    - Query `Metrics.available_metric_types/1` to determine data availability
    - Assign chart_data, available_types, table_views, time_range
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.8, 4.9, 4.10_

  - [ ] 7.2 Implement SensorMetricsLive template and event handlers
    - Create the HEEx template with: sensor name header, link back to `/sensors/:id`, status banner for pending/revoked sensors
    - Render time range selector (1h/6h/24h/72h) with keyboard navigation and aria attributes
    - Render chart slots in defined order using ChartComponent or chart_placeholder
    - Implement `handle_event("select_range", ...)` pushing patch with new range in URL
    - Implement `handle_event("toggle_table_view", ...)` toggling table view per metric
    - Implement `handle_info({:metrics_updated, ...})` querying latest snapshots and pushing new points to charts via `push_event`
    - Handle "offline during selected time range" banner (Requirement 9.4, 9.5)
    - _Requirements: 4.5, 4.6, 4.9, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.1, 7.3, 7.4, 7.5, 7.7, 9.1, 9.2, 9.3, 9.4, 9.5, 11.4_

  - [ ]* 7.3 Write unit tests for SensorMetricsLive
    - Test page renders charts for available metrics
    - Test correct placeholders for unavailable and no-data metrics
    - Test 404 for non-existent sensor
    - Test pending/revoked status banner rendering
    - Test RBAC enforcement (sensors:view permission required)
    - Test time range selection updates URL and re-queries
    - Test invalid time range falls back to 6h
    - Test PubSub subscription and real-time update handling
    - Test table view toggle
    - _Requirements: 15.4, 15.6, 15.7_

- [ ] 8. Implement the Pool Metrics LiveView page
  - [ ] 8.1 Create `ConfigManagerWeb.MetricsLive.PoolMetricsLive`
    - Create `lib/config_manager_web/live/metrics_live/pool_metrics_live.ex`
    - Implement `mount/3`: load pool and members, handle 404, handle empty pool, subscribe to `"pool:#{pool_id}"` and per-sensor PubSub topics
    - Implement `handle_params/3`: parse time range from URL, validate, re-query
    - Query `Metrics.list_snapshots_for_pool/4` for each metric type
    - Determine large pool (>10 sensors) for min/max/avg summary mode
    - Assign pool, members, member_ids (MapSet), chart_data, expanded_charts, debounce state
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.8_

  - [ ] 8.2 Implement PoolMetricsLive template and event handlers
    - Create the HEEx template with: pool name header, link back to `/pools/:id`, empty pool message
    - Render aggregate charts with per-sensor lines (≤10) or min/max/avg summary (>10) with expand toggle
    - Disambiguate per-container metrics by sensor name and container name
    - Implement `handle_event("select_range", ...)` and `handle_event("expand_chart", ...)`
    - Implement debounced PubSub handling: `handle_info({:metrics_updated, ...})` schedules debounced update, `handle_info({:debounced_update, ...})` queries and pushes
    - Implement pool membership handlers: `handle_info({:sensors_assigned, ...})` and `handle_info({:sensors_removed, ...})` for subscribe/unsubscribe and re-query
    - Ignore updates from non-member sensors
    - Per-sensor links in legend/chart lines to `/sensors/:sensor_id/metrics`
    - _Requirements: 5.3, 5.4, 5.5, 5.6, 5.7, 5.9, 5.10, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 10.3_

  - [ ]* 8.3 Write property test for pool non-member update ignored (Property 15)
    - **Property 15: Pool metrics page ignores non-member sensor updates**
    - Generate random sensor_pod_ids, some in pool and some not, verify non-member updates do not change chart data
    - **Validates: Requirements 7.6**

  - [ ]* 8.4 Write unit tests for PoolMetricsLive
    - Test aggregate chart rendering for pools with ≤10 and >10 sensors
    - Test empty pool message
    - Test 404 for non-existent pool
    - Test RBAC enforcement
    - Test pool membership change updates subscriptions
    - Test debounced update coalescing
    - Test non-member sensor updates are ignored
    - Test per-container disambiguation by sensor and container name
    - _Requirements: 15.6, 15.7_

- [ ] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Add routes, navigation links, and final wiring
  - [ ] 10.1 Add metrics routes to the router
    - Add `live "/sensors/:id/metrics", MetricsLive.SensorMetricsLive, :show` to the authenticated scope with `sensors:view` permission
    - Add `live "/pools/:id/metrics", MetricsLive.PoolMetricsLive, :show` to the authenticated scope with `sensors:view` permission
    - _Requirements: 4.1, 4.7, 5.1, 5.7, 10.4, 10.5_

  - [ ] 10.2 Add navigation links to existing pages
    - Add "Metrics" link on the sensor detail page (`/sensors/:id`) linking to `/sensors/:id/metrics`
    - Add "Metrics" link on the pool detail page (`/pools/:id`) linking to `/pools/:id/metrics`
    - _Requirements: 10.1, 10.2_

  - [ ] 10.3 Add metrics configuration to application config files
    - Add `:metrics_sample_interval_ms`, `:metrics_retention_hours`, `:metrics_prune_interval_ms`, `:metrics_prune_batch_size`, `:metrics_chart_point_limit` to `config/config.exs` with defaults
    - Add test-specific overrides in `config/test.exs` (shorter intervals, lower retention for test speed)
    - _Requirements: 14.1, 14.4_

  - [ ]* 10.4 Write integration and accessibility tests
    - Test FK cascade: delete SensorPod verifies MetricSnapshots are deleted
    - Test PubSub flow: Sampler writes → broadcast → LiveView receives → pushes to client
    - Test accessibility: aria-label on chart containers, table fallback renders, keyboard time range selection, threshold text labels, color contrast note
    - Test navigation links present on sensor and pool detail pages
    - Test chart point limit and downsampling note displayed
    - _Requirements: 15.1, 15.5, 15.6, 15.7, 15.8, 15.9, 15.10_

- [ ] 11. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (15 properties)
- Unit tests validate specific examples, edge cases, and UI rendering behavior
- The implementation uses Elixir/Phoenix with Ecto (SQLite), LiveView, and Chart.js
- PropCheck (`propcheck ~> 1.4`) is already available in project dependencies
- Chart.js is a new client-side dependency added to `assets/package.json`
