# Requirements Document: Historical Metrics

## Introduction

This feature adds historical metrics persistence and time-series charting to the RavenWire Config Manager. The current Health Registry stores only the latest HealthReport per sensor in ETS, providing no visibility into past health state. Operators need to answer "what happened 6 hours ago?" for incident investigation, capacity planning, and capture-loss analysis.

The feature introduces a SQLite-backed metrics persistence layer that periodically snapshots key health metrics from incoming HealthReports, retains them for at least 72 hours, and prunes older data automatically. New LiveView pages at `/sensors/:id/metrics` and `/pools/:id/metrics` render interactive time-series charts for each metric type. A time range selector allows operators to focus on 1-hour, 6-hour, 24-hour, or 72-hour windows. Charts update in real time as new snapshots arrive via PubSub.

Metrics that are not yet available in the HealthReport protobuf (Vector records/sec, sink buffer usage) display a clear "data not available" placeholder rather than empty or misleading charts. All charts are accessible, providing text-based data tables as alternatives to visual graphs.

## Glossary

- **Metrics_Store**: The Ecto-backed context module (`ConfigManager.Metrics`) that provides the public API for writing, querying, and pruning historical metric snapshots in SQLite.
- **Metric_Snapshot**: A single row in the `metric_snapshots` SQLite table representing one point-in-time sample of a specific metric series for a specific sensor.
- **Snapshot_Sampler**: A GenServer (`ConfigManager.Metrics.Sampler`) that runs on a configurable interval (default 60 seconds), reads the latest HealthReport from the Health_Registry for each known sensor, extracts key metric values, and writes Metric_Snapshots to the database via the Metrics_Store.
- **Health_Registry**: The existing ETS-backed GenServer (`ConfigManager.Health.Registry`) that stores the latest HealthReport per sensor, updated by the gRPC health stream.
- **HealthReport**: The protobuf message streamed from Sensor Agents containing containers, capture, storage, and clock data. Does NOT currently include forwarding metrics (Vector records/sec, sink buffer usage).
- **Health_Key**: The string key used by the Health_Registry for a Sensor_Pod. In the current enrollment flow this is `SensorPod.name`, matching `HealthReport.sensor_pod_id`.
- **Sensor_Pod**: A sensor identity record in the `sensor_pods` SQLite table. Metrics pages may display pending, enrolled, or revoked sensors, but the Snapshot_Sampler only writes snapshots for Sensor_Pods that can be matched to a Health_Key.
- **Sensor_Pool**: A logical grouping of Sensor_Pods for fleet management.
- **Metric_Type**: A string identifier for a specific metric series. Valid types: `packets_received_rate`, `drop_percent`, `cpu_percent`, `memory_bytes`, `pcap_disk_used_percent`, `clock_offset_ms`, `vector_records_per_sec`, `sink_buffer_used_percent`.
- **Time_Range**: A user-selectable window for chart display. Valid values: `1h`, `6h`, `24h`, `72h`.
- **Chart_Component**: A LiveView function component that renders a single time-series chart using a client-side JavaScript charting library (e.g., Chart.js) via a LiveView hook.
- **Config_Manager**: The Phoenix/Elixir LiveView web application that manages the RavenWire sensor fleet.
- **Retention_Period**: The minimum duration for which Metric_Snapshots are retained before pruning. Default: 72 hours. Configurable via application environment.
- **Pruner**: A periodic process (part of the Snapshot_Sampler or a separate scheduled task) that deletes Metric_Snapshots older than the Retention_Period.
- **Series_Key**: A stable identifier for one line in a chart, derived from Metric_Type plus relevant metadata such as container name and sensor ID. Examples: `default`, `container:zeek`, `container:suricata`.

## Requirements

### Requirement 1: Metrics Persistence Table

**User Story:** As a platform operator, I want health metrics to be persisted to durable storage, so that I can review historical sensor health after the fact.

#### Acceptance Criteria

1. THE Metrics_Store SHALL store Metric_Snapshots in a SQLite table named `metric_snapshots` with columns: `id` (binary_id primary key), `sensor_pod_id` (binary_id foreign key to sensor_pods), `metric_type` (string), `series_key` (string, default `default`), `value` (float), `recorded_at` (utc_datetime_usec), and `metadata` (text, JSON-encoded map for supplementary context).
2. THE Metrics_Store SHALL create a composite query path on `(sensor_pod_id, metric_type, series_key, recorded_at)` to support efficient time-range queries; this MAY be satisfied by the unique index on the same columns.
3. THE Metrics_Store SHALL create an index on `recorded_at` to support efficient pruning of old snapshots.
4. THE Metrics_Store SHALL create a composite index on `(metric_type, recorded_at)` to support efficient pool and aggregate metric queries across many sensors.
5. THE Metrics_Store SHALL create a unique index on `(sensor_pod_id, metric_type, series_key, recorded_at)` to prevent duplicate samples for the same series timestamp.
6. WHEN a Metric_Snapshot is written, THE Metrics_Store SHALL validate that `metric_type` is one of the defined Metric_Type values, `series_key` is non-empty and contains no whitespace, `value` is a finite number, `sensor_pod_id` references an existing Sensor_Pod, and `metadata` encodes to a JSON object.
7. THE Metrics_Store SHALL store `recorded_at` with microsecond precision in UTC.
8. THE Metrics_Store SHALL use `on_delete: :delete_all` or an equivalent cleanup policy so deleting a Sensor_Pod removes its Metric_Snapshots and does not leave orphaned metrics.
9. THE Metrics_Store SHALL NOT store secret-bearing fields such as certificates, API tokens, private keys, or sink credentials in the `metadata` column.

### Requirement 2: Periodic Snapshot Sampling

**User Story:** As a platform operator, I want metrics to be sampled at regular intervals from the live health stream, so that historical data accumulates without requiring changes to the Sensor Agent.

#### Acceptance Criteria

1. THE Snapshot_Sampler SHALL run as a supervised GenServer started by the application supervisor.
2. THE Snapshot_Sampler SHALL sample metrics from the Health_Registry at a configurable interval, defaulting to 60 seconds.
3. WHEN the Snapshot_Sampler fires, THE Snapshot_Sampler SHALL map Health_Registry entries to Sensor_Pod database records using the current Health_Key mapping before writing snapshots, and SHALL skip health entries that do not match a known Sensor_Pod.
4. WHEN the Snapshot_Sampler fires, THE Snapshot_Sampler SHALL extract the following metrics where available: aggregate `packets_received_rate` (sum of per-consumer `packets_received` delta divided by elapsed report time), aggregate `drop_percent` (weighted average across consumers), per-container `cpu_percent` and `memory_bytes` (stored with container name in metadata), `pcap_disk_used_percent` (from storage.used_percent), and `clock_offset_ms` (from clock.offset_ms).
5. THE Snapshot_Sampler SHALL compute aggregate `drop_percent` as `sum(packets_dropped) / sum(packets_received + packets_dropped) * 100` when packet counters are available; when counters are not available but consumer `drop_percent` values are available, it SHALL use an unweighted average and record `{"drop_percent_method": "unweighted"}` in metadata.
6. WHEN a HealthReport does not contain data for a given Metric_Type (e.g., forwarding metrics not yet in the protobuf), THE Snapshot_Sampler SHALL skip that Metric_Type for that sensor rather than writing a zero or null value.
7. THE Snapshot_Sampler SHALL store the sample interval in application configuration under `:config_manager, :metrics_sample_interval_ms`.
8. WHEN the Snapshot_Sampler writes new snapshots, THE Snapshot_Sampler SHALL broadcast `{:metrics_updated, sensor_pod_id}` to the PubSub topic `"sensor_metrics:#{sensor_pod_id}"` so that open chart pages receive updates.
9. THE Snapshot_Sampler SHALL track the previous HealthReport per sensor to compute rate-based metrics. WHEN no previous report exists for a sensor, THE Snapshot_Sampler SHALL skip rate-based metrics for that sensor on the first sample.
10. WHEN a rate counter decreases, the report timestamp does not advance, or the elapsed report time is zero or negative, THE Snapshot_Sampler SHALL treat the counter as reset or invalid and skip the affected rate metric for that sample.
11. THE Snapshot_Sampler SHALL use the HealthReport timestamp as `recorded_at` when available and valid; otherwise it SHALL use the sampler's current UTC time and include `{"timestamp_source": "sampler"}` in metadata.
12. THE Snapshot_Sampler SHALL set `series_key` to `default` for single-series metrics and to a stable scoped value such as `container:zeek` for per-container metrics, with whitespace or unsafe characters sanitized so the value is non-empty and contains no whitespace.
13. THE Snapshot_Sampler SHALL avoid writing duplicate snapshots for the same Sensor_Pod, Metric_Type, Series_Key, and `recorded_at`.
14. IF writing snapshots fails, THEN THE Snapshot_Sampler SHALL log the error, keep running, and retry on the next scheduled interval without crashing the application supervisor.

### Requirement 3: Data Retention and Pruning

**User Story:** As a platform operator, I want old metrics data to be automatically cleaned up, so that the SQLite database does not grow unbounded.

#### Acceptance Criteria

1. THE Pruner SHALL delete all Metric_Snapshots with `recorded_at` older than the configured Retention_Period.
2. THE Pruner SHALL run on a configurable interval, defaulting to every 15 minutes.
3. THE Pruner SHALL execute deletion in batches (default 1000 rows per batch) to avoid long-running SQLite write locks.
4. THE Pruner SHALL store the Retention_Period in application configuration under `:config_manager, :metrics_retention_hours`, defaulting to 72.
5. IF the Pruner encounters a database error during deletion, THEN THE Pruner SHALL log the error and retry on the next scheduled interval rather than crashing.
6. THE Pruner SHALL log the number of deleted rows after each pruning cycle at the `:info` log level.
7. THE Pruner SHALL never delete snapshots newer than 72 hours unless the application is running in a test environment with an explicit override.
8. THE Pruner SHALL use UTC cutoffs and SHALL compute the cutoff from the database-independent application clock once per pruning cycle.

### Requirement 4: Per-Sensor Metrics Page

**User Story:** As a platform operator, I want to view historical metrics charts for a specific sensor, so that I can investigate past health issues and plan capacity.

#### Acceptance Criteria

1. THE Config_Manager SHALL serve a LiveView page at the route `/sensors/:id/metrics` that displays time-series charts for the selected Sensor_Pod.
2. WHEN the page loads, THE Config_Manager SHALL query the Metrics_Store for all Metric_Snapshots belonging to the specified Sensor_Pod within the selected Time_Range (default 6h).
3. THE Config_Manager SHALL render one chart slot for each defined Metric_Type in the configured chart order, rendering a Chart_Component when data exists and a placeholder when data does not exist or the source is unavailable.
4. THE Config_Manager SHALL display charts in a consistent order: packets_received_rate, drop_percent, cpu_percent, memory_bytes, pcap_disk_used_percent, clock_offset_ms, vector_records_per_sec, sink_buffer_used_percent.
5. WHEN a Metric_Type has no data for the selected sensor and time range, THE Config_Manager SHALL display the specific placeholder required by Requirement 9 instead of an empty chart.
6. THE Config_Manager SHALL display the sensor name and a link back to the sensor detail page (`/sensors/:id`) in the page header.
7. THE Config_Manager SHALL require the `sensors:view` RBAC permission to access the page.
8. WHEN the requested Sensor_Pod ID does not exist, THE Config_Manager SHALL display a 404 Not Found page.
9. WHEN the Sensor_Pod status is `pending` or `revoked`, THE Config_Manager SHALL display a status banner and SHALL still render historical snapshots when they exist.
10. THE Config_Manager SHALL limit initial query result size by downsampling or bucketing data when the selected Time_Range would return more than the configured chart point limit.

### Requirement 5: Per-Pool Aggregate Metrics Page

**User Story:** As a platform operator, I want to view aggregate metrics across all sensors in a pool, so that I can assess pool-wide health and identify outliers.

#### Acceptance Criteria

1. THE Config_Manager SHALL serve a LiveView page at the route `/pools/:id/metrics` that displays aggregate time-series charts for all Sensor_Pods in the specified Sensor_Pool.
2. WHEN the page loads, THE Config_Manager SHALL query the Metrics_Store for Metric_Snapshots belonging to all Sensor_Pods in the specified pool within the selected Time_Range (default 6h).
3. THE Config_Manager SHALL render aggregate charts showing one line per sensor for single-series metrics and one line per sensor plus Series_Key for multi-series metrics, with each line labeled and visually distinguishable.
4. WHEN a pool has more than 10 sensors, THE Config_Manager SHALL display a summary chart showing min, max, and average across all sensors instead of individual lines, with an option to expand to individual sensor lines.
5. WHEN the pool has no member sensors, THE Config_Manager SHALL display a message "No sensors assigned to this pool" instead of charts.
6. THE Config_Manager SHALL display the pool name and a link back to the pool detail page (`/pools/:id`) in the page header.
7. THE Config_Manager SHALL require the `sensors:view` RBAC permission to access the page.
8. WHEN the requested Sensor_Pool ID does not exist, THE Config_Manager SHALL display a 404 Not Found page.
9. WHEN rendering per-container metrics in pool view, THE Config_Manager SHALL disambiguate each line by both sensor name and container name.
10. THE Config_Manager SHALL subscribe to pool membership updates so that sensors added to or removed from the pool are reflected without requiring a full page reload.

### Requirement 6: Time Range Selection

**User Story:** As a platform operator, I want to select different time windows for the charts, so that I can zoom in on recent events or see longer trends.

#### Acceptance Criteria

1. THE Config_Manager SHALL display a time range selector on both the sensor metrics page and the pool metrics page with options: 1h, 6h, 24h, 72h.
2. WHEN the operator selects a different Time_Range, THE Config_Manager SHALL re-query the Metrics_Store for the new range and update all charts without a full page reload.
3. THE Config_Manager SHALL default to the 6h time range on initial page load.
4. THE Config_Manager SHALL visually indicate which Time_Range is currently selected.
5. THE Config_Manager SHALL preserve the selected Time_Range when new real-time data arrives and charts update.
6. THE Config_Manager SHALL reflect the selected Time_Range in the URL query string so refreshes and shared links preserve the selected window.
7. IF an invalid Time_Range is provided in the URL or LiveView event, THEN THE Config_Manager SHALL fall back to the default 6h range and SHALL NOT execute an unbounded query.

### Requirement 7: Real-Time Chart Updates

**User Story:** As a platform operator, I want charts to update in real time as new metrics arrive, so that I can monitor live trends without refreshing the page.

#### Acceptance Criteria

1. WHEN the sensor metrics page is open, THE Config_Manager SHALL subscribe to the PubSub topic `"sensor_metrics:#{sensor_pod_id}"` for the displayed sensor.
2. WHEN the pool metrics page is open, THE Config_Manager SHALL subscribe to the PubSub topic `"sensor_metrics:#{sensor_pod_id}"` for each sensor in the displayed pool.
3. WHEN a `{:metrics_updated, sensor_pod_id}` message is received, THE Config_Manager SHALL query the latest Metric_Snapshots for the affected sensor and push the new data points to the client-side charts.
4. THE Config_Manager SHALL append new data points to existing charts without re-rendering the entire chart, using the LiveView JavaScript hook to call the charting library's update API.
5. WHEN new data points arrive for the selected rolling Time_Range, THE Config_Manager SHALL shift the chart's visible window forward to include the new data while maintaining the selected range duration.
6. WHEN the pool metrics page receives a metrics update for a sensor that is not currently a member of the displayed pool, THE Config_Manager SHALL ignore the update.
7. THE Config_Manager SHALL debounce or coalesce rapid metrics updates to avoid unbounded LiveView re-renders and client chart updates.
8. WHEN pool membership changes, THE Config_Manager SHALL subscribe to newly added sensor metrics topics and unsubscribe from removed sensor metrics topics.

### Requirement 8: Chart Rendering

**User Story:** As a platform operator, I want clear, readable time-series charts, so that I can quickly identify trends and anomalies.

#### Acceptance Criteria

1. THE Chart_Component SHALL render time-series line charts with time on the x-axis and the metric value on the y-axis.
2. THE Chart_Component SHALL use a client-side JavaScript charting library integrated via a LiveView hook.
3. THE Chart_Component SHALL display the metric name as the chart title.
4. THE Chart_Component SHALL display appropriate y-axis units for each Metric_Type: "pps" for packets_received_rate, "%" for drop_percent and cpu_percent and pcap_disk_used_percent, "MB" or "GB" for memory_bytes, "ms" for clock_offset_ms, "rec/s" for vector_records_per_sec, "%" for sink_buffer_used_percent.
5. THE Chart_Component SHALL display human-readable time labels on the x-axis appropriate to the selected Time_Range (e.g., "HH:MM" for 1h/6h, "MMM DD HH:MM" for 24h/72h).
6. THE Chart_Component SHALL support hover/tooltip interaction showing the exact value and timestamp for a data point.
7. WHEN a chart contains data for multiple sensors (pool view), THE Chart_Component SHALL display a legend mapping line colors to sensor names.
8. THE Chart_Component SHALL use threshold lines or background shading to indicate warning and critical zones where applicable: drop_percent above 1% (warning) and above 5% (critical), cpu_percent above 80% (warning) and above 95% (critical), pcap_disk_used_percent above 85% (warning) and above 95% (critical), clock_offset_ms outside ±50ms (warning) and outside ±100ms (critical).
9. THE Chart_Component SHALL use stable chart and series IDs so LiveView updates can patch changed series without recreating every chart.
10. THE Chart_Component SHALL honor reduced-motion preferences and SHALL NOT use continuous animation for live updates.
11. THE Chart_Component SHALL cap the number of rendered points per series using a configurable chart point limit and SHALL show a note when data has been downsampled.

### Requirement 9: Graceful Handling of Unavailable Metrics

**User Story:** As a platform operator, I want to understand which metrics are not yet available, so that I am not confused by missing charts.

#### Acceptance Criteria

1. WHEN a Metric_Type is not available because the HealthReport protobuf does not include the source data (vector_records_per_sec, sink_buffer_used_percent), THE Config_Manager SHALL display a chart placeholder with the message "Data source not yet available — requires HealthReport protobuf extension for [metric name]".
2. WHEN a Metric_Type has no snapshots for the selected time range but the data source exists in the protobuf, THE Config_Manager SHALL display a chart placeholder with the message "No data recorded for [metric name] in the selected time range".
3. THE Config_Manager SHALL distinguish between "data source not available" (protobuf limitation) and "no data recorded" (sensor offline or recently enrolled) using distinct placeholder messages and visual styling.
4. WHEN a sensor has been offline for the entire selected time range, THE Config_Manager SHALL display a banner indicating "Sensor was offline during the selected time range" above the chart area.
5. THE Config_Manager SHALL determine "offline during selected time range" from the absence of any snapshots for metrics whose source exists in the current HealthReport schema, not from missing future-only Metric_Types.

### Requirement 10: Navigation and Linking

**User Story:** As a platform operator, I want to navigate to metrics pages from existing sensor and pool pages, so that I can quickly access historical data.

#### Acceptance Criteria

1. THE Config_Manager SHALL add a "Metrics" navigation link on the sensor detail page (`/sensors/:id`) that links to `/sensors/:id/metrics`.
2. THE Config_Manager SHALL add a "Metrics" navigation link on the pool detail page (`/pools/:id`) that links to `/pools/:id/metrics`.
3. WHEN the operator is on the pool metrics page, THE Config_Manager SHALL provide links from each sensor's chart line or legend entry to that sensor's individual metrics page (`/sensors/:sensor_id/metrics`).
4. THE Config_Manager SHALL add the metrics routes to the authenticated scope in the router with the `sensors:view` permission requirement.
5. THE auth-rbac-audit route policy SHALL include `/sensors/:id/metrics` and `/pools/:id/metrics` as read-only `sensors:view` routes.

### Requirement 11: Chart Accessibility

**User Story:** As a platform operator using assistive technology, I want to access metrics data in a non-visual format, so that I can review historical health without relying on chart visuals.

#### Acceptance Criteria

1. THE Chart_Component SHALL include an `aria-label` attribute on the chart container describing the metric name, time range, and data summary (e.g., "Packets received rate chart, last 6 hours, range 1200 to 4500 pps").
2. THE Chart_Component SHALL provide a "View as table" toggle that renders the chart data as an accessible HTML table with columns for timestamp and value.
3. WHEN the table view is active, THE Config_Manager SHALL display the data sorted by timestamp in descending order with human-readable formatting.
4. THE time range selector SHALL be keyboard-navigable and announce the selected range to screen readers.
5. THE Chart_Component SHALL use sufficient color contrast ratios (minimum 4.5:1 against the chart background) for all data lines and threshold indicators.
6. WHEN threshold zones are displayed, THE Chart_Component SHALL convey threshold information through text labels or patterns in addition to color.
7. THE Chart_Component SHALL provide accessible series labels for multi-line charts, including sensor name and container name when applicable.

### Requirement 12: Metrics Query API

**User Story:** As a developer building the metrics UI, I want a clean context API for querying metrics, so that LiveView modules remain thin and testable.

#### Acceptance Criteria

1. THE Metrics_Store SHALL provide a function `list_snapshots(sensor_pod_id, metric_type, time_range, opts \\ [])` that returns Metric_Snapshots ordered by `recorded_at` ascending within the specified time range.
2. THE Metrics_Store SHALL provide a function `list_snapshots_for_pool(pool_id, metric_type, time_range, opts \\ [])` that returns Metric_Snapshots for all sensors in the pool, grouped by sensor_pod_id and series_key, ordered by `recorded_at` ascending within each group.
3. THE Metrics_Store SHALL provide a function `available_metric_types(sensor_pod_id)` that returns the list of Metric_Types for which at least one snapshot exists for the given sensor.
4. THE Metrics_Store SHALL provide a function `latest_snapshot(sensor_pod_id, metric_type)` that returns the most recent Metric_Snapshot for a given sensor and metric type, or nil.
5. THE Metrics_Store SHALL provide a function `write_snapshots(snapshots)` that inserts a list of Metric_Snapshots in a single transaction and returns the inserted count.
6. THE Metrics_Store SHALL provide a function `prune_before(cutoff_datetime, batch_size)` that deletes snapshots older than the cutoff in batches and returns the total number of deleted rows.
7. THE Metrics_Store query functions SHALL validate Time_Range inputs and SHALL never run an unbounded query from user-provided parameters.
8. THE Metrics_Store query functions SHALL support optional bucketing/downsampling options for chart rendering.

### Requirement 13: Container-Level Metric Disambiguation

**User Story:** As a platform operator, I want CPU and memory charts to show per-container breakdowns, so that I can identify which container is consuming resources.

#### Acceptance Criteria

1. WHEN the Snapshot_Sampler writes `cpu_percent` and `memory_bytes` snapshots, THE Snapshot_Sampler SHALL write one snapshot per container, storing the original container name in the `metadata` JSON field as `{"container": "container_name"}` and setting `series_key` to `container:<sanitized_container_name>`.
2. THE Chart_Component for cpu_percent and memory_bytes SHALL render one line per container, with each line labeled by container name.
3. WHEN a sensor has multiple containers, THE Chart_Component SHALL display a legend mapping line colors to container names.
4. THE Metrics_Store `list_snapshots` function SHALL support an optional `metadata_filter` parameter to query snapshots for a specific container.
5. THE Metric_Snapshot `series_key` for container metrics SHALL be stable for the container name, so chart updates can append to the correct series.

### Requirement 14: Configuration

**User Story:** As a platform administrator, I want metrics behavior to be configurable, so that I can tune sampling and retention for my deployment size.

#### Acceptance Criteria

1. THE Config_Manager SHALL support the following application environment configuration keys under `:config_manager`: `:metrics_sample_interval_ms` (default 60_000), `:metrics_retention_hours` (default 72), `:metrics_prune_interval_ms` (default 900_000), `:metrics_prune_batch_size` (default 1000).
2. WHEN the Snapshot_Sampler starts, THE Snapshot_Sampler SHALL read configuration values from the application environment and use them for scheduling.
3. IF a configuration value is missing or invalid, THEN THE Snapshot_Sampler SHALL fall back to the documented default value and log a warning.
4. THE Config_Manager SHALL support `:metrics_chart_point_limit` (default 1000 points per series) to bound chart query and rendering cost.
5. IF `:metrics_retention_hours` is configured below 72 outside the test environment, THEN THE Config_Manager SHALL use 72 and log a warning.

### Requirement 15: Tests and Verification

**User Story:** As an engineer implementing historical metrics, I want explicit test expectations, so that persistence, retention, chart queries, and realtime behavior are verified.

#### Acceptance Criteria

1. THE Config_Manager SHALL include migration or schema tests proving the `metric_snapshots` table, foreign key, indexes, defaults, and validation rules are present.
2. THE Config_Manager SHALL include Snapshot_Sampler tests for each Metric_Type derived from the current HealthReport schema.
3. THE Config_Manager SHALL include tests proving rate metrics are skipped on the first sample, on counter resets, and on non-advancing timestamps.
4. THE Config_Manager SHALL include tests proving unavailable future metrics are skipped by the sampler and rendered as "data source not yet available" placeholders.
5. THE Config_Manager SHALL include pruning tests proving old rows are deleted in batches and rows within the Retention_Period are preserved.
6. THE Config_Manager SHALL include LiveView tests for sensor metrics page rendering, pool metrics page rendering, time range changes, 404s, and RBAC enforcement.
7. THE Config_Manager SHALL include realtime tests proving matching PubSub updates append new points and unrelated updates are ignored.
8. THE Config_Manager SHALL include accessibility tests proving table fallback, chart labels, keyboard time range selection, and non-color threshold labels are present.
9. THE Config_Manager SHALL include tests proving metadata does not persist secrets or certificate material.
10. THE Config_Manager SHALL include tests proving chart point limits and downsampling are applied for large result sets.
