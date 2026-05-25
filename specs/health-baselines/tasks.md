# Tasks: Health Baselines and Capacity Warnings

Status: Health Baselines v1 is implemented and merged to `main` from the deployed-verified Historical Metrics branch. The persistence/context/worker/browser route slice has local regression coverage, E2E fixtures, deployed full-profile E2E verification, service health, and cleanup audit passing. No Public API endpoints are added in this feature. Remaining broad property coverage and deeper worker-hardening work is tracked under Follow-up Hardening and does not block this validated v1 branch.

## Task 1: Database Migration and Ecto Schema

- [x] 1.1 Create migration for `health_baselines` table with columns: id (binary_id PK), sensor_pod_id (binary_id FK → sensor_pods, nullable, on_delete: delete_all), pool_id (binary_id FK → sensor_pools, nullable, on_delete: delete_all), metric_type (string, NOT NULL), series_key (string, NOT NULL, default "default"), mean (float, NOT NULL), stddev (float, NOT NULL), p5 (float, NOT NULL), p95 (float, NOT NULL), min_value (float, NOT NULL), max_value (float, NOT NULL), sample_count (integer, NOT NULL), window_start (utc_datetime, NOT NULL), window_end (utc_datetime, NOT NULL), computed_at (utc_datetime, NOT NULL), timestamps; add partial unique indexes on (sensor_pod_id, metric_type, series_key) WHERE sensor_pod_id IS NOT NULL and (pool_id, metric_type, series_key) WHERE pool_id IS NOT NULL; add lookup indexes on sensor_pod_id and pool_id
- [x] 1.2 Create `ConfigManager.Baselines.HealthBaseline` Ecto schema with changeset validation: required fields (metric_type, mean, stddev, p5, p95, min_value, max_value, sample_count, window_start, window_end, computed_at), stddev ≥ 0, sample_count > 0, scope validation (exactly one of sensor_pod_id or pool_id must be set), unique constraints on sensor and pool indexes
- [x] 1.3 Write unit tests for HealthBaseline changeset: valid sensor baseline accepted, valid pool baseline accepted, both sensor_pod_id and pool_id set rejected, both nil rejected, negative stddev rejected, zero sample_count rejected, missing required fields rejected

## Task 2: Pure Statistical Functions

- [x] 2.1 Implement `ConfigManager.Baselines.Statistics.compute_profile/2` that takes a list of numeric values and a minimum sample count (default 240), returns `{:ok, %{mean, stddev, p5, p95, min_value, max_value, sample_count}}` when sufficient data exists, or `{:error, :insufficient_data}` when below minimum; use population standard deviation; implement percentile via linear interpolation between nearest ranks
- [x] 2.2 Implement `ConfigManager.Baselines.Statistics.anomaly_score/4` that computes `abs(value - mean) / stddev` for stddev > 0, returns 0.0 when value == mean regardless of stddev, and for stddev == 0 with value != mean returns a large sentinel value only when `abs(value - mean) > min_delta`
- [x] 2.3 Implement `ConfigManager.Baselines.Statistics.classify/4` that returns `{:anomaly, score}` when anomaly_score exceeds sigma_threshold or value falls outside [p5, p95], and `:normal` otherwise; handle zero-stddev case using min_delta
- [x] 2.4 Implement `ConfigManager.Baselines.Statistics.linear_regression/2` that takes a list of `{timestamp_unix, value}` pairs and minimum point count (default 12), computes OLS slope, intercept, and r_squared; returns `{:ok, %{slope, intercept, r_squared}}` or `{:error, :insufficient_data}`
- [x] 2.5 Implement `ConfigManager.Baselines.Statistics.project/3` that computes `slope * future_timestamp + intercept`
- [x] 2.6 Implement `ConfigManager.Baselines.Statistics.time_to_threshold/4` that computes when the projected value reaches a threshold; returns `{:ok, timestamp}` if breach occurs within horizon, `{:error, :no_breach}` if not, `{:error, :flat_trend}` if slope ≈ 0
- [x] 2.7 Implement `ConfigManager.Baselines.Statistics.percentile/2` that computes the p-th percentile from a sorted list using linear interpolation

## Task 3: Baselines Context Module

- [x] 3.1 Implement `ConfigManager.Baselines.upsert_baseline/1` that inserts or updates a health baseline using `Repo.insert/2` with `on_conflict: :replace_all` on the appropriate unique index, handling both sensor and pool baselines
- [x] 3.2 Implement `ConfigManager.Baselines.list_baselines_for_sensor/1` returning all baselines for a sensor_pod_id ordered by metric_type
- [x] 3.3 Implement `ConfigManager.Baselines.list_baselines_for_pool/1` returning all pool-level baselines (sensor_pod_id IS NULL, pool_id matches) ordered by metric_type
- [x] 3.4 Implement `ConfigManager.Baselines.get_baseline/3` and `get_pool_baseline/3` for single baseline lookups
- [x] 3.5 Implement `ConfigManager.Baselines.compute_sensor_baseline/4` that queries `Metrics.list_snapshots/4` for the baseline window (default 48h), excludes the most recent 10 minutes, extracts values, and calls `Statistics.compute_profile/2`; returns `{:ok, profile_map}` or `{:error, :insufficient_data}`
- [x] 3.6 Implement `ConfigManager.Baselines.compute_pool_baseline/4` that loads pool member sensors, queries snapshots for all members, combines values, checks minimum 2 sensors with sufficient data, and calls `Statistics.compute_profile/2`; returns `{:ok, profile_map}` or `{:error, :insufficient_sensors | :insufficient_data}`
- [x] 3.7 Implement `ConfigManager.Baselines.evaluate_anomaly/3` that calls `Statistics.classify/4` with the appropriate sigma threshold (per-metric or default) and min_delta, returns `{:anomaly, score, details_map}` or `:normal`
- [x] 3.8 Implement `ConfigManager.Baselines.compute_forecast/4` that queries last 6h of snapshots, runs `Statistics.linear_regression/2`, projects to forecast horizon, checks against `capacity_threshold/1`, returns `{:ok, forecast_map}` or `{:error, reason}`
- [x] 3.9 Implement `ConfigManager.Baselines.capacity_threshold/1` returning 95.0 for pcap_disk_used_percent, 95.0 for cpu_percent, 10.0 for drop_percent, nil for non-capacity metrics (memory_bytes handled separately with total memory context)
- [x] 3.10 Implement configuration accessors: `baseline_window_hours/0`, `default_sigma/0`, `cooldown_minutes/0`, `forecast_horizon_hours/0` with validation and fallback to defaults on invalid values
- [x] 3.11 Implement `ConfigManager.Baselines.delete_baselines_for_sensor/1` for cleanup
- [x] 3.12 Write property test for outlier identification (Property 15): generate pool baselines and per-sensor current values, verify outlier set matches sensors deviating > 2σ from pool mean

## Task 4: Alert Rule Seeds for Baseline Alert Types

- [x] 4.1 Extend the alert rule seeding (or create a new migration seed) to add two new default alert rules: `baseline_anomaly` (description: "Metric deviates significantly from baseline", threshold: 3.0, unit: "sigma", severity: "warning", enabled: true, builtin: true) and `capacity_warning` (description: "Metric trend predicts capacity exhaustion", threshold: 24, unit: "hours", severity: "warning", enabled: true, builtin: true)
- [x] 4.2 Extend the `@alert_types` list in `ConfigManager.Alerts.AlertRule` schema to include `"baseline_anomaly"` and `"capacity_warning"`
- [x] 4.3 Write unit tests verifying both new alert rules exist with correct defaults after seeding; verify idempotency (seeding twice doesn't duplicate)

## Task 5: Baselines Worker GenServer

- [x] 5.1 Create `ConfigManager.Baselines.Worker` GenServer with init that loads existing baselines and enabled rules, subscribes to current sensor metric topics plus sensor/rule updates, and schedules initial baseline recomputation and forecast timers
- [x] 5.2 Implement `handle_info(:recompute_baselines, state)` that iterates all enrolled sensors and all metric types, calls `Baselines.compute_sensor_baseline/4` for each, upserts results to DB, then iterates all pools with ≥ 2 qualifying sensors and calls `Baselines.compute_pool_baseline/4`, upserts pool baselines, updates state cache, broadcasts `{:baselines_updated}`, and reschedules timer
- [x] 5.3 Implement `handle_info({:metrics_updated, sensor_pod_id}, state)` that reads latest metric snapshots, evaluates each against cached baselines using `Baselines.evaluate_anomaly/3`, fires `baseline_anomaly` alerts via `Alerts.fire_alert/1`, auto-resolves cleared anomalies via `Alerts.auto_resolve_alert/1`, updates anomaly state, and broadcasts anomaly status
- [x] 5.4 Implement `handle_info(:recompute_forecasts, state)` that iterates all sensors and capacity metrics (pcap_disk_used_percent, cpu_percent, memory_bytes, drop_percent), calls `Baselines.compute_forecast/4` for each, fires `capacity_warning` alerts when threshold breach predicted, auto-resolves when forecast no longer predicts breach, updates state cache, broadcasts forecast updates, reschedules timer
- [x] 5.5 Implement `handle_call({:get_forecasts, sensor_pod_id}, ...)` and `handle_call({:get_anomaly_status, sensor_pod_id}, ...)` for LiveView queries against cached state
- [x] 5.6 Implement PubSub subscription refresh for new or updated sensors by resubscribing to current `"sensor_metrics:#{sensor_pod_id}"` topics when sensor pod events arrive
- [x] 5.7 Add Baselines Worker to application supervision tree in `ConfigManager.Application`, after Metrics.Sampler and Alert Engine

## Task 6: Sensor Baselines LiveView Page

- [x] 6.1 Create `ConfigManagerWeb.BaselinesLive.SensorBaselinesLive` with mount that loads SensorPod by ID, returns 404 if not found, loads baselines via `Baselines.list_baselines_for_sensor/1`, loads current metric values from latest snapshots, computes anomaly scores, computes forecasts, and subscribes to `"baselines:sensor:#{sensor_pod_id}"` and `"sensor_metrics:#{sensor_pod_id}"` PubSub topics
- [x] 6.2 Implement summary card rendering for each metric type showing: baseline mean, stddev, p5/p95 range, current value, anomaly score, and visual indicator (normal=green, warning=amber, anomaly=red); show "Baseline not available" placeholder for metrics with insufficient data; show "Insufficient data for forecast" when applicable
- [x] 6.3 Implement anomaly highlighting: when a metric has an active anomaly, apply warning/critical CSS class to the summary card border and show the anomaly score prominently
- [x] 6.4 Implement capacity warning display: when a metric has an active capacity warning, show projected time to threshold breach, forecasted value, and critical threshold in the summary card
- [x] 6.5 Implement real-time PubSub handlers: `handle_info({:anomaly_status, ...})` updates anomaly indicators, `handle_info({:forecasts_updated, ...})` refreshes capacity warnings, `handle_info({:metrics_updated, ...})` updates current values and recomputes display scores, `handle_info({:baselines_updated})` reloads baselines from DB
- [x] 6.6 Write unit test for sensor baselines page: renders summary cards for available metrics, shows placeholder for insufficient data, handles 404 for non-existent sensor, verifies sensors:view permission required

## Task 7: Pool Baselines LiveView Page

- [x] 7.1 Create `ConfigManagerWeb.BaselinesLive.PoolBaselinesLive` with mount that loads pool by ID, returns 404 if not found, loads member sensors, loads pool-level baselines via `Baselines.list_baselines_for_pool/1`, computes per-sensor deviations from pool baseline, identifies outliers (sensors deviating > 2σ from pool mean), and subscribes to `"baselines:pool:#{pool_id}"` PubSub topic
- [x] 7.2 Implement pool baseline display: aggregate baseline summary per metric type, per-sensor comparison table with columns (sensor name, current value, pool mean, deviation from pool, status), and outlier highlighting
- [x] 7.3 Implement real-time PubSub handler: `handle_info({:baselines_updated})` reloads pool and sensor baselines, recomputes deviations and outliers
- [x] 7.4 Handle edge cases: empty pool shows "No sensors assigned to this pool", pool with < 2 sensors with data shows "Insufficient sensors for pool baseline"
- [x] 7.5 Write unit test for pool baselines page: renders pool baselines and comparison table, shows empty pool message, handles 404, verifies sensors:view permission required

## Task 8: Router and Navigation Updates

- [x] 8.1 Add routes to the authenticated scope in `ConfigManagerWeb.Router`: `/sensors/:id/baselines` → `BaselinesLive.SensorBaselinesLive` with `required_permission: "sensors:view"`, `/pools/:id/baselines` → `BaselinesLive.PoolBaselinesLive` with `required_permission: "sensors:view"`
- [x] 8.2 Add "Baselines" navigation link on the sensor detail page (`SensorDetailLive`) linking to `/sensors/:id/baselines`
- [x] 8.3 Add "Baselines" navigation link on the pool detail page linking to `/pools/:id/baselines`
- [x] 8.4 Write unit test verifying both baselines routes are accessible with sensors:view permission and return 403 for unauthorized roles
- [x] 8.5 Write unit test verifying navigation links exist on sensor detail and pool detail pages

## Task 9: Configuration Support

- [x] 9.1 Add default configuration values to `config/config.exs`: `:baseline_window_hours` (48), `:baseline_recompute_interval_ms` (3_600_000), `:anomaly_default_sigma` (3.0), `:anomaly_cooldown_minutes` (15), `:anomaly_min_delta_by_metric` (%{}), `:capacity_forecast_horizon_hours` (24), `:capacity_forecast_interval_ms` (900_000), `:capacity_min_forecast_samples` (12)
- [x] 9.2 Add test-specific configuration overrides to `config/test.exs`: shorter intervals for faster test execution (e.g., `:baseline_recompute_interval_ms` → 100, `:capacity_forecast_interval_ms` → 100)

## Task 10: End-to-End Integration Tests

- [x] 10.1 Write integration coverage for anomaly detection flow: create sensor with metric snapshots → Worker evaluates anomalous value → baseline_anomaly alert fired → normal value auto-resolves alert
- [x] 10.2 Write integration test for anomaly auto-resolve flow: anomaly alert active → new snapshot arrives with normal value → Worker auto-resolves alert → sensor baselines page updates
- [x] 10.3 Write integration test for capacity warning flow: create sensor with trending metric data → Worker computes forecast → threshold breach predicted → capacity_warning alert fired → sensor baselines page shows time-to-breach
- [x] 10.4 Write integration test for capacity warning auto-resolve: capacity warning active → trend reverses → Worker auto-resolves → sensor baselines page updates
- [x] 10.5 Write integration test for baseline recomputation: Worker timer fires → baselines recomputed with new data → DB updated → PubSub broadcast → LiveView refreshes

## Task 11: Browser E2E Verification

- [x] 11.1 Add full-profile Playwright coverage for sensor and pool baseline pages using deterministic `e2e-` database fixtures and cleanup
- [x] 11.2 Deploy Health Baselines to the test server and run `cd e2e && npm run preflight && npm run test:full`
- [x] 11.3 Verify no lingering `e2e-` sensors, baseline fixtures, metric fixtures, pools, users, alerts, PCAP requests, rulesets, or repositories remain after the deployed E2E run

## Follow-up Hardening

These items are intentionally deferred from the validated v1 branch. They improve confidence and operational polish, but they do not block the deployed Health Baselines feature.

- [ ] Add broad property coverage for statistical profile correctness, insufficient-data thresholds, anomaly score/classification, linear regression accuracy, threshold breach timing, and minimum forecast samples.
- [ ] Add broad property/context coverage for exclusion-window filtering, baseline upsert round-trip uniqueness, pool aggregate baseline math, pool minimum sensor threshold, configuration fallback behavior, and capacity threshold defaults.
- [ ] Harden Worker state reconstruction by rebuilding anomaly/capacity cooldown and active-alert state from recent DB alerts on startup.
- [ ] Add explicit cooldown suppression for repeated `baseline_anomaly` alerts within `anomaly_cooldown_minutes`.
- [ ] Add dynamic PubSub unsubscribe behavior when sensors are removed or no longer need metric subscriptions.
- [ ] Add focused Worker tests for scheduler lifecycle, per-metric sigma overrides, cooldown suppression, anomaly auto-resolve, and capacity warning auto-resolve.
- [ ] Add deeper integration tests for FK cascade cleanup of sensor/pool baselines and alert-rule disable/re-enable behavior.
- [ ] Consider adding per-sensor baseline mean to the pool comparison table if operators need side-by-side sensor-vs-pool baseline comparison.
