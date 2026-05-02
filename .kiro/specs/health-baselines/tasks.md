# Tasks: Health Baselines and Capacity Warnings

## Task 1: Database Migration and Ecto Schema

- [ ] 1.1 Create migration for `health_baselines` table with columns: id (binary_id PK), sensor_pod_id (binary_id FK → sensor_pods, nullable, on_delete: delete_all), pool_id (binary_id FK → sensor_pools, nullable, on_delete: delete_all), metric_type (string, NOT NULL), series_key (string, NOT NULL, default "default"), mean (float, NOT NULL), stddev (float, NOT NULL), p5 (float, NOT NULL), p95 (float, NOT NULL), min_value (float, NOT NULL), max_value (float, NOT NULL), sample_count (integer, NOT NULL), window_start (utc_datetime, NOT NULL), window_end (utc_datetime, NOT NULL), computed_at (utc_datetime, NOT NULL), timestamps; add partial unique indexes on (sensor_pod_id, metric_type, series_key) WHERE sensor_pod_id IS NOT NULL and (pool_id, metric_type, series_key) WHERE pool_id IS NOT NULL; add lookup indexes on sensor_pod_id and pool_id
- [ ] 1.2 Create `ConfigManager.Baselines.HealthBaseline` Ecto schema with changeset validation: required fields (metric_type, mean, stddev, p5, p95, min_value, max_value, sample_count, window_start, window_end, computed_at), stddev ≥ 0, sample_count > 0, scope validation (exactly one of sensor_pod_id or pool_id must be set), unique constraints on sensor and pool indexes
- [ ] 1.3 Write unit tests for HealthBaseline changeset: valid sensor baseline accepted, valid pool baseline accepted, both sensor_pod_id and pool_id set rejected, both nil rejected, negative stddev rejected, zero sample_count rejected, missing required fields rejected

## Task 2: Pure Statistical Functions

- [ ] 2.1 Implement `ConfigManager.Baselines.Statistics.compute_profile/2` that takes a list of numeric values and a minimum sample count (default 240), returns `{:ok, %{mean, stddev, p5, p95, min_value, max_value, sample_count}}` when sufficient data exists, or `{:error, :insufficient_data}` when below minimum; use population standard deviation; implement percentile via linear interpolation between nearest ranks
- [ ] 2.2 Implement `ConfigManager.Baselines.Statistics.anomaly_score/4` that computes `abs(value - mean) / stddev` for stddev > 0, returns 0.0 when value == mean regardless of stddev, and for stddev == 0 with value != mean returns a large sentinel value only when `abs(value - mean) > min_delta`
- [ ] 2.3 Implement `ConfigManager.Baselines.Statistics.classify/4` that returns `{:anomaly, score}` when anomaly_score exceeds sigma_threshold or value falls outside [p5, p95], and `:normal` otherwise; handle zero-stddev case using min_delta
- [ ] 2.4 Implement `ConfigManager.Baselines.Statistics.linear_regression/2` that takes a list of `{timestamp_unix, value}` pairs and minimum point count (default 12), computes OLS slope, intercept, and r_squared; returns `{:ok, %{slope, intercept, r_squared}}` or `{:error, :insufficient_data}`
- [ ] 2.5 Implement `ConfigManager.Baselines.Statistics.project/3` that computes `slope * future_timestamp + intercept`
- [ ] 2.6 Implement `ConfigManager.Baselines.Statistics.time_to_threshold/4` that computes when the projected value reaches a threshold; returns `{:ok, timestamp}` if breach occurs within horizon, `{:error, :no_breach}` if not, `{:error, :flat_trend}` if slope ≈ 0
- [ ] 2.7 Implement `ConfigManager.Baselines.Statistics.percentile/2` that computes the p-th percentile from a sorted list using linear interpolation
- [ ] 2.8 Write property test for statistical profile correctness (Property 1): generate lists of 240+ random floats, verify mean = sum/count, stddev matches population formula, p5/p95 are correct percentiles, min/max match, sample_count matches length
- [ ] 2.9 Write property test for insufficient data threshold (Property 2): generate lists with lengths from 0 to 300, verify compute_profile returns error below 240 and ok at/above 240
- [ ] 2.10 Write property test for anomaly score computation (Property 7): generate random (value, mean, stddev > 0) triples, verify score = abs(value - mean) / stddev; verify score = 0 when value == mean
- [ ] 2.11 Write property test for anomaly classification with zero-stddev (Property 8): generate random (value, baseline, sigma, min_delta) tuples including zero-stddev cases, verify classification correctness for both normal stddev and zero-stddev paths
- [ ] 2.12 Write property test for linear regression accuracy (Property 11): generate points from known linear functions y = slope * x + intercept + bounded_noise, verify recovered slope is within tolerance, projection at future timestamp is within tolerance
- [ ] 2.13 Write property test for capacity warning threshold breach detection (Property 12): generate random (slope, intercept, threshold, horizon) tuples, verify time_to_threshold returns {:ok, ts} when breach occurs and {:error, :no_breach} when not; verify returned timestamp satisfies slope * ts + intercept ≈ threshold
- [ ] 2.14 Write property test for minimum samples for forecast (Property 13): generate point sets with lengths from 0 to 20, verify linear_regression returns error below 12 and ok at/above 12

## Task 3: Baselines Context Module

- [ ] 3.1 Implement `ConfigManager.Baselines.upsert_baseline/1` that inserts or updates a health baseline using `Repo.insert/2` with `on_conflict: :replace_all` on the appropriate unique index, handling both sensor and pool baselines
- [ ] 3.2 Implement `ConfigManager.Baselines.list_baselines_for_sensor/1` returning all baselines for a sensor_pod_id ordered by metric_type
- [ ] 3.3 Implement `ConfigManager.Baselines.list_baselines_for_pool/1` returning all pool-level baselines (sensor_pod_id IS NULL, pool_id matches) ordered by metric_type
- [ ] 3.4 Implement `ConfigManager.Baselines.get_baseline/3` and `get_pool_baseline/3` for single baseline lookups
- [ ] 3.5 Implement `ConfigManager.Baselines.compute_sensor_baseline/4` that queries `Metrics.list_snapshots/4` for the baseline window (default 48h), excludes the most recent 10 minutes, extracts values, and calls `Statistics.compute_profile/2`; returns `{:ok, profile_map}` or `{:error, :insufficient_data}`
- [ ] 3.6 Implement `ConfigManager.Baselines.compute_pool_baseline/4` that loads pool member sensors, queries snapshots for all members, combines values, checks minimum 2 sensors with sufficient data, and calls `Statistics.compute_profile/2`; returns `{:ok, profile_map}` or `{:error, :insufficient_sensors | :insufficient_data}`
- [ ] 3.7 Implement `ConfigManager.Baselines.evaluate_anomaly/3` that calls `Statistics.classify/4` with the appropriate sigma threshold (per-metric or default) and min_delta, returns `{:anomaly, score, details_map}` or `:normal`
- [ ] 3.8 Implement `ConfigManager.Baselines.compute_forecast/4` that queries last 6h of snapshots, runs `Statistics.linear_regression/2`, projects to forecast horizon, checks against `capacity_threshold/1`, returns `{:ok, forecast_map}` or `{:error, reason}`
- [ ] 3.9 Implement `ConfigManager.Baselines.capacity_threshold/1` returning 95.0 for pcap_disk_used_percent, 95.0 for cpu_percent, 10.0 for drop_percent, nil for non-capacity metrics (memory_bytes handled separately with total memory context)
- [ ] 3.10 Implement configuration accessors: `baseline_window_hours/0`, `default_sigma/0`, `cooldown_minutes/0`, `forecast_horizon_hours/0` with validation and fallback to defaults on invalid values
- [ ] 3.11 Implement `ConfigManager.Baselines.delete_baselines_for_sensor/1` for cleanup
- [ ] 3.12 Write property test for exclusion window filtering (Property 3): generate snapshot sets with timestamps spanning 48h including last 10 minutes, verify excluded snapshots don't affect the computed profile
- [ ] 3.13 Write property test for baseline upsert round-trip and uniqueness (Property 4): generate random baseline attributes, upsert, read back, verify equality; upsert twice with same key, verify single row with latest values
- [ ] 3.14 Write property test for pool aggregate baseline (Property 5): generate 2-5 sensors with random snapshot sets, verify pool sample_count = sum, pool mean = overall mean, pool min ≤ all sensor mins, pool max ≥ all sensor maxes
- [ ] 3.15 Write property test for pool minimum sensor threshold (Property 6): generate pools with 0-3 sensors having sufficient data, verify error for < 2, ok for ≥ 2
- [ ] 3.16 Write property test for outlier identification (Property 15): generate pool baselines and per-sensor current values, verify outlier set matches sensors deviating > 2σ from pool mean
- [ ] 3.17 Write property test for configuration validation with fallback (Property 16): generate random config values (valid and invalid), verify valid values used and invalid values fall back to defaults
- [ ] 3.18 Write unit tests for capacity thresholds: verify capacity_threshold/1 returns correct values for each capacity metric and nil for non-capacity metrics

## Task 4: Alert Rule Seeds for Baseline Alert Types

- [ ] 4.1 Extend the alert rule seeding (or create a new migration seed) to add two new default alert rules: `baseline_anomaly` (description: "Metric deviates significantly from baseline", threshold: 3.0, unit: "sigma", severity: "warning", enabled: true, builtin: true) and `capacity_warning` (description: "Metric trend predicts capacity exhaustion", threshold: 24, unit: "hours", severity: "warning", enabled: true, builtin: true)
- [ ] 4.2 Extend the `@alert_types` list in `ConfigManager.Alerts.AlertRule` schema to include `"baseline_anomaly"` and `"capacity_warning"`
- [ ] 4.3 Write unit tests verifying both new alert rules exist with correct defaults after seeding; verify idempotency (seeding twice doesn't duplicate)

## Task 5: Baselines Worker GenServer

- [ ] 5.1 Create `ConfigManager.Baselines.Worker` GenServer with init that loads existing baselines from DB into state cache, rebuilds cooldown map from recent baseline_anomaly alerts, rebuilds active_anomalies and active_warnings sets from active alerts in DB, subscribes to sensor_metrics PubSub topics for all known sensors, and schedules initial baseline recomputation and forecast timers
- [ ] 5.2 Implement `handle_info(:recompute_baselines, state)` that iterates all enrolled sensors and all metric types, calls `Baselines.compute_sensor_baseline/4` for each, upserts results to DB, then iterates all pools with ≥ 2 qualifying sensors and calls `Baselines.compute_pool_baseline/4`, upserts pool baselines, updates state cache, broadcasts `{:baselines_updated}`, and reschedules timer
- [ ] 5.3 Implement `handle_info({:metrics_updated, sensor_pod_id}, state)` that reads latest metric snapshots, evaluates each against cached baselines using `Baselines.evaluate_anomaly/3`, checks cooldown map before firing `baseline_anomaly` alerts via `Alerts.fire_alert/1`, auto-resolves cleared anomalies via `Alerts.auto_resolve_alert/1`, updates cooldown map and active_anomalies set, broadcasts anomaly status
- [ ] 5.4 Implement `handle_info(:recompute_forecasts, state)` that iterates all sensors and capacity metrics (pcap_disk_used_percent, cpu_percent, memory_bytes, drop_percent), calls `Baselines.compute_forecast/4` for each, fires `capacity_warning` alerts when threshold breach predicted, auto-resolves when forecast no longer predicts breach, updates state cache, broadcasts forecast updates, reschedules timer
- [ ] 5.5 Implement `handle_call({:get_forecasts, sensor_pod_id}, ...)` and `handle_call({:get_anomaly_status, sensor_pod_id}, ...)` for LiveView queries against cached state
- [ ] 5.6 Implement dynamic PubSub subscription management: subscribe to `"sensor_metrics:#{sensor_pod_id}"` for new sensors as they appear, unsubscribe when sensors are removed
- [ ] 5.7 Add Baselines Worker to application supervision tree in `ConfigManager.Application`, after Metrics.Sampler and Alert Engine
- [ ] 5.8 Write property test for cooldown suppression (Property 9): generate sequences of anomalous readings with timestamps for the same sensor+metric, verify at most one alert fires within any cooldown window
- [ ] 5.9 Write property test for anomaly auto-resolve (Property 10): generate anomaly → normal sequences, verify auto-resolve fires and active_anomalies set is updated
- [ ] 5.10 Write property test for capacity warning auto-resolve (Property 14): generate warning → trend-reversal sequences, verify auto-resolve fires and active_warnings set is updated
- [ ] 5.11 Write unit test for Worker lifecycle: starts under supervisor, schedules recomputation at configured interval (default 1h), schedules forecasts at configured interval (default 15min)
- [ ] 5.12 Write unit test for per-metric sigma override: configure different sigma thresholds for drop_percent (2.0) and cpu_percent (3.0), verify anomaly evaluation uses the correct threshold for each metric

## Task 6: Sensor Baselines LiveView Page

- [ ] 6.1 Create `ConfigManagerWeb.BaselinesLive.SensorBaselinesLive` with mount that loads SensorPod by ID, returns 404 if not found, loads baselines via `Baselines.list_baselines_for_sensor/1`, loads current metric values from Health Registry or latest snapshots, computes anomaly scores, loads forecasts via `Baselines.Worker.get_forecasts/1`, subscribes to `"baselines:sensor:#{sensor_pod_id}"` and `"sensor_metrics:#{sensor_pod_id}"` PubSub topics
- [ ] 6.2 Implement summary card rendering for each metric type showing: baseline mean, stddev, p5/p95 range, current value, anomaly score, and visual indicator (normal=green, warning=amber, anomaly=red); show "Baseline not available" placeholder for metrics with insufficient data; show "Insufficient data for forecast" when applicable
- [ ] 6.3 Implement anomaly highlighting: when a metric has an active anomaly, apply warning/critical CSS class to the summary card border and show the anomaly score prominently
- [ ] 6.4 Implement capacity warning display: when a metric has an active capacity warning, show projected time to threshold breach, forecasted value, and critical threshold in the summary card
- [ ] 6.5 Implement real-time PubSub handlers: `handle_info({:anomaly_status, ...})` updates anomaly indicators, `handle_info({:forecasts_updated, ...})` refreshes capacity warnings, `handle_info({:metrics_updated, ...})` updates current values and recomputes display scores, `handle_info({:baselines_updated})` reloads baselines from DB
- [ ] 6.6 Write unit test for sensor baselines page: renders summary cards for available metrics, shows placeholder for insufficient data, handles 404 for non-existent sensor, verifies sensors:view permission required

## Task 7: Pool Baselines LiveView Page

- [ ] 7.1 Create `ConfigManagerWeb.BaselinesLive.PoolBaselinesLive` with mount that loads pool by ID, returns 404 if not found, loads member sensors, loads pool-level baselines via `Baselines.list_baselines_for_pool/1`, loads per-sensor baselines for all members, computes per-sensor deviations from pool baseline, identifies outliers (sensors deviating > 2σ from pool mean), subscribes to `"baselines:pool:#{pool_id}"` PubSub topic
- [ ] 7.2 Implement pool baseline display: aggregate baseline summary per metric type, per-sensor comparison table with columns (sensor name, current value, sensor baseline mean, pool baseline mean, deviation from pool), outlier highlighting
- [ ] 7.3 Implement real-time PubSub handler: `handle_info({:baselines_updated})` reloads pool and sensor baselines, recomputes deviations and outliers
- [ ] 7.4 Handle edge cases: empty pool shows "No sensors assigned to this pool", pool with < 2 sensors with data shows "Insufficient sensors for pool baseline"
- [ ] 7.5 Write unit test for pool baselines page: renders pool baselines and comparison table, shows empty pool message, handles 404, verifies sensors:view permission required

## Task 8: Router and Navigation Updates

- [ ] 8.1 Add routes to the authenticated scope in `ConfigManagerWeb.Router`: `/sensors/:id/baselines` → `BaselinesLive.SensorBaselinesLive` with `required_permission: "sensors:view"`, `/pools/:id/baselines` → `BaselinesLive.PoolBaselinesLive` with `required_permission: "sensors:view"`
- [ ] 8.2 Add "Baselines" navigation link on the sensor detail page (`SensorDetailLive`) linking to `/sensors/:id/baselines`
- [ ] 8.3 Add "Baselines" navigation link on the pool detail page linking to `/pools/:id/baselines`
- [ ] 8.4 Write unit test verifying both baselines routes are accessible with sensors:view permission and return 403 for unauthorized roles
- [ ] 8.5 Write unit test verifying navigation links exist on sensor detail and pool detail pages

## Task 9: Configuration Support

- [ ] 9.1 Add default configuration values to `config/config.exs`: `:baseline_window_hours` (48), `:baseline_recompute_interval_ms` (3_600_000), `:anomaly_default_sigma` (3.0), `:anomaly_cooldown_minutes` (15), `:anomaly_min_delta_by_metric` (%{}), `:capacity_forecast_horizon_hours` (24), `:capacity_forecast_interval_ms` (900_000), `:capacity_min_forecast_samples` (12)
- [ ] 9.2 Add test-specific configuration overrides to `config/test.exs`: shorter intervals for faster test execution (e.g., `:baseline_recompute_interval_ms` → 100, `:capacity_forecast_interval_ms` → 100)
- [ ] 9.3 Write unit test verifying all configuration keys return correct defaults when not explicitly set

## Task 10: End-to-End Integration Tests

- [ ] 10.1 Write integration test for full anomaly detection flow: create sensor with metric snapshots → Worker computes baseline → new snapshot arrives with anomalous value → Worker detects anomaly → baseline_anomaly alert fired → sensor baselines page shows anomaly indicator
- [ ] 10.2 Write integration test for anomaly auto-resolve flow: anomaly alert active → new snapshot arrives with normal value → Worker auto-resolves alert → sensor baselines page updates
- [ ] 10.3 Write integration test for capacity warning flow: create sensor with trending metric data → Worker computes forecast → threshold breach predicted → capacity_warning alert fired → sensor baselines page shows time-to-breach
- [ ] 10.4 Write integration test for capacity warning auto-resolve: capacity warning active → trend reverses → Worker auto-resolves → sensor baselines page updates
- [ ] 10.5 Write integration test for baseline recomputation: Worker timer fires → baselines recomputed with new data → DB updated → PubSub broadcast → LiveView refreshes
- [ ] 10.6 Write integration test for FK cascade: delete SensorPod → verify all its baselines are deleted; delete SensorPool → verify pool baselines are deleted
- [ ] 10.7 Write integration test for alert rule integration: disable baseline_anomaly rule → verify no anomaly alerts fired even when metrics are anomalous; re-enable → verify alerts resume