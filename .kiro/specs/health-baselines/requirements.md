# Requirements Document: Health Baselines and Capacity Warnings

## Introduction

The RavenWire Config Manager's historical-metrics spec provides time-series persistence and charting for sensor health metrics (packet rate, drop percentage, CPU, memory, disk usage, clock offset). The platform-alert-center spec provides threshold-based alerting for conditions like high packet drops, disk critical, and sensor offline. However, both systems use static thresholds: a drop rate above 5% triggers an alert regardless of whether the sensor normally operates at 3% drops (indicating a real problem) or normally operates at 4.5% drops (indicating normal behavior for a high-traffic segment).

This feature adds health baselines and capacity warnings to the Config Manager. It establishes per-sensor and per-pool health baselines from historical metrics data, detects anomalies when current metrics deviate significantly from the established baseline, and generates capacity warnings when metric trends indicate a sensor or pool is approaching resource limits. Baselines are computed automatically from the retained historical metrics and update as new data arrives.

The baseline system integrates with the historical-metrics spec for data access and with the platform-alert-center spec for surfacing anomaly alerts and capacity warnings. New LiveView pages at `/sensors/:id/baselines` and `/pools/:id/baselines` display baseline information, current deviations, and capacity forecasts.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Health_Baseline**: A statistical profile of a sensor's normal operating range for a specific Metric_Type, computed from historical Metric_Snapshots. Includes mean, standard deviation, and percentile boundaries.
- **Baseline_Window**: The time period of historical data used to compute a Health_Baseline. Default: 48 hours of data within the 72-hour retention window.
- **Anomaly**: A condition where a sensor's current metric value deviates from its Health_Baseline by more than a configurable number of standard deviations (default: 3 sigma) or falls outside the configured percentile boundary.
- **Anomaly_Score**: A numeric value representing how far a current metric deviates from the baseline, expressed as the number of standard deviations from the mean. Higher scores indicate more significant deviations.
- **Capacity_Warning**: A predictive alert generated when a metric's trend indicates it will exceed a critical threshold within a configurable forecast horizon (default: 24 hours).
- **Capacity_Forecast**: A linear trend projection of a metric's future value based on recent historical data, used to predict when a threshold will be breached.
- **Forecast_Horizon**: The time period into the future for which capacity forecasts are computed. Default: 24 hours.
- **Metric_Snapshot**: A single point-in-time sample of a metric, from the historical-metrics spec.
- **Metric_Type**: A string identifier for a metric series, from the historical-metrics spec (e.g., `packets_received_rate`, `drop_percent`, `cpu_percent`, `memory_bytes`, `pcap_disk_used_percent`, `clock_offset_ms`).
- **Metrics_Store**: The Ecto-backed context module from the historical-metrics spec that provides the API for querying historical Metric_Snapshots.
- **Alert_Engine**: The GenServer from the platform-alert-center spec that evaluates alert conditions and fires alerts.
- **Alert_Rule**: A configurable alert definition from the platform-alert-center spec.
- **Sensor_Pool**: A named grouping of Sensor_Pods from the sensor-pool-management spec.
- **Sensor_Pod**: An individual sensor node enrolled in the Config_Manager.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec.
- **Audit_Entry**: An append-only record in the `audit_log` table.

## Requirements

### Requirement 1: Baseline Computation

**User Story:** As a platform operator, I want the system to automatically compute health baselines from historical metrics, so that anomaly detection is calibrated to each sensor's normal operating range.

#### Acceptance Criteria

1. THE Config_Manager SHALL compute a Health_Baseline for each Sensor_Pod and each Metric_Type that has sufficient historical data (at least 4 hours of Metric_Snapshots within the Baseline_Window).
2. THE Health_Baseline SHALL include: mean value, standard deviation, 5th percentile, 95th percentile, minimum observed value, maximum observed value, sample count, and the time range of data used.
3. THE Config_Manager SHALL recompute Health_Baselines periodically at a configurable interval (default: every 1 hour) to incorporate new data.
4. THE Config_Manager SHALL store computed Health_Baselines in a `health_baselines` database table with columns: `id`, `sensor_pod_id` (nullable), `pool_id` (nullable), `metric_type`, `series_key`, `mean`, `stddev`, `p5`, `p95`, `min_value`, `max_value`, `sample_count`, `window_start`, `window_end`, and `computed_at`.
5. WHEN a Sensor_Pod has fewer than 4 hours of historical data for a Metric_Type, THE Config_Manager SHALL skip baseline computation for that metric and display "Insufficient data for baseline" on the baselines page.
6. THE Config_Manager SHALL compute baselines using data from the configured Baseline_Window (default 48 hours), excluding the most recent 10 minutes to avoid including transient spikes in the baseline.
7. THE Config_Manager SHALL create uniqueness constraints that allow at most one current baseline per `(sensor_pod_id, metric_type, series_key)` and at most one current pool baseline per `(pool_id, metric_type, series_key)`.

### Requirement 2: Per-Pool Aggregate Baselines

**User Story:** As a platform operator, I want pool-level baselines that aggregate across all sensors in a pool, so that I can identify when a pool as a whole is behaving abnormally.

#### Acceptance Criteria

1. THE Config_Manager SHALL compute aggregate Health_Baselines per Sensor_Pool by combining the Metric_Snapshots from all Sensor_Pods in the pool within the Baseline_Window.
2. THE pool-level Health_Baseline SHALL include the same statistical fields as per-sensor baselines: mean, standard deviation, percentiles, min, max, and sample count.
3. THE Config_Manager SHALL store pool-level baselines in the same `health_baselines` table with `pool_id` set and `sensor_pod_id` set to NULL.
4. THE Config_Manager SHALL recompute pool-level baselines on the same schedule as per-sensor baselines.
5. WHEN a pool has fewer than 2 sensors with sufficient data, THE Config_Manager SHALL skip pool-level baseline computation and display "Insufficient sensors for pool baseline."

### Requirement 3: Anomaly Detection

**User Story:** As a platform operator, I want to be alerted when a sensor's metrics deviate significantly from its baseline, so that I can investigate unexpected behavior.

#### Acceptance Criteria

1. THE Config_Manager SHALL evaluate each new Metric_Snapshot against the sensor's Health_Baseline for the corresponding Metric_Type.
2. WHEN a metric value differs from the baseline mean by more than a configurable number of standard deviations (default: 3 sigma) or falls outside the configured percentile range, THE Config_Manager SHALL classify the reading as an Anomaly.
3. THE Config_Manager SHALL compute an Anomaly_Score for each metric reading as `abs(value - mean) / stddev`, providing a continuous measure of deviation severity.
4. WHEN an Anomaly is detected, THE Config_Manager SHALL fire a platform alert via the Alert_Engine with Alert_Type `baseline_anomaly`, including the Metric_Type, current value, baseline mean, standard deviation, and Anomaly_Score.
5. THE Config_Manager SHALL support configurable anomaly sensitivity per Metric_Type, allowing operators to set different sigma thresholds for different metrics (e.g., 2 sigma for drop_percent, 3 sigma for cpu_percent).
6. THE Config_Manager SHALL suppress repeated anomaly alerts for the same sensor and Metric_Type within a configurable cooldown period (default: 15 minutes) to avoid alert fatigue.
7. WHEN a metric value returns within the baseline range after an Anomaly, THE Config_Manager SHALL auto-resolve the corresponding platform alert.
8. WHEN a Health_Baseline has `stddev` equal to 0, THE Config_Manager SHALL avoid division by zero by treating values equal to the mean as Anomaly_Score 0 and values different from the mean as anomalous only when the absolute difference exceeds the configured minimum delta for that Metric_Type.

### Requirement 4: Capacity Forecasting

**User Story:** As a platform operator, I want to receive warnings when metric trends indicate a sensor is approaching resource limits, so that I can take proactive action before capacity is exhausted.

#### Acceptance Criteria

1. THE Config_Manager SHALL compute a Capacity_Forecast for capacity-related Metric_Types: `pcap_disk_used_percent`, `cpu_percent`, `memory_bytes`, and `drop_percent`.
2. THE Capacity_Forecast SHALL use linear regression on the most recent 6 hours of Metric_Snapshots to project the metric's value at the end of the Forecast_Horizon (default: 24 hours).
3. WHEN a Capacity_Forecast predicts that a metric will exceed its critical threshold within the Forecast_Horizon, THE Config_Manager SHALL generate a Capacity_Warning.
4. THE critical thresholds for capacity warnings SHALL be: `pcap_disk_used_percent` at 95%, `cpu_percent` at 95%, `memory_bytes` at 90% of total memory when total memory is known, and `drop_percent` at 10%.
5. THE Config_Manager SHALL fire a platform alert via the Alert_Engine with Alert_Type `capacity_warning` when a Capacity_Warning is generated, including the Metric_Type, current value, projected value, projected time to threshold breach, and the critical threshold.
6. THE Config_Manager SHALL recompute Capacity_Forecasts at a configurable interval (default: every 15 minutes).
7. WHEN a Capacity_Forecast no longer predicts a threshold breach (e.g., the trend reversed), THE Config_Manager SHALL auto-resolve the corresponding capacity warning alert.
8. THE Config_Manager SHALL display the estimated time to threshold breach on the baselines page when a Capacity_Warning is active.
9. THE Config_Manager SHALL skip Capacity_Forecast generation for a metric series with fewer than a configurable minimum number of samples in the forecast window (default: 12 samples) and display "Insufficient data for forecast" instead of projecting from sparse data.

### Requirement 5: Per-Sensor Baselines Page

**User Story:** As a platform operator, I want to view baseline information and anomaly status for a specific sensor, so that I can understand its normal operating range and current deviations.

#### Acceptance Criteria

1. THE Config_Manager SHALL serve a LiveView page at `/sensors/:id/baselines` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display a summary card for each Metric_Type showing: baseline mean, standard deviation, 5th/95th percentile range, current value, Anomaly_Score, and a visual indicator (normal/warning/anomaly).
3. WHEN a Metric_Type has an active Anomaly, THE Config_Manager SHALL highlight the corresponding summary card with a warning or critical visual style.
4. WHEN a Metric_Type has an active Capacity_Warning, THE Config_Manager SHALL display the projected time to threshold breach and the forecasted value.
5. THE Config_Manager SHALL display a "Baseline not available" placeholder for Metric_Types with insufficient historical data.
6. THE Config_Manager SHALL update anomaly status and capacity warnings in real time via PubSub as new Metric_Snapshots arrive.
7. THE Config_Manager SHALL add a "Baselines" navigation link on the sensor detail page that links to `/sensors/:id/baselines`.

### Requirement 6: Per-Pool Baselines Page

**User Story:** As a platform operator, I want to view pool-level baselines and identify sensors that deviate from the pool norm, so that I can spot outliers across the fleet.

#### Acceptance Criteria

1. THE Config_Manager SHALL serve a LiveView page at `/pools/:id/baselines` accessible to all authenticated Users with the `sensors:view` Permission.
2. THE Config_Manager SHALL display pool-level aggregate baselines for each Metric_Type alongside per-sensor deviation summaries.
3. THE Config_Manager SHALL highlight sensors whose current metrics deviate significantly from the pool baseline, identifying them as outliers.
4. THE Config_Manager SHALL display a per-sensor comparison table showing each sensor's current value, its individual baseline mean, the pool baseline mean, and the deviation from pool baseline.
5. THE Config_Manager SHALL add a "Baselines" navigation link on the pool detail page that links to `/pools/:id/baselines`.

### Requirement 7: Alert Integration

**User Story:** As a platform operator, I want baseline anomalies and capacity warnings to appear in the Platform Alert Center, so that all platform health conditions are visible in one place.

#### Acceptance Criteria

1. THE Config_Manager SHALL register `baseline_anomaly` and `capacity_warning` as Alert_Types in the Alert_Engine, alongside the existing alert types from the platform-alert-center spec.
2. THE Config_Manager SHALL create default Alert_Rules for `baseline_anomaly` (severity `warning`) and `capacity_warning` (severity `warning`) during initial setup.
3. THE Config_Manager SHALL allow operators to configure the severity and enabled status of baseline anomaly and capacity warning alert rules through the existing `/alerts/rules` page.
4. THE Config_Manager SHALL include baseline context in alert details: baseline mean, standard deviation, current value, Anomaly_Score (for anomalies), and projected time to breach (for capacity warnings).
5. THE Config_Manager SHALL auto-resolve baseline anomaly alerts when the metric returns within the baseline range and auto-resolve capacity warning alerts when the forecast no longer predicts a threshold breach.

### Requirement 8: Configuration

**User Story:** As a platform administrator, I want baseline and capacity warning behavior to be configurable, so that I can tune sensitivity for my deployment.

#### Acceptance Criteria

1. THE Config_Manager SHALL support the following application environment configuration keys under `:config_manager`: `:baseline_window_hours` (default 48), `:baseline_recompute_interval_ms` (default 3_600_000), `:anomaly_default_sigma` (default 3.0), `:anomaly_cooldown_minutes` (default 15), `:anomaly_min_delta_by_metric` (default empty map), `:capacity_forecast_horizon_hours` (default 24), `:capacity_forecast_interval_ms` (default 900_000).
2. THE Config_Manager SHALL allow per-Metric_Type anomaly sigma thresholds to be configured via the baselines page or application configuration.
3. IF a configuration value is missing or invalid, THEN THE Config_Manager SHALL fall back to the documented default value and log a warning.

### Requirement 9: Deferred Capabilities

**User Story:** As a product owner, I want deferred baseline capabilities documented, so that the team knows what is planned for future enhancements.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement time-of-day or day-of-week baseline profiles in this feature. Baselines are computed as a single statistical profile over the Baseline_Window. Time-aware baselines are deferred to a future enhancement.
2. THE Config_Manager SHALL NOT implement machine learning-based anomaly detection in this feature. Anomaly detection uses statistical deviation (sigma-based) only. ML-based detection is deferred.
3. THE Config_Manager SHALL NOT implement capacity planning recommendations (e.g., "add more sensors to this pool") in this feature. Capacity warnings indicate approaching limits but do not prescribe remediation. Recommendations are deferred.
4. THE Config_Manager SHALL NOT implement baseline export or comparison across time periods in this feature. These are deferred to a future analytics enhancement.
