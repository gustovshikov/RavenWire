# Requirements Document: Live Data-Flow Visualization

## Introduction

The RavenWire Config Manager dashboard and sensor detail page currently display health data in tabular form: container states, capture consumer counters, storage percentages, and clock stats. While this answers "what is the current value?" it does not answer "how does data flow through the sensor pipeline, and where is it breaking?" Operators must mentally reconstruct the pipeline topology — network interface → AF_PACKET ring → analysis tools (Zeek, Suricata) → PCAP ring → Vector → forwarding sinks — and cross-reference multiple table rows to locate a degraded segment.

This feature adds a live data-flow visualization that renders the sensor pipeline as a visual flow map with throughput annotations and health-state indicators on each segment. The visualization is available per-sensor at a dedicated route linked from the sensor detail page and per-pool at a dedicated route linked from the pool detail page. Each pipeline segment displays its current state using color-coded and icon/text-annotated indicators so that operators can instantly see where data is flowing, where it is degraded, where it has stopped, and where telemetry is not available. The visualization updates in real time via PubSub as new HealthReport data arrives.

The current `HealthReport` protobuf includes container health, capture stats (per-consumer packets, drops, NIC/fallback throughput, app-native Zeek/Suricata process input telemetry when available, and PCAP ring-writer counters), Vector ingress record rates, storage stats, clock stats, and limited system stats (`capture_interface`, `nic_driver`, `af_packet_available`). It does **not** include forwarding data (Vector sink status, buffer usage, destination health), physical link/carrier or SPAN source status, or a manager-visible active PCAP flush/carve signal. The visualization handles missing telemetry gracefully, rendering "data not available" placeholders for segments without upstream telemetry rather than inferring health from absence.

## Current Implementation Context

This feature starts after the validated single-site pilot MVP plus Platform Alert Center, Historical Metrics, and Health Baselines. It must build on the current Phoenix LiveView application and existing health registry behavior rather than defining a new telemetry plane.

- `ConfigManager.Health.Registry.pod_topic/1` is the source of truth for pod-scoped PubSub topics. The current sensor detail page derives the registry key from `SensorPod.name` and subscribes through `Registry.pod_topic(health_key)`.
- Global health updates continue to use the existing `"sensor_pods"` topic.
- Forwarding sink configuration exists, but forwarding runtime telemetry is still unavailable in `HealthReport`; forwarding runtime state must remain `no_data` until the protobuf and sensor agent expose real sink telemetry.
- Current HealthReport data exposes PCAP ring-writer counters in capture consumer stats, but it does not expose a manager-visible "active PCAP flush" signal for Alert_Driven_Mode; the PCAP branch must render as armed/idle unless future telemetry explicitly reports active flushing.
- Current HealthReport system stats expose capture-interface name, NIC driver, and AF_PACKET availability. They do not prove physical link, carrier, or mirror/SPAN source readiness.
- Historical Metrics and Health Baselines are implemented, but this feature should derive live visualization state from the latest HealthReport/Registry data, sensor identity, pool membership, and forwarding configuration only where configuration is useful for labels/topology.
- This feature is browser/UI focused and SHALL NOT add new `/api/v1` endpoints.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Sensor_Pod**: A deployed sensor instance with an identity record in the `sensor_pods` database table and real-time health state in the Health_Registry.
- **Health_Registry**: The in-memory ETS-backed GenServer (`ConfigManager.Health.Registry`) that stores the latest `HealthReport` for each connected Sensor_Pod.
- **HealthReport**: A protobuf message streamed from the Sensor_Agent to the Config_Manager via gRPC, containing container health, capture stats, app-native process telemetry when available, Vector ingress record rates, storage stats, clock stats, and limited system stats.
- **Pipeline_Visualization**: The visual flow map component that renders the sensor data pipeline as a directed graph of connected segments with throughput annotations and health indicators.
- **Pipeline_Segment**: A single node in the Pipeline_Visualization representing one stage of the data pipeline (for example, AF_PACKET, Zeek, Suricata, PCAP Ring, Vector, or the aggregate Forwarding Sinks node).
- **Segment_State**: The health state of a Pipeline_Segment, one of: healthy, degraded, failed, disabled, pending_reload, or no_data.
- **Segment_Connector**: A directed edge between two Pipeline_Segments in the Pipeline_Visualization, annotated with throughput or record rate when available.
- **Connector_Flow_State**: The visual flow state of a Segment_Connector, one of: flowing, degraded, idle, stopped, or unknown. Connector_Flow_State is derived from source segment state, target segment state, staleness, capture mode, and structured throughput telemetry.
- **Speed_Tier**: A coarse animation speed tier derived from numeric throughput telemetry, one of: gbps, mbps, kbps, zero, or unknown.
- **Pipeline_Topology**: The ordered graph of Pipeline_Segments and Segment_Connectors that represents the data flow through a sensor. The canonical topology is: NIC/capture interface → AF_PACKET → [Zeek, Suricata, PCAP Ring] → Vector → [Forwarding Sinks].
- **Aggregate_Pipeline**: A pool-level Pipeline_Visualization that summarizes the pipeline health of all member sensors, showing per-segment counts of healthy, degraded, failed, disabled, pending_reload, and no_data members.
- **Sensor_Pipeline_Page**: The LiveView page at `/sensors/:id/pipeline/graph` that displays the per-sensor Pipeline_Visualization. The legacy `/sensors/:id/pipeline` route is retained as an authenticated redirect to this page.
- **Pool_Pipeline_Page**: The LiveView page at `/pools/:id/pipeline` that displays the Aggregate_Pipeline for a sensor pool.
- **Throughput_Annotation**: A human-readable throughput or record rate label displayed on a Segment_Connector (for example, "8.2 Gbps", "12k eps", "41 alerts/hr"). It is display-only; behavior such as animation speed SHALL use structured numeric throughput fields, not parsed display text.
- **Missing_Telemetry**: A condition where the HealthReport does not contain data for a Pipeline_Segment or segment annotation, requiring the visualization to display an explicit "data not available" indicator rather than inferring health. Missing segment health telemetry assigns `no_data`; missing annotation-only telemetry, such as PCAP storage, assigns a `no_data` annotation or badge without overriding container-derived segment health.
- **Stale_HealthReport**: A HealthReport whose timestamp is older than the configured freshness threshold (default 60 seconds).
- **Visual_State_Palette**: The set of visual indicators mapping Segment_State to color, icon, and text label: green/checkmark for healthy, yellow/warning-triangle for degraded, red/x-circle for failed, gray/circle-slash for disabled, blue/refresh for pending_reload, and gray-dashed/question-circle for no_data.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that compares the current user's role permissions against the permission required by a route or action.
- **PubSub**: The Phoenix PubSub system used for real-time health updates, with pod-scoped topics returned by `ConfigManager.Health.Registry.pod_topic/1` and fleet-wide updates on `"sensor_pods"`.

## Requirements

### Requirement 1: Per-Sensor Pipeline Visualization Route

**User Story:** As a sensor operator, I want to view the data-flow pipeline of a single sensor as a visual flow map, so that I can instantly see where data is flowing and where it is degraded without reading tables of numbers.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Sensor_Pipeline_Page at `/sensors/:id/pipeline/graph`, retain `/sensors/:id/pipeline` as an authenticated compatibility redirect, and link to the graph page from the sensor detail page at `/sensors/:id`.
2. WHEN an authenticated user navigates to the Sensor_Pipeline_Page for an existing Sensor_Pod in any enrollment state, THE Sensor_Pipeline_Page SHALL render the Pipeline_Visualization with all available health data and identity status for that Sensor_Pod.
3. WHEN an authenticated user navigates to the Sensor_Pipeline_Page for a non-existent Sensor_Pod identifier, THE Config_Manager SHALL display a 404 Not Found page.
4. THE Sensor_Pipeline_Page SHALL be accessible to all authenticated users with the `sensors:view` permission for read-only viewing.
5. THE Sensor_Pipeline_Page SHALL include navigation links back to the sensor detail page and to the parent pool pipeline page when the sensor belongs to a pool.

### Requirement 2: Pipeline Topology Layout

**User Story:** As a sensor operator, I want the pipeline visualization to show the canonical RavenWire data-flow topology, so that I can understand the path data takes from network capture to forwarding destination.

#### Acceptance Criteria

1. THE Pipeline_Visualization SHALL render the following Pipeline_Segments in the canonical Pipeline_Topology order: NIC/capture interface, AF_PACKET ring buffer, Zeek, Suricata, PCAP Ring (pcap_ring_writer), Vector, and Forwarding Sinks.
2. THE Pipeline_Visualization SHALL render Segment_Connectors as directed edges showing the data flow direction from source segment to destination segment.
3. THE Pipeline_Visualization SHALL render the analysis stage (Zeek, Suricata, PCAP Ring) as parallel branches from the AF_PACKET segment, converging at the Vector segment.
4. WHEN the HealthReport includes additional capture consumers beyond Zeek, Suricata, and pcap_ring_writer, THE Pipeline_Visualization SHALL render those consumers as additional parallel branches in the analysis stage with deterministic segment IDs in the form `capture_consumer:<sanitized-name>`, stable sorting by normalized consumer name, and labels derived from the original consumer name.
5. THE Pipeline_Visualization SHALL render exactly one stable Forwarding Sinks terminal segment after Vector in v1, with the canonical ID `forwarding_sinks`. Configured sink names, enabled counts, disabled counts, and sink labels SHALL render as metrics, badges, or tooltip content on that single segment. Enabled sinks' runtime state SHALL remain `no_data`; explicitly disabled sink configurations SHALL remain configuration detail within the aggregate segment and SHALL NOT add sink nodes.
6. THE Pipeline_Visualization SHALL maintain a consistent left-to-right or top-to-bottom layout direction across all sensor views.
7. THE Pipeline_Visualization SHALL derive the NIC/capture-interface segment only from current system telemetry (`capture_interface`, `nic_driver`, `af_packet_available`) and SHALL NOT infer physical link, carrier, or mirror/SPAN source readiness from those fields.
8. THE Pipeline_Visualization SHALL visually represent live data movement by rendering a static connector base path plus an optional animated overlay of discrete graphical elements (for example, flowing dashes or dots) along the SVG paths of the Segment_Connectors.
9. THE visual flow treatment for the PCAP Ring connector SHALL be telemetry-safe: in Full_PCAP_Mode it MAY show PCAP branch flow only when current PCAP branch telemetry is present and the target segment is healthy; capture mode alone SHALL NOT create heavy flow. In Alert_Driven_Mode it SHALL show an armed or idle static/subtle path unless current telemetry explicitly proves active flushing.
10. THE Pipeline_Visualization SHALL use a responsive layout: a left-to-right graph on wide screens and a top-to-bottom graph or table-first fallback on narrow screens, without overlapping segment labels, connector labels, badges, or tooltips.

### Requirement 3: Segment Health State Indicators

**User Story:** As a sensor operator, I want each pipeline segment to show its health state using distinct visual indicators, so that I can identify problems at a glance without reading detailed metrics.

#### Acceptance Criteria

1. THE Pipeline_Visualization SHALL assign each Pipeline_Segment exactly one Segment_State from the set: healthy, degraded, failed, disabled, pending_reload, or no_data.
2. THE Pipeline_Visualization SHALL render each Segment_State using the Visual_State_Palette:
   - Healthy: green background or border with a checkmark icon and "Healthy" text label.
   - Degraded: yellow background or border with a warning-triangle icon and "Degraded" text label.
   - Failed: red background or border with an x-circle icon and "Failed" text label.
   - Disabled: gray background or border with a circle-slash icon and "Disabled" text label.
   - Pending Reload: blue background or border with a refresh icon and "Pending Reload" text label.
   - No Data: gray dashed border with a question-circle icon and "No Data" text label.
3. THE Pipeline_Visualization SHALL NOT rely on color alone to communicate Segment_State; each state SHALL be distinguishable by icon shape and text label in addition to color.
4. WHEN a Pipeline_Segment has Missing_Telemetry, THE Pipeline_Visualization SHALL assign the `no_data` Segment_State, render that segment with a distinct "No Data" indicator using a dashed border or outline style, and SHALL NOT infer the segment as healthy or failed.
5. THE Pipeline_Visualization SHALL assign each Segment_Connector exactly one Connector_Flow_State:
   - Flowing: source and target are capable of passing data, telemetry is current enough to trust, and throughput is present or expected.
   - Degraded: source or target is degraded, stale, or drop-pressure affected.
   - Idle: the path is valid but throughput is zero, or Alert_Driven_Mode PCAP is armed without active flush telemetry.
   - Stopped: source or target is failed or disabled.
   - Unknown: required telemetry is missing or either side is `no_data`.
6. THE Pipeline_Visualization SHALL derive Connector_Flow_State from source segment state, target segment state, staleness, capture mode, and structured throughput data; it SHALL NOT animate `no_data`, failed, disabled, or stale-unknown paths as healthy flow.

### Requirement 4: Segment State Derivation Rules

**User Story:** As a sensor operator, I want the pipeline segment states to be derived from actual telemetry data using clear rules, so that the visualization accurately reflects the real state of each component.

#### Acceptance Criteria

1. THE Config_Manager SHALL derive the AF_PACKET segment state as follows:
   - Healthy: WHEN at least one capture consumer is present and no consumer has `drop_percent > 5.0` and no consumer has `bpf_restart_pending == true`.
   - Degraded: WHEN any capture consumer has `drop_percent > 5.0`.
   - Failed: WHEN capture telemetry explicitly reports an unrecoverable capture failure in a future HealthReport schema.
   - Pending Reload: WHEN any capture consumer has `bpf_restart_pending == true`.
   - No Data: WHEN no capture data is present in the HealthReport.
2. THE Config_Manager SHALL derive each analysis-tool segment state (Zeek, Suricata, PCAP Ring) from the corresponding container health in the HealthReport:
   - Healthy: WHEN the container state is "running" and no degradation conditions apply.
   - Degraded: WHEN the container state is "running" and CPU exceeds 90 percent (when CPU data is available), the corresponding capture consumer has `drop_percent > 5.0`, the container state is "restarting", or the container state is an unknown non-running value.
   - Failed: WHEN the container state is "error" or "stopped" unexpectedly.
   - Disabled: WHEN the component is configured as intentionally disabled.
   - No Data: WHEN the container is expected but not present in the HealthReport and there is no configuration data proving that it is intentionally disabled.
3. THE Config_Manager SHALL derive the Vector segment state from the Vector container health:
   - Healthy: WHEN the Vector container state is "running".
   - Degraded: WHEN the Vector container state is "running" but forwarding buffer usage exceeds 85 percent (when forwarding data is available).
   - Failed: WHEN the Vector container state is "error" or "stopped".
   - No Data: WHEN the Vector container is not present in the HealthReport.
4. THE Config_Manager SHALL derive the aggregate Forwarding Sinks segment state from forwarding telemetry when available:
   - Healthy: reserved for future telemetry when all enabled sinks report connected or healthy status.
   - Degraded: reserved for future telemetry when any enabled sink reports elevated latency or partial delivery failures.
   - Failed: reserved for future telemetry when any enabled sink reports disconnected or unreachable status.
   - Disabled: WHEN all configured sinks are explicitly disabled; this is configuration state, not runtime delivery health.
   - No Data: WHEN no sink configuration is available, or when at least one enabled sink exists and no forwarding runtime data is available in the HealthReport.
5. WHEN the HealthReport is a Stale_HealthReport (timestamp older than the configured freshness threshold), THE Pipeline_Visualization SHALL render all segments derived from that report with a stale-data overlay or badge indicating the age of the data.
6. THE Config_Manager SHALL NOT derive a failed state from zero throughput or zero packet counters alone, because a live sensor may have no observed traffic during the reporting interval.
7. THE Config_Manager SHALL derive the NIC/capture-interface segment from limited system telemetry:
   - Healthy: WHEN `system.capture_interface` is present and `system.af_packet_available == true`.
   - Degraded: WHEN `system.capture_interface` is present and `system.af_packet_available == false`.
   - Failed: reserved for future explicit physical link, carrier, or capture-interface failure telemetry.
   - No Data: WHEN system telemetry is absent or `system.capture_interface` is blank.
8. THE Config_Manager SHALL normalize expected container names using the aliases already accepted by the sensor detail page, including `systemd-*` and hyphenated aliases for Zeek, Suricata, Vector, and pcap_ring_writer.
9. THE Config_Manager SHALL treat nil, zero, negative, or invalid HealthReport timestamps as stale with unknown age; future timestamps SHALL be clamped to an age of 0 seconds for display and derivation.

### Requirement 5: Throughput and Rate Annotations

**User Story:** As a sensor operator, I want to see throughput numbers and record rates on each pipeline connection, so that I can quantify the data volume at each stage and identify bottlenecks.

#### Acceptance Criteria

1. THE Pipeline_Visualization SHALL display a Throughput_Annotation on the Segment_Connector between the NIC/capture-interface segment and AF_PACKET showing a deduplicated capture-ingress throughput estimate in human-readable units (bps, Kbps, Mbps, Gbps).
2. THE Pipeline_Visualization SHALL display a Throughput_Annotation on each Segment_Connector from AF_PACKET to an analysis tool showing app-native process throughput for Zeek and Suricata when `process_telemetry_source` is present, otherwise the per-consumer NIC/fallback throughput from capture stats.
3. WHEN capture consumer stats include `packets_received`, THE Pipeline_Visualization SHALL display the packet count as a secondary annotation. THE Pipeline_Visualization SHALL display packet rate only when a derived rate is available from Health_Registry deltas or a future HealthReport field.
4. THE Pipeline_Visualization SHALL render Segment_Connectors from Zeek, Suricata, PCAP Ring, and additional capture consumers to Vector using Vector ingress record-rate telemetry (`rec/s`) when `HealthReport.vector.input_records_per_sec` includes the source segment ID. Missing Vector ingress telemetry SHALL render those connectors with "—" and `unknown` flow state.
5. WHEN forwarding telemetry is available in a future HealthReport schema, THE Pipeline_Visualization SHALL display a Throughput_Annotation on the Segment_Connector from Vector to Forwarding Sinks showing the aggregate forwarding rate.
6. THE Pipeline_Visualization SHALL format all throughput values using a shared or equivalent pure formatter consistent with the dashboard and sensor detail page (bps, Kbps, Mbps, Gbps for throughput; KB, MB, GB, TB for byte values), without making core derivation code depend on web-layer modules.
7. WHEN throughput data is not available for a Segment_Connector, THE Pipeline_Visualization SHALL display a dash character ("—") as the Throughput_Annotation rather than displaying zero or omitting the annotation.
8. WHEN throughput is available and equal to zero, THE Pipeline_Visualization SHALL display "0 bps" and SHALL NOT treat the zero value as Missing_Telemetry.
9. WHEN a Segment_Connector has numeric throughput telemetry, THE Pipeline_Visualization SHALL expose `throughput_bps`, `throughput_label`, `flow_state`, and `speed_tier` as structured connector fields.
10. WHEN a Segment_Connector has `flow_state = flowing`, THE Pipeline_Visualization SHALL scale the baseline CSS animation speed from `speed_tier`, providing distinct visual speed tiers for gbps (fastest), mbps (medium), and kbps/bps (slowest).
11. THE Pipeline_Visualization SHALL derive `speed_tier` from numeric `throughput_bps`; it SHALL NOT parse Throughput_Annotation display text to determine behavior.
12. WHEN interface-backed capture consumers such as Zeek and Suricata do not expose app-native process telemetry, THE Sensor_Agent SHALL keep `throughput_bps` populated from the configured capture interface `rx_bytes` delta instead of reporting zero solely because `bytes_written` is unavailable.
13. WHEN Zeek `stats.log` or Suricata EVE `stats` telemetry is available, THE Sensor_Agent SHALL populate `process_throughput_bps`, `process_packets_per_sec`, `process_drop_percent`, and `process_telemetry_source`; Config Manager SHALL prefer those process fields for Zeek/Suricata branch connector labels and analysis-tool degradation.
14. THE Pipeline_Visualization SHALL NOT sum parallel AF_PACKET branch throughput values into the NIC-to-AF_PACKET connector when those values can represent fan-out copies of the same capture interface stream. Until HealthReport includes explicit per-interface ingress telemetry, THE Pipeline_Visualization SHALL use the largest numeric capture-consumer throughput as the deduplicated ingress estimate and SHALL keep per-consumer values on the branch connectors.

### Requirement 6: PCAP Ring Storage Annotation

**User Story:** As a sensor operator, I want to see the PCAP ring buffer usage directly on the pipeline visualization, so that I can spot storage pressure without navigating to a separate section.

#### Acceptance Criteria

1. THE Pipeline_Visualization SHALL display the PCAP Ring segment with storage usage information: used percentage and ring size from the HealthReport storage stats.
2. WHEN the storage used percentage exceeds 85 percent and is less than or equal to 95 percent, THE PCAP Ring segment SHALL include a warning indicator in addition to its container-derived Segment_State.
3. WHEN the storage used percentage exceeds 95 percent, THE PCAP Ring segment SHALL include a critical indicator in addition to its container-derived Segment_State.
4. WHEN storage stats are not available in the HealthReport, THE PCAP Ring segment SHALL display "storage data not available" as a `no_data` storage annotation or badge without overriding the PCAP Ring Segment_State derived from container and capture telemetry.
5. WHEN `pcap_ring_writer` capture consumer stats include PCAP-specific counters such as `packets_written`, `bytes_written`, `wrap_count`, `socket_drops`, or `overwrite_risk`, THE PCAP Ring segment SHALL expose those values in metrics and tooltip content without treating them as active flush/carve telemetry.

### Requirement 7: Per-Pool Aggregate Pipeline Visualization

**User Story:** As a fleet operator, I want to see an aggregate pipeline view for a sensor pool, so that I can quickly assess the overall health of all sensors in the pool without checking each one individually.

#### Acceptance Criteria

1. THE Config_Manager SHALL expose a Pool_Pipeline_Page at `/pools/:id/pipeline` for each sensor pool.
2. THE Pool_Pipeline_Page SHALL be accessible to all authenticated users with the `sensors:view` permission.
3. THE Aggregate_Pipeline SHALL render the same canonical Pipeline_Topology as the per-sensor view, but each Pipeline_Segment SHALL display a summary count of member sensors in each Segment_State (for example, "8 healthy, 1 degraded, 1 failed").
4. THE Aggregate_Pipeline SHALL derive per-segment state counts by evaluating the segment state derivation rules (Requirement 4) for each member sensor's HealthReport independently and then counting the results.
5. THE Aggregate_Pipeline SHALL assign an overall segment state to each Pipeline_Segment based on the worst reporting member state: failed if any reporting member is failed, degraded if any reporting member is degraded (and none failed), pending_reload if any reporting member is pending reload (and none failed or degraded), no_data if no members have telemetry for that segment, healthy if all reporting members are healthy, and disabled if all members are disabled. If some members are no_data and reporting members are otherwise healthy, the overall state SHALL remain healthy with a visible no_data count badge.
6. WHEN a member sensor has no HealthReport in the Health_Registry, THE Aggregate_Pipeline SHALL count that sensor as "no data" for all segments and SHALL display the no-data count separately from the state counts.
7. THE Pool_Pipeline_Page SHALL display the total number of member sensors and the number currently reporting health data.
8. THE Pool_Pipeline_Page SHALL include navigation links to each member sensor's Sensor_Pipeline_Page.
9. WHEN the pool has zero member sensors, THE Pool_Pipeline_Page SHALL display an empty state message indicating that no sensors are assigned to the pool.
10. WHEN the requested pool ID does not exist, THE Config_Manager SHALL display a 404 Not Found page.

### Requirement 8: Real-Time Updates

**User Story:** As a sensor operator, I want the pipeline visualization to update in real time as new health data arrives, so that I can watch the pipeline respond to changes without refreshing the page.

#### Acceptance Criteria

1. WHEN the Sensor_Pipeline_Page is mounted and the LiveView WebSocket is connected, THE Sensor_Pipeline_Page SHALL subscribe to PubSub updates for the displayed Sensor_Pod using `ConfigManager.Health.Registry.pod_topic(health_key)`, where `health_key` is the same registry key used by the existing sensor detail page.
2. WHEN a new HealthReport arrives for the displayed Sensor_Pod, THE Sensor_Pipeline_Page SHALL re-derive all segment states and throughput annotations and update the Pipeline_Visualization within 2 seconds.
3. WHEN the displayed Sensor_Pod transitions to or from a degraded state via PubSub degradation events, THE Sensor_Pipeline_Page SHALL update the affected segment indicators without requiring a page reload.
4. THE Sensor_Pipeline_Page SHALL display the timestamp of the most recent HealthReport to indicate data freshness.
5. WHEN the Pool_Pipeline_Page is mounted and the LiveView WebSocket is connected, THE Pool_Pipeline_Page SHALL subscribe to PubSub updates for all member sensors through `Registry.pod_topic(member_health_key)` and to the pool topic (`"pool:#{pool_id}"`).
6. WHEN a new HealthReport arrives for any member sensor of the displayed pool, THE Pool_Pipeline_Page SHALL re-derive the aggregate segment state counts and update the Aggregate_Pipeline.
7. WHEN a sensor is added to or removed from the pool via PubSub pool membership events, THE Pool_Pipeline_Page SHALL update the member count and re-derive the aggregate view.
8. THE Sensor_Pipeline_Page SHALL ignore PubSub updates for Sensor_Pods other than the displayed one.
9. THE Pool_Pipeline_Page SHALL debounce or coalesce rapid health updates so that high-frequency health streams do not cause unbounded LiveView re-renders.
10. WHEN the Pool_Pipeline_Page receives a PubSub update for a sensor that is not currently a member of the displayed pool, THE Pool_Pipeline_Page SHALL ignore that update.
11. WHEN forwarding configuration changes for the displayed sensor's pool or displayed pool, THE relevant Pipeline_Page SHALL re-read forwarding configuration and update configured sink labels without inferring runtime sink health.

### Requirement 9: Graceful Handling of Missing Telemetry

**User Story:** As a sensor operator, I want the pipeline visualization to clearly indicate when telemetry data is missing for a segment, so that I do not mistake missing data for a healthy or failed state.

#### Acceptance Criteria

1. WHEN the HealthReport does not include forwarding data (Vector sink status, buffer usage, destination health), THE Pipeline_Visualization SHALL render the Vector-to-Forwarding Sinks connector and the single Forwarding Sinks segment with a "Forwarding data not available" label and the `no_data` visual indicator when any enabled sink exists. Disabled sink configurations SHALL render only as configuration details, counts, badges, or tooltip rows unless all configured sinks are disabled.
2. WHEN the HealthReport does not include capture stats, THE Pipeline_Visualization SHALL render the AF_PACKET segment and analysis-tool connectors with a "Capture data not available" label and the `no_data` visual indicator.
3. WHEN the HealthReport does not include storage stats, THE PCAP Ring segment SHALL display "Storage data not available" as a storage annotation or badge, and SHALL keep its Segment_State derived from container and capture telemetry.
4. WHEN the Health_Registry has no HealthReport for the displayed Sensor_Pod, THE Sensor_Pipeline_Page SHALL render the Pipeline_Topology with all health-derived segments in the `no_data` state and display a prominent banner indicating that the sensor is not currently reporting health data. The aggregate Forwarding Sinks segment MAY still display safe forwarding configuration labels, counts, and disabled configuration detail without implying runtime health.
5. THE Pipeline_Visualization SHALL clearly distinguish the `no_data` visual indicator from the disabled and failed states so that operators understand the difference between "no data received" and "component is down."
6. THE Pipeline_Visualization SHALL preserve explicit zero values, such as `throughput_bps = 0`, as real telemetry rather than treating them as Missing_Telemetry.

### Requirement 10: Accessibility

**User Story:** As an operator using assistive technology, I want the pipeline visualization to be accessible without relying solely on color, so that I can understand the pipeline state using a screen reader or in high-contrast mode.

#### Acceptance Criteria

1. THE Pipeline_Visualization SHALL provide an accessible text description (via `aria-label` or equivalent) for each Pipeline_Segment that includes the segment name, current Segment_State, and key metric values.
2. THE Pipeline_Visualization SHALL provide an accessible text description for each Segment_Connector that includes the source segment, destination segment, and Throughput_Annotation value.
3. THE Pipeline_Visualization SHALL NOT rely on color alone to communicate any state; every Segment_State SHALL be distinguishable by icon shape and text label.
4. THE Pipeline_Visualization SHALL be navigable via keyboard, allowing focus to move between Pipeline_Segments and Segment_Connectors.
5. THE Pipeline_Visualization SHALL include a screen-reader-accessible summary table as an alternative representation of the pipeline state, listing each segment with its state and metrics in tabular form. On narrow screens, the same summary data MAY be visibly promoted as the table-first fallback.
6. BECAUSE the Pipeline_Visualization uses SVG connectors for visual layout, THE Config_Manager SHALL provide equivalent semantic HTML fallback content for screen readers.
7. THE Pipeline_Visualization SHALL preserve usable contrast in high-contrast mode and SHALL meet WCAG AA contrast targets for text and meaningful icon outlines.

### Requirement 11: Navigation Integration

**User Story:** As a sensor operator, I want to navigate between the pipeline visualization and related pages, so that I can drill into details or see the broader fleet context.

#### Acceptance Criteria

1. THE sensor detail page SHALL include a link or tab to the Sensor_Pipeline_Page for the displayed sensor.
2. THE pool detail page SHALL include a link or tab to the Pool_Pipeline_Page for the displayed pool.
3. THE Sensor_Pipeline_Page SHALL include a link to the full sensor detail page for the displayed sensor.
4. THE Pool_Pipeline_Page SHALL include links to each member sensor's pipeline view.
5. WHEN a Pipeline_Segment on the Sensor_Pipeline_Page is clicked or activated, THE Config_Manager SHALL navigate to or scroll to the corresponding detail section on the sensor detail page (for example, clicking the Zeek segment navigates to the container section filtered to Zeek).
6. THE Pool_Pipeline_Page SHALL include a link back to the pool detail page.
7. THE route map and RBAC policy declarations SHALL include `/sensors/:id/pipeline`, `/sensors/:id/pipeline/graph`, and `/pools/:id/pipeline` with the `sensors:view` permission.

### Requirement 12: Segment Detail Tooltip or Popover

**User Story:** As a sensor operator, I want to see detailed metrics for a pipeline segment without leaving the visualization, so that I can quickly inspect a segment's health data.

#### Acceptance Criteria

1. WHEN an operator hovers over or focuses on a Pipeline_Segment, THE Pipeline_Visualization SHALL display a tooltip or popover showing the detailed metrics for that segment.
2. THE tooltip for an analysis-tool segment (Zeek, Suricata) SHALL include: container state, uptime, CPU percentage, memory usage, packets received, packets dropped, effective drop percentage, throughput, and telemetry source (`zeek stats.log`, `suricata eve stats`, or `NIC fallback`).
3. THE tooltip for the AF_PACKET segment SHALL include: aggregate throughput, per-consumer packet counts, per-consumer drop percentages, BPF restart pending status, and process telemetry source/rates when present.
4. THE tooltip for the PCAP Ring segment SHALL include: container state, storage path, total bytes, used bytes, available bytes, used percentage, and PCAP ring-writer counters (`packets_written`, `bytes_written`, `wrap_count`, `socket_drops`, `overwrite_risk`) when telemetry is available.
5. THE tooltip for the Vector segment SHALL include: container state, uptime, CPU percentage, memory usage, and forwarding buffer usage when available.
6. THE tooltip for the Forwarding Sinks segment SHALL include configured sink count, enabled count, disabled count, sink labels, destination labels when safe, future connection status, latency, and error count when available; or "Forwarding data not available" when runtime telemetry is missing. It SHALL NOT expose raw sink credentials.
7. THE tooltip SHALL be dismissible via Escape key or by moving focus away from the segment.
8. THE tooltip content SHALL be accessible to screen readers.
9. THE tooltip SHALL avoid exposing raw internal errors, secrets, bearer tokens, certificates, or full sink credentials.

### Requirement 13: Stale and Offline Sensor Handling

**User Story:** As a sensor operator, I want the pipeline visualization to clearly indicate when a sensor is offline or has stale data, so that I do not mistake old data for current state.

#### Acceptance Criteria

1. WHEN the most recent HealthReport timestamp for the displayed Sensor_Pod is older than the configured freshness threshold (default 60 seconds), THE Sensor_Pipeline_Page SHALL display a stale-data warning banner indicating the time since the last report.
2. WHEN the HealthReport is stale, THE Pipeline_Visualization SHALL render all health-derived segments with a visual stale-data overlay (for example, reduced opacity or a clock badge) in addition to their derived Segment_State.
3. WHEN the Health_Registry has no HealthReport for the displayed Sensor_Pod, THE Sensor_Pipeline_Page SHALL render the Pipeline_Topology skeleton with all health-derived segments in the `no_data` state and a banner indicating the sensor is not reporting. The aggregate Forwarding Sinks segment MAY still display forwarding configuration labels, counts, and disabled configuration detail without implying runtime health.
4. WHEN the Sensor_Pod status in the database is "revoked", THE Sensor_Pipeline_Page SHALL display a revoked status banner and render available or stale telemetry when present; revocation SHALL NOT override derived segment states to `disabled`.
5. WHEN the Sensor_Pod status in the database is "pending", THE Sensor_Pipeline_Page SHALL display a pending enrollment banner and render the pipeline using available telemetry if present, otherwise using the `no_data` state.
6. THE stale-data threshold SHALL default to 60 seconds and SHALL be configurable by the Config_Manager, consistent with the sensor detail page threshold.
7. THE pure derivation module SHALL receive the current time through an explicit option and SHALL NOT call `DateTime.utc_now/0` internally, so deterministic tests can pass a fixed `now`.
8. WHEN a HealthReport in the Health_Registry is stale, THE dashboard SHALL NOT label that sensor, host, capture plane, or management plane as current/running solely from the stale snapshot; it SHALL label the row as stale while preserving the last reported metrics for operator context.

### Requirement 14: Pipeline Visualization Component Architecture

**User Story:** As an engineer implementing the visualization, I want the pipeline rendering to be a reusable component, so that it can be embedded in both the sensor detail page and the pool pipeline page without duplication.

#### Acceptance Criteria

1. THE Pipeline_Visualization SHALL be implemented as a reusable Phoenix LiveView function component or LiveComponent that accepts pipeline state data as attributes and renders the visualization.
2. THE Pipeline_Visualization component SHALL accept a mode attribute distinguishing between single-sensor mode and aggregate-pool mode.
3. THE Pipeline_Visualization component SHALL accept segment state data as a structured map, decoupling the rendering from the HealthReport data structure.
4. THE segment state derivation logic SHALL be implemented in a dedicated pure-function module separate from the LiveView and component modules, enabling property-based testing without LiveView dependencies.
5. THE Pipeline_Visualization component SHALL be testable in isolation by providing mock segment state data.
6. THE derivation module SHALL expose a stable structured output that includes segment ID, label, state, metrics, warnings, tooltip data, and accessible summary text for each segment.
7. THE derivation module SHALL expose stable connector output that includes `id`, `source_id`, `target_id`, `throughput_bps`, `throughput_label`, `secondary_label`, `flow_state`, `speed_tier`, `capture_mode_context` (nil when not applicable), and accessible summary text.
8. THE rendering component SHALL not directly query the Health_Registry, database, or PubSub; LiveViews SHALL provide already-derived pipeline state to the component.
9. THE rendering component SHALL render connector animation from derived connector fields and SHALL NOT rederive flow health from raw HealthReport data or formatted throughput labels.
10. THE `derive_sensor_pipeline/3` public API SHALL accept an options contract containing `:now`, `:stale_threshold_sec`, `:forwarding_sinks`, `:forwarding_summary`, `:capture_mode`, and `:degradation_reasons`; LiveViews SHALL provide those values from the database, Health_Registry, and existing forwarding context.

### Requirement 15: Performance and Rendering Constraints

**User Story:** As an operator monitoring a busy environment, I want the visualization to remain responsive, so that live updates do not make the dashboard sluggish or distracting.

#### Acceptance Criteria

1. THE Sensor_Pipeline_Page SHALL render and update a single-sensor visualization without blocking the LiveView process on long-running computation.
2. THE Pool_Pipeline_Page SHALL handle pools with at least 100 member sensors by deriving aggregate state in bounded time and without rendering one full per-sensor graph per member.
3. THE Pipeline_Visualization SHALL use stable segment and connector IDs so LiveView diffs can update changed values without replacing the entire graph on every health report.
4. THE Pipeline_Visualization SHALL implement the flowing packet animation exclusively using CSS keyframes and SVG stroke properties (for example, `stroke-dasharray` and `stroke-dashoffset`) to avoid JavaScript rendering overhead and maintain LiveView diff efficiency.
5. THE Pipeline_Visualization SHALL keep flow animation subtle and informational; labels, icons, and state badges SHALL remain sufficient to understand the pipeline when animation is absent.
6. WHEN the user has enabled reduced motion, THE Pipeline_Visualization SHALL fully disable connector animation while keeping the static topology and all labels visible.

### Requirement 16: Tests and Verification

**User Story:** As an engineer implementing the pipeline visualization, I want explicit test expectations, so that segment state derivation, real-time updates, accessibility, and edge cases are verified.

#### Acceptance Criteria

1. THE Config_Manager SHALL include tests for the segment state derivation module covering all derivation rules in Requirement 4, including boundary conditions for drop percentage thresholds, CPU thresholds, and storage thresholds.
2. THE Config_Manager SHALL include tests verifying that Missing_Telemetry is correctly identified for each segment type when the corresponding HealthReport field is absent or nil.
3. THE Config_Manager SHALL include LiveView tests verifying that the Sensor_Pipeline_Page subscribes to the correct PubSub topic and updates when a matching HealthReport arrives.
4. THE Config_Manager SHALL include LiveView tests verifying that the Pool_Pipeline_Page correctly aggregates segment states across multiple member sensors.
5. THE Config_Manager SHALL include tests verifying that PubSub messages for unrelated Sensor_Pods do not change the displayed Sensor_Pipeline_Page.
6. THE Config_Manager SHALL include tests verifying that stale HealthReport data triggers the stale-data overlay and warning banner.
7. THE Config_Manager SHALL include accessibility-oriented tests or assertions verifying that each Pipeline_Segment has an accessible label including segment name and state, and that the screen-reader summary table is present.
8. THE Config_Manager SHALL include tests verifying that the Throughput_Annotation formatting produces correct human-readable output for a range of input magnitudes, including zero, sub-Kbps, Mbps, and Gbps values.
9. THE Config_Manager SHALL include RBAC tests verifying that the Sensor_Pipeline_Page and Pool_Pipeline_Page enforce the `sensors:view` permission.
10. THE Config_Manager SHALL include tests verifying that explicit zero throughput is rendered as "0 bps" and is not treated as Missing_Telemetry.
11. THE Config_Manager SHALL include tests verifying that revoked and pending sensors render the correct status banners and segment states.
12. THE Config_Manager SHALL include tests verifying that pool aggregate updates are coalesced or debounced under rapid PubSub message bursts.
13. THE Config_Manager SHALL include tests verifying that a failed target segment stops connector animation even when the source segment is healthy.
14. THE Config_Manager SHALL include tests verifying that a degraded source or target segment produces degraded connector flow.
15. THE Config_Manager SHALL include tests verifying that Alert_Driven_Mode PCAP without active flush telemetry renders the PCAP connector as idle rather than flowing.
16. THE Config_Manager SHALL include tests verifying that formatted throughput labels are never parsed to determine connector behavior.
17. THE Config_Manager SHALL include tests verifying that NIC/capture-interface state is derived only from current system fields and never implies physical mirror/SPAN link health.
18. THE Config_Manager SHALL include full-profile Playwright E2E coverage against the deployed test server for sensor pipeline rendering, pool pipeline rendering, missing-telemetry placeholders, permission behavior, and cleanup of any `e2e-` fixtures.
19. THE Sensor_Agent SHALL include Go regression tests verifying that interface-backed capture throughput reads `rx_bytes`, computes deltas without underflow on counter resets, and preserves packet/drop counters while providing the byte source used for `throughput_bps`.
20. THE Config_Manager SHALL include derivation regression tests verifying that NIC-to-AF_PACKET throughput uses the deduplicated ingress estimate and does not double-count Zeek and Suricata fan-out throughput.
