Overall: **the repo has the start of a useful management UI, but it is not yet a full sensor management plane.** Right now it has routes for dashboard, enrollment, PCAP config, rule deployment, and support bundles. The router exposes only those core pages: `/`, `/enrollment`, `/pcap-config`, `/rules`, and `/support-bundle`. ([GitHub][1])

The Kiro spec is much more ambitious: it calls for real-time health, live data flow, full tool configuration, active capture mode, Vector sink state, rule-store management, PCAP pivoting, RBAC, SSO, audit logging, historical metrics, and Community ID-based PCAP workflows. ([GitHub][2])

## What exists now

The current web UI appears to include:

| Area            | Current functionality                                                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard       | Lists connected Sensor Pods, container state, uptime, CPU/memory, capture consumer packet/drop stats, and clock status. ([GitHub][3]) |
| Enrollment      | Shows pending enrollment requests, approves/denies them, and lists enrolled pods with certificate serial/expiration. ([GitHub][4])    |
| PCAP config     | Per-pod Alert-Driven PCAP settings: ring size, pre-alert window, post-alert window, alert severity threshold. ([GitHub][5])           |
| Rule deployment | Allows pasting Suricata rules and deploying to a pod or pool. ([GitHub][6])                                                           |
| Support bundle  | Generates and downloads support bundles from enrolled sensor pods. ([GitHub][7])                                                      |

That is a solid MVP start. But functionality-wise, it is still missing several things I would expect before calling RavenWire an industry-leading open-source sensor platform.

---

# Biggest missing web management functionality

## 1. Authentication, RBAC, and audit visibility

This is the biggest gap. The Kiro requirements say the Config Manager should require authentication before configuration changes, and later support roles like viewer, analyst, sensor-operator, rule-manager, platform-admin, and auditor. ([GitHub][2])

Right now, the browser routes shown in the router are not protected by an auth pipeline. They go through the basic browser pipeline, but there is no visible login, user session enforcement, role check, or permission gate before pages like `/pcap-config`, `/rules`, or `/support-bundle`. ([GitHub][1])

You should add:

| Feature                | Why it matters                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| Local admin login      | Needed for lab/self-hosted use.                                                                              |
| Role-based access      | A viewer should not deploy rules or download PCAP.                                                           |
| OIDC/SAML later        | Makes it usable in enterprise environments.                                                                  |
| API tokens with scopes | Needed for Splunk workflow actions and automation.                                                           |
| Audit log UI           | Every config change, enrollment approval, rule push, PCAP carve, and bundle download should be attributable. |
| Audit export           | Useful for incident review and compliance.                                                                   |

Recommended UI pages:

```text
/admin/users
/admin/roles
/admin/api-tokens
/audit
/audit/export
```

---

## 2. Sensor detail page

The dashboard shows all pods, but there does not appear to be a dedicated **Sensor Pod detail page**. You need one.

A real management UI should let the operator click a sensor and see everything about it:

```text
/sensors/:id
```

Should include:

| Section        | Details                                                                                               |
| -------------- | ----------------------------------------------------------------------------------------------------- |
| Identity       | Name, UUID, pool, cert serial, cert expiration, enrollment time, last seen                            |
| Host readiness | Interface state, NIC driver, kernel version, AF_PACKET support, disk, time sync, capabilities         |
| Containers     | Zeek, Suricata, Vector, pcap_ring_writer, Strelka submitter, netsniff-ng when enabled                 |
| Capture        | Interface, fanout groups, BPF profile, packet/drop counters, throughput                               |
| Storage        | PCAP path, ring size, free space, prune status, alert PCAP count                                      |
| Forwarding     | Vector sink status, queue/buffer usage, destination health                                            |
| Actions        | Validate config, reload Zeek, reload Suricata, restart Vector, generate support bundle, revoke sensor |

The current dashboard is good for “what is unhealthy?” but not enough for “why is it unhealthy?”

---

## 3. Sensor pool management

The spec has `Sensor_Pool` as a core data model, and rules can target pools, but I do not see a web UI for creating pools, assigning sensors to pools, or managing pool-level policy. The current rule page can deploy to “all pods in pool,” but there is not a pool-management workflow visible in the router. ([GitHub][1])

You need:

```text
/pools
/pools/new
/pools/:id
/pools/:id/config
/pools/:id/sensors
/pools/:id/deployments
```

Pool management should include:

| Feature                   | Why it matters                                       |
| ------------------------- | ---------------------------------------------------- |
| Create/edit/delete pools  | Needed for scalable fleet organization.              |
| Assign sensors to pools   | Critical for “sensor pods that enroll into manager.” |
| Pool-level config profile | Avoid per-sensor snowflakes.                         |
| Canary rollout            | Deploy to 1 sensor, verify, then continue.           |
| Rollback                  | If bad BPF/rules break capture, revert fast.         |
| Drift detection           | Show sensors not matching desired pool config.       |

This should become one of the highest-priority UI additions.

---

## 4. Versioned configuration management

The current PCAP config page saves a few fields to the database and dispatches to the Sensor Agent. The `SensorPod` schema currently stores fields like `pcap_ring_size_mb`, `pre_alert_window_sec`, `post_alert_window_sec`, and `alert_severity_threshold`. ([GitHub][8])

That works for a simple MVP, but an industry-grade system needs **versioned configuration bundles**, not loose per-pod fields.

Add a UI for:

```text
/configs
/configs/:version
/configs/:version/diff
/configs/:version/deploy
/configs/:version/rollback
```

Should support:

| Feature                 | Needed for                          |
| ----------------------- | ----------------------------------- |
| Config versions         | Know what changed and when.         |
| Human-readable diffs    | Review before deploy.               |
| Validation before apply | Prevent breaking sensors.           |
| Last-known-good marking | Fast rollback.                      |
| Per-pool desired state  | Scalable operations.                |
| Per-sensor actual state | Drift detection.                    |
| Deployment history      | Troubleshooting and accountability. |

This would make RavenWire feel much more like a real management platform.

---

## 5. Full tool configuration editors

The requirements call for per-Sensor Pod configuration editors for Zeek, Suricata, Strelka, Vector, and BPF filters. ([GitHub][2])

Right now, the UI only appears to expose PCAP settings and simple Suricata rule paste/deploy. ([GitHub][5])

Missing editors:

| Tool        | Missing UI                                                                                           |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| Zeek        | Script policy selection, package enable/disable, analyzer toggles, log path, file extraction options |
| Suricata    | Ruleset selection, rule category enable/disable, thresholding, local suppressions, reload status     |
| Vector      | Sink selection, Splunk/Cribl/HTTP/syslog settings, schema mode, buffer size, sink health             |
| BPF         | Elephant flow exclusions, CIDR pairs, port exclusions, validate/compile/test                         |
| Strelka     | Scanner enable/disable, timeout, dedup TTL, max file size, queue health                              |
| netsniff-ng | Full PCAP mode settings, file rotation, storage tier settings                                        |

The BPF editor is especially important because a bad BPF profile can either overload the sensor or blind it.

---

## 6. Live data-flow visualization

The spec explicitly calls for a live pipeline view:

```text
network interface → AF_PACKET ring → Zeek / Suricata → Strelka → Vector → forwarding sink
```

with throughput or record rate on each segment and degraded segments highlighted. ([GitHub][2])

This is missing from the current UI.

This would be one of the coolest “RavenWire signature” features. I would build it as a visual flow map per sensor and per pool:

```text
Mirror Port
   ↓  8.2 Gbps
AF_PACKET
   ↓
 ┌────────────┬──────────────┬───────────────┐
 Zeek         Suricata       PCAP Ring
 12k eps      41 alerts/hr   4 GB ring / 72%
   ↓             ↓              ↓
 Vector ────────┴──────→ Splunk HEC / Cribl
                         sink healthy / 2ms latency
```

Add visual states:

| State  | Meaning               |
| ------ | --------------------- |
| Green  | healthy               |
| Yellow | degraded              |
| Red    | failed                |
| Gray   | disabled              |
| Blue   | pending config reload |

This would make the UI feel less like a database admin page and more like a network sensor command center.

---

## 7. Historical metrics and graphs

The current dashboard shows current health, but the requirements call for at least 72 hours of retained historical health metrics, with time-series graphs for CPU, memory, AF_PACKET drop rate, and packets received per second. ([GitHub][2])

Missing:

```text
/sensors/:id/metrics
/pools/:id/metrics
/metrics/compare
```

Needed charts:

| Metric              | Why                                 |
| ------------------- | ----------------------------------- |
| Packet receive rate | Shows traffic load.                 |
| Drop percentage     | Shows capture loss.                 |
| CPU/memory          | Capacity planning.                  |
| Vector records/sec  | Forwarding health.                  |
| Sink buffer usage   | Detect downstream outage.           |
| PCAP disk usage     | Prevent capture loss.               |
| Clock drift         | Multi-sensor correlation integrity. |

For a sensor platform, “what happened 6 hours ago?” matters a lot.

---

## 8. PCAP search, carve, and pivot UI

The requirements call for PCAP retrieval by sensor, time range, Community ID, 5-tuple, Suricata alert ID, or Zeek UID. They also say the Config Manager UI should expose Community ID as a primary pivot field. ([GitHub][2])

Right now, the UI has Alert-Driven PCAP **configuration**, but I do not see a UI for actual PCAP search/retrieval.

Add:

```text
/pcap
/pcap/search
/pcap/carve
/pcap/requests
/pcap/downloads
```

Should support:

| Feature                    | Why                                      |
| -------------------------- | ---------------------------------------- |
| Time-range search          | Basic packet retrieval                   |
| Community ID search        | Best pivot key for Zeek/Suricata/Splunk  |
| 5-tuple search             | Useful fallback                          |
| Alert ID / Zeek UID search | Analyst workflow                         |
| PCAP request history       | Audit and repeatability                  |
| Chain-of-custody manifest  | Required if PCAP may be used as evidence |
| Download permission checks | Raw packet data is sensitive             |

This is a major missing capability if the project goal is “alert-driven packet evidence.”

---

## 9. Rule Store, not just rule deployment

The current rules UI lets an operator paste Suricata rules and deploy them. That is useful, but the Kiro spec wants a full Rule Store with filtering, deduplication, enable/disable, repository polling, rule counts, Zeek package management, YARA support, and ruleset assignment. ([GitHub][6])

Missing pages:

```text
/rules/store
/rules/repositories
/rules/rulesets
/rules/categories
/rules/deployments
/rules/zeek-packages
/rules/yara
```

Needed features:

| Feature                                         | Priority |
| ----------------------------------------------- | -------- |
| Browse/search rules by SID/name/category/source | High     |
| Enable/disable individual rules                 | High     |
| Enable/disable categories                       | High     |
| Compose named rulesets                          | High     |
| Assign rulesets to pools                        | High     |
| Show deployed rule version per pool             | High     |
| Detect out-of-sync sensors                      | High     |
| Add ET Open/Snort/custom repo URLs              | Medium   |
| Manual repo update button                       | Medium   |
| YARA rule management                            | v1       |
| Zeek package management                         | v1       |

The current paste-and-push UI is an MVP action page, not a full detection-content management system.

---

## 10. Certificate and sensor lifecycle management

Enrollment exists, but the lifecycle after enrollment is thin. The enrollment page lists pending and enrolled pods with cert details. ([GitHub][4])

Missing lifecycle actions:

| Feature                            | Why                                         |
| ---------------------------------- | ------------------------------------------- |
| Generate enrollment token from UI  | Bootstrap new sensors cleanly               |
| Token TTL and one-time-use display | Prevent stale tokens                        |
| Revoke sensor                      | Remove compromised/decommissioned sensor    |
| Rotate cert now                    | Fix cert issues manually                    |
| Show cert health                   | Avoid silent expiration                     |
| Quarantine sensor                  | Keep enrolled but block config/rule updates |
| Rename sensor                      | Operational clarity                         |
| Move sensor to pool                | Fleet management                            |
| Re-enroll sensor                   | Recovery workflow                           |

Right now, enrollment is mostly approve/deny. It needs to become full identity lifecycle management.

---

## 11. Forwarding and schema management

The requirements say Vector should support configurable forwarding sinks and selectable schema modes such as raw, ECS, OCSF, and Splunk CIM. ([GitHub][2])

Missing UI:

```text
/forwarding
/forwarding/sinks
/forwarding/schema
/forwarding/buffers
```

Needed controls:

| Feature                             | Why                          |
| ----------------------------------- | ---------------------------- |
| Add Splunk HEC sink                 | Core expected deployment     |
| Add Cribl HTTP sink                 | Your intended reference path |
| Add file/syslog/HTTP/Kafka/S3 sinks | Portability                  |
| Test sink connection                | Avoid blind config pushes    |
| Select schema mode                  | Integration quality          |
| View buffer usage                   | Downstream outage visibility |
| Retry/drop counters                 | Troubleshooting              |
| Secret handling                     | Protect HEC tokens/API keys  |

This matters because Vector is the only egress path in the design.

---

## 12. Alerts and management-plane notifications

The UI currently shows degraded pod state, but there is no obvious alert center.

Add:

```text
/alerts
/alerts/rules
/alerts/notifications
```

Not SIEM alerts — platform alerts:

| Alert                  | Example                         |
| ---------------------- | ------------------------------- |
| Sensor offline         | No health stream for 60 seconds |
| Packet drops high      | AF_PACKET drop > threshold      |
| Clock drift            | Offset > 100 ms                 |
| Disk critical          | PCAP storage > 90%              |
| Vector sink down       | Splunk/Cribl unavailable        |
| Rule deployment failed | Sensor rejected bundle          |
| Cert expiring          | Rotation failed                 |
| BPF validation failed  | Bad filter blocked deploy       |
| PCAP prune failed      | Cannot reclaim space            |

The requirements specifically mention surfacing storage pruning failure and clock drift in the UI. ([GitHub][2])

---

## 13. Deployment status and rollback workflow

If RavenWire is going to manage many sensors, every pushed change needs an observable deployment state:

```text
/deployments
/deployments/:id
```

Show:

| Item              | Example                                                         |
| ----------------- | --------------------------------------------------------------- |
| Target            | Pool `prod-east`                                                |
| Version           | Config `v42`                                                    |
| Status            | pending, validating, deploying, successful, failed, rolled back |
| Per-sensor result | sensor-01 ok, sensor-02 failed validation                       |
| Operator          | user/API token                                                  |
| Timestamp         | start/end                                                       |
| Diff              | what changed                                                    |
| Rollback button   | restore previous version                                        |

This is how you avoid “I pushed a rule and half the sensors broke.”

---

## 14. Sensor Agent action console

The UI should expose the **allowed** Sensor Agent actions, not arbitrary commands. The design already says the Sensor Agent has a narrow control API and Config Manager should not access Podman directly. ([GitHub][9])

Add safe action buttons:

| Action                  | Scope       |
| ----------------------- | ----------- |
| Validate config         | sensor/pool |
| Apply config            | sensor/pool |
| Reload Zeek             | sensor/pool |
| Reload Suricata         | sensor/pool |
| Restart Vector          | sensor/pool |
| Rotate certificate      | sensor      |
| Generate support bundle | sensor      |
| Request health snapshot | sensor      |
| Test forwarding sink    | sensor/pool |
| Carve PCAP              | sensor      |

Each action should create an audit event and show result status.

---

# Priority order I would implement

## Phase A — make the current UI safe and operational

1. Add login/auth.
2. Add RBAC gates around rule deploy, PCAP config, support bundle, enrollment.
3. Add audit log table and `/audit` view.
4. Add sensor detail page.
5. Add pool management.
6. Add config versioning/diff/rollback.

## Phase B — make it a real sensor-management platform

1. Add live data-flow visualization.
2. Add historical metrics charts.
3. Add Vector forwarding sink management.
4. Add BPF filter editor with validation.
5. Add deployment tracking and drift detection.
6. Add platform alert center.

## Phase C — make it analyst-useful

1. Add PCAP search/carve/download UI.
2. Add Community ID pivot.
3. Add PCAP request history and chain-of-custody manifest.
4. Add Splunk workflow action docs/token generation.
5. Add rule-store browsing, rulesets, repositories, and pool assignment.

## Phase D — make it industry-leading

1. Add detection content lifecycle: Suricata, Zeek packages, YARA.
2. Add canary deploys.
3. Add health baselines and capacity warnings.
4. Add offline update bundle import.
5. Add public API docs generated from the same backend the UI uses.
6. Add multi-manager/HA status later.

---

# My top 10 “must add” UI items

1. **Auth + RBAC + audit log**
2. **Sensor detail page**
3. **Sensor pool management**
4. **Versioned config with diff/rollback**
5. **Live pipeline/data-flow visualization**
6. **Historical metrics graphs**
7. **PCAP carve/search/download UI with Community ID**
8. **BPF elephant-flow editor**
9. **Vector forwarding sink/schema management**
10. **Rule Store/ruleset/repository management**

The repo already has a decent first cut, but the current web UI is closer to a **control-panel MVP** than a true management platform. The big architectural move should be shifting from “per-page actions against individual pods” to **pool-based, versioned, audited, role-controlled fleet management**.

[1]: https://github.com/gustovshikov/RavenWire/blob/main/config-manager/lib/config_manager_web/router.ex 'RavenWire/config-manager/lib/config_manager_web/router.ex at main · gustovshikov/RavenWire · GitHub'
[2]: https://raw.githubusercontent.com/gustovshikov/RavenWire/main/.kiro/specs/network-sensor-stack/requirements.md 'raw.githubusercontent.com'
[3]: https://github.com/gustovshikov/RavenWire/raw/refs/heads/main/config-manager/lib/config_manager_web/live/dashboard_live.ex 'raw.githubusercontent.com'
[4]: https://github.com/gustovshikov/RavenWire/raw/refs/heads/main/config-manager/lib/config_manager_web/live/enrollment_live.ex 'raw.githubusercontent.com'
[5]: https://github.com/gustovshikov/RavenWire/raw/refs/heads/main/config-manager/lib/config_manager_web/live/pcap_config_live.ex 'raw.githubusercontent.com'
[6]: https://github.com/gustovshikov/RavenWire/raw/refs/heads/main/config-manager/lib/config_manager_web/live/rule_deployment_live.ex 'raw.githubusercontent.com'
[7]: https://github.com/gustovshikov/RavenWire/raw/refs/heads/main/config-manager/lib/config_manager_web/live/support_bundle_live.ex 'raw.githubusercontent.com'
[8]: https://github.com/gustovshikov/RavenWire/blob/main/config-manager/lib/config_manager/sensor_pod.ex 'RavenWire/config-manager/lib/config_manager/sensor_pod.ex at main · gustovshikov/RavenWire · GitHub'
[9]: https://raw.githubusercontent.com/gustovshikov/RavenWire/main/.kiro/specs/network-sensor-stack/design.md 'raw.githubusercontent.com'
