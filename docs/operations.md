# Operations

`sensorctl` is the primary operator surface for RavenWire.

RavenWire installs as system Quadlet units because the capture stack needs host packet-capture capabilities that rootless containers cannot provide reliably.

Docker Compose and Vagrant are not supported deployment paths. Install, run, and validation work should go through `sensorctl` and the Quadlet units in `deploy/quadlet/`.

## Commands

```bash
sensorctl install
sensorctl install --pilot-hardening
sensorctl install --capture-iface ens16f1 --pod-name sensor-01 --manager-url http://127.0.0.1:4000/api/v1
sensorctl start [app|sensor-pod|management-pod|unit]
sensorctl stop [app|sensor-pod|management-pod|unit]
sensorctl restart [app|sensor-pod|management-pod|unit]
sensorctl status [unit]
sensorctl logs [unit]
sensorctl cleanup [--podman] [--docker]
sensorctl uninstall [--purge] [--images]
sensorctl enroll --manager https://manager:8443 --token <token>
sensorctl agent status --sensor https://sensor:9091
sensorctl agent show-drops --sensor https://sensor:9091
sensorctl agent collect-support-bundle --sensor https://sensor:9091 --output ./support.tar.gz
sensorctl test
```

If no unit is provided, `start`, `stop`, and `restart` operate on the full dual-pod app. `sensorctl start` starts `management-pod.target`, waits for Config Manager, generates the initial enrollment token when needed, then starts `sensor-pod.target`.

`sensorctl install` supports these deployment options:

| Flag | Purpose |
|---|---|
| `--capture-iface` | Capture interface for Zeek, Suricata, and `pcap_ring_writer`. Falls back to `CAPTURE_IFACE` and then interface detection. |
| `--pod-name` | Sensor pod identity. Falls back to `SENSOR_POD_NAME` and then hostname. |
| `--manager-url` | Config Manager enrollment API base URL. Defaults to `http://127.0.0.1:4000/api/v1`. |
| `--skip-build` | Reuse existing local images instead of rebuilding them. |
| `--pilot-hardening` | Write non-demo manager secrets to `/etc/ravenwire/manager.env` for production-pilot use. |

`sensorctl install` also reads a small set of environment overrides before it writes the persistent sensor environment:

| Environment | Default | Purpose |
|---|---:|---|
| `MIN_STORAGE_GB` | `10` | Minimum available storage required at `/sensor/pcap` before Sensor Agent allows capture startup. Lower only for constrained lab hosts. |
| `MIN_DISK_WRITE_MBPS` | `50` | Minimum write-throughput gate for the PCAP storage path. |
| `CAPTURE_IFACE` | detected | Capture interface when `--capture-iface` is omitted. |
| `SENSOR_POD_NAME` | hostname | Sensor identity when `--pod-name` is omitted. |
| `CONTROL_API_HOST` | detected | Host/IP advertised to Config Manager during enrollment. |

The manager also loads `/etc/ravenwire/manager.env`. A normal lab/test install writes the existing demo manager login there for repeatable test-server behavior. A `--pilot-hardening` install writes generated or operator-provided values:

| Environment | Default in `--pilot-hardening` | Purpose |
|---|---:|---|
| `SECRET_KEY_BASE` | generated | Phoenix signing/encryption secret; demo values are rejected in hardening mode. |
| `RAVENWIRE_ADMIN_USER` | `RavenWire` | Initial platform-admin username when the users table is empty. |
| `RAVENWIRE_ADMIN_PASSWORD` | generated and printed once | Initial platform-admin password; demo and too-short values are rejected. |
| `RAVENWIRE_SINK_ENCRYPTION_KEY` | generated | Base64-encoded 32-byte key for forwarding sink secrets. |
| `RAVENWIRE_API_DOCS_REQUIRE_AUTH` | `true` | Require authentication for `/api/docs` in hardened pilot installs. |

During install, `sensorctl` brings the capture interface up, enables promiscuous mode, disables GRO/LRO when `ethtool` is available, and best-effort tunes queue/ring depth to reduce burst drops. Unsupported NIC tuning commands are allowed to fail so portable installs still proceed; Sensor Agent reports any remaining tuning gaps as soft readiness warnings.

## Quadlet Layout

```text
deploy/quadlet/
  management-pod/
    config-manager.container
    management-pod.target
  sensor-pod/
    sensor-agent.container
    pcap-ring-writer.container
    zeek.container
    suricata.container
    vector.container
    capture-pipeline.target
    analysis-pipeline.target
    sensor-pod.target
```

## Host State

`sensorctl install` prepares these main host paths:

```text
/data/config_manager
/data/ca
/data/metrics
/etc/ravenwire
/etc/sensor
/var/sensor
/var/run/sensor
/sensor/pcap
```

The baseline Suricata rules file is installed at `/etc/sensor/suricata/rules/suricata.rules`. It contains one low-noise starter SID so Suricata loads without an empty-rules warning on first boot. Treat it as a smoke-test placeholder, not a real detection ruleset.

`sensorctl uninstall` removes installed Quadlet and target files. `sensorctl uninstall --purge` also removes RavenWire host data and generated certificates/config. `sensorctl uninstall --images` removes locally built RavenWire images.

## Journal Storage Protection

`sensorctl install` installs `/etc/systemd/journald.conf.d/ravenwire.conf` and restarts `systemd-journald`.
The drop-in caps persistent journal use at `256M`, runtime journal use at `64M`, keeps at least `4G` free on the persistent journal filesystem, and expires journal entries after `3day`.
Install also rotates and vacuums existing journal files to `256M`/`3day` so an already-large journal is trimmed immediately.
`sensorctl uninstall` removes this RavenWire-owned drop-in and restarts `systemd-journald`.

`sensorctl install` also installs `/etc/logrotate.d/ravenwire` for RavenWire host log handoff paths under `/var/sensor/logs`.
Suricata EVE output is configured to rotate hourly, and Vector follows the rotated `eve*.json` files.
The host logrotate rule caps large Zeek, Suricata, Vector, and Sensor Agent audit log files with `maxsize 128M`, `rotate 2`, compression, and `copytruncate`.
`sensorctl install` also enables `ravenwire-log-prune.timer`, which runs hourly and enforces RavenWire storage retention: `/var/sensor/logs` files older than `1` day are removed, individual logs over `128M` are deleted or truncated if active, aggregate handoff log usage is kept below `768M`, support bundles are kept under `256M`, and `/sensor/pcap/alerts` is kept under `8192M` with a `7` day retention safety net.
The same pruner preserves a default `4096M` free-space reserve on the filesystem that backs `/sensor/pcap/alerts` by deleting or truncating non-PCAP RavenWire logs first. Override with `RAVENWIRE_PCAP_RESERVED_FREE_MB` for larger capture volumes.

The Sensor Agent also assigns a default `7` day retention time to carved PCAP artifacts and starts its PCAP retention pruner hourly. Override with `PCAP_RETENTION` and `PCAP_RETENTION_PRUNE_INTERVAL` duration values such as `168h` and `1h`.

Use `sensorctl cleanup` to run the journal vacuum, RavenWire storage pruner, logrotate rule, and stale support-bundle cleanup immediately. Add `--podman` to prune unused Podman artifacts, or `--docker` for old Docker lab artifacts.

## Logs

```bash
sensorctl logs
sensorctl logs sensor-agent.service
sensorctl logs pcap-ring-writer.service
sensorctl logs config-manager.service
```

Use `sensorctl logs --lines 500` to change the number of journal lines.

## Agent Inspection

Agent commands talk to the Sensor Agent control API over mTLS. Provide the sensor URL with `--sensor` or `SENSORCTL_SENSOR_URL`. Certificates can come from `SENSORCTL_CERT`, `SENSORCTL_KEY`, and `SENSORCTL_CA`, or from `~/.sensorctl/config.yaml` / `./sensorctl.yaml`.

```yaml
sensor_url: https://sensor-host:9091
cert: /etc/sensor/certs/sensor.crt
key: /etc/sensor/certs/sensor.key
ca: /etc/sensor/certs/ca-chain.pem
```

## Validation

```bash
sensorctl test
```

This runs the `sensorctl` Go checks, Sensor Agent Go checks, and the Linux build check for `pcap_ring_writer`.

For browser-visible manager workflows, also run the Playwright E2E suite against the configured test server:

```bash
cd e2e
npm install
npm run install:browsers
npm run test:smoke
npm run test:full
```

Set `E2E_BASE_URL`, `E2E_ADMIN_USER`, and `E2E_ADMIN_PASSWORD` before running authenticated browser tests. The E2E suite performs HTTP/static asset preflight, SSH service and built-in sensor health checks, LiveView connectivity checks, pool workflows, forwarding workflows, PCAP search/retrieval workflows, BPF editor workflows, ruleset/repository workflows, and support/deployment page checks.

## Production Pilot Runbook

The checked-in Quadlet units are suitable for development and the shared test server. For a single-site pilot outside a lab, use this checklist before treating the deployment as release-ready:

1. Install with hardening enabled:

   ```bash
   export RAVENWIRE_ADMIN_USER=<admin-user>
   export RAVENWIRE_ADMIN_PASSWORD=<store-securely>
   sensorctl install --pilot-hardening --capture-iface <span-interface> --pod-name sensor-01
   sensorctl start
   sensorctl status
   ```

   If you want `sensorctl` to generate the first admin password, do not set `RAVENWIRE_ADMIN_PASSWORD`; capture the generated `RAVENWIRE_BOOTSTRAP_ADMIN_PASSWORD` printed during install and store it in the site password vault.

2. Put Config Manager behind the intended TLS/proxy/firewall boundary. Expose only the required browser/API path for operators and the sensor enrollment/control paths required by the deployment. Keep `/etc/ravenwire/manager.env`, `/data/ca`, and support bundles off public shares.

3. Size storage before traffic capture. Set `MIN_STORAGE_GB`, `PCAP_RETENTION`, and `PCAP_RETENTION_PRUNE_INTERVAL` for the expected sensor load, then verify `sensorctl cleanup`.

4. Back up configuration, database, CA material, and manager secrets before relying on the deployment:

   ```bash
   sudo tar --xattrs --acls -czf ravenwire-pilot-backup.tgz /data/config_manager /data/ca /etc/ravenwire
   ```

5. Perform a restore drill on a test host or maintenance window: stop RavenWire, restore the archive, run `sensorctl start`, verify login, verify the built-in sensor, and run the validation commands below.

6. Validate each upgrade or redeploy:

   ```bash
   sensorctl test
   cd e2e
   npm run preflight
   npm run test:full
   ```

7. Confirm service health and cleanup after validation: `sensorctl status` should show the management and sensor units active, and the E2E cleanup audit should show no lingering `e2e-` pools, users, sensors, rulesets, repositories, forwarding sinks, alerts, PCAP requests, metric fixtures, or baseline fixtures.

8. Roll back by restoring the previous git revision or image set, rerunning `sensorctl install --skip-build` only when the expected images already exist, starting RavenWire, and repeating the validation gate. Restore the latest known-good backup if the database or CA material changed during the failed upgrade.

9. Keep distribution private/internal until a public project license is selected.

## Fresh Reset

```bash
sensorctl stop
sensorctl uninstall --purge --images
sensorctl install --capture-iface ens16f1 --pod-name sensor-01
sensorctl start
```

## Current Boundaries

The single-site pilot MVP target includes the implemented fleet pool management, sensor detail pages, deployment/drift views, rule store, BPF editor, Vector forwarding sink management, PCAP browser search/retrieval, support bundles, browser E2E regression path, browser-surface auth/RBAC/audit hardening, Platform Alert Center, and Historical Metrics pages. Admin user management, API token management UI, audit filtering/export, route/event permission checks, and role-aware controls are part of the current browser MVP surface.

Bearer-token `/api/v1` Public API controllers are implemented for current workflows and are separate from the Sensor Agent mTLS API. The implemented Public API is documented at `/api/docs`, with raw OpenAPI JSON at `/api/v1/openapi.json`. API tokens are rate-limited by token ID, defaulting to 100 requests per minute, and authenticated API requests write request-level audit entries.

The current implementation does not yet include forwarding telemetry from HealthReport, alert notification delivery, live data-flow visualization, offline update bundles, canary deployments, or multi-manager HA. Health Baselines is implemented on the current feature branch with local regression coverage and deployed full-profile E2E verification. Historical Metrics and Health Baselines store snapshots/baselines in the Config Manager database, so normal `/data/config_manager` backup and restore coverage also covers metric history and learned baseline state. The remaining features are specified under `specs/` and summarized in [Implementation Roadmap](implementation-roadmap.md).
