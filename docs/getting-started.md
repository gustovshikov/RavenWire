# Getting Started

RavenWire has one supported operating path: Podman containers managed by systemd Quadlet and operated with `sensorctl`.

The current project state is a single-site production pilot MVP candidate: local install, automatic first-run enrollment, authenticated manager access, health reporting, sensor detail pages, pool management, deployment/drift views, rule and BPF management, Vector forwarding sink management, support bundles, browser E2E coverage, alert-driven PCAP plumbing, browser PCAP search/retrieval, implemented bearer-token `/api/v1` controllers, local OpenAPI docs at `/api/docs`, per-token API rate limiting, request-level API audit entries, Platform Alert Center, Historical Metrics pages, and Health Baselines pages. Remaining production-pilot hardening is tracked in [Implementation Roadmap](implementation-roadmap.md); forwarding telemetry, alert notification delivery, live data-flow visualization, and HA remain roadmap work under `specs/`.

## Prerequisites

- Linux host with systemd
- Rootful Podman access through `sudo`
- A capture interface connected to a span/TAP feed
- At least `10 GB` free under `/sensor/pcap` for the default readiness gate
- Capture NIC queue/ring tuning through `iproute2` and, when available, `ethtool`
- Go, if building `sensorctl` locally

The default readiness thresholds are intentionally conservative for packet capture. Lab VMs with less storage can lower the install/start gate by exporting `MIN_STORAGE_GB`, for example `MIN_STORAGE_GB=8 sensorctl install --capture-iface ens16f1`. Production sensors should leave the default in place or raise it to match expected PCAP retention.

## Build sensorctl

```bash
cd sensorctl
go build -o ../bin/sensorctl .
export PATH="$PWD/../bin:$PATH"
```

## Install

```bash
sensorctl install --capture-iface <span-interface>
```

This builds the RavenWire images with rootful Podman, prepares host directories and baseline sensor config, configures the capture interface, and copies units from `deploy/quadlet/` into:

```text
/etc/containers/systemd/
/etc/systemd/system/
```

If `--capture-iface` is omitted, `sensorctl` checks `CAPTURE_IFACE` and then tries the first up, non-loopback interface. Pass the interface explicitly for repeatable deployments.

Install also seeds a low-noise Suricata starter rule so the detection engine is active on first boot. Replace or extend `/etc/sensor/suricata/rules/suricata.rules` through rule deployment before using the sensor for real monitoring.

For production-pilot use, install with hardening enabled:

```bash
sensorctl install --pilot-hardening --capture-iface <span-interface>
```

`--pilot-hardening` writes `/etc/ravenwire/manager.env` with root-only permissions, generates `SECRET_KEY_BASE` and `RAVENWIRE_SINK_ENCRYPTION_KEY` if they are not already provided, and rejects the bundled demo admin password. If `RAVENWIRE_ADMIN_PASSWORD` is omitted, `sensorctl` prints a generated bootstrap password once during install. Store it securely, then follow the backup, restore, rollback, TLS/proxy/firewall, and cleanup checklist in [Operations](operations.md).

## Start

```bash
sensorctl start
sensorctl status
sensorctl logs
```

On a fresh install, `sensorctl start` starts Config Manager, creates a one-time enrollment token, then starts the sensor pod so it auto-enrolls.

The manager UI is available from Config Manager once the management pod is running. The current browser routes include `/login`, `/`, `/sensors/:id`, `/sensors/:id/metrics`, `/sensors/:id/baselines`, `/enrollment`, `/pools`, `/pools/:id/forwarding`, `/pools/:id/forwarding/sinks/new`, `/pools/:id/forwarding/sinks/:sink_id/edit`, `/pools/:id/metrics`, `/pools/:id/baselines`, `/deployments`, `/alerts`, `/alerts/rules`, `/alerts/notifications`, `/pcap-config`, `/pcap`, `/pcap/search`, `/pcap/requests`, `/rules/store`, `/rules/rulesets`, `/support-bundle`, `/audit`, `/audit/export`, `/admin/users`, `/admin/roles`, and `/admin/api-tokens`.

## Validate

```bash
sensorctl test
```

This runs the local Go checks for `sensorctl` and `sensor-agent`, plus the Linux build check for `pcap_ring_writer`. There is no separate Compose capture harness in the supported path.

## Stop Or Uninstall

```bash
sensorctl stop
sensorctl uninstall
sensorctl uninstall --purge --images
```

Manual enrollment remains available for split manager/sensor deployments. See [Enrollment](enrollment.md) for options.

Implementation planning lives in [Implementation Roadmap](implementation-roadmap.md). Lower-level deployment and route details are in [Operations](operations.md) and [Architecture](architecture.md).
