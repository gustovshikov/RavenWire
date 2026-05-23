# Getting Started

RavenWire has one supported operating path: Podman containers managed by systemd Quadlet and operated with `sensorctl`.

The current project state is a professional MVP candidate: local install, automatic first-run enrollment, authenticated manager access, health reporting, sensor detail pages, pool management, deployment/drift views, rule and BPF management, Vector forwarding sink management, support bundles, browser E2E coverage, alert-driven PCAP plumbing, and browser PCAP search/retrieval. Remaining MVP hardening is tracked in [Implementation Roadmap](implementation-roadmap.md); forwarding telemetry, alerting, historical observability, public API docs, and HA remain roadmap work under `.kiro/specs/`.

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

## Start

```bash
sensorctl start
sensorctl status
sensorctl logs
```

On a fresh install, `sensorctl start` starts Config Manager, creates a one-time enrollment token, then starts the sensor pod so it auto-enrolls.

The manager UI is available from Config Manager once the management pod is running. The current browser routes include `/login`, `/`, `/sensors/:id`, `/enrollment`, `/pools`, `/pools/:id/forwarding`, `/pools/:id/forwarding/sinks/new`, `/pools/:id/forwarding/sinks/:sink_id/edit`, `/deployments`, `/pcap-config`, `/pcap`, `/pcap/search`, `/pcap/requests`, `/rules/store`, `/rules/rulesets`, `/support-bundle`, `/audit`, `/audit/export`, `/admin/users`, `/admin/roles`, and `/admin/api-tokens`.

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
