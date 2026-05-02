# Getting Started

RavenWire has one supported operating path: Podman containers managed by systemd Quadlet and operated with `sensorctl`.

The current project state is an MVP sensor/manager stack with local install, automatic first-run enrollment, health reporting, support bundles, rule/config screens, and alert-driven PCAP plumbing. Fleet UX, RBAC, deployment tracking, pool management, public API docs, and advanced observability are specified under `.kiro/specs/` and should be implemented in that order.

## Prerequisites

- Linux host with systemd
- Rootful Podman access through `sudo`
- A capture interface connected to a span/TAP feed
- Go, if building `sensorctl` locally

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

## Start

```bash
sensorctl start
sensorctl status
sensorctl logs
```

On a fresh install, `sensorctl start` starts Config Manager, creates a one-time enrollment token, then starts the sensor pod so it auto-enrolls.

The manager UI is available from Config Manager once the management pod is running. The current browser routes are `/`, `/enrollment`, `/pcap-config`, `/rules`, and `/support-bundle`.

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
