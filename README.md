# RavenWire

RavenWire is a Podman-managed network sensor stack for standing up independently deployable sensor pods and a manager control plane.

The project has one primary operating path:

```text
Linux host
Podman
systemd / Quadlet
sensorctl
RavenWire sensor or manager pod
```

Docker Compose and Vagrant are no longer first-class workflows; `sensorctl` is the supported install and validation surface.

## Core Stack

Sensor node:

- Sensor Agent
- Zeek
- Suricata
- Vector
- `pcap_ring_writer`
- Local PCAP index and last-known-good config

Manager node:

- Config Manager
- Enrollment CA
- Sensor registry
- Policy/config distribution
- Health dashboard

## Quick Start

Build or install `sensorctl`, then use the top-level operations commands:

```bash
cd sensorctl
go build -o ../bin/sensorctl .
export PATH="$PWD/../bin:$PATH"

sensorctl install
sensorctl start
sensorctl status
sensorctl logs
sensorctl cleanup
```

For a capture host with a known span interface:

```bash
sensorctl install --capture-iface ens16f1 --pod-name sensor-01
sensorctl start
```

Stop or remove the deployment:

```bash
sensorctl stop
sensorctl uninstall
sensorctl uninstall --purge --images
```

Run local project checks:

```bash
sensorctl test
```

## Repository Layout

```text
.
├── config-manager/          # Elixir/Phoenix management plane
├── sensor-agent/            # Go Sensor Agent and pcap_ring_writer
├── sensorctl/               # RavenWire operations CLI
├── config/sensor/           # Baseline sensor configs
├── deploy/quadlet/          # Podman Quadlet deployment units
├── docs/                    # Getting started, operations, enrollment, architecture
└── .kiro/specs/             # Product specs and implementation notes
```

## Operational Model

RavenWire uses Podman Quadlet units checked into `deploy/quadlet/`:

```text
deploy/quadlet/
  management-pod/
  sensor-pod/
```

`sensorctl install` builds the local RavenWire images with rootful Podman, prepares host directories and baseline sensor config, copies Quadlet units into the system Quadlet directory, configures the capture interface, and reloads systemd. `sensorctl start` starts the management pod first, creates a one-time enrollment token, then starts the sensor pod so the initial dual-pod setup auto-enrolls through the same deployment path used later.

During install, `sensorctl` also installs a RavenWire journald drop-in that caps host systemd journal growth. This keeps chatty capture services from consuming the host filesystem if a test deployment is left running.

The goal is that local testing, production-ish testing, and deployment all exercise the same basic model: Podman containers supervised by systemd.

## Security Model

- Config Manager never mounts the Podman socket.
- Sensor Agent is the only component with local lifecycle authority.
- Control actions are allowlisted and audited.
- Sensors enroll with one-time tokens and mTLS certificates.
- Capture components receive only the capabilities needed for packet capture.
- Sensors keep a last-known-good config for offline operation.

## Docs

- [Getting Started](docs/getting-started.md)
- [Operations](docs/operations.md)
- [Enrollment](docs/enrollment.md)
- [Architecture](docs/architecture.md)
- [Implementation Roadmap](docs/implementation-roadmap.md)

## Roadmap Boundaries

The mainline MVP is intentionally narrow: manager enrollment, sensor health, Zeek, Suricata, Vector, Sensor Agent, and alert-driven PCAP.

These remain roadmap or optional extensions, not required for the clean operating path:

- Full PCAP mode with netsniff-ng
- Strelka
- Arkime
- AF_XDP / DPDK / PF_RING
- 25Gbps benchmark profiles
- Tier 2 remote PCAP replication
- Advanced flow/session indexing

## License

No project license has been selected yet.
