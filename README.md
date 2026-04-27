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

Docker Compose and Vagrant are no longer first-class workflows. Optional lab helpers live under `tools/lab/` for capture validation only.

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
sensorctl start sensor-pod
sensorctl status
sensorctl logs sensor-pod
```

Enroll a sensor:

```bash
sensorctl enroll \
  --manager https://manager:8443 \
  --token <token> \
  --pod-name sensor-01 \
  --cert-dir /etc/sensor/certs
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
├── tools/lab/               # Optional capture validation helpers
└── .kiro/specs/             # Product specs and implementation notes
```

## Operational Model

RavenWire uses Podman Quadlet units checked into `deploy/quadlet/`:

```text
deploy/quadlet/
  management-pod/
  sensor-pod/
```

`sensorctl install` copies those units into the user systemd container directory and reloads systemd. `sensorctl start`, `stop`, `restart`, `status`, and `logs` operate on those units directly.

The goal is that local testing, production-ish testing, and deployment all exercise the same basic model: Podman containers supervised by systemd.

## Security Model

- Config Manager never mounts the Podman socket.
- Sensor Agent is the only component with local lifecycle authority.
- Control actions are allowlisted and audited.
- Sensors enroll with one-time tokens and mTLS certificates.
- Capture components receive only the capabilities needed for packet capture.
- Sensors keep a last-known-good config for offline operation.

## Optional Lab Capture Test

The lab harness is useful for validating Zeek, Suricata, Vector, and `pcap_ring_writer` on a Linux host:

```bash
export CAPTURE_IFACE=eth0
podman compose -p ravenwire-lab -f tools/lab/compose.capture-test.yml up -d
tools/lab/verify-capture.sh
podman compose -p ravenwire-lab -f tools/lab/compose.capture-test.yml down
```

This is not the deployment path.

## Docs

- [Getting Started](docs/getting-started.md)
- [Operations](docs/operations.md)
- [Enrollment](docs/enrollment.md)
- [Architecture](docs/architecture.md)

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

TBD.
