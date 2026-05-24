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

The default `sensorctl install` path writes lab/test manager defaults to `/etc/ravenwire/manager.env` so the first manager login is predictable when the users table is empty:

```text
Username: RavenWire
Password: RavenWire2026!
```

For production-pilot use, run `sensorctl install --pilot-hardening`. It writes a root-only `/etc/ravenwire/manager.env`, generates `SECRET_KEY_BASE` and `RAVENWIRE_SINK_ENCRYPTION_KEY` when they are not already set, and rejects the bundled demo admin password. If `RAVENWIRE_ADMIN_PASSWORD` is omitted in hardening mode, `sensorctl` generates and prints a one-time bootstrap password during install; store it securely.

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

Run browser end-to-end checks against the deployed test server:

```bash
cd e2e
npm install
npm run install:browsers
export E2E_BASE_URL=http://172.16.10.38:4000
export E2E_ADMIN_USER=<admin username>
export E2E_ADMIN_PASSWORD=<admin password>
npm run test:smoke
```

The browser suite performs server preflight, verifies LiveView assets and socket connectivity, checks that the built-in sensor is visible on the dashboard, and exercises pool creation in a real browser. See [e2e/README.md](e2e/README.md) for full-suite and cleanup options.

Run the full regression gate for browser-visible feature work after the required E2E environment variables are set:

```bash
sensorctl test && (cd e2e && npm run test:full)
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
└── specs/                   # Product specs and implementation notes
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

The current MVP target is a single-site production pilot: a deployable sensor/manager stack with authenticated manager access, sensor enrollment and health, sensor detail pages, pools, desired-state deployment tracking, rule and BPF management, Vector forwarding sink management, support bundles, alert-driven PCAP plumbing plus browser PCAP search/retrieval, implemented bearer-token `/api/v1` controllers for current workflows, local OpenAPI docs at `/api/docs`, per-token API rate limiting and request-level API audit entries, and real-browser regression coverage against a deployed test server.

The MVP release gate is not just "containers start." It requires:

- `sensorctl` install/start/status/logs/uninstall/test on the supported Quadlet path.
- First-run manager enrollment and authenticated UI access.
- A live built-in sensor visible on the dashboard and sensor detail page.
- Pool creation, sensor assignment, config editing, forwarding sink management, deployment/drift views, rule store workflows, and BPF profile editing.
- Admin user management, API token management UI, audit filtering/export, audited state-changing manager actions, and role-aware browser route protection for the MVP surface.
- Passing local checks plus the browser E2E smoke/full profile for changed browser workflows.

Before using the pilot outside a lab, install with `sensorctl install --pilot-hardening`, put the manager behind the intended TLS/proxy/firewall boundary, back up `/data/config_manager`, `/data/ca`, and `/etc/ravenwire`, and complete the restore/rollback validation in [Operations](docs/operations.md). A broader production release still needs additional packaging and HA work.

These remain roadmap or optional extensions, not required for the clean operating path:

- Full PCAP mode with netsniff-ng
- Forwarding runtime telemetry beyond the current placeholder UI
- Additional Public API controllers for sensors, pools, forwarding, and BPF once those automation routes are intentionally added
- Platform Alert Center notification delivery and live data-flow visualization
- Strelka
- Arkime
- AF_XDP / DPDK / PF_RING
- 25Gbps benchmark profiles
- Tier 2 remote PCAP replication
- Advanced flow/session indexing
- Multi-manager HA and offline update bundles

Post-MVP work starts from feature specs. The spec-first gate requires a feature to have `requirements.md`, `design.md`, and `tasks.md` before implementation begins; existing specs must be reviewed and updated when roadmap reality changes. Platform Alert Center, Historical Metrics, and Health Baselines are implemented with deployed full-profile E2E verification.

## License And Distribution

No public project license has been selected yet. Treat the repository as private/internal distribution until a license decision is made.
