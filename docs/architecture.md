# Architecture

RavenWire is organized around one deployable model: Podman containers supervised by systemd through Quadlet.

The current codebase is an MVP foundation. It can install a local dual-pod stack, enroll the first sensor, collect health, expose early manager screens, and run alert-driven packet capture. The specs under `.kiro/specs/` define the next product layer: auth/RBAC, fleet views, deployment tracking, rule and forwarding management, PCAP search, alerting, historical metrics, and production operations.

The Config Manager web UI follows the Orbital Plasma design system documented in [Design](design.md).

## Sensor Node

```text
Sensor Pod
  Sensor Agent
  Zeek
  Suricata
  Vector
  pcap_ring_writer
```

The Sensor Agent owns local control operations and keeps the management plane away from direct host or Podman socket access.

Sensor-local responsibilities currently include:

- Bootstrap and enrollment state tracking.
- mTLS control API with an allowlisted route set.
- Health collection and drop counters.
- BPF/capture config application.
- Alert-driven PCAP indexing and carving.
- Support bundle generation.
- Last-known-good config behavior.

## Manager Node

```text
Management Pod
  Config Manager
  Enrollment CA
  Sensor registry
  Health dashboard
```

Manager-side responsibilities currently include:

- Browser dashboard and early operator pages.
- Enrollment token creation, approval, denial, and certificate issuance.
- Sensor registry and health registry.
- Health gRPC endpoint.
- Sensor support bundle proxying.

## Packet Path

Each capture consumer binds its own AF_PACKET socket to the monitored interface:

| Consumer | Fanout Group | Purpose |
|---|---:|---|
| Zeek | `1` | Protocol metadata |
| Suricata | `2` | Signatures and alerts |
| pcap_ring_writer | `4` | Alert-window packet history |

RavenWire avoids a shared userspace packet broker for the MVP. Scalability comes from independently deployable sensor pods, enrollment, manager-driven config, and offline last-known-good behavior.

## Current Route Surface

Config Manager browser routes:

| Route | Purpose |
|---|---|
| `/` | Health dashboard. |
| `/enrollment` | Enrollment queue and approval workflow. |
| `/pcap-config` | Current PCAP configuration screen. |
| `/rules` | Current rule deployment screen. |
| `/support-bundle` | Support bundle workflow. |
| `/support-bundle/download/:pod_id` | Support bundle download proxy. |

Config Manager API routes:

| Route | Protection | Purpose |
|---|---|---|
| `POST /api/v1/enroll` | Bootstrap token | Sensor enrollment request. |
| `GET /api/v1/enroll/status` | Bootstrap token/pod lookup | Enrollment polling. |
| `GET /api/v1/health/:pod_id` | mTLS | Sensor health lookup. |
| `POST /api/v1/enrollment/:id/approve` | mTLS | Approve enrollment. |
| `POST /api/v1/enrollment/:id/deny` | mTLS | Deny enrollment. |
| `GET /api/v1/crl` | mTLS | Certificate revocation list. |

Sensor Agent mTLS control routes:

| Route | Purpose |
|---|---|
| `GET /health` | Current health snapshot. |
| `POST /control/reload/zeek` | Reload Zeek. |
| `POST /control/reload/suricata` | Reload Suricata. |
| `POST /control/restart/vector` | Restart Vector. |
| `POST /control/capture-mode` | Switch capture mode. |
| `POST /control/config` | Apply pool/config bundle. |
| `POST /control/config/validate` | Validate config before apply. |
| `POST /control/cert/rotate` | Rotate certificate. |
| `POST /control/pcap/carve` | Carve alert-window PCAP. |
| `POST /control/support-bundle` | Generate support bundle. |
| `GET /control/support-bundle/download` | Download generated support bundle. |

Sensor-internal routes:

| Route | Purpose |
|---|---|
| `POST /enroll` | Pre-certificate local bootstrap listener. |
| `POST /alerts` | Vector-to-PCAP alert ingestion. |
| `GET /alerts/health` | Alert queue health. |

## Forward Architecture

Implementation should follow the spec order in `.kiro/specs/README.md`. The main dependency is `auth-rbac-audit`, which introduces sessions, users, roles, route guards, API token scopes, and audit logging before the wider fleet workflows are exposed.

New public automation endpoints should use `/api/v1`. Internal Sensor Agent routes can stay separate, but public docs must distinguish bearer-token Public API routes from mTLS/internal control routes.
