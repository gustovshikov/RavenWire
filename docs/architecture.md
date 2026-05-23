# Architecture

RavenWire is organized around one deployable model: Podman containers supervised by systemd through Quadlet.

The current codebase is a professional MVP candidate. It can install a local dual-pod stack, enroll the first sensor, authenticate manager users, collect health, show fleet and sensor detail views, manage pools, track desired-state deployments and drift, manage rule and BPF configuration, proxy support bundles, and run alert-driven packet capture. The specs under `.kiro/specs/` define both the remaining MVP hardening work and the post-MVP product roadmap.

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

- Authenticated browser dashboard and operator pages.
- Enrollment token creation, approval, denial, and certificate issuance.
- Sensor registry and health registry.
- Health gRPC endpoint.
- Sensor detail, pool management, deployment/drift, rule store, BPF editor, and audit views.
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
| `/login` | Manager login. |
| `/password/change` | Required/self-service password change. |
| `/` | Health dashboard. |
| `/sensors/:id` | Sensor detail, health, readiness, capture, storage, forwarding placeholder, and sensor actions. |
| `/enrollment` | Enrollment queue and approval workflow. |
| `/pools` | Pool list. |
| `/pools/new` | Pool creation. |
| `/pools/:id` | Pool overview, deployment entry points, rule/BPF state, and delete confirmation. |
| `/pools/:id/sensors` | Pool sensor assignment/removal. |
| `/pools/:id/config` | Pool desired configuration. |
| `/pools/:id/bpf` | Pool BPF filter editor. |
| `/pools/:id/deployments` | Pool deployment history. |
| `/pools/:id/drift` | Pool drift summary. |
| `/deployments` | Desired-state deployment list. |
| `/deployments/:id` | Deployment detail, cancel, and rollback entry points. |
| `/pcap-config` | Current PCAP configuration screen. |
| `/rules/store` | Rule store browsing and rule enablement controls. |
| `/rules/categories` | Rule category controls. |
| `/rules/repositories` | Rule repository management. |
| `/rules/rulesets` | Ruleset list and creation. |
| `/rules/rulesets/:id` | Ruleset detail, pool assignment, and deploy entry points. |
| `/rules/deployments` | Rule deployment history. |
| `/rules` | Quick rule deployment screen. |
| `/support-bundle` | Support bundle workflow. |
| `/support-bundle/download/:pod_id` | Support bundle download proxy. |
| `/audit` | Audit log browser with filters, pagination, and detail view. |
| `/audit/export` | Filtered audit export page. |
| `/admin/users` | Local user management. |
| `/admin/roles` | Role and permission reference. |
| `/admin/api-tokens` | Scoped API token management. |

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

Implementation should follow the spec order in `.kiro/specs/README.md`. The professional MVP release gate is now the implemented sensor stack plus authenticated manager workflows for fleet health, sensor detail, pools, deployments, rules, BPF, support bundles, and audit visibility. Remaining auth/RBAC hardening should be finished before treating the MVP as release-ready.

New public automation endpoints should use `/api/v1`. Internal Sensor Agent routes can stay separate, but public docs must distinguish bearer-token Public API routes from mTLS/internal control routes.
