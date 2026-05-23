# Architecture

RavenWire is organized around one deployable model: Podman containers supervised by systemd through Quadlet.

The current codebase is a single-site production pilot MVP candidate. It can install a local dual-pod stack, enroll the first sensor, authenticate manager users, collect health, show fleet and sensor detail views, manage pools, track desired-state deployments and drift, manage rule, BPF, and Vector forwarding configuration, proxy support bundles, run alert-driven packet capture, expose browser PCAP search/retrieval, and serve implemented bearer-token `/api/v1` controllers. The specs under `.kiro/specs/` define both the remaining production-pilot hardening work and the post-MVP product roadmap.

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
- Sensor detail, pool management, deployment/drift, rule store, BPF editor, forwarding, and audit views.
- Bearer-token `/api/v1` controllers for current PCAP, rules, deployments, support bundle, audit, user, token, repository, and enrollment workflows.
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
| `/sensors/:id` | Sensor detail, health, readiness, capture, storage, forwarding summary, and sensor actions. |
| `/enrollment` | Enrollment queue and approval workflow. |
| `/pools` | Pool list. |
| `/pools/new` | Pool creation. |
| `/pools/:id` | Pool overview, deployment entry points, rule/BPF state, and delete confirmation. |
| `/pools/:id/sensors` | Pool sensor assignment/removal. |
| `/pools/:id/config` | Pool desired configuration. |
| `/pools/:id/forwarding` | Pool Vector forwarding sink overview and schema mode controls. |
| `/pools/:id/forwarding/sinks/new` | Forwarding sink creation form. |
| `/pools/:id/forwarding/sinks/:sink_id/edit` | Forwarding sink edit form. |
| `/pools/:id/bpf` | Pool BPF filter editor. |
| `/pools/:id/deployments` | Pool deployment history. |
| `/pools/:id/drift` | Pool drift summary. |
| `/deployments` | Desired-state deployment list. |
| `/deployments/:id` | Deployment detail, cancel, and rollback entry points. |
| `/pcap-config` | Current PCAP configuration screen. |
| `/pcap` and `/pcap/search` | Browser PCAP search and carve submission. |
| `/pcap/requests` | PCAP request history. |
| `/pcap/requests/:id` | PCAP request detail, status, and download entry point. |
| `/pcap/requests/:id/manifest` | Chain-of-custody manifest view. |
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
| `/api/docs` | Local Public API documentation UI backed by `/api/v1/openapi.json`. |

Config Manager API routes:

| Route | Protection | Purpose |
|---|---|---|
| `GET /api/v1/openapi.json` | Public by default; browser auth optional through hardened docs config | Raw OpenAPI 3.0 document for bearer-token Public API routes. |
| `POST /api/v1/enrollments/:id/approve` | Bearer token, `enrollment:manage` | Approve enrollment through the Public API. |
| `POST /api/v1/enrollments/:id/deny` | Bearer token, `enrollment:manage` | Deny enrollment through the Public API. |
| `/api/v1/pcap/...` | Bearer token, `pcap:configure/search/download` | PCAP config, carve request, history, manifest, and download API. |
| `/api/v1/rules...`, `/api/v1/rulesets`, `/api/v1/repositories` | Bearer token, `sensors:view`, `rules:manage`, or `rules:deploy` | Rule store, ruleset, repository, and deployment entry points. |
| `/api/v1/deployments...` | Bearer token, `sensors:view` or `deployments:manage` | Deployment list/detail/create/cancel/rollback API. |
| `POST /api/v1/support-bundles` | Bearer token, `bundle:download` | Request a support bundle through the Public API. |
| `/api/v1/audit...` | Bearer token, `audit:view` or `audit:export` | Audit list and export API. |
| `/api/v1/admin/users`, `/api/v1/admin/api-tokens` | Bearer token, `users:manage` or `tokens:manage` | Admin user and API token creation API. |
| `POST /api/v1/enroll` | Bootstrap token | Sensor enrollment request. |
| `GET /api/v1/enroll/status` | Bootstrap token/pod lookup | Enrollment polling. |
| `GET /api/v1/health/:pod_id` | mTLS | Sensor health lookup. |
| `POST /api/v1/enrollment/:id/approve` | mTLS | Approve enrollment. |
| `POST /api/v1/enrollment/:id/deny` | mTLS | Deny enrollment. |
| `GET /api/v1/crl` | mTLS | Certificate revocation list. |

Bearer-token Public API routes include `X-API-Version: v1`, request IDs on JSON error responses, per-token rate limiting by API token ID with a default of 100 requests per minute, and request-level audit entries that avoid logging raw bearer tokens or request bodies.

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

Implementation should follow the spec order in `.kiro/specs/README.md`. The single-site pilot MVP release gate is now the implemented sensor stack plus authenticated manager workflows for fleet health, sensor detail, pools, deployments, rules, BPF, forwarding, browser PCAP search/retrieval, support bundles, audit visibility, and current bearer-token API controllers. Forwarding telemetry remains placeholder-only until HealthReport includes sink runtime metrics.

New public automation endpoints should use `/api/v1`. Internal Sensor Agent routes can stay separate, but public docs must distinguish bearer-token Public API routes from mTLS/internal control routes.
