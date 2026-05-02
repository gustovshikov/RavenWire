# Implementation Roadmap

This document connects the current codebase to the specs that should guide implementation work.

## Source Of Truth

- `docs/` describes the current supported operator and architecture model.
- `.kiro/specs/` describes planned product behavior and implementation tasks.
- `.kiro/specs/README.md` is the canonical spec index, dependency order, API versioning rule, and permission catalog.

When these disagree, update the spec first if the behavior is planned, then update `docs/` once the implementation is real enough for operators or contributors to rely on it.

## Current Foundation

The repo currently supports:

- `sensorctl` install/start/stop/restart/status/logs/uninstall/test.
- Rootful Podman plus systemd Quadlet deployment from `deploy/quadlet/`.
- Local dual-pod bring-up for Config Manager and a sensor pod.
- Automatic first-run enrollment for the single-host dual-pod path.
- Manual `sensorctl enroll` for split manager/sensor deployments.
- Sensor Agent mTLS control API with an allowlisted route set.
- Health collection, drop counters, support bundles, CRL loading, and request IDs.
- Zeek, Suricata, Vector, and `pcap_ring_writer` baseline config.
- Alert-driven PCAP ingestion, indexing, carving, and custody metadata foundations.
- Early manager UI routes for dashboard, enrollment, PCAP config, rules, and support bundles.

The supported validation path is `sensorctl test`. There is no Compose, Vagrant, or separate capture harness to maintain.

## Not Yet Productized

These areas are specified but should not be assumed complete in the current app:

- Production authentication, sessions, RBAC, API tokens, and audit log.
- Sensor detail pages and fleet navigation beyond the early dashboard.
- Sensor pool management.
- Desired-state deployment tracking, rollback, and drift detection.
- Rule store lifecycle and approval workflow.
- BPF filter editor.
- Vector forwarding sink management.
- PCAP search/retrieval UI and public download flow.
- Platform alert center.
- Historical metrics, health baselines, and live data-flow visualization.
- Canary deployments and detection content lifecycle management.
- Offline update bundle import.
- Public API documentation site and OpenAPI generation.
- Multi-manager HA status.

## Implementation Order

| Order | Spec | Why it comes here |
|---:|---|---|
| 1 | `auth-rbac-audit` | Establishes users, sessions, roles, permission checks, API tokens, and audit events before broadening the app surface. |
| 2 | `sensor-detail-page`, `sensor-pool-management` | Creates the fleet navigation spine and grouping model used by later workflows. |
| 3 | `deployment-tracking` | Adds desired-state snapshots, rollout state, rollback, and drift detection. |
| 4 | `rule-store-management`, `bpf-filter-editor`, `vector-forwarding-mgmt` | Adds the main configurable content and forwarding controls. |
| 5 | `pcap-search-retrieval`, `platform-alert-center`, `historical-metrics`, `health-baselines`, `live-data-flow-viz` | Adds operator investigation and observability workflows. |
| 6 | `canary-deploys`, `detection-content-lifecycle`, `offline-update-bundle`, `public-api-docs`, `multi-manager-ha` | Adds advanced rollout, air-gap, integration, documentation, and production operations. |

The lower-level `network-sensor-stack`, `network-sensor-stack/interface-switching`, and `sensor-stack-production-hardening` specs define capture-plane behavior that higher-level UI and management-plane specs should reference rather than redefine.

## Shared Contracts

Public API routes must be versioned under `/api/v1`. Do not add new public automation routes under an unversioned `/api` prefix.

The Sensor Agent control API is internal and mTLS-oriented. Keep those routes separate from bearer-token Public API routes in code and documentation.

The canonical permissions are owned by `auth-rbac-audit`:

```text
dashboard:view
sensors:view
sensor:operate
enrollment:manage
pcap:configure
pcap:search
pcap:download
pools:manage
deployments:manage
rules:deploy
rules:manage
forwarding:manage
bpf:manage
alerts:manage
bundle:download
audit:view
audit:export
users:manage
roles:view
tokens:manage
system:manage
```

`alerts:view` is only a UI/display alias for `sensors:view`; it should not become a stored permission.

## Implementation Rules

- Use the route paths and permission strings from `auth-rbac-audit`.
- Add new feature-specific permissions to `auth-rbac-audit` before using them downstream.
- Keep secrets out of snapshots, support bundles, audit logs, generated OpenAPI examples, and exported manifests.
- Use existing `sensorctl` and Quadlet deployment flows for validation.
- Keep current internal Sensor Agent routes allowlisted.
- Add tests proportional to the blast radius: route guards and policy checks for auth work, property tests for parsers/validators, and LiveView/API tests for user workflows.
