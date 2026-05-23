# Implementation Roadmap

This document connects the current codebase to the specs that should guide implementation work.

## Source Of Truth

- `docs/` describes the current supported operator and architecture model.
- `.kiro/specs/` describes planned product behavior and implementation tasks.
- `.kiro/specs/README.md` is the canonical spec index, dependency order, API versioning rule, and permission catalog.

When these disagree, update the spec first if the behavior is planned, then update `docs/` once the implementation is real enough for operators or contributors to rely on it.

## Professional MVP Target

RavenWire's professional MVP is the smallest release that is useful to another operator without hand-holding. It is broader than the original capture-plane MVP, but still bounded to one supported deployment path and one manager/sensor operating model.

The professional MVP includes:

- A single supported install/run/validate path: `sensorctl` plus rootful Podman Quadlet units.
- Automatic first-run enrollment for the local manager/sensor path and manual enrollment for split deployments.
- Authenticated Config Manager access, password-change support, route guards, role policy checks, and an audit trail for manager mutations.
- Fleet dashboard, sensor detail pages, stale/offline handling, and support bundle generation/download.
- Sensor pools with sensor assignment/removal, desired pool configuration, deployment history, and drift views.
- Desired-state deployment tracking, rollback entry points, drift detection, and real-time update plumbing.
- Rule repository, rule store, ruleset, pool assignment, and rule deployment entry points.
- Pool-level BPF filter editor with validation, versioning, reset, and restart-required surfacing.
- Pool-level Vector forwarding sink management with encrypted secrets, schema mode selection, RBAC/audit coverage, and explicit deployment semantics.
- Alert-driven PCAP plumbing in the sensor stack and manager PCAP configuration screen.
- Browser E2E smoke/full profiles that run against a real test server and gate browser-visible workflows.

The professional MVP does not include every future operator feature. Forwarding telemetry from HealthReport is still placeholder-only. PCAP search/retrieval is now the first pulled-forward post-MVP target: backend PCAP request/custody/API plumbing exists, but the operator browser search, history, manifest, and download workflow is still in progress. Platform alerting, historical metrics, health baselines, live data-flow visualization, public API documentation, canary rollouts, detection-content lifecycle, offline update bundles, and multi-manager HA remain post-MVP roadmap work until explicitly pulled forward.

## Current Implementation

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
- Authenticated manager UI routes for dashboard, enrollment, sensor detail, pools, deployments, PCAP config, PCAP search/retrieval, rules, BPF, support bundles, and audit browsing.
- Sensor pool management, desired-state deployment tracking, rule store management, BPF profile editing, Vector forwarding sink management, and real-browser E2E coverage.

The supported local validation path is `sensorctl test`. Browser-visible manager workflows are validated with the Playwright E2E suite in `e2e/` against the configured test server. There is no Compose, Vagrant, or separate capture harness to maintain.

## MVP Release Gates

Before calling the professional MVP release-ready, close these gates:

- Keep the completed MVP subset of `auth-rbac-audit` covered: admin user management, API token management UI, audit filters/pagination/detail/export, browser route permission checks, role-based UI visibility, and audit coverage for state-changing workflows are now implemented for the browser MVP surface.
- Explicitly defer token-authenticated Public API controllers from the MVP unless they are pulled forward; the Sensor Agent mTLS API remains separate from future bearer-token automation APIs.
- Keep the full browser E2E suite passing against the test server and add E2E coverage for any newly completed browser workflow.
- Run the full regression gate: `sensorctl test && (cd e2e && npm run test:full)`.
- Keep the test server clean after E2E runs: no lingering `e2e-` pools, rulesets, repositories, or other tracked records.
- Update user-facing docs when a route or workflow becomes supported enough for operators.

## Post-MVP Roadmap

These areas are specified but should not be assumed complete in the current app:

- Forwarding telemetry from HealthReport and sink-runtime delivery health beyond the current placeholder UI.
- PCAP search/retrieval test-server verification and any follow-up hardening from the first full E2E run.
- Platform alert center.
- Historical metrics, health baselines, and live data-flow visualization.
- Canary deployments and detection content lifecycle management.
- Offline update bundle import.
- Public API documentation site and OpenAPI generation.
- Multi-manager HA status.

## Implementation Order

| Order | Spec | Status | Why it comes here |
|---:|---|---|---|
| 1 | `auth-rbac-audit` | Browser MVP implemented; token-authenticated Public API controllers deferred unless pulled forward. | Establishes users, sessions, roles, permission checks, API token scopes, and audit events. |
| 2 | `sensor-detail-page`, `sensor-pool-management` | Implemented for MVP; optional/deeper tests remain. | Creates the fleet navigation spine and grouping model used by later workflows. |
| 3 | `deployment-tracking` | Implemented for MVP. | Adds desired-state snapshots, rollout state, rollback, and drift detection. |
| 4 | `rule-store-management`, `bpf-filter-editor` | Implemented for MVP. | Adds the main configurable detection and capture controls. |
| 5 | `e2e-browser-test-suite` | Implemented and required for browser-visible workflow completion. | Provides real-browser regression coverage against the deployed test server. |
| 6 | `vector-forwarding-mgmt` | Implemented for the browser MVP surface with pool-level sink CRUD, encrypted secrets, schema mode selection, connection test dispatch, RBAC/audit integration, sensor detail summary, telemetry placeholder, and full-profile E2E coverage. | Adds operator-managed forwarding sinks beyond the baseline Vector config. |
| 7 | `pcap-search-retrieval` | Browser workflow implemented locally; pending deployment and full-profile E2E verification. | Completes the operator investigation loop using existing sensor PCAP plumbing. |
| 8 | `platform-alert-center`, `historical-metrics`, `health-baselines`, `live-data-flow-viz` | Not started; post-MVP. | Adds platform-native alerting and observability workflows after PCAP retrieval lands. |
| 9 | `canary-deploys`, `detection-content-lifecycle`, `offline-update-bundle`, `public-api-docs`, `multi-manager-ha` | Not started; post-MVP. | Adds advanced rollout, air-gap, integration, documentation, and production operations. |

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
- Every behavior change must include or update unit tests for the changed module or workflow unless the reason for omitting them is documented in the implementation notes.
- Add tests proportional to the blast radius: route guards and policy checks for auth work, property tests for parsers/validators, and LiveView/API tests for user workflows.
