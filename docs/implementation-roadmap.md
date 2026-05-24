# Implementation Roadmap

This document connects the current codebase to the specs that should guide implementation work.

## Source Of Truth

- `docs/` describes the current supported operator and architecture model.
- `specs/` describes planned product behavior and implementation tasks.
- `specs/README.md` is the canonical spec index, dependency order, API versioning rule, and permission catalog.

When these disagree, update the spec first if the behavior is planned, then update `docs/` once the implementation is real enough for operators or contributors to rely on it.

## Single-site Production Pilot MVP Target

RavenWire's current MVP target is a single-site production pilot: the smallest release that is useful to another operator without hand-holding for one manager/sensor deployment. It is broader than the original capture-plane MVP, but it is not yet an enterprise production release.

The single-site pilot MVP includes:

- A single supported install/run/validate path: `sensorctl` plus rootful Podman Quadlet units.
- Automatic first-run enrollment for the local manager/sensor path and manual enrollment for split deployments.
- Authenticated Config Manager access, password-change support, route guards, role policy checks, and an audit trail for manager mutations.
- Fleet dashboard, sensor detail pages, stale/offline handling, and support bundle generation/download.
- Sensor pools with sensor assignment/removal, desired pool configuration, deployment history, and drift views.
- Desired-state deployment tracking, rollback entry points, drift detection, and real-time update plumbing.
- Rule repository, rule store, ruleset, pool assignment, and rule deployment entry points.
- Pool-level BPF filter editor with validation, versioning, reset, and restart-required surfacing.
- Pool-level Vector forwarding sink management with encrypted secrets, schema mode selection, RBAC/audit coverage, and explicit deployment semantics.
- Alert-driven PCAP plumbing in the sensor stack, manager PCAP configuration, and browser PCAP search/history/detail/manifest/download workflows.
- Implemented bearer-token `/api/v1` Public API controllers for current operator workflows, with local OpenAPI documentation, per-token rate limiting, request-level API audit entries, and route/spec consistency checks.
- Browser E2E smoke/full profiles that run against a real test server and gate browser-visible workflows.

The current validated state is a single-site pilot MVP candidate, not a broader production/enterprise release. Forwarding telemetry from HealthReport is still placeholder-only. Platform alerting, historical metrics, health baselines, live data-flow visualization, canary rollouts, detection-content lifecycle, offline update bundles, production packaging, and multi-manager HA remain roadmap work until explicitly pulled forward.

## Current Implementation

The repo currently supports:

- `sensorctl` install/start/stop/restart/status/logs/uninstall/test, including opt-in `--pilot-hardening` manager secret generation.
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
- Bearer-token `/api/v1` controllers for enrollment actions, PCAP, rule/repository/ruleset operations, deployments, support bundle requests, audit list/export, admin user creation, and API token creation.

The supported local validation path is `sensorctl test`. Browser-visible manager workflows are validated with the Playwright E2E suite in `e2e/` against the configured test server. The latest recorded full local/server/E2E validation was commit `6bfded4` on 2026-05-23. There is no Compose, Vagrant, or separate capture harness to maintain.

## MVP Release Gates

Before calling the single-site pilot MVP release-ready, keep these gates closed:

- Keep the completed MVP subset of `auth-rbac-audit` covered: admin user management, API token management UI, audit filters/pagination/detail/export, browser route permission checks, role-based UI visibility, and audit coverage for state-changing workflows are now implemented for the browser MVP surface.
- Treat implemented bearer-token Public API controllers and local OpenAPI docs as current surface. Keep adding route/spec, permission, envelope, rate-limit, and audit tests whenever new API routes are added.
- Keep the full browser E2E suite passing against the test server and add E2E coverage for any newly completed browser workflow.
- Run the full regression gate: `sensorctl test && (cd e2e && npm run test:full)`.
- Keep the test server clean after E2E runs: no lingering `e2e-` pools, rulesets, repositories, or other tracked records.
- Update user-facing docs when a route or workflow becomes supported enough for operators.
- For production-pilot installs, use `sensorctl install --pilot-hardening`, keep `/etc/ravenwire/manager.env` root-only, and verify generated/operator secrets are stored in the site password vault.
- Complete a pilot runbook pass before tagging: service health, `sensorctl test`, deployed full E2E, no lingering `e2e-` data, docs consistency, backup, restore drill, rollback validation, storage/PCAP retention sizing, and cleanup audit.
- Keep distribution private/internal until a public project license is selected.

## Spec-First Post-MVP Gate

Post-MVP implementation starts from feature specs, not from roadmap prose alone. This spec-first gate requires verifying that the spec directory exists with `requirements.md`, `design.md`, and `tasks.md` before starting any new product branch; create those files first if they are missing.

If a spec already exists, reconcile stale assumptions before code changes. For Platform Alert Center, review `specs/platform-alert-center/` before implementation and keep forwarding sink runtime telemetry deferred or disabled until HealthReport exposes real sink runtime metrics.

## Production Pilot Hardening

These gaps do not block a controlled single-site pilot, but they do block a broader production release:

- The default lab/test install still uses `MIX_ENV=dev` and demo manager credentials for repeatable test-server behavior. Production-pilot installs must use `sensorctl install --pilot-hardening`, which writes `/etc/ravenwire/manager.env` with generated/operator `SECRET_KEY_BASE`, `RAVENWIRE_ADMIN_USER`, `RAVENWIRE_ADMIN_PASSWORD`, `RAVENWIRE_SINK_ENCRYPTION_KEY`, and authenticated API docs settings.
- TLS/proxy/firewall guidance, backup/restore of `/data/config_manager`, `/data/ca`, and `/etc/ravenwire`, upgrade/redeploy validation, rollback validation, storage sizing, PCAP retention sizing, and cleanup-audit steps are documented as the pilot runbook in `docs/operations.md` and must be executed before tagging a stable pilot.
- Release metadata is currently private/internal distribution. A public release remains incomplete until a project license is selected.

## Post-MVP Roadmap

These areas are specified but should not be assumed complete in the current app:

- Forwarding telemetry from HealthReport and sink-runtime delivery health beyond the current placeholder UI.
- Additional Public API controllers for sensors, pools, forwarding, and BPF once those automation routes are intentionally added.
- Platform alert center.
- Historical metrics, health baselines, and live data-flow visualization.
- Canary deployments and detection content lifecycle management.
- Offline update bundle import.
- Multi-manager HA status.

## Implementation Order

| Order | Spec | Status | Why it comes here |
|---:|---|---|---|
| 1 | `auth-rbac-audit` | Browser MVP implemented; bearer-token `/api/v1` controllers exist for current workflows, with local OpenAPI docs, per-token rate limiting, and request-level API audit entries now implemented. | Establishes users, sessions, roles, permission checks, API token scopes, and audit events. |
| 2 | `sensor-detail-page`, `sensor-pool-management` | Implemented for MVP; optional/deeper tests remain. | Creates the fleet navigation spine and grouping model used by later workflows. |
| 3 | `deployment-tracking` | Implemented for MVP. | Adds desired-state snapshots, rollout state, rollback, and drift detection. |
| 4 | `rule-store-management`, `bpf-filter-editor` | Implemented for MVP. | Adds the main configurable detection and capture controls. |
| 5 | `e2e-browser-test-suite` | Implemented and required for browser-visible workflow completion. | Provides real-browser regression coverage against the deployed test server. |
| 6 | `vector-forwarding-mgmt` | Implemented for the browser MVP surface with pool-level sink CRUD, encrypted secrets, schema mode selection, connection test dispatch, RBAC/audit integration, sensor detail summary, telemetry placeholder, and full-profile E2E coverage. | Adds operator-managed forwarding sinks beyond the baseline Vector config. |
| 7 | `pcap-search-retrieval` | Implemented and full-profile E2E verified against the test server. | Completes the operator investigation loop using existing sensor PCAP plumbing. |
| 8 | `public-api-docs` | Implemented for the current Public API surface: OpenAPI JSON, local `/api/docs`, version headers, docs auth config, request IDs on Public API errors, per-token rate limiting, request-level API audit entries, and route/spec tests. | Documents and stabilizes the current automation surface before more product expansion. |
| 9 | `platform-alert-center`, `historical-metrics`, `health-baselines`, `live-data-flow-viz` | Not started; post-MVP. | Adds platform-native alerting and observability workflows after the pilot API/documentation gap is closed. |
| 10 | `canary-deploys`, `detection-content-lifecycle`, `offline-update-bundle`, `multi-manager-ha` | Not started; post-MVP. | Adds advanced rollout, air-gap, content lifecycle, and production operations. |

The lower-level `network-sensor-stack`, `network-sensor-stack/interface-switching`, and `sensor-stack-production-hardening` specs define capture-plane behavior that higher-level UI and management-plane specs should reference rather than redefine.

The next post-MVP branch should begin with Platform Alert Center. Its spec exists, but implementation must first confirm which alert rules can be backed by current health reports and system events; Vector sink-down behavior remains placeholder-only until forwarding telemetry is implemented.

## Shared Contracts

Public API routes must be versioned under `/api/v1`. Do not add new public automation routes under an unversioned `/api` prefix.

The Sensor Agent control API is internal and mTLS-oriented. Keep those routes separate from bearer-token Public API routes in code and documentation.

Every new Public API endpoint must land with matching OpenAPI path/schema updates, route/spec consistency coverage, permission tests, envelope/pagination/error tests, rate-limit coverage where applicable, and request-level audit assertions. Do not add speculative API endpoints ahead of implemented product behavior.

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
