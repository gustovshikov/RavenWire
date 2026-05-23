# RavenWire Specs Source of Truth

This directory is the implementation source of truth for planned RavenWire features. Each feature spec should contain:

- `requirements.md` — user-facing behavior and acceptance criteria.
- `design.md` — implementation architecture, data model, interfaces, route map, correctness properties, and test strategy.
- `tasks.md` — implementation checklist ordered so dependencies land before consumers.
- `.config.kiro` — unique Kiro spec metadata.

## Shared Contracts

The `auth-rbac-audit` spec owns the canonical RBAC model. Downstream specs may introduce a feature-specific permission only by adding it to `auth-rbac-audit` Requirement 4, the Policy design, and the route/API catalog.

Canonical permissions:

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

`alerts:view` is a UI/display alias for `sensors:view`, not a stored permission.

Public API routes are versioned under `/api/v1`. New public automation endpoints must not be added under an unversioned `/api` prefix. Existing Sensor Agent enrollment and mTLS endpoints may remain where their owning specs place them, but Public API documentation must clearly distinguish bearer-token Public API routes from internal Sensor Agent routes.

## Implementation Order

1. `auth-rbac-audit` — authentication, roles, route guards, API token scopes, audit log.
2. `sensor-detail-page` and `sensor-pool-management` — navigation spine for later fleet features.
3. `deployment-tracking` — desired-state snapshots, deployments, rollback, and drift.
4. `rule-store-management`, `bpf-filter-editor`, and `vector-forwarding-mgmt` — configurable content and forwarding state.
5. `e2e-browser-test-suite` — real-browser regression coverage against the deployed test server before expanding additional browser workflows.
6. `pcap-search-retrieval` — first post-MVP operator investigation workflow; backend PCAP request/custody/API plumbing and browser search/retrieval are implemented locally, pending test-server E2E verification.
7. `platform-alert-center`, `historical-metrics`, `health-baselines`, and `live-data-flow-viz` — platform observability workflows after PCAP retrieval.
8. `canary-deploys`, `detection-content-lifecycle`, `offline-update-bundle`, `public-api-docs`, and `multi-manager-ha` — advanced rollout, air-gap, integration, and production operations.

The existing `network-sensor-stack` and `sensor-stack-production-hardening` specs define lower-level Sensor Agent and capture-plane behavior. UI and management-plane specs should reference those contracts rather than redefining capture semantics.

## Professional MVP Gate

The MVP release target is a professional sensor/manager product slice, not only a running capture stack. The MVP includes the completed lower-level sensor stack plus authenticated manager workflows for dashboard health, sensor detail, pool management, desired-state deployments and drift, rule store management, BPF profile editing, Vector forwarding sink management, support bundles, audit visibility, and real-browser E2E coverage.

Before treating the MVP as release-ready:

- Keep the MVP hardening subset of `auth-rbac-audit` covered: browser route/event permission checks, role-aware UI visibility, admin user/token management, audit filters/pagination/detail/export, and audit coverage for state-changing workflows are implemented for the browser MVP surface.
- Defer token-authenticated Public API controllers explicitly unless they are pulled into the MVP; do not blur those future bearer-token APIs with the existing Sensor Agent mTLS API.
- Keep `sensorctl test` and the relevant browser E2E profile passing against the configured Test_Server.
- Add or update E2E coverage for every completed browser-visible workflow.
- Document any feature that is intentionally deferred in its owning spec rather than leaving it implied.

Post-MVP roadmap work includes forwarding telemetry from HealthReport, PCAP browser search/retrieval test-server verification, platform alerts, historical metrics, health baselines, live data-flow visualization, canary deploys, detection-content lifecycle, offline update bundles, public API docs, and multi-manager HA. PCAP backend request/custody/API plumbing and browser workflow are implemented locally; the remaining gap is full-profile real-browser validation against the deployed test server.

## Documentation Rules

- Use exact route paths and permission strings from `auth-rbac-audit`.
- Use `/api/v1` for Public API examples.
- State whether a route is read-only, write-capable, or action-only.
- Do not expose secret values in examples, snapshots, bundles, audits, or API schemas.
- Cross-spec dependencies should be named explicitly in the Introduction or Glossary.
- Deferred functionality belongs in a `Deferred Capabilities` requirement rather than being left ambiguous.

## Testing Requirements

- Every behavior change must include or update unit tests for the changed module or workflow unless the implementation notes document why a unit test is not practical.
- Broaden coverage with integration or property tests when a change crosses route guards, parsers, validators, LiveView workflows, API contracts, or deployment validation paths.
- Browser-visible workflow changes must include or update end-to-end browser coverage from `e2e-browser-test-suite` and pass against the configured Test_Server unless an explicit exception is documented in the feature notes.
- The full regression suite must include unit tests, integration tests, property tests, and the real-browser smoke or full E2E profile appropriate to the changed workflow.
