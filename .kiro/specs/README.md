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
5. `pcap-search-retrieval`, `platform-alert-center`, `historical-metrics`, `health-baselines`, and `live-data-flow-viz` — operator workflows and observability.
6. `canary-deploys`, `detection-content-lifecycle`, `offline-update-bundle`, `public-api-docs`, and `multi-manager-ha` — advanced rollout, air-gap, integration, and production operations.

The existing `network-sensor-stack` and `sensor-stack-production-hardening` specs define lower-level Sensor Agent and capture-plane behavior. UI and management-plane specs should reference those contracts rather than redefining capture semantics.

## Documentation Rules

- Use exact route paths and permission strings from `auth-rbac-audit`.
- Use `/api/v1` for Public API examples.
- State whether a route is read-only, write-capable, or action-only.
- Do not expose secret values in examples, snapshots, bundles, audits, or API schemas.
- Cross-spec dependencies should be named explicitly in the Introduction or Glossary.
- Deferred functionality belongs in a `Deferred Capabilities` requirement rather than being left ambiguous.
