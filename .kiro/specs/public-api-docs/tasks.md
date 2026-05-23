# Implementation Plan: Public API Documentation

## Overview

The bearer-token `/api/v1` Public API controllers already exist for the current
pilot surface: enrollment approval/denial, PCAP config, PCAP search/history/detail,
manifest/download, rules, rulesets, repositories, deployments, support bundle
requests, audit list/export, user creation, and API token creation. This plan now
hardens and documents that implemented surface with OpenAPI 3.0 JSON, local docs
UI, response-envelope documentation, API version headers, request IDs, rate-limit
policy, and route/spec consistency tests. This feature should not add speculative
new management capabilities.

## Tasks

- [x] 1. Confirm current implemented API surface
  - [x] Confirm bearer-token API token authentication is wired for protected `/api/v1` controllers.
  - [x] Confirm permission-specific route scopes exist for enrollment actions, PCAP, rules, deployments, support bundles, audit, users, and API tokens.
  - [x] Confirm API controller tests exist for token auth, PCAP, rules, and route permission matrices.
  - _Requirements: 3.1-3.5, 4.1-4.7, 5.3-5.6_

- [x] 2. Add API support modules
  - [x] 2.1 Create `ConfigManagerWeb.Api.Errors`
  - [x] 2.2 Create `ConfigManagerWeb.Api.Pagination`
  - [x] 2.3 Create `ConfigManagerWeb.Api.Schemas`
  - [x] 2.4 Create `ConfigManagerWeb.Api.Spec`
  - _Requirements: 1.1, 1.4, 1.5, 5.8, 6.1-6.6_

- [x] 3. Harden `/api/v1` router conventions
  - [x] Public API scopes exist under `/api/v1`.
  - [x] Add `X-API-Version: v1` response plug for the Public API scope.
  - [x] Return 404 for unsupported prefixes such as `/api/v2`.
  - [x] Add a route consistency test proving no new unversioned `/api/...` Public API routes are introduced.
  - _Requirements: 3.1-3.5_

- [x] 4. Implement OpenAPI JSON endpoint
  - [x] 4.1 Implement `OpenApiController` serving `/api/v1/openapi.json`
  - [x] 4.2 Include title, version, server URL, bearer auth scheme, contact info, schemas, examples, and required permissions
  - [x] 4.3 Add configuration option to require auth for docs in hardened deployments
  - [x] 4.4 Add tests for valid OpenAPI 3.0 structure
  - _Requirements: 1.1-1.6_

- [x] 5. Implement local API docs UI
  - [x] 5.1 Implement a local no-CDN docs renderer for this API surface.
  - [x] 5.2 Serve `/api/docs`
  - [x] 5.3 Configure the docs UI to load `/api/v1/openapi.json`
  - [x] 5.4 Support Bearer token entry for "Try it out" requests
  - [x] 5.5 Add test proving no CDN assets are referenced
  - _Requirements: 2.1-2.6_

- [x] 6. Document implemented read endpoints
  - [x] Document deployment list/detail controllers.
  - [x] Document PCAP request list/detail, carve creation, download, and manifest export controllers.
  - [x] Document rule/ruleset/repository list controllers.
  - [x] Document audit list controller.
  - [x] Add sensor and pool read controllers only if they are implemented as part of this feature; otherwise omit them from OpenAPI and leave them as future Public API expansion.
  - _Requirements: 5.1-5.6, 5.8, 5.9_

- [x] 7. Document implemented write endpoints
  - [x] Document enrollment approval/denial endpoints.
  - [x] Document PCAP config update and carve request creation endpoints.
  - [x] Document rule deploy, rule/ruleset/repository creation, deployment create/cancel/rollback, support bundle request, audit export, user creation, and API token creation endpoints.
  - [x] Omit forwarding and BPF endpoints until explicit API controllers exist for those contexts.
  - [x] Ensure all documented write endpoints use canonical RBAC permissions from auth-rbac-audit.
  - _Requirements: 4.1-4.7, 5.3, 5.7_

- [x] 8. Harden API authentication, rate limiting, and audit
  - [x] Use existing API token authentication from auth-rbac-audit.
  - [x] Apply token scoped permissions to every protected endpoint.
  - [x] Add or document per-token rate limit with default 100 requests/minute.
  - [x] Verify audit coverage for authenticated API requests and add missing request-level audit entries where required.
  - [x] Redact Authorization headers, bearer tokens, secrets, and credential-bearing request bodies in logs, audits, examples, and generated docs.
  - _Requirements: 4.1-4.7_

- [x] 9. Add consistency and safety tests
  - [x] 9.1 Test OpenAPI documented routes match Phoenix router routes
  - [x] 9.2 Test every documented protected route uses a canonical permission
  - [x] 9.3 Test consistent success, pagination, and error envelopes
  - [x] 9.4 Test request ID appears in headers and error bodies
  - [x] 9.5 Test unsupported API versions return 404
  - _Requirements: 1.4, 3.4, 5.8, 6.1-6.6_

- [ ] 10. Final verification
  - [x] 10.1 Run formatter
  - [x] 10.2 Run API controller, OpenAPI, router consistency, and docs UI tests
  - [x] 10.3 Verify `/api/docs` on the deployed test server and confirm the spec loads from `/api/v1/openapi.json`
  - [x] 10.4 Confirm deferred capabilities are omitted from the generated OpenAPI paths
  - _Requirements: 7.1-7.5_

## Notes

- Public API docs must distinguish bearer-token Public API routes from internal Sensor Agent mTLS routes.
- Documenting an endpoint means it is implemented and tested; planned endpoints stay out of OpenAPI until their contexts exist.
