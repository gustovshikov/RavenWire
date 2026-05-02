# Implementation Plan: Public API Documentation

## Overview

Implement a versioned `/api/v1` Public API documentation layer with OpenAPI 3.0 JSON, local Swagger UI, consistent response envelopes, bearer token auth, RBAC scope documentation, request IDs, rate limiting, and audit logging.

## Tasks

- [ ] 1. Add API support modules
  - [ ] 1.1 Create `ConfigManagerWeb.Api.Errors`
  - [ ] 1.2 Create `ConfigManagerWeb.Api.Pagination`
  - [ ] 1.3 Create `ConfigManagerWeb.Api.Schemas`
  - [ ] 1.4 Create `ConfigManagerWeb.Api.Spec`
  - _Requirements: 1.1, 1.4, 1.5, 5.8, 6.1-6.6_

- [ ] 2. Add `/api/v1` router conventions
  - [ ] 2.1 Add Public API scope under `/api/v1`
  - [ ] 2.2 Add `X-API-Version: v1` response plug for the Public API scope
  - [ ] 2.3 Return 404 for unsupported prefixes such as `/api/v2`
  - [ ] 2.4 Confirm no new unversioned `/api/...` Public API routes are introduced
  - _Requirements: 3.1-3.5_

- [ ] 3. Implement OpenAPI JSON endpoint
  - [ ] 3.1 Implement `OpenApiController` serving `/api/v1/openapi.json`
  - [ ] 3.2 Include title, version, server URL, bearer auth scheme, contact info, schemas, examples, and required permissions
  - [ ] 3.3 Add configuration option to require auth for docs in hardened deployments
  - [ ] 3.4 Add tests for valid OpenAPI 3.0 structure
  - _Requirements: 1.1-1.6_

- [ ] 4. Implement local API docs UI
  - [ ] 4.1 Vendor Swagger UI assets into static assets
  - [ ] 4.2 Serve `/api/docs`
  - [ ] 4.3 Configure Swagger UI to load `/api/v1/openapi.json`
  - [ ] 4.4 Support Bearer token entry through the Swagger authorization dialog
  - [ ] 4.5 Add test proving no CDN assets are referenced
  - _Requirements: 2.1-2.6_

- [ ] 5. Implement initial read endpoints
  - [ ] 5.1 Add sensor list/detail/health controllers
  - [ ] 5.2 Add pool list/detail/sensor membership controllers
  - [ ] 5.3 Add deployment list/detail controllers
  - [ ] 5.4 Add PCAP request list/detail, carve creation, download, and manifest export controllers when pcap-search-retrieval context is available
  - [ ] 5.5 Add rule/ruleset/repository list and detail controllers
  - [ ] 5.6 Add audit list controller
  - [ ] 5.7 Document each endpoint in OpenAPI
  - _Requirements: 5.1-5.6, 5.8, 5.9_

- [ ] 6. Implement write endpoint documentation and controllers where backing contexts exist
  - [ ] 6.1 Add deployment create/cancel/rollback endpoints
  - [ ] 6.2 Omit forwarding and BPF endpoints until their contexts are implemented
  - [ ] 6.3 Ensure all write endpoints use canonical RBAC permissions from auth-rbac-audit
  - _Requirements: 4.1-4.7, 5.3, 5.7_

- [ ] 7. Add API authentication, rate limiting, and audit
  - [ ] 7.1 Use existing API token authentication from auth-rbac-audit
  - [ ] 7.2 Apply token scoped permissions to every protected endpoint
  - [ ] 7.3 Add per-token rate limit with default 100 requests/minute
  - [ ] 7.4 Record audit entries for authenticated API requests
  - [ ] 7.5 Redact Authorization headers, bearer tokens, secrets, and credential-bearing request bodies
  - _Requirements: 4.1-4.7_

- [ ] 8. Add consistency and safety tests
  - [ ] 8.1 Test OpenAPI documented routes match Phoenix router routes
  - [ ] 8.2 Test every documented protected route uses a canonical permission
  - [ ] 8.3 Test consistent success, pagination, and error envelopes
  - [ ] 8.4 Test request ID appears in headers and error bodies
  - [ ] 8.5 Test unsupported API versions return 404
  - _Requirements: 1.4, 3.4, 5.8, 6.1-6.6_

- [ ] 9. Final verification
  - [ ] 9.1 Run formatter
  - [ ] 9.2 Run API controller, OpenAPI, router consistency, and docs UI tests
  - [ ] 9.3 Manually open `/api/docs` in dev and confirm the spec loads from `/api/v1/openapi.json`
  - [ ] 9.4 Confirm deferred capabilities are omitted from the generated OpenAPI paths
  - _Requirements: 7.1-7.5_

## Notes

- Public API docs must distinguish bearer-token Public API routes from internal Sensor Agent mTLS routes.
- Documenting an endpoint means it is implemented and tested; planned endpoints stay out of OpenAPI until their contexts exist.
