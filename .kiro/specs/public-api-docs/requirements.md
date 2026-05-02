# Requirements Document: Public API Documentation

## Introduction

The RavenWire Config Manager exposes a web UI built with Phoenix LiveView, but it does not currently provide a documented, versioned REST API for external automation. Operators who want to integrate the Config Manager with external tools (Splunk workflow actions, CI/CD pipelines, SOAR platforms, custom scripts) must reverse-engineer the LiveView event handlers or use the internal Sensor Agent Client API, neither of which is stable or documented.

This feature adds public API documentation generated from the same Phoenix backend that serves the UI. An OpenAPI 3.0 specification is auto-generated from the existing API controllers and context modules, and interactive documentation is served at `/api/docs` using Swagger UI or a similar tool. The API is versioned under a `/api/v1/` prefix, and authentication uses the existing API token system from the auth-rbac-audit spec.

The API surface mirrors the operations available in the UI where stable backend contexts already exist: sensor management, pool management, deployment operations, rule store management, forwarding configuration, BPF profile management, and audit log queries. The API does not introduce new capabilities beyond what the UI provides; endpoints for feature areas that are not implemented yet are deferred until those contexts exist.

## Glossary

- **Config_Manager**: The Phoenix/LiveView web application that manages the RavenWire sensor fleet.
- **Public_API**: The versioned REST API exposed by the Config_Manager for external automation and integration, served under the `/api/v1/` prefix.
- **OpenAPI_Spec**: An OpenAPI 3.0 specification document (JSON) that describes the Public_API's endpoints, request/response schemas, authentication requirements, and error formats.
- **API_Docs_Page**: An interactive API documentation page served at `/api/docs` that renders the OpenAPI_Spec using Swagger UI or a similar tool, allowing operators to explore and test API endpoints.
- **API_Version**: The version prefix for the Public_API (currently `v1`). Used to support future breaking changes without disrupting existing integrations.
- **API_Token**: A bearer token with scoped permissions and optional expiry, from the auth-rbac-audit spec. Used to authenticate Public_API requests.
- **API_Controller**: A Phoenix controller module that handles REST API requests, delegates to context modules, and returns JSON responses.
- **RBAC_Gate**: The runtime permission check from the auth-rbac-audit spec that enforces role-based access on API endpoints.
- **Audit_Entry**: An append-only record in the `audit_log` table.
- **Rate_Limit**: A per-token request rate limit to prevent API abuse.

## Requirements

### Requirement 1: OpenAPI Specification Generation

**User Story:** As a developer integrating with the Config Manager, I want an OpenAPI 3.0 specification available, so that I can generate client libraries and understand the API contract.

#### Acceptance Criteria

1. THE Config_Manager SHALL generate an OpenAPI 3.0 specification document describing all Public_API endpoints.
2. THE OpenAPI_Spec SHALL be served at `/api/v1/openapi.json` as a JSON document accessible without authentication, unless an application configuration setting requires authentication for documentation in hardened deployments.
3. THE OpenAPI_Spec SHALL include: API title ("RavenWire Config Manager API"), version (`v1`), server URL, authentication scheme (Bearer token), and contact information.
4. THE OpenAPI_Spec SHALL describe each API endpoint with: HTTP method, path, summary, description, request parameters, request body schema (where applicable), response schemas for success and error cases, required permissions, and example request/response pairs.
5. THE OpenAPI_Spec SHALL define reusable schema components for common data types: Sensor_Pod, Sensor_Pool, Deployment, Suricata_Rule, Ruleset, BPF_Profile, Forwarding_Sink, Audit_Entry, and pagination metadata.
6. THE OpenAPI_Spec SHALL be generated from annotations or schema definitions co-located with the API controller modules, so that the spec stays in sync with the implementation.

### Requirement 2: Interactive API Documentation

**User Story:** As a developer integrating with the Config Manager, I want interactive API documentation, so that I can explore endpoints and test requests directly from the browser.

#### Acceptance Criteria

1. THE Config_Manager SHALL serve an interactive API documentation page at `/api/docs` using Swagger UI or a functionally equivalent tool.
2. THE API_Docs_Page SHALL render the OpenAPI_Spec with a navigable endpoint list, request/response schema display, and a "Try it out" feature for making test requests.
3. THE API_Docs_Page SHALL support entering a Bearer token for authenticated requests via the Swagger UI authorization dialog.
4. THE API_Docs_Page SHALL be accessible without authentication for documentation browsing, but "Try it out" requests SHALL require a valid API_Token.
5. THE API_Docs_Page SHALL display the API version prominently and link to the raw OpenAPI_Spec JSON.
6. THE Config_Manager SHALL serve the Swagger UI assets from the application's static assets, not from an external CDN, to support air-gapped deployments.

### Requirement 3: API Versioning

**User Story:** As a developer integrating with the Config Manager, I want the API versioned, so that future changes do not break my existing integrations.

#### Acceptance Criteria

1. THE Config_Manager SHALL prefix all Public_API endpoints with `/api/v1/`, except documentation endpoints such as `/api/docs`.
2. THE Config_Manager SHALL include the API version in the OpenAPI_Spec's `info.version` field.
3. THE Config_Manager SHALL document the API versioning strategy: the `v1` prefix will remain stable for the current major version; breaking changes will introduce a new version prefix (e.g., `/api/v2/`); non-breaking additions (new endpoints, new optional fields) will be added to the current version without a version bump.
4. THE Config_Manager SHALL return a `404 Not Found` response for requests to unsupported API version prefixes (e.g., `/api/v2/` before v2 exists).
5. THE Config_Manager SHALL include an `X-API-Version: v1` response header on all Public_API responses.

### Requirement 4: API Authentication

**User Story:** As a developer integrating with the Config Manager, I want to authenticate API requests using existing API tokens, so that I can use the same credentials for UI and API access.

#### Acceptance Criteria

1. THE Config_Manager SHALL authenticate Public_API requests using Bearer tokens in the `Authorization` header, using the existing API_Token system from the auth-rbac-audit spec.
2. WHEN a request includes a valid API_Token, THE Config_Manager SHALL apply the token's scoped permissions to authorize the request, consistent with the RBAC model.
3. WHEN a request does not include an `Authorization` header or includes an invalid/expired token, THE Config_Manager SHALL return a `401 Unauthorized` JSON response with an error message.
4. WHEN a request includes a valid token but the token lacks the required permission for the endpoint, THE Config_Manager SHALL return a `403 Forbidden` JSON response with an error message indicating the required permission.
5. THE Config_Manager SHALL record an Audit_Entry for each authenticated API request, including the API_Token name, the endpoint, the HTTP method, and the result.
6. THE Config_Manager SHALL support a configurable rate limit per API_Token (default: 100 requests per minute) and return `429 Too Many Requests` when the limit is exceeded.
7. THE Config_Manager SHALL NOT record full Authorization header values, bearer tokens, request bodies containing secrets, or plaintext credentials in API audit entries or logs.

### Requirement 5: API Endpoint Coverage

**User Story:** As a developer integrating with the Config Manager, I want API endpoints covering the same operations available in the UI, so that I can automate any management task.

#### Acceptance Criteria

1. THE Public_API SHALL expose endpoints for sensor management: list sensors, get sensor detail, get sensor health.
2. THE Public_API SHALL expose endpoints for pool management: list pools, get pool detail, list pool sensors.
3. THE Public_API SHALL expose endpoints for deployment operations: list deployments, get deployment detail, create deployment, cancel deployment, initiate rollback.
4. THE Public_API SHALL expose endpoints for rule store management: list rules, get rule, list rulesets, get ruleset, list repositories.
5. THE Public_API SHALL expose endpoints for PCAP workflows when the pcap-search-retrieval context is implemented: list carve requests, create carve request, get carve request detail, download completed PCAP, and export custody manifest.
6. THE Public_API SHALL expose endpoints for audit log queries: list audit entries with filtering by action, actor, target, and date range.
7. THE Public_API SHALL expose forwarding and BPF endpoints only when the corresponding forwarding and BPF management contexts are implemented; until then, the OpenAPI_Spec SHALL omit those endpoints rather than documenting non-functional routes.
8. THE Public_API SHALL use consistent JSON response formats: success responses with a `data` key, error responses with an `error` key containing `code` and `message` fields, and paginated responses with `data`, `meta` (page, page_size, total_count, total_pages) keys.
9. THE Public_API SHALL use standard HTTP status codes: `200` for success, `201` for created, `204` for no content, `400` for bad request, `401` for unauthorized, `403` for forbidden, `404` for not found, `409` for conflict, `422` for validation errors, `429` for rate limited, `500` for internal server error.

### Requirement 6: API Error Responses

**User Story:** As a developer integrating with the Config Manager, I want consistent, informative error responses, so that I can handle errors programmatically.

#### Acceptance Criteria

1. THE Public_API SHALL return error responses as JSON objects with the structure: `{"error": {"code": "string", "message": "string", "details": {}}}`.
2. THE `code` field SHALL use machine-readable error codes (e.g., `validation_error`, `not_found`, `active_deployment_exists`, `permission_denied`, `rate_limited`).
3. THE `message` field SHALL contain a human-readable error description.
4. FOR validation errors (`422`), THE `details` field SHALL contain a map of field names to error messages, consistent with Ecto changeset error formatting.
5. THE Public_API SHALL NOT include stack traces, internal module names, or database error details in error responses.
6. THE Public_API SHALL include a stable request identifier in error responses and logs so operators can correlate client-visible failures with server-side diagnostics without exposing internals.

### Requirement 7: Deferred Capabilities

**User Story:** As a product owner, I want deferred API capabilities documented, so that the team knows what is planned for future enhancements.

#### Acceptance Criteria

1. THE Config_Manager SHALL NOT implement webhook/event subscription endpoints in this feature. Webhook notifications for deployment events and alerts are deferred to a future enhancement.
2. THE Config_Manager SHALL NOT implement GraphQL or gRPC API interfaces in this feature. Only REST/JSON is supported. Alternative API protocols are deferred.
3. THE Config_Manager SHALL NOT implement API key rotation endpoints in this feature. API token management is handled through the existing `/admin/api-tokens` UI from the auth-rbac-audit spec. Programmatic token management is deferred.
4. THE Config_Manager SHALL NOT implement bulk operation endpoints (e.g., bulk deploy to multiple pools) in this feature. Bulk operations are deferred to a future API enhancement.
5. THE Config_Manager SHALL NOT implement API usage analytics or per-endpoint metrics in this feature. API observability is deferred.
