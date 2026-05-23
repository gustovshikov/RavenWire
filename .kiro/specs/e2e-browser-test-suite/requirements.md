# Requirements Document: End-to-End Browser Test Suite

## Introduction

Recent RavenWire work exposed failures that unit and LiveView tests did not catch, including a production-like browser submitting a LiveView form as a plain HTTP POST because the JavaScript assets were not present in the deployed Config Manager. The system also depends on a real sensor stack reporting health to the manager, which means some operator workflows can only be trusted after they run against a deployed environment.

This feature adds a browser-based end-to-end test suite that runs against the real RavenWire test server. The suite verifies that the Config Manager UI, Phoenix LiveView client, static assets, authentication, pool workflows, sensor health reporting, BPF management, rule management, and deployment-facing pages work together in a real browser against a real deployed stack.

The first required test target is the existing test server at `http://172.16.10.38:4000`, reachable over SSH as `eric@172.16.10.38`. The suite must be configurable so future test servers can be substituted without changing test code.

## Glossary

- **E2E_Test_Suite**: The browser automation suite that validates complete RavenWire workflows through a real browser against a deployed server.
- **Test_Server**: A deployed RavenWire environment used for end-to-end verification. The default Test_Server is `172.16.10.38`.
- **Browser_Runner**: The test runner that launches and controls real browsers. The preferred implementation is Playwright.
- **Preflight_Check**: A non-browser verification step that confirms the Test_Server is reachable, required services are active, static assets are served, and the built-in sensor is reporting health before browser tests begin.
- **Test_Artifact**: A screenshot, trace, video, console log, network log, or structured report produced by a test run, especially on failure.
- **E2E_Test_Data**: Pools, profiles, rules, or other records created by the E2E_Test_Suite using unique names and cleaned up after each run.
- **Built_In_Sensor**: The sensor pod installed with the RavenWire test server and expected to report health to the Config Manager dashboard.

## Requirements

### Requirement 1: Real Test Server Execution

**User Story:** As a RavenWire maintainer, I want the end-to-end suite to run against the real deployed test server, so that browser workflows are validated in the same environment operators manually test.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL run against a configurable base URL supplied by `E2E_BASE_URL`, defaulting in local documentation to `http://172.16.10.38:4000`.
2. THE E2E_Test_Suite SHALL support SSH-based server preflight and cleanup using `E2E_SSH_USER` and `E2E_SSH_HOST`, defaulting in local documentation to `eric` and `172.16.10.38`.
3. THE E2E_Test_Suite SHALL require test credentials to be supplied through environment variables and SHALL NOT store passwords or secrets in source control.
4. THE E2E_Test_Suite SHALL fail fast when the Test_Server is unreachable, returns non-2xx responses for required pages, or does not expose required static assets.
5. THE E2E_Test_Suite SHALL be able to run from a developer workstation without requiring a local RavenWire stack.
6. THE E2E_Test_Suite SHALL leave the Test_Server running after the suite completes, regardless of pass or failure.

### Requirement 2: Server Preflight and Sensor Health

**User Story:** As a RavenWire maintainer, I want the suite to confirm the deployed stack is healthy before browser tests run, so that failures identify environment problems separately from UI regressions.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL verify that the Config Manager HTTP endpoint is reachable before launching browser tests.
2. THE E2E_Test_Suite SHALL verify that the deployed static assets required for Phoenix LiveView are served successfully, including `app.js`, `phoenix.min.js`, and `phoenix_live_view.min.js`.
3. THE E2E_Test_Suite SHALL verify over SSH that required RavenWire services are active on the Test_Server, including Config Manager and the built-in sensor services.
4. THE E2E_Test_Suite SHALL verify that at least one enrolled Built_In_Sensor has a recent `last_seen` timestamp before dashboard assertions run.
5. IF the Built_In_Sensor is not reporting health, THEN THE E2E_Test_Suite SHALL fail the preflight with a clear message that distinguishes sensor health failure from dashboard rendering failure.
6. THE E2E_Test_Suite SHALL record preflight results in the final test report.

### Requirement 3: Authentication and LiveView Client Regression Coverage

**User Story:** As a RavenWire maintainer, I want browser tests to verify authentication and LiveView connectivity, so that missing JavaScript or broken sessions are caught immediately.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL log in through the real `/login` page using credentials supplied by environment variables.
2. THE E2E_Test_Suite SHALL verify that authenticated navigation reaches the dashboard after login.
3. THE E2E_Test_Suite SHALL verify on every tested LiveView page that the LiveView JavaScript client is loaded and connected.
4. THE E2E_Test_Suite SHALL fail if a LiveView form submission performs a plain browser POST to a LiveView-only route.
5. THE E2E_Test_Suite SHALL capture browser console errors and fail on unexpected JavaScript exceptions.
6. THE E2E_Test_Suite SHALL include an explicit regression test for the pool creation flow at `/pools/new` so the missing-LiveView-assets failure cannot return unnoticed.

### Requirement 4: Core Operator Workflow Coverage

**User Story:** As a RavenWire maintainer, I want critical operator workflows covered in the browser, so that feature-complete screens keep working after future changes.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL verify that the dashboard displays the Built_In_Sensor and does not incorrectly show the "No sensor pods connected" empty state while a sensor is reporting health.
2. THE E2E_Test_Suite SHALL verify the pool workflow: create a pool, view the pool detail page, edit pool settings when implemented, assign or inspect sensors when available, and delete or clean up the test pool.
3. THE E2E_Test_Suite SHALL verify navigation from pool detail pages to pool configuration, pool sensors, deployments, and BPF filters when those routes are implemented.
4. THE E2E_Test_Suite SHALL verify the BPF workflow: create or open a BPF profile, add structured rules, validate the generated expression, save changes, verify pending deployment state, reset or clean up the profile.
5. THE E2E_Test_Suite SHALL verify rule store and ruleset workflows after the rule-store-management feature is implemented, including create, edit, validate, and deployment entry points.
6. THE E2E_Test_Suite SHALL verify deployment and drift pages after the deployment-tracking feature is implemented.
7. THE E2E_Test_Suite SHALL verify PCAP search, support bundle, and sensor detail workflows after those features are implemented.
8. THE E2E_Test_Suite SHALL skip not-yet-implemented workflow tests with explicit pending markers rather than silently omitting planned coverage.

### Requirement 5: Data Isolation and Cleanup

**User Story:** As a RavenWire maintainer, I want E2E tests to create isolated data and clean up after themselves, so that repeated test runs do not pollute the shared test server.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL create test records using unique names prefixed with `e2e-`.
2. THE E2E_Test_Suite SHALL track every record it creates during a run.
3. THE E2E_Test_Suite SHALL clean up E2E_Test_Data after each test or suite run using supported UI, API, or SSH-assisted cleanup paths.
4. THE E2E_Test_Suite SHALL NOT delete records that do not have the `e2e-` prefix unless a test explicitly created and tracked the record.
5. THE E2E_Test_Suite SHALL tolerate cleanup being re-run after a failed test.
6. THE E2E_Test_Suite SHALL report any cleanup failure separately from the workflow failure that triggered it.

### Requirement 6: Artifacts and Debuggability

**User Story:** As a RavenWire maintainer, I want actionable artifacts when E2E tests fail, so that failures can be diagnosed without re-running manually first.

#### Acceptance Criteria

1. THE Browser_Runner SHALL capture screenshots on failure.
2. THE Browser_Runner SHALL capture browser traces or videos for failed tests.
3. THE E2E_Test_Suite SHALL capture console logs and failed network requests.
4. THE E2E_Test_Suite SHALL include the current page URL, browser name, Test_Server base URL, and preflight summary in failure output.
5. THE E2E_Test_Suite SHALL store Test_Artifacts in a predictable ignored directory such as `test-results/e2e`.
6. THE E2E_Test_Suite SHALL make artifacts available from CI when CI execution is added.

### Requirement 7: Test Commands and Documentation

**User Story:** As a RavenWire maintainer, I want one documented command to run the full test suite, so that manual regression testing is repeatable.

#### Acceptance Criteria

1. THE repository SHALL provide a documented command for running only the browser E2E suite.
2. THE repository SHALL provide a documented command for running the full regression suite, including unit tests, integration tests, property tests, and browser E2E tests.
3. THE documented commands SHALL list all required environment variables and safe defaults.
4. THE documentation SHALL explain how to run the suite against the default Test_Server.
5. THE documentation SHALL explain how to interpret preflight failures, browser failures, and cleanup failures.
6. THE documentation SHALL state that feature work touching browser-visible workflows is not complete until relevant E2E coverage passes against the Test_Server or an explicit exception is documented.

### Requirement 8: CI and Release Gate Readiness

**User Story:** As a RavenWire maintainer, I want the E2E suite to become a release gate, so that broken browser workflows do not ship.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL be structured so it can run locally and in CI with the same test code.
2. THE E2E_Test_Suite SHALL use environment variables for all server addresses, credentials, and SSH details.
3. THE E2E_Test_Suite SHALL support a smoke profile for fast validation of login, dashboard, LiveView assets, and pool creation.
4. THE E2E_Test_Suite SHALL support a full profile for all implemented browser workflows.
5. THE E2E_Test_Suite SHALL return a non-zero exit code on any failed required test.
6. BEFORE a feature spec is marked complete, THE relevant E2E smoke or full profile SHALL pass against the Test_Server.

### Requirement 9: Security and Safety

**User Story:** As a RavenWire maintainer, I want server-based E2E tests to be safe for a shared test environment, so that automated checks do not expose secrets or disrupt manual testing.

#### Acceptance Criteria

1. THE E2E_Test_Suite SHALL NOT print passwords, API tokens, session cookies, or secret configuration values in logs or artifacts.
2. THE E2E_Test_Suite SHALL redact sensitive request headers from traces when supported by the Browser_Runner.
3. THE E2E_Test_Suite SHALL avoid destructive actions against non-test data.
4. THE E2E_Test_Suite SHALL use least-privilege test credentials where possible.
5. THE E2E_Test_Suite SHALL document any SSH or database cleanup command it performs.
6. THE E2E_Test_Suite SHALL require an explicit opt-in environment variable before using direct database cleanup on the Test_Server.
