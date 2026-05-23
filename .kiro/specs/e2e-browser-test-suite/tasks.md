# Implementation Plan: End-to-End Browser Test Suite

## Overview

This plan adds a real-browser end-to-end regression suite for RavenWire. The implementation proceeds in layers: test harness, environment validation, preflight checks, authentication, LiveView regression tests, core workflows, cleanup, documentation, and finally full-suite gating.

## Tasks

- [x] 1. Create the Playwright E2E harness
  - [x] 1.1 Add a top-level `e2e/` directory with Playwright configuration
    - Add `e2e/package.json`, `e2e/playwright.config.ts`, and initial test directories
    - Configure screenshots, traces, videos, retries, and `test-results` output
    - Configure smoke and full test profiles
    - _Requirements: 6.1, 6.2, 6.5, 8.1, 8.3, 8.4_

  - [x] 1.2 Add environment parsing and validation
    - Implement `support/env.ts`
    - Require `E2E_BASE_URL`, `E2E_ADMIN_USER`, and `E2E_ADMIN_PASSWORD`
    - Support `E2E_SSH_USER`, `E2E_SSH_HOST`, `E2E_PROFILE`, `E2E_ALLOW_DB_CLEANUP`, and `E2E_SENSOR_NAME`
    - Redact secrets in logs and error output
    - _Requirements: 1.1, 1.2, 1.3, 8.2, 9.1_

- [x] 2. Implement server preflight checks
  - [x] 2.1 Add HTTP preflight checks
    - Verify `/login` is reachable
    - Verify required static assets are served: `app.js`, `phoenix.min.js`, `phoenix_live_view.min.js`
    - Fail fast with clear diagnostics on unreachable server or missing assets
    - _Requirements: 1.4, 2.1, 2.2_

  - [x] 2.2 Add SSH service preflight checks
    - Check active status for Config Manager and sensor stack services
    - Report inactive or missing services separately from browser failures
    - _Requirements: 2.3, 6.4_

  - [x] 2.3 Add built-in sensor health preflight
    - Verify the expected sensor is enrolled
    - Verify the sensor has a recent `last_seen` timestamp
    - Fail with a sensor health message when the sensor is not reporting
    - _Requirements: 2.4, 2.5, 2.6_

- [x] 3. Implement authentication and LiveView helpers
  - [x] 3.1 Add browser login helper
    - Log in through `/login` using environment-provided credentials
    - Persist authenticated browser context state for the run
    - _Requirements: 3.1, 3.2_

  - [x] 3.2 Add LiveView connectivity helper
    - Assert `window.liveSocket` exists and is connected on tested LiveView pages
    - Capture and fail on unexpected browser console exceptions
    - _Requirements: 3.3, 3.5_

  - [x] 3.3 Add plain POST regression guard
    - Detect unexpected navigation to Phoenix router errors after LiveView form submits
    - Use the guard in pool creation and future LiveView form tests
    - _Requirements: 3.4, 3.6_

- [x] 4. Add smoke browser tests
  - [x] 4.1 Add login and navigation smoke test
    - Open `/login`, authenticate, and verify the dashboard loads
    - _Requirements: 3.1, 3.2_

  - [x] 4.2 Add dashboard sensor smoke test
    - Verify the built-in sensor appears on the dashboard
    - Verify the disconnected empty state is not shown when preflight confirms sensor health
    - _Requirements: 4.1_

  - [x] 4.3 Add LiveView asset smoke test
    - Verify LiveView JavaScript is loaded and connected in the browser
    - Verify no unexpected console errors appear
    - _Requirements: 3.3, 3.5_

  - [x] 4.4 Add pool creation regression test
    - Navigate to `/pools/new`
    - Create a uniquely named `e2e-` pool
    - Verify successful navigation to the pool detail page
    - Verify no plain POST to `/pools/new` occurs
    - Clean up the created pool
    - _Requirements: 3.4, 3.6, 4.2, 5.1, 5.3_

- [x] 5. Add data tracking and cleanup fixtures
  - [x] 5.1 Add test data name generator
    - Generate unique `e2e-` names for pools, BPF profiles, rules, and future workflow records
    - _Requirements: 5.1_

  - [x] 5.2 Add cleanup registry
    - Track every record created by a test
    - Clean up child records before parent records
    - Make cleanup idempotent after partial failures
    - _Requirements: 5.2, 5.3, 5.5_

  - [x] 5.3 Add safe database cleanup option
    - Require `E2E_ALLOW_DB_CLEANUP=true` before direct database cleanup
    - Delete only tracked `e2e-` records
    - Document every SSH/database cleanup command used by the suite
    - _Requirements: 5.4, 5.6, 9.3, 9.5, 9.6_

- [x] 6. Add pool workflow full tests
  - [x] 6.1 Verify pool list, create, detail, and cleanup
    - Create a pool from the browser and verify it appears in the list and detail views
    - Clean up the pool at the end of the test
    - _Requirements: 4.2, 5.1, 5.3_

  - [x] 6.2 Verify pool configuration and sensor routes when implemented
    - Navigate from pool detail to config, sensors, deployments, and BPF routes
    - Mark unavailable routes as explicit pending tests until implemented
    - _Requirements: 4.3, 4.8_

- [x] 7. Add BPF workflow full tests
  - [x] 7.1 Verify BPF editor navigation and LiveView connection
    - Open `/pools/:id/bpf` for an E2E-created pool
    - Assert LiveView is connected
    - _Requirements: 3.3, 4.4_

  - [x] 7.2 Verify BPF profile edit, validate, save, and reset
    - Create or open a BPF profile
    - Add structured rules
    - Validate the generated expression
    - Save changes and verify pending deployment state
    - Reset or clean up the test profile
    - _Requirements: 4.4, 5.3_

- [x] 8. Add rule store, deployment, and sensor workflow tests
  - [x] 8.1 Add rule store workflow tests when implemented
    - Cover create, edit, validate, and deployment entry points
    - _Requirements: 4.5, 4.8_

  - [x] 8.2 Add deployment tracking and drift workflow tests when implemented
    - Cover deployment list/detail and drift status pages
    - _Requirements: 4.6, 4.8_

  - [x] 8.3 Add sensor detail, PCAP, and support bundle tests when implemented
    - Cover sensor detail navigation, PCAP search/retrieval, and support bundle entry points
    - _Requirements: 4.7, 4.8_

  - [x] 8.4 Add admin and audit hardening workflow tests when implemented
    - Cover admin users, roles, API token management, audit filters/detail, and audit export entry points
    - _Requirements: 4.8, 6.1_

- [x] 9. Add commands and documentation
  - [x] 9.1 Document E2E-only command
    - Add README instructions for running the browser suite against the default Test_Server
    - Include required environment variables
    - _Requirements: 7.1, 7.3, 7.4_

  - [x] 9.2 Document full regression command
    - Define a command that runs unit, integration, property, and browser E2E tests
    - Document expected runtime and prerequisites
    - _Requirements: 7.2, 7.5_

  - [x] 9.3 Document feature completion gate
    - State that browser-visible feature work requires relevant E2E coverage before completion
    - Document how to record exceptions when E2E coverage is not practical
    - _Requirements: 7.6, 8.6_

- [x] 10. Prepare CI and release gate integration
  - [x] 10.1 Add CI-ready scripts without hard-coded credentials
    - Ensure the same Playwright tests can run locally and in CI
    - Use environment variables for all server and credential configuration
    - _Requirements: 8.1, 8.2_

  - [x] 10.2 Add artifact upload support for CI
    - Publish screenshots, traces, videos, console logs, and JSON summaries from failed CI runs
    - _Requirements: 6.1, 6.2, 6.3, 6.6_

  - [x] 10.3 Enforce smoke/full profiles as gates
    - Use smoke for browser-visible changes
    - Use full for release candidates and completed feature specs
    - Ensure failing required E2E tests return a non-zero exit code
    - _Requirements: 8.3, 8.4, 8.5, 8.6_
