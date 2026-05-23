# RavenWire End-to-End Browser Tests

This suite runs Playwright browser tests against a deployed RavenWire test server. It is intended to catch browser, LiveView, packaging, and real-environment regressions that Phoenix unit tests cannot catch.

## Setup

Local prerequisites:

- Node.js 18 or newer.
- Network access to the RavenWire test server over HTTP and SSH.
- SSH access to the configured test server, defaulting to `eric@172.16.10.38`.
- The test server must have `systemctl` and `sqlite3` available for preflight checks.

Install the test runner dependencies and the Chromium browser used by Playwright:

```bash
cd e2e
npm install
npm run install:browsers
```

Set credentials and target server details through environment variables. Do not commit secrets. The runner automatically loads `e2e/.env` when present, and shell exports take precedence.

For a local machine, copy the example and fill in the admin credentials:

```bash
cp .env.example .env
```

Alternatively, export the values in your shell or through your local secret manager:

```bash
export E2E_BASE_URL=http://172.16.10.38:4000
export E2E_ADMIN_USER=<admin username>
export E2E_ADMIN_PASSWORD=<admin password>
export E2E_SSH_USER=eric
export E2E_SSH_HOST=172.16.10.38
export E2E_SENSOR_NAME=sensor-01
```

For the default shared test server, verify SSH before running the suite:

```bash
ssh eric@172.16.10.38 systemctl is-active config-manager.service
```

## Commands

Run the smoke suite:

```bash
npm run test:smoke
```

Run every implemented browser workflow:

```bash
npm run test:full
```

The full profile covers login, dashboard/sensor visibility, pools, deployments, rules, BPF, support/PCAP entry points, admin user/role/token pages, and audit filtering/export.

Run the full RavenWire regression gate from the repository root:

```bash
sensorctl test && (cd e2e && npm run test:full)
```

Run only the server preflight:

```bash
npm run preflight
```

The first run on a new machine should be:

```bash
cd e2e
npm install
npm run install:browsers
npm run preflight
npm run test:smoke
```

## What Preflight Checks

Preflight verifies that:

- `/login` is reachable.
- `/assets/app.js`, `/assets/phoenix.min.js`, and `/assets/phoenix_live_view.min.js` are served.
- Required systemd services are active on the test server.
- The expected built-in sensor, defaulting to `sensor-01`, is enrolled and has a recent `last_seen_at`.

Set `E2E_SKIP_SSH_PREFLIGHT=true` only when intentionally running browser-only HTTP smoke checks. The full suite should use SSH preflight.

## Artifacts

Failure screenshots, traces, videos, console logs, and JSON summaries are written under `e2e/test-results/` and `e2e/playwright-report/`.

## Cleanup

Tests create records with an `e2e-` prefix and clean up records they create. Direct SQLite cleanup is disabled unless `E2E_ALLOW_DB_CLEANUP=true`, and it only targets tracked `e2e-` records.

## Feature Completion Gate

Browser-visible feature work is not complete until the relevant E2E smoke or full profile passes against the configured test server. If E2E coverage is not practical for a change, document the exception in the owning feature notes with the manual verification performed instead.

## CI

The GitHub Actions workflow in `.github/workflows/e2e.yml` can run the same suite from CI. Configure these repository secrets:

- `E2E_ADMIN_USER`
- `E2E_ADMIN_PASSWORD`

Optional repository variables override defaults:

- `E2E_BASE_URL`
- `E2E_SSH_USER`
- `E2E_SSH_HOST`
- `E2E_SENSOR_NAME`
- `E2E_ALLOW_DB_CLEANUP`

Run the workflow manually with the `smoke` profile for browser-visible changes and `full` for release candidates. The workflow uploads Playwright reports, traces, screenshots, and videos from `e2e/test-results/` and `e2e/playwright-report/`.
