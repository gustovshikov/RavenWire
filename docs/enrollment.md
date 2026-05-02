# Enrollment

Enrollment gives each sensor pod its own identity before it streams health or accepts remote configuration.

There are two enrollment paths:

- Normal single-host dual-pod install: `sensorctl start` generates a one-time token and the sensor auto-enrolls.
- Split manager/sensor install: an operator creates a token and runs `sensorctl enroll` on the sensor host.

## Sensor CLI

For the normal single-host dual-pod deployment, enrollment is automatic:

```bash
sensorctl install --capture-iface <span-interface>
sensorctl start
```

`sensorctl start` creates the one-time token from the running Config Manager and passes it to the first sensor start.

For split deployments, manual enrollment is still available:

```bash
sensorctl enroll --manager https://manager:8443 --token <token>
```

Useful options:

```bash
sensorctl enroll \
  --manager https://manager:8443 \
  --token <token> \
  --pod-name sensor-pod-1 \
  --cert-dir /etc/sensor/certs
```

`sensorctl enroll` accepts either a manager base URL or an `/api/v1` URL. It posts to `/api/v1/enroll`. If the manager auto-approves the request, it writes:

```text
sensor.key
sensor.crt
ca-chain.pem
```

If the manager returns `202 Accepted`, the enrollment was submitted and is waiting for operator approval.

Use `sensorctl enroll --status --sensor https://sensor:9091` to inspect bootstrap state and blocking errors without submitting a new enrollment request.

## Current Manager Routes

Config Manager currently exposes these enrollment and certificate-adjacent routes:

| Route | Caller | Purpose |
|---|---|---|
| `POST /api/v1/enroll` | `sensorctl` or Sensor Agent bootstrap | Submit token, pod name, and public key. |
| `GET /api/v1/enroll/status` | Sensor Agent bootstrap | Poll pending approval by pod name. |
| `POST /api/v1/enrollment/:id/approve` | mTLS manager-side action | Approve a pending enrollment. |
| `POST /api/v1/enrollment/:id/deny` | mTLS manager-side action | Deny a pending enrollment. |
| `GET /api/v1/crl` | Sensor Agent | Fetch certificate revocation list. |

The Public API specs reserve bearer-token automation routes under `/api/v1`, but production auth/RBAC and token scopes are not implemented yet. The `auth-rbac-audit` spec is the first implementation dependency before broadening the public API.

## Sensor Bootstrap

The Sensor Agent bootstrap state machine progresses through:

```text
installed
enrolling
pending_approval
config_received
config_validated
capture_active
```

During pre-certificate bootstrap the Sensor Agent also has a minimal local enrollment listener that accepts only `POST /enroll`. That listener is internal to bootstrap and is separate from Config Manager's `/api/v1/enroll` route.

## Runtime

After enrollment, the Sensor Agent should use the certificate bundle for mTLS manager communication and keep the last-known-good config available locally so the sensor can continue operating during manager outages.
