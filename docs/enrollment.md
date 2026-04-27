# Enrollment

Enrollment gives each sensor pod its own identity before it streams health or accepts remote configuration.

## Sensor CLI

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

`sensorctl enroll` posts to `/api/v1/enroll`. If the manager auto-approves the request, it writes:

```text
sensor.key
sensor.crt
ca-chain.pem
```

If the manager returns `202 Accepted`, the enrollment was submitted and is waiting for operator approval.

## Runtime

After enrollment, the Sensor Agent should use the certificate bundle for mTLS manager communication and keep the last-known-good config available locally so the sensor can continue operating during manager outages.
