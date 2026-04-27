# Production Podman

Podman plus systemd Quadlet is the official deployment target. Compose is intentionally kept on the development side of the repo.

## Layout

```text
deploy/quadlet/
  management-pod/
  sensor-pod/
```

Each sensor node should be independently deployable and self-healing through systemd:

```text
Linux host
Podman
systemd / Quadlet
Sensor Agent
Zeek / Suricata / Vector / pcap_ring_writer
```

The manager side owns enrollment, registry, policy/config distribution, and health visibility:

```text
Config Manager
Enrollment CA
Sensor registry
Policy/config distribution
Health dashboard
```

## Commands

```bash
sensorctl podman install
sensorctl podman start sensor-pod
sensorctl podman status
```

Runtime-aware equivalents:

```bash
sensorctl runtime detect
sensorctl runtime podman install-quadlet
sensorctl runtime podman test-spike
```

## Design Rule

Scalability comes from the manager/enrollment/config model, not from stretching Docker Compose into production. Each sensor should be able to run offline from its last-known-good config, reconnect to the manager when available, and receive policy changes through the Sensor Agent.
