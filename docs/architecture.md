# Architecture

RavenWire is organized around one deployable model: Podman containers supervised by systemd through Quadlet.

## Sensor Node

```text
Sensor Pod
  Sensor Agent
  Zeek
  Suricata
  Vector
  pcap_ring_writer
```

The Sensor Agent owns local control operations and keeps the management plane away from direct host or Podman socket access.

## Manager Node

```text
Management Pod
  Config Manager
  Enrollment CA
  Sensor registry
  Health dashboard
```

## Packet Path

Each capture consumer binds its own AF_PACKET socket to the monitored interface:

| Consumer | Fanout Group | Purpose |
|---|---:|---|
| Zeek | `1` | Protocol metadata |
| Suricata | `2` | Signatures and alerts |
| pcap_ring_writer | `4` | Alert-window packet history |

RavenWire avoids a shared userspace packet broker for the MVP. Scalability comes from independently deployable sensor pods, enrollment, manager-driven config, and offline last-known-good behavior.

## Optional Lab Tools

`tools/lab/` contains validation helpers for capture behavior. They are intentionally outside `deploy/` so they do not compete with the Quadlet deployment path.
