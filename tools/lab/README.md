# RavenWire Lab Tools

This directory contains optional capture validation helpers. They are not the
deployment path. The supported RavenWire path is Podman + Quadlet through
`sensorctl`.

## Capture Test

Run this on a Linux host with Podman Compose support and a mirror/TAP interface:

```bash
export CAPTURE_IFACE=eth0
podman compose -p ravenwire-lab -f tools/lab/compose.capture-test.yml up -d
```

Generate traffic if the interface is quiet:

```bash
TRAFFIC_IFACE=veth1 DEST_IP=10.99.0.2 tools/lab/gen-traffic.sh
```

Verify the lab stack:

```bash
tools/lab/verify-capture.sh
```

Stop it when finished:

```bash
podman compose -p ravenwire-lab -f tools/lab/compose.capture-test.yml down
```

The lab stack runs Zeek, Suricata, Vector, the shared production
`pcap_ring_writer`, and a small `pcap_carve_simulator` helper that triggers one
alert-window PCAP carve.
