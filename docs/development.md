# Development

RavenWire uses Docker and Compose for developer convenience. This path is for fast local iteration, the Vagrant Linux VM, and the Phase 0.5 spike stack.

## Layout

```text
deploy/compose/
  docker-compose.spike.yml  # Zeek, Suricata, Vector, pcap_ring_writer, pcap_manager
  compose.dev.yml           # Demo manager plus sensor services
```

The spike Compose file keeps the Compose project name as `spike` through `sensorctl`, so verification scripts still inspect containers such as `spike-zeek-1`.

## Commands

```bash
sensorctl dev up
sensorctl dev test-spike
```

The older commands still work for now:

```bash
sensorctl env up
sensorctl test spike
```

## Runtime Overrides

Development defaults to Docker:

```bash
CONTAINER_RUNTIME=docker COMPOSE="docker compose" sensorctl test spike
```

To run the same spike workflow with Podman-compatible Compose:

```bash
CONTAINER_RUNTIME=podman COMPOSE="podman compose" sensorctl runtime podman test-spike
```

Scripts that inspect containers should use:

```bash
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
COMPOSE="${COMPOSE:-docker compose}"
```

Then call `$CONTAINER_RUNTIME logs ...`, `$CONTAINER_RUNTIME exec ...`, and `$COMPOSE logs ...`.
