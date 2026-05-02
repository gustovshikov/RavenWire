# Operations

`sensorctl` is the primary operator surface for RavenWire.

RavenWire installs as system Quadlet units because the capture stack needs host packet-capture capabilities that rootless containers cannot provide reliably.

Docker Compose and Vagrant are not supported deployment paths. Install, run, and validation work should go through `sensorctl` and the Quadlet units in `deploy/quadlet/`.

## Commands

```bash
sensorctl install
sensorctl install --capture-iface ens16f1 --pod-name sensor-01 --manager-url http://127.0.0.1:4000/api/v1
sensorctl start [app|sensor-pod|management-pod|unit]
sensorctl stop [app|sensor-pod|management-pod|unit]
sensorctl restart [app|sensor-pod|management-pod|unit]
sensorctl status [unit]
sensorctl logs [unit]
sensorctl uninstall [--purge] [--images]
sensorctl enroll --manager https://manager:8443 --token <token>
sensorctl agent status --sensor https://sensor:9091
sensorctl agent show-drops --sensor https://sensor:9091
sensorctl agent collect-support-bundle --sensor https://sensor:9091 --output ./support.tar.gz
sensorctl test
```

If no unit is provided, `start`, `stop`, and `restart` operate on the full dual-pod app. `sensorctl start` starts `management-pod.target`, waits for Config Manager, generates the initial enrollment token when needed, then starts `sensor-pod.target`.

`sensorctl install` supports these deployment options:

| Flag | Purpose |
|---|---|
| `--capture-iface` | Capture interface for Zeek, Suricata, and `pcap_ring_writer`. Falls back to `CAPTURE_IFACE` and then interface detection. |
| `--pod-name` | Sensor pod identity. Falls back to `SENSOR_POD_NAME` and then hostname. |
| `--manager-url` | Config Manager enrollment API base URL. Defaults to `http://127.0.0.1:4000/api/v1`. |
| `--skip-build` | Reuse existing local images instead of rebuilding them. |

## Quadlet Layout

```text
deploy/quadlet/
  management-pod/
    config-manager.container
    management-pod.target
  sensor-pod/
    sensor-agent.container
    pcap-ring-writer.container
    zeek.container
    suricata.container
    vector.container
    capture-pipeline.target
    analysis-pipeline.target
    sensor-pod.target
```

## Host State

`sensorctl install` prepares these main host paths:

```text
/data/config_manager
/data/ca
/data/metrics
/etc/sensor
/var/sensor
/var/run/sensor
/sensor/pcap
```

`sensorctl uninstall` removes installed Quadlet and target files. `sensorctl uninstall --purge` also removes RavenWire host data and generated certificates/config. `sensorctl uninstall --images` removes locally built RavenWire images.

## Logs

```bash
sensorctl logs
sensorctl logs sensor-agent.service
sensorctl logs pcap-ring-writer.service
sensorctl logs config-manager.service
```

Use `sensorctl logs --lines 500` to change the number of journal lines.

## Agent Inspection

Agent commands talk to the Sensor Agent control API over mTLS. Provide the sensor URL with `--sensor` or `SENSORCTL_SENSOR_URL`. Certificates can come from `SENSORCTL_CERT`, `SENSORCTL_KEY`, and `SENSORCTL_CA`, or from `~/.sensorctl/config.yaml` / `./sensorctl.yaml`.

```yaml
sensor_url: https://sensor-host:9091
cert: /etc/sensor/certs/sensor.crt
key: /etc/sensor/certs/sensor.key
ca: /etc/sensor/certs/ca-chain.pem
```

## Validation

```bash
sensorctl test
```

This runs the `sensorctl` Go checks, Sensor Agent Go checks, and the Linux build check for `pcap_ring_writer`.

## Fresh Reset

```bash
sensorctl stop
sensorctl uninstall --purge --images
sensorctl install --capture-iface ens16f1 --pod-name sensor-01
sensorctl start
```

## Current Boundaries

The current implementation does not yet include production authentication/RBAC, fleet pool management, deployment tracking, public API token management, or multi-manager HA. Those features are specified under `.kiro/specs/` and summarized in [Implementation Roadmap](implementation-roadmap.md).
