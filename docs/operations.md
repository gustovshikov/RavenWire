# Operations

`sensorctl` is the primary operator surface for RavenWire.

## Commands

```bash
sensorctl install
sensorctl start [sensor-pod|management-pod|unit]
sensorctl stop [sensor-pod|management-pod|unit]
sensorctl restart [sensor-pod|management-pod|unit]
sensorctl status [unit]
sensorctl logs [unit]
sensorctl enroll --manager https://manager:8443 --token <token>
sensorctl agent status --sensor https://sensor:9091
sensorctl agent show-drops --sensor https://sensor:9091
sensorctl test
```

If no unit is provided, `start`, `stop`, and `restart` default to `sensor-pod`.

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
    sensor-pod.target
```

## Logs

```bash
sensorctl logs
sensorctl logs sensor-agent.service
sensorctl logs pcap-ring-writer.service
```

## Validation

```bash
sensorctl test
```

This runs Go package checks and validates the optional lab compose definition when Podman Compose is available.
