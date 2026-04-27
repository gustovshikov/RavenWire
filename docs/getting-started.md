# Getting Started

RavenWire has one supported operating path: Podman containers managed by systemd Quadlet and operated with `sensorctl`.

## Prerequisites

- Linux host
- Podman
- systemd user services
- Go, if building `sensorctl` locally

## Build sensorctl

```bash
cd sensorctl
go build -o ../bin/sensorctl .
export PATH="$PWD/../bin:$PATH"
```

## Install Units

```bash
sensorctl install
```

This copies units from `deploy/quadlet/` into:

```text
~/.config/containers/systemd/
```

## Start A Sensor

```bash
sensorctl start sensor-pod
sensorctl status
sensorctl logs sensor-pod
```

## Enroll

```bash
sensorctl enroll --manager https://manager:8443 --token <token>
```

See [Enrollment](enrollment.md) for options.
