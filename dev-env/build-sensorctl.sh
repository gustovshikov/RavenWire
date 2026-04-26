#!/usr/bin/env bash
# dev-env/build-sensorctl.sh — Build sensorctl inside the VM
# Run inside the VM: bash /vagrant/dev-env/build-sensorctl.sh
set -euo pipefail

echo "==> Building sensorctl"
cd /vagrant/sensorctl
go mod tidy
go build -o /usr/local/bin/sensorctl .
echo "==> sensorctl installed at /usr/local/bin/sensorctl"
sensorctl --help
