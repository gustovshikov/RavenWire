#!/usr/bin/env bash
# dev-env/install-sensorctl-mac.sh
# Build and install sensorctl on macOS for running from the host.
# sensorctl on macOS only manages the VM (env/test commands).
# It shells out to `vagrant` and `vagrant ssh` for all VM operations.
#
# Prerequisites: Go 1.22+ installed on macOS (brew install go)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v go &>/dev/null; then
  echo "Error: Go not found. Install with: brew install go"
  exit 1
fi

echo "==> Building sensorctl for macOS"
cd "${REPO_ROOT}/sensorctl"
go mod tidy
go build -o "${REPO_ROOT}/bin/sensorctl" .

echo "==> Installed at ${REPO_ROOT}/bin/sensorctl"
echo ""
echo "Add to your PATH:"
echo "  export PATH=\"${REPO_ROOT}/bin:\$PATH\""
echo ""
echo "Or install system-wide:"
echo "  sudo cp ${REPO_ROOT}/bin/sensorctl /usr/local/bin/sensorctl"
echo ""
echo "Quick start:"
echo "  sensorctl test spike              # full automated test"
echo "  sensorctl test spike --keep-running  # leave VM up after"
echo "  sensorctl env ssh                 # SSH into VM"
