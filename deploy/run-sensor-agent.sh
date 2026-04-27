#!/usr/bin/env bash
# run-sensor-agent.sh — start the sensor-agent on the deployment host
set -euo pipefail

BINARY=/opt/sensor-stack/sensor-agent/sensor-agent-linux
TOKEN="${SENSOR_ENROLLMENT_TOKEN:-auto-1777227306}"
CONFIG_MANAGER_URL="${CONFIG_MANAGER_URL:-http://127.0.0.1:4000}"
CAPTURE_IFACE="${CAPTURE_IFACE:-ens16f1}"
POD_NAME="${SENSOR_POD_NAME:-sensor-pod-1}"

# Required directories
mkdir -p /etc/sensor/certs /etc/sensor/zeek
mkdir -p /var/sensor/logs/zeek /var/sensor/logs/suricata
mkdir -p /var/sensor/suricata/rules
mkdir -p /sensor/pcap/alerts
mkdir -p /var/run/sensor

# Minimal capture config if not present
if [ ! -f /etc/sensor/capture.conf ]; then
cat > /etc/sensor/capture.conf <<EOF
{
  "consumers": [
    {"name": "zeek",            "fanout_group_id": 1, "fanout_mode": "PACKET_FANOUT_HASH", "interface": "${CAPTURE_IFACE}", "thread_count": 2},
    {"name": "suricata",        "fanout_group_id": 2, "fanout_mode": "PACKET_FANOUT_HASH", "interface": "${CAPTURE_IFACE}", "thread_count": 2},
    {"name": "pcap_ring_writer","fanout_group_id": 4, "fanout_mode": "PACKET_FANOUT_HASH", "interface": "${CAPTURE_IFACE}", "thread_count": 1}
  ]
}
EOF
fi

# Minimal BPF filter (pass all for demo)
if [ ! -f /etc/sensor/bpf_filters.conf ]; then
  echo "# BPF filter — pass all traffic for demo" > /etc/sensor/bpf_filters.conf
fi

echo "Starting sensor-agent..."
echo "  Pod name:       $POD_NAME"
echo "  Interface:      $CAPTURE_IFACE"
echo "  Config Manager: $CONFIG_MANAGER_URL"

export SENSOR_POD_NAME="$POD_NAME"
export SENSOR_ENROLLMENT_TOKEN="$TOKEN"
# HTTP URL for enrollment REST calls (cert manager appends /enroll to this)
export CONFIG_MANAGER_URL="http://127.0.0.1:4000/api/v1"
# gRPC address for health stream (host:port only, no scheme)
export GRPC_ADDR="127.0.0.1:9090"
export GRPC_INSECURE="true"
export CAPTURE_IFACE="$CAPTURE_IFACE"
export CAPTURE_CONFIG_PATH=/etc/sensor/capture.conf
export BPF_FILTER_PATH=/etc/sensor/bpf_filters.conf
export AUDIT_LOG_PATH=/var/sensor/audit.log
export CERT_DIR=/etc/sensor/certs
export PCAP_ALERTS_DIR=/sensor/pcap/alerts
export PCAP_DB_PATH=/sensor/pcap/pcap.db
export HEALTH_BUFFER_PATH=/var/sensor/health-buffer.bin
export LAST_KNOWN_CONFIG_PATH=/etc/sensor/last-known-config.json
export CONTROL_API_PORT=9091
# Use Docker socket for demo (Podman not installed)
export PODMAN_SOCKET_PATH=/var/run/docker.sock

exec "$BINARY"
