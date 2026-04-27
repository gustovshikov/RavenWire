#!/usr/bin/env bash
set -euo pipefail

DB=/var/lib/docker/volumes/deploy_cm_data/_data/config_manager.db
CERTS=/etc/sensor/certs

echo "==> Stopping any running sensor-agent"
pkill -f sensor-agent-linux 2>/dev/null || true
sleep 1

echo "==> Clearing old certs"
rm -f "$CERTS/sensor.crt" "$CERTS/sensor.key" "$CERTS/ca-chain.pem"

echo "==> Removing stale pod record"
sqlite3 "$DB" "DELETE FROM sensor_pods WHERE name='sensor-pod-1';" 2>/dev/null || true

echo "==> Inserting fresh enrollment token"
NEW_UUID=$(cat /proc/sys/kernel/random/uuid)
NEW_TOKEN="auto-$(date +%s)"
sqlite3 "$DB" "INSERT INTO enrollment_tokens (id, token, created_by, consumed_at, expires_at, inserted_at, updated_at) VALUES ('$NEW_UUID', '$NEW_TOKEN', 'admin', NULL, datetime('now', '+2 hours'), datetime('now'), datetime('now'));"
echo "   Token: $NEW_TOKEN"

echo "==> Starting sensor-agent"
export SENSOR_POD_NAME="sensor-pod-1"
export SENSOR_ENROLLMENT_TOKEN="$NEW_TOKEN"
export CONFIG_MANAGER_URL="http://127.0.0.1:4000/api/v1"
export GRPC_ADDR="127.0.0.1:9090"
export GRPC_INSECURE="true"
export CAPTURE_IFACE="ens16f1"
export CAPTURE_CONFIG_PATH=/etc/sensor/capture.conf
export BPF_FILTER_PATH=/etc/sensor/bpf_filters.conf
export AUDIT_LOG_PATH=/var/sensor/audit.log
export CERT_DIR="$CERTS"
export PCAP_ALERTS_DIR=/sensor/pcap/alerts
export PCAP_DB_PATH=/sensor/pcap/pcap.db
export HEALTH_BUFFER_PATH=/var/sensor/health-buffer.bin
export LAST_KNOWN_CONFIG_PATH=/etc/sensor/last-known-config.json
export CONTROL_API_PORT=9091
export PODMAN_SOCKET_PATH=/var/run/docker.sock

exec /opt/sensor-stack/sensor-agent/sensor-agent-linux
