#!/usr/bin/env bash
# tools/lab/gen-traffic.sh — Generate test traffic for the lab capture stack
#
# Generates a mix of TCP, UDP, and ICMP traffic so Zeek, Suricata, and
# pcap_ring_writer have packets to process during the lab test window.
set -euo pipefail

IFACE="${TRAFFIC_IFACE:-veth1}"
DEST_IP="${DEST_IP:-10.99.0.2}"
DURATION="${DURATION:-30}"  # seconds

echo "==> Generating traffic on ${IFACE} for ${DURATION}s"
echo "    Destination: ${DEST_IP}"
echo "    Press Ctrl+C to stop early"

# Ensure veth1 is up
ip link set "${IFACE}" up 2>/dev/null || true

END=$((SECONDS + DURATION))

while [ $SECONDS -lt $END ]; do
  # ICMP — generates conn.log entries in Zeek
  ping -I "${IFACE}" -c 3 -W 1 "${DEST_IP}" &>/dev/null || true

  # TCP SYN to various ports — generates Suricata alerts with community_id
  for port in 80 443 22 8080 3306; do
    timeout 0.5 bash -c "echo '' > /dev/tcp/${DEST_IP}/${port}" 2>/dev/null || true
  done

  # UDP — DNS-like traffic
  echo -n "test" | nc -u -w 1 "${DEST_IP}" 53 2>/dev/null || true
  echo -n "test" | nc -u -w 1 "${DEST_IP}" 5353 2>/dev/null || true

  sleep 1
done

echo "==> Traffic generation complete"
