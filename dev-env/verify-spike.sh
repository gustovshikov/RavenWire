#!/usr/bin/env bash
# dev-env/verify-spike.sh — Automated verification of all four spike goals
#
# Run inside the VM after `docker-compose up` and traffic generation:
#   /vagrant/dev-env/verify-spike.sh
#
# Exit codes:
#   0 — all goals verified
#   1 — one or more goals failed
set -euo pipefail

LOGS_DIR="${LOGS_DIR:-/var/lib/docker/volumes/spike_logs/_data}"
CONTROL_SOCK="${CONTROL_SOCK:-/var/run/pcap_ring.sock}"

# Detect if we're running on the host (not inside a container)
# If the control socket isn't accessible directly, use docker exec
USE_DOCKER_EXEC=false
if [ ! -S "$CONTROL_SOCK" ] && command -v docker &>/dev/null; then
  USE_DOCKER_EXEC=true
fi
PASS=0
FAIL=0

green() { echo -e "\033[32m✓ $*\033[0m"; }
red()   { echo -e "\033[31m✗ $*\033[0m"; }
info()  { echo -e "\033[36m  $*\033[0m"; }

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "ok" ]; then
    green "$desc"
    PASS=$((PASS + 1))
  else
    red "$desc"
    info "$result"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "══════════════════════════════════════════════════"
echo "  Network Sensor Stack — Spike Verification"
echo "══════════════════════════════════════════════════"
echo ""

# ── Goal 1: Zeek producing logs ──────────────────────────────────────────────
echo "Goal 1: Zeek and Suricata producing logs"

ZEEK_LOG="${LOGS_DIR}/zeek/conn.log"
if [ -f "$ZEEK_LOG" ] && [ -s "$ZEEK_LOG" ]; then
  LINE_COUNT=$(wc -l < "$ZEEK_LOG")
  check "Zeek conn.log exists and non-empty (${LINE_COUNT} lines)" "ok"
else
  check "Zeek conn.log exists and non-empty" "File not found or empty: ${ZEEK_LOG}"
fi

SURI_LOG="${LOGS_DIR}/suricata/eve.json"
if [ -f "$SURI_LOG" ] && [ -s "$SURI_LOG" ]; then
  LINE_COUNT=$(wc -l < "$SURI_LOG")
  check "Suricata eve.json exists and non-empty (${LINE_COUNT} lines)" "ok"
else
  check "Suricata eve.json exists and non-empty" "File not found or empty: ${SURI_LOG}"
fi

echo ""

# ── Goal 2: Community ID present and preserved ───────────────────────────────
echo "Goal 2: Community ID present in all outputs"

# Check Zeek
if grep -q '"community_id"' "$ZEEK_LOG" 2>/dev/null; then
  SAMPLE=$(grep -o '"community_id":"[^"]*"' "$ZEEK_LOG" | head -1 | cut -d'"' -f4)
  check "community_id present in Zeek conn.log (sample: ${SAMPLE:0:30}...)" "ok"
else
  check "community_id present in Zeek conn.log" "Field not found in ${ZEEK_LOG}"
fi

# Check Suricata
if grep -q '"community_id"' "$SURI_LOG" 2>/dev/null; then
  SAMPLE=$(grep -o '"community_id":"[^"]*"' "$SURI_LOG" | head -1 | cut -d'"' -f4)
  check "community_id present in Suricata eve.json (sample: ${SAMPLE:0:30}...)" "ok"
else
  check "community_id present in Suricata eve.json" "Field not found in ${SURI_LOG}"
fi

# Check Vector output
VECTOR_LOG="${LOGS_DIR}/vector/output.json"
if [ -f "$VECTOR_LOG" ] && grep -q '"community_id"' "$VECTOR_LOG" 2>/dev/null; then
  # Verify a specific community_id value is preserved unchanged
  CID=$(grep -o '"community_id":"[^"]*"' "$ZEEK_LOG" 2>/dev/null | head -1 | cut -d'"' -f4)
  if [ -n "$CID" ] && grep -q "\"community_id\":\"${CID}\"" "$VECTOR_LOG" 2>/dev/null; then
    check "community_id preserved unchanged through Vector (value: ${CID:0:30}...)" "ok"
  else
    check "community_id preserved unchanged through Vector" \
      "Value mismatch or not found in Vector output"
  fi
else
  check "community_id present in Vector output.json" \
    "File not found or field missing: ${VECTOR_LOG}"
fi

echo ""

# ── Goal 3: pcap_ring_writer ring stats ──────────────────────────────────────
echo "Goal 3: pcap_ring_writer ring stats"

get_ring_stats() {
  if [ "$USE_DOCKER_EXEC" = "true" ]; then
    docker exec spike-pcap_ring_writer-1 \
      sh -c 'printf "{\"cmd\":\"status\"}" | nc -U -w 2 /var/run/pcap_ring.sock 2>/dev/null' 2>/dev/null || \
    # Fallback: check container logs for stats
    docker logs spike-pcap_ring_writer-1 2>/dev/null | grep -o '"packets_written":[0-9]*' | tail -1
  elif [ -S "$CONTROL_SOCK" ]; then
    echo '{"cmd":"status"}' | nc -U -w 2 "$CONTROL_SOCK" 2>/dev/null
  fi
}

# Check pcap_manager output for packet count (most reliable indicator)
PCAP_MGR_LOG=$(docker logs spike-pcap_manager-1 2>/dev/null || echo "")
RING_PKTS=$(echo "$PCAP_MGR_LOG" | grep -o '"packets_written":[0-9]*' | tail -1 | cut -d: -f2 || echo "0")

if [ -z "$RING_PKTS" ]; then
  # Try direct stats
  STATS=$(get_ring_stats)
  RING_PKTS=$(echo "$STATS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('stats',{}).get('packets_written',0))" 2>/dev/null || echo "0")
fi

if [ "${RING_PKTS:-0}" -gt 0 ] 2>/dev/null; then
  check "pcap_ring_writer packets_written=${RING_PKTS}" "ok"
else
  check "pcap_ring_writer packets_written > 0" \
    "Got ${RING_PKTS:-0} — is traffic flowing on CAPTURE_IFACE? Run gen-traffic.sh first"
fi

echo ""

# ── Goal 4: Carved PCAP valid ────────────────────────────────────────────────
echo "Goal 4: Carved PCAP file valid"

# Check inside pcap_manager container first (carved file is in /tmp inside container)
CARVE_FILE=""
if [ "$USE_DOCKER_EXEC" = "true" ]; then
  CARVE_FILE=$(docker exec spike-pcap_manager-1 sh -c 'ls -t /tmp/alert_carve_*.pcap 2>/dev/null | head -1' 2>/dev/null || echo "")
  if [ -n "$CARVE_FILE" ]; then
    # Copy out of container for inspection
    docker cp "spike-pcap_manager-1:${CARVE_FILE}" /tmp/ 2>/dev/null || true
    CARVE_FILE="/tmp/$(basename "$CARVE_FILE")"
  fi
fi

# Also check host /tmp
if [ -z "$CARVE_FILE" ]; then
  CARVE_FILE=$(ls -t /tmp/alert_carve_*.pcap 2>/dev/null | head -1 || echo "")
fi

if [ -n "$CARVE_FILE" ] && [ -f "$CARVE_FILE" ]; then
  # Check PCAP magic number (little-endian: d4 c3 b2 a1)
  MAGIC=$(xxd -l 4 "$CARVE_FILE" 2>/dev/null | awk '{print $2$3}' | head -1 || echo "")
  if [ "$MAGIC" = "d4c3b2a1" ]; then
    check "Carved PCAP has valid magic number (0xa1b2c3d4 LE)" "ok"
  else
    check "Carved PCAP has valid magic number" \
      "Got magic: ${MAGIC} (expected d4c3b2a1)"
  fi

  # Check packet count with tcpdump
  if command -v tcpdump &>/dev/null; then
    PKT_COUNT=$(tcpdump -r "$CARVE_FILE" -n 2>/dev/null | wc -l || echo "0")
    if [ "$PKT_COUNT" -gt 0 ]; then
      check "Carved PCAP contains ${PKT_COUNT} packets" "ok"
      info "File: ${CARVE_FILE} ($(du -h "$CARVE_FILE" | cut -f1))"
    else
      check "Carved PCAP contains packets" \
        "0 packets — carve window may have had no traffic"
    fi
  else
    check "Carved PCAP file exists ($(du -h "$CARVE_FILE" | cut -f1))" "ok"
    info "Install tcpdump for packet count verification"
  fi
else
  check "Carved PCAP file exists in /tmp/" \
    "No alert_carve_*.pcap found — has pcap_manager run yet?"
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "See spike/README.md 'What to Check if Something Fails' for troubleshooting."
  exit 1
fi

echo "All spike goals verified. Ready to proceed to Phase 1 tasks."
exit 0
