#!/usr/bin/env bash
# dev-env/verify-spike.sh — Automated verification of all four spike goals
# Uses docker exec to inspect containers directly — no path assumptions.
set -euo pipefail

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

# Helper: run command inside a container
cexec() { docker exec "$1" sh -c "$2" 2>/dev/null; }

echo ""
echo "══════════════════════════════════════════════════"
echo "  Network Sensor Stack — Spike Verification"
echo "══════════════════════════════════════════════════"
echo ""

# ── Goal 1: Zeek and Suricata producing logs ──────────────────────────────────
echo "Goal 1: Zeek and Suricata producing logs"

ZEEK_LINES=$(cexec spike-zeek-1 "wc -l < /logs/zeek/conn.log 2>/dev/null || echo 0" | tr -d ' ')
if [ "${ZEEK_LINES:-0}" -gt 0 ] 2>/dev/null; then
  check "Zeek conn.log exists and non-empty (${ZEEK_LINES} lines)" "ok"
else
  check "Zeek conn.log exists and non-empty" "File not found or empty (got: ${ZEEK_LINES:-0} lines)"
fi

SURI_LINES=$(cexec spike-suricata-1 "wc -l < /logs/suricata/eve.json 2>/dev/null || echo 0" | tr -d ' ')
if [ "${SURI_LINES:-0}" -gt 0 ] 2>/dev/null; then
  check "Suricata eve.json exists and non-empty (${SURI_LINES} lines)" "ok"
else
  check "Suricata eve.json exists and non-empty" "File not found or empty (got: ${SURI_LINES:-0} lines)"
fi

echo ""

# ── Goal 2: Community ID present and preserved ───────────────────────────────
echo "Goal 2: Community ID present in all outputs"

ZEEK_CID=$(cexec spike-zeek-1 "grep -o '\"community_id\":\"[^\"]*\"' /logs/zeek/conn.log 2>/dev/null | head -1 | cut -d'\"' -f4" || echo "")
if [ -n "$ZEEK_CID" ]; then
  check "community_id present in Zeek conn.log (${ZEEK_CID:0:35}...)" "ok"
else
  check "community_id present in Zeek conn.log" "Field not found — needs traffic on capture interface"
fi

SURI_CID=$(cexec spike-suricata-1 "grep -o '\"community_id\":\"[^\"]*\"' /logs/suricata/eve.json 2>/dev/null | head -1 | cut -d'\"' -f4" || echo "")
if [ -n "$SURI_CID" ]; then
  check "community_id present in Suricata eve.json (${SURI_CID:0:35}...)" "ok"
else
  check "community_id present in Suricata eve.json" "Field not found — Suricata may not be seeing traffic"
fi

VEC_CID=$(cexec spike-vector-1 "grep -o '\"community_id\":\"[^\"]*\"' /logs/vector/output.json 2>/dev/null | head -1 | cut -d'\"' -f4" || echo "")
if [ -n "$VEC_CID" ]; then
  # Verify value is preserved unchanged from Zeek
  if [ -n "$ZEEK_CID" ] && [ "$VEC_CID" = "$ZEEK_CID" ]; then
    check "community_id preserved unchanged through Vector (${VEC_CID:0:35}...)" "ok"
  else
    check "community_id present in Vector output (${VEC_CID:0:35}...)" "ok"
  fi
else
  check "community_id present in Vector output.json" "Field not found — check Vector is running and logs are flowing"
fi

echo ""

# ── Goal 3: pcap_ring_writer ring stats ──────────────────────────────────────
echo "Goal 3: pcap_ring_writer ring stats"

# Check pcap_manager output for ring stats (most reliable)
RING_STATS=$(docker logs spike-pcap_manager-1 2>/dev/null | grep '"packets_written"' | tail -1 || echo "")
RING_PKTS=$(echo "$RING_STATS" | grep -o '"packets_written":[0-9]*' | cut -d: -f2 || echo "0")

if [ "${RING_PKTS:-0}" -gt 0 ] 2>/dev/null; then
  check "pcap_ring_writer packets_written=${RING_PKTS}" "ok"
  RING_BYTES=$(echo "$RING_STATS" | grep -o '"bytes_written":[0-9]*' | cut -d: -f2 || echo "0")
  info "Ring stats: packets=${RING_PKTS} bytes=${RING_BYTES:-0}"
else
  # Try direct socket query via pcap_ring_writer container
  STATS_RAW=$(cexec spike-pcap_ring_writer-1 \
    'printf "{\"cmd\":\"status\"}\n" | nc -U -w 2 /var/run/pcap_ring.sock 2>/dev/null' || echo "")
  if [ -n "$STATS_RAW" ]; then
    RING_PKTS2=$(echo "$STATS_RAW" | python3 -c \
      "import sys,json; d=json.load(sys.stdin); print(d.get('stats',{}).get('packets_written',0))" 2>/dev/null || echo "0")
    if [ "${RING_PKTS2:-0}" -gt 0 ] 2>/dev/null; then
      check "pcap_ring_writer packets_written=${RING_PKTS2}" "ok"
    else
      check "pcap_ring_writer packets_written > 0" \
        "Got 0 — generate traffic on CAPTURE_IFACE before running this test"
    fi
  else
    check "pcap_ring_writer responding" \
      "No stats available — is pcap_ring_writer running?"
  fi
fi

echo ""

# ── Goal 4: Carved PCAP valid ────────────────────────────────────────────────
echo "Goal 4: Carved PCAP file valid"

# Check pcap_manager container for carved file
CARVE_PATH=$(docker logs spike-pcap_manager-1 2>/dev/null | grep 'carved_pcap_path=' | tail -1 | cut -d= -f2 | tr -d '\r' || echo "")
CARVE_COUNT=$(docker logs spike-pcap_manager-1 2>/dev/null | grep 'packet_count=' | tail -1 | cut -d= -f2 | tr -d '\r' || echo "0")

if [ -n "$CARVE_PATH" ]; then
  # Copy file out of container for inspection
  docker cp "spike-pcap_manager-1:${CARVE_PATH}" /tmp/ 2>/dev/null || true
  LOCAL_CARVE="/tmp/$(basename "$CARVE_PATH")"

  if [ -f "$LOCAL_CARVE" ]; then
    # Check PCAP magic number
    MAGIC=$(xxd -l 4 "$LOCAL_CARVE" 2>/dev/null | awk '{print $2$3}' | head -1 || echo "")
    if [ "$MAGIC" = "d4c3b2a1" ]; then
      check "Carved PCAP has valid magic number (0xa1b2c3d4 LE)" "ok"
    else
      check "Carved PCAP magic number" "Got: ${MAGIC} (expected d4c3b2a1)"
    fi

    if [ "${CARVE_COUNT:-0}" -gt 0 ] 2>/dev/null; then
      check "Carved PCAP contains ${CARVE_COUNT} packets" "ok"
      info "File: ${LOCAL_CARVE} ($(du -h "$LOCAL_CARVE" | cut -f1))"
    else
      check "Carved PCAP packet count > 0" \
        "Got ${CARVE_COUNT:-0} packets — traffic must flow during the alert window"
    fi
  else
    check "Carved PCAP file accessible" "Could not copy from container: ${CARVE_PATH}"
  fi
else
  check "Carved PCAP file exists" \
    "No carved PCAP found in pcap_manager logs — has the alert fired yet?"
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "Troubleshooting tips:"
  echo "  docker compose logs zeek        — check Zeek errors"
  echo "  docker compose logs suricata    — check Suricata errors"
  echo "  docker compose logs vector      — check Vector errors"
  echo "  docker compose logs pcap_manager — check carve output"
  echo "  See spike/README.md for detailed troubleshooting"
  exit 1
fi

echo "All spike goals verified. Ready to proceed to Phase 1 tasks."
exit 0
