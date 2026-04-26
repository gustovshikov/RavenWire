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

if [ -S "$CONTROL_SOCK" ]; then
  STATS=$(echo '{"cmd":"status"}' | nc -U -w 2 "$CONTROL_SOCK" 2>/dev/null || echo "")
  if [ -n "$STATS" ]; then
    PKTS=$(echo "$STATS" | jq -r '.stats.packets_written // 0' 2>/dev/null || echo "0")
    if [ "$PKTS" -gt 0 ] 2>/dev/null; then
      check "pcap_ring_writer packets_written=${PKTS}" "ok"
    else
      check "pcap_ring_writer packets_written > 0" \
        "Got ${PKTS} — is traffic flowing on CAPTURE_IFACE?"
    fi
    WRAPS=$(echo "$STATS" | jq -r '.stats.wrap_count // 0' 2>/dev/null || echo "0")
    info "Ring stats: $(echo "$STATS" | jq -c '.stats' 2>/dev/null || echo "$STATS")"
  else
    check "pcap_ring_writer control socket responding" \
      "No response from ${CONTROL_SOCK}"
  fi
else
  check "pcap_ring_writer control socket exists" \
    "Socket not found: ${CONTROL_SOCK} — is pcap_ring_writer running?"
fi

echo ""

# ── Goal 4: Carved PCAP valid ────────────────────────────────────────────────
echo "Goal 4: Carved PCAP file valid"

CARVE_FILE=$(ls -t /tmp/alert_carve_*.pcap 2>/dev/null | head -1 || echo "")

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
