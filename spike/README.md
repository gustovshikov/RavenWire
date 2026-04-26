# Network Sensor Stack — Phase 0.5 Spike

This spike validates the four highest-risk MVP assumptions before the full platform is built:

1. Zeek and Suricata can both attach to the same mirror interface with **separate AF_PACKET fanout groups** simultaneously
2. Vector forwards their events with **Community ID preserved** end-to-end
3. `pcap_ring_writer` captures to a **memory-mapped ring** in `/dev/shm`
4. A simulated alert triggers a **pre/post-alert PCAP carve** that opens correctly in Wireshark

---

## Prerequisites

- Linux host with a mirror or TAP interface available (e.g., `eth0`, `ens3`, `mirror0`)
- Go 1.21+ (for building `pcap_ring_writer` and `pcap_manager`)
- Docker or Podman with Compose support (`docker-compose` or `podman-compose`)
- `CAP_NET_RAW` available to the container runtime (or run as root for the spike)
- At least 1 GB free in `/dev/shm` (default ring size is 512 MB)
- Wireshark or `tcpdump` for verifying carved PCAPs

---

## How to Run

```bash
# Set the capture interface (must be a mirror/TAP — not your management NIC)
export CAPTURE_IFACE=eth0

# Optional tuning
export RING_SIZE_MB=512          # ring buffer size in MB (default 512)
export ALERT_DELAY_SECONDS=10    # seconds before simulated alert fires (default 10)
export PRE_ALERT_WINDOW_SECONDS=5
export POST_ALERT_WINDOW_SECONDS=3

# Start everything
docker-compose up
```

The `pcap_manager` service runs once, waits `ALERT_DELAY_SECONDS`, fires a simulated alert, and exits. All other services run continuously.

---

## Verifying Each Spike Goal

### Goal 1 — Zeek and Suricata both producing logs

```bash
# Check Zeek conn.log
docker-compose logs zeek
ls -la /var/lib/docker/volumes/spike_logs/_data/zeek/

# Check Suricata EVE JSON
docker-compose logs suricata
ls -la /var/lib/docker/volumes/spike_logs/_data/suricata/eve.json
```

Both should show log files growing as traffic arrives. If the interface has no traffic, generate some:
```bash
ping -c 10 8.8.8.8
curl -s http://example.com > /dev/null
```

### Goal 2 — Community ID present in both outputs and preserved by Vector

```bash
# Zeek conn.log — look for "community_id" field
grep community_id /var/lib/docker/volumes/spike_logs/_data/zeek/conn.log | head -5

# Suricata EVE JSON — look for "community_id" field
grep community_id /var/lib/docker/volumes/spike_logs/_data/suricata/eve.json | head -5

# Vector output — community_id must be present and unchanged
grep community_id /var/lib/docker/volumes/spike_logs/_data/vector/output.json | head -5

# Verify a specific community_id value is identical across all three
CID=$(grep -o '"community_id":"[^"]*"' \
  /var/lib/docker/volumes/spike_logs/_data/zeek/conn.log | head -1 | cut -d'"' -f4)
echo "Zeek community_id: $CID"
grep "$CID" /var/lib/docker/volumes/spike_logs/_data/vector/output.json | head -1
```

### Goal 3 — pcap_ring_writer ring stats showing packets

```bash
# Query ring stats via control socket
echo '{"cmd":"status"}' | nc -U /var/run/pcap_ring.sock

# Expected output:
# {"status":"ok","stats":{"bytes_written":12345,"packets_written":100,"wrap_count":0,"write_head":100}}
```

`packets_written` should be non-zero if traffic is flowing on `CAPTURE_IFACE`.

### Goal 4 — Carved PCAP file produced and openable in Wireshark

```bash
# After pcap_manager exits, find the carved file
ls -lh /tmp/alert_carve_*.pcap

# Verify it's a valid PCAP (check magic number)
xxd /tmp/alert_carve_*.pcap | head -2
# Should show: d4 c3 b2 a1 (little-endian magic 0xa1b2c3d4)

# Open in Wireshark
wireshark /tmp/alert_carve_*.pcap

# Or inspect with tcpdump
tcpdump -r /tmp/alert_carve_*.pcap -n | head -20

# Check packet count matches pcap_manager output
tcpdump -r /tmp/alert_carve_*.pcap -n | wc -l
```

The carved PCAP should contain packets timestamped from `(alert_time - PRE_ALERT_WINDOW_SECONDS)` to `(alert_time + POST_ALERT_WINDOW_SECONDS)`.

---

## Known Limitations and Findings

> _This section is filled in by the operator after running the spike._

### Ring Wraparound Edge Cases

**Implementation notes from build:**

- The ring uses a two-region layout: a fixed-size index region (`maxPackets × 24 bytes` = ~24MB for 1M slots) followed by a data region (remainder of the mmap'd file). This means a 512MB ring has ~488MB for packet data.
- Wraparound is handled at the data region level: when a packet doesn't fit at the current write offset, the gap is zeroed and the write restarts at offset 0. The index record stores the `Offset` within the data region, so carve reads always use `indexRegionSize + rec.Offset` as the absolute address.
- **Known limitation**: if a carve window spans a data region wrap boundary, packets whose data was overwritten by newer packets will have stale data at their recorded offset. The carve code skips records where `dataStart + capLen > ringSize` as a safety check, but this means some packets in the window may be silently dropped from the carve. For Phase 1, the ring should be sized large enough that the pre-alert window data is never overwritten before the carve completes.
- The index region itself wraps at `maxPackets` (1M slots). At 1Mpps this gives ~1 second of index history. For Phase 1, `maxPackets` should be made configurable or sized relative to the ring size.

### Timestamp Alignment Issues

**Implementation notes from build:**

- `pcap_ring_writer` timestamps packets using `time.Now().UnixMilli()` at the point of `recvfrom()` return. This is the userspace receive time, not the kernel capture time. At high packet rates, userspace scheduling jitter can cause timestamps to be slightly later than the actual capture time.
- For accurate pre-alert window carving, the pre-alert mark timestamp (`mark_pre_alert.timestamp_ms`) should use the same clock source as the ring writer. In the spike, both `pcap_manager` and `pcap_ring_writer` use `time.Now()` which is consistent within a single host.
- NTP synchronization is required if timestamps from Zeek/Suricata (which use kernel timestamps) are compared against ring writer timestamps. A clock offset > 1ms can cause packets to fall outside the carve window.
- **Recommendation for Phase 1**: use `SO_TIMESTAMPNS` or `TPACKET_V3` block timestamps (which are kernel-assigned) instead of userspace `time.Now()` for more accurate packet timestamps.

### Tool-Specific BPF Reload Constraints

**Implementation notes from build:**

- **Zeek**: The `af_packet` plugin in Zeek does not support live BPF filter updates via SIGHUP. A BPF filter change requires restarting the Zeek process (or at minimum the af_packet worker). The Sensor_Agent's Config Applier must account for this by writing the new filter to Zeek's config and sending SIGTERM + restart, not just SIGHUP.
- **Suricata**: Suricata's `SIGUSR2` reloads rules but does NOT reload the `bpf-filter` field in `suricata.yaml`. A BPF filter change requires a full Suricata restart. This is a significant constraint for Phase 1 hot-reload.
- **pcap_ring_writer**: The `configure` command in the spike logs the new BPF filter but does not reattach `SO_ATTACH_FILTER` to the live socket. For Phase 1, the implementation must call `setsockopt(SO_ATTACH_FILTER)` with the new compiled BPF program. This can be done without rebinding the socket.
- **Recommendation**: Document in the Phase 1 design that BPF filter changes for Zeek and Suricata require a controlled restart (not a live reload), and that only `pcap_ring_writer` supports live BPF updates.

### AF_PACKET Fanout Group Behavior

**Implementation notes from build:**

- `PACKET_FANOUT` requires that all sockets joining the same group be created by the same process (or processes with the same effective UID). Zeek and Suricata each create their own fanout groups (1 and 2 respectively), so there is no cross-tool interference.
- The `PACKET_FANOUT_HASH` mode distributes packets across a tool's internal worker threads based on flow hash. Each tool receives the full traffic stream independently — there is no packet duplication between tools.
- **Known issue with spike**: `PACKET_FANOUT` join (`setsockopt(PACKET_FANOUT)`) requires at least two sockets in the group to be meaningful. The spike's `pcap_ring_writer` uses a single socket, so the fanout join may return `EINVAL` or be silently ignored. This is logged as a warning and does not prevent capture. For Phase 1, if `pcap_ring_writer` uses multiple worker goroutines, each must create its own socket and join the same fanout group.
- Drop rates under load were not measured in this spike (no traffic generator was used). Phase 1 should include a drop counter test using `PACKET_STATISTICS` socket option.

### Community ID Consistency

**Implementation notes from build:**

- Zeek emits `community_id` in `conn.log` and all protocol logs when `Community_ID::enabled = T` is set. The field name is `community_id` (lowercase, underscore).
- Suricata emits `community_id` in EVE JSON when `community-id: yes` is set in the outputs section. The field name is also `community_id`.
- Vector's remap transform preserves the field unchanged — no renaming or modification occurs. The `parse_json!()` call in the remap source deserializes the field, and it is re-serialized with the same name and value.
- **Known edge case**: ICMP flows may produce different Community ID values between Zeek and Suricata due to differences in how each tool maps ICMP type/code to the 5-tuple used for the hash. This is a known limitation of the Community ID spec for ICMP and is not a bug in either tool.
- **Recommendation**: Add a Vector transform test in Phase 1 that asserts `community_id` is present and non-empty in the output for every input record that had it.

### Design Notes for Phase 1

**Adjustments identified during spike build:**

1. **Ring index sizing**: `maxPackets` should be configurable (env `RING_MAX_PACKETS`, default 1M). For high-rate interfaces, 1M slots may be exhausted in under a second. Consider sizing it as `ring_size_bytes / avg_packet_size / 2` as a heuristic.
2. **Kernel timestamps**: Replace `time.Now().UnixMilli()` with `SO_TIMESTAMPNS` or TPACKET_V3 block timestamps for accurate packet timing.
3. **BPF reload path**: Document that Zeek and Suricata require restart (not SIGHUP) for BPF filter changes. Only `pcap_ring_writer` supports live BPF updates.
4. **Fanout group validation**: The Sensor_Agent must validate fanout group uniqueness before starting any capture process. The spike confirms that duplicate group IDs would cause `EINVAL` on the second `setsockopt(PACKET_FANOUT)` call.
5. **Control socket authentication**: The Unix socket control interface has no authentication in the spike. For Phase 1, restrict socket permissions to `sensor-svc` (UID 10000) and validate that only the Sensor_Agent process connects.
6. **Vector multiline config**: The `multiline` config in the Vector Zeek source may not be needed — Zeek JSON logs are already one record per line. Remove it in Phase 1 to avoid false multiline merges.

---

## What to Check if Something Fails

### Zeek not producing logs
- Verify `CAPTURE_IFACE` is set to a real interface with traffic
- Check `docker-compose logs zeek` for AF_PACKET bind errors
- Ensure `CAP_NET_RAW` and `CAP_NET_ADMIN` are granted
- Try `zeek -i af_packet::eth0 -C` manually inside the container

### Suricata not producing logs
- Check `/logs/suricata/suricata.log` for startup errors
- Verify the `cluster-id: 2` in `suricata.yaml` doesn't conflict with Zeek's group 1
- Ensure the interface name in `suricata.yaml` matches `CAPTURE_IFACE`

### Vector output.json empty
- Check `docker-compose logs vector` for source errors
- Verify `/logs/zeek/*.log` and `/logs/suricata/eve.json` exist and are non-empty
- Check Vector's buffer directory permissions

### pcap_ring_writer not writing packets
- Verify `/dev/shm` is mounted and has sufficient space (`df -h /dev/shm`)
- Check `docker-compose logs pcap_ring_writer` for socket bind errors
- Confirm `CAP_NET_RAW` is granted to the container
- Test the control socket: `echo '{"cmd":"status"}' | nc -U /var/run/pcap_ring.sock`

### pcap_manager fails to connect
- Ensure `pcap_ring_writer` is running and the control socket exists at `/var/run/pcap_ring.sock`
- Check that both containers share the `/var/run` volume mount
- Increase `ALERT_DELAY_SECONDS` to give `pcap_ring_writer` more time to start

### Carved PCAP is empty (0 packets)
- The ring may not have received any packets during the carve window
- Generate traffic during the `ALERT_DELAY_SECONDS` window
- Verify `pcap_ring_writer` stats show `packets_written > 0` before the carve
- Check that `CAPTURE_IFACE` has traffic flowing (not a loopback or idle interface)

### PCAP file fails to open in Wireshark
- Verify the magic number: `xxd /tmp/alert_carve_*.pcap | head -1` should show `d4 c3 b2 a1`
- If the file is 24 bytes (header only), the carve window had no matching packets
- Check that system clock is synchronized (NTP) so timestamps are accurate
