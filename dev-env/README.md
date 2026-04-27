# Development Environment

Vagrant + VirtualBox VM that mirrors the target sensor node environment.

## Why Vagrant/VirtualBox

- AF_PACKET is Linux-only — macOS cannot run the capture stack natively
- VirtualBox supports promiscuous mode on virtual NICs, needed for traffic replay in Phase 1
- The `Vagrantfile` is version-controlled — any contributor gets an identical environment with `vagrant up`
- The veth pair setup mirrors how a real sensor node uses a mirror/TAP interface

## Quick Start (Recommended)

Install `sensorctl` on your Mac, then run the full automated test with one command:

```bash
# Install prerequisites
brew install --cask virtualbox vagrant
brew install go

# Build sensorctl on macOS
bash dev-env/install-sensorctl-mac.sh
export PATH="$PWD/bin:$PATH"

# Run the full automated spike test
# (boots VM, starts stack, generates traffic, verifies, halts VM)
sensorctl dev test-spike
```

That's it. `sensorctl dev test-spike` handles everything end-to-end.

## Manual Setup (if you prefer step-by-step)

```bash
# Install VirtualBox
brew install --cask virtualbox

# Install Vagrant
brew install --cask vagrant

# Optional: faster shared folder sync
vagrant plugin install vagrant-vbguest
```

## First Boot

```bash
# From the repo root
vagrant up        # ~5-10 min first time (downloads box, provisions)
vagrant ssh       # SSH into the VM
```

## Running the Spike

```bash
# Inside the VM
cd /vagrant
CAPTURE_IFACE=veth0 docker compose -p spike -f deploy/compose/docker-compose.spike.yml up -d

# In a second terminal (inside VM), generate traffic
sudo /vagrant/dev-env/gen-traffic.sh

# Wait ~15 seconds for pcap_manager to fire its simulated alert, then verify
/vagrant/dev-env/verify-spike.sh
```

## VM Details

| Property | Value |
|---|---|
| OS | Ubuntu 22.04 LTS (Jammy) |
| RAM | 8GB |
| CPUs | 4 |
| Capture interface | `veth0` (fanout groups 1–4) |
| Traffic injection | `veth1` (10.99.0.1/24) |
| Ring buffer | `/dev/shm` (2GB) |
| Control socket | `/var/run/pcap_ring.sock` |
| Config Mgr port | 8443 (forwarded to host) |

## Useful Commands

```bash
# Rebuild spike binaries after code changes
cd /vagrant/spike/pcap_ring_writer && go build -o /usr/local/bin/pcap_ring_writer .
cd /vagrant/spike/pcap_manager && go build -o /usr/local/bin/pcap_manager .

# Check veth pair is up
ip link show veth0 veth1

# Check ring buffer space
df -h /dev/shm

# Query pcap_ring_writer stats directly
echo '{"cmd":"status"}' | nc -U /var/run/pcap_ring.sock | jq .

# Inspect a carved PCAP
tcpdump -r /tmp/alert_carve_*.pcap -n | head -20

# Tail Vector output
tail -f /var/lib/docker/volumes/spike_logs/_data/vector/output.json | jq .community_id

# Re-provision if needed (e.g., after Vagrantfile changes)
vagrant provision
```

## Phase 1 Notes

When Phase 1 tasks begin, the same VM is used. Additional setup will be added to `provision.sh` as needed:
- Elixir/OTP for Config_Manager development
- Podman + Quadlet for container definitions
- mTLS certificate tooling

The `Vagrantfile` forwards port 8443 to the host so the Config_Manager LiveView UI is accessible at `https://localhost:8443` from your macOS browser.

## sensorctl Commands

```bash
# VM management
sensorctl env up                    # boot VM
sensorctl env up --provision        # boot + force re-provision
sensorctl env down                  # halt VM
sensorctl env status                # show VM state
sensorctl env ssh                   # SSH into VM
sensorctl env destroy -f            # destroy VM completely

# Testing
sensorctl test spike                # full automated spike test (boot → traffic → verify → halt)
sensorctl test spike --keep-running # leave VM running after test
sensorctl test spike --skip-boot    # skip boot (VM already running)
sensorctl test spike --alert-delay 20 --traffic-duration 40  # custom timing
sensorctl test verify               # just run verify-spike.sh (no traffic gen)
```
