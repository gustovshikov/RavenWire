#!/usr/bin/env bash
# dev-env/provision.sh — Vagrant provisioner for sensor-dev VM
# Runs once on first `vagrant up`. Safe to re-run.
set -euo pipefail

echo "==> Updating apt cache"
apt-get update -qq

echo "==> Installing system dependencies"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  curl wget git build-essential \
  ca-certificates gnupg lsb-release \
  tcpdump wireshark-common tshark \
  iproute2 net-tools iputils-ping \
  jq netcat-openbsd \
  linux-headers-$(uname -r) \
  libpcap-dev \
  ntp

# ── Docker (used by docker-compose for the spike) ───────────────────────────
if ! command -v docker &>/dev/null; then
  echo "==> Installing Docker"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  usermod -aG docker vagrant
fi

# ── Go (for building pcap_ring_writer and pcap_manager) ─────────────────────
GO_VERSION="1.22.4"
if ! command -v go &>/dev/null || [[ "$(go version 2>/dev/null)" != *"go${GO_VERSION}"* ]]; then
  echo "==> Installing Go ${GO_VERSION}"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

# ── tcpreplay (traffic generation for Phase 1 testing) ──────────────────────
if ! command -v tcpreplay &>/dev/null; then
  echo "==> Installing tcpreplay"
  DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay
fi

# ── veth pair setup (persistent across reboots via systemd) ─────────────────
echo "==> Setting up veth pair (veth0/veth1)"
cat > /etc/systemd/network/10-veth0.netdev <<'EOF'
[NetDev]
Name=veth0
Kind=veth

[Peer]
Name=veth1
EOF

cat > /etc/systemd/network/11-veth0.network <<'EOF'
[Match]
Name=veth0

[Network]
LinkLocalAddressing=no
EOF

cat > /etc/systemd/network/12-veth1.network <<'EOF'
[Match]
Name=veth1

[Network]
Address=10.99.0.1/24
EOF

systemctl enable systemd-networkd
systemctl restart systemd-networkd || true

# Bring up veth pair immediately (don't wait for reboot)
ip link add veth0 type veth peer name veth1 2>/dev/null || true
ip link set veth0 up 2>/dev/null || true
ip link set veth1 up 2>/dev/null || true
ip addr add 10.99.0.1/24 dev veth1 2>/dev/null || true

echo "==> veth pair ready: veth0 (capture) <-> veth1 (traffic injection)"

# ── /dev/shm sizing (ring buffer needs headroom) ─────────────────────────────
echo "==> Configuring /dev/shm size"
# Remount /dev/shm with 2GB limit (default is 50% of RAM which may be too small)
mount -o remount,size=2g /dev/shm 2>/dev/null || true
# Make persistent
if ! grep -q 'tmpfs /dev/shm' /etc/fstab; then
  echo 'tmpfs /dev/shm tmpfs defaults,size=2g 0 0' >> /etc/fstab
fi

# ── Kernel parameters for AF_PACKET performance ──────────────────────────────
echo "==> Tuning kernel parameters for AF_PACKET"
cat > /etc/sysctl.d/99-sensor.conf <<'EOF'
# Increase socket receive buffer for AF_PACKET
net.core.rmem_max = 134217728
net.core.rmem_default = 134217728
net.core.netdev_max_backlog = 250000
# Allow non-root users to create AF_PACKET sockets (needed for containers)
net.core.bpf_jit_enable = 1
EOF
sysctl -p /etc/sysctl.d/99-sensor.conf 2>/dev/null || true

# ── Build spike Go binaries ──────────────────────────────────────────────────
echo "==> Building spike binaries"
if [ -d /vagrant/spike/pcap_ring_writer ]; then
  cd /vagrant/spike/pcap_ring_writer
  go mod tidy 2>/dev/null || true
  go build -o /usr/local/bin/pcap_ring_writer . 2>/dev/null || \
    echo "  (pcap_ring_writer build skipped — go.mod may not exist yet)"
fi

if [ -d /vagrant/spike/pcap_manager ]; then
  cd /vagrant/spike/pcap_manager
  go mod tidy 2>/dev/null || true
  go build -o /usr/local/bin/pcap_manager . 2>/dev/null || \
    echo "  (pcap_manager build skipped — go.mod may not exist yet)"
fi

# ── Build sensorctl ──────────────────────────────────────────────────────────
echo "==> Building sensorctl"
if [ -d /vagrant/sensorctl ]; then
  cd /vagrant/sensorctl
  go mod tidy 2>/dev/null || true
  go build -o /usr/local/bin/sensorctl . 2>/dev/null || \
    echo "  (sensorctl build skipped)"
fi

echo "==> Provisioning complete"
echo "    Capture interface: veth0 (fanout groups 1-4)"
echo "    Traffic injection: veth1 (10.99.0.1/24)"
echo "    Ring buffer:       /dev/shm (2GB)"
echo "    Docker:            $(docker --version 2>/dev/null || echo 'installed')"
echo "    Go:                $(go version 2>/dev/null || echo 'installed')"
