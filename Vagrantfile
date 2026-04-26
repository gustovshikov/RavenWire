# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Network Sensor Stack — Development Environment
#
# Provides a Linux VM that mirrors the target sensor node environment.
# Includes a veth pair for AF_PACKET testing without physical hardware.
#
# Usage:
#   vagrant up
#   vagrant ssh
#   cd /vagrant/spike && CAPTURE_IFACE=veth0 docker-compose up
#
# Traffic generation (inside VM):
#   sudo /vagrant/dev-env/gen-traffic.sh
#
# Requirements:
#   - VirtualBox 7.x
#   - Vagrant 2.3+
#   - vagrant-vbguest plugin (optional, for shared folder perf):
#       vagrant plugin install vagrant-vbguest

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.box_version = ">= 20240101.0.0"
  config.vm.hostname = "sensor-dev"

  # ── VM resources ────────────────────────────────────────────────────────────
  config.vm.provider "virtualbox" do |vb|
    vb.name   = "sensor-dev"
    vb.memory = 8192   # 8GB — Zeek + Suricata + ring buffer need headroom
    vb.cpus   = 4

    # Enable promiscuous mode on the NAT NIC (needed for packet capture tests)
    vb.customize ["modifyvm", :id, "--nicpromisc1", "allow-all"]

    # Increase video memory to avoid VirtualBox warnings
    vb.customize ["modifyvm", :id, "--vram", "16"]

    # Disable USB to avoid driver issues
    vb.customize ["modifyvm", :id, "--usb", "off"]
  end

  # ── Network ─────────────────────────────────────────────────────────────────
  # Private network for host↔VM file transfer and future multi-VM setups
  config.vm.network "private_network", ip: "192.168.56.10"

  # Forward Config_Manager web UI port (used in Phase 1)
  config.vm.network "forwarded_port", guest: 8443, host: 8443, auto_correct: true

  # ── Shared folder ───────────────────────────────────────────────────────────
  # Mount the repo root into the VM so edits on macOS are immediately visible
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  # ── Provisioning ────────────────────────────────────────────────────────────
  config.vm.provision "shell", path: "dev-env/provision.sh", privileged: true

  # Print usage after first boot
  config.vm.post_up_message = <<~MSG
    ╔══════════════════════════════════════════════════════════════╗
    ║  sensor-dev VM is ready                                      ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  From your Mac (repo root):                                  ║
    ║    sensorctl test spike          — full automated spike test ║
    ║    sensorctl test spike --keep-running  — leave VM up after  ║
    ║    sensorctl env ssh             — SSH into VM               ║
    ║    sensorctl env down            — halt VM                   ║
    ║                                                              ║
    ║  Inside the VM:                                              ║
    ║    cd /vagrant/spike                                         ║
    ║    CAPTURE_IFACE=veth0 docker-compose up                     ║
    ║    sudo /vagrant/dev-env/gen-traffic.sh                      ║
    ║    /vagrant/dev-env/verify-spike.sh                          ║
    ║                                                              ║
    ║  Config Mgr UI (Phase 1): https://localhost:8443             ║
    ╚══════════════════════════════════════════════════════════════╝
  MSG
end
