#!/bin/bash
# flabel replay box provisioning. Idempotent: safe to re-run.
set -uo pipefail
exec > >(tee -a /var/log/fl-startup.log) 2>&1
echo "=== fl-replay startup $(date -Is) ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y

# Replay + capture toolchain. tcpreplay brings tcpprep/tcprewrite, which we need for
# the direction split and for rewriting destination MACs at the FW's replay legs.
apt-get install -y tcpreplay tshark suricata python3-pip curl gnupg jq chrony ethtool

# Zeek from the upstream OpenSUSE build service repo (Ubuntu has no zeek package).
if ! command -v zeek >/dev/null 2>&1; then
  echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
    > /etc/apt/sources.list.d/security-zeek.list
  curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
    | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg
  apt-get update -y
  apt-get install -y zeek
fi
# Symlinks, NOT a profile.d PATH export. Measured 2026-08-17: /etc/profile.d is read by login
# shells only, so `sudo flabel ...` — which is how a replay runs, because tcpreplay needs raw
# sockets — could not find zeek at all. The tool was installed and invisible at the same time,
# and the run failed after a full replay and a 60s settle had already been spent.
for b in zeek zeek-config zeekctl zkg; do
  [ -x "/opt/zeek/bin/$b" ] && ln -sf "/opt/zeek/bin/$b" "/usr/local/bin/$b"
done

# uv, for running flabel itself (zero runtime deps, dev-managed by uv).
if ! command -v uv >/dev/null 2>&1; then
  curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
fi

# NTP: pin to the GCE metadata server, which is what PAN-OS will also be pointed at.
# today.md requires both hosts on one clock source; the wall-clock window that bounds
# the threat-log query is only meaningful if they agree.
cat > /etc/chrony/conf.d/gce.conf <<'EOF'
server metadata.google.internal iburst prefer
EOF
systemctl restart chrony || systemctl restart chronyd || true

# Replay NICs: no offloads, and do not let the kernel answer for replayed addresses.
# We inject L2 frames directly, so the stack should stay out of the way entirely.
for i in ens5 ens6; do
  if [ -d "/sys/class/net/$i" ]; then
    ip link set "$i" up
    ethtool -K "$i" tx off rx off tso off gso off gro off lro off 2>/dev/null || true
    sysctl -w "net.ipv4.conf.$i.arp_ignore=8" 2>/dev/null || true
    sysctl -w "net.ipv4.conf.$i.rp_filter=0" 2>/dev/null || true
  fi
done
sysctl -w net.ipv4.ip_forward=1

install -d -m 0755 /opt/flabel /var/lib/flabel/captures /var/lib/flabel/runs

# The wrapper is installed FROM THE CHECKOUT, not written here. It used to live only on the box,
# which put it outside every gate the Python has — and all three bugs that reached "it is
# running" on 2026-08-17 were in it: Zeek invisible under sudo, a relative capture path resolved
# against the repo, and the config file overwriting the caller's environment. It now has tests
# (tests/test_flabel_run.py), so what matters is that the box runs the tested copy.
if [ -x /opt/flabel/repo/tools/flabel-run ]; then
  install -m 0755 /opt/flabel/repo/tools/flabel-run /usr/local/bin/flabel-run
fi
echo "=== versions ==="
tcpreplay --version 2>&1 | head -1
/opt/zeek/bin/zeek --version 2>&1 | head -1
suricata --build-info 2>&1 | head -2
echo "=== fl-replay startup COMPLETE $(date -Is) ==="
touch /var/lib/flabel/.provisioned
