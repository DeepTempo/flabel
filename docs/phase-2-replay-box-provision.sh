#!/bin/bash
# flabel replay box provisioning. Idempotent: safe to re-run.
set -uo pipefail
exec > >(tee -a /var/log/fl-startup.log) 2>&1
echo "=== fl-replay startup $(date -Is) ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y

# Replay + capture toolchain. tcpreplay brings tcpprep/tcprewrite, which we need for
# the direction split and for rewriting destination MACs at the FW's replay legs.
apt-get install -y tcpreplay tshark python3-pip curl gnupg jq chrony ethtool software-properties-common

# Suricata from ppa:oisf/suricata-stable, NOT plain apt (#142). noble/universe tops out at
# 7.0.3, and 7.0.3 skips any rule marked `requires: version >= 8.0.0` — measured on 2026-08-24 as
# "84958 rules successfully loaded, 0 rules failed, 2 rules were skipped because the running
# Suricata version 7.0.3 is less than 8.0.0". §2.4 attests a tier only on rules_loaded ==
# total_admitted, so those 2 skipped rules meant tier 2 was NEVER attested and every tier-2 run
# contributed rows that could not become current.
#
# The version is pinned and then HELD. Pinned because it must equal Dockerfile.toolchain's
# SURICATA_PACKAGE_VERSION or CI and the box disagree about what produced a label; held because
# an unattended `apt upgrade` would otherwise move the engine underneath a corpus already
# labelled with it, and nothing in the store would record that it happened.
SURICATA_PACKAGE_VERSION=1:8.0.6-0ubuntu0
if ! dpkg-query -W -f='${Version}' suricata 2>/dev/null | grep -qx "$SURICATA_PACKAGE_VERSION"; then
  add-apt-repository -y ppa:oisf/suricata-stable
  apt-get update -y
  # The OISF package bundles /usr/bin/suricata-update, which Ubuntu ships as its own package;
  # dpkg refuses to overwrite across packages, so the standalone one goes first. Nothing in
  # flabel calls suricata-update — rules/{fetch,admit,snapshot} do that job — and the only
  # reverse-dependency was Ubuntu's own suricata.
  apt-get remove -y suricata suricata-update || true
  apt-get install -y "suricata=$SURICATA_PACKAGE_VERSION"
  apt-mark hold suricata
fi

# Wireshark from ppa:wireshark-dev/stable, for the same reason as Suricata: noble ships 4.2.2 and
# the pin is 4.6.6. editcap and capinfos are not incidental tools here — editcap performs capture
# NORMALISATION, so a version the CI toolchain does not test is a version producing corpus input
# nobody has checked. capinfos and editcap both come from wireshark-common; tshark is separate and
# is what selects one link type out of a multi-interface pcapng.
#
# The setuid prompt is preseeded off because nothing on this box captures live traffic — it replays.
WIRESHARK_PACKAGE_VERSION=4.6.6-1~ubuntu24.04.0~ppa1
if ! dpkg-query -W -f='${Version}' wireshark-common 2>/dev/null | grep -qx "$WIRESHARK_PACKAGE_VERSION"; then
  add-apt-repository -y ppa:wireshark-dev/stable
  apt-get update -y
  echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
  apt-get install -y "wireshark-common=$WIRESHARK_PACKAGE_VERSION" "tshark=$WIRESHARK_PACKAGE_VERSION"
  apt-mark hold wireshark-common tshark
fi

# The OISF package installs /etc/suricata as 0750 suricata:suricata; Ubuntu's was world-readable.
# Suricata resolves `reference-config-file` and `threshold-config` against /etc/suricata even when
# flabel's own config declines to name them, so an unreadable directory turns every run's log into
# "Error: reference-config: Permission denied". Measured harmless to label content — flabel's
# suricata.yaml records that the reference config changes the load by 0 rules — but it is noise in
# a log that is read, and it fails the regression test that asserts the engine parses our config
# cleanly. Nothing secret lives in that directory.
[ -d /etc/suricata ] && chmod o+rx /etc/suricata && chmod o+r /etc/suricata/*.config /etc/suricata/*.yaml 2>/dev/null

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

# The Zeek JA4 package. Installed here rather than by hand, because a tool installed by hand
# is a box that cannot be rebuilt — the lesson #142 records about Suricata, which this script
# still installs from plain apt and which is therefore still wrong (Phase 4 P4-1).
#
# Pinned to the same tag AND commit as Dockerfile.toolchain. The commit check is not
# ceremony: JA4 values ride on published labels, so a moved tag would silently change what
# the store holds, and the two would disagree with no version number moving. If it fires,
# verify upstream before touching the pin.
#
# It must be a version pin and not `latest` for the same reason. zkg's own dependencies
# (python3-git, python3-semantic-version) arrive with the zeek-zkg package, so nothing extra
# is needed here — but zkg's shebang is `#!/usr/bin/env python3`, so it must not be called
# with a virtualenv ahead of /usr/bin on PATH. At boot, as root, it is not.
# zkg's shebang is `#!/usr/bin/env python3`, which resolves through PATH. Under `uv run` the
# project virtualenv comes first and that interpreter has none of zkg's dependencies — so zkg
# breaks only when called from a test, which is the one place it needs to work. Bind it to the
# interpreter that actually has GitPython and semantic-version, exactly as Dockerfile.toolchain
# does. Re-applied on every run because a zeek-zkg package upgrade restores the original.
[ -x /opt/zeek/bin/zkg ] && sed -i '1s|.*|#!/usr/bin/python3|' /opt/zeek/bin/zkg

JA4_PACKAGE_VERSION=v0.18.8
JA4_PACKAGE_COMMIT=3ecddb5f1d0b92210535171a62901bf3d596c7b8
if ! /opt/zeek/bin/zeek --parse-only -e '@load ja4' >/dev/null 2>&1; then
  zkg autoconfig
  zkg install --force --version "$JA4_PACKAGE_VERSION" zeek/foxio/ja4
  clone="$(zkg config | sed -n 's/^state_dir = //p' | head -1)/clones/package/ja4"
  resolved="$(git -C "$clone" rev-parse HEAD)"
  if [ "$resolved" != "$JA4_PACKAGE_COMMIT" ]; then
    echo "ja4 tag $JA4_PACKAGE_VERSION resolved to $resolved, expected $JA4_PACKAGE_COMMIT." >&2
    echo "A moved tag changes JA4 values on labels. Verify upstream, then update the pin." >&2
    exit 1
  fi
fi
# The gate is the capability, not the directory: a package installed somewhere Zeek will not
# load it is exactly the failure worth catching, and it is how src/flabel/zeek.py asks.
/opt/zeek/bin/zeek --parse-only -e '@load ja4' || {
  echo "ja4 installed but @load ja4 still fails — check ZEEKPATH and the zkg install." >&2
  exit 1
}

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
