#!/bin/bash
# flabel replay box provisioning. Idempotent: safe to re-run.
set -uo pipefail
exec > >(tee -a /var/log/fl-startup.log) 2>&1
echo "=== fl-replay startup $(date -Is) ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y || die "apt-get update failed — every install below depends on it"

# Replay + capture toolchain. tcpreplay brings tcpprep/tcprewrite, which we need for
# the direction split and for rewriting destination MACs at the FW's replay legs.
# `tshark` is deliberately NOT here — the pinned Wireshark block below owns it, and installing
# noble's 4.2.2 first only to replace it wastes a boot and briefly leaves a mismatched binary.
# `git` is needed by the ja4 commit check and is NOT present on every image; `ca-certificates`
# by add-apt-repository and by the curl below. Both were assumed before.
apt-get install -y tcpreplay python3-pip curl gnupg jq chrony ethtool \
  software-properties-common git ca-certificates \
  || die "the base toolchain did not install"

#: A package is at a pinned version only if dpkg says it is INSTALLED at it. `${Version}` alone is
#: printed for a removed-but-conffiles (`rc`) package too, so a box where Suricata was removed by
#: hand would report the pin and skip the install — leaving no engine at all. `grep -F` because a
#: Debian version is full of regex metacharacters: `1:8.0.6` matches `1X8Y0Z6` without it.
pinned_at() {
  # `grep -Fx >/dev/null`, NOT `grep -Fqx`: -q exits on the first match and closes the pipe, so
  # dpkg-query can take SIGPIPE and exit 141 — and `set -o pipefail` then makes this function
  # report "not pinned" for a correctly pinned package, which now costs a spurious `die`.
  dpkg-query -W -f='${db:Status-Status} ${Version}' "$1" 2>/dev/null | grep -Fx "installed $2" >/dev/null
}

#: Fail the whole provision, loudly. This script runs WITHOUT `set -e`, so every step that must
#: not be skipped past has to say so itself.
#:
#: **One write, and a pause.** A first version also appended straight to /var/log/fl-startup.log
#: "in case tee loses it", which duplicated every fatal line in that log — measured. The real
#: problem is different: line 4's `tee` is a BACKGROUND process, so exiting immediately can kill
#: it with the last lines still buffered, losing exactly the diagnostic you most want. The sleep
#: lets it drain. Measured: one line, and it survives.
die() {
  echo "fl-startup: FATAL: $*" >&2
  sleep 0.2
  exit 1
}

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
if ! pinned_at suricata "$SURICATA_PACKAGE_VERSION"; then
  add-apt-repository -y ppa:oisf/suricata-stable || die "could not add ppa:oisf/suricata-stable"
  apt-get update -y
  # **Unhold FIRST.** A previous run holds this package, and a hold plus `-y` is refused rather
  # than obeyed, so a version bump would fail every time while the script carried on and re-held.
  apt-mark unhold suricata suricata-update >/dev/null 2>&1 || true
  # The OISF package bundles /usr/bin/suricata-update, which Ubuntu ships as its own package;
  # dpkg refuses to overwrite across packages, so the standalone one goes first. Nothing in
  # flabel calls suricata-update — rules/{fetch,admit,snapshot} do that job — and the only
  # reverse-dependency was Ubuntu's own suricata. `|| true` because on a fresh box it is absent
  # and remove fails, which is not an error here.
  # ONLY suricata-update: it is the package that owns the conflicting /usr/bin/suricata-update.
  # Removing `suricata` too was gratuitous, and it is what turned a failed install into a box
  # with no engine at all before the die below could fire.
  apt-get remove -y suricata-update || true
  # --allow-downgrades because pinning BACKWARDS is a legitimate operation and apt refuses it
  # under -y otherwise; --allow-change-held-packages so a leftover hold cannot veto the pin.
  apt-get install -y --allow-downgrades --allow-change-held-packages \
    "suricata=$SURICATA_PACKAGE_VERSION" || die "suricata=$SURICATA_PACKAGE_VERSION did not install"
fi
# **Verify, THEN hold — never the other way round.** Holding first is what turns a failed install
# into a box with no engine that still reports success: `apt-mark hold` succeeds on a package that
# is not installed at all (measured), so the marker would outlive the thing it claims to pin.
pinned_at suricata "$SURICATA_PACKAGE_VERSION" \
  || die "suricata is not installed at $SURICATA_PACKAGE_VERSION after the install step"
apt-mark hold suricata >/dev/null || die "could not hold suricata — the pin would be unprotected"
# The hold is VERIFIED, not assumed: `apt-mark hold` succeeds on a package that is not installed
# (measured), so its exit code is weak evidence. This block also *unheld* above, so a silently
# failed hold leaves the box LESS protected than before the run.
apt-mark showhold | grep -Fx suricata >/dev/null || die "suricata is not held after apt-mark hold"

# Wireshark from ppa:wireshark-dev/stable, for the same reason as Suricata: noble ships 4.2.2 and
# the pin is 4.6.6. editcap and capinfos are not incidental tools here — editcap performs capture
# NORMALISATION, so a version the CI toolchain does not test is a version producing corpus input
# nobody has checked. capinfos and editcap both come from wireshark-common; tshark is separate and
# is what selects one link type out of a multi-interface pcapng.
#
# The setuid prompt is preseeded off because nothing on this box captures live traffic — it replays.
WIRESHARK_PACKAGE_VERSION=4.6.6-1~ubuntu24.04.0~ppa1
# BOTH packages are checked, not just wireshark-common: they are held together, so a run that got
# one and missed the other would skip this block forever and leave tshark held at the wrong version.
if ! pinned_at wireshark-common "$WIRESHARK_PACKAGE_VERSION" \
   || ! pinned_at tshark "$WIRESHARK_PACKAGE_VERSION"; then
  add-apt-repository -y ppa:wireshark-dev/stable || die "could not add ppa:wireshark-dev/stable"
  apt-get update -y
  echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
  apt-mark unhold wireshark-common tshark >/dev/null 2>&1 || true
  apt-get install -y --allow-downgrades --allow-change-held-packages \
    "wireshark-common=$WIRESHARK_PACKAGE_VERSION" "tshark=$WIRESHARK_PACKAGE_VERSION" \
    || die "wireshark $WIRESHARK_PACKAGE_VERSION did not install"
fi
pinned_at wireshark-common "$WIRESHARK_PACKAGE_VERSION" \
  || die "wireshark-common is not installed at $WIRESHARK_PACKAGE_VERSION"
pinned_at tshark "$WIRESHARK_PACKAGE_VERSION" \
  || die "tshark is not installed at $WIRESHARK_PACKAGE_VERSION"
apt-mark hold wireshark-common tshark >/dev/null || die "could not hold wireshark-common tshark — the pin would be unprotected"
# The hold is VERIFIED, not assumed: `apt-mark hold` succeeds on a package that is not installed
# (measured), so its exit code is weak evidence. This block also *unheld* above, so a silently
# failed hold leaves the box LESS protected than before the run.
apt-mark showhold | grep -Fx wireshark-common >/dev/null || die "wireshark-common is not held after apt-mark hold"

# **/etc/suricata is left as the package installs it (0750), and that is NOT isolation.**
#
# Measured 2026-08-28, on the path production actually takes: tools/flabel-run invokes flabel under
# `$SUDO`, so Suricata runs as ROOT, and root is not stopped by a 0750 directory. The production
# run's own log says `threshold-config: Threshold config parsed: 0 rule(s) found` — it READ the
# file. The "Permission denied" lines only appear for a non-root caller, i.e. when a developer runs
# the suite by hand.
#
# So an earlier chmod here was pointless, and the comment that replaced it — claiming the 0750 mode
# isolated the corpus from an unhashed file — was simply wrong. Both are recorded because the wrong
# reasoning is the instructive part: a permission bit cannot isolate a process that runs as root.
#
# The real exposure: Suricata resolves `reference-config-file` and `threshold-file` against
# /etc/suricata when flabel's config names neither, and threshold.config is its SUPPRESSION file.
# It holds 0 rules today, so nothing is suppressed — but it is an unhashed, package-managed,
# machine-local file that can drop alerts from the corpus, and `config_sha256` covers only the
# files in flabel's own data directory.
#
# The fix belongs in flabel, not here: name both paths at files flabel owns and hash them, so the
# isolation is a property of the configuration rather than of one machine's directory mode. Until
# that lands, do not chmod anything here — it would make the exposure worse, not better.

# Zeek from the upstream OpenSUSE build service repo (Ubuntu has no zeek package).
#
# **The key is scoped and its fingerprint is checked**, ported from Dockerfile.toolchain, which
# spells out why the previous form was wrong: the key went into /etc/apt/trusted.gpg.d, and a key
# there is a valid signer for EVERY repo including Ubuntu's own. That plus no fingerprint check is
# trust-on-first-use over whatever download.opensuse.org served, with root-level package
# installation on the only box that produces this project's ground truth.
#
# Exactly one primary key is required as well as the right fingerprint: `signed-by` trusts every
# key in the file, so an extra key is as bad as a wrong one. OBS keys do rotate — verify upstream,
# then update the literal.
ZEEK_REPO_KEY_FPR=F9FA0223B56B116C363737EF5DA57BDD6DD785CA

# **Outside the `command -v zeek` guard, deliberately.** A first version put all of this inside it,
# which made the whole fix dead code on every box that already had Zeek — i.e. on fl-replay, the
# only box this protects. Worse, the line that removes the old globally-trusted key sat inside the
# branch that only runs when no previous run installed one: self-cancelling by construction.
#
# Every step here is idempotent, so running it on each boot is both safe and the point: a key check
# that only runs at first install is a key check that never re-checks a rotated key.
install -d -m 0755 /etc/apt/keyrings
curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key" \
  | gpg --dearmor > /etc/apt/keyrings/security-zeek.gpg.new \
  || die "could not fetch the Zeek repo signing key"
colons="$(gpg --show-keys --with-colons /etc/apt/keyrings/security-zeek.gpg.new)"
served="$(echo "$colons" | awk -F: '$1=="pub"{p=1;next} p&&$1=="fpr"{print $10;exit}')"
keys="$(echo "$colons" | grep -c '^pub:' || true)"
if [ "$keys" != "1" ] || [ "$served" != "$ZEEK_REPO_KEY_FPR" ]; then
  echo "fl-startup: Zeek repo key check FAILED." >&2
  echo "fl-startup:   expected exactly 1 primary key, fingerprint $ZEEK_REPO_KEY_FPR" >&2
  echo "fl-startup:   served $keys key(s), primary fingerprint: ${served:-none}" >&2
  echo "fl-startup: signed-by trusts EVERY key in the file, so an extra key is as bad as a wrong" >&2
  echo "fl-startup: one. OBS keys do rotate: verify upstream, then update the literal." >&2
  rm -f /etc/apt/keyrings/security-zeek.gpg.new
  die "refusing to add the Zeek repo with an unverified signing key"
fi
mv /etc/apt/keyrings/security-zeek.gpg.new /etc/apt/keyrings/security-zeek.gpg
# Retire the globally-trusted copy earlier versions installed. A key in trusted.gpg.d is a valid
# signer for EVERY repo including Ubuntu's own, so leaving it is the whole problem, not a leftover.
rm -f /etc/apt/trusted.gpg.d/security_zeek.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/security-zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" \
  > /etc/apt/sources.list.d/security-zeek.list

# Zeek from the upstream OpenSUSE build service repo (Ubuntu has no zeek package).
if ! command -v zeek >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y zeek || die "zeek did not install"
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
JA4_OK=yes
# Install only. Verification is deliberately NOT here — see the commit-pin block below, which runs
# on every boot rather than only when this branch is taken.
if ! /opt/zeek/bin/zeek --parse-only -e '@load ja4' >/dev/null 2>&1; then
  zkg autoconfig
  if ! zkg install --force --version "$JA4_PACKAGE_VERSION" zeek/foxio/ja4; then
    # Said plainly, because the first version blamed a moved tag for this: a failed install leaves
    # no clone, so the commit comparison below would find nothing and report a tag rewrite.
    echo "fl-startup: zkg install of ja4 FAILED (network? zkg deps?) — NOT a moved tag." >&2
    JA4_OK=no
  fi
fi

# **The commit pin is checked on EVERY boot, not only when ja4 was just installed.** The first
# version of this put the comparison inside the `if ! zeek --parse-only` above — so on any box that
# already had ja4, which is fl-replay and every re-run, the commit was never compared to the pin at
# all. The pin exists precisely because a tag is mutable: a moved tag, a hand-install, or a leftover
# from an older pin would have provisioned clean and green while changing the JA4 values that ride
# on published labels. A check that only runs on first install is not a pin.
if [ "$JA4_OK" = yes ]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "fl-startup: git is missing, so the ja4 COMMIT pin cannot be checked." >&2
    JA4_OK=no
  else
    clone="$(zkg config 2>/dev/null | sed -n 's/^state_dir = //p' | head -1)/clones/package/ja4"
    if [ ! -d "$clone/.git" ]; then
      echo "fl-startup: no ja4 clone at $clone, so the commit pin cannot be checked." >&2
      JA4_OK=no
    else
      JA4_INSTALLED_COMMIT="$(git -C "$clone" rev-parse HEAD 2>/dev/null)"
      if [ "$JA4_INSTALLED_COMMIT" != "$JA4_PACKAGE_COMMIT" ]; then
        echo "fl-startup: ja4 is at commit ${JA4_INSTALLED_COMMIT:-unknown}, expected $JA4_PACKAGE_COMMIT." >&2
        echo "fl-startup: a MOVED TAG changes JA4 values on labels. Verify upstream, then update the pin." >&2
        JA4_OK=no
      fi
    fi
  fi
fi
# The gate is the capability, not the directory: a package installed somewhere Zeek will not load
# it is exactly the failure worth catching, and it is how src/flabel/zeek.py asks.
#
# **Recorded, not fatal here.** An `exit` at this point would skip everything below it — uv, the
# NTP pin, the NIC offload and arp/rp_filter settings that tier-1 replay fidelity depends on, and
# the install of the tested flabel-run wrapper. Those failing silently is worse than a missing
# fingerprint. The failure is re-raised at the end, before the box is marked provisioned.
if ! /opt/zeek/bin/zeek --parse-only -e '@load ja4' >/dev/null 2>&1; then
  echo "fl-startup: ja4 installed but '@load ja4' still fails — check ZEEKPATH and the zkg install." >&2
  JA4_OK=no
fi

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
# --- /etc/flabel-toolchain.json ----------------------------------------------------------------
#
# **Without this file the box cannot say what produced a label, and CI's container can.**
# provenance.py reads `ja4_zeek_package` and `wireshark` from here and from nowhere else: editcap
# has NO runtime version source — ingest.py invokes it without capturing one — so if this file is
# absent every run block records `editcap: null` and `ja4_zeek_package: null`. That was the state
# on 2026-08-27, which is how a run published to production carried a null editcap version while
# this very script was arguing that editcap's version is corpus-critical.
#
# Same shape as Dockerfile.toolchain's block, including the empty-value check: `grep | head` always
# exits 0, so a changed `--version` format would otherwise record "" and still succeed.
{
  semver() { grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }
  zeek_v="$(/opt/zeek/bin/zeek --version 2>/dev/null | semver)"
  suricata_v="$(suricata -V 2>/dev/null | semver)"
  wireshark_v="$(editcap --version 2>/dev/null | semver)"
  # **ja4 is recorded only if it actually verified.** $JA4_PACKAGE_VERSION is a shell literal, so
  # writing it unconditionally would put "v0.18.8" on every label from a box where the package is
  # absent or at the wrong commit — provenance.py reads this file and has no other source. A
  # missing key is handled correctly downstream; a confident wrong answer is not.
  # ja4_commit is required too, matching Dockerfile.toolchain rather than being laxer than CI.
  for pair in "zeek:$zeek_v" "suricata:$suricata_v" "wireshark:$wireshark_v"; do
    case "$pair" in *:) die "empty version for ${pair%:*} — the --version parse failed";; esac
  done
  {
    printf '{\n  "zeek": "%s",\n  "suricata": "%s",\n  "wireshark": "%s"' \
        "$zeek_v" "$suricata_v" "$wireshark_v"
    if [ "$JA4_OK" = yes ]; then
      [ -n "${JA4_INSTALLED_COMMIT:-}" ] || die "ja4 verified but no commit was recorded"
      printf ',\n  "ja4_zeek_package": "%s",\n  "ja4_zeek_commit": "%s"' \
          "$JA4_PACKAGE_VERSION" "$JA4_INSTALLED_COMMIT"
    fi
    printf '\n}\n'
  } > /etc/flabel-toolchain.json || die "could not write /etc/flabel-toolchain.json"
  chmod 0644 /etc/flabel-toolchain.json
  jq -e . /etc/flabel-toolchain.json >/dev/null || die "/etc/flabel-toolchain.json is not valid JSON"
}

# --- versions: ASSERTED, not merely printed ----------------------------------------------------
#
# Printing a version into a log nobody diffs is how a pin silently stops applying. These are the
# same pins the blocks above install, checked once more at the end so that a box which drifted —
# by an unattended upgrade, a hand-installed package, a half-finished run — fails here instead of
# labelling captures with a toolchain the repo does not describe.
echo "=== versions ==="
tcpreplay --version 2>&1 | head -1
/opt/zeek/bin/zeek --version 2>&1 | head -1
suricata -V 2>&1 | head -1
editcap --version 2>&1 | head -1
cat /etc/flabel-toolchain.json

pinned_at suricata "$SURICATA_PACKAGE_VERSION"          || die "suricata drifted off its pin"
pinned_at wireshark-common "$WIRESHARK_PACKAGE_VERSION" || die "wireshark-common drifted off its pin"
pinned_at tshark "$WIRESHARK_PACKAGE_VERSION"           || die "tshark drifted off its pin"
[ "$JA4_OK" = yes ] || die "the ja4 package is not usable — see the ja4 errors above"

# `.provisioned` is a claim, so it goes LAST and only after every check above has passed. It used
# to be written unconditionally, which meant a half-provisioned box asserted it was ready.
echo "=== fl-replay startup COMPLETE $(date -Is) ==="
touch /var/lib/flabel/.provisioned
