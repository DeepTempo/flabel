#!/bin/bash
# Reachability spike probe (flabel #122, PRD §13 Q16).
#
# Replays a slice of a capture out two interfaces, split by direction, and prints the
# replay window in a form the correlator could invert. Deliberately NOT flabel code:
# this exists to answer "can a cloud VM-Series see replayed traffic at all", and the
# repo forbids building Phase 2 before that is answered.
#
# usage: replay-probe.sh <pcap> <packets> <multiplier> [smac_mode] [dmac1] [dmac2]
#   smac_mode: keep | rewrite   (rewrite = use each egress NIC's own MAC as source)
set -euo pipefail

PCAP="${1:?pcap path}"
PACKETS="${2:-3000}"
MULT="${3:-1000}"
SMAC_MODE="${4:-rewrite}"
DMAC1="${5:-}"
DMAC2="${6:-}"

IF1=ens5   # replay leg 1 -> fl-ngfw ethernet1/1 (zone 1)
IF2=ens6   # replay leg 2 -> fl-ngfw ethernet1/2 (zone 2)
WORK=/var/lib/flabel/captures
cd "$WORK"

SLICE=probe-slice.pcap
CACHE=probe-slice.cache
READY=probe-ready.pcap

rm -f "$SLICE" "$CACHE" "$READY"

echo "### slicing $PACKETS packets from $PCAP"
editcap -r "$PCAP" "$SLICE" 1-"$PACKETS"

# Direction split. auto=client uses TCP handshake direction to decide which side is the
# client, which generalises to arbitrary captures; the alternative (--cidr on the capture's
# own public IP, which the filenames encode) is deterministic but filename-dependent.
echo "### direction split"
tcpprep --auto=client --pcap="$SLICE" --cachefile="$CACHE" 2>&1 | tail -2 || true

# MAC rewriting. GCE's virtual switch is IP-routed and enforces the source MAC of a vNIC,
# so a replayed frame carrying the capture's original source MAC is the likely drop point.
# Destination MAC is left alone by default: the 0.0.0.0/0 custom route should cause GCP to
# deliver to the firewall by destination IP regardless of L2, which is what we are testing.
REWRITE_ARGS=()
if [ "$SMAC_MODE" = "rewrite" ]; then
  MAC1=$(cat "/sys/class/net/$IF1/address")
  MAC2=$(cat "/sys/class/net/$IF2/address")
  REWRITE_ARGS+=("--enet-smac=$MAC1,$MAC2")
  echo "### smac rewrite: $IF1=$MAC1 $IF2=$MAC2"
fi
if [ -n "$DMAC1" ] && [ -n "$DMAC2" ]; then
  REWRITE_ARGS+=("--enet-dmac=$DMAC1,$DMAC2")
  echo "### dmac rewrite: $DMAC1 / $DMAC2"
fi

if [ ${#REWRITE_ARGS[@]} -gt 0 ]; then
  tcprewrite "${REWRITE_ARGS[@]}" --cachefile="$CACHE" --infile="$SLICE" --outfile="$READY"
else
  cp "$SLICE" "$READY"
fi

# The two numbers correlation needs: where the replay sat on the wall clock, and where the
# capture sits in its own time. ts_pcap = (ts_wall - REPLAY_START) * MULT + PCAP_FIRST
PCAP_FIRST=$(tshark -r "$SLICE" -T fields -e frame.time_epoch -c 1 2>/dev/null | tr -d '\r')
REPLAY_START=$(date -u +%s.%N)

echo "### replaying at multiplier $MULT"
set +e
sudo tcpreplay -i "$IF1" -I "$IF2" --cachefile="$CACHE" --multiplier="$MULT" "$READY" 2>&1 | tail -12
RC=$?
set -e
REPLAY_END=$(date -u +%s.%N)

echo "### RESULT"
cat <<EOF
{
  "rc": $RC,
  "pcap_first_ts": $PCAP_FIRST,
  "replay_start_wall": $REPLAY_START,
  "replay_end_wall": $REPLAY_END,
  "multiplier": $MULT,
  "smac_mode": "$SMAC_MODE",
  "packets": $PACKETS
}
EOF
