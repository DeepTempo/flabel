# Phase 2 reachability spike — the answer to PRD §13 Q16

**Question (PRD §13 Q16, CLAUDE.md gate):** can a cloud VM-Series see replayed traffic at all?

**Answer: yes, in a two-zone Layer 3 deployment — and the original 5-tuple survives intact.**
Measured 2026-08-17 in `pm-proto-496816`. This unblocks Phase 2 planning.

**Virtual wire, which PRD §5 specifies, is not viable in GCP and PRD §5 needs amending.** A
vwire interface carries no IP address, and GCP's virtual switch forwards by destination IP
rather than by L2 adjacency, so there is no route target to deliver replayed frames to. The
L3 design substitutes an interface with an IP, which a VPC custom route *can* target.

## What was measured

A 2,000-packet slice of a real internet-facing capture
(`lax/capture_2026-07-08_pub-216.152.152.123.pcap`), split by direction with
`tcpprep --auto=client` and replayed out two interfaces with `tcpreplay --multiplier 1000`.
985 packets left `ens5`, 1,015 left `ens6`.

PAN-OS dataplane capture (`debug dataplane packet-diag`, receive stage, filtered to
`ingress-interface ethernet1/1`) recorded **984 packets received**. `view-pcap` showed the
original public addresses unchanged — scanner hosts in `scanner.modat.io` addressing the
capture's own public IP.

So the cheapest transport works, and the two fallbacks designed for issue #122 are **not
needed**:

| Transport | Verdict |
| :-- | :-- |
| Raw L3 replay + `--can-ip-forward` + VPC custom routes | **Works.** Tuple preserved. |
| VXLAN/GRE encap + PAN-OS tunnel content inspection | Not needed. |
| `tcprewrite --pnat` | Not needed — and it would have rewritten the addresses labels are keyed on, requiring an invertible prefix map. |

This matters beyond plumbing: because the tuple survives, `correlate._place` needs no change
at all. It matches on bidirectional 5-tuple, and a tier-1 detection carries the same addresses
Zeek saw in the capture file.

## Two findings that affect label coverage

**1. Non-SYN TCP was dropped — 1,014 packets (`flow_tcp_non_syn_drop`).** A capture of
arbitrary traffic starts mid-stream, so many flows have no SYN. PAN-OS rejects non-SYN TCP that
matches no existing session, which means no session, no Content-ID, and therefore **no threat
log for those flows** — an under-report that nothing in the output would have explained.
Fixed with `set deviceconfig setting session tcp-reject-non-syn no`.

This is the Tier-1 analogue of a loss condition and Phase 2 should treat it as one: the
proportion of the capture that reached the firewall is a number a consumer needs, not a
detail. A tier-1 run that inspected 60% of the flows must not read like one that inspected
all of them.

**2. `flow_policy_deny` — 948 packets.** Expected: no security policy exists yet. Sessions
cannot form until one does, so this spike deliberately proves *reachability* via the receive
stage rather than via traffic logs.

## Lab facts worth keeping

- **PAN-OS config node is `mgt-config`, not `mgmt-config`.** Every `set mgmt-config ...`
  returns `Invalid syntax`.
- **The CLI will not run piped commands without a pty and `set cli scripting-mode on`.**
  Non-interactive `ssh admin@host 'show system info'` authenticates and returns *nothing* —
  exit code 0, empty output. `panw.py` must not be built on that.
- **GCE MACs are derived from the IP**: `10.20.1.2` → `42:01:0a:14:01:02`. Predictable, so
  destination-MAC discovery needs no ARP round trip. Not currently needed — GCP routes by
  destination IP and the capture's original MACs are left alone.
- The base VM-Series image ships **Applications-only content** (`threat-version: 0`). Threat
  Prevention signatures require an explicit content install; without it there is no tier-1
  signal whatsoever. Installed `9136-10199`.
- PAYG flex-bundle licensing activated with no Marketplace interaction — the image is readable
  directly from `paloaltonetworksgcp-public`.

## Topology

Three VPCs, because GCP permits one interface per VPC per instance. Both hosts NTP to
`metadata.google.internal`, satisfying the shared-clock requirement — which per PRD §5 only
needs to scope the log query, not to place labels.

| Host | mgmt | replay1 | replay2 |
| :-- | :-- | :-- | :-- |
| `fl-replay` (Ubuntu 24.04) | 10.10.0.4 | 10.20.1.4 (`ens5`) | 10.20.2.4 (`ens6`) |
| `fl-ngfw` (PAN-OS 11.1.15) | 10.10.0.2 | 10.20.1.2 (`ethernet1/1`, zone `replay1`) | 10.20.2.2 (`ethernet1/2`, zone `replay2`) |

VPC routes `fl-replay{1,2}-to-ngfw` send `0.0.0.0/0` to the firewall at priority 100, which is
what makes GCP deliver packets addressed to arbitrary internet destinations.

Forwarding is by **policy-based forwarding keyed on ingress zone** (`replay1-to-replay2` and
its reverse) rather than by destination prefix. Destination-based static routes would need
per-capture route injection, since both directions of an arbitrary capture are arbitrary
internet space; PBF by ingress zone is capture-independent and keeps the two directions of a
flow in one session, which Content-ID needs to inspect server responses.
