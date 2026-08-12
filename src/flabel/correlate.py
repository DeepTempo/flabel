"""Attaching detections to the flows they fired on (spec §9).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.

This is the step where a wrong answer is cheapest to produce and hardest to see. Zeek and
Suricata each report what they saw; correlation decides which flow a detection *belongs* to,
and every decision it makes lands in `labels.json` as a verdict about a specific connection.
So the two rules that matter here are both about refusing to guess:

* a detection is attached to a flow only when exactly one flow can be it — spec §13's "never
  assign a detection to a flow by guess" — and otherwise becomes a reported
  `UnmatchedDetection` rather than a dropped row (spec §2.5);
* provenance is built by `provenance.build_source_entry` from the *snapshot's* record of the
  source, never from the registry as it reads now.

Two things this module deliberately does not do:

**It does not normalise the tuple.** Step 6 already translated Suricata's 5-tuple into Zeek's
spelling — lowercased protocol, `IPv6-ICMP` → `icmp`, compressed IPv6 literals, ICMP
type/code mirrored into the port columns (spec §8). Fields are compared as given. A second
normalisation here would be two places that have to agree about what a tuple is, and the one
that silently repaired a step 6 regression would hide it.

**It does not filter.** An `identify`-class detection reaching here is a mis-wired pipeline,
not an input to screen out: step 6 suppressed and counted those before a `Detection` existed.
`build_source_entry` raises on one, and this module lets it.
"""

from __future__ import annotations

import math
import sys
from collections.abc import Mapping, Sequence

from flabel.errors import FlabelError, SnapshotError
from flabel.models import (
    CorrelationResult,
    Detection,
    Flow,
    Label,
    SnapshotManifest,
    SourceAdmission,
    SourceEntry,
    UnmatchedDetection,
    UnmatchedReason,
)
from flabel.provenance import build_source_entry

#: Spec §9's default: past 1% of detections unplaceable, the labels no longer describe the
#: capture well enough to be training data. Phase 2 configures its own, looser value rather
#: than relaxing this one.
DEFAULT_THRESHOLD = 0.01

#: Zeek's spelling for both ICMP and ICMPv6 — its `transport_proto` has only tcp/udp/icmp/
#: unknown_transport — so the protocol field cannot tell the two families apart and the
#: address has to (see `_counterparts`).
ICMP = "icmp"

# --- what Zeek puts in the ICMP port columns ------------------------------------------------
#
# ICMP has no ports. Zeek writes the ICMP *type* in `id.orig_p`, and in `id.resp_p` either the
# type it pairs that type with (a request/reply pair) or, for every other type, the ICMP code.
# A single Suricata alert record carries only the type and code of its own packet, so step 8's
# mirroring produces `(type, code)` — exact whenever Zeek wrote the code, and one field out
# whenever Zeek wrote a counterpart type. Closing that gap is spec §8's residual, and it is
# closed here rather than in `suricata.py` because only correlation has both records in hand.
#
# **Measured, not recalled.** Swept on Zeek 8.0.4 by sending one packet of every ICMP type with
# code 7 and reading back `id.resp_p` from `conn.log`: the types below came back paired with
# each other, and every other type came back as 7. Two corrections to spec §8 fall out of that
# sweep, both of which would otherwise have left detections uncorrelatable:
#
#   * §8 says mirroring is "exact for ICMPv4". It is exact for the echo *request* only —
#     type 8 pairs with 0, which is also its code — while an alert on the echo *reply* yields
#     `(0, 0)` against a flow whose responder column holds `8`. ICMPv4 timestamp, information
#     and address-mask exchanges are out by the same field.
#   * §8 names ICMPv6 *echo* as the residual. Neighbour discovery (135/136) pairs the same way
#     and is far more common on a real capture, so handling echo alone would look like the
#     residual had been closed while leaving the ordinary case broken.
#
# An entry that Zeek turns out not to pair costs nothing: it only permits a responder value
# Zeek would then never write. A missing entry costs an unmatched detection — reported, and
# never a wrong flow.
ICMPV4_COUNTERPART = {0: 8, 8: 0, 9: 10, 10: 9, 13: 14, 14: 13, 15: 16, 16: 15, 17: 18, 18: 17}
ICMPV6_COUNTERPART = {
    128: 129,
    129: 128,
    130: 131,
    131: 130,
    133: 134,
    134: 133,
    135: 136,
    136: 135,
    139: 140,
    140: 139,
    144: 145,
    145: 144,
}


def correlate(
    detections: Sequence[Detection],
    flows: Mapping[str, Flow],
    manifest: SnapshotManifest,
    threshold: float = DEFAULT_THRESHOLD,
) -> CorrelationResult:
    """Attach each detection to the one flow it fired on, and consolidate to one label per flow.

    `manifest` is the snapshot Suricata actually ran — spec §12's orchestration asserts that
    its `snapshot_id` equals `SuricataRunInfo.snapshot_id`, because a `rules update` landing
    between the two loads would otherwise have every label cite a ruleset whose rules never ran.

    Raises `SnapshotError` for a detection from a source the snapshot does not describe,
    `ValueError` for anything `build_source_entry` refuses (an `identify` source, an
    unresolvable snapshot id, a tier outside `{1, 2}`), and `FlabelError` when more than
    `threshold` of the detections could not be placed.
    """
    _check_threshold(threshold)
    # From the manifest rather than built here (#49). `sources` is a tuple, and the
    # comprehension that indexes it is the same one `suricata.py` needs; two copies would carry
    # two copies of the duplicate-name hazard `SnapshotManifest.__post_init__` now rejects.
    # Read once into a local, because the property rebuilds the mapping on every access.
    admissions = manifest.sources_by_name

    # Every entry is built *before* any matching, so the guards inside `build_source_entry` run
    # over the whole detection set rather than over the subset that happened to correlate. An
    # identify-class alert on an uncorrelatable tuple is the same mis-wired pipeline as one on
    # a tuple that matches, and a snapshot id no reader can resolve is broken whether or not
    # this particular capture produced a label from it.
    entries = [
        (detection, _entry(detection, admissions, manifest.snapshot_id)) for detection in detections
    ]

    matched: dict[str, list[SourceEntry]] = {}
    matched_flows: dict[str, Flow] = {}
    unmatched: list[UnmatchedDetection] = []

    for detection, entry in entries:
        flow, reason = _place(detection, flows)
        if flow is None or reason is not None:
            # `UnmatchedDetection` rejects a reason outside the Literal, so a placement that
            # returned neither a flow nor a reason fails loudly here rather than silently
            # becoming a label-less detection nobody counted.
            unmatched.append(
                UnmatchedDetection(detection=detection, reason=reason)  # type: ignore[arg-type]
            )
            continue
        matched.setdefault(flow.uid, []).append(entry)
        matched_flows[flow.uid] = flow

    result = CorrelationResult(
        labels=_labels(matched, matched_flows),
        unmatched=tuple(sorted(unmatched, key=_unmatched_order)),
        flows_total=len(flows),
        detections_total=len(detections),
    )
    _gate(result, threshold)
    return result


# --- placing one detection -------------------------------------------------------------------


def _place(
    detection: Detection, flows: Mapping[str, Flow]
) -> tuple[Flow | None, UnmatchedReason | None]:
    """The flow this detection belongs to, or `None` and the reason it could not be decided.

    Spec §9's four steps, in order. The order is load-bearing: a *lone* candidate is matched
    without consulting the clock, because Suricata timestamps the alerting packet while Zeek's
    window is bounded by the packets it attributed to the connection, and those disagree at the
    edges often enough that requiring containment unconditionally would lose real detections.
    """
    candidates = [flow for flow in flows.values() if _same_tuple(detection, flow)]

    if not candidates:
        return None, "no_flow_match"
    if len(candidates) == 1:
        return candidates[0], None

    # Port reuse within one capture: the same 5-tuple, more than once. The clock is the only
    # thing that separates them.
    contained = [flow for flow in candidates if flow.ts_first <= detection.ts <= flow.ts_last]
    if len(contained) == 1:
        return contained[0], None
    return None, "ambiguous_flow_match"


def _same_tuple(detection: Detection, flow: Flow) -> bool:
    """Whether the detection's 5-tuple is this flow's, in either direction.

    Zeek names the initiator, and a rule can fire on either direction of the same connection —
    an alert on the server's reply carries the server as `src_ip`. Both halves have to be
    reversed together: matching the addresses one way and the ports the other would attach a
    detection to a different conversation between the same two hosts.
    """
    if detection.proto != flow.proto:
        return False

    orientations: list[tuple[int, int]] = []
    if detection.src_ip == flow.src_ip and detection.dst_ip == flow.dst_ip:
        orientations.append((flow.src_port, flow.dst_port))
    if detection.src_ip == flow.dst_ip and detection.dst_ip == flow.src_ip:
        orientations.append((flow.dst_port, flow.src_port))

    return any(
        _same_ports(detection, initiator, responder) for initiator, responder in orientations
    )


def _same_ports(detection: Detection, initiator: int, responder: int) -> bool:
    """Whether the detection's port columns are this flow's, in the given orientation.

    Exact for everything with real ports. For ICMP the initiator column holds the type and is
    still exact; the responder column is where Zeek and a single alert record can legitimately
    disagree, so a counterpart type is accepted there as well as the mirrored code. Nothing
    wider than that: for a one-way type Zeek writes the code, so two destination-unreachable
    flows between the same pair differ only in that column and ignoring it would turn one right
    answer into two candidates.
    """
    if detection.src_port != initiator:
        return False
    if detection.dst_port == responder:
        return True
    if detection.proto != ICMP:
        return False
    return _counterparts(detection.src_ip).get(detection.src_port) == responder


def _counterparts(address: str) -> Mapping[int, int]:
    """The counterpart table for the address family, since the protocol name cannot say.

    A colon appears in every textual IPv6 address — including the IPv4-mapped form, which is
    still carried in an IPv6 header — and never in an IPv4 one. Both tools write addresses in
    canonical text form (`suricata.py` compresses them precisely so these comparisons work), so
    this reads the family without parsing, and without a malformed address raising.
    """
    return ICMPV6_COUNTERPART if ":" in address else ICMPV4_COUNTERPART


# --- provenance ------------------------------------------------------------------------------


def _entry(
    detection: Detection, admissions: Mapping[str, SourceAdmission], snapshot_id: str
) -> SourceEntry:
    """This detection's provenance, built from the snapshot's record of its source.

    A source the snapshot does not describe is a hard failure, matching §8's handling of a SID
    that belongs to no source: `-S` loads only snapshot rules and §8 resolves every alert's
    source through `sid_index.json`, so this should be unreachable. Failing rather than
    dropping is the same reasoning as there — the alternative is a label with an invented
    origin. `SnapshotError` rather than the `KeyError` the lookup would raise, so it reaches
    the operator as a reason and exit 1 rather than as a traceback.

    Everything past the lookup belongs to `build_source_entry`, which is where `label_basis`,
    `admission_basis` and `licence` are derived — once, for this step and step 8 both.
    """
    try:
        admission = admissions[detection.source]
    except KeyError:
        raise SnapshotError(
            f"detection sid {detection.sid} names source {detection.source!r}, which snapshot "
            f"{snapshot_id} does not describe (it has {sorted(admissions)}): its label would "
            f"cite an origin the snapshot cannot account for"
        ) from None
    return build_source_entry(detection, admission, snapshot_id)


# --- consolidation ---------------------------------------------------------------------------


def _labels(
    matched: Mapping[str, list[SourceEntry]], flows: Mapping[str, Flow]
) -> tuple[Label, ...]:
    """One `Label` per flow that any detection fired on, in spec §10's order.

    Sorted here rather than left to `labels.py` so the returned tuple is already canonical: the
    result must not depend on the order Suricata reported its alerts in, which is what makes
    step 10's reproducibility gate meaningful rather than lucky. `labels.py` sorting again is
    idempotent.

    Identical entries are kept rather than de-duplicated. Suricata emits one alert per matching
    packet, so a rule can fire twice on one flow; nothing in §9 or §10 asks for uniqueness, and
    collapsing them would make the output say the rule fired once.
    """
    labels = [
        Label(
            flow=flows[uid],
            verdict="malicious",
            # Lower is higher trust (spec §4), so the best tier is the minimum. `Label`
            # re-derives this and refuses a value that disagrees.
            best_tier=min(entry.tier for entry in entries),
            sources=tuple(sorted(entries, key=_source_order)),
        )
        for uid, entries in matched.items()
    ]
    return tuple(sorted(labels, key=lambda label: (label.flow.ts_first, label.flow.uid)))


def _source_order(entry: SourceEntry) -> tuple[int, str, int, int]:
    """Spec §10: `sources` sorted by `(tier, source, sid, rev)`, numerically for the numbers."""
    return (entry.tier, entry.source, entry.sid, entry.rev)


def _unmatched_order(item: UnmatchedDetection) -> tuple[float, str, int]:
    """Spec §10: `unmatched_detections` sorted by `(ts, source, sid)`."""
    return (item.detection.ts, item.detection.source, item.detection.sid)


# --- the gate ---------------------------------------------------------------------------------


def _check_threshold(threshold: float) -> None:
    """Refuse a threshold that would silently switch the gate off.

    `argparse(type=float)` accepts `nan` and `inf`, and every comparison against `nan` is
    `False` — so `--unmatched-threshold nan` would discard any proportion of a capture's
    detections and still exit 0, with nothing in the output saying the gate was off. A ratio
    cannot exceed 1, so a threshold above 1 is the same thing spelled differently. `bool` is
    excluded explicitly because `True` is `1`, as it is in `provenance.py` and `suricata.py`.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError(f"unmatched threshold must be a number, not {type(threshold).__name__}")
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError(
            f"unmatched threshold {threshold!r} is not a share between 0 and 1: a threshold "
            f"outside that range disables the gate instead of setting it"
        )


def _gate(result: CorrelationResult, threshold: float) -> None:
    """Spec §9: silent at zero unmatched, a warning above zero, a failed run above `threshold`.

    Silence at zero is what makes the warning worth reading — it always means something was
    lost. The failure is a `FlabelError` (exit 1, no `labels.json`), because past the threshold
    the labels no longer describe the capture and a file that says otherwise is worse than none.
    """
    if not result.unmatched:
        return

    summary = (
        f"{len(result.unmatched)} of {result.detections_total} detections "
        f"({result.unmatched_ratio:.2%}) could not be attached to exactly one flow"
    )
    if result.unmatched_ratio > threshold:
        # Warned before raising, so an operator watching the run sees the count even though the
        # `UnmatchedDetection` records go no further: a raise carries no result, and there is no
        # `labels.json` on a hard failure to record them in.
        _warn(f"{summary}; above the {threshold:.2%} threshold, so this run has failed")
        raise FlabelError(
            f"{summary}, above the unmatched threshold of {threshold}: the labels would not "
            f"describe this capture. Raise --unmatched-threshold to accept the loss, or check "
            f"that Zeek and Suricata read the same capture."
        )

    _warn(f"{summary}; they are reported in unmatched_detections[] and carry no label")


def _warn(message: str) -> None:
    """Print a non-fatal loss on stderr (spec §12), in `zeek.py`'s wording.

    stdout is reserved (spec §12), and `CorrelationResult` has no `warnings` field — the
    unmatched detections themselves are what the run block reports (spec §11).
    """
    print(f"flabel: warning: {message}", file=sys.stderr)
