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
from dataclasses import replace

from flabel.errors import CorrelationError, SnapshotError
from flabel.models import (
    CORRELATABLE_PROTOCOLS,
    DEFAULT_THRESHOLD,
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
from flabel.provenance import build_device_source_entry, build_source_entry

#: Re-exported so `from flabel.correlate import DEFAULT_THRESHOLD` keeps working — this is where
#: readers look for it, next to the gate that applies it. It is *defined* in `models.py` because
#: `provenance.py` records it in the run block (#68) and `correlate` already imports `provenance`,
#: so defining it here made that a cycle. Same move, and the same reason, as `SNAPSHOT_ID`.

#: Zeek's spelling for both ICMP and ICMPv6 — its `transport_proto` has only tcp/udp/icmp/
#: unknown_transport — so the protocol field cannot tell the two families apart and the
#: address has to (see `_counterparts`).
ICMP = "icmp"

# --- what Zeek puts in the ICMP port columns ------------------------------------------------
#
# ICMP has no ports. Zeek writes the ICMP *type* in `id.orig_p`, and in `id.resp_p` either the
# type it pairs that type with (a request/reply pair) or, for every other type, the ICMP code.
# A single Suricata alert record carries only the type and code of its own packet, so step 6's
# mirroring produces `(type, code)` — exact whenever Zeek wrote the code, and one field out
# whenever Zeek wrote a counterpart type. Closing that gap is spec §8's residual, and it is
# closed here rather than in `suricata.py` because only correlation has both records in hand.
#
# **Measured, and re-measured on every CI run.** Swept exhaustively — ICMPv4 types 0-45 and
# ICMPv6 types 0-160, one packet each at code 7 — reading `id.resp_p` back from `conn.log`: the
# types below came back paired with each other, and every other type came back as 7.
# `test_the_icmp_tables_are_what_zeek_actually_writes` is that sweep, run against the pinned
# Zeek, so an upgrade that changed this behaviour fails the build instead of silently making
# every affected ICMP detection uncorrelatable. Two corrections to spec §8 fall out of it, both
# of which would otherwise have left detections uncorrelatable:
#
#   * §8 says mirroring is "exact for ICMPv4". It is exact for the echo *request* only —
#     type 8 pairs with 0, which is also its code — while an alert on the echo *reply* yields
#     `(0, 0)` against a flow whose responder column holds `8`. ICMPv4 timestamp, information
#     and address-mask exchanges are out by the same field.
#   * §8 names ICMPv6 *echo* as the residual. Neighbour discovery (135/136) pairs the same way
#     and is far more common on a real capture, so handling echo alone would look like the
#     residual had been closed while leaving the ordinary case broken.
#
# **The two error directions are not symmetric, and not in the direction intuition suggests.**
# A *missing* entry is safe: the detection goes unmatched, which is reported, and is never a
# wrong flow. A *spurious* entry — claiming Zeek pairs a type it does not — is not. For an
# unpaired type Zeek writes the code in the responder column, so `(A, X, B, Y)` is a real,
# distinct one-way flow; an entry saying X pairs with Y makes a detection of type X match that
# flow as well as the one it belongs to, and two one-way flows merge. That is precisely what
# `test_the_icmp_relaxation_does_not_merge_two_one_way_flows` exists to prevent, reached from
# the other side.
#
# So these tables are extended only from a fresh sweep against the pinned Zeek — never from an
# RFC, a specification, or memory. The margin is thinner than it looks, because flabel's inputs
# are malicious captures, where non-standard type/code combinations are a technique rather than
# an accident.
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
    manifest: SnapshotManifest | None,
    threshold: float = DEFAULT_THRESHOLD,
    address_indicators: frozenset[int] | None = None,
    device_rulesets: Mapping[tuple[int, str, int, str, int, str], str] | None = None,
) -> CorrelationResult:
    """Attach each detection to the one flow it fired on, and consolidate to one label per flow.

    `manifest` is the snapshot Suricata actually ran — spec §12's orchestration asserts that
    its `snapshot_id` equals `SuricataRunInfo.snapshot_id`, because a `rules update` landing
    between the two loads would otherwise have every label cite a ruleset whose rules never ran.

    **`None` is a replay-only run** (#132): tier 1 loads no Suricata rules, so there is no
    snapshot to cite and demanding one would fail a run over rules it was never going to read.
    Nothing tier 1 emits needs it — a tier-1 entry's `ruleset` is the device's content version,
    threaded through `device_rulesets`, and `_entry` routes on `detection.tier` before it ever
    reaches the snapshot lookup. A tier-2 detection arriving with no manifest is therefore a
    mis-wired pipeline rather than a data condition, and raises rather than degrading.

    `address_indicators` is the snapshot's per-rule classification — the sids whose rules fire
    on the header tuple alone (issue #75), from `rules.snapshot.load_address_indicators`. **`None`
    means the snapshot recorded none**, and every `label_basis` then takes the weaker
    `indicator-reference` with a warning on the result; see `provenance.build_source_entry`. The
    warning is emitted here rather than per label because this is the one place that knows the
    fact once for the whole run.

    Raises `SnapshotError` for a detection from a source the snapshot does not describe,
    `ValueError` for anything `build_source_entry` refuses (an `identify` source, an
    unresolvable snapshot id, a tier outside `{1, 2}`), and `CorrelationError` when more than
    `threshold` of the detections could not be placed.
    """
    _check_threshold(threshold)
    # From the manifest rather than built here (#49). `sources` is a tuple, and the
    # comprehension that indexes it is the same one `suricata.py` needs; two copies would carry
    # two copies of the duplicate-name hazard `SnapshotManifest.__post_init__` now rejects.
    # Read once into a local, because the property rebuilds the mapping on every access.
    admissions = manifest.sources_by_name if manifest is not None else {}

    # Reported once for the run, not once per label (issue #75, PLAN 11c). Spec §2.5: the
    # downgrade is a decision taken in the absence of a fact, so the absence has to be stated.
    unclassified: tuple[str, ...] = ()
    if manifest is not None and address_indicators is None and detections:
        unclassified = (
            f"snapshot {manifest.snapshot_id} recorded no per-rule indicator classification, so "
            f"every label_basis in this run is indicator-reference rather than direct. Rebuild "
            f"the snapshot with `flabel rules update` for per-rule bases.",
        )

    # Every entry is built *before* any matching, so the guards inside `build_source_entry` run
    # over the whole detection set rather than over the subset that happened to correlate. An
    # identify-class alert on an uncorrelatable tuple is the same mis-wired pipeline as one on
    # a tuple that matches, and a snapshot id no reader can resolve is broken whether or not
    # this particular capture produced a label from it.
    entries = [
        (
            detection,
            _entry(
                detection,
                admissions,
                manifest.snapshot_id if manifest is not None else None,
                address_indicators,
                device_rulesets,
            ),
        )
        for detection in detections
    ]

    matched: dict[str, list[SourceEntry]] = {}
    matched_flows: dict[str, Flow] = {}
    unmatched: list[UnmatchedDetection] = []

    # Indexed once for the whole run, not rebuilt per detection (#56).
    index = index_flows(flows)

    for detection, entry in entries:
        flow, reason = _place(detection, index)
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
    # The gate both warns and, past the threshold, raises. Its warnings belong in the result so
    # they reach `run.warnings[]`, so it returns them rather than only printing them (issue #57).
    return replace(result, warnings=unclassified + _gate(result, threshold))


# --- finding the candidates --------------------------------------------------------------------
#
# The flows are indexed once per run rather than scanned once per detection (#56). The scan was
# O(detections x flows): at 500k flows and 20k detections — a size `docs/prd.md` explicitly
# anticipates when it speaks of multi-GB captures — that is 10^10 comparisons, tens of minutes in
# a stage the PRD assumes is free next to Zeek. Nothing in the suite would have noticed, because
# the largest case here is a few hundred detections against a handful of flows.
#
# The index is keyed by the whole tuple, and each flow is inserted under **both orientations**,
# which is what `_same_tuple` used to establish by comparing. A detection is then looked up by
# its own tuple: matching forward finds the flow's forward key, and matching reversed finds the
# reversed key. No behaviour changes — `test_the_index_agrees_with_the_predicate_it_replaced`
# asserts the two produce identical candidate sets, and `_same_tuple` is kept as the reference
# it is checked against rather than deleted.

#: Flow lookup key: protocol, then the initiator and responder halves in order.
TupleKey = tuple[str, str, int, str, int]
TupleIndex = Mapping[TupleKey, list[Flow]]


def _tuple_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> TupleKey:
    return (proto, src_ip, src_port, dst_ip, dst_port)


def index_flows(flows: Mapping[str, Flow]) -> dict[TupleKey, list[Flow]]:
    """Every flow under both orientations of its 5-tuple.

    A flow whose two orientations coincide — same address and port on both sides — lands in one
    bucket twice; `_candidates` de-duplicates by `uid`, so that costs a wasted slot rather than a
    doubled candidate.
    """
    index: dict[TupleKey, list[Flow]] = {}
    for flow in flows.values():
        forward = _tuple_key(flow.proto, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
        reverse = _tuple_key(flow.proto, flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port)
        index.setdefault(forward, []).append(flow)
        index.setdefault(reverse, []).append(flow)
    return index


def _candidates(detection: Detection, index: TupleIndex) -> list[Flow]:
    """The flows this detection could belong to, by lookup rather than by scan.

    Two keys at most, and the second only for ICMP: the counterpart type Zeek may have written
    in the responder column is a function of the detection's own type and address family, so it
    is computable here without a second index. That is why the relaxation costs one extra dict
    lookup rather than a scan.

    De-duplicated by `uid` because a flow can be reachable under more than one key — both
    orientations of a symmetric tuple, or the exact and counterpart keys when a detection's code
    happens to equal its counterpart type.
    """
    keys = [
        _tuple_key(
            detection.proto,
            detection.src_ip,
            detection.src_port,
            detection.dst_ip,
            detection.dst_port,
        )
    ]

    if detection.proto == ICMP:
        counterpart = _counterparts(detection.src_ip).get(detection.src_port)
        if counterpart is not None and counterpart != detection.dst_port:
            keys.append(
                _tuple_key(
                    detection.proto,
                    detection.src_ip,
                    detection.src_port,
                    detection.dst_ip,
                    counterpart,
                )
            )

    found: dict[str, Flow] = {}
    for key in keys:
        for flow in index.get(key, ()):
            found.setdefault(flow.uid, flow)
    return list(found.values())


# --- placing one detection -------------------------------------------------------------------


def _place(detection: Detection, index: TupleIndex) -> tuple[Flow | None, UnmatchedReason | None]:
    """The flow this detection belongs to, or `None` and the reason it could not be decided.

    Spec §9's steps, in order. The order is load-bearing: a *lone* candidate is matched
    without consulting the clock, because Suricata timestamps the alerting packet while Zeek's
    window is bounded by the packets it attributed to the connection, and those disagree at the
    edges often enough that requiring containment unconditionally would lose real detections.

    The protocol check comes first and needs no index (issue #84). Zeek writes
    `unknown_transport` with both port columns zeroed for anything that is not TCP, UDP or ICMP,
    so there is no tuple to compare — and two such conversations between one host pair are
    written with the *same* 5-tuple, which is why this returns a reason instead of falling
    through to a candidate lookup that could only guess between them.

    Zeek does record the difference in `conn.log`'s `ip_proto` column and `Flow` does not carry
    it, so this is flabel's limit rather than the data's. Correlating these properly is issue
    #96; reporting is the right answer either way, and it is the one that does not invent a
    correlation the model cannot support.
    """
    # Casefolded *here and only here*. The tuple comparison below stays exact, because §8 says
    # step 6 already translated the tuple into Zeek's spelling and a second normalisation would
    # be two places that must agree. But this decision is about whether Zeek has a *name* for
    # the protocol, and an un-normalised `TCP` is not an unsupported transport — it is a step-6
    # regression, which must stay visible as `no_flow_match` and stay inside the gate. Matching
    # exactly here would classify every detection as unsupported the moment step 6 broke, empty
    # the gate's denominator, and switch the gate off exactly when it was needed.
    #
    # An *empty* protocol is excluded from the exclusion for the same reason. `suricata.py`
    # yields `""` when an eve alert record carries no `proto` key at all, and that is a parse
    # failure, not an ESP packet. Calling it unsupported would take it out of the gate, which
    # is precisely backwards: nothing was measured, so nothing licenses tolerating the loss.
    proto = detection.proto.casefold()
    if proto and proto not in CORRELATABLE_PROTOCOLS:
        return None, "unsupported_transport"

    candidates = _candidates(detection, index)

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
    detection: Detection,
    admissions: Mapping[str, SourceAdmission],
    snapshot_id: str | None,
    address_indicators: frozenset[int] | None = None,
    device_rulesets: Mapping[tuple[int, str, int, str, int, str], str] | None = None,
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
    # Tier 1 has no snapshot behind it. Its signature set is the vendor's and its admission
    # decision is the operator's threat exceptions on the device, so both identifiers come from
    # the device and `admissions` has nothing to say about it (Phase 2, #122). Routed on `tier`
    # rather than on `source`, because the tier is the field a label already publishes to mean
    # exactly this distinction — and a tier-1 detection reaching the snapshot lookup below would
    # fail with "the snapshot does not describe it", which is true and useless.
    if detection.tier == 1:
        ruleset = (device_rulesets or {}).get(
            (
                detection.sid,
                detection.src_ip,
                detection.src_port,
                detection.dst_ip,
                detection.dst_port,
                detection.proto,
            ),
            "",
        )
        return build_device_source_entry(detection, ruleset)

    # Past the tier-1 return, so a `None` snapshot here means a tier-2 detection on a run that
    # loaded no rules. That is not a capture flabel can describe — it is `correlate` being handed
    # alerts from an engine the mode says never ran — so it fails with the wiring named rather
    # than building a label whose `ruleset` is the string "None" (spec §4's own guard, one layer
    # up from where it would otherwise catch this).
    if snapshot_id is None:
        raise SnapshotError(
            f"detection sid {detection.sid} is tier {detection.tier}, but this run loaded no "
            f"ruleset snapshot: a replay-only run has no tier-2 rules, so this detection came "
            f"from a stage the run's mode says did not happen"
        )

    try:
        admission = admissions[detection.source]
    except KeyError:
        raise SnapshotError(
            f"detection sid {detection.sid} names source {detection.source!r}, which snapshot "
            f"{snapshot_id} does not describe (it has {sorted(admissions)}): its label would "
            f"cite an origin the snapshot cannot account for"
        ) from None
    # `None` stays `None` — "the snapshot recorded nothing" is not the same fact as "this sid
    # is not an indicator", and `build_source_entry` treats them differently on purpose.
    shape = None if address_indicators is None else detection.sid in address_indicators
    return build_source_entry(detection, admission, snapshot_id, shape)


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


def _source_order(entry: SourceEntry) -> tuple[int, str, int, int, str]:
    """Spec §10: `sources` sorted by `(tier, source, sid, rev, direction)`, numbers numerically.

    `direction` joined the key with the field itself (issue #115). Before it, one rule firing on
    both halves of a flow produced two *identical* entries and the tie could not be observed;
    now they differ, and eve.json's record order is not *guaranteed* stable between runs — spec
    §10's measured instability is in `flow` records, not `alert` records, so this closes a latent
    tie rather than an observed failure. An unbroken tie would make `labels.json` differ across
    two runs over one capture and fail Goal 2 for a reason having nothing to do with the pipeline.
    """
    return (entry.tier, entry.source, entry.sid, entry.rev, entry.direction)


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


def _gate(result: CorrelationResult, threshold: float) -> tuple[str, ...]:
    """Spec §9: silent at zero unmatched, a warning above zero, a failed run above `threshold`.

    Silence at zero is what makes the warning worth reading — it always means something was
    lost. The failure is a `CorrelationError` (exit 1, no `labels.json`), because past the
    threshold the labels no longer describe the capture and a file that says otherwise is worse
    than none.

    Returns the warnings it emitted, so they reach `run.warnings[]` as well as stderr (issue
    #57). On the raising path the exception carries the result and the caller writes `run.json`
    from it, so the message has to be on the result *before* the raise — which is why the
    warning is built once and used for both.
    """
    if not result.unmatched:
        return ()

    # Reported apart from the ratio, because they are not in it (issue #84). Folding them into
    # one percentage would print a numerator and a denominator drawn from different populations
    # — the operator would check the arithmetic, find it wrong, and stop trusting the number.
    unsupported = result.unsupported_transport_total
    aside = (
        f", plus {unsupported} on a transport Zeek cannot express, which the gate does not judge"
        if unsupported
        else ""
    )
    summary = (
        f"{len(result.unmatched) - unsupported} of {result.correlatable_total} correlatable "
        f"detections ({result.unmatched_ratio:.2%}) could not be attached to exactly one flow"
        f"{aside}"
    )
    if result.unmatched_ratio > threshold:
        # Warned as well as raised. The exception carries the result, so the caller can write
        # `unmatched_detections[]` into `run.json` (spec §10) — but the warning reaches an
        # operator watching the run, who is not reading a file that does not exist yet.
        failed = f"{summary}; above the {threshold:.2%} threshold, so this run has failed"
        _warn(failed)
        raise CorrelationError(
            f"{summary}, above the unmatched threshold of {threshold}: the labels would not "
            f"describe this capture. Raise --unmatched-threshold to accept the loss, or check "
            f"that Zeek and Suricata read the same capture.",
            # Carries the warning too, so `run.json` on the failed path says what stderr said.
            result=replace(result, warnings=(failed,)),
        )

    tolerated = f"{summary}; they are reported in unmatched_detections[] and carry no label"
    _warn(tolerated)
    return (tolerated,)


def _warn(message: str) -> None:
    """Print a non-fatal loss on stderr (spec §12), in `zeek.py`'s wording.

    stdout is reserved (spec §12). The message is *also* carried on
    `CorrelationResult.warnings` so it reaches `run.warnings[]` (issue #57) — stderr is not kept,
    and an operator reading the run directory afterwards is the normal case.
    """
    print(f"flabel: warning: {message}", file=sys.stderr)
