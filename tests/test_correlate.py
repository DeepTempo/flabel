"""Attaching detections to flows (spec §9).

Synthetic `Detection` and `Flow` values only — no Zeek, no Suricata, no fixtures. Correlation
is pure, so its suite is fast and hermetic, and every input is visible in the test that uses it.

The defect class these tests exist to catch is the one green CI missed through steps 3-6: a
**silent wrong answer**. Correlation is where that is cheapest to produce — a detection quietly
attached to the wrong flow, or quietly dropped, still yields a well-formed `labels.json` that
exits 0 and is wrong in the field the whole artifact exists to assert. So the tests below are
written against the plausible-but-wrong result rather than against the implementation:

* a lone candidate whose window excludes the detection (spec §9 matches it; an implementation
  that always checks containment silently loses it);
* a detection inside *two* windows, not only outside both;
* sids 2 and 10, which sort the wrong way as strings;
* `flows_total` counted over flows that produced no label;
* an ICMP relaxation wide enough to merge two one-way flows.

The ICMP counterpart tables are **measured, and re-measured on every CI run** — see
`test_the_icmp_tables_are_what_zeek_actually_writes`, the one test here that invokes Zeek. The
parametrized table tests around it prove only that the matcher reads the tables: they build
their fixtures from the constant they iterate, so they cannot say anything about Zeek, and a
comment claiming otherwise is how a remembered measurement passes for a real one.
"""

from __future__ import annotations

import struct
import subprocess
import time
from pathlib import Path

import pytest

from flabel import correlate as correlate_module
from flabel.correlate import ICMPV4_COUNTERPART, ICMPV6_COUNTERPART, correlate
from flabel.errors import CorrelationError, SnapshotError, exit_code_for
from flabel.models import (
    Detection,
    Flow,
    SnapshotManifest,
    SourceAdmission,
    SourceSpec,
)

SNAPSHOT_ID = "8a39182c18a3c9d3"

CLIENT = "10.0.0.1"
SERVER = "198.51.100.7"

#: A ratio can never exceed 1, so this is the loosest legal threshold: it keeps the gate from
#: firing in the tests that are about *what* is unmatched rather than about the gate itself.
#: Spelled once, so those tests read as "gate off" instead of as a magic number.
NO_GATE = 1.0


def make_admission(**overrides) -> SourceAdmission:
    fields = {
        "name": "et/open",
        "url": "https://example.invalid/emerging.rules.tar.gz",
        "licence": "MIT",
        "source_class": "signature",
        "admission_basis": "metadata-filter",
        "rules_fetched": 51778,
        "rules_admitted": 21221,
        "rules_excluded_no_confidence": 5836,
        "rules_excluded_low_confidence": 11425,
        "rules_excluded_low_severity": 13296,
        "rules_excluded_commented": 19479,
        "ja4_rules_admitted": 0,
        "ja3_rules_admitted": 5,
        "fetched_at": "2026-08-12T00:00:00.000000Z",
    }
    return SourceAdmission(**{**fields, **overrides})


def make_manifest(*admissions: SourceAdmission, snapshot_id: str = SNAPSHOT_ID) -> SnapshotManifest:
    records = admissions or (make_admission(),)
    return SnapshotManifest(
        snapshot_id=snapshot_id,
        created_at="2026-08-12T00:00:00.000000Z",
        flabel_version="0.0.0",
        sources=records,
        total_admitted=sum(record.rules_admitted for record in records),
        total_ja4_admitted=sum(record.ja4_rules_admitted for record in records),
    )


def make_detection(**overrides) -> Detection:
    fields = {
        "source": "et/open",
        "tier": 2,
        "sid": 2011465,
        "rev": 5,
        "classtype": "trojan-activity",
        "app_proto": "http",
        "threat": "ET MALWARE Example C2 Checkin",
        "ts": 1_700_000_005.0,
        "src_ip": CLIENT,
        "src_port": 51234,
        "dst_ip": SERVER,
        "dst_port": 80,
        "proto": "tcp",
    }
    return Detection(**{**fields, **overrides})


def make_flow(**overrides) -> Flow:
    fields = {
        "uid": "CFlow00000000000001",
        "src_ip": CLIENT,
        "src_port": 51234,
        "dst_ip": SERVER,
        "dst_port": 80,
        "proto": "tcp",
        "ts_first": 1_700_000_000.0,
        "ts_last": 1_700_000_010.0,
    }
    return Flow(**{**fields, **overrides})


def by_uid(*flows: Flow) -> dict[str, Flow]:
    """Flows keyed the way `zeek.py` hands them over."""
    return {flow.uid: flow for flow in flows}


def many_detections(count: int, unmatched: int) -> list[Detection]:
    """`count` detections on one flow, `unmatched` of them pointing at an absent tuple."""
    return [
        make_detection(sid=index, dst_ip="203.0.113.9" if index < unmatched else SERVER)
        for index in range(count)
    ]


# --- the ordinary cases --------------------------------------------------------------------


def test_one_flow_and_one_detection_yield_one_label():
    """The base case, asserted down to the provenance rather than to the label count."""
    flow = make_flow()
    detection = make_detection()

    result = correlate([detection], by_uid(flow), make_manifest())

    assert len(result.labels) == 1
    label = result.labels[0]
    assert label.verdict == "malicious"
    assert label.best_tier == 2
    assert len(label.sources) == 1
    entry = label.sources[0]
    assert (entry.source, entry.sid, entry.rev) == ("et/open", 2011465, 5)
    assert result.unmatched == ()


def test_the_label_carries_the_flow_it_matched_rather_than_a_reconstruction():
    """A `Flow` rebuilt from the 5-tuple would silently drop everything not in the tuple.

    `ja4`, `ja4s` and `server_name` are joined onto the flow from `ssl.log` by step 5 and are
    not part of the match key, so an implementation that constructs a fresh `Flow` from the
    fields it compared produces a label that is complete, well-formed, and missing the
    fingerprints — with nothing downstream able to tell they were ever there.
    """
    flow = make_flow(ja4="t13d1516h2_8daaf6152771_b186095e22b6", server_name="c2.example.invalid")

    result = correlate([make_detection()], by_uid(flow), make_manifest())

    assert result.labels[0].flow is flow


def test_two_detections_on_one_flow_consolidate_into_one_label():
    """One label per flow, not one per detection — otherwise a flow gets two verdicts."""
    detections = [make_detection(sid=2011465), make_detection(sid=2019401, rev=3)]

    result = correlate(detections, by_uid(make_flow()), make_manifest())

    assert len(result.labels) == 1
    assert [entry.sid for entry in result.labels[0].sources] == [2011465, 2019401]


def test_a_rule_firing_twice_on_one_flow_keeps_both_assertions():
    """Identical detections are kept, not silently collapsed.

    Suricata emits one alert per matching packet, so the same rule can fire twice on one flow.
    Nothing in spec §9 or §10 asks for de-duplication, and dropping one would make the output
    say the rule fired once. Recorded here as a deliberate decision rather than an accident, so
    a future change to it has to change this test.
    """
    result = correlate([make_detection(), make_detection()], by_uid(make_flow()), make_manifest())

    assert len(result.labels[0].sources) == 2


def test_a_flow_with_no_detection_gets_no_label():
    """flabel labels malicious flows and says nothing about the rest (spec §13)."""
    quiet = make_flow(uid="CQuiet0000000000001", src_ip="10.0.0.99", src_port=40000)

    result = correlate([make_detection()], by_uid(make_flow(), quiet), make_manifest())

    assert [label.flow.uid for label in result.labels] == ["CFlow00000000000001"]


def test_a_detection_matches_its_flow_in_the_reverse_direction():
    """Zeek names the initiator; a rule can fire on either direction of the same connection.

    Spec §9 step 1 says "in either direction" precisely because an alert on the server's reply
    carries the server as `src_ip`. Matching forward only would leave every such detection
    unmatched, and past 1% that fails the run.
    """
    inbound = make_detection(src_ip=SERVER, src_port=80, dst_ip=CLIENT, dst_port=51234)

    result = correlate([inbound], by_uid(make_flow()), make_manifest())

    assert len(result.labels) == 1
    assert result.unmatched == ()


def test_a_reversed_tuple_needs_both_halves_reversed():
    """The tuple is directional, not a set.

    An implementation comparing sorted endpoints — or the ports independently of the addresses
    — would match a detection from A:51234→B:80 against a flow from A:80→B:51234, which is a
    different conversation. This is the shape a "match either direction" reading goes wrong in.
    """
    detection = make_detection(src_port=80, dst_port=51234)

    result = correlate([detection], by_uid(make_flow()), make_manifest(), threshold=NO_GATE)

    assert result.labels == ()
    assert [item.reason for item in result.unmatched] == ["no_flow_match"]


def test_a_tuple_absent_from_the_flows_is_unmatched_not_dropped():
    """Spec §11's "detection uncorrelatable" row — reported, never silently discarded."""
    detection = make_detection(dst_ip="203.0.113.9")

    result = correlate([detection], by_uid(make_flow()), make_manifest(), threshold=NO_GATE)

    assert result.labels == ()
    assert len(result.unmatched) == 1
    assert result.unmatched[0].reason == "no_flow_match"
    assert result.unmatched[0].detection is detection


def test_the_protocol_is_part_of_the_tuple():
    """The same addresses and ports over UDP is a different flow.

    Step 6 lowercases the protocol precisely so this comparison is meaningful; dropping it from
    the match would attach a UDP alert to a TCP conversation between the same endpoints.
    """
    result = correlate(
        [make_detection(proto="udp")], by_uid(make_flow()), make_manifest(), threshold=NO_GATE
    )

    assert [item.reason for item in result.unmatched] == ["no_flow_match"]


def test_correlation_does_not_renormalise_the_protocol_case():
    """Spec §8: step 6 already translated the tuple into Zeek's spelling; §9 compares as given.

    A second normalisation here would be two places that must agree about what a tuple is. This
    is the check that it is absent: an un-normalised `TCP` must fail to match rather than be
    quietly fixed up, so a regression in step 6 surfaces as reported unmatched detections
    instead of being masked here.
    """
    result = correlate(
        [make_detection(proto="TCP")], by_uid(make_flow()), make_manifest(), threshold=NO_GATE
    )

    assert [item.reason for item in result.unmatched] == ["no_flow_match"]


# --- candidate resolution ------------------------------------------------------------------


def test_a_lone_candidate_matches_even_when_the_detection_is_outside_its_window():
    """Spec §9 orders the rules: one candidate is matched, and only *multiple* consult the clock.

    The plausible-but-wrong implementation applies containment unconditionally. It passes every
    happy-path test, then loses real detections whose timestamp sits fractionally outside the
    conn's window — which is ordinary, because Suricata timestamps the alerting packet while
    Zeek's window is bounded by the packets it attributed to the connection.
    """
    flow = make_flow(ts_first=1_700_000_100.0, ts_last=1_700_000_110.0)

    result = correlate([make_detection(ts=1_700_000_005.0)], by_uid(flow), make_manifest())

    assert len(result.labels) == 1
    assert result.unmatched == ()


def test_port_reuse_is_resolved_by_time_containment():
    """Two connections, one 5-tuple: the detection belongs to the window that contains it."""
    first = make_flow(uid="CEarly0000000000001", ts_first=1_700_000_000.0, ts_last=1_700_000_010.0)
    second = make_flow(uid="CLate00000000000001", ts_first=1_700_000_100.0, ts_last=1_700_000_110.0)

    result = correlate([make_detection(ts=1_700_000_105.0)], by_uid(first, second), make_manifest())

    assert len(result.labels) == 1
    assert result.labels[0].flow is second, "the detection landed in the second window"


@pytest.mark.parametrize(
    ("ts", "expected_uid"),
    [
        pytest.param(1_700_000_000.0, "CEarly0000000000001", id="on-ts-first"),
        pytest.param(1_700_000_010.0, "CEarly0000000000001", id="on-ts-last"),
    ],
)
def test_the_window_includes_its_endpoints(ts, expected_uid):
    """`[ts_first, ts_last]` is closed (spec §9).

    A single-packet flow has `ts_first == ts_last`, so a half-open window would make every
    detection on one unmatchable — and an alert on the first or last packet of a connection is
    the common case, not an edge case.
    """
    early = make_flow(uid="CEarly0000000000001", ts_first=1_700_000_000.0, ts_last=1_700_000_010.0)
    late = make_flow(uid="CLate00000000000001", ts_first=1_700_000_100.0, ts_last=1_700_000_110.0)

    result = correlate([make_detection(ts=ts)], by_uid(early, late), make_manifest())

    assert result.labels[0].flow.uid == expected_uid


def test_a_detection_outside_every_candidate_window_is_ambiguous():
    """Spec §11's "ambiguous flow match" row, and spec §13: never assign a flow by guess."""
    first = make_flow(uid="CEarly0000000000001", ts_first=1_700_000_000.0, ts_last=1_700_000_010.0)
    second = make_flow(uid="CLate00000000000001", ts_first=1_700_000_100.0, ts_last=1_700_000_110.0)

    result = correlate(
        [make_detection(ts=1_700_000_050.0)],
        by_uid(first, second),
        make_manifest(),
        threshold=NO_GATE,
    )

    assert result.labels == (), "an ambiguous detection must produce no label at all"
    assert [item.reason for item in result.unmatched] == ["ambiguous_flow_match"]


def test_a_detection_inside_two_candidate_windows_is_ambiguous():
    """The other half of the ambiguity, and the one an "outside both" test never reaches.

    Overlapping connections on one 5-tuple happen whenever Zeek's inactivity timeout splits a
    long conversation, or a client reuses a port before the old flow expires. An implementation
    that takes the first containing candidate picks one by position in a dict — a guess, and a
    stable-looking one.
    """
    first = make_flow(uid="CEarly0000000000001", ts_first=1_700_000_000.0, ts_last=1_700_000_060.0)
    second = make_flow(uid="CLate00000000000001", ts_first=1_700_000_050.0, ts_last=1_700_000_110.0)

    result = correlate(
        [make_detection(ts=1_700_000_055.0)],
        by_uid(first, second),
        make_manifest(),
        threshold=NO_GATE,
    )

    assert result.labels == ()
    assert [item.reason for item in result.unmatched] == ["ambiguous_flow_match"]


def test_ambiguity_is_resolved_per_detection_not_per_capture():
    """One unplaceable detection must not cost the placeable ones their labels."""
    first = make_flow(uid="CEarly0000000000001", ts_first=1_700_000_000.0, ts_last=1_700_000_010.0)
    second = make_flow(uid="CLate00000000000001", ts_first=1_700_000_100.0, ts_last=1_700_000_110.0)
    detections = [make_detection(ts=1_700_000_005.0), make_detection(ts=1_700_000_050.0, sid=99)]

    result = correlate(detections, by_uid(first, second), make_manifest(), threshold=NO_GATE)

    assert [label.flow.uid for label in result.labels] == ["CEarly0000000000001"]
    assert len(result.unmatched) == 1


# --- ICMP: the counterpart-type residual (spec §8, owned here) ------------------------------


def test_an_icmpv4_echo_request_detection_matches_exactly():
    """The case step 6's mirroring already gets right, pinned so the ICMP path cannot break it.

    Measured on Zeek 8.0.4: an ICMPv4 echo exchange is one conn with `id.orig_p 8` and
    `id.resp_p 0`, and mirroring `icmp_type`/`icmp_code` yields exactly `(8, 0)`.
    """
    flow = make_flow(src_port=8, dst_port=0, proto="icmp")

    result = correlate(
        [make_detection(src_port=8, dst_port=0, proto="icmp")], by_uid(flow), make_manifest()
    )

    assert len(result.labels) == 1


def test_an_icmpv6_echo_detection_matches_the_flow_for_the_same_exchange():
    """The residual spec §8 hands to step 7, and the reason correlation treats ICMP specially.

    Zeek writes the *reply* type in `id.resp_p` for an ICMPv6 echo — measured `128 -> 129` —
    where a single Suricata alert record can only yield `(128, 0)`, since it does not carry the
    counterpart type. Without this, every ICMPv6 echo detection is uncorrelatable, and three
    such alerts in 150 are enough to trip the 1% gate and fail an otherwise good run.
    """
    flow = make_flow(src_ip="fd00::a1", src_port=128, dst_ip="fd00::b2", dst_port=129, proto="icmp")
    detection = make_detection(
        src_ip="fd00::a1", src_port=128, dst_ip="fd00::b2", dst_port=0, proto="icmp"
    )

    result = correlate([detection], by_uid(flow), make_manifest())

    assert len(result.labels) == 1
    assert result.unmatched == ()


def test_an_icmpv4_echo_reply_detection_matches_the_same_exchange():
    """Spec §8 calls mirroring exact for ICMPv4. Measured, that holds for the *request* only.

    An echo exchange is one conn, `id.orig_p 8 -> id.resp_p 0`. An alert on the reply packet
    carries type 0, code 0, so its tuple is `(server, 0, client, 0)` — and against the reversed
    flow the responder column holds the request type `8`, not the code `0`. The same
    one-field-out problem as ICMPv6, in the family the spec describes as exact.
    """
    flow = make_flow(src_port=8, dst_port=0, proto="icmp")
    reply = make_detection(src_ip=SERVER, src_port=0, dst_ip=CLIENT, dst_port=0, proto="icmp")

    result = correlate([reply], by_uid(flow), make_manifest())

    assert len(result.labels) == 1


def test_an_icmpv6_reply_detection_matches_through_the_reversed_flow():
    """Both halves at once: reverse-direction matching *and* the counterpart column."""
    flow = make_flow(src_ip="fd00::a1", src_port=128, dst_ip="fd00::b2", dst_port=129, proto="icmp")
    reply = make_detection(
        src_ip="fd00::b2", src_port=129, dst_ip="fd00::a1", dst_port=0, proto="icmp"
    )

    result = correlate([reply], by_uid(flow), make_manifest())

    assert len(result.labels) == 1


@pytest.mark.parametrize(("kind", "counterpart"), sorted(ICMPV4_COUNTERPART.items()))
def test_the_matching_reads_the_icmpv4_table(kind, counterpart):
    """Every table entry is honoured by the matcher.

    This asserts the *code reads the table*, and deliberately nothing more: it builds its
    fixture from the same constant it iterates, so it would pass against a table of nonsense.
    What the table says about Zeek is proved against Zeek itself, by
    `test_the_icmp_tables_are_what_zeek_actually_writes` below.
    """
    flow = make_flow(src_port=kind, dst_port=counterpart, proto="icmp")
    detection = make_detection(src_port=kind, dst_port=0, proto="icmp")

    assert len(correlate([detection], by_uid(flow), make_manifest()).labels) == 1


@pytest.mark.parametrize(("kind", "counterpart"), sorted(ICMPV6_COUNTERPART.items()))
def test_the_matching_reads_the_icmpv6_table(kind, counterpart):
    """The ICMPv6 half of the same limited claim — the matcher honours every entry."""
    flow = make_flow(
        src_ip="fd00::a1", src_port=kind, dst_ip="fd00::b2", dst_port=counterpart, proto="icmp"
    )
    detection = make_detection(
        src_ip="fd00::a1", src_port=kind, dst_ip="fd00::b2", dst_port=0, proto="icmp"
    )

    assert len(correlate([detection], by_uid(flow), make_manifest()).labels) == 1


# --- the tables against the tool that produces them -------------------------------------------

#: A code no counterpart type takes, so a responder column echoing the code can never be
#: mistaken for one holding a paired type. Zero would be ambiguous against ICMPv4 type 0.
SWEEP_CODE = 7

ETHERNET = b"\x02" * 6 + b"\x02" * 5 + b"\x01"
IPV4_SRC, IPV4_DST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
IPV6_SRC = bytes.fromhex("fd000000000000000000000000000001")
IPV6_DST = bytes.fromhex("fd000000000000000000000000000002")


def _icmp4_packet(icmp_type: int, code: int) -> bytes:
    """One Ethernet/IPv4/ICMP packet. Checksums are left zero — Zeek is invoked with `-C`."""
    icmp = struct.pack("!BBHHH", icmp_type, code, 0, 0x1234, 1) + b"payload!"
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, IPV4_SRC, IPV4_DST
    )
    return ETHERNET + b"\x08\x00" + header + icmp


def _icmp6_packet(icmp_type: int, code: int) -> bytes:
    """One Ethernet/IPv6/ICMPv6 packet, likewise unchecksummed."""
    icmp = struct.pack("!BBHI", icmp_type, code, 0, 0) + b"\x00" * 16
    header = struct.pack("!IHBB", 0x60000000, len(icmp), 58, 64) + IPV6_SRC + IPV6_DST
    return ETHERNET + b"\x86\xdd" + header + icmp


def _write_pcap(path: Path, packets: list[bytes]) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate(packets):
        out += struct.pack("<IIII", 1_700_000_000 + index * 10, 0, len(packet), len(packet))
        out += packet
    path.write_bytes(out)


def _sweep(tmp_path: Path, build, types: range) -> dict[int, int]:
    """Send one packet of each type at `SWEEP_CODE` and read back what Zeek put in `id.resp_p`.

    The code is deliberately not 0: it is a value no counterpart type takes, so a responder
    column echoing the code can never be mistaken for one holding a paired type.
    """
    capture = tmp_path / "icmp.pcap"
    _write_pcap(capture, [build(kind, SWEEP_CODE) for kind in types])
    outdir = tmp_path / "zeek"
    outdir.mkdir()
    subprocess.run(
        ["zeek", "-C", "-D", "-r", str(capture)], cwd=outdir, check=True, capture_output=True
    )

    paired: dict[int, int] = {}
    for line in (outdir / "conn.log").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        orig_p, resp_p = int(fields[3]), int(fields[5])
        if resp_p != SWEEP_CODE:
            paired[orig_p] = resp_p
    return paired


@pytest.mark.requires_tools
def test_the_icmp_tables_are_what_zeek_actually_writes(tmp_path: Path):
    """The tables are measured facts about Zeek, so Zeek is what checks them (spec §8).

    Correlation's ICMP special case exists because Zeek writes a *counterpart type* in
    `id.resp_p` for some ICMP types and the *code* for all the others, while a Suricata alert
    can only ever yield `(type, code)`. Which types those are is not a design choice — it is
    behaviour of the pinned Zeek build, and spec §8 now states it as fact.

    The tests above prove the matcher reads the tables. Only this one proves the tables are
    true, and it is the difference between a measurement and a remembered measurement: without
    it, a Zeek upgrade that changed this behaviour would silently make every affected ICMP
    detection uncorrelatable, and the 1% gate would fail good runs while blaming correlation.

    Exhaustive over the ranges that contain every pairing, rather than over the table's own
    keys — iterating the keys could only ever confirm what the table already says, and would
    never reveal a pair the table is *missing*.
    """
    assert _sweep(tmp_path, _icmp4_packet, range(0, 46)) == ICMPV4_COUNTERPART
    v6 = tmp_path / "v6"
    v6.mkdir()
    assert _sweep(v6, _icmp6_packet, range(0, 161)) == ICMPV6_COUNTERPART


def test_the_icmp_relaxation_does_not_merge_two_one_way_flows():
    """The over-relaxation this special case must not become.

    For a one-way type Zeek writes the *code* in `id.resp_p` — measured: type 3 code 1 gives
    `3 -> 1`. So two destination-unreachable flows between the same pair differ only in that
    column, and an implementation that ignored the column whenever the protocol is ICMP would
    see two candidates for a detection that has exactly one right answer, then pick by clock.
    """
    host = make_flow(uid="CHost00000000000001", src_port=3, dst_port=1, proto="icmp")
    port = make_flow(uid="CPort00000000000001", src_port=3, dst_port=3, proto="icmp")
    detection = make_detection(src_port=3, dst_port=3, proto="icmp")

    result = correlate([detection], by_uid(host, port), make_manifest())

    assert result.labels[0].flow.uid == "CPort00000000000001"


def test_the_counterpart_relaxation_is_icmp_only():
    """A TCP responder port that happens to look like a counterpart must not be forgiven.

    Ports are exact for every protocol that has them; the relaxation exists only because Zeek
    puts something other than a port in that column for ICMP.
    """
    flow = make_flow(src_port=128, dst_port=129, proto="tcp")
    detection = make_detection(src_port=128, dst_port=0, proto="tcp")

    result = correlate([detection], by_uid(flow), make_manifest(), threshold=NO_GATE)

    assert [item.reason for item in result.unmatched] == ["no_flow_match"]


def test_the_counterpart_table_is_chosen_by_address_family():
    """ICMPv4 and ICMPv6 number their types differently, and the tables must not be merged.

    Zeek writes `icmp` for both — its `transport_proto` has no ICMPv6 value — so the protocol
    field cannot tell them apart and the address has to. Type 128 is unassigned in ICMPv4, so a
    v4 flow pairing 128 with 129 cannot exist, and matching one would be a guess.
    """
    flow = make_flow(src_port=128, dst_port=129, proto="icmp")
    detection = make_detection(src_port=128, dst_port=0, proto="icmp")

    result = correlate([detection], by_uid(flow), make_manifest(), threshold=NO_GATE)

    assert [item.reason for item in result.unmatched] == ["no_flow_match"]


# --- provenance comes from the snapshot -----------------------------------------------------


def test_a_detection_whose_source_is_absent_from_the_manifest_raises():
    """Spec §9: a typed `SnapshotError`, matching §8's handling of a SID owned by no source.

    The `KeyError` the lookup raises on its own reaches the operator as a traceback rather than
    a reason, and dropping the detection instead would emit a run that exits 0 having lost it.
    The message names both halves of the mismatch — the source and the snapshot that does not
    describe it — because either one alone leaves the reader guessing which is wrong.
    """
    detection = make_detection(source="abuse.ch/urlhaus")

    with pytest.raises(SnapshotError) as raised:
        correlate([detection], by_uid(make_flow()), make_manifest())

    assert "abuse.ch/urlhaus" in str(raised.value)
    assert SNAPSHOT_ID in str(raised.value)


def test_an_identify_detection_is_a_hard_failure_not_a_filter():
    """Spec §9: step 6 already suppressed and counted these, so one here means it was bypassed.

    Asserting `labels == ()` instead would satisfy the words — no label from an identify
    source — while producing a run that exits 0 having silently lost a detection. The raise is
    the point.
    """
    admission = make_admission(name="oisf/trafficid", source_class="identify")

    with pytest.raises(ValueError, match="identify"):
        correlate(
            [make_detection(source="oisf/trafficid")],
            by_uid(make_flow()),
            make_manifest(admission),
        )


def test_an_identify_detection_fails_even_when_it_matches_no_flow():
    """The bypass is the same bypass whether or not the tuple happens to correlate.

    Building every entry before matching is what makes this hold. Validating only the matched
    detections would let an identify alert on an uncorrelatable tuple pass as an ordinary
    unmatched row — a mis-wired pipeline reported as a routine loss.
    """
    admission = make_admission(name="oisf/trafficid", source_class="identify")
    detection = make_detection(source="oisf/trafficid", dst_ip="203.0.113.9")

    with pytest.raises(ValueError, match="identify"):
        correlate([detection], by_uid(make_flow()), make_manifest(admission), threshold=NO_GATE)


def test_a_broken_manifest_fails_even_when_nothing_correlates():
    """A ruleset id no reader can resolve must fail the run, not wait for a match to notice.

    A capture whose detections all go unmatched would otherwise exit 0 against a manifest that
    could never have produced a traceable label — the defect surfacing only on the next capture.
    """
    with pytest.raises(ValueError, match="snapshot"):
        correlate(
            [make_detection(dst_ip="203.0.113.9")],
            by_uid(make_flow()),
            make_manifest(snapshot_id="None"),
            threshold=NO_GATE,
        )


def test_each_detection_gets_the_admission_for_its_own_source():
    """Two sources in one snapshot: the terms must follow the detection, not the position.

    Both licences are real values, so an implementation indexing the manifest by position — or
    reusing the first admission — produces labels that are complete and cite the wrong feed.
    """
    manifest = make_manifest(
        make_admission(name="et/open", licence="MIT"),
        make_admission(name="abuse.ch/urlhaus", licence="CC0-1.0", source_class="ioc-name"),
    )
    detections = [
        make_detection(source="et/open", sid=2011465),
        make_detection(source="abuse.ch/urlhaus", sid=3000001),
    ]

    result = correlate(detections, by_uid(make_flow()), manifest)

    terms = {entry.source: (entry.licence, entry.label_basis) for entry in result.labels[0].sources}
    assert terms == {
        "et/open": ("MIT", "direct"),
        "abuse.ch/urlhaus": ("CC0-1.0", "indicator-reference"),
    }


def test_the_terms_come_from_the_manifest_not_the_live_registry():
    """Spec §9: a label's terms come from the snapshot that produced it.

    `build_source_entry` refuses a `SourceSpec` outright, which is what makes this enforced
    rather than advised — a correlate that reached for `config.load_sources()` could not even
    construct an entry. Asserted here so the enforcement is exercised from this module's own
    call site, not only from `test_provenance.py`.
    """
    manifest = make_manifest(make_admission(licence="CC0-1.0", admission_basis="wholesale"))

    entry = correlate([make_detection()], by_uid(make_flow()), manifest).labels[0].sources[0]

    assert (entry.licence, entry.admission_basis) == ("CC0-1.0", "wholesale")


def test_the_right_admission_is_found_in_a_multi_source_snapshot():
    """`SnapshotManifest.sources` is a tuple; `sources_by_name` is the index (#49).

    A dict-shaped assumption about the tuple itself raises `TypeError`, which is loud — but an
    implementation that only ever looked at `sources[0]` is not, and against a single-source
    manifest it is indistinguishable from a correct one.
    """
    manifest = make_manifest(
        make_admission(name="stamus/lateral", licence="GPL-3.0"),
        make_admission(name="et/open", licence="MIT"),
    )

    entry = correlate([make_detection()], by_uid(make_flow()), manifest).labels[0].sources[0]

    assert entry.licence == "MIT"


def test_every_entry_cites_the_manifests_own_snapshot_id():
    """The ruleset on a label is the one that produced it, taken from the manifest it came in."""
    entry = correlate([make_detection()], by_uid(make_flow()), make_manifest()).labels[0].sources[0]

    assert entry.ruleset == SNAPSHOT_ID


def test_a_sourcespec_registry_cannot_be_passed_as_a_manifest_source():
    """The realistic miswiring, exercised through `correlate` rather than only the builder.

    A step 9 that assembled a manifest out of `config.load_sources()` values would produce
    labels carrying today's registry terms over yesterday's rules — the highest-ranked risk in
    `docs/prd.md`. It fails at this call site, with a message naming the type.
    """
    spec = SourceSpec(
        name="et/open",
        url="https://example.invalid/emerging.rules.tar.gz",
        licence="MIT",
        source_class="signature",
        admission_basis="metadata-filter",
    )
    manifest = SnapshotManifest(
        snapshot_id=SNAPSHOT_ID,
        created_at="2026-08-12T00:00:00.000000Z",
        flabel_version="0.0.0",
        sources=(spec,),  # type: ignore[arg-type]
        total_admitted=1,
        total_ja4_admitted=0,
    )

    with pytest.raises(ValueError, match="SourceAdmission"):
        correlate([make_detection()], by_uid(make_flow()), manifest)


# --- consolidation ---------------------------------------------------------------------------


def test_best_tier_is_the_minimum_not_the_maximum():
    """Lower is higher trust: a tier-1 NGFW verdict outranks tier-2 screening (spec §4).

    `Label.__post_init__` rejects a `best_tier` that disagrees with `min(sources.tier)`, so a
    `max` would raise rather than lie — but the value is asserted here anyway, because that
    backstop belongs to the model and this is the step that chooses.
    """
    detections = [make_detection(tier=2, sid=2011465), make_detection(tier=1, sid=900001)]

    result = correlate(detections, by_uid(make_flow()), make_manifest())

    assert result.labels[0].best_tier == 1


def test_sources_are_sorted_by_tier_then_source_then_sid_then_rev():
    """Spec §10's order, applied here so the tuple is canonical before serialisation.

    sids 2 and 10 are deliberate: sorted as strings "10" precedes "2", and every other
    assertion in this file would still pass. Reproducibility (Goal 2) rests on this order.
    """
    manifest = make_manifest(make_admission(name="a/first"), make_admission(name="z/last"))
    detections = [
        make_detection(source="z/last", tier=2, sid=10, rev=1),
        make_detection(source="a/first", tier=2, sid=10, rev=2),
        make_detection(source="a/first", tier=2, sid=10, rev=1),
        make_detection(source="a/first", tier=2, sid=2, rev=1),
        make_detection(source="z/last", tier=1, sid=10, rev=1),
    ]

    result = correlate(detections, by_uid(make_flow()), manifest)

    assert [
        (entry.tier, entry.source, entry.sid, entry.rev) for entry in result.labels[0].sources
    ] == [
        (1, "z/last", 10, 1),
        (2, "a/first", 2, 1),
        (2, "a/first", 10, 1),
        (2, "a/first", 10, 2),
        (2, "z/last", 10, 1),
    ]


def test_labels_are_sorted_by_first_timestamp_then_uid():
    """Spec §10's label order, so the result is canonical whatever order Zeek's dict was in."""
    early = make_flow(uid="Czzz000000000000001", ts_first=1_700_000_000.0)
    late_a = make_flow(
        uid="Caaa000000000000001", src_port=40001, ts_first=1_700_000_500.0, ts_last=1_700_000_600.0
    )
    late_b = make_flow(
        uid="Cbbb000000000000001", src_port=40002, ts_first=1_700_000_500.0, ts_last=1_700_000_600.0
    )
    detections = [
        make_detection(src_port=40002, ts=1_700_000_550.0, sid=3),
        make_detection(src_port=40001, ts=1_700_000_550.0, sid=2),
        make_detection(ts=1_700_000_005.0, sid=1),
    ]

    result = correlate(detections, by_uid(late_b, late_a, early), make_manifest())

    assert [label.flow.uid for label in result.labels] == [
        "Czzz000000000000001",
        "Caaa000000000000001",
        "Cbbb000000000000001",
    ]


def test_unmatched_are_sorted_by_timestamp_then_source_then_sid():
    """Spec §10's order for `unmatched_detections[]`, for the same reason as the labels."""
    manifest = make_manifest(make_admission(name="a/first"), make_admission(name="z/last"))
    detections = [
        make_detection(source="z/last", sid=5, ts=1_700_000_900.0, dst_ip="203.0.113.9"),
        make_detection(source="a/first", sid=9, ts=1_700_000_900.0, dst_ip="203.0.113.9"),
        make_detection(source="a/first", sid=1, ts=1_700_000_100.0, dst_ip="203.0.113.9"),
    ]

    result = correlate(detections, by_uid(make_flow()), manifest, threshold=NO_GATE)

    assert [
        (item.detection.ts, item.detection.source, item.detection.sid) for item in result.unmatched
    ] == [
        (1_700_000_100.0, "a/first", 1),
        (1_700_000_900.0, "a/first", 9),
        (1_700_000_900.0, "z/last", 5),
    ]


def test_the_result_does_not_depend_on_the_order_the_detections_arrive_in():
    """Goal 2: two runs over the same capture must serialise identically.

    Suricata's alert order is stable, but nothing downstream should depend on it — this is the
    property that makes step 10's reproducibility gate meaningful rather than lucky.
    """
    flows = by_uid(make_flow(), make_flow(uid="CSecond000000000001", src_port=40001))
    detections = [
        make_detection(sid=7),
        make_detection(src_port=40001, sid=3),
        make_detection(sid=1, tier=1),
    ]

    forwards = correlate(detections, flows, make_manifest())
    backwards = correlate(list(reversed(detections)), flows, make_manifest())

    assert forwards == backwards


def test_flows_total_counts_every_flow_not_only_the_labelled_ones():
    """`counts.flows` describes the capture, not the verdicts.

    Counting labelled flows would report a capture of 2,000 flows with 3 labels as a capture of
    3 flows — and every ratio computed from it downstream would be wrong in the flattering
    direction.
    """
    flows = by_uid(
        make_flow(),
        make_flow(uid="CQuiet0000000000001", src_ip="10.0.0.99"),
        make_flow(uid="CQuiet0000000000002", src_ip="10.0.0.98"),
    )

    result = correlate([make_detection()], flows, make_manifest())

    assert (result.flows_total, len(result.labels)) == (3, 1)


def test_detections_total_counts_the_unmatched_ones_too():
    """It is the denominator of the gate: counting only matched detections makes it always 0."""
    detections = [make_detection(), make_detection(sid=2, dst_ip="203.0.113.9")]

    result = correlate(detections, by_uid(make_flow()), make_manifest(), threshold=0.5)

    assert result.detections_total == 2
    assert result.unmatched_ratio == 0.5


def test_the_inputs_are_not_mutated():
    """Pure means pure: a caller's flow mapping is still theirs afterwards."""
    flows = by_uid(make_flow())
    detections = [make_detection()]

    correlate(detections, flows, make_manifest())

    assert list(flows) == ["CFlow00000000000001"]
    assert len(detections) == 1


def test_no_detections_is_not_a_failure():
    """A capture with no alerts is an ordinary successful run with nothing to say."""
    result = correlate([], by_uid(make_flow()), make_manifest())

    assert (result.labels, result.unmatched) == ((), ())
    assert result.unmatched_ratio == 0.0
    assert result.flows_total == 1


# --- the unmatched gate ----------------------------------------------------------------------


def test_one_unmatched_in_two_hundred_passes():
    """0.5% is under the 1% default: a handful of uncorrelatable alerts is normal."""
    result = correlate(many_detections(200, 1), by_uid(make_flow()), make_manifest())

    assert len(result.unmatched) == 1
    assert len(result.labels[0].sources) == 199


def test_one_unmatched_in_fifty_fails_the_run():
    """2% is above the default: at that rate the labels no longer describe the capture."""
    with pytest.raises(CorrelationError, match="unmatched"):
        correlate(many_detections(50, 1), by_uid(make_flow()), make_manifest())


@pytest.mark.parametrize(
    ("unmatched", "total", "fails"),
    [
        pytest.param(1, 100, False, id="exactly-the-threshold"),
        pytest.param(2, 100, True, id="a-hair-over"),
    ],
)
def test_the_gate_fires_above_the_threshold_not_at_it(unmatched, total, fails):
    """Spec §9 says *above* the threshold, and 1-in-100 is the value that tells the two apart.

    A `>=` comparison fails a run sitting exactly on the documented limit, which is the value
    an operator who read the spec will choose deliberately.
    """
    detections = many_detections(total, unmatched)
    flows = by_uid(make_flow())

    if fails:
        with pytest.raises(CorrelationError):
            correlate(detections, flows, make_manifest())
    else:
        assert len(correlate(detections, flows, make_manifest()).unmatched) == unmatched


def test_the_threshold_is_configurable():
    """`--unmatched-threshold` (spec §12); Phase 2 sets its own rather than relaxing this one."""
    detections = many_detections(50, 1)
    flows = by_uid(make_flow())

    assert len(correlate(detections, flows, make_manifest(), threshold=0.05).unmatched) == 1

    with pytest.raises(CorrelationError):
        correlate(detections, flows, make_manifest(), threshold=0.001)


def test_the_gate_failure_exits_one():
    """Spec §12/§13: a hard failure is exit 1, and nothing may claim a verdict afterwards."""
    with pytest.raises(CorrelationError) as raised:
        correlate(many_detections(50, 1), by_uid(make_flow()), make_manifest())

    assert exit_code_for(raised.value) == 1


def test_the_gate_failure_carries_the_unmatched_records():
    """The records are the content of the failure, and the raise must not discard them.

    Spec §11 requires every unmatched detection reported, and spec §10 puts them in `run.json`
    on a failed run — but step 9 can only write what the exception hands it. Before
    `CorrelationError` this raise carried a message and nothing else, so the one failure that
    is *about* lost detections was the one that lost them.
    """
    with pytest.raises(CorrelationError) as raised:
        correlate(many_detections(50, 1), by_uid(make_flow()), make_manifest())

    result = raised.value.result
    assert result is not None, "the gate raised without the result step 9 has to report"
    assert len(result.unmatched) == 1
    assert result.unmatched[0].reason == "no_flow_match"
    assert result.detections_total == 50


def test_zero_unmatched_is_silent(capsys):
    """Spec §9: silence at zero, so a warning in the log always means something was lost."""
    correlate([make_detection()], by_uid(make_flow()), make_manifest())

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_any_unmatched_warns_on_stderr(capsys):
    """Below the threshold is still a loss, and spec §2.5 forbids losing it silently.

    stderr, not stdout: spec §12 reserves stdout, and a warning printed there would land in a
    pipeline's parsed output.
    """
    correlate(many_detections(200, 1), by_uid(make_flow()), make_manifest())

    captured = capsys.readouterr()
    assert "1 of 200" in captured.err
    assert captured.out == ""


@pytest.mark.parametrize(
    "threshold",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(-0.1, id="negative"),
        pytest.param(1.5, id="above-one"),
        pytest.param(True, id="bool"),
        pytest.param("0.01", id="string"),
    ],
)
def test_a_threshold_that_would_disable_the_gate_is_refused(threshold):
    """`argparse(type=float)` accepts `nan` and `inf`, and every comparison against them is False.

    A run invoked with `--unmatched-threshold nan` would then discard any proportion of its
    detections and exit 0 — the gate silently off, with nothing in the output saying so. A
    ratio can never exceed 1, so a threshold above 1 is the same thing spelled differently.
    """
    with pytest.raises(ValueError, match="threshold"):
        correlate([make_detection()], by_uid(make_flow()), make_manifest(), threshold=threshold)


def test_a_threshold_of_zero_means_any_loss_fails():
    """The strictest useful setting, and it must not be mistaken for "unset"."""
    with pytest.raises(CorrelationError):
        correlate(many_detections(200, 1), by_uid(make_flow()), make_manifest(), threshold=0.0)


def test_the_gate_measures_detections_not_flows():
    """The denominator is total detections (spec §9), which is not the number of flows.

    Measured against a flow count, the same run passes or fails depending on how busy the
    capture was — the sort of ratio that looks reasonable and reports the wrong thing.
    """
    quiet = (
        make_flow(uid=f"CQuiet{index:013d}", src_port=40000 + index, src_ip="10.0.0.99")
        for index in range(49)
    )
    flows = by_uid(make_flow(), *quiet)

    with pytest.raises(CorrelationError, match="1 of 20"):
        correlate(many_detections(20, 1), flows, make_manifest())


def test_the_ordinary_thresholds_survive_the_guard():
    """The guard must not reject real values, including the documented default and an int."""
    assert correlate([make_detection()], by_uid(make_flow()), make_manifest(), 0.01).labels
    assert correlate([make_detection()], by_uid(make_flow()), make_manifest(), 1).labels


# --- the index against the scan it replaced ---------------------------------------------------
#
# #56 replaced an O(detections x flows) scan with a lookup. The scan's predicate, `_same_tuple`,
# is deliberately kept: it is the readable definition of "this detection could be this flow",
# and it is what the index is checked against. A performance change that alters which flows are
# candidates is a correctness change wearing a performance change's clothes.


def _brute_force(detection: Detection, flows: dict[str, Flow]) -> set[str]:
    """Candidates the way the pre-#56 scan found them."""
    return {flow.uid for flow in flows.values() if correlate_module._same_tuple(detection, flow)}


def _indexed(detection: Detection, flows: dict[str, Flow]) -> set[str]:
    index = correlate_module.index_flows(flows)
    return {flow.uid for flow in correlate_module._candidates(detection, index)}


def _population() -> dict[str, Flow]:
    """Flows spanning every case the two implementations could disagree on.

    Deliberately includes the awkward ones: both orientations of one conversation, a symmetric
    tuple whose two keys collide, ICMP flows whose responder column holds a counterpart type and
    others where it holds a code, and IPv6 alongside IPv4.
    """
    flows = [
        make_flow(uid="C01"),
        make_flow(uid="C02", src_ip=SERVER, src_port=80, dst_ip=CLIENT, dst_port=51234),
        make_flow(uid="C03", src_port=51235),
        make_flow(uid="C04", proto="udp", src_port=53, dst_port=53),
        make_flow(uid="C05", proto="udp", src_ip=CLIENT, src_port=9, dst_ip=CLIENT, dst_port=9),
        make_flow(uid="C06", proto="icmp", src_port=8, dst_port=0),
        make_flow(uid="C07", proto="icmp", src_port=0, dst_port=8),
        make_flow(uid="C08", proto="icmp", src_port=3, dst_port=1),
        make_flow(uid="C09", proto="icmp", src_port=3, dst_port=4),
        make_flow(
            uid="C10",
            proto="icmp",
            src_ip="fd00::a1",
            dst_ip="fd00::b2",
            src_port=135,
            dst_port=136,
        ),
        make_flow(
            uid="C11", proto="icmp", src_ip="fd00::a1", dst_ip="fd00::b2", src_port=1, dst_port=7
        ),
        make_flow(uid="C12", proto="tcp", src_ip="fd00::a1", dst_ip="fd00::b2", dst_port=443),
    ]
    return by_uid(*flows)


@pytest.mark.parametrize(
    "detection",
    [
        pytest.param(make_detection(), id="forward"),
        pytest.param(
            make_detection(src_ip=SERVER, src_port=80, dst_ip=CLIENT, dst_port=51234), id="reverse"
        ),
        pytest.param(make_detection(src_port=51235), id="other-port"),
        pytest.param(make_detection(dst_port=8080), id="no-match"),
        pytest.param(make_detection(proto="udp", src_port=53, dst_port=53), id="udp"),
        pytest.param(
            make_detection(proto="udp", src_ip=CLIENT, src_port=9, dst_ip=CLIENT, dst_port=9),
            id="symmetric-tuple",
        ),
        pytest.param(make_detection(proto="icmp", src_port=8, dst_port=0), id="icmp-echo-request"),
        pytest.param(make_detection(proto="icmp", src_port=0, dst_port=0), id="icmp-echo-reply"),
        pytest.param(make_detection(proto="icmp", src_port=3, dst_port=1), id="icmp-code"),
        pytest.param(
            make_detection(
                proto="icmp", src_ip="fd00::a1", dst_ip="fd00::b2", src_port=135, dst_port=0
            ),
            id="icmpv6-neighbour-solicit",
        ),
        pytest.param(
            make_detection(
                proto="icmp", src_ip="fd00::a1", dst_ip="fd00::b2", src_port=1, dst_port=7
            ),
            id="icmpv6-unpaired",
        ),
        pytest.param(
            make_detection(proto="tcp", src_ip="fd00::a1", dst_ip="fd00::b2", dst_port=443),
            id="ipv6-tcp",
        ),
        pytest.param(make_detection(proto="icmp", src_port=200, dst_port=7), id="icmp-no-table"),
    ],
)
def test_the_index_agrees_with_the_predicate_it_replaced(detection):
    """The index must select exactly the flows the scan did — no more, and no fewer.

    Selecting *more* is the dangerous direction: a detection with two candidates where it used
    to have one stops being matched at all and becomes `ambiguous_flow_match`, so a speedup
    would silently start losing labels.
    """
    flows = _population()

    assert _indexed(detection, flows) == _brute_force(detection, flows)


def test_a_flow_whose_orientations_collide_is_not_a_double_candidate():
    """Same address and port on both sides: one flow, indexed twice, still one candidate.

    Without de-duplication it would arrive as two, and two candidates go to the clock — turning
    a flow that matches exactly into a possible `ambiguous_flow_match`.
    """
    flow = make_flow(proto="udp", src_ip=CLIENT, src_port=9, dst_ip=CLIENT, dst_port=9)
    detection = make_detection(proto="udp", src_ip=CLIENT, src_port=9, dst_ip=CLIENT, dst_port=9)

    index = correlate_module.index_flows(by_uid(flow))

    assert [candidate.uid for candidate in correlate_module._candidates(detection, index)] == [
        "CFlow00000000000001"
    ]


def test_correlation_stays_fast_at_capture_scale():
    """The regression #56 fixed, pinned so it cannot come back unnoticed.

    50,000 flows and 5,000 detections is well inside what `docs/prd.md` anticipates. Under the
    old scan that is 2.5x10^8 tuple comparisons — tens of seconds at best. Indexed, it is
    5,000 dict lookups.

    The assertion is deliberately loose: it is a guard against reintroducing an O(n*m) scan, not
    a benchmark, and a tight bound would be flaky on shared CI. A quadratic implementation misses
    it by orders of magnitude, which is the only distinction that matters here.
    """
    flows = by_uid(
        *(
            make_flow(
                uid=f"CBulk{index:014d}", src_port=1024 + index % 60000, ts_last=1_700_000_010.0
            )
            for index in range(50_000)
        )
    )
    detections = [make_detection(sid=index, src_port=1024 + index) for index in range(5_000)]

    started = time.perf_counter()
    result = correlate(detections, flows, make_manifest(), threshold=NO_GATE)
    elapsed = time.perf_counter() - started

    assert result.detections_total == 5_000
    assert elapsed < 5.0, (
        f"correlation took {elapsed:.1f}s — the O(detections x flows) scan is back"
    )


# --- protocols Zeek cannot express (issue #84, PLAN step 12) --------------------------------
#
# Zeek's `transport_proto` holds only tcp/udp/icmp/unknown_transport, and it zeroes the port
# columns for anything else, while Suricata reports the real protocol and — for SCTP — the real
# ports. Before step 12 this made every such detection uncorrelatable, and the 1% gate then
# failed the whole run on a capture that was otherwise perfectly labellable.
#
# Craig's decision (2026-08-13, issue #84): report it, never correlate it. The alternative,
# matching on the address pair alone, is refused by `test_two_such_flows_are_indistinguishable`
# below.

UNSUPPORTED = "unsupported_transport"


def esp_detection(**overrides) -> Detection:
    """An alert Suricata reported on IP protocol 50, which carries no ports at any layer."""
    fields = {"proto": "esp", "src_port": 0, "dst_port": 0, "dst_ip": SERVER}
    return make_detection(**{**fields, **overrides})


def unknown_transport_flow(**overrides) -> Flow:
    """A flow as Zeek writes it for anything that is not TCP, UDP or ICMP: no protocol, no ports."""
    fields = {
        "uid": "CUnknown000000000001",
        "src_port": 0,
        "dst_port": 0,
        "proto": "unknown_transport",
        "dst_ip": SERVER,
    }
    return make_flow(**{**fields, **overrides})


def test_a_detection_on_an_unsupported_transport_is_never_attached_to_a_flow():
    """Even though a flow between exactly these two addresses exists and is the right one.

    That is the whole decision: `unknown_transport` is not a protocol, it is Zeek saying it has
    no name for one. Attaching to it would assert a correlation the data cannot support.
    """
    flow = unknown_transport_flow()

    result = correlate([esp_detection()], by_uid(flow), make_manifest(), threshold=NO_GATE)

    assert result.labels == ()
    assert len(result.unmatched) == 1
    assert result.unmatched[0].reason == UNSUPPORTED
    assert result.unmatched[0].detection.proto == "esp"


def test_two_such_flows_are_indistinguishable_which_is_why_the_address_pair_was_refused():
    """Measured on Zeek 8.0.4: ESP and SCTP between one host pair give two flows, one tuple.

    `tests/fixtures/make_awkward.py::write_two_unsupported_transports_pcap` produces exactly
    this, and Zeek writes both as `10.0.0.5 0 10.0.0.200 0 unknown_transport` with different
    uids. So matching on the address pair would attach an ESP alert to the SCTP flow, and no
    check `Flow` can currently make would notice — the tuples are equal. This test pins the
    refusal, not the ambiguity: the answer is `unsupported_transport`, not
    `ambiguous_flow_match`.

    Zeek does record `ip_proto` (50 and 132) and `Flow` does not carry it, so this is flabel's
    limit rather than the data's — issue #96, and `test_canaries.py` asserts the column exists
    so nobody has to take that on trust.
    """
    flows = by_uid(
        unknown_transport_flow(uid="CJKFoj4bpHEhTeaRoj"),
        unknown_transport_flow(uid="CRdT6w4PA64qWKmBk3"),
    )

    result = correlate([esp_detection()], flows, make_manifest(), threshold=NO_GATE)

    assert [record.reason for record in result.unmatched] == [UNSUPPORTED]


def test_sctp_disagrees_on_the_ports_too_and_is_still_reported_the_same_way():
    """Suricata reads SCTP's real ports; Zeek writes `0 0`. Two fields out, one answer."""
    detection = esp_detection(proto="sctp", src_port=40000, dst_port=80)

    result = correlate([detection], by_uid(unknown_transport_flow()), make_manifest(), NO_GATE)

    assert [record.reason for record in result.unmatched] == [UNSUPPORTED]


def test_an_unsupported_transport_with_no_flow_at_all_still_names_the_protocol():
    """`no_flow_match` would be true but useless: the protocol is the cause, not the tuple."""
    result = correlate([esp_detection()], {}, make_manifest(), threshold=NO_GATE)

    assert [record.reason for record in result.unmatched] == [UNSUPPORTED]


def test_unsupported_transports_alone_do_not_fire_the_gate():
    """A capture that is entirely ESP is a successful run with no labels, not a failed one.

    At the default 1% threshold, ten unmatched detections out of ten would fail every time if
    they counted. They are excluded from the denominator, so the ratio is 0.0 and the run lives.
    """
    detections = [esp_detection(sid=index) for index in range(10)]

    result = correlate(detections, by_uid(unknown_transport_flow()), make_manifest())

    assert result.unmatched_ratio == 0.0
    assert len(result.unmatched) == 10


def test_the_gate_still_fires_on_a_real_tuple_failure_beside_unsupported_transports():
    """The test that stops this fix from becoming a way to switch the gate off.

    100 correlatable detections with 2 unplaced is 2% — above the 1% default. Adding 200 ESP
    detections would drag that to 0.67% and silence the gate if they counted in the denominator,
    which is exactly the regression to guard: a genuine tuple-normalisation defect hidden behind
    a pile of traffic correlation was never going to place anyway.
    """
    detections = many_detections(100, unmatched=2)
    detections += [esp_detection(sid=1000 + index) for index in range(200)]

    with pytest.raises(CorrelationError) as raised:
        correlate(detections, by_uid(make_flow(), unknown_transport_flow()), make_manifest())

    result = raised.value.result
    assert result.unmatched_ratio == pytest.approx(0.02)
    assert exit_code_for(raised.value) == 1


def test_the_count_holds_every_unmatched_while_the_ratio_holds_only_the_correlatable():
    """Asserted together, because the risk is that they quietly become the same number.

    `counts.unmatched` is the scale of the loss and must not hide anything; `unmatched_ratio`
    is the number the gate acted on. One run, both read.
    """
    detections = many_detections(10, unmatched=1)
    detections += [esp_detection(sid=2000 + index) for index in range(20)]

    result = correlate(
        detections, by_uid(make_flow(), unknown_transport_flow()), make_manifest(), NO_GATE
    )

    assert len(result.unmatched) == 21, "every unmatched detection is reported"
    assert result.unmatched_ratio == pytest.approx(0.1), "1 of 10 correlatable, not 21 of 30"
    assert result.detections_total == 30


def test_an_unnormalised_protocol_name_is_a_step_6_regression_not_an_unsupported_transport():
    """The protocol check casefolds; the tuple comparison does not. Both halves matter.

    Written after the first implementation of #84 got this wrong. Matching the correlatable set
    exactly would classify `TCP` as `unsupported_transport` — and because unsupported
    transports are excluded from the gate's denominator, a step-6 regression that stopped
    lowercasing would empty the denominator entirely and silence the gate on every run. The
    gate would report 0.00% while nothing correlated at all.

    So an un-normalised name stays correlatable, fails the exact tuple compare, and is reported
    as `no_flow_match` — inside the gate, where it can fail the run.
    """
    detections = [make_detection(sid=index, proto="TCP") for index in range(10)]

    with pytest.raises(CorrelationError) as raised:
        correlate(detections, by_uid(make_flow()), make_manifest())

    result = raised.value.result
    assert [record.reason for record in result.unmatched] == ["no_flow_match"] * 10
    assert result.correlatable_total == 10, "an unknown spelling must not leave the denominator"
    assert result.unmatched_ratio == 1.0
