"""The shared vocabulary in `models.py` (spec §4).

Every module codes against these dataclasses rather than owning its own, which is what lets
steps 3-8 be built in parallel. Two properties carry real weight and are tested exhaustively
over the class list rather than by example:

* `may_label` is what stops an `identify`-class source ever producing a label (spec §2.8).
* `label_basis` is what distinguishes "this flow is malicious" from "this flow referenced
  something on a blocklist", which is the honesty of the whole output.
"""

from __future__ import annotations

import dataclasses
import inspect
import pathlib
from typing import get_args

import pytest

from flabel import models
from flabel.models import (
    CorrelationResult,
    Detection,
    Flow,
    Ja4Status,
    Label,
    LabelEntry,
    LabelName,
    NormalizedCapture,
    SnapshotManifest,
    SourceAdmission,
    SourceClass,
    SourceEntry,
    SourceSpec,
    SuricataRunInfo,
    UnmatchedDetection,
    ZeekRunInfo,
    verdict_entry,
)

#: Derived from the type, not restated. A hardcoded list would keep passing while silently
#: testing 4 of 5 classes the day someone adds one.
SOURCE_CLASSES = get_args(SourceClass)


def make_spec(**overrides) -> SourceSpec:
    fields = {
        "name": "example/source",
        "url": "https://example.invalid/rules.tar.gz",
        "licence": "MIT",
        "source_class": "signature",
        "admission_basis": "wholesale",
    }
    return SourceSpec(**{**fields, **overrides})


@pytest.mark.parametrize("source_class", SOURCE_CLASSES)
def test_may_label_is_false_exactly_for_identify(source_class):
    """Exhaustive over the class list, so adding a class forces a decision here."""
    assert make_spec(source_class=source_class).may_label is (source_class != "identify")


@pytest.mark.parametrize(
    ("source_class", "expected"),
    [
        ("signature", "direct"),
        ("ioc-dest", "direct"),
        ("ioc-name", "indicator-reference"),
        ("identify", None),
    ],
)
def test_label_basis_is_indicator_reference_exactly_for_ioc_name(source_class, expected):
    """`ioc-name` matches a looked-up name, so the flow only *referenced* the indicator."""
    assert make_spec(source_class=source_class).label_basis == expected


def test_label_basis_is_none_exactly_when_the_source_may_not_label():
    for source_class in SOURCE_CLASSES:
        spec = make_spec(source_class=source_class)
        assert (spec.label_basis is None) is (not spec.may_label)


def test_sources_are_enabled_by_default():
    assert make_spec().enabled is True


def all_models() -> list[type]:
    """Every dataclass in `models.py`, discovered rather than listed.

    Discovery matters: a hardcoded list would let a model added in a later step skip the
    frozen check entirely, and an unfrozen model means provenance editable after the fact.
    """
    return [
        obj
        for _, obj in inspect.getmembers(models, inspect.isclass)
        if dataclasses.is_dataclass(obj) and obj.__module__ == models.__name__
    ]


def test_every_model_is_discovered():
    """Guards the guard: if discovery silently returned nothing, the sweep below is vacuous."""
    assert len(all_models()) >= 12


@pytest.mark.parametrize("model", all_models(), ids=lambda m: m.__name__)
def test_every_model_is_a_frozen_dataclass(model):
    """Frozen, because a label's provenance must not be editable after the fact."""
    assert model.__dataclass_params__.frozen, f"{model.__name__} is mutable"


def test_a_frozen_model_rejects_assignment():
    with pytest.raises(dataclasses.FrozenInstanceError):
        make_spec().name = "something/else"  # type: ignore[misc]


def make_flow(**overrides) -> Flow:
    fields = {
        "uid": "CHhAvVGS1DHFjwGM9",
        "src_ip": "10.0.0.1",
        "src_port": 44001,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "proto": "tcp",
        "ts_first": 1.0,
        "ts_last": 2.0,
    }
    return Flow(**{**fields, **overrides})


def test_flow_tls_fields_default_to_none():
    """A flow with no TLS handshake has no JA4, and absence must not read as a value."""
    flow = make_flow()
    assert (flow.ja4, flow.ja4s, flow.server_name) == (None, None, None)


def test_a_label_carries_its_asserting_sources_as_a_tuple():
    sources = (make_entry(),)
    label = Label(flow=make_flow(), best_tier=2, labels=(verdict_entry(sources),), sources=sources)

    assert [entry.name for entry in label.labels] == ["verdict"]
    assert label.labels[0].value == "malicious"
    assert isinstance(label.sources, tuple)


def make_entry(**overrides) -> SourceEntry:
    fields = {
        "tier": 2,
        "source": "et/open",
        "sid": 2000001,
        "rev": 3,
        "ruleset": "0123456789abcdef",
        "admission_basis": "metadata-filter",
        "licence": "MIT",
        "classtype": "trojan-activity",
        "label_basis": "direct",
        "direction": "to_server",
        "threat": "ET MALWARE Example",
    }
    return SourceEntry(**{**fields, **overrides})


def test_a_verdict_other_than_malicious_is_rejected():
    """Spec §13's first never-do. `Literal` alone does not enforce this at runtime.

    Checked on the `verdict` ENTRY since schema 2.0 (#138) — the guard moved with the field, and a
    forged entry is now the way a non-malicious verdict would arrive.
    """
    forged = LabelEntry(name="verdict", value="benign", tier=2, sids=(make_entry().sid,))
    with pytest.raises(ValueError, match="verdict"):
        Label(flow=make_flow(), best_tier=2, labels=(forged,), sources=(make_entry(),))


def test_a_label_with_no_asserting_source_is_rejected():
    """A label nothing asserted has no provenance, which is the one thing labels must have."""
    with pytest.raises(ValueError, match="sources"):
        # No sources, so no verdict entry can be derived either — the guard under test is the
        # empty `sources`, and an empty `labels` would otherwise trip the verdict check first.
        Label(flow=make_flow(), best_tier=2, labels=(), sources=())


def test_best_tier_must_agree_with_its_sources():
    """Two fields that can disagree is a defect in an artifact whose value is provenance."""
    with pytest.raises(ValueError, match="best_tier"):
        sources = (make_entry(tier=2),)
        Label(flow=make_flow(), best_tier=1, labels=(verdict_entry(sources),), sources=sources)


def test_best_tier_is_the_minimum_not_the_maximum():
    """Lower tier is higher trust, so the best of two sources is the smaller number."""
    sources = (make_entry(tier=2), make_entry(tier=1, source="panw/ngfw"))
    label = Label(
        flow=make_flow(),
        best_tier=1,
        labels=(verdict_entry(sources),),
        sources=sources,
    )
    assert label.best_tier == 1


@pytest.mark.parametrize(
    ("model", "kwargs", "bad_field"),
    [
        (SourceSpec, {"source_class": "wishful"}, "source_class"),
        (SourceSpec, {"admission_basis": "vibes"}, "admission_basis"),
        (SourceEntry, {"label_basis": "hunch"}, "label_basis"),
        (SourceEntry, {"direction": "sideways"}, "direction"),
        # `Detection` too, because it reaches `labels.json` directly inside
        # `unmatched_detections[]` — the same publication path `SourceEntry` is guarded on.
        (Detection, {"direction": "sideways"}, "direction"),
        (UnmatchedDetection, {"reason": "dunno"}, "reason"),
    ],
)
def test_enum_fields_reject_undocumented_values(model, kwargs, bad_field):
    """Every Literal that reaches output is enforced, not merely annotated."""
    builders = {
        SourceSpec: make_spec,
        SourceEntry: make_entry,
        Detection: make_detection,
        UnmatchedDetection: lambda **kw: UnmatchedDetection(
            detection=make_detection(), **{"reason": "no_flow_match", **kw}
        ),
    }
    with pytest.raises(ValueError, match=bad_field):
        builders[model](**kwargs)


def test_correlation_result_reports_zero_loss_when_there_were_no_detections():
    """Nothing to place is not the same as failing to place things."""
    result = CorrelationResult(labels=(), unmatched=(), flows_total=2, detections_total=0)
    assert result.unmatched_ratio == 0.0


def test_correlation_result_ratio_is_correlatable_unmatched_over_correlatable():
    result = CorrelationResult(
        labels=(),
        unmatched=(UnmatchedDetection(detection=make_detection(), reason="no_flow_match"),),
        flows_total=10,
        detections_total=4,
    )
    assert result.unmatched_ratio == 0.25


def test_a_complete_capture_has_no_truncation_offset():
    capture = NormalizedCapture(
        path=pathlib.Path("/tmp/run/normalized.pcap"),
        original_path=pathlib.Path("/in/capture.pcapng"),
        sha256="0" * 64,
        capture_format="pcapng",
        bytes_total=4096,
        input_status="complete",
        packets_read=14,
        link_type=1,
        snaplen=65535,
    )
    assert capture.truncated_at_offset is None
    assert capture.discarded_link_types == ()
    assert capture.normalization == ()


def test_an_unknown_capture_format_is_rejected():
    with pytest.raises(ValueError, match="capture_format"):
        NormalizedCapture(
            path=pathlib.Path("/tmp/x.pcap"),
            original_path=pathlib.Path("/in/x.snoop"),
            sha256="0" * 64,
            capture_format="snoop",
            bytes_total=1,
            input_status="complete",
            packets_read=0,
            link_type=1,
            snaplen=65535,
        )


def make_detection(**overrides) -> Detection:
    fields = {
        "source": "et/open",
        "tier": 2,
        "sid": 2000001,
        "rev": 3,
        "classtype": "trojan-activity",
        "app_proto": "tls",
        "threat": "ET MALWARE Example",
        "ts": 1.5,
        "src_ip": "10.0.0.1",
        "src_port": 44001,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "proto": "tcp",
        "direction": "to_server",
    }
    return Detection(**{**fields, **overrides})


def test_detection_metadata_defaults_to_empty():
    """Spec §8 parses `alert.metadata`; absent metadata is empty, not missing."""
    assert make_detection().metadata == ()


def test_unmatched_detection_records_why_it_could_not_be_placed():
    unmatched = UnmatchedDetection(detection=make_detection(), reason="no_flow_match")

    assert unmatched.reason == "no_flow_match"
    assert unmatched.detection.sid == 2000001


# --- the stage run infos --------------------------------------------------------------------


def test_ja4_status_is_a_status_and_ja4_package_version_is_a_version():
    """Two fields because they answer two questions, and one used to answer both.

    `zeek.py` stored `absent:not-installed` in `ja4_package_version` while `models.py` was
    shared by three parallel steps. Anything printing that field printed nonsense, so the status
    now has its own typed field and the version field holds a version or nothing.
    """
    info = ZeekRunInfo(
        version="8.0.4",
        flags=("-C", "-D"),
        log_dir=pathlib.Path("/run/zeek"),
        ja4_status="not-installed",
    )

    assert info.ja4_status == "not-installed"
    assert info.ja4_package_version is None
    assert info.warnings == ()


@pytest.mark.parametrize("status", get_args(Ja4Status))
def test_every_ja4_status_is_accepted(status):
    """Three values, and all three reachable: `probe-failed` is a defect worth distinguishing."""
    info = ZeekRunInfo(
        version="8.0.4", flags=("-D",), log_dir=pathlib.Path("/run/zeek"), ja4_status=status
    )
    assert info.ja4_status == status


def test_an_unknown_ja4_status_is_rejected():
    """A Literal that reaches the run block is enforced, like every other one here."""
    with pytest.raises(ValueError, match="ja4_status"):
        ZeekRunInfo(
            version="8.0.4",
            flags=("-D",),
            log_dir=pathlib.Path("/run/zeek"),
            ja4_status="maybe",
        )


def test_no_ja4_status_at_all_is_allowed():
    """None means nothing probed it — distinct from `probe-failed`, which means something did."""
    info = ZeekRunInfo(version="8.0.4", flags=("-D",), log_dir=pathlib.Path("/run/zeek"))
    assert info.ja4_status is None


def test_the_suricata_run_info_counts_rules_the_engine_rejected():
    """A rule that never loaded never examined the capture, so the number is not optional.

    Defaulting to zero rather than None on purpose: these come off one line of Suricata's own
    output alongside the loaded count, so a run that has a loaded count has all three.
    """
    info = SuricataRunInfo(
        version="8.0.6",
        snapshot_id="deadbeef",
        rules_loaded=85_542,
        alerts_total=0,
        rules_failed=3,
        rules_skipped=1,
        config_sha256="0" * 64,
        warnings=("coverage unverified",),
    )

    assert (info.rules_failed, info.rules_skipped) == (3, 1)
    assert info.config_sha256 == "0" * 64
    assert info.warnings == ("coverage unverified",)
    assert info.tool_failures == ()


def test_the_suricata_run_info_defaults_the_new_fields():
    """Every field added for the run block has a default, so no existing call site breaks.

    `rules_failed` and `rules_skipped` default to **zero** and `identify_alerts_suppressed` to
    **None**, and the asymmetry is the point (issue #86 review). The first two come off the same
    line of Suricata's output as the loaded count, so a run that has a loaded count has all three
    — zero is a measurement. The third is taken by the eve pass and is independent of it, so zero
    would be an *assertion* that nothing was suppressed by a caller that never looked.
    """
    info = SuricataRunInfo(version="8.0.6", snapshot_id="x", rules_loaded=1, alerts_total=0)

    assert (info.rules_failed, info.rules_skipped) == (0, 0)
    assert info.identify_alerts_suppressed is None, (
        "a suppression count nobody took must not read as zero suppressions"
    )
    assert info.config_sha256 is None
    assert info.warnings == ()


# --- the snapshot manifest names each source exactly once ----------------------------------
#
# Issue #49. The duplicate is rejected on the type rather than by whichever reader notices,
# because the failure is silent: every consumer resolves a source by name, and a name appearing
# twice with different terms means `licence`, `admission_basis` and `label_basis` on every label
# from that source describe whichever entry the lookup happened to keep. Both entries are
# well-formed, so nothing downstream can detect it.


def make_admission(**overrides) -> SourceAdmission:
    fields = {
        "name": "et/open",
        "url": "https://example.invalid/emerging.rules.tar.gz",
        "licence": "MIT",
        "source_class": "signature",
        "admission_basis": "metadata-filter",
        "rules_fetched": 10,
        "rules_admitted": 10,
        "rules_excluded_no_confidence": 0,
        "rules_excluded_low_confidence": 0,
        "rules_excluded_low_severity": 0,
        "rules_excluded_commented": 0,
        "ja4_rules_admitted": 0,
        "ja3_rules_admitted": 0,
        "fetched_at": "2026-08-12T00:00:00.000000Z",
    }
    return SourceAdmission(**{**fields, **overrides})


def make_manifest(*admissions: SourceAdmission) -> SnapshotManifest:
    sources = admissions or (make_admission(),)
    return SnapshotManifest(
        snapshot_id="8a39182c18a3c9d3",
        created_at="2026-08-12T00:00:00.000000Z",
        flabel_version="0.1.0",
        sources=sources,
        total_admitted=sum(a.rules_admitted for a in sources),
        total_ja4_admitted=0,
    )


def test_a_manifest_naming_one_source_twice_is_refused():
    """The wrong-terms defect, caught where it starts instead of where it shows up.

    Two entries for `et/open` with different classes would give every label from it whichever
    `label_basis` the lookup kept — `direct` or `indicator-reference`, the difference between
    "this flow is the attack" and "this flow referenced an indicator".
    """
    with pytest.raises(ValueError, match="once"):
        make_manifest(
            make_admission(name="et/open", source_class="signature"),
            make_admission(name="et/open", source_class="ioc-name"),
        )


def test_a_manifest_naming_one_source_twice_is_refused_even_when_identical():
    """Identical duplicates are still refused.

    Not because they would resolve wrongly today, but because `total_admitted` and the
    per-source counts double-count them, and a reader cannot tell an intentional repeat from a
    writer bug. There is no case where the same source belongs in a snapshot twice.
    """
    with pytest.raises(ValueError, match="once"):
        make_manifest(make_admission(), make_admission())


def test_distinct_source_names_are_accepted():
    """The ordinary case: nine sources, nine names."""
    manifest = make_manifest(
        make_admission(name="et/open"),
        make_admission(name="abuse.ch/urlhaus", source_class="ioc-name"),
    )
    assert len(manifest.sources) == 2


def test_sources_by_name_indexes_every_source():
    """The lookup every consumer needs, defined once (issue #49).

    `suricata.py` resolves a SID's originating source through it and correlation resolves a
    detection's terms through it. Written separately in each, they are two places that can
    disagree about the same tuple — the argument that pre-placed `build_source_entry`.
    """
    urlhaus = make_admission(name="abuse.ch/urlhaus", source_class="ioc-name")
    manifest = make_manifest(make_admission(name="et/open"), urlhaus)

    assert set(manifest.sources_by_name) == {"et/open", "abuse.ch/urlhaus"}
    assert manifest.sources_by_name["abuse.ch/urlhaus"] is urlhaus


def test_sources_by_name_cannot_silently_drop_an_entry():
    """The index is total, because uniqueness is enforced at construction.

    A dict comprehension over a tuple that may repeat a key is exactly how the defect in #49
    stayed invisible: the lookup keeps the last and reports nothing.
    """
    manifest = make_manifest(
        make_admission(name="et/open"),
        make_admission(name="pawpatrules", source_class="signature"),
        make_admission(name="oisf/trafficid", source_class="identify"),
    )
    assert len(manifest.sources_by_name) == len(manifest.sources)


def test_the_ratio_excludes_unsupported_transports_from_both_sides():
    """Renamed from `..._is_unmatched_over_detections`, which stopped being true in step 12.

    The old name was the formula a future reader would have "fixed" the code to match. Three of
    four detections here are unsupported and one ordinary detection went unplaced: the ratio is
    1/1, not 4/4 and not 1/4.
    """
    detection = make_detection()
    result = CorrelationResult(
        labels=(),
        unmatched=(
            UnmatchedDetection(detection=detection, reason="no_flow_match"),
            *(
                UnmatchedDetection(detection=detection, reason="unsupported_transport")
                for _ in range(3)
            ),
        ),
        flows_total=1,
        detections_total=4,
    )

    assert result.unsupported_transport_total == 3
    assert result.correlatable_total == 1
    assert result.unmatched_ratio == 1.0


def test_a_correlation_result_cannot_claim_fewer_detections_than_it_carries():
    """The negative-ratio case: `correlatable_total` of -1 passes any threshold (#84 review).

    Every unmatched detection is a detection, so `detections_total` can never be smaller than
    `len(unmatched)`. Without this the model publishes a negative percentage that is below the
    gate by arithmetic rather than by measurement.
    """
    detection = make_detection()
    with pytest.raises(ValueError, match="every unmatched detection is a detection"):
        CorrelationResult(
            labels=(),
            unmatched=(
                UnmatchedDetection(detection=detection, reason="unsupported_transport"),
                UnmatchedDetection(detection=detection, reason="no_flow_match"),
            ),
            flows_total=1,
            detections_total=0,
        )


# --- the guards on a multi-label Label (#138, schema 2.0) --------------------------------------
#
# Each of these is a guard that shipped unexercised in the first draft of #138: the sabotage round
# removed the check and the suite stayed green. Written afterwards, which is the wrong order and is
# recorded here so the next reader knows the tests came from breaking the code rather than from
# reading it.


def one_source() -> tuple[SourceEntry, ...]:
    return (make_entry(),)


def one_tier_1_source() -> tuple[SourceEntry, ...]:
    """A tier-1 source, for the tests that need a legitimate `threat-name`.

    `threat-name` permits only tier 1 (`LABEL_KINDS`), so a test using it as scaffolding needs a
    tier-1 source or the entry cannot be built at all. Four tests below used a tier-2 one and got
    away with it while nothing enforced the kind's tiers — and one of them would then have raised
    on the tier rather than on the thing it was testing.
    """
    return (make_entry(tier=1, source="panw/device", sid=30001),)


def test_a_label_with_no_verdict_is_rejected():
    """A `Label` exists because something was asserted, and `verdict` is that assertion.

    Without it the object is a flow plus provenance and no claim — which would serialise as a
    label, and a consumer counting labels would count it.
    """
    sources = one_source()
    threat = LabelEntry(name="threat-name", value="Some Threat", tier=1, sids=(30001,))
    with pytest.raises(ValueError, match="verdict"):
        Label(flow=make_flow(), best_tier=2, labels=(threat,), sources=sources)


def test_two_verdicts_on_one_flow_are_rejected():
    """Asserting twice is not asserting harder; it is a document that cannot be read."""
    sources = one_source()
    verdict = verdict_entry(sources)
    with pytest.raises(ValueError, match="verdict"):
        Label(flow=make_flow(), best_tier=2, labels=(verdict, verdict), sources=sources)


def test_a_repeated_label_name_is_rejected():
    """Craig's decision 2: one `threat-name` per flow, chosen by precedence.

    Two entries of one name would mean the choice was never made, and a consumer would have to
    invent a tiebreak the producer declined to.
    """
    sources = one_tier_1_source()
    first = LabelEntry(name="threat-name", value="A", tier=1, sids=(sources[0].sid,))
    second = LabelEntry(name="threat-name", value="B", tier=1, sids=(sources[0].sid,))
    with pytest.raises(ValueError, match="repeated"):
        Label(
            flow=make_flow(),
            best_tier=1,
            labels=tuple(sorted((verdict_entry(sources), first, second), key=lambda e: e.name)),
            sources=sources,
        )


def test_the_verdict_entrys_tier_must_agree_with_best_tier():
    """One flow's trust level, recorded twice. The repo's rule is to enforce, not deduplicate.

    `best_tier` is kept at the top level because the PRD and spec name it and consumers read it;
    that makes it a second record of the verdict entry's tier, and two records that can disagree
    is the flaw this artifact exists to avoid.
    """
    sources = one_source()
    wrong = LabelEntry(name="verdict", value="malicious", tier=1, sids=(sources[0].sid,))
    with pytest.raises(ValueError, match="best_tier"):
        Label(flow=make_flow(), best_tier=2, labels=(wrong,), sources=sources)


def test_label_entries_out_of_name_order_are_rejected():
    """Canonical output: the same data serialises the same way however it was assembled (§10)."""
    sources = one_tier_1_source()
    threat = LabelEntry(name="threat-name", value="Some Threat", tier=1, sids=(sources[0].sid,))
    with pytest.raises(ValueError, match="sorted"):
        Label(
            flow=make_flow(),
            best_tier=1,
            labels=(verdict_entry(sources), threat),  # "verdict" > "threat-name"
            sources=sources,
        )


def test_a_label_entry_asserting_an_empty_value_is_rejected():
    """An empty string serialises as a value, so it would publish a label that claims nothing."""
    with pytest.raises(ValueError, match="empty"):
        LabelEntry(name="threat-name", value="", tier=1, sids=(30001,))


def test_a_label_entry_with_no_signature_behind_it_is_rejected():
    """Goal 1: an assertion that cannot be traced to what produced it must not ship."""
    with pytest.raises(ValueError, match="sids"):
        LabelEntry(name="threat-name", value="Some Threat", tier=1, sids=())


def test_label_entry_sids_must_be_sorted():
    """This tuple reaches the file directly, so its order is part of the canonical form."""
    with pytest.raises(ValueError, match="sorted"):
        LabelEntry(name="verdict", value="malicious", tier=2, sids=(200, 100))


def test_an_unknown_label_name_is_rejected():
    """`Literal` is a hint. A name no consumer is written against would serialise happily."""
    with pytest.raises(ValueError, match="name"):
        LabelEntry(name="severity", value="high", tier=1, sids=(30001,))


def test_label_kinds_and_the_label_name_literal_describe_the_same_set():
    """The two-copies guard for #145.

    `LABEL_KINDS` carries arity and permitted tiers; `LabelName` carries static typing, which a
    `Mapping` cannot provide. So both exist, and this is what stops them drifting — the hazard
    spec-label-store §6.2 invokes to justify the table in the first place. Without it, adding a
    kind to one and not the other leaves `blfile` and `LabelEntry` disagreeing about what a
    label is, with nothing red.
    """
    assert tuple(get_args(LabelName)) == tuple(models.LABEL_KINDS)


def test_a_label_kind_permitting_no_tier_is_rejected():
    """Found by sabotage: this guard shipped with no test, because nothing builds a bad kind.

    Only reachable by editing `LABEL_KINDS`, which is exactly when it matters — a kind no tier may
    assert makes every entry of that kind unconstructible, and the error would surface as a
    confusing per-entry failure rather than as the table being wrong.
    """
    with pytest.raises(ValueError, match="tiers is empty"):
        models.LabelKind(arity="single", tiers=())


def test_a_label_kind_with_an_unknown_arity_is_rejected():
    """The same reason `_check` exists at all: `Literal` is a hint, not a runtime constraint."""
    with pytest.raises(ValueError, match="arity"):
        models.LabelKind(arity="several", tiers=(1,))


def test_the_label_kinds_table_is_well_formed():
    """A table validator, not a spot check.

    `LabelKind.__post_init__` fires while someone is editing this file, which is the right time —
    but only for the cases it knows about. This asserts the shipped table against
    `models.KNOWN_TIERS` rather than a literal, so adding a tier is one edit and this test follows.
    """
    for name, kind in models.LABEL_KINDS.items():
        assert isinstance(kind.tiers, tuple), f"{name}: tiers must be a tuple"
        assert kind.tiers, f"{name} permits no tier"
        assert set(kind.tiers) <= set(models.KNOWN_TIERS), (
            f"{name} permits a tier that cannot exist"
        )
        assert list(kind.tiers) == sorted(set(kind.tiers)), (
            f"{name}: tiers not ascending and unique"
        )
        assert kind.arity in get_args(models.LabelArity)


def test_the_label_kinds_table_cannot_be_mutated_at_runtime():
    """It is the label vocabulary. Any module holding a reference could otherwise rewrite it.

    Untested until a review pointed out that the monkeypatch test below substitutes a plain dict,
    so nothing asserted the real table's immutability — a later "simplify" dropping
    `MappingProxyType` would have passed CI.
    """
    with pytest.raises(TypeError):
        models.LABEL_KINDS["verdict"] = models.LabelKind(arity="multi", tiers=(1, 2))


@pytest.mark.parametrize(
    "tiers",
    [
        pytest.param((3,), id="a-tier-that-does-not-exist"),
        pytest.param((0,), id="tier-zero"),
        pytest.param((2, 1), id="descending"),
        pytest.param((1, 1), id="duplicated"),
        pytest.param((True,), id="a-bool-that-serialises-as-true"),
        pytest.param([1], id="a-list-not-a-tuple"),
        pytest.param(1, id="a-bare-int"),
        pytest.param(("1",), id="a-string"),
    ],
)
def test_a_label_kind_with_malformed_tiers_is_rejected(tiers):
    """Found by review, and `tiers=(3,)` is the one that matters.

    It has *identical* consequences to `tiers=()` — every entry of that kind unconstructible,
    surfacing as a confusing per-entry error rather than as the table being wrong — which is the
    stated rationale for the empty-tiers guard, word for word. One raised and the other did not.

    `(True,)` follows `provenance`'s existing convention: it guards `isinstance(tier, bool)`
    because `True == 1` and the tier would serialise into `labels.json` as `true`.
    """
    with pytest.raises((ValueError, TypeError)):
        models.LabelKind(arity="single", tiers=tiers)


def test_a_label_entry_at_a_tier_its_kind_does_not_permit_is_rejected():
    """`threat-name` is tier-1 only (spec §4), and that was declared but never enforced.

    Not hypothetical: before this guard existed, four tests in this file built
    `LabelEntry(name="threat-name", tier=2)` as incidental scaffolding, and one of them —
    the unknown-sid test — would have gone on passing while raising for a different reason
    entirely. Extending `threat-name` to tier 2 stays purely additive: it is one edit to
    `LABEL_KINDS`.
    """
    with pytest.raises(ValueError, match="permits only tier"):
        LabelEntry(name="threat-name", value="Some Threat", tier=2, sids=(30001,))


def test_a_single_arity_label_entry_rejects_a_sequence_value():
    """Arity is declared per kind, so it has to be checked per kind.

    `value` is typed `str`, and a type hint is not a check — the same reason `_check` exists.
    A list reaching a single-arity kind would serialise as a JSON array in the one field the
    PRD calls the trainable value, and every consumer branches on type from then on.
    """
    with pytest.raises(ValueError, match="arity|single"):
        LabelEntry(name="verdict", value=["malicious"], tier=2, sids=(30001,))


def test_the_multi_arity_branch_works_before_any_multi_kind_exists(monkeypatch):
    """Both arities are enforced, so declaring `multi` on a kind is one edit and not a rewrite.

    Every kind is `single` today, which would leave the `multi` branch unexecuted — a declared
    value with no behaviour behind it, which is the drift `LABEL_KINDS` exists to prevent. So the
    table is patched to make one kind `multi` and both directions are checked. When MITRE lands,
    this is the test that says the guard was already working.
    """
    patched = dict(models.LABEL_KINDS)
    patched["threat-name"] = models.LabelKind(arity="multi", tiers=(1,))
    monkeypatch.setattr(models, "LABEL_KINDS", patched)

    with pytest.raises(ValueError, match="multi"):
        LabelEntry(name="threat-name", value="T1190", tier=1, sids=(30001,))

    several = LabelEntry(name="threat-name", value=("T1059", "T1190"), tier=1, sids=(30001,))
    assert several.value == ("T1059", "T1190")


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(["T1059", "T1190"], id="a-list-makes-provenance-mutable"),
        pytest.param({"T1059", "T1190"}, id="a-set-is-unordered-and-unserialisable"),
        # `("", "T1190")` and NOT `("T1190", "")`: the latter is unsorted, so the sorted guard
        # catches it first and this case would pass without the empty-item guard existing at all.
        # Found by sabotage — removing the empty-item check left the suite green.
        pytest.param(("", "T1190"), id="an-empty-item-asserts-nothing"),
        pytest.param(("T1190", "T1059"), id="unsorted-breaks-canonical-output"),
        pytest.param(("T1059", "T1059"), id="duplicated"),
    ],
)
def test_a_multi_arity_value_must_be_a_sorted_unique_tuple_of_non_empty_strings(monkeypatch, value):
    """The multi guard originally admitted every one of these.

    It checked "not a str, and all items are str", which lets a list, a set and a generator
    through. Three things that matters for: `models`' own docstring says everything here is frozen
    because *a claim that can be edited after the fact is not provenance*; a set or a generator
    fails inside `labels.py` AFTER the pipeline has succeeded, which is the late-failure class
    `serialise_bytes` exists to prevent; and `sids` seven lines below is required sorted because
    *this tuple reaches the file directly* — a multi value reaches it the same way.
    """
    patched = dict(models.LABEL_KINDS)
    patched["threat-name"] = models.LabelKind(arity="multi", tiers=(1,))
    monkeypatch.setattr(models, "LABEL_KINDS", patched)
    with pytest.raises(ValueError):
        LabelEntry(name="threat-name", value=value, tier=1, sids=(30001,))


def test_a_multi_arity_generator_value_is_rejected(monkeypatch):
    """Separately, because the old guard's own `all()` EXHAUSTED it before anything could fail.

    The entry then constructed holding a spent generator, and `dataclasses.asdict` died with
    "cannot pickle 'generator' object" — one stage after the mistake was made.
    """
    patched = dict(models.LABEL_KINDS)
    patched["threat-name"] = models.LabelKind(arity="multi", tiers=(1,))
    monkeypatch.setattr(models, "LABEL_KINDS", patched)
    with pytest.raises(ValueError):
        LabelEntry(name="threat-name", value=(x for x in ("T1190",)), tier=1, sids=(30001,))


def test_a_label_entry_citing_an_unknown_sid_is_rejected():
    """Goal 1, enforced instead of asserted (#140).

    `Label` validated the verdict entry thoroughly and the others not at all, so a `threat-name`
    naming a sid no source on the flow carries serialised looking exactly as traceable as a real
    one. `LabelEntry`'s docstring claims this is where traceability is carried for assertions
    narrower than `sources[]`; that claim needed a guard behind it.
    """
    sources = one_tier_1_source()
    invented = LabelEntry(name="threat-name", value="Ghost", tier=1, sids=(999999,))
    with pytest.raises(ValueError, match="cannot be traced"):
        Label(
            flow=make_flow(),
            best_tier=1,
            labels=tuple(sorted((verdict_entry(sources), invented), key=lambda e: e.name)),
            sources=sources,
        )


def test_a_label_entry_claiming_a_tier_none_of_its_sources_had_is_rejected():
    """A tier is a trust level. Claiming one the source was not reported at overstates the label.

    Reachable by a wiring mistake rather than by data: `_label_entries` takes the tier off the
    entry it selected, so a future edit taking it from the flow — or from `best_tier` — would
    publish tier 1 for a tier-2 detection, which is the one field a consumer weights by.
    """
    sources = one_source()
    # The source's OWN sid, so the only thing wrong is the tier. Hardcoding a sid made this hit
    # the unknown-sid guard instead and pass for the wrong reason.
    overstated = LabelEntry(name="threat-name", value="Some Threat", tier=1, sids=(sources[0].sid,))
    # The distinctive phrase, not just "tier": the kind-permits-tier guard added in #145 also
    # contains that word, and this whole change exists because a test passed on the wrong guard.
    with pytest.raises(ValueError, match="none of its own sources"):
        Label(
            flow=make_flow(),
            best_tier=2,
            labels=tuple(sorted((verdict_entry(sources), overstated), key=lambda e: e.name)),
            sources=sources,
        )


def test_a_label_entry_citing_a_real_sid_at_its_real_tier_is_accepted():
    """The complement, so the guard above cannot be over-applied to legitimate output."""
    sources = one_tier_1_source()
    entry = sources[0]
    honest = LabelEntry(name="threat-name", value="Some Threat", tier=entry.tier, sids=(entry.sid,))

    label = Label(
        flow=make_flow(),
        best_tier=entry.tier,
        labels=tuple(sorted((verdict_entry(sources), honest), key=lambda e: e.name)),
        sources=sources,
    )

    assert [e.name for e in label.labels] == ["threat-name", "verdict"]
