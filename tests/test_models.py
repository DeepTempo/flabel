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
    Label,
    NormalizedCapture,
    SourceClass,
    SourceEntry,
    SourceSpec,
    UnmatchedDetection,
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
    label = Label(flow=make_flow(), verdict="malicious", best_tier=2, sources=(make_entry(),))

    assert label.verdict == "malicious"
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
        "threat": "ET MALWARE Example",
    }
    return SourceEntry(**{**fields, **overrides})


def test_a_verdict_other_than_malicious_is_rejected():
    """Spec §13's first never-do. `Literal` alone does not enforce this at runtime."""
    with pytest.raises(ValueError, match="verdict"):
        Label(flow=make_flow(), verdict="benign", best_tier=2, sources=(make_entry(),))


def test_a_label_with_no_asserting_source_is_rejected():
    """A label nothing asserted has no provenance, which is the one thing labels must have."""
    with pytest.raises(ValueError, match="sources"):
        Label(flow=make_flow(), verdict="malicious", best_tier=2, sources=())


def test_best_tier_must_agree_with_its_sources():
    """Two fields that can disagree is a defect in an artifact whose value is provenance."""
    with pytest.raises(ValueError, match="best_tier"):
        Label(flow=make_flow(), verdict="malicious", best_tier=1, sources=(make_entry(tier=2),))


def test_best_tier_is_the_minimum_not_the_maximum():
    """Lower tier is higher trust, so the best of two sources is the smaller number."""
    label = Label(
        flow=make_flow(),
        verdict="malicious",
        best_tier=1,
        sources=(make_entry(tier=2), make_entry(tier=1, source="panw/ngfw")),
    )
    assert label.best_tier == 1


@pytest.mark.parametrize(
    ("model", "kwargs", "bad_field"),
    [
        (SourceSpec, {"source_class": "wishful"}, "source_class"),
        (SourceSpec, {"admission_basis": "vibes"}, "admission_basis"),
        (SourceEntry, {"label_basis": "hunch"}, "label_basis"),
        (UnmatchedDetection, {"reason": "dunno"}, "reason"),
    ],
)
def test_enum_fields_reject_undocumented_values(model, kwargs, bad_field):
    """Every Literal that reaches output is enforced, not merely annotated."""
    builders = {
        SourceSpec: make_spec,
        SourceEntry: make_entry,
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


def test_correlation_result_ratio_is_unmatched_over_detections():
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
    }
    return Detection(**{**fields, **overrides})


def test_detection_metadata_defaults_to_empty():
    """Spec §8 parses `alert.metadata`; absent metadata is empty, not missing."""
    assert make_detection().metadata == ()


def test_unmatched_detection_records_why_it_could_not_be_placed():
    unmatched = UnmatchedDetection(detection=make_detection(), reason="no_flow_match")

    assert unmatched.reason == "no_flow_match"
    assert unmatched.detection.sid == 2000001
