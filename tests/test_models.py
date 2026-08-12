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

import pytest

from flabel.models import (
    Detection,
    Flow,
    Label,
    SnapshotManifest,
    SourceAdmission,
    SourceEntry,
    SourceSpec,
    UnmatchedDetection,
)

SOURCE_CLASSES = ("signature", "ioc-dest", "ioc-name", "identify")


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


ALL_MODELS = (
    SourceSpec,
    SourceAdmission,
    SnapshotManifest,
    Flow,
    Detection,
    SourceEntry,
    Label,
    UnmatchedDetection,
)


@pytest.mark.parametrize("model", ALL_MODELS, ids=lambda m: m.__name__)
def test_every_model_is_a_frozen_dataclass(model):
    """Frozen, because a label's provenance must not be editable after the fact."""
    assert dataclasses.is_dataclass(model)
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
    entry = SourceEntry(
        tier=2,
        source="et/open",
        sid=2000001,
        rev=3,
        ruleset="0123456789abcdef",
        admission_basis="metadata-filter",
        licence="MIT",
        classtype="trojan-activity",
        label_basis="direct",
        threat="ET MALWARE Example",
    )
    label = Label(flow=make_flow(), verdict="malicious", best_tier=2, sources=(entry,))

    assert label.verdict == "malicious"
    assert isinstance(label.sources, tuple)


def test_unmatched_detection_records_why_it_could_not_be_placed():
    detection = Detection(
        source="et/open",
        tier=2,
        sid=2000001,
        rev=3,
        classtype="trojan-activity",
        app_proto="tls",
        threat="ET MALWARE Example",
        ts=1.5,
        src_ip="10.0.0.1",
        src_port=44001,
        dst_ip="10.0.0.2",
        dst_port=443,
        proto="tcp",
    )
    unmatched = UnmatchedDetection(detection=detection, reason="no_flow_match")

    assert unmatched.reason == "no_flow_match"
    assert unmatched.detection.sid == 2000001
