"""The one place a `Detection` becomes provenance (spec §4, §9).

`build_source_entry` is pre-placed on `main` ahead of steps 7 and 8 (#44). Both need it and
neither owns it: step 7 must construct `SourceEntry` values because `CorrelationResult.labels`
is `tuple[Label, ...]` and a `Label` cannot be built without them, while PLAN step 8 assigns
the derivation of `label_basis`, `admission_basis` and `licence` to `labels.py`. Two parallel
worktrees inventing that separately is how steps 3-6 ended up with three incompatible
tool-failure conventions.

The tests here are therefore about *provenance being complete and honest*, not about plumbing:
every field spec §4 demands is present (Goal 1, with no "where applicable" escape), and a
source that may not label cannot produce an entry at all (spec §2.8).
"""

from __future__ import annotations

import dataclasses

import pytest

from flabel.models import Detection, SourceEntry, SourceSpec
from flabel.provenance import build_source_entry

SNAPSHOT_ID = "8a39182c18a3c9d3"


def make_spec(**overrides) -> SourceSpec:
    fields = {
        "name": "et/open",
        "url": "https://example.invalid/emerging.rules.tar.gz",
        "licence": "MIT",
        "source_class": "signature",
        "admission_basis": "metadata-filter",
    }
    return SourceSpec(**{**fields, **overrides})


def make_detection(**overrides) -> Detection:
    fields = {
        "source": "et/open",
        "tier": 2,
        "sid": 2011465,
        "rev": 5,
        "classtype": "trojan-activity",
        "app_proto": "http",
        "threat": "ET MALWARE Example C2 Checkin",
        "ts": 1_700_000_000.5,
        "src_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_ip": "198.51.100.7",
        "dst_port": 80,
        "proto": "tcp",
    }
    return Detection(**{**fields, **overrides})


# --- every field spec §4 demands is carried ------------------------------------------------


def test_every_source_entry_field_is_populated():
    """Goal 1 in its automated form: no field is left to a default or omitted as "n/a".

    Derived from the dataclass rather than a hardcoded list, so adding a field to
    `SourceEntry` fails here until the builder is taught where it comes from — which is the
    only thing standing between "we added a provenance field" and "every label silently
    carries None for it".
    """
    entry = build_source_entry(make_detection(), make_spec(), SNAPSHOT_ID)

    unset = [
        field.name
        for field in dataclasses.fields(SourceEntry)
        if getattr(entry, field.name) is None
    ]
    assert not unset, f"SourceEntry fields left unpopulated: {unset}"


def test_fields_come_from_the_detection_and_the_spec_not_from_each_other():
    """The detection carries what the engine observed; the spec carries what we admitted.

    Asserted field by field because a builder that crossed the two — a licence from the rule
    text, a sid from the registry — would still produce a complete-looking entry.
    """
    detection = make_detection()
    spec = make_spec()
    entry = build_source_entry(detection, spec, SNAPSHOT_ID)

    assert entry.tier == detection.tier
    assert entry.source == detection.source
    assert entry.sid == detection.sid
    assert entry.rev == detection.rev
    assert entry.classtype == detection.classtype
    assert entry.threat == detection.threat

    assert entry.admission_basis == spec.admission_basis
    assert entry.licence == spec.licence
    assert entry.ruleset == SNAPSHOT_ID


def test_classtype_none_is_preserved_rather_than_defaulted():
    """10,949 of 85,545 admitted rules declare no `classtype:` (spec §8).

    A missing classtype is ordinary, so it must survive as None. Substituting a placeholder
    would put text in provenance that the feed never asserted.
    """
    entry = build_source_entry(make_detection(classtype=None), make_spec(), SNAPSHOT_ID)
    assert entry.classtype is None


def test_no_field_is_populated_from_the_detections_own_source_string():
    """`licence` and `admission_basis` come from the registry, never from the alert.

    Trivially true of the implementation, but it is the property that makes a label traceable
    to a *reviewed* source rather than to whatever name an alert happened to carry.
    """
    entry = build_source_entry(make_detection(), make_spec(licence="CC0-1.0"), SNAPSHOT_ID)
    assert entry.licence == "CC0-1.0"


# --- label_basis is derived once, here -----------------------------------------------------


@pytest.mark.parametrize(
    ("source_class", "expected"),
    [
        ("signature", "direct"),
        ("ioc-dest", "direct"),
        ("ioc-name", "indicator-reference"),
    ],
)
def test_label_basis_is_derived_from_the_source_class(source_class, expected):
    """`ioc-name` matched a looked-up name, so the flow *referenced* the indicator (spec §5).

    Reporting that as `direct` would overstate what was observed. This is the derivation both
    steps 7 and 8 would otherwise have written separately.
    """
    entry = build_source_entry(make_detection(), make_spec(source_class=source_class), SNAPSHOT_ID)
    assert entry.label_basis == expected


def test_label_basis_is_taken_from_the_spec_property_not_recomputed():
    """One derivation, not two that must agree.

    `SourceSpec.label_basis` already answers this; a second copy of the rule here would be a
    place for the two to drift.
    """
    spec = make_spec(source_class="ioc-name")
    entry = build_source_entry(make_detection(), spec, SNAPSHOT_ID)
    assert entry.label_basis == spec.label_basis


# --- spec §2.8: an identify source can never produce a label -------------------------------


def test_identify_source_cannot_produce_an_entry():
    """Spec §2.8, enforced a second time on purpose.

    Step 6 already drops `identify` detections before correlation and counts them in
    `identify_alerts_suppressed`. This is the backstop for the day something reaches here
    anyway: `SourceSpec.label_basis` is None for an identify source, so without the check the
    entry would be constructed with a null basis and `SourceEntry.__post_init__` would reject
    it with a message about a Literal — true, but describing the symptom rather than the
    never-do it violates.
    """
    spec = make_spec(source_class="identify", name="oisf/trafficid")
    with pytest.raises(ValueError, match="identify"):
        build_source_entry(make_detection(source="oisf/trafficid"), spec, SNAPSHOT_ID)


def test_mismatched_spec_is_refused():
    """The spec must describe the detection's own source.

    Handing the wrong spec would attribute one feed's licence and admission basis to another
    feed's alert. Both are complete, plausible values, so nothing downstream could detect it —
    the label would simply cite the wrong origin, which is the failure mode spec §13 exists to
    prevent.
    """
    with pytest.raises(ValueError, match="does not describe"):
        build_source_entry(
            make_detection(source="abuse.ch/urlhaus"), make_spec(name="et/open"), SNAPSHOT_ID
        )


def test_empty_snapshot_id_is_refused():
    """`ruleset` is what makes a label reproducible; an empty one traces to nothing."""
    with pytest.raises(ValueError, match="snapshot_id"):
        build_source_entry(make_detection(), make_spec(), "")


# --- shape --------------------------------------------------------------------------------


def test_the_entry_is_frozen():
    """Provenance that can be edited after the fact is not provenance."""
    entry = build_source_entry(make_detection(), make_spec(), SNAPSHOT_ID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.licence = "Proprietary"  # type: ignore[misc]


def test_building_twice_from_the_same_inputs_gives_equal_entries():
    """Pure. Goal 2 requires the same run to serialise identically, and this is upstream of it."""
    first = build_source_entry(make_detection(), make_spec(), SNAPSHOT_ID)
    second = build_source_entry(make_detection(), make_spec(), SNAPSHOT_ID)
    assert first == second
