"""The one place a `Detection` becomes provenance (spec §4, §9).

`build_source_entry` is pre-placed on `main` ahead of steps 7 and 8 (#44). Both need it and
neither owns it: step 7 must construct `SourceEntry` values because `CorrelationResult.labels`
is `tuple[Label, ...]` and a `Label` cannot be built without them, while PLAN step 8 assigns
the derivation of `label_basis`, `admission_basis` and `licence` to `labels.py`. Two parallel
worktrees inventing that separately is how steps 3-6 ended up with three incompatible
tool-failure conventions.

The tests here are about *provenance being complete and honest*, not about plumbing. The
defect class they exist to catch is the one green CI missed all through steps 3-6: an entry
that is complete, well-formed, plausible, and wrong. So the guards are tested by the wrong
answer they would otherwise let through, not by the exception type they raise.
"""

from __future__ import annotations

import dataclasses

import pytest

from flabel.models import Detection, SourceAdmission, SourceEntry, SourceSpec
from flabel.provenance import KNOWN_TIERS, build_source_entry, spec_from_admission

SNAPSHOT_ID = "8a39182c18a3c9d3"

#: Every `SourceEntry` field that must carry a real value. `classtype` is the sole legitimate
#: null — 10,949 of the 85,545 rules in the measured snapshot declare no `classtype:` — so it
#: is named as the exception rather than left implicit. Hardcoded, so that adding a field to
#: `SourceEntry` fails `test_the_mandatory_field_set_is_exactly_this` until someone decides
#: which side of the line it belongs on.
MANDATORY_FIELDS = frozenset(
    {
        "tier",
        "source",
        "sid",
        "rev",
        "ruleset",
        "admission_basis",
        "licence",
        "label_basis",
        "threat",
    }
)
NULLABLE_FIELDS = frozenset({"classtype"})


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


# --- the terms come from the snapshot, not the registry ------------------------------------


def test_terms_come_from_the_admission_record_not_the_live_registry():
    """The defect this signature exists to prevent (#45 review).

    A snapshot is built, then `data/sources.toml` is edited — or an operator passes
    `--sources other.toml` — and a run is made against the *older* snapshot. Every label must
    carry the terms recorded when those rules were fetched, because those are the terms the
    rules that actually fired were admitted on.
    """
    admission = make_admission(licence="CC0-1.0", admission_basis="wholesale")
    entry = build_source_entry(make_detection(), admission, SNAPSHOT_ID)

    assert entry.licence == "CC0-1.0"
    assert entry.admission_basis == "wholesale"


def test_a_reclassified_source_does_not_change_labels_from_an_older_snapshot():
    """The dangerous half of the same defect, and the one no field check would catch.

    Moving `abuse.ch/urlhaus` from `ioc-name` to `ioc-dest` in the registry flips every label
    from `indicator-reference` to `direct` — "this flow looked up a bad name" becomes "this
    flow is the attack". Both values are valid, so nothing downstream could tell. The
    snapshot's own record is what decides.
    """
    snapshotted = make_admission(name="abuse.ch/urlhaus", source_class="ioc-name")
    entry = build_source_entry(make_detection(source="abuse.ch/urlhaus"), snapshotted, SNAPSHOT_ID)
    assert entry.label_basis == "indicator-reference"


def test_a_sourcespec_is_refused_where_an_admission_is_required():
    """The type hint is not the guard, and this is the test that makes it one.

    `SourceSpec` carries all five attributes this function reads off a `SourceAdmission`, so
    before this check a registry spec passed straight through and produced a well-formed
    entry — reintroducing the live-registry defect the signature was changed to prevent, with
    a spec paragraph asserting it could not happen. Nothing else in the repo checks
    annotations: CI runs ruff, and there is no mypy or pyright.

    The realistic miswiring is a step 7 worktree writing
    `build_source_entry(d, load_sources()[d.source], manifest.snapshot_id)` — every test
    green, CI green, and a reviewer seeing a call to the blessed function.
    """
    spec = SourceSpec(
        name="et/open",
        url="https://example.invalid/emerging.rules.tar.gz",
        licence="MIT",
        source_class="signature",
        admission_basis="metadata-filter",
    )
    with pytest.raises(ValueError, match="SourceAdmission"):
        build_source_entry(make_detection(), spec, SNAPSHOT_ID)  # type: ignore[arg-type]


def test_spec_from_admission_carries_every_term_across():
    """The adapter must not drop a field, or the derivation runs on a default."""
    admission = make_admission(source_class="ioc-dest", licence="CC0-1.0")
    spec = spec_from_admission(admission)

    assert isinstance(spec, SourceSpec)
    assert spec.name == admission.name
    assert spec.url == admission.url
    assert spec.licence == admission.licence
    assert spec.source_class == admission.source_class
    assert spec.admission_basis == admission.admission_basis


# --- every field spec §4 demands is carried ------------------------------------------------


def test_the_mandatory_field_set_is_exactly_this():
    """Adding a `SourceEntry` field must be a decision, not a silent pass.

    Without this, a Phase 2 field (`content_version`, `panos_version`, `device_observed_at`
    per docs/prd.md) added with an empty-string default would sail through the completeness
    check below, which only looks at the fields it already knows about.
    """
    declared = {field.name for field in dataclasses.fields(SourceEntry)}
    assert declared == MANDATORY_FIELDS | NULLABLE_FIELDS, (
        "SourceEntry's fields changed. Add each new field to MANDATORY_FIELDS or to "
        "NULLABLE_FIELDS, and teach build_source_entry where its value comes from."
    )


def test_every_mandatory_field_is_populated_with_a_real_value():
    """Goal 1 in its automated form, with no "where applicable" escape.

    Non-empty, not merely non-None: `licence=""` and `threat=""` are complete-looking and
    useless. Spec §4 provides `"unstated"` as the way to say a licence is unknown, so an
    empty string is a defect rather than an honest gap.
    """
    entry = build_source_entry(make_detection(), make_admission(), SNAPSHOT_ID)

    empty = [
        name
        for name in sorted(MANDATORY_FIELDS)
        if getattr(entry, name) is None or getattr(entry, name) == ""
    ]
    assert not empty, f"mandatory SourceEntry fields empty or unset: {empty}"


@pytest.mark.parametrize(
    ("field", "detection_kwargs", "admission_kwargs"),
    [
        pytest.param("threat", {"threat": ""}, {}, id="threat"),
        pytest.param("licence", {}, {"licence": ""}, id="licence"),
    ],
)
def test_an_empty_mandatory_field_is_refused(field, detection_kwargs, admission_kwargs):
    """The invariant the completeness test only appeared to check.

    `SourceEntry` has no field defaults, so a mandatory field can only arrive empty if its
    input was — and `suricata.py` checks that the `signature` *key* exists, not that it has a
    value, so a rule emitting `"signature": ""` produces a label naming no threat. Asserting
    non-emptiness over a populated fixture could never have caught either case.
    """
    with pytest.raises(ValueError, match=field):
        build_source_entry(
            make_detection(**detection_kwargs), make_admission(**admission_kwargs), SNAPSHOT_ID
        )


def test_fields_come_from_the_detection_and_the_admission_not_from_each_other():
    """The detection carries what the engine observed; the admission what we admitted.

    Asserted field by field because a builder that crossed the two — a licence from the rule
    text, a sid from the manifest — would still produce a complete-looking entry.
    """
    detection = make_detection()
    admission = make_admission()
    entry = build_source_entry(detection, admission, SNAPSHOT_ID)

    assert entry.tier == detection.tier
    assert entry.source == detection.source
    assert entry.sid == detection.sid
    assert entry.rev == detection.rev
    assert entry.classtype == detection.classtype
    assert entry.threat == detection.threat

    assert entry.admission_basis == admission.admission_basis
    assert entry.licence == admission.licence
    assert entry.ruleset == SNAPSHOT_ID


def test_classtype_none_is_preserved_rather_than_defaulted():
    """A missing classtype is ordinary and must survive as None.

    Substituting a placeholder would put text in provenance that the feed never asserted.
    """
    entry = build_source_entry(make_detection(classtype=None), make_admission(), SNAPSHOT_ID)
    assert entry.classtype is None


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
    entry = build_source_entry(
        make_detection(), make_admission(source_class=source_class), SNAPSHOT_ID
    )
    assert entry.label_basis == expected


def test_label_basis_is_taken_from_the_spec_property_not_recomputed():
    """One derivation, not two that must agree."""
    admission = make_admission(source_class="ioc-name")
    entry = build_source_entry(make_detection(), admission, SNAPSHOT_ID)
    assert entry.label_basis == spec_from_admission(admission).label_basis


# --- spec §2.8: an identify source can never produce a label -------------------------------


def test_identify_source_cannot_produce_an_entry():
    """Spec §2.8, enforced a second time on purpose.

    Step 6 already drops `identify` detections before correlation and counts them in
    `identify_alerts_suppressed`. This is the backstop for the day something reaches here
    anyway: `label_basis` is None for an identify source, so without the check the entry
    would be rejected by `SourceEntry.__post_init__` with a message about a Literal — true,
    but describing the symptom rather than the never-do it violates.
    """
    admission = make_admission(name="oisf/trafficid", source_class="identify")
    with pytest.raises(ValueError, match="identify"):
        build_source_entry(make_detection(source="oisf/trafficid"), admission, SNAPSHOT_ID)


def test_mismatched_admission_is_refused():
    """The admission record must describe the detection's own source.

    Handing the wrong record would attribute one feed's licence and admission basis to
    another feed's alert. Both are complete, plausible values, so nothing downstream could
    detect it — the label would simply cite the wrong origin.
    """
    with pytest.raises(ValueError, match="does not describe"):
        build_source_entry(
            make_detection(source="abuse.ch/urlhaus"), make_admission(name="et/open"), SNAPSHOT_ID
        )


def test_the_name_check_runs_before_the_identify_check():
    """A mis-built mapping must not be diagnosed as a suppression bug.

    If the wrong admission happens to be the identify source, reporting "should have been
    suppressed upstream" sends the reader hunting in `suricata.py` for a filter that is
    working correctly.
    """
    admission = make_admission(name="oisf/trafficid", source_class="identify")
    with pytest.raises(ValueError, match="does not describe"):
        build_source_entry(make_detection(source="et/open"), admission, SNAPSHOT_ID)


# --- the ruleset must be resolvable, not merely present ------------------------------------


@pytest.mark.parametrize(
    "snapshot_id",
    [
        pytest.param("", id="empty"),
        pytest.param(" ", id="whitespace"),
        pytest.param("None", id="stringified-default"),
        pytest.param("8a39182c", id="truncated"),
        pytest.param("8A39182C18A3C9D3", id="uppercase"),
        pytest.param("../../etc/passwd", id="path"),
        # `$` matches before a trailing newline, so `match` accepts this and the id lands in
        # `ruleset` as a string that resolves to no directory. `fullmatch` is what rejects it.
        pytest.param("8a39182c18a3c9d3\n", id="trailing-newline"),
        # The un-stringified default. `SNAPSHOT_ID.match(None)` raises TypeError, which would
        # reach the operator as the traceback this guard exists to replace.
        pytest.param(None, id="unstringified-default"),
    ],
)
def test_an_unresolvable_snapshot_id_is_refused(snapshot_id):
    """`--ruleset-snapshot` defaults to None meaning "newest available" (spec §12).

    A caller stringifying that default hands over the literal "None", which a non-empty check
    accepts and which then appears on every label as a ruleset nobody can look up. The format
    is the one `load_snapshot` enforces, so an id that passes here resolves to a directory.
    """
    with pytest.raises(ValueError, match="snapshot"):
        build_source_entry(make_detection(), make_admission(), snapshot_id)


# --- tier is the trust ranking -------------------------------------------------------------


@pytest.mark.parametrize(
    "tier",
    [
        0,
        3,
        -1,
        99,
        # `True == 1` in Python, so `True in (1, 2)` is true and the tier would serialise into
        # labels.json as `true`. Guarded in suricata.py and rules/snapshot.py for the same
        # reason.
        pytest.param(True, id="bool-true"),
    ],
)
def test_an_unknown_tier_is_refused(tier):
    """`Label.best_tier` is `min(tier)` and consumers weight labels by it (spec §4).

    Tier 1 is a PANW NGFW verdict and tier 2 is open-source screening. A stray edit setting
    tier 1 in `suricata.py` would present Suricata guesses as firewall verdicts — complete,
    well-formed, and wrong in the one field that ranks trust.
    """
    with pytest.raises(ValueError, match="tier"):
        build_source_entry(make_detection(tier=tier), make_admission(), SNAPSHOT_ID)


@pytest.mark.parametrize("tier", KNOWN_TIERS)
def test_known_tiers_are_accepted(tier):
    """Phase 2 adds tier-1 entries without changing the schema (spec §2.7), so both pass."""
    entry = build_source_entry(make_detection(tier=tier), make_admission(), SNAPSHOT_ID)
    assert entry.tier == tier


# --- shape ---------------------------------------------------------------------------------


def test_the_entry_is_frozen():
    """Provenance that can be edited after the fact is not provenance."""
    entry = build_source_entry(make_detection(), make_admission(), SNAPSHOT_ID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.licence = "Proprietary"  # type: ignore[misc]


def test_building_twice_from_the_same_inputs_gives_equal_entries():
    """Pure. Goal 2 requires the same run to serialise identically, and this is upstream of it."""
    first = build_source_entry(make_detection(), make_admission(), SNAPSHOT_ID)
    second = build_source_entry(make_detection(), make_admission(), SNAPSHOT_ID)
    assert first == second
