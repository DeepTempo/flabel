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
from typing import get_args

import pytest

from flabel.models import (
    Detection,
    SourceAdmission,
    SourceClass,
    SourceEntry,
    SourceSpec,
    label_basis,
    may_label,
)
from flabel.provenance import KNOWN_TIERS, build_source_entry

SNAPSHOT_ID = "8a39182c18a3c9d3"

#: Derived from the type, not restated, so adding a source class forces a decision here.
SOURCE_CLASSES = get_args(SourceClass)

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


@pytest.mark.parametrize("source_class", SOURCE_CLASSES)
def test_a_spec_and_an_admission_of_the_same_class_agree(source_class):
    """One derivation behind both call styles, asserted over every class.

    A caller holding a registry spec asks `spec.may_label`; a caller holding a snapshot record
    asks `may_label(admission.source_class)`. They must be the same answer — the previous
    shape reached the second by building a throwaway `SourceSpec`, which is what made the
    duplication in `suricata.py` and here possible in the first place.
    """
    spec = SourceSpec(
        name="example/source",
        url="https://example.invalid/rules.tar.gz",
        licence="MIT",
        source_class=source_class,
        admission_basis="wholesale",
    )
    assert spec.may_label is may_label(source_class)
    assert spec.label_basis == label_basis(source_class)


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


def test_label_basis_is_taken_from_the_shared_derivation_not_recomputed():
    """One derivation, not two that must agree."""
    admission = make_admission(source_class="ioc-name")
    entry = build_source_entry(make_detection(), admission, SNAPSHOT_ID)
    assert entry.label_basis == label_basis(admission.source_class)


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


# ===========================================================================================
# Step 8 — the run block (spec §10, §11). Everything above this line is read-only to step 8.
# ===========================================================================================
#
# The run block is what makes spec §2.5 true: "absence is never a signal. Every enumerated
# loss condition is reported." So the tests here are mostly about a *number that is present
# and wrong* rather than about a key that is missing — a `counts.unmatched` of 0 asserted by a
# stage that never ran reads exactly like a clean run, and nothing downstream can tell.

import json  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402

from flabel.labels import SCHEMA_VERSION  # noqa: E402
from flabel.models import (  # noqa: E402
    CorrelationResult,
    Flow,
    Ja4Status,
    Label,
    NormalizedCapture,
    SnapshotManifest,
    SuricataRunInfo,
    ToolFailure,
    UnmatchedDetection,
    ZeekRunInfo,
)
from flabel.provenance import (  # noqa: E402
    TOOLCHAIN_MANIFEST,
    build_run_block,
    read_toolchain,
)

SPEC = Path(__file__).resolve().parents[1] / "docs" / "spec.md"

STARTED = "2026-08-12T10:00:00.000000Z"
FINISHED = "2026-08-12T10:00:01.500000Z"


def make_capture(tmp_path: Path, **overrides) -> NormalizedCapture:
    fields = {
        "path": tmp_path / "run-tmp" / "normalized.pcap",
        "original_path": tmp_path / "operator" / "capture.pcapng",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "capture_format": "pcapng",
        "bytes_total": 4096,
        "input_status": "complete",
        "packets_read": 120,
        "normalization": ("convert: editcap -F pcap",),
    }
    return NormalizedCapture(**{**fields, **overrides})


def make_zeek_info(tmp_path: Path, **overrides) -> ZeekRunInfo:
    fields = {
        "version": "8.0.9",
        "flags": ("-C", "-D"),
        "log_dir": tmp_path / "zeek",
        "retained_logs": ("conn.log",),
        "ja4_status": "present",
    }
    return ZeekRunInfo(**{**fields, **overrides})


def make_suricata_info(**overrides) -> SuricataRunInfo:
    fields = {
        "version": "8.0.6",
        "snapshot_id": SNAPSHOT_ID,
        "rules_loaded": 85519,
        "alerts_total": 3,
        "config_sha256": "9f" * 32,
    }
    return SuricataRunInfo(**{**fields, **overrides})


def make_manifest(*admissions) -> SnapshotManifest:
    sources = admissions or (make_admission(),)
    return SnapshotManifest(
        snapshot_id=SNAPSHOT_ID,
        created_at="2026-08-12T00:00:00.000000Z",
        flabel_version="0.0.0",
        sources=sources,
        total_admitted=sum(source.rules_admitted for source in sources),
        total_ja4_admitted=sum(source.ja4_rules_admitted for source in sources),
    )


def make_flow(**overrides) -> Flow:
    fields = {
        "uid": "CHhAvVGS1DHFjwGM9",
        "src_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_ip": "198.51.100.7",
        "dst_port": 443,
        "proto": "tcp",
        "ts_first": 1_700_000_000.5,
        "ts_last": 1_700_000_010.25,
    }
    return Flow(**{**fields, **overrides})


def make_label() -> Label:
    entry = build_source_entry(make_detection(), make_admission(), SNAPSHOT_ID)
    return Label(flow=make_flow(), verdict="malicious", best_tier=2, sources=(entry,))


def make_correlation(**overrides) -> CorrelationResult:
    fields = {
        "labels": (make_label(),),
        "unmatched": (),
        "flows_total": 40,
        "detections_total": 3,
    }
    return CorrelationResult(**{**fields, **overrides})


def full_run(tmp_path: Path, **overrides) -> dict:
    """A run block with every stage having completed — the ordinary success case."""
    arguments = {
        "started_at": STARTED,
        "finished_at": FINISHED,
        "capture": make_capture(tmp_path),
        "manifest": make_manifest(),
        "zeek": make_zeek_info(tmp_path),
        "suricata": make_suricata_info(),
        "correlation": make_correlation(),
        # A completed run resolved its snapshot. Stated rather than inferred from `manifest`
        # being present, for the same reason the run block itself does not infer it.
        "snapshot_resolved": True,
        "toolchain_path": tmp_path / "absent-toolchain.json",
    }
    return build_run_block(**{**arguments, **overrides})


def write_toolchain(tmp_path: Path, payload) -> Path:
    path = tmp_path / "flabel-toolchain.json"
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
    return path


# --- the run block exists whether or not anything succeeded ---------------------------------


def test_a_run_block_is_assemblable_with_no_stage_having_completed(tmp_path):
    """`run.json` is written by every run, including one that died in ingest (issue #23).

    A builder that needed a capture, a manifest and a correlation result could only describe
    a run that already worked — which is the one case that needs no explaining.
    """
    block = build_run_block(
        started_at=STARTED,
        finished_at=FINISHED,
        tool_failures=(ToolFailure(tool="zeek", argv=("zeek",), exit_code=127, message="no"),),
        toolchain_path=tmp_path / "absent.json",
    )
    assert block["tool_failures"][0]["exit_code"] == 127
    assert json.dumps(block)  # serialisable on its own, with no labels anywhere near it


def test_the_key_set_is_the_same_whether_the_run_succeeded_or_died(tmp_path):
    """A consumer must be able to read one shape, not two.

    Dropping sections on failure would mean every reader writing `if "counts" in run`, and the
    first one to forget reports a dead run as a clean one.
    """
    complete = full_run(tmp_path)
    empty = build_run_block(
        started_at=STARTED, finished_at=FINISHED, toolchain_path=tmp_path / "absent.json"
    )

    def shape(node):
        if isinstance(node, dict):
            return {key: shape(value) for key, value in sorted(node.items())}
        return None

    assert shape(complete) == shape(empty)


def test_a_fact_that_was_never_established_is_null_not_zero(tmp_path):
    """The whole point of spec §2.5, at the one place it is easiest to get wrong.

    `counts.unmatched: 0` from a run whose correlation never happened is not a smaller claim
    than the truth — it is the *opposite* claim, and it is the one a training pipeline would
    read as "nothing was lost".
    """
    block = build_run_block(
        started_at=STARTED, finished_at=FINISHED, toolchain_path=tmp_path / "absent.json"
    )
    for section in ("input", "ruleset", "tools", "counts"):
        assert set(block[section]), f"{section} lost its keys"
        assert all(value is None for value in block[section].values()), (
            f"{section} invented a value for a stage that never ran: {block[section]}"
        )


def test_counts_are_null_per_source_not_all_or_nothing(tmp_path):
    """Suricata's counts and correlation's counts come from different stages.

    A run that loaded rules and then failed in correlation knows `rules_loaded` and does not
    know `labels`. Collapsing that to "counts unknown" would throw away a fact we have.
    """
    block = full_run(tmp_path, correlation=None)
    assert block["counts"]["rules_loaded"] == 85519
    assert block["counts"]["labels"] is None
    assert block["counts"]["unmatched"] is None


# --- input.path is the operator's file (spec §10, plan step 8) ------------------------------


def test_input_path_is_the_operators_capture_not_the_normalized_copy(tmp_path):
    """The normalized copy lives in a per-run temp directory and means nothing to a reader.

    It also differs on every run by construction, so writing it would break Goal 2 from inside
    the field spec §10 excludes precisely to keep it comparable.
    """
    capture = make_capture(tmp_path)
    block = full_run(tmp_path, capture=capture)

    assert block["input"]["path"] == str(capture.original_path)
    assert str(capture.path) not in json.dumps(block)


def test_input_carries_every_field_the_run_block_declares(tmp_path):
    capture = make_capture(
        tmp_path,
        input_status="partial",
        truncated_at_offset=3072,
        discarded_link_types=("EN10MB", "LINUX_SLL"),
        discarded_packets=7,
    )
    block = full_run(tmp_path, capture=capture)["input"]

    assert block["sha256"] == capture.sha256
    assert block["format"] == "pcapng"
    assert block["bytes"] == 4096
    assert block["input_status"] == "partial"
    assert block["packets_read"] == 120
    assert block["truncated_at_offset"] == 3072
    assert block["discarded_link_types"] == ["EN10MB", "LINUX_SLL"]
    assert block["discarded_packets"] == 7
    assert block["normalization"] == ["convert: editcap -F pcap"]


def test_the_two_renamed_fields_use_their_json_names(tmp_path):
    """`capture_format` serialises as `format` and `bytes_total` as `bytes` (models.py).

    The model renamed them to dodge builtins; the run block must not inherit the workaround.
    """
    block = full_run(tmp_path)["input"]
    assert "capture_format" not in block and "bytes_total" not in block


# --- tools: a status is never a version -----------------------------------------------------


def test_the_ja4_package_version_comes_from_the_toolchain_manifest(tmp_path):
    """Spec §8: `zkg list` is the only local source, and a labelling run may not shell out."""
    manifest = write_toolchain(tmp_path, {"ja4_zeek_package": "v0.18.8", "wireshark": "4.6.6"})
    block = full_run(tmp_path, toolchain_path=manifest)

    assert block["tools"]["ja4_zeek_package"] == "v0.18.8"
    assert block["tools"]["editcap"] == "4.6.6"


def test_an_absent_toolchain_manifest_leaves_the_version_null_and_the_run_succeeds(tmp_path):
    """The ordinary laptop case. It is a missing *version*, not a missing run."""
    block = full_run(tmp_path, toolchain_path=tmp_path / "nothing-here.json")

    assert block["tools"]["ja4_zeek_package"] is None
    assert block["tools"]["ja4_status"] == "present"
    assert block["tools"]["zeek"] == "8.0.9"


def test_the_ja4_status_never_lands_in_the_version_slot(tmp_path):
    """The type abuse PR #30 flagged, now asserted rather than commented.

    `zeek.py` leaves `ja4_package_version` None; if some future edit puts a status there
    instead, the run block must refuse it rather than ship `"not-installed"` as a version —
    a string that reads like one and resolves to nothing.
    """
    from typing import get_args

    statuses = get_args(Ja4Status)
    zeek = make_zeek_info(tmp_path, ja4_status="not-installed", ja4_package_version="not-installed")
    block = full_run(tmp_path, zeek=zeek)

    assert block["tools"]["ja4_zeek_package"] not in statuses
    assert block["tools"]["ja4_zeek_package"] is None
    assert block["tools"]["ja4_status"] == "not-installed"
    assert any("version" in warning for warning in block["warnings"])


def test_a_real_package_version_on_the_zeek_info_is_preferred_to_the_manifest(tmp_path):
    """What actually ran beats what the image recorded at build time.

    `zeek.py` cannot fill it today, but if it ever can, that observation is the better source
    and the manifest becomes the fallback rather than the authority.
    """
    manifest = write_toolchain(tmp_path, {"ja4_zeek_package": "v0.0.1"})
    zeek = make_zeek_info(tmp_path, ja4_package_version="v0.18.8")
    block = full_run(tmp_path, zeek=zeek, toolchain_path=manifest)
    assert block["tools"]["ja4_zeek_package"] == "v0.18.8"


def test_tools_records_the_zeek_flags_so_a_lost_D_is_visible(tmp_path):
    """Spec §2.3. Without `-D` uids differ every run, so it has to be visible in the output."""
    assert full_run(tmp_path)["tools"]["zeek_flags"] == ["-C", "-D"]


def test_the_suricata_config_hash_reaches_the_run_block(tmp_path):
    """A run is only reproducible against a known config (models.py, `config_sha256`)."""
    assert full_run(tmp_path)["tools"]["suricata_config_sha256"] == "9f" * 32


# --- reading the toolchain manifest ----------------------------------------------------------


def test_the_default_manifest_location_is_the_one_the_image_writes():
    """`Dockerfile.toolchain` writes exactly this path and `test_toolchain.py` asserts it."""
    assert Path("/etc/flabel-toolchain.json") == TOOLCHAIN_MANIFEST


def test_an_absent_manifest_reads_as_empty_without_complaint(tmp_path):
    values, warnings = read_toolchain(tmp_path / "nope.json")
    assert values == {} and warnings == ()


def test_a_malformed_manifest_warns_rather_than_failing_or_going_quiet(tmp_path):
    """A manifest that exists and cannot be parsed is a broken image, not a laptop.

    Silently treating it as absent would hide that; failing the run would lose every label
    over a provenance detail. So it warns, and `warnings[]` carries it into the run block.
    """
    path = write_toolchain(tmp_path, "{not json")
    values, warnings = read_toolchain(path)

    assert values == {}
    assert warnings and any("toolchain" in warning for warning in warnings)


def test_a_manifest_that_is_not_utf8_warns_rather_than_crashing_the_run_block(tmp_path):
    """The malformed case above is valid UTF-8, so it never reached this branch.

    `read_text(encoding="utf-8")` raises `UnicodeDecodeError` on undecodable bytes, and that is
    a `ValueError`, **not** an `OSError` — so it escaped the read's exception clause entirely.
    One bad byte in a truncated `/etc/flabel-toolchain.json` would then crash `build_run_block`
    on every run, including the failure path where step 9 is writing `run.json` to explain why
    the run died. Spec §10 says `run.json` is written by every run; this is the test that keeps
    an unrelated provenance file from making that untrue.
    """
    path = tmp_path / "flabel-toolchain.json"
    path.write_bytes(b'{"zeek": "8.0.4\xff\xfe"}')

    values, warnings = read_toolchain(path)

    assert values == {}
    assert warnings and any("UTF-8" in warning for warning in warnings)


def test_a_run_block_still_builds_when_the_toolchain_manifest_is_undecodable(tmp_path):
    """The whole point of the branch above: the report survives the unreadable file."""
    path = tmp_path / "flabel-toolchain.json"
    path.write_bytes(b"\xff\xfe\x00broken")

    block = full_run(tmp_path, toolchain_path=path)

    # The two fields the manifest is the only source for. `tools.zeek` and `tools.suricata`
    # come from their stages' run info and are unaffected — which is the point: an unreadable
    # provenance file costs the facts it held, not the report.
    assert block["tools"]["editcap"] is None
    assert block["tools"]["ja4_zeek_package"] is None
    assert any("UTF-8" in warning for warning in block["warnings"])


def test_a_non_string_version_is_rejected_rather_than_serialised_as_a_number(tmp_path):
    """`"ja4_zeek_package": 18` would otherwise land in a `str | None` slot as an int.

    Every consumer comparing it against a pinned string would then silently never match.
    """
    path = write_toolchain(tmp_path, {"ja4_zeek_package": 18, "wireshark": ""})
    values, warnings = read_toolchain(path)

    assert "ja4_zeek_package" not in values and "wireshark" not in values
    assert len(warnings) == 2


def test_a_manifest_that_is_not_an_object_is_rejected(tmp_path):
    path = write_toolchain(tmp_path, ["v0.18.8"])
    values, warnings = read_toolchain(path)
    assert values == {} and warnings


def test_the_manifest_warning_reaches_the_run_block(tmp_path):
    """A warning nobody can read is not a report (spec §2.5)."""
    path = write_toolchain(tmp_path, "{not json")
    block = full_run(tmp_path, toolchain_path=path)
    assert any("toolchain" in warning for warning in block["warnings"])


# --- counts ------------------------------------------------------------------------------------


def test_counts_come_from_the_stage_that_measured_them(tmp_path):
    correlation = make_correlation(
        unmatched=(
            UnmatchedDetection(detection=make_detection(sid=1), reason="no_flow_match"),
            UnmatchedDetection(detection=make_detection(sid=2), reason="ambiguous_flow_match"),
        ),
        detections_total=8,
    )
    suricata = make_suricata_info(rules_failed=26, rules_skipped=4, identify_alerts_suppressed=11)
    counts = full_run(tmp_path, correlation=correlation, suricata=suricata)["counts"]

    assert counts["flows"] == 40
    assert counts["detections"] == 8
    assert counts["labels"] == 1
    assert counts["unmatched"] == 2
    assert counts["unmatched_ratio"] == pytest.approx(0.25)
    assert counts["identify_alerts_suppressed"] == 11
    assert counts["rules_loaded"] == 85519
    assert counts["rules_failed"] == 26
    assert counts["rules_skipped"] == 4


def test_the_unmatched_ratio_is_the_models_own_derivation(tmp_path):
    """One derivation, not a second division that can round differently."""
    correlation = make_correlation(
        unmatched=(UnmatchedDetection(detection=make_detection(), reason="no_flow_match"),),
        detections_total=3,
    )
    counts = full_run(tmp_path, correlation=correlation)["counts"]
    assert counts["unmatched_ratio"] == correlation.unmatched_ratio
    assert isinstance(counts["unmatched_ratio"], float)


def test_the_label_count_is_labels_not_source_entries(tmp_path):
    """One flow with three asserting sources is one label.

    Counting entries would inflate the headline number a reader trusts most.
    """
    entries = tuple(
        build_source_entry(make_detection(sid=sid), make_admission(), SNAPSHOT_ID)
        for sid in (1, 2, 3)
    )
    label = Label(flow=make_flow(), verdict="malicious", best_tier=2, sources=entries)
    block = full_run(tmp_path, correlation=make_correlation(labels=(label,)))
    assert block["counts"]["labels"] == 1


# --- every loss condition in spec §11 has somewhere to be reported ----------------------------


def loss_condition_fields() -> list[str]:
    """The `Field` column of spec §11's table, read from the spec at test time.

    Read rather than restated. A hardcoded copy is a copy that can be trimmed to match the
    implementation, which turns the closed list Goal 3 is checked against into a list of
    whatever happens to be built.
    """
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("## 11. Loss conditions", 1)[1].split("\n## ", 1)[0]

    fields: list[str] = []
    for line in section.splitlines():
        if not line.startswith("|") or line.startswith("| :--") or "| Field |" in line:
            continue
        columns = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(columns) != 3:
            continue
        # Only the Field column, and only its code spans: the Condition and Fault-injection
        # columns also contain backticks (`identify`, `conn.log`), and the "Snapshot missing"
        # row's field cell is prose because that condition has no field at all.
        fields.extend(re.findall(r"`([^`]+)`", columns[1]))
    return fields


def loss_condition_rows() -> int:
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("## 11. Loss conditions", 1)[1].split("\n## ", 1)[0]
    return sum(
        1
        for line in section.splitlines()
        if line.startswith("|") and not line.startswith("| :--") and "| Field |" not in line
    )


def resolve(document: dict, path: str):
    """Resolve a spec §11 field path against a `labels.json` document.

    Three shapes appear in that column and all three have to work:

    * `counts.unmatched` — a path inside the run block;
    * `packets_read` — a bare name sharing the previous entry's parent (`input.…`);
    * `unmatched_detections[]` — a document-level array, outside the run block entirely.

    Raises `KeyError` naming the path when it resolves nowhere, so a failure says which
    loss condition has no home rather than which dict lookup blew up.
    """
    node = document
    for part in path.split("."):
        name = part.removesuffix("[]")
        if isinstance(node, list):
            if not node:
                raise KeyError(f"{path}: the array is empty, so `[]` proves nothing")
            node = node[0]
        if not isinstance(node, dict) or name not in node:
            raise KeyError(path)
        node = node[name]
    return node


def test_every_loss_condition_field_in_the_spec_has_a_home(tmp_path):
    """Goal 3, checked against spec §11 itself rather than against a copy of it.

    Two of the twelve field paths are document-level (`unmatched_detections[]`), not run-block
    fields — the plan says "in the run block", but the spec's own table names them where they
    live. Both are resolved here, and the run-block half is asserted separately below.
    """
    from flabel.labels import build_document

    fields = loss_condition_fields()
    assert len(fields) >= 12, f"spec §11 parsed to only {fields} — the parser is broken"

    correlation = make_correlation(
        unmatched=(
            UnmatchedDetection(detection=make_detection(sid=1), reason="no_flow_match"),
            UnmatchedDetection(detection=make_detection(sid=2), reason="ambiguous_flow_match"),
        )
    )
    run = full_run(
        tmp_path,
        capture=make_capture(
            tmp_path, input_status="partial", truncated_at_offset=99, discarded_packets=1
        ),
        correlation=correlation,
        tool_failures=(ToolFailure(tool="zeek", argv=("zeek",), exit_code=1, message="x"),),
    )
    document = build_document(run=run, labels=correlation.labels, unmatched=correlation.unmatched)
    decoded = json.loads(json.dumps(document))

    parent = ""
    missing = []
    for field in fields:
        candidates = [field]
        if "." not in field and parent:
            candidates.insert(0, f"{parent}.{field}")
        if not any(_resolves(decoded["run"], candidate) for candidate in candidates) and not any(
            _resolves(decoded, candidate) for candidate in candidates
        ):
            missing.append(field)
        if "." in field:
            parent = field.split(".", 1)[0]
    assert not missing, (
        f"spec §11 names these fields and the output has nowhere for them: {missing}"
    )


def _resolves(document, path) -> bool:
    try:
        resolve(document, path)
    except KeyError:
        return False
    return True


def test_the_run_block_alone_reports_every_loss_condition_it_can(tmp_path):
    """`run.json` exists without a `labels.json` beside it (issue #23).

    So the loss conditions whose fields live in the run block must be readable from it on its
    own — a failed run cannot point at an `unmatched_detections[]` that was never written.
    """
    run = full_run(tmp_path)
    for field in loss_condition_fields():
        if field.startswith("unmatched_detections"):
            continue
        candidates = [field, f"input.{field}"]
        assert any(_resolves(run, candidate) for candidate in candidates), (
            f"{field} is not readable from the run block alone"
        )


def test_the_loss_condition_summary_covers_every_row_of_the_spec_table(tmp_path):
    """One flag per §11 row, so adding a row cannot quietly go unreported.

    The count is read from the spec rather than written down here: a hardcoded 9 would stay
    green the day a tenth loss condition is specified and never surfaced.
    """
    summary = full_run(tmp_path)["loss_conditions"]
    assert len(summary) == loss_condition_rows(), (
        f"spec §11 lists {loss_condition_rows()} conditions and the run block flags "
        f"{len(summary)}: {sorted(summary)}"
    )


@pytest.mark.parametrize(
    ("condition", "overrides"),
    [
        pytest.param(
            "input_truncated",
            lambda tmp_path: {
                "capture": make_capture(tmp_path, input_status="partial", truncated_at_offset=3072)
            },
            id="input-truncated",
        ),
        pytest.param(
            "multi_datalink_discard",
            lambda tmp_path: {
                "capture": make_capture(
                    tmp_path,
                    input_status="partial",
                    discarded_link_types=("LINUX_SLL",),
                    discarded_packets=4,
                )
            },
            id="multi-datalink",
        ),
        pytest.param(
            "detection_uncorrelatable",
            lambda tmp_path: {
                "correlation": make_correlation(
                    unmatched=(
                        UnmatchedDetection(detection=make_detection(), reason="no_flow_match"),
                    )
                )
            },
            id="uncorrelatable",
        ),
        pytest.param(
            "ambiguous_flow_match",
            lambda tmp_path: {
                "correlation": make_correlation(
                    unmatched=(
                        UnmatchedDetection(
                            detection=make_detection(), reason="ambiguous_flow_match"
                        ),
                    )
                )
            },
            id="ambiguous",
        ),
        pytest.param(
            "tool_failure",
            lambda tmp_path: {
                "tool_failures": (
                    ToolFailure(tool="zeek", argv=("zeek",), exit_code=127, message="x"),
                )
            },
            id="tool-failure",
        ),
        pytest.param(
            "snapshot_missing",
            lambda tmp_path: {"snapshot_resolved": False, "manifest": None},
            id="snapshot",
        ),
        pytest.param(
            "identify_alert_suppressed",
            lambda tmp_path: {"suricata": make_suricata_info(identify_alerts_suppressed=3)},
            id="identify",
        ),
        pytest.param(
            "rules_failed_or_skipped",
            lambda tmp_path: {"suricata": make_suricata_info(rules_failed=26)},
            id="rules-failed",
        ),
        pytest.param(
            "ja4_unavailable",
            lambda tmp_path: {"zeek": make_zeek_info(tmp_path, ja4_status="not-installed")},
            id="ja4",
        ),
    ],
)
def test_each_loss_condition_flag_is_false_until_its_fault_is_injected(
    tmp_path, condition, overrides
):
    """The summary must track the authoritative fields, not be set by hand somewhere.

    A flag hardwired to False is the failure mode: it looks like a clean run for every input,
    and spec §13 forbids reporting full coverage when a loss condition fired.
    """
    clean = full_run(tmp_path)["loss_conditions"]
    assert clean[condition] is False, f"{condition} fired on a clean run"

    injected = full_run(tmp_path, **overrides(tmp_path))["loss_conditions"]
    assert injected[condition] is True, f"{condition} did not fire when its fault was injected"


def test_a_crash_before_the_snapshot_loads_does_not_claim_the_ruleset_was_missing(tmp_path):
    """The two runs `manifest is None` used to conflate, told apart.

    Zeek is OOM-killed, step 9 catches `ToolError` and writes `run.json` — and at that point
    the snapshot has not been loaded, because it is loaded for correlation, after Zeek. Deriving
    `snapshot_missing` from the absent manifest would blame a missing ruleset for a crash that
    had nothing to do with the ruleset, in the one file whose job is saying honestly what the
    run did and did not see. §11 defines that row as a specific operator error —
    `--ruleset-snapshot nonexistent` — not as "we never got there".
    """
    crashed = build_run_block(
        started_at=STARTED,
        finished_at=FINISHED,
        capture=make_capture(tmp_path),
        tool_failures=(ToolFailure(tool="zeek", argv=("zeek",), exit_code=-9, message="killed"),),
        toolchain_path=tmp_path / "absent-toolchain.json",
    )

    assert crashed["loss_conditions"]["snapshot_missing"] is None
    assert crashed["loss_conditions"]["tool_failure"] is True


def test_an_unknown_loss_condition_is_null_rather_than_false(tmp_path):
    """ "No JA4 problem" and "nothing ever probed JA4" are different facts.

    False here would assert the run checked and found nothing wrong, which it did not.
    """
    summary = build_run_block(
        started_at=STARTED, finished_at=FINISHED, toolchain_path=tmp_path / "absent.json"
    )["loss_conditions"]
    assert summary["ja4_unavailable"] is None
    assert summary["identify_alert_suppressed"] is None
    # Tool failures are known even when every stage is absent: the caller passes them in.
    assert summary["tool_failure"] is False


# --- the rest of the run block ------------------------------------------------------------------


def test_the_run_block_carries_the_phase_1_constants(tmp_path):
    block = full_run(tmp_path)
    assert block["mode"] == "offline"
    assert block["tiers_attempted"] == [2]
    assert block["tiers_unavailable"] == [1]
    assert block["schema_version"] == SCHEMA_VERSION


def test_the_duration_is_derived_from_the_two_timestamps(tmp_path):
    """Two stamps and a duration that can disagree is one fact recorded twice."""
    block = full_run(tmp_path)
    assert block["duration_seconds"] == pytest.approx(1.5)
    assert isinstance(block["duration_seconds"], float)


def test_a_finish_before_the_start_is_refused(tmp_path):
    """A negative duration is a mis-wired caller, and it would ship as a plausible number."""
    with pytest.raises(ValueError, match="duration"):
        full_run(tmp_path, started_at=FINISHED, finished_at=STARTED)


def test_a_non_canonical_timestamp_is_refused(tmp_path):
    """Spec §10 says one format everywhere, so the run block enforces it on its own inputs."""
    with pytest.raises(ValueError, match="ISO-8601"):
        full_run(tmp_path, started_at="2026-08-12 10:00:00")


def test_the_ruleset_section_reports_the_snapshot_that_produced_the_labels(tmp_path):
    manifest = make_manifest(
        make_admission(),
        make_admission(name="pawpatrules", licence="CC-BY-SA-4.0", admission_basis="wholesale"),
    )
    ruleset = full_run(tmp_path, manifest=manifest)["ruleset"]

    assert ruleset["snapshot_id"] == SNAPSHOT_ID
    assert ruleset["total_admitted"] == manifest.total_admitted
    assert [source["name"] for source in ruleset["sources"]] == ["et/open", "pawpatrules"]
    assert ruleset["sources"][0]["rules_excluded_unloadable"] == 0


def test_the_ruleset_sources_are_sorted_by_name(tmp_path):
    """Canonical output (spec §10): the manifest's tuple order must not reach the file."""
    manifest = make_manifest(
        make_admission(name="pawpatrules", admission_basis="wholesale"),
        make_admission(
            name="abuse.ch/urlhaus", source_class="ioc-name", admission_basis="wholesale"
        ),
        make_admission(name="et/open"),
    )
    names = [
        source["name"] for source in full_run(tmp_path, manifest=manifest)["ruleset"]["sources"]
    ]
    assert names == sorted(names)


def test_warnings_from_every_stage_reach_the_run_block(tmp_path):
    """A stage's non-fatal loss reported only to stderr is a loss nobody reading the run sees."""
    block = full_run(
        tmp_path,
        capture=make_capture(tmp_path, warnings=("ingest: tail record trimmed",)),
        zeek=make_zeek_info(tmp_path, warnings=("zeek: ja4 unavailable",)),
        suricata=make_suricata_info(warnings=("suricata: 26 rules failed to load",)),
    )
    assert block["warnings"] == [
        "ingest: tail record trimmed",
        "zeek: ja4 unavailable",
        "suricata: 26 rules failed to load",
    ]


def test_tool_failures_from_the_stages_are_collected_alongside_the_callers(tmp_path):
    """`ToolError` carries the records; the caller may also hold ones it caught elsewhere.

    Reading only the argument would drop the records a stage recorded before raising — the
    exact loss `errors.ToolError` exists to prevent.
    """
    zeek_failure = ToolFailure(tool="zeek", argv=("zeek", "-r"), exit_code=1, message="died")
    suricata_failure = ToolFailure(tool="suricata", argv=("suricata",), exit_code=None, message="k")
    block = full_run(
        tmp_path,
        zeek=make_zeek_info(tmp_path, tool_failures=(zeek_failure,)),
        suricata=make_suricata_info(tool_failures=(suricata_failure,)),
    )

    assert [failure["tool"] for failure in block["tool_failures"]] == ["zeek", "suricata"]
    assert block["tool_failures"][0]["argv"] == ["zeek", "-r"]
    assert block["tool_failures"][1]["exit_code"] is None


def test_a_tool_failure_is_not_recorded_twice(tmp_path):
    """Step 9 catches `ToolError` holding both `.failures` and `.run_info`, and the run info
    carries the same records. Passing both must not double the count."""
    failure = ToolFailure(tool="zeek", argv=("zeek",), exit_code=1, message="died")
    block = full_run(
        tmp_path,
        zeek=make_zeek_info(tmp_path, tool_failures=(failure,)),
        tool_failures=(failure,),
    )
    assert len(block["tool_failures"]) == 1


def test_the_run_block_is_json_serialisable_with_no_conversion_left_to_the_caller(tmp_path):
    """Every value is already a JSON primitive: no Path, no tuple-of-dataclass, no enum."""
    block = full_run(tmp_path, capture=make_capture(tmp_path))
    text = json.dumps(block, sort_keys=True, indent=2, allow_nan=False)
    assert json.loads(text) == block


def test_building_the_same_run_block_twice_gives_the_same_block(tmp_path):
    """Pure, and upstream of Goal 2."""
    assert full_run(tmp_path) == full_run(tmp_path)


# --- the run block is exactly what spec §10 declares ------------------------------------


def spec_run_block_paths() -> set[str]:
    """Every key path in spec §10's run block literal, read from the spec at test time.

    Parsed rather than restated for the same reason as spec §11's field list: a copy here can
    be trimmed to match whatever was built, at which point the test asserts nothing about the
    spec. The walk tracks brace depth so `input.packets_read` is distinguishable from a
    top-level `packets_read`, and so a quoted *value* (`"offline"`) is not mistaken for a key.
    """
    text = SPEC.read_text(encoding="utf-8")
    block = text.split("### Run block", 1)[1].split("```", 2)[1].split("\n", 1)[1]

    paths: set[str] = set()
    stack: list[str] = []
    pending: str | None = None
    index = 0
    while index < len(block):
        char = block[index]
        if char == '"':
            end = block.index('"', index + 1)
            token = block[index + 1 : end]
            after = end + 1
            while after < len(block) and block[after] == " ":
                after += 1
            if after < len(block) and block[after] == ":":
                paths.add(".".join(part for part in (*stack, token) if part))
                pending = token
                index = after + 1
                continue
            index = after
            continue
        if char == "{":
            stack.append(pending or "")
            pending = None
        elif char == "}" and stack:
            stack.pop()
        index += 1
    return paths


def flatten(block: dict, prefix: str = "") -> set[str]:
    paths = set()
    for key, value in block.items():
        path = f"{prefix}{key}"
        paths.add(path)
        if isinstance(value, dict):
            paths |= flatten(value, f"{path}.")
    return paths


def test_the_run_block_carries_exactly_the_keys_spec_10_declares(tmp_path):
    """Neither missing nor invented, and checked against the spec rather than a copy of it.

    A missing key is a fact with nowhere to go; an invented one is a field a consumer will
    start depending on that no document promises. `loss_conditions` is the one exception, and
    it is called out below rather than quietly excused.
    """
    declared = spec_run_block_paths()
    assert len(declared) > 30, f"spec §10 parsed to {sorted(declared)} — the parser is broken"

    built = flatten(full_run(tmp_path))
    # `loss_conditions` is `{...}` in the spec: §10 names the key and §11 puts each condition's
    # authoritative field elsewhere in the block, so the spec never spells out its members.
    # Its own coverage test is `test_the_loss_condition_summary_covers_every_row_of_the_spec_table`.
    built = {path for path in built if not path.startswith("loss_conditions.")}

    assert built == declared, (
        f"run block does not match spec §10.\n"
        f"  missing: {sorted(declared - built)}\n"
        f"  extra:   {sorted(built - declared)}"
    )
