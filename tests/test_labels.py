"""Canonical `labels.json`, and the `NOTICE` that ships beside it (spec §10).

Reproducibility (Goal 2) rests entirely on this module: two runs over one capture must
produce the same bytes, so every ordering decision and every number-to-text decision here is
part of the contract rather than a formatting preference.

The defect class these tests are written against is the one that green CI missed all through
steps 3-6 — output that is complete, well-formed, plausible, and wrong. A sort that happens to
be stable on the fixture, a timestamp that reads correctly in one timezone, a model field that
quietly stops being serialised: none of those raise, and all of them are silently wrong. So the
assertions below are mostly "would this catch a plausible wrong answer", not "does it run".
"""

from __future__ import annotations

import dataclasses
import json
import re
import time
from datetime import UTC, datetime

import pytest

from flabel import correlate
from flabel import labels as labels_module
from flabel import notice as notice_module
from flabel.labels import (
    SCHEMA_VERSION,
    build_document,
    iso_from_epoch,
    serialise,
    serialise_bytes,
)
from flabel.models import (
    Detection,
    Flow,
    Label,
    SnapshotManifest,
    SourceAdmission,
    SourceEntry,
    UnmatchedDetection,
)
from flabel.rules import utc_now

SNAPSHOT_ID = "8a39182c18a3c9d3"

#: flabel's one timestamp format (spec §10): ISO-8601 UTC, microsecond precision, `Z`.
#: Written here as a pattern rather than a format string so a test cannot pass by sharing the
#: implementation's own `strftime` argument.
ISO_8601_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

#: Every key in the serialised document whose value is a moment in time. Collected by name so
#: `_assert_timestamps_are_canonical` can walk any document and catch an epoch float that was
#: never converted — the "floats never emitted where a string is expected" rule in spec §10.
TIMESTAMP_KEYS = frozenset(
    {"ts", "ts_first", "ts_last", "fetched_at", "created_at", "started_at", "finished_at"}
)


# --- fixtures -------------------------------------------------------------------------------


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
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "ja4s": None,
        "server_name": "example.invalid",
    }
    return Flow(**{**fields, **overrides})


def make_detection(**overrides) -> Detection:
    fields = {
        "source": "et/open",
        "tier": 2,
        "sid": 2011465,
        "rev": 5,
        "classtype": "trojan-activity",
        "app_proto": "tls",
        "threat": "ET MALWARE Example C2 Checkin",
        "ts": 1_700_000_002.75,
        "src_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_ip": "198.51.100.7",
        "dst_port": 443,
        "proto": "tcp",
        "direction": "to_server",
        "metadata": ("confidence High", "signature_severity Major"),
    }
    return Detection(**{**fields, **overrides})


def make_entry(**overrides) -> SourceEntry:
    fields = {
        "tier": 2,
        "source": "et/open",
        "sid": 2011465,
        "rev": 5,
        "ruleset": SNAPSHOT_ID,
        "admission_basis": "metadata-filter",
        "licence": "MIT",
        "classtype": "trojan-activity",
        "label_basis": "direct",
        "direction": "to_server",
        "threat": "ET MALWARE Example C2 Checkin",
    }
    return SourceEntry(**{**fields, **overrides})


def make_label(flow: Flow | None = None, *entries: SourceEntry) -> Label:
    sources = entries or (make_entry(),)
    return Label(
        flow=flow or make_flow(),
        verdict="malicious",
        best_tier=min(entry.tier for entry in sources),
        sources=sources,
    )


def make_unmatched(**overrides) -> UnmatchedDetection:
    reason = overrides.pop("reason", "no_flow_match")
    return UnmatchedDetection(detection=make_detection(**overrides), reason=reason)


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


def make_manifest(*admissions: SourceAdmission) -> SnapshotManifest:
    sources = admissions or (make_admission(),)
    return SnapshotManifest(
        snapshot_id=SNAPSHOT_ID,
        created_at="2026-08-12T00:00:00.000000Z",
        flabel_version="0.0.0",
        sources=sources,
        total_admitted=sum(source.rules_admitted for source in sources),
        total_ja4_admitted=sum(source.ja4_rules_admitted for source in sources),
    )


#: A run block stand-in. `build_document` takes the run block as an already-assembled mapping —
#: `provenance.build_run_block` produces the real one — so these tests can exercise the
#: serialiser without dragging the whole pipeline in.
RUN = {
    "flabel_version": "0.0.0",
    "schema_version": SCHEMA_VERSION,
    "started_at": "2026-08-12T10:00:00.000000Z",
    "finished_at": "2026-08-12T10:00:01.500000Z",
    "duration_seconds": 1.5,
    "mode": "offline",
}


def document(*, labels=None, unmatched=None, run=None) -> dict:
    return build_document(
        run=RUN if run is None else run,
        labels=() if labels is None else labels,
        unmatched=() if unmatched is None else unmatched,
    )


def _walk(node, path="$"):
    """Yield `(path, key, value)` for every mapping entry in a decoded document."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield f"{path}.{key}", key, value
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


def _assert_timestamps_are_canonical(decoded) -> None:
    seen = 0
    for path, key, value in _walk(decoded):
        if key not in TIMESTAMP_KEYS:
            continue
        seen += 1
        assert isinstance(value, str), (
            f"{path} is {type(value).__name__} {value!r}: spec §10 says a timestamp is an "
            f"ISO-8601 string, and an epoch float here is the exact 'float emitted where a "
            f"string is expected' case"
        )
        assert ISO_8601_UTC.fullmatch(value), f"{path} = {value!r} is not ISO-8601 UTC µs Z"
    assert seen, "the fixture carried no timestamps, so this test proved nothing"


# --- one timestamp format, everywhere -------------------------------------------------------


def test_epoch_timestamps_become_iso_8601_utc():
    """A known epoch to a known string, so the conversion is pinned rather than self-consistent.

    Asserting only "it round-trips" would pass for a conversion that is wrong by a fixed
    offset — which is precisely what a local-timezone bug looks like.
    """
    assert iso_from_epoch(1_700_000_000.5) == "2023-11-14T22:13:20.500000Z"
    assert iso_from_epoch(1_700_000_000.123456) == "2023-11-14T22:13:20.123456Z"
    assert iso_from_epoch(1_699_999_999.0) == "2023-11-14T22:13:19.000000Z"


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="TZ cannot be changed on this platform")
def test_timestamps_do_not_depend_on_the_host_timezone(monkeypatch):
    """Spec §10: no locale-dependent formatting.

    `datetime.fromtimestamp(ts)` without a tzinfo returns *local* time, and on a UTC CI runner
    that bug is invisible — every test passes, and every timestamp shipped from a machine in
    another zone is silently wrong by whole hours.
    """
    monkeypatch.setenv("TZ", "Asia/Kathmandu")  # UTC+05:45, so an hour-only bug shows too
    time.tzset()
    try:
        assert iso_from_epoch(1_700_000_000.5) == "2023-11-14T22:13:20.500000Z"
    finally:
        monkeypatch.undo()
        time.tzset()


def test_the_timestamp_format_matches_the_one_the_rules_package_already_writes():
    """One format everywhere (spec §10), asserted across the two modules that produce it.

    `rules.utc_now` stamps `fetched_at` and `created_at`; this module stamps flow and detection
    times. They are separate `strftime` calls in files this step may not merge, so the only
    thing keeping them one format is this assertion.
    """
    assert ISO_8601_UTC.fullmatch(utc_now())
    assert ISO_8601_UTC.fullmatch(iso_from_epoch(datetime.now(UTC).timestamp()))


def test_a_timestamp_out_of_range_is_refused_rather_than_crashing_opaquely():
    """An unconvertible `ts` must name itself, not surface as a bare OverflowError."""
    with pytest.raises(ValueError, match="timestamp"):
        iso_from_epoch(1e300)


# --- the document shape (spec §4) -----------------------------------------------------------


def test_the_document_has_exactly_the_four_top_level_keys_spec_4_declares():
    decoded = json.loads(serialise(document(labels=(make_label(),))))
    assert set(decoded) == {"schema_version", "run", "labels", "unmatched_detections"}


def test_schema_version_is_one_constant_in_both_places_the_spec_names_it():
    """Spec §4 puts it at the document root and §10 puts it in the run block.

    Two literals would be two things to forget, and Goal 6 says the value must not change when
    Phase 2 adds tier-1 entries — so a consumer keying off either must see the same string.
    """
    decoded = json.loads(serialise(document(labels=(make_label(),))))
    assert decoded["schema_version"] == SCHEMA_VERSION == "1.0"
    assert decoded["run"]["schema_version"] == SCHEMA_VERSION


def test_a_run_with_no_labels_still_produces_a_document():
    """The empty result is a real result, and it must serialise like any other.

    Also the shape step 9 needs: a run block has to be assemblable and writable without
    waiting on a non-empty `labels` array.
    """
    decoded = json.loads(serialise(document()))
    assert decoded["labels"] == []
    assert decoded["unmatched_detections"] == []
    assert decoded["run"] == RUN


def test_the_run_block_serialises_on_its_own():
    """`run.json` is the run block and nothing else (issue #23), written on every run.

    So the canonical serialiser must work on a bare run block, not only on a whole document.
    """
    text = serialise(RUN)
    assert json.loads(text) == RUN
    assert text.endswith("\n")


# --- canonical bytes (Goal 2) ----------------------------------------------------------------


def test_two_serialisations_of_the_same_data_are_byte_identical():
    """Goal 2's floor. Anything set-ordered or dict-insertion-ordered breaks here."""
    first = serialise(document(labels=(make_label(),), unmatched=(make_unmatched(),)))
    second = serialise(document(labels=(make_label(),), unmatched=(make_unmatched(),)))
    assert first.encode() == second.encode()


def test_the_bytes_do_not_depend_on_the_order_the_data_arrived_in():
    """The stronger claim, and the one a same-order comparison cannot make.

    Two runs can legitimately produce flows and detections in different orders — a dict
    iteration order, a differently-ordered `eve.json` — and the canonical form must erase that
    difference rather than record it.
    """
    early = make_label(make_flow(uid="AAA", ts_first=1.0))
    late = make_label(make_flow(uid="BBB", ts_first=2.0))
    first_unmatched = make_unmatched(ts=10.0, sid=1)
    second_unmatched = make_unmatched(ts=20.0, sid=2)

    forwards = serialise(
        document(labels=(early, late), unmatched=(first_unmatched, second_unmatched))
    )
    backwards = serialise(
        document(labels=(late, early), unmatched=(second_unmatched, first_unmatched))
    )
    assert forwards == backwards


def test_the_output_is_indented_json_with_sorted_keys_and_a_trailing_newline():
    text = serialise(document(labels=(make_label(),)))
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert "\n  " in text, "indent=2 is part of the canonical form"

    keys = re.findall(r'^  "(\w+)"', text, re.MULTILINE)
    assert keys == sorted(keys), f"top-level keys are not sorted: {keys}"


def test_non_ascii_threat_text_survives_as_itself():
    """`ensure_ascii=False` (spec §10). Rule `msg:` text is not guaranteed ASCII.

    Escaping it to `\\uXXXX` still round-trips through `json.loads`, so a decode-and-compare
    test would pass either way — the byte-level check is what pins it.
    """
    threat = "ET MALWARE Sürprise — Ω callback"
    label = make_label(None, make_entry(threat=threat))
    text = serialise(document(labels=(label,)))

    assert threat in text
    assert "\\u" not in text


def test_a_non_finite_number_is_refused_rather_than_written_as_invalid_json():
    """`json.dump` emits bare `NaN`/`Infinity` by default, which no strict parser accepts.

    A run whose `unmatched_ratio` went non-finite would write a file that looks fine to Python
    and fails everywhere else. `allow_nan=False` turns that into an error here.
    """
    with pytest.raises(ValueError):
        serialise({**RUN, "duration_seconds": float("nan")})


# --- ordering (spec §10) ----------------------------------------------------------------------


def test_labels_sort_by_ts_first_then_uid():
    """The tiebreak matters: two flows can share a `ts_first` to the microsecond.

    Sorting on `ts_first` alone leaves their order at the mercy of input order, which is
    exactly the non-determinism Goal 2 rules out.
    """
    same_time = [make_label(make_flow(uid=uid, ts_first=5.0)) for uid in ("Ccc", "Aaa", "Bbb")]
    earlier = make_label(make_flow(uid="Zzz", ts_first=1.0))

    decoded = json.loads(serialise(document(labels=(*same_time, earlier))))
    assert [entry["flow"]["uid"] for entry in decoded["labels"]] == ["Zzz", "Aaa", "Bbb", "Ccc"]


def test_labels_sort_on_the_numeric_time_not_on_its_text():
    """`ts_first` serialises as text, but the sort is over the number.

    Only a same-second pair with different sub-second parts distinguishes the two orderings
    for most inputs; this pair is chosen so a naive string sort of the *unformatted* float
    ("10.0" < "9.0") gives the wrong answer.
    """
    decoded = json.loads(
        serialise(
            document(
                labels=(
                    make_label(make_flow(uid="later", ts_first=10.0)),
                    make_label(make_flow(uid="earlier", ts_first=9.0)),
                )
            )
        )
    )
    assert [entry["flow"]["uid"] for entry in decoded["labels"]] == ["earlier", "later"]


def test_sources_within_a_label_sort_by_tier_source_sid_rev():
    entries = (
        make_entry(tier=2, source="pawpatrules", sid=3300158, rev=1),
        make_entry(tier=2, source="et/open", sid=2011465, rev=9),
        make_entry(tier=2, source="et/open", sid=2011465, rev=2),
        make_entry(tier=2, source="et/open", sid=2000000, rev=1),
        make_entry(tier=1, source="panw/ngfw", sid=99, rev=1),
    )
    decoded = json.loads(serialise(document(labels=(make_label(None, *entries),))))

    ordered = [
        (entry["tier"], entry["source"], entry["sid"], entry["rev"])
        for entry in decoded["labels"][0]["sources"]
    ]
    assert ordered == sorted(ordered)
    assert ordered[0] == (1, "panw/ngfw", 99, 1)


def test_two_entries_differing_only_in_direction_have_a_stable_order():
    """The reproducibility hazard `direction` introduced, and why it is in the sort key.

    One rule matching both halves of a flow — `alert ip any any -> any any` on a request and
    its response — used to produce two **identical** entries, so the order Suricata reported
    them in could not change the file. Carrying `direction` makes them different records, and
    eve.json's record order is not guaranteed stable between runs. Without `direction` in the sort
    key the tie would be broken by eve order, and two runs over one capture could write
    `to_client` first sometimes — a Goal 2 failure blaming the pipeline for an ordering nobody
    chose. Latent rather than observed: spec §10's measured instability is in `flow` records.
    """
    to_client = make_entry(direction="to_client")
    to_server = make_entry(direction="to_server")

    forwards = serialise(document(labels=(make_label(None, to_server, to_client),)))
    backwards = serialise(document(labels=(make_label(None, to_client, to_server),)))

    assert forwards == backwards
    ordered = [entry["direction"] for entry in json.loads(forwards)["labels"][0]["sources"]]
    assert ordered == ["to_client", "to_server"], "sorted, not merely stable"


def test_the_two_sort_keys_are_the_same_key():
    """`labels._entry_key` and `correlate._source_order` sort the same records, so they agree.

    Two modules sort a label's `sources`: `correlate` so the returned tuple is already canonical,
    and `labels` on the way out. Both docstrings claim the keys are identical and, until this
    test, nothing checked it. The realistic drift — a field added to one and not the other — is
    caught by the ordering tests either side of this one; what is not is a *reordering*
    (`(tier, source, sid, direction, rev)` against `(tier, source, sid, rev, direction)`), which
    is harmless only for as long as `labels.py` re-sorts everything anyway.
    """
    entries = [
        make_entry(),
        make_entry(direction="to_client"),
        make_entry(direction="unknown", rev=6),
        make_entry(tier=1, source="panw/ngfw", sid=99),
    ]

    assert [labels_module._entry_key(entry) for entry in entries] == [
        correlate._source_order(entry) for entry in entries
    ]


def test_unmatched_detections_sort_by_ts_source_sid():
    unmatched = (
        make_unmatched(ts=3.0, source="et/open", sid=2),
        make_unmatched(ts=1.0, source="pawpatrules", sid=9),
        make_unmatched(ts=1.0, source="et/open", sid=7),
        make_unmatched(ts=1.0, source="et/open", sid=3),
    )
    decoded = json.loads(serialise(document(unmatched=unmatched)))

    ordered = [
        (entry["detection"]["ts"], entry["detection"]["source"], entry["detection"]["sid"])
        for entry in decoded["unmatched_detections"]
    ]
    assert ordered == sorted(ordered)


# --- Goal 1 over the serialised file ----------------------------------------------------------
#
# `test_provenance.py` already asserts the same completeness over the `SourceEntry` *object*.
# This is the other half: a field can be lost between a correct object and the file, by a
# serialiser that forgets it or an encoder that drops it. Nothing upstream would notice.


def _mandatory_and_nullable() -> tuple[frozenset[str], frozenset[str]]:
    """The field split `test_provenance.py` already decided, imported rather than re-stated.

    Copying the list here would let the two drift, and a trimmed copy is precisely how a
    "required fields" test stops requiring a field.
    """
    from test_provenance import MANDATORY_FIELDS, NULLABLE_FIELDS

    return MANDATORY_FIELDS, NULLABLE_FIELDS


def test_every_mandatory_source_entry_field_survives_serialisation():
    """Goal 1, automated, over `labels.json` itself."""
    mandatory, nullable = _mandatory_and_nullable()
    decoded = json.loads(serialise(document(labels=(make_label(),))))
    entry = decoded["labels"][0]["sources"][0]

    assert set(entry) == set(mandatory | nullable), (
        f"serialised source entry keys {sorted(entry)} do not match SourceEntry's fields — "
        f"a field was dropped or invented on the way to JSON"
    )
    empty = [name for name in sorted(mandatory) if entry.get(name) in (None, "")]
    assert not empty, f"mandatory fields empty in labels.json: {empty}"


def test_no_model_field_is_dropped_on_the_way_to_json():
    """Every dataclass field reaches the file, so adding one cannot silently do nothing.

    The realistic failure is a hand-written `{"uid": ..., "src_ip": ...}` serialiser that
    stops matching the model the day a field is added — green tests, and a `ja4` that is
    computed, carried, and never written down.
    """
    decoded = json.loads(serialise(document(labels=(make_label(),), unmatched=(make_unmatched(),))))
    label = decoded["labels"][0]
    unmatched = decoded["unmatched_detections"][0]

    for model, serialised in (
        (Label, label),
        (Flow, label["flow"]),
        (SourceEntry, label["sources"][0]),
        (UnmatchedDetection, unmatched),
        (Detection, unmatched["detection"]),
    ):
        declared = {field.name for field in dataclasses.fields(model)}
        assert declared == set(serialised), (
            f"{model.__name__} declares {sorted(declared)} but serialises as {sorted(serialised)}"
        )


def test_every_timestamp_in_the_document_is_canonical():
    decoded = json.loads(serialise(document(labels=(make_label(),), unmatched=(make_unmatched(),))))
    _assert_timestamps_are_canonical(decoded)


def test_optional_flow_fields_stay_null_rather_than_becoming_placeholders():
    """A flow with no TLS has no JA4, and that must read as absence, not as an empty string.

    Substituting `""` would put a value in the file the pipeline never observed — and would
    make "no TLS" indistinguishable from "JA4 computed as nothing".
    """
    decoded = json.loads(
        serialise(document(labels=(make_label(make_flow(ja4=None, server_name=None)),)))
    )
    flow = decoded["labels"][0]["flow"]
    assert flow["ja4"] is None and flow["ja4s"] is None and flow["server_name"] is None


def test_the_verdict_is_always_malicious():
    """Spec §13's first never-do. Asserted over the file, where a consumer reads it."""
    decoded = json.loads(serialise(document(labels=(make_label(),))))
    assert {entry["verdict"] for entry in decoded["labels"]} == {"malicious"}


def test_a_dataclass_that_was_not_converted_is_refused():
    """No `default=str` escape hatch in the encoder.

    With one, an unconverted model would serialise as its `repr` — a string that looks like
    data and parses as nothing.
    """
    with pytest.raises(TypeError):
        serialise({"run": RUN, "oops": make_flow()})


# --- NOTICE (spec §10) -------------------------------------------------------------------------


GPL_ADMISSION = dict(
    name="stamus/lateral",
    url="https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz",
    licence="GPL-3.0-only",
    source_class="signature",
    admission_basis="wholesale",
)
CC_BY_ADMISSION = dict(
    name="the-hunters-ledger/open",
    url="https://the-hunters-ledger.com/feeds/suricata/hunters-ledger.rules",
    licence="CC-BY-4.0",
    source_class="signature",
    admission_basis="wholesale",
)


def test_notice_lists_a_source_that_asserted_a_label():
    manifest = make_manifest(
        make_admission(**GPL_ADMISSION),
        make_admission(**CC_BY_ADMISSION),
    )
    label = make_label(
        None,
        make_entry(source="stamus/lateral", licence="GPL-3.0-only", admission_basis="wholesale"),
        make_entry(
            source="the-hunters-ledger/open", licence="CC-BY-4.0", admission_basis="wholesale"
        ),
    )
    text = notice_module.render_notice((label,), manifest)

    assert "stamus/lateral" in text and "GPL-3.0-only" in text
    assert "the-hunters-ledger/open" in text and "CC-BY-4.0" in text
    # The attribution requirement, not merely the SPDX id: the point of NOTICE is telling an
    # operator what they must do, and an id alone leaves them to look it up.
    assert "Attribution required" in text


def test_notice_omits_a_source_that_asserted_nothing():
    """Spec §10: sources present in the snapshot but which asserted nothing are not listed.

    Listing the whole snapshot would be the easy implementation and would read as a claim that
    every feed contributed to this run's verdicts.
    """
    manifest = make_manifest(make_admission(**GPL_ADMISSION), make_admission())
    label = make_label(
        None,
        make_entry(source="stamus/lateral", licence="GPL-3.0-only", admission_basis="wholesale"),
    )
    text = notice_module.render_notice((label,), manifest)

    assert "stamus/lateral" in text
    assert "et/open" not in text


def test_notice_names_a_source_once_however_many_labels_it_asserted():
    manifest = make_manifest(make_admission(**GPL_ADMISSION))
    entry = make_entry(source="stamus/lateral", licence="GPL-3.0-only", admission_basis="wholesale")
    labels = (
        make_label(make_flow(uid="AAA"), entry),
        make_label(make_flow(uid="BBB"), dataclasses.replace(entry, sid=2)),
    )
    text = notice_module.render_notice(labels, manifest)
    assert text.count("stamus/lateral\n") == 1


def test_notice_terms_come_from_the_snapshot_the_labels_cite():
    """Same authority as `build_source_entry`: the snapshot, never the registry as it reads now.

    A NOTICE built from `config.load_sources()` would state today's licence over yesterday's
    rules — plausible, complete, and wrong about the terms the operator is actually bound by.
    """
    manifest = make_manifest(make_admission(licence="MIT"))
    label = make_label(None, make_entry(licence="MIT"))
    assert "MIT" in notice_module.render_notice((label,), manifest)


def test_notice_refuses_a_label_whose_licence_disagrees_with_the_snapshot():
    """Two records of one fact that can disagree is a provenance defect, not a formatting one.

    Whichever one NOTICE printed would be a coin toss, so it refuses instead.
    """
    manifest = make_manifest(make_admission(licence="MIT"))
    label = make_label(None, make_entry(licence="GPL-3.0-only"))
    with pytest.raises(ValueError, match="licence"):
        notice_module.render_notice((label,), manifest)


def test_notice_refuses_a_label_from_a_source_absent_from_the_snapshot():
    """An attribution flabel cannot substantiate must not be invented (spec §13)."""
    manifest = make_manifest(make_admission(name="et/open"))
    label = make_label(None, make_entry(source="abuse.ch/urlhaus"))
    with pytest.raises(ValueError, match="abuse.ch/urlhaus"):
        notice_module.render_notice((label,), manifest)


def test_notice_states_an_unrecognised_licence_rather_than_guessing_at_its_terms():
    """A new feed's SPDX id must appear even when flabel has no attribution text for it.

    Printing a generic paragraph as though it were the licence's requirement would be a claim
    about terms; naming the id and saying so is not.
    """
    manifest = make_manifest(make_admission(licence="Apache-2.0"))
    label = make_label(None, make_entry(licence="Apache-2.0"))
    text = notice_module.render_notice((label,), manifest)
    assert "Apache-2.0" in text
    assert "not recorded" in text


def test_notice_is_byte_identical_across_two_renderings():
    """It ships inside the run directory, so Goal 2 compares it like any other artifact."""
    manifest = make_manifest(make_admission(**GPL_ADMISSION), make_admission(**CC_BY_ADMISSION))
    labels = (
        make_label(
            None,
            make_entry(
                source="the-hunters-ledger/open",
                licence="CC-BY-4.0",
                admission_basis="wholesale",
            ),
            make_entry(
                source="stamus/lateral", licence="GPL-3.0-only", admission_basis="wholesale"
            ),
        ),
    )
    first = notice_module.render_notice(labels, manifest)
    second = notice_module.render_notice(labels, manifest)
    assert first == second
    # Sorted by source name, so a differently-ordered `sources` tuple cannot reorder the file.
    assert first.index("stamus/lateral") < first.index("the-hunters-ledger/open")


def test_notice_for_a_run_with_no_labels_says_so():
    """An empty NOTICE file would read as a missing artifact rather than an honest result."""
    text = notice_module.render_notice((), make_manifest())
    assert text.strip()
    assert "no labels" in text.lower()


def test_notice_carries_no_wall_clock_of_its_own():
    """Reproducibility again: a generation timestamp would differ on every run.

    Everything datable in the file comes from the snapshot, which is frozen.
    """
    text = notice_module.render_notice((), make_manifest())
    assert str(datetime.now(UTC).year) not in text.replace(SNAPSHOT_ID, "")


# --- purity ------------------------------------------------------------------------------------


def test_neither_module_formats_through_the_locale():
    """Spec §10: no locale-dependent formatting.

    `test_architecture.py` guards I/O; this guards the other thing §10 names. `locale` is the
    one import that would make `%d`-style output depend on the host, and neither module has a
    reason to hold it.
    """
    for module in (labels_module, notice_module):
        assert not hasattr(module, "locale"), f"{module.__name__} imports locale"


# --- label_basis reaches the file it is written for -------------------------------------------
#
# The derivation itself is `models.label_basis`, tested through `build_source_entry` in
# `test_provenance.py` — this step must not write a second copy of it (#44). What is untested
# there is the last hop: that the value survives into `labels.json`, where the consumer whose
# reading of the verdict depends on it actually looks.


@pytest.mark.parametrize(
    ("source_class", "expected"),
    [("signature", "direct"), ("ioc-dest", "direct"), ("ioc-name", "indicator-reference")],
)
def test_the_label_basis_of_each_source_class_reaches_labels_json(source_class, expected):
    """ "This flow looked up a bad name" and "this flow is the attack" are different verdicts.

    Built through `build_source_entry` rather than by handing `SourceEntry` the answer, so the
    assertion covers the derivation and the serialisation together — a test constructing the
    entry with `label_basis=expected` would prove only that a string survives a dict copy.

    `address_indicator=False` states that this rule is not a header-tuple indicator, which is
    what isolates the feed-level answer (PLAN 11c). The per-rule half can only move an entry
    toward `indicator-reference`, so without this the `signature` and `ioc-dest` cases would take
    the downgrade that an unclassified snapshot gets.
    """
    from flabel.provenance import build_source_entry

    detection = make_detection(source="abuse.ch/urlhaus")
    admission = make_admission(
        name="abuse.ch/urlhaus", source_class=source_class, admission_basis="wholesale"
    )
    entry = build_source_entry(detection, admission, SNAPSHOT_ID, address_indicator=False)

    decoded = json.loads(serialise(document(labels=(make_label(None, entry),))))
    assert decoded["labels"][0]["sources"][0]["label_basis"] == expected


def test_an_identify_source_never_reaches_a_serialised_label():
    """Spec §2.8 and §13, asserted at the last point before the file.

    `build_source_entry` refuses it, so no `Label` can be constructed and nothing can be
    serialised. Stated here because "never becomes a label" has to hold in the artifact, not
    only in the function that builds one.
    """
    from flabel.provenance import build_source_entry

    admission = make_admission(
        name="oisf/trafficid", source_class="identify", admission_basis="wholesale"
    )
    with pytest.raises(ValueError, match="identify"):
        build_source_entry(make_detection(source="oisf/trafficid"), admission, SNAPSHOT_ID)


# --- the bytes that reach the disk ----------------------------------------------------------
#
# `ensure_ascii=False` (spec §10) means the output carries whatever non-ASCII characters a
# third-party rule's `msg:` text contains. Every test above inspects a `str`, and a `str` cannot
# show the defect: `Path.write_text` encodes with the *locale* encoding, so the same correct
# string becomes `UnicodeEncodeError` under `LANG=C` and mojibake under cp1252 — both after the
# pipeline has already succeeded. These tests are about the encode step, so they assert bytes.

#: A rule msg with characters outside ASCII. Real feeds carry these: rule authors write in the
#: language they think in, and malware family names are not all Latin-1.
NON_ASCII_THREAT = "ET MALWARE Trojan.Крипт — beaconing to café.example"


def test_the_document_round_trips_through_utf8_bytes():
    """The encoding is bound in the library, not left to the caller's locale."""
    document = build_document(
        run={"flabel_version": "0.1.0"},
        labels=[make_label(None, make_entry(threat=NON_ASCII_THREAT))],
        unmatched=[],
    )

    raw = serialise_bytes(document)

    assert isinstance(raw, bytes)
    assert json.loads(raw.decode("utf-8"))["labels"][0]["sources"][0]["threat"] == NON_ASCII_THREAT


def test_non_ascii_threat_text_survives_as_characters_not_escapes():
    """`ensure_ascii=False` is the spec's choice; this proves it reaches the bytes intact.

    If `ensure_ascii` were ever flipped back on, the file would still parse to the same string —
    so a `json.loads` round-trip cannot catch it. The bytes can.
    """
    document = build_document(
        run={}, labels=[make_label(None, make_entry(threat=NON_ASCII_THREAT))], unmatched=[]
    )

    raw = serialise_bytes(document)

    assert "café".encode() in raw
    # The escape `ensure_ascii=True` would emit instead, spelled without a non-ASCII
    # literal in a bytes context.
    assert b"caf\\u00e9" not in raw


def test_the_bytes_are_writable_where_the_locale_cannot_encode_them(tmp_path):
    """The failure this helper exists to prevent, reproduced against the filesystem.

    `write_bytes` is unaffected by locale; `write_text` is not. Under `LANG=C` the second form
    raises `UnicodeEncodeError` — after a successful run, on the file that is the product.
    """
    document = build_document(
        run={}, labels=[make_label(None, make_entry(threat=NON_ASCII_THREAT))], unmatched=[]
    )
    path = tmp_path / "labels.json"

    path.write_bytes(serialise_bytes(document))

    assert json.loads(path.read_text(encoding="utf-8"))["labels"][0]["sources"][0]["threat"] == (
        NON_ASCII_THREAT
    )


# --- attribution follows the text, not the verdict ------------------------------------------
#
# Craig's decision, 2026-08-12. `unmatched_detections[].detection.threat` is verbatim rule
# `msg:` text from sources that asserted no label, and several admitted feeds are CC-BY,
# share-alike or copyleft. Scoping NOTICE to `labels[].sources` would make a licence obligation
# depend on whether a detection happened to correlate.


def test_a_source_reaching_only_an_unmatched_detection_is_still_attributed():
    """Its rule text is in labels.json just the same; only the verdict is absent."""
    manifest = make_manifest(
        make_admission(name="et/open", licence="MIT"),
        make_admission(name="pawpatrules", licence="CC-BY-SA-4.0"),
    )
    label = make_label(None, make_entry(source="et/open", licence="MIT"))
    stray = make_unmatched(source="pawpatrules", threat="PAW Suspicious TLS SNI")

    text = notice_module.render_notice((label,), manifest, (stray,))

    assert "pawpatrules" in text
    assert "share-alike" in text


def test_a_source_that_asserted_nothing_at_all_is_still_omitted():
    """The widening is to text that appears, not to the whole snapshot.

    NOTICE describes what was used; the snapshot describes what was available. Listing every
    feed would read as a claim that each contributed to this run.
    """
    manifest = make_manifest(
        make_admission(name="et/open", licence="MIT"),
        make_admission(name="abuse.ch/urlhaus", licence="CC0-1.0"),
    )
    label = make_label(None, make_entry(source="et/open", licence="MIT"))

    text = notice_module.render_notice((label,), manifest)

    assert "abuse.ch/urlhaus" not in text


def test_the_unmatched_licence_comes_from_the_snapshot_not_the_registry():
    """An unmatched detection carries no SourceEntry, so the manifest is the authority.

    Same rule as everywhere else: terms are frozen with the rules that fired, never read from
    data/sources.toml as it is today.
    """
    manifest = make_manifest(make_admission(name="stamus/lateral", licence="GPL-3.0-only"))
    stray = make_unmatched(source="stamus/lateral")

    licences = notice_module.labelling_sources((), (stray,), manifest)

    assert licences == {"stamus/lateral": "GPL-3.0-only"}


def test_every_licence_in_the_shipped_registry_has_attribution_text():
    """A new feed under an unlisted licence must fail the build, not degrade quietly.

    Without this, adding a tenth source under, say, Apache-2.0 makes NOTICE print "Licence
    terms not recorded in flabel" for a shipping feed — legally safe, operationally useless,
    and silent. NOTICE is the artifact with legal weight, so the gap should be loud.
    """
    from flabel.config import load_sources

    missing = sorted({spec.licence for spec in load_sources()} - set(notice_module.ATTRIBUTION))
    assert not missing, (
        f"sources.toml ships licences with no ATTRIBUTION entry: {missing}. "
        f"Add the obligation text rather than letting NOTICE fall back to UNRECORDED."
    )
