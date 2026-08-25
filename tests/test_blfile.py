"""`blfile` and the `labels-collection` document — spec-label-store §6.3, §6.4.

Pure wherever it can be. The document is built from composed flows and plain row dicts, so §6.4's
four corrections — the `{tier: run_id}` map, per-capture `coverage`, `origin.uri_status` beside
`selection.flows_without_origin`, and a `builder` pinning the store schema and `LABEL_KINDS` — are
checked on every push rather than on `fl-replay` alone (§2's testing line).

The fixtures come from `test_flabeldb_merge` on purpose: two copies of "what a `flow_labels` row
looks like" is the duplicate-authority defect this repo keeps catching, and a collection test that
agreed with itself about the row shape would prove nothing about the store.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from flabel import labels as labels_module
from flabel.models import LABEL_KINDS
from flabeldb import blfile, collection, merge
from test_flabeldb_merge import (
    CAPTURE,
    FLOW_KEY,
    OTHER_CAPTURE,
    TIER1_RUN,
    TIER2_RUN,
    authority_of,
    entry,
    flow_struct,
    row,
    source,
)

BUILT_AT = "2026-08-25T14:02:11.402931Z"
VERSION = "0.1.0"
URI = "gs://tempo-datasets-002-north-south/lax_capture_2026-07-08.pcap"
FILENAME = "lax_capture_2026-07-08.pcap"


# --- fixtures ------------------------------------------------------------------------------------


def sighting(*, run_id: str, capture: str = CAPTURE, recorded: bool = True, **overrides) -> dict:
    """One `captures` row — a SIGHTING of a capture at a path (§4.2), not the capture itself."""
    seen = {
        "capture_sha256": capture,
        "uri": URI if recorded else None,
        "uri_status": "gs" if recorded else collection.NOT_RECORDED,
        "filename": FILENAME,
        "link_type": 1,
        # PLURAL (§4.2, §6.1). A mergecap pcapng's interfaces need not agree.
        "snaplens": [262144],
        "observed_by_run_id": run_id,
    }
    seen.update(overrides)
    return seen


def run_block(
    *,
    unmatched: int = 0,
    unsupported: int = 0,
    detections: int = 10,
    input_status: str = "complete",
    fired: tuple[str, ...] = (),
) -> dict:
    """A `docs/spec.md` §10 run block, cut down to what §6.4's `coverage` reads."""
    conditions = {
        "input_truncated": False,
        "detection_uncorrelatable": False,
        "ja4_unavailable": False,
        "rules_failed_or_skipped": None,
        "tool_failure": False,
    }
    for name in fired:
        conditions[name] = True
    correlatable = detections - unsupported
    return {
        "schema_version": "2.0",
        "mode": "offline",
        "input": {"sha256": CAPTURE, "input_status": input_status, "uri": URI},
        "counts": {
            "flows": 40,
            "detections": detections,
            "labels": 3,
            "unmatched": unmatched,
            "unmatched_unsupported_transport": unsupported,
            "unmatched_ratio": (
                0.0 if correlatable <= 0 else (unmatched - unsupported) / correlatable
            ),
        },
        "loss_conditions": conditions,
    }


def run_row(run_id: str, block: dict | None = None) -> dict:
    """§4.1 stores the block as STRING so §6.4 can embed it verbatim; this is that string."""
    return {"run_id": run_id, "run_block": json.dumps(block if block else run_block())}


def built(
    *,
    rows=None,
    auth=None,
    sightings=None,
    run_rows=None,
    labels=("verdict",),
    arrange=None,
    **selection_kwargs,
) -> collection.Built:
    """Build a document from `rows`.

    `arrange` re-orders the composed flows before `collection.build` sees them, and it exists
    because of a sabotage that stayed green: `merge.compose` already emits flows sorted by
    `(capture, flow_key)`, so with a stable sort downstream, **`collection`'s own ordering rule is
    unobservable through `compose`** — dropping the `flow_key` tie-break entirely left every
    ordering test passing. A test that cannot see the rule it names is not testing it.
    """
    rows = [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])] if rows is None else rows
    auth = authority_of(tier2=TIER2_RUN) if auth is None else auth
    sightings = [sighting(run_id=TIER2_RUN)] if sightings is None else sightings
    run_rows = [run_row(TIER2_RUN)] if run_rows is None else run_rows
    merged = merge.compose(rows, auth)
    if arrange is not None:
        merged = dataclasses.replace(merged, flows=tuple(arrange(merged.flows)))
    return collection.build(
        merged=merged,
        auth=auth,
        sightings=sightings,
        run_rows=run_rows,
        selection=collection.Selection(labels=tuple(labels), **selection_kwargs),
        built_at=BUILT_AT,
        version=VERSION,
    )


# --- the document is not a labels.json ----------------------------------------------------------


def test_the_document_names_its_own_type_and_version():
    """§6.4, §9: a collection spans many runs, captures and snapshots, so `labels.json`'s single
    `run` block has no honest value to hold. A `labels.json` consumer fails on this, which is
    correct — and it must not be stamped with the pipeline's `schema_version`."""
    document = built().document
    assert document["document_type"] == "labels-collection"
    assert document["schema_version"] == "1.0"
    assert document["schema_version"] != labels_module.SCHEMA_VERSION
    assert "run" not in document
    assert isinstance(document["runs"], list)


def test_the_builder_pins_the_store_schema_and_label_kinds_not_just_its_own_version():
    """§6.4's fourth correction. The merge lives in `blfile` now, so `builder.version` covers it —
    but a changed `LABEL_KINDS` changes what `--label verdict` MEANS, and a changed schema changes
    what was read. Neither is the tool's version."""
    builder = built().document["builder"]
    assert builder == {
        "tool": "blfile",
        "version": VERSION,
        "store_schema": collection.store_schema_digest(),
        "label_kinds": collection.label_kinds_digest(),
    }
    assert len(builder["store_schema"]) == 16
    assert len(builder["label_kinds"]) == 16


def test_the_label_kinds_digest_moves_when_the_table_does(monkeypatch):
    """A digest that does not change when its subject does is decoration. Widening `threat-name`
    to tier 2 is exactly the edit §6.2 says is "purely additive" — and it changes what a document
    built before it means."""
    from flabel import models

    before = collection.label_kinds_digest()
    widened = dict(models.LABEL_KINDS)
    widened["threat-name"] = models.LabelKind(arity="single", tiers=(1, 2))
    monkeypatch.setattr(models, "LABEL_KINDS", widened)
    assert collection.label_kinds_digest() != before


def test_the_store_schema_digest_moves_when_a_column_moves(monkeypatch):
    """Column ORDER is part of the declaration — `schema.differences` compares it — so a
    reordering is a change this digest has to show. It is not sorted away."""
    from flabeldb import schema

    before = collection.store_schema_digest()
    table = schema.TABLES["runs"]
    reordered = dict(schema.TABLES)
    reordered["runs"] = schema.Table(
        description=table.description,
        fields=tuple(reversed(table.fields)),
        partition_field=table.partition_field,
        clustering=table.clustering,
    )
    monkeypatch.setattr(schema, "TABLES", reordered)
    assert collection.store_schema_digest() != before


# --- selection (§6.3) -----------------------------------------------------------------------------


def test_bare_blfile_selects_verdict():
    """§6.3. Not every kind: ANDing all of them would emit only flows carrying all of them."""
    assert blfile.DEFAULT_LABEL == "verdict"
    args = blfile.build_parser().parse_args([])
    assert args.label is None, "the default is applied in main, so --label stays distinguishable"
    assert built().document["selection"]["labels"] == ["verdict"]


def test_two_label_values_emit_only_flows_carrying_both():
    """§6.3's AND, and §9's "never emit a flow missing any requested label kind". Ragged rows are
    useless as training data and `docs/spec.md` §2.5 refuses to let absence be a signal."""
    with_threat = row(
        run_id=TIER1_RUN,
        sources=[source(tier=1, sid=700, name="panw")],
        flow_key="a" * 64,
        entries=[
            entry(name="verdict", value="malicious", tier=1, sids=[700]),
            entry(name="threat-name", value="Zbot", tier=1, sids=[700]),
        ],
    )
    verdict_only = row(run_id=TIER1_RUN, sources=[source(tier=1, sid=701, name="panw")])

    document = built(
        rows=[with_threat, verdict_only],
        auth=authority_of(tier1=TIER1_RUN),
        sightings=[sighting(run_id=TIER1_RUN)],
        run_rows=[run_row(TIER1_RUN)],
        labels=("verdict", "threat-name"),
    ).document

    assert document["selection"] == {
        "labels": ["verdict", "threat-name"],
        "match": "all",
        "captures": 1,
        "flows": 1,
        "flows_without_origin": 0,
    }
    assert [record["flow"]["flow_key"] for record in document["labels"]] == ["a" * 64]


def test_an_unknown_label_exits_2_naming_the_permitted_set(capsys):
    """§6.3."""
    assert blfile.main(["--label", "not-a-kind"]) == blfile.EXIT_USAGE
    message = capsys.readouterr().err
    assert "not-a-kind" in message
    assert "verdict" in message and "threat-name" in message


def test_blfile_reads_label_kinds_rather_than_a_second_copy_of_the_names(monkeypatch):
    """§6.2, and the 2026-08-19 placeholder sabotage is why this is asserted rather than assumed.

    A literal list of names here would agree with every test written against it — including this
    one — right up until `LABEL_KINDS` gained a kind and `blfile` did not. Adding a kind to the
    table must make `blfile` accept it, with nothing else edited.
    """
    assert blfile.unknown_labels(["mitre-technique"]) == ["mitre-technique"]
    monkeypatch.setattr(
        blfile, "LABEL_KINDS", {**LABEL_KINDS, "mitre-technique": LABEL_KINDS["verdict"]}
    )
    assert blfile.unknown_labels(["mitre-technique"]) == []


def test_the_document_filters_captures_by_digest():
    """§3.1 makes the digest the identity, so that is what the pure layer compares.

    The `<sha|name>` half of §6.3's contract is resolved one layer up, in `blfile.collect`, through
    the `captures` table — see the test below for why it cannot be done here.
    """
    here = row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])
    elsewhere = row(
        run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")], capture=OTHER_CAPTURE
    )
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN},
            {"capture_sha256": OTHER_CAPTURE, "tier": 1, "run_id": TIER1_RUN},
        ]
    )
    document = built(
        rows=[here, elsewhere],
        auth=auth,
        sightings=[
            sighting(run_id=TIER2_RUN),
            sighting(run_id=TIER1_RUN, capture=OTHER_CAPTURE, filename="other.pcap"),
        ],
        run_rows=[run_row(TIER2_RUN), run_row(TIER1_RUN)],
        captures=(CAPTURE,),
    ).document
    assert document["selection"]["captures"] == 1
    assert {record["origin"]["capture_sha256"] for record in document["labels"]} == {CAPTURE}


def test_capture_resolves_a_name_the_authoritative_run_never_saw(monkeypatch):
    """§6.3's `--capture <sha|name>`, and a defect measured 2026-08-25 before this test existed.

    §4.2's `captures` table is append-only — one row per SIGHTING, because a URI is a location and
    the digest is the identity — so one capture legitimately carries several names. `blfile` used
    to resolve the name to a digest in SQL and then filter **again** downstream, by name, against
    the authoritative run's sighting alone. Ask for the name an older run saw and every flow of a
    capture the store had resolved correctly was dropped: an empty collection at exit 0, which is
    the absence-as-a-signal failure `docs/spec.md` §2.5 exists to prevent.
    """
    seen = {}

    def capture_shas(bq, dataset, wanted):
        seen["wanted"] = list(wanted)
        return [CAPTURE]  # the table knows this name; the authoritative sighting does not

    def authoritative(bq, dataset, captures=()):
        seen["captures"] = list(captures)
        return [{"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN}]

    monkeypatch.setattr(blfile.query, "capture_shas", capture_shas)
    monkeypatch.setattr(blfile.query, "authoritative", authoritative)
    monkeypatch.setattr(
        blfile.query,
        "flow_labels",
        lambda bq, dataset, run_ids: [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])],
    )
    monkeypatch.setattr(
        blfile.query,
        "sightings",
        lambda bq, dataset, run_ids: [sighting(run_id=TIER2_RUN, filename="renamed-since.pcap")],
    )
    monkeypatch.setattr(blfile.query, "runs", lambda bq, dataset, run_ids: [run_row(TIER2_RUN)])

    result = blfile.collect(
        object(),
        "flabel",
        collection.Selection(labels=("verdict",), captures=("the-name-an-older-run-saw.pcap",)),
        built_at=BUILT_AT,
        version=VERSION,
    )
    assert seen["wanted"] == ["the-name-an-older-run-saw.pcap"]
    assert seen["captures"] == [CAPTURE], "the name must be resolved to a digest in SQL"
    assert result.document["selection"]["flows"] == 1
    assert result.document["selection"]["captures"] == 1


def test_a_capture_the_store_has_never_seen_selects_nothing_rather_than_everything(monkeypatch):
    """An unresolvable `--capture` must not fall through to an unrestricted query — that would
    silently build the whole corpus for a typo."""
    monkeypatch.setattr(blfile.query, "capture_shas", lambda bq, dataset, wanted: [])

    def refuse(*args, **kwargs):
        raise AssertionError("an unrestricted query was issued for an unknown capture")

    monkeypatch.setattr(blfile.query, "authoritative", refuse)
    monkeypatch.setattr(blfile.query, "flow_labels", lambda bq, dataset, run_ids: [])
    monkeypatch.setattr(blfile.query, "sightings", lambda bq, dataset, run_ids: [])
    monkeypatch.setattr(blfile.query, "runs", lambda bq, dataset, run_ids: [])

    result = blfile.collect(
        object(),
        "flabel",
        collection.Selection(labels=("verdict",), captures=("no-such.pcap",)),
        built_at=BUILT_AT,
        version=VERSION,
    )
    assert result.document["selection"]["flows"] == 0


def test_limit_caps_the_emitted_flows_after_ordering():
    """`--limit` is applied to the composed, ORDERED flows — never in SQL, and never earlier.

    A `LIMIT` on `flow_labels` would cut a flow's tier-2 row off from its tier-1 one and merge half
    of it. Limiting before the sort is the subtler version of the same fault: the flows that
    survive stop being a property of the data.

    **The fixture runs `flow_key` and `ts_first` in opposite directions on purpose.** With them
    ascending together — which is what this test had first — limiting before the sort selects the
    same two flows and the sabotage stays green.
    """
    rows = [
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2000 + index)],
            flow_key=f"{index:064d}",
            flow=flow_struct(ts_first=f"2026-07-08T12:00:0{3 - index}.000000Z"),
        )
        for index in range(4)
    ]
    document = built(rows=rows, limit=2).document
    assert document["selection"]["flows"] == 2
    assert [record["flow"]["flow_key"] for record in document["labels"]] == [
        f"{3:064d}",
        f"{2:064d}",
    ]


def test_a_limit_below_one_is_a_usage_error(capsys):
    """`--limit 0` selects nothing, which is not what an operator typing it means."""
    assert blfile.main(["--limit", "0"]) == blfile.EXIT_USAGE
    assert "--limit 0" in capsys.readouterr().err


# --- origin (§6.4) --------------------------------------------------------------------------------


def test_origin_run_ids_is_a_tier_to_run_id_map_naming_every_contributing_tier():
    """§6.4's first correction. A merged record's `sources` can hold a tier-1 entry from an August
    replay run and a tier-2 entry from a December offline run — a `Label` no single run asserted —
    and `docs/spec.md` §13 requires every assertion to NAME what produced it. A flat list is
    "recoverable with effort by cross-referencing three fields", which is weaker than that."""
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[sighting(run_id=TIER1_RUN), sighting(run_id=TIER2_RUN)],
        run_rows=[run_row(TIER1_RUN), run_row(TIER2_RUN)],
    ).document

    (record,) = document["labels"]
    assert record["origin"]["run_ids"] == {"1": TIER1_RUN, "2": TIER2_RUN}


def test_a_flow_with_no_recorded_origin_is_refused_and_counted():
    """§6.4, §9. Every run in the archive predates `--source-uri`, so the headline requirement is
    unmet for all of them — `uri_status: not-recorded` and this count are what make that visible
    instead of silent."""
    result = built(sightings=[sighting(run_id=TIER2_RUN, recorded=False)])
    assert result.document["labels"] == []
    assert result.document["selection"]["flows"] == 0
    assert result.document["selection"]["flows_without_origin"] == 1
    assert result.flows_without_origin == 1


def test_allow_missing_origin_emits_it_and_the_count_is_published_either_way():
    """§6.4: "and the count is published either way". The flag changes what is emitted, never
    whether the shortfall is reported."""
    result = built(
        sightings=[sighting(run_id=TIER2_RUN, recorded=False)], allow_missing_origin=True
    )
    (record,) = result.document["labels"]
    assert record["origin"]["uri"] is None
    assert record["origin"]["uri_status"] == "not-recorded"
    assert result.document["selection"]["flows_without_origin"] == 1
    assert result.document["selection"]["flows"] == 1


def test_origin_takes_the_lowest_tier_that_actually_recorded_one():
    """§6.5 resolves origin by "the lowest surviving tier's run when two tiers DISAGREE", and a
    `not-recorded` sighting is not a disagreeing value — §4.2 added `uri_status` precisely so a
    null `uri` is one fact rather than two.

    This matters today, not hypothetically: every archived run predates `--source-uri`, so a strict
    lowest-tier rule would refuse a flow whose origin the store demonstrably holds from a newer run
    at the other tier.
    """
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[
            sighting(run_id=TIER1_RUN, recorded=False),
            sighting(run_id=TIER2_RUN, recorded=True),
        ],
        run_rows=[run_row(TIER1_RUN), run_row(TIER2_RUN)],
    ).document

    (record,) = document["labels"]
    assert record["origin"]["uri"] == URI
    assert record["origin"]["uri_status"] == "gs"
    assert document["selection"]["flows_without_origin"] == 0


def test_two_recorded_origins_still_resolve_by_the_lowest_tier():
    """The half of §6.5 that IS about a disagreement. A URI is a location and the digest is the
    identity (§4.2), so two sightings of one capture at two paths are both true — and the pick has
    to be a property of the data rather than of row order."""
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[
            sighting(run_id=TIER2_RUN, uri="gs://bucket/later.pcap"),
            sighting(run_id=TIER1_RUN, uri="gs://bucket/earlier.pcap"),
        ],
        run_rows=[run_row(TIER1_RUN), run_row(TIER2_RUN)],
    ).document

    (record,) = document["labels"]
    assert record["origin"]["uri"] == "gs://bucket/earlier.pcap"


def test_snaplens_is_plural_in_the_document_too():
    """§6.4's example literal said `snaplen`; §4.2, §6.1 and the `captures` column are plural, and
    §4.2 records that this exact drift already had to be corrected once at LS-3.

    A single value would have to invent a winner where a mergecap pcapng's interfaces disagree —
    measured 96 and 65535 — which is the one fact the field exists to expose, since Zeek refuses a
    merge across differing snapshot lengths.
    """
    document = built(sightings=[sighting(run_id=TIER2_RUN, snaplens=[96, 65535])]).document
    (record,) = document["labels"]
    assert record["origin"]["snaplens"] == [96, 65535]
    assert "snaplen" not in record["origin"]


# --- coverage (§6.4) ------------------------------------------------------------------------------


def test_coverage_is_present_per_capture_and_matches_the_run_blocks_counts():
    """§6.4's second correction. §4.4 stores `unmatched` precisely so a consumer is not misled by a
    short label list, and revision 1's document dropped it — re-creating the misreading at corpus
    level. `docs/spec.md` §10 requires this answerable in one lookup."""
    block = run_block(unmatched=3, unsupported=1, detections=20, fired=("ja4_unavailable",))
    document = built(run_rows=[run_row(TIER2_RUN, block)]).document

    (record,) = document["labels"]
    coverage = record["origin"]["coverage"]
    assert coverage["input_status"] == block["input"]["input_status"]
    assert coverage["unmatched"] == block["counts"]["unmatched"]
    assert coverage["loss_conditions_fired"] == ["ja4_unavailable"]


def test_a_single_runs_coverage_ratio_is_the_run_blocks_own_ratio():
    """The formula, pinned to the model that publishes it.

    `unmatched_ratio` is **not** `unmatched / detections`: `docs/spec.md` §10 says outright that it
    excludes unsupported-transport detections, because a detection on ESP or SCTP was never going
    to correlate (#84). Recomputing it the obvious way would quietly publish a different number
    from the one the run was gated on.
    """
    block = run_block(unmatched=5, unsupported=2, detections=20)
    document = built(run_rows=[run_row(TIER2_RUN, block)]).document

    (record,) = document["labels"]
    assert record["origin"]["coverage"]["unmatched_ratio"] == block["counts"]["unmatched_ratio"]
    assert record["origin"]["coverage"]["unmatched_ratio"] != (
        block["counts"]["unmatched"] / block["counts"]["detections"]
    )


def test_coverage_aggregates_across_the_captures_authoritative_runs():
    """A capture can be supplied by two runs, one per tier. Quoting only the lowest tier's block
    would report `unmatched: 0` over a capture whose tier-2 run left seven detections unplaced —
    which is the misreading `coverage` exists to prevent, one level up."""
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[sighting(run_id=TIER1_RUN), sighting(run_id=TIER2_RUN)],
        run_rows=[
            run_row(TIER1_RUN, run_block(unmatched=3, detections=40, fired=("ja4_unavailable",))),
            run_row(
                TIER2_RUN,
                run_block(unmatched=7, detections=60, fired=("rules_failed_or_skipped",)),
            ),
        ],
    ).document

    (record,) = document["labels"]
    coverage = record["origin"]["coverage"]
    assert coverage["unmatched"] == 10
    assert coverage["unmatched_ratio"] == 10 / 100
    assert coverage["loss_conditions_fired"] == ["ja4_unavailable", "rules_failed_or_skipped"]


def test_a_null_loss_condition_is_not_a_fired_one():
    """§10: each flag is `null` rather than `false` when the stage that would know never ran, and
    "JA4 was fine" and "nothing ever probed JA4" are different facts. Only `True` fires."""
    block = run_block()
    assert block["loss_conditions"]["rules_failed_or_skipped"] is None
    document = built(run_rows=[run_row(TIER2_RUN, block)]).document
    (record,) = document["labels"]
    assert record["origin"]["coverage"]["loss_conditions_fired"] == []


def test_input_status_is_partial_if_any_contributing_run_read_the_capture_short():
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[sighting(run_id=TIER1_RUN), sighting(run_id=TIER2_RUN)],
        run_rows=[
            run_row(TIER1_RUN, run_block(input_status="complete")),
            run_row(TIER2_RUN, run_block(input_status="partial")),
        ],
    ).document
    (record,) = document["labels"]
    assert record["origin"]["coverage"]["input_status"] == "partial"


def test_an_unmeasured_count_is_null_rather_than_zero():
    """`docs/spec.md` §10 is emphatic that a null count means "not measured". Reporting zero would
    assert that nothing was lost about a capture nobody counted."""
    block = run_block()
    block["counts"]["unmatched"] = None
    document = built(run_rows=[run_row(TIER2_RUN, block)]).document
    (record,) = document["labels"]
    assert record["origin"]["coverage"]["unmatched"] is None
    assert record["origin"]["coverage"]["unmatched_ratio"] is None


# --- the run blocks, verbatim ---------------------------------------------------------------------


def test_run_blocks_are_embedded_verbatim_and_ordered_by_run_id():
    """§4.1 stores `run_block` as STRING, not JSON, precisely so this is possible: the JSON type
    normalises on ingest — sorts keys, drops duplicates, renders 12.30 as 12.3 — and a normalising
    column cannot be verbatim."""
    block = run_block(unmatched=2)
    block["warnings"] = ["something the pipeline said"]
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[sighting(run_id=TIER1_RUN), sighting(run_id=TIER2_RUN)],
        run_rows=[run_row(TIER2_RUN, block), run_row(TIER1_RUN)],
    ).document

    assert document["runs"][0] == json.loads(run_row(TIER1_RUN)["run_block"])
    assert document["runs"][1] == block
    assert TIER1_RUN < TIER2_RUN, "the fixture must actually exercise the ordering"


# --- canonical ordering and serialisation (§6.4, `docs/spec.md` §10) ------------------------------


def test_flows_are_ordered_by_capture_then_time_then_flow_key():
    """§6.4: `flow_key` replaces `uid` as the tie-break, since §3.2 disqualifies `uid` from
    carrying ordering meaning — under `-D` a uid is positional, "connection #N" in every capture.

    **`arrange` hands the flows over in descending key order, and without it this test proves
    nothing.** `merge.compose` already emits them sorted by `(capture, flow_key)` and `sorted` is
    stable, so deleting the tie-break from `collection.build` left this passing — a sabotage that
    stayed green, and the escape was here rather than in the code.
    """
    same_time = "2026-07-08T12:00:00.000000Z"
    rows = [
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2001)],
            flow_key="b" * 64,
            flow=flow_struct(ts_first=same_time),
        ),
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2002)],
            flow_key="a" * 64,
            flow=flow_struct(ts_first=same_time),
        ),
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2003)],
            flow_key="c" * 64,
            flow=flow_struct(ts_first="2026-07-08T11:00:00.000000Z"),
        ),
    ]
    document = built(
        rows=rows,
        arrange=lambda flows: sorted(flows, key=lambda record: record.flow_key, reverse=True),
    ).document
    assert [record["flow"]["flow_key"] for record in document["labels"]] == [
        "c" * 64,
        "a" * 64,
        "b" * 64,
    ]


def test_labels_within_a_record_are_sorted_by_name():
    document = built(
        rows=[
            row(
                run_id=TIER1_RUN,
                sources=[source(tier=1, sid=700, name="panw")],
                entries=[
                    entry(name="verdict", value="malicious", tier=1, sids=[700]),
                    entry(name="threat-name", value="Zbot", tier=1, sids=[700]),
                ],
            )
        ],
        auth=authority_of(tier1=TIER1_RUN),
        sightings=[sighting(run_id=TIER1_RUN)],
        run_rows=[run_row(TIER1_RUN)],
    ).document
    (record,) = document["labels"]
    assert [item["name"] for item in record["labels"]] == ["threat-name", "verdict"]


def test_the_serialiser_is_byte_for_byte_labels_jsons():
    """Two copies of `docs/spec.md` §10's encoder settings is the duplicate-authority defect.

    `collection.serialise` cannot import `labels.serialise` — `tests/test_architecture.py` shares
    only `flabel.models` with the store, and `labels.py` is a pipeline module — so the two are
    pinned to each other here instead. `allow_nan=False` is part of what is being pinned: the
    default emits bare `NaN`, which Python reads back and no strict parser accepts.
    """
    document = built().document
    assert collection.serialise(document) == labels_module.serialise(document)
    assert collection.serialise(document).endswith("}\n")


def test_a_non_finite_ratio_is_refused_rather_than_shipped():
    """`allow_nan=False`, which the pin above only covers while the sample document is finite."""
    document = built().document
    document["labels"][0]["origin"]["coverage"]["unmatched_ratio"] = float("inf")
    with pytest.raises(ValueError):
        collection.serialise(document)


def test_the_timestamp_format_is_the_one_labels_json_uses():
    """`docs/spec.md` §10's one timestamp format, pinned across the same architecture boundary."""
    for ts in (0.0, 1783166400.5, 1783166400.123456):
        assert collection._iso(ts) == labels_module.iso_from_epoch(ts)


def test_a_flow_carries_the_stores_struct_plus_its_key():
    """§4.3 is a superset of `labels.json`'s flow: `ip_proto` and the canonical pair are the
    content-derived halves of the flow key, and §3.2 measured two ESP conversations between one
    host pair written with identical 5-tuples — so without `ip_proto` the key degenerates."""
    (record,) = built().document["labels"]
    assert record["flow"]["flow_key"] == FLOW_KEY
    assert record["flow"]["ip_proto"] == 6
    assert record["flow"]["zeek_uid"] == "CabCdE1"
    assert record["flow"]["ts_first"] == "2026-07-08T12:00:00.000000Z"


# --- the CLI --------------------------------------------------------------------------------------


def test_a_cross_tier_conflict_exits_1_rather_than_being_reported_as_a_defect(monkeypatch, capsys):
    """§9's "must never silently pick a winner", at the exit-code layer. 1 is a statement about the
    DATA; 3 would say `blfile` is broken, and a bare `raise` reaches the interpreter as 1 — which
    is why nothing in `main` re-raises."""
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        blfile,
        "collect",
        _raising(merge.MergeConflict("tiers disagree on single-arity label 'verdict'")),
    )
    assert blfile.main([]) == blfile.EXIT_REFUSED
    assert "disagreement" in capsys.readouterr().err


def test_an_inconsistent_view_exits_1_and_not_3(monkeypatch, capsys):
    """`merge.authority` raising is a statement about the store, not a defect in this file."""
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        blfile, "collect", _raising(merge.StoreInconsistent("two runs for capture … tier 2"))
    )
    assert blfile.main([]) == blfile.EXIT_REFUSED
    assert "inconsistent" in capsys.readouterr().err


def test_a_bare_value_error_is_a_defect_and_not_a_report_about_the_store(monkeypatch, capsys):
    """The handler above is a NAMED class, and this is why it has to be.

    `except ValueError` was what it caught first, and that is far broader than the code it
    publishes: `json.JSONDecodeError` **is** a `ValueError`, and so is every ordinary coding slip —
    `min()` on an empty sequence, `int()` on garbage. A bug in `collection.build` reported itself as
    a disagreement in the dataset, which is the failure the `MergeConflict`-is-not-a-`ValueError`
    rule exists to prevent, one level up.
    """
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect", _raising(ValueError("min() arg is an empty sequence")))
    assert blfile.main([]) == blfile.EXIT_INTERNAL
    assert "DEFECT in blfile" in capsys.readouterr().err


def test_a_run_block_that_will_not_parse_names_the_run(monkeypatch, capsys):
    """`json.JSONDecodeError` from three frames down tells an operator nothing about which row is
    corrupt — and being a `ValueError`, it used to reach the handler above."""
    with pytest.raises(merge.StoreInconsistent, match=TIER2_RUN):
        collection.build(
            merged=merge.compose(
                [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])],
                authority_of(tier2=TIER2_RUN),
            ),
            auth=authority_of(tier2=TIER2_RUN),
            sightings=[sighting(run_id=TIER2_RUN)],
            run_rows=[{"run_id": TIER2_RUN, "run_block": '{"counts": {'}],
            selection=collection.Selection(labels=("verdict",)),
            built_at=BUILT_AT,
            version=VERSION,
        )


def test_an_unrecognised_failure_exits_3_so_exit_1_can_only_mean_the_store(monkeypatch, capsys):
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect", _raising(KeyError("flow_key")))
    assert blfile.main([]) == blfile.EXIT_INTERNAL
    assert "DEFECT in blfile" in capsys.readouterr().err


def test_a_missing_project_or_extra_reads_as_a_sentence_and_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(blfile.client_module, "client", _raising(RuntimeError("no project: …")))
    assert blfile.main([]) == blfile.EXIT_USAGE
    assert "no project" in capsys.readouterr().err


def test_a_malformed_dataset_never_reaches_a_credential(monkeypatch, capsys):
    """Checked BEFORE the client is built. The name is interpolated into SQL, and `apply`'s view
    path runs `CREATE OR REPLACE VIEW` as `dataOwner`."""

    def refuse(**kwargs):
        raise AssertionError("a client was built for a name that is not an identifier")

    monkeypatch.setattr(blfile.client_module, "client", refuse)
    assert blfile.main(["--dataset", "flabel;DROP"]) == blfile.EXIT_USAGE
    assert "not a BigQuery identifier" in capsys.readouterr().err


def test_the_identifier_pattern_is_flabel_dbs_and_not_a_second_copy():
    from flabeldb import cli

    assert blfile.IDENTIFIER is cli.IDENTIFIER


def test_output_is_written_as_utf_8_regardless_of_the_locale(monkeypatch, tmp_path):
    """`Path.write_text` encodes with the LOCALE encoding — under `LANG=C` that is ASCII, so one
    accented character in a rule's `msg` raises AFTER the whole collection has been built."""
    result = built(
        rows=[
            row(
                run_id=TIER2_RUN,
                sources=[source(tier=2, sid=2001, threat="Trojan Ratón")],
            )
        ]
    )
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect", lambda *args, **kwargs: result)
    target = tmp_path / "collection.json"
    assert blfile.main(["--output", str(target)]) == blfile.EXIT_OK

    document = json.loads(target.read_bytes().decode("utf-8"))
    assert document["labels"][0]["sources"][0]["threat"] == "Trojan Ratón"


def test_the_shortfall_is_said_out_loud_on_stderr(monkeypatch, capsys):
    """`docs/spec.md` §2.5 refuses to let absence be a signal, and a collection that came back
    empty because every flow was refused looks exactly like a corpus with nothing malicious in
    it."""
    result = built(sightings=[sighting(run_id=TIER2_RUN, recorded=False)])
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect", lambda *args, **kwargs: result)
    assert blfile.main([]) == blfile.EXIT_OK

    message = capsys.readouterr().err
    assert "no recorded origin" in message
    assert "REFUSED" in message
    assert "--allow-missing-origin" in message


def test_a_refused_flow_is_named_on_stderr_rather_than_only_counted(monkeypatch, capsys):
    """§9's counted refusal, on §3.2's precedent: refuse the row, count it, **record it**."""
    result = built(
        rows=[
            row(
                run_id=TIER2_RUN,
                sources=[source(tier=2, sid=2001)],
                entries=[
                    entry(name="verdict", value="malicious", tier=2, sids=[2001]),
                    entry(name="threat-name", value="Zbot", tier=2, sids=[2001]),
                ],
            )
        ]
    )
    assert result.refused == 1
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect", lambda *args, **kwargs: result)
    assert blfile.main([]) == blfile.EXIT_OK

    message = capsys.readouterr().err
    assert "could not be composed" in message
    assert "threat-name" in message
    assert "run_exclusions" in message


def _raising(error):
    def raise_it(*args, **kwargs):
        raise error

    return raise_it


# --- what the review of 2026-08-25 found ---------------------------------------------------------


def test_the_ratio_is_pinned_to_the_model_and_not_to_the_test_fixture():
    """`collection._ratio` is a hand-copy of `models.CorrelationResult.unmatched_ratio`.

    It was pinned to a THIRD hand-copy — the one in `run_block` above — so a change to the model's
    formula would leave `collection` and the fixture wrong together with every test green. Pinned to
    the model itself now, which is the only copy that is authoritative.
    """
    from flabel.models import CorrelationResult

    for detections, unmatched, unsupported in [(20, 5, 2), (10, 0, 0), (7, 7, 7), (100, 3, 0)]:
        model = CorrelationResult(
            labels=(),
            unmatched=tuple(
                _unmatched_detection(
                    reason="unsupported_transport" if index < unsupported else "no_flow_match"
                )
                for index in range(unmatched)
            ),
            flows_total=40,
            detections_total=detections,
        )
        assert collection._ratio(unmatched, unsupported, detections) == model.unmatched_ratio, (
            f"detections={detections} unmatched={unmatched} unsupported={unsupported}"
        )


def test_a_missing_unsupported_count_nulls_the_ratio_instead_of_publishing_the_forbidden_one():
    """The asymmetry that was the defect.

    With `unsupported or 0`, a contributing run that never published
    `counts.unmatched_unsupported_transport` — every run predating #84 — reduced the ratio to
    exactly `unmatched / detections`, which `docs/spec.md` §10 says does not reproduce the published
    number. A missing `unmatched` made the ratio null and loud; a missing `unsupported` made it
    wrong and quiet.
    """
    block = run_block(unmatched=5, detections=20)
    block["counts"]["unmatched_unsupported_transport"] = None
    document = built(run_rows=[run_row(TIER2_RUN, block)]).document
    (record,) = document["labels"]
    assert record["origin"]["coverage"]["unmatched_ratio"] is None
    assert record["origin"]["coverage"]["unmatched_ratio"] != 5 / 20


def test_a_count_only_some_contributing_runs_measured_is_null_not_a_partial_sum():
    """§10: a null count means "not measured". Summing the runs that DID measure publishes one
    run's number as though it described the capture — "measured as none" standing in for "not
    measured", which is §2.5's whole subject."""
    partial = run_block(unmatched=7, detections=40)
    silent = run_block(unmatched=0, detections=60)
    silent["counts"]["unmatched"] = None
    document = built(
        rows=[
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        auth=authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
        sightings=[sighting(run_id=TIER1_RUN), sighting(run_id=TIER2_RUN)],
        run_rows=[run_row(TIER1_RUN, partial), run_row(TIER2_RUN, silent)],
    ).document
    (record,) = document["labels"]
    assert record["origin"]["coverage"]["unmatched"] is None, "7 was published as the capture total"


def test_flows_from_two_captures_are_ordered_by_capture_first():
    """§6.4's ordering is `(origin.capture_sha256, flow.ts_first, flow_key)`, and nothing exercised
    the primary key: every ordering fixture built one capture, so deleting `capture_sha256` from the
    sort left the suite green and two captures' flows would interleave by time."""
    here = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2001)],
        flow=flow_struct(ts_first="2026-07-08T23:00:00.000000Z"),
    )
    elsewhere = row(
        run_id=TIER1_RUN,
        sources=[source(tier=1, sid=700, name="panw")],
        capture=OTHER_CAPTURE,
        flow=flow_struct(ts_first="2026-07-08T01:00:00.000000Z"),
    )
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN},
            {"capture_sha256": OTHER_CAPTURE, "tier": 1, "run_id": TIER1_RUN},
        ]
    )
    document = built(
        rows=[here, elsewhere],
        auth=auth,
        sightings=[
            sighting(run_id=TIER2_RUN),
            sighting(run_id=TIER1_RUN, capture=OTHER_CAPTURE, filename="other.pcap"),
        ],
        run_rows=[run_row(TIER2_RUN), run_row(TIER1_RUN)],
    ).document
    # CAPTURE ("aaa…") sorts before OTHER_CAPTURE ("bbb…") even though its flow is 22 hours later.
    assert CAPTURE < OTHER_CAPTURE
    assert [record["origin"]["capture_sha256"] for record in document["labels"]] == [
        CAPTURE,
        OTHER_CAPTURE,
    ]


def test_non_ascii_survives_the_serialiser_unescaped():
    """`ensure_ascii=False` is a `docs/spec.md` §10 setting, and neither pin could see it: the
    byte-for-byte comparison used an all-ASCII document, and the UTF-8 round-trip went through
    `json.loads`, which decodes `\\u00f3` identically. The output carries whatever non-ASCII a
    third-party rule's `msg:` text contains."""
    document = built(
        rows=[row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001, threat="Trojan Ratón")])]
    ).document
    text = collection.serialise(document)
    assert "Ratón" in text
    assert "\\u00f3" not in text
    assert text == labels_module.serialise(document)


def test_an_unwritable_output_path_is_the_operators_problem_not_the_stores(monkeypatch, capsys):
    """The most ordinary mistake there is, and it used to escape `main` entirely and reach the
    interpreter as exit 1 — the code this tool publishes as "the store holds a disagreement". An
    automation wrapper branching on 1 would have reported a corrupt dataset for a typo'd path."""
    result = built()
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect", lambda *args, **kwargs: result)
    assert blfile.main(["--output", "/no/such/directory/c.json"]) == blfile.EXIT_USAGE
    message = capsys.readouterr().err
    assert "cannot write" in message
    assert blfile.EXIT_USAGE != blfile.EXIT_REFUSED


def test_the_output_lands_through_a_temporary_so_a_kill_leaves_no_half_file(monkeypatch, tmp_path):
    """`models.partial_name`'s convention and issue #70. A collection is a larger, slower write than
    `labels.json` and is what a training pipeline consumes, so a killed process must not leave a
    half-written file that looks finished."""
    from flabel import models

    seen = {}
    real = blfile.os.replace

    def watched(src, dst):
        seen["src"] = str(src)
        return real(src, dst)

    monkeypatch.setattr(blfile.os, "replace", watched)
    target = tmp_path / "collection.json"
    blfile.write_document(target, '{"ok": true}\n')

    assert seen["src"].endswith(models.PARTIAL_SUFFIX), seen
    assert models.is_partial(seen["src"])
    assert target.read_text() == '{"ok": true}\n'
    assert list(tmp_path.iterdir()) == [target], "the temporary must not survive"


def test_a_capture_name_resolving_to_several_digests_is_said_out_loud(monkeypatch, capsys):
    """§3.1 says the digest is the identity. Two captures both named `capture.pcap` — ordinary on a
    box ingesting daily files — make one `--capture` value build a collection over both, and
    silently widening a restriction is the opposite of what the operator asked for."""
    monkeypatch.setattr(
        blfile.query, "capture_shas", lambda bq, dataset, wanted: [CAPTURE, OTHER_CAPTURE]
    )
    monkeypatch.setattr(blfile.query, "authoritative", lambda bq, dataset, captures=(): [])
    monkeypatch.setattr(blfile.query, "flow_labels", lambda bq, dataset, run_ids: [])
    monkeypatch.setattr(blfile.query, "sightings", lambda bq, dataset, run_ids: [])
    monkeypatch.setattr(blfile.query, "runs", lambda bq, dataset, run_ids: [])
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())

    assert blfile.main(["--capture", "capture.pcap"]) == blfile.EXIT_OK
    message = capsys.readouterr().err
    assert "1 --capture value(s) resolved to 2 capture(s)" in message
    assert CAPTURE in message and OTHER_CAPTURE in message


def _unmatched_detection(*, reason: str):
    """One `models.UnmatchedDetection`, built only so `CorrelationResult` can derive its ratio."""
    from flabel.models import Detection, UnmatchedDetection

    return UnmatchedDetection(
        detection=Detection(
            source="et-open",
            tier=2,
            sid=2001,
            rev=1,
            classtype=None,
            app_proto=None,
            threat="t",
            ts=0.0,
            src_ip="1.1.1.1",
            src_port=1,
            dst_ip="2.2.2.2",
            dst_port=2,
            proto="tcp",
            direction="to_server",
        ),
        reason=reason,
    )
