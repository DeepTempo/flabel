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
    BOTH_RUN,
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
        # Inputs, so §6.5's `--rebuild` reads the selection instead of inferring it.
        "limit": None,
        "allow_missing_origin": False,
        "as_of": None,
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

    def authoritative(bq, dataset, captures=(), *, as_of=None):
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

    # §6.4's literal is `{ "run_id": "…", "…": "the run block, verbatim" }` — the id BESIDE the
    # block, which LS-7 omitted and §6.5's `--rebuild` needs as its pinned set.
    assert document["runs"][0] == {
        "run_id": TIER1_RUN,
        "capture_sha256": CAPTURE,
        "supplies": [1],
        **json.loads(run_row(TIER1_RUN)["run_block"]),
    }
    assert document["runs"][1] == {
        "run_id": TIER2_RUN,
        "capture_sha256": CAPTURE,
        "supplies": [2],
        **block,
    }
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
    monkeypatch.setattr(
        blfile.query, "authoritative", lambda bq, dataset, captures=(), *, as_of=None: []
    )
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


# --- LS-9: reproduction (§6.5) --------------------------------------------------------------------


def prior_document(**kwargs) -> dict:
    """A prior collection, **round-tripped through JSON** the way `--rebuild` reads one.

    The round trip is the point. `dataclasses.asdict` leaves `sids` as a tuple and `json.loads`
    yields a list, so a fixture built in memory and compared to another built in memory agrees on
    something a real rebuild never sees. Measured against production before this was fixed: every
    one of 20 records was reported as differing, on nothing but `(40151,) != [40151]`.
    """
    return json.loads(collection.serialise(built(**kwargs).document))


def test_the_document_records_the_run_ids_it_was_built_from():
    """§6.4's literal is `{ "run_id": "…", "…": "the run block, verbatim" }`, and LS-7 emitted only
    the block — so the document did not name its own runs and §6.5 had no pinned set to read.

    `origin.run_ids` is not a substitute: it names only the runs that contributed an EMITTED flow,
    so a run whose flows were all refused for missing origin, or truncated away by `--limit`, is
    absent from it.
    """
    document = prior_document()
    assert [entry["run_id"] for entry in document["runs"]] == [TIER2_RUN]
    block = json.loads(run_row(TIER2_RUN)["run_block"])
    assert document["runs"][0] == {
        "run_id": TIER2_RUN,
        "capture_sha256": CAPTURE,
        # **The tiers this run SUPPLIES here**, which is not the same as what it attested.
        "supplies": [2],
        **block,
    }
    for key in ("run_id", "capture_sha256", "supplies"):
        assert key not in block, f"the run block has no {key} of its own, so nothing is shadowed"


def test_the_selection_records_its_inputs_so_rebuild_reads_rather_than_infers():
    document = prior_document(limit=1, allow_missing_origin=True, as_of="2026-08-25T00:00:00Z")
    assert document["selection"]["limit"] == 1
    assert document["selection"]["allow_missing_origin"] is True
    assert document["selection"]["as_of"] == "2026-08-25T00:00:00Z"


def test_read_prior_takes_the_selection_and_the_pinned_run_set():
    prior = collection.read_prior(prior_document(limit=5, allow_missing_origin=True))
    assert prior.pinned_runs == (TIER2_RUN,)
    assert prior.selection.labels == ("verdict",)
    assert prior.selection.limit == 5
    assert prior.selection.allow_missing_origin is True


def test_read_prior_carries_the_cutoff_so_the_rebuilt_document_still_records_it():
    """**A document built with `--as-of` could not be reproduced at all**, and the failure message
    blamed the store.

    `read_prior` dropped the cutoff while `comparable` kept `selection.as_of` in the comparison, so
    the rebuild wrote `as_of: null` against a document that said otherwise: one difference, and
    `blfile` exited 1 announcing that "the rows those runs hold have changed". Nothing had changed.

    Carrying it forward is inert for querying — the authority is read from the document, so no
    cutoff is re-applied — and §6.5 refuses `--rebuild --as-of` on the COMMAND LINE, which is not
    the same as forgetting what the document said.

    **The document must actually carry a cutoff for this to mean anything.** An earlier version of
    this test used one whose `as_of` was already null, so carrying and dropping were
    indistinguishable and the sabotage stayed green.
    """
    document = prior_document(as_of="2026-08-25T00:00:00Z")
    assert document["selection"]["as_of"] == "2026-08-25T00:00:00Z"
    assert collection.read_prior(document).selection.as_of == "2026-08-25T00:00:00Z"


def test_read_prior_refuses_a_labels_json():
    """§9 forbids a collection stamped with `labels.json`'s version, and the other direction matters
    as much: handed a labels.json, `--rebuild` would read no selection, rebuild from an empty pinned
    set, and report a perfect reproduction of nothing."""
    with pytest.raises(collection.NotACollection, match="document_type"):
        collection.read_prior({"schema_version": "2.0", "run": {}, "labels": []})


def test_read_prior_refuses_a_document_version_it_cannot_reproduce():
    document = prior_document()
    document["schema_version"] = "0.9"
    with pytest.raises(collection.NotACollection, match="schema_version"):
        collection.read_prior(document)


def test_read_prior_refuses_a_document_written_before_run_ids_were_recorded():
    """Documents LS-7 wrote have `runs[]` entries with no `run_id`. Refusing names the reason rather
    than rebuilding from an empty pin and calling it a reproduction."""
    document = prior_document()
    document["runs"] = [
        {key: value for key, value in document["runs"][0].items() if key != "run_id"}
    ]
    with pytest.raises(collection.NotACollection, match="runs\\[0\\]"):
        collection.read_prior(document)


def test_reproduction_is_over_records_with_built_at_excluded():
    """§6.5, and the same correction `docs/spec.md` §10 already made for a run's output: byte
    identity is unachievable, so the comparison is over records."""
    first = prior_document()
    second = json.loads(collection.serialise(built().document))
    second["built_at"] = "2099-01-01T00:00:00.000000Z"
    assert first["built_at"] != second["built_at"]
    assert collection.differences(collection.comparable(first), collection.comparable(second)) == []


def test_a_tuple_and_a_list_of_the_same_sids_are_not_a_difference():
    """**The bug that made `--rebuild` incapable of ever reproducing anything.**

    One side of the comparison comes from `json.loads` of a file, the other is built in memory where
    `dataclasses.asdict` leaves `sids` a tuple — and `(40151,)` does not equal `[40151]`. Against
    the production store every record was reported as differing on nothing else. A document is JSON,
    so the value compared is the JSON value.
    """
    in_memory = built().document
    from_file = json.loads(collection.serialise(in_memory))
    assert isinstance(in_memory["labels"][0]["labels"][0]["sids"], tuple)
    assert isinstance(from_file["labels"][0]["labels"][0]["sids"], list)
    assert (
        collection.differences(collection.comparable(from_file), collection.comparable(in_memory))
        == []
    )


def test_the_outcome_counts_are_not_part_of_the_reproduction():
    """Measured against production: a `--limit 20` document pins only the runs whose flows survived
    truncation, while its `flows_without_origin` counted the whole pre-limit selection — 408 against
    20. Rebuilding from the pin asks a narrower question and honestly reports the smaller number.

    Dropping the counts costs no detection: a changed flow count IS an added or removed record.
    """
    assert set(collection.SELECTION_OUTCOMES) == {"captures", "flows", "flows_without_origin"}
    document = prior_document()
    narrowed = json.loads(json.dumps(document))
    narrowed["selection"]["flows_without_origin"] = 408
    assert (
        collection.differences(collection.comparable(document), collection.comparable(narrowed))
        == []
    )


def test_a_changed_selection_input_is_a_difference():
    """The inputs stay in the comparison — a rebuild reads them from the document, so a mismatch
    would be a defect in this tool rather than a change in the store."""
    document = prior_document()
    other = json.loads(json.dumps(document))
    other["selection"]["labels"] = ["threat-name"]
    found = collection.differences(collection.comparable(document), collection.comparable(other))
    assert any("selection" in line for line in found)


def test_a_lost_flow_and_a_gained_flow_are_both_named():
    document = prior_document()
    changed = json.loads(json.dumps(document))
    changed["labels"] = []
    found = collection.differences(collection.comparable(document), collection.comparable(changed))
    assert any("was in the document and is not in the rebuild" in line for line in found)
    assert any(FLOW_KEY in line for line in found)


def test_differences_are_keyed_on_the_flow_and_not_on_position():
    """A rebuild that gained one flow would otherwise report every later record as changed, burying
    the one real finding under a list of shifted rows."""
    document = prior_document(
        rows=[
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)], flow_key="a" * 64),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2002)], flow_key="b" * 64),
        ]
    )
    without_first = json.loads(json.dumps(document))
    without_first["labels"] = without_first["labels"][1:]
    found = collection.differences(
        collection.comparable(document), collection.comparable(without_first)
    )
    assert len(found) == 1, found
    assert "a" * 64 in found[0]


def test_a_changed_run_set_is_named_in_both_directions():
    document = prior_document()
    changed = json.loads(json.dumps(document))
    changed["runs"] = []
    found = collection.differences(collection.comparable(document), collection.comparable(changed))
    assert any(f"run {TIER2_RUN} was in the document" in line for line in found)


def test_a_builder_mismatch_is_reported_naming_both_values():
    """§6.5 asks for it to be "reported naming both" — reported, not fatal. It is a fact about the
    two builds rather than a difference in the records."""
    moved = collection.builder_differences(
        {"version": "0.1.0", "label_kinds": "aaaa"}, {"version": "0.2.0", "label_kinds": "bbbb"}
    )
    assert len(moved) == 2
    assert any("'0.1.0'" in line and "'0.2.0'" in line for line in moved)
    assert any("'aaaa'" in line and "'bbbb'" in line for line in moved)


def test_the_builder_is_not_part_of_the_records_comparison():
    """Otherwise a version bump would read as a failed reproduction."""
    document = prior_document()
    other = json.loads(json.dumps(document))
    other["builder"]["version"] = "9.9.9"
    assert (
        collection.differences(collection.comparable(document), collection.comparable(other)) == []
    )
    assert "builder" not in collection.comparable(document)


# --- LS-9 at the CLI ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--label", "verdict"),
        ("--as-of", "2026-08-25T00:00:00Z"),
        ("--capture", CAPTURE),
        ("--limit", "5"),
        ("--allow-missing-origin", None),
    ],
)
def test_rebuild_refuses_a_flag_it_would_silently_ignore(flag, value, tmp_path, capsys):
    """§6.5 names `--label` and `--as-of`, on §12's precedent for `--sources`: a flag that looks
    like it changed the selection and did not is worse than one that errors.

    The other three are refused on the identical reasoning — a rebuild takes its selection from the
    document, so every one of these would be ignored.
    """
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(built().document), encoding="utf-8")
    argv = ["--rebuild", str(target), flag] + ([value] if value else [])
    assert blfile.main(argv) == blfile.EXIT_USAGE
    message = capsys.readouterr().err
    assert flag in message
    assert "silently ignored" in message


#: Every flag `blfile` has, and whether `--rebuild` must refuse it. Pinned as a literal so that
#: adding a flag to the parser fails **here** rather than being quietly allowed — deciding which
#: column a new flag belongs in is the whole judgement, and it must be made deliberately.
#:
#: Two earlier versions of this could not fail. The first compared `REBUILD_REFUSES` to a
#: hand-written copy of the same five names, so whoever added a flag updated both literals in one
#: edit. The second derived the shaping set from the parser and subtracted a hardcoded allowlist —
#: which moved the one-edit escape to the other side of the subtraction, and would also have
#: mislabelled a genuinely non-shaping flag like `--verbose` as one that must be refused.
FLAGS_AND_WHETHER_REBUILD_REFUSES_THEM = {
    "help": False,
    "project": False,  # where to read
    "dataset": False,  # where to read
    "local_adc": False,  # how to authenticate
    "output": False,  # where to write
    "rebuild": False,  # the flag itself
    "label": True,  # every one of these shapes a selection --rebuild takes from the document
    "capture": True,
    "limit": True,
    "allow_missing_origin": True,
    "as_of": True,
}


def test_every_parser_flag_is_classified():
    """A flag added to the parser and to neither column is the gap the refusal exists to close."""
    dests = {action.dest for action in blfile.build_parser()._actions}
    assert dests == set(FLAGS_AND_WHETHER_REBUILD_REFUSES_THEM), (
        f"unclassified: {sorted(dests - set(FLAGS_AND_WHETHER_REBUILD_REFUSES_THEM))}; "
        f"listed but not a flag: "
        f"{sorted(set(FLAGS_AND_WHETHER_REBUILD_REFUSES_THEM) - dests)}. Decide which column it "
        f"belongs in — that decision is what this test exists to force."
    )


def test_the_refusal_list_matches_the_classification():
    """`--rebuild` must refuse exactly the flags classified as shaping a selection."""
    expected = {name for name, refuses in FLAGS_AND_WHETHER_REBUILD_REFUSES_THEM.items() if refuses}
    assert set(blfile.REBUILD_REFUSES) == expected


def test_rebuild_reports_the_conflict_before_validating_the_labels(tmp_path, capsys):
    """`--rebuild x --label nonsense` must report the conflict, not the unknown kind: the label was
    never going to be used."""
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(built().document), encoding="utf-8")
    assert blfile.main(["--rebuild", str(target), "--label", "not-a-kind"]) == blfile.EXIT_USAGE
    message = capsys.readouterr().err
    assert "silently ignored" in message
    assert "LABEL_KINDS" not in message


def test_a_rebuild_file_that_is_missing_or_not_json_is_a_usage_error(tmp_path, capsys):
    assert blfile.main(["--rebuild", str(tmp_path / "absent.json")]) == blfile.EXIT_USAGE
    assert "cannot read" in capsys.readouterr().err

    broken = tmp_path / "broken.json"
    broken.write_text('{"document_type":', encoding="utf-8")
    assert blfile.main(["--rebuild", str(broken)]) == blfile.EXIT_USAGE
    assert "is not JSON" in capsys.readouterr().err


def test_a_pinned_run_absent_from_the_store_is_a_hard_failure_naming_it(monkeypatch, capsys):
    """§6.5's hard failure. §1 makes the store a derived index over the archive, so a run it no
    longer holds cannot be re-derived — a rebuild that quietly omitted it would answer a different
    question and look like a reproduction."""
    prior = collection.read_prior(prior_document())
    monkeypatch.setattr(blfile.query, "exclusions", lambda bq, dataset, run_ids: [])
    monkeypatch.setattr(blfile.query, "runs", lambda bq, dataset, run_ids: [])
    with pytest.raises(blfile.PinnedRunMissing, match=TIER2_RUN):
        blfile.collect_rebuild(object(), "flabel", prior, built_at=BUILT_AT)


def test_that_hard_failure_exits_1_because_it_is_about_the_store(monkeypatch, tmp_path, capsys):
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(built().document), encoding="utf-8")
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        blfile,
        "collect_rebuild",
        _raising(blfile.PinnedRunMissing(f"{TIER2_RUN} is not in flabel")),
    )
    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_REFUSED
    assert TIER2_RUN in capsys.readouterr().err


def test_rebuild_issues_no_query_that_re_decides_authority():
    """The authority is read from the document, so no statement asks the store for it.

    `query.pinned_authority` existed for exactly one commit and was the CRITICAL defect: it
    recovered a run's tiers from `tiers_attested`, which is what a run claimed and not what it
    supplies. There is now nothing to ask.
    """
    assert not hasattr(blfile.query, "pinned_authority")


def test_as_of_reaches_the_query_and_bare_blfile_reads_the_view(monkeypatch):
    """Two paths, one rule: without a cutoff the view is read, with one the same file is re-rendered
    as a parameterised SELECT."""
    seen = {}

    def authoritative(bq, dataset, captures=(), *, as_of=None):
        seen["as_of"] = as_of
        return []

    monkeypatch.setattr(blfile.query, "authoritative", authoritative)
    monkeypatch.setattr(blfile.query, "flow_labels", lambda *a, **k: [])
    monkeypatch.setattr(blfile.query, "sightings", lambda *a, **k: [])
    monkeypatch.setattr(blfile.query, "runs", lambda *a, **k: [])

    blfile.collect(object(), "flabel", collection.Selection(labels=("verdict",)), built_at=BUILT_AT)
    assert seen["as_of"] is None
    blfile.collect(
        object(),
        "flabel",
        collection.Selection(labels=("verdict",), as_of="2026-08-25T00:00:00Z"),
        built_at=BUILT_AT,
    )
    assert seen["as_of"] == "2026-08-25T00:00:00Z"


def test_a_reproduction_failure_exits_1_and_names_the_differences(monkeypatch, tmp_path, capsys):
    """A rebuild that did not reproduce is a statement about the DATA — the store no longer yields
    what that document recorded — so it shares 1 with the conflicts. Exit 0 would make `--rebuild` a
    command that cannot fail."""
    document = built().document
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(document), encoding="utf-8")

    # The store now yields one fewer flow than the document recorded.
    fewer = built(
        rows=[row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)], flow_key="z" * 64)]
    )
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect_rebuild", lambda *a, **k: fewer)

    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_REFUSED
    message = capsys.readouterr().err
    assert "DID NOT reproduce" in message
    assert FLOW_KEY in message


def test_a_successful_reproduction_says_so_and_exits_0(monkeypatch, tmp_path, capsys):
    result = built()
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(result.document), encoding="utf-8")
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect_rebuild", lambda *a, **k: built())

    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_OK
    message = capsys.readouterr().err
    assert "REPRODUCED" in message
    assert "built_at excluded" in message


def test_a_builder_mismatch_is_reported_but_does_not_fail_the_reproduction(
    monkeypatch, tmp_path, capsys
):
    """§6.5 says "reported naming both". It is printed FIRST, because a changed `label_kinds`
    changes what `--label verdict` means and a reader needs that before anything below it."""
    document = json.loads(collection.serialise(built().document))
    document["builder"]["label_kinds"] = "0000000000000000"
    target = tmp_path / "c.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect_rebuild", lambda *a, **k: built())

    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_OK
    message = capsys.readouterr().err
    assert "builder.label_kinds" in message
    assert "0000000000000000" in message
    assert "REPRODUCED" in message
    assert message.index("builder.label_kinds") < message.index("REPRODUCED")


def test_a_rebuild_refuses_a_run_that_has_since_been_retracted(monkeypatch):
    """**Reproduction is an audit capability; retraction is a correction. Retraction wins.**

    §4.5 is explicit that `run_exclusions` "covers the cases nobody wants to think about: a capture
    that must come out for legal or customer-data reasons, and a run later found to be mislabelled."
    `authoritative_runs` anti-joins the table, so the ordinary read path never sees an excluded
    run — but `--rebuild` pins a set recorded *before* the exclusion existed, so it is the one that
    can resurrect one. A rebuild that silently reproduced it would re-publish exactly what somebody
    removed, and a retraction that can be reproduced past is not a retraction.
    """
    prior = collection.read_prior(prior_document())
    monkeypatch.setattr(
        blfile.query,
        "exclusions",
        lambda bq, dataset, run_ids: [
            {
                "run_id": TIER2_RUN,
                "reason": "customer data removal",
                "excluded_by": "craig@deeptempo.ai",
                "excluded_at": "2026-08-26T00:00:00Z",
            }
        ],
    )

    def never(*args, **kwargs):
        raise AssertionError("a retracted run's rows were read")

    monkeypatch.setattr(blfile.query, "runs", never)
    monkeypatch.setattr(blfile.query, "flow_labels", never)

    with pytest.raises(blfile.PinnedRunExcluded) as raised:
        blfile.collect_rebuild(object(), "flabel", prior, built_at=BUILT_AT)
    message = str(raised.value)
    assert TIER2_RUN in message
    assert "customer data removal" in message, "§4.5 stores the reason so it stays auditable"
    assert "WITHOUT" in message, "the remedy is a fresh build, which honours the exclusion"


def test_a_retracted_pin_exits_1_because_it_is_about_the_data(monkeypatch, tmp_path, capsys):
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(built().document), encoding="utf-8")
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        blfile,
        "collect_rebuild",
        _raising(blfile.PinnedRunExcluded(f"{TIER2_RUN} — reason 'legal removal'")),
    )
    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_REFUSED
    assert "legal removal" in capsys.readouterr().err


# --- the end-to-end rebuild, which nothing exercised ---------------------------------------------


def fake_store(rows, sightings_rows, run_rows):
    """A `query` stand-in that answers from fixtures, so the WHOLE rebuild path runs.

    **This is the test the plan names and the review found missing.** Every earlier CLI-level
    reproduction test monkeypatched `collect_rebuild` away, and the two that called it returned
    before composing anything — so `collect_rebuild` was never run to completion anywhere in the
    suite. That is #171's shape: the one path production takes was the one path no test exercised,
    and it is why the pinned-tier defect and the dropped-cutoff defect were both invisible.
    """

    def patch(monkeypatch):
        monkeypatch.setattr(blfile.query, "exclusions", lambda bq, dataset, run_ids: [])
        monkeypatch.setattr(
            blfile.query,
            "runs",
            lambda bq, dataset, run_ids: [r for r in run_rows if r["run_id"] in set(run_ids)],
        )
        monkeypatch.setattr(
            blfile.query,
            "flow_labels",
            lambda bq, dataset, run_ids: [r for r in rows if r["run_id"] in set(run_ids)],
        )
        monkeypatch.setattr(
            blfile.query,
            "sightings",
            lambda bq, dataset, run_ids: [
                s for s in sightings_rows if s["observed_by_run_id"] in set(run_ids)
            ],
        )

    return patch


def test_a_rebuild_reproduces_the_document_it_was_given(monkeypatch):
    """PLAN's first named test, driven through `read_prior` and `collect_rebuild` for real."""
    rows = [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])]
    sightings_rows = [sighting(run_id=TIER2_RUN)]
    run_rows = [run_row(TIER2_RUN)]
    document = json.loads(
        collection.serialise(built(rows=rows, sightings=sightings_rows, run_rows=run_rows).document)
    )
    fake_store(rows, sightings_rows, run_rows)(monkeypatch)

    prior = collection.read_prior(document)
    rebuilt = blfile.collect_rebuild(object(), "flabel", prior, built_at="2099-01-01T00:00:00.0Z")

    assert (
        collection.differences(
            collection.comparable(document), collection.comparable(rebuilt.document)
        )
        == []
    )
    assert rebuilt.document["built_at"] != document["built_at"]


def test_a_rebuild_reproduces_a_partially_superseded_capture(monkeypatch):
    """**The variant that catches the CRITICAL defect.**

    A `--both` run supplies tier 1 while a newer `--offline` run supplies tier 2, so the `--both`
    run ATTESTS a tier it does not supply. Recovering the pin from `tiers_attested` made this exact
    document un-rebuildable — two runs for one (capture, tier) — and no test could see it because
    none of them composed anything.
    """
    both = row(
        run_id=BOTH_RUN,
        sources=[source(tier=1, sid=700, name="panw"), source(tier=2, sid=2001)],
    )
    newer = row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2002)], flow_key="c" * 64)
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 1, "run_id": BOTH_RUN},
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN},
        ]
    )
    rows = [both, newer]
    sightings_rows = [sighting(run_id=BOTH_RUN), sighting(run_id=TIER2_RUN)]
    run_rows = [run_row(BOTH_RUN), run_row(TIER2_RUN)]
    document = json.loads(
        collection.serialise(
            built(rows=rows, auth=auth, sightings=sightings_rows, run_rows=run_rows).document
        )
    )
    fake_store(rows, sightings_rows, run_rows)(monkeypatch)

    prior = collection.read_prior(document)
    rebuilt = blfile.collect_rebuild(object(), "flabel", prior, built_at="2099-01-01T00:00:00.0Z")
    assert (
        collection.differences(
            collection.comparable(document), collection.comparable(rebuilt.document)
        )
        == []
    )


def test_a_rebuild_reproduces_a_document_that_had_a_cutoff(monkeypatch):
    """The variant that catches the dropped-cutoff defect: an `--as-of` document must reproduce."""
    rows = [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])]
    sightings_rows = [sighting(run_id=TIER2_RUN)]
    run_rows = [run_row(TIER2_RUN)]
    document = json.loads(
        collection.serialise(
            built(
                rows=rows,
                sightings=sightings_rows,
                run_rows=run_rows,
                as_of="2026-08-25T00:00:00Z",
            ).document
        )
    )
    fake_store(rows, sightings_rows, run_rows)(monkeypatch)

    prior = collection.read_prior(document)
    rebuilt = blfile.collect_rebuild(object(), "flabel", prior, built_at="2099-01-01T00:00:00.0Z")
    assert rebuilt.document["selection"]["as_of"] == "2026-08-25T00:00:00Z"
    assert (
        collection.differences(
            collection.comparable(document), collection.comparable(rebuilt.document)
        )
        == []
    )


def test_a_rebuild_reproduces_a_limited_document(monkeypatch):
    """`--limit` truncates a prefix of a total order, and the pin covers every tier-supplier of
    every capture in that prefix — so re-applying the same limit yields the identical prefix."""
    rows = [
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2000 + index)],
            flow_key=f"{index:064d}",
            flow=flow_struct(ts_first=f"2026-07-08T12:00:0{index}.000000Z"),
        )
        for index in range(4)
    ]
    sightings_rows = [sighting(run_id=TIER2_RUN)]
    run_rows = [run_row(TIER2_RUN)]
    document = json.loads(
        collection.serialise(
            built(rows=rows, sightings=sightings_rows, run_rows=run_rows, limit=2).document
        )
    )
    assert document["selection"]["flows"] == 2
    fake_store(rows, sightings_rows, run_rows)(monkeypatch)

    prior = collection.read_prior(document)
    rebuilt = blfile.collect_rebuild(object(), "flabel", prior, built_at="2099-01-01T00:00:00.0Z")
    assert (
        collection.differences(
            collection.comparable(document), collection.comparable(rebuilt.document)
        )
        == []
    )


def test_a_rebuild_notices_when_the_rows_really_did_change(monkeypatch):
    """The other half: the reproduction must FAIL when the store no longer holds what the document
    recorded. Otherwise every test above is satisfied by a comparison that cannot fail."""
    rows = [
        row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)], flow_key="a" * 64),
        row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2002)], flow_key="b" * 64),
    ]
    sightings_rows = [sighting(run_id=TIER2_RUN)]
    run_rows = [run_row(TIER2_RUN)]
    document = json.loads(
        collection.serialise(built(rows=rows, sightings=sightings_rows, run_rows=run_rows).document)
    )
    # The store has lost one flow since.
    fake_store(rows[:1], sightings_rows, run_rows)(monkeypatch)

    prior = collection.read_prior(document)
    rebuilt = blfile.collect_rebuild(object(), "flabel", prior, built_at="2099-01-01T00:00:00.0Z")
    found = collection.differences(
        collection.comparable(document), collection.comparable(rebuilt.document)
    )
    assert len(found) == 1
    assert "b" * 64 in found[0]


# --- the rest of the 2026-08-25 review -----------------------------------------------------------


def _wrong_shape(**override) -> str:
    """A minimally valid-looking collection with one field replaced, as JSON text.

    It pins a plausible run so each case reaches the refusal it is named for rather than the
    empty-`runs` one — see the parametrisation below for why that mattered.
    """
    document = {
        "document_type": "labels-collection",
        "schema_version": "1.0",
        "built_at": BUILT_AT,
        "builder": {},
        "selection": {
            "labels": ["verdict"],
            "match": "all",
            "captures": 1,
            "flows": 0,
            "flows_without_origin": 0,
            "limit": None,
            "allow_missing_origin": False,
            "as_of": None,
        },
        "runs": [{"run_id": TIER2_RUN, "capture_sha256": CAPTURE, "supplies": [2]}],
        "labels": [],
    }
    document.update(override)
    return json.dumps(document)


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        ("[]", "holds a list, not an object"),
        ("5", "holds a int, not an object"),
        ('"x"', "holds a str, not an object"),
        ("{}", "document_type"),
        # **Each fixture must reach the refusal it is named for.** These all carried `"runs": []`,
        # so once the empty-runs refusal was added they died on *that* — and the parametrisation
        # asserted only exit 2 and "cannot be rebuilt", so the `builder` case stayed green with its
        # own guard deleted. Each now pins a plausible run and asserts a distinguishing substring.
        (_wrong_shape(runs=42), "runs is a int"),
        (_wrong_shape(runs=[1]), "runs[0] is a int"),
        (_wrong_shape(selection=["x"]), "selection is a list"),
        (_wrong_shape(builder=["x"]), "builder is a list"),
        (_wrong_shape(labels=[1, 2]), "labels[0] is a int"),
    ],
)
def test_a_valid_json_file_of_the_wrong_shape_is_a_usage_error(
    contents, expected, tmp_path, capsys
):
    """**Each of these used to reach the interpreter as exit 1** — the code this tool publishes as a
    refusal about the store — because `read_prior` checked a handful of fields by hand and indexed
    the rest blindly. It is an operator's file, so it is exit 2.
    """
    target = tmp_path / "c.json"
    target.write_text(contents, encoding="utf-8")
    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_USAGE
    message = capsys.readouterr().err
    assert "cannot be rebuilt" in message
    assert expected in message, f"reached the wrong refusal: {message}"


def test_a_non_finite_number_in_a_rebuild_file_is_the_operators_problem(
    monkeypatch, tmp_path, capsys
):
    """`json.loads` accepts the `NaN` literal and `serialise` refuses it (`allow_nan=False`, §10).

    It reached the interpreter as exit 1 first, then — once the report path was wrapped — as exit 3
    announcing "a DEFECT in blfile". **Both were wrong: it is a fact about a file the operator
    passed in**, so it is exit 2, and an earlier version of this test pinned the wrong answer.
    `read_prior` now canonicalises the document once, which catches this and anything else that
    cannot be serialised, in one place rather than from two layers down.
    """
    document = json.loads(collection.serialise(built().document))
    target = tmp_path / "c.json"
    target.write_text(
        json.dumps(document).replace('"unmatched_ratio": 0.0', '"unmatched_ratio": NaN'),
        encoding="utf-8",
    )
    monkeypatch.setattr(blfile.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(blfile, "collect_rebuild", lambda *a, **k: built())
    assert blfile.main(["--rebuild", str(target)]) == blfile.EXIT_USAGE
    message = capsys.readouterr().err
    assert "cannot be canonicalised" in message
    assert "DEFECT in blfile" not in message


def test_rebuild_refuses_limit_zero_rather_than_calling_it_absent(tmp_path, capsys):
    """`0 == False` in Python, so `not in (None, False, ())` treated `--limit 0` as not supplied and
    the operator got "selects nothing" instead of "--rebuild ignores --limit". Right code, wrong
    explanation."""
    target = tmp_path / "c.json"
    target.write_text(collection.serialise(built().document), encoding="utf-8")
    assert blfile.main(["--rebuild", str(target), "--limit", "0"]) == blfile.EXIT_USAGE
    assert "silently ignored" in capsys.readouterr().err


@pytest.mark.parametrize(
    "cutoff",
    [
        "yesterday",
        "2026-13-99",
        "",
        "now()",
        # **The boundary cases, and the reason the first gate was wrong.** `fromisoformat` takes all
        # three since 3.11 and BigQuery rejects all three, so a check built on it alone let
        # `--as-of 20260825` — an ordinary way to type a date — through to a `BadRequest`
        # "a DEFECT in blfile". Every case the first parametrisation chose was one Python also
        # rejected, so it could not see this, and the sabotage that restored the old gate stayed
        # green against it.
        "20260825",
        "2026-W35-1",
        "2026-08-25T00:00:00,5",
        # **Measured against the live service, 2026-08-25.** BigQuery refuses both, and the gate
        # accepted both until then: `:SS` was optional, and the offset was matched but never
        # range-checked. Neither was in this list, so the sabotages that restored those two holes
        # stayed green.
        "2026-08-25T14:30",
        "2026-08-25T00:00:00+99:99",
        "2026-08-25T00:00:00+2400",
        # And two the digit classes match but the calendar does not.
        "2026-02-30",
        "2026-08-25T25:00:00",
    ],
)
def test_a_malformed_as_of_is_a_usage_error_not_a_defect(cutoff, capsys):
    """It used to reach BigQuery, be rejected, and surface as a traceback plus "This is a DEFECT in
    blfile" at exit 3 — for a typo. The value is also written verbatim into the published
    `selection.as_of`, so a malformed cutoff would become part of the provenance."""
    assert blfile.main(["--as-of", cutoff]) == blfile.EXIT_USAGE
    assert "not an ISO-8601 instant" in capsys.readouterr().err


@pytest.mark.parametrize(
    "cutoff",
    [
        "2026-08-25T00:00:00Z",
        "2026-08-25T00:00:00+00:00",
        "2026-08-25T00:00:00+0000",
        "2026-08-25 00:00:00",
        "2026-08-25",
        # BigQuery's literal format is `YYYY-[M]M-[D]D[( |T)[H]H:[M]M:[S]S[.F]]` — single digits
        # allowed. A `fromisoformat` backstop refused these, making the gate STRICTER than the thing
        # it guards. Wrong in the safer direction, still wrong.
        "2026-8-5",
        "2026-8-5T1:02:03.123456+00:00",
    ],
)
def test_a_well_formed_cutoff_is_accepted(cutoff):
    assert blfile._is_instant(cutoff)


def test_a_rewritten_run_block_is_not_a_reproduction():
    """§6.4 embeds the blocks as provenance — ruleset snapshot, tool versions, mode, `input`.
    Comparing only the id set meant a run row rewritten by a re-ingest reported REPRODUCED, which is
    exactly the scenario `--rebuild` audits."""
    document = prior_document()
    changed = json.loads(json.dumps(document))
    changed["runs"][0]["mode"] = "both"
    found = collection.differences(collection.comparable(document), collection.comparable(changed))
    assert len(found) == 1
    assert "block differs" in found[0] and "mode" in found[0]


def test_the_same_records_in_a_different_order_are_not_a_reproduction():
    """§6.4's canonical ordering is part of the document, so a re-ordering is a difference."""
    document = prior_document(
        rows=[
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)], flow_key="a" * 64),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2002)], flow_key="b" * 64),
        ]
    )
    reversed_records = json.loads(json.dumps(document))
    reversed_records["labels"] = list(reversed(reversed_records["labels"]))
    found = collection.differences(
        collection.comparable(document), collection.comparable(reversed_records)
    )
    assert len(found) == 1
    assert "order differs" in found[0]


def test_a_repeated_flow_key_is_reported_rather_than_collapsed():
    """`differences` indexes records by (capture, flow_key), and the cardinality check that used to
    catch a duplicate — `selection.flows` — is now excluded from the comparison. §3.2 makes the pair
    a flow's identity, so this asserts the assumption instead of trusting it."""
    document = prior_document()
    doubled = json.loads(json.dumps(document))
    doubled["labels"] = doubled["labels"] + doubled["labels"]
    found = collection.differences(collection.comparable(document), collection.comparable(doubled))
    assert any("two records for one (capture, flow_key)" in line for line in found)


def test_a_view_cannot_be_rendered_with_a_query_parameter_in_it():
    """`render_view(as_of=True, ddl=True)` is reachable and yields `CREATE OR REPLACE VIEW …
    @as_of`, which BigQuery cannot create: a view takes no parameters."""
    from flabeldb import schema

    with pytest.raises(ValueError, match="mutually exclusive"):
        schema.render_view("authoritative_runs", "flabel", as_of=True, ddl=True)


def test_read_prior_refuses_a_run_listed_under_two_captures():
    """**I claimed this was unreachable and it was not.**

    §3.3 derives a run id from one capture, so the store cannot produce it — but `--rebuild` builds
    its `Authority` from a *document*, and a hand-edited one can say anything. It reached
    `collection.build`'s own guard, which raises a bare `ValueError`, which `main` classifies as
    "a DEFECT in blfile" at exit 3 — for a bad input file. It is a fact about the file, so exit 2.
    """
    document = prior_document()
    entry = document["runs"][0]
    document["runs"] = [entry, {**entry, "capture_sha256": "b" * 64}]
    with pytest.raises(collection.NotACollection, match="listed under two captures"):
        collection.read_prior(document)


@pytest.mark.parametrize("supplies", ["1", 1, [1, "2"], [True], None, {}])
def test_read_prior_refuses_a_supplies_that_is_not_tier_numbers(supplies):
    """`supplies` is what the pin is *made of*. A string is iterable and would produce tiers of
    `"1"`; `True` is an `int` in Python and would serialise as `true`, the exclusion
    `provenance.build_source_entry` already makes for `Detection.tier`."""
    document = prior_document()
    document["runs"][0]["supplies"] = supplies
    with pytest.raises(collection.NotACollection):
        collection.read_prior(document)


def test_read_prior_refuses_a_capture_that_is_not_a_string():
    document = prior_document()
    document["runs"][0]["capture_sha256"] = ["a" * 64]
    with pytest.raises(collection.NotACollection, match="not str"):
        collection.read_prior(document)


def test_the_build_guard_survives_as_a_backstop_for_the_other_path():
    """`collection.build` is reached from a fresh build too, where the authority comes from the
    view. `read_prior` is the gate for the rebuild path; this stays because the other path exists.
    """
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN},
            {"capture_sha256": OTHER_CAPTURE, "tier": 2, "run_id": TIER2_RUN},
        ]
    )
    rows = [
        row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)], capture=CAPTURE),
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2002)],
            capture=OTHER_CAPTURE,
            flow_key="d" * 64,
        ),
    ]
    with pytest.raises(ValueError, match="supplies two captures"):
        collection.build(
            merged=merge.compose(rows, auth),
            auth=auth,
            sightings=[
                sighting(run_id=TIER2_RUN),
                sighting(run_id=TIER2_RUN, capture=OTHER_CAPTURE),
            ],
            run_rows=[run_row(TIER2_RUN)],
            selection=collection.Selection(labels=("verdict",), allow_missing_origin=True),
            built_at=BUILT_AT,
            version=VERSION,
        )


def test_a_run_id_that_is_not_a_string_is_a_usage_error():
    """The field `by_run.setdefault` hashes and `sorted(set(pinned))` orders — and the one the last
    round's validation fix did not check. A list `run_id` raised `TypeError: unhashable type` and a
    mixed int/str pair raised on the sort; both escaped `read_prior` and reached the interpreter as
    exit 1, the code reserved for a refusal about the store."""
    document = prior_document()
    document["runs"][0]["run_id"] = ["x"]
    with pytest.raises(collection.NotACollection, match="not str"):
        collection.read_prior(document)


def test_run_ids_of_mixed_type_do_not_reach_the_sort():
    document = prior_document()
    document["runs"].append({**document["runs"][0], "run_id": 7, "capture_sha256": "b" * 64})
    with pytest.raises(collection.NotACollection, match="not str"):
        collection.read_prior(document)


def test_a_document_that_pins_no_runs_is_refused_rather_than_reproduced():
    """**The most likely document an operator has on disk today.** Every archived run predates
    `--source-uri`, so bare `blfile` emits 0 flows and therefore pins nothing.

    Every query short-circuits on an empty id list, so a `runs: []` document read nothing — not the
    exclusions, not the runs, not a row — and printed "REPRODUCED … 0 flow(s)" at exit 0. It did so
    even against a dataset that does not exist. `read_prior`'s own docstring gives that exact
    failure as the reason it refuses a `labels.json`, and the same end was reachable through this
    door.
    """
    document = prior_document()
    document["runs"] = []
    document["labels"] = []
    with pytest.raises(collection.NotACollection, match="runs is empty"):
        collection.read_prior(document)


def test_a_zero_flow_rebuild_cannot_report_success_against_a_dataset_that_is_not_there(
    monkeypatch, tmp_path, capsys
):
    """The end-to-end shape of the finding above: nothing queried, so nothing could fail."""
    document = json.loads(collection.serialise(built().document))
    document["runs"] = []
    document["labels"] = []
    target = tmp_path / "c.json"
    target.write_text(json.dumps(document), encoding="utf-8")

    def never(**kwargs):
        raise AssertionError("a client was built for a document that pins nothing")

    monkeypatch.setattr(blfile.client_module, "client", never)
    assert blfile.main(["--rebuild", str(target), "--dataset", "no_such_dataset"]) == (
        blfile.EXIT_USAGE
    )
    assert "runs is empty" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "value"),
    [("origin", None), ("origin", 5), ("flow", None), ("flow", "x")],
)
def test_a_record_whose_origin_or_flow_is_not_an_object_is_a_usage_error(field, value):
    """`record.get("origin", {})` returns `None` for a key that is PRESENT and null, so the default
    does not save the `.get` after it — `differences` raised `AttributeError`, reported as a defect
    in `blfile`. It is a fact about the operator's file."""
    document = prior_document()
    document["labels"][0][field] = value
    with pytest.raises(collection.NotACollection, match=field):
        collection.read_prior(document)


@pytest.mark.parametrize("limit", ["5", True, 1.5, []])
def test_a_selection_limit_that_is_not_a_whole_number_is_a_usage_error(limit):
    """`chosen[: "5"]` raises `TypeError: slice indices must be integers`, and `True` silently means
    a limit of one — `bool` is an `int` in Python, the exclusion `provenance.build_source_entry`
    already makes for `Detection.tier`."""
    document = prior_document()
    document["selection"]["limit"] = limit
    with pytest.raises(collection.NotACollection):
        collection.read_prior(document)


def test_a_run_block_that_shadows_a_pin_key_is_refused():
    """The run block is spread **last**, so a block that ever gained a `run_id` of its own would win
    and `--rebuild` would pin whatever the block said, silently.

    `docs/spec.md` §10's key set has none of the three today, and the test that looked like it
    guarded this inspected a hand-written fixture rather than the real thing — so the guard lives in
    `build`, where it cannot be out of date.
    """
    from flabeldb import collection as module

    assert module.PIN_KEYS == ("run_id", "capture_sha256", "supplies")
    for key in module.PIN_KEYS:
        block = {**json.loads(run_row(TIER2_RUN)["run_block"]), key: "hijacked"}
        with pytest.raises(merge.StoreInconsistent, match="pinned set"):
            built(run_rows=[{"run_id": TIER2_RUN, "run_block": json.dumps(block)}])


def test_the_same_run_listed_twice_is_reported():
    """`runs` is excluded from the top-level key loop, so its LENGTH is never compared — the same
    symmetry gap the labels index already had a check for.

    **Asserted in the DOCUMENT direction, which is the only one that can happen**: the rebuilt side
    is machine-generated by `build`, which cannot emit a duplicate entry. An earlier version passed
    the doubled document as the *rebuilt* side, so deleting the document branch of the guard left
    this green while the reachable case went back to reporting REPRODUCED.
    """
    document = prior_document()
    doubled = json.loads(json.dumps(document))
    doubled["runs"] = doubled["runs"] + doubled["runs"]

    found = collection.differences(collection.comparable(doubled), collection.comparable(document))
    assert any("the document lists the same run twice" in line for line in found), found
    # The other branch still reports, so neither is dead.
    found = collection.differences(collection.comparable(document), collection.comparable(doubled))
    assert any("the rebuild lists the same run twice" in line for line in found), found


def test_a_view_file_with_no_header_placeholder_is_refused(monkeypatch, tmp_path):
    """Before LS-9 each view file carried its own literal CREATE. Now the CREATE only appears where
    the placeholder is — so a new view file without one would be run by `flabel-db apply` as a plain
    SELECT: it prints "view <name>", exits 0, and creates nothing. `apply` is the gate."""
    from flabeldb import schema

    scratch = tmp_path / "views"
    scratch.mkdir()
    (scratch / "headerless.sql").write_text("SELECT 1 AS x\n", encoding="utf-8")
    monkeypatch.setattr(schema, "VIEWS", scratch)
    assert schema.view_names() == ("headerless",)
    with pytest.raises(ValueError, match=r"missing \['\{header\}', '\{as_of\}'\]"):
        schema.render_view("headerless", "flabel")


def test_a_view_file_missing_only_the_as_of_site_is_refused(monkeypatch, tmp_path):
    """The other half, and the worse one. A file with a header and no as-of site renders, for
    `blfile --as-of`, as the view body with **no cutoff predicate** — while `selection.as_of` in the
    document it writes still claims one. That is a provenance falsehood, which is worse than the
    "apply succeeds at nothing" case the guard was originally added for."""
    from flabeldb import schema

    scratch = tmp_path / "views"
    scratch.mkdir()
    (scratch / "halfway.sql").write_text("{header}\nSELECT 1 AS x\n", encoding="utf-8")
    monkeypatch.setattr(schema, "VIEWS", scratch)
    with pytest.raises(ValueError, match=r"missing \['\{as_of\}'\]"):
        schema.render_view("halfway", "flabel")


def test_a_placeholder_named_only_in_a_comment_does_not_satisfy_the_guard(monkeypatch, tmp_path):
    """`views/authoritative_runs.sql` documents this hazard in its own comments and line 4 already
    names `{dataset}` that way — so a guard that greps the whole file is satisfied by prose."""
    from flabeldb import schema

    scratch = tmp_path / "views"
    scratch.mkdir()
    (scratch / "commented.sql").write_text(
        "-- see {header} and {as_of} below\nSELECT 1 AS x\n", encoding="utf-8"
    )
    monkeypatch.setattr(schema, "VIEWS", scratch)
    with pytest.raises(ValueError, match="outside its comments"):
        schema.render_view("commented", "flabel")


# --- the declaration, and the test that stops it having a next missed field -----------------------


def _unspecced(value, shape, path="the document"):
    """Keys a real document carries at a level the declaration constrains, that it does not name.

    Walks the two together. An earlier version flattened each side to a set of paths and subtracted
    — which was circular: it filtered the document's paths to the ones the declaration mentioned
    before comparing, so an undeclared key was excluded from the comparison by the very fact of
    being undeclared. It passed with two new fields added to `build`.
    """
    found: list[str] = []
    if shape.fields is not None and isinstance(value, dict):
        if not shape.embeds:
            # `embeds` maps wrap something written elsewhere — a verbatim run block, a §4.2
            # sighting, a §4.3 flow struct — so naming every key would be a lie. Everywhere else is
            # closed, and that is where this test has teeth.
            for name in value:
                if name not in shape.fields:
                    found.append(f"{path}.{name}")
        for name, field in shape.fields.items():
            if name in value:
                found += _unspecced(value[name], field, f"{path}.{name}")
    if shape.items is not None and isinstance(value, list):
        for index, item in enumerate(value):
            found += _unspecced(item, shape.items, f"{path}[{index}]")
    return found


def test_the_declaration_covers_every_field_a_real_document_carries():
    """**This is what makes the shape a guarantee rather than another checklist.**

    Three consecutive review rounds found the same defect in `read_prior`: validation that covered
    every field but one, and the one it missed reached the interpreter as exit 1 or was announced as
    "a DEFECT in blfile" at exit 3. Round one missed the pinned tiers; round two validated two of
    three pin fields and missed `run_id`; round three validated `run_id` and `limit` and missed
    `selection.labels`.

    So the field list is no longer maintained by hand-and-hope: adding a key to `build` without a
    line in `DOCUMENT_SHAPE` fails **here**. Same arrangement as `RUN_ID_COLUMN` against
    `schema.TABLES` and `LOAD_ORDER` against the declaration.

    The walk stops where the declaration stops, on purpose: the interiors of `flow`, `sources`,
    `labels[]` entries and `builder` are compared by equality and never indexed, so
    `read_prior`'s canonicalisation check is their whole requirement.
    """
    missing = _unspecced(prior_document(), collection.DOCUMENT_SHAPE)
    assert not missing, (
        f"these keys are in a real document and not in DOCUMENT_SHAPE: {sorted(missing)}. "
        f"Add a line to the declaration — a field with no spec is the next one to be missed."
    )


def test_the_declaration_names_nothing_a_real_document_lacks():
    """The other direction: a spec for a field `build` does not emit would refuse every real
    document, which is a gate that fails closed on nothing. `validate_document` requires every
    declared field to be present, so a real document passing it proves this."""
    collection.validate_document(prior_document())


def test_a_scalar_where_a_list_belongs_is_refused_rather_than_iterated():
    """`selection.labels = "verdict"` used to become seven one-character label kinds: no flow
    carries them, the rebuild emits nothing, and `blfile` exits 1 saying "the rows those runs hold
    have changed". Nothing had changed — the file was wrong."""
    document = prior_document()
    document["selection"]["labels"] = "verdict"
    with pytest.raises(collection.NotACollection, match="not list"):
        collection.read_prior(document)


def test_an_unhashable_flow_key_is_refused_before_it_reaches_the_record_index():
    """`differences` keys its index on `(origin.capture_sha256, flow.flow_key)`. A list there raised
    `TypeError: unhashable type` — reported as "a DEFECT in blfile" at exit 3 — and the guard that
    was supposed to cover it only checked that `flow` was an object."""
    document = prior_document()
    document["labels"][0]["flow"]["flow_key"] = ["x"]
    with pytest.raises(collection.NotACollection, match="flow_key"):
        collection.read_prior(document)


def test_an_origin_with_no_capture_digest_is_refused():
    """`origin: {}` passed the container check, yielded `capture_sha256 -> None`, and reached three
    `sorted()` calls over keys of mixed type. The fix's own comment claimed to have closed this."""
    document = prior_document()
    document["labels"][0]["origin"] = {}
    with pytest.raises(collection.NotACollection, match="capture_sha256"):
        collection.read_prior(document)


def test_a_limit_the_command_line_would_refuse_is_refused_in_a_document_too():
    """`blfile --limit 0` exits 2, but the document path accepted `limit: 0` — and then the rebuild
    emitted nothing and exited 1 announcing that the store's rows had changed."""
    document = prior_document()
    document["selection"]["limit"] = 0
    with pytest.raises(collection.NotACollection, match="smallest legal value"):
        collection.read_prior(document)


def test_the_coverage_test_can_actually_fail():
    """**The guard behind the guard.** `test_the_declaration_covers_every_field_a_real_document…`
    is what stops `DOCUMENT_SHAPE` having a next missed field — so a version of it that could not
    fail would be worse than none. An earlier version was exactly that: it flattened both sides to
    path sets and subtracted, filtering the document's paths by the declaration *before* comparing,
    so an undeclared key was excluded by the fact of being undeclared. It passed with two new
    fields added to `build`.

    Same shape as `test_the_stdlib_trap_this_guard_exists_for_is_still_real`.
    """
    document = prior_document()
    document["a_field_nobody_declared"] = 1
    document["selection"]["another_one"] = 2
    missing = _unspecced(document, collection.DOCUMENT_SHAPE)
    assert "the document.a_field_nobody_declared" in missing
    assert "the document.selection.another_one" in missing


def test_the_coverage_walk_stops_where_the_declaration_does():
    """An `embeds` map wraps something written elsewhere, so its extra keys are not findings — but
    the walk must still descend into the fields it *does* declare."""
    document = prior_document()
    document["runs"][0]["a_run_block_key"] = 1
    document["labels"][0]["flow"]["another"] = 2
    assert _unspecced(document, collection.DOCUMENT_SHAPE) == []


def test_a_record_index_key_of_mixed_type_does_not_raise():
    """`differences` sorts its record keys, and a `None` capture digest beside a string one used to
    raise `TypeError` on `sorted()` — reported as "a DEFECT in blfile" at exit 3.

    `read_prior` now refuses such a document outright, so this is belt-and-braces — but
    `differences` is also called on freshly built documents that never went through `read_prior`,
    and the cost of proving it cannot raise is one test.
    """
    left = {
        "labels": [
            {"origin": {"capture_sha256": None}, "flow": {"flow_key": "a"}},
            {"origin": {"capture_sha256": "c"}, "flow": {"flow_key": "b"}},
        ]
    }
    right = {"labels": []}
    found = collection.differences(left, right)
    assert len(found) == 2
    found = collection.differences(right, left)
    assert len(found) == 2
