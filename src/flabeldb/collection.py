"""The `labels-collection` document — spec-label-store §6.4.

**A new document type, not a `labels.json` variant.** A collection spans many runs, captures and
snapshots, and `labels.json`'s single `run` block has no honest value to hold. A `labels.json`
consumer fails on this document, which is correct (§6.4, §9).

Pure, for `merge.py`'s reason: this is where §6.4's four corrections live — the `{tier: run_id}`
map, per-capture `coverage`, `origin.uri_status` with `selection.flows_without_origin`, and a
`builder` that pins the store schema and `LABEL_KINDS` digests — and none of them should need a
credential to check.

Three rules §6.4 leaves to the implementer, decided here and recorded because they are the kind of
thing that gets re-derived differently next time:

**Origin resolves to the lowest authoritative tier that actually recorded one.** §6.5 says origin
takes "the lowest surviving tier's run when two tiers disagree", and a `not-recorded` sighting is
not a disagreeing value — §4.2 added `uri_status` precisely so a null `uri` is *one* fact rather
than two. Every run in the archive predates `--source-uri`, so a strict lowest-tier rule would
refuse a flow whose origin the store demonstrably holds, from a newer run at the other tier. Two
*recorded* origins still resolve by lowest tier, which is what §6.5 is about.

**`coverage` aggregates across the capture's authoritative runs** rather than quoting one of them.
§6.4 puts it in the document because §4.4 stores `unmatched` so a consumer is not misled by a short
label list; quoting only the lowest tier's block would report `unmatched: 0` over a capture whose
tier-2 run left seven detections unplaced, re-creating that misreading at corpus level. `unmatched`
and the loss flags are therefore the sum and the union, and `unmatched_ratio` is recomputed by
`models.CorrelationResult`'s own formula over the summed counts — **not** `unmatched / detections`,
which §10 is explicit does not reproduce it (issue #84).

**`snaplens` is plural here too.** §6.4's example literal said `snaplen`; §4.2, §6.1 and the
`captures` column are plural, and §4.2 records that this exact drift already had to be corrected
once at LS-3. A singular value would have to invent a winner where a `mergecap` pcapng's interfaces
disagree — measured 96 and 65535 — which is the one fact the field exists to expose.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from flabeldb import merge, schema
from flabeldb.identity import DIGEST_CHARS

DOCUMENT_TYPE = "labels-collection"

#: **Not `labels.json`'s.** §9: a collection stamped with the pipeline's `schema_version` would
#: invite a consumer to read it as one, and this document has no `run` block.
SCHEMA_VERSION = "1.0"

TOOL = "blfile"

#: `captures.uri_status` for a run whose block has no `uri` key at all — every run that predates
#: `--source-uri`, which is every run in the archive (§4.2, §6.1).
NOT_RECORDED = "not-recorded"

#: `docs/spec.md` §10's timestamp format, written out because `tests/test_architecture.py` shares
#: only `flabel.models` with this package. `test_blfile.py` pins it to `labels.iso_from_epoch`.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

INDENT = 2


@dataclasses.dataclass(frozen=True)
class Selection:
    """What was asked for, before anything was read. `match` is always `all` — §6.3 ANDs."""

    labels: tuple[str, ...]
    captures: tuple[str, ...] = ()
    limit: int | None = None
    allow_missing_origin: bool = False


@dataclasses.dataclass(frozen=True)
class Built:
    """The document, and the two counts a caller reports on stderr rather than reading back out."""

    document: dict[str, Any]
    #: Flows in the selection whose capture has no recorded origin. Published in the document
    #: **either way** (§6.4); dropped from `labels[]` unless `--allow-missing-origin`.
    flows_without_origin: int
    #: Flows `merge` could not construct — §9's counted refusal, on §3.2's precedent.
    refused: int
    refusal_notes: tuple[str, ...]


# --- digests (§6.4's `builder`) -----------------------------------------------------------------


def store_schema_digest() -> str:
    """`schema.TABLES` as one id. A changed schema changes what was read (§6.4).

    Order is **not** sorted away: column order is part of the declaration — `schema.differences`
    compares it — so a reordering is a change this digest must show.
    """
    return _digest(
        [
            [
                name,
                table.description,
                table.partition_field,
                list(table.clustering),
                _columns(table.fields),
            ]
            for name, table in schema.TABLES.items()
        ]
    )


def label_kinds_digest() -> str:
    """`models.LABEL_KINDS` as one id.

    §6.4: `builder.version` covers the merge now that it lives here, but a changed `LABEL_KINDS`
    changes what `--label verdict` *means*, and that is not the tool's version.
    """
    from flabel.models import LABEL_KINDS

    return _digest([[name, kind.arity, list(kind.tiers)] for name, kind in LABEL_KINDS.items()])


def _columns(fields: Sequence[schema.Column]) -> list:
    return [[item.name, item.field_type, item.mode, _columns(item.fields)] for item in fields]


def _digest(material: Any) -> str:
    text = json.dumps(material, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
    return sha256(text.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


# --- the document --------------------------------------------------------------------------------


def build(
    *,
    merged: merge.Merged,
    auth: merge.Authority,
    sightings: Iterable[Mapping[str, Any]],
    run_rows: Iterable[Mapping[str, Any]],
    selection: Selection,
    built_at: str,
    version: str,
) -> Built:
    """§6.4's document, from composed flows and the rows that give them context."""
    blocks = _run_blocks(run_rows)
    origins = _origins(auth, sightings)
    coverage = {
        capture: _coverage(
            [blocks[run_id] for run_id in sorted(set(tiers.values())) if run_id in blocks]
        )
        for capture, tiers in auth.by_capture.items()
    }

    wanted = tuple(selection.labels)
    chosen = [
        record
        for record in merged.flows
        if _carries_every(record, wanted) and _selected_capture(record, selection.captures)
    ]

    without_origin = [record for record in chosen if not _has_origin(origins, record)]
    if not selection.allow_missing_origin:
        # §6.4, §9: refuse to EMIT the flow. The document is still produced and the count is
        # published either way, which is what makes the shortfall visible rather than silent.
        chosen = [record for record in chosen if _has_origin(origins, record)]

    chosen.sort(
        key=lambda record: (record.capture_sha256, record.label.flow.ts_first, record.flow_key)
    )
    if selection.limit is not None:
        chosen = chosen[: selection.limit]

    captures_present = {record.capture_sha256 for record in chosen}
    runs_present = sorted(
        {
            run_id
            for capture in captures_present
            for run_id in auth.by_capture.get(capture, {}).values()
        }
    )

    document = {
        "document_type": DOCUMENT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "built_at": built_at,
        "builder": {
            "tool": TOOL,
            "version": version,
            "store_schema": store_schema_digest(),
            "label_kinds": label_kinds_digest(),
        },
        "selection": {
            "labels": list(wanted),
            # §6.3: multiple values are ANDed, because ragged rows are useless as training data
            # and `docs/spec.md` §2.5 refuses to let absence be a signal.
            "match": "all",
            "captures": len(captures_present),
            "flows": len(chosen),
            "flows_without_origin": len(without_origin),
        },
        "runs": [blocks[run_id] for run_id in runs_present if run_id in blocks],
        "labels": [
            _record(record, origins.get(record.capture_sha256), coverage.get(record.capture_sha256))
            for record in chosen
        ],
    }
    return Built(
        document=document,
        flows_without_origin=len(without_origin),
        refused=merged.refused,
        refusal_notes=merged.refusal_notes,
    )


def serialise(document: Mapping[str, Any]) -> str:
    """Canonical JSON, `docs/spec.md` §10's settings, trailing newline.

    Written out rather than imported from `flabel.labels`: the architecture guard shares only
    `flabel.models` with this package, and `labels.py` is a pipeline module written for one run at
    a time. `test_blfile.py` asserts the two produce identical bytes, on the same reasoning
    `test_the_two_sort_keys_are_the_same_key` uses.
    """
    return (
        json.dumps(document, sort_keys=True, indent=INDENT, ensure_ascii=False, allow_nan=False)
        + "\n"
    )


# --- selection ------------------------------------------------------------------------------------


def _carries_every(record: merge.MergedFlow, wanted: Sequence[str]) -> bool:
    """§6.3's AND. §9: never emit a flow missing any requested label kind."""
    names = {entry.name for entry in record.label.labels}
    return all(name in names for name in wanted)


def _selected_capture(record: merge.MergedFlow, captures: Sequence[str]) -> bool:
    """`--capture`, repeatable (§6.3) — matched on the **digest only**.

    `blfile.collect` resolves the operator's `<sha|name>` to digests through `query.capture_shas`
    before this is reached, so a name never arrives here. That is not tidiness: §4.2's `captures`
    table is append-only, one row per *sighting*, so a capture legitimately carries several names,
    and a name comparison against the authoritative run's sighting alone dropped every flow of a
    capture the SQL had already resolved. §3.1 makes the digest the identity; the name is an entry
    point, and resolving it is a job for the table that holds every sighting.

    Matching on a name here as well would also be a branch production never takes — #171's shape:
    the one value that was wrong in production was the one value no test exercised.
    """
    return not captures or record.capture_sha256 in captures


def _has_origin(origins: Mapping[str, Mapping[str, Any]], record: merge.MergedFlow) -> bool:
    origin = origins.get(record.capture_sha256)
    if origin is None:
        return False
    return bool(origin.get("uri")) and origin.get("uri_status") not in (None, NOT_RECORDED)


# --- origin (§6.4, §6.5) --------------------------------------------------------------------------


def _origins(
    auth: merge.Authority, sightings: Iterable[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    """One origin per capture, resolved from the authoritative runs' sightings.

    `captures` is append-only — one row per SIGHTING, because a URI is a location and the digest is
    the identity (§4.2) — so a capture seen by five runs has five rows and the collection must pick
    one deterministically. It picks the **lowest authoritative tier that recorded an origin**, and
    falls back to the lowest tier's sighting when none did, so `filename`, `link_type` and
    `snaplens` are still published for a flow that will then be counted as origin-less.
    """
    by_run: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in sightings:
        by_run[(row["capture_sha256"], row["observed_by_run_id"])] = row

    resolved: dict[str, dict[str, Any]] = {}
    for capture, tiers in auth.by_capture.items():
        candidates = [
            by_run[(capture, run_id)]
            for _tier, run_id in sorted(tiers.items())
            if (capture, run_id) in by_run
        ]
        if not candidates:
            continue
        recorded = [
            row
            for row in candidates
            if row.get("uri") and row.get("uri_status") not in (None, NOT_RECORDED)
        ]
        chosen = recorded[0] if recorded else candidates[0]
        resolved[capture] = {
            "capture_sha256": capture,
            "uri": chosen.get("uri"),
            "uri_status": chosen.get("uri_status") or NOT_RECORDED,
            "filename": chosen.get("filename"),
            "link_type": chosen.get("link_type"),
            # PLURAL — see this module's docstring and §6.1.
            "snaplens": list(chosen.get("snaplens") or ()),
        }
    return resolved


# --- coverage (§6.4) ------------------------------------------------------------------------------


def _coverage(blocks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """What was lost about this capture, over every run currently supplying a tier of it.

    `loss_conditions` is `null` per flag when the stage that would know never ran (§10), and a
    `null` is emphatically not a fired condition — "JA4 was fine" and "nothing ever probed JA4" are
    different facts, which is the whole reason that field is tri-state.
    """
    statuses = {
        (block.get("input") or {}).get("input_status")
        for block in blocks
        if (block.get("input") or {}).get("input_status")
    }
    unmatched = _total(blocks, "unmatched")
    unsupported = _total(blocks, "unmatched_unsupported_transport")
    detections = _total(blocks, "detections")

    fired: set[str] = set()
    for block in blocks:
        for name, value in (block.get("loss_conditions") or {}).items():
            if value is True:
                fired.add(name)

    return {
        # "partial" wins: a capture read short by any contributing run was read short.
        "input_status": (
            "partial" if "partial" in statuses else ("complete" if statuses else None)
        ),
        "unmatched": unmatched,
        "unmatched_ratio": _ratio(unmatched, unsupported, detections),
        "loss_conditions_fired": sorted(fired),
    }


def _total(blocks: Sequence[Mapping[str, Any]], key: str) -> int | None:
    """The sum of a `counts` field across the contributing runs, or `None` if **any** did not
    establish it.

    `None` rather than `0`, and `None` rather than a partial sum. `docs/spec.md` §10 is emphatic
    that a null count means "not measured": reporting zero would assert that nothing was lost about
    a capture nobody counted, and summing the runs that *did* measure would publish one run's number
    as if it described the capture. Both are "measured as none" standing in for "not measured",
    which is §2.5's whole subject.
    """
    if not blocks:
        return None
    values = [(block.get("counts") or {}).get(key) for block in blocks]
    return None if any(value is None for value in values) else sum(values)


def _ratio(unmatched: int | None, unsupported: int | None, detections: int | None) -> float | None:
    """`models.CorrelationResult.unmatched_ratio`'s formula, over the summed counts.

    **Not `unmatched / detections`.** `docs/spec.md` §10 says outright that the published ratio
    excludes unsupported-transport detections, so the obvious division does not reproduce it: a
    detection on ESP or SCTP was never going to correlate, and counting it would let ordinary IPsec
    traffic drag the number around. Zero correlatable detections is zero loss, not a division by
    zero — the model's own rule.

    **A null `unsupported` makes the whole ratio null**, and that asymmetry was a real defect: with
    `unsupported or 0`, a contributing run that never published
    `counts.unmatched_unsupported_transport` — every run predating issue #84 — silently reduced this
    to exactly the division the paragraph above forbids. A missing `unmatched` made the ratio null
    and loud; a missing `unsupported` made it wrong and quiet.
    """
    if unmatched is None or detections is None or unsupported is None:
        return None
    correlatable = detections - unsupported
    if correlatable <= 0:
        return 0.0
    return (unmatched - unsupported) / correlatable


# --- records --------------------------------------------------------------------------------------


def _run_blocks(rows: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """`runs.run_block` parsed back. §4.1 stores it as STRING, not JSON, precisely so §6.4 can
    embed it **verbatim**: the JSON type normalises on ingest — sorts keys, drops duplicates,
    renders 12.30 as 12.3 — and a normalising column cannot be verbatim.

    A block that will not parse is a `StoreInconsistent` **naming the run**, not a
    `json.JSONDecodeError` from three frames down. `JSONDecodeError` is a `ValueError`, so letting
    it escape would put a corrupt row under the same handler as a coding bug in this module — the
    distinction `merge.StoreInconsistent` exists to keep. A `null` block is different and is
    skipped: `parse.rows` always writes one, so a null is a row that predates the column rather
    than one that is wrong.
    """
    blocks: dict[str, dict[str, Any]] = {}
    for row in rows:
        raw = row.get("run_block")
        if raw is None:
            continue
        if not isinstance(raw, str):
            blocks[row["run_id"]] = dict(raw)
            continue
        try:
            blocks[row["run_id"]] = json.loads(raw)
        except json.JSONDecodeError as error:
            raise merge.StoreInconsistent(
                f"run {row['run_id']}'s run_block is not JSON: {error}. §4.1 stores it as STRING "
                f"so §6.4 can embed it verbatim, which means nothing validates it on the way in"
            ) from error
    return blocks


def _record(
    record: merge.MergedFlow,
    origin: Mapping[str, Any] | None,
    coverage: Mapping[str, Any] | None,
) -> dict[str, Any]:
    resolved = dict(
        origin
        or {
            "capture_sha256": record.capture_sha256,
            "uri": None,
            "uri_status": NOT_RECORDED,
            "filename": None,
            "link_type": None,
            "snaplens": [],
        }
    )
    resolved["run_ids"] = dict(record.run_ids)
    resolved["coverage"] = dict(coverage or {})
    return {
        "origin": resolved,
        "flow": _flow(record),
        "best_tier": record.label.best_tier,
        "labels": [dataclasses.asdict(entry) for entry in record.label.labels],
        "sources": [dataclasses.asdict(entry) for entry in record.label.sources],
    }


def _flow(record: merge.MergedFlow) -> dict[str, Any]:
    """§4.3's struct — a superset of `labels.json`'s flow — plus the key it is stored under."""
    flow = dict(record.flow)
    flow["flow_key"] = record.flow_key
    flow["ts_first"] = _iso(record.label.flow.ts_first)
    flow["ts_last"] = _iso(record.label.flow.ts_last)
    return flow


def _iso(ts: float) -> str:
    """Epoch seconds in flabel's one timestamp format (`docs/spec.md` §10).

    `UTC` is passed explicitly: `datetime.fromtimestamp(ts)` without a tzinfo returns *local* time,
    which is invisible on a UTC CI runner and silently wrong by whole hours everywhere else.
    """
    return datetime.fromtimestamp(ts, UTC).strftime(TIMESTAMP_FORMAT) + "Z"
