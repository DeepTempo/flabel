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

#: The `selection` fields that describe the RESULT rather than the request. Excluded from a
#: reproduction comparison — see `comparable`, which records the measurement that showed why.
SELECTION_OUTCOMES = frozenset({"captures", "flows", "flows_without_origin"})

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
    #: §6.5's audit cutoff, an ISO-8601 instant or `None`. Filters candidate runs on `ingested_at`,
    #: never on `finished_at` — see `schema.AS_OF_PREDICATE` for why both clocks are needed.
    as_of: str | None = None


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
            [blocks[run_id] for run_id in sorted(set(tiers.values())) if run_id in blocks],
            # The keys, not the values: a capture supplied by one run at both tiers still has two
            # tiers, and `set(tiers.values())` would collapse it to one block and one tier.
            sorted(tiers),
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
    # run_id -> (capture, the tiers it SUPPLIES here). A run covers exactly one capture (§3.3), so
    # the pair is well defined; `supplies` is a subset of that run's `tiers_attested` whenever a
    # newer run has taken one of its tiers.
    supplied: dict[str, tuple[str, list[int]]] = {}
    for capture in captures_present:
        for tier, run_id in sorted(auth.by_capture.get(capture, {}).items()):
            capture_seen, tiers = supplied.setdefault(run_id, (capture, []))
            tiers.append(tier)
            if capture_seen != capture:
                # **Not unreachable, and an earlier version of this said it was.** §3.3 makes it
                # impossible for a run the STORE produced, but `--rebuild` builds an `Authority`
                # from a document, and a hand-edited one can name a run under two captures. That
                # reached here and was reported as "a DEFECT in blfile" at exit 3 for a bad input
                # file. `read_prior` now refuses it as `NotACollection`, so this is the backstop
                # rather than the gate — kept because `build` is reachable from both paths.
                raise ValueError(
                    f"run {run_id} supplies two captures ({capture_seen}, {capture}); §3.3 derives "
                    f"a run id from one capture, so this must not be guessed at"
                )
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
            # **Inputs, not outcomes**, and they are here so §6.5's `--rebuild` can READ the
            # selection instead of inferring it. Both are derivable from the records — the limit
            # from the record count, the flag from whether any emitted origin is `not-recorded` —
            # and an inference that happens to work is a worse contract than a field.
            "limit": selection.limit,
            "allow_missing_origin": selection.allow_missing_origin,
            "as_of": selection.as_of,
        },
        # **`run_id`, `capture_sha256` and `supplies` beside the verbatim block.** §6.4's example
        # literal shows the id and LS-7 omitted it; the other two are what make §6.5's pinned set
        # *usable*, and getting that wrong was a defect rather than a shortfall.
        #
        # "The pinned `run_id` set" is under-specified in §6.5, and the first implementation read
        # it as ids alone and recovered each run's tiers from `runs.tiers_attested`. Those are
        # different things — §5.2 rule 2 turns on exactly the difference — so a `--both` run
        # ATTESTING [1, 2] while SUPPLYING only tier 1 made the rebuild see two runs for one
        # (capture, tier) and fail, naming a view it had never queried, on a consistent store.
        # Measured: any capture re-run at one tier produced an un-rebuildable document.
        #
        # With the authority recorded, a rebuild is a function of the document plus the rows —
        # which is what §6.5 promises — rather than of today's `tiers_attested`.
        "runs": [
            _run_entry(run_id, supplied[run_id], blocks[run_id])
            for run_id in runs_present
            if run_id in blocks
        ],
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


# --- reproduction (§6.5) --------------------------------------------------------------------------


class NotACollection(Exception):
    """The file handed to `--rebuild` is not a `labels-collection` this build can reproduce from."""


@dataclasses.dataclass(frozen=True)
class Prior:
    """A previous collection, as the inputs needed to rebuild it plus what it claimed.

    §6.5: `--rebuild` "takes the selection **and the pinned `run_id` set** from a prior document,
    making the output a function of that document plus the store." Everything here is read from the
    file; nothing is inferred, which is why LS-9 added `selection.limit`,
    `selection.allow_missing_origin` and `runs[].run_id` to §6.4's block.
    """

    selection: Selection
    #: The runs the prior document was built from. **Pinned**: §5.1's "which run supplies this tier
    #: now" is not re-asked, or `--rebuild` would be a function of today's store.
    pinned_runs: tuple[str, ...]
    #: Which run supplied which (capture, tier), **read from the document**. Not re-derived from
    #: `runs.tiers_attested`: a run can attest a tier a newer run has since taken, and treating
    #: attested as supplied made every partially-superseded capture un-rebuildable.
    authority: merge.Authority
    builder: Mapping[str, Any]
    document: Mapping[str, Any]


# --- the shape `--rebuild` reads (§6.4), declared once -------------------------------------------
#
# **Why a declaration rather than a checklist.** Three consecutive rounds of review found the same
# defect here: a validation fix that covered every field but one, and the one it missed reached the
# interpreter as exit 1 or was announced as "a DEFECT in blfile" at exit 3. Round one missed the
# pinned tiers, round two validated two of three pin fields and missed `run_id`, round three
# validated `run_id` and `limit` and missed `selection.labels`. Each fix was correct and each left a
# next field to miss.
#
# So the shape is stated once, walked once, and `test_blfile.py` asserts it covers every
# key a real document carries — the same arrangement `RUN_ID_COLUMN` has against `schema.TABLES`
# and `LOAD_ORDER` has against the declaration. A field added to `build` without a
# line here is a failing test rather than a latent crash.
#
# What is deliberately NOT specced: the interiors of `flow`, `sources`, `labels[]` entries and
# `builder`. No rebuild path indexes into them — they are compared by equality, which cannot raise —
# so the canonicalisation check in `read_prior` is their whole requirement. Anything a code path
# *reads* is specced; that is the rule, and the coverage test enforces it one level down from here.


@dataclasses.dataclass(frozen=True)
class Shape:
    """What one field of the document may be."""

    kind: tuple[type, ...]
    #: May be present and `null`.
    nullable: bool = False
    #: `bool` is a subclass of `int`, and `True` as a limit silently means one flow.
    reject_bool: bool = False
    #: For a list: what each element must be.
    items: Shape | None = None
    #: For a mapping: the fields that are read. Extra keys are ignored at runtime and refused by the
    #: coverage test, which is the split that matters — runtime must not crash, the test must not
    #: let a field go unspecced.
    fields: Mapping[str, Shape] | None = None
    #: For an int: the smallest legal value.
    minimum: int | None = None
    #: A list that must not be empty.
    non_empty: bool = False
    #: This mapping **embeds something written elsewhere**, so it carries keys this declaration has
    #: no business naming: a `runs[]` entry wraps §6.4's verbatim run block, `origin` wraps §4.2's
    #: sighting plus the coverage block, `flow` wraps §4.3's struct. Only the keys a rebuild path
    #: *indexes* are specced; the rest are compared by equality, which cannot raise, and are covered
    #: by `read_prior`'s canonicalisation check.
    #:
    #: **Everything else is closed**, and that is where the coverage test has teeth: a new key
    #: in the document proper, in `selection`, or in a `labels[]` record must be declared or the
    #: test fails. An `embeds` map is where "declare every key" would be a lie.
    embeds: bool = False


_STRING = Shape(kind=(str,))
_INT = Shape(kind=(int,), reject_bool=True)
_BOOL = Shape(kind=(bool,))

#: §6.4's document, as the fields any rebuild path reads.
DOCUMENT_SHAPE = Shape(
    kind=(Mapping,),
    fields={
        "document_type": _STRING,
        "schema_version": _STRING,
        "built_at": _STRING,
        "builder": Shape(kind=(Mapping,)),
        "selection": Shape(
            kind=(Mapping,),
            fields={
                "labels": Shape(kind=(list,), items=_STRING),
                "match": _STRING,
                "captures": _INT,
                "flows": _INT,
                "flows_without_origin": _INT,
                # `minimum=1` because `blfile` refuses `--limit 0` on the command line, and a
                # document path that accepts what the CLI refuses put the failure on exit 1.
                "limit": Shape(kind=(int,), reject_bool=True, nullable=True, minimum=1),
                "allow_missing_origin": _BOOL,
                "as_of": Shape(kind=(str,), nullable=True),
            },
        ),
        "runs": Shape(
            kind=(list,),
            non_empty=True,
            items=Shape(
                kind=(Mapping,),
                embeds=True,
                fields={
                    "run_id": _STRING,
                    "capture_sha256": _STRING,
                    "supplies": Shape(kind=(list,), non_empty=True, items=_INT),
                },
            ),
        ),
        "labels": Shape(
            kind=(list,),
            items=Shape(
                kind=(Mapping,),
                fields={
                    # `capture_sha256` and `flow_key` are the pair `differences` keys its record
                    # index on (§3.2), so they must be hashable strings or the index raises.
                    "origin": Shape(
                        kind=(Mapping,), embeds=True, fields={"capture_sha256": _STRING}
                    ),
                    "flow": Shape(kind=(Mapping,), embeds=True, fields={"flow_key": _STRING}),
                    "best_tier": _INT,
                    "labels": Shape(kind=(list,), items=Shape(kind=(Mapping,))),
                    "sources": Shape(kind=(list,), items=Shape(kind=(Mapping,))),
                },
            ),
        ),
    },
)


def _named(kinds: tuple[type, ...]) -> str:
    return " or ".join("object" if kind is Mapping else kind.__name__ for kind in kinds)


def validate_document(
    document: object, shape: Shape = DOCUMENT_SHAPE, path: str = "the document"
) -> None:
    """Walk `document` against `shape`, raising `NotACollection` naming the path that is wrong.

    Every message names the path, because "not an object" is useless without knowing which one.
    """
    if document is None:
        if shape.nullable:
            return
        raise NotACollection(f"{path} is null")
    if not isinstance(document, shape.kind):
        raise NotACollection(f"{path} is a {type(document).__name__}, not {_named(shape.kind)}")
    if shape.reject_bool and isinstance(document, bool):
        raise NotACollection(
            f"{path} is a bool; `True` is an int in Python and would be read as the number 1"
        )
    if shape.minimum is not None and isinstance(document, int) and document < shape.minimum:
        raise NotACollection(
            f"{path} is {document}, and the smallest legal value is {shape.minimum}"
        )
    if shape.non_empty and not document:
        raise NotACollection(f"{path} is empty")
    if shape.items is not None:
        for index, item in enumerate(document):
            validate_document(item, shape.items, f"{path}[{index}]")
    if shape.fields is not None:
        for name, field in shape.fields.items():
            if name not in document:
                raise NotACollection(f"{path} has no {name!r}")
            validate_document(document[name], field, f"{path}.{name}")


def read_prior(document: Mapping[str, Any]) -> Prior:
    """A prior `labels-collection` as a `Prior`, or a readable refusal.

    Three steps, in this order and for this reason:

    1. **Identity** — `document_type` and `schema_version`. §9 says a collection must never be
       stamped with `labels.json`'s version, and the other direction matters as much: handed a
       `labels.json`, `--rebuild` would read no selection, rebuild from an empty pin, and report a
       perfect reproduction of nothing.
    2. **Shape** — one walk of `DOCUMENT_SHAPE`, which is the whole of the type checking. This
       replaced four rounds of per-field `isinstance` calls, each of which covered every field but
       one; see that declaration for the history.
    3. **Meaning** — the things a type cannot say: that the document canonicalises, and that it
       does not name one run under two captures.
    """
    if not isinstance(document, Mapping):
        raise NotACollection(f"the file holds a {type(document).__name__}, not an object")
    kind = document.get("document_type")
    if kind != DOCUMENT_TYPE:
        raise NotACollection(
            f"document_type is {kind!r}, not {DOCUMENT_TYPE!r}. `--rebuild` needs a collection; a "
            f"labels.json describes one run over one capture and has no selection to reproduce"
        )
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        raise NotACollection(
            f"schema_version is {version!r} and this build writes {SCHEMA_VERSION!r}. Reproducing "
            f"across a document version is not what §6.5 promises"
        )

    validate_document(document)

    try:
        # Catches a `NaN`/`Infinity` literal — `json.loads` accepts them and `serialise` refuses
        # them (`allow_nan=False`, spec §10) — plus anything else that cannot be canonicalised. It
        # is also what covers every field the shape deliberately does not spec, since a value that
        # survives canonicalisation can only ever be compared, never indexed.
        serialise(document)
    except ValueError as error:
        raise NotACollection(f"this document cannot be canonicalised: {error}") from error

    selection = document["selection"]
    runs = document["runs"]
    pinned = [entry["run_id"] for entry in runs]
    # Types are `DOCUMENT_SHAPE`'s job. What is left is the one thing a type cannot say: §3.3
    # derives a run id from one capture, so no run may be listed under two. The store cannot
    # produce that — but a hand-edited document can, and it used to reach `build`'s own guard and
    # be reported as "a DEFECT in blfile" at exit 3 for a bad input file.
    by_run: dict[str, str] = {}
    for entry in runs:
        seen = by_run.setdefault(entry["run_id"], entry["capture_sha256"])
        if seen != entry["capture_sha256"]:
            raise NotACollection(
                f"run {entry['run_id']} is listed under two captures ({seen}, "
                f"{entry['capture_sha256']}). §3.3 derives a run id from one capture, so this "
                f"document is inconsistent with itself"
            )
    rows = [
        {"capture_sha256": entry["capture_sha256"], "tier": tier, "run_id": entry["run_id"]}
        for entry in runs
        for tier in entry["supplies"]
    ]
    try:
        authority = merge.authority(rows)
    except merge.StoreInconsistent as error:
        raise NotACollection(
            f"the document's own pinned set names two runs for one (capture, tier): {error}. That "
            f"is a defect in the document rather than in the store"
        ) from error
    return Prior(
        selection=Selection(
            labels=tuple(selection.get("labels") or ()),
            limit=selection.get("limit"),
            allow_missing_origin=bool(selection.get("allow_missing_origin")),
            # **Carried forward, and it has to be.** `collect_rebuild` never passes this to a
            # query — the pinned authority is read from the document, so no cutoff is re-applied —
            # but the rebuilt document must record the same cutoff the original did. Dropping it
            # made the rebuild write `as_of: null` against a document that said otherwise, so
            # `differences` reported one difference and `blfile` exited 1 announcing that "the rows
            # those runs hold have changed". Nothing had changed. §6.5 refuses `--rebuild --as-of`
            # from the COMMAND LINE; that is not the same as forgetting what the document said.
            as_of=selection.get("as_of"),
        ),
        pinned_runs=tuple(sorted(set(pinned))),
        authority=authority,
        builder=dict(document.get("builder") or {}),
        document=document,
    )


def comparable(document: Mapping[str, Any]) -> dict[str, Any]:
    """The part of a document a reproduction is judged on — **everything but `built_at` and
    `builder`**, canonicalised.

    §6.5: "Reproduction is over records, excluding `built_at` — not byte-for-byte", the same
    correction `docs/spec.md` §10 already made for a run's output. `builder` is excluded here and
    compared separately, because a changed `LABEL_KINDS` or store schema is a fact about the build
    rather than a difference in the records, and §6.5 asks for it to be "reported naming both".

    **The round trip through `serialise` is what makes "over records" true rather than aspirational,
    and without it `--rebuild` could never reproduce anything.** One side of the comparison comes
    from `json.loads` of a file and the other is freshly built in memory, where
    `dataclasses.asdict` leaves `sids` and a `multi` value as **tuples** — and `(40151,)` does not
    equal `[40151]`. Measured against the production store: every single record was reported as
    differing, on nothing but that. A document is JSON, so the value being compared is the JSON
    value, not the Python scaffolding that happened to produce it.
    """
    kept = {key: value for key, value in document.items() if key not in ("built_at", "builder")}
    selection = kept.get("selection")
    if isinstance(selection, Mapping):
        # §6.5's promise is over **records**. `selection`'s INPUTS are kept — they are what was
        # asked for, and a rebuild reads them from this very document, so a mismatch would be a
        # defect. Its derived COUNTS are dropped, and `flows_without_origin` is why.
        #
        # Measured against production: a `--limit 20` document pins only the 3 runs whose flows
        # survived truncation, while its `flows_without_origin` counted the 408 in the whole
        # pre-limit selection. Rebuilding from those 3 runs asks a genuinely narrower question and
        # honestly reports 20 — so the count differs while every record matches.
        #
        # Dropping them costs no detection: a changed flow count shows up as an added or removed
        # record, and an origin appearing shows up as `origin.uri` on the record itself. A count
        # that can only disagree when nothing about the records has is not evidence.
        kept["selection"] = {
            key: value for key, value in selection.items() if key not in SELECTION_OUTCOMES
        }
    return json.loads(serialise(kept))


def builder_differences(prior: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    """Every `builder` field that moved, naming both values (§6.5)."""
    return [
        f"builder.{key}: the document says {prior.get(key)!r}, this build is {current.get(key)!r}"
        for key in sorted(set(prior) | set(current))
        if prior.get(key) != current.get(key)
    ]


def differences(prior: Mapping[str, Any], rebuilt: Mapping[str, Any]) -> list[str]:
    """How a rebuild differs from the document it reproduces, in terms an operator can act on.

    Structural first — a differing flow count explains every per-record difference below it — and
    then per flow, keyed on `flow_key` rather than on position, because a rebuild that gained one
    flow would otherwise report every later record as changed.
    """
    found: list[str] = []
    # **Every top-level key, not a list of three.** An allowlist meant a field the document gains
    # later is never compared, so a rebuild that differed in it would report success — and it made
    # `comparable`'s exclusion of `built_at` unobservable, which a sabotage caught: keeping
    # `built_at` in `comparable` changed nothing, because nothing looked at it.
    for key in sorted((set(prior) | set(rebuilt)) - {"runs", "labels"}):
        if prior.get(key) != rebuilt.get(key):
            found.append(f"{key}: {prior.get(key)!r} became {rebuilt.get(key)!r}")

    old_runs = {entry.get("run_id"): entry for entry in prior.get("runs") or ()}
    new_runs = {entry.get("run_id"): entry for entry in rebuilt.get("runs") or ()}
    # The same symmetry the labels index has below: `runs` is excluded from the top-level key loop,
    # so its LENGTH is never compared, and a document listing one run twice would compare equal to a
    # rebuild listing it once.
    for label, entries, index in (
        ("document", prior.get("runs"), old_runs),
        ("rebuild", rebuilt.get("runs"), new_runs),
    ):
        if len(entries or ()) != len(index):
            found.append(f"the {label} lists the same run twice")
    for run_id in sorted(set(old_runs) - set(new_runs), key=str):
        found.append(f"run {run_id} was in the document and is not in the rebuild")
    for run_id in sorted(set(new_runs) - set(old_runs), key=str):
        found.append(f"run {run_id} is in the rebuild and was not in the document")
    # **The blocks themselves, not only the id set.** §6.4 embeds them as provenance — ruleset
    # snapshot, tool versions, mode, `input` — and comparing ids alone meant a run row rewritten by
    # a re-ingest reported REPRODUCED. That is precisely the scenario `--rebuild` audits.
    for run_id in sorted(set(old_runs) & set(new_runs), key=str):
        if old_runs[run_id] != new_runs[run_id]:
            fields = sorted(
                key
                for key in set(old_runs[run_id]) | set(new_runs[run_id])
                if old_runs[run_id].get(key) != new_runs[run_id].get(key)
            )
            found.append(f"run {run_id}'s block differs: {', '.join(fields)}")

    keyed = lambda records: {  # noqa: E731 - a one-line index, named for what it is
        (
            record.get("origin", {}).get("capture_sha256"),
            record.get("flow", {}).get("flow_key"),
        ): record
        for record in records or ()
    }
    old, new = keyed(prior.get("labels")), keyed(rebuilt.get("labels"))
    # `keyed` is a dict, so a repeated (capture, flow_key) would collapse and the cardinality check
    # that used to catch it — `selection.flows` — is now excluded. §3.2 makes the pair unique per
    # collection, so this asserts the assumption rather than trusting it.
    for label, records, index in (("document", prior, old), ("rebuild", rebuilt, new)):
        if len(records.get("labels") or ()) != len(index):
            found.append(
                f"the {label} carries two records for one (capture, flow_key); §3.2 makes that "
                f"pair a flow's identity, so this is a defect in whatever wrote it"
            )
    for key in sorted(set(old) - set(new), key=str):
        found.append(
            f"flow {key[1]} of capture {key[0]} was in the document and is not in the rebuild"
        )
    for key in sorted(set(new) - set(old), key=str):
        found.append(
            f"flow {key[1]} of capture {key[0]} is in the rebuild and was not in the document"
        )
    # Order is part of the contract (§6.4's canonical ordering), so a rebuild that emitted the same
    # records in a different sequence is not a reproduction. Compared only when the sets match, so
    # an added flow reports as one addition rather than as a re-ordering too.
    if set(old) == set(new) and list(old) != list(new):
        found.append(
            "the records are the same but their order differs; §6.4's canonical ordering is part "
            "of the document"
        )
    for key in sorted(set(old) & set(new), key=str):
        if old[key] != new[key]:
            found.append(
                f"flow {key[1]} of capture {key[0]} differs: "
                + ", ".join(
                    f"{field} {old[key].get(field)!r} -> {new[key].get(field)!r}"
                    for field in sorted(set(old[key]) | set(new[key]))
                    if old[key].get(field) != new[key].get(field)
                )
            )
    return found


#: The three keys LS-9 puts beside a verbatim run block. §6.4's example shows `run_id`; the
#: other two are what make the pinned set usable (see `build`).
PIN_KEYS = ("run_id", "capture_sha256", "supplies")


def _run_entry(run_id: str, supplied: tuple[str, list[int]], block: Mapping[str, Any]) -> dict:
    """One `runs[]` entry: the pin, then the run block verbatim.

    **A collision is refused rather than resolved.** The block is spread last, so a run block that
    ever gained a `run_id` key of its own would win and `--rebuild` would start pinning whatever the
    block said, silently. `docs/spec.md` §10's key set has none of these three today and the earlier
    test for it inspected a hand-written fixture rather than the real thing — so the guard is here,
    where it cannot be out of date.
    """
    collisions = [key for key in PIN_KEYS if key in block]
    if collisions:
        # **`StoreInconsistent`, not `ValueError`.** The trigger is `runs.run_block`, a STRING
        # column `_run_blocks` records as deliberately unvalidated on ingest — so this is a fact
        # about a row the store holds. A bare `ValueError` reached `main`'s catch-all and printed
        # "This is a DEFECT in blfile" with a developer-facing message and no operator workaround.
        # `_run_blocks` already raises `StoreInconsistent` for an unparseable block, for this
        # reason.
        raise merge.StoreInconsistent(
            f"run {run_id}'s block carries {collisions}, which §6.4's entry uses for the pinned "
            f"set. Spreading the block last would let it decide what this document pins; rename "
            f"the pin keys or nest them before this can ship"
        )
    return {"run_id": run_id, "capture_sha256": supplied[0], "supplies": supplied[1], **block}


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


def _coverage(
    blocks: Sequence[Mapping[str, Any]], tiers: Sequence[int] = ()
) -> dict[str, Any]:
    """What was lost about this capture, over every run currently supplying a tier of it.

    `loss_conditions` is `null` per flag when the stage that would know never ran (§10), and a
    `null` is emphatically not a fired condition — "JA4 was fine" and "nothing ever probed JA4" are
    different facts, which is the whole reason that field is tri-state.

    **`tiers_supplying` (#184) is here rather than left to the consumer**, because `origin.run_ids`
    is per *flow* — it names the tiers that contributed to that flow — so a tier-2-only flow reads
    `{"2": ...}` whether the capture had a tier-1 run that did not flag it or was never replayed at
    all. §2.5 exists to keep those apart and Phase 4 put both populations in one corpus. §6.4's own
    standard is that "recoverable with effort by cross-referencing three fields" is weaker than a
    field, and that argument applies to itself.

    **It reports authority, not attempt, and the name is doing work.** A run that attempted a tier
    without attesting it (§2.4), or one since excluded (§4.5), supplies nothing and is absent here.
    `tiers_examined` was the name in #184 and would have invited the opposite reading. What a
    consumer is actually asking is whether *currently valid* evidence from that tier exists,
    because that is what makes the absence of a label mean anything. Measured 2026-08-28 before
    choosing: no capture in production has an attempted tier without an authoritative run, so the
    two readings agree on today's data and diverge only on a future exclusion or attestation
    failure — which is exactly when a consumer must not be misled.
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
        "tiers_supplying": sorted(tiers),
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
