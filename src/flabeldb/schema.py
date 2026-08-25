"""The store's tables, declared once, as the objects the load jobs already need.

**Pure: no client, no network, no credential.** That is what lets CI check it. Spec §2's testing
line records that the `requires_bigquery` tests do not run anywhere — GitHub Actions has no GCP
credential, the metadata server is not there, and the repo is public so no key may be committed —
so logic put behind a client is logic nothing verifies. The schema and the comparison stay out here;
only `apply` and the live read need `client.py`.

Declared in Python rather than in a committed `.sql` file because **the load jobs need the schema in
Python form anyway**, so a `.sql` copy would be a second statement of one fact — and this repo's
recurring defect is two copies where one gets ignored. Views are the other way round: they are SQL
and nothing else needs them, so they live in `views/` as text.
"""

from __future__ import annotations

import pathlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

#: BigQuery modes. `REPEATED` is spelled out rather than inferred from a Python list because the
#: difference between a repeated and a nullable column of the same type is the difference between a
#: list and a scalar, and it reads the same in a casual comparison — which is why `differences()`
#: checks it explicitly.
NULLABLE = "NULLABLE"
REQUIRED = "REQUIRED"
REPEATED = "REPEATED"

#: What `tables.get` calls a type, mapped to what we declare it as.
#:
#: **BigQuery answers in a different vocabulary than it accepts.** Measured against
#: `flabel_scratch` on 2026-08-21, on tables `flabel-db apply` had just created from this very
#: file: the API returned `INTEGER` for every `INT64` and `RECORD` for every `STRUCT`. Unnormalised,
#: that produced **24 differences against a clean dataset** — and before that, a `RECORD` reaching
#: `Column.__post_init__` raised `only a STRUCT may carry subfields`, uncaught, which exits 1 =
#: `EXIT_DRIFT`. So `verify` could never succeed against a table that exists, and the deploy gate
#: would have blocked every deploy while naming a schema problem that did not exist.
#:
#: `INTEGER` and `RECORD` are measured. `FLOAT` and `BOOLEAN` are BigQuery's documented legacy
#: names for types this schema does not currently use — included so that the day a column gains
#: one, it is already right, and marked so nobody mistakes them for something we have seen.
TYPE_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "INTEGER": "INT64",  # measured
        "RECORD": "STRUCT",  # measured
        "FLOAT": "FLOAT64",  # documented; unused here
        "BOOLEAN": "BOOL",  # documented; unused here
    }
)


#: Every type a column in this declaration may be given, in the vocabulary we declare in.
#:
#: Checked by `Table.__post_init__` and **deliberately not by `Column.__post_init__`**, which is
#: the whole lesson of Critical 1. A `Column` is built by this file's declaration AND by
#: `client.from_bigquery` reading a live table, so a guard there fires on live data: a `RECORD`
#: coming back from `tables.get` raised `only a STRUCT may carry subfields`, uncaught, which exits
#: 1 = `EXIT_DRIFT`, so `verify` could never succeed against a table that exists. A type name this
#: file has never heard of must be REPORTED as drift, not crashed on. `Table` is built by the
#: declaration only — `LiveTable` exists to keep it that way — so the strict check goes there.
DECLARABLE_TYPES = frozenset(
    {
        "STRING",
        "BYTES",
        "INT64",
        "FLOAT64",
        "NUMERIC",
        "BIGNUMERIC",
        "BOOL",
        "TIMESTAMP",
        "DATE",
        "TIME",
        "DATETIME",
        "INTERVAL",
        "GEOGRAPHY",
        "JSON",
        "STRUCT",
    }
)

#: The column types `partition_field` may name.
#:
#: These are the three that BigQuery's **time-unit** partitioning accepts — and time-unit is all
#: `cli._apply` can build, because it emits `bigquery.TimePartitioning(field=...)` for any declared
#: `partition_field` and nothing else. INT64 range partitioning is a real BigQuery feature that
#: this code does not emit, so declaring one would produce a table `apply` cannot create. The guard
#: therefore tracks what `apply` can do rather than what the service can; widen it here and in
#: `_apply` together, or not at all.
PARTITIONABLE_TYPES = frozenset({"DATE", "DATETIME", "TIMESTAMP"})

#: BigQuery clusters on at most four columns. A fifth fails at `CREATE TABLE`.
MAX_CLUSTERING_KEYS = 4


def canonical_type(field_type: str) -> str:
    """`field_type` in the vocabulary this module declares in.

    An unknown name is returned **unchanged rather than guessed**: normalisation exists to stop two
    spellings of one type reading as drift, and a normaliser that invented a mapping would do the
    opposite — hide real drift as a match.
    """
    return TYPE_ALIASES.get(field_type, field_type)


@dataclass(frozen=True)
class Column:
    """One BigQuery field. Frozen, like everything in `flabel.models`, for the same reason."""

    name: str
    field_type: str
    mode: str = NULLABLE
    fields: tuple[Column, ...] = ()

    def __post_init__(self) -> None:
        # Canonicalised HERE, at construction, rather than in `differences()` — because this is the
        # one place every Column passes through, whether it came from this file's declaration or
        # from `client.from_bigquery` reading the live table. Normalising at the single choke point
        # is what makes the comparison like-with-like on both sides without either side knowing
        # about the other. The dataclass is frozen, so the write goes through object.__setattr__.
        object.__setattr__(self, "field_type", canonical_type(self.field_type))
        if self.mode not in (NULLABLE, REQUIRED, REPEATED):
            raise ValueError(f"{self.name}: {self.mode!r} is not a BigQuery mode")
        if self.fields and self.field_type != "STRUCT":
            raise ValueError(f"{self.name}: only a STRUCT may carry subfields")
        if self.field_type == "STRUCT" and not self.fields:
            raise ValueError(f"{self.name}: a STRUCT with no subfields describes nothing")


def column(
    name: str, field_type: str, *, mode: str = NULLABLE, fields: Sequence[Column] = ()
) -> Column:
    """A `Column`, with the subfield tuple built for the caller."""
    return Column(name=name, field_type=field_type, mode=mode, fields=tuple(fields))


@dataclass(frozen=True)
class Table:
    """A table declaration: its columns, and how BigQuery should lay them out.

    `partition_field` must name a **top-level** column. Measured 2026-08-20: BigQuery refuses a
    field inside a STRUCT at `CREATE TABLE` — "The field specified for partitioning can only be a
    top-level field" — and a control on a top-level timestamp created fine, so it is the nesting
    rather than the syntax. `__post_init__` refuses it here instead, where a test can see it.
    """

    fields: tuple[Column, ...]
    partition_field: str | None = None
    clustering: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.fields:
            raise ValueError("a table with no columns describes nothing")
        names = [item.name for item in self.fields]
        if len(names) != len(set(names)):
            raise ValueError(f"repeated column name in {names}")
        # Type names are validated HERE and not in `Column`, because a `Column` is also built by
        # `client.from_bigquery` reading a live table — see `DECLARABLE_TYPES` for why that
        # distinction is Critical 1's lesson rather than a style choice.
        _check_types(self.fields)
        if len(self.clustering) > MAX_CLUSTERING_KEYS:
            raise ValueError(
                f"{list(self.clustering)} is {len(self.clustering)} clustering keys; BigQuery "
                f"accepts at most four"
            )
        if len(set(self.clustering)) != len(self.clustering):
            raise ValueError(f"{list(self.clustering)} names a clustering key twice")
        for key in (*self.clustering, *((self.partition_field,) if self.partition_field else ())):
            if "." in key:
                raise ValueError(
                    f"{key!r} reaches inside a STRUCT; BigQuery allows only top-level fields for "
                    f"partitioning and clustering"
                )
            if key not in names:
                raise ValueError(f"{key!r} is not a column of this table")
        if self.partition_field is not None:
            # The guard that was missing. Refusing `flow.ts_first` while accepting `run_id` — a
            # STRING — moved one of two identical failures into CI and left the other at
            # `CREATE TABLE`.
            partitioned = next(item for item in self.fields if item.name == self.partition_field)
            if partitioned.field_type not in PARTITIONABLE_TYPES:
                raise ValueError(
                    f"{self.partition_field!r} is a {partitioned.field_type} column, so it cannot "
                    f"be the partition field; time-unit partitioning takes "
                    f"{sorted(PARTITIONABLE_TYPES)}"
                )
            if partitioned.mode == REPEATED:
                raise ValueError(
                    f"{self.partition_field!r} is REPEATED, so it cannot be the partition field"
                )


def _check_types(fields: Sequence[Column], prefix: str = "") -> None:
    """Raise if any declared column, at any depth, names a type BigQuery does not have."""
    for item in fields:
        if item.field_type not in DECLARABLE_TYPES:
            raise ValueError(f"{prefix}{item.name}: {item.field_type!r} is not a BigQuery type")
        if item.fields:
            _check_types(item.fields, prefix=f"{prefix}{item.name}.")


def _flow() -> Column:
    """The flow, as `labels.json` emits it, plus the content-derived halves of its key.

    `ip_proto` is here because spec §9 step 0 measured two ESP or SCTP conversations between one
    host pair being written with *identical* 5-tuples and different uids — so without it the flow
    key degenerates and two real flows collide into one. `zeek_uid` is stored and must never be
    joined on: under `-D` a uid is positional, so it is "connection #N" in every capture.
    """
    return column(
        "flow",
        "STRUCT",
        fields=[
            column("proto", "STRING"),
            column("ip_proto", "INT64"),
            column("ip_lo", "STRING"),
            column("port_lo", "INT64"),
            column("ip_hi", "STRING"),
            column("port_hi", "INT64"),
            column("src_ip", "STRING"),
            column("src_port", "INT64"),
            column("dst_ip", "STRING"),
            column("dst_port", "INT64"),
            column("ts_first", "TIMESTAMP"),
            column("ts_last", "TIMESTAMP"),
            column("zeek_uid", "STRING"),
            column("ja4", "STRING"),
            column("ja4s", "STRING"),
            column("server_name", "STRING"),
        ],
    )


TABLES: Mapping[str, Table] = MappingProxyType(
    {
        # --- §4.1 -----------------------------------------------------------------------------
        "runs": Table(
            description="One row per ingested run. THE COMMIT MARKER: a run is visible only when "
            "its row exists, because a multi-table load is not atomic.",
            fields=(
                column("run_id", "STRING", mode=REQUIRED),
                column("capture_sha256", "STRING", mode=REQUIRED),
                column("mode", "STRING", mode=REQUIRED),
                column("tiers_attempted", "INT64", mode=REPEATED),
                column("tiers_attested", "INT64", mode=REPEATED),
                column("attestation_notes", "STRING", mode=REPEATED),
                column("started_at", "TIMESTAMP"),
                column("finished_at", "TIMESTAMP"),
                column("flabel_version", "STRING"),
                column("snapshot_id", "STRING"),
                column("archive_uri", "STRING"),
                # STRING, not JSON: the JSON type normalises on ingest — sorts keys, drops
                # duplicates, renders 12.30 as 12.3 — and spec §6.4 embeds this VERBATIM into a
                # collection document. A normalising column cannot be verbatim.
                column("run_block", "STRING"),
                column("ingested_at", "TIMESTAMP"),
            ),
            partition_field="finished_at",
            clustering=("capture_sha256", "mode"),
        ),
        # --- §4.2 -----------------------------------------------------------------------------
        "captures": Table(
            description="One row per SIGHTING of a capture at a path. Append-only; a capture "
            "accumulates sightings, because a URI is a location and the digest is the identity.",
            fields=(
                column("capture_sha256", "STRING", mode=REQUIRED),
                column("uri", "STRING"),
                # gs | local | not-recorded. The third exists so a null `uri` is ONE fact: spec §10
                # is emphatic that null means "not measured", so without it "the operator passed a
                # local path" and "this run predates --source-uri" would be the same value.
                column("uri_status", "STRING"),
                column("filename", "STRING"),
                column("bytes", "INT64"),
                column("format", "STRING"),
                column("link_type", "INT64"),
                # PLURAL. A mergecap pcapng carries one interface description block per input file
                # and nothing makes them agree (measured: 96 and 65535), so a single value would
                # invent a winner and erase the disagreement — the fact the field exists to expose,
                # since Zeek refuses a merge across differing snapshot lengths.
                column("snaplens", "INT64", mode=REPEATED),
                column("observed_by_run_id", "STRING", mode=REQUIRED),
                column("observed_at", "TIMESTAMP"),
            ),
            clustering=("capture_sha256",),
        ),
        # --- §4.3 -----------------------------------------------------------------------------
        "flow_labels": Table(
            description="One row per (run, flow), holding the Label exactly as labels.json emits "
            "it. NOT split per tier: the merge happens in blfile, in Python.",
            fields=(
                column("run_id", "STRING", mode=REQUIRED),
                column("capture_sha256", "STRING", mode=REQUIRED),
                column("flow_key", "STRING", mode=REQUIRED),
                _flow(),
                column("best_tier", "INT64"),
                column(
                    "labels",
                    "STRUCT",
                    mode=REPEATED,
                    fields=[
                        column("name", "STRING"),
                        # REPEATED even for a single-arity kind, so one shape serves both and
                        # `LABEL_KINDS[name].arity` is what tells a reader which to expect.
                        column("value", "STRING", mode=REPEATED),
                        column("tier", "INT64"),
                        column("sids", "INT64", mode=REPEATED),
                    ],
                ),
                column(
                    "sources",
                    "STRUCT",
                    mode=REPEATED,
                    fields=[
                        column("tier", "INT64"),
                        column("source", "STRING"),
                        column("sid", "INT64"),
                        column("rev", "INT64"),
                        column("ruleset", "STRING"),
                        column("admission_basis", "STRING"),
                        column("licence", "STRING"),
                        column("classtype", "STRING"),
                        column("label_basis", "STRING"),
                        column("threat", "STRING"),
                        column("direction", "STRING"),
                    ],
                ),
            ),
            # NO PARTITION. Revision 1 had PARTITION BY DATE(flow.ts_first); BigQuery rejects a
            # field inside a STRUCT at CREATE TABLE, and nothing queries on flow time anyway, so
            # the partition bought nothing while contorting the schema around it.
            clustering=("capture_sha256", "flow_key"),
        ),
        # --- §4.4 -----------------------------------------------------------------------------
        "unmatched": Table(
            description="Detections that fired and could not be placed on a flow. Stored because "
            "spec §13 forbids reading an empty labels[] as 'nothing malicious was found'.",
            fields=(
                column("run_id", "STRING", mode=REQUIRED),
                column("capture_sha256", "STRING", mode=REQUIRED),
                column("tier", "INT64"),
                column("source", "STRING"),
                column("sid", "INT64"),
                column("rev", "INT64"),
                column("threat", "STRING"),
                column("ts", "TIMESTAMP"),
                column("proto", "STRING"),
                column("src_ip", "STRING"),
                column("src_port", "INT64"),
                column("dst_ip", "STRING"),
                column("dst_port", "INT64"),
                column("direction", "STRING"),
                column("reason", "STRING"),
            ),
            partition_field="ts",
            clustering=("capture_sha256", "reason"),
        ),
        # --- §4.5 -----------------------------------------------------------------------------
        "run_exclusions": Table(
            description="Retraction as a RECORD, not a delete. Supersession is decided by wall "
            "clock, and an operator may pin an old --ruleset-snapshot, so a debugging run can "
            "finish later and become authoritative; this is the only way to undo that.",
            fields=(
                column("run_id", "STRING", mode=REQUIRED),
                column("reason", "STRING", mode=REQUIRED),
                column("excluded_at", "TIMESTAMP"),
                column("excluded_by", "STRING"),
            ),
            clustering=("run_id",),
        ),
    }
)


#: Where the committed view SQL lives. Beside this module, because a view is part of the
#: declaration rather than part of the CLI that applies it.
VIEWS = pathlib.Path(__file__).parent / "views"

#: The one predicate `--as-of` adds, and the reason it is here rather than written into a second
#: statement. §6.5: the cutoff filters on `ingested_at` and **never** on `finished_at` — a backfill
#: ingests old tarballs late, so a run finishing 2026-08-17 can carry an `ingested_at` of
#: 2026-09-01, and a `finished_at` filter would let a document rebuilt "as of the 25th" silently
#: gain a run that was not in the store that day. Both clocks are needed and they do different
#: jobs: `ingested_at` selects the candidate set, `finished_at` (already in the ORDER BY) decides
#: which candidate wins.
AS_OF_PREDICATE = "\n    AND r.ingested_at <= @as_of"


def view_names() -> tuple[str, ...]:
    """Every committed view, by name. Sorted, so `apply` is deterministic."""
    return tuple(sorted(path.stem for path in VIEWS.glob("*.sql")))


def render_view(name: str, dataset: str, *, as_of: bool = False, ddl: bool = True) -> str:
    """One committed view's SQL, rendered for the job in hand.

    **Two renderings of one file, which is what stops the supersession rule existing twice.**
    §9 says the merge rule must never be implemented twice and §4.6 says there is exactly one
    view; `--as-of` needs the same selection with one extra predicate, and a second statement —
    view or otherwise — would be a copy that can drift. So:

    * `ddl=True, as_of=False` is what `flabel-db apply` writes. The as-of placeholder renders to
      nothing, so the **executed statement** is exactly what LS-3 shipped and no `apply` against a
      live dataset is implied by LS-9. (The returned *string* is not byte-identical — the file
      gained explanatory comments — but they precede the `CREATE`, and BigQuery does not store
      them. Nothing in the repo compares view text: `cli._verify` diffs `schema.TABLES` only.)
    * `ddl=False, as_of=True` is what `blfile --as-of` runs: the same body as a bare SELECT, with
      `@as_of` bound as a parameter rather than interpolated.

    The dataset is interpolated because it cannot be bound — a dataset name is part of a table
    path, not a value — and `cli.IDENTIFIER` is what guards it at both call sites.
    """
    if name not in view_names():
        raise ValueError(f"{name!r} is not a committed view; have {list(view_names())}")
    if as_of and ddl:
        # Reachable, and it produces `CREATE OR REPLACE VIEW … @as_of`, which BigQuery cannot
        # create: a view takes no parameters. Refused rather than left as a footgun for the next
        # caller, since the two flags are independent booleans and nothing else pairs them.
        raise ValueError(
            "a view cannot carry a query parameter, so as_of and ddl are mutually exclusive: "
            "render the DDL for `flabel-db apply`, or the bare SELECT for `blfile --as-of`"
        )
    header = f"CREATE OR REPLACE VIEW `{dataset}.{name}` AS" if ddl else ""
    return (
        (VIEWS / f"{name}.sql")
        .read_text(encoding="utf-8")
        .replace("{header}", header)
        .replace("{as_of}", AS_OF_PREDICATE if as_of else "")
        .replace("{dataset}", dataset)
    )


@dataclass(frozen=True)
class LiveTable:
    """A table as `tables.get` reports it.

    Deliberately **not** a `Table`: `Table.__post_init__` validates the declaration, and a live
    table is exactly the thing that may be invalid — a console edit can leave it clustered on a
    column that no longer exists, and raising while reading it would turn "the dataset is wrong"
    into a traceback instead of a report.
    """

    fields: tuple[Column, ...]
    partition_field: str | None = None
    clustering: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class Patch:
    """How to bring one live table to the declaration.

    `mask` is the `update_table` field mask — nothing is sent unless it is named there, so an
    unchanged property is never written. `fields` is the schema to send when `"schema"` is in the
    mask: it is the **live order with additions appended**, because BigQuery ignores a reordering
    (measured) and sending the declaration's order would claim a change that does not happen.
    """

    mask: tuple[str, ...] = ()
    fields: tuple[Column, ...] = ()
    changes: tuple[str, ...] = ()
    rebuild: tuple[str, ...] = ()

    @property
    def is_noop(self) -> bool:
        """Whether the live table already matches the declaration."""
        return not self.mask and not self.rebuild


#: The one mode change BigQuery accepts, as `(live, declared)`. Measured 2026-08-21: every other
#: pairing — including NULLABLE->REPEATED and REPEATED->NULLABLE — is refused with
#: "Field a has changed mode from X to Y".
_RELAXATION = (REQUIRED, NULLABLE)


def _merge_fields(
    table: str, declared: Sequence[Column], live: Sequence[Column], prefix: str = ""
) -> tuple[list[Column], list[str], list[str]]:
    """The schema to send, what that patches, and what it cannot.

    Additions are appended after every live column, at each level of nesting, for the same measured
    reason the top level is: a reordered schema is accepted and ignored.
    """
    by_name = {item.name: item for item in declared}
    merged: list[Column] = []
    changes: list[str] = []
    rebuild: list[str] = []

    for actual in live:
        path = f"{prefix}{actual.name}"
        item = by_name.get(actual.name)
        if item is None:
            rebuild.append(
                f"{table}.{path}: column is not declared, and BigQuery cannot drop a column"
            )
            merged.append(actual)
            continue
        if actual.field_type != item.field_type:
            rebuild.append(
                f"{table}.{path}: type is {actual.field_type}, declared {item.field_type} — "
                f"BigQuery cannot change a column's type"
            )
            merged.append(actual)
            continue
        mode = actual.mode
        if actual.mode != item.mode:
            if (actual.mode, item.mode) == _RELAXATION:
                mode = item.mode
                changes.append(f"{table}.{path}: relax mode {actual.mode} -> {item.mode}")
            else:
                rebuild.append(
                    f"{table}.{path}: mode is {actual.mode}, declared {item.mode} — BigQuery "
                    f"allows only {_RELAXATION[0]} -> {_RELAXATION[1]}"
                )
                merged.append(actual)
                continue
        subfields = actual.fields
        if item.fields or actual.fields:
            subfields, sub_changes, sub_rebuild = _merge_fields(
                table, item.fields, actual.fields, prefix=f"{path}."
            )
            changes.extend(sub_changes)
            rebuild.extend(sub_rebuild)
            subfields = tuple(subfields)
        merged.append(
            Column(name=actual.name, field_type=actual.field_type, mode=mode, fields=subfields)
        )

    live_names = {item.name for item in live}
    for item in declared:
        if item.name in live_names:
            continue
        path = f"{prefix}{item.name}"
        if item.mode == REQUIRED:
            # Measured: refused at the top level and inside a STRUCT alike. A REQUIRED column
            # cannot be added to a table that already has rows it would have to be non-null in.
            rebuild.append(
                f"{table}.{path}: column is missing and is declared {REQUIRED} — BigQuery cannot "
                f"append a {REQUIRED} column"
            )
            continue
        merged.append(item)
        changes.append(f"{table}.{path}: add column ({item.field_type} {item.mode})")

    # THE TRAP. `update_table` returns 200 for a reordered schema and the live order does not
    # change, so calling this patchable would make `apply` claim a fix it never made and leave
    # `verify` reporting drift forever. Same helper `differences()` uses, so the gate and the repair
    # cannot disagree.
    reordered = _order_difference(table, declared, live, prefix)
    if reordered:
        rebuild.append(reordered)
    return merged, changes, rebuild


def _order_difference(
    table: str, declared: Sequence[Column], live: Sequence[Column], prefix: str = ""
) -> str | None:
    """A message if the columns present on both sides sit in a different order, else `None`.

    Compared over the columns present on BOTH sides, so an added or dropped column is reported as
    itself and not also as a reordering — one fact, one message.

    Order is load-bearing for a reason `apply` cannot fix: `update_table` accepts a reordered schema
    and **silently ignores it** (measured 2026-08-21), so once a table's order diverges from the
    declaration it stays diverged until the table is rebuilt. One helper serves `differences()` and
    `patch_plan()` so the gate and the repair can never disagree about what counts as reordered.
    """
    declared_names = [item.name for item in declared]
    live_names = {item.name for item in live}
    common_live = [item.name for item in live if item.name in declared_names]
    common_declared = [name for name in declared_names if name in live_names]
    if common_live == common_declared:
        return None
    where = f"{table}.{prefix[:-1]}" if prefix else table
    return (
        f"{where}: column order is {common_live}, declared {common_declared} — BigQuery accepts a "
        f"reordered schema and silently ignores it, so this needs the table rebuilt"
    )


def patch_plan(name: str, declared: Table, live: LiveTable) -> Patch:
    """What `apply` can change about `live` to reach `declared`, and what needs a table rebuild.

    Pure, and that is the point: `apply`'s judgement about what BigQuery permits is the part most
    worth checking, and the `requires_bigquery` tests that would check it do not run in CI. The
    executor in `cli.py` does as it is told here and nothing more.

    Additive changes and relaxations only — that is the whole of what BigQuery permits on an
    existing table, so a narrowed type, a dropped column, a tightened mode, a reordering or any
    partitioning change is named as a rebuild rather than attempted and failed obscurely
    (Craig, 2026-08-20).
    """
    merged, changes, rebuild = _merge_fields(name, declared.fields, live.fields)
    mask: list[str] = []
    if changes:
        mask.append("schema")

    if declared.partition_field != live.partition_field:
        # Measured: all three directions refused — "Cannot convert non partitioned table to
        # partitioned table", "Cannot change partitioning/clustering spec", "Cannot change
        # partitioned table to non partitioned table".
        rebuild.append(
            f"{name}: partitioned on {live.partition_field!r}, declared "
            f"{declared.partition_field!r} — BigQuery cannot add, remove or repoint partitioning"
        )
    if tuple(declared.clustering) != tuple(live.clustering):
        mask.append("clustering_fields")
        changes.append(
            f"{name}: clustering is {list(live.clustering)}, declared {list(declared.clustering)}"
        )
    if declared.description != live.description:
        mask.append("description")
        changes.append(f"{name}: description differs from the declaration")

    return Patch(
        mask=tuple(mask),
        fields=tuple(merged) if "schema" in mask else (),
        changes=tuple(changes),
        rebuild=tuple(rebuild),
    )


def field_of(table: str, name: str) -> Column:
    """The named column of the named table. Raises `KeyError` if either is absent."""
    for item in TABLES[table].fields:
        if item.name == name:
            return item
    raise KeyError(f"{table} has no column {name!r}")


def differences(live: Mapping[str, LiveTable]) -> tuple[str, ...]:
    """Every way `live` disagrees with the declaration, as sentences.

    Pure, and that is what makes it CI-checkable: `client.py` reads the live schema and hands the
    result here. Every kind of drift is reported separately, because "detects a difference" is
    satisfied by code that notices only one — and the drift this exists for is a table patched by
    hand in the console, which could be any of them:

        a column added, dropped, retyped, or its MODE changed — `REPEATED` and `NULLABLE` on the
            same type read alike in a casual comparison, and are the difference between a list and
            a scalar
        the column ORDER, at every level of nesting
        the PARTITION field, the CLUSTERING keys (in order), and the table DESCRIPTION
        a table present in the dataset that the declaration does not name

    The last four were invisible until 2026-08-21, because this compared field lists only. Measured
    against this declaration at the time: reversing all 13 columns of `runs` yielded zero
    differences, and any clustering at all went unnoticed.

    The dataset's own LOCATION is checked by `cli._verify` rather than here, because `LOCATION`
    belongs to the client — it is part of the store's identity — and this module stays pure.

    Ordered by table then column, so two runs report the same differences in the same order.
    """
    found: list[str] = []
    for name in sorted(TABLES):
        declared = TABLES[name]
        if name not in live:
            found.append(f"{name}: table is missing from the dataset")
            continue
        actual = live[name]
        found.extend(_field_differences(name, declared.fields, tuple(actual.fields)))
        # Everything below was invisible to the gate. Measured against this declaration:
        # `flow_labels` clustered on `zeek_uid` — the store's single named never-do — verified
        # clean, and reversing all 13 columns of `runs` yielded zero differences.
        if declared.partition_field != actual.partition_field:
            found.append(
                f"{name}: partitioned on {actual.partition_field!r}, declared "
                f"{declared.partition_field!r}"
            )
        if tuple(declared.clustering) != tuple(actual.clustering):
            found.append(
                f"{name}: clustered on {list(actual.clustering)}, declared "
                f"{list(declared.clustering)} — clustering is hierarchical, so the ORDER of the "
                f"keys is part of the layout, not a set"
            )
        if declared.description != actual.description:
            found.append(
                f"{name}: description differs from the declaration (the declaration is the truth; "
                f"a console edit is not)"
            )
    for name in sorted(set(live) - set(TABLES)):
        found.append(f"{name}: table exists in the dataset but is not declared")
    return tuple(found)


def _field_differences(
    table: str, declared: Sequence[Column], live: Sequence[Column], prefix: str = ""
) -> list[str]:
    by_name = {item.name: item for item in live}
    found: list[str] = []
    for item in declared:
        path = f"{prefix}{item.name}"
        actual = by_name.pop(item.name, None)
        if actual is None:
            found.append(f"{table}.{path}: column is missing from the dataset")
            continue
        if actual.field_type != item.field_type:
            found.append(f"{table}.{path}: type is {actual.field_type}, declared {item.field_type}")
        if actual.mode != item.mode:
            found.append(f"{table}.{path}: mode is {actual.mode}, declared {item.mode}")
        if item.fields or actual.fields:
            found.extend(_field_differences(table, item.fields, actual.fields, prefix=f"{path}."))
    for leftover in sorted(by_name):
        found.append(f"{table}.{prefix}{leftover}: unexpected column, not in the declaration")
    reordered = _order_difference(table, declared, live, prefix)
    if reordered:
        found.append(reordered)
    return found
