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
        names = [item.name for item in self.fields]
        if len(names) != len(set(names)):
            raise ValueError(f"repeated column name in {names}")
        for key in (*self.clustering, *((self.partition_field,) if self.partition_field else ())):
            if "." in key:
                raise ValueError(
                    f"{key!r} reaches inside a STRUCT; BigQuery allows only top-level fields for "
                    f"partitioning and clustering"
                )
            if key not in names:
                raise ValueError(f"{key!r} is not a column of this table")


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


def field_of(table: str, name: str) -> Column:
    """The named column of the named table. Raises `KeyError` if either is absent."""
    for item in TABLES[table].fields:
        if item.name == name:
            return item
    raise KeyError(f"{table} has no column {name!r}")


def differences(live: Mapping[str, Sequence[Column]]) -> tuple[str, ...]:
    """Every way `live` disagrees with the declaration, as sentences.

    Pure, and that is what makes it CI-checkable: `client.py` reads the live schema and hands the
    result here. Four kinds of drift are reported separately because "detects a difference" is
    satisfied by code that notices only one — and the drift this exists for is a column patched by
    hand in the console, which could be any of them. A changed **mode** is the one most likely to
    slip: `REPEATED` and `NULLABLE` on the same type read alike, and are the difference between a
    list and a scalar.

    Ordered by table then column, so two runs report the same differences in the same order.
    """
    found: list[str] = []
    for name in sorted(TABLES):
        declared = TABLES[name].fields
        if name not in live:
            found.append(f"{name}: table is missing from the dataset")
            continue
        found.extend(_field_differences(name, declared, tuple(live[name])))
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
    return found
