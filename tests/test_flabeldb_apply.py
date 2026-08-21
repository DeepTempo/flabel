"""`flabel-db apply`, and the line between what BigQuery will patch and what it will not.

`_apply` had **no test at all**, and it did not patch: `create_table(exists_ok=True)` returns
`get_table` on conflict and never calls `update_table` — verified in the library source, then
measured on `flabel_scratch` 2026-08-21, where a table created with one column and re-applied with
two kept one column and its original description while `apply` printed a success line for it.

Craig decided 2026-08-20 that **apply patches what it can and says plainly what it cannot.** So the
decision of which is which is the thing that needs testing, and it lives in `schema.patch_plan` —
pure, no client, so CI can check it, because the `requires_bigquery` tests below do not run there.

Every rule encoded here was measured against the real service on 2026-08-21, one change at a time
on a throwaway table, rather than read off the documentation:

    append a NULLABLE column .................. ACCEPTED
    append a REPEATED column .................. ACCEPTED
    append a REQUIRED column .................. REFUSED
    append a NULLABLE/REPEATED STRUCT subfield  ACCEPTED
    append a REQUIRED STRUCT subfield ......... REFUSED
    relax REQUIRED -> NULLABLE ................ ACCEPTED
    tighten NULLABLE -> REQUIRED .............. REFUSED
    any other mode change ..................... REFUSED
    change a column's type .................... REFUSED
    drop a column ............................. REFUSED
    change a table or column description ...... ACCEPTED
    set / change / remove clustering .......... ACCEPTED
    add, remove or repoint partitioning ....... REFUSED
    reorder columns ........................... ACCEPTED AND SILENTLY IGNORED

That last one is the trap: `update_table` returns 200 for a reordered schema and the live order does
not change, so treating a reorder as patchable would make `apply` claim a fix it did not make and
leave `verify` reporting drift forever. It is a rebuild.
"""

from __future__ import annotations

import pytest

from flabeldb import schema

REQUIRED, NULLABLE, REPEATED = schema.REQUIRED, schema.NULLABLE, schema.REPEATED


def declared(**kw) -> schema.Table:
    kw.setdefault(
        "fields",
        (
            schema.column("run_id", "STRING", mode=REQUIRED),
            schema.column("note", "STRING"),
        ),
    )
    return schema.Table(**kw)


def live_of(table: schema.Table, **kw) -> schema.LiveTable:
    """The same table as the API would report it, unless a keyword says otherwise."""
    return schema.LiveTable(
        fields=kw.pop("fields", table.fields),
        partition_field=kw.pop("partition_field", table.partition_field),
        clustering=kw.pop("clustering", table.clustering),
        description=kw.pop("description", table.description),
    )


def plan_for(table: schema.Table, **live) -> schema.Patch:
    return schema.patch_plan("t", table, live_of(table, **live))


# --- nothing to do ----------------------------------------------------------------------------


def test_a_table_that_already_matches_needs_no_patch_and_no_rebuild():
    found = plan_for(declared())
    assert found.mask == ()
    assert found.changes == ()
    assert found.rebuild == ()
    assert found.is_noop


def test_the_real_declaration_is_a_noop_against_itself_for_every_table():
    """Guards against a planner that reports work on a dataset `apply` has just created."""
    for name, table in schema.TABLES.items():
        found = schema.patch_plan(name, table, live_of(table))
        assert found.is_noop, f"{name}: {found.changes + found.rebuild}"


# --- what BigQuery accepts, so apply must actually do it ----------------------------------------


@pytest.mark.parametrize("mode", [NULLABLE, REPEATED])
def test_a_declared_column_the_table_lacks_is_appended(mode):
    table = declared(
        fields=(
            schema.column("run_id", "STRING", mode=REQUIRED),
            schema.column("note", "STRING"),
            schema.column("added", "INT64", mode=mode),
        )
    )
    found = plan_for(table, fields=table.fields[:2])

    assert "schema" in found.mask
    assert found.rebuild == ()
    assert any("added" in message for message in found.changes)
    assert [item.name for item in found.fields] == ["run_id", "note", "added"], (
        "an addition must be APPENDED to the live order, never used to reorder"
    )


def test_a_required_column_is_relaxed_to_nullable_because_that_direction_is_allowed():
    table = declared(fields=(schema.column("run_id", "STRING"),))
    found = plan_for(table, fields=(schema.column("run_id", "STRING", mode=REQUIRED),))

    assert "schema" in found.mask
    assert found.rebuild == ()
    assert found.fields[0].mode == NULLABLE
    assert any("relax" in message.lower() for message in found.changes)


def test_a_missing_struct_subfield_is_appended():
    def struct(*subfields):
        return schema.column("flow", "STRUCT", fields=list(subfields))

    table = declared(
        fields=(struct(schema.column("proto", "STRING"), schema.column("port", "INT64")),)
    )
    found = plan_for(table, fields=(struct(schema.column("proto", "STRING")),))

    assert "schema" in found.mask
    assert found.rebuild == ()
    assert [item.name for item in found.fields[0].fields] == ["proto", "port"]
    assert any("flow.port" in message for message in found.changes)


def test_clustering_is_patchable_because_bigquery_allows_it_to_change():
    table = declared(clustering=("run_id",))
    found = plan_for(table, clustering=("note",))

    assert "clustering_fields" in found.mask
    assert found.rebuild == ()
    assert any("cluster" in message.lower() for message in found.changes)


def test_a_stale_description_is_patchable():
    table = declared(description="the truth")
    found = plan_for(table, description="something a console edit left behind")

    assert "description" in found.mask
    assert found.rebuild == ()


# --- what BigQuery refuses, so apply must NAME it rather than fail obscurely --------------------


def test_appending_a_required_column_is_a_rebuild_not_a_patch():
    table = declared(
        fields=(
            schema.column("run_id", "STRING", mode=REQUIRED),
            schema.column("note", "STRING"),
            schema.column("added", "INT64", mode=REQUIRED),
        )
    )
    found = plan_for(table, fields=table.fields[:2])

    assert found.rebuild, "a REQUIRED addition cannot be patched — BigQuery refuses it"
    assert any("added" in message and "REQUIRED" in message for message in found.rebuild)
    assert "schema" not in found.mask, "nothing else to patch, so do not send a schema update"


def test_tightening_a_mode_is_a_rebuild():
    table = declared(fields=(schema.column("run_id", "STRING", mode=REQUIRED),))
    found = plan_for(table, fields=(schema.column("run_id", "STRING"),))

    assert any("run_id" in message for message in found.rebuild)
    assert found.changes == ()


@pytest.mark.parametrize(
    "live_mode, declared_mode",
    [(NULLABLE, REPEATED), (REPEATED, NULLABLE), (REQUIRED, REPEATED)],
)
def test_no_other_mode_change_is_patchable(live_mode, declared_mode):
    table = declared(fields=(schema.column("run_id", "STRING", mode=declared_mode),))
    found = plan_for(table, fields=(schema.column("run_id", "STRING", mode=live_mode),))

    assert found.rebuild
    assert found.changes == ()


def test_a_changed_type_is_a_rebuild_and_says_so():
    table = declared(fields=(schema.column("run_id", "INT64"),))
    found = plan_for(table, fields=(schema.column("run_id", "STRING"),))

    assert any("run_id" in message and "type" in message for message in found.rebuild)


def test_an_undeclared_live_column_is_a_rebuild_because_a_column_cannot_be_dropped():
    table = declared()
    found = plan_for(table, fields=(*table.fields, schema.column("smuggled", "STRING")))

    assert any("smuggled" in message for message in found.rebuild)


def test_a_reordered_table_is_a_rebuild_even_though_the_api_returns_200():
    """The measured trap: a reorder is accepted and silently ignored."""
    table = declared()
    found = plan_for(table, fields=tuple(reversed(table.fields)))

    assert found.rebuild, "reversed columns must not read as patchable"
    assert any("order" in message.lower() for message in found.rebuild)
    assert "schema" not in found.mask


@pytest.mark.parametrize(
    "declared_field, live_field",
    [("finished_at", None), (None, "finished_at"), ("finished_at", "other_at")],
    ids=["add-partitioning", "remove-partitioning", "repoint-partitioning"],
)
def test_every_partitioning_change_is_a_rebuild(declared_field, live_field):
    fields = (
        schema.column("finished_at", "TIMESTAMP"),
        schema.column("other_at", "TIMESTAMP"),
    )
    table = schema.Table(fields=fields, partition_field=declared_field)
    found = schema.patch_plan(
        "t", table, schema.LiveTable(fields=fields, partition_field=live_field)
    )

    assert any("partition" in message.lower() for message in found.rebuild)


# --- the whole point: a rebuild is named, not hidden -------------------------------------------


def test_what_can_be_patched_is_patched_even_when_something_else_needs_a_rebuild():
    """Craig 2026-08-20: apply patches what it can and says what it cannot. Both, not either."""
    table = declared(
        fields=(
            schema.column("run_id", "INT64", mode=REQUIRED),  # type change -> rebuild
            schema.column("note", "STRING"),
            schema.column("added", "INT64"),  # -> patchable
        ),
        description="the truth",  # -> patchable
    )
    found = schema.patch_plan(
        "t",
        table,
        schema.LiveTable(
            fields=(
                schema.column("run_id", "STRING", mode=REQUIRED),
                schema.column("note", "STRING"),
            ),
            description="stale",
        ),
    )

    assert any("added" in message for message in found.changes), "the patchable part was dropped"
    assert "description" in found.mask
    assert any("run_id" in message for message in found.rebuild), "the rebuild was not named"
    assert not found.is_noop


# --- apply itself, which had no test at all ----------------------------------------------------

#: The `db` extra. A MARKER, not a skipif: the detection is the fragile part —
#: `find_spec` on a dotted name RAISES when the parent is absent rather than returning
#: None, so three copies of that check made the suite red on a checkout without the extra.
#: tests/conftest.py now owns it, once. These tests import the client's exception TYPES
#: and call no API; CI installs the extra precisely so they are not skipped there.
needs_client = pytest.mark.requires_db_extra


class FakeBQ:
    """A BigQuery client that records calls. The client's own `Table`/`SchemaField` are real.

    Faking the *transport* and not the *types* is deliberate: the types are pure data and the bug
    this file exists for was a wrong belief about which METHOD patches, which a fake type would
    have let us restate rather than catch.
    """

    project = "p"

    def __init__(self, existing=None):
        self.existing = dict(existing or {})
        self.created: list = []
        self.updated: list[tuple[str, list[str]]] = []
        self.queries: list[str] = []

    def get_table(self, reference):
        from google.api_core.exceptions import NotFound

        name = reference.rsplit(".", 1)[-1]
        if name not in self.existing:
            raise NotFound(f"no such table: {reference}")
        return self.existing[name]

    def create_table(self, table, exists_ok=False):
        self.created.append(table)
        self.existing[table.table_id] = table
        return table

    def update_table(self, table, mask):
        self.updated.append((table.table_id, list(mask)))
        self.existing[table.table_id] = table
        return table

    def query(self, sql, job_config=None):
        self.queries.append(sql)
        return type("Job", (), {"result": lambda self: []})()


def as_live_table(name, table):
    """`table` as the client object `tables.get` would hand back, legacy type names and all."""
    from flabeldb import client

    bigquery = client._bigquery()
    found = bigquery.Table(f"p.d.{name}", schema=client.to_bigquery(table.fields))
    found.description = table.description
    if table.partition_field:
        found.time_partitioning = bigquery.TimePartitioning(field=table.partition_field)
    if table.clustering:
        found.clustering_fields = list(table.clustering)
    return found


@needs_client
def test_apply_creates_a_table_that_is_not_there():
    from flabeldb import cli

    bq = FakeBQ()
    assert cli._apply(bq, "d") == cli.EXIT_OK
    assert sorted(item.table_id for item in bq.created) == sorted(schema.TABLES)
    assert bq.updated == [], "nothing existed, so nothing should have been patched"


@needs_client
def test_apply_does_not_write_to_a_table_that_already_matches():
    from flabeldb import cli

    bq = FakeBQ({name: as_live_table(name, t) for name, t in schema.TABLES.items()})
    assert cli._apply(bq, "d") == cli.EXIT_OK
    assert bq.created == []
    assert bq.updated == [], "a matching table must not be rewritten"


@needs_client
def test_apply_patches_a_table_that_exists_and_is_missing_a_column():
    """THE DEFECT. `create_table(exists_ok=True)` returned the existing table and changed nothing.

    Measured on `flabel_scratch` 2026-08-21: one column in, two declared, and the live table still
    had one column and its original description while `apply` printed a success line.
    """
    from flabeldb import cli

    live = {name: as_live_table(name, t) for name, t in schema.TABLES.items()}
    narrowed = as_live_table("run_exclusions", schema.TABLES["run_exclusions"])
    narrowed.schema = list(narrowed.schema)[:-1]  # drop `excluded_by`, a NULLABLE column
    live["run_exclusions"] = narrowed

    bq = FakeBQ(live)
    assert cli._apply(bq, "d") == cli.EXIT_OK
    assert [name for name, _ in bq.updated] == ["run_exclusions"]
    name, mask = bq.updated[0]
    assert "schema" in mask
    assert "excluded_by" in [f.name for f in bq.existing["run_exclusions"].schema], (
        "apply reported success without the column arriving"
    )


@needs_client
def test_apply_names_a_rebuild_and_does_not_report_success(capsys):
    """A narrowed type cannot be patched, so `apply` must say so and must not exit 0."""
    from flabeldb import cli

    live = {name: as_live_table(name, t) for name, t in schema.TABLES.items()}
    bigquery = __import__("google.cloud.bigquery", fromlist=["bigquery"])
    broken = as_live_table("run_exclusions", schema.TABLES["run_exclusions"])
    broken.schema = [
        bigquery.SchemaField("run_id", "INTEGER", mode="REQUIRED"),  # declared STRING
        *list(broken.schema)[1:],
    ]
    live["run_exclusions"] = broken

    bq = FakeBQ(live)
    found = cli._apply(bq, "d")
    output = capsys.readouterr()

    assert found == cli.EXIT_DRIFT, "apply could not reach the declaration, so it must not exit 0"
    combined = output.out + output.err
    assert "run_exclusions" in combined
    assert "rebuild" in combined.lower(), "the operator must be told a rebuild is what this needs"


@needs_client
def test_apply_still_creates_every_view():
    from flabeldb import cli

    bq = FakeBQ({name: as_live_table(name, t) for name, t in schema.TABLES.items()})
    cli._apply(bq, "d")
    assert len(bq.queries) == len(cli.view_sql("d"))
    assert any("authoritative_runs" in sql for sql in bq.queries)


@needs_client
def test_a_rebuild_does_not_stop_the_other_tables_being_patched():
    """Patches what it can, says what it cannot — both, in one run."""
    from flabeldb import cli

    live = {name: as_live_table(name, t) for name, t in schema.TABLES.items()}
    bigquery = __import__("google.cloud.bigquery", fromlist=["bigquery"])
    broken = as_live_table("captures", schema.TABLES["captures"])
    broken.schema = [
        bigquery.SchemaField("capture_sha256", "INTEGER", mode="REQUIRED"),
        *list(broken.schema)[1:],
    ]
    live["captures"] = broken
    patchable = as_live_table("run_exclusions", schema.TABLES["run_exclusions"])
    patchable.schema = list(patchable.schema)[:-1]
    live["run_exclusions"] = patchable

    bq = FakeBQ(live)
    assert cli._apply(bq, "d") == cli.EXIT_DRIFT
    assert [name for name, _ in bq.updated] == ["run_exclusions"], (
        "the patchable table was skipped because another one needed a rebuild"
    )
