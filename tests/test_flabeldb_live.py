"""The live round-trip: `flabel-db apply`, then `verify`, against a real BigQuery dataset.

**These are the tests whose absence let PR #157 go green with two broken commands.** Everything
else in the LS-3 suite is pure — it clusters on `schema.differences()` and the exit codes and stops
exactly where the code meets BigQuery, which is where both Criticals lived and where all four
measured surprises in spec §10 lived.

They do NOT run in CI: there is no GCP credential there, the metadata server is absent from GitHub
Actions, and this repo is public so no key may be committed (Workload Identity Federation would
solve it and was declined as out of scope). They are run by hand on `fl-replay`, which reaches the
instance service account through the metadata server with no `sudo` and no reauthentication:

    uv run pytest -q --bigquery -m requires_bigquery

`flabel-db verify` is a pre-deploy gate in `tools/flabel-deploy` for the same reason.

Run them with the project set and a scratch dataset that already exists:

    GCP_PROJECT=<id> uv run pytest -q --bigquery tests/test_flabeldb_live.py

They are **off without `--bigquery`**, because they delete and recreate tables and the metadata
server on `fl-replay` would otherwise make a bare `pytest` rewrite a dataset.
`FLABELDB_TEST_DATASET` overrides the dataset, which defaults to `flabel_scratch`. They never touch
`flabel`: the fixture refuses to run against it, because these tests delete and recreate tables.
"""

from __future__ import annotations

import os

import pytest

from flabeldb import schema

pytestmark = pytest.mark.requires_bigquery

DATASET = os.environ.get("FLABELDB_TEST_DATASET", "flabel_scratch")


@pytest.fixture(scope="module")
def bq():
    """A real client, or a skip. Never `flabel` — these tests destroy and recreate tables."""
    if DATASET == "flabel":
        pytest.fail(
            "refusing to run the live tests against `flabel`: they delete and recreate tables. "
            "Set FLABELDB_TEST_DATASET to a scratch dataset."
        )
    pytest.importorskip("google.cloud.bigquery", reason="the db extra is not installed")
    from flabeldb import client

    if not (os.environ.get("GCP_PROJECT") or _metadata_project()):
        pytest.skip("no project: set GCP_PROJECT (or run on an instance with a metadata server)")
    found = client.client(project=os.environ.get("GCP_PROJECT") or _metadata_project())
    try:
        found.get_dataset(f"{found.project}.{DATASET}")
    except Exception as error:  # noqa: BLE001 - any failure here means we cannot test, not a bug
        pytest.skip(f"cannot reach {DATASET}: {type(error).__name__}: {error}")
    return found


def _metadata_project() -> str | None:
    """The project from the GCE metadata server, or None. No `sudo`, no credential file."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        headers={"Metadata-Flavor": "Google"},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.read().decode().strip()
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def rebuild(bq, name: str) -> None:
    """`name`, deleted and recreated from the declaration. The manual rebuild, done by hand."""
    from flabeldb import client

    bigquery = client._bigquery()
    table = schema.TABLES[name]
    reference = f"{bq.project}.{DATASET}.{name}"
    bq.delete_table(reference, not_found_ok=True)
    target = bigquery.Table(reference, schema=client.to_bigquery(table.fields))
    target.description = table.description
    if table.partition_field:
        target.time_partitioning = bigquery.TimePartitioning(field=table.partition_field)
    if table.clustering:
        target.clustering_fields = list(table.clustering)
    bq.create_table(target)


def test_apply_then_verify_is_clean(bq, capsys):
    """CRITICAL 1, as it was actually measured.

    Before the fix this did not merely report phantom drift: `verify` died with
    `ValueError: flow: only a STRUCT may carry subfields`, uncaught, which exits 1 = EXIT_DRIFT —
    so `tools/flabel-deploy` would have blocked every deploy while naming a schema problem that did
    not exist. With the guard past, it reported 24 differences against a dataset `apply` had just
    created, because `tables.get` answers `INTEGER` for `INT64` and `RECORD` for `STRUCT`.
    """
    from flabeldb import cli

    for name in schema.TABLES:
        rebuild(bq, name)

    assert cli._apply(bq, DATASET) == cli.EXIT_OK
    capsys.readouterr()
    assert cli._verify(bq, DATASET) == cli.EXIT_OK, capsys.readouterr().err


def test_verify_sees_real_drift_in_the_live_table(bq, capsys):
    """The other half: a clean verify is only worth something if a dirty one still fails."""
    from flabeldb import cli, client

    bigquery = client._bigquery()
    rebuild(bq, "run_exclusions")
    reference = f"{bq.project}.{DATASET}.run_exclusions"
    live = bq.get_table(reference)
    live.schema = [*list(live.schema), bigquery.SchemaField("smuggled", "STRING")]
    bq.update_table(live, ["schema"])

    assert cli._verify(bq, DATASET) == cli.EXIT_DRIFT
    assert "smuggled" in capsys.readouterr().err
    rebuild(bq, "run_exclusions")


def test_apply_patches_a_live_table_rather_than_reporting_a_success_it_did_not_make(bq, capsys):
    """CRITICAL 2. `create_table(exists_ok=True)` printed a success line and changed nothing."""
    from flabeldb import cli, client

    bigquery = client._bigquery()
    table = schema.TABLES["run_exclusions"]
    reference = f"{bq.project}.{DATASET}.run_exclusions"
    bq.delete_table(reference, not_found_ok=True)
    narrowed = bigquery.Table(reference, schema=client.to_bigquery(table.fields)[:-1])
    narrowed.description = "a stale description left behind by a console edit"
    bq.create_table(narrowed)

    assert cli._apply(bq, DATASET) == cli.EXIT_OK
    live = bq.get_table(reference)
    assert "excluded_by" in [field.name for field in live.schema], "apply did not patch"
    assert live.description == table.description, "apply did not patch the description"
    assert list(live.clustering_fields or ()) == list(table.clustering)
    capsys.readouterr()
    assert cli._verify(bq, DATASET) == cli.EXIT_OK, "apply patched, but verify still sees drift"


def test_a_narrowed_type_is_named_as_a_rebuild_and_apply_does_not_exit_zero(bq, capsys):
    """Craig 2026-08-20: apply must name a rebuild rather than fail obscurely.

    BigQuery refuses a type change on `update_table` with a bare
    `400 Provided Schema does not match Table`, which says nothing about what to do.
    """
    from flabeldb import cli, client

    bigquery = client._bigquery()
    table = schema.TABLES["captures"]
    reference = f"{bq.project}.{DATASET}.captures"
    bq.delete_table(reference, not_found_ok=True)
    fields = client.to_bigquery(table.fields)
    fields[0] = bigquery.SchemaField("capture_sha256", "INT64", mode="REQUIRED")
    broken = bigquery.Table(reference, schema=fields)
    broken.description = table.description
    broken.clustering_fields = list(table.clustering)
    bq.create_table(broken)

    assert cli._apply(bq, DATASET) == cli.EXIT_DRIFT
    output = capsys.readouterr()
    combined = output.out + output.err
    assert "capture_sha256" in combined
    assert "REBUILT" in combined or "rebuild" in combined.lower()

    rebuild(bq, "captures")
    capsys.readouterr()
    assert cli._apply(bq, DATASET) == cli.EXIT_OK, "the rebuild the message asked for did not work"

