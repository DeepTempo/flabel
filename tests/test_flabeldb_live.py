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


# --- the identity, measured rather than asserted about ------------------------------------------


def test_the_store_writes_as_the_instance_service_account(bq):
    """Invariant 7 against the real metadata server, not a monkeypatch.

    The pure tests in `test_flabeldb_credentials.py` prove `credentials()` reaches for the instance
    identity and never ADC. This proves the identity it reaches is the one the box actually has —
    compared against what the metadata server reports rather than a literal, because this repo is
    public and internal identifiers are never committed.
    """
    import google.auth.compute_engine

    from flabeldb import client

    found = client.credentials()
    assert isinstance(found, google.auth.compute_engine.Credentials)

    expected = _metadata_service_account()
    if not expected:
        pytest.skip("no metadata server: this assertion is about a GCE instance identity")

    request = __import__("google.auth.transport.requests", fromlist=["requests"]).Request()
    found.refresh(request)
    assert found.service_account_email == expected, (
        "the store would write as an identity other than the instance service account"
    )
    assert found.token, "the instance identity minted no token"


def test_the_client_reaches_the_dataset_as_that_identity(bq):
    """The end of the chain: no `sudo`, no reauthentication, a real read.

    `gcloud` on the box needs root because its credential store is per-user; a client library does
    not. That difference is the whole reason LS-3 was resumed on `fl-replay`.
    """
    dataset = bq.get_dataset(f"{bq.project}.{DATASET}")
    assert dataset.location.lower() == "us-central1", (
        f"{DATASET} is in {dataset.location}, but the results bucket is US-CENTRAL1 regional and a "
        f"load job needs a compatible dataset location"
    )


def _metadata_service_account() -> str | None:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        headers={"Metadata-Flavor": "Google"},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.read().decode().strip()
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


# --- the layout, against a real table -----------------------------------------------------------


def test_bigquery_will_not_cluster_on_zeek_uid_at_all(bq):
    """A measured correction to the handoff, worth keeping as a test.

    The handoff cites "`flow_labels` clustered on `zeek_uid` verifies clean" as the example of
    verify's blindness. The blindness was real — `differences()` compared field lists and nothing
    else — but **that particular state is unreachable through the API**. Measured 2026-08-21:

        400 The field specified for clustering cannot be found in the schema.
            Invalid field: zeek_uid.

    because `zeek_uid` lives inside the `flow` STRUCT and BigQuery clusters on top-level fields
    only. So the store's one named never-do is guarded twice over, by `Table.__post_init__` on the
    way in and by BigQuery itself. The reachable clustering drift is a top-level column, which is
    what the next test uses.
    """
    from flabeldb import client

    rebuild(bq, "flow_labels")
    live = bq.get_table(f"{bq.project}.{DATASET}.flow_labels")
    live.clustering_fields = ["zeek_uid"]
    with pytest.raises(Exception, match="clustering"):
        bq.update_table(live, ["clustering_fields"])
    del client


def test_verify_sees_the_clustering_drift_it_used_to_be_blind_to(bq, capsys):
    """Clustering on a top-level column that is not the declared key — a reachable console edit.

    `differences()` compared field lists only, so any clustering was invisible to the gate.
    Clustering is one of the few things BigQuery lets `apply` patch, so once visible it is
    repairable rather than a rebuild.
    """
    from flabeldb import cli

    rebuild(bq, "flow_labels")
    reference = f"{bq.project}.{DATASET}.flow_labels"
    live = bq.get_table(reference)
    live.clustering_fields = ["run_id"]
    bq.update_table(live, ["clustering_fields"])
    assert bq.get_table(reference).clustering_fields == ["run_id"], "the setup did not take"

    assert cli._verify(bq, DATASET) == cli.EXIT_DRIFT
    error = capsys.readouterr().err
    assert "run_id" in error
    assert "flow_labels" in error

    # and apply repairs it, because clustering is patchable (measured)
    assert cli._apply(bq, DATASET) == cli.EXIT_OK
    assert bq.get_table(reference).clustering_fields == list(
        schema.TABLES["flow_labels"].clustering
    )
    capsys.readouterr()
    assert cli._verify(bq, DATASET) == cli.EXIT_OK


def test_verify_sees_a_stale_description_on_a_real_table(bq, capsys):
    from flabeldb import cli

    rebuild(bq, "run_exclusions")
    reference = f"{bq.project}.{DATASET}.run_exclusions"
    live = bq.get_table(reference)
    live.description = "someone edited this in the console"
    bq.update_table(live, ["description"])

    assert cli._verify(bq, DATASET) == cli.EXIT_DRIFT
    assert "description" in capsys.readouterr().err

    assert cli._apply(bq, DATASET) == cli.EXIT_OK
    assert bq.get_table(reference).description == schema.TABLES["run_exclusions"].description


def test_verify_sees_reversed_columns_on_a_real_table_and_apply_names_the_rebuild(bq, capsys):
    """Order drift is permanent until a rebuild, so the gate seeing it is the whole value.

    Measured: `update_table` accepts a reordered schema with a 200 and the live order does not
    change — so `apply` must NAME this rather than claim it fixed it.
    """
    from flabeldb import cli, client

    bigquery = client._bigquery()
    table = schema.TABLES["run_exclusions"]
    reference = f"{bq.project}.{DATASET}.run_exclusions"
    bq.delete_table(reference, not_found_ok=True)
    reversed_table = bigquery.Table(
        reference, schema=list(reversed(client.to_bigquery(table.fields)))
    )
    reversed_table.description = table.description
    reversed_table.clustering_fields = list(table.clustering)
    bq.create_table(reversed_table)

    assert cli._verify(bq, DATASET) == cli.EXIT_DRIFT
    assert "order" in capsys.readouterr().err.lower()

    assert cli._apply(bq, DATASET) == cli.EXIT_DRIFT
    output = capsys.readouterr()
    assert "rebuild" in (output.out + output.err).lower()

    rebuild(bq, "run_exclusions")
    capsys.readouterr()
    assert cli._verify(bq, DATASET) == cli.EXIT_OK


def test_the_dataset_location_is_checked_against_the_real_dataset(bq, capsys):
    """A location is immutable, so the gate is the only place this can be caught."""
    from flabeldb import cli, client

    assert bq.get_dataset(f"{bq.project}.{DATASET}").location.lower() == client.LOCATION
    for name in schema.TABLES:
        rebuild(bq, name)
    capsys.readouterr()
    assert cli._verify(bq, DATASET) == cli.EXIT_OK, capsys.readouterr().err
