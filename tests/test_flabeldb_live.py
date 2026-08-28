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
import uuid

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


def empty(bq, name: str) -> None:
    """`name`, emptied — **`TRUNCATE`, not delete-and-recreate.**

    `rebuild` is DDL, and BigQuery's metadata is eventually consistent behind it: dropping a table
    and immediately inserting into the replacement is the shape that produced five fixture errors in
    one run of this file, once the crossed-clocks fixture went function-scoped and turned a single
    rebuild into five. Emptying a table that already matches the declaration needs no DDL, so a
    fixture that only wants an empty table uses this instead.

    `rebuild` stays for the tests whose subject IS the table's shape.
    """
    bq.query(f"TRUNCATE TABLE `{bq.project}.{DATASET}.{name}`").result()


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


# --- the view, against the real engine ----------------------------------------------------------
#
# The pure view tests grep the SQL for vocabulary. This is the behavioural test the plan specified
# and that was never written: four captures, each isolating one decision, asserting the exact set
# of rows the real engine returns.
#
# MEASURED 2026-08-21, running all five sabotages against `flabel_scratch`. The two suites are
# COMPLEMENTARY, and neither subsumes the other:
#
#     sabotage                                  grep tests   these tests
#     ---------------------------------------   ----------   -----------
#     ORDER BY drops run_id                     CAUGHT       passed
#     ORDER BY finished_at ASC                  passed       CAUGHT (2)
#     EXISTS instead of NOT EXISTS              passed       CAUGHT (5)
#     UNNEST(tiers_attempted)                   CAUGHT       CAUGHT (2)
#     WHERE recency >= 1                        passed       CAUGHT (3)
#
# So three of the five inversions were invisible to a suite that only greps — which is why these
# exist. But the first row is the one to keep in mind, and it is why the grep tests STAY: with the
# tie-break gone, the winner of a same-second tie is whatever the engine felt like returning, and
# it returned the run this test expects. A behavioural test cannot reliably catch the absence of a
# tie-break, because the sabotaged view is not wrong on every execution — it is merely no longer a
# function of the data. `test_the_view_orders_by_run_id_as_well_as_finished_at` catches it
# deterministically by reading the statement, and that is the right tool for that one decision.


VIEW_RUNS = (
    # capture, run_id, finished_at, tiers_attempted, tiers_attested
    # A — two runs finishing in the SAME SECOND. The run_id tie-break decides, nothing else can.
    ("cap-a", "run-a1", "2026-08-21 12:00:00", [2], [2]),
    ("cap-a", "run-a2", "2026-08-21 12:00:00", [2], [2]),
    # B — plain recency. Catches an ORDER BY that sorts ascending.
    ("cap-b", "run-b-old", "2026-08-20 09:00:00", [2], [2]),
    ("cap-b", "run-b-new", "2026-08-21 09:00:00", [2], [2]),
    # C — the newest run is RETRACTED, so the older one is authoritative again.
    ("cap-c", "run-c-old", "2026-08-20 09:00:00", [2], [2]),
    ("cap-c", "run-c-new", "2026-08-21 09:00:00", [2], [2]),
    # D — tier 2 was ATTEMPTED and not ATTESTED (#142's shape: Suricata loaded none of the
    #     snapshot). It must supply tier 1 and must NOT supply tier 2.
    ("cap-d", "run-d", "2026-08-21 09:00:00", [1, 2], [1]),
)

#: What the view must return. Written out in full rather than derived, because a derivation would
#: be a second implementation of the rule under test.
VIEW_EXPECTED = {
    ("cap-a", 2, "run-a2"),
    ("cap-b", 2, "run-b-new"),
    ("cap-c", 2, "run-c-old"),
    ("cap-d", 1, "run-d"),
}


@pytest.fixture(scope="module")
def authoritative_rows(bq):
    """The world of `VIEW_RUNS` loaded into a real dataset, and what the view says about it."""
    from flabeldb import cli

    rebuild(bq, "runs")
    rebuild(bq, "run_exclusions")

    values = ", ".join(
        f"('{run_id}', '{capture}', 'offline', {attempted}, {attested}, TIMESTAMP '{finished} UTC')"
        for capture, run_id, finished, attempted, attested in VIEW_RUNS
    )
    bq.query(
        f"INSERT INTO `{bq.project}.{DATASET}.runs` "
        f"(run_id, capture_sha256, mode, tiers_attempted, tiers_attested, finished_at) "
        f"VALUES {values}"
    ).result()
    bq.query(
        f"INSERT INTO `{bq.project}.{DATASET}.run_exclusions` "
        f"(run_id, reason, excluded_at) VALUES "
        f"('run-c-new', 'retracted by the view test', CURRENT_TIMESTAMP())"
    ).result()

    for name, sql in cli.view_sql(DATASET):
        assert name == "authoritative_runs"
        bq.query(sql).result()

    rows = bq.query(
        f"SELECT capture_sha256, tier, run_id FROM `{bq.project}.{DATASET}.authoritative_runs`"
    ).result()
    return {(row.capture_sha256, row.tier, row.run_id) for row in rows}


def test_the_view_returns_exactly_one_authoritative_run_per_capture_and_tier(authoritative_rows):
    """The whole contract in one assertion. Every sabotage in the plan's list fails here."""
    assert authoritative_rows == VIEW_EXPECTED


def test_two_runs_finishing_in_the_same_second_are_broken_by_run_id(authoritative_rows):
    """#138's correction on a second comparator. On a box that replays a capture in seconds, two
    runs finishing in the same second is the ORDINARY case, not an edge one.

    **This test cannot be relied on to catch a missing tie-break**, and that is a property of the
    thing under test rather than a weakness here. Measured: with `run_id` removed from the ORDER
    BY, the engine still returned `run-a2` and this passed. That is exactly the defect — the winner
    stops being a function of the data and becomes whatever the engine returned — but it means the
    deterministic guard is the one that reads the statement, and it lives in
    `test_flabeldb_schema.py`. Kept because it pins the CORRECT answer, and because a tie-break
    that sorted the wrong way would fail here every time.
    """
    for_a = {row for row in authoritative_rows if row[0] == "cap-a"}
    assert for_a == {("cap-a", 2, "run-a2")}, (
        "the same-second tie was decided by something other than the run_id, or not at all"
    )


def test_the_newer_run_wins_when_the_timestamps_actually_differ(authoritative_rows):
    """Catches an ORDER BY that sorts the right column the wrong way."""
    assert ("cap-b", 2, "run-b-new") in authoritative_rows
    assert ("cap-b", 2, "run-b-old") not in authoritative_rows


def test_a_retracted_run_hands_authority_back_to_the_older_one(authoritative_rows):
    """§4.5: retraction is a record, not a delete, so it is joined away on every read. `EXISTS` in
    place of `NOT EXISTS` still greps as "run_exclusions" and inverts the whole meaning."""
    assert ("cap-c", 2, "run-c-old") in authoritative_rows
    assert ("cap-c", 2, "run-c-new") not in authoritative_rows


def test_a_tier_that_was_attempted_but_not_attested_supplies_nothing(authoritative_rows):
    """§2.4, and #142's exact shape: a run whose Suricata loaded NONE of the snapshot exits 0 and
    would otherwise supersede good tier-2 knowledge with a near-complete one."""
    assert ("cap-d", 1, "run-d") in authoritative_rows
    assert not [row for row in authoritative_rows if row[0] == "cap-d" and row[1] == 2], (
        "an unattested tier supplied an authoritative row"
    )


# --- §5.3's recovery, against the real service --------------------------------------------------
#
# **This is the step's proof, and nothing pure substitutes for it.** Revision 1 said "re-running
# the same ingest completes it"; §10 M1 measured that a load job which FAILS consumes its job id
# permanently, so that was false and a half-loaded run was unrecoverable except by full rebuild.
# The pure tests in `test_flabeldb_ingest.py` cover the walk's logic; these cover the claim that
# the logic and BigQuery agree about what a burnt id is.


#: A fresh namespace for every session, and it is not optional.
#:
#: **A BigQuery job id is permanent** (§10 M1) — that is the fact this whole recovery path exists
#: for. So a test that asserts on attempt NUMBERS cannot reuse a `run_id` between sessions: the
#: second run finds yesterday's attempt 1 already failed and attempt 2 already succeeded, and the
#: walk correctly answers something different from what the first run measured. Found by running
#: these twice; the first pass was green and the second was not.
#:
#: Deliberately non-deterministic, unlike everything else in this repo. The rows these produce are
#: not compared across sessions — the attempt numbers are — so a fresh namespace is the property
#: that matters and a fixed one would be actively wrong.
SESSION = uuid.uuid4().hex[:8]


def a_parsed_run(run_id_salt: str):
    """A minimal `ParsedRun` whose rows satisfy the declaration. Built here rather than fetched:
    the tarball is `ingest_one`'s concern, and what these tests interrupt is the ORDERING."""
    import hashlib

    from flabeldb import parse

    # sha256 of the salt, not `hash()`: str hashing is salted per interpreter (PYTHONHASHSEED), so
    # the same fixture would name a different capture on every run and the `run_id` with it — which
    # is the one thing these tests need to hold across two calls.
    digest = hashlib.sha256(f"{SESSION}-{run_id_salt}".encode()).hexdigest()
    capture = digest
    # Six DIGITS of microseconds, derived from the same digest. The first version interpolated the
    # salt itself, which produced `2026-08-24T00:00:00.burnt1Z` — BigQuery refused the load with
    # "Could not parse ... as a timestamp", loudly and before writing anything, which is the
    # behaviour you want from a bad row but a poor way to learn your fixture is malformed.
    micros = f"{int(digest[:8], 16) % 1_000_000:06d}"
    document = {
        "run": {
            "mode": "offline",
            "started_at": f"2026-08-24T00:00:00.{micros}Z",
            "finished_at": "2026-08-24T00:01:00.000000Z",
            "flabel_version": "0.0.0",
            "tiers_attempted": [2],
            "tool_failures": [],
            "counts": {"rules_loaded": 10, "rules_failed": 0, "rules_skipped": 0},
            "ruleset": {"snapshot_id": "b8b1e00ed2285240", "total_admitted": 10},
            "input": {"sha256": capture, "path": "/x/y.pcap", "bytes": 1, "snaplens": [96]},
        },
        "labels": [
            {
                "best_tier": 2,
                "flow": {
                    "proto": "tcp",
                    "src_ip": "10.0.0.1",
                    "src_port": 1234,
                    "dst_ip": "10.0.0.2",
                    "dst_port": 80,
                    "ts_first": "2026-08-24T00:00:01.000000Z",
                    "ts_last": "2026-08-24T00:00:02.000000Z",
                    "uid": "CabcDEF",
                },
                "labels": [{"name": "verdict", "value": "malicious", "tier": 2, "sids": [1]}],
                "sources": [{"tier": 2, "source": "et/open", "sid": 1, "rev": 1}],
            }
        ],
        "unmatched_detections": [],
    }
    return parse.rows(document, ingested_at="2026-08-24T12:00:00.000000Z")


def counts_for(bq, run_id: str) -> dict[str, int]:
    from flabeldb import ingest

    found = {}
    for table in ingest.LOAD_ORDER:
        column = ingest.RUN_COLUMN[table]
        sql = (
            f"SELECT COUNT(*) AS c FROM `{bq.project}.{DATASET}.{table}` "
            f"WHERE {column} = '{run_id}'"
        )
        found[table] = list(bq.query(sql).result())[0].c
    return found


def test_a_run_interrupted_before_the_commit_marker_is_invisible_then_completes_cleanly(bq):
    """§5.3's whole promise, in one test.

    Stop after `flow_labels`. Its rows are in the table and the `runs` row is not, so **nothing can
    reach them** — every read joins through the commit marker. Re-run: the run completes, and the
    row counts are what a single clean ingest would have produced, not double.
    """
    from flabeldb import ingest

    for name in ingest.LOAD_ORDER:
        rebuild(bq, name)
    parsed = a_parsed_run("recov1")
    run_id = parsed.run["run_id"]

    interrupted = ingest.load_run(bq, DATASET, parsed, stop_after="flow_labels")
    assert interrupted["status"] == "interrupted"

    half = counts_for(bq, run_id)
    assert half["flow_labels"] == 1, "the interrupted load did not land its rows"
    assert half["runs"] == 0, "the commit marker landed despite the interruption"
    assert not ingest.already_committed(bq, DATASET, run_id), (
        "a run with no `runs` row read as committed, so the guard is not reading the marker"
    )

    completed = ingest.load_run(bq, DATASET, a_parsed_run("recov1"))
    assert completed["status"] == "ingested"

    final = counts_for(bq, run_id)
    assert final == {"flow_labels": 1, "unmatched": 0, "captures": 1, "runs": 1}, final


def test_re_ingesting_a_committed_run_is_free_and_changes_nothing(bq):
    """The primary guard (§7.4), against the service. Without it the second call would clear and
    reload every table — correct in the end, and a great deal of billed work per published run."""
    from flabeldb import ingest

    for name in ingest.LOAD_ORDER:
        rebuild(bq, name)
    parsed = a_parsed_run("idem1")
    run_id = parsed.run["run_id"]

    assert ingest.load_run(bq, DATASET, parsed)["status"] == "ingested"
    before = counts_for(bq, run_id)

    again = ingest.load_run(bq, DATASET, a_parsed_run("idem1"))
    assert again["status"] == "already-present"
    assert counts_for(bq, run_id) == before


def test_a_burnt_job_id_is_walked_past_rather_than_locking_the_run_out(bq):
    """**§10 M1, end to end.** Force a load to fail by sending a row the table cannot take, then
    confirm the walk takes attempt 2 and the run ingests.

    Revision 1's "just re-run it" died here: the failed job keeps its id forever, so an id derived
    from `(run_id, table)` alone would make this run permanently un-ingestable.
    """
    from flabeldb import ingest

    for name in ingest.LOAD_ORDER:
        rebuild(bq, name)
    parsed = a_parsed_run("burnt1")
    run_id = parsed.run["run_id"]

    # Attempt 1 for `runs`, deliberately poisoned: a column the table does not declare.
    doomed = ingest.job_id(run_id, "runs", 1)
    with pytest.raises(Exception):  # noqa: B017 - the client's own load error, whatever it is
        ingest.load_rows(bq, DATASET, "runs", [{"not_a_column": "x"}], doomed)

    assert ingest.probe_job(bq, doomed) == ingest.FAILED, (
        "a load that failed did not read as FAILED, so the walk cannot know to step past it"
    )
    assert ingest.next_attempt(lambda job: ingest.probe_job(bq, job), run_id, "runs") == 2

    completed = ingest.load_run(bq, DATASET, a_parsed_run("burnt1"))
    assert completed["status"] == "ingested"
    assert counts_for(bq, run_id)["runs"] == 1


def test_a_load_that_succeeded_is_not_repeated_on_a_re_run(bq):
    """The other half of the walk: `SUCCEEDED` means done. Without it, recovering a half-loaded
    run would double the rows of every table that had already landed."""
    from flabeldb import ingest

    for name in ingest.LOAD_ORDER:
        rebuild(bq, name)
    parsed = a_parsed_run("dedupe1")
    run_id = parsed.run["run_id"]

    ingest.load_run(bq, DATASET, parsed, stop_after="flow_labels")
    assert counts_for(bq, run_id)["flow_labels"] == 1

    # Re-run. Step 2 clears the half-loaded rows and step 3 reloads them under a FRESH id, so the
    # count is what one clean ingest produces — not zero (cleared then skipped) and not two.
    ingest.load_run(bq, DATASET, a_parsed_run("dedupe1"))
    assert counts_for(bq, run_id)["flow_labels"] == 1, "recovery did not restore exactly one row"


# --- a clean capture is a result, against the real view ------------------------------------------
#
# `docs/spec.md` §13: an all-IPsec capture "exits 0 with `labels[]` empty", and `_write_output`
# writes `labels.json` unconditionally on the success path — so a run that labelled nothing is
# published and is indexed. `test_flabel_run.py` pins both of those. What the indexing is FOR
# cannot be tested there: it needs the view, and the view needs BigQuery. This is the other half,
# and it is the behaviour revision 1's deleted publish-on-exit-0 bullet was reaching for.


def a_run_over(capture: str, *, started_at: str, finished_at: str, labelled: bool):
    """A run over `capture` attesting tier 2, with or without a label.

    `started_at` is the only thing separating the two runs' identities: §3.3 derives `run_id` from
    `(capture, mode, started_at, flabel_version)`, and the other three are held equal deliberately
    — two runs over ONE capture is the situation under test.
    """
    from flabeldb import parse

    label = {
        "best_tier": 2,
        "flow": {
            "proto": "tcp",
            "src_ip": "10.0.0.1",
            "src_port": 1234,
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
            "ts_first": "2026-08-24T00:00:01.000000Z",
            "ts_last": "2026-08-24T00:00:02.000000Z",
            "uid": "CabcDEF",
        },
        "labels": [{"name": "verdict", "value": "malicious", "tier": 2, "sids": [1]}],
        "sources": [{"tier": 2, "source": "et/open", "sid": 1, "rev": 1}],
    }
    document = {
        "run": {
            "mode": "offline",
            "started_at": started_at,
            "finished_at": finished_at,
            "flabel_version": "0.0.0",
            "tiers_attempted": [2],
            "tool_failures": [],
            # Attested: `rules_loaded == total_admitted` and neither is zero (§2.4). Load-bearing
            # for the empty run — a run that attests nothing supersedes nothing, so without this
            # the test would go green while proving the opposite of what it claims.
            "counts": {"rules_loaded": 10, "rules_failed": 0, "rules_skipped": 0},
            "ruleset": {"snapshot_id": "b8b1e00ed2285240", "total_admitted": 10},
            "input": {"sha256": capture, "path": "/x/y.pcap", "bytes": 1, "snaplens": [96]},
        },
        "labels": [label] if labelled else [],
        "unmatched_detections": [],
    }
    return parse.rows(document, ingested_at="2026-08-24T12:00:00.000000Z")


def authoritative_for(bq, capture: str) -> set[tuple[int, str]]:
    """`(tier, run_id)` the view currently supplies for one capture."""
    rows = bq.query(
        f"SELECT tier, run_id FROM `{bq.project}.{DATASET}.authoritative_runs` "
        f"WHERE capture_sha256 = '{capture}'"
    ).result()
    return {(row.tier, row.run_id) for row in rows}


def authoritative_labels(bq, capture: str) -> int:
    """Flow labels reachable THROUGH the view — `blfile`'s read (§5.2), reduced to a count.

    `a.tier = 2` because both runs here attest tier 2 and nothing else, so the filter changes no
    result; it keeps the count a count of LABELS rather than of (label, tier) pairs, which is what
    it would silently become the day a run in this fixture attests two tiers.
    """
    rows = bq.query(
        f"SELECT COUNT(*) AS c FROM `{bq.project}.{DATASET}.flow_labels` AS f "
        f"JOIN `{bq.project}.{DATASET}.authoritative_runs` AS a "
        f"ON a.run_id = f.run_id AND a.capture_sha256 = f.capture_sha256 "
        f"WHERE f.capture_sha256 = '{capture}' AND a.tier = 2"
    ).result()
    return list(rows)[0].c


def test_a_run_that_labelled_nothing_takes_the_tier_and_leaves_nothing_authoritative(bq):
    """**An empty `labels[]` is a result, not an absence.**

    A capture that was examined and found clean is knowledge, and it has to clear the stale tier
    rather than let yesterday's labels stand as current. So: ingest a run that labels a flow and
    confirm the view supplies it, then ingest a LATER run over the same capture that labelled
    nothing, and confirm the tier is now supplied by the later run and reaches no labels at all.

    The superseded rows are **not deleted**. §4.5's distinction — a record, not a delete — applies
    to supersession as much as to retraction: the old labels stay in `flow_labels` and stop being
    current, which is what makes a reproduction of an earlier run possible at all.
    """
    import hashlib

    from flabeldb import cli, ingest

    for name in ingest.LOAD_ORDER:
        rebuild(bq, name)
    rebuild(bq, "run_exclusions")
    for _name, sql in cli.view_sql(DATASET):
        bq.query(sql).result()

    capture = hashlib.sha256(f"{SESSION}-clean-sweep".encode()).hexdigest()
    laden = a_run_over(
        capture,
        started_at="2026-08-24T00:00:00.000001Z",
        finished_at="2026-08-24T00:01:00.000000Z",
        labelled=True,
    )
    clean = a_run_over(
        capture,
        started_at="2026-08-24T02:00:00.000002Z",
        finished_at="2026-08-24T02:01:00.000000Z",
        labelled=False,
    )

    assert laden.run["run_id"] != clean.run["run_id"], "the two runs share an id"
    assert clean.flow_labels == [], "the clean run's fixture carries labels"
    assert clean.run["tiers_attested"] == [2], (
        "the empty run attested nothing, so it could supersede nothing and every assertion below "
        f"would hold for the wrong reason: {clean.run['attestation_notes']}"
    )

    assert ingest.load_run(bq, DATASET, laden)["status"] == "ingested"
    assert authoritative_for(bq, capture) == {(2, laden.run["run_id"])}
    assert authoritative_labels(bq, capture) == 1, (
        "the laden run supplied no authoritative label, so there is nothing here to clear"
    )

    assert ingest.load_run(bq, DATASET, clean)["status"] == "ingested"
    assert authoritative_for(bq, capture) == {(2, clean.run["run_id"])}, (
        "a run that labelled nothing did not take the tier, so a capture since found clean still "
        "reads as malicious"
    )
    assert authoritative_labels(bq, capture) == 0, (
        "the superseded labels are still reachable through the view"
    )
    assert counts_for(bq, laden.run["run_id"])["flow_labels"] == 1, (
        "supersession deleted the older run's rows — they are a record and must survive it"
    )


# --- LS-8: the one query `tools/reconcile_store.py` adds ------------------------------------------


@pytest.fixture(scope="module")
def counted_rows(bq):
    """Two runs' rows in a real dataset, then `row_counts` over them.

    Rebuilt rather than appended to, because the assertion is about counts and a leftover row from
    another test would make it wrong for a reason that has nothing to do with the query.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import reconcile_store

    for name in ("runs", "captures", "flow_labels", "unmatched"):
        rebuild(bq, name)

    first, second = "aaaa0000aaaa0000", "bbbb1111bbbb1111"
    capture = "c" * 64
    statements = [
        f"INSERT INTO `{bq.project}.{DATASET}.runs` (run_id, capture_sha256, mode) "
        f"VALUES ('{first}', '{capture}', 'offline'), ('{second}', '{capture}', 'replay')",
        # `captures` names the run in a DIFFERENT column (§4.2) — the whole point of this test.
        f"INSERT INTO `{bq.project}.{DATASET}.captures` "
        f"(capture_sha256, observed_by_run_id) VALUES ('{capture}', '{first}')",
        f"INSERT INTO `{bq.project}.{DATASET}.flow_labels` "
        f"(run_id, capture_sha256, flow_key) VALUES "
        f"('{first}', '{capture}', 'f1'), ('{first}', '{capture}', 'f2'), "
        f"('{second}', '{capture}', 'f3')",
        f"INSERT INTO `{bq.project}.{DATASET}.unmatched` "
        f"(run_id, capture_sha256) VALUES ('{first}', '{capture}')",
    ]
    for sql in statements:
        bq.query(sql).result()
    return first, second, reconcile_store.row_counts(bq, DATASET, reconcile_store.run_id_columns())


def test_row_counts_counts_every_table_for_every_run(counted_rows):
    """One statement, so every table is counted at the same point in time — four queries would be
    four, and a backfill running beside this would be counted mid-flight in one and after it in
    another."""
    first, second, counts = counted_rows
    assert counts[first] == {"runs": 1, "captures": 1, "flow_labels": 2, "unmatched": 1}


def test_row_counts_reads_captures_through_observed_by_run_id(counted_rows):
    """§4.2 names the run differently in `captures`, and getting it wrong would return zero
    sightings for every run and report the whole archive as broken. This is that column, against
    the real table rather than against the declaration."""
    first, _second, counts = counted_rows
    assert counts[first]["captures"] == 1


def test_a_run_with_no_rows_in_a_table_is_absent_rather_than_zero(counted_rows):
    """`GROUP BY` yields no row for an empty group, so the reconciliation reads a missing key as
    zero. That is `compare_run`'s `actual.get(table, 0)`, and this is the shape it relies on."""
    _first, second, counts = counted_rows
    assert "captures" not in counts[second]
    assert "unmatched" not in counts[second]
    assert counts[second]["flow_labels"] == 1


def test_the_reconciliation_reports_a_row_count_shortfall_against_a_real_dataset(counted_rows):
    """The end the whole tool exists for, over rows that really are in BigQuery: a tarball that
    parses to more rows than the store holds."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import reconcile_store

    first, _second, counts = counted_rows
    expectation = reconcile_store.RunExpectation(
        run_id=first,
        archive_uri="gs://example/results/LABELED_x.tar.gz",
        rows={"runs": 1, "captures": 1, "flow_labels": 431, "unmatched": 1},
        counts={"labels": 431, "unmatched": 1},
        refused=0,
    )
    result = reconcile_store.reconcile([expectation], counts, [first])
    assert not result.agrees
    (found,) = [item for item in result.disagreements if item.kind == "row-count"]
    assert found.table == "flow_labels"
    assert (found.expected, found.actual) == (431, 2)


# --- LS-9: the cutoff, against real timestamps ----------------------------------------------------


@pytest.fixture
def crossed_clocks(bq):
    """Two runs over one capture whose clocks are **crossed** — the state §6.5 is entirely about.

    A backfill ingests old tarballs late, so one of these finished early and was ingested last,
    which is exactly the pair a `finished_at` filter gets backwards.

    **Function-scoped, and it rebuilds every time.** As a module fixture it was emptied by the last
    test in this file, which calls `rebuild(bq, "runs")` itself — so it worked only because pytest
    happened to run that test last. Reorder the file and
    `test_a_cutoff_before_everything_yields_nothing` would pass against an empty table, which is
    the count-of-zero-that-proves-nothing pattern LS-8's review already found once. The row count is
    asserted after the insert for the same reason.
    """
    from flabeldb import query

    empty(bq, "runs")
    empty(bq, "run_exclusions")
    capture = "d" * 64
    rows = [
        # (run_id, finished_at, ingested_at)
        ("ea111111111111ea", "2026-08-17T00:00:00", "2026-08-17T01:00:00"),  # early, early
        ("la222222222222la", "2026-08-18T00:00:00", "2026-09-01T00:00:00"),  # early-ish, LATE
    ]
    values = ", ".join(
        f"('{run_id}', '{capture}', 'offline', [2], TIMESTAMP '{finished}', TIMESTAMP '{ingested}')"
        for run_id, finished, ingested in rows
    )
    bq.query(
        f"INSERT INTO `{bq.project}.{DATASET}.runs` "
        f"(run_id, capture_sha256, mode, tiers_attested, finished_at, ingested_at) VALUES {values}"
    ).result()
    held = list(bq.query(f"SELECT COUNT(*) AS n FROM `{bq.project}.{DATASET}.runs`").result())[0][
        "n"
    ]
    assert held == len(rows), f"the fixture inserted {len(rows)} rows and the table holds {held}"
    return capture, query


def test_without_a_cutoff_the_later_finisher_is_authoritative(crossed_clocks, bq):
    """The baseline: §4.6 picks on `finished_at`, so the run that finished later wins."""
    capture, query = crossed_clocks
    rows = query.authoritative(bq, DATASET, [capture])
    assert [row["run_id"] for row in rows] == ["la222222222222la"]


def test_a_run_finished_before_the_cutoff_but_ingested_after_it_is_excluded(crossed_clocks, bq):
    """**The assertion that pins the whole of §6.5, and the one a plausible implementation gets
    backwards.**

    `la222222222222la` finished 2026-08-18 — comfortably before a cutoff of 2026-08-25 — but was
    not ingested until 2026-09-01. A document rebuilt "as of the 25th" must NOT gain it, because it
    was not in the store that day. A `finished_at` filter would include it, and the collection would
    silently differ from the one that document recorded.
    """
    capture, query = crossed_clocks
    rows = query.authoritative(bq, DATASET, [capture], as_of="2026-08-25T00:00:00Z")

    ids = [row["run_id"] for row in rows]
    assert "la222222222222la" not in ids, (
        "the run was ingested after the cutoff and must not supply the tier; this is what "
        "filtering on finished_at instead of ingested_at gets wrong"
    )
    assert ids == ["ea111111111111ea"], "authority falls back to the run that WAS in the store"


def test_a_cutoff_before_everything_yields_nothing(crossed_clocks, bq):
    capture, query = crossed_clocks
    assert query.authoritative(bq, DATASET, [capture], as_of="2026-01-01T00:00:00Z") == []


def test_a_cutoff_after_everything_agrees_with_the_view(crossed_clocks, bq):
    """One rule, two renderings. With the cutoff past every `ingested_at`, the re-rendered SELECT
    must return exactly what the view returns — which is the check that the two cannot diverge."""
    capture, query = crossed_clocks
    via_view = query.authoritative(bq, DATASET, [capture])
    via_render = query.authoritative(bq, DATASET, [capture], as_of="2099-01-01T00:00:00Z")
    assert via_render == via_view


def test_the_cutoff_still_lets_finished_at_decide_between_survivors(bq):
    """Both clocks, doing different jobs: `ingested_at` selects the candidates, `finished_at` picks
    the winner among them. With both runs ingested before the cutoff, the later finisher wins."""
    from flabeldb import query

    empty(bq, "runs")
    empty(bq, "run_exclusions")
    capture = "e" * 64
    values = ", ".join(
        f"('{run_id}', '{capture}', 'offline', [2], TIMESTAMP '{finished}', TIMESTAMP '{ingested}')"
        for run_id, finished, ingested in [
            ("aa333333333333aa", "2026-08-10T00:00:00", "2026-08-11T00:00:00"),
            ("bb444444444444bb", "2026-08-12T00:00:00", "2026-08-11T00:00:00"),
        ]
    )
    bq.query(
        f"INSERT INTO `{bq.project}.{DATASET}.runs` "
        f"(run_id, capture_sha256, mode, tiers_attested, finished_at, ingested_at) VALUES {values}"
    ).result()
    rows = query.authoritative(bq, DATASET, [capture], as_of="2026-08-25T00:00:00Z")
    assert [row["run_id"] for row in rows] == ["bb444444444444bb"]
