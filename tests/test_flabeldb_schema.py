"""The store's schema, and the two commands that keep the live dataset matching it.

`flabel-db apply` makes the tables right today; **`verify` is the point of this module.** It is
what notices the day a column is patched in the console — modelled on a failure already on this
project's books, where `ci.yml`'s toolchain digest is updated by hand and can silently lag
`Dockerfile.toolchain` with every test still passing, because the pins and the stale image agree.

Everything here is pure: `schema.py` declares tables as client objects and `verify` compares two
declarations, so neither needs BigQuery. That is deliberate rather than convenient —
spec-label-store §2's testing line records that the `requires_bigquery` tests do not run in CI (no
credential exists, and Workload Identity Federation was declined as out of scope), so any logic put
behind a client is logic CI cannot see. The comparison is where the value is, so it stays out here.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from flabeldb import schema

#: Three tests below import the client's exception TYPES (not the client). They are pure — no API
#: call — but they cannot run without the `db` extra, so they skip rather than error on a checkout
#: that has not installed it. CI does install it, precisely so they are not skipped there.
#: The `db` extra. A MARKER, not a skipif: the detection is the fragile part —
#: `find_spec` on a dotted name RAISES when the parent is absent rather than returning
#: None, so three copies of that check made the suite red on a checkout without the extra.
#: tests/conftest.py now owns it, once. These tests import the client's exception TYPES
#: and call no API; CI installs the extra precisely so they are not skipped there.
needs_client = pytest.mark.requires_db_extra

DATASET = "flabel"
TABLES = ("runs", "captures", "flow_labels", "unmatched", "run_exclusions")


def test_the_five_tables_of_spec_4_are_declared():
    """Spec §4.1-§4.5. A missing table is a store that silently drops a whole kind of record."""
    assert tuple(schema.TABLES) == TABLES


def test_run_block_is_a_string_and_not_json():
    """Revision 2's correction, and it is a correctness rule rather than a preference.

    BigQuery's `JSON` type normalises on ingest — it sorts keys, drops duplicates and normalises
    numeric literals, so `12.30` comes back as `12.3`. Spec §6.4 embeds the run block *verbatim*
    into a collection document, and a normalising column cannot be verbatim. Stored as the
    canonical bytes.
    """
    field = schema.field_of("runs", "run_block")
    assert field.field_type == "STRING", (
        "run_block must be STRING: a JSON column normalises numbers, so it cannot be the verbatim "
        "record spec §6.4 embeds into a collection"
    )


def test_flow_labels_has_no_partition():
    """Measured, not assumed: BigQuery refuses to partition on a field inside a STRUCT.

    Revision 1 declared `PARTITION BY DATE(flow.ts_first)`. Against the live service that fails at
    `CREATE TABLE` with "The field specified for partitioning can only be a top-level field", and a
    control table partitioned on a top-level timestamp created fine — so it is the nesting, not the
    syntax. Nothing queries on flow time either, so the partition bought nothing while requiring
    the schema to be contorted around it. Clustering serves the access pattern.
    """
    assert schema.TABLES["flow_labels"].partition_field is None
    assert schema.TABLES["flow_labels"].clustering == ("capture_sha256", "flow_key")


def test_every_partition_field_is_top_level():
    """The general form of the rule the measurement produced, so it cannot recur in another table.

    `runs` and `unmatched` are both partitioned, and a future table will be too. A dotted path here
    means someone reached into a STRUCT again and will discover it at `CREATE TABLE` rather than in
    CI.
    """
    for name, table in schema.TABLES.items():
        if table.partition_field is None:
            continue
        assert "." not in table.partition_field, (
            f"{name} partitions on {table.partition_field!r}, which reaches inside a STRUCT. "
            f"BigQuery rejects that at CREATE TABLE."
        )
        top_level = {field.name for field in table.fields}
        assert table.partition_field in top_level, (
            f"{name} partitions on {table.partition_field!r}, which is not one of its columns"
        )


def test_captures_records_snaplens_plural():
    """Follows LS-1: the field is a repeated `snaplens`, not a scalar `snaplen`.

    A `mergecap` pcapng's interfaces need not agree on snapshot length, so a single value would
    invent a winner and hide the disagreement — which is the fact the field exists to expose, since
    Zeek refuses a merge across differing snapshot lengths. Spec §4.2's column list still said
    `snaplen` after LS-1 changed it; that drift is what this pins.
    """
    field = schema.field_of("captures", "snaplens")
    assert field.mode == "REPEATED"
    assert field.field_type == "INT64"
    with pytest.raises(KeyError):
        schema.field_of("captures", "snaplen")


def test_runs_records_attested_tiers_not_merely_attempted():
    """Spec §2.4. `tiers_unavailable` could never carry this, which is why the column exists.

    A failed run is never ingested and spec §10 says `tiers_unavailable` is empty on every
    successful run — so a column derived from it would equal `tiers_attempted` in every row that
    will ever exist, and #142's zero-rules-loaded run would have superseded good tier-2 knowledge.
    `attestation_notes` is what makes a refusal readable rather than merely visible.
    """
    assert schema.field_of("runs", "tiers_attested").mode == "REPEATED"
    assert schema.field_of("runs", "attestation_notes").mode == "REPEATED"


def test_zeek_uid_is_stored_but_is_not_a_clustering_or_partition_key():
    """Measured: under `-D` a uid is positional, so it collides across every capture (§3.2).

    It is kept because it is how an operator finds the flow in that run's `conn.log`. What must
    never happen is the store treating it as identity — and a clustering key is exactly the shape
    of accident that would.
    """
    flow = schema.field_of("flow_labels", "flow")
    assert any(sub.name == "zeek_uid" for sub in flow.fields), "the observation is kept"
    for name, table in schema.TABLES.items():
        assert "zeek_uid" not in table.clustering, f"{name} clusters on zeek_uid"
        assert table.partition_field != "zeek_uid"


# --- verify -----------------------------------------------------------------------------------


def fake_bq(location: str = "us-central1"):
    """A stand-in client that answers `get_dataset`, which `_verify` asks before anything else.

    It asks because the dataset's LOCATION is immutable and part of the store's identity: the
    results bucket is US-CENTRAL1 regional, and BigQuery job ids are namespaced
    `project:location.jobid`.

    It also answers `query` with no rows, because `_verify` runs §7.4's duplicate-`run_id`
    assertion once the shape is clean. A fake that did not would make every clean-verify test fail
    on the guard rather than on what it is testing — and adding it here rather than silencing the
    guard is the point: verify really does query now.
    """

    class Empty:
        def result(self):
            return iter(())

    class Bq:
        project = "p"

        def get_dataset(self, _reference):
            return type("Dataset", (), {"location": location})()

        def query(self, _sql, **_kwargs):
            return Empty()

    return Bq()


def test_verify_is_silent_when_the_live_schema_matches():
    """Note this compares the declaration to a copy of ITSELF, so it cannot fail on its own.

    Kept because it pins the no-drift path, but the test that actually exercises the comparison is
    `test_the_declaration_round_trips_through_the_apis_own_vocabulary` below, and the one that
    exercises it against BigQuery is in `test_flabeldb_live.py`.
    """
    live = {name: schema.TABLES[name] for name in schema.TABLES}
    assert schema.differences(live) == ()


@pytest.mark.parametrize(
    "mutate, expected",
    [
        pytest.param(
            lambda fields: fields[:-1],
            "missing",
            id="a-dropped-column",
        ),
        pytest.param(
            lambda fields: (*fields, schema.column("smuggled", "STRING")),
            "unexpected",
            id="an-added-column",
        ),
        pytest.param(
            lambda fields: (schema.column(fields[0].name, "BOOL"), *fields[1:]),
            "type",
            id="a-changed-type",
        ),
        pytest.param(
            lambda fields: (
                schema.column(fields[0].name, fields[0].field_type, mode="REPEATED"),
                *fields[1:],
            ),
            "mode",
            id="a-changed-mode",
        ),
    ],
)
def test_verify_detects_each_kind_of_drift(mutate, expected):
    """Four assertions, not one.

    "Detects a difference" is satisfied by code that notices only one kind — and the drift this is
    built against is a hand-patched column in the console, which could be any of the four. A
    changed *mode* is the one most likely to be missed: `REPEATED` versus `NULLABLE` on the same
    type reads as the same column in a casual comparison, and it is the difference between a list
    and a scalar.
    """
    live = {name: schema.TABLES[name] for name in schema.TABLES}
    live["runs"] = schema.LiveTable(
        fields=tuple(mutate(tuple(schema.TABLES["runs"].fields))),
        partition_field=schema.TABLES["runs"].partition_field,
        clustering=schema.TABLES["runs"].clustering,
        description=schema.TABLES["runs"].description,
    )

    found = schema.differences(live)
    assert found, "verify saw no difference"
    assert any(expected in message for message in found), (
        f"no reported difference mentions {expected!r}: {found}"
    )


def test_verify_reports_a_table_that_does_not_exist_at_all():
    """The failure mode of a half-run `apply`, which is likelier than a patched column."""
    live = {name: schema.TABLES[name] for name in schema.TABLES}
    del live["run_exclusions"]

    found = schema.differences(live)
    assert any("run_exclusions" in message for message in found)


# --- the view ---------------------------------------------------------------------------------

VIEWS = pathlib.Path(schema.__file__).parent / "views"


def sql_of(name: str) -> str:
    """The view's executable SQL, with `--` comments stripped.

    These tests assert on what the statement DOES, and the file is heavily commented — the first
    version of `test_the_view_reads_attested_tiers_not_attempted_ones` failed because a comment
    explaining why `tiers_attempted` is the wrong column contains the words `tiers_attempted`. A
    test that greps prose is a test that reports on prose.
    """
    text = (VIEWS / name).read_text(encoding="utf-8")
    return "\n".join(line.split("--")[0] for line in text.splitlines())


def test_authoritative_runs_is_the_only_view():
    """Revision 2 deleted `current_labels`: the merge moved into `blfile`, in Python.

    Two implementations of the one rule the store exists to express was the review's central
    finding, and it was worse than the usual duplication because a divergence would surface only
    on `--rebuild` — the command whose whole promise is that it does not diverge.
    """
    assert sorted(path.name for path in VIEWS.glob("*.sql")) == ["authoritative_runs.sql"]


def test_the_view_is_templated_on_the_dataset_so_it_can_be_dry_run_against_scratch():
    """Committed SQL that hardcodes `flabel` cannot be checked against `flabel_scratch`.

    A gate that can only be exercised against production is a gate nobody runs.
    """
    text = sql_of("authoritative_runs.sql")
    assert "{dataset}" in text
    assert not re.search(r"\bflabel\.", text), (
        "the view SQL names the dataset literally; template it so verify can dry-run it"
    )


def test_the_view_orders_by_run_id_as_well_as_finished_at():
    """#138's correction, applied to a second comparator.

    `finished_at` alone is not a total order, and on a box that replays a whole capture in seconds
    two runs finishing in the same second is the ORDINARY case — so without the tie-break the
    authoritative run follows whatever order the engine returned, which is not a property of the
    data.
    """
    text = sql_of("authoritative_runs.sql")
    ordering = re.search(r"ORDER BY(.+?)\)", text, re.IGNORECASE | re.DOTALL)
    assert ordering, "no ORDER BY in the view"
    assert "run_id" in ordering.group(1), (
        "finished_at alone is not a total order; run_id must break the tie"
    )


def test_the_view_excludes_runs_that_have_been_retracted():
    """Retraction is a record, not a delete (§4.5), so the view has to anti-join it.

    Supersession is decided by wall clock, and spec §12 lets an operator pin an old
    `--ruleset-snapshot` — so a debugging run finishes later and becomes authoritative, inverting
    the argument that justified supersession. Without this join there is no way to undo that.
    """
    text = sql_of("authoritative_runs.sql")
    assert "run_exclusions" in text, "the view does not consult run_exclusions"


def test_the_view_reads_attested_tiers_not_attempted_ones():
    """The whole point of §2.4: an unattested tier must not supply an authoritative row."""
    text = sql_of("authoritative_runs.sql")
    assert "tiers_attested" in text
    assert "tiers_attempted" not in text


# --- the CLI's behaviour without the extra, and its templating --------------------------------


def test_help_works_even_when_the_client_cannot_be_imported(monkeypatch):
    """`flabel-db --help` must not require the `db` extra.

    The client is imported lazily for this: an operator reaching for `--help` is usually the one
    who has not run `uv sync --extra db` yet, and answering them with an ImportError traceback from
    inside a library is the least useful thing the tool could do.

    **Absence is simulated rather than assumed.** The first version of this test just called
    `--help` and passed — which proves nothing when the extra IS installed, and CI now installs it.
    Making `_bigquery` raise is what actually exercises the laziness.
    """
    from flabeldb import cli, client

    def refuse():
        raise RuntimeError(client._MISSING_EXTRA)

    monkeypatch.setattr(client, "_bigquery", refuse)

    with pytest.raises(SystemExit) as raised:
        cli.build_parser().parse_args(["--help"])
    assert raised.value.code == 0


def test_a_missing_extra_reads_as_a_sentence_naming_the_fix(monkeypatch, capsys):
    """Not an ImportError traceback. The failure is an environment, not a defect.

    `flabel` deliberately has no dependencies, so "the client is not installed" is the ORDINARY
    state of a fresh checkout rather than a broken one — which makes the message part of the
    contract.
    """
    from flabeldb import cli, client

    def refuse(*_args, **_kwargs):
        raise RuntimeError(client._MISSING_EXTRA)

    monkeypatch.setattr(client, "client", refuse)
    assert cli.main(["verify"]) == cli.EXIT_USAGE

    captured = capsys.readouterr()
    assert "uv sync --extra db" in captured.err, "the message must name the fix"
    assert "Traceback" not in captured.err


def test_the_view_sql_resolves_the_dataset_it_is_given():
    """So `verify` can dry-run against `flabel_scratch` rather than only against production."""
    from flabeldb import cli

    rendered = dict(cli.view_sql("flabel_scratch"))
    assert "authoritative_runs" in rendered
    assert "flabel_scratch.runs" in rendered["authoritative_runs"]
    assert "{dataset}" not in rendered["authoritative_runs"]


def test_verify_exits_non_zero_on_drift_and_names_it(monkeypatch, capsys):
    """The exit code is the gate: `tools/flabel-deploy` stops on it.

    A `verify` that printed a difference and exited 0 would be a gate that reports and permits,
    which is worse than none — the report scrolls past and the deploy proceeds.
    """
    from flabeldb import cli, client

    short = {name: schema.LiveTable(fields=()) for name in schema.TABLES}
    monkeypatch.setattr(client, "client", lambda **_: fake_bq())
    monkeypatch.setattr(client, "live_schema", lambda _bq, _dataset: short)

    assert cli.main(["verify"]) == cli.EXIT_DRIFT
    assert "DIFFERS" in capsys.readouterr().err


def test_verify_exits_zero_when_the_dataset_matches(monkeypatch, capsys):
    """The complement, so drift detection cannot be satisfied by always failing."""
    from flabeldb import cli, client

    matching = {name: schema.TABLES[name] for name in schema.TABLES}
    monkeypatch.setattr(client, "client", lambda **_: fake_bq())
    monkeypatch.setattr(client, "live_schema", lambda _bq, _dataset: matching)

    assert cli.main(["verify"]) == cli.EXIT_OK
    assert "matches the declaration" in capsys.readouterr().out


def test_the_dataset_location_is_pinned_to_the_buckets_region():
    """Measured, and it is a requirement rather than a default.

    `gs://pm-proto-496816-flabel-pcaps` is a `US-CENTRAL1` **regional** bucket; a load job needs a
    compatible dataset location, and BigQuery job ids are namespaced `project:location.jobid`, so
    the location is part of the idempotency namespace too. Revision 1 of the spec never stated one.
    """
    from flabeldb import client

    assert client.LOCATION == "us-central1"


@needs_client
def test_a_credential_failure_is_not_reported_as_missing_tables(monkeypatch):
    """Found by running it: an expired credential made `verify` report every table as absent.

    `live_schema` caught a bare `Exception` on `get_table`, so "I could not ask" became "it is not
    there" — and the operator reads DIFFERS, runs `apply`, and hits the auth error one step later
    having been told something false about the dataset. Only `NotFound` means absent; every other
    failure has to propagate.
    """
    from google.api_core.exceptions import Forbidden, NotFound

    from flabeldb import client

    class Bq:
        project = "p"

        def __init__(self, error):
            self._error = error

        def get_table(self, _name):
            raise self._error

    # NotFound: the table really is absent, and that IS drift.
    absent = client.live_schema(Bq(NotFound("no such table")), "d")
    assert absent == {}

    # Anything else must not be silently turned into drift.
    with pytest.raises(Forbidden):
        client.live_schema(Bq(Forbidden("credential expired")), "d")


@needs_client
def test_a_credential_failure_exits_usage_and_not_drift(monkeypatch, capsys):
    """The two answers are different facts and must not share an exit code.

    `tools/flabel-deploy` reads exit 1 as "the dataset drifted, stop the deploy". An unusable
    credential exiting 1 would send the operator to look at the schema when nothing was ever read.
    Measured while building this: an expired laptop credential raised `RefreshError`, which exited
    1 as a bare traceback.
    """
    from google.auth.exceptions import RefreshError

    from flabeldb import cli, client

    monkeypatch.setattr(client, "client", lambda **_: fake_bq())

    def refuse(*_args, **_kwargs):
        raise RefreshError("Reauthentication is needed")

    monkeypatch.setattr(client, "live_schema", refuse)

    assert cli.main(["verify"]) == cli.EXIT_USAGE
    captured = capsys.readouterr()
    assert "NOT a report about the dataset" in captured.err
    assert "Traceback" not in captured.err


def test_an_unexpected_failure_is_not_swallowed_as_a_credential_problem(monkeypatch, capsys):
    """The complement: only real credential failures are converted.

    A blanket `except Exception -> EXIT_USAGE` would turn a real defect in `differences()` into a
    tidy message about authentication, which is the same absence-as-signal error one level up.

    It must not propagate either. A bare `raise` here reaches the interpreter and exits **1**,
    which is `EXIT_DRIFT` — so a defect in our own code would tell `tools/flabel-deploy` that the
    dataset drifted. It exits `EXIT_INTERNAL`, with the traceback kept, because a defect is a bug
    report and not a fact about the store.
    """
    from flabeldb import cli, client

    monkeypatch.setattr(client, "client", lambda **_: fake_bq())

    def explode(*_args, **_kwargs):
        raise ZeroDivisionError("a real defect")

    monkeypatch.setattr(client, "live_schema", explode)

    assert cli.main(["verify"]) == cli.EXIT_INTERNAL
    captured = capsys.readouterr()
    assert "Traceback" in captured.err, "a defect must stay debuggable"
    assert "ZeroDivisionError" in captured.err
    assert "NOT a report about the dataset" not in captured.err, (
        "a real defect was dressed up as an authentication problem"
    )


# --- the API's own type names ------------------------------------------------------------------
#
# `tables.get` does not answer in the vocabulary we declare in. Measured against
# `pm-proto-496816.flabel_scratch` on 2026-08-21, immediately after a clean `flabel-db apply`: the
# API returned INTEGER for every INT64 and RECORD for every STRUCT, and `verify` produced **24
# differences against a dataset it had itself just created** — after first dying with
# `ValueError: flow: only a STRUCT may carry subfields`, uncaught, which exits 1 = EXIT_DRIFT.
# So the deploy gate would have blocked every deploy while reporting a schema problem that did not
# exist. The match path had never executed: every test above builds the live side out of
# `schema.TABLES`, so it compares the declaration to a copy of itself.

#: The alias pairs, as `(what the API says, what we declare)`.
#: INTEGER and RECORD are **measured** on the live service. FLOAT64 and BOOL do not appear anywhere
#: in this schema, so their aliases are BigQuery's documented legacy names rather than something
#: this project has seen — they are here so the day a column gains one, it is already right.
LEGACY_TYPE_NAMES = (
    ("INTEGER", "INT64"),
    ("RECORD", "STRUCT"),
    ("FLOAT", "FLOAT64"),
    ("BOOLEAN", "BOOL"),
)


@pytest.mark.parametrize("legacy, ours", LEGACY_TYPE_NAMES)
def test_the_apis_legacy_type_name_is_the_same_type_as_ours(legacy, ours):
    """Two spellings of one type must not read as drift. `INTEGER` is measured, not assumed."""
    assert schema.canonical_type(legacy) == schema.canonical_type(ours) == ours


def test_a_type_name_we_do_not_know_is_left_alone_rather_than_guessed():
    """Normalisation must not silently invent a type — that would hide real drift as a match."""
    assert schema.canonical_type("GEOGRAPHY") == "GEOGRAPHY"


def test_a_record_carrying_subfields_is_accepted_because_that_is_what_the_api_returns():
    """The exact ValueError that killed the live `verify`: `only a STRUCT may carry subfields`."""
    found = schema.column("flow", "RECORD", fields=[schema.column("proto", "STRING")])
    assert found.field_type == "STRUCT", "a RECORD is a STRUCT, and should be stored as one"
    assert found.fields[0].name == "proto"


def test_a_struct_by_either_name_still_needs_subfields():
    """Normalising the name must not cost us the guard on the other side of it."""
    with pytest.raises(ValueError, match="describes nothing"):
        schema.column("flow", "RECORD")


def test_a_non_struct_carrying_subfields_is_still_refused():
    with pytest.raises(ValueError, match="only a STRUCT may carry subfields"):
        schema.column("flow", "STRING", fields=[schema.column("proto", "STRING")])


def as_the_api_returns_it(fields):
    """`fields`, respelled the way `tables.get` spells them — the measured legacy names."""
    bigquery = __import__("google.cloud.bigquery", fromlist=["bigquery"])
    to_legacy = {ours: legacy for legacy, ours in LEGACY_TYPE_NAMES}
    return [
        bigquery.SchemaField(
            item.name,
            to_legacy.get(item.field_type, item.field_type),
            mode=item.mode,
            fields=as_the_api_returns_it(item.fields) if item.fields else (),
        )
        for item in fields
    ]


@needs_client
@pytest.mark.parametrize("table", TABLES)
def test_the_declaration_round_trips_through_the_apis_own_vocabulary(table):
    """`differences(from_bigquery(to_bigquery(declared))) == ()`, with the legacy names injected.

    This is the test whose absence let PR #157 go green with a `verify` that could not succeed.
    It is pure — no API call — but it needs the client's `SchemaField`, so it skips without the
    extra and runs in CI, which installs it.
    """
    from flabeldb import client

    declared = schema.TABLES[table].fields
    live = client.from_bigquery(as_the_api_returns_it(client.to_bigquery(declared)))

    declaration = schema.TABLES[table]
    everything = {name: schema.TABLES[name] for name in schema.TABLES}
    round_tripped = schema.LiveTable(
        fields=live,
        partition_field=declaration.partition_field,
        clustering=declaration.clustering,
        description=declaration.description,
    )
    assert schema.differences({**everything, table: round_tripped}) == ()


# --- the credential detector, and the exit code an unknown failure must never take -------------
#
# The detector matched `type(error).__name__` against a frozenset of seven names. Exact names, so
# **every subclass escaped it.** Measured against the installed library 2026-08-21:
# `google.auth.exceptions` holds 18 exception classes, the frozenset matched 3 by name, and 15
# escaped — including `ReauthFailError`, which is a `RefreshError` subclass and is the exact failure
# spec-label-store §7.1 quotes from the box. All 18 subclass `GoogleAuthError`, so one isinstance
# check covers what 18 names could not.
#
# But the real defect was the DEFAULT. Anything unmatched hit a bare `raise`, which reaches the
# interpreter and exits 1 — `EXIT_DRIFT`. So an unrecognised failure, including a defect in our own
# code, told `tools/flabel-deploy` that the dataset had drifted. `EXIT_INTERNAL` exists so that
# cannot happen: exit 1 now means drift and nothing else.


def test_the_exit_codes_are_four_distinct_values():
    from flabeldb import cli

    codes = (cli.EXIT_OK, cli.EXIT_DRIFT, cli.EXIT_USAGE, cli.EXIT_INTERNAL)
    assert len(set(codes)) == len(codes), f"two exit codes collide: {codes}"


def test_an_internal_error_can_never_be_read_as_drift():
    """The collision that matters: `flabel-deploy` stops on EXIT_DRIFT and blames the schema."""
    from flabeldb import cli

    assert cli.EXIT_INTERNAL != cli.EXIT_DRIFT
    assert cli.EXIT_INTERNAL != 1


def _failing_verify(monkeypatch, error):
    """`flabel-db verify` where the live read raises `error`."""
    from flabeldb import cli, client

    monkeypatch.setattr(client, "client", lambda **_: fake_bq())
    monkeypatch.setattr(client, "live_schema", lambda *a, **k: (_ for _ in ()).throw(error))
    return cli.main(["verify"])


def _google_auth_exception_classes():
    """Every exception class in `google.auth.exceptions`, discovered rather than listed.

    Discovered on purpose: a hand-written list is what the frozenset was, and it went stale the
    moment the library gained a subclass. This test cannot.
    """
    import inspect

    from db_extra import module_is_available

    if not module_is_available("google.auth.exceptions"):
        # Collection happens before any skip can apply, so this MUST NOT import google. Returning
        # empty makes the parametrised test an empty parameter set, which pytest skips. Found by
        # actually syncing without the extra — the item-5 measurement caught this very function.
        return []

    import google.auth.exceptions as module

    return sorted(
        name
        for name, obj in vars(module).items()
        if inspect.isclass(obj) and issubclass(obj, BaseException)
    )


@needs_client
@pytest.mark.parametrize("name", _google_auth_exception_classes())
def test_every_google_auth_failure_exits_usage_and_not_drift(name, monkeypatch, capsys):
    """All 18, not the 3 the frozenset happened to name."""
    import google.auth.exceptions as module

    from flabeldb import cli

    error_type = getattr(module, name)
    try:
        error = error_type("could not authenticate")
    except TypeError:  # pragma: no cover - a class needing other arguments
        error = error_type()

    assert _failing_verify(monkeypatch, error) == cli.EXIT_USAGE, (
        f"{name} was not recognised as a credential failure and landed on an exit code that "
        f"says something about the dataset"
    )
    assert "NOT a report about the dataset" in capsys.readouterr().err


@needs_client
def test_the_reauth_failure_spec_7_1_quotes_from_the_box_is_recognised(monkeypatch):
    """`ReauthFailError` — a `RefreshError` SUBCLASS, so the name-matching frozenset missed it."""
    from google.auth.exceptions import ReauthFailError, RefreshError

    from flabeldb import cli

    assert issubclass(ReauthFailError, RefreshError), "the library changed shape; revisit this"
    error = ReauthFailError("Reauthentication is needed. Please run `gcloud auth login`")
    assert _failing_verify(monkeypatch, error) == cli.EXIT_USAGE


@needs_client
@pytest.mark.parametrize(
    "name", ["Forbidden", "PermissionDenied", "Unauthorized", "Unauthenticated", "RetryError"]
)
def test_the_api_core_failures_that_mean_we_never_read_the_dataset_exit_usage(name, monkeypatch):
    """`RetryError` is measured NOT to be a `GoogleAPICallError`, so it has to be named itself."""
    import google.api_core.exceptions as module

    from flabeldb import cli

    error_type = getattr(module, name)
    try:
        error = error_type("denied")
    except TypeError:
        error = error_type("denied", cause=None)

    assert _failing_verify(monkeypatch, error) == cli.EXIT_USAGE


@needs_client
def test_a_not_found_is_not_a_credential_failure(monkeypatch):
    """`NotFound` shares `ClientError` with `Forbidden`, so the match names types, not a base.

    It is also the one API error that IS a fact about the dataset, which is why `live_schema`
    catches it and nothing else.
    """
    from google.api_core.exceptions import ClientError, Forbidden, NotFound

    from flabeldb import cli

    assert issubclass(NotFound, ClientError) and issubclass(Forbidden, ClientError), (
        "the library changed shape; a base-class match would now be safe, but check"
    )
    assert _failing_verify(monkeypatch, NotFound("no such dataset")) == cli.EXIT_INTERNAL


# --- verify beyond the field list ---------------------------------------------------------------
#
# `differences()` compared field lists and nothing else, so everything BigQuery lays a table out
# with was invisible to the gate. Two consequences, both measured against this declaration:
#
#   - `flow_labels` clustered on `zeek_uid` verified CLEAN. That is the store's single named
#     never-do: under Zeek's `-D` a uid is positional, so it means "connection #N in this capture"
#     and clustering on it groups unrelated flows from different captures.
#   - Reversing all 13 columns of `runs` yielded ZERO differences, because the comparison indexed
#     the live side by name.
#
# Column order matters for a reason apply cannot fix: `update_table` accepts a reordered schema and
# silently ignores it (measured), so order drift is permanent until the table is rebuilt. A gate
# that cannot see it lets a hand-built table diverge from the declaration for good.


def declared_live() -> dict:
    """The live side as a perfect copy of the declaration.

    A `Table` is used directly as the live shape: it carries the same four attributes `LiveTable`
    does, which is what lets `differences()` read either.
    """
    return {name: schema.TABLES[name] for name in schema.TABLES}


def altered(name: str, **changes) -> dict:
    """`declared_live()` with one table replaced by a `LiveTable` differing in `changes`."""
    table = schema.TABLES[name]
    live = declared_live()
    live[name] = schema.LiveTable(
        fields=changes.pop("fields", table.fields),
        partition_field=changes.pop("partition_field", table.partition_field),
        clustering=changes.pop("clustering", table.clustering),
        description=changes.pop("description", table.description),
    )
    assert not changes, f"unknown keys: {sorted(changes)}"
    return live


def test_the_declaration_verifies_clean_against_itself():
    assert schema.differences(declared_live()) == ()


def test_clustering_on_zeek_uid_is_reported():
    """The store's ONE named never-do: spec §4.3, because under `-D` a uid is positional —
    "connection #N" in every capture — so clustering on it groups unrelated flows.

    Measured 2026-08-21: BigQuery will not actually accept this state, because `zeek_uid` sits
    inside the `flow` STRUCT and clustering takes top-level fields only ("400 The field specified
    for clustering cannot be found in the schema"). So this tests the COMPARISON against a state the
    API would refuse — kept because the comparison is what was blind, and a future top-level
    `zeek_uid` column would make it reachable. The reachable case is the parametrised test below,
    and `test_flabeldb_live.py` pins BigQuery's refusal itself.
    """
    found = schema.differences(altered("flow_labels", clustering=("zeek_uid",)))

    assert found, "clustering on zeek_uid verified clean"
    assert any("cluster" in message.lower() for message in found)
    assert any("zeek_uid" in message for message in found)


def test_reversing_every_column_of_runs_is_reported():
    """13 columns reversed, zero differences reported. The comparison indexed live by name."""
    reversed_fields = tuple(reversed(schema.TABLES["runs"].fields))
    assert len(reversed_fields) == 13, "the runs declaration changed; update this count"

    found = schema.differences(altered("runs", fields=reversed_fields))

    assert found, "reversing all 13 columns yielded no differences"
    assert any("order" in message.lower() for message in found)


def test_reordering_a_structs_subfields_is_reported():
    """Nesting is where a name-indexed comparison is easiest to fool."""
    flow = schema.field_of("flow_labels", "flow")
    swapped = schema.column("flow", "STRUCT", fields=tuple(reversed(flow.fields)))
    fields = tuple(
        swapped if item.name == "flow" else item for item in schema.TABLES["flow_labels"].fields
    )

    found = schema.differences(altered("flow_labels", fields=fields))

    assert any("order" in message.lower() for message in found)


@pytest.mark.parametrize(
    "table, change, word",
    [
        pytest.param("runs", {"partition_field": None}, "partition", id="partition-dropped"),
        pytest.param("runs", {"partition_field": "ingested_at"}, "partition", id="partition-moved"),
        pytest.param(
            "flow_labels", {"partition_field": "run_id"}, "partition", id="partition-added"
        ),
        pytest.param("runs", {"clustering": ()}, "cluster", id="clustering-dropped"),
        pytest.param("runs", {"clustering": ("mode",)}, "cluster", id="clustering-narrowed"),
        pytest.param(
            "runs", {"clustering": ("mode", "capture_sha256")}, "cluster", id="clustering-reordered"
        ),
        pytest.param(
            "captures",
            {"description": "edited in the console"},
            "description",
            id="description-changed",
        ),
        pytest.param("captures", {"description": ""}, "description", id="description-dropped"),
    ],
)
def test_the_layout_verify_was_blind_to_is_reported(table, change, word):
    found = schema.differences(altered(table, **change))

    assert found, f"{change} verified clean"
    assert any(word in message.lower() for message in found), f"no message mentions {word}: {found}"
    assert any(table in message for message in found)


def test_clustering_order_is_significant_and_not_a_set():
    """BigQuery clusters hierarchically: ('a','b') and ('b','a') are different physical layouts."""
    found = schema.differences(altered("runs", clustering=("mode", "capture_sha256")))
    assert found


def test_an_added_column_is_not_also_reported_as_a_reordering():
    """One fact, one message. Order is compared over the columns present on BOTH sides."""
    fields = (*schema.TABLES["run_exclusions"].fields, schema.column("smuggled", "STRING"))
    found = schema.differences(altered("run_exclusions", fields=fields))

    assert any("smuggled" in message for message in found)
    assert not any("order" in message.lower() for message in found), (
        f"an appended column was also reported as a reordering: {found}"
    )


def test_a_dropped_column_is_not_also_reported_as_a_reordering():
    fields = schema.TABLES["run_exclusions"].fields[:-1]
    found = schema.differences(altered("run_exclusions", fields=fields))

    assert any("missing" in message for message in found)
    assert not any("order" in message.lower() for message in found), (
        f"a dropped column was also reported as a reordering: {found}"
    )


# --- the dataset itself, not just its tables ----------------------------------------------------


@needs_client
def test_a_dataset_in_the_wrong_location_is_drift(monkeypatch, capsys):
    """A location is IMMUTABLE, so this is the one drift that can never be patched at all.

    It matters beyond tidiness: the results bucket is US-CENTRAL1 *regional* and a load job needs a
    compatible dataset location, and BigQuery job ids are namespaced `project:location.jobid`, so
    the location is part of the idempotency namespace (spec §10 M2, M4).
    """
    from flabeldb import cli, client

    monkeypatch.setattr(client, "client", lambda **_: fake_bq(location="us-east1"))
    monkeypatch.setattr(
        client, "live_schema", lambda *_: {name: schema.TABLES[name] for name in schema.TABLES}
    )

    assert cli.main(["verify"]) == cli.EXIT_DRIFT
    error = capsys.readouterr().err
    assert "us-east1" in error and "us-central1" in error
    assert "IMMUTABLE" in error or "immutable" in error


@needs_client
def test_the_location_comparison_is_not_case_sensitive(monkeypatch, capsys):
    """BigQuery returned `us-central1` lowercase for this dataset (measured), but it reports
    multi-regions as `US`/`EU`, so the comparison is deliberately case-insensitive rather than
    relying on the casing one dataset happened to have."""
    from flabeldb import cli, client

    monkeypatch.setattr(client, "client", lambda **_: fake_bq(location="US-CENTRAL1"))
    monkeypatch.setattr(
        client, "live_schema", lambda *_: {name: schema.TABLES[name] for name in schema.TABLES}
    )

    assert cli.main(["verify"]) == cli.EXIT_OK, capsys.readouterr().err


@needs_client
def test_a_dataset_that_does_not_exist_is_not_reported_as_five_missing_tables(monkeypatch, capsys):
    """Measured live 2026-08-21 against a project whose dataset does not exist: `verify` listed
    five tables as "missing from the dataset" and then advised running `apply`.

    Both halves are wrong. Nothing was read, so nothing is known about tables; and `apply` cannot
    create a dataset — that is LS-6 — so the advice sends the operator in a circle. `NotFound` on a
    table means the table is absent; on the dataset it means the container is not there.
    """
    from google.api_core.exceptions import NotFound

    from flabeldb import cli, client

    class Bq:
        project = "p"

        def get_dataset(self, reference):
            raise NotFound(f"Not found: Dataset {reference}")

    monkeypatch.setattr(client, "client", lambda **_: Bq())

    assert cli.main(["--dataset", "flabl_typo", "verify"]) == cli.EXIT_DRIFT
    error = capsys.readouterr().err
    assert "flabl_typo" in error
    assert "does not exist" in error
    assert "missing from the dataset" not in error, "it reported tables it never looked at"
    assert "Run `flabel-db apply`" not in error, (
        "it told the operator to run apply, which cannot create a dataset — that is the drift "
        "path's advice, and this is not drift in a dataset"
    )
    assert "not by `apply`" in error, "it should say plainly that apply is not the fix here"


@needs_client
def test_a_credential_failure_reaching_the_dataset_is_still_not_drift(monkeypatch, capsys):
    """`get_dataset` is now the FIRST call, so it is where an expired credential surfaces."""
    from google.auth.exceptions import RefreshError

    from flabeldb import cli, client

    class Bq:
        project = "p"

        def get_dataset(self, _reference):
            raise RefreshError("Reauthentication is needed")

    monkeypatch.setattr(client, "client", lambda **_: Bq())

    assert cli.main(["verify"]) == cli.EXIT_USAGE
    assert "NOT a report about the dataset" in capsys.readouterr().err


# --- the declaration guards, which had never executed --------------------------------------------
#
# `Column.__post_init__` and `Table.__post_init__` reject a malformed declaration, and until now
# every one of those branches was unexecuted: the tests above assert properties OF the declaration
# by re-implementing the guard's own logic (`test_every_partition_field_is_top_level` walks TABLES
# and checks for a dot), which passes whether or not the guard exists.
#
# The gap that matters is not the untested branch, it is the MISSING one. `partition_field` reaching
# into a STRUCT is refused; `partition_field="run_id"`, a STRING, is accepted — and both fail at
# `CREATE TABLE` with the same consequence, a table that cannot be created from its own declaration.
#
# WHERE a guard lives is load-bearing, and Critical 1 is why. `Column` is built by the declaration
# AND by `client.from_bigquery` reading a live table, so a guard there fires on live data: a
# `RECORD` reaching it raised `only a STRUCT may carry subfields`, which exits 1 = EXIT_DRIFT, so
# `verify` could never succeed against a table that exists. `Table` is built by the declaration
# only — `LiveTable` exists to keep it that way — so strict guards belong there.


def a_table(**changes) -> schema.Table:
    """A minimal valid `Table`, with `changes` applied. Valid, so a failure names one cause."""
    fields = changes.pop(
        "fields",
        (
            schema.column("run_id", "STRING", mode=schema.REQUIRED),
            schema.column("finished_at", "TIMESTAMP"),
            schema.column("flow", "STRUCT", fields=(schema.column("zeek_uid", "STRING"),)),
        ),
    )
    return schema.Table(fields=fields, **changes)


def test_the_minimal_table_this_sections_fixtures_build_on_is_itself_valid():
    """Otherwise every `pytest.raises` below could be passing for the wrong reason."""
    assert a_table().fields


# --- guards that existed and were never executed --------------------------------------------


def test_a_mode_that_is_not_a_bigquery_mode_is_refused():
    with pytest.raises(ValueError, match="is not a BigQuery mode"):
        schema.column("run_id", "STRING", mode="MANDATORY")


def test_two_columns_of_the_same_name_are_refused():
    """A dict-shaped comparison would silently keep the last one and report no drift."""
    with pytest.raises(ValueError, match="repeated column name"):
        a_table(
            fields=(
                schema.column("run_id", "STRING"),
                schema.column("run_id", "TIMESTAMP"),
            )
        )


@pytest.mark.parametrize("key", ["flow.ts_first", "flow.zeek_uid"])
def test_a_partition_field_reaching_into_a_struct_is_refused(key):
    """Measured 2026-08-20 at `CREATE TABLE`: "can only be a top-level field"."""
    with pytest.raises(ValueError, match="reaches inside a STRUCT"):
        a_table(partition_field=key)


def test_a_clustering_key_reaching_into_a_struct_is_refused():
    """The same rule, the other input. Measured 2026-08-21 against the live service: clustering
    `flow_labels` on `zeek_uid` fails with "The field specified for clustering cannot be found in
    the schema", because it is inside the `flow` STRUCT."""
    with pytest.raises(ValueError, match="reaches inside a STRUCT"):
        a_table(clustering=("flow.zeek_uid",))


def test_a_partition_field_that_is_not_a_column_at_all_is_refused():
    with pytest.raises(ValueError, match="is not a column of this table"):
        a_table(partition_field="ingested_at")


def test_a_clustering_key_that_is_not_a_column_at_all_is_refused():
    with pytest.raises(ValueError, match="is not a column of this table"):
        a_table(clustering=("capture_sha256",))


# --- guards that were missing -----------------------------------------------------------------


def test_partitioning_on_a_string_is_refused_the_way_a_nested_field_already_was():
    """THE POINT OF THIS SECTION. `partition_field="flow.ts_first"` was refused and
    `partition_field="run_id"` — a STRING — was accepted, with the identical consequence.

    `_apply` builds `bigquery.TimePartitioning(field=...)` for any declared `partition_field`, and
    time-unit partitioning takes a DATE, DATETIME or TIMESTAMP column. A STRING there fails at
    `CREATE TABLE`, which is exactly the failure the nesting guard exists to move into CI.
    """
    with pytest.raises(ValueError, match="partition"):
        a_table(partition_field="run_id")


@pytest.mark.parametrize("field_type", ["TIMESTAMP", "DATE", "DATETIME"])
def test_the_three_types_time_unit_partitioning_accepts_are_accepted(field_type):
    """The complement, so the guard cannot be satisfied by refusing everything."""
    table = a_table(
        fields=(schema.column("when", field_type),),
        partition_field="when",
    )
    assert table.partition_field == "when"


def test_partitioning_on_an_int64_is_refused_because_apply_cannot_build_it():
    """INT64 range partitioning is a real BigQuery feature and `_apply` does not emit it — it
    builds `TimePartitioning` unconditionally. Declaring one would produce a table this code
    cannot create, so the guard tracks what `apply` can do, not what BigQuery can.
    """
    with pytest.raises(ValueError, match="partition"):
        a_table(fields=(schema.column("n", "INT64"),), partition_field="n")


def test_partitioning_on_a_repeated_column_is_refused():
    """A REPEATED TIMESTAMP passes the type check and is still not a partition key — BigQuery
    partitions on one value per row, and a repeated column has none or many."""
    with pytest.raises(ValueError, match="REPEATED"):
        a_table(
            fields=(schema.column("when", "TIMESTAMP", mode=schema.REPEATED),),
            partition_field="when",
        )


def test_a_fifth_clustering_key_is_refused():
    """BigQuery caps clustering at four columns. A fifth fails at `CREATE TABLE`."""
    fields = tuple(schema.column(f"c{index}", "STRING") for index in range(5))
    with pytest.raises(ValueError, match="four"):
        schema.Table(fields=fields, clustering=tuple(f"c{index}" for index in range(5)))


def test_four_clustering_keys_are_accepted():
    fields = tuple(schema.column(f"c{index}", "STRING") for index in range(4))
    table = schema.Table(fields=fields, clustering=tuple(f"c{index}" for index in range(4)))
    assert len(table.clustering) == 4


def test_the_same_clustering_key_twice_is_refused():
    """Not a layout BigQuery has any meaning for, and it would read as a 2-key table."""
    with pytest.raises(ValueError, match="twice|repeated|duplicate"):
        a_table(clustering=("run_id", "run_id"))


def test_a_table_with_no_columns_is_refused():
    """`differences()` would report a clean match between two tables that describe nothing."""
    with pytest.raises(ValueError, match="no columns"):
        schema.Table(fields=())


def test_a_type_name_that_is_not_a_bigquery_type_is_refused_in_the_declaration():
    """A typo here reaches `CREATE TABLE`, which is the failure the guards exist to move earlier."""
    with pytest.raises(ValueError, match="not a BigQuery type"):
        a_table(fields=(schema.column("run_id", "VARCHAR"),))


def test_the_type_name_is_validated_inside_a_struct_too():
    """Nesting is where a declaration-walking check is easiest to write wrong."""
    with pytest.raises(ValueError, match="not a BigQuery type"):
        a_table(fields=(schema.column("flow", "STRUCT", fields=(schema.column("n", "TEXT"),)),))


def test_an_unknown_type_from_the_LIVE_read_is_drift_and_not_an_exception():
    """CRITICAL 1's LESSON, pinned. The type-name guard must be declaration-only.

    A `RECORD` from `tables.get` reaching `Column.__post_init__` raised, uncaught, and exited 1 =
    EXIT_DRIFT — so `verify` could not succeed against a table that exists and the deploy gate
    would have blocked every deploy naming a schema problem that did not exist. The day BigQuery
    returns a type this file has never heard of, `verify` must REPORT it, not crash on it.
    """
    from flabeldb import client

    class Field:
        name, field_type, mode, fields = "run_id", "SOMETHING_NEW", "REQUIRED", ()

    live = client.from_bigquery([Field()])
    assert live[0].field_type == "SOMETHING_NEW", "an unknown type was guessed at, or refused"

    found = schema.differences(altered("run_exclusions", fields=live))
    assert found, "an undeclared type from the live read verified clean"


def test_every_declared_table_passes_every_guard():
    """`TABLES` is built at import, so this is really a statement that the guards above are not so
    strict that the declaration itself could not be written. It fails loudly if a new guard is
    added that the store's own schema violates."""
    for name, table in schema.TABLES.items():
        rebuilt = schema.Table(
            fields=table.fields,
            partition_field=table.partition_field,
            clustering=table.clustering,
            description=table.description,
        )
        assert rebuilt == table, name


# --- the two identifiers that cannot be query parameters ----------------------------------------
#
# `_show`'s row filters are parameterised. `--project` and `--dataset` cannot be: a dataset name is
# part of a table PATH, not a value, so `view_sql`, `_verify` and `_show` all reach SQL by
# interpolation. `apply`'s view path runs `CREATE OR REPLACE VIEW` as `dataOwner`, which is the
# rights to replace anything in the dataset. The input is an operator's own, so this is defence in
# depth rather than a hole being closed — but it is one regex against a statement that runs with
# those rights.


@pytest.mark.parametrize(
    "flag, value",
    [
        ("--dataset", "flabel`; DROP TABLE x; --"),
        ("--dataset", "flabel.other"),
        ("--dataset", "flabel scratch"),
        ("--dataset", ""),
        ("--project", "p`.`q"),
        ("--project", "p; SELECT 1"),
    ],
)
def test_a_dataset_or_project_that_is_not_an_identifier_is_refused(flag, value, capsys):
    """EXIT_USAGE, not EXIT_DRIFT: nothing was read, so nothing can be said about the dataset."""
    from flabeldb import cli

    assert cli.main([flag, value, "verify"]) == cli.EXIT_USAGE
    assert "identifier" in capsys.readouterr().err


def test_the_check_happens_before_a_client_is_ever_built(monkeypatch, capsys):
    """Otherwise a malformed name reaches a credential and a billing project before being caught."""
    from flabeldb import cli, client

    def fail(*_args, **_kwargs):
        raise AssertionError("a client was built for an invalid identifier")

    monkeypatch.setattr(client, "client", fail)
    assert cli.main(["--dataset", "bad name", "verify"]) == cli.EXIT_USAGE
    capsys.readouterr()


#: A hyphenated project id, an underscored dataset name, and the two shortest legal forms.
#: Shapes rather than this project's actual ids — the repo is public.
@pytest.mark.parametrize("value", ["flabel", "flabel_scratch", "some-proto-123456", "a1"])
def test_the_names_this_project_actually_uses_are_accepted(value):
    """The complement: a guard that rejected the real dataset would be found only in production."""
    from flabeldb import cli

    assert cli.IDENTIFIER.match(value), f"{value!r} is a name this project uses"


def test_the_default_dataset_passes_its_own_check():
    """The one name that must never be rejected, since it is used when the flag is absent."""
    from flabeldb import cli, client

    assert cli.IDENTIFIER.match(client.DEFAULT_DATASET)


# --- show: a flag is never silently ignored ------------------------------------------------------


def test_run_id_and_capture_cannot_both_be_given():
    """`_show` reads them as a chain and `--run-id` wins, so passing both silently answered a
    narrower question than the one asked. Argparse refuses it now, which is exit 2 from argparse
    itself — the same treatment #132 gave the mode flags."""
    from flabeldb import cli

    with pytest.raises(SystemExit) as raised:
        cli.build_parser().parse_args(["show", "--run-id", "r", "--capture", "c"])
    assert raised.value.code == 2


@pytest.mark.parametrize("argv", [["show"], ["show", "--run-id", "r"], ["show", "--capture", "c"]])
def test_each_of_the_three_ways_to_ask_is_still_accepted(argv):
    """The complement, so the exclusion cannot be satisfied by refusing the useful cases."""
    from flabeldb import cli

    args = cli.build_parser().parse_args(argv)
    assert args.action == "show"


# --- §7.4 guard 4: the assertion that the other three are still connected ------------------------


def test_duplicate_run_ids_are_reported_as_drift():
    """§7.4: guards 1-3 are the mechanism; this proves the mechanism is still WORKING.

    A duplicate `run_id` in `runs` means the commit marker landed twice for one run, so every
    read that joins through it doubles. None of guards 1-3 can notice that about themselves —
    an idempotency guard cannot report that it stopped working — which is why the check is a
    query over the data rather than another branch in the loader.
    """
    from flabeldb import cli

    found = cli.duplicate_run_ids([("abc123", 2), ("def456", 3)])

    assert found
    assert any("abc123" in message and "2" in message for message in found)


def test_no_duplicates_is_silent():
    from flabeldb import cli

    assert cli.duplicate_run_ids([]) == ()


def test_the_duplicate_check_names_every_offender_not_just_the_first():
    """One duplicated run is a bug; five is a different bug, and the count is the difference."""
    from flabeldb import cli

    found = cli.duplicate_run_ids([("a", 2), ("b", 2), ("c", 9)])
    assert len(found) == 3


def test_verify_actually_RUNS_the_duplicate_check(monkeypatch, capsys):
    """**Found by sabotage.** Deleting the call from `_verify` left all 127 tests green: the guard
    was tested and unwired, which is the exact failure mode §7.4 wrote guard 4 to prevent one layer
    down. A guard nothing calls is a guard that has stopped working, silently.
    """
    from flabeldb import cli, client

    class Row:
        run_id, n = "dupe0000", 2

    class Bq:
        project = "p"

        def get_dataset(self, _reference):
            return type("Dataset", (), {"location": "us-central1"})()

        def query(self, _sql, **_kwargs):
            return type("Job", (), {"result": lambda self: iter([Row()])})()

    monkeypatch.setattr(client, "client", lambda **_: Bq())
    monkeypatch.setattr(
        client, "live_schema", lambda *_a, **_k: {n: schema.TABLES[n] for n in schema.TABLES}
    )

    assert cli.main(["verify"]) == cli.EXIT_DRIFT
    assert "dupe0000" in capsys.readouterr().err


def test_the_duplicate_check_is_skipped_while_the_shape_is_still_wrong(monkeypatch, capsys):
    """A query over `runs` means nothing when `runs` is missing — and reporting a query failure
    on top of "table is missing" would bury the fact that matters under a consequence of it."""
    from flabeldb import cli, client

    class Bq:
        project = "p"

        def get_dataset(self, _reference):
            return type("Dataset", (), {"location": "us-central1"})()

        def query(self, _sql, **_kwargs):
            raise AssertionError("the duplicate check queried a dataset whose shape is wrong")

    monkeypatch.setattr(client, "client", lambda **_: Bq())
    monkeypatch.setattr(client, "live_schema", lambda *_a, **_k: {})

    assert cli.main(["verify"]) == cli.EXIT_DRIFT
    assert "missing" in capsys.readouterr().err


# --- LS-9: the one file, rendered two ways -------------------------------------------------------


def test_the_view_file_is_rendered_for_the_ddl_and_for_the_as_of_select():
    """§9 forbids implementing the supersession rule twice and §4.6 says there is exactly one view.

    `--as-of` needs the same selection with one more predicate, and a view takes no parameters — so
    the same file is rendered a second way instead of a second statement existing. One text rendered
    two ways cannot diverge; a second view could, which is what §4.6 records removing.
    """
    ddl = schema.render_view("authoritative_runs", "flabel_scratch")
    adhoc = schema.render_view("authoritative_runs", "flabel_scratch", as_of=True, ddl=False)

    assert ddl.count("CREATE OR REPLACE VIEW") == 1
    assert adhoc.count("CREATE OR REPLACE VIEW") == 0
    assert "{" not in ddl.replace("{", "", 0) or "{header}" not in ddl
    for rendered in (ddl, adhoc):
        assert "{header}" not in rendered and "{as_of}" not in rendered
        assert "{dataset}" not in rendered


def test_the_two_renderings_differ_by_exactly_the_cutoff_and_the_create():
    """The property that makes "one rule" true rather than asserted: the as-of statement is the
    view's body with **one** predicate added, and nothing else."""
    import difflib

    ddl = schema.render_view("authoritative_runs", "flabel_scratch")
    adhoc = schema.render_view("authoritative_runs", "flabel_scratch", as_of=True, ddl=False)
    changed = [
        line
        for line in difflib.unified_diff(ddl.splitlines(), adhoc.splitlines(), lineterm="", n=0)
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    removed = [line for line in changed if line.startswith("-")]
    added = [line for line in changed if line.startswith("+") and line[1:].strip()]
    assert len(removed) == 1 and "CREATE OR REPLACE VIEW" in removed[0]
    assert len(added) == 1
    assert added[0].lstrip("+").strip() == "AND r.ingested_at <= @as_of"


def test_the_cutoff_filters_ingested_at_and_never_finished_at():
    """**§6.5's whole argument, and the thing a plausible implementation gets backwards.**

    A backfill ingests old tarballs late, so a run finishing 2026-08-17 can carry an `ingested_at`
    of 2026-09-01. Filtering on `finished_at` would let a document rebuilt "as of the 25th" silently
    gain a run that was not in the store that day. Both clocks are needed and they do different
    jobs: `ingested_at` selects the candidate set, `finished_at` decides which candidate wins.
    """
    assert "ingested_at" in schema.AS_OF_PREDICATE
    assert "finished_at" not in schema.AS_OF_PREDICATE

    adhoc = sql_of("authoritative_runs.sql").replace("{as_of}", schema.AS_OF_PREDICATE)
    # `finished_at` still appears — in the ORDER BY, which is what decides the winner.
    ordering = re.search(r"ORDER BY(.+?)\)", adhoc, re.IGNORECASE | re.DOTALL)
    assert "finished_at" in ordering.group(1)
    # ...and the cutoff is a predicate, not part of that ordering.
    assert "ingested_at" not in ordering.group(1)


def test_the_cutoff_is_a_bound_parameter_and_not_interpolated():
    """A timestamp IS a value, unlike a dataset name, so nothing interpolates it."""
    assert "@as_of" in schema.AS_OF_PREDICATE
    adhoc = schema.render_view("authoritative_runs", "flabel_scratch", as_of=True, ddl=False)
    assert "@as_of" in adhoc


def test_the_ddl_rendering_carries_no_cutoff_at_all():
    """The view must stay what LS-3 shipped: `apply` against a live dataset is not implied by LS-9,
    and a view that filtered on a parameter it cannot take would not be creatable."""
    ddl = schema.render_view("authoritative_runs", "flabel")
    assert "ingested_at" not in ddl
    assert "@as_of" not in ddl


def test_render_view_refuses_a_name_it_does_not_have():
    with pytest.raises(ValueError, match="not a committed view"):
        schema.render_view("current_labels", "flabel")


def test_view_names_matches_the_files_on_disk():
    assert schema.view_names() == tuple(sorted(path.stem for path in VIEWS.glob("*.sql")))
