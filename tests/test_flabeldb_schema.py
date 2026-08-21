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


def test_verify_is_silent_when_the_live_schema_matches():
    live = {name: schema.TABLES[name].fields for name in schema.TABLES}
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
    live = {name: schema.TABLES[name].fields for name in schema.TABLES}
    live["runs"] = tuple(mutate(tuple(live["runs"])))

    found = schema.differences(live)
    assert found, "verify saw no difference"
    assert any(expected in message for message in found), (
        f"no reported difference mentions {expected!r}: {found}"
    )


def test_verify_reports_a_table_that_does_not_exist_at_all():
    """The failure mode of a half-run `apply`, which is likelier than a patched column."""
    live = {name: schema.TABLES[name].fields for name in schema.TABLES}
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

    short = dict.fromkeys(schema.TABLES, ())
    monkeypatch.setattr(client, "client", lambda **_: type("Bq", (), {"project": "p"})())
    monkeypatch.setattr(client, "live_schema", lambda _bq, _dataset: short)

    assert cli.main(["verify"]) == cli.EXIT_DRIFT
    assert "DIFFERS" in capsys.readouterr().err


def test_verify_exits_zero_when_the_dataset_matches(monkeypatch, capsys):
    """The complement, so drift detection cannot be satisfied by always failing."""
    from flabeldb import cli, client

    matching = {name: schema.TABLES[name].fields for name in schema.TABLES}
    monkeypatch.setattr(client, "client", lambda **_: type("Bq", (), {"project": "p"})())
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

    monkeypatch.setattr(client, "client", lambda **_: type("Bq", (), {"project": "p"})())

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

    monkeypatch.setattr(client, "client", lambda **_: type("Bq", (), {"project": "p"})())

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

    everything = {name: schema.TABLES[name].fields for name in schema.TABLES}
    assert schema.differences({**everything, table: live}) == ()


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

    monkeypatch.setattr(client, "client", lambda **_: type("Bq", (), {"project": "p"})())
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
