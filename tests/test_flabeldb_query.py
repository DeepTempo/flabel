"""Reading the store — spec-label-store §5.2 step 1, and the two things the SQL must not do.

`query.py` is deliberately thin, so these are few. Both of the checks that matter are structural
and run without a credential: nothing limits the flow rows, and every value that filters a row is
bound rather than interpolated.
"""

from __future__ import annotations

import inspect

import pytest

from flabeldb import query


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeBQ:
    """Records the SQL it is handed. `project` is what `query.table` interpolates beside the
    dataset, so it is a real attribute rather than a stub."""

    project = "a-project"

    def __init__(self, rows=()):
        self.rows = list(rows)
        self.statements: list[str] = []
        self.configs: list[object] = []

    def query(self, sql, job_config=None):
        self.statements.append(sql)
        self.configs.append(job_config)
        return FakeResult(self.rows)


# --- the identifier that cannot be a parameter ---------------------------------------------------


def test_the_dataset_is_checked_because_it_cannot_be_bound():
    """A dataset name is part of a table path, not a value, so no `ScalarQueryParameter` can carry
    it. `cli._show` makes the same split, and `apply`'s view path runs `CREATE OR REPLACE VIEW` as
    `dataOwner` — an interpolated statement there executes with the rights to replace anything."""
    bq = FakeBQ()
    assert query.table(bq, "flabel_scratch", "runs") == "`a-project.flabel_scratch.runs`"
    with pytest.raises(ValueError, match="not a BigQuery identifier"):
        query.table(bq, "flabel`; DROP", "runs")


def test_the_identifier_pattern_is_flabel_dbs_own():
    """One pattern guarding one interpolation. Two would be the duplicate-authority defect."""
    from flabeldb import cli

    assert query.IDENTIFIER is cli.IDENTIFIER


# --- the LIMIT that must not exist ----------------------------------------------------------------


@pytest.mark.requires_db_extra
def test_nothing_in_this_module_limits_or_paginates_the_rows():
    """`--limit` is applied after composition, in `collection.build`.

    A flow's rows come from up to one run per tier (§4.6), so a `LIMIT` here would cut a flow's
    tier-2 row off from its tier-1 one and merge half of it — silently, and only for captures near
    the boundary. §5.2 accepts the scale that implies: a few hundred labels per capture is not a
    scale problem, and composing in Python is the whole reason the merge is not in SQL.

    Asserted over the **statements the module actually issues**, not over its source: a first
    version grepped the file and went red on its own docstring, which is a test of the prose.
    """
    bq = FakeBQ()
    runs = ["0123456789abcdef"]
    query.authoritative(bq, "flabel")
    query.authoritative(bq, "flabel", ["a" * 64])
    query.flow_labels(bq, "flabel", runs)
    query.runs(bq, "flabel", runs)
    query.sightings(bq, "flabel", runs)
    query.capture_shas(bq, "flabel", ["some.pcap"])

    assert len(bq.statements) == 6, "every read path must be covered by this assertion"
    offenders = [sql for sql in bq.statements if "LIMIT" in sql.upper()]
    assert not offenders, f"a LIMIT reached the store's read path: {offenders}"


def test_the_flow_row_query_selects_every_column_the_merge_reads():
    """A column dropped from the projection reaches `merge` as `None` and refuses the flow — a
    counted refusal for a defect in the SELECT, which reads as bad data."""
    source = inspect.getsource(query.flow_labels)
    for column in (
        "run_id",
        "capture_sha256",
        "flow_key",
        "flow",
        "best_tier",
        "labels",
        "sources",
    ):
        assert column in source, column


# --- the filters that must be parameters ---------------------------------------------------------


@pytest.mark.requires_db_extra
@pytest.mark.parametrize(
    ("call", "kwargs"),
    [
        (query.authoritative, {"captures": ["a" * 64]}),
        (query.flow_labels, {"run_ids": ["0123456789abcdef"]}),
        (query.runs, {"run_ids": ["0123456789abcdef"]}),
        (query.sightings, {"run_ids": ["0123456789abcdef"]}),
        (query.capture_shas, {"wanted": ["some-capture.pcap"]}),
    ],
)
def test_every_row_filter_is_bound_rather_than_interpolated(call, kwargs):
    """The row filters ARE parameterisable, so they are parameters. Only the two identifiers that
    cannot be bound are interpolated, and those are pattern-checked above."""
    bq = FakeBQ()
    values = next(iter(kwargs.values()))
    call(bq, "flabel", *kwargs.values())

    (sql,) = bq.statements
    (config,) = bq.configs
    assert "@" in sql, sql
    for value in values:
        assert value not in sql, f"{value!r} was interpolated into the statement"
    assert config is not None and config.query_parameters


@pytest.mark.requires_db_extra
def test_an_empty_run_id_set_asks_nothing_rather_than_asking_for_everything():
    """`IN UNNEST([])` matches nothing, but building the statement at all would be a query issued
    for a question with no subject — and one typo away from a projection over the whole table."""
    bq = FakeBQ()
    assert query.flow_labels(bq, "flabel", []) == []
    assert query.runs(bq, "flabel", []) == []
    assert query.sightings(bq, "flabel", []) == []
    assert query.capture_shas(bq, "flabel", []) == []
    assert bq.statements == []


@pytest.mark.requires_db_extra
def test_authoritative_reads_the_view_and_not_the_runs_table():
    """§4.6 is the only view, and it already anti-joins `run_exclusions`. Reading `runs` directly
    would be the supersession rule written a second time — §9's "must never implement the merge
    rule twice", one field over."""
    bq = FakeBQ()
    query.authoritative(bq, "flabel")
    (sql,) = bq.statements
    assert "authoritative_runs" in sql
    assert query.VIEW == "authoritative_runs"


def test_run_ids_of_is_distinct_and_sorted():
    rows = [
        {"capture_sha256": "a", "tier": 1, "run_id": "bbb"},
        {"capture_sha256": "a", "tier": 2, "run_id": "aaa"},
        {"capture_sha256": "b", "tier": 1, "run_id": "bbb"},
    ]
    assert query.run_ids_of(rows) == ["aaa", "bbb"]


def test_the_project_is_checked_too_and_not_only_the_dataset():
    """Two identifiers reach a table path; only one used to be guarded.

    `blfile` validates `--project`, but `client.client` falls back to `$GCP_PROJECT` when the flag
    is absent — and on `fl-replay` the id comes from `flabel.env`, never a flag, so the unchecked
    half was the one actually in use.
    """
    bq = FakeBQ()
    bq.project = "a-project`; DROP"
    with pytest.raises(ValueError, match="project"):
        query.table(bq, "flabel", "runs")

    bq.project = None
    with pytest.raises(ValueError, match="project"):
        query.table(bq, "flabel", "runs")


def test_a_trailing_newline_does_not_pass_the_identifier_check():
    """`IDENTIFIER` is anchored with `$`, which also matches BEFORE a trailing newline, so `.match`
    accepts `"flabel\\n"`. `fullmatch` is the correction `models` records for the same pair."""
    bq = FakeBQ()
    with pytest.raises(ValueError, match="dataset"):
        query.table(bq, "flabel\n", "runs")
