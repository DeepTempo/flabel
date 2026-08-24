"""`flabel-ingest` — spec-label-store §5.3, §7.4, and the ordering that makes a crash survivable.

**The parts that matter are pure and run in CI.** §2.4's testing line says the `requires_bigquery`
tests run nowhere else, and §5.3 is where LS-4's two measured surprises live — so the attempt walk
and the load ordering are written as logic over a `probe` callable rather than as something only a
live dataset can exercise. `test_flabeldb_live.py` then drives the same code against BigQuery.
"""

from __future__ import annotations

import re

import pytest

from flabeldb import ingest

RUN_ID = "0123456789abcdef"


# --- the ordering that makes a half-ingest invisible rather than wrong --------------------------


def test_runs_lands_last_because_every_read_joins_through_it():
    """§5.3. `runs` is THE COMMIT MARKER: a crash mid-ingest must leave rows nothing can reach,
    not a run that looks present and is missing its flows."""
    assert ingest.LOAD_ORDER[-1] == "runs"


def test_every_table_that_ingest_writes_is_in_the_order_exactly_once():
    """A table missing from the order is never loaded; one listed twice loads twice. Both are
    silent, so the order is checked against the declaration rather than eyeballed."""
    from flabeldb import schema

    written = set(schema.TABLES) - {"run_exclusions"}
    assert set(ingest.LOAD_ORDER) == written
    assert len(ingest.LOAD_ORDER) == len(set(ingest.LOAD_ORDER))


def test_run_exclusions_is_never_written_by_ingest():
    """§4.5: retraction is an operator's record, not something an ingest may manufacture."""
    assert "run_exclusions" not in ingest.LOAD_ORDER


# --- job ids ------------------------------------------------------------------------------------


def test_a_job_id_is_attempt_numbered():
    """§5.3: `ingest-<run_id>-<table>-<attempt>`. The attempt number is the whole point — without
    it one transient failure burns the id permanently (§10 M1)."""
    assert ingest.job_id(RUN_ID, "runs", 1) == f"ingest-{RUN_ID}-runs-1"
    assert ingest.job_id(RUN_ID, "flow_labels", 4) == f"ingest-{RUN_ID}-flow_labels-4"


def test_job_ids_differ_across_tables_and_attempts():
    seen = {
        ingest.job_id(RUN_ID, table, attempt)
        for table in ingest.LOAD_ORDER
        for attempt in (1, 2, 3)
    }
    assert len(seen) == len(ingest.LOAD_ORDER) * 3


def test_a_job_id_is_a_legal_bigquery_job_id():
    """Letters, numbers, underscores and dashes, up to 1024. A run_id is 16 hex characters and a
    table name is snake_case, so this holds — pinned because a violation surfaces as a 400 from
    the load rather than as anything about ingest."""
    for table in ingest.LOAD_ORDER:
        found = ingest.job_id(RUN_ID, table, 12)
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,1024}", found), found


# --- the attempt walk: §5.3's recovery, and §10 M1's burnt id -----------------------------------


def probe_from(states: dict[str, str]):
    """A stand-in for asking BigQuery about a job id. Missing keys read as `missing`."""
    return lambda job: states.get(job, ingest.MISSING)


def test_a_fresh_run_uses_attempt_one():
    assert ingest.next_attempt(probe_from({}), RUN_ID, "runs") == 1


def test_a_table_whose_job_already_SUCCEEDED_is_not_reloaded():
    """The half-loaded case. Re-running must not double the rows of a table that finished."""
    states = {ingest.job_id(RUN_ID, "flow_labels", 1): ingest.SUCCEEDED}
    assert ingest.next_attempt(probe_from(states), RUN_ID, "flow_labels") is None


def test_a_FAILED_attempt_is_walked_past_rather_than_retried_under_its_own_id():
    """**§10 M1, measured:** a load job that FAILS still consumes its job id permanently. A job id
    derived only from `(run_id, table)` is therefore burnt by the first transient failure and the
    run can never be ingested again — which is what made revision 1's "just re-run it" false."""
    states = {ingest.job_id(RUN_ID, "runs", 1): ingest.FAILED}
    assert ingest.next_attempt(probe_from(states), RUN_ID, "runs") == 2


def test_several_consecutive_failures_are_walked_past():
    states = {ingest.job_id(RUN_ID, "runs", n): ingest.FAILED for n in (1, 2, 3)}
    assert ingest.next_attempt(probe_from(states), RUN_ID, "runs") == 4


def test_a_success_after_failures_still_means_done():
    """The realistic recovery shape: attempt 1 failed, attempt 2 landed. Nothing more to do."""
    states = {
        ingest.job_id(RUN_ID, "runs", 1): ingest.FAILED,
        ingest.job_id(RUN_ID, "runs", 2): ingest.SUCCEEDED,
    }
    assert ingest.next_attempt(probe_from(states), RUN_ID, "runs") is None


def test_the_walk_is_bounded_so_a_probe_that_always_fails_cannot_spin():
    """An unbounded walk against a permanently broken table is an infinite loop against a billed
    API. It raises instead, naming the run and the table.

    The probe COUNTS, and gives up well past the bound rather than answering forever. That is
    deliberate: the first version of this test just returned `FAILED` every time, so replacing the
    bound with `while True` did not fail it — **it hung**, and took the whole suite with it. A hang
    is a red build eventually, but it is a two-minute timeout instead of a one-line assertion, and
    it says nothing about which guard broke.
    """
    calls = 0

    def always_failed(_job: str) -> str:
        nonlocal calls
        calls += 1
        assert calls <= ingest.MAX_ATTEMPTS + 5, "the walk is unbounded; it never stopped asking"
        return ingest.FAILED

    with pytest.raises(RuntimeError, match="attempt"):
        ingest.next_attempt(always_failed, RUN_ID, "runs")
    assert calls == ingest.MAX_ATTEMPTS, f"{calls} probes for a bound of {ingest.MAX_ATTEMPTS}"


def test_the_walk_asks_about_each_attempt_in_order_and_stops():
    """It must not probe attempt 7 before attempt 2 — each probe is an API call."""
    asked: list[str] = []

    def probe(job: str) -> str:
        asked.append(job)
        return ingest.FAILED if job.endswith(("-1", "-2")) else ingest.MISSING

    assert ingest.next_attempt(probe, RUN_ID, "runs") == 3
    assert asked == [ingest.job_id(RUN_ID, "runs", n) for n in (1, 2, 3)]


# --- --skip-tier: load, but never attest --------------------------------------------------------


def test_skip_tier_removes_the_tier_from_attested_and_says_so():
    """§6.3 / #142: "load but never attest tier n". The rows still land — that is the difference
    between "we have no record" and "we have a record we will not treat as current" (§2.4)."""
    attested, notes = ingest.apply_skip_tiers((1, 2), ("existing note",), skip=(2,))

    assert attested == (1,)
    assert "existing note" in notes
    assert any("2" in note and "skip" in note.lower() for note in notes), notes


def test_skipping_a_tier_that_was_not_attested_anyway_changes_nothing_and_adds_no_note():
    """A note about a tier that was already refused would be a second explanation for one fact."""
    attested, notes = ingest.apply_skip_tiers((1,), (), skip=(2,))
    assert attested == (1,)
    assert notes == ()


def test_skipping_nothing_is_the_identity():
    assert ingest.apply_skip_tiers((1, 2), ("n",), skip=()) == ((1, 2), ("n",))


def test_skip_tier_can_empty_the_attested_set():
    """Which is legal and meaningful: every row loads, nothing supersedes."""
    attested, notes = ingest.apply_skip_tiers((1, 2), (), skip=(1, 2))
    assert attested == ()
    assert len(notes) == 2


# --- the gs:// contract -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "uri, bucket, name",
    [
        ("gs://b/results/LABELED_x.tar.gz", "b", "results/LABELED_x.tar.gz"),
        ("gs://b/o.tar.gz", "b", "o.tar.gz"),
        ("gs://b-u.c_k-et/a/b/c.tar.gz", "b-u.c_k-et", "a/b/c.tar.gz"),
    ],
)
def test_a_gs_uri_splits_into_bucket_and_object(uri, bucket, name):
    assert ingest.split_gs_uri(uri) == (bucket, name)


@pytest.mark.parametrize(
    "uri",
    [
        "s3://b/o",
        "/local/path.tar.gz",
        "gs://",
        "gs://bucket",
        # **Found by sabotage.** Loosening the object pattern from `.+` to `.*` left every other
        # case red and this one absent, so the guard could have been widened silently. A bucket
        # with a trailing slash names no object; fetching it would 404 three frames down instead
        # of costing nothing and saying so.
        "gs://bucket/",
        "b/o",
        "",
    ],
)
def test_anything_that_is_not_a_gs_object_is_refused_before_any_network_call(uri):
    """§6.1 gave `--source-uri` the same treatment: validated, not merely recorded."""
    with pytest.raises(ValueError, match="gs://"):
        ingest.split_gs_uri(uri)
