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


# --- what BigQuery's job state actually means (§10 M1) ------------------------------------------


class Job:
    """The two attributes `classify_job` reads, in the shapes the client returns them."""

    def __init__(self, state="DONE", error_result=None):
        self.state = state
        self.error_result = error_result


def test_a_finished_job_with_no_error_succeeded():
    assert ingest.classify_job(Job(state="DONE")) == ingest.SUCCEEDED


def test_a_finished_job_WITH_an_error_result_failed_even_though_its_state_is_DONE():
    """**§10 M1, measured, and the trap.** A bad-row load left `state: DONE`, `errorResult:
    invalid`, `outputRows: None` — so reading `state` alone calls a failed load a success, skips
    the retry, and lands a `runs` row for a table that has no rows."""
    job = Job(state="DONE", error_result={"reason": "invalid", "message": "bad row"})
    assert ingest.classify_job(job) == ingest.FAILED


def test_an_absent_job_is_missing():
    assert ingest.classify_job(None) == ingest.MISSING


@pytest.mark.parametrize("state", ["RUNNING", "PENDING"])
def test_a_job_still_IN_FLIGHT_is_neither_and_raises(state):
    """Calling it FAILED would walk past a load that is about to land and duplicate its rows;
    calling it SUCCEEDED would skip a table that has none yet. §3.3 assumes one runner, so this
    means a previous invocation is still going — which is an operator's problem, named."""
    with pytest.raises(RuntimeError, match="still running"):
        ingest.classify_job(Job(state=state))


# --- extracting the published tarball ------------------------------------------------------------


def _tarball(tmp_path, name="LABELED_x_20260824T000000Z", extra=None):
    """A tarball shaped exactly as `tools/flabel-run` builds one: `tar -czf - -C <dir> <name>`,
    so it unpacks to a single directory of that name."""
    import tarfile

    root = tmp_path / "src" / name
    (root / "zeek").mkdir(parents=True)
    (root / "labels.json").write_text('{"run": {}, "labels": [], "unmatched_detections": []}')
    (root / "NOTICE").write_text("notice")
    for path, body in (extra or {}).items():
        target = tmp_path / "src" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    archive = tmp_path / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=name)
    return archive


def test_a_published_tarball_unpacks_to_its_single_run_directory(tmp_path):
    archive = _tarball(tmp_path)
    found = ingest.extract(archive, tmp_path / "out")

    assert found.name == "LABELED_x_20260824T000000Z"
    assert (found / "labels.json").is_file()


def test_an_archive_with_no_run_directory_is_refused(tmp_path):
    """`flabel-run` builds `-C <dir> <name>`, so exactly one top-level directory. Anything else is
    not one of ours and guessing which directory to read would be a guess about provenance."""
    import tarfile

    archive = tmp_path / "flat.tar.gz"
    loose = tmp_path / "labels.json"
    loose.write_text("{}")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(loose, arcname="labels.json")

    with pytest.raises(ValueError, match="one directory"):
        ingest.extract(archive, tmp_path / "out")


def test_a_member_escaping_the_destination_is_refused(tmp_path):
    """Path traversal in a tar member. The archive comes from our own bucket, but "we wrote it"
    is exactly the assumption that makes this the classic unreviewed extract — and the bucket is
    writable by two project Owners (#164), which is the whole point of that issue."""
    import io
    import tarfile

    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("../escaped.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"boom"))

    with pytest.raises(ValueError, match="outside"):
        ingest.extract(archive, tmp_path / "out")


def test_an_absolute_member_path_is_refused(tmp_path):
    import io
    import tarfile

    archive = tmp_path / "abs.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("/etc/passwd")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"boom"))

    with pytest.raises(ValueError, match="outside"):
        ingest.extract(archive, tmp_path / "out")


def test_a_symlink_member_is_refused(tmp_path):
    """A symlink pointing out of the tree turns a later write into a write anywhere. Refused
    rather than filtered: nothing `flabel-run` produces contains one."""
    import tarfile

    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("run/evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)

    with pytest.raises(ValueError, match="symlink|link"):
        ingest.extract(archive, tmp_path / "out")


def test_an_archive_of_an_EMPTY_directory_is_refused(tmp_path):
    """**Found by sabotage**, and the only case the `nested` check catches on its own.

    Removing that check left every other extraction test green, because a flat archive of one FILE
    is still caught downstream by the `is_dir` fallback — with a message close enough that the
    assertion matched. An archive holding one empty DIRECTORY passes both: it is a single top-level
    name, and it is a directory. Without `nested` it extracts happily and hands back a run
    directory with nothing in it, so the failure surfaces later as a missing `labels.json` and
    blames the run rather than the archive.
    """
    import tarfile

    empty = tmp_path / "src" / "LABELED_empty_20260824T000000Z"
    empty.mkdir(parents=True)
    archive = tmp_path / "empty.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(empty, arcname=empty.name)

    with pytest.raises(ValueError, match="one directory"):
        ingest.extract(archive, tmp_path / "out")


# --- the CLI surface, per §6.3 -------------------------------------------------------------------


def test_the_parser_matches_the_documented_contract():
    """§6.3: `flabel-ingest <gs://…tar.gz>`, `--backfill`, `--skip-tier n`, `--local-adc`."""
    args = ingest.build_parser().parse_args(["gs://b/o.tar.gz"])
    assert args.uri == "gs://b/o.tar.gz"
    assert args.backfill is False
    assert args.skip_tier == []
    assert args.local_adc is False


def test_skip_tier_is_repeatable_and_integer():
    args = ingest.build_parser().parse_args(
        ["gs://b/o.tar.gz", "--skip-tier", "1", "--skip-tier", "2"]
    )
    assert args.skip_tier == [1, 2]


def test_skip_tier_refuses_a_tier_that_does_not_exist():
    """`models.KNOWN_TIERS` is the one authority. A typo'd `--skip-tier 3` that silently did
    nothing would leave the operator believing a tier was suppressed when it was not."""
    with pytest.raises(SystemExit) as raised:
        ingest.build_parser().parse_args(["gs://b/o.tar.gz", "--skip-tier", "3"])
    assert raised.value.code == 2


def test_a_uri_that_is_not_gs_exits_usage_before_any_client_is_built(monkeypatch, capsys):
    """Validated, not merely recorded — the treatment §6.1 gave `--source-uri`."""
    from flabeldb import client

    def fail(*_a, **_k):
        raise AssertionError("a client was built for an invalid URI")

    monkeypatch.setattr(client, "client", fail)
    assert ingest.main(["/local/run"]) == ingest.EXIT_USAGE
    assert "gs://" in capsys.readouterr().err


def test_the_exit_codes_are_distinct_and_1_can_only_mean_one_thing():
    """Same discipline as `flabel-db` (#157's finding): an unrecognised failure must never share a
    code with a real outcome, or a batch caller cannot tell them apart."""
    codes = {ingest.EXIT_OK, ingest.EXIT_FAILED, ingest.EXIT_USAGE, ingest.EXIT_INTERNAL}
    assert len(codes) == 4
    assert ingest.EXIT_OK == 0


# --- which column identifies a run, per table ----------------------------------------------------


def test_every_table_ingest_writes_declares_the_column_clear_orphans_filters_on():
    """**Found by running it against a real tarball**, which is the only way it could be found.

    `clear_orphans` deleted `WHERE run_id = @run_id` from every table in `LOAD_ORDER`, and
    `captures` HAS NO `run_id` COLUMN — a capture row is a SIGHTING (§4.2), so its reference is
    `observed_by_run_id`. BigQuery answered `400 Unrecognized name: run_id`, and the whole ingest
    exited 3 before loading anything.

    Nothing pure could have caught it: the column list is in `schema.py`, the SQL is in
    `ingest.py`, and neither module reads the other. So the two are joined here — every column
    `clear_orphans` filters on must be declared by the table it filters.
    """
    from flabeldb import schema

    for table in ingest.LOAD_ORDER:
        column = ingest.RUN_COLUMN[table]
        declared = {field.name for field in schema.TABLES[table].fields}
        assert column in declared, (
            f"clear_orphans would filter {table} on {column!r}, which it does not declare. "
            f"BigQuery answers 400 Unrecognized name and the run does not ingest."
        )


def test_the_run_column_map_covers_exactly_the_tables_that_are_loaded():
    """A table in `LOAD_ORDER` with no entry is a KeyError mid-ingest, after some tables have
    already loaded — the worst moment for it. One with a spare entry is dead weight that reads
    like a table we write and do not."""
    assert set(ingest.RUN_COLUMN) == set(ingest.LOAD_ORDER)


def test_captures_is_the_one_that_differs_and_that_is_why_the_map_exists():
    assert ingest.RUN_COLUMN["captures"] == "observed_by_run_id"
    assert ingest.RUN_COLUMN["runs"] == "run_id"


# --- the walk that `load_run` actually uses ------------------------------------------------------
#
# **Found by driving the recovery path against the real service.** §5.3's step 3 says a job that
# "exists and succeeded means this table is done" — and its step 2 has just DELETED that table's
# rows, unconditionally, because a new run and a half-loaded run are indistinguishable. After the
# delete, "done" is false. Measured: `flow_labels` ended a recovery with ZERO rows — cleared by
# step 2, skipped by step 3 — and the `runs` commit marker landed on top of the emptiness.


def test_after_a_clear_a_SUCCEEDED_id_is_used_not_done():
    """The distinction the live failure turned up. `next_attempt` answers §5.3 literally;
    `first_unused_attempt` answers the question that matters once the rows have been cleared."""
    states = {ingest.job_id(RUN_ID, "flow_labels", 1): ingest.SUCCEEDED}

    assert ingest.next_attempt(probe_from(states), RUN_ID, "flow_labels") is None
    assert ingest.first_unused_attempt(probe_from(states), RUN_ID, "flow_labels") == 2


def test_the_unused_walk_steps_past_both_kinds_of_used_id():
    states = {
        ingest.job_id(RUN_ID, "runs", 1): ingest.SUCCEEDED,
        ingest.job_id(RUN_ID, "runs", 2): ingest.FAILED,
        ingest.job_id(RUN_ID, "runs", 3): ingest.SUCCEEDED,
    }
    assert ingest.first_unused_attempt(probe_from(states), RUN_ID, "runs") == 4


def test_a_fresh_run_still_uses_attempt_one():
    assert ingest.first_unused_attempt(probe_from({}), RUN_ID, "runs") == 1


def test_the_unused_walk_is_bounded_too():
    calls = 0

    def all_used(_job: str) -> str:
        nonlocal calls
        calls += 1
        assert calls <= ingest.MAX_ATTEMPTS + 5, "the walk is unbounded"
        return ingest.SUCCEEDED

    with pytest.raises(RuntimeError, match="attempt ids are used"):
        ingest.first_unused_attempt(all_used, RUN_ID, "runs")


# --- --backfill: the flag, not the operation -----------------------------------------------------
#
# LS-4 supplies the mechanism; **LS-8 is the whole-archive run** plus `tools/reconcile_store.py`,
# and it depends on LS-5 and LS-7. So this loops and reports, and reconciles nothing.


def test_only_tarballs_are_selected_and_the_order_is_deterministic():
    """A prefix holds whatever anyone put there. Ordering matters because a partial backfill that
    is resumed should cover the same ground in the same sequence."""
    names = [
        "results/b.tar.gz",
        "results/notes.txt",
        "results/a.tar.gz",
        "results/",
        "results/c.tgz",
    ]
    found = ingest.select_tarballs("gs://bucket", names)

    assert found == ["gs://bucket/results/a.tar.gz", "gs://bucket/results/b.tar.gz"]


def test_a_prefix_with_no_tarballs_is_an_empty_list_and_not_an_error():
    """An archive nobody has published to yet is a real state, not a failure."""
    assert ingest.select_tarballs("gs://bucket", ["results/", "results/README"]) == []


def test_backfill_ingests_each_uri_in_turn():
    seen = []

    def fake(uri):
        seen.append(uri)
        return {"run_id": uri[-8:], "status": "ingested"}

    summary = ingest.backfill_over(["gs://b/1.tar.gz", "gs://b/2.tar.gz"], fake)

    assert seen == ["gs://b/1.tar.gz", "gs://b/2.tar.gz"]
    assert summary["ingested"] == 2
    assert summary["already_present"] == 0
    assert summary["failed"] == []


def test_a_run_already_present_is_counted_separately_from_one_ingested():
    """The two are different facts about a backfill, and collapsing them would make a second full
    pass look like it did the same work as the first."""

    def fake(uri):
        return {"run_id": "x", "status": "already-present" if "1" in uri else "ingested"}

    summary = ingest.backfill_over(["gs://b/1.tar.gz", "gs://b/2.tar.gz"], fake)

    assert summary["ingested"] == 1
    assert summary["already_present"] == 1


def test_one_failing_tarball_does_not_stop_the_rest():
    """**The property that makes a backfill worth running unattended.** Stopping on the first bad
    archive would mean one corrupt object holds up every run published after it — and #164 says a
    replaced tarball is possible, so a bad one is not hypothetical."""

    def fake(uri):
        if "2" in uri:
            raise ValueError("not one of ours")
        return {"run_id": "x", "status": "ingested"}

    summary = ingest.backfill_over(["gs://b/1.tar.gz", "gs://b/2.tar.gz", "gs://b/3.tar.gz"], fake)

    assert summary["ingested"] == 2
    assert [uri for uri, _ in summary["failed"]] == ["gs://b/2.tar.gz"]
    assert "not one of ours" in summary["failed"][0][1]


def test_a_backfill_that_failed_on_everything_still_reports_rather_than_raising():
    """The caller needs the list. Raising the first error would discard the other ninety-nine."""

    def fake(_uri):
        raise ValueError("boom")

    summary = ingest.backfill_over(["gs://b/1.tar.gz", "gs://b/2.tar.gz"], fake)
    assert summary["ingested"] == 0
    assert len(summary["failed"]) == 2


def test_a_second_full_backfill_ingests_nothing():
    """LS-8's stated acceptance test, in miniature — the property, here, rather than the
    whole-archive run. The already-committed guard (§7.4) is what supplies it."""

    def fake(_uri):
        return {"run_id": "x", "status": "already-present"}

    summary = ingest.backfill_over(["gs://b/1.tar.gz"] * 5, fake)
    assert summary["ingested"] == 0
    assert summary["already_present"] == 5
