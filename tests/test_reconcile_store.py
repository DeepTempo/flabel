"""Reconciling the store against the archive — `tools/reconcile_store.py`, LS-8 (#152).

**The reconciliation IS the test**, which the plan says outright — so what these tests do is prove
it fails when it should. A reconciler that cannot report a disagreement is a green light wired to
nothing, and that is the defect class this project keeps finding.

The comparison is pure and takes its two sides as arguments, which is what makes all of it reachable
without a credential — the same split, for the same reason, as `triage.summarise` and
`collection.build`. Only the fetch and the one `COUNT(*)` query need BigQuery.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from reconcile_store import (  # noqa: E402
    COUNTS_FIELD,
    RUN_ID_COLUMN,
    Disagreement,
    RunExpectation,
    compare_run,
    expectation_of,
    format_report,
    main,
    orphans,
    reconcile,
    run_id_columns,
)

RUN = "0123456789abcdef"
OTHER = "fedcba9876543210"
CAPTURE = "a" * 64
URI = "gs://bucket/results/LABELED_capture_2026-07-08.tar.gz"


# --- fixtures ------------------------------------------------------------------------------------


def expectation(
    *,
    run_id: str = RUN,
    labels: int = 3,
    unmatched: int = 2,
    refused: int = 0,
    counts: dict | None = None,
) -> RunExpectation:
    """What one tarball says the store should hold. `counts` defaults to agreeing with the rows."""
    if counts is None:
        counts = {"labels": labels + refused, "unmatched": unmatched}
    return RunExpectation(
        run_id=run_id,
        archive_uri=URI,
        rows={"runs": 1, "captures": 1, "flow_labels": labels, "unmatched": unmatched},
        counts=counts,
        refused=refused,
    )


def held(*, runs: int = 1, captures: int = 1, flow_labels: int = 3, unmatched: int = 2) -> dict:
    """What the store actually holds, per table."""
    return {
        "runs": runs,
        "captures": captures,
        "flow_labels": flow_labels,
        "unmatched": unmatched,
    }


def kinds(found) -> list[str]:
    return sorted(item.kind for item in found)


# --- the column mapping, which is the one thing that could break everything quietly --------------


def test_captures_is_keyed_on_observed_by_run_id_and_not_run_id():
    """§4.2: a `captures` row is one SIGHTING of a capture by a run, not a fact about the run — so
    that table names the run differently, and counting on `run_id` there would return zero
    sightings for every run and report the whole archive as broken."""
    assert RUN_ID_COLUMN["captures"] == "observed_by_run_id"
    assert RUN_ID_COLUMN["flow_labels"] == "run_id"


def test_every_run_id_column_is_a_real_column_of_that_table():
    """Checked against `schema.TABLES` rather than trusted. A rename in the declaration would
    otherwise make this tool fail loudly for a reason that has nothing to do with the archive."""
    assert run_id_columns() == RUN_ID_COLUMN


def test_a_column_that_is_not_declared_is_refused(monkeypatch):
    import reconcile_store

    monkeypatch.setitem(reconcile_store.RUN_ID_COLUMN, "flow_labels", "run")
    with pytest.raises(ValueError, match="flow_labels.run is not a column"):
        run_id_columns()


def test_a_table_that_is_not_declared_is_refused(monkeypatch):
    import reconcile_store

    monkeypatch.setitem(reconcile_store.RUN_ID_COLUMN, "flow_label", "run_id")
    with pytest.raises(ValueError, match="not a declared table"):
        run_id_columns()


def test_every_table_a_run_writes_is_reconciled():
    """A table missing from `RUN_ID_COLUMN` is never counted and nothing says so — the same silent
    loss `ingest.LOAD_ORDER` is checked against the declaration for."""
    from flabeldb import ingest, schema

    assert set(RUN_ID_COLUMN) == set(ingest.LOAD_ORDER)
    assert set(RUN_ID_COLUMN) == set(schema.TABLES) - {"run_exclusions"}


# --- a run that agrees ---------------------------------------------------------------------------


def test_a_run_that_agrees_produces_nothing():
    assert compare_run(expectation(), held()) == []


def test_reconcile_over_an_agreeing_archive_agrees():
    result = reconcile([expectation()], {RUN: held()}, [RUN])
    assert result.agrees
    assert result.runs_checked == 1
    assert result.disagreements == ()


# --- leg 1: the store against the archive --------------------------------------------------------


def test_a_run_the_store_cannot_see_is_reported_once_and_not_four_times():
    """§5.3 makes the `runs` row the commit marker, so its absence IS the finding. Reporting the
    other three tables as well would bury the one line that explains them."""
    found = compare_run(expectation(), held(runs=0, captures=0, flow_labels=0, unmatched=0))
    assert kinds(found) == ["not-ingested"]
    assert found[0].table == "runs"
    assert "never ingested" in found[0].detail
    assert "flabel-ingest" in found[0].detail


def test_a_duplicate_runs_row_is_reported_because_every_read_joins_through_it():
    """§7.4's guard 4. A duplicate multiplies rather than merely repeating."""
    found = compare_run(expectation(), held(runs=2))
    assert "duplicate-run" in kinds(found)


@pytest.mark.parametrize("table", ["captures", "flow_labels", "unmatched"])
def test_a_row_count_disagreement_names_the_table_and_both_numbers(table):
    """The measured failure of §5.3: a visible run pointing at rows that are not there."""
    store = held()
    store[table] = store[table] - 1
    (found,) = [item for item in compare_run(expectation(), store) if item.kind == "row-count"]
    assert found.table == table
    assert found.expected == expectation().rows[table]
    assert found.actual == store[table]
    assert str(found.expected) in found.detail and str(found.actual) in found.detail


def test_a_runs_marker_over_an_empty_table_is_caught():
    """The exact state §5.3 measured against the live service and redesigned step 3 to prevent:
    cleared by step 2, skipped by step 3 as already done, then the commit marker landed on top of
    the emptiness. A reconciliation that missed this would miss the failure it exists for."""
    (found,) = [
        item
        for item in compare_run(expectation(labels=431), held(flow_labels=0))
        if item.kind == "row-count"
    ]
    assert found.table == "flow_labels"
    assert (found.expected, found.actual) == (431, 0)


# --- leg 2: the archive against its own self-report ----------------------------------------------


def test_a_corrupted_run_count_fails_the_reconciliation():
    """**The plan's named test**: "proven by a deliberately corrupted count failing it".

    This leg needs no store at all. `run.counts.labels` was written by `provenance.py` from
    `models.CorrelationResult`; the row count is what `flabeldb.parse` produces from `labels[]` now.

    **These are not two independent measurements of the capture**, and the docstring for this tool
    used to imply they were: `cli.py` builds `counts.labels` and `labels[]` from the same
    `correlation.labels` list in one process, so at labelling time they cannot disagree. What leg 2
    catches is a document that changed after it was published, and a reader that loses rows — see
    the test below for the second, which is the one leg 1 structurally cannot reach.
    """
    corrupted = expectation(labels=3, counts={"labels": 99, "unmatched": 2})
    (found,) = [item for item in compare_run(corrupted, held()) if item.kind == "self-report"]
    assert found.table == "flow_labels"
    assert found.expected == 99
    assert found.actual == 3
    assert "inconsistent with ITSELF" in found.detail


def test_a_reader_that_loses_rows_satisfies_leg_1_and_is_caught_by_leg_2():
    """**This is why both legs exist**, and it is the case neither one covers alone.

    Leg 1 compares the store against `flabeldb.parse`. If that parse silently drops a label, the
    rows it produced were the rows that got loaded — so the store and the parse agree exactly and
    leg 1 is satisfied. `run.counts.labels` is then the only number left in the file that still says
    what the run actually found, and leg 2 is the only thing reading it.

    Here: the run labelled 4 flows, the reader produced 3, and the store faithfully holds those 3.
    """
    lossy_read = expectation(labels=3, counts={"labels": 4, "unmatched": 2})
    found = compare_run(lossy_read, held(flow_labels=3))
    assert kinds(found) == ["self-report"], "leg 1 agreed, as it must, and leg 2 caught it"
    assert found[0].expected == 4 and found[0].actual == 3


def test_a_null_count_is_not_compared_against():
    """§10 is emphatic that a null count means NOT MEASURED — Suricata's four counts are null
    whenever that pass failed before establishing them. Comparing against one invents a number."""
    unmeasured = expectation(counts={"labels": None, "unmatched": None})
    assert compare_run(unmeasured, held()) == []


def test_a_refused_flow_is_added_back_rather_than_reported_as_a_shortfall():
    """`parse.rows` refuses a flow whose transport carries no derivable `ip_proto` (§3.2, #96), so
    the store legitimately holds fewer rows than the run labelled.

    **Nothing in BigQuery records that number** — it exists only in the archive — which is the
    second reason this tool re-parses instead of reasoning from the store.
    """
    with_refusals = expectation(labels=3, refused=2)
    assert with_refusals.counts["labels"] == 5
    assert compare_run(with_refusals, held(flow_labels=3)) == []


def test_a_refusal_does_not_excuse_a_missing_row():
    """**Leg 1 must never consult `refused` at all**, and the numbers here are chosen to prove it.

    `expectation.rows["flow_labels"]` is ALREADY the post-refusal count — the parse produced three
    rows having refused two more — so leg 1 compares three against the store and the refusals have
    no business in it. The shortfall below is exactly two, the same as `refused`, which is the one
    case a leg-1 adjustment would silently excuse. An earlier version of this test used a shortfall
    of one and could not tell the two behaviours apart.
    """
    short_by_exactly_the_refusals = compare_run(
        expectation(labels=3, refused=2), held(flow_labels=1)
    )
    (found,) = [item for item in short_by_exactly_the_refusals if item.kind == "row-count"]
    assert (found.expected, found.actual) == (3, 1)


def test_unmatched_detections_are_never_adjusted_by_refusals():
    """A refusal is about a FLOW's transport. An unmatched detection was never placed on a flow, so
    the refusal count has nothing to say about it — adding it there would hide a real shortfall."""
    found = compare_run(expectation(unmatched=2, refused=2), held(unmatched=2))
    assert found == []
    found = compare_run(expectation(unmatched=2, refused=2), held(unmatched=1))
    assert "row-count" in kinds(found)


def test_the_refusal_adjustment_rests_on_two_proto_sets_agreeing():
    """The claim that `refused` is normally zero — and so that leg 2 is normally exact — holds only
    because the protos a label can carry are exactly the protos the store can write.

    Those two sets are declared in two places and **nothing pinned them together** before this:
    `models.CORRELATABLE_PROTOCOLS` decides what `correlate` will attach a detection to, and
    `identity.WRITABLE_PROTOS` decides what `parse` will write a row for. If they ever diverge,
    `refused` becomes non-zero for ordinary traffic and this reconciliation reports a shortfall it
    cannot explain. Same shape as the `DEVICE_UNNAMED_THREAT` drift: one authority does not help if
    the other side is ignored.
    """
    from flabel.models import CORRELATABLE_PROTOCOLS
    from flabeldb.identity import WRITABLE_PROTOS

    assert set(WRITABLE_PROTOS) == set(CORRELATABLE_PROTOCOLS)


def test_only_the_two_row_bearing_tables_have_a_self_report_to_check():
    """`runs` and `captures` are one row each by construction, so there is no count to compare —
    and inventing one would be a check that can only ever pass."""
    assert set(COUNTS_FIELD) == {"flow_labels", "unmatched"}


# --- orphans, and what they say about #164 -------------------------------------------------------


def test_a_run_in_the_store_with_no_tarball_is_an_orphan():
    """§1: the store is a DERIVED index over the archive, so a run with no tarball behind it cannot
    be re-derived by anything."""
    (found,) = orphans([RUN, OTHER], [expectation(run_id=RUN)])
    assert found.kind == "orphan"
    assert found.run_id == OTHER
    assert "derived index" in found.detail


def test_an_orphan_beside_an_un_ingested_tarball_is_the_replaced_object_signature():
    """A narrowing of #164, not a closing of it.

    `identity.run_id` hashes four fields — `capture_sha256`, `mode`, `started_at`,
    `flabel_version` — **not the whole run block**, which is what this docstring claimed first. So
    this pair appears only when a replacement changes the capture digest, the mode or the start
    time; one that keeps all three keeps the id and is caught by leg 1 instead.
    """
    replaced = expectation(run_id="1111111111111111")
    result = reconcile([replaced], {OTHER: held()}, [OTHER])
    assert kinds(result.disagreements) == ["not-ingested", "orphan"]
    assert "#164" in next(i for i in result.disagreements if i.kind == "orphan").detail


def test_an_orphan_is_not_invented_for_a_run_the_archive_explains():
    assert orphans([RUN], [expectation(run_id=RUN)]) == []


# --- attestation is not a row count --------------------------------------------------------------


def test_skip_tier_cannot_cause_a_disagreement():
    """The plan says to run the backfill with `--skip-tier 2` until #142 is fixed.

    `--skip-tier` changes `runs.tiers_attested` and `attestation_notes` — it does not change how
    many rows any table holds — so a reconciliation that compared attestation would report the
    documented mechanism as a fault. Rows are what is compared, and this pins that.
    """
    # Asserted as a property of the comparison rather than by grepping COUNTS_FIELD's two values
    # for the word "tier", which held for essentially any plausible mapping and said nothing.
    #
    # `--skip-tier` rewrites `runs.tiers_attested` and `attestation_notes` before the load
    # (`ingest.apply_skip_tiers`). Neither is a row count and neither is in `run.counts`, so a run
    # whose tier-2 attestation was suppressed reconciles exactly as one that was not.
    assert set(COUNTS_FIELD.values()) <= {"labels", "unmatched"}
    assert compare_run(expectation(), held()) == []


# --- the report ----------------------------------------------------------------------------------


def test_the_report_names_the_run_the_uri_the_table_and_both_numbers():
    """A count with no detail is not a check anyone can act on."""
    result = reconcile([expectation(labels=3)], {RUN: held(flow_labels=1)}, [RUN])
    text = format_report(result, dataset="flabel", archive="gs://bucket/results")

    assert RUN in text
    assert URI in text
    assert "flow_labels" in text
    assert "expected 3" in text and "store has 1" in text
    assert "row-count" in text


def test_the_agreeing_report_says_so_rather_than_saying_nothing():
    text = format_report(
        reconcile([expectation()], {RUN: held()}, [RUN]),
        dataset="flabel",
        archive="gs://bucket/results",
    )
    assert "agrees with the archive on every run" in text
    assert "1 run(s)" in text


def test_the_report_counts_disagreements_and_the_runs_they_fall_on():
    result = reconcile(
        [expectation(run_id=RUN, labels=3), expectation(run_id=OTHER, labels=3)],
        {RUN: held(flow_labels=1), OTHER: held(flow_labels=2, unmatched=1)},
        [RUN, OTHER],
    )
    text = format_report(result, dataset="flabel", archive="gs://bucket/results")
    assert "3 disagreement(s) across 2 run(s)" in text


# --- expectation_of, over a real ParsedRun -------------------------------------------------------


def parsed_run(*, labels: int, unmatched: int, counts: dict, refused: int = 0):
    """A `parse.ParsedRun` built by hand, carrying the run block as the STRING §4.1 stores."""
    from flabeldb.parse import ParsedRun

    block = {"mode": "offline", "input": {"sha256": CAPTURE}, "counts": counts}
    return ParsedRun(
        run={"run_id": RUN, "capture_sha256": CAPTURE, "run_block": json.dumps(block)},
        capture={"capture_sha256": CAPTURE, "observed_by_run_id": RUN},
        flow_labels=[{"run_id": RUN} for _ in range(labels)],
        unmatched=[{"run_id": RUN} for _ in range(unmatched)],
        refused=refused,
        refusal_notes=tuple(f"refused {index}" for index in range(refused)),
    )


def test_expectation_of_counts_rows_through_ingests_own_row_selector():
    """`ingest.rows_for` is what the loader uses, so the reconciliation counts the same rows the
    ingest would have loaded rather than a second opinion about which they are."""
    found = expectation_of(
        parsed_run(labels=4, unmatched=7, counts={"labels": 4, "unmatched": 7}), URI
    )
    assert found.rows == {"runs": 1, "captures": 1, "flow_labels": 4, "unmatched": 7}
    assert found.run_id == RUN
    assert found.archive_uri == URI


def test_expectation_of_reads_counts_out_of_the_stored_run_block():
    """The same STRING the store holds (§4.1), not a second traversal of the document."""
    found = expectation_of(
        parsed_run(labels=4, unmatched=7, counts={"labels": 4, "unmatched": 7, "flows": 40}), URI
    )
    assert found.counts["labels"] == 4
    assert found.counts["flows"] == 40


def test_expectation_of_carries_the_refusals_and_their_reasons():
    found = expectation_of(
        parsed_run(labels=2, unmatched=0, counts={"labels": 3, "unmatched": 0}, refused=1), URI
    )
    assert found.refused == 1
    assert len(found.refusal_notes) == 1
    assert compare_run(found, held(flow_labels=2, unmatched=0)) == []


def test_a_run_block_with_no_counts_block_at_all_compares_nothing():
    """A run that failed part-way has every un-run stage's field null (§10), and `run.json` has no
    `labels` to carry. Nothing to compare is not a disagreement."""
    found = expectation_of(parsed_run(labels=0, unmatched=0, counts={}), URI)
    assert found.counts == {}
    assert compare_run(found, held(flow_labels=0, unmatched=0)) == []


# --- the command --------------------------------------------------------------------------------


def test_no_archive_prefix_is_a_usage_error_and_names_the_env_var(monkeypatch, capsys):
    monkeypatch.delenv("FLABEL_RESULTS_URI", raising=False)
    assert main([]) == 2
    message = capsys.readouterr().err
    assert "FLABEL_RESULTS_URI" in message
    assert "--archive" in message


def test_the_archive_is_never_defaulted_to_the_real_bucket():
    """`tools/flabel-run:281` hardcodes the results URI and that is one of #162's named sites.

    A second copy here would make `CLAUDE.md`'s "never commit internal identifiers" less true
    rather than more, and the whole compounding cost in #162 is that the next person writing a file
    has no way to tell whether the rule is real.
    """
    source = Path(__file__).resolve().parents[1] / "tools" / "reconcile_store.py"
    text = source.read_text(encoding="utf-8")
    assert "pm-proto" not in text
    assert "flabel-pcaps" not in text
    assert "default=None" in text


def test_a_non_gs_archive_is_refused_before_any_credential(monkeypatch, capsys):
    monkeypatch.setenv("FLABEL_RESULTS_URI", "/local/path")

    def refuse(**kwargs):
        raise AssertionError("a client was built for an archive that is not a gs:// URI")

    import reconcile_store

    monkeypatch.setattr(reconcile_store.client_module, "client", refuse)
    assert main([]) == 2
    assert "not a gs:// URI" in capsys.readouterr().err


def test_the_exit_code_says_whether_they_agree(monkeypatch, capsys):
    """Exit 1 means the two sides disagree — a real answer, kept apart from 2 and 3 for the reason
    `flabel-db` keeps drift apart from usage."""
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")
    monkeypatch.setattr(reconcile_store.client_module, "client", lambda **kwargs: object())

    for store, expected in (({RUN: held()}, 0), ({RUN: held(flow_labels=0)}, 1)):
        monkeypatch.setattr(
            reconcile_store, "archive_expectations", lambda **kwargs: ([expectation()], [])
        )
        monkeypatch.setattr(reconcile_store, "row_counts", lambda *a, _store=store, **k: _store)
        assert main([]) == expected
        capsys.readouterr()


def test_an_unrecognised_failure_exits_3_so_exit_1_can_only_mean_disagreement(monkeypatch, capsys):
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")
    monkeypatch.setattr(reconcile_store.client_module, "client", lambda **kwargs: object())

    def boom(**kwargs):
        raise KeyError("run_block")

    monkeypatch.setattr(reconcile_store, "archive_expectations", boom)
    assert main([]) == 3
    assert "DEFECT in reconcile_store" in capsys.readouterr().err


def test_a_missing_project_or_extra_reads_as_a_sentence(monkeypatch, capsys):
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")

    def unusable(**kwargs):
        raise RuntimeError("no project: pass --project or set GCP_PROJECT")

    monkeypatch.setattr(reconcile_store.client_module, "client", unusable)
    assert main([]) == 2
    assert "no project" in capsys.readouterr().err


def test_run_id_narrows_both_sides_so_one_run_can_be_investigated(monkeypatch, capsys):
    """`--run-id` is for chasing a single disagreement. It must narrow the STORE side too —
    otherwise every other run in the store becomes an orphan of a one-run archive."""
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")
    monkeypatch.setattr(reconcile_store.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        reconcile_store, "archive_expectations", lambda **kwargs: ([expectation()], [])
    )
    monkeypatch.setattr(reconcile_store, "row_counts", lambda *a, **k: {RUN: held(), OTHER: held()})
    assert main(["--run-id", RUN]) == 0
    assert "agrees" in capsys.readouterr().out


def test_a_disagreement_is_not_a_bare_boolean():
    """Every finding names its kind, its run, and a sentence saying what to do about it."""
    for item in reconcile([expectation(labels=3)], {RUN: held(flow_labels=0)}, [RUN]).disagreements:
        assert isinstance(item, Disagreement)
        assert item.kind and item.run_id and item.detail
        assert len(item.detail) > 40, item


# --- what the 2026-08-25 review found ------------------------------------------------------------


def test_leg_2_still_runs_on_a_run_the_store_has_never_seen():
    """**The review's first finding, and the one that mattered most.**

    `compare_run` used to `return` on a missing `runs` marker, which put leg 2 behind "the store has
    this run". Every tarball in the archive was un-ingested the first time the tool was run, so leg
    2 executed zero times out of twenty-five — and the report's `0 [self-report]` meant "never
    checked" while reading as "all twenty-five are consistent". Leg 2 needs no store at all.

    This is #171's shape: the one value that was wrong in production was the one never exercised.
    """
    corrupted_and_absent = expectation(labels=3, counts={"labels": 99, "unmatched": 2})
    found = compare_run(corrupted_and_absent, held(runs=0, captures=0, flow_labels=0, unmatched=0))
    assert kinds(found) == ["not-ingested", "self-report"]


def test_the_missing_marker_still_short_circuits_leg_1_only():
    """Leg 1 stays short-circuited: §5.3 makes the marker the commit, so with it absent every other
    table reads "0 rows" too and three more lines bury the one that explains them."""
    found = compare_run(expectation(), held(runs=0, captures=0, flow_labels=0, unmatched=0))
    assert kinds(found) == ["not-ingested"]
    assert not any(item.kind == "row-count" for item in found)


def test_an_unreadable_object_is_a_finding_about_the_archive_not_an_error():
    """`ingest.backfill_over`'s argument, which this tool got wrong first: one bad object must not
    discard the answers for every other run.

    `select_tarballs` matches anything ending `.tar.gz`, so a note or a hand-tarred file in the
    prefix was enough to produce no report at all — the whole reconciliation exiting 3 and blaming
    itself for a fact about the archive.
    """
    unreadable = Disagreement(
        kind="parse-failed",
        run_id="",
        archive_uri="gs://bucket/results/not-a-run.tar.gz",
        detail="this object is under the results prefix and could not be read as a published run",
    )
    result = reconcile([expectation()], {RUN: held()}, [RUN], unreadable=[unreadable])
    assert not result.agrees
    assert kinds(result.disagreements) == ["parse-failed"]
    assert result.runs_checked == 1, "the readable run was still checked"


def test_the_report_does_not_claim_the_store_said_a_number_it_never_said():
    """Leg 2's `actual` is the PARSE count; the store is not party to it.

    One report carrying both kinds otherwise printed two different claims about what the store
    holds, for one table: "expected 3, store has 0" beside "expected 99, store has 3".
    """
    corrupted = expectation(labels=3, counts={"labels": 99, "unmatched": 2})
    text = format_report(
        reconcile([corrupted], {RUN: held(flow_labels=0)}, [RUN]),
        dataset="flabel",
        archive="gs://bucket/results",
    )
    assert "run block says 99, the document parses to 3" in text
    assert "store has 3" not in text
    assert "expected 3, store has 0" in text


def test_run_id_column_is_ingests_map_and_not_a_second_copy():
    """`ingest.RUN_COLUMN`'s own comment records this map drifting being MEASURED on 2026-08-24 — a
    run exited 3 having loaded nothing. A second declaration of a fact that has already cost one
    run is the duplicate-authority defect, and asserting only the KEY set (which this file did at
    first) would not have caught a wrong column."""
    from flabeldb import ingest

    assert RUN_ID_COLUMN is ingest.RUN_COLUMN


def test_the_credential_classifier_is_a_public_name():
    """Reached from outside the package, and reached from inside an `except` block. A rename of a
    private name would leave the suite green and raise `AttributeError` from the one place an error
    must not be possible."""
    from flabeldb import ingest

    assert callable(ingest.is_credential_failure)
    assert not hasattr(ingest, "_is_credential_failure")


def test_a_run_id_that_matches_nothing_is_a_usage_error_not_agreement(monkeypatch, capsys):
    """A typo in the one argument an operator uses to chase a single disagreement used to report
    "the store agrees with the archive on every run" — after downloading the whole archive to
    compare nothing."""
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")
    monkeypatch.setattr(reconcile_store.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        reconcile_store, "archive_expectations", lambda **kwargs: ([expectation()], [])
    )
    monkeypatch.setattr(reconcile_store, "row_counts", lambda *a, **k: {RUN: held()})

    assert main(["--run-id", "deadbeefdeadbeef"]) == 2
    message = capsys.readouterr().err
    assert "matched nothing" in message
    assert "deadbeefdeadbeef" in message


def test_a_broken_pipe_is_not_a_disagreement(monkeypatch):
    """`reconcile_store.py | head`. The reader going away is not a fact about the store, and
    letting it escape exits 1 — the code reserved for the two sides disagreeing."""
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")
    monkeypatch.setattr(reconcile_store.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        reconcile_store, "archive_expectations", lambda **kwargs: ([expectation()], [])
    )
    monkeypatch.setattr(reconcile_store, "row_counts", lambda *a, **k: {RUN: held()})

    def burst(_text):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(reconcile_store.sys.stdout, "write", burst)
    # The handler redirects fd 1 to /dev/null — CPython's documented recipe, so the interpreter's
    # final flush cannot re-raise. Stubbed here because doing it for real closes the descriptor
    # pytest is capturing through and takes the whole session down with an OSError.
    redirected: list[int] = []
    monkeypatch.setattr(reconcile_store.os, "dup2", lambda src, dst: redirected.append(dst))
    expected_fd = reconcile_store.sys.stdout.fileno()
    assert main([]) == 0
    # `sys.stdout.fileno()`, not the literal 1 — under pytest that is the capture file, which is
    # exactly why the redirect has to ask rather than assume.
    assert redirected == [expected_fd], "the flush-at-exit guard must still be applied"


def test_a_credential_failure_from_the_client_is_the_environment_not_a_disagreement(
    monkeypatch, capsys
):
    """`--local-adc` with no ADC raises `DefaultCredentialsError`, which derives from
    `GoogleAuthError` and **not** from `RuntimeError` — so the narrower `except RuntimeError` let it
    escape `main` and reach the interpreter as exit 1."""
    import reconcile_store

    class DefaultCredentialsErrorish(Exception):
        pass

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")

    def unusable(**kwargs):
        raise DefaultCredentialsErrorish("could not automatically determine credentials")

    monkeypatch.setattr(reconcile_store.client_module, "client", unusable)
    assert main([]) == 2
    assert "cannot build a client" in capsys.readouterr().err


def test_the_pure_half_cannot_reach_the_interpreter_as_exit_1(monkeypatch, capsys):
    """`reconcile` and `format_report` sat outside every handler, so any failure in them exited 1 —
    the code this tool publishes as "the store and the archive disagree"."""
    import reconcile_store

    monkeypatch.setenv("FLABEL_RESULTS_URI", "gs://bucket/results")
    monkeypatch.setattr(reconcile_store.client_module, "client", lambda **kwargs: object())
    monkeypatch.setattr(
        reconcile_store, "archive_expectations", lambda **kwargs: ([expectation()], [])
    )
    monkeypatch.setattr(reconcile_store, "row_counts", lambda *a, **k: {RUN: held()})

    def boom(*args, **kwargs):
        raise TypeError("unorderable types")

    monkeypatch.setattr(reconcile_store, "format_report", boom)
    assert main([]) == 3
    assert "DEFECT in reconcile_store" in capsys.readouterr().err


def test_a_same_run_id_replacement_is_caught_by_leg_1_rather_than_as_an_orphan():
    """The half of #164 the first version of this tool did not claim, and the stronger half.

    `identity.run_id` depends on the capture digest, the mode and `started_at` — so a replacement
    that keeps those three keeps the id, and no orphan appears. Leg 1 then compares the store's rows
    for the OLD run against a fresh parse of the NEW tarball, so any change in cardinality fires.
    """
    from flabeldb.identity import run_id

    before = run_id(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso="2026-07-08T12:00:00Z",
        flabel_version="0.0.0",
    )
    # A replacement that rewrites counts, ruleset and warnings but not those three fields.
    after = run_id(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso="2026-07-08T12:00:00Z",
        flabel_version="0.0.0",
    )
    assert before == after, "run_id does not cover the whole run block"

    replaced = expectation(run_id=before, labels=9, counts={"labels": 9, "unmatched": 2})
    result = reconcile([replaced], {before: held(flow_labels=3)}, [before])
    assert kinds(result.disagreements) == ["row-count"]
    assert not any(item.kind == "orphan" for item in result.disagreements)
