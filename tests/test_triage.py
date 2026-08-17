"""The triage summariser must not flatter a run (tools/triage.py, issue #113).

This is an exploration tool, not a gate, so it has no pass/fail to prove. What it *can* get
wrong is worse for being quiet: counting a failed run's absent labels as a clean zero, averaging
a partial ruleset into the totals, or reporting one snapshot's numbers beside another's. Each of
those makes the summary read better than the runs justify, which is the defect class this whole
project keeps finding.

So the tests here are mostly about the runs it must refuse to flatter. `summarise` and
`format_report` are pure and take their inputs as arguments, which is what makes that reachable
without a toolchain — the same split, for the same reason, as `corpus_gate.verify`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from triage import (  # noqa: E402
    UBIQUITOUS,
    format_report,
    prevalence,
    read_run,
    summarise,
)

SNAPSHOT = "40cac3960114e1b4"


def entry(
    source="pawpatrules", sid=3300982, basis="indicator-reference", classtype="misc-activity"
):
    return {
        "source": source,
        "sid": sid,
        "rev": 1,
        "label_basis": basis,
        "classtype": classtype,
        "threat": "a rule",
        "tier": 2,
        "ruleset": SNAPSHOT,
        "admission_basis": "wholesale",
        "licence": "CC-BY-SA-4.0",
    }


def write_run(
    root: Path,
    name: str,
    *entries: dict,
    labels_file: bool = True,
    flows: int = 100,
    loaded: int = 85302,
    admitted: int = 85302,
    status: str = "complete",
    unmatched: int = 0,
    snapshot: str = SNAPSHOT,
    warnings: tuple[str, ...] = (),
    discarded: int = 0,
) -> Path:
    """A run directory close enough to a real one to exercise every rule."""
    rundir = root / name
    rundir.mkdir(parents=True)
    document = {
        "schema_version": "1.0",
        "run": {
            "counts": {
                "flows": flows,
                "detections": len(entries),
                "labels": len(entries),
                "unmatched": unmatched,
                "unmatched_ratio": 0.0 if not unmatched else 0.5,
                "rules_loaded": loaded,
            },
            "ruleset": {"snapshot_id": snapshot, "total_admitted": admitted},
            "input": {"input_status": status, "discarded_packets": discarded},
            "unmatched_threshold": 0.01,
            "warnings": list(warnings),
        },
        "labels": [{"flow": {"uid": f"C{i}"}, "sources": [e]} for i, e in enumerate(entries)],
    }
    if not labels_file:
        document.pop("labels")
        (rundir / "run.json").write_text(json.dumps(document), encoding="utf-8")
        return rundir
    (rundir / "labels.json").write_text(json.dumps(document), encoding="utf-8")
    (rundir / "run.json").write_text(json.dumps({**document, "labels": None}), encoding="utf-8")
    return rundir


# --- the runs it must refuse to flatter ---------------------------------------------------------


def test_a_failed_run_is_not_counted_as_zero_labels(tmp_path):
    """Issue #23 one level up: absence of labels.json means the run DIED.

    Counting it as a clean zero is the single most damaging thing this tool could do, because a
    capture that produced nothing and a capture that never ran look identical in a summary table
    and only one of them is evidence.
    """
    run = read_run(write_run(tmp_path, "dead", labels_file=False))

    assert run.failed
    assert run.labels is None, "a dead run must not report 0 labels"
    assert any("FAILED" in c for c in run.concerns)


def test_a_partial_ruleset_is_reported_not_averaged_in(tmp_path):
    """40 of 85,302 rules loaded is not a quiet capture — it is an unrun one (cf. #101)."""
    run = read_run(write_run(tmp_path, "partial", loaded=40, admitted=85302))

    assert any("partial ruleset" in c for c in run.concerns)


def test_a_truncated_capture_is_reported(tmp_path):
    run = read_run(write_run(tmp_path, "trunc", status="partial"))

    assert any("less than the whole capture" in c for c in run.concerns)


def test_unplaced_detections_are_reported_with_the_bar_they_were_measured_against(tmp_path):
    """The threshold is in the run block since #68, so the concern can name it."""
    run = read_run(write_run(tmp_path, "unmatched", entry(), unmatched=3))

    concern = next(c for c in run.concerns if "no flow" in c)
    assert "threshold 0.01" in concern


def test_discarded_packets_are_reported(tmp_path):
    run = read_run(write_run(tmp_path, "sll", discarded=4))

    assert any("foreign link type" in c for c in run.concerns)


def test_a_directory_with_neither_file_does_not_raise(tmp_path):
    """A run killed between mkdir and the first write. Triage must survive it and say so."""
    (tmp_path / "killed").mkdir()

    run = read_run(tmp_path / "killed")

    assert run.failed
    assert any("killed" in c for c in run.concerns)


def test_a_clean_run_has_no_concerns(tmp_path):
    """The complement: a tool that flags everything is a tool nobody reads."""
    assert read_run(write_run(tmp_path, "clean", entry())).concerns == ()


# --- the prevalence heuristic, which is the point -----------------------------------------------
#
# Tested as a function rather than by parsing the text table. The first version of these tests
# did parse it and matched the wrong rows twice — `" 7 "` found the capture named `dead7` — which
# is a good argument for the judgement living somewhere a test can call directly.


@pytest.mark.parametrize(
    ("seen", "captures", "expected"),
    [
        (6, 6, "EVERY"),  # #113's scanner rules: every internet-facing capture there is
        (4, 6, "EVERY"),  # two thirds exactly — the boundary, and it counts as ubiquitous
        (3, 6, ""),  # half is neither, and claiming either would be a guess
        (2, 6, ""),
        (1, 6, "one"),  # where a real finding usually is — #113's Realtek attempt
        (1, 1, "one"),  # one of one is `one`, not `EVERY`: a single capture proves no pattern
        (0, 6, ""),
        (5, 0, ""),  # no sound runs to be a share of
    ],
)
def test_prevalence_says_only_what_was_measured(seen, captures, expected):
    assert prevalence(seen, captures) == expected


def test_the_ubiquity_threshold_is_a_share_not_a_count():
    """A constant meaning 'seen 4 times' would mean different things at 5 captures and 500."""
    assert 0 < UBIQUITOUS < 1


def test_prevalence_counts_captures_not_entries(tmp_path):
    """A rule firing 500 times in ONE capture is not ubiquitous, and the distinction is the tool.

    Counting entries would call a single chatty capture a fleet-wide pattern — the exact wrong
    answer, because a rule firing 500 times on one host is the most interesting thing in a
    directory, not the least.
    """
    write_run(tmp_path, "chatty", *[entry(sid=42) for _ in range(500)])
    for i in range(5):
        write_run(tmp_path, f"quiet{i}")

    report = summarise(list(tmp_path.iterdir()))
    key = next(k for k in report.totals if k[1] == 42)

    assert report.totals[key] == 500, "the entry count is still the entry count"
    assert report.captures_per_key[key] == 1
    assert prevalence(report.captures_per_key[key], len(report.runs)) == "one"


def test_a_failed_run_is_not_in_the_prevalence_denominator(tmp_path):
    """Otherwise a directory of dead runs makes every rule look rare, which reads as findings."""
    write_run(tmp_path, "ok1", entry(sid=7))
    write_run(tmp_path, "ok2", entry(sid=7))
    for i in range(8):
        write_run(tmp_path, f"dead{i}", labels_file=False)

    report = summarise(list(tmp_path.iterdir()))
    sound = [r for r in report.runs if not r.failed]
    key = next(k for k in report.totals if k[1] == 7)

    assert len(sound) == 2, "the eight dead runs must not count as captures"
    assert prevalence(report.captures_per_key[key], len(sound)) == "EVERY"


def test_the_flag_actually_reaches_the_report(tmp_path):
    """The complement of testing the function: it has to be wired into what a human reads."""
    for i in range(6):
        write_run(tmp_path, f"cap{i}", entry(sid=3300982))

    assert "EVERY" in format_report(summarise(list(tmp_path.iterdir())))


# --- comparability ------------------------------------------------------------------------------


def test_runs_against_different_snapshots_are_called_out(tmp_path):
    """Two snapshots in one summary means the totals are not a measurement of anything.

    Easy to do by accident — this session did it, running the same capture before and after a
    ruleset change into the same output directory.
    """
    write_run(tmp_path, "a", entry(), snapshot="1111111111111111")
    write_run(tmp_path, "b", entry(), snapshot="2222222222222222")

    text = format_report(summarise(list(tmp_path.iterdir())))

    assert "different snapshots" in text
    assert "not comparable" in text


def test_one_snapshot_is_stated_rather_than_warned_about(tmp_path):
    write_run(tmp_path, "a", entry())
    write_run(tmp_path, "b", entry())

    text = format_report(summarise(list(tmp_path.iterdir())))

    assert "different snapshots" not in text
    assert SNAPSHOT in text


# --- run warnings -------------------------------------------------------------------------------


def test_warnings_are_collapsed_by_kind_with_a_count(tmp_path):
    """One warning per capture x 200 captures is a wall nobody reads; the count is the signal."""
    for i in range(4):
        write_run(tmp_path, f"c{i}", warnings=("ja4 package not installed: no flow will carry",))

    text = format_report(summarise(list(tmp_path.iterdir())))

    assert "x4" in text
    assert text.count("ja4 package not installed") == 1


# --- shape --------------------------------------------------------------------------------------


def test_an_empty_directory_summarises_to_something_readable(tmp_path):
    assert "0 capture" in format_report(summarise([]))


def test_entries_are_keyed_by_basis_so_a_promotion_is_visible(tmp_path):
    """A rule moving from indicator-reference to direct is asserting ordinary traffic IS an
    attack. Same reasoning as corpus_gate's EntryKey — the sid alone would hide it."""
    write_run(tmp_path, "a", entry(sid=5, basis="indicator-reference"))
    write_run(tmp_path, "b", entry(sid=5, basis="direct"))

    report = summarise(list(tmp_path.iterdir()))

    assert len([k for k in report.totals if k[1] == 5]) == 2


# --- two flaws found by pointing the tool at its own author's output ----------------------------


def test_prevalence_is_blank_when_the_runs_are_not_comparable():
    """Across a ruleset change the denominator mixes rulesets, so a share of it means nothing.

    Measured on this session's own output: two runs of one capture spanning the #113 fix reported
    `EVERY` for rules present in both, and `one` for the two scanner rules that had been
    *removed* — the exact inversion of the truth.
    """
    assert prevalence(6, 6, comparable=True) == "EVERY"
    assert prevalence(6, 6, comparable=False) == ""
    assert prevalence(1, 6, comparable=False) == ""


def test_the_report_blanks_the_flag_and_says_why_on_mixed_snapshots(tmp_path):
    """A wrong column with a caveat printed elsewhere is still a wrong column."""
    write_run(tmp_path, "a", entry(sid=99), snapshot="1111111111111111")
    write_run(tmp_path, "b", entry(sid=99), snapshot="2222222222222222")

    text = format_report(summarise(list(tmp_path.iterdir())))

    assert "different snapshots" in text
    assert "would not mean anything" in text
    # Only the DATA rows: the caption below the table explains what `EVERY` and `one` mean and
    # legitimately contains both words. Matching the whole section failed here first.
    rows = [
        line
        for line in text.split("=== what fired", 1)[1].splitlines()
        if line[:8].strip().isdigit()
    ]
    assert rows, "the table has no data rows, so this asserts nothing"
    assert not any("EVERY" in row or "one" in row for row in rows)


def test_one_snapshot_keeps_the_flag(tmp_path):
    """The complement: the guard must not blank the column on ordinary comparable runs."""
    for i in range(4):
        write_run(tmp_path, f"c{i}", entry(sid=99))

    assert "EVERY" in format_report(summarise(list(tmp_path.iterdir())))


def test_a_long_run_name_keeps_its_timestamp_not_its_prefix():
    """Run directories are `{capture}_{timestamp}Z`, so two runs of one capture differ only at
    the END. Truncating from the right displayed them identically — the one case a reader most
    needs to tell apart."""
    from triage import _fit

    a = _fit("lax_capture_2026-07-10_pub-216.152.152.123_20260816T134917.706030Z")
    b = _fit("lax_capture_2026-07-10_pub-216.152.152.123_20260816T143449.963454Z")

    assert a != b, "two runs of one capture must not display identically"
    assert a.endswith("Z") and b.endswith("Z")
    assert len(a) == len(b) == 52


def test_a_short_name_is_left_alone():
    from triage import _fit

    assert _fit("small.pcap_2026Z") == "small.pcap_2026Z"


# --- running from a capture directory, which is the normal case ---------------------------------


def test_the_repo_is_found_from_the_script_not_the_cwd():
    """The captures are outside the checkout by necessity, so that is where an operator stands.

    The first version resolved nothing: `uv run flabel` with no `--project` exits 2 from another
    directory, and spec §12's relative `--rules-dir` default would then have looked for the
    snapshot store beside the captures. It failed loudly, which is the only reason this is a
    footnote rather than an issue.
    """
    from triage import DEFAULT_RULES_DIR, REPO

    assert (REPO / "pyproject.toml").is_file(), f"{REPO} is not the flabel checkout"
    assert (REPO / "src" / "flabel").is_dir()
    assert DEFAULT_RULES_DIR.is_absolute()
    assert DEFAULT_RULES_DIR.is_relative_to(REPO), "the store must live in the checkout"


def test_the_subprocess_is_pinned_to_the_checkout_and_an_absolute_rules_dir(monkeypatch, tmp_path):
    """Both flags are load-bearing, so both are asserted on the argv rather than trusted."""
    import triage

    seen = {}

    class Done:
        returncode, stderr = 0, ""

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["cwd"] = kwargs.get("cwd")
        return Done()

    monkeypatch.setattr(triage.subprocess, "run", fake_run)
    triage.label_one(tmp_path / "c.pcap", tmp_path / "out", tmp_path / "rules")

    argv = seen["argv"]
    assert "--project" in argv, "uv resolves the environment from the cwd without this"
    assert argv[argv.index("--project") + 1] == str(triage.REPO)
    assert "--rules-dir" in argv
    assert Path(argv[argv.index("--rules-dir") + 1]).is_absolute()
    assert seen["cwd"] == triage.REPO


def test_an_absent_snapshot_store_refuses_rather_than_labelling_against_nothing(tmp_path, capsys):
    """Twenty captures against a store that is not there is twenty runs of nothing.

    Worse than a crash, because each run still produces a directory and the summary would report
    a tidy zero for every capture — the shape this whole tool exists to refuse.
    """
    from triage import main

    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"")

    code = main(
        [
            "triage.py",
            str(capture),
            "--output-dir",
            str(tmp_path / "out"),
            "--rules-dir",
            str(tmp_path / "absent"),
        ]
    )

    assert code == 2
    assert "no snapshot store" in capsys.readouterr().err


def test_jobs_must_be_at_least_one(tmp_path):
    """`--jobs 0` is a ThreadPoolExecutor ValueError deep in the run, after the argv was fine."""
    from triage import main

    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"")
    with pytest.raises(SystemExit):
        main(["triage.py", str(capture), "--output-dir", str(tmp_path / "o"), "--jobs", "0"])
