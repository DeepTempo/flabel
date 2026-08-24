"""The Goal 5 liveness gate must be able to FAIL (issue #88).

`feeds_liveness.verify` decides whether Goal 5's real review has gone dark. Its whole value is
in the failing branches, so those are what is exercised here — the passing case is one test and
the ways it can be wrongly green are the rest.

The gate takes `now` and the run list as arguments precisely so this file can drive the boundary
without waiting a week or reaching the network. That split is why the tests exist at all: the
previous three gates in this repo each shipped with their failure path unreachable (#74, #98,
#101), and each was caught only by breaking the fix on purpose.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from feeds_liveness import ENV_MAX_AGE, MAX_AGE_DAYS, main, max_age_days, parse_timestamp, verify

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)


def run(days_ago: float, conclusion: str = "success") -> dict:
    """One GitHub workflow-run record, in the shape `gh api --jq` projects."""
    return {
        "conclusion": conclusion,
        "created_at": (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z"),
    }


def fresh_run(conclusion: str = "success") -> dict:
    """A run that is fresh against the REAL clock, for the two `main` tests only.

    `main` takes no `now`: its own docstring says it is "argv parsing and file reading. The
    decision is `verify`" — and `verify` *is* clock-injectable, which is why every freshness test
    below is deterministic. Building a `main` fixture from `NOW` quietly coupled two parsing tests
    to the wall clock instead.

    It was a time bomb with a known fuse. `NOW` is 2026-08-15 and the threshold is 7 days, so these
    two passed until 2026-08-22 and failed every run after. Measured 2026-08-24: they turned `main`
    itself red on the merge of PR #160 — a docs-only change that had been green on its branch three
    days earlier — while the feeds workflow was perfectly healthy, having run successfully at
    04:31 that morning. A liveness gate that cries wolf about itself is one people learn to ignore,
    which is the opposite of what this file is for.
    """
    return {
        "conclusion": conclusion,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


# --- the passing case, and it must be narrow ---------------------------------------------------


def test_a_recent_success_passes(capsys):
    assert verify([run(0.5)], NOW) == 0
    assert "live" in capsys.readouterr().out


def test_the_newest_success_is_what_counts_not_the_newest_run():
    """A red run today over a green run yesterday is still a live review.

    The schedule is daily and upstream feeds are fetched live, so a single red day is ordinary.
    Failing on it would make this a duplicate of the issue `feeds` already files, and a gate that
    fires on the ordinary case is a gate that gets deleted.
    """
    assert verify([run(0.1, "failure"), run(1.0, "success")], NOW) == 0


def test_the_order_of_the_api_response_does_not_decide_the_verdict():
    """GitHub returns newest-first today. Nothing in the contract promises it will tomorrow.

    Sorting rather than trusting position is cheap; a gate that reads the wrong element reports
    the age of an arbitrary run, which is worse than no gate because it looks like one.
    """
    oldest_first = [run(30.0), run(10.0), run(0.5)]
    assert verify(oldest_first, NOW) == 0
    assert verify(list(reversed(oldest_first)), NOW) == 0


# --- the failing branches, one test each -------------------------------------------------------


def test_a_stale_success_fails(capsys):
    assert verify([run(MAX_AGE_DAYS + 1)], NOW) == 1
    assert "gh workflow run feeds.yml" in capsys.readouterr().err


def test_a_run_that_only_ever_failed_is_dark(capsys):
    """Sustained failure is not liveness. This is the 2026-08-15 breakage, in miniature.

    The first scheduled run after step 11d died on `set -euo pipefail` under `sh`. It *ran* — so
    a check keyed on "did it run" would have called Goal 5 healthy while the review had in fact
    stopped happening.
    """
    assert verify([run(0.1, "failure"), run(1.1, "failure")], NOW) == 1
    assert "not completed once" in capsys.readouterr().err


def test_no_runs_at_all_fails(capsys):
    assert verify([], NOW) == 1
    assert "never run" in capsys.readouterr().err


def test_an_unreachable_api_fails_rather_than_passing(capsys):
    """`None` means "could not determine", and that must never be green.

    This is the branch most likely to be quietly softened the first time a token scope changes and
    someone wants their PR to merge. Spec §2.5: absence is never a signal.
    """
    assert verify(None, NOW) == 1
    assert "not a pass" in capsys.readouterr().err


def test_unreadable_timestamps_are_not_reported_as_a_quiet_schedule(capsys):
    """A changed API shape and a dark schedule are different faults and must diagnose differently.

    If every `created_at` is unparseable, treating the list as "no successful run" would send
    someone to the Actions tab to re-enable a workflow that is running perfectly well.
    """
    assert verify([{"conclusion": "success", "created_at": "not-a-date"}], NOW) == 1
    error = capsys.readouterr().err
    assert "readable `created_at`" in error
    assert "no successful run" in error  # the message says what it is NOT


def test_one_bad_record_does_not_decide_the_verdict():
    """The complement of the test above: one malformed entry is tolerated, all of them is not."""
    assert verify([{"conclusion": "success", "created_at": None}, run(0.5)], NOW) == 0


# --- the boundary, exactly ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (MAX_AGE_DAYS - 0.01, 0),
        (MAX_AGE_DAYS, 0),  # inclusive: exactly at the limit is still live
        (MAX_AGE_DAYS + 0.01, 1),
    ],
)
def test_the_threshold_boundary_is_where_it_says_it_is(age, expected):
    assert verify([run(age)], NOW) == expected


def test_the_threshold_is_an_argument_so_a_caller_can_tighten_it():
    assert verify([run(3.0)], NOW, threshold_days=2) == 1
    assert verify([run(3.0)], NOW, threshold_days=4) == 0


# --- the override, which relaxes a check and so must fail loudly when it is wrong ---------------


def test_the_override_is_read_from_the_environment():
    assert max_age_days({ENV_MAX_AGE: "30"}) == 30.0


def test_an_absent_or_empty_override_is_the_default():
    assert max_age_days({}) == float(MAX_AGE_DAYS)
    assert max_age_days({ENV_MAX_AGE: ""}) == float(MAX_AGE_DAYS)


@pytest.mark.parametrize("bad", ["verylong", "0", "-1", "7 days", "1e", " "])
def test_a_nonsense_override_raises_rather_than_falling_back(bad):
    """Falling back to the default would leave someone believing they had suspended this gate.

    Wrong in the tolerable direction for most settings; wrong in the intolerable direction for
    one whose entire purpose is to relax a check, because the person who set it stops looking.
    (`""` is excluded deliberately: empty is the documented way to say "unset", covered above.)
    """
    with pytest.raises(ValueError, match=ENV_MAX_AGE):
        max_age_days({ENV_MAX_AGE: bad})


@pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "Infinity", "NaN"])
def test_a_non_finite_override_cannot_switch_the_gate_off(bad):
    """`nan` and `inf` both parse, both survive `<= 0`, and both disable this gate silently.

    `age > float("nan")` is False for every age, so `FLABEL_FEEDS_MAX_AGE_DAYS=nan` makes the
    review immortal while reading, in a diff, as a number someone chose. Found by writing this
    test, not by reading the code — the first version of the guard checked only `<= 0`.
    """
    with pytest.raises(ValueError, match="finite"):
        max_age_days({ENV_MAX_AGE: bad})


def test_the_gate_really_would_have_been_immortal_without_that_guard():
    """The sabotage, run rather than asserted: NaN as a bare threshold passes at any age.

    This is what the guard above is worth. `verify` takes the threshold as a float, so this
    reaches past `max_age_days` and shows the underlying comparison doing the wrong thing.
    """
    assert verify([run(10_000)], NOW, threshold_days=float("nan")) == 0


# --- parsing ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ["2026-08-15T04:28:48Z", "2026-08-15T04:28:48+00:00", "2026-08-15T04:28:48"],
)
def test_the_three_timestamp_shapes_github_and_humans_produce_all_parse(raw):
    parsed = parse_timestamp(raw)
    assert parsed is not None
    assert parsed.tzinfo is not None, "a naive timestamp would raise on subtraction from `now`"


@pytest.mark.parametrize("raw", [None, "", 17, "not-a-date", {}])
def test_unusable_timestamps_are_none_rather_than_an_exception(raw):
    assert parse_timestamp(raw) is None


# --- main(), which is argv and file reading only -------------------------------------------------


def test_main_reads_the_jq_projection(tmp_path, capsys):
    path = tmp_path / "runs.json"
    path.write_text(json.dumps([fresh_run()]))
    assert main(["prog", str(path)]) == 0


def test_main_also_reads_a_raw_api_response(tmp_path):
    """`gh api` without `--jq` returns an object. Doing something sensible with it is free."""
    path = tmp_path / "runs.json"
    path.write_text(json.dumps({"workflow_runs": [fresh_run()]}))
    assert main(["prog", str(path)]) == 0


def test_a_missing_file_fails_rather_than_passing(tmp_path, capsys):
    assert main(["prog", str(tmp_path / "absent.json")]) == 1
    assert "not a pass" in capsys.readouterr().err


def test_a_json_document_of_the_wrong_shape_fails(tmp_path, capsys):
    path = tmp_path / "runs.json"
    path.write_text('"a string is not a run list"')
    assert main(["prog", str(path)]) == 1
    assert "neither a list of runs" in capsys.readouterr().err


def test_wrong_argv_is_a_usage_error_not_a_pass(tmp_path):
    assert main(["prog"]) == 2
    assert main(["prog", "a", "b"]) == 2
