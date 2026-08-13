"""Goal 2: two runs over one capture and one snapshot are identical (docs/spec.md §10).

This is the gate the whole reproducibility argument reduces to. Everything else — `-D`, the
content-addressed snapshot, `--runmode single`, recording the toolchain versions — exists to make
this test passable, and none of it is checked end to end anywhere else.

**Identical after canonicalisation, not byte-identical.** Spec §10 claimed byte-identity until
step 5 disproved it: every Zeek TSV log carries `#open`/`#close` wall-clock headers, so a byte
comparison fails on all of them. `flabel.canonical` is the primitive, and `tests/test_canonical.py`
proves it catches real differences rather than erasing everything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from gates import BENIGN, offline, only_run_dir, truncate_mid_record

from flabel import canonical, cli
from flabel.errors import EXIT_SUCCESS

pytestmark = pytest.mark.requires_tools


def label_once(rules_dir: Path, output: Path, capture: Path = BENIGN) -> Path:
    assert cli.main(offline(capture, rules_dir, output)) == EXIT_SUCCESS
    return only_run_dir(output)


def test_two_runs_over_one_capture_are_identical(labelling_snapshot: Path, tmp_path: Path):
    """Goal 2. Two full `--offline` runs, same capture, same pinned snapshot.

    Everything that legitimately differs — the run directory's name, the three wall-clock fields,
    Zeek's log headers, Suricata's `stats` records — is erased by canonicalisation. What remains
    is the analytic content, and it must be equal record for record.
    """
    first = label_once(labelling_snapshot, tmp_path / "one")
    second = label_once(labelling_snapshot, tmp_path / "two")

    assert canonical.differences(first, second) == []


def test_the_uids_are_stable_across_runs(labelling_snapshot: Path, tmp_path: Path):
    """The specific thing `-D` buys, asserted on the labels rather than on `conn.log`.

    A flow's `uid` is the join key the whole document is built on, so unstable uids would make
    two runs' labels incomparable even where every detection matched identically. `test_zeek.py`
    proves `-D` keeps them stable in `conn.log`; this proves the property survives all the way
    into `labels.json`, which is what a consumer actually reads.
    """
    first = label_once(labelling_snapshot, tmp_path / "one")
    second = label_once(labelling_snapshot, tmp_path / "two")

    uids = [
        {label["flow"]["uid"] for label in json.loads((run / "labels.json").read_text())["labels"]}
        for run in (first, second)
    ]
    assert uids[0] == uids[1]
    assert uids[0], "the fixture must produce labels, or this test proves nothing"


def test_the_same_capture_labelled_from_two_directories_is_identical(
    labelling_snapshot: Path, tmp_path: Path
):
    """`run.input.path` is the operator's own path, and excluding it has to do real work.

    Spec §10 excludes it precisely so this passes: the same capture labelled from two locations
    is the same run. Without a copy of the capture at a second path the exclusion would never be
    exercised, and a gate that cannot fail is not a gate.
    """
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    copy = elsewhere / "benign.pcap"
    copy.write_bytes(BENIGN.read_bytes())

    first = label_once(labelling_snapshot, tmp_path / "one")
    second = label_once(labelling_snapshot, tmp_path / "two", capture=copy)

    assert canonical.differences(first, second) == []
    # And the field really did differ, so the exclusion was doing something.
    paths = {
        json.loads((run / "run.json").read_text())["run"]["input"]["path"]
        for run in (first, second)
    }
    assert len(paths) == 2, "both runs recorded the same path — the exclusion proved nothing"


def test_a_different_capture_is_not_reproducible_against_the_first(
    labelling_snapshot: Path, tmp_path: Path
):
    """The direction that makes the gate meaningful: it must be able to fail.

    Two runs over *different* captures have to differ, or the comparison is erasing the content
    it exists to compare. This is the same both-directions discipline `test_canonical.py` applies
    to each rule, applied once to the whole assembled gate.
    """
    truncated = truncate_mid_record(BENIGN, tmp_path / "shorter.pcap", keep=5)

    first = label_once(labelling_snapshot, tmp_path / "one")
    second = label_once(labelling_snapshot, tmp_path / "two", capture=truncated)

    reported = canonical.differences(first, second)

    # **Naming the files is the whole assertion.** Asserting only that the list is non-empty was
    # useless: two different captures have different `input.sha256`, and `sha256` is deliberately
    # not excluded, so `run.json` and `labels.json` differ no matter what the canonicalizer does
    # to the logs. Verified by sabotage — making `_canonical_file` return `()` for every `.log`,
    # which erases all of Zeek's and Suricata's output, left this test *and* the headline Goal 2
    # test both green. The gate could be hollowed out completely with CI passing.
    differing = {line.split(":")[0] for line in reported}
    assert "zeek/conn.log" in differing, (
        f"the tool logs compared equal across two different captures: {sorted(differing)}. The "
        f"canonicalizer is erasing analytic content, not just wall-clock noise."
    )
    assert "suricata/eve.json" in differing, (
        f"suricata's alerts compared equal across two different captures: {sorted(differing)}"
    )


def test_the_snapshot_id_is_recorded_identically_in_both_runs(
    labelling_snapshot: Path, tmp_path: Path
):
    """A label cites the ruleset that produced it, and reproducibility depends on it being one.

    If two runs resolved different snapshots — the `rules update` race step 9 asserts against —
    the labels would be reproducible only by coincidence.
    """
    first = label_once(labelling_snapshot, tmp_path / "one")
    second = label_once(labelling_snapshot, tmp_path / "two")

    ids = {
        json.loads((run / "run.json").read_text())["run"]["ruleset"]["snapshot_id"]
        for run in (first, second)
    }
    assert len(ids) == 1


def test_a_quiet_ruleset_is_reproducible_too(quiet_snapshot: Path, tmp_path: Path):
    """Zero labels is a result, and it has to be a *reproducible* one.

    Worth its own case because the labelling path and the no-labels path write different files:
    `NOTICE` says something else, and `labels[]` is empty. A gate that only ever ran against a
    capture that produced labels would not cover the ordinary outcome.
    """
    first = label_once(quiet_snapshot, tmp_path / "one")
    second = label_once(quiet_snapshot, tmp_path / "two")

    assert canonical.differences(first, second) == []
    assert json.loads((first / "labels.json").read_text())["labels"] == []


def test_the_gate_notices_when_the_log_comparison_is_disabled(
    labelling_snapshot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Sabotage the primitive and confirm the gate goes red — the guard on the guard.

    A reproducibility gate is uniquely dangerous to get wrong, because a gate that cannot fail
    looks exactly like one that passes, forever. Every other test here asserts that two runs are
    *equal*, and all of them would keep passing if `canonical` started returning nothing at all.

    So this one breaks it on purpose. With `.log` files canonicalising to nothing, two runs over
    genuinely different captures must still be caught by the remaining comparisons — and the
    moment they are not, the whole gate is decorative.
    """
    truncated = truncate_mid_record(BENIGN, tmp_path / "shorter.pcap", keep=5)
    first = label_once(labelling_snapshot, tmp_path / "one")
    second = label_once(labelling_snapshot, tmp_path / "two", capture=truncated)

    # Sanity: intact, the logs are what carries the difference.
    intact = {line.split(":")[0] for line in canonical.differences(first, second)}
    assert "zeek/conn.log" in intact

    real = canonical.canonical_records
    monkeypatch.setattr(canonical, "canonical_records", lambda text: ())
    sabotaged = {line.split(":")[0] for line in canonical.differences(first, second)}
    monkeypatch.setattr(canonical, "canonical_records", real)

    assert "zeek/conn.log" not in sabotaged, (
        "the sabotage did not take effect, so this test proves nothing about the gate"
    )
    assert intact - sabotaged, (
        "disabling the log comparison changed nothing the gate reports — the log comparison "
        "was never contributing to it"
    )
