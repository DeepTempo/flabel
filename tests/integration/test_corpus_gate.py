"""The broad false-positive gate must be able to FAIL (PLAN step 11d, issue #75).

These tests need no toolchain: they feed `corpus_gate` synthetic `labels.json` documents, because
the question is not "does the pipeline run" — `test_benign_corpus.py` covers that — but "does the
gate notice a label nobody argued for".

That distinction is this session's lesson stated twice: the Goal 2 reproducibility gate could be
hollowed out entirely with CI green (#74), and three of step 13's fixes shipped with tests that
passed against the unfixed code (#98). A gate living only inside a scheduled workflow is unprovable
by construction, so the decision was extracted to be tested here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from corpus_gate import TOLERATED, load_tolerated, review, unaccounted

KNOWN_INDICATOR = {
    "source": "pawpatrules",
    "sid": 3317444,
    "rev": 1,
    "label_basis": "indicator-reference",
    "threat": "the 127.0.0.1 rule",
}
KNOWN_DIRECT = {
    "source": "pawpatrules",
    "sid": 3321290,
    "rev": 1,
    "label_basis": "direct",
    "threat": "loose FormBook pcre",
}


def write_run(root: Path, name: str, *sources: dict) -> Path:
    """A run directory holding one label carrying `sources`, or none if empty."""
    rundir = root / name
    rundir.mkdir(parents=True)
    labels = [{"sources": list(sources)}] if sources else []
    (rundir / "labels.json").write_text(
        json.dumps({"schema_version": 1, "run": {}, "labels": labels}), encoding="utf-8"
    )
    return rundir


@pytest.fixture
def tolerated():
    return load_tolerated()


def test_the_committed_residue_passes(tmp_path: Path, tolerated):
    """The three sids measured against two different rulesets are accounted for."""
    runs = [
        write_run(tmp_path, "a", KNOWN_INDICATOR, KNOWN_INDICATOR),
        write_run(tmp_path, "b", KNOWN_DIRECT),
        write_run(tmp_path, "c"),
    ]

    assert unaccounted(runs, tolerated) == []


def test_a_new_sid_fails(tmp_path: Path, tolerated):
    """The case the gate exists for: a rule nobody has argued for labels benign traffic."""
    newcomer = {**KNOWN_DIRECT, "sid": 9999999, "threat": "ET MALWARE Something Plausible"}
    runs = [write_run(tmp_path, "a", KNOWN_INDICATOR, newcomer)]

    offenders = unaccounted(runs, tolerated)

    assert [o.source["sid"] for o in offenders] == [9999999]
    assert offenders[0].capture == "a", "a failure has to name the capture to be actionable"


def test_a_new_source_fails_even_on_a_tolerated_sid(tmp_path: Path, tolerated):
    """Sids are only unique within a feed, so the source is part of the key."""
    impostor = {**KNOWN_INDICATOR, "source": "et/open"}

    assert [
        o.source["source"] for o in unaccounted([write_run(tmp_path, "a", impostor)], tolerated)
    ] == ["et/open"]


def test_a_tolerated_sid_claiming_direct_instead_fails(tmp_path: Path, tolerated):
    """`label_basis` is part of the key, and this is why.

    sid 3317444 is tolerated as `indicator-reference` — it establishes that a flow reached a
    flagged address. The same sid claiming `direct` asserts that ordinary traffic *is* the attack,
    which is issue #75's defect returning under a sid that is already on the list. Reachable for
    real: it is what a regression in step 11c's composition would produce.
    """
    overclaim = {**KNOWN_INDICATOR, "label_basis": "direct"}

    offenders = unaccounted([write_run(tmp_path, "a", overclaim)], tolerated)

    assert len(offenders) == 1
    assert offenders[0].source["label_basis"] == "direct"


def test_a_tolerated_entry_that_stops_firing_is_reported_not_failed(tmp_path: Path, tolerated):
    """An upstream fix must not read as a regression — but it must not go unnoticed either.

    If pawpatrules ever repairs the 127.0.0.1 rule, this list should shrink. Failing would punish
    the improvement; staying silent would let the list drift into permanence.
    """
    result = review([write_run(tmp_path, "a", KNOWN_DIRECT)], tolerated)

    assert result.offenders == []
    assert (
        KNOWN_INDICATOR["source"],
        KNOWN_INDICATOR["sid"],
        "indicator-reference",
    ) in result.stale


def test_a_run_that_wrote_no_labels_is_a_failure_not_zero_labels(tmp_path: Path, tolerated):
    """Issue #23: the absence of labels.json is the signal that the run died."""
    rundir = tmp_path / "died"
    rundir.mkdir()
    (rundir / "run.json").write_text(json.dumps({"run": {"tool_failures": ["boom"]}}), "utf-8")

    with pytest.raises(RuntimeError, match="wrote no labels.json"):
        review([rundir], tolerated)


def test_every_tolerated_entry_carries_a_reason():
    """An allowlist that can be appended to without argument stops being a review."""
    document = json.loads(TOLERATED.read_text(encoding="utf-8"))

    assert document["entries"], "an empty tolerated list should be expressed by deleting entries"
    for entry in document["entries"]:
        assert entry["reason"].strip(), f"{entry['source']} sid {entry['sid']} has no reason"
        assert entry["label_basis"] in {"direct", "indicator-reference"}


def test_a_reasonless_entry_is_refused(tmp_path: Path):
    """The guard above checks the committed file; this checks the loader that enforces it."""
    path = tmp_path / "tolerated.json"
    path.write_text(
        json.dumps(
            {"entries": [{"source": "x", "sid": 1, "label_basis": "direct", "reason": "  "}]}
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="no reason"):
        load_tolerated(path)
