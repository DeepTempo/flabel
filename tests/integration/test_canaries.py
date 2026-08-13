"""Goal 5 and the loss-condition fault injections (docs/spec.md §11, PLAN.md step 10).

**Goal 5 is the standing false-positive review for every wholesale-admitted source.** Those feeds
pass through no per-rule gate — the risk is concentrated in `pawpatrules`' 21,464 ungated rules —
so the only thing standing between a bad upstream rule and a corrupted training set is a capture
whose correct label count is known to be zero.

The version of Goal 5 that runs here is deliberately the weaker one. Against a **real** nine-feed
snapshot the canary cannot run in this suite at all: spec §2.2 forbids the test suite contacting
rule feeds, and a real snapshot is 124 MB (42 MB of `rules.rules` alone), far too large to commit.
That gate runs in `.github/workflows/feeds.yml` on a schedule, against freshly fetched feeds
(Craig, 2026-08-12 — issue #24). What these tests prove is the half that can be proved offline:
the pipeline does not invent labels, and the fixture the scheduled gate depends on is intact.

Both halves are needed. The scheduled workflow could pass forever against a canary someone had
quietly edited into emptiness; these tests could pass forever against rules that never fire.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from gates import BENIGN, MATCHES_CANARY, build_snapshot, offline, only_run_dir, truncate_mid_record

from flabel import cli
from flabel.errors import EXIT_FAILURE, EXIT_SUCCESS

FIXTURES = BENIGN.parent

#: The malicious canary, still unsourced (spec §14, issue #24). The test below activates itself
#: the moment the file appears, so the gap cannot be forgotten into permanence.
MALICIOUS = FIXTURES / "malicious.pcap"


def label(rules_dir: Path, output: Path, capture: Path = BENIGN, *extra: str) -> Path:
    assert cli.main(offline(capture, rules_dir, output, *extra)) == EXIT_SUCCESS
    return only_run_dir(output)


def labels_of(rundir: Path) -> list[dict]:
    return json.loads((rundir / "labels.json").read_text(encoding="utf-8"))["labels"]


def run_block(rundir: Path) -> dict:
    return json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]


# --- Goal 5 ---------------------------------------------------------------------------------


@pytest.mark.requires_tools
def test_the_benign_canary_produces_zero_labels(quiet_snapshot: Path, tmp_path: Path):
    """Goal 5, in the form this suite can prove: the pipeline does not invent labels.

    The snapshot is real and fully loaded — three rules for UDP, ICMPv4 and ICMPv6 — and the
    canary carries none of those protocols. So every stage runs for real and the correct answer
    is zero. A label here means the pipeline manufactured a verdict from traffic no rule matched,
    which is a worse defect than a false positive from a bad rule.
    """
    rundir = label(quiet_snapshot, tmp_path / "out")

    assert labels_of(rundir) == []
    assert run_block(rundir)["counts"]["labels"] == 0
    # The rules really did load; zero labels from zero rules would prove nothing.
    assert run_block(rundir)["counts"]["rules_loaded"] == 3


@pytest.mark.requires_tools
def test_zero_labels_still_writes_a_complete_run_directory(quiet_snapshot: Path, tmp_path: Path):
    """ "Nothing malicious found" is a result, and it is the ordinary one.

    It must be distinguishable from a run that died — which writes `run.json` and *no*
    `labels.json` (issue #23) — so the clean case has to produce the complete set.
    """
    rundir = label(quiet_snapshot, tmp_path / "out")

    assert (rundir / "labels.json").is_file()
    assert (rundir / "run.json").is_file()
    assert (rundir / "NOTICE").is_file()
    assert (rundir / "zeek" / "conn.log").is_file()


def test_the_benign_canary_fixture_is_the_one_the_gate_was_measured_against():
    """A gate whose fixture can be edited is a gate that can be made to pass by editing it.

    The canary's value is that *zero labels is known-correct by construction*, established by
    reading its 14 packets. Any change to it — however well-meant — invalidates the measurement
    recorded on issue #24 (0 detections against the full 85,431-rule snapshot) and has to be
    re-measured rather than assumed.

    If this fails because the fixture was regenerated: re-run the scheduled feeds workflow, then
    update the digest here with the result recorded in `tests/fixtures/README.md`. Do not update
    it to make the build green.
    """
    digest = hashlib.sha256(BENIGN.read_bytes()).hexdigest()

    assert digest == BENIGN_SHA256, (
        f"tests/fixtures/benign.pcap changed (now {digest}). The canary is the standing "
        f"false-positive review for every wholesale-admitted source; re-measure before "
        f"accepting the new fixture."
    )


#: sha256 of `tests/fixtures/benign.pcap` as it stood when Goal 5 was measured against the full
#: nine-feed snapshot `8c9e8d58af0a8d64` (0 detections, recorded on issue #24).
BENIGN_SHA256 = "7aa343087a8743a73ced055b4af2c743de8e96a1a7112e127c1d97499f522ab1"


@pytest.mark.requires_tools
@pytest.mark.skipif(
    not MALICIOUS.exists(),
    reason=(
        "the malicious canary is not sourced yet (spec §14, issue #24). This skip is the "
        "record of that gap — see tests/fixtures/README.md for what the fixture must satisfy."
    ),
)
def test_the_malicious_canary_produces_at_least_one_label(tmp_path: Path):
    """The sensitivity half of the canary pair: a capture that *should* be labelled, is.

    Zero labels on the benign canary proves specificity and nothing else — a pipeline that had
    silently stopped labelling anything would pass it every time. This is the test that would
    catch that, which is why the pair is only meaningful together.

    Activates itself when the fixture lands; until then the skip keeps the gap visible in test
    output rather than absent from it.
    """
    rules_dir = tmp_path / "rules"
    build_snapshot(rules_dir, {"et/open": [MATCHES_CANARY]})

    rundir = label(rules_dir, tmp_path / "out", capture=MALICIOUS)

    assert labels_of(rundir), "the malicious canary produced no label — sensitivity regression"


# --- loss conditions, injected end to end (spec §11) --------------------------------------------
#
# Spec §11 is a closed list of nine ways a run can under-report, each with a named field. The
# field-resolution half is asserted in `tests/test_provenance.py`, which parses §11's table at run
# time. What is asserted here is the other half: that a real run, with the fault really present,
# actually sets it. A field that resolves and is never `true` reports nothing.


@pytest.mark.requires_tools
def test_the_loss_condition_keys_are_exactly_the_nine(quiet_snapshot: Path, tmp_path: Path):
    """The closed list is closed, checked against a real run rather than a constructed block."""
    conditions = run_block(label(quiet_snapshot, tmp_path / "out"))["loss_conditions"]

    assert set(conditions) == {
        "input_truncated",
        "multi_datalink_discard",
        "detection_uncorrelatable",
        "ambiguous_flow_match",
        "tool_failure",
        "snapshot_missing",
        "identify_alert_suppressed",
        "rules_failed_or_skipped",
        "ja4_unavailable",
    }


@pytest.mark.requires_tools
def test_a_clean_run_reports_no_loss_it_did_not_have(quiet_snapshot: Path, tmp_path: Path):
    """Spec §2.5 cuts both ways: silence must mean nothing happened, so noise must not be free.

    A gate that reported losses on a clean run would be as useless as one that reported none on a
    lossy one — an operator would learn to ignore it.
    """
    conditions = run_block(label(quiet_snapshot, tmp_path / "out"))["loss_conditions"]

    assert conditions["input_truncated"] is False
    assert conditions["multi_datalink_discard"] is False
    assert conditions["detection_uncorrelatable"] is False
    assert conditions["ambiguous_flow_match"] is False
    assert conditions["tool_failure"] is False
    assert conditions["snapshot_missing"] is False
    assert conditions["rules_failed_or_skipped"] is False


@pytest.mark.requires_tools
def test_a_truncated_capture_is_labelled_and_reported_as_partial(
    quiet_snapshot: Path, tmp_path: Path
):
    """§11 row 1. Truncation is a reported loss, not a refusal — and not a non-zero exit.

    Spec §12 is explicit that partial input is deliberately *not* a distinct exit code: truncated
    captures are common, and a non-zero exit would make every ordinary `set -e` script treat a
    successful run as a failure. So the run succeeds and the run block carries the truncation.
    """
    truncated = truncate_mid_record(BENIGN, tmp_path / "truncated.pcap", keep=8)

    rundir = label(quiet_snapshot, tmp_path / "out", truncated)

    block = run_block(rundir)
    assert block["input"]["input_status"] == "partial"
    assert block["input"]["truncated_at_offset"] is not None
    assert block["loss_conditions"]["input_truncated"] is True
    assert block["input"]["packets_read"] == 8, "the eight whole packets were still read"
    # Exit 0 is asserted by `label` itself: partial input is not a failure (spec §12).


@pytest.mark.requires_tools
def test_an_identify_source_alert_is_suppressed_and_counted(tmp_path: Path):
    """§11 row 7, and spec §2.8's hardest guarantee: an `identify` source can never label.

    The rule fires — it matches the canary exactly as the labelling rule does — and produces no
    label. Counting it is what makes the suppression visible; a silent drop would be
    indistinguishable from a rule that never matched.
    """
    rules_dir = tmp_path / "rules"
    build_snapshot(rules_dir, {"oisf/trafficid": [9000003]}, classes={"oisf/trafficid": "identify"})

    rundir = label(rules_dir, tmp_path / "out")

    block = run_block(rundir)
    assert labels_of(rundir) == [], "an identify-class source produced a label (spec §2.8)"
    assert block["counts"]["identify_alerts_suppressed"] >= 1
    assert block["loss_conditions"]["identify_alert_suppressed"] is True


@pytest.mark.requires_tools
def test_a_rule_the_engine_cannot_compile_is_reported_not_hidden(tmp_path: Path):
    """§11 row 8, one of the two rows added after step 6 measured the tools.

    Suricata loads what it can and exits 0, so a snapshot whose rules partly fail produces a run
    that looks complete and is missing every label those rules would have made. Since #46 the
    shortfall no longer fails the run — it is reported, and the operator decides. Non-interactive
    here, so it proceeds; what must survive is the record.
    """
    rules_dir = tmp_path / "rules"
    build_snapshot(rules_dir, {"et/open": [MATCHES_CANARY, 9000004]})

    rundir = label(rules_dir, tmp_path / "out")

    block = run_block(rundir)
    assert block["counts"]["rules_failed"] >= 1
    assert block["loss_conditions"]["rules_failed_or_skipped"] is True
    assert any("did not load" in warning for warning in block["warnings"])
    # And the rules that did load still did their job.
    assert labels_of(rundir), "a partial ruleset must still label what it matched"


@pytest.mark.requires_tools
def test_a_missing_snapshot_fails_before_a_run_directory_exists(tmp_path: Path):
    """§11 row 6. A hard failure, exit 1, and never a fallback to a different ruleset.

    Silently substituting another snapshot would break the guarantee the id exists to give: a
    label names the ruleset that produced it.
    """
    output = tmp_path / "out"
    output.mkdir()

    code = cli.main(
        offline(BENIGN, tmp_path / "rules", output, "--ruleset-snapshot", "0123456789abcdef")
    )

    assert code == EXIT_FAILURE
    assert list(output.iterdir()) == [], "a refusal to start must leave nothing behind"


@pytest.mark.requires_tools
def test_ja4_availability_is_reported_either_way(quiet_snapshot: Path, tmp_path: Path):
    """§11 row 9, the other row added after the tools were measured.

    A null `ja4` on a flow has two causes — no TLS in the capture, or no fingerprinting package
    installed — and they are not the same fact. The value depends on the environment (CI runs the
    toolchain container with the package; a laptop may not), so what is asserted is that the run
    *states* which, rather than which one it states.
    """
    block = run_block(label(quiet_snapshot, tmp_path / "out"))

    assert block["tools"]["ja4_status"] in {"present", "not-installed", "probe-failed"}
    assert block["loss_conditions"]["ja4_unavailable"] is (
        block["tools"]["ja4_status"] != "present"
    )
