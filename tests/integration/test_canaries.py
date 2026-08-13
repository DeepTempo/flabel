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
import sys
from pathlib import Path

import pytest
from gates import (
    ANY_IP_PROTOCOL,
    BENIGN,
    MATCHES_CANARY,
    build_snapshot,
    offline,
    only_run_dir,
    truncate_mid_record,
)

from flabel import cli
from flabel.errors import EXIT_FAILURE, EXIT_SUCCESS

FIXTURES = BENIGN.parent
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))

from make_awkward import (  # noqa: E402  (needs the path entry above)
    write_esp_pcap,
    write_two_unsupported_transports_pcap,
)

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
# Spec §11 is a closed list of nine ways a run can under-report, each with a named field. Three
# things check them, and it is worth being exact about which does what — the easy misreading is
# that this section covers all nine end to end. It does not.
#
#   * `tests/test_provenance.py` parses §11's table at run time, asserts every field resolves in
#     the run block, and unit-tests each flag's derivation against a synthetic run info.
#   * The stage tests inject each fault where it originates — `test_ingest.py` for the datalink
#     discard, `test_correlate.py` for the ambiguous match, `test_cli.py` for a tool failure.
#   * **Here**: the faults reachable through a real end-to-end run — truncation, identify
#     suppression, a rule the engine cannot compile, a missing snapshot, and an absent ja4
#     package. Five of the nine.
#
# The other four are covered at stage level with their derivations unit-tested; what they lack is
# a full-pipeline run with the fault present. Recorded rather than glossed, because a docstring
# claiming "all nine" would be believed.


@pytest.mark.requires_tools
def test_the_loss_condition_keys_are_exactly_the_ten(quiet_snapshot: Path, tmp_path: Path):
    """The closed list is closed, checked against a real run rather than a constructed block."""
    conditions = run_block(label(quiet_snapshot, tmp_path / "out"))["loss_conditions"]

    assert set(conditions) == {
        "input_truncated",
        "multi_datalink_discard",
        "detection_uncorrelatable",
        "ambiguous_flow_match",
        "unsupported_transport",
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


@pytest.mark.requires_tools
def test_a_run_without_the_ja4_package_says_so(
    quiet_snapshot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """§11 row 9, with the fault actually injected (PLAN step 10: "the `ja4` package absent").

    The obvious assertion here is a tautology, and was one until this test replaced it:
    `loss_conditions.ja4_unavailable` is *computed* from `tools.ja4_status`, so asserting the two
    agree restates `provenance.py` rather than testing it. Worse, CI runs `--strict-toolchain`,
    which requires the package present — so the `True` branch of the flag was never reached by
    any end-to-end run at all.

    What matters is the consequence: a null `ja4` on a flow means "no TLS here" when the package
    is present and "never computed" when it is absent, and a consumer training on the output
    cannot tell those apart unless the run says which.
    """
    from flabel import zeek

    monkeypatch.setattr(
        zeek, "_ja4_status", lambda binary: ("not-installed", "ja4 package not installed")
    )

    block = run_block(label(quiet_snapshot, tmp_path / "out"))

    assert block["tools"]["ja4_status"] == "not-installed"
    assert block["loss_conditions"]["ja4_unavailable"] is True
    assert any("ja4" in warning.lower() for warning in block["warnings"])


# --- protocols Zeek cannot express (issue #84, PLAN step 12) --------------------------------


def esp_snapshot(tmp_path: Path) -> Path:
    """A real snapshot holding the one `alert ip` rule, which fires on any IP protocol."""
    root = tmp_path / "rules-any-ip"
    build_snapshot(root, {"et/open": [ANY_IP_PROTOCOL]})
    return root


def test_a_capture_that_is_entirely_esp_completes_instead_of_failing(tmp_path: Path):
    """Issue #84's headline: this exact capture used to exit 1 with no labels.json at all.

    IPsec is ordinary in enterprise captures and the wholesale-admitted feeds are full of
    `alert ip` reputation rules, so the crash was reachable from real traffic. The run must now
    succeed and say what it could not do, rather than dying and saying nothing.
    """
    capture = write_esp_pcap(tmp_path / "esp.pcap")
    rundir = label(esp_snapshot(tmp_path), tmp_path / "out", capture)

    run = run_block(rundir)
    assert labels_of(rundir) == [], "an ESP flow cannot be correlated, so it cannot be labelled"
    assert run["counts"]["unmatched_unsupported_transport"] == 1
    assert run["counts"]["unmatched_ratio"] == 0.0, "the gate does not judge what it cannot place"

    document = json.loads((rundir / "labels.json").read_text(encoding="utf-8"))
    assert [record["reason"] for record in document["unmatched_detections"]] == [
        "unsupported_transport"
    ]
    assert {record["detection"]["proto"] for record in document["unmatched_detections"]} == {"esp"}


def test_the_loss_is_reported_even_though_the_run_succeeded(tmp_path: Path):
    """The row exists *because* the gate tolerates this one (spec §2.5, §11).

    `detection_uncorrelatable` covers `no_flow_match` only. Without its own flag, a capture
    whose every detection was discarded would report a `loss_conditions` block of falses — a
    clean-looking run that labelled nothing and never said why.
    """
    capture = write_esp_pcap(tmp_path / "esp.pcap")
    conditions = run_block(label(esp_snapshot(tmp_path), tmp_path / "out", capture))[
        "loss_conditions"
    ]

    assert conditions["unsupported_transport"] is True
    assert conditions["detection_uncorrelatable"] is False, "no tuple was absent; none was compared"
    assert conditions["tool_failure"] is False


def test_zeek_writes_one_tuple_for_two_such_conversations_and_one_field_apart(tmp_path: Path):
    """The measurement the design rests on, re-taken by the suite rather than remembered.

    ESP and SCTP between one host pair are two flows in `conn.log` with **identical 5-tuples**
    and different uids, so nothing correlation currently reads can tell them apart — which is
    why step 12 reports rather than guessing.

    But Zeek does record the difference, in a column flabel does not parse: `ip_proto` is 50 and
    132. Asserted here so the limit is recorded as *ours* rather than Zeek's. Correlating these
    properly is possible and is issue #96; until then the honest answer is the one this step
    gives, and a comment claiming the data does not exist would have been wrong.
    """
    capture = write_two_unsupported_transports_pcap(tmp_path / "both.pcap")
    rundir = label(esp_snapshot(tmp_path), tmp_path / "out", capture)

    fields: list[str] = []
    rows: list[dict[str, str]] = []
    for line in (rundir / "zeek" / "conn.log").read_text(encoding="utf-8").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#"):
            rows.append(dict(zip(fields, line.split("\t"), strict=False)))

    tuples = {
        (r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"], r["proto"]) for r in rows
    }

    assert len(rows) == 2, "two conversations"
    assert len(tuples) == 1, "one 5-tuple — which is why step 12 refuses to guess between them"
    assert len({r["uid"] for r in rows}) == 2
    assert {r["ip_proto"] for r in rows} == {"50", "132"}, (
        "Zeek does distinguish them; flabel's Flow carries no ip_proto (issue #96)"
    )
