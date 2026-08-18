"""CLI surface and pipeline orchestration (docs/spec.md §12, PLAN.md step 9).

Two layers here, and the split is deliberate.

The **orchestration** tests replace one stage with a stub that raises, because step 9's job is
not to make Zeek fail — it is to do the right thing *when* a stage fails, and every one of
those paths is about which files exist afterwards. Provoking a real OOM kill or a real
correlation-gate breach through the toolchain would test steps 5–7 again and leave step 9's
actual behaviour — run.json written, labels.json absent — asserted by accident.

The **end-to-end** tests run the real pipeline over the benign canary and carry
``requires_tools``. They are what proves the wiring itself, which no stub can.

The rule of the file: every failure test asserts *both* halves of issue #23 — the loss is
readable by a script, and nothing claims a verdict.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flabel import cli
from flabel.errors import (
    EXIT_FAILURE,
    EXIT_NOT_IMPLEMENTED,
    EXIT_SUCCESS,
    EXIT_USAGE,
    CorrelationError,
    ToolError,
)
from flabel.models import (
    CorrelationResult,
    Detection,
    Flow,
    SourceAdmission,
    SourceSpec,
    ToolFailure,
    UnmatchedDetection,
    ZeekRunInfo,
)
from flabel.rules.snapshot import write_snapshot

FIXTURES = Path(__file__).resolve().parent / "fixtures"
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))

import make_awkward as awkward  # noqa: E402  (needs the path entry above)
import make_canary as canary  # noqa: E402

BENIGN = FIXTURES / "benign.pcap"
SYNTHETIC_RULES = FIXTURES / "rules" / "synthetic.rules"


# --- fixture construction -------------------------------------------------------------------
#
# Snapshots are written by step 4's real `write_snapshot`, never hand-assembled, for the reason
# `tests/test_suricata.py` gives at its own copy of this helper: a hand-built snapshot agrees
# with the reader by construction, which is exactly the disagreement worth catching. The two
# copies are deliberate rather than shared — a fixture helper in `conftest.py` would be a step-1
# file, and these two steps want different source names in their snapshots.


def rule_lines() -> dict[int, str]:
    """The synthetic fixture rules, keyed by SID."""
    lines = {}
    for line in SYNTHETIC_RULES.read_text(encoding="utf-8").splitlines():
        if not line.startswith("alert"):
            continue
        match = re.search(r"\bsid:(\d+);", line)
        assert match is not None, f"synthetic rule has no sid: {line}"
        lines[int(match.group(1))] = line
    return lines


RULES = rule_lines()

#: The rule that matches the benign canary's HTTP flow (10.0.0.5:49152 -> 10.0.0.200:80), so a
#: run over `benign.pcap` produces exactly one label and a NOTICE with content in it.
MATCHES_CANARY = 9000001

#: `alert ip any any -> any any` — fires on any IP protocol, including the ones Zeek cannot
#: name in `transport_proto` (issue #84). Used here to produce a *tolerated* correlation loss.
ANY_IP_PROTOCOL = 9000010


def make_snapshot(
    root: Path,
    contents: Mapping[str, Sequence[int]],
    created_at: str = "2026-08-12T00:00:00.000000Z",
) -> Path:
    """A real snapshot under `root`, from `contents` (source name -> SIDs).

    `created_at` is a parameter because `load_snapshot(root, None)` orders by it: a test with two
    snapshots that shared a timestamp would be resolved by snapshot-id tiebreak, i.e. by content
    hash, and would pass or fail depending on which random-looking id sorted higher.
    """
    admitted = {name: [RULES[sid] for sid in sorted(contents[name])] for name in sorted(contents)}
    admissions = [
        SourceAdmission(
            name=name,
            url=f"https://example.invalid/{name}.rules",
            licence="MIT",
            source_class="signature",
            admission_basis="wholesale",
            rules_fetched=len(rules),
            rules_admitted=len(rules),
            rules_excluded_no_confidence=0,
            rules_excluded_low_confidence=0,
            rules_excluded_low_severity=0,
            rules_excluded_commented=0,
            ja4_rules_admitted=0,
            ja3_rules_admitted=0,
            fetched_at="2026-08-12T00:00:00.000000Z",
        )
        for name, rules in admitted.items()
    ]
    manifest = write_snapshot(root, admitted, admissions, created_at=created_at)
    return root / manifest.snapshot_id


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """A rules root holding one snapshot whose single rule matches the benign canary."""
    root = tmp_path / "rules"
    make_snapshot(root, {"et/open": [MATCHES_CANARY]})
    return root


def offline(capture: Path, rules_dir: Path, output_dir: Path, *extra: str) -> list[str]:
    """The argv for an ordinary labelling run, so a test names only what it varies."""
    return [
        "--offline",
        str(capture),
        "--rules-dir",
        str(rules_dir),
        "--output-dir",
        str(output_dir),
        *extra,
    ]


def run_dirs(output_dir: Path) -> list[Path]:
    """The run directories under `output_dir`, in name order."""
    return sorted(path for path in output_dir.iterdir() if path.is_dir())


def only_run_dir(output_dir: Path) -> Path:
    directories = run_dirs(output_dir)
    assert len(directories) == 1, f"expected exactly one run directory, found {directories}"
    return directories[0]


def snapshot_id_of(rules_dir: Path) -> str:
    """The id of the one snapshot under `rules_dir`, which is also its directory name."""
    directories = [path for path in rules_dir.iterdir() if path.is_dir()]
    assert len(directories) == 1, f"expected exactly one snapshot, found {directories}"
    return directories[0].name


# --- the no-network guard -------------------------------------------------------------------


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if flabel's own code opens a socket (spec §2.2).

    Guards the Python package, which is the claim spec §2.2 actually makes: only
    `flabel rules update` performs network I/O. Zeek and Suricata are separate processes with
    their own sockets, and this cannot see them — nor should it, since they are handed a file
    and never a URL.
    """

    def deny(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            "a labelling run attempted a network connection; spec §2.2 permits network I/O "
            "only in `flabel rules update`, and Goal 2 depends on it"
        )

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "create_connection", deny)


# --- usage: the threshold is rejected at parse time (#59) -------------------------------------
#
# `correlate._check_threshold` is a sharp guard in the wrong place: it fires after ingest, Zeek
# and Suricata have run, and it raises `ValueError`, which maps to exit 1. So a typo cost the
# whole pipeline — up to the ~35 minutes issue #56 measured — and then reported "the run failed"
# rather than "you invoked it wrong". Validating in an argparse `type=` callable moves both.


@pytest.mark.parametrize(
    "value",
    ["nan", "inf", "-inf", "1.5", "-0.1", "abc", "", "1e400"],
)
def test_a_bad_unmatched_threshold_exits_2_before_anything_runs(
    value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec §12 assigns 2 to usage errors, and argv is readable before any tool starts (#59).

    `nan` is the sharp one: every comparison against it is `False`, so the unmatched gate would
    be silently switched off and the run would exit 0 having discarded any proportion of the
    detections. `1e400` is `inf` by another spelling, which a plain range check would miss.
    """

    def never(*args: object, **kwargs: object) -> None:
        raise AssertionError("the pipeline ran before the threshold was validated")

    monkeypatch.setattr(cli, "load_snapshot", never)
    monkeypatch.setattr(cli, "normalize", never)

    with pytest.raises(SystemExit) as raised:
        cli.main(offline(BENIGN, tmp_path / "rules", tmp_path, "--unmatched-threshold", value))

    assert raised.value.code == EXIT_USAGE


@pytest.mark.parametrize("value", ["0", "0.01", "1", "0.5"])
def test_a_valid_unmatched_threshold_is_accepted(value: str) -> None:
    """The guard must not reject the range it exists to defend."""
    args = cli.build_parser().parse_args(["--offline", "x.pcap", "--unmatched-threshold", value])
    assert args.unmatched_threshold == float(value)


def test_the_threshold_default_is_the_specs(tmp_path: Path) -> None:
    """Spec §12 fixes it at 0.01, and correlate.py must not hold a second copy of that number."""
    from flabel.correlate import DEFAULT_THRESHOLD

    args = cli.build_parser().parse_args(["--offline", "x.pcap"])
    assert args.unmatched_threshold == DEFAULT_THRESHOLD == 0.01


# --- the default path is tier 1 (Phase 2, #122) ----------------------------------------------


def test_the_default_path_is_no_longer_a_stub(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`flabel <capture>` runs tier 1 (Craig, 2026-08-17), and still does after #132.

    With no device configured it fails for the reason it actually has — missing configuration —
    rather than announcing an unbuilt feature. Exit 3 was "not implemented"; there is nothing
    unimplemented left to report.

    #132 narrowed the default from tier 1 + tier 2 to tier 1 alone, which leaves this test's
    subject untouched: both defaults need the device, so both fail here for the same reason. The
    tests that can tell the two defaults apart are in "the three modes" below, and they had to be
    written — this one passes under either.
    """
    monkeypatch.delenv("FLABEL_INLINE_HOST", raising=False)
    monkeypatch.delenv("FLABEL_INLINE_API_KEY", raising=False)
    monkeypatch.delenv("FLABEL_INLINE_API_KEY_FILE", raising=False)

    code = cli.main([str(BENIGN), "--output-dir", str(tmp_path)])

    assert code != EXIT_NOT_IMPLEMENTED
    captured = capsys.readouterr()
    assert cli.STUB_MESSAGE not in captured.err
    assert "FLABEL_INLINE_HOST" in captured.err


def test_an_unconfigured_tier_1_run_names_the_offline_alternative(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator must not be left guessing at a capability that does work without a device."""
    monkeypatch.delenv("FLABEL_INLINE_HOST", raising=False)
    monkeypatch.delenv("FLABEL_INLINE_API_KEY", raising=False)
    monkeypatch.delenv("FLABEL_INLINE_API_KEY_FILE", raising=False)

    cli.main([str(BENIGN), "--output-dir", str(tmp_path)])

    assert "--offline" in capsys.readouterr().err


def test_a_tier_1_run_that_cannot_reach_a_device_writes_no_run_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec §13: a run directory is complete or absent.

    Configuration is resolved before any stage runs, so an unconfigured tier-1 invocation leaves
    nothing behind — the same contract the stub had, for a different reason.
    """
    monkeypatch.delenv("FLABEL_INLINE_HOST", raising=False)
    monkeypatch.delenv("FLABEL_INLINE_API_KEY", raising=False)
    monkeypatch.delenv("FLABEL_INLINE_API_KEY_FILE", raising=False)

    cli.main([str(BENIGN), "--output-dir", str(tmp_path)])

    assert list(tmp_path.iterdir()) == []


def test_the_stub_leaves_stdout_untouched(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Spec §12 reserves stdout. A message on it would become someone's parse target."""
    cli.main([str(BENIGN), "--output-dir", str(tmp_path)])

    assert capsys.readouterr().out == ""


# --- failures that happen before a run directory can exist ------------------------------------
#
# Spec §12's exit-1 row names two: a missing snapshot and an unreadable capture. Both are
# refusals to start rather than runs that died, so there is nothing to report about a run and a
# directory holding only a `run.json` saying "nothing happened" would be noise on disk.


def test_a_missing_snapshot_exits_1_and_creates_no_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Spec §11's `snapshot missing` loss condition, and spec §7: never fall back to another."""
    output = tmp_path / "out"
    output.mkdir()

    code = cli.main(
        offline(BENIGN, tmp_path / "rules", output, "--ruleset-snapshot", "0123456789abcdef")
    )

    assert code == EXIT_FAILURE
    assert list(output.iterdir()) == []
    assert capsys.readouterr().err != ""


def test_an_unreadable_capture_exits_1_and_creates_no_directory(
    tmp_path: Path, rules_dir: Path
) -> None:
    """The second pre-directory failure spec §12 names."""
    output = tmp_path / "out"
    output.mkdir()

    code = cli.main(offline(tmp_path / "not-a-capture.pcap", rules_dir, output))

    assert code == EXIT_FAILURE
    assert list(output.iterdir()) == []


# --- a stage that dies mid-run: run.json, and no labels.json (#23) ----------------------------


def zeek_that_dies(monkeypatch: pytest.MonkeyPatch, failure: ToolFailure) -> None:
    """Replace the Zeek stage with one that fails exactly as step 5 promises it will."""
    info = ZeekRunInfo(
        version="8.0.9",
        flags=("-C", "-D"),
        log_dir=Path("zeek"),
        tool_failures=(failure,),
    )

    def boom(capture: Path, outdir: Path) -> None:
        outdir.mkdir(parents=True, exist_ok=True)
        raise ToolError("zeek killed by signal 9", failures=(failure,), run_info=info)

    monkeypatch.setattr(cli, "run_zeek", boom)


OOM = ToolFailure(
    tool="zeek",
    argv=("zeek", "-C", "-D", "-r", "capture.pcap"),
    exit_code=None,
    message="zeek killed by signal 9 (an OOM kill arrives as SIGKILL)",
)


def test_a_tool_failure_writes_run_json_and_no_labels_json(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """Both halves of issue #23, which is the whole point of the decision.

    Spec §11 requires the failure recorded; spec §13 forbids a partial `labels.json`. The array
    therefore lives in a document that may exist — and the *absence* of `labels.json` is the
    signal, because a consumer can test for a missing file but has to be told to read a status
    field inside one.
    """
    zeek_that_dies(monkeypatch, OOM)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert (rundir / "run.json").is_file()
    assert not (rundir / "labels.json").exists(), "a dead run must claim no verdict"


def test_the_tool_failure_is_readable_by_a_script(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rejected alternative was stderr only, which makes a caller parse prose.

    `ToolError.failures` exists to carry the argv, the exit code and whether the tool was
    killed rather than exited. Catching the exception and printing `str(exc)` would throw all
    three away at the moment they became the point.
    """
    zeek_that_dies(monkeypatch, OOM)
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    run = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))
    failures = run["run"]["tool_failures"]
    assert len(failures) == 1
    assert failures[0]["tool"] == "zeek"
    assert failures[0]["argv"] == list(OOM.argv)
    # None, not 0: a killed process has no exit code, and reporting one would invent it.
    assert failures[0]["exit_code"] is None
    assert "signal 9" in failures[0]["message"]


def test_a_dead_run_still_records_the_ruleset_it_attempted(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed run that cannot say what it tried is a worse artifact than one that reports both."""
    zeek_that_dies(monkeypatch, OOM)
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    run = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))
    assert run["run"]["ruleset"]["snapshot_id"] == snapshot_id_of(rules_dir)
    assert run["run"]["input"]["path"] == str(BENIGN)


def test_a_stage_that_never_ran_is_null_not_zero(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec §10: `null` distinguishes "not measured" from "measured as none".

    Zero detections from a Suricata pass that never happened is a claim about the capture. It
    is the §2.5 failure mode in the run block itself.
    """
    zeek_that_dies(monkeypatch, OOM)
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    run = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))
    assert run["run"]["counts"]["detections"] is None
    assert run["run"]["counts"]["labels"] is None


# --- the correlation gate: the unmatched records survive the failure (Craig, 2026-08-13) ------


def gate_failure() -> CorrelationError:
    """The gate firing over detections that could not be placed."""
    detection = Detection(
        source="et/open",
        tier=2,
        sid=MATCHES_CANARY,
        rev=3,
        classtype="trojan-activity",
        app_proto="http",
        threat="FLABEL TEST synthetic HTTP request",
        ts=1700000000.0,
        src_ip="10.0.0.5",
        src_port=49152,
        dst_ip="10.0.0.200",
        dst_port=80,
        proto="tcp",
        direction="to_server",
    )
    result = CorrelationResult(
        labels=(),
        unmatched=(UnmatchedDetection(detection=detection, reason="no_flow_match"),),
        flows_total=2,
        detections_total=1,
    )
    return CorrelationError("1 of 1 detections unplaced (100.0%)", result=result)


def test_the_gate_failure_writes_the_unmatched_records_into_run_json(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run.json` is `labels.json` minus the verdicts (Craig, 2026-08-13).

    The gate fires *because* detections went unplaced, so a run.json carrying only
    `counts.unmatched` would report the scale of the loss and not its content — and the reason
    is the diagnosis: `no_flow_match` is a tuple-normalisation bug, `ambiguous_flow_match` is
    port reuse. They are different faults in different modules.
    """
    error = gate_failure()
    monkeypatch.setattr(cli, "correlate", lambda *args, **kwargs: (_ for _ in ()).throw(error))
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists()
    document = json.loads((rundir / "run.json").read_text(encoding="utf-8"))
    assert [item["reason"] for item in document["unmatched_detections"]] == ["no_flow_match"]
    assert document["unmatched_detections"][0]["detection"]["sid"] == MATCHES_CANARY


def test_run_json_never_carries_an_empty_labels_array(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rejected alternative, and the reason the whole file exists (#23).

    `"labels": []` reads as "nothing malicious was found" when the pipeline in fact died. A
    consumer training on the output cannot tell it from a clean capture. The key is *absent*,
    not empty.
    """
    monkeypatch.setattr(
        cli, "correlate", lambda *args, **kwargs: (_ for _ in ()).throw(gate_failure())
    )
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    document = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))
    assert "labels" not in document
    assert document["schema_version"] == "1.0"
    assert "run" in document


# --- the snapshot Suricata ran must be the snapshot correlation is given (PLAN step 9) --------


def test_a_snapshot_id_disagreement_fails_the_run(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run_suricata` returns only an id, so step 9 loads the snapshot a second time.

    With `--ruleset-snapshot` defaulting to "newest available", a `rules update` landing between
    the two loads resolves a *different* snapshot — and every label then cites a ruleset whose
    rules never ran. The assertion is one line; without it the two loads are silently allowed to
    disagree, and the output is well-formed and wrong.
    """

    def wrong_snapshot(capture: Path, snapshot: Path, outdir: Path):
        from flabel.models import SuricataRunInfo

        outdir.mkdir(parents=True, exist_ok=True)
        return [], SuricataRunInfo(
            version="8.0.6",
            snapshot_id="ffffffffffffffff",
            rules_loaded=1,
            alerts_total=0,
        )

    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(cli, "run_suricata", wrong_snapshot)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists()
    assert (rundir / "run.json").is_file()


def _zeek_ok(outdir: Path) -> tuple[dict[str, Flow], ZeekRunInfo]:
    """A Zeek stage that succeeded with no flows — enough to reach the stages under test."""
    outdir.mkdir(parents=True, exist_ok=True)
    return {}, ZeekRunInfo(version="8.0.9", flags=("-C", "-D"), log_dir=outdir)


def _total_admitted(rules_dir: Path) -> int:
    """What the snapshot says it admitted, read from the manifest rather than assumed.

    A literal here would agree with the fixture by construction and stop agreeing the moment the
    fixture gained a rule — which is how a stub starts reporting a shortfall nobody intended.
    """
    manifest = json.loads(
        (rules_dir / snapshot_id_of(rules_dir) / "manifest.json").read_text(encoding="utf-8")
    )
    return manifest["total_admitted"]


def _suricata_ok(rules_dir: Path, snapshot_id: str | None = None):
    """A Suricata stage that loaded the whole snapshot cleanly and found nothing.

    `snapshot_id` overrides the real one, which is how the mid-run `rules update` is simulated.
    """
    from flabel.models import SuricataRunInfo

    resolved = snapshot_id or snapshot_id_of(rules_dir)
    loaded = _total_admitted(rules_dir)

    def run(capture: Path, snapshot: Path, outdir: Path):
        outdir.mkdir(parents=True, exist_ok=True)
        return [], SuricataRunInfo(
            version="8.0.6",
            snapshot_id=resolved,
            rules_loaded=loaded,
            alerts_total=0,
        )

    return run


# --- the rules shortfall: warn, quantify, and never block a non-TTY (#46) ---------------------


def suricata_with_shortfall(monkeypatch: pytest.MonkeyPatch, snapshot_id: str) -> None:
    """A Suricata pass that loaded fewer rules than the snapshot admitted."""
    from flabel.models import SuricataRunInfo

    def short(capture: Path, snapshot: Path, outdir: Path):
        outdir.mkdir(parents=True, exist_ok=True)
        return [], SuricataRunInfo(
            version="8.0.6",
            snapshot_id=snapshot_id,
            rules_loaded=1,
            alerts_total=0,
            rules_failed=1,
            rules_skipped=0,
            warnings=("1 of 2 rules (50.00%) did not load: 1 failed, 0 skipped.",),
        )

    monkeypatch.setattr(cli, "run_suricata", short)


@pytest.fixture
def two_rule_snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "rules"
    make_snapshot(root, {"et/open": [MATCHES_CANARY, 9000006]})
    return root


def test_a_shortfall_without_a_tty_proceeds_and_never_blocks(
    tmp_path: Path,
    two_rule_snapshot: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """flabel runs in CI, cron and `set -e` scripts (#46).

    "Default yes" is the answer for the case where nobody can be asked. A prompt there either
    hangs the pipeline or blocks step 10's own gates, and the fault would look like a hang
    rather than a question.
    """
    snapshot = snapshot_id_of(two_rule_snapshot)
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot)
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: False)

    def never(*args: object, **kwargs: object) -> str:
        raise AssertionError("a non-interactive run must never wait on a prompt")

    monkeypatch.setattr("builtins.input", never)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, two_rule_snapshot, output))

    assert code == EXIT_SUCCESS
    assert (only_run_dir(output) / "labels.json").is_file()


def test_a_shortfall_is_recorded_in_the_run_block_either_way(
    tmp_path: Path, two_rule_snapshot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-interactive run must never lose the fact that rules went missing (spec §2.5)."""
    snapshot = snapshot_id_of(two_rule_snapshot)
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot)
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: False)
    output = tmp_path / "out"

    cli.main(offline(BENIGN, two_rule_snapshot, output))

    document = json.loads((only_run_dir(output) / "labels.json").read_text(encoding="utf-8"))
    assert document["run"]["counts"]["rules_failed"] == 1
    assert any("did not load" in warning for warning in document["run"]["warnings"])


def test_a_shortfall_shows_the_count_and_the_percentage(
    tmp_path: Path,
    two_rule_snapshot: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ "N rules failed" alone does not tell an operator whether to care (#46).

    26 of 85,431 is a curiosity; 26 of 40 is a broken snapshot. The percentage is what makes
    the number answerable, and it is why no threshold was invented in its place.
    """
    snapshot = snapshot_id_of(two_rule_snapshot)
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot)
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: False)

    cli.main(offline(BENIGN, two_rule_snapshot, tmp_path / "out"))

    err = capsys.readouterr().err
    assert "50.00%" in err
    assert "did not load" in err


def test_declining_the_prompt_stops_the_run_and_claims_no_verdict(
    tmp_path: Path, two_rule_snapshot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator decides in the moment, with the loss quantified in front of them (#46).

    Declining is a deliberate stop, so it exits 1 with no `labels.json` — a partial ruleset
    that the operator judged unacceptable must not leave behind labels that look complete.
    """
    snapshot = snapshot_id_of(two_rule_snapshot)
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot)
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: True)
    monkeypatch.setattr(cli, "prompt_is_visible", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, two_rule_snapshot, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists()
    assert (rundir / "run.json").is_file()


@pytest.mark.parametrize("answer", ["", "y", "Y", "yes", "  "])
def test_the_prompt_defaults_to_yes(
    answer: str, tmp_path: Path, two_rule_snapshot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Y/n` with a capital Y means bare Enter continues (#46)."""
    snapshot = snapshot_id_of(two_rule_snapshot)
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot)
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: True)
    monkeypatch.setattr(cli, "prompt_is_visible", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)

    code = cli.main(offline(BENIGN, two_rule_snapshot, tmp_path / "out"))

    assert code == EXIT_SUCCESS


def test_no_shortfall_asks_nothing(
    tmp_path: Path,
    rules_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Spec §9's habit, applied here: silence means nothing was lost.

    A prompt on every run would train the operator to answer it without reading, which is the
    same as not asking.
    """
    from flabel.models import SuricataRunInfo

    snapshot = snapshot_id_of(rules_dir)
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(
        cli,
        "run_suricata",
        lambda capture, snap, outdir: (
            outdir.mkdir(parents=True, exist_ok=True),
            (
                [],
                SuricataRunInfo(
                    version="8.0.6", snapshot_id=snapshot, rules_loaded=1, alerts_total=0
                ),
            ),
        )[1],
    )

    def never(*args: object, **kwargs: object) -> str:
        raise AssertionError("nothing was lost, so nothing should be asked")

    monkeypatch.setattr("builtins.input", never)
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: True)
    monkeypatch.setattr(cli, "prompt_is_visible", lambda: True)

    assert cli.main(offline(BENIGN, rules_dir, tmp_path / "out")) == EXIT_SUCCESS


# --- run directory naming -------------------------------------------------------------------


def test_the_run_directory_is_named_for_the_capture_and_the_time() -> None:
    """Spec §1: `{capture-name}_{datetime}/`."""
    when = datetime(2026, 8, 13, 14, 25, 30, 123456, tzinfo=UTC)

    assert cli.run_directory_name(Path("/tmp/benign.pcap"), when).startswith("benign_")


@pytest.mark.parametrize(
    "name, expected",
    [
        ("benign.pcap", "benign"),
        ("benign.pcapng", "benign"),
        ("benign.pcap.gz", "benign"),
        ("benign.pcapng.gz", "benign"),
        ("capture", "capture"),
        ("my.capture.2026.pcap", "my.capture.2026"),
    ],
)
def test_every_capture_suffix_is_stripped_from_the_run_directory_name(
    name: str, expected: str
) -> None:
    """A directory called `benign.pcap_2026...` reads as a file, and `.pcap.gz` is two suffixes.

    Only the container suffixes are stripped. `my.capture.2026.pcap` keeps its dots, because
    they are the operator's naming and not ours to reinterpret.
    """
    when = datetime(2026, 8, 13, 14, 25, 30, 123456, tzinfo=UTC)

    assert cli.run_directory_name(Path(name), when).split("_")[0] == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (".pcap", "capture"),  # the whole name is the suffix
        (".pcapng", "capture"),
        (".pcap.gz", "capture"),
        ("..pcap", "capture"),  # stripping leaves a bare dot
        (".hidden.pcap", "hidden"),  # a genuinely hidden input still gets a findable output
        ("...pcap", "capture"),
    ],
)
def test_a_run_directory_is_never_hidden_from_ls(name: str, expected: str) -> None:
    """An operator who cannot find their output has lost it (#95).

    The guard used to be `len(name) > len(suffix)`, so a capture named exactly `.pcap` kept its
    name and produced `.pcap_2026…Z` — invisible to `ls`, and the run looks like it produced
    nothing. That guard was also redundant: `or "capture"` already covered the empty case it
    was protecting against.

    The run directory is flabel's output, not the operator's file, so a name that hides it is
    ours to reject. Dots *inside* the name stay — see the test above.
    """
    when = datetime(2026, 8, 13, 14, 25, 30, 123456, tzinfo=UTC)

    directory = cli.run_directory_name(Path(name), when)

    assert not directory.startswith("."), f"{name!r} produced a hidden run directory: {directory}"
    assert directory.split("_")[0] == expected


def test_run_directory_names_sort_chronologically() -> None:
    """PLAN step 9. `ls` is how an operator finds the latest run, so name order is time order."""
    early = cli.run_directory_name(Path("c.pcap"), datetime(2026, 8, 13, 9, 5, 0, 0, tzinfo=UTC))
    late = cli.run_directory_name(Path("c.pcap"), datetime(2026, 8, 13, 10, 5, 0, 0, tzinfo=UTC))

    assert early < late
    # The trap this guards: a non-zero-padded hour would sort "10:05" before "9:05".
    assert "T090500" in early


# --- end to end, with the real toolchain ------------------------------------------------------


@pytest.mark.requires_tools
def test_offline_over_the_benign_canary_writes_a_complete_run_directory(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """PLAN step 9's headline test, and the first time the whole pipeline runs as one thing."""
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_SUCCESS
    rundir = only_run_dir(output)
    assert (rundir / "zeek").is_dir()
    assert (rundir / "zeek" / "conn.log").is_file()
    assert (rundir / "labels.json").is_file()
    assert (rundir / "run.json").is_file()
    assert (rundir / "NOTICE").is_file()


@pytest.mark.requires_tools
def test_the_end_to_end_run_labels_the_flow_the_rule_matched(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """A run directory that exists proves wiring; a label proves the wiring carries meaning.

    **Two labels, not one, and that is the fixture being right rather than the rule being
    loose.** Both of the canary's flows are cleartext HTTP to port 80 — flow 2 was moved there
    from 443 in #42, because HTTP on 443 legitimately trips pawpatrules 3300303 and a canary
    whose value is that zero labels is known-correct must not itself carry anomalous traffic.
    So the rule matches both, and this asserts consolidation across two flows: one label each,
    one source entry each, never one label carrying both flows' detections.
    """
    output = tmp_path / "out"
    cli.main(offline(BENIGN, rules_dir, output))

    document = json.loads((only_run_dir(output) / "labels.json").read_text(encoding="utf-8"))
    assert len(document["labels"]) == 2
    assert len({label["flow"]["uid"] for label in document["labels"]}) == 2
    for label in document["labels"]:
        assert label["verdict"] == "malicious"
        assert label["best_tier"] == 2
        assert len(label["sources"]) == 1
        assert label["sources"][0]["sid"] == MATCHES_CANARY
        assert label["sources"][0]["ruleset"] == snapshot_id_of(rules_dir)
        assert label["sources"][0]["label_basis"] == "direct"

    # Spec §10: sorted by (ts_first, uid), so two runs cannot order them differently.
    keys = [(label["flow"]["ts_first"], label["flow"]["uid"]) for label in document["labels"]]
    assert keys == sorted(keys)


@pytest.mark.requires_tools
def test_the_direction_reaches_labels_json_from_the_engine(
    tmp_path: Path, no_network: None
) -> None:
    """Issue #115 end to end: eve.json says which way, and `labels.json` says the same.

    `alert ip any any -> any any` matches every packet of the canary's two HTTP flows, so each
    flow is labelled with **both** a `to_server` entry (the request) and a `to_client` one (the
    response) — from one rule, on one flow. Nothing else in the suite asserts both values
    survive the whole pipeline, and the pipeline is where the value can be lost: a
    `build_source_entry` that stopped reading `detection.direction`, or a `suricata.py` that
    stopped parsing it, leaves every unit test in `test_provenance.py` green.

    Asserted against eve.json rather than against a literal, so the test cannot drift into
    agreeing with a hardcoded default.
    """
    output = tmp_path / "out"
    rules = tmp_path / "rules"
    make_snapshot(rules, {"et/open": [ANY_IP_PROTOCOL]})

    assert cli.main(offline(BENIGN, rules, output)) == EXIT_SUCCESS

    rundir = only_run_dir(output)
    document = json.loads((rundir / "labels.json").read_text(encoding="utf-8"))
    entries = [entry for label in document["labels"] for entry in label["sources"]]
    assert entries, "no source entries, so this asserts nothing"

    reported = [
        json.loads(line)["direction"]
        for line in (rundir / "suricata" / "eve.json").read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line)["event_type"] == "alert"
    ]
    assert sorted(entry["direction"] for entry in entries) == sorted(reported), (
        "labels.json does not carry the directions the engine reported"
    )
    assert {"to_server", "to_client"} <= set(reported), (
        "the fixture stopped producing both directions, so the assertion above is weaker than "
        "it reads — a rule matching only requests would pass it"
    )


@pytest.mark.requires_tools
def test_the_end_to_end_notice_attributes_the_source_that_labelled(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """NOTICE describes what was *used*, and it is the artifact carrying legal weight."""
    output = tmp_path / "out"
    cli.main(offline(BENIGN, rules_dir, output))

    notice = (only_run_dir(output) / "NOTICE").read_text(encoding="utf-8")
    assert "et/open" in notice
    assert "MIT" in notice


@pytest.mark.requires_tools
def test_run_json_and_labels_json_carry_the_same_run_block(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """One run, one run block. Two assemblies would let `finished_at` differ between the files.

    Not cosmetic: they are two records of one fact, and the copy that drifts is the one a
    reader trusts.
    """
    output = tmp_path / "out"
    cli.main(offline(BENIGN, rules_dir, output))

    rundir = only_run_dir(output)
    labels = json.loads((rundir / "labels.json").read_text(encoding="utf-8"))
    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))
    assert labels["run"] == run["run"]


@pytest.mark.requires_tools
def test_rerunning_creates_a_sibling_and_leaves_the_first_untouched(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """Spec §13: never overwrite or modify a previous run directory."""
    output = tmp_path / "out"

    assert cli.main(offline(BENIGN, rules_dir, output)) == EXIT_SUCCESS
    first = only_run_dir(output)
    original = (first / "labels.json").read_bytes()

    assert cli.main(offline(BENIGN, rules_dir, output)) == EXIT_SUCCESS

    directories = run_dirs(output)
    assert len(directories) == 2
    assert directories == sorted(directories), "run directory names must sort chronologically"
    assert (first / "labels.json").read_bytes() == original


@pytest.mark.requires_tools
def test_the_end_to_end_run_makes_no_network_call(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """Spec §2.2, and the reason Goal 2 is achievable at all.

    Asserted over the real pipeline rather than the stubbed one, because the stubs are exactly
    the stages that would dial out — `zeek --parse-only` probing for JA4, and Suricata reading
    a snapshot.
    """
    assert cli.main(offline(BENIGN, rules_dir, tmp_path / "out")) == EXIT_SUCCESS


@pytest.mark.requires_tools
def test_the_normalized_capture_does_not_survive_the_run(tmp_path: Path, rules_dir: Path) -> None:
    """It lives in a per-run temporary directory (spec §10), so it must not be in the output.

    A copy of the operator's capture inside the run directory would also be capture data
    written outside the one place spec §13 permits it.
    """
    output = tmp_path / "out"
    cli.main(offline(BENIGN, rules_dir, output))

    rundir = only_run_dir(output)
    assert not list(rundir.rglob("normalized.pcap"))


# --- `flabel rules` ---------------------------------------------------------------------------


def _one_local_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point `rules update` at one source whose feed is a local file.

    The registry is narrowed to a single source as well as the transport being replaced. Nine
    copies of one fixture would collide on SID — every feed would claim the same rules — and the
    resulting `sid_index` failure would be an artifact of the test rather than anything about
    the code under it.
    """
    spec = SourceSpec(
        name="et/open",
        url="https://example.invalid/et-open.rules",
        licence="MIT",
        source_class="signature",
        admission_basis="wholesale",
    )
    text = SYNTHETIC_RULES.read_text(encoding="utf-8")
    monkeypatch.setattr(cli, "enabled_sources", lambda path=None: (spec,))
    monkeypatch.setattr(cli, "fetch_feed", lambda spec, fetcher=None: (text, {}))


def test_rules_list_reports_the_snapshots_on_disk(
    rules_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Spec §12's second subcommand. An operator needs to know what `--ruleset-snapshot` accepts."""
    code = cli.main(["rules", "list", "--rules-dir", str(rules_dir)])

    assert code == EXIT_SUCCESS
    assert snapshot_id_of(rules_dir) in capsys.readouterr().out


def test_rules_list_on_an_empty_rules_dir_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Zero snapshots is a real answer, not a failure — but silence would look like a broken
    command."""
    code = cli.main(["rules", "list", "--rules-dir", str(tmp_path / "empty")])

    assert code == EXIT_SUCCESS
    assert capsys.readouterr().err != ""


def test_rules_update_builds_a_snapshot_from_the_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one network path (spec §2.2), wired end to end with the transport stubbed.

    The feeds themselves are never contacted — spec §2's testing line — so the fetch is replaced
    and everything downstream of it is the real admission and snapshot code.
    """
    _one_local_source(monkeypatch)
    root = tmp_path / "rules"

    code = cli.main(["rules", "update", "--rules-dir", str(root)])

    assert code == EXIT_SUCCESS
    snapshots = [path for path in root.iterdir() if path.is_dir()]
    assert len(snapshots) == 1
    assert (snapshots[0] / "rules.rules").is_file()
    assert (snapshots[0] / "manifest.json").is_file()
    assert (snapshots[0] / "sid_index.json").is_file()


def test_rules_update_reports_what_each_source_yielded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Admission drops rules by design, so a silent update hides how much of a feed survived."""
    _one_local_source(monkeypatch)

    cli.main(["rules", "update", "--rules-dir", str(tmp_path / "rules")])

    err = capsys.readouterr().err
    assert "et/open" in err
    assert "admitted" in err


def test_rules_is_a_subcommand_not_a_capture_name(tmp_path: Path) -> None:
    """`flabel rules ...` dispatches to the subcommand, as `git` does with its own.

    Recorded because it is a real ambiguity: a capture file literally named `rules` has to be
    given as `./rules`. The alternative — inspecting the filesystem to decide what the operator
    meant — would make the command's behaviour depend on the working directory.
    """
    with pytest.raises(SystemExit) as raised:
        cli.main(["rules"])

    assert raised.value.code == EXIT_USAGE


# --- verification round: the failure paths must not lose the failure --------------------------
#
# Every finding below was traced through the code by a fresh reviewer and reproduced here before
# being fixed. The shape they share is the one this project keeps finding: the run *fails*, and
# the artifact it leaves behind does not say so.


def test_an_unexpected_exception_still_writes_run_json(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run.json` is written by EVERY run (#23) — including one that died on a bare ValueError.

    Not hypothetical. `provenance.build_source_entry` raises plain `ValueError` for an empty
    `threat`, and `suricata.py` checks only that the `signature` *key* exists, not that it has a
    value — a gap already recorded in docs/status.yaml from an earlier round. A wholesale-admitted
    feed shipping one rule with `msg:""` would therefore reach correlation, raise, and — before
    this test — escape `except FlabelError` as a traceback, leaving a run directory holding
    `zeek/` and `suricata/` and neither `run.json` nor `labels.json`.

    That is the one state spec §13 does not allow: not a complete run directory, and not none.
    """
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(cli, "run_suricata", _suricata_ok(rules_dir))

    def raises_value_error(*args: object, **kwargs: object) -> None:
        raise ValueError("threat is empty: a label that names no threat has no content")

    monkeypatch.setattr(cli, "correlate", raises_value_error)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE, "an unforeseen crash is a failure, never a success"
    rundir = only_run_dir(output)
    assert (rundir / "run.json").is_file(), "the run directory must never lack its run block"
    assert not (rundir / "labels.json").exists()


def test_the_run_block_records_why_the_run_failed(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `run.json` that reads like a clean run is worse than no `run.json` at all.

    The snapshot-id mismatch is the sharpest case: no tool failed, no detection went unplaced, so
    `tool_failures[]` is empty, every `loss_conditions` flag is false, and — before this test —
    nothing anywhere in the document said the run died. The reason went to stderr only, which is
    exactly what issue #23 rejected: a script would have to parse prose to learn what happened.
    """
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(cli, "run_suricata", _suricata_ok(rules_dir, snapshot_id="f" * 16))
    output = tmp_path / "out"

    assert cli.main(offline(BENIGN, rules_dir, output)) == EXIT_FAILURE

    run = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))["run"]
    assert any("failed" in warning.lower() for warning in run["warnings"]), (
        "a reader of run.json alone must be able to tell the run did not finish"
    )
    assert any("snapshot" in warning.lower() for warning in run["warnings"])


def test_a_successful_labelling_run_leaves_stdout_empty(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """Spec §12 reserves stdout for the pipeline. `input()` writes its prompt there.

    Verified: `input("...")` sends the prompt to `sys.stdout`, not stderr. So with stdout
    redirected — `flabel --offline capture.pcap > run.log`, an ordinary thing to do — the
    shortfall prompt went into the log file and the operator saw a silent terminal and a process
    that looked wedged. The TTY check closed the CI case and left this one open.
    """
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot_id_of(rules_dir))
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: True)
    monkeypatch.setattr(cli, "prompt_is_visible", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    cli.main(offline(BENIGN, rules_dir, tmp_path / "out"))

    captured = capsys.readouterr()
    assert captured.out == "", "the prompt and every message belong on stderr"
    assert "did not load" in captured.err


def test_the_prompt_is_skipped_when_nobody_could_see_it(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A prompt nobody can read is a hang, whichever stream is redirected.

    `stdin.isatty()` alone is not the question — the operator has to *see* the question to answer
    it. With stderr redirected to a file the prompt is invisible even on an interactive stdin,
    which is the same wedged process #46 exists to prevent.
    """
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot_id_of(rules_dir))
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: True)
    monkeypatch.setattr(cli, "prompt_is_visible", lambda: False)

    def never(*args: object, **kwargs: object) -> str:
        raise AssertionError("a prompt nobody can see must never be asked")

    monkeypatch.setattr("builtins.input", never)

    assert cli.main(offline(BENIGN, rules_dir, tmp_path / "out")) == EXIT_SUCCESS


def test_interrupting_the_prompt_stops_the_run_cleanly(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C is at least as likely as typing `n`, and the prompt invites it.

    Treated as declining rather than as a crash: the operator answered the question, just not with
    a keystroke the parser was looking for. A traceback here would leave the run directory with
    neither file.
    """
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    suricata_with_shortfall(monkeypatch, snapshot_id_of(rules_dir))
    monkeypatch.setattr(cli, "stdin_is_a_tty", lambda: True)
    monkeypatch.setattr(cli, "prompt_is_visible", lambda: True)

    def interrupted(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupted)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert (rundir / "run.json").is_file()
    assert not (rundir / "labels.json").exists()


def test_an_editcap_failure_in_ingest_reports_rather_than_vanishing(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The judgment call in this step, and it was previously untested.

    Spec §12's carve-out names "a missing snapshot, an unreadable capture" as the failures that
    leave no run directory. An `editcap` failure is neither — the operator's file was readable —
    so the default applies and the `ToolFailure` records survive on disk.
    """
    failure = ToolFailure(
        tool="editcap",
        argv=("editcap", "-F", "pcap", "in.pcapng", "out.pcap"),
        exit_code=2,
        message="editcap exited non-zero: unsupported encapsulation",
    )

    def boom(capture: Path, workdir: Path) -> None:
        raise ToolError("editcap failed", failures=(failure,), run_info=None)

    monkeypatch.setattr(cli, "normalize", boom)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists()
    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]
    assert [f["tool"] for f in run["tool_failures"]] == ["editcap"]
    assert run["tool_failures"][0]["exit_code"] == 2
    # The stage never ran, so its section is null rather than a zeroed-out claim.
    assert run["input"]["packets_read"] is None


def test_a_suricata_tool_failure_is_reported_like_any_other(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run_suricata` records rather than raises, so step 9 restores the one convention.

    This is the path a zero-rule load takes — the case that stays fatal under #46 — and nothing
    exercised it end to end.
    """
    from flabel.models import SuricataRunInfo

    failure = ToolFailure(
        tool="suricata",
        argv=("suricata", "-r", "capture.pcap"),
        exit_code=0,
        message="suricata loaded none of the snapshot's 2 rules (2 failed, 0 skipped)",
    )

    def failed(capture: Path, snapshot: Path, outdir: Path):
        outdir.mkdir(parents=True, exist_ok=True)
        return [], SuricataRunInfo(
            version="8.0.6",
            snapshot_id=snapshot_id_of(rules_dir),
            rules_loaded=0,
            alerts_total=0,
            tool_failures=(failure,),
        )

    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(cli, "run_suricata", failed)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists()
    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]
    assert [f["tool"] for f in run["tool_failures"]] == ["suricata"]
    assert run["loss_conditions"]["tool_failure"] is True


def test_unmatched_detections_is_null_when_correlation_never_ran(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same empty-array-versus-absent mistake this file exists to prevent, one key down.

    A run that died in Zeek measured no detections at all. `"unmatched_detections": []` there
    reads as "every detection was placed" — spec §2.5's failure mode, and the exact argument
    issue #23 makes about `labels: []`. `counts.unmatched` is already `null` on that path; these
    two are the same fact and must not disagree.
    """
    zeek_that_dies(monkeypatch, OOM)
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    document = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))
    assert document["unmatched_detections"] is None
    assert document["run"]["counts"]["unmatched"] is None


def test_a_successful_run_records_no_unmatched_detections_as_an_empty_list(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half: correlation ran and placed everything, which is a measurement of zero."""
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(cli, "run_suricata", _suricata_ok(rules_dir))
    output = tmp_path / "out"

    assert cli.main(offline(BENIGN, rules_dir, output)) == EXIT_SUCCESS

    document = json.loads((only_run_dir(output) / "run.json").read_text(encoding="utf-8"))
    assert document["unmatched_detections"] == []
    assert "labels" not in document


def test_a_failure_while_writing_notice_leaves_no_labels_and_an_honest_run_json(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`labels.json` is written last, but `run.json` was written first and claimed success.

    `notice.render_notice` raises on a source under two licences or absent from the manifest. If
    that fires after `run.json` is on disk, the directory is left with a run block reporting
    labels, no loss conditions and no failures — beside no `labels.json`. That is "report full
    coverage when a loss condition fired" in the one file left standing.
    """
    monkeypatch.setattr(cli, "run_zeek", lambda capture, outdir: _zeek_ok(outdir))
    monkeypatch.setattr(cli, "run_suricata", _suricata_ok(rules_dir))

    def boom(*args: object, **kwargs: object) -> bytes:
        raise ValueError("et/open appears under two licences")

    monkeypatch.setattr(cli, "render_notice_bytes", boom)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, rules_dir, output))

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists()
    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]
    assert any("licence" in warning.lower() for warning in run["warnings"]), (
        "run.json must not survive as a record of a run that succeeded"
    )


# --- atomic output (issue #70, PLAN step 13b) ----------------------------------------------


def test_a_failed_write_leaves_no_artifact_and_no_temporary(tmp_path: Path):
    """Spec §13: either a complete run directory exists or none does.

    A plain `write_bytes` interrupted part-way leaves a truncated JSON document, which parses as
    neither a valid result nor an absent one — the single state §13 names. Since the *absence* of
    `labels.json` is what a consumer reads as "this run did not finish" (issue #23), a
    half-written one is worse than no file.

    Injected at the boundary rather than by killing a process: `serialise_bytes` has already
    produced the payload, so the failure is in the write itself, which is the case that matters.
    """
    from flabel import cli as cli_module

    target = tmp_path / "labels.json"
    original = Path.write_bytes

    def explode(self: Path, payload: bytes) -> int:
        if self.name.endswith(".partial"):
            original(self, payload[: len(payload) // 2])
            raise OSError(28, "No space left on device")
        return original(self, payload)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "write_bytes", explode)
        with pytest.raises(OSError, match="No space left"):
            cli_module._write_atomic(target, b'{"schema_version": 1}')

    assert not target.exists(), "a failed write must not leave a partial document behind"
    assert list(tmp_path.iterdir()) == [], (
        "the temporary must be cleaned up, or a later reader mistakes it for state"
    )


def test_the_temporary_is_named_so_the_reproducibility_gate_ignores_it(tmp_path: Path):
    """`canonical` compares the documents a run claims; a leftover temporary is not one.

    Asserted on the name rather than trusting the cleanup above, because the cleanup cannot run
    if the process is killed outright — which is the failure this whole change is about.
    """
    from flabel import cli as cli_module

    seen: list[str] = []
    original = Path.write_bytes

    def record(self: Path, payload: bytes) -> int:
        seen.append(self.name)
        return original(self, payload)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "write_bytes", record)
        cli_module._write_atomic(tmp_path / "labels.json", b"{}")

    assert seen == [".labels.json.partial"], f"unexpected write sequence: {seen}"
    assert (tmp_path / "labels.json").read_bytes() == b"{}"
    assert not (tmp_path / ".labels.json.partial").exists()


@pytest.mark.requires_tools
def test_a_clock_stepping_backwards_still_writes_run_json(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Issue #62's actual cost was the file, so the file is what this asserts.

    `_duration` raised on a negative elapsed time, and `build_run_block` raises while the report
    is being assembled — so an NTP step or a VM resume during a run left a directory with no
    `run.json`, the one thing spec §10 says every run writes. A unit test on the block would have
    passed throughout: the block was never the thing that went missing.

    The clock is stepped between the run's two `datetime.now(UTC)` calls, which is exactly where a
    correction lands in the field.
    """
    import flabel.cli as cli_module

    real_now = datetime.now
    calls = {"n": 0}

    def stepping_now(tz=None):
        calls["n"] += 1
        stamp = real_now(tz)
        # First call is started_at; every later one is after the step correction.
        return stamp if calls["n"] == 1 else stamp - timedelta(seconds=90)

    monkeypatch.setattr(cli_module, "datetime", type("D", (), {"now": staticmethod(stepping_now)}))

    code = cli_module.main(offline(BENIGN, rules_dir, tmp_path / "out"))

    rundir = only_run_dir(tmp_path / "out")
    assert (rundir / "run.json").is_file(), (
        "a backwards clock cost the whole report — this is issue #62 returning"
    )
    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]
    assert run["duration_seconds"] is None
    assert any("clock went backwards" in warning for warning in run["warnings"])
    assert code == EXIT_SUCCESS, "the run itself was fine; only the duration was unknowable"


@pytest.mark.requires_tools
def test_a_tolerated_correlation_loss_reaches_the_run_block_not_only_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Issue #57: `CorrelationResult` had no `warnings`, alone among the stages.

    So the gate's warning went to stderr and stopped there. stderr is not kept — an operator
    reading the run directory afterwards is the normal case, and `run.json` is the artifact issue
    #23 exists to make authoritative. A loss that only ever appeared on a terminal is a loss the
    record does not show.

    Asserted on the file *and* on stderr, in that order: the file is the new requirement, and
    checking stderr too proves the warning was not simply moved rather than added.
    """
    make_snapshot(tmp_path / "rules", {"et/open": [ANY_IP_PROTOCOL]})
    capture = awkward.write_esp_pcap(tmp_path / "esp.pcap")

    assert cli.main(offline(capture, tmp_path / "rules", tmp_path / "out")) == EXIT_SUCCESS

    run = json.loads((only_run_dir(tmp_path / "out") / "run.json").read_text(encoding="utf-8"))
    warnings = run["run"]["warnings"]

    assert any("could not be attached to exactly one flow" in w for w in warnings), (
        f"the correlation loss never reached run.warnings[]: {warnings}"
    )
    assert "could not be attached" in capsys.readouterr().err, "and it must still reach stderr"


@pytest.mark.requires_tools
def test_an_empty_capture_is_refused_fast_and_leaves_nothing_behind(
    rules_dir: Path, tmp_path: Path
):
    """Issue #85 at the level where the 63 seconds actually happened.

    The first version of this assertion lived on `normalize()`, which never invoked Suricata under
    any version of the code — so `elapsed < 5.0` passed against the unfixed code too. It measured
    nothing. The 63.1s was a property of `cli.main`, so the bound belongs here.

    Three assertions, because PLAN 13f promised all three: the exit code, that **no run directory
    is created**, and that it happens far inside Suricata's 60-second thread-start budget.
    """
    capture = tmp_path / "empty.pcap"
    canary.write_pcap(str(capture), [])
    output = tmp_path / "out"

    started = time.perf_counter()
    code = cli.main(offline(capture, rules_dir, output))
    elapsed = time.perf_counter() - started

    assert code == EXIT_FAILURE
    assert not output.exists() or list(output.iterdir()) == [], (
        "a refused capture must leave no run directory (PLAN 13f, spec §13)"
    )
    assert elapsed < 5.0, (
        f"refusing an empty capture took {elapsed:.1f}s — that is Suricata's 60-second "
        f"thread-start budget being spent on a file it cannot read (issue #85)"
    )


def test_every_output_artifact_goes_through_the_atomic_write(tmp_path: Path):
    """13b's fix is in the call sites, and nothing asserted they use it.

    `_write_atomic` had two tests, both calling it directly — so reverting `_write_output` to
    `write_bytes` left the suite green and the non-atomic write back. Verified by sabotage.

    Spies on the helper rather than on `Path.write_bytes`, because the question is not "was a
    write attempted" but "did every artifact route through the thing that makes it atomic".
    """
    import flabel.cli as cli_module

    routed: list[str] = []
    original = cli_module._write_atomic

    def spy(path: Path, payload: bytes) -> None:
        routed.append(path.name)
        return original(path, payload)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cli_module, "_write_atomic", spy)
        make_snapshot(tmp_path / "rules", {"et/open": [MATCHES_CANARY]})
        assert cli.main(offline(BENIGN, tmp_path / "rules", tmp_path / "out")) == EXIT_SUCCESS

    assert set(routed) == {"run.json", "NOTICE", "labels.json"}, (
        f"an artifact bypassed the atomic write: routed {routed}"
    )


def test_the_shortfall_check_survives_counts_that_were_never_taken():
    """`None < int` raises TypeError, and here that would cost `run.json` (#86 review).

    Unreachable today — every `None` count comes from `_failed()`, which always attaches a
    `ToolFailure`, so `_label` raises before the shortfall is computed. But that invariant lives
    in another function with nothing asserting it, and this is the last arithmetic on the
    nullable counts. A `TypeError` inside run assembly is issue #62's failure shape, in the step
    that exists to stop it.
    """
    import flabel.cli as cli_module
    from flabel.models import SnapshotManifest, SuricataRunInfo

    info = SuricataRunInfo(
        version="8.0.6",
        snapshot_id="8a39182c18a3c9d3",
        rules_loaded=None,
        alerts_total=None,
        rules_failed=None,
        rules_skipped=None,
        identify_alerts_suppressed=None,
    )
    manifest = SnapshotManifest(
        snapshot_id="8a39182c18a3c9d3",
        created_at="2026-08-12T00:00:00.000000Z",
        flabel_version="0.0.0",
        sources=(),
        total_admitted=85_431,
        total_ja4_admitted=0,
    )

    assert cli_module._shortfall(info, manifest) is False, (
        "an unestablished count is not a shortfall — and must not raise"
    )


# --- a damaged newer snapshot must not silently downgrade the run (#91) -------------------------


def rules_dir_with_a_damaged_newer_snapshot(tmp_path: Path) -> tuple[Path, str, str]:
    """A rules root holding a good older snapshot and a newer one whose manifest is corrupt.

    Returns `(root, good id, broken id)`. Both are written by the real `write_snapshot`, then
    one manifest is truncated — the failure an interrupted write or a bad disk actually leaves,
    rather than a hand-assembled directory that might not resemble one.
    """
    root = tmp_path / "rules"
    good = make_snapshot(root, {"et/open": [MATCHES_CANARY]}, "2026-08-01T00:00:00.000000Z")
    broken = make_snapshot(root, {"et/open": [ANY_IP_PROTOCOL]}, "2026-08-11T00:00:00.000000Z")
    (broken / "manifest.json").write_text("{ truncated", encoding="utf-8")
    return root, good.name, broken.name


@pytest.mark.requires_tools
def test_a_damaged_newer_snapshot_is_named_in_the_run_block(tmp_path: Path, no_network: None):
    """The end-to-end half of #91, and the half that matters.

    `load_snapshot` returning the warning is not the fix — `cli.py` recording it is. Testing the
    helper and not the call site is the mistake step 13b shipped (#98), so this drives the real
    pipeline and reads the artifact an operator would read.

    The run still succeeds: an older ruleset is a usable ruleset, and refusing would strand every
    machine with one bad directory. What must not happen is succeeding *quietly*.
    """
    root, good, broken = rules_dir_with_a_damaged_newer_snapshot(tmp_path)
    output = tmp_path / "out"

    code = cli.main(offline(BENIGN, root, output))

    assert code == EXIT_SUCCESS
    document = json.loads((only_run_dir(output) / "labels.json").read_text(encoding="utf-8"))
    run = document["run"]

    assert run["ruleset"]["snapshot_id"] == good, "the run should fall back to the usable snapshot"
    warnings = run["warnings"]
    assert any(broken in warning for warning in warnings), (
        f"the run was labelled against {good} because {broken} could not be read, and said "
        f"nothing about it. warnings[] was {warnings}"
    )


@pytest.mark.requires_tools
def test_the_operator_watching_the_run_is_told_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_network: None
):
    """stderr as well as the artifact: spec §12's reader and spec §10's are different people.

    stderr specifically, never stdout — spec §12 reserves stdout, and putting this there would
    corrupt `flabel --offline x.pcap > run.log` the way the shortfall prompt once did.
    """
    root, _, broken = rules_dir_with_a_damaged_newer_snapshot(tmp_path)

    cli.main(offline(BENIGN, root, tmp_path / "out"))

    captured = capsys.readouterr()
    assert broken in captured.err
    assert broken not in captured.out


@pytest.mark.requires_tools
def test_an_undamaged_store_adds_no_snapshot_warning(
    tmp_path: Path, rules_dir: Path, no_network: None
):
    """A warning on every ordinary run is a warning nobody reads.

    Asserts the absence of *this* warning rather than of all warnings: a laptop without the JA4
    package legitimately emits one, and `warnings == []` would make this test a statement about
    the machine it runs on instead of about the snapshot store.
    """
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    document = json.loads((only_run_dir(output) / "labels.json").read_text(encoding="utf-8"))
    offenders = [w for w in document["run"]["warnings"] if "skipped as unreadable" in w]
    assert offenders == []


def test_rules_list_names_a_damaged_snapshot_it_omitted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """`rules list` is where an operator looks after a run cited an id they did not expect (#91).

    A directory the labelling run warns about, silently missing from the listing, sends them to
    the one place that has decided not to mention it.
    """
    root, good, broken = rules_dir_with_a_damaged_newer_snapshot(tmp_path)

    assert cli.main(["rules", "list", "--rules-dir", str(root)]) == EXIT_SUCCESS

    captured = capsys.readouterr()
    assert broken in captured.err
    # stdout stays parseable: a warning among the ids is a line some script reads as an id.
    assert broken not in captured.out
    assert good in captured.out


# --- --sources is refused on a labelling run, not ignored (#71) ---------------------------------


def test_sources_on_a_labelling_run_is_refused(tmp_path: Path, rules_dir: Path) -> None:
    """The flag was parsed and discarded, so an operator believed something untrue.

    `cli._label` never read it — only `_rules_update` does. The behaviour was right: a label's
    terms come from the snapshot manifest, never the live registry (spec §4). The interface was
    not. Spec §5's own argument — "a registry that loads with a setting silently ignored is
    worse than one that refuses to load" — applied to the CLI instead of the TOML.
    """
    registry = tmp_path / "mine.toml"
    registry.write_text("", encoding="utf-8")

    code = cli.main(offline(BENIGN, rules_dir, tmp_path / "out", "--sources", str(registry)))

    assert code == EXIT_USAGE


def test_the_refusal_says_where_the_flag_does_work(
    tmp_path: Path, rules_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refusal that does not answer the question the operator was asking is half a refusal."""
    cli.main(offline(BENIGN, rules_dir, tmp_path / "out", "--sources", str(tmp_path / "m.toml")))

    error = capsys.readouterr().err
    assert "flabel rules update --sources" in error
    assert "snapshot carries its own terms" in error


def test_the_refusal_happens_before_anything_runs(tmp_path: Path, rules_dir: Path) -> None:
    """No run directory, no Zeek, no Suricata — the fault was visible in argv (cf. #59).

    Same reasoning as `--unmatched-threshold`: burning a pipeline that issue #56 measured at up
    to ~35 minutes and then reporting a usage error is the wrong order to do those in.
    """
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output, "--sources", str(tmp_path / "m.toml")))

    assert not output.exists(), "a refused invocation must not leave a run directory"


def test_the_stub_path_refuses_it_too(tmp_path: Path) -> None:
    """`flabel <capture> --sources f` is the same wrong invocation, and exits 2 rather than 3.

    The usage error wins over "not implemented" because the invocation is wrong either way, and
    telling someone their flag was ignored is more use than telling them to come back in Phase 2.
    It held when the default path was built, and holds again now the default has changed (#132):
    what a snapshot's terms are does not depend on which tiers a mode runs.
    """
    assert cli.main([str(BENIGN), "--sources", str(tmp_path / "m.toml")]) == EXIT_USAGE


def test_an_ordinary_labelling_run_is_unaffected(tmp_path: Path, rules_dir: Path) -> None:
    """The complement: not passing the flag must not have become a usage error."""
    assert cli.main(offline(BENIGN, rules_dir, tmp_path / "out")) != EXIT_USAGE


def test_rules_update_still_accepts_it(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The flag's real home. Refusing it here too would be the over-fix.

    A missing file is used as the probe, so this reaches `_rules_update`'s own handling without
    a network fetch: exit 1 with "source registry not found" proves the flag was read, where
    exit 2 would mean it had been refused.
    """
    code = cli.main(["rules", "update", "--sources", str(tmp_path / "absent.toml")])

    assert code != EXIT_USAGE
    assert "source registry not found" in capsys.readouterr().err


# --- the run records the gate it was held to (#68) ----------------------------------------------


@pytest.mark.requires_tools
def test_a_run_records_the_threshold_it_was_given(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """The call site, not the helper. `build_run_block` accepting the value is not the fix.

    Testing the helper and not the call site is what step 13b shipped (#98), so this drives the
    real pipeline and reads the artifact.
    """
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output, "--unmatched-threshold", "0.25"))

    document = json.loads((only_run_dir(output) / "labels.json").read_text(encoding="utf-8"))
    assert document["run"]["unmatched_threshold"] == 0.25


@pytest.mark.requires_tools
def test_a_run_given_no_threshold_records_the_default(
    tmp_path: Path, rules_dir: Path, no_network: None
) -> None:
    """The default is as much "the rule this artifact was produced under" as an explicit value."""
    from flabel.correlate import DEFAULT_THRESHOLD

    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output))

    document = json.loads((only_run_dir(output) / "labels.json").read_text(encoding="utf-8"))
    assert document["run"]["unmatched_threshold"] == DEFAULT_THRESHOLD


def test_a_dead_run_records_the_threshold_in_run_json(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path where the question is hardest to answer afterwards.

    A run that died writes `run.json` and no `labels.json` (#23). That artifact reports
    `counts.unmatched: null` — nothing was measured — so "what bar was this held to" cannot be
    recovered from it at all unless the run says. Threading the value through `_Progress` rather
    than passing it to `_run_block` from `args` is what makes this path carry it.
    """
    zeek_that_dies(monkeypatch, OOM)
    output = tmp_path / "out"

    cli.main(offline(BENIGN, rules_dir, output, "--unmatched-threshold", "0.4"))

    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists(), "the run must have died, for this to test"
    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]
    assert run["counts"]["unmatched"] is None
    assert run["unmatched_threshold"] == 0.4


# --- the three modes (#132) -----------------------------------------------------------------
#
# The device is stubbed at `tier1.run` and nowhere deeper. That boundary is the project's
# standing line — "tools real, network stubbed", and the PANW device is never contacted — so
# stubbing here replaces exactly the network and leaves the whole of `_label`'s orchestration
# real: the mode derivation, the stage gating, correlation, and every artifact written.
#
# The stub returns a genuine `Tier1Result`, not a namespace with three attributes. A stub shaped
# to what the caller happens to read today keeps passing when the caller starts reading a fourth
# field; a real dataclass fails to construct the moment the record changes.

#: The canary's HTTP flow, which `MATCHES_CANARY` also fires on — so a tier-1 detection built on
#: it correlates to the same flow a tier-2 one does, and `--both` can be shown consolidating two
#: assertions onto one label rather than emitting two labels.
CANARY_FLOW = ("10.0.0.5", 49152, "10.0.0.200", 80, "tcp")

#: A plausible PANW content/config pair. Non-empty because `build_device_source_entry` refuses an
#: empty ruleset: a tier-1 label that cannot name the signature set behind it is the
#: unattributable verdict spec §13 forbids.
DEVICE_RULESET = "AppThreat-9136-10199/config-2817"


def device_detection(sid: int = 30001, threat: str = "Realtek SDK RCE") -> Detection:
    """One tier-1 detection on the canary's HTTP flow."""
    src_ip, src_port, dst_ip, dst_port, proto = CANARY_FLOW
    return Detection(
        source="panw",
        tier=1,
        sid=sid,
        rev=1,
        classtype="attempted-admin",
        app_proto="web-browsing",
        threat=threat,
        ts=0.0,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        direction="to_server",
    )


def stub_device(
    monkeypatch: pytest.MonkeyPatch,
    *,
    detections: Sequence[Detection] = (),
    warnings: Sequence[str] = (),
) -> dict[str, int]:
    """Replace the tier-1 stage with one that reports `detections`, and count its calls.

    The returned dict is what lets a test assert a stage did **not** run. Asserting only on the
    output cannot tell "the device was skipped" from "the device ran and found nothing", and
    those are the two readings this whole change turns on.
    """
    from flabel import replay as replay_mod
    from flabel import tier1 as tier1_mod
    from flabel.panw import DeviceInfo

    calls = {"count": 0}

    def fake_run(capture, workdir, *, report, **settings):
        calls["count"] += 1
        for key in cli.DEVICE_STEPS:
            report.skip(key, "stubbed")
        return tier1_mod.Tier1Result(
            detections=tuple(detections),
            rulesets={
                (
                    detection.sid,
                    detection.src_ip,
                    detection.src_port,
                    detection.dst_ip,
                    detection.dst_port,
                    detection.proto,
                ): DEVICE_RULESET
                for detection in detections
            },
            window=replay_mod.ReplayWindow(
                pcap_first_ts=0.0,
                pcap_last_ts=1.0,
                replay_start_wall=1000.0,
                replay_end_wall=1001.0,
                multiplier=1.0,
            ),
            device=DeviceInfo(
                hostname="fw-test",
                serial="000000000000",
                sw_version="11.1.4",
                app_version="9136-10199",
                threat_version="9136-10199",
                model="PA-VM",
            ),
            entries_retrieved=len(detections),
            logs_written=len(detections),
            declined=(),
            collapsed=0,
            warnings=tuple(warnings),
        )

    monkeypatch.setattr(cli.tier1, "run", fake_run)
    monkeypatch.setenv("FLABEL_INLINE_HOST", "192.0.2.1")
    monkeypatch.setenv("FLABEL_INLINE_API_KEY", "not-a-real-key")
    monkeypatch.delenv("FLABEL_INLINE_API_KEY_FILE", raising=False)
    return calls


def read_run(output_dir: Path) -> dict:
    return json.loads((only_run_dir(output_dir) / "run.json").read_text(encoding="utf-8"))


def read_labels(output_dir: Path) -> dict:
    return json.loads((only_run_dir(output_dir) / "labels.json").read_text(encoding="utf-8"))


@pytest.mark.requires_tools
def test_the_default_run_is_replay_only_and_does_not_run_suricata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """`flabel <capture>` is tier 1 alone as of 2026-08-18 (Craig, #132).

    Asserted by what is **absent**: no `suricata/` directory, null rule counts, and a null
    `ruleset` block. A test that only checked the label would pass with Suricata still running,
    which is the defect class `docs/status.yaml` records three times in one day.
    """
    output = tmp_path / "out"
    calls = stub_device(monkeypatch, detections=[device_detection()])

    assert cli.main([str(BENIGN), "--output-dir", str(output)]) == EXIT_SUCCESS

    rundir = only_run_dir(output)
    assert calls["count"] == 1, "the device stage must have run"
    assert not (rundir / "suricata").exists(), "a replay-only run must not run Suricata"
    assert (rundir / "zeek").is_dir(), "Zeek is the flow substrate in every mode, not a tier"

    run = read_run(output)["run"]
    assert run["mode"] == "replay"
    assert run["tiers_attempted"] == [1]
    assert run["tiers_unavailable"] == []
    assert run["counts"]["rules_loaded"] is None, "null means not measured; 0 would be a claim"
    assert run["ruleset"]["snapshot_id"] is None


@pytest.mark.requires_tools
def test_a_replay_only_run_labels_from_the_device_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """The positive half: the mode still produces a traceable verdict."""
    output = tmp_path / "out"
    stub_device(monkeypatch, detections=[device_detection()])

    cli.main([str(BENIGN), "--output-dir", str(output)])

    labels = read_labels(output)["labels"]
    assert len(labels) == 1, f"expected one tier-1 label, got {labels}"
    (entry,) = labels[0]["sources"]
    assert entry["tier"] == 1
    assert entry["ruleset"] == DEVICE_RULESET, "a tier-1 label names the device's content version"
    assert labels[0]["best_tier"] == 1


@pytest.mark.requires_tools
def test_a_replay_only_run_needs_no_ruleset_snapshot_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """A fresh checkout can run the default without `flabel rules update` first (#132).

    `--rules-dir` points at an empty directory, which `--offline` would fail on with
    `SnapshotError` before creating a run directory. Tier 1 reads no Suricata rules, so failing
    a run over 85,000 rules it was never going to open would be a precondition invented by the
    orchestration rather than required by the pipeline.
    """
    empty = tmp_path / "no-rules"
    empty.mkdir()
    output = tmp_path / "out"
    stub_device(monkeypatch, detections=[device_detection()])

    code = cli.main([str(BENIGN), "--rules-dir", str(empty), "--output-dir", str(output)])

    assert code == EXIT_SUCCESS
    assert read_run(output)["run"]["mode"] == "replay"


@pytest.mark.requires_tools
def test_both_runs_the_device_and_suricata_and_consolidates_onto_one_label(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """`--both` is what the bare command used to do, and it must still do all of it.

    Both tiers fire on the canary's *first* HTTP flow, so the run is also the check that
    consolidation survived the refactor: that flow must come out as ONE label carrying two
    source entries with `best_tier` the stronger of them, not as two labels.

    The canary has a second HTTP flow that only the tier-2 rule matches, and it is left in
    rather than engineered away — it is the control. A consolidation bug that merged everything
    onto one label would satisfy "the shared flow has two entries" and be caught only by the
    flow that must stay separate.
    """
    output = tmp_path / "out"
    calls = stub_device(monkeypatch, detections=[device_detection()])

    code = cli.main(
        [
            "--both",
            str(BENIGN),
            "--rules-dir",
            str(rules_dir),
            "--output-dir",
            str(output),
        ]
    )

    assert code == EXIT_SUCCESS
    assert calls["count"] == 1
    rundir = only_run_dir(output)
    assert (rundir / "suricata").is_dir(), "--both must run Suricata"

    run = read_run(output)["run"]
    assert run["mode"] == "both"
    assert run["tiers_attempted"] == [1, 2]
    assert run["counts"]["rules_loaded"], "--both loads the ruleset"
    assert run["ruleset"]["snapshot_id"] == snapshot_id_of(rules_dir)

    labels = read_labels(output)["labels"]
    by_flow = {(label["flow"]["src_ip"], label["flow"]["src_port"]): label for label in labels}
    assert len(by_flow) == len(labels) == 2, f"one label per flow, got {labels}"

    shared = by_flow[(CANARY_FLOW[0], CANARY_FLOW[1])]
    assert sorted(entry["tier"] for entry in shared["sources"]) == [1, 2], (
        "the flow both tiers flagged must be one label carrying both assertions"
    )
    assert shared["best_tier"] == 1

    (tier2_only,) = [label for label in labels if label is not shared]
    assert [entry["tier"] for entry in tier2_only["sources"]] == [2]
    assert tier2_only["best_tier"] == 2


@pytest.mark.requires_tools
def test_offline_still_never_touches_the_device(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """`--offline` is unchanged, and the stub's call count is what proves it."""
    output = tmp_path / "out"
    calls = stub_device(monkeypatch, detections=[device_detection()])

    assert cli.main(offline(BENIGN, rules_dir, output)) == EXIT_SUCCESS

    assert calls["count"] == 0, "--offline must not invoke the tier-1 stage"
    run = read_run(output)["run"]
    assert run["mode"] == "offline"
    assert run["tiers_attempted"] == [2]
    assert all(
        entry["tier"] == 2 for label in read_labels(output)["labels"] for entry in label["sources"]
    )


def test_offline_and_both_together_are_refused(tmp_path: Path) -> None:
    """Two irreconcilable requests. Picking a winner would silently ignore the loser."""
    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args(["--offline", "--both", str(BENIGN)])
    assert excinfo.value.code == EXIT_USAGE


def test_a_ruleset_snapshot_is_refused_on_a_replay_only_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same reasoning as `--sources` (#71): ignoring a flag is worse than refusing it.

    The refusal must also happen *before* a run directory exists, which is the contract every
    usage error in spec §12 has.
    """
    output = tmp_path / "out"
    stub_device(monkeypatch)

    code = cli.main(
        [str(BENIGN), "--ruleset-snapshot", "0123456789abcdef", "--output-dir", str(output)]
    )

    assert code == EXIT_USAGE
    assert not output.exists(), "a refused invocation must not leave a run directory"
    assert "--both" in capsys.readouterr().err, "the refusal must name the mode that accepts it"


@pytest.mark.requires_tools
def test_a_ruleset_snapshot_is_still_accepted_by_the_modes_that_load_rules(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """The complement of the refusal above, so it cannot be over-applied."""
    stub_device(monkeypatch, detections=[device_detection()])
    snapshot = snapshot_id_of(rules_dir)

    offline_out = tmp_path / "offline-out"
    assert (
        cli.main(offline(BENIGN, rules_dir, offline_out, "--ruleset-snapshot", snapshot))
        != EXIT_USAGE
    )

    both_out = tmp_path / "both-out"
    assert (
        cli.main(
            [
                "--both",
                str(BENIGN),
                "--rules-dir",
                str(rules_dir),
                "--output-dir",
                str(both_out),
                "--ruleset-snapshot",
                snapshot,
            ]
        )
        != EXIT_USAGE
    )


@pytest.mark.requires_tools
def test_a_replay_only_notice_records_that_no_rule_source_is_behind_the_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """NOTICE is written in every mode: its absence must not be something to interpret.

    What it says changes. A replay-only run cites no snapshot, and the one entry it carries
    records the *absence* of an obligation for the vendor's threat names — which spec §4 calls a
    statement rather than a gap.
    """
    output = tmp_path / "out"
    stub_device(monkeypatch, detections=[device_detection()])

    cli.main([str(BENIGN), "--output-dir", str(output)])

    notice = (only_run_dir(output) / "NOTICE").read_text(encoding="utf-8")
    assert "Ruleset snapshot: none" in notice
    assert "proprietary:vendor-signature" in notice


@pytest.mark.requires_tools
def test_a_both_run_that_loses_the_device_says_which_half_it_lost(
    tmp_path: Path, rules_dir: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """`tiers_unavailable` earns its place on the failure path, not the success path (#132).

    Phase 1 published `[1]` on every run whatever happened, so the field could not answer the
    one question its reader has: of the two tiers I asked for, which did I get?
    """
    output = tmp_path / "out"

    def explode(capture, workdir, *, report, **settings):
        raise ToolError("the device stopped answering mid-replay")

    monkeypatch.setattr(cli.tier1, "run", explode)
    monkeypatch.setenv("FLABEL_INLINE_HOST", "192.0.2.1")
    monkeypatch.setenv("FLABEL_INLINE_API_KEY", "not-a-real-key")

    code = cli.main(
        ["--both", str(BENIGN), "--rules-dir", str(rules_dir), "--output-dir", str(output)]
    )

    assert code == EXIT_FAILURE
    rundir = only_run_dir(output)
    assert not (rundir / "labels.json").exists(), "a failed run claims no verdicts (issue #23)"
    run = read_run(output)["run"]
    assert run["mode"] == "both"
    assert run["tiers_attempted"] == [1, 2]
    assert run["tiers_unavailable"] == [1, 2], "the device was lost, and Suricata never reached"


def test_help_states_what_the_bare_command_does() -> None:
    """The default mode is selected by the ABSENCE of a flag, so nothing else can describe it.

    argparse gives every option a help string and gives the default mode none, which left the
    one behaviour most operators get as the only one `--help` did not mention. Asserted on the
    rendered text rather than on the description constant, because the wrapping is manual —
    `RawDescriptionHelpFormatter` does not wrap — and a long line silently overflowing the
    terminal is the failure this is most likely to acquire.
    """
    rendered = cli.build_parser().format_help()

    assert "With no mode flag" in rendered
    assert "tier 1 only" in rendered
    assert "Zeek runs in every mode" in rendered
    overlong = [line for line in rendered.splitlines() if len(line) > 80]
    assert not overlong, f"--help has lines wider than 80 columns: {overlong}"
