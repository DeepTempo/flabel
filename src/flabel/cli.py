"""Argument parsing, orchestration and exit codes (docs/spec.md §12, PLAN.md step 9).

This module is the only place the stages meet. Everything it does beyond wiring falls into
three jobs, and each exists because the alternative is a run that looks complete and is not.

**It decides which artifacts exist.** Spec §13 permits a complete run directory or none, and
issue #23 resolved what "none" means when a tool dies mid-run: the directory holds `run.json`
and *no* `labels.json`, because §11 requires the failure recorded and §13 forbids a partial
labels file. The absence of `labels.json` is the signal — a consumer tests for a missing file,
where a status field inside one has to be read and understood. `run.json` is written by every
run, successful or not, so there is one place to find the run block regardless of outcome.

**It refuses to start on some failures and reports on others.** A missing snapshot and an
unreadable capture (spec §12) are refusals: nothing ran, so no directory appears. Everything
after normalization is a run that died, and a run that died reports what it lost.

**It is where the operator is asked.** Spec §11's rule-load shortfall is the one place flabel
puts a decision back to a person, and only when there is a person there to take it (#46).
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

# Imported under a distinct name: `progress` is already the local _Progress instance
# threaded through _label, and shadowing it would be a very quiet bug.
from flabel import __version__, tier1
from flabel import progress as progress_mod
from flabel.config import enabled_sources, load_admission_policies
from flabel.correlate import DEFAULT_THRESHOLD, _check_threshold, correlate
from flabel.errors import (
    EXIT_SUCCESS,
    ConfigError,
    CorrelationError,
    FlabelError,
    SnapshotError,
    ToolError,
    UsageError,
    exit_code_for,
)
from flabel.ingest import normalize
from flabel.labels import build_document, serialise_bytes
from flabel.models import (
    TIERS_BY_MODE,
    CorrelationResult,
    Detection,
    NormalizedCapture,
    RunMode,
    SnapshotManifest,
    SuricataRunInfo,
    ToolFailure,
    ZeekRunInfo,
    partial_name,
)
from flabel.notice import render_notice_bytes
from flabel.provenance import build_run_block
from flabel.rules import utc_now
from flabel.rules.admit import admit
from flabel.rules.fetch import fetch_feed
from flabel.rules.snapshot import (
    load_address_indicators,
    load_snapshot,
    scan_snapshots,
    write_snapshot,
)
from flabel.suricata import run_suricata
from flabel.zeek import run_zeek

#: What the Phase 1 default path used to print (US-22). The stub is gone — `flabel <capture>` runs
#: tier 1 — and this is kept only so a test can assert the string never appears again. Retired
#: rather than deleted because "the default path announces an unbuilt feature" is a regression
#: worth naming, and a test asserting the absence of an anonymous string reads like a typo.
STUB_MESSAGE = "Coming Soon (TM)"

#: Spec §12's defaults. Relative, and resolved at use rather than at import: `Path.cwd()` in a
#: default argument is evaluated once when the module loads, which is not where the operator is.
DEFAULT_RULES_DIR = Path(".flabel/rules")
DEFAULT_OUTPUT_DIR = Path(".")

#: The subcommand word. `flabel rules ...` dispatches here rather than being read as a capture
#: path, the way `git` treats its own subcommands — so a capture file literally named `rules`
#: must be given as `./rules`. The alternative, deciding from whether such a file exists, would
#: make the command mean different things in different directories.
RULES_COMMAND = "rules"

#: Sortable, second-and-microsecond resolution, no characters a shell or filesystem dislikes.
#: Zero-padded throughout, which is what makes name order equal time order: an unpadded hour
#: would sort "10:05" before "9:05" and an operator reading `ls` would take the wrong run.
RUN_DIR_TIMESTAMP = "%Y%m%dT%H%M%S.%fZ"

#: Stripped from a capture's name when naming its run directory, longest chain first, so
#: `capture.pcapng.gz` yields `capture` rather than `capture.pcapng`.
CAPTURE_SUFFIXES = (".gz", ".pcapng", ".pcap")

#: The run's stages, in the order they happen, as (key, label). The display draws every one of
#: them from the start — including the ones still to come — because a list that grows as it goes
#: tells the operator nothing about how much is left.
#:
#: Tier-2-only runs skip the four device stages rather than omitting them, so `--offline` and a
#: full run are visibly the same pipeline with a piece switched off.
STEPS: tuple[tuple[str, str], ...] = (
    ("ingest", "ingest"),
    ("device", "device"),
    ("clock", "clock"),
    ("prep", "prep"),
    ("replay", "replay"),
    ("settle", "settle"),
    ("flush", "flush"),
    ("query", "query"),
    ("zeek", "zeek"),
    ("suricata", "suricata"),
    ("correlate", "correlate"),
    ("write", "write"),
)

#: Device stages, skipped as a group when the mode does not include tier 1.
DEVICE_STEPS = ("device", "clock", "prep", "replay", "settle", "flush", "query")

#: The tier-2 stage, skipped when the mode does not include it. A one-element tuple rather than a
#: bare string so the two skip groups read the same way at the call site — and so a second tier-2
#: stage can be added without the reader having to notice which of the two conventions applies.
SURICATA_STEPS = ("suricata",)

LABELS_NAME = "labels.json"
RUN_NAME = "run.json"
NOTICE_NAME = "NOTICE"
ZEEK_DIR = "zeek"
SURICATA_DIR = "suricata"
TEMP_PREFIX = "flabel-"


# --- argument parsing ---------------------------------------------------------------------


def unmatched_threshold(value: str) -> float:
    """Parse and validate `--unmatched-threshold`, so a typo exits 2 immediately (#59).

    The validation itself is `correlate._check_threshold`, called rather than restated: it is
    the definition of a usable threshold, and a second copy here would be a second thing to
    keep in step. What this adds is *when* and *as what*. Before, the guard fired inside
    `correlate()` — after ingest, Zeek and Suricata had run, which issue #56 measured at up to
    ~35 minutes — and raised `ValueError`, which maps to exit 1. So an operator who mistyped a
    flag burned the whole pipeline and was then told "the run failed" rather than "you invoked
    it wrong". Both are wrong for a fault that was visible in argv before anything started.

    `_check_threshold` stays where it is as the backstop (#59): `correlate()` is public, and
    step 10 and any future caller reach it without passing through argparse.
    """
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a number; --unmatched-threshold is a share between 0 and 1"
        ) from None
    try:
        _check_threshold(number)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return number


def build_parser() -> argparse.ArgumentParser:
    """The labelling parser: the three modes of spec §12, one flag each (#132)."""
    parser = argparse.ArgumentParser(
        prog="flabel",
        description="Label malicious flows in a packet capture.",
        epilog=(
            f"ruleset snapshots:\n"
            f"  flabel {RULES_COMMAND} update [--sources FILE] [--rules-dir DIR]\n"
            f"  flabel {RULES_COMMAND} list   [--rules-dir DIR]\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("capture", type=Path, help="the pcap/pcapng capture to label")
    # Mutually exclusive, and argparse's own group rather than a hand-rolled check, so
    # `--offline --both` exits 2 with a message naming both flags before any tool runs. The two
    # requests are not reconcilable — one says "do not touch the device", the other "use it" —
    # and picking a winner would make the losing flag silently ineffective, which is the failure
    # `--sources` was refused for (spec §5, §12).
    tiers = parser.add_mutually_exclusive_group()
    tiers.add_argument(
        "--offline",
        action="store_true",
        help="tier 2 only: Suricata + Zeek read the capture. No device, no replay, no network.",
    )
    tiers.add_argument(
        "--both",
        action="store_true",
        help=(
            "tier 1 and tier 2: replay past the device AND run Suricata, labelling from both. "
            "This was the default until 2026-08-18 (#132)."
        ),
    )
    parser.add_argument(
        "--ruleset-snapshot",
        default=None,
        metavar="ID",
        help=(
            "ruleset snapshot to label against (default: newest available). Tier 2 only — "
            "REFUSED on a replay-only run, which loads no rules"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        metavar="DIR",
        help="where the run directory is created (default: the working directory)",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        metavar="DIR",
        help=f"ruleset snapshot store (default: {DEFAULT_RULES_DIR})",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "REFUSED on a labelling run — a snapshot carries its own terms (spec §4). "
            "Declared here so the refusal can explain itself instead of argparse saying "
            "'unrecognized arguments'. Use `flabel rules update --sources FILE`."
        ),
    )
    parser.add_argument(
        "--unmatched-threshold",
        type=unmatched_threshold,
        default=DEFAULT_THRESHOLD,
        metavar="FLOAT",
        help=(
            f"fail above this share of unplaced *correlatable* detections "
            f"(default: {DEFAULT_THRESHOLD}). Detections on a transport Zeek cannot name are "
            f"reported but not counted here — see counts.unmatched_unsupported_transport"
        ),
    )
    parser.add_argument("--version", action="version", version=f"flabel {__version__}")
    return parser


def build_rules_parser() -> argparse.ArgumentParser:
    """The `flabel rules` parser (spec §12)."""
    parser = argparse.ArgumentParser(
        prog=f"flabel {RULES_COMMAND}", description="Manage ruleset snapshots."
    )
    actions = parser.add_subparsers(dest="action", required=True)

    update = actions.add_parser("update", help="fetch the enabled sources and write a snapshot")
    update.add_argument("--sources", type=Path, default=None, metavar="FILE")
    update.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, metavar="DIR")

    listing = actions.add_parser("list", help="list the snapshots on disk")
    listing.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, metavar="DIR")
    return parser


def _mode(args: argparse.Namespace) -> RunMode:
    """Which pipelines this invocation asked for (spec §12, #132).

    The bare command is **replay-only** as of 2026-08-18. It used to mean tier 1 + tier 2, and
    the change is deliberate: the two tiers answer different questions, and pairing them on every
    run made every replay pay a full Suricata rule load and every output mix the tier under
    evaluation with the open-source baseline. `--both` is that old default, now named.

    Derived in one place and passed down, rather than each stage re-reading `args.offline`. The
    gating question is asked five times in `_label` — snapshot, device settings, skip lists,
    correlation, NOTICE — and five independent readings of two booleans is five chances for one
    of them to disagree about what the operator asked for.
    """
    if args.offline:
        return "offline"
    return "both" if args.both else "replay"


# --- run directory ------------------------------------------------------------------------


def run_directory_name(capture: Path, when: datetime) -> str:
    """`{capture-name}_{datetime}` (spec §1), with the container suffixes stripped.

    Stripped because a directory called `benign.pcap_2026...` reads as a file, and because
    `.pcap.gz` is two suffixes rather than one. Only the container suffixes go: a capture named
    `my.capture.2026.pcap` keeps its dots, which are the operator's naming and not ours to
    reinterpret.
    """
    name = capture.name
    changed = True
    while changed:
        changed = False
        for suffix in CAPTURE_SUFFIXES:
            if name.lower().endswith(suffix):
                name = name[: -len(suffix)]
                changed = True
                break
    # Leading dots go, and the fallback catches what is left (#95). The guard here used to be
    # `len(name) > len(suffix)`, which left a capture named exactly `.pcap` unstripped and
    # produced the run directory `.pcap_2026…Z` — hidden from `ls`, so the operator cannot find
    # their own output. It was also redundant: `or "capture"` already handled the empty case it
    # was protecting. `..pcap` and `.hidden.pcap` had the same problem one level down.
    #
    # The run directory is *our* output, not the operator's file, so a name that hides it is
    # ours to reject. Dots inside the name are still the operator's naming and are left alone —
    # `my.capture.2026.pcap` keeps its dots.
    name = name.lstrip(".")
    return f"{name or 'capture'}_{when.strftime(RUN_DIR_TIMESTAMP)}"


def _make_run_directory(output_dir: Path, capture: Path, when: datetime) -> Path:
    """Create this run's directory, refusing to touch one that already exists.

    `exist_ok=False` is spec §13's "never overwrite or modify a previous run directory" spelled
    as code. It can only trigger if two runs over one capture land in the same microsecond or a
    clock stepped backwards (issue #62); either way, adding to somebody else's run directory is
    worse than failing.
    """
    rundir = Path(output_dir) / run_directory_name(capture, when)
    try:
        rundir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise UsageError(
            f"{rundir} already exists; flabel never writes into a previous run directory"
        ) from exc
    except OSError as exc:
        raise UsageError(f"could not create run directory {rundir}: {exc}") from exc
    return rundir


def _stamp(when: datetime) -> str:
    """flabel's one timestamp format (spec §10), which `provenance` validates on the way in."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# --- what the run knows so far --------------------------------------------------------------


@dataclass
class _Progress:
    """Everything the run block needs, filled in as stages complete.

    Mutable and accumulating on purpose. A run can die in any stage and still has to report
    what it established before it did, so the failure path needs one object holding whatever
    exists rather than a signature per stage. Every field starts `None` because spec §10 makes
    `null` mean "not measured" — distinct from zero, which is a claim about the capture.
    """

    #: What the operator asked for (#132). On `_Progress` for the same reason
    #: `unmatched_threshold` is: *every* path that writes a run block needs it, including the
    #: failure paths, and a `run.json` that cannot say which pipelines were meant to run cannot
    #: be read as evidence of what was lost. Not defaulted — a run always has a mode, and a
    #: default here would let a caller publish someone else's.
    mode: RunMode
    #: Whether the tier-1 stage returned. Distinct from `mode` including tier 1: the difference
    #: between the two is exactly `tiers_unavailable`, which is the field that tells a reader a
    #: `--both` run lost its device half rather than never having had one.
    tier1_ran: bool = False
    capture: NormalizedCapture | None = None
    manifest: SnapshotManifest | None = None
    zeek: ZeekRunInfo | None = None
    suricata: SuricataRunInfo | None = None
    correlation: CorrelationResult | None = None
    snapshot_resolved: bool | None = None
    #: The gate this run is held to. On `_Progress` rather than passed to `_run_block` from
    #: `args`, so that *every* path which writes a run block carries it — including the failure
    #: paths, which write `run.json` and are exactly where "what bar was this measured against"
    #: is hardest to answer afterwards. Set before anything can fail (#68).
    unmatched_threshold: float = DEFAULT_THRESHOLD
    tool_failures: tuple[ToolFailure, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


def _absorb(progress: _Progress, exc: FlabelError) -> None:
    """Take the evidence off an exception before it becomes an exit code.

    `ToolError` carries `failures` and `run_info`, and `CorrelationError` carries `result`,
    precisely so the caller can report the loss it is about to fail on (spec §4, §9). Catching
    either and printing `str(exc)` would discard the argv, the exit code and whether the tool
    was killed — the records those attributes exist to carry.
    """
    if isinstance(exc, ToolError):
        progress.tool_failures = (*progress.tool_failures, *exc.failures)
        if isinstance(exc.run_info, ZeekRunInfo):
            progress.zeek = exc.run_info
        elif isinstance(exc.run_info, SuricataRunInfo):
            progress.suricata = exc.run_info
    elif isinstance(exc, CorrelationError) and isinstance(exc.result, CorrelationResult):
        progress.correlation = exc.result


def _run_block(started_at: str, progress: _Progress) -> dict[str, Any]:
    """Assemble the run block once, for whichever files this run is going to write."""
    return build_run_block(
        started_at=started_at,
        finished_at=_stamp(datetime.now(UTC)),
        capture=progress.capture,
        manifest=progress.manifest,
        zeek=progress.zeek,
        suricata=progress.suricata,
        correlation=progress.correlation,
        mode=progress.mode,
        tier1_ran=progress.tier1_ran,
        snapshot_resolved=progress.snapshot_resolved,
        unmatched_threshold=progress.unmatched_threshold,
        tool_failures=progress.tool_failures,
        warnings=progress.warnings,
    )


def _run_document(run: dict[str, Any], progress: _Progress) -> dict[str, Any]:
    """`run.json` — the `labels.json` document minus the verdicts (Craig, 2026-08-13).

    Built through `build_document` rather than assembled here so the unmatched records are
    ordered and rendered by exactly the code that renders them in `labels.json`; a second
    renderer is a second thing that can disagree about what a detection looks like.

    Then `labels` is **deleted, not emptied**. That is the whole decision in issue #23: an empty
    array reads as "nothing malicious was found" when the pipeline in fact died, and a consumer
    training on the output cannot tell it from a clean capture. The key's absence cannot be
    misread as a verdict.

    It carries `unmatched_detections` on every run, including successful ones, because spec §11
    names that array as the field for the uncorrelatable-detection loss condition — and the run
    where it matters most is the one the gate failed, which writes no `labels.json` to hold it.
    `counts.unmatched` gives the scale; only the records give the reason, and `no_flow_match`
    (a tuple-normalisation fault) and `ambiguous_flow_match` (port reuse) are different bugs in
    different modules.
    """
    document = build_document(
        run=run, labels=(), unmatched=progress.correlation.unmatched if progress.correlation else ()
    )
    del document["labels"]
    if progress.correlation is None:
        # `null`, not `[]`, when correlation never ran — the same distinction as the key above,
        # one line down. A run that died in Zeek measured no detections at all, and an empty array
        # there asserts that every detection was placed. `counts.unmatched` is already `null` on
        # that path; these are two records of one fact and must not disagree.
        document["unmatched_detections"] = None
    return document


def _write_atomic(path: Path, payload: bytes) -> None:
    """Write `path` so that it either does not exist or is complete (issue #70).

    Spec §13: either a complete run directory exists or none does. A plain `write_bytes` breaks
    that on a kill, a full disk or an OOM part-way through — the file is left truncated, and a
    truncated JSON document parses as neither a valid result nor an absent one, which is the
    single state §13 names. The absence of `labels.json` is load-bearing here (issue #23), so a
    half-written one is worse than no file at all.

    `os.replace` is atomic within a filesystem, and the temporary lives in the run directory
    rather than the system temp dir so the rename can never cross a device. Its name comes from
    `models.partial_name`, which `canonical` also reads: a temporary left behind by a *killed*
    process — the case the cleanup below cannot cover — must not be compared by the
    reproducibility gate, or a crash surfaces as a Goal 2 failure naming a file neither run meant
    to publish.
    """
    temporary = path.with_name(partial_name(path.name))
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    except OSError:
        # A failed write must not leave the temporary behind to be mistaken for state, and must
        # not mask the original error with one from the cleanup.
        temporary.unlink(missing_ok=True)
        raise


def _write_run_json(rundir: Path, document: dict[str, Any]) -> None:
    _write_atomic(rundir / RUN_NAME, serialise_bytes(document))


def _fail(rundir: Path, started_at: str, progress: _Progress, exc: FlabelError) -> int:
    """Report a run that died: `run.json`, no `labels.json`, and the exception's exit code.

    **The reason is recorded in the run block, not only printed.** Found in verification: for a
    tool failure or a correlation breach the evidence travels in `tool_failures[]` or
    `unmatched_detections[]`, so the document spoke for itself — but a snapshot-id mismatch or a
    declined prompt left a `run.json` with no failures, no unplaced detections and every
    `loss_conditions` flag false. It read exactly like a clean run, and the only statement to the
    contrary was prose on stderr. That is what issue #23 rejected: a script should not have to
    parse a log to learn that the artifact beside it is not a result.
    """
    print(f"flabel: {exc}", file=sys.stderr)
    progress.warnings = (*progress.warnings, f"the run failed and wrote no labels: {exc}")
    _write_run_json(rundir, _run_document(_run_block(started_at, progress), progress))
    print(f"flabel: run details in {rundir / RUN_NAME}; no labels were written", file=sys.stderr)
    return exit_code_for(exc)


def _unexpected(exc: BaseException) -> FlabelError:
    """Wrap an unforeseen crash so it still leaves a run block behind.

    `errors.py` already says an exception that is not a `FlabelError` maps to failure, but before
    this nothing routed one there: `_label` caught `FlabelError` alone, so a bare `ValueError`
    escaped as a traceback and the run directory kept `zeek/` and `suricata/` with neither
    `run.json` nor `labels.json` — the one state spec §13 forbids, being neither a complete run
    directory nor none.

    Not hypothetical. `provenance.build_source_entry` raises plain `ValueError` for an empty
    `threat`, and §8 checks only that the `signature` *key* exists, so a wholesale-admitted feed
    shipping one rule with `msg:""` reaches correlation and raises.
    """
    return FlabelError(f"unexpected {type(exc).__name__}: {exc}")


# --- the rule-load shortfall (#46) -----------------------------------------------------------


def stdin_is_a_tty() -> bool:
    """Whether there is anybody there to answer a prompt.

    A function rather than an inline `sys.stdin.isatty()` so the two branches are testable
    without a pseudo-terminal, and because `sys.stdin` can be `None` under some launchers.
    """
    try:
        return bool(sys.stdin is not None and sys.stdin.isatty())
    except (AttributeError, ValueError):  # a detached or closed stdin is not a terminal
        return False


def prompt_is_visible() -> bool:
    """Whether the question would actually reach the person expected to answer it.

    `stdin.isatty()` is not the whole test. A prompt nobody can read is a hang, and the operator
    has to *see* the question — so the stream the prompt is written to has to be a terminal too.
    With `flabel --offline capture.pcap 2> run.log` on an interactive shell, stdin is a terminal
    and the question is in a file, which is the same wedged process #46 exists to prevent.
    """
    try:
        return bool(sys.stderr is not None and sys.stderr.isatty())
    except (AttributeError, ValueError):
        return False


def _shortfall(info: SuricataRunInfo, manifest: SnapshotManifest) -> bool:
    """Did the engine load less than the snapshot admitted?

    Three signals rather than one, because they fail differently: `rules_failed` is a rule this
    build cannot parse, `rules_skipped` is one dropped for duplicating another's SID, and a
    `rules_loaded` below `total_admitted` is rules that went missing without the engine saying
    which counter they belong to.

    **`None` means the pass never established the count, and there is no shortfall to report**
    (issue #86 made these nullable). Guarded explicitly rather than relied upon: today every
    `None` comes from `_failed()`, which always attaches a `ToolFailure`, so `_label` raises
    before reaching here — but that invariant lives in another function a hundred lines away with
    nothing asserting it. `None < int` raises `TypeError`, and a `TypeError` here escapes into run
    assembly and **costs `run.json`**, which is issue #62's shape in the step that exists to stop
    it. `bool(None or None)` would be `False`, which is right by accident and wrong by reasoning.
    """
    if info.rules_loaded is None:
        return False
    return bool(
        info.rules_failed or info.rules_skipped or info.rules_loaded < manifest.total_admitted
    )


def _confirm_shortfall(info: SuricataRunInfo, manifest: SnapshotManifest) -> bool:
    """Warn about rules that never loaded, and ask whether to continue (#46, spec §11).

    The numbers are printed from `SuricataRunInfo.warnings`, which `suricata.py` composed with
    the count *and* the share of the ruleset it represents. Not restated here: "26 rules failed"
    is a curiosity against 85,431 and a broken snapshot against 40, so the percentage is what
    makes the number answerable — and it belongs in one place, since the run block carries the
    same sentence.

    **The prompt appears only when stdin is a TTY.** flabel runs in CI, cron and `set -e`
    scripts, where a prompt either hangs the pipeline or blocks step 10's own gates. Without a
    TTY the run proceeds — that is what "default yes" means — and the warning is in the run
    block either way, so a non-interactive run never loses the fact that rules went missing.
    No flag controls this: spec §12's contract is closed, and a flag would be a second way to
    say what the default already answers.
    """
    for warning in info.warnings:
        print(f"flabel: {warning}", file=sys.stderr)

    if not (stdin_is_a_tty() and prompt_is_visible()):
        print(
            "flabel: continuing (no terminal to ask, so the default answer applies)",
            file=sys.stderr,
        )
        return True

    # The prompt goes to **stderr**, and `input()` is called bare. `input(prompt)` writes its
    # argument to stdout, which spec §12 reserves — and redirecting stdout is an ordinary thing
    # to do, so the question would land in the operator's log file while their terminal sat
    # silent in front of a process that looked wedged. Verified, not assumed.
    print(
        "flabel: label this capture with the rules that did load? [Y/n] ", end="", file=sys.stderr
    )
    sys.stderr.flush()
    try:
        answer = input()
    except EOFError:
        return True
    except KeyboardInterrupt:
        # Ctrl-C at a prompt is an answer, not a crash — and the likeliest one, since the prompt
        # invites it. Letting it escape would leave a run directory with no `run.json`.
        print("", file=sys.stderr)
        return False
    return not answer.strip().lower().startswith("n")


# --- the labelling run ------------------------------------------------------------------------


#: Where the tier-1 stage gets the device from. **Environment, not flags** — spec §12 fixes the
#: CLI contract and says Phase 2 adds none, so a lab endpoint cannot become an argument. The two
#: `FLABEL_INLINE_*` names are the ones `.env.example` already shipped, and are reused rather
#: than replaced.
#:
#: The key is read from a file when `FLABEL_INLINE_API_KEY_FILE` is set, which is how the replay
#: host holds it: a credential in a 0600 file is not in the process environment of everything the
#: run spawns, and does not reach a crash dump or a `ps` listing.
def _device_settings() -> dict[str, object]:
    """The tier-1 stage's configuration, or a `ConfigError` naming what is missing."""
    host = os.environ.get("FLABEL_INLINE_HOST", "").strip()
    key_file = os.environ.get("FLABEL_INLINE_API_KEY_FILE", "").strip()
    key = os.environ.get("FLABEL_INLINE_API_KEY", "").strip()
    if key_file:
        try:
            key = Path(key_file).read_text().strip()
        except OSError as exc:
            raise ConfigError(
                f"FLABEL_INLINE_API_KEY_FILE {key_file} could not be read: {exc}"
            ) from exc
    if not host or not key:
        raise ConfigError(
            "a tier-1 run needs the inline device's address and an API key. Set "
            "FLABEL_INLINE_HOST and either FLABEL_INLINE_API_KEY_FILE or FLABEL_INLINE_API_KEY "
            "(see .env.example), or run the Tier 2 pipeline with --offline."
        )
    return {
        "host": host,
        "api_key": key,
        "interfaces": (
            os.environ.get("FLABEL_REPLAY_IF1", "ens5"),
            os.environ.get("FLABEL_REPLAY_IF2", "ens6"),
        ),
        "multiplier": float(os.environ.get("FLABEL_REPLAY_MULTIPLIER", "1000")),
        "topspeed": os.environ.get("FLABEL_REPLAY_TOPSPEED", "").lower() in {"1", "true", "yes"},
        "settle_seconds": int(os.environ.get("FLABEL_SETTLE_SECONDS", "60")),
    }


def _label(args: argparse.Namespace) -> int:
    """Wire ingest -> zeek -> suricata -> correlate -> labels into one run directory.

    The order of the first two steps is spec §12's, not an accident. A missing snapshot and an
    unreadable capture are the two failures it says leave *no* run directory: nothing ran, so
    there is no run to report, and a directory holding a `run.json` that says "nothing happened"
    would be litter. Everything after that is a run that died, and a run that died reports.
    """
    started = datetime.now(UTC)
    started_at = _stamp(started)
    mode = _mode(args)
    tier1_wanted = 1 in TIERS_BY_MODE[mode]
    tier2_wanted = 2 in TIERS_BY_MODE[mode]
    progress = _Progress(unmatched_threshold=args.unmatched_threshold, mode=mode)

    # Resolved first, before the snapshot, because it is free and it is the precondition
    # specific to the mode the operator actually invoked. A tier-1 run with no device configured
    # should say so, rather than first complaining about a ruleset it would also have needed.
    # Neither failure creates a run directory, so spec §13 is unaffected either way.
    device_settings = _device_settings() if tier1_wanted else None

    # Before any directory exists: `SnapshotError` propagates to `main` (spec §12).
    #
    # **Not loaded at all on a replay-only run** (#132). Tier 1 reads no Suricata rules, so
    # requiring a snapshot would fail the new default on a fresh checkout — over 85,000 rules the
    # run was never going to open — and would then publish a `ruleset` block naming a snapshot
    # that did not participate in a single label. `_ruleset_section` already renders `None` as
    # all-null, which is spec §2.5's distinction between "not measured" and zero, applied to a
    # whole block.
    snapshot_dir: Path | None = None
    manifest: SnapshotManifest | None = None
    if tier2_wanted:
        snapshot_dir, manifest, snapshot_warnings = load_snapshot(
            args.rules_dir, args.ruleset_snapshot
        )
        progress.manifest = manifest
        progress.snapshot_resolved = True
        # Both readers, because they are different people (#91): stderr for the operator watching
        # the run (spec §12), `run.warnings[]` for whoever reads the artifact later (spec §10).
        for warning in snapshot_warnings:
            print(f"flabel: warning: {warning}", file=sys.stderr)
        progress.warnings = (*progress.warnings, *snapshot_warnings)

    say = progress_mod.reporter(list(STEPS))
    # Skipped, never omitted: all three modes draw the same twelve stages so the display shows one
    # pipeline with pieces switched off rather than three different-looking pipelines. The reason
    # string is the flag the operator typed, so the line answers "why" without them re-deriving it.
    if not tier1_wanted:
        for key in DEVICE_STEPS:
            say.skip(key, "offline")
    if not tier2_wanted:
        for key in SURICATA_STEPS:
            say.skip(key, "replay-only")

    with TemporaryDirectory(prefix=TEMP_PREFIX) as workdir:
        # The normalized capture lives here and nowhere else (spec §10). Not in the run
        # directory: it is derived, it would double the output's size, and spec §13 forbids
        # copying capture data outside the run directory — which includes not adding a second
        # copy of the operator's packets to an artifact they will ship somewhere.
        try:
            say.start("ingest")
            progress.capture = normalize(args.capture, Path(workdir))
            say.header(
                f"{args.capture.name} │ {progress_mod.count(progress.capture.packets_read)} packets"
            )
            say.finish(
                "ingest",
                f"{progress.capture.input_status} │ "
                f"{progress_mod.count(progress.capture.packets_read)} pkts",
            )
        except ToolError as exc:
            say.fail("ingest", str(exc)[:60])
            # `editcap` failed. Unlike `CaptureError`, the operator's file was readable, so
            # there is a run worth reporting — and the `ToolFailure` records are the only
            # description of what went wrong. Create the directory *now* rather than earlier,
            # so an unreadable capture still leaves nothing behind.
            _absorb(progress, exc)
            return _fail(
                _make_run_directory(args.output_dir, args.capture, started),
                started_at,
                progress,
                exc,
            )

        rundir = _make_run_directory(args.output_dir, args.capture, started)

        try:
            # Tier 1 first: it is the only stage with a deadline. The device's threat logs are
            # selected by a wall-clock window, so the longer the gap between the replay and the
            # query the more unrelated traffic the padded window can sweep in.
            tier1_result = None
            if device_settings is not None:
                tier1_result = tier1.run(
                    progress.capture.path,
                    Path(workdir),
                    report=say,
                    **device_settings,  # type: ignore[arg-type]
                )
                progress.tier1_ran = True
                for warning in tier1_result.warnings:
                    print(f"flabel: warning: {warning}", file=sys.stderr)
                progress.warnings = (*progress.warnings, *tier1_result.warnings)

            say.start("zeek", "reading the capture")
            flows, progress.zeek = run_zeek(progress.capture.path, rundir / ZEEK_DIR)
            say.finish("zeek", f"{len(flows):,} flows")

            detections: tuple[Detection, ...] = ()
            indicators: frozenset[int] | None = None
            if tier2_wanted:
                assert snapshot_dir is not None and manifest is not None, (
                    "tier 2 is wanted, so the snapshot loaded above must exist"
                )
                detections, indicators = _tier2(progress, say, snapshot_dir, manifest, rundir, args)

            # Tier 1 and tier 2 are correlated together, not separately: a flow both tiers
            # flagged must come out as ONE label carrying both assertions, which is what
            # `best_tier` and the multi-entry `sources[]` exist for. Measured 2026-08-17 —
            # Suricata's single label on a 19,890-flow capture named the same 5-tuple the
            # firewall did.
            if tier1_result is not None:
                detections = (*detections, *tier1_result.detections)

            say.start("correlate", f"{len(detections)} detections")
            progress.correlation = correlate(
                detections,
                flows,
                manifest,
                args.unmatched_threshold,
                indicators,
                device_rulesets=tier1_result.rulesets if tier1_result else None,
            )

            # Inside the `try`, so a failure while rendering NOTICE or serialising is reported
            # like any other. Outside it, such a failure escaped past the handler and left the
            # `run.json` written moments earlier standing as a record of a successful run —
            # complete, plausible, and describing a run that did not finish.
            say.finish(
                "correlate",
                f"{len(progress.correlation.labels)} labels │ "
                f"{len(progress.correlation.unmatched)} unmatched",
            )

            say.start("write", rundir.name)
            code = _write_output(rundir, started_at, progress, manifest)
            say.finish("write", rundir.name)
            say.close()
            return code
        except FlabelError as exc:
            _absorb(progress, exc)
            return _fail(rundir, started_at, progress, exc)
        except Exception as exc:  # noqa: BLE001 — deliberately broad; see `_unexpected`
            traceback.print_exc()
            return _fail(rundir, started_at, progress, _unexpected(exc))


def _tier2(
    progress: _Progress,
    say: progress_mod.Reporter,
    snapshot_dir: Path,
    manifest: SnapshotManifest,
    rundir: Path,
    args: argparse.Namespace,
) -> tuple[tuple[Detection, ...], frozenset[int] | None]:
    """Run Suricata and return its detections with the snapshot's indicator classification.

    Extracted when the stage became conditional (#132). It was inline while every run did it;
    a mode that skips it needs the whole block — the run, the two guards on the snapshot, and
    the operator prompt — to move together, because each of them is meaningless without the
    others and leaving any behind would run a check against a stage that did not happen.
    """
    say.start("suricata", "loading rules")

    detections, progress.suricata = run_suricata(
        progress.capture.path,  # type: ignore[union-attr]
        snapshot_dir,
        rundir / SURICATA_DIR,
    )
    say.finish(
        "suricata",
        f"{progress.suricata.rules_loaded or 0:,} rules │ "
        f"{progress.suricata.alerts_total or 0} alerts",
    )
    if progress.suricata.tool_failures:
        # `run_suricata` records rather than raises, so the one convention the rest of
        # the pipeline uses is restored here and the failure takes the same path as
        # every other (spec §4).
        raise ToolError(
            progress.suricata.tool_failures[0].message,
            failures=progress.suricata.tool_failures,
            run_info=progress.suricata,
        )

    # The manifest handed to `correlate` must be the one Suricata ran (spec §9).
    # `run_suricata` loads a manifest and returns only the id, so this is the second
    # load — and with `--ruleset-snapshot` defaulting to "newest available", a
    # `rules update` landing between the two resolves a *different* snapshot. Every
    # label would then cite a ruleset whose rules never ran: well-formed, and wrong in
    # the field that makes a label reproducible.
    if manifest.snapshot_id != progress.suricata.snapshot_id:
        raise SnapshotError(
            f"the snapshot Suricata ran ({progress.suricata.snapshot_id}) is not the "
            f"one loaded for correlation ({manifest.snapshot_id}); a `rules update` "
            f"landed mid-run, and every label would cite rules that never ran"
        )

    # **After** the assertion above, not before it. `_shortfall` compares the engine's
    # loaded count against *this* manifest's `total_admitted`, so if the two snapshots
    # ever disagree the percentage put to the operator is computed from mismatched
    # inputs — and declining would report "the ruleset was incomplete" in place of the
    # real diagnosis. Order the cheap certainty first.
    if _shortfall(progress.suricata, manifest) and not _confirm_shortfall(
        progress.suricata, manifest
    ):
        # `FlabelError` itself, not `UsageError`: declining is a deliberate stop, and
        # spec §12 reserves exit 2 for an invocation argparse could not express. The
        # operator invoked flabel correctly and then judged the ruleset too incomplete
        # to label against, which is exit 1 — a run that wrote no labels.
        raise FlabelError(
            "stopped at the operator's request: the ruleset was incomplete, so no "
            "labels were written"
        )

    # Read from the snapshot that Suricata actually ran, after the id assertion above
    # (issue #75, PLAN 11c). `None` means this snapshot recorded no per-rule
    # classification — schema 1, or the schema 2 the definition in #79 corrected — and
    # `correlate` then downgrades every basis and says so once in `run.warnings[]`.
    # Deliberately not defaulted to an empty set: "recorded nothing" and "recorded that
    # no rule is an indicator" are different facts about the ruleset.
    indicators = load_address_indicators(snapshot_dir)

    return detections, indicators


def _write_output(
    rundir: Path, started_at: str, progress: _Progress, manifest: SnapshotManifest | None
) -> int:
    """Write the three artifacts of a successful run.

    `labels.json` is written **last**, deliberately. It is the file that claims verdicts, and
    its presence is what a consumer reads as "this run completed" (issue #23). Writing it first
    would mean a failure while rendering NOTICE left behind a directory asserting labels for a
    run that did not finish.

    One run block, assembled once and shared by both documents: two assemblies would let
    `finished_at` differ between two records of the same run, and the copy that drifts is the
    one a reader trusts.
    """
    result = progress.correlation
    assert result is not None, "a successful run always has a correlation result"

    run = _run_block(started_at, progress)
    _write_run_json(rundir, _run_document(run, progress))
    _write_atomic(
        rundir / NOTICE_NAME, render_notice_bytes(result.labels, manifest, result.unmatched)
    )
    _write_atomic(
        rundir / LABELS_NAME,
        serialise_bytes(build_document(run=run, labels=result.labels, unmatched=result.unmatched)),
    )

    print(
        f"flabel: {len(result.labels)} labelled flow(s) of {result.flows_total}, "
        f"{result.detections_total} detection(s) -> {rundir}",
        file=sys.stderr,
    )
    return EXIT_SUCCESS


# --- `flabel rules` ----------------------------------------------------------------------------


def _rules_update(args: argparse.Namespace) -> int:
    """Fetch every enabled source and write one snapshot (spec §5-§7).

    The only network path in the package (spec §2.2). One `fetched_at` for the whole update
    rather than one per feed, because the snapshot is a single act of acquisition and per-feed
    clock readings would make two identical updates produce different manifests.
    """
    specs = enabled_sources(args.sources)
    # Read from the same registry the sources come from, so one `--sources` selects both the
    # feeds and the terms they are admitted on (#75).
    # Per source, unioned with the global table (#113). One read of the registry, so every feed
    # in this snapshot is admitted under the same terms — a second read could see a file edited
    # mid-run and give two feeds different policies inside one snapshot id.
    policies = load_admission_policies(args.sources)
    fetched_at = utc_now()

    admitted: dict[str, list[str]] = {}
    admissions = []
    raw: dict[str, str] = {}
    data: dict[str, dict[str, bytes]] = {}

    for spec in specs:
        text, files = fetch_feed(spec)
        rules, admission = admit(spec, text.splitlines(), fetched_at, policies[spec.name])
        admitted[spec.name] = rules
        admissions.append(admission)
        raw[spec.name] = text
        if files:
            data[spec.name] = files
        print(
            f"flabel: {spec.name}: {admission.rules_admitted} of {admission.rules_fetched} "
            f"admitted",
            file=sys.stderr,
        )

    manifest = write_snapshot(args.rules_dir, admitted, admissions, raw=raw, data=data)
    print(
        f"flabel: snapshot {manifest.snapshot_id}: {manifest.total_admitted} rules from "
        f"{len(manifest.sources)} source(s) in {Path(args.rules_dir) / manifest.snapshot_id}",
        file=sys.stderr,
    )
    return EXIT_SUCCESS


def _rules_list(args: argparse.Namespace) -> int:
    """List the snapshots on disk, newest last, so `--ruleset-snapshot` has known arguments."""
    snapshots, unusable = scan_snapshots(args.rules_dir)

    # On stderr, and before the listing, because this is the subcommand an operator reaches for
    # when a run cited a snapshot id they did not expect (#91). A damaged directory that a
    # labelling run warns about but `rules list` does not mention sends them looking in the one
    # place that has decided not to tell them.
    for name, reason in unusable:
        print(
            f"flabel: warning: {name} is not a usable snapshot and is omitted below: {reason}",
            file=sys.stderr,
        )

    if not snapshots:
        print(
            f"flabel: no ruleset snapshots in {args.rules_dir} — run `flabel rules update`",
            file=sys.stderr,
        )
        return EXIT_SUCCESS

    # stdout, because this subcommand's output *is* data: a caller pipes it to pick an id.
    # The labelling pipeline leaves stdout alone (spec §12); this is not the pipeline. The
    # warnings above are on stderr for the same reason — a damaged-snapshot note in the middle
    # of a list of ids is a line some script will try to parse as an id.
    for manifest in sorted(snapshots, key=lambda entry: entry.created_at):
        print(
            f"{manifest.snapshot_id}  {manifest.created_at}  "
            f"{manifest.total_admitted} rules  {len(manifest.sources)} source(s)"
        )
    return EXIT_SUCCESS


def _rules(argv: Sequence[str]) -> int:
    args = build_rules_parser().parse_args(list(argv))
    if args.action == "update":
        return _rules_update(args)
    return _rules_list(args)


# --- entry point --------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Parse, dispatch, and map every deliberate failure to its exit code (spec §12)."""
    arguments = list(sys.argv[1:] if argv is None else argv)

    try:
        if arguments and arguments[0] == RULES_COMMAND:
            return _rules(arguments[1:])

        args = build_parser().parse_args(arguments)
        if args.sources is not None:
            # Rejected rather than obeyed, and rejected rather than ignored (#71).
            #
            # Obeying it is out of the question: a label's terms — licence, source_class,
            # admission_basis, url — come from the snapshot manifest, never the live registry
            # (spec §4). `enabled` describes the registry now, not what was admitted then, and
            # letting a later registry edit change the reading of an old snapshot would make
            # labels retroactively unattributable. That decision is settled and is not what
            # this changes.
            #
            # What changes is that the flag used to be parsed and discarded. An operator running
            # `flabel --offline capture.pcap --sources my-registry.toml` reasonably believed
            # they had changed which sources may label. They had not, and nothing said so. It is
            # spec §5's own argument — "a registry that loads with a setting silently ignored is
            # worse than one that refuses to load" — applied to the CLI instead of the TOML.
            raise UsageError(
                "--sources has no effect on a labelling run and is refused rather than ignored. "
                "A snapshot carries its own terms: the licence, source class and admission basis "
                "on every label come from the manifest written when the rules were fetched, not "
                "from the registry as it stands now (spec §4). Choosing a registry is something "
                "you do when building a snapshot:\n"
                "\n"
                "    flabel rules update --sources <file>\n"
                "\n"
                "then label against the snapshot it produced, with --ruleset-snapshot <id>."
            )
        if args.ruleset_snapshot is not None and _mode(args) == "replay":
            # Same reasoning as `--sources`, one mode along (#132). A replay-only run loads no
            # Suricata rules, so naming a snapshot cannot change a single label — and an operator
            # who passed one believes they have pinned the rules this run labelled against.
            # Accepting and ignoring it would put that belief in writing, because `run.ruleset`
            # would then either name a snapshot that did not run or contradict the flag they
            # typed. Refusing costs them one retry; ignoring costs them the reading of the
            # artifact.
            raise UsageError(
                "--ruleset-snapshot has no effect on a replay-only run and is refused rather "
                "than ignored: the default pipeline labels from the inline device and loads no "
                "Suricata rules, so there is no ruleset for a snapshot id to select. Add "
                "--both to run Suricata alongside the device, or --offline to run it alone."
            )
        return _label(args)
    except FlabelError as exc:
        # Every deliberate failure inherits from `FlabelError`, so this one clause covers them
        # all.
        print(f"flabel: {exc}", file=sys.stderr)
        return exit_code_for(exc)
    except Exception as exc:  # noqa: BLE001 — a CLI owns its exit code
        # An unforeseen crash still has to exit deliberately. Letting it escape gave exit 1 by
        # accident of the interpreter rather than by decision, and `errors.exit_code_for` already
        # says what a non-`FlabelError` means. The traceback is still printed, because a crash
        # here is a defect and swallowing it would make it harder to fix, not less real.
        traceback.print_exc()
        print(f"flabel: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        return exit_code_for(exc)
