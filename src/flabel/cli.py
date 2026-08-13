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
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from flabel import __version__
from flabel.config import enabled_sources
from flabel.correlate import DEFAULT_THRESHOLD, _check_threshold, correlate
from flabel.errors import (
    EXIT_SUCCESS,
    CorrelationError,
    FlabelError,
    NotImplementedInPhase1,
    SnapshotError,
    ToolError,
    UsageError,
    exit_code_for,
)
from flabel.ingest import normalize
from flabel.labels import build_document, serialise_bytes
from flabel.models import (
    CorrelationResult,
    NormalizedCapture,
    SnapshotManifest,
    SuricataRunInfo,
    ToolFailure,
    ZeekRunInfo,
)
from flabel.notice import render_notice_bytes
from flabel.provenance import build_run_block
from flabel.rules import utc_now
from flabel.rules.admit import admit
from flabel.rules.fetch import fetch_feed
from flabel.rules.snapshot import list_snapshots, load_snapshot, write_snapshot
from flabel.suricata import run_suricata
from flabel.zeek import run_zeek

#: What the Phase 1 default path prints (US-22). Exact text, because it is the string an
#: operator will search for and the one the test asserts.
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
    """The labelling parser: `flabel <capture>` and `flabel --offline <capture>` (spec §12)."""
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
    parser.add_argument(
        "--offline",
        action="store_true",
        help="run the Tier 2 (Suricata + Zeek) pipeline. Permanent — Phase 2 adds no flags.",
    )
    parser.add_argument(
        "--ruleset-snapshot",
        default=None,
        metavar="ID",
        help="ruleset snapshot to label against (default: newest available)",
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
        help="source registry (default: the packaged data/sources.toml)",
    )
    parser.add_argument(
        "--unmatched-threshold",
        type=unmatched_threshold,
        default=DEFAULT_THRESHOLD,
        metavar="FLOAT",
        help=f"fail above this share of unplaced detections (default: {DEFAULT_THRESHOLD})",
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
            if len(name) > len(suffix) and name.lower().endswith(suffix):
                name = name[: -len(suffix)]
                changed = True
                break
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

    capture: NormalizedCapture | None = None
    manifest: SnapshotManifest | None = None
    zeek: ZeekRunInfo | None = None
    suricata: SuricataRunInfo | None = None
    correlation: CorrelationResult | None = None
    snapshot_resolved: bool | None = None
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
        snapshot_resolved=progress.snapshot_resolved,
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
    unmatched = progress.correlation.unmatched if progress.correlation else ()
    document = build_document(run=run, labels=(), unmatched=unmatched)
    del document["labels"]
    return document


def _write_run_json(rundir: Path, document: dict[str, Any]) -> None:
    (rundir / RUN_NAME).write_bytes(serialise_bytes(document))


def _fail(rundir: Path, started_at: str, progress: _Progress, exc: FlabelError) -> int:
    """Report a run that died: `run.json`, no `labels.json`, and the exception's exit code."""
    print(f"flabel: {exc}", file=sys.stderr)
    _write_run_json(rundir, _run_document(_run_block(started_at, progress), progress))
    print(f"flabel: run details in {rundir / RUN_NAME}; no labels were written", file=sys.stderr)
    return exit_code_for(exc)


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


def _shortfall(info: SuricataRunInfo, manifest: SnapshotManifest) -> bool:
    """Did the engine load less than the snapshot admitted?

    Three signals rather than one, because they fail differently: `rules_failed` is a rule this
    build cannot parse, `rules_skipped` is one dropped for duplicating another's SID, and a
    `rules_loaded` below `total_admitted` is rules that went missing without the engine saying
    which counter they belong to.
    """
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

    if not stdin_is_a_tty():
        print(
            "flabel: continuing (stdin is not a terminal, so the default answer applies)",
            file=sys.stderr,
        )
        return True

    try:
        answer = input("flabel: label this capture with the rules that did load? [Y/n] ")
    except EOFError:
        return True
    return not answer.strip().lower().startswith("n")


# --- the labelling run ------------------------------------------------------------------------


def _label(args: argparse.Namespace) -> int:
    """Wire ingest -> zeek -> suricata -> correlate -> labels into one run directory.

    The order of the first two steps is spec §12's, not an accident. A missing snapshot and an
    unreadable capture are the two failures it says leave *no* run directory: nothing ran, so
    there is no run to report, and a directory holding a `run.json` that says "nothing happened"
    would be litter. Everything after that is a run that died, and a run that died reports.
    """
    started = datetime.now(UTC)
    started_at = _stamp(started)
    progress = _Progress()

    # Before any directory exists: `SnapshotError` propagates to `main` (spec §12).
    snapshot_dir, manifest = load_snapshot(args.rules_dir, args.ruleset_snapshot)
    progress.manifest = manifest
    progress.snapshot_resolved = True

    with TemporaryDirectory(prefix=TEMP_PREFIX) as workdir:
        # The normalized capture lives here and nowhere else (spec §10). Not in the run
        # directory: it is derived, it would double the output's size, and spec §13 forbids
        # copying capture data outside the run directory — which includes not adding a second
        # copy of the operator's packets to an artifact they will ship somewhere.
        try:
            progress.capture = normalize(args.capture, Path(workdir))
        except ToolError as exc:
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
            flows, progress.zeek = run_zeek(progress.capture.path, rundir / ZEEK_DIR)

            detections, progress.suricata = run_suricata(
                progress.capture.path, snapshot_dir, rundir / SURICATA_DIR
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

            progress.correlation = correlate(detections, flows, manifest, args.unmatched_threshold)
        except FlabelError as exc:
            _absorb(progress, exc)
            return _fail(rundir, started_at, progress, exc)

        return _write_output(rundir, started_at, progress, manifest)


def _write_output(
    rundir: Path, started_at: str, progress: _Progress, manifest: SnapshotManifest
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
    (rundir / NOTICE_NAME).write_bytes(
        render_notice_bytes(result.labels, manifest, result.unmatched)
    )
    (rundir / LABELS_NAME).write_bytes(
        serialise_bytes(build_document(run=run, labels=result.labels, unmatched=result.unmatched))
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
    fetched_at = utc_now()

    admitted: dict[str, list[str]] = {}
    admissions = []
    raw: dict[str, str] = {}
    data: dict[str, dict[str, bytes]] = {}

    for spec in specs:
        text, files = fetch_feed(spec)
        rules, admission = admit(spec, text.splitlines(), fetched_at)
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
    snapshots = list_snapshots(args.rules_dir)
    if not snapshots:
        print(
            f"flabel: no ruleset snapshots in {args.rules_dir} — run `flabel rules update`",
            file=sys.stderr,
        )
        return EXIT_SUCCESS

    # stdout, because this subcommand's output *is* data: a caller pipes it to pick an id.
    # The labelling pipeline leaves stdout alone (spec §12); this is not the pipeline.
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
        if not args.offline:
            raise NotImplementedInPhase1(
                f"{STUB_MESSAGE}\n"
                f"Tier 1 (PANW NGFW) labelling is Phase 2 and is not built yet. "
                f"For the Tier 2 pipeline — Suricata and Zeek reading the capture file — "
                f"run: flabel --offline {args.capture}"
            )
        return _label(args)
    except FlabelError as exc:
        # Every deliberate failure inherits from `FlabelError`, so this one clause covers them
        # all. Anything else is an unforeseen crash and is left to escape as a traceback rather
        # than being flattened into an exit code that would imply flabel understood it.
        print(f"flabel: {exc}", file=sys.stderr)
        return exit_code_for(exc)
