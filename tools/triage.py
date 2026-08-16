"""Run many captures and summarise what fired — the operator's triage loop (#113).

WHY THIS EXISTS

Issue #113 was found by running one internet-facing capture and then hand-writing Python to ask
"which rules produced these 555 labels". That question is the same every time, and the answer is
the whole value of a labelling run to someone deciding whether to trust it. Writing it once, with
tests, beats writing it again per capture.

WHAT IT IS NOT

**Not a gate, and not CI.** `tests/integration/corpus_gate.py` is the gate: it runs a committed
corpus and fails on anything not argued for in `tolerated.json`. This is exploration — it has no
opinion about pass or fail, it reports. The two must not be confused, because a tool that reports
"nothing unusual" is not evidence of anything, and the gate is.

**Not for committed fixtures.** Real captures carry real addresses and real payloads. They cannot
go in a public repo (`docs/spec.md` §13, and `tests/fixtures/README.md` on what a fixture must
clear), so this points at a directory outside the tree and writes its output there too.

**Not part of the CLI.** Spec §12's contract is closed — `--offline` is permanent and Phase 2 adds
no flags — so this is a script beside the package rather than a `flabel` subcommand.

THE ONE HEURISTIC WORTH HAVING

`PREVALENCE`. A sid firing on nearly every capture is describing the internet rather than the
traffic; a sid firing on one capture is a finding. That single ratio is what makes 587 scanner
entries legible at a glance instead of after an afternoon — the Censys and Palo Alto rules of
#113 fire on every internet-facing capture there is, and the Realtek exploit attempt fired once.

It is a prompt, not a verdict. A genuinely compromised fleet would trip one real rule everywhere,
and a rare false positive is still a false positive. The column says what was measured and leaves
the judgement where it belongs.

    uv run python tools/triage.py /path/to/captures/*.pcap --output-dir /path/to/runs
    uv run python tools/triage.py --report /path/to/runs
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: What identifies a rule's contribution across captures. `label_basis` is part of the key for
#: the reason `corpus_gate` gives: a rule that starts claiming `direct` where it claimed
#: `indicator-reference` is asserting that ordinary traffic *is* an attack, and that is a change
#: worth seeing even though the sid did not move.
EntryKey = tuple[str, int, str, str]

#: A sid firing on at least this share of captures is flagged as ubiquitous. Two thirds rather
#: than "all", because a scanner rule misses the captures taken behind NAT and would otherwise
#: read as specific. Tuned for prompting a human, not for deciding anything.
UBIQUITOUS = 2 / 3


@dataclass(frozen=True)
class CaptureRun:
    """One capture's outcome, read from its run directory."""

    name: str
    flows: int | None
    detections: int | None
    labels: int | None
    unmatched: int | None
    unmatched_ratio: float | None
    threshold: float | None
    input_status: str | None
    rules_loaded: int | None
    total_admitted: int | None
    snapshot: str | None
    warnings: tuple[str, ...] = ()
    #: Why this run cannot be read at face value, if anything. Empty means sound.
    concerns: tuple[str, ...] = ()
    entries: Counter[EntryKey] = field(default_factory=Counter)

    @property
    def failed(self) -> bool:
        """A run that wrote no `labels.json` — it died (#23), and its zero is not a zero."""
        return self.labels is None


def prevalence(seen: int, captures: int, comparable: bool = True) -> str:
    """How widely a rule fired: `EVERY`, `one`, or nothing.

    A function rather than an expression inside the formatter, because it is the one piece of
    judgement in this tool and a test should be able to reach it without parsing a text table.
    The first version of these tests did parse the table, and matched the wrong rows twice.

    Zero captures yields nothing rather than dividing — a report over no sound runs has no
    prevalence to describe.

    `comparable=False` blanks it for the same reason. When the runs used different snapshots the
    denominator mixes rulesets, so "fired on 4 of 6" counts captures that could not all have
    fired it. Found by pointing this tool at its own author's output: two runs of one capture
    spanning the #113 fix reported `EVERY` for rules present in both and `one` for the two
    scanner rules that had been *removed* — the exact inversion of the truth. A caveat printed
    elsewhere does not fix a column that is wrong.
    """
    if captures <= 0 or not comparable:
        return ""
    if seen == 1:
        return "one"
    return "EVERY" if seen / captures >= UBIQUITOUS else ""


@dataclass(frozen=True)
class Report:
    runs: tuple[CaptureRun, ...]
    #: Every source entry across every capture, and how many captures each appeared in.
    totals: Counter[EntryKey]
    captures_per_key: dict[EntryKey, int]


def _concerns(run: dict[str, Any]) -> tuple[str, ...]:
    """Why this run reviewed less than it appears to, or `()`.

    Read from the run's own block rather than inferred, and reported rather than raised: the
    point of triage is to see everything at once, including the runs that are not trustworthy.
    Silently averaging them into the totals is how a partial ruleset becomes a claim about
    coverage.
    """
    found = []
    counts, ruleset, capture = run["counts"], run["ruleset"], run["input"]

    loaded, admitted = counts.get("rules_loaded"), ruleset.get("total_admitted")
    if loaded is not None and admitted is not None and loaded != admitted:
        found.append(f"loaded {loaded} of {admitted} rules — a partial ruleset")
    if capture.get("input_status") not in (None, "complete"):
        found.append(f"input_status {capture.get('input_status')!r} — less than the whole capture")
    if counts.get("unmatched"):
        found.append(
            f"{counts['unmatched']} detection(s) placed on no flow "
            f"(ratio {counts.get('unmatched_ratio')}, threshold {run.get('unmatched_threshold')})"
        )
    if capture.get("discarded_packets"):
        found.append(f"{capture['discarded_packets']} packet(s) discarded as a foreign link type")
    return tuple(found)


def read_run(rundir: Path) -> CaptureRun:
    """One run directory as a `CaptureRun`. Never raises for a run that failed.

    A failed run is data — it is the answer to "why did this capture produce nothing" — so it is
    reported with `labels=None` rather than skipped or counted as a clean zero. That distinction
    is issue #23's whole subject, one level up: absence of `labels.json` means the run died.
    """
    name = rundir.name
    labels_path, run_path = rundir / "labels.json", rundir / "run.json"
    source = labels_path if labels_path.exists() else run_path
    if not source.exists():
        # Named rather than positional: the count of `None`s is not something a reader should
        # have to verify against the field order, and getting it wrong is a TypeError only on
        # the path that is hardest to reach.
        return CaptureRun(
            name=name,
            flows=None,
            detections=None,
            labels=None,
            unmatched=None,
            unmatched_ratio=None,
            threshold=None,
            input_status=None,
            rules_loaded=None,
            total_admitted=None,
            snapshot=None,
            concerns=("wrote neither labels.json nor run.json — killed?",),
        )

    document = json.loads(source.read_text(encoding="utf-8"))
    run = document["run"]
    counts = run["counts"]
    entries: Counter[EntryKey] = Counter()
    for label in document.get("labels", []):
        for entry in label["sources"]:
            entries[
                (entry["source"], entry["sid"], entry["label_basis"], entry["classtype"] or "-")
            ] += 1

    concerns = list(_concerns(run))
    if not labels_path.exists():
        concerns.insert(0, "wrote no labels.json — the run FAILED, so this is not zero labels")

    return CaptureRun(
        name=name,
        flows=counts.get("flows"),
        detections=counts.get("detections"),
        labels=counts.get("labels") if labels_path.exists() else None,
        unmatched=counts.get("unmatched"),
        unmatched_ratio=counts.get("unmatched_ratio"),
        threshold=run.get("unmatched_threshold"),
        input_status=run["input"].get("input_status"),
        rules_loaded=counts.get("rules_loaded"),
        total_admitted=run["ruleset"].get("total_admitted"),
        snapshot=run["ruleset"].get("snapshot_id"),
        warnings=tuple(run.get("warnings", ())),
        concerns=tuple(concerns),
        entries=entries,
    )


def summarise(rundirs: list[Path]) -> Report:
    """Every run, plus per-key totals and how many captures each key appeared in."""
    runs = tuple(read_run(d) for d in sorted(rundirs))
    totals: Counter[EntryKey] = Counter()
    captures: dict[EntryKey, int] = defaultdict(int)
    for run in runs:
        totals.update(run.entries)
        for key in run.entries:
            captures[key] += 1
    return Report(runs, totals, dict(captures))


def format_report(report: Report) -> str:
    """The whole summary as text. Pure, so a test can read it rather than a terminal."""
    runs = report.runs
    out: list[str] = []
    scored = [r for r in runs if not r.failed]

    out.append(f"=== {len(runs)} capture(s) ===")
    out.append(f"{'capture':52s} {'flows':>8s} {'detns':>6s} {'labels':>7s}  notes")
    for r in runs:
        note = "FAILED" if r.failed else ("!" * len(r.concerns) if r.concerns else "")
        out.append(
            f"{_fit(r.name):52s} {_num(r.flows):>8s} {_num(r.detections):>6s} "
            f"{_num(r.labels):>7s}  {note}"
        )

    if scored:
        out.append("")
        out.append(
            f"totals: {sum(r.labels or 0 for r in scored)} labels, "
            f"{sum(report.totals.values())} source entries, "
            f"{sum(r.flows or 0 for r in scored)} flows"
        )
        snapshots = {r.snapshot for r in scored if r.snapshot}
        if len(snapshots) > 1:
            out.append(
                f"  WARNING: {len(snapshots)} different snapshots across these runs "
                f"({', '.join(sorted(snapshots))}) — they are not comparable"
            )
        elif snapshots:
            out.append(f"  snapshot: {snapshots.pop()}")

    if report.totals:
        n = len(scored)
        # Prevalence across a ruleset change is a share of a denominator that mixes rulesets, so
        # the column is suppressed rather than caveated — see `prevalence`.
        comparable = len({r.snapshot for r in scored if r.snapshot}) <= 1
        out.append("")
        out.append("=== what fired, most entries first ===")
        out.append(
            f"{'entries':>8s} {'caps':>5s} {'':4s} {'source':14s} {'sid':>9s}  "
            f"{'basis':20s} {'classtype':20s}"
        )
        for key, count in report.totals.most_common():
            source, sid, basis, classtype = key
            seen = report.captures_per_key[key]
            flag = prevalence(seen, n, comparable)
            out.append(
                f"{count:8d} {seen:5d} {flag:>4s} {source:14s} {sid:9d}  "
                f"{basis:20s} {classtype:20s}"
            )
        out.append("")
        if not comparable:
            out.append(
                "  the caps flag is BLANK because these runs used different snapshots: the "
                "denominator would\n  mix rulesets, so a share of it would not mean anything. "
                "Re-run them against one snapshot."
            )
        out.append(
            "  caps = how many captures the rule fired on. `EVERY` means it fired on at least "
            f"{UBIQUITOUS:.0%} of\n  them, which usually means it describes the internet rather "
            "than this traffic — that is how\n  #113's scanner rules looked. `one` is where a "
            "real finding usually is. Neither is a verdict."
        )

    unsound = [r for r in runs if r.concerns]
    if unsound:
        out.append("")
        out.append("=== runs that cannot be read at face value ===")
        for r in unsound:
            for concern in r.concerns:
                out.append(f"  {_fit(r.name):52s} {concern}")

    noted = [(r, w) for r in runs for w in r.warnings]
    if noted:
        out.append("")
        out.append(f"=== {len(noted)} run warning(s) ===")
        seen_once: set[str] = set()
        for _run, w in noted:
            head = w.split(":")[0][:70]
            if head in seen_once:
                continue
            seen_once.add(head)
            count = sum(1 for _, other in noted if other.split(":")[0][:70] == head)
            out.append(f"  x{count:<4d} {head}")

    return "\n".join(out)


def _num(value: int | None) -> str:
    return "-" if value is None else str(value)


def _fit(name: str, width: int = 52) -> str:
    """A run directory name at `width`, keeping the END rather than the start.

    Run directories are `{capture}_{timestamp}Z`, so two runs of one capture differ only in the
    suffix — truncating from the right made them display identically, which is exactly the case
    a reader most needs to tell apart. Found by using the tool.
    """
    return name if len(name) <= width else "…" + name[-(width - 1) :]


# --- driving the runs -----------------------------------------------------------------------


def label_one(capture: Path, output_dir: Path, rules_dir: Path | None) -> tuple[Path, int, str]:
    """Run `flabel --offline` over one capture. Returns (capture, exit code, stderr tail).

    Invoked as a subprocess rather than by importing `cli.main`, deliberately: that is how an
    operator runs it, it isolates a crash to one capture, and it is what makes `--jobs` possible
    at all — the pipeline is not written to be re-entered in one process.
    """
    argv = [
        "uv",
        "run",
        "flabel",
        "--offline",
        str(capture),
        "--output-dir",
        str(output_dir),
    ]
    if rules_dir is not None:
        argv += ["--rules-dir", str(rules_dir)]
    done = subprocess.run(argv, capture_output=True, text=True)
    return capture, done.returncode, done.stderr.strip().splitlines()[-1] if done.stderr else ""


def run_captures(
    captures: list[Path], output_dir: Path, rules_dir: Path | None, jobs: int
) -> list[tuple[Path, int, str]]:
    """Label every capture, up to `jobs` at once, reporting each as it finishes.

    Suricata loading an 85k ruleset is ~20s of mostly single-threaded work per capture, so a
    directory of them is dominated by that and parallelises almost linearly. Measured 2026-08-16:
    17 small captures took over ten minutes sequentially.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(label_one, c, output_dir, rules_dir): c for c in captures}
        for done in concurrent.futures.as_completed(futures):
            capture, code, tail = done.result()
            results.append((capture, code, tail))
            status = "ok" if code == 0 else f"EXIT {code}"
            print(f"  [{len(results)}/{len(captures)}] {capture.name} — {status}", file=sys.stderr)
            if code != 0 and tail:
                print(f"        {tail[:160]}", file=sys.stderr)
    return sorted(results)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="triage.py",
        description="Run many captures through flabel and summarise what fired.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("captures", nargs="*", type=Path, help="captures, or a directory of them")
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        metavar="DIR",
        help="skip running: summarise the run directories already under DIR",
    )
    parser.add_argument("--output-dir", type=Path, default=None, metavar="DIR")
    parser.add_argument("--rules-dir", type=Path, default=None, metavar="DIR")
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(8, (os.cpu_count() or 2)),
        metavar="N",
        help="captures to label at once (default: min(8, cores))",
    )
    args = parser.parse_args(argv[1:])

    if args.report is not None:
        if not args.report.is_dir():
            print(f"{args.report} is not a directory", file=sys.stderr)
            return 2
        rundirs = [p for p in args.report.iterdir() if p.is_dir()]
        if not rundirs:
            print(f"{args.report} holds no run directories", file=sys.stderr)
            return 2
        print(format_report(summarise(rundirs)))
        return 0

    if not args.captures or args.output_dir is None:
        parser.error("give captures and --output-dir, or --report DIR")

    captures = _expand(args.captures)
    if not captures:
        print("no captures matched", file=sys.stderr)
        return 2
    if args.jobs < 1:
        parser.error("--jobs must be at least 1")

    print(f"labelling {len(captures)} capture(s), {args.jobs} at a time…", file=sys.stderr)
    results = run_captures(captures, args.output_dir, args.rules_dir, args.jobs)
    failed = [c for c, code, _ in results if code != 0]

    rundirs = [p for p in args.output_dir.iterdir() if p.is_dir()]
    print()
    print(format_report(summarise(rundirs)))
    if failed:
        # Non-zero, because a summary over a subset that does not say so is the failure this
        # whole project keeps finding. The report above still prints — the captures that did
        # run are still worth reading.
        print(f"\n{len(failed)} capture(s) did not label: {', '.join(c.name for c in failed)}")
        return 1
    return 0


def _expand(paths: list[Path]) -> list[Path]:
    """Directories become the captures inside them; files are taken as given.

    `*.pcap*` rather than `*.pcap`, so a `.pcapng` or a `.pcap.gz` in the directory cannot be
    silently left unreviewed — the same glob, and the same reasoning, as `corpus_gate.CAPTURE_GLOB`.
    """
    found: list[Path] = []
    for path in paths:
        found.extend(sorted(path.glob("*.pcap*")) if path.is_dir() else [path])
    return found


if __name__ == "__main__":  # pragma: no cover - exercised through main/summarise
    sys.exit(main(sys.argv))
