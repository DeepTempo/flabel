"""The broad false-positive review: the benign corpus against a real ruleset (PLAN step 11d).

Extracted from `.github/workflows/feeds.yml` rather than written inside it, and the reason is this
session's own lesson three times over. A gate whose logic lives in a YAML heredoc runs only on the
schedule that invokes it, so nothing can prove it is able to *fail* — which is how the Goal 2
reproducibility gate came to be hollowed out with CI green (#74), how three of step 13's fixes
shipped with tests that passed against the unfixed code (#98), and how the first version of *this*
module put every guard inside `main` where no test reached it (found reviewing #101; turning its
`return 1` into `return 0` left all eight tests green).

So the verdict is `verify`, which takes its inputs as arguments and returns an exit code. `main` is
argv parsing and nothing else. `test_corpus_gate.py` calls `verify` directly with a one-capture
list, which is what makes the failure paths testable at all — the run-directory count guard demands
one directory per capture, so proving the offender path against the real 17 would mean fabricating
seventeen.

Run it directly against a directory of run directories:

    uv run python tests/integration/corpus_gate.py corpus-runs
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "benign-corpus"
TOLERATED = CORPUS / "tolerated.json"

#: `*.pcap*` rather than `*.pcap`, so a `.pcapng` added to the corpus cannot be silently
#: unreviewed. `benign-corpus/README.md` invites additions and `test_the_corpus_is_actually_present`
#: only asserts a floor, so a narrower glob here would have dropped one without a word.
CAPTURE_GLOB = "*.pcap*"

#: What identifies a source entry for this gate. `label_basis` is part of the key on purpose: a
#: tolerated rule that starts claiming `direct` where it claimed `indicator-reference` is asserting
#: that ordinary traffic *is* an attack, and that is a regression even though the sid is unchanged.
#: Reachable for real — it is what a regression in step 11c's composition produces.
EntryKey = tuple[str, int, str]

LEGAL_BASES = frozenset({"direct", "indicator-reference"})

#: How far a tolerated entry may grow before it is treated as a new defect.
#:
#: Exact counts are too brittle to assert — upstream rule text changes daily — but "no bound at
#: all" is not the only alternative. sid 3317444's destination is literally `127.0.0.1`: if upstream
#: broadens it, one tolerated entry could swallow the whole corpus and this gate would print the
#: hits and exit 0. An order of magnitude keeps all the churn tolerance and closes the blow-up.
COUNT_CEILING_FACTOR = 10

#: A ceiling on the allowlist itself. Three entries can become thirty by appending, one reviewed
#: diff at a time, with nothing ever noticing the trend — so a fourth entry has to raise this
#: number deliberately rather than ride along in a list. Growth should be an argument, not a habit.
MAX_TOLERATED = 3


class Offender(NamedTuple):
    """A source entry the tolerated list does not account for."""

    capture: str
    source: dict[str, Any]
    #: Why it failed, so the message names the cause rather than restating the entry.
    why: str


class Review(NamedTuple):
    """What the corpus produced, and which of it was unexpected."""

    labels_total: int
    seen: Counter[EntryKey]
    offenders: list[Offender]
    #: Tolerated entries that did not fire. Not a failure — an improvement to act on.
    stale: list[EntryKey]
    #: Runs whose own `run.json` says they reviewed less than the whole ruleset or capture.
    unsound: list[str]


def entry_key(source: dict[str, Any]) -> EntryKey:
    return (source["source"], source["sid"], source["label_basis"])


def load_tolerated(path: Path = TOLERATED) -> dict[EntryKey, dict[str, Any]]:
    """The known-and-argued-for entries, keyed for lookup.

    Validated here rather than only in a test over the committed file, because `load_tolerated`
    is public and a caller may point it anywhere. Each check exists for a failure that would
    otherwise diagnose wrong:

    * A **duplicate triple** would silently collapse last-wins, so a reviewer reads one reason
      and the code applies the other — the same shape as the duplicate-source-name defect in
      `_read_manifest` (#49) that this repo decided not to paper over.
    * A **sid as a string** passes a naive reason check and then never matches an int sid, so the
      entry reads as stale *and* the real false positive reads as new. Two wrong answers from one
      typo.
    * A **`label_basis` outside the two legal values** would make an entry unmatchable in the same
      way.
    * An **empty reason** makes the list an allowlist rather than a review. `"TODO"` still passes
      this, and human PR review is the only real defence — said plainly rather than implied.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = document["entries"]

    if len(entries) > MAX_TOLERATED:
        raise ValueError(
            f"{len(entries)} tolerated entries, over the {MAX_TOLERATED} this gate allows. Raising "
            f"the ceiling is the argument to make in review — appending to the list is not"
        )

    tolerated: dict[EntryKey, dict[str, Any]] = {}
    for entry in entries:
        missing = {"source", "sid", "label_basis", "reason"} - set(entry)
        if missing:
            raise ValueError(f"tolerated entry {entry} is missing {sorted(missing)}")
        if not isinstance(entry["sid"], int) or isinstance(entry["sid"], bool):
            raise ValueError(
                f"tolerated sid {entry['sid']!r} is not an integer: it would never match a real "
                f"detection, so the entry would read as stale and the false positive as new"
            )
        if entry["label_basis"] not in LEGAL_BASES:
            raise ValueError(
                f"tolerated entry {entry['source']} sid {entry['sid']} has label_basis "
                f"{entry['label_basis']!r}, not one of {sorted(LEGAL_BASES)}"
            )
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise ValueError(
                f"tolerated entry {entry['source']} sid {entry['sid']} has no reason: an entry "
                f"with no argument for it is not an entry"
            )
        key = entry_key(entry)
        if key in tolerated:
            raise ValueError(
                f"tolerated entry {key} appears twice: one reason would be read in review and the "
                f"other applied by the gate"
            )
        tolerated[key] = entry
    return tolerated


def _unsound(rundir: Path) -> str | None:
    """Why this run reviewed less than it claims to have, or `None` if it is sound.

    Read from the run's own `run.json`, because the data is already on disk and the alternative is
    a gate that prints "no unaccounted-for label on 17 real protocol captures" about a run that
    loaded forty rules. `_confirm_shortfall` proceeds by default when stdin is not a TTY, which CI
    never is, so a per-run rule-load shortfall is a warning and nothing more.
    """
    path = rundir / "run.json"
    if not path.exists():
        return "wrote no run.json"
    run = json.loads(path.read_text(encoding="utf-8"))["run"]

    loaded = run["counts"]["rules_loaded"]
    admitted = run["ruleset"]["total_admitted"]
    if loaded != admitted:
        return f"loaded {loaded} of {admitted} admitted rules, so it reviewed a partial ruleset"

    status = run["input"]["input_status"]
    if status != "complete":
        return f"input_status is {status!r}, so it reviewed less than the capture"
    return None


def review(rundirs: list[Path], tolerated: dict[EntryKey, dict[str, Any]]) -> Review:
    """Every source entry the corpus produced, split into accounted-for and not.

    Raises rather than returning for a run that produced no `labels.json`: that is a pipeline
    failure, and reading it as "this capture produced no labels" is issue #23's defect — the
    absence of the file is the signal that the run died.
    """
    seen: Counter[EntryKey] = Counter()
    offenders: list[Offender] = []
    unsound: list[str] = []
    labels_total = 0

    for rundir in rundirs:
        labels_path = rundir / "labels.json"
        if not labels_path.exists():
            # `run.json` may be absent too — a run killed between mkdir and the first write. Read
            # it only if it is there, so the message is about the missing labels either way.
            run_path = rundir / "run.json"
            detail = (
                run_path.read_text(encoding="utf-8")[:400]
                if run_path.exists()
                else "no run.json either"
            )
            raise RuntimeError(f"{rundir.name} wrote no labels.json — it failed: {detail}")

        reason = _unsound(rundir)
        if reason is not None:
            unsound.append(f"{rundir.name}: {reason}")

        document = json.loads(labels_path.read_text(encoding="utf-8"))
        labels_total += len(document["labels"])
        for label in document["labels"]:
            for source in label["sources"]:
                key = entry_key(source)
                seen[key] += 1
                if key not in tolerated:
                    offenders.append(Offender(rundir.name, source, "not in tolerated.json"))

    # A tolerated entry that blew up is a new defect wearing a known sid.
    for key, entry in tolerated.items():
        ceiling = entry.get("count_when_measured", 0) * COUNT_CEILING_FACTOR
        if ceiling and seen[key] > ceiling:
            offenders.append(
                Offender(
                    "(across the corpus)",
                    {**entry, "rev": "-", "threat": entry["reason"][:60]},
                    f"fired {seen[key]}x against {entry['count_when_measured']}x when measured, "
                    f"over the {COUNT_CEILING_FACTOR}x ceiling",
                )
            )

    stale = [key for key in tolerated if key not in seen]
    return Review(labels_total, seen, offenders, stale, unsound)


def unaccounted(rundirs: list[Path], tolerated: dict[EntryKey, dict[str, Any]]) -> list[Offender]:
    """Just the offenders, for a caller that only needs pass or fail."""
    return review(rundirs, tolerated).offenders


def verify(root: Path, captures: list[Path], tolerated: dict[EntryKey, dict[str, Any]]) -> int:
    """The whole verdict, as an exit code. Every guard lives here so every guard is testable.

    Takes `captures` and `tolerated` as arguments rather than reading them itself, which is what
    lets a test pass a one-capture list: the count guard below demands one run directory per
    capture, so proving the offender path against the real corpus would mean fabricating
    seventeen directories.
    """
    if not captures:
        print("the corpus is empty — this gate would pass by measuring nothing", file=sys.stderr)
        return 1

    if not root.is_dir():
        print(
            f"{root} does not exist: the labelling step produced nothing, so this gate reviewed "
            f"nothing. Read that step's log — the failure is upstream of here.",
            file=sys.stderr,
        )
        return 1

    rundirs = sorted(p for p in root.iterdir() if p.is_dir())
    if len(rundirs) != len(captures):
        print(
            f"{len(captures)} captures but {len(rundirs)} run directories: a capture failed to "
            f"produce output, so this gate did not review it",
            file=sys.stderr,
        )
        return 1

    try:
        result = review(rundirs, tolerated)
    except (RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"a run directory could not be read: {exc}", file=sys.stderr)
        return 1

    print(f"captures   : {len(rundirs)}")
    print(f"labels     : {result.labels_total}")
    print(f"entries    : {sum(result.seen.values())}")
    for key, count in sorted(result.seen.items(), key=lambda kv: -kv[1]):
        source, sid, basis = key
        known = "known" if key in tolerated else "NEW"
        print(f"  {count:4d}x  {basis:20s} {source} sid {sid}  [{known}]")

    # stderr, not stdout: a note nobody reads on a green scheduled run is a note that lets the
    # allowlist drift into permanence.
    for source, sid, basis in result.stale:
        print(
            f"NOTE: tolerated {source} sid {sid} ({basis}) no longer fires — remove it from "
            f"tolerated.json and lower the ceiling",
            file=sys.stderr,
        )

    if result.unsound:
        for line in result.unsound:
            print(f"UNSOUND RUN: {line}", file=sys.stderr)
        print(
            "\nAt least one run reviewed less than the whole ruleset or the whole capture, so "
            "'no false positives' would be a stronger claim than what was measured.",
            file=sys.stderr,
        )
        return 1

    if result.offenders:
        for capture, source, why in result.offenders:
            print(
                f"NEW FALSE POSITIVE: {capture}: {source['source']} sid {source['sid']} "
                f"rev {source['rev']} basis {source['label_basis']} — {why} — {source['threat']}",
                file=sys.stderr,
            )
        print(
            f"\n{len(result.offenders)} source entr(y/ies) on ordinary protocol traffic that "
            f"tolerated.json does not account for. This is issue #75's defect recurring. Decide "
            f"whether the rule is wrong, the admission policy should exclude it, or the label is "
            f"fair — and if it is fair, add it to that file WITH A REASON. Do not delete a capture "
            f"to make this pass.",
            file=sys.stderr,
        )
        return 1

    print(f"Goal 5 broad: no unaccounted-for label on {len(rundirs)} real protocol captures")
    return 0


def main(argv: list[str]) -> int:
    """argv parsing only. The verdict is `verify`, so that the verdict can be tested."""
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <directory-of-run-directories>", file=sys.stderr)
        return 2
    try:
        tolerated = load_tolerated()
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"tolerated.json is unusable: {exc}", file=sys.stderr)
        return 1
    return verify(Path(argv[1]), sorted(CORPUS.glob(CAPTURE_GLOB)), tolerated)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
