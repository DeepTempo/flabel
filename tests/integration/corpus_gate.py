"""The broad false-positive review: the benign corpus against a real ruleset (PLAN step 11d).

Extracted from `.github/workflows/feeds.yml` rather than written inside it, and the reason is this
session's own lesson twice over. A gate whose logic lives in a YAML heredoc runs only on the
schedule that invokes it, so nothing can prove it is able to *fail* — which is how the Goal 2
reproducibility gate came to be hollowed out with CI green (fixed in #74), and how three of step
13's fixes shipped with tests that passed against the unfixed code (fixed in #98).

So the decision is a function here, `unaccounted`, and `tests/integration/test_corpus_gate.py`
feeds it synthetic label documents to prove it fails on a new offender and passes on the known
residue. The workflow calls `main`.

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

#: What identifies a source entry for this gate. `label_basis` is part of the key on purpose: a
#: tolerated rule that starts claiming `direct` where it claimed `indicator-reference` is asserting
#: that ordinary traffic *is* an attack, and that is a regression even though the sid is unchanged.
EntryKey = tuple[str, int, str]


class Offender(NamedTuple):
    """A source entry the tolerated list does not account for."""

    capture: str
    source: dict[str, Any]


class Review(NamedTuple):
    """What the corpus produced, and which of it was unexpected."""

    labels_total: int
    seen: Counter[EntryKey]
    offenders: list[Offender]
    #: Tolerated entries that did not fire. Not a failure — an improvement to act on.
    stale: list[EntryKey]


def entry_key(source: dict[str, Any]) -> EntryKey:
    return (source["source"], source["sid"], source["label_basis"])


def load_tolerated(path: Path = TOLERATED) -> dict[EntryKey, dict[str, Any]]:
    """The known-and-argued-for entries, keyed for lookup.

    Every entry must carry a non-empty `reason`. An allowlist that can be appended to without
    argument is how a false-positive review stops being one — the same reasoning `canonical`'s
    `EXCLUDED_FILES` docstring gives for keeping its list small and justified per name.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    tolerated: dict[EntryKey, dict[str, Any]] = {}
    for entry in document["entries"]:
        if not entry.get("reason", "").strip():
            raise ValueError(
                f"tolerated entry {entry.get('source')} sid {entry.get('sid')} has no reason: "
                f"an entry with no argument for it is not an entry"
            )
        tolerated[entry_key(entry)] = entry
    return tolerated


def review(rundirs: list[Path], tolerated: dict[EntryKey, dict[str, Any]]) -> Review:
    """Every source entry the corpus produced, split into accounted-for and not.

    Raises rather than returning for a run that produced no `labels.json`: that is a pipeline
    failure, and reading it as "this capture produced no labels" is issue #23's defect — the
    absence of the file is the signal that the run died.
    """
    seen: Counter[EntryKey] = Counter()
    offenders: list[Offender] = []
    labels_total = 0

    for rundir in rundirs:
        labels_path = rundir / "labels.json"
        if not labels_path.exists():
            run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))
            raise RuntimeError(f"{rundir.name} wrote no labels.json — it failed: {run['run']}")

        document = json.loads(labels_path.read_text(encoding="utf-8"))
        labels_total += len(document["labels"])
        for label in document["labels"]:
            for source in label["sources"]:
                key = entry_key(source)
                seen[key] += 1
                if key not in tolerated:
                    offenders.append(Offender(rundir.name, source))

    stale = [key for key in tolerated if key not in seen]
    return Review(labels_total, seen, offenders, stale)


def unaccounted(rundirs: list[Path], tolerated: dict[EntryKey, dict[str, Any]]) -> list[Offender]:
    """Just the verdict, for a caller that only needs pass or fail."""
    return review(rundirs, tolerated).offenders


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <directory-of-run-directories>", file=sys.stderr)
        return 2
    root = Path(argv[1])

    captures = sorted(CORPUS.glob("*.pcap"))
    if not captures:
        print("the corpus is empty — this gate would pass by measuring nothing", file=sys.stderr)
        return 1

    rundirs = sorted(p for p in root.iterdir() if p.is_dir())
    if len(rundirs) != len(captures):
        print(
            f"{len(captures)} captures but {len(rundirs)} run directories: a capture failed to "
            f"produce output, so this gate did not review it",
            file=sys.stderr,
        )
        return 1

    tolerated = load_tolerated()
    try:
        result = review(rundirs, tolerated)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"captures   : {len(rundirs)}")
    print(f"labels     : {result.labels_total}")
    print(f"entries    : {sum(result.seen.values())}")
    for key, count in sorted(result.seen.items(), key=lambda kv: -kv[1]):
        source, sid, basis = key
        known = "known" if key in tolerated else "NEW"
        print(f"  {count:4d}x  {basis:20s} {source} sid {sid}  [{known}]")

    for source, sid, basis in result.stale:
        print(
            f"NOTE: tolerated {source} sid {sid} ({basis}) no longer fires — consider removing it"
        )

    if result.offenders:
        for capture, source in result.offenders:
            print(
                f"NEW FALSE POSITIVE: {capture}: {source['source']} sid {source['sid']} "
                f"rev {source['rev']} basis {source['label_basis']} — {source['threat']}",
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

    print("Goal 5 broad: no unaccounted-for label on 17 real protocol captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
