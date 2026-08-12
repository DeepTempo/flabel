"""Measure the admission filter against real feeds — the reproducer for issue #11.

Not a test, and never run by the suite: `pytest` does not collect this name, and the suite may
not contact a rule-feed endpoint (docs/spec.md §2). It lives here for the same reason
`make_canary.py` does — it produces fixture-grade facts that a human runs deliberately.

Two modes, and the offline one is the point:

    # once, with a network: fetch the nine feeds and keep the exact payloads
    uv run python tests/fixtures/rules/measure_feeds.py --live --save /tmp/feed-mirror

    # thereafter, offline and byte-for-byte reproducible, including in an air-gapped lab
    uv run python tests/fixtures/rules/measure_feeds.py --mirror /tmp/feed-mirror

A mirror is a directory holding one payload per source at `<mirror>/<source name>` — so
`<mirror>/et/open` and `<mirror>/abuse.ch/urlhaus`. `--save` writes exactly that layout.

`--snapshot <dir>` additionally writes a real snapshot from the result, which is how the
snapshot id, the sid index and the companion data files were checked at full scale.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from flabel.config import enabled_sources
from flabel.errors import FlabelError
from flabel.models import SourceSpec
from flabel.rules import utc_now
from flabel.rules.admit import admit
from flabel.rules.fetch import Fetcher, HttpsFetcher, LocalFetcher, extract_feed
from flabel.rules.snapshot import load_sid_index, load_snapshot, write_snapshot

COLUMNS = (
    f"{'source':26} {'basis':16} {'fetched':>8} {'admitted':>9} {'%':>6} {'no-conf':>8} "
    f"{'low-conf':>9} {'low-sev':>8} {'unload':>7} {'#alert':>7} {'ja3':>4} {'ja4':>4} "
    f"{'data':>5}"
)


def mirror_path(root: Path, spec: SourceSpec) -> Path:
    """Where a mirror keeps one source's payload. The `/` in a name becomes a directory."""
    return root.joinpath(*spec.name.split("/"))


def transport(args: argparse.Namespace, specs: tuple[SourceSpec, ...]) -> Fetcher:
    if args.mirror:
        return LocalFetcher({spec.url: mirror_path(args.mirror, spec) for spec in specs})
    return HttpsFetcher()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--mirror", type=Path, help="read payloads from this mirror directory")
    source.add_argument("--live", action="store_true", help="fetch from the registry URLs")
    parser.add_argument("--save", type=Path, help="with --live, write a mirror for later reuse")
    parser.add_argument("--sources", type=Path, help="registry override, as --sources does")
    parser.add_argument("--snapshot", type=Path, help="also write a snapshot under this root")
    args = parser.parse_args()

    specs = enabled_sources(args.sources)
    fetcher = transport(args, specs)
    fetched_at = utc_now()

    admitted: dict[str, list[str]] = {}
    admissions = []
    raw: dict[str, str] = {}
    data: dict[str, dict[str, bytes]] = {}
    failures = 0

    print(COLUMNS)
    print("-" * len(COLUMNS))
    for spec in specs:
        try:
            payload = fetcher.read(spec.url)
            if args.save:
                target = mirror_path(args.save, spec)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            text, files = extract_feed(payload, spec.url)
            rules, counts = admit(spec, text.splitlines(), fetched_at)
        except FlabelError as exc:
            # Printed rather than raised: one dead feed should not hide the other eight from a
            # measurement run, even though a real `rules update` fails on it.
            print(f"!! {spec.name}: {exc}")
            failures += 1
            continue

        admitted[spec.name] = rules
        admissions.append(counts)
        raw[spec.name] = text
        if files:
            data[spec.name] = files

        share = 100 * counts.rules_admitted / counts.rules_fetched
        print(
            f"{counts.name:26} {counts.admission_basis:16} {counts.rules_fetched:8} "
            f"{counts.rules_admitted:9} {share:5.1f}% {counts.rules_excluded_no_confidence:8} "
            f"{counts.rules_excluded_low_confidence:9} {counts.rules_excluded_low_severity:8} "
            f"{counts.rules_excluded_unloadable:7} {counts.rules_excluded_commented:7} "
            f"{counts.ja3_rules_admitted:4} {counts.ja4_rules_admitted:4} {len(files):5}"
        )

    if not admissions:
        print("no source produced any rules")
        return 1

    totals = _totals(admissions)
    print("-" * len(COLUMNS))
    print(totals)

    for admission in admissions:
        accounted = (
            admission.rules_admitted
            + admission.rules_excluded_no_confidence
            + admission.rules_excluded_low_confidence
            + admission.rules_excluded_low_severity
            + admission.rules_excluded_unloadable
        )
        assert accounted == admission.rules_fetched, f"{admission.name} does not balance"
    print("spec §6 identity holds for every source: fetched == admitted + sum(excluded)")

    if args.snapshot:
        manifest = write_snapshot(args.snapshot, admitted, admissions, raw=raw, data=data)
        directory, reloaded = load_snapshot(args.snapshot, manifest.snapshot_id)
        index = load_sid_index(directory)
        print(f"\nsnapshot {manifest.snapshot_id} at {directory}")
        print(f"  rules.rules      {(directory / 'rules.rules').stat().st_size:>12} bytes")
        print(f"  sid_index.json   {len(index):>12} sids over {len(reloaded.sources)} sources")
        print(f"  data files       {sum(len(files) for files in data.values()):>12}")
        print(f"  reload verified: {reloaded == manifest}")

    return 1 if failures else 0


def _totals(admissions: list) -> str:
    fetched = sum(a.rules_fetched for a in admissions)
    admitted = sum(a.rules_admitted for a in admissions)
    return (
        f"{'TOTAL':26} {'':16} {fetched:8} {admitted:9} {100 * admitted / fetched:5.1f}% "
        f"{sum(a.rules_excluded_no_confidence for a in admissions):8} "
        f"{sum(a.rules_excluded_low_confidence for a in admissions):9} "
        f"{sum(a.rules_excluded_low_severity for a in admissions):8} "
        f"{sum(a.rules_excluded_unloadable for a in admissions):7} "
        f"{sum(a.rules_excluded_commented for a in admissions):7} "
        f"{sum(a.ja3_rules_admitted for a in admissions):4} "
        f"{sum(a.ja4_rules_admitted for a in admissions):4}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
