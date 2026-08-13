"""Shared helpers for the end-to-end gates (PLAN.md step 10).

These tests drive `cli.main` for real — the whole pipeline, the real toolchain, a real snapshot
written by `write_snapshot`. Nothing here stubs a stage, because the gates exist to prove the
assembled thing behaves, and a stub would prove the assembly instead.

The snapshot helper is local to this package rather than shared with `tests/test_cli.py`: that
one builds snapshots to exercise the CLI's own branches, this one builds them to be *labelled
against*, and a single helper serving both would grow parameters until it served neither.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from flabel.rules.snapshot import write_snapshot

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BENIGN = FIXTURES / "benign.pcap"
SYNTHETIC_RULES = FIXTURES / "rules" / "synthetic.rules"


def rule_lines() -> dict[int, str]:
    lines = {}
    for line in SYNTHETIC_RULES.read_text(encoding="utf-8").splitlines():
        if not line.startswith("alert"):
            continue
        match = re.search(r"\bsid:(\d+);", line)
        assert match is not None, f"synthetic rule has no sid: {line}"
        lines[int(match.group(1))] = line
    return lines


RULES = rule_lines()

#: Matches the benign canary's HTTP flows. Used where a gate needs labels to exist.
MATCHES_CANARY = 9000001

#: Rules that cannot match the benign canary: it carries no UDP, no ICMP and no TLS. Used where a
#: gate needs a *loaded, real* ruleset that nonetheless asserts nothing about this capture.
MISSES_CANARY = (9000006, 9000007, 9000008)


def build_snapshot(
    root: Path,
    contents: Mapping[str, Sequence[int]],
    classes: Mapping[str, str] | None = None,
) -> Path:
    """A real snapshot under `root`, written by step 4's own writer."""
    from flabel.models import SourceAdmission

    classes = classes or {}
    admitted = {name: [RULES[sid] for sid in sorted(contents[name])] for name in sorted(contents)}
    admissions = [
        SourceAdmission(
            name=name,
            url=f"https://example.invalid/{name}.rules",
            licence="MIT",
            source_class=classes.get(name, "signature"),
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
    manifest = write_snapshot(root, admitted, admissions, created_at="2026-08-12T00:00:00.000000Z")
    return root / manifest.snapshot_id


def offline(capture: Path, rules_dir: Path, output_dir: Path, *extra: str) -> list[str]:
    return [
        "--offline",
        str(capture),
        "--rules-dir",
        str(rules_dir),
        "--output-dir",
        str(output_dir),
        *extra,
    ]


def only_run_dir(output_dir: Path) -> Path:
    directories = sorted(path for path in output_dir.iterdir() if path.is_dir())
    assert len(directories) == 1, f"expected exactly one run directory, found {directories}"
    return directories[0]


def truncate_mid_record(source: Path, destination: Path, keep: int = 8) -> Path:
    """A copy of `source` holding `keep` whole packets and then a record cut part-way through.

    Walking the record headers rather than slicing at an arbitrary byte, because the two failure
    modes are different and only one of them is the loss condition under test. Cutting too early
    leaves a pcap with *no* complete packet, and Suricata then fails to read a first timestamp at
    all — a tool failure, not a truncated input. Spec §11's row is about a capture that is read
    successfully and is short, which is the ordinary real-world case.
    """
    import struct

    data = source.read_bytes()
    offset, ends = 24, []
    while offset + 16 <= len(data):
        incl_len = struct.unpack("<I", data[offset + 8 : offset + 12])[0]
        offset += 16 + incl_len
        ends.append(offset)

    assert len(ends) > keep, f"{source} has only {len(ends)} packets; cannot keep {keep}"
    destination.write_bytes(data[: ends[keep - 1] + 8])
    return destination
