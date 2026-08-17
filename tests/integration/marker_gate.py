"""The convention watch: is pawpatrules still marking its rules the way the policy assumes?

Issue #117 keys an admission policy on an **emoji in rule text**. `sources.toml` argued that
reversal at length, and this module is the half that makes it defensible: the convention is not
trusted, it is watched. A feed can change its own `msg:` text without notice, and the failure that
would follow is the quiet kind — the policy stays in the registry reading as though it is in force
while excluding nothing, which is issue #75 reappearing through the mechanism built to prevent it.

Three properties, each a different way the convention can move:

1. **The policy still bites.** `rules_excluded_marker` for pawpatrules is non-zero. If the feed
   drops the emoji, or renames it, this is what goes to zero.
2. **It has not run away.** The count stays inside an order of magnitude of what was measured.
   The same reasoning as `corpus_gate.COUNT_CEILING_FACTOR`: exact counts are too brittle to
   assert against a feed that changes daily, but "no bound at all" is not the only alternative —
   a convention change that made every rule look observational would otherwise pass silently
   while gutting the feed.
3. **No unclassified marker is being admitted.** Every marker on an admitted rule is one someone
   has looked at and placed on one side or the other. A NEW marker is the interesting event: it
   means the feed grew a category, and nobody has decided whether it detects or observes.

Run it against a real snapshot:

    uv run python tests/integration/marker_gate.py .flabel/rules

Like `corpus_gate`, the verdict is `verify` — it takes its inputs as arguments and returns an exit
code, and `main` is argv parsing and nothing else. A gate whose logic lives inside `main` cannot be
proved able to fail, which this repo has now learned four separate times.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from flabel.rules.admit import marker_of
from flabel.rules.snapshot import RULES_NAME, load_snapshot

SOURCE = "pawpatrules"

#: Markers seen on admitted rules when the policy was written, measured 2026-08-17 against the
#: 2026-08-12 mirror. Each was read and placed: these DETECT, or are the feed's own brand.
#:
#: The set is the point. A marker not in here is not necessarily wrong — it is *unreviewed*, and
#: the whole argument for keying a policy on this convention is that a change to it is loud.
KNOWN_ADMITTED_MARKERS = frozenset(
    {
        "\N{POLICE CARS REVOLVING LIGHT}",  # 9,669 — detection
        "\N{WAVING BLACK FLAG}",  # 6,910 — flagged address (pirate flag ZWJ sequence)
        "\N{SKULL AND CROSSBONES}",  # 3,859 — C2 / malware family
        "\N{WARNING SIGN}",  # 265 — malware infrastructure
        "\N{BELL}",  # 81 — recon and lateral movement; kept deliberately (#118)
        "\N{FIRE}",  # 34 — FireEye BEACON signatures
        "\N{BIOHAZARD SIGN}",  # 32 — trojan download
        "\N{SKULL}",  # 10 — suspicious download
        "\N{EYES}",  # 1 — HTTP direct to a public IP
    }
)

#: What was measured when the policy shipped. Not asserted exactly — upstream churns ~570 rules a
#: day — but it is the anchor the ceiling below is a multiple of.
EXPECTED_EXCLUDED = 445
CEILING_FACTOR = 10


def markers_of_admitted(rules: list[str]) -> Counter[str]:
    """Every marker appearing on an admitted rule, counted."""
    return Counter(marker for rule in rules if (marker := marker_of(rule)) is not None)


def verify(rules_dir: Path, expected_excluded: int = EXPECTED_EXCLUDED) -> int:
    """0 if the convention still holds, 1 with a diagnosis if it has moved.

    Takes the rules *root* and resolves the newest snapshot inside it, which is what
    `flabel rules update --rules-dir` writes and therefore what the scheduled workflow has.
    """
    directory, manifest, _ = load_snapshot(rules_dir, None)
    rules_text = (directory / RULES_NAME).read_text(encoding="utf-8")
    admissions = {admission.name: admission for admission in manifest.sources}

    admission = admissions.get(SOURCE)
    if admission is None:
        print(f"FAIL: {SOURCE} is not in the snapshot at all, so its policy reviewed nothing")
        return 1

    excluded = admission.rules_excluded_marker
    print(f"{SOURCE}: {admission.rules_admitted} admitted, {excluded} excluded by marker")

    if excluded == 0:
        print(
            "FAIL: the marker policy excluded NOTHING. Either the feed stopped writing the "
            "convention `sources.toml` keys on, or the policy was dropped from the registry. "
            "Issue #117 is back either way: the observational rules are being admitted and "
            "`go.dev` is a `verdict: malicious` label again."
        )
        return 1

    ceiling = expected_excluded * CEILING_FACTOR
    if excluded > ceiling:
        print(
            f"FAIL: {excluded} rules excluded by marker, over the ceiling of {ceiling} "
            f"({expected_excluded} x {CEILING_FACTOR}). A convention change that made most of "
            f"the feed look observational would gut it while every other gate stayed green."
        )
        return 1

    source_rules = [
        rule for rule in rules_text.splitlines() if rule.startswith("alert") and _is_paw(rule)
    ]
    seen = markers_of_admitted(source_rules)
    unknown = sorted(set(seen) - KNOWN_ADMITTED_MARKERS)
    if unknown:
        for marker in unknown:
            print(f"FAIL: unreviewed marker {marker!r} on {seen[marker]} admitted rules")
        print(
            "The feed has grown a marker nobody has classified. Read a sample and decide whether "
            "it detects or observes, then add it to KNOWN_ADMITTED_MARKERS or to the registry's "
            "`exclude_msg_markers`. This is the event the watch exists for."
        )
        return 1

    print(f"markers on admitted rules, all reviewed: {''.join(sorted(seen))}")
    return 0


def _is_paw(rule: str) -> bool:
    """Whether a rule is one of this feed's, by its brand prefix.

    The snapshot concatenates every source's rules into one file and the sid index is the
    authority on origin — but a marker census only needs the rules carrying the convention, and
    the brand prefix identifies those exactly. A rule from another feed that happened to start
    with a paw print would be counted; none of the other eight uses emoji in `msg:` at all.
    """
    return "\N{PAW PRINTS}" in rule


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <rules-dir>", file=sys.stderr)
        return 2
    return verify(Path(argv[1]))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
