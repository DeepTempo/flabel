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

from flabel.config import load_admission_policies
from flabel.rules.admit import marker_of
from flabel.rules.snapshot import RULES_NAME, load_sid_index, load_snapshot
from flabel.suricata import SID

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
#: The brand is deliberately NOT in the set above. `marker_of` never returns it while the
#: registry names it as `msg_brand_marker`, so seeing it means the feed changed the shape of its
#: own prefix — which is exactly the event worth failing on.

#: What was measured when the policy shipped. Not asserted exactly — upstream churns ~570 rules a
#: day — but it is the anchor the band below is built from.
EXPECTED_EXCLUDED = 445

#: The band the exclusion count must stay inside. A **floor** as well as a ceiling, which the
#: first draft lacked: with only `excluded == 0` to catch a shrinking policy, upstream could
#: re-mark 440 of the 445 rules under a marker this policy does not exclude and the gate would
#: pass on 5 — "the policy still bites" asserted at one rule in 445. That is the floor-of-one
#: weakness this repo has been burned by before.
#:
#: The ceiling is a share of the feed rather than a multiple of the anchor. `corpus_gate` uses a
#: 10x multiple, but there it bounds a handful of tolerated false-positive entries; here it would
#: bound the DELETION of detection rules, and 445 x 10 is 4,450 — 20.7% of a feed whose policy is
#: sold as costing 2.1%.
FLOOR_FACTOR = 10
CEILING_SHARE = 0.05


def markers_of_admitted(rules: list[str], brand: str | None) -> Counter[str]:
    """Every marker appearing on an admitted rule, counted.

    `brand` is the feed's own logo, which is on every rule and classifies nothing — passed in
    from the shipped policy so the census reads a rule exactly the way `admit` did.
    """
    return Counter(marker for rule in rules if (marker := marker_of(rule, brand)) is not None)


def verify(
    rules_dir: Path,
    expected_excluded: int = EXPECTED_EXCLUDED,
    ceiling_share: float = CEILING_SHARE,
) -> int:
    """0 if the convention still holds, 1 with a diagnosis if it has moved.

    Takes the rules *root* and resolves the newest snapshot inside it, which is what
    `flabel rules update --rules-dir` writes and therefore what the scheduled workflow has.

    `expected_excluded` and `ceiling_share` are arguments so both bounds are reachable from a
    test against a small fixture — the same reason `corpus_gate.verify` takes its inputs rather
    than reading them. The shipped values are asserted separately, against the real feed's size,
    by `test_the_shipped_band_brackets_what_was_measured`.
    """
    directory, manifest, warnings = load_snapshot(rules_dir, None)
    for warning in warnings:
        # Returned rather than printed by `load_snapshot` precisely so a caller has to unpack it
        # to ignore it. Ignoring it here would be that argument made and then discarded.
        print(f"note: {warning}")
    rules_text = (directory / RULES_NAME).read_text(encoding="utf-8")
    admissions = {admission.name: admission for admission in manifest.sources}

    policy = load_admission_policies()[SOURCE]
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

    floor = expected_excluded // FLOOR_FACTOR
    if excluded < floor:
        print(
            f"FAIL: only {excluded} rules excluded by marker, under the floor of {floor} "
            f"({expected_excluded} // {FLOOR_FACTOR}). Non-zero is not the same as working: "
            f"upstream re-marking the observational rules under a marker this policy does not "
            f"name would leave a handful excluded and #117 otherwise restored."
        )
        return 1

    ceiling = int(admission.rules_fetched * ceiling_share)
    if excluded > ceiling:
        print(
            f"FAIL: {excluded} rules excluded by marker, over the ceiling of {ceiling} "
            f"({ceiling_share:.0%} of the {admission.rules_fetched} fetched). A convention "
            f"change that made most of the feed look observational would delete real detection "
            f"rules while every other gate stayed green."
        )
        return 1

    source_rules = _rules_of_source(rules_text, load_sid_index(directory))
    seen = markers_of_admitted(source_rules, policy.msg_brand_marker)
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


def _rules_of_source(rules_text: str, index: dict[int, str]) -> list[str]:
    """The admitted rules belonging to `SOURCE`, by the snapshot's own attribution.

    By `sid_index.json` rather than by looking for the feed's logo in the rule text. The first
    draft did the latter, and it was circular: the census exists to detect the convention
    CHANGING, so a feed that stopped writing its brand would drop out of its own census — the
    rules would be admitted with an unrecognised marker and the check that should have caught it
    would no longer be looking at them. The sid index is what spec §8 already calls the authority
    on where a rule came from.
    """
    rules = []
    for line in rules_text.splitlines():
        if not line.startswith("alert"):
            continue
        match = SID.search(line)
        if match and index.get(int(match.group(1))) == SOURCE:
            rules.append(line)
    return rules


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <rules-dir>", file=sys.stderr)
        return 2
    return verify(Path(argv[1]))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
