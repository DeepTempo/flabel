"""The `NOTICE` file that ships beside `labels.json` (spec §10).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.

It lists **every source that asserted at least one label in this run**, with its licence and
what that licence requires of whoever redistributes the output. Sources present in the snapshot
that asserted nothing are not listed: the snapshot describes what was *available*, and NOTICE
describes what was *used*. Printing the whole snapshot would be the shorter implementation and
would read as a claim that every feed contributed to these verdicts.

**The terms come from the snapshot, never from `data/sources.toml` as it reads now** — the same
authority `build_source_entry` uses above, and for the same reason: between `flabel rules
update` and a labelling run an upstream licence can be corrected, and a NOTICE built from the
live registry would state today's terms over yesterday's rules. Since a label already carries
the licence it was admitted under, the two records are cross-checked here and a disagreement is
refused rather than resolved by picking one.

Nothing in the file is wall-clock: everything datable comes from the snapshot, which is frozen.
The run directory is compared after canonicalisation for Goal 2, and a generation timestamp
would make it differ on every run for no analytic reason.
"""

from __future__ import annotations

from collections.abc import Sequence

from flabel.models import Label, SnapshotManifest

#: What each licence actually asks of someone redistributing labels derived from its rules.
#: Keyed by the SPDX id the registry records (spec §5). Deliberately a statement of the
#: obligation rather than the licence text: an operator reading NOTICE needs to know what they
#: must do, and an SPDX id on its own leaves them to go and look it up.
#:
#: This is not legal advice and does not replace the licence; it is a pointer to the duty.
ATTRIBUTION: dict[str, str] = {
    "CC0-1.0": (
        "Public-domain dedication. No attribution required; listed here so every verdict's "
        "origin is traceable."
    ),
    "MIT": (
        "Attribution required: the copyright notice and permission notice must accompany "
        "redistribution of these rules or works derived from them."
    ),
    "CC-BY-4.0": (
        "Attribution required: credit the source, link to the licence, and indicate whether "
        "changes were made."
    ),
    "CC-BY-SA-4.0": (
        "Attribution required, and share-alike: credit the source, link to the licence, "
        "indicate changes, and license derivative rule sets under the same terms."
    ),
    "GPL-3.0-only": (
        "Attribution required, and copyleft: redistributing these rules or a derivative "
        "requires GPL-3.0-only terms and corresponding source."
    ),
    "unstated": (
        "The source states no licence. Terms are unknown — do not redistribute these rules "
        "without establishing them."
    ),
}

#: Used when the registry names an SPDX id this module has no obligation text for. It states
#: the gap instead of printing a generic paragraph, which would be a claim about terms flabel
#: cannot substantiate — the same never-do as a label whose origin cannot be traced (spec §13).
UNRECORDED = (
    "Licence terms not recorded in flabel. Consult the source's own licence before redistributing."
)

HEADER = "flabel — attribution for the rule sources that asserted labels in this run"


def labelling_sources(labels: Sequence[Label]) -> dict[str, str]:
    """Source name -> licence, for every source that asserted at least one label.

    The licence is read off the `SourceEntry`, which froze it at snapshot time. A source
    appears once however many labels or entries it asserted.

    A source asserting two different licences within one run is a corrupted snapshot rather
    than a formatting problem, so it raises: printing either one would be a coin toss.
    """
    licences: dict[str, str] = {}
    for label in labels:
        for entry in label.sources:
            existing = licences.setdefault(entry.source, entry.licence)
            if existing != entry.licence:
                raise ValueError(
                    f"{entry.source} asserted labels under two licences, {existing!r} and "
                    f"{entry.licence!r}: attribution cannot be stated for either"
                )
    return licences


def render_notice(labels: Sequence[Label], manifest: SnapshotManifest) -> str:
    """The `NOTICE` text for this run.

    `manifest` supplies each source's URL and is the authority the labels are checked against;
    `labels` decides who is listed at all.
    """
    # The manifest's own index, not a fourth copy of the same comprehension (#49): uniqueness
    # is guaranteed on the type, so this cannot silently drop an entry the way a local
    # dict-comprehension over a tuple with a repeated name would.
    admissions = manifest.sources_by_name
    licences = labelling_sources(labels)

    lines = [
        HEADER,
        "",
        f"Ruleset snapshot: {manifest.snapshot_id}",
        "",
    ]

    if not licences:
        lines.append(
            "This run asserted no labels, so no rule source requires attribution here. The "
            "snapshot's full source list is in labels.json under run.ruleset.sources."
        )
        return "\n".join(lines) + "\n"

    # Sorted by name so a differently-ordered `sources` tuple cannot reorder the file — the
    # run directory is compared for Goal 2 like any other artifact.
    for name in sorted(licences):
        admission = admissions.get(name)
        if admission is None:
            # An attribution flabel cannot substantiate must not be invented. Correlation
            # already refuses a detection whose source is absent from the manifest, so
            # reaching here means a label was built against a different snapshot.
            raise ValueError(
                f"{name} asserted a label but is absent from snapshot {manifest.snapshot_id}: "
                f"its attribution cannot be established"
            )
        licence = licences[name]
        if admission.licence != licence:
            raise ValueError(
                f"{name} labels cite licence {licence!r} but snapshot "
                f"{manifest.snapshot_id} recorded {admission.licence!r}: two records of one "
                f"fact disagree, and neither can be published as the terms"
            )

        lines.extend(
            [
                name,
                f"  Licence: {licence}",
                f"  Source:  {admission.url}",
                f"  {ATTRIBUTION.get(licence, UNRECORDED)}",
                "",
            ]
        )

    return "\n".join(lines).rstrip("\n") + "\n"
