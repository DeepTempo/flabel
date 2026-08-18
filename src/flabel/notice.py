"""The `NOTICE` file that ships beside `labels.json` (spec §10).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.

It lists **every source whose rule text appears anywhere in this run's output**, with its
licence and what that licence requires of whoever redistributes it. That is a wider set than the
sources that asserted a label (Craig, 2026-08-12): `unmatched_detections[].detection.threat` is
verbatim rule `msg:` text from sources that asserted nothing, and several admitted feeds are
CC-BY, share-alike or copyleft. Attribution must not depend on whether a detection happened to
correlate, which is an accident of the capture rather than anything about the source.

Sources present in the snapshot but absent from the output are still not listed: the snapshot
describes what was *available*, and NOTICE describes what was *used*. Printing the whole snapshot
would be the shorter implementation and would read as a claim that every feed contributed.

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

from flabel.models import DEVICE_LICENCE, Label, SnapshotManifest, UnmatchedDetection

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

HEADER = "flabel — attribution for the rule sources whose content appears in this run's output"


def labelling_sources(
    labels: Sequence[Label],
    unmatched: Sequence[UnmatchedDetection] = (),
    manifest: SnapshotManifest | None = None,
) -> dict[str, str]:
    """Source name -> licence, for every source whose rule text appears in this run's output.

    **Not only the sources that asserted a label** (Craig, 2026-08-12). Spec §10 originally
    scoped `NOTICE` to `labels[].sources`, but `unmatched_detections[].detection.threat` is
    verbatim rule `msg:` text copied into `labels.json` from sources that asserted nothing — and
    several admitted feeds are CC-BY-4.0, CC-BY-SA-4.0 or GPL-3.0-only, whose terms ask for
    attribution wherever their text is redistributed. Scoping attribution to whether a detection
    happened to *correlate* would make a licence obligation depend on an accident of the capture.

    Over-attributing costs a longer file; under-attributing is a licence breach in the one
    artifact that carries legal weight, in a public repo.

    The licence comes off the `SourceEntry` where there is one, because that froze it at
    snapshot time. An unmatched detection carries no entry, so its source is resolved through
    `manifest` — the same authority, one step less direct.

    A source appearing under two different licences within one run is a corrupted snapshot
    rather than a formatting problem, so it raises: printing either would be a coin toss.
    """
    licences: dict[str, str] = {}

    def record(source: str, licence: str) -> None:
        existing = licences.setdefault(source, licence)
        if existing != licence:
            raise ValueError(
                f"{source} appears under two licences, {existing!r} and {licence!r}: "
                f"attribution cannot be stated for either"
            )

    for label in labels:
        for entry in label.sources:
            record(entry.source, entry.licence)

    # Sources reached only through an unmatched detection. Their text is in the output just the
    # same; only the verdict is absent.
    if unmatched and manifest is not None:
        admissions = manifest.sources_by_name
        for item in unmatched:
            admission = admissions.get(item.detection.source)
            if admission is not None:
                record(admission.name, admission.licence)

    return licences


def render_notice(
    labels: Sequence[Label],
    manifest: SnapshotManifest,
    unmatched: Sequence[UnmatchedDetection] = (),
) -> str:
    """The `NOTICE` text for this run.

    `manifest` supplies each source's URL and is the authority the labels are checked against.
    `labels` and `unmatched` together decide who is listed — every source whose text reached the
    output, not only those that reached a verdict.
    """
    # The manifest's own index, not a fourth copy of the same comprehension (#49): uniqueness
    # is guaranteed on the type, so this cannot silently drop an entry the way a local
    # dict-comprehension over a tuple with a repeated name would.
    admissions = manifest.sources_by_name
    licences = labelling_sources(labels, unmatched, manifest)

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
        if admission is None and licences[name] == DEVICE_LICENCE:
            # A tier-1 source has no snapshot entry and never will: its signatures are the
            # vendor's, not a feed flabel admitted (Phase 2, #122). It is still listed rather
            # than skipped, because a threat *name* is vendor text that appears verbatim in the
            # output, and NOTICE is the record of whose text is in there — but what it records
            # is the absence of an obligation, which is a statement, not a gap.
            lines.extend(
                [
                    name,
                    f"    {DEVICE_LICENCE}",
                    "    No attribution obligation: these are proprietary device signatures, and",
                    "    this output is not redistributed. The signature set and the device policy",
                    "    that admitted each detection are named per-label in sources[].ruleset.",
                    "",
                ]
            )
            continue
        if admission is None:
            # An attribution flabel cannot substantiate must not be invented. Correlation
            # already refuses a detection whose source is absent from the manifest, so
            # reaching here means a label was built against a different snapshot.
            raise ValueError(
                f"{name} appears in this run's output but is absent from snapshot "
                f"{manifest.snapshot_id}: its attribution cannot be established"
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


def render_notice_bytes(
    labels: Sequence[Label],
    manifest: SnapshotManifest,
    unmatched: Sequence[UnmatchedDetection] = (),
) -> bytes:
    """The `NOTICE` text as UTF-8 bytes — what a caller writes to disk.

    Same reasoning as `labels.serialise_bytes`: `Path.write_text` encodes with the locale
    encoding, which is ASCII under `LANG=C`, so a source name or licence string carrying a
    non-ASCII character would raise after a successful run or silently write mojibake. NOTICE is
    the artifact with legal weight, so garbling it is worse here than almost anywhere else.
    """
    return render_notice(labels, manifest, unmatched).encode("utf-8")
