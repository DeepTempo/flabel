"""Which tiers a run may supersede with — spec-label-store §2.4.

**Pure.** Reads a run block and returns a verdict; no client, no network, no clock.

Revision 1 said "only a *delivered* tier supersedes", with delivered defined as
`tier ∈ tiers_attempted and tier ∉ tiers_unavailable`. **That invariant could never fire.** A failed
run is never ingested (§2.5) and `docs/spec.md` §10 states `tiers_unavailable` is empty on every
successful run, so every row in `runs` would have carried `delivered == attempted`.

And the hazard it was written for walked past it. #142 — `fl-replay`'s Suricata 7.0.3 refusing an
8.0 ruleset and loading only part of it — exits 0, writes `labels.json`, publishes, and reports
`tiers_unavailable: []`. Under revision 1 that run *delivered* tier 2 and superseded good knowledge
with an empty result.

So delivery is attested from **positive evidence** instead: a tier counts only when the run block
shows the work actually happened. An unattested tier is **loaded but does not supersede** — its rows
exist and `blfile` will not select them as authoritative, which is the difference between "we have
no record" and "we have a record we will not treat as current".

Attestation is computed here, at ingest, rather than at read time, so the *reason* a tier was
refused can be written beside it in `runs.attestation_notes`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

#: The modes that replay past the inline device, and so can attest tier 1 (`models.TIERS_BY_MODE`).
REPLAY_MODES = frozenset({"replay", "both"})

#: The tool whose failure means tier-1 detections were never retrieved.
TIER_1_TOOL = "panw"


def _attempted(run: Mapping[str, Any]) -> frozenset[int]:
    return frozenset(run.get("tiers_attempted") or ())


def _tier_2(run: Mapping[str, Any]) -> tuple[bool, str | None]:
    """§2.4: attested when `counts.rules_loaded == ruleset.total_admitted`, both non-null, non-zero.

    **`0 == 0` is the trap the non-zero clause closes.** A snapshot that admitted nothing and a
    Suricata that loaded nothing agree perfectly and prove nothing at all.

    **Which clause caught #142, corrected 2026-08-27.** This said `0 == 0` was "#142's exact
    shape". It was not, and the difference matters for what each clause is worth. Measured, #142
    loaded 84,958 of 84,960 — so it was the **equality** clause that refused it, and a threshold
    of "nearly all" would have let it through. The non-zero clause has no incident behind it and
    stays on its own argument: two counts that are both zero are not evidence of agreement.
    """
    loaded = (run.get("counts") or {}).get("rules_loaded")
    total = (run.get("ruleset") or {}).get("total_admitted")

    if loaded is None or total is None:
        return False, (
            f"tier 2 not attested: rules_loaded={loaded!r} and total_admitted={total!r}, and a "
            f"null is 'not measured' — there is no positive evidence the ruleset was loaded"
        )
    if not loaded or not total:
        return False, (
            f"tier 2 not attested: rules_loaded={loaded} of total_admitted={total}. Zero rules "
            f"examined the capture, so an empty alert set says nothing about it (#142)"
        )
    if loaded != total:
        return False, (
            f"tier 2 not attested: {loaded} of {total} admitted rules loaded, so {total - loaded} "
            f"never examined the capture and any label they would have produced is absent from a "
            f"run that otherwise looks complete"
        )
    return True, None


def _tier_1(run: Mapping[str, Any]) -> tuple[bool, str | None]:
    """§2.4: `mode ∈ {replay, both}` and tier-1 detections retrieved without a `panw` tool failure.

    The failure matters because a failed threat-log query returns no detections, which is
    indistinguishable from a capture in which nothing fired — unless the failure is read.
    """
    failures = [
        failure
        for failure in (run.get("tool_failures") or ())
        if (failure.get("tool") if isinstance(failure, Mapping) else getattr(failure, "tool", None))
        == TIER_1_TOOL
    ]
    if failures:
        return False, (
            f"tier 1 not attested: the {TIER_1_TOOL} tool failed, so no threat log was retrieved. "
            f"An empty detection set from a failed query reads exactly like a clean capture"
        )
    return True, None


def tiers(run: Mapping[str, Any]) -> tuple[tuple[int, ...], tuple[str, ...]]:
    """`(tiers_attested, attestation_notes)` for one run block.

    **`attested ⊆ attempted`, always.** A tier the run never asked for earns no note either: a note
    about tier 2 on a replay-only run would read as a complaint about something nobody requested,
    and §9's non-behaviours depend on "no record" and "record we distrust" staying distinguishable.

    Sorted and returned as tuples so two runs of the same shape serialise identically into the
    REPEATED columns of §4.1.
    """
    attempted = _attempted(run)
    mode = run.get("mode")

    attested: list[int] = []
    notes: list[str] = []

    checks = []
    if 1 in attempted and mode in REPLAY_MODES:
        checks.append((1, _tier_1(run)))
    if 2 in attempted:
        checks.append((2, _tier_2(run)))

    for tier, (ok, note) in checks:
        if ok:
            attested.append(tier)
        elif note is not None:
            notes.append(note)

    return tuple(sorted(attested)), tuple(notes)


def unattested(attempted: Sequence[int], attested: Sequence[int]) -> tuple[int, ...]:
    """Attempted but not attested — loaded, and not authoritative. For readable reporting."""
    return tuple(sorted(set(attempted) - set(attested)))
