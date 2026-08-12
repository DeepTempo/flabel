"""Assembling what a label says about its own origin (spec §4, §10).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.

This module currently holds one function. `build_source_entry` is pre-placed here ahead of
steps 7 and 8 (#44) because both need it and neither owns it. Step 7 cannot avoid it —
`CorrelationResult.labels` is `tuple[Label, ...]` and a `Label` requires `SourceEntry` values —
while PLAN step 8 assigns the derivation of `label_basis`, `admission_basis` and `licence` to
the labelling side. Two parallel worktrees writing that separately is precisely how steps 3-6
produced three incompatible tool-failure conventions; the fix there was one shape in one place,
and the fix here is the same one applied before the collision rather than after.

The run block (spec §10) is step 8's to build and lands in this module later.
"""

from __future__ import annotations

from flabel.models import Detection, SourceEntry, SourceSpec


def build_source_entry(detection: Detection, spec: SourceSpec, snapshot_id: str) -> SourceEntry:
    """The one place a `Detection` becomes a label's provenance.

    A `Detection` says what the engine observed; `spec` says what flabel admitted and on what
    terms; `snapshot_id` says which exact ruleset produced it. A `SourceEntry` is those three
    facts joined, and it is the only thing a consumer of `labels.json` has to trace a verdict
    back to its origin — so every field is populated from a named source and none is defaulted.

    Raises `ValueError` rather than a `FlabelError` for the same reason `models.py` does: these
    are broken invariants, not operator-facing failures, and `cli.py` maps anything
    unrecognised to exit 1.
    """
    # Spec §2.8. Step 6 already drops identify-class detections before correlation and counts
    # them in `identify_alerts_suppressed`, so reaching here means that filter was bypassed.
    # Checked again anyway: this is the last point at which an identify source could acquire a
    # verdict, and spec §13 lists a label attributable to one as a never-do.
    if not spec.may_label:
        raise ValueError(
            f"{spec.name} is an identify-class source and can never produce a label "
            f"(spec §2.8); detection sid {detection.sid} should have been suppressed upstream"
        )

    # A plausible wrong answer is the dangerous one here. Handing the wrong spec would attribute
    # one feed's licence and admission basis to another feed's alert, and every field would
    # still be present and well-formed, so nothing downstream could notice.
    if detection.source != spec.name:
        raise ValueError(
            f"spec {spec.name!r} does not describe detection from {detection.source!r}: "
            f"a label would cite the wrong origin"
        )

    # `ruleset` is what makes a label reproducible against a known set of rules. An empty id
    # traces to nothing, and a snapshot is not optional (spec §7).
    if not snapshot_id:
        raise ValueError("snapshot_id is empty: a label whose ruleset is unnamed is untraceable")

    label_basis = spec.label_basis
    # Unreachable while `may_label` is checked above; asserted so the two cannot drift apart
    # silently if `SourceSpec` ever gains a class that may label without a basis.
    assert label_basis is not None

    return SourceEntry(
        # From the detection: what the engine actually observed.
        tier=detection.tier,
        source=detection.source,
        sid=detection.sid,
        rev=detection.rev,
        classtype=detection.classtype,
        threat=detection.threat,
        # From the registry: the terms this source was admitted on. Never from the rule text —
        # a label must trace to a reviewed source, not to whatever an alert claimed to be.
        admission_basis=spec.admission_basis,
        licence=spec.licence,
        # Derived once, from `SourceSpec.label_basis`, rather than recomputed from
        # `source_class` here. A second copy of that rule is a second place for it to drift.
        label_basis=label_basis,
        # From the run: which exact ruleset produced this.
        ruleset=snapshot_id,
    )
