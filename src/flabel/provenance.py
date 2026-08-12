"""Assembling what a label says about its own origin (spec §4, §10).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.

This module currently holds one function. `build_source_entry` is pre-placed here ahead of
steps 7 and 8 (#44) because both need it and neither owns it. Step 7 cannot avoid it —
`CorrelationResult.labels` is `tuple[Label, ...]` and a `Label` requires `SourceEntry` values —
while PLAN step 8 assigned the derivation of `label_basis`, `admission_basis` and `licence` to
the labelling side. Two parallel worktrees writing that separately is how steps 3-6 produced
three incompatible tool-failure conventions; the fix there was one shape in one place, and the
fix here is the same one applied before the collision rather than after.

**A label's terms come from the snapshot, never from the live registry.** This is the whole
reason the function takes a `SourceAdmission` rather than a `SourceSpec`. `SourceAdmission` is
what the manifest recorded when the rules were fetched, frozen alongside the rules that actually
fired; `SourceSpec` is whatever `data/sources.toml` says today, and `--sources` lets an operator
substitute a different file entirely. Between `flabel rules update` and a labelling run, a
licence can be corrected upstream or a `source_class` reconsidered — and then every label from
the older snapshot would carry today's terms over yesterday's rules, with every field present
and plausible and nothing downstream able to tell. The worst version is not the licence: a
`source_class` edit moving `abuse.ch/urlhaus` from `ioc-name` to `ioc-dest` silently turns
`indicator-reference` into `direct` on labels already emitted, which is the difference between
"this flow looked up a bad name" and "this flow is the attack" — `docs/prd.md`'s highest-ranked
risk. `suricata.py` already resolves a detection's source through the manifest for the same
reason; this function agrees with it rather than introducing a second authority.

The run block (spec §10) is step 8's to build and lands in this module later.
"""

from __future__ import annotations

from flabel.models import (
    SNAPSHOT_ID,
    Detection,
    SourceAdmission,
    SourceEntry,
    label_basis,
    may_label,
)

#: Tiers that mean something. Tier 1 is a PANW NGFW verdict, tier 2 is open-source screening;
#: lower is higher trust, and `Label.best_tier` ranks labels by it. Phase 1 only ever produces
#: 2, but the closed set is `{1, 2}` so that Phase 2 adding tier-1 entries stays additive
#: (spec §2.7) rather than requiring this constant to change.
KNOWN_TIERS = (1, 2)


def build_source_entry(
    detection: Detection, admission: SourceAdmission, snapshot_id: str
) -> SourceEntry:
    """The one place a `Detection` becomes a label's provenance.

    A `Detection` says what the engine observed; `admission` says what flabel admitted and on
    what terms, as recorded in the snapshot manifest; `snapshot_id` says which exact ruleset
    produced it. A `SourceEntry` is those three facts joined, and it is the only thing a
    consumer of `labels.json` has to trace a verdict back to its origin — so every field is
    populated from a named source and none is defaulted.

    Raises `ValueError` rather than a `FlabelError` for every guard below, because each marks a
    mis-wired pipeline rather than anything an operator did: reaching them means an earlier
    stage failed to do its job, and `cli.py` maps anything unrecognised to exit 1. The one
    genuinely operator-facing case — a detection whose source is not in the snapshot at all —
    belongs to the caller, and spec §9 makes it a typed `SnapshotError` there.
    """
    # The type hint is not the guard. `SourceSpec` carries all five attributes this function
    # reads off an admission — `name`, `url`, `licence`, `source_class`, `admission_basis` — so
    # passing one works at runtime, produces a well-formed entry, and reintroduces exactly the
    # live-registry defect this signature was changed to prevent. Nothing in the repo checks
    # annotations: CI runs ruff, and there is no mypy or pyright in the dev group. So the
    # distinction the module docstring rests on is asserted here or not at all.
    if not isinstance(admission, SourceAdmission):
        raise ValueError(
            f"admission must be a SourceAdmission from the snapshot manifest, not "
            f"{type(admission).__name__}: a label's terms come from the snapshot that "
            f"produced it, never from the registry as it reads now"
        )

    # Then the name, because it is the precondition for every check below. Diagnosing a
    # mis-built mapping as an identify-class suppression bug sends the reader to the wrong
    # module.
    if detection.source != admission.name:
        raise ValueError(
            f"admission for {admission.name!r} does not describe a detection from "
            f"{detection.source!r}: a label would cite the wrong origin"
        )

    # Not merely non-empty. `--ruleset-snapshot` defaults to None meaning "newest available",
    # so a caller stringifying it hands over the literal "None" — non-empty, well-formed to a
    # naive check, and on every label in the file as a ruleset that can never be looked up.
    # The format is the same one `load_snapshot` enforces, so an id that passes here is one a
    # reader can actually resolve back to a directory.
    #
    # `isinstance` first because the *un*-stringified `None` is the likelier miswiring, and
    # `SNAPSHOT_ID.match(None)` raises `TypeError` — reaching the operator as the traceback
    # this guard exists to replace. `fullmatch` rather than `match`, because `$` also matches
    # before a trailing newline: an id read from a file with the newline left on would
    # otherwise pass and land in `ruleset` as a string that resolves to nothing.
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID.fullmatch(snapshot_id):
        raise ValueError(
            f"snapshot_id {snapshot_id!r} is not a snapshot id: a label whose ruleset cannot "
            f"be looked up is untraceable (spec §13)"
        )

    # Spec §2.8. Step 6 already drops identify-class detections before correlation and counts
    # them in `identify_alerts_suppressed`, so reaching here means that filter was bypassed.
    # Checked again anyway: this is the last point at which an identify source could acquire a
    # verdict, and spec §13 lists a label attributable to one as a never-do.
    if not may_label(admission.source_class):
        raise ValueError(
            f"{admission.name} is an identify-class source and can never produce a label "
            f"(spec §2.8); detection sid {detection.sid} should have been suppressed upstream"
        )

    # `tier` is the trust ranking — `Label.best_tier` is `min(tier)` and a consumer weights
    # labels by it — so an out-of-range value is not a cosmetic defect. Unvalidated, a stray
    # edit setting tier 1 in `suricata.py` would present open-source screening results as NGFW
    # verdicts, complete and well-formed and wrong in the field that matters most.
    #
    # `bool` is excluded explicitly because `True == 1` in Python, so `True in (1, 2)` is true
    # and the tier would serialise into `labels.json` as `true`. `suricata.py` and
    # `rules/snapshot.py` both guard this same trap; not doing so here would make this the
    # outlier.
    if isinstance(detection.tier, bool) or detection.tier not in KNOWN_TIERS:
        raise ValueError(
            f"detection sid {detection.sid} has tier {detection.tier!r}, not one of "
            f"{list(KNOWN_TIERS)}: tier ranks label trust and cannot be invented"
        )

    # Checked here rather than left to the test fixtures. `SourceEntry` has no field defaults,
    # so the only way a mandatory field arrives empty is that its input was empty — and
    # `suricata.py` checks only that the `signature` *key* exists, so a rule emitting
    # `"signature": ""` yields a label that names no threat while passing every other check.
    # An empty `licence` is likewise a claim about terms rather than an absence of one: §4
    # provides `"unstated"` for that, and it is not the empty string.
    for field, value in (("threat", detection.threat), ("licence", admission.licence)):
        if not value:
            raise ValueError(
                f"{field} is empty for sid {detection.sid} from {admission.name}: a label "
                f"that is missing it looks complete and asserts nothing"
            )

    basis = label_basis(admission.source_class)
    # Unreachable while `may_label` is checked above; asserted so the two cannot drift apart
    # silently if a class is ever added that may label without a basis.
    assert basis is not None

    return SourceEntry(
        # From the detection: what the engine actually observed.
        tier=detection.tier,
        source=detection.source,
        sid=detection.sid,
        rev=detection.rev,
        classtype=detection.classtype,
        threat=detection.threat,
        # From the snapshot's admission record: the terms this source was admitted on, frozen
        # with the rules that fired. Never from the live registry — see the module docstring.
        admission_basis=admission.admission_basis,
        licence=admission.licence,
        # Derived once, by `models.label_basis`, rather than recomputed here. A second copy of
        # that rule is a second place for it to drift.
        label_basis=basis,
        # From the run: which exact ruleset produced this.
        ruleset=snapshot_id,
    )
