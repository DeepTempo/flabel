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


# ===========================================================================================
# The run block (spec §10, §11) — added in step 8.
# ===========================================================================================
#
# `build_run_block` is the other half of this module's job. `build_source_entry` above answers
# "where did this verdict come from"; the run block answers "what did this run actually see,
# and what did it miss". Spec §2.5 is the whole design brief: *absence is never a signal*, so
# every enumerated loss condition has a named field here and silence means nothing happened.
#
# Two consequences shape everything below.
#
# **The block is always the same shape.** Every section and every key is present on every run,
# succeeded or died. A fact the run never established is `null` — never `0`, never `[]`, never
# a dropped key. Those three are the same mistake in different clothes: `counts.unmatched: 0`
# from a run whose correlation never happened is not a smaller claim than the truth, it is the
# opposite one, and a training pipeline reads it as "nothing was lost". A stable key set is
# also what lets a consumer write one reader instead of one per outcome.
#
# **It is assemblable with nothing having succeeded.** `tool_failures[]` is reported in a
# separate `run.json`, written into a run directory with no `labels.json` beside it (Craig,
# 2026-08-12, issue #23): spec §11 requires the failure recorded and §13 forbids a partial
# `labels.json`, so the array moved to a document that may exist. `run.json` is written by
# *every* run, so a consumer has one place to look regardless of outcome — which means every
# stage argument here is optional and none of them may be required to produce a block.

# Imports for the run block sit here rather than at the top of the file because step 8 was
# scoped to *append* to this module: `build_source_entry` and everything above it was written
# ahead of steps 7 and 8 (#44) and had to stay byte-stable while both were built in parallel
# worktrees. Fold them into the top block once both have merged — nothing depends on the
# placement, and the `noqa` marks the one rule it breaks.
import json  # noqa: E402
import re  # noqa: E402
from collections.abc import Sequence  # noqa: E402
from dataclasses import asdict  # noqa: E402
from datetime import datetime  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, get_args  # noqa: E402

from flabel import __version__  # noqa: E402
from flabel.labels import SCHEMA_VERSION  # noqa: E402
from flabel.models import (  # noqa: E402
    CorrelationResult,
    Ja4Status,
    NormalizedCapture,
    SnapshotManifest,
    SuricataRunInfo,
    ToolFailure,
    UnmatchedReason,
    ZeekRunInfo,
)

TOOLCHAIN_MANIFEST = Path("/etc/flabel-toolchain.json")

#: flabel's one timestamp format (spec §10), as a pattern rather than a `strftime` string:
#: `started_at` and `finished_at` arrive from the caller, so this module validates the format
#: rather than producing it. `labels.iso_from_epoch` is what writes it.
ISO_8601_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")

#: Phase 1 constants (spec §10). Tier 1 is the PANW NGFW path, which Phase 1 does not attempt;
#: saying so explicitly is the difference between "no tier-1 verdicts" and "tier 1 found
#: nothing", which is spec §2.5 applied to a whole tier.
MODE = "offline"
TIERS_ATTEMPTED = (2,)
TIERS_UNAVAILABLE = (1,)

#: Keys read out of `/etc/flabel-toolchain.json`, and where each lands in `tools`. `zeek` and
#: `suricata` are deliberately absent: those come from the binaries that actually ran, which is
#: a better fact than what the image recorded at build time. `editcap` has no runtime record —
#: `ingest.py` invokes it without capturing a version — so the manifest is its only source that
#: does not shell out.
_TOOLCHAIN_KEYS = ("ja4_zeek_package", "wireshark")

#: Values `ja4_package_version` must never hold. Spec §4 reserves that field for a real version
#: and gives status its own `ja4_status`; PR #30 flagged the type abuse, and this is the guard
#: that makes a relapse loud instead of shipping `"not-installed"` where a version belongs.
_JA4_STATUS_VALUES = frozenset(get_args(Ja4Status))


def read_toolchain(path: Path = TOOLCHAIN_MANIFEST) -> tuple[dict[str, str], tuple[str, ...]]:
    """Tool versions recorded by the image build, and anything wrong with the manifest.

    Read from a file rather than obtained by running anything. `zkg list` is the only local
    source of the `ja4` package version, and shelling out to it from a labelling run risks the
    network call spec §2.2 forbids and step 9 asserts against.

    Three outcomes, deliberately different:

    * **absent** — the ordinary laptop case. Empty, and no warning: the resulting `null` in
      `tools.ja4_zeek_package` already says the version is unknown, and warning on every local
      run would train a reader to ignore `warnings[]`.
    * **present and unusable** — a broken image, which is a defect. Warned, not fatal: losing
      every label over a provenance detail would be the wrong trade, and losing the fact
      silently would be spec §2.5's exact failure.
    * **present and usable** — the versions, with any individually unusable value dropped and
      warned about. A non-string value would otherwise land in a `str | None` slot as an int,
      and every consumer comparing it against a pinned string would silently never match.

    Returns the pair rather than a record because `models.py` owns every dataclass in flabel
    and is read-only to this step.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, ()
    except OSError as exc:
        return {}, (f"toolchain manifest {path} could not be read: {exc}",)
    except UnicodeDecodeError as exc:
        # Caught separately because it is **not** an `OSError` — it subclasses `ValueError`, so
        # it escapes the clause above and takes `build_run_block` down with it. A truncated or
        # half-written `/etc/flabel-toolchain.json` in a broken image would then crash the run
        # block on every run, including the failure path where step 9 is trying to write
        # `run.json` to explain why the run died. Losing the whole report over an unreadable
        # byte in an unrelated provenance file is exactly the trade this function's three
        # outcomes exist to avoid.
        return {}, (f"toolchain manifest {path} is not valid UTF-8: {exc}",)

    try:
        document = json.loads(raw)
    except ValueError as exc:
        return {}, (f"toolchain manifest {path} is not valid JSON: {exc}",)

    if not isinstance(document, dict):
        return {}, (f"toolchain manifest {path} is a {type(document).__name__}, not an object",)

    values: dict[str, str] = {}
    warnings: list[str] = []
    for key in _TOOLCHAIN_KEYS:
        if key not in document:
            continue
        value = document[key]
        if not isinstance(value, str) or not value.strip():
            warnings.append(
                f"toolchain manifest {path}: {key} is {value!r}, not a version string — "
                f"the field is reported as unknown rather than as that value"
            )
            continue
        values[key] = value
    return values, tuple(warnings)


def build_run_block(
    *,
    started_at: str,
    finished_at: str,
    capture: NormalizedCapture | None = None,
    manifest: SnapshotManifest | None = None,
    zeek: ZeekRunInfo | None = None,
    suricata: SuricataRunInfo | None = None,
    correlation: CorrelationResult | None = None,
    snapshot_resolved: bool | None = None,
    tool_failures: Sequence[ToolFailure] = (),
    warnings: Sequence[str] = (),
    toolchain_path: Path = TOOLCHAIN_MANIFEST,
    flabel_version: str = __version__,
) -> dict[str, Any]:
    """The run block of spec §10, ready to serialise and complete for any outcome.

    Every stage argument is optional because a run can die in any of them and still has to
    report what it lost (issue #23). `tool_failures` is for records the caller holds that no
    stage's run info carries — a `ToolError` caught from a stage already carries its own.

    Returns plain JSON primitives: no `Path`, no tuple of dataclasses, no work left for the
    caller between here and `labels.serialise`.
    """
    _check_timestamp(started_at, "started_at")
    _check_timestamp(finished_at, "finished_at")

    versions, toolchain_warnings = read_toolchain(toolchain_path)
    ja4_version, ja4_warnings = _ja4_package_version(zeek, versions)
    failures = _collect_failures(zeek, suricata, tool_failures)

    return {
        "flabel_version": flabel_version,
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": _duration(started_at, finished_at),
        "mode": MODE,
        "tiers_attempted": list(TIERS_ATTEMPTED),
        "tiers_unavailable": list(TIERS_UNAVAILABLE),
        "input": _input_section(capture),
        "ruleset": _ruleset_section(manifest),
        "tools": _tools_section(zeek, suricata, versions, ja4_version),
        "counts": _counts_section(correlation, suricata),
        "loss_conditions": _loss_conditions(
            capture, zeek, suricata, correlation, snapshot_resolved, failures
        ),
        "tool_failures": [_failure(failure) for failure in failures],
        "warnings": [
            *(capture.warnings if capture else ()),
            *(zeek.warnings if zeek else ()),
            *(suricata.warnings if suricata else ()),
            *toolchain_warnings,
            *ja4_warnings,
            *warnings,
        ],
    }


# --- timestamps ---------------------------------------------------------------------------


def _check_timestamp(value: str, field: str) -> None:
    """Reject anything that is not flabel's one timestamp format (spec §10).

    Enforced on the way in rather than assumed. `started_at` and `finished_at` are the two
    fields this module does not derive, so a caller passing `datetime.now().isoformat()` —
    naive, no `Z`, variable precision — would put a second timestamp format into a document
    whose whole point is having one.
    """
    if not isinstance(value, str) or not ISO_8601_UTC.fullmatch(value):
        raise ValueError(
            f"{field}={value!r} is not ISO-8601 UTC with microsecond precision and a Z suffix "
            f"(spec §10 requires one timestamp format everywhere)"
        )


def _duration(started_at: str, finished_at: str) -> float:
    """Elapsed wall-clock seconds, derived rather than accepted as a third argument.

    Two timestamps and an independently supplied duration are one fact recorded twice, and the
    copy that drifts is the one a reader trusts. A negative result means the caller wired the
    two the wrong way round, which would otherwise ship as a plausible number.
    """
    elapsed = (
        datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)
    ).total_seconds()
    if elapsed < 0:
        raise ValueError(
            f"duration is negative: finished_at {finished_at} precedes started_at {started_at}"
        )
    return elapsed


# --- sections -----------------------------------------------------------------------------
#
# Each returns the same keys whether or not its stage ran; `None` means the fact was never
# established. See the section note at the top of this block for why that is not `0` or `{}`.


def _input_section(capture: NormalizedCapture | None) -> dict[str, Any]:
    """The capture as the operator handed it over (spec §10).

    `path` is `original_path`, never the normalized copy. The normalized copy lives in a
    per-run temporary directory, so it means nothing to a reader and differs on every run by
    construction — which would break Goal 2 from inside the one input field spec §10 excludes
    from the comparison precisely to keep it comparable.

    `format` and `bytes` use their spec §10 names: the model calls them `capture_format` and
    `bytes_total` only because the obvious names shadow builtins, and the output should not
    inherit a Python workaround.
    """
    if capture is None:
        return dict.fromkeys(
            (
                "path",
                "sha256",
                "format",
                "bytes",
                "input_status",
                "packets_read",
                "truncated_at_offset",
                "discarded_link_types",
                "discarded_packets",
                "normalization",
            )
        )
    return {
        "path": str(capture.original_path),
        "sha256": capture.sha256,
        "format": capture.capture_format,
        "bytes": capture.bytes_total,
        "input_status": capture.input_status,
        "packets_read": capture.packets_read,
        "truncated_at_offset": capture.truncated_at_offset,
        "discarded_link_types": list(capture.discarded_link_types),
        "discarded_packets": capture.discarded_packets,
        # Ordered, not sorted: it is the sequence of transformations applied.
        "normalization": list(capture.normalization),
    }


def _ruleset_section(manifest: SnapshotManifest | None) -> dict[str, Any]:
    """Which exact rules ran, and on what terms each source was admitted."""
    if manifest is None:
        return dict.fromkeys(("snapshot_id", "sources", "total_admitted", "total_ja4_admitted"))
    return {
        "snapshot_id": manifest.snapshot_id,
        # Sorted by name so the manifest's tuple order cannot reach the file. Canonical output
        # means the same data serialises the same way however it was assembled (spec §10).
        "sources": [asdict(source) for source in sorted(manifest.sources, key=lambda s: s.name)],
        "total_admitted": manifest.total_admitted,
        "total_ja4_admitted": manifest.total_ja4_admitted,
    }


def _tools_section(
    zeek: ZeekRunInfo | None,
    suricata: SuricataRunInfo | None,
    versions: dict[str, str],
    ja4_version: str | None,
) -> dict[str, Any]:
    """What ran, at which versions (spec §10).

    `zeek` and `suricata` come from the binaries that actually ran; `editcap` and
    `ja4_zeek_package` come from the toolchain manifest, because nothing records them at run
    time and neither may be obtained by shelling out (spec §2.2, §8).

    `ja4_status` and `ja4_zeek_package` are separate fields and stay that way: one is whether
    fingerprinting worked, the other is which package version was installed. A status written
    into the version slot is a string that reads like a version and resolves to nothing.
    """
    return {
        "zeek": zeek.version if zeek else None,
        "zeek_flags": list(zeek.flags) if zeek else None,
        "suricata": suricata.version if suricata else None,
        "editcap": versions.get("wireshark"),
        "ja4_zeek_package": ja4_version,
        "ja4_status": zeek.ja4_status if zeek else None,
        "suricata_config_sha256": suricata.config_sha256 if suricata else None,
    }


def _ja4_package_version(
    zeek: ZeekRunInfo | None, versions: dict[str, str]
) -> tuple[str | None, tuple[str, ...]]:
    """The installed `ja4` package version, or None, plus anything wrong with the candidates.

    The Zeek pass wins if it ever carries a real version — an observation of what ran beats
    what the image recorded at build time — and the manifest is the fallback. Today `zeek.py`
    always leaves it None, so the manifest is in practice the only source.

    A `Ja4Status` value in that slot is refused rather than passed through. It is well-formed,
    plausible, and wrong in exactly the way this project keeps finding: `"not-installed"` reads
    as a version string to anything that does not already know better.
    """
    warnings: list[str] = []
    candidates = (
        ("ZeekRunInfo.ja4_package_version", zeek.ja4_package_version if zeek else None),
        ("the toolchain manifest", versions.get("ja4_zeek_package")),
    )
    for origin, value in candidates:
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            warnings.append(f"{origin} holds {value!r}, which is not a version string")
            continue
        if value in _JA4_STATUS_VALUES:
            warnings.append(
                f"{origin} holds the ja4 status {value!r} where a package version belongs; "
                f"ja4_zeek_package is reported as unknown and the status is in ja4_status"
            )
            continue
        return value, tuple(warnings)
    return None, tuple(warnings)


def _counts_section(
    correlation: CorrelationResult | None, suricata: SuricataRunInfo | None
) -> dict[str, Any]:
    """The run's totals, each null until the stage that measures it has run.

    Split by stage rather than all-or-nothing: a run that loaded rules and then died in
    correlation knows `rules_loaded` and does not know `labels`, and collapsing that to
    "counts unknown" throws away a fact we have.

    `labels` counts labels, not source entries. One flow asserted by three rules is one label,
    and counting entries would inflate the headline number a reader trusts most.
    """
    return {
        "flows": correlation.flows_total if correlation else None,
        "detections": correlation.detections_total if correlation else None,
        "labels": len(correlation.labels) if correlation else None,
        "unmatched": len(correlation.unmatched) if correlation else None,
        # The model's own derivation, not a second division that can round differently.
        "unmatched_ratio": correlation.unmatched_ratio if correlation else None,
        "identify_alerts_suppressed": suricata.identify_alerts_suppressed if suricata else None,
        "rules_loaded": suricata.rules_loaded if suricata else None,
        "rules_failed": suricata.rules_failed if suricata else None,
        "rules_skipped": suricata.rules_skipped if suricata else None,
    }


# --- loss conditions (spec §11) -----------------------------------------------------------


def _loss_conditions(
    capture: NormalizedCapture | None,
    zeek: ZeekRunInfo | None,
    suricata: SuricataRunInfo | None,
    correlation: CorrelationResult | None,
    snapshot_resolved: bool | None,
    failures: tuple[ToolFailure, ...],
) -> dict[str, bool | None]:
    """One flag per row of spec §11: did this loss condition fire?

    **Derived here, never stored.** Spec §10's run block names a `loss_conditions` key while
    spec §11 puts each condition's authoritative field elsewhere in the block — `input.*`,
    `counts.*`, `tools.ja4_status`, `tool_failures[]`. Reading it as a second copy of those
    values would create nine pairs of fields that can disagree, which this project treats as a
    defect. Reading it as an index computed from them costs nothing and gives a consumer one
    object to check, instead of reconstructing spec §11's rules from six scattered numbers
    every time. Spec §13 forbids reporting full coverage when any loss condition fired, and
    this is the field that makes that answerable in one lookup.

    `None`, not `False`, when the stage that would know never ran. "JA4 was fine" and "nothing
    ever probed JA4" are different facts, and `False` asserts the first.
    """
    unmatched_reasons = (
        {entry.reason for entry in correlation.unmatched} if correlation is not None else None
    )
    # Checked against the Literal rather than against string constants spelled here. A rename in
    # `models.UnmatchedReason` would leave a comparison that simply never matches — reporting
    # "no ambiguous matches occurred" on a run that had them, which is spec §13's never-do
    # reached by a refactor. `_JA4_STATUS_VALUES` above uses `get_args` for the same reason;
    # this asserts the names still exist rather than trusting two spellings to stay in step.
    known_reasons = set(get_args(UnmatchedReason))
    assert {"no_flow_match", "ambiguous_flow_match"} <= known_reasons, (
        f"UnmatchedReason changed to {sorted(known_reasons)}; the loss_conditions rows below "
        f"name reasons that no longer exist and would silently report no loss"
    )
    return {
        "input_truncated": None if capture is None else capture.truncated_at_offset is not None,
        "multi_datalink_discard": None if capture is None else bool(capture.discarded_link_types),
        "detection_uncorrelatable": (
            None if unmatched_reasons is None else "no_flow_match" in unmatched_reasons
        ),
        "ambiguous_flow_match": (
            None if unmatched_reasons is None else "ambiguous_flow_match" in unmatched_reasons
        ),
        # Known on every run: the caller passes what it caught, and no stage having failed is
        # itself an observation rather than an absence.
        "tool_failure": bool(failures),
        # Told, not inferred. `manifest is None` conflates two different runs: one where
        # `--ruleset-snapshot` named a snapshot that does not exist — the §11 row, a specific
        # and diagnosable operator error — and one where Zeek was OOM-killed before the
        # snapshot was ever loaded. Inferring the first from the second would blame a missing
        # ruleset for every mid-pipeline crash, which is a false statement in the one file whose
        # job is saying honestly what the run did and did not see. Only the caller knows which
        # happened, so only the caller can say.
        "snapshot_missing": snapshot_resolved
        if snapshot_resolved is None
        else not snapshot_resolved,
        "identify_alert_suppressed": (
            None if suricata is None else suricata.identify_alerts_suppressed > 0
        ),
        "rules_failed_or_skipped": (
            None if suricata is None else bool(suricata.rules_failed or suricata.rules_skipped)
        ),
        "ja4_unavailable": (
            None if zeek is None or zeek.ja4_status is None else zeek.ja4_status != "present"
        ),
    }


# --- tool failures ------------------------------------------------------------------------


def _collect_failures(
    zeek: ZeekRunInfo | None,
    suricata: SuricataRunInfo | None,
    extra: Sequence[ToolFailure],
) -> tuple[ToolFailure, ...]:
    """Every tool failure this run knows about, in pipeline order and each recorded once.

    Both sources are read because `ToolError` carries `failures` *and* `run_info`, and the run
    info carries the same records: a caller doing `except ToolError as exc` naturally has both
    in hand. Reading only the argument would drop what a stage recorded before raising, and
    reading both without de-duplicating would double the count of a single failed tool.
    """
    ordered: list[ToolFailure] = [
        *(zeek.tool_failures if zeek else ()),
        *(suricata.tool_failures if suricata else ()),
        *extra,
    ]
    seen: set[ToolFailure] = set()
    unique: list[ToolFailure] = []
    for failure in ordered:
        if failure in seen:
            continue
        seen.add(failure)
        unique.append(failure)
    return tuple(unique)


def _failure(failure: ToolFailure) -> dict[str, Any]:
    """One `ToolFailure` as JSON.

    `argv` is the full argument vector, including per-run paths. That is deliberate and does not
    break Goal 2 — though not for the reason first recorded here. `run.json` **is** compared
    (`canonical.DOCUMENTS`); step 10 kept it in rather than out, because a run block that drifts
    between two runs over one capture is exactly what Goal 2 should catch. What makes the argv
    safe is that `tool_failures[]` is populated only on a *failed* run, and a failed run writes
    no `labels.json` — it is not one of the two runs a reproducibility comparison is made
    between. Spec §8 puts the argv here precisely so `ZeekRunInfo.flags` can stay free of paths.

    `exit_code` is null for a process that was killed rather than exiting — an OOM
    kill arrives as a signal, and reporting it as an exit code would invent one.
    """
    return {
        "tool": failure.tool,
        "argv": list(failure.argv),
        "exit_code": failure.exit_code,
        "message": failure.message,
    }
