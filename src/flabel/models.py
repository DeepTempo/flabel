"""Every dataclass in flabel (spec §4).

This module imports nothing from the package. It is the base of the dependency graph, which
is what allows the pipeline stages to be built and tested independently of one another
instead of each owning its own private notion of a flow or a detection.

Everything here is frozen. A label's provenance is a claim about how a verdict was reached,
and a claim that can be edited after the fact is not provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args


def _check(value: object, allowed: tuple[object, ...], field: str, owner: str) -> None:
    """Reject a value outside its `Literal`.

    `Literal` is a type hint, not a runtime check: without this, `Label(verdict="benign")`
    constructs happily. Spec §13's first never-do is asserting a flow is benign, so the
    constraint is enforced rather than annotated.

    Raises `ValueError` rather than a flabel exception because this module imports nothing
    from the package; `cli.py` maps anything unrecognised to exit 1.
    """
    if value not in allowed:
        raise ValueError(f"{owner}.{field}: {value!r} is not one of {list(allowed)}")


# --- configuration ------------------------------------------------------------------------

#: What kind of assertion a source's rules make. This drives whether a source may label at
#: all, and what a label from it means:
#:   signature  a rule matched traffic content        -> the flow is malicious
#:   ioc-dest   a rule matched a known-bad endpoint   -> the flow is malicious
#:   ioc-name   a rule matched a looked-up name       -> the flow *referenced* an indicator
#:   identify   a rule identifies benign software     -> never a label
SourceClass = Literal["signature", "ioc-dest", "ioc-name", "identify"]

#: How rules from a source were selected. `metadata-filter` requires ET-style metadata.
AdmissionBasis = Literal["metadata-filter", "wholesale"]

#: How directly a label follows from its rule match. Carried on every SourceEntry so a
#: consumer can tell a content match from an indirect reference without reading rule text.
LabelBasis = Literal["direct", "indicator-reference"]

#: Container format of the capture as sniffed by magic bytes, never by file extension.
CaptureFormat = Literal["pcap", "pcapng", "pcap.gz", "pcapng.gz"]

#: Whether the whole capture was read. `partial` covers truncation and discarded link types;
#: both still exit 0, with the run block saying what was lost (spec §12).
InputStatus = Literal["complete", "partial"]

#: Why a detection could not be attached to exactly one flow.
UnmatchedReason = Literal["no_flow_match", "ambiguous_flow_match"]

#: Whether JA4 fingerprinting was available to the Zeek pass, and if not, why not.
#:
#: Three values, not two, and never absence. Without a status a consumer cannot tell "this
#: capture had no TLS" from "the fingerprinting package was not installed" — and spec §2.5 says
#: absence is never a signal. `probe-failed` is separated from `not-installed` because the
#: first is a defect (a broken ZEEKPATH, a half-finished `zkg` install) and the second is the
#: ordinary laptop case; both lose JA4, and reporting them as one hides the defect.
Ja4Status = Literal["present", "not-installed", "probe-failed"]


@dataclass(frozen=True)
class SourceSpec:
    """One rule feed in the registry (spec §5)."""

    name: str
    url: str
    licence: str
    source_class: SourceClass
    admission_basis: AdmissionBasis
    enabled: bool = True

    def __post_init__(self) -> None:
        _check(self.source_class, get_args(SourceClass), "source_class", "SourceSpec")
        _check(self.admission_basis, get_args(AdmissionBasis), "admission_basis", "SourceSpec")

    @property
    def may_label(self) -> bool:
        """Whether a detection from this source may become a label.

        False exactly for `identify` sources, which describe benign software. Enforced in
        code and asserted in a test, because a label from one would be a false positive by
        construction (spec §2.8).
        """
        return self.source_class != "identify"

    @property
    def label_basis(self) -> LabelBasis | None:
        """The basis a label from this source carries, or None if it may not label.

        `ioc-name` sources match a name that was looked up — a DNS query or an HTTP host —
        so the flow referenced the indicator rather than being the malicious traffic itself.
        Reporting that as `direct` would overstate what was observed.
        """
        if not self.may_label:
            return None
        return "indicator-reference" if self.source_class == "ioc-name" else "direct"


# --- ruleset snapshot ---------------------------------------------------------------------


@dataclass(frozen=True)
class SourceAdmission:
    """What one source contributed to a snapshot, and what was dropped on the way.

    The exclusion counters are separate on purpose: `fetched == admitted + sum(excluded)` is
    asserted, so rules cannot go missing unaccounted for. "No confidence key" is counted
    apart from "confidence too low" because the distinction feeds issue #10, and "unloadable"
    apart from both because it is flabel's configuration talking, not the feed's metadata.
    """

    name: str
    #: The exact endpoint the rules came from. Without it, a label's origin traces only to a
    #: source *name* in a TOML file that can change between runs, and swapping two feeds'
    #: URLs would be undetectable in the output (spec §13: never emit a label whose origin
    #: can't be traced). Added in step 2 over spec §4's field list.
    url: str
    licence: str
    source_class: SourceClass
    admission_basis: AdmissionBasis
    #: Candidate rule lines seen — active `alert` lines only. Commented-out rules are counted
    #: in `rules_excluded_commented` instead, and are NOT part of this total.
    rules_fetched: int
    rules_admitted: int
    rules_excluded_no_confidence: int
    rules_excluded_low_confidence: int
    rules_excluded_low_severity: int
    #: Disabled (`#alert`) rules. Added in step 2 over spec §4: ET Open 8.0 ships 19,479 of
    #: them against 51,778 active rules, so without this counter they are invisible, and
    #: spec §6's `fetched == admitted + sum(excluded)` identity cannot describe the feed.
    rules_excluded_commented: int
    ja4_rules_admitted: int
    ja3_rules_admitted: int
    fetched_at: str
    #: Rules this engine cannot load, excluded at admission rather than left to fail at load
    #: time. Today that is exactly the rules whose address specification negates `$HOME_NET`,
    #: which is the empty set under flabel's `HOME_NET: any` — see `rules/admit.py`. Counted
    #: apart from the metadata buckets because nothing about the rule's *content* is at fault:
    #: it is a rule flabel's configuration cannot run. Part of the `fetched == admitted +
    #: sum(excluded)` identity like every other exclusion.
    #:
    #: Last in the field list, with a default, only because every field above it is required —
    #: a defaulted field cannot precede a mandatory one. Every call site passes it by keyword.
    rules_excluded_unloadable: int = 0

    def __post_init__(self) -> None:
        _check(self.source_class, get_args(SourceClass), "source_class", "SourceAdmission")
        _check(
            self.admission_basis,
            get_args(AdmissionBasis),
            "admission_basis",
            "SourceAdmission",
        )


@dataclass(frozen=True)
class SnapshotManifest:
    """The immutable description of one ruleset snapshot (spec §7)."""

    snapshot_id: str
    created_at: str
    flabel_version: str
    sources: tuple[SourceAdmission, ...]
    total_admitted: int
    total_ja4_admitted: int


# --- pipeline -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Flow:
    """One connection as Zeek saw it, keyed by Zeek's `uid`.

    `uid` is the join key for the whole pipeline, which is why Zeek must run with `-D`:
    without it the uid differs on every run and labels from two runs cannot be joined.

    The TLS fields default to None, and absence is never a signal — a flow with no handshake
    simply has no JA4, which is different from a JA4 that failed to compute.
    """

    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    ts_first: float
    ts_last: float
    ja4: str | None = None
    ja4s: str | None = None
    server_name: str | None = None


@dataclass(frozen=True)
class Detection:
    """One alert, before it has been attached to a flow."""

    source: str
    tier: int
    sid: int
    rev: int
    classtype: str | None
    app_proto: str | None
    threat: str
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    #: The rule's `metadata:` values, as Suricata reports them in `alert.metadata`. Spec §8
    #: says to parse this; spec §4's field list omitted somewhere to put it. It is what issue
    #: #10 (should untagged ET rules be admitted?) will be answered from.
    metadata: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceEntry:
    """One source's assertion on a label, carrying everything needed to trace it.

    Phase 2 adds tier-1 entries to a label's `sources` without changing the schema, which is
    why the tier lives here rather than being implied by the document.
    """

    tier: int
    source: str
    sid: int
    rev: int
    ruleset: str
    admission_basis: AdmissionBasis
    licence: str
    classtype: str | None
    label_basis: LabelBasis
    threat: str

    def __post_init__(self) -> None:
        _check(self.admission_basis, get_args(AdmissionBasis), "admission_basis", "SourceEntry")
        _check(self.label_basis, get_args(LabelBasis), "label_basis", "SourceEntry")


@dataclass(frozen=True)
class Label:
    """A malicious verdict on one flow, with every source that asserted it.

    There is no benign verdict: flabel labels malicious flows and says nothing about the
    rest. `best_tier` is the *minimum* tier across sources, because a lower tier is a
    higher-trust observation.
    """

    flow: Flow
    verdict: Literal["malicious"]
    best_tier: int
    sources: tuple[SourceEntry, ...]

    def __post_init__(self) -> None:
        _check(self.verdict, ("malicious",), "verdict", "Label")
        if not self.sources:
            raise ValueError(
                "Label.sources is empty: a label with no asserting source has no provenance"
            )
        expected = min(entry.tier for entry in self.sources)
        if self.best_tier != expected:
            # Two fields that can disagree is a flaw in an artifact whose whole value is
            # provenance, so agreement is enforced rather than assumed.
            raise ValueError(
                f"Label.best_tier is {self.best_tier} but min(sources.tier) is {expected}"
            )


@dataclass(frozen=True)
class UnmatchedDetection:
    """A detection that could not be attached to exactly one flow, and why.

    Reported rather than dropped: silence must mean nothing happened, never "something
    happened and we didn't say" (spec §2.5).
    """

    detection: Detection
    reason: Literal["no_flow_match", "ambiguous_flow_match"]

    def __post_init__(self) -> None:
        _check(self.reason, get_args(UnmatchedReason), "reason", "UnmatchedDetection")


# --- tool and stage results ----------------------------------------------------------------
#
# These four are named by spec §8 and §9 as return types but were absent from spec §4's field
# list, so they are defined here in step 2 rather than by whichever of steps 3/5/6/7 reaches
# them first. models.py exists so those steps can be built in parallel; a step that has to
# *create* a shared type collides with its siblings in exactly the file meant to prevent that.
#
# Fields are derived from the run block in spec §10, which is what these ultimately populate.
# A later step may need to *add* a field — a far smaller collision than defining the type.


@dataclass(frozen=True)
class ToolFailure:
    """A tool that exited non-zero, was killed, or could not be run at all (spec §11).

    Recorded as well as raised: the run reports what was lost rather than merely dying.
    """

    tool: str
    argv: tuple[str, ...]
    exit_code: int | None
    message: str


@dataclass(frozen=True)
class NormalizedCapture:
    """The capture every consumer reads, plus everything provenance needs about it.

    One normalized file, so Zeek and Suricata cannot disagree about the input (spec §2.4).

    Two field names differ from their `labels.json` keys because `format` and `bytes` shadow
    builtins: `capture_format` serialises as `format`, `bytes_total` as `bytes`.
    """

    path: Path
    original_path: Path
    sha256: str
    capture_format: CaptureFormat
    bytes_total: int
    input_status: InputStatus
    packets_read: int
    #: Byte offset of the first short record, or None when the capture is complete. A
    #: truncated pcap proceeds as partial input; a truncated pcapng is a hard failure.
    truncated_at_offset: int | None = None
    discarded_link_types: tuple[str, ...] = ()
    discarded_packets: int = 0
    #: Every transformation applied, in order — decompression, conversion, link-type split.
    normalization: tuple[str, ...] = ()
    #: Non-fatal losses, in the words the run block's `warnings[]` should carry (spec §10). The
    #: counters above say *what* was lost in numbers; these say it in a sentence, for the one
    #: reader who sees only the warnings list.
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check(self.capture_format, get_args(CaptureFormat), "capture_format", "NormalizedCapture")
        _check(self.input_status, get_args(InputStatus), "input_status", "NormalizedCapture")


@dataclass(frozen=True)
class ZeekRunInfo:
    """What the Zeek pass did, for the run block's `tools` section.

    `flags` is recorded because `-D` is mandatory (spec §2.3): without it connection uids
    differ every run, so a run that lost the flag must be visible in its own output.
    """

    version: str
    flags: tuple[str, ...]
    log_dir: Path
    retained_logs: tuple[str, ...] = ()
    #: Whether JA4 was computable at all. `None` only when nothing probed it.
    ja4_status: Ja4Status | None = None
    #: The installed `zeek/foxio/ja4` version, and *only* a version string. `zeek.py` cannot
    #: know it — `zkg list` is the only local source and a labelling run may not shell out to
    #: it (spec §2.2) — so the Zeek pass leaves this None and `provenance.py` fills it from
    #: `/etc/flabel-toolchain.json`. Whether JA4 worked is `ja4_status`; putting a status here
    #: was a type abuse flagged on PR #30 and is now impossible to read as a version.
    ja4_package_version: str | None = None
    warnings: tuple[str, ...] = ()
    tool_failures: tuple[ToolFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.ja4_status is not None:
            _check(self.ja4_status, get_args(Ja4Status), "ja4_status", "ZeekRunInfo")


@dataclass(frozen=True)
class SuricataRunInfo:
    """What the Suricata pass did, for the run block's `tools` and `counts` sections."""

    version: str
    snapshot_id: str
    rules_loaded: int
    alerts_total: int
    #: Rules the engine rejected, and rules it declined to load. Recorded rather than only
    #: compared against the snapshot's count: a rule that never loaded never examined the
    #: capture, so a run that looks complete is missing every label it would have produced.
    rules_failed: int = 0
    rules_skipped: int = 0
    #: Alerts dropped because their source may not label (spec §2.8). Counted, never silent.
    identify_alerts_suppressed: int = 0
    #: sha256 over flabel's own Suricata configuration, in `suricata.config_files()` order. A
    #: run is only reproducible against a *known* config: `HOME_NET` decides whether a whole
    #: class of rule can fire, and the eve selection decides what is recorded at all.
    config_sha256: str | None = None
    warnings: tuple[str, ...] = ()
    tool_failures: tuple[ToolFailure, ...] = ()


@dataclass(frozen=True)
class CorrelationResult:
    """The outcome of attaching detections to flows (spec §9).

    Carries the unmatched detections alongside the labels because a detection that could not
    be placed is a loss condition to report, not a row to drop (spec §2.5).
    """

    labels: tuple[Label, ...]
    unmatched: tuple[UnmatchedDetection, ...]
    flows_total: int
    detections_total: int

    @property
    def unmatched_ratio(self) -> float:
        """Share of detections that could not be placed. Zero detections is zero loss."""
        if self.detections_total == 0:
            return 0.0
        return len(self.unmatched) / self.detections_total
