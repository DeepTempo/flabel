"""Every dataclass in flabel (spec §4).

This module imports nothing from the package. It is the base of the dependency graph, which
is what allows the pipeline stages to be built and tested independently of one another
instead of each owning its own private notion of a flow or a detection.

Everything here is frozen. A label's provenance is a claim about how a verdict was reached,
and a claim that can be edited after the fact is not provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

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


@dataclass(frozen=True)
class SourceSpec:
    """One rule feed in the registry (spec §5)."""

    name: str
    url: str
    licence: str
    source_class: SourceClass
    admission_basis: AdmissionBasis
    enabled: bool = True

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
    apart from "confidence too low" because the distinction feeds issue #10.
    """

    name: str
    licence: str
    source_class: SourceClass
    admission_basis: AdmissionBasis
    rules_fetched: int
    rules_admitted: int
    rules_excluded_no_confidence: int
    rules_excluded_low_confidence: int
    rules_excluded_low_severity: int
    ja4_rules_admitted: int
    ja3_rules_admitted: int
    fetched_at: str


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


@dataclass(frozen=True)
class UnmatchedDetection:
    """A detection that could not be attached to exactly one flow, and why.

    Reported rather than dropped: silence must mean nothing happened, never "something
    happened and we didn't say" (spec §2.5).
    """

    detection: Detection
    reason: Literal["no_flow_match", "ambiguous_flow_match"]
