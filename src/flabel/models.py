"""Every dataclass in flabel (spec §4).

This module imports nothing from the package. It is the base of the dependency graph, which
is what allows the pipeline stages to be built and tested independently of one another
instead of each owning its own private notion of a flow or a detection.

Everything here is frozen. A label's provenance is a claim about how a verdict was reached,
and a claim that can be edited after the fact is not provenance.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal, get_args

#: Spec §9's default: past 1% of detections unplaceable, the labels no longer describe the
#: capture well enough to be training data. Phase 2 configures its own, looser value rather
#: than relaxing this one.
#:
#: Here rather than in `correlate.py`, where it reads most naturally, because `provenance.py`
#: records it in the run block (#68) and `correlate` imports `provenance` — so the obvious home
#: made it a cycle. `models.py` imports nothing from the package and is the base of the
#: dependency graph, which is what makes it the place two modules can agree on a constant.
#: `correlate` re-exports it, so nothing about how it is imported changes.
DEFAULT_THRESHOLD = 0.01


def _check(value: object, allowed: tuple[object, ...], field: str, owner: str) -> None:
    """Reject a value outside its `Literal`.

    `Literal` is a type hint, not a runtime check: without this, a forged
    `LabelEntry(name="verdict", value="benign", ...)`
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
#:
#: `device-policy` is Phase 2's (Craig, 2026-08-17) and makes a different kind of statement from
#: the other two. Those describe a decision flabel made when admitting rules into a snapshot;
#: `device-policy` says the decision was made **on the firewall**, by its threat exceptions, and
#: that flabel admitted what the device reported without second-guessing it.
#:
#: Saying so explicitly is the point. A consumer weighting labels by trust has to know that the
#: gate for these entries lives in a configuration flabel does not contain — which is why a
#: tier-1 entry's `ruleset` carries the device's content version *and* its config version, so the
#: policy that admitted a detection is as identifiable as the signature that produced it.
AdmissionBasis = Literal["metadata-filter", "wholesale", "device-policy"]

#: What a tier-1 label's terms are, given that PANW signatures are not open-source rules.
#:
#: **Deliberately not an SPDX identifier** (Craig, 2026-08-17). The licence field exists to carry
#: a redistribution obligation, because tier-2 rules are other people's text and shipping labels
#: derived from them incurs duties `NOTICE` spells out. A device signature is proprietary and this
#: output is neither redistributed nor sold, so there is no obligation to record.
#:
#: Populated rather than blanked, because a consumer reading `licence` across a mixed-tier label
#: must be able to tell "no obligation, vendor signature" from "we forgot". `notice.py` matches on
#: this exact value to render the non-obligation, which is why it lives here rather than in either
#: of the two modules that need it.
DEVICE_LICENCE = "proprietary:vendor-signature (not redistributed)"

#: What `panw.detections` puts in `Detection.threat` when PAN-OS supplied no threat name at all.
#:
#: **Here rather than in `panw.py`, for the same reason `DEVICE_LICENCE` is** — two modules need to
#: agree on it, and a string literal repeated in both is a string literal that can drift. `panw`
#: writes it; `correlate` reads it, to keep it out of a `threat-name` label (#140).
#:
#: A sentinel rather than an empty string because spec §4 forbids an empty `threat`: a source entry
#: has to say *something* about what fired, and "the device sent no name" is that something. What it
#: must not do is get promoted to a label, where it would assert that the threat is called
#: "unnamed".
DEVICE_UNNAMED_THREAT = "unnamed"

#: Which pipelines the operator asked for, named after the flag that selects each (#132,
#: Craig 2026-08-18). Phase 1 recorded a single hardcoded `"offline"` because there was only one
#: pipeline; a run block that still said so while tier 1 replayed past a firewall would be a
#: provenance field describing a run that did not happen.
#:
#: Named for the invocation rather than for the tiers, so `mode` answers "what was asked for" and
#: `tiers_attempted` answers "what that meant" — two facts that a single field conflated for as
#: long as one implied the other.
RunMode = Literal["replay", "offline", "both"]

#: Which tiers each mode attempts. The one place the mapping is stated: `cli` gates its stages on
#: it and `provenance` publishes it, and two copies would let the artifact claim a tier the
#: pipeline never ran.
TIERS_BY_MODE: dict[RunMode, tuple[int, ...]] = {
    "replay": (1,),
    "offline": (2,),
    "both": (1, 2),
}

#: What a label asserts about a flow (#138, Craig 2026-08-19). One `Label` carries several.
#:
#: `verdict` was a field on `Label` until schema 2.0, and promoting it into a list is what makes a
#: second kind of assertion possible without another field per kind. Hyphenated to match the
#: enumerated *values* elsewhere in this module — `indicator-reference`, `device-policy` — where
#: field names stay snake_case.
#:
#: `threat-name` is **tier-1 only** today: it publishes what the inline device called the threat.
#: The Suricata path could supply one from a rule's `msg`, and deliberately does not yet, because
#: `msg` text is the *rule's* description rather than a threat identifier and choosing between
#: 84,977 of them is a policy question nobody has answered. Adding it later is purely additive,
#: which is the whole point of decision 3 in #138.
LabelName = Literal["verdict", "threat-name"]

#: How many values one assertion of a kind may carry. `single` is every kind today; `multi` exists
#: because MITRE technique ids are the next kind expected and a flow plausibly carries several.
LabelArity = Literal["single", "multi"]


@dataclass(frozen=True)
class LabelKind:
    """What a label kind permits: how many values, and which tiers may assert it.

    **Declared here so it is enforced in one place rather than known in several.** Before this,
    "`threat-name` is tier-1 only" lived in spec §4 as prose and in `correlate`'s selection rule
    as behaviour, and nothing rejected a tier-2 `threat-name` — which is how four tests in
    `test_models.py` came to build one as incidental scaffolding, one of them then passing for a
    reason it did not claim.
    """

    arity: LabelArity
    #: Ascending. A tier absent here cannot assert this kind at all.
    tiers: tuple[int, ...]

    def __post_init__(self) -> None:
        _check(self.arity, get_args(LabelArity), "arity", "LabelKind")
        if not self.tiers:
            raise ValueError("LabelKind.tiers is empty: a kind no tier may assert cannot exist")


#: The one authority for what a label kind is. `LabelName` above carries the static typing a
#: `Mapping` cannot, so both exist and a test asserts they describe the same set — otherwise
#: adding a kind to one and not the other leaves `blfile` and `LabelEntry` disagreeing with
#: nothing red. Extending `threat-name` to tier 2, or adding a `multi` kind, is an edit here.
LABEL_KINDS: Mapping[str, LabelKind] = MappingProxyType(
    {
        "verdict": LabelKind(arity="single", tiers=(1, 2)),
        "threat-name": LabelKind(arity="single", tiers=(1,)),
    }
)

#: How directly a label follows from its rule match. Carried on every SourceEntry so a
#: consumer can tell a content match from an indirect reference without reading rule text.
LabelBasis = Literal["direct", "indicator-reference"]

#: Which way the packet that matched was going, as Suricata reported it (issue #115).
#:
#: Carried onto every `SourceEntry` and never consulted for a verdict. A destination-anchored
#: IOC rule — `alert ip any any -> <flagged address> any`, 19.5% of the measured 84,977-rule
#: snapshot — fires on our RST *back* to an unsolicited inbound packet, and its `msg` then reads
#: "Outgoing connection to ..." beside a flow that is inbound. Both halves of that label are
#: what the rule and the capture actually said; publishing which direction matched is what lets
#: a consumer tell them apart, and it is cheaper and safer than flabel inferring an answer
#: (spec §2.5, and the option rejected on #115).
#:
#: `unknown` is a **measured** third value, not a defensive default: an unsolicited ICMP
#: destination-unreachable belongs to no exchange, and Suricata 8.0.6 emits that alert with no
#: `direction` key at all. A sentinel rather than `None` (Craig, 2026-08-17), following
#: `licence: "unstated"` — every `SourceEntry` field stays non-null except `classtype`.
#:
#: **The frame of reference is Suricata's flow, not Zeek's.** `to_server` means the matching
#: packet travelled towards the endpoint *Suricata* treats as the responder. The `Label` beside
#: it names a Zeek flow, and correlation matches a detection's tuple **in either direction**
#: (spec §9) precisely because it does not require the two engines to agree on who initiated.
#: They normally do; a midstream pickup, or a UDP flow one engine has expired and the other has
#: not, are the cases where they need not. So this field is a faithful report of what the engine
#: that raised the alert said, and not a derived statement about `Label.flow`'s orientation.
#: Deriving one would be a different field and a different claim.
Direction = Literal["to_server", "to_client", "unknown"]

#: Codepoints that join or modify an emoji rather than being one of their own, and the Unicode
#: categories of the same (#117). A ZWJ sequence like the pirate flag is four codepoints and one
#: glyph, and 6,910 pawpatrules rules lead with it; a rule's marker is its first character.
#:
#: Here rather than in `rules/admit.py`, where the parse lives, because `config.py` validates the
#: registry's marker list against the same definition and `admit` imports `config` — so the
#: obvious home made it a cycle. Same move, and the same reason, as `DEFAULT_THRESHOLD`.
EMOJI_JOINERS = frozenset({"\u200d", "️"})
COMBINING_CATEGORIES = frozenset({"Mn", "Cf"})

#: What may be a rule's marker (#117). Category `So` — "Symbol, other" — is what fourteen of the
#: feed's sixteen markers are, and what no letter, quotation mark or space is. Requiring it stops
#: a French rule title reporting `É` as a marker, and a non-breaking space reporting `\xa0`; the
#: second is not cosmetic, because a marker nobody recognises means the rule is ADMITTED.
#:
#: `\N{INFORMATION SOURCE}` is the exception and is named rather than accommodated by loosening
#: the rule. **It is category `Ll`**, a lowercase letter, because it derives from an italic *i* —
#: measured, after a review recommended a bare `So` test that would have rejected the one marker
#: #113 and #117 both depend on. Widening the test to letters would have admitted `É` and `é`,
#: which is the failure it exists to prevent, so the single character is listed instead.
PICTOGRAPH_CATEGORIES = frozenset({"So"})
LETTERLIKE_MARKERS = frozenset({"\N{INFORMATION SOURCE}"})


def is_marker(char: str) -> bool:
    """Whether `char` is a single character that may be a rule's `msg:` marker.

    Total over any string, including `""` and multi-character input, because both callers reach
    it with unvalidated text — `config._markers` with a registry entry and `admit._first_marker`
    with feed text. `unicodedata.category` raises `TypeError` on anything but one character, and
    a `TypeError` reaching an operator where a `ConfigError` was promised is the same defect this
    repo already fixed in `build_source_entry`'s snapshot-id guard.
    """
    if len(char) != 1:
        return False
    return char in LETTERLIKE_MARKERS or unicodedata.category(char) in PICTOGRAPH_CATEGORIES


#: Container format of the capture as sniffed by magic bytes, never by file extension.
CaptureFormat = Literal["pcap", "pcapng", "pcap.gz", "pcapng.gz"]

#: Whether the whole capture was read. `partial` covers truncation and discarded link types;
#: both still exit 0, with the run block saying what was lost (spec §12).
InputStatus = Literal["complete", "partial"]

#: Why a detection could not be attached to exactly one flow.
#:
#: `unsupported_transport` is decided from the detection alone and before any flow lookup
#: (issue #84): Zeek's `transport_proto` holds only tcp/udp/icmp/unknown_transport, so a
#: detection on ESP, SCTP or GRE has no tuple to compare against. It is reported rather than
#: correlated, and excluded from the gate's denominator — see `CorrelationResult`.
UnmatchedReason = Literal["no_flow_match", "ambiguous_flow_match", "unsupported_transport"]

#: In-progress output files, written under this name and `os.replace`d into place (issue #70).
#:
#: Defined here rather than in `cli.py` because two modules need the one convention and they sit
#: on opposite sides of the purity line: `cli` writes these, and `canonical` must not compare them
#: — a temporary left behind by a killed process is not an artifact the run claims, and comparing
#: it turns a crash into a misreported Goal 2 failure. Same argument that moved `SNAPSHOT_ID` here.
PARTIAL_SUFFIX = ".partial"


def partial_name(name: str) -> str:
    """The in-progress name for an output file: hidden, and suffixed."""
    return f".{name}{PARTIAL_SUFFIX}"


def is_partial(name: str) -> bool:
    """Whether a path name is an in-progress output file rather than a finished artifact."""
    return Path(name).name.endswith(PARTIAL_SUFFIX)


#: The protocols Zeek can name in `transport_proto`, and so the only ones a detection can be
#: correlated on. Anything else is `unknown_transport` on Zeek's side, with the port columns
#: zeroed — not a tuple that can be compared, whatever Suricata reported.
CORRELATABLE_PROTOCOLS = frozenset({"tcp", "udp", "icmp"})

#: Whether JA4 fingerprinting was available to the Zeek pass, and if not, why not.
#:
#: Three values, not two, and never absence. Without a status a consumer cannot tell "this
#: capture had no TLS" from "the fingerprinting package was not installed" — and spec §2.5 says
#: absence is never a signal. `probe-failed` is separated from `not-installed` because the
#: first is a defect (a broken ZEEKPATH, a half-finished `zkg` install) and the second is the
#: ordinary laptop case; both lose JA4, and reporting them as one hides the defect.
Ja4Status = Literal["present", "not-installed", "probe-failed"]


# --- what a source class means -------------------------------------------------------------
#
# These two are functions of `source_class` and nothing else, so they are module-level rather
# than methods. Both facts have to be read off a `SourceAdmission` — the snapshot's record of
# a source — as well as off a `SourceSpec`, and when the only way to do that was through a
# `SourceSpec` property, two modules independently built a throwaway `SourceSpec` out of an
# admission just to reach them. An adapter written twice to get at two properties means the
# properties are on the wrong object. `SourceSpec` keeps its properties, delegating, so no
# caller had to change.


def may_label(source_class: SourceClass) -> bool:
    """Whether a detection from a source of this class may become a label.

    False exactly for `identify`, which describes benign software. Enforced in code and
    asserted in a test, because a label from one would be a false positive by construction
    (spec §2.8).
    """
    return source_class != "identify"


def label_basis(source_class: SourceClass) -> LabelBasis | None:
    """The basis a label from this class carries, or None if it may not label.

    `ioc-name` sources match a name that was looked up — a DNS query or an HTTP host — so the
    flow referenced the indicator rather than being the malicious traffic itself. Reporting
    that as `direct` would overstate what was observed.
    """
    if not may_label(source_class):
        return None
    return "indicator-reference" if source_class == "ioc-name" else "direct"


# --- ruleset snapshot identity ---------------------------------------------------------------

#: A snapshot id is the first 16 hex characters of a sha256 over the snapshot's content
#: (spec §7). The pattern lives here, in the module that imports nothing, because both
#: `rules/snapshot.py` (which resolves an id to a directory) and `provenance.py` (which refuses
#: to write an unresolvable one onto a label) have to agree on what an id looks like — and
#: `provenance.py` is a pure module, so importing the pattern from the snapshot writer would
#: point a pure module at an impure one.
SNAPSHOT_ID_LENGTH = 16

#: Use `fullmatch`, never `match`: `$` also matches before a trailing newline, so an id read
#: from a file with the newline left on would otherwise pass.
SNAPSHOT_ID = re.compile(rf"^[0-9a-f]{{{SNAPSHOT_ID_LENGTH}}}$")


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

    # Both delegate to the module-level functions above. The names deliberately match: a
    # caller holding a spec asks `spec.may_label`, a caller holding an admission asks
    # `may_label(admission.source_class)`, and there is one derivation behind both. A method
    # body resolves names through the module globals, not the class namespace, so the bare
    # call below reaches the function rather than recursing into the property.
    @property
    def may_label(self) -> bool:
        """Whether a detection from this source may become a label (spec §2.8)."""
        return may_label(self.source_class)

    @property
    def label_basis(self) -> LabelBasis | None:
        """The basis a label from this source carries, or None if it may not label."""
        return label_basis(self.source_class)


@dataclass(frozen=True)
class AdmissionPolicy:
    """What to admit, by rule kind rather than by source (#75).

    `SourceSpec.source_class` classifies a whole **feed**; this classifies individual **rules**.
    The distinction is the whole of #75: `pawpatrules` is one source containing both direct
    detections and policy observations, so no per-source setting can separate them. Measured
    2026-08-13 against 85,431 admitted rules — 23 captures of ordinary protocol traffic produced
    138 malicious labels, 117 of them from the 436 rules whose `classtype` is `policy-violation`.
    Excluding that one classtype removes 85% of the measured false positives at a cost of 0.5%
    of the ruleset.

    Empty by default, so a registry that says nothing admits exactly what it admitted before.
    """

    #: `classtype:` values whose rules are never admitted. A rule declaring one of these is
    #: excluded at admission rather than filtered later, so `snapshot_id` describes exactly the
    #: ruleset that ran and a label's terms cannot disagree with what produced it.
    #: Stored casefolded, so the comparison in `excludes` cannot depend on how the registry or
    #: the feed happened to capitalise. `config.load_admission_policy` casefolds on the way in.
    exclude_classtypes: frozenset[str] = frozenset()

    def excludes(self, classtype: str | None) -> bool:
        """Whether a rule declaring `classtype` is excluded.

        A rule with no `classtype:` is never excluded by this policy. 10,949 of 85,431 admitted
        rules declare none, so treating absence as a match would silently drop 12.8% of the
        ruleset on a policy that never named it.

        **Compared case-insensitively.** `admit.CLASSTYPE` reads `[A-Za-z0-9._-]+` from the rule
        while `config.CLASSTYPE_NAME` forbids uppercase in the registry, so a feed shipping
        `classtype:Policy-Violation;` could never be excluded *and* the operator could not write a
        policy that matched it — the registry would load, the setting would read as in force, and
        the rules would keep labelling. `_metadata_verdict` casefolds for exactly this reason and
        says so: a capitalisation change upstream must not silently change what a run admits.
        """
        return classtype is not None and classtype.casefold() in self.exclude_classtypes

    #: Leading `msg:` markers whose rules are never admitted (#117). `pawpatrules` writes one
    #: emoji per rule — `\N{POLICE CARS REVOLVING LIGHT}` for a detection, `\N{EYE}` / `\N{LOCK}`
    #: / `\N{GLOBE WITH MERIDIANS}` / `\N{FACE WITH RAISED EYEBROW}` for an observation — and it
    #: is the ONLY field separating the two. Measured: 571 rules carry one of the five
    #: observational markers, 126 of them the info-marked rules `exclude_classtypes` already
    #: removes, and **0 of the remaining 445 carry `misc-activity`** — so #113's classtype policy
    #: cannot reach one of them. They declare `bad-unknown` and `attempted-recon`, where genuine
    #: detections also live.
    #:
    #: Not casefolded, unlike `exclude_classtypes`: these are pictographs, `str.casefold` does
    #: nothing to them, and pretending otherwise would suggest a normalisation that is not
    #: happening.
    exclude_msg_markers: frozenset[str] = frozenset()

    #: The marker a feed puts on EVERY rule as its own branding, which therefore classifies
    #: nothing (#117). `pawpatrules` writes a paw print on all 21,467 of its rules, so without
    #: naming it the first pictograph would be the same on every one of them.
    #:
    #: Stated here rather than inferred from shape. The first cut treated *any* leading marker
    #: followed by a dash as branding, which meant a rule written `<eye> - DNS request to .dev`
    #: — no brand at all — reported no marker and was ADMITTED. That is #117 reopening through a
    #: formatting change upstream could make without notice, which is exactly the risk this
    #: policy already concedes is real.
    msg_brand_marker: str | None = None

    def excludes_marker(self, marker: str | None) -> bool:
        """Whether a rule whose leading `msg:` marker is `marker` is excluded.

        A rule with no marker is never excluded — 33 pawpatrules rules and eight entire feeds
        carry none, so treating absence as a match would drop them all on a policy that never
        named them. Same rule, and the same reason, as `excludes` for an absent `classtype:`.
        """
        return marker is not None and marker in self.exclude_msg_markers


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
    #: Rules dropped because their `classtype:` is one the admission policy excludes (#75).
    #: Its own counter, like every other exclusion, because §6's
    #: `fetched == admitted + sum(excluded)` identity has to keep describing the feed.
    rules_excluded_classtype: int = 0
    #: Rules dropped because the marker leading their `msg:` is one the policy excludes (#117).
    #: Its own counter for the same reason as every other exclusion: §6's
    #: `fetched == admitted + sum(excluded)` identity has to keep describing the feed.
    rules_excluded_marker: int = 0

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

    def __post_init__(self) -> None:
        # A duplicate name is rejected here rather than by whichever reader happens to notice,
        # because every consumer resolves a source by name and the failure is silent: a name
        # that appears twice with different terms yields whichever entry the lookup kept, and
        # `label_basis`, `licence` and `admission_basis` on every label from that source then
        # describe the wrong entry. Nothing downstream can detect it — both entries are
        # well-formed. Enforcing it on the type means no manifest with duplicates can exist as
        # an object at all, however it was built: read from disk, constructed in a test, or
        # assembled by a future writer.
        #
        # `_read_manifest` already converts a ValueError from this constructor into a
        # `SnapshotError`, so the operator gets a reason and exit 1 rather than a traceback.
        seen: set[str] = set()
        duplicates: set[str] = set()
        for admission in self.sources:
            if admission.name in seen:
                duplicates.add(admission.name)
            seen.add(admission.name)
        if duplicates:
            raise ValueError(
                f"SnapshotManifest.sources names each source once; some appear more "
                f"than once, and a label resolving through them would cite one entry's terms "
                f"while another's rules fired: {sorted(duplicates)}"
            )

    @property
    def sources_by_name(self) -> Mapping[str, SourceAdmission]:
        """The admissions indexed by source name — the lookup every consumer needs.

        A property rather than a line each caller writes. `suricata.py` resolves a SID's
        originating source through it and correlation resolves a detection's terms through it,
        so without this both build the same comprehension over a tuple, and the duplicate-name
        hazard above lives in each copy. Same argument as `build_source_entry`: a lookup
        written in more than one place is a lookup that can disagree with itself.

        Uniqueness is guaranteed by `__post_init__`, so this cannot silently drop an entry.
        """
        return {admission.name: admission for admission in self.sources}


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
    #: Which side of the flow the matching packet was on (issue #115). No default: the value
    #: comes from the engine, and a default is how it would silently stop doing so.
    direction: Direction
    #: The rule's `metadata:` values, as Suricata reports them in `alert.metadata`. Spec §8
    #: says to parse this; spec §4's field list omitted somewhere to put it. It is what issue
    #: #10 (should untagged ET rules be admitted?) will be answered from.
    metadata: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # A `Detection` reaches `labels.json` directly, inside `unmatched_detections[]`, so the
        # same argument that guards `SourceEntry` applies one model down: the `Literal` is a
        # hint, and an unrecognised direction would serialise happily and mean nothing to a
        # consumer written against spec §4's three values. `direction` is the only enumerated
        # field here; the rest are the engine's raw report, checked where they are read.
        _check(self.direction, get_args(Direction), "direction", "Detection")


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
    direction: Direction

    def __post_init__(self) -> None:
        _check(self.admission_basis, get_args(AdmissionBasis), "admission_basis", "SourceEntry")
        _check(self.label_basis, get_args(LabelBasis), "label_basis", "SourceEntry")
        _check(self.direction, get_args(Direction), "direction", "SourceEntry")


@dataclass(frozen=True)
class LabelEntry:
    """One assertion about a flow, and what asserted it (#138, schema 2.0).

    **`tier` and `sids` are provenance, not decoration.** Once a label is one entry among several,
    the document can no longer imply that `sources[]` accounts for all of them — a `threat-name`
    chosen from one tier-1 detection is not asserted by the other sources beside it. Goal 1 and
    spec §13 require every assertion to name what produced it, and this is where that is carried
    for assertions that are narrower than the whole `sources[]` list.
    """

    name: LabelName
    #: A `str` for a `single` kind, an ordered `tuple[str, ...]` for a `multi` one. Which applies
    #: follows from `name` through `LABEL_KINDS`, so a consumer never has to branch on the value
    #: it happens to find.
    value: str | tuple[str, ...]
    #: The tier of the source(s) that assert *this* entry. For `verdict` that is `min(sources.tier)`
    #: — the same number `Label.best_tier` publishes — and `Label` enforces the two agree.
    tier: int
    #: The signature ids behind this entry, sorted. A tuple rather than a single sid because
    #: `verdict` is asserted by every source on the flow, and a future label may be too.
    sids: tuple[int, ...]

    def __post_init__(self) -> None:
        _check(self.name, get_args(LabelName), "name", "LabelEntry")
        kind = LABEL_KINDS[self.name]
        if self.tier not in kind.tiers:
            # Declared in `LABEL_KINDS` and therefore enforced. spec §4 says `threat-name` is
            # tier-1 only, and prose is not a guard: a tier-2 threat name whose sid a real
            # tier-2 source carries would otherwise pass every other check here.
            raise ValueError(
                f"LabelEntry {self.name!r} claims tier {self.tier}, but that kind permits only "
                f"tier(s) {list(kind.tiers)}"
            )
        if kind.arity == "single" and not isinstance(self.value, str):
            raise ValueError(
                f"LabelEntry {self.name!r} has arity 'single' but its value is "
                f"{type(self.value).__name__}: one assertion, one value"
            )
        if kind.arity == "multi" and (
            isinstance(self.value, str) or not all(isinstance(item, str) for item in self.value)
        ):
            raise ValueError(
                f"LabelEntry {self.name!r} has arity 'multi' but its value is not a sequence of "
                f"strings: {self.value!r}"
            )
        if not self.value:
            raise ValueError(
                f"LabelEntry.value is empty for {self.name!r}: a label asserting nothing is not a "
                f"label, and an empty string serialises as one that is"
            )
        if not self.sids:
            raise ValueError(
                f"LabelEntry.sids is empty for {self.name!r}: an assertion with no signature "
                f"behind it cannot be traced (Goal 1)"
            )
        if tuple(sorted(self.sids)) != tuple(self.sids):
            # Canonical output means the same data serialises the same way however it was
            # assembled (spec §10), and this tuple reaches the file directly.
            raise ValueError(f"LabelEntry.sids for {self.name!r} is not sorted: {self.sids}")


def verdict_entry(sources: Sequence[SourceEntry]) -> LabelEntry:
    """The `verdict` assertion for a flow, derived from the sources that carry it.

    Here rather than in `correlate` — the module that builds labels — for the reason
    `models.label_basis` is: **a test that hand-builds this agrees with itself.** Every verdict
    entry in the codebase, production and fixture alike, comes through this one function, so a
    change to what a verdict entry looks like cannot pass because the fixtures were updated to
    match it.

    Every source on a flow asserts the verdict, so it carries all their sids and the best (lowest)
    tier. The sids are deduplicated: a rule firing twice keeps both `sources[]` entries, because
    collapsing them would say the rule fired once, but the label's sid list is the set of what is
    behind the claim rather than a count of firings.

    **`sids` is a set of signature ids, NOT one element per asserting source** (#140), and the
    difference is visible: PANW threat ids and Suricata sids share no namespace, so a tier-1
    detection and a tier-2 rule that happen to use the same number publish one sid where two
    sources asserted. Nothing becomes untraceable — `sources[]` still carries both entries in full,
    which is where per-source detail belongs — so this is the reading being pinned down rather than
    a defect. Carrying `(source, sid)` pairs instead would be a second schema break for something
    no consumer has been misled by.
    """
    if not sources:
        raise ValueError(
            "a verdict needs at least one source: there is nothing else to derive it from"
        )
    return LabelEntry(
        name="verdict",
        value="malicious",
        tier=min(entry.tier for entry in sources),
        sids=tuple(sorted({entry.sid for entry in sources})),
    )


@dataclass(frozen=True)
class Label:
    """Everything asserted about one flow, with every source that asserted anything.

    There is no benign verdict: flabel labels malicious flows and says nothing about the
    rest. `best_tier` is the *minimum* tier across sources, because a lower tier is a
    higher-trust observation.

    **`labels` replaced a `verdict` field in schema 2.0** (#138). A flow can carry more than one
    assertion — today `verdict` and, on inline runs, `threat-name` — and a field per kind would
    have made every future kind another schema decision.
    """

    flow: Flow
    best_tier: int
    labels: tuple[LabelEntry, ...]
    sources: tuple[SourceEntry, ...]

    def __post_init__(self) -> None:
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

        names = [entry.name for entry in self.labels]
        # A `Label` exists because something was asserted, and `verdict` is that assertion. Without
        # it the object is a flow with provenance and no claim — which is not a label, and would
        # serialise as one.
        if names.count("verdict") != 1:
            raise ValueError(
                f"Label.labels must carry exactly one verdict entry, got {names}: a label with no "
                f"verdict asserts nothing, and two verdicts assert twice"
            )
        if len(names) != len(set(names)):
            # Craig's decision 2 (#138): one `threat-name` per flow, chosen by precedence. Two
            # entries of one name would mean the choice was not made.
            raise ValueError(f"Label.labels has repeated names {names}: each label appears once")

        verdict = next(entry for entry in self.labels if entry.name == "verdict")
        _check(verdict.value, ("malicious",), "verdict", "Label")
        if verdict.tier != self.best_tier:
            raise ValueError(
                f"the verdict entry's tier is {verdict.tier} but Label.best_tier is "
                f"{self.best_tier}: one flow's trust level recorded twice, disagreeing"
            )
        if tuple(sorted(names)) != tuple(names):
            raise ValueError(f"Label.labels is not sorted by name: {names}")

        # **Every entry's provenance is checked, not only the verdict's** (#140). The first version
        # of this validated `verdict` thoroughly and the others not at all, so a `threat-name`
        # naming a sid no source carries — or a tier no source has — serialised looking exactly as
        # traceable as one that was real. `LabelEntry`'s docstring claims this is where Goal 1 is
        # carried for assertions narrower than `sources[]`; that claim needs a guard behind it.
        #
        # Checked against `sources` rather than trusted from the builder because this is the model
        # every producer goes through, and a hand-built `Label` in a fixture is a producer too.
        by_sid: dict[int, set[int]] = {}
        for source in self.sources:
            by_sid.setdefault(source.sid, set()).add(source.tier)
        for entry in self.labels:
            unknown = [sid for sid in entry.sids if sid not in by_sid]
            if unknown:
                raise ValueError(
                    f"Label.labels[{entry.name!r}] cites sid(s) {unknown} that no source on this "
                    f"flow carries: the assertion cannot be traced (Goal 1)"
                )
            if not any(entry.tier in by_sid[sid] for sid in entry.sids):
                raise ValueError(
                    f"Label.labels[{entry.name!r}] claims tier {entry.tier}, which none of its "
                    f"own sources {list(entry.sids)} was reported at"
                )


@dataclass(frozen=True)
class UnmatchedDetection:
    """A detection that could not be attached to exactly one flow, and why.

    Reported rather than dropped: silence must mean nothing happened, never "something
    happened and we didn't say" (spec §2.5).
    """

    detection: Detection
    reason: UnmatchedReason

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
    #: `None` where the pass failed before establishing the number, never `0` (issue #86).
    #:
    #: Spec §10: "every field whose stage did not run is `null` — not zero, not an empty list."
    #: These used to be plain `int`s that a failure filled with zeros, so `run.json` published
    #: `rules_loaded: 0` for a run where the engine may have loaded all 85,000 rules, and
    #: `loss_conditions` then reported `rules_failed_or_skipped: false` — a zero load reading as
    #: a clean load. A count that was genuinely measured before a later failure survives.
    rules_loaded: int | None
    alerts_total: int | None
    #: Rules the engine rejected, and rules it declined to load. Recorded rather than only
    #: compared against the snapshot's count: a rule that never loaded never examined the
    #: capture, so a run that looks complete is missing every label it would have produced.
    rules_failed: int | None = 0
    rules_skipped: int | None = 0
    #: Alerts dropped because their source may not label (spec §2.8). Counted, never silent.
    #:
    #: Defaults to `None`, unlike the two above (issue #86 review). Their zero default is
    #: defensible — they come off the same line of Suricata's output as the loaded count, so a run
    #: with a loaded count has all three — but this one is measured by the eve pass and is
    #: independent of it. A zero default here would have any caller that omits it *assert* that
    #: nothing was suppressed, which is the defect this field's own docstring forbids.
    identify_alerts_suppressed: int | None = None
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
    #: Non-fatal losses this stage observed, for `run.warnings[]` (issue #57).
    #:
    #: Every sibling stage returns these — `NormalizedCapture`, `ZeekRunInfo`, `SuricataRunInfo`
    #: — and correlation did not, so its gate warning reached stderr and nothing else. An
    #: operator reading `run.json` after the fact, which is the normal case because stderr is
    #: not kept, could not see that anything had been warned about.
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """The counts and the records they summarise have to agree (issue #84's review).

        `Label` and `SnapshotManifest` both enforce this class of agreement already, on the
        argument that two fields which can disagree are a flaw in an artifact whose whole value
        is provenance. The step 12 derivations were the first pair exempt, and the exemption was
        reachable: `detections_total=0` with two unmatched records gives `correlatable_total`
        of -1 and a ratio of -1.0, which is below any threshold — a negative percentage that
        passes the gate. `correlate()` cannot build that, so this is a guard on the model rather
        than a fix to a live path.
        """
        if self.detections_total < len(self.unmatched):
            raise ValueError(
                f"CorrelationResult claims {self.detections_total} detections but carries "
                f"{len(self.unmatched)} unmatched ones; every unmatched detection is a detection"
            )

    @property
    def unsupported_transport_total(self) -> int:
        """Unmatched detections on a protocol Zeek cannot express at all (issue #84)."""
        return sum(1 for record in self.unmatched if record.reason == "unsupported_transport")

    @property
    def correlatable_total(self) -> int:
        """Detections that had a tuple worth comparing — the gate's denominator."""
        return self.detections_total - self.unsupported_transport_total

    @property
    def unmatched_ratio(self) -> float:
        """The share the gate acts on: correlatable unmatched over correlatable detections.

        **Not `len(unmatched) / detections_total`**, and spec §10 says so where this is
        published. A detection on ESP or SCTP was never going to correlate — Zeek has no name
        for its protocol — so counting it would let ordinary IPsec traffic fail a run, and
        counting enough of it would drag a genuine tuple-normalisation defect below the
        threshold and silence the gate. `counts.unmatched` still reports every one of them, so
        the scale of the loss is not hidden; only the ratio is narrowed to what it can judge.

        Zero correlatable detections is zero loss, not a division by zero.
        """
        correlatable = self.correlatable_total
        if correlatable == 0:
            return 0.0
        return (len(self.unmatched) - self.unsupported_transport_total) / correlatable
