"""Which of a feed's rules may produce labels — the admission policy (docs/spec.md §6).

Pure: text in, admitted text and counts out. No network, no filesystem, no clock beyond the
`fetched_at` the caller supplies. `test_architecture.py` enforces the first part of that.

Two ideas do all the work here.

**Admission is per source, never global.** Only `et/open` publishes the ET metadata taxonomy,
so only `et/open` is metadata-filtered; the IOC feeds carry no `confidence` key at all and a
global filter would exclude 100% of them (issue #11 records that an earlier draft of the
research made exactly this mistake).

**Every rule that does not make it into the snapshot is counted, in exactly one bucket.**
`rules_fetched == rules_admitted + sum(excluded)` is asserted here and again in the tests, so
rules cannot go missing unaccounted for. Disabled (`#alert`) rules sit outside that identity
in their own counter: ET Open ships 19,479 of them against 51,778 active rules, and folding
them in would make the admitted percentage describe a population nobody ever runs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from flabel import config
from flabel.errors import ConfigError
from flabel.models import SourceAdmission, SourceSpec
from flabel.rules import utc_now

#: An enabled rule. Matched against the stripped line, so a feed that indents its rules — or
#: ships CRLF — is read the same way Suricata reads it.
ACTIVE_RULE = re.compile(r"^alert\s")

#: A rule the feed shipped switched off. `#+\s*` covers `#alert`, `##alert` and `# alert`
#: alike; ET Open uses the first spelling for all 19,479 of them, but the others are legal in
#: a hand-maintained feed and must not be mistaken for prose.
DISABLED_RULE = re.compile(r"^#+\s*alert\s")

#: One `metadata:` option and its comma-separated `key value` pairs, up to the closing `;`.
#: `finditer`, not `search`: Suricata allows several `metadata:` options on one rule and their
#: keys merge, so reading only the first would drop a `confidence` that lives in the second.
METADATA_OPTION = re.compile(r"\bmetadata\s*:\s*([^;]*);")

#: The metadata key admission gates on, and the only value that passes.
CONFIDENCE_KEY = "confidence"
ADMITTED_CONFIDENCE = frozenset({"high"})

#: The severity key, and the values spec §6 accepts. A rule with no severity key fails this
#: test like any other rule that does not meet the bar — spec §6 requires *both* conditions.
SEVERITY_KEY = "signature_severity"
ADMITTED_SEVERITY = frozenset({"major", "critical"})

#: Counted by presence of the keyword, per spec §6. Deliberately literal: `ja3s.hash` is a
#: different keyword (the server-side fingerprint) and is not counted as either.
JA3_KEYWORD = "ja3.hash"
JA4_KEYWORD = "ja4.hash"


def admit(
    spec: SourceSpec,
    rule_lines: Iterable[str],
    fetched_at: str | None = None,
) -> tuple[list[str], SourceAdmission]:
    """Filter `rule_lines` for `spec`, returning the admitted rules and the counts.

    Admitted rules keep their text and their original order — only surrounding whitespace and
    CR are removed, so a feed switching to CRLF does not change every rule byte and with it the
    snapshot id. Ordering for the snapshot is `snapshot.py`'s job, because the id must not
    depend on fetch order (spec §7).

    `fetched_at` defaults to now, which keeps `flabel rules update` from having to thread a
    clock through; every test passes it explicitly so an admission can be compared field by
    field.
    """
    filtered = spec.admission_basis == "metadata-filter"
    if filtered:
        _require_metadata_publisher(spec)

    admitted: list[str] = []
    fetched = commented = 0
    no_confidence = low_confidence = low_severity = 0
    ja3 = ja4 = 0

    for line in rule_lines:
        rule = line.strip()
        if DISABLED_RULE.match(rule):
            # Never admitted under either basis: the feed's author disabled it, and a
            # labelling tool has no standing to re-enable someone else's retired rule.
            commented += 1
            continue
        if not ACTIVE_RULE.match(rule):
            continue  # a comment, a blank line, or a `config`/`var` directive
        fetched += 1

        verdict = _metadata_verdict(rule) if filtered else None

        if verdict is None:
            admitted.append(rule)
            # Counted among *admitted* rules only, as the field names say. A run reports these
            # so that zero JA4 labels reads as "no JA4 content published upstream" rather than
            # "the JA4 path is broken" (issue #13); counting rules the filter dropped would
            # break exactly that reading.
            if JA3_KEYWORD in rule:
                ja3 += 1
            if JA4_KEYWORD in rule:
                ja4 += 1
        elif verdict == "no_confidence":
            no_confidence += 1
        elif verdict == "low_confidence":
            low_confidence += 1
        else:
            low_severity += 1

    if filtered and fetched == no_confidence:
        raise ConfigError(_no_confidence_message(spec, fetched))

    admission = SourceAdmission(
        name=spec.name,
        url=spec.url,
        licence=spec.licence,
        source_class=spec.source_class,
        admission_basis=spec.admission_basis,
        rules_fetched=fetched,
        rules_admitted=len(admitted),
        rules_excluded_no_confidence=no_confidence,
        rules_excluded_low_confidence=low_confidence,
        rules_excluded_low_severity=low_severity,
        rules_excluded_commented=commented,
        ja4_rules_admitted=ja4,
        ja3_rules_admitted=ja3,
        fetched_at=utc_now() if fetched_at is None else fetched_at,
    )
    _verify_identity(admission)
    return admitted, admission


def rule_metadata(rule: str) -> dict[str, str]:
    """The `metadata:` keys of one rule, lowercased keys, later options merged over earlier.

    Public because issue #10 — should untagged ET rules be admitted? — will be answered by
    counting metadata keys across a real feed, and that question should not need a second
    parser written for it.
    """
    metadata: dict[str, str] = {}
    for option in METADATA_OPTION.findall(rule):
        for item in option.split(","):
            pair = item.strip().split(None, 1)
            if not pair:
                continue
            metadata[pair[0].casefold()] = pair[1].strip() if len(pair) > 1 else ""
    return metadata


def _metadata_verdict(rule: str) -> str | None:
    """`None` to admit, otherwise the name of the counter this rule is excluded into.

    The order is what makes the counters a partition: a rule with no `confidence` key is
    counted for that and nothing else, even though its severity may also be too low. Which
    means "low severity" reads as "would have been admitted but for its severity" — the only
    reading from which the coverage question in issue #11 can be answered.
    """
    metadata = rule_metadata(rule)
    confidence = metadata.get(CONFIDENCE_KEY)
    if confidence is None:
        return "no_confidence"
    if confidence.casefold() not in ADMITTED_CONFIDENCE:
        return "low_confidence"
    # Values are compared case-folded throughout: ET writes `High`/`Major`, and a
    # capitalisation change upstream must not silently drop 21,000 rules from a run.
    if metadata.get(SEVERITY_KEY, "").casefold() not in ADMITTED_SEVERITY:
        return "low_severity"
    return None


def _require_metadata_publisher(spec: SourceSpec) -> None:
    """Reject `metadata-filter` on a source that cannot carry ET metadata.

    `config.load_sources` already refuses this combination, but a `SourceSpec` can be built
    without going through the registry, and the consequence here is silent: the filter would
    admit nothing and the run would look like a feed that matched nothing.

    Read through the `config` module rather than imported by value, so there is exactly one
    list of which feeds publish the taxonomy (PLAN.md step 4) and a test can prove it.
    """
    if spec.name not in config.ET_METADATA_SOURCES:
        raise ConfigError(
            f"source {spec.name!r} uses admission_basis 'metadata-filter' but is not a known "
            f"publisher of ET-style metadata, so the filter would admit nothing. Sources known "
            f"to carry it: {sorted(config.ET_METADATA_SOURCES)}"
        )


def _no_confidence_message(spec: SourceSpec, fetched: int) -> str:
    return (
        f"source {spec.name!r} is admitted by metadata filter but not one of its {fetched} "
        f"active rules carries a `confidence` key. Either the feed stopped publishing ET "
        f"metadata or the fetch returned the wrong artifact; both would make the filter admit "
        f"zero rules, which is indistinguishable in the output from a ruleset that matched "
        f"nothing. The registry's load-time check cannot see this — it validates the source "
        f"name, not the fetched content — so it is checked here instead."
    )


def _verify_identity(admission: SourceAdmission) -> None:
    """Spec §6: `fetched == admitted + sum(excluded)`, checked rather than trusted.

    A `ValueError` because a violation is a bug in this module, not a condition an operator
    can act on; `cli.py` maps anything unrecognised to exit 1.
    """
    accounted = (
        admission.rules_admitted
        + admission.rules_excluded_no_confidence
        + admission.rules_excluded_low_confidence
        + admission.rules_excluded_low_severity
    )
    if accounted != admission.rules_fetched:
        raise ValueError(
            f"admission for {admission.name!r} does not balance: {admission.rules_fetched} "
            f"fetched but {accounted} accounted for. Every excluded rule must increment "
            f"exactly one counter (docs/spec.md §6)."
        )
