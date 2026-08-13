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

One of those buckets is not about the feed's content at all. **A rule this engine cannot load
is excluded here rather than handed over to fail**, because Suricata exits 0 on a rule it
rejected and `suricata._check_ruleset_loaded` then fails the whole run — see
`negates_home_net`, which is the three pawpatrules rules that negate a `$HOME_NET` of `any`.

And one rule about zero: **a source that admits no rules at all is a hard failure**, never a
source with a zero next to its name. Spec §5 deleted `abuse.ch/sslbl-c2` for exactly this
reason, and the failure is easy to reach by accident — a corporate proxy answering 200 with an
HTML block page is valid UTF-8 with no `alert` line in it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from flabel import config
from flabel.errors import ConfigError
from flabel.models import AdmissionPolicy, SourceAdmission, SourceSpec

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

#: `classtype:` as declared in the rule text. Read from the rule rather than from
#: `classification.config`, for the reason spec §8 gives: `alert.category` is a *description*
#: looked up by name, so it varies by machine and is empty for any classtype the file omits.
CLASSTYPE = re.compile(r"\bclasstype\s*:\s*([A-Za-z0-9._-]+)\s*;")

#: Keywords that make a rule inspect the packet's *contents*. A rule with none of these decides
#: purely from the header tuple — see `is_ioc_shaped`.
PAYLOAD_KEYWORDS = ("content:", "pcre:", "ja3.hash", "ja4.hash", "dataset:")

#: A rule continued on the next physical line. Read line by line, such a rule is truncated at
#: the backslash and what reaches the snapshot is a fragment Suricata refuses to load. See
#: `_logical_rules` for why a *comment* ending in a backslash is emphatically not one of these.
CONTINUATION = "\\"

#: The Suricata variable flabel sets to `any`, and which therefore cannot be negated.
HOME_NET_VAR = "$HOME_NET"

#: `$HOME_NET` as a whole variable reference. The lookahead is the whole point: `$HOME_NET` is a
#: prefix of `$HOME_NETWORKS`, and a plain substring test would delete rules about an entirely
#: different variable — a silent loss of coverage, which is the failure this module exists to
#: make impossible.
HOME_NET_REFERENCE = re.compile(rf"{re.escape(HOME_NET_VAR)}(?![A-Za-z0-9_])")

#: Characters that end a bare address term inside an address specification. A negation applies
#: to the term or bracketed list that follows the `!`, and these are where that term stops.
ADDRESS_DELIMITERS = frozenset({",", "[", "]", " ", "\t"})


def admit(
    spec: SourceSpec,
    rule_lines: Iterable[str],
    fetched_at: str,
    policy: AdmissionPolicy | None = None,
) -> tuple[list[str], SourceAdmission]:
    """Filter `rule_lines` for `spec`, returning the admitted rules and the counts.

    Admitted rules keep their text and their original order — only surrounding whitespace and
    CR are removed, so a feed switching to CRLF does not change every rule byte and with it the
    snapshot id. Ordering for the snapshot is `snapshot.py`'s job, because the id must not
    depend on fetch order (spec §7).

    `fetched_at` is required rather than defaulted to now. This function is pure, and a default
    that read the clock would make it silently non-deterministic — two identical calls returning
    different `SourceAdmission` values. `flabel.rules.utc_now()` is what a caller passes.

    Spec §6 types the second argument as `Iterable[str]` of *physical* lines; rules continued
    with a trailing backslash are rejoined before anything is counted or classified.
    """
    filtered = spec.admission_basis == "metadata-filter"
    if filtered:
        _require_metadata_publisher(spec)

    admitted: list[str] = []
    fetched = commented = 0
    no_confidence = low_confidence = low_severity = unloadable = 0
    by_classtype = 0
    policy = AdmissionPolicy() if policy is None else policy
    ja3 = ja4 = 0

    for line in _logical_rules(rule_lines, spec):
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
        # Checked *after* the metadata filter, so a rule the filter already excluded stays in
        # its metadata bucket and "low severity" keeps reading as "would have been admitted but
        # for its severity" (issue #11). A rule reaches this test only if it would be admitted.
        if verdict is None and negates_home_net(rule):
            verdict = "unloadable"
        # After the two tests above, for the reason the comment there gives: a rule the metadata
        # filter already dropped stays in its metadata bucket, so "excluded by classtype" keeps
        # reading as "would have been admitted, but its kind is not one we label from".
        if verdict is None and policy.excludes(classtype_of(rule)):
            verdict = "classtype"

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
        elif verdict == "unloadable":
            unloadable += 1
        elif verdict == "classtype":
            by_classtype += 1
        else:
            low_severity += 1

    if not admitted:
        # Strictly stronger than checking for a missing `confidence` key, and it covers the
        # cases that check cannot see: upstream dropping `signature_severity` instead, a proxy
        # answering 200 with an HTML block page, a feed deprecated into a one-line notice.
        # Every one of those would otherwise write a snapshot whose manifest reads
        # `rules_admitted: 0` — indistinguishable from a ruleset that matched nothing, which is
        # the failure spec §5 deleted a source to avoid.
        raise ConfigError(_nothing_admitted_message(spec, fetched, no_confidence, unloadable))

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
        fetched_at=fetched_at,
        rules_excluded_unloadable=unloadable,
        rules_excluded_classtype=by_classtype,
    )
    _verify_identity(admission)
    return admitted, admission


def _logical_rules(lines: Iterable[str], spec: SourceSpec) -> Iterator[str]:
    """Rejoin rules split across physical lines with a trailing backslash.

    Suricata reads a rule file this way, and a reader that did not would admit a fragment
    ending in `\\` — a rule Suricata then refuses to load, counted meanwhile as admitted.

    **A comment is a comment, even when it ends with a backslash.** Suricata tests for the
    leading `#` before it tests for a continuation, and so does this. That is not pedantry:
    `pawpatrules` ends 89 lines with a backslash and every one of them is a line of the ASCII-art
    banner in its file headers (measured 2026-08-12 — the feed ships no multi-line rules at all).
    Treating those as continuations would splice the following line into the comment, and the day
    a banner ends immediately above a rule, that rule would vanish from the snapshot in silence.
    A fragment left dangling after a commented-out rule is not a rule either — it fails
    `ACTIVE_RULE` and is ignored, where Suricata would report a parse error.

    The join itself is byte-faithful: only the backslash is removed and the next physical line
    appended verbatim, exactly as Suricata's parser does it. Whitespace between rule options is
    insignificant, but inside a quoted `msg:` or `content:` it is not, so nothing is stripped.

    A dangling continuation at end of input is a truncated feed, not a rule.
    """
    pending: list[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if pending:
            if line.endswith(CONTINUATION):
                pending.append(line[: -len(CONTINUATION)])
                continue
            pending.append(line)
            yield "".join(pending)
            pending = []
            continue
        if line.lstrip().startswith("#"):
            yield line
            continue
        if line.endswith(CONTINUATION):
            pending.append(line[: -len(CONTINUATION)])
            continue
        yield line
    if pending:
        raise ConfigError(
            f"source {spec.name!r} ends with a rule continued by '{CONTINUATION}' and nothing "
            f"following it. The feed is truncated; a partial rule is not admitted."
        )


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


def classtype_of(rule: str) -> str | None:
    """The `classtype:` a rule declares, or `None` when it declares none.

    `None` is ordinary rather than exceptional: measured 2026-08-13, 10,949 of 85,431 admitted
    rules across the nine feeds declare no classtype at all.
    """
    match = CLASSTYPE.search(rule)
    return match.group(1) if match else None


def is_ioc_shaped(rule: str) -> bool:
    """Whether a rule decides purely from the header tuple, with no payload inspection.

    **This is the definition that separates "this flow *is* the malicious activity" from "this
    flow touched a known-bad indicator"**, and it is applied per rule because the existing
    `source_class` applies per feed. Measured 2026-08-13: 16,667 of 85,431 admitted rules are
    IOC-shaped (19.5%), and **16,067 of those declare `classtype: trojan-activity`** — so the
    declared classtype cannot be used to find them. The shape has to be read off the rule.

    The test is the absence of every keyword that inspects content: `content`, `pcre`, the JA3/JA4
    hash matches, and `dataset` lookups. What remains matches on addresses, ports, protocol and
    flow state — which is exactly what an indicator is.

    Why the distinction earns its keep: an IOC rule cannot be *wrong about the traffic*. It can
    only be wrong about whether the indicator is still bad, which is a different failure mode with
    a different half-life, and it is the failure mode behind the stale `127.0.0.1` rule in #75.

    **First cut, and deliberately conservative.** It counts a TLS-SNI or DNS-name match as
    IOC-shaped, which is right — a name is an indicator. It does not attempt to distinguish a
    single-address rule from one matching a large network, and it says nothing about whether the
    indicator is fresh. Before this drives `label_basis` (step 3 of #75) a sample of the 16,667
    should be read by hand, because it moves the meaning of a label on a fifth of the ruleset.
    """
    body = rule.split("(", 1)[1] if "(" in rule else ""
    return not any(keyword in body for keyword in PAYLOAD_KEYWORDS)


def negates_home_net(rule: str) -> bool:
    """Whether `rule`'s address specification negates `$HOME_NET`, which flabel sets to `any`.

    **Measured, and logically unavoidable.** With `HOME_NET: any`, Suricata 8.0.6 refuses three
    pawpatrules rules — sids **3300158**, **3300159** and **3321393** — with:

        Complete IP space negated. Rule address range is NIL.

    All three are written `alert udp $HOME_NET any -> ![…,$HOME_NET] …`. Negating a `HOME_NET` of
    `any` leaves the empty set, so the rule can never match anything and Suricata says so. This
    is not a misconfiguration that a better `HOME_NET` would fix: nothing can make `$HOME_NET`
    mean everything *and* `!$HOME_NET` mean something.

    `HOME_NET: any` is settled. Measured against the live feeds: only these 3 rules negate
    `HOME_NET`, while **1,397** are `$HOME_NET`-anchored and would go silently dead on a
    public-addressed capture if `HOME_NET` were RFC1918 — a capture from a hosting provider or a
    cloud VPC would simply produce no labels, which is the worst failure this tool has. Trading
    3 rules for 1,397 is the whole of the decision.

    So they are excluded here rather than left to fail at load time. Suricata still exits 0 with
    a failed-rule count, which `suricata._check_ruleset_loaded` turns into a hard failure — so
    "let them fail" is not a quiet degradation, it is a run that never produces labels at all.

    **What counts as a negation.** A `!` applying to a bare term or to a bracketed list that
    contains `$HOME_NET`: `!$HOME_NET`, `![10.0.0.0/8,$HOME_NET]`, and the nested forms. Only the
    rule *header* is examined — everything before the options block — so a `!` inside a
    `content:` or `pcre:` cannot be mistaken for an address negation. Suricata's own parser
    splits the rule at the same place. `$HOME_NET` is matched as a whole variable reference, not
    as a substring, so `!$HOME_NETWORKS` is a different variable and is left alone.

    Public because the measurement script reports on it, and because "which rules did flabel
    refuse to hand the engine" should be answerable without a second parser written for it.
    """
    header = rule.split("(", 1)[0]
    return any(
        HOME_NET_REFERENCE.search(_negated_term(header, index + 1))
        for index, char in enumerate(header)
        if char == "!"
    )


def _negated_term(header: str, start: int) -> str:
    """The text a `!` at `start - 1` applies to: a bracketed list, or a bare term.

    Brackets are matched by depth rather than by the first `]`, because Suricata's address lists
    nest — `![10.0.0.0/8,[192.168.0.0/16,$HOME_NET]]` negates the whole outer list, and stopping
    at the first `]` would read only part of it. An unbalanced bracket yields the rest of the
    header, which over-reports rather than under-reports: a malformed header is a rule Suricata
    will not load either way, and the safe direction is to keep it out of the snapshot.
    """
    if start >= len(header):
        return ""
    if header[start] != "[":
        end = start
        while end < len(header) and header[end] not in ADDRESS_DELIMITERS:
            end += 1
        return header[start:end]

    depth = 0
    for index in range(start, len(header)):
        if header[index] == "[":
            depth += 1
        elif header[index] == "]":
            depth -= 1
            if depth == 0:
                return header[start : index + 1]
    return header[start:]


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


def _nothing_admitted_message(
    spec: SourceSpec, fetched: int, no_confidence: int, unloadable: int
) -> str:
    """Why nothing was admitted, in the words that name the likely cause.

    The four cases read very differently to an operator, so the message distinguishes them even
    though the failure is the same. Order matters: `fetched == 0` is checked first, because with
    no rules at all every other test below is also trivially true.
    """
    if fetched == 0:
        return (
            f"source {spec.name!r} produced no active `alert` rules at all. The payload parsed "
            f"but contained no rules — a proxy block page, an error document, or a feed "
            f"deprecated into a notice all look like this. A snapshot is not written from it, "
            f"because `rules_admitted: 0` in the manifest is indistinguishable from a ruleset "
            f"that matched nothing (docs/spec.md §2.5, and §5's deletion of abuse.ch/sslbl-c2)."
        )
    if fetched == unloadable:
        return (
            f"source {spec.name!r} published {fetched} active rules and every one of them "
            f"negates {HOME_NET_VAR}, which flabel sets to `any` — so none of them can match "
            f'anything and Suricata refuses to load them ("Complete IP space negated"). This '
            f"is a feed flabel's configuration cannot run at all rather than a feed that "
            f"matched nothing; see `negates_home_net`."
        )
    if spec.admission_basis == "metadata-filter" and fetched == no_confidence:
        return (
            f"source {spec.name!r} is admitted by metadata filter but not one of its {fetched} "
            f"active rules carries a `confidence` key. Either the feed stopped publishing ET "
            f"metadata or the fetch returned the wrong artifact. The registry's load-time check "
            f"cannot see this — it validates the source name, not the fetched content."
        )
    return (
        f"source {spec.name!r} admitted none of its {fetched} active rules. Under "
        f"'{spec.admission_basis}' that should be impossible unless the feed's content changed "
        f"shape: if `signature_severity` or `confidence` stopped being published, every rule "
        f"lands in an exclusion counter and the run would otherwise report a ruleset that "
        f"simply matched nothing."
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
        + admission.rules_excluded_unloadable
        + admission.rules_excluded_classtype
    )
    if accounted != admission.rules_fetched:
        raise ValueError(
            f"admission for {admission.name!r} does not balance: {admission.rules_fetched} "
            f"fetched but {accounted} accounted for. Every excluded rule must increment "
            f"exactly one counter (docs/spec.md §6)."
        )
