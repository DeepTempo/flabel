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
import unicodedata
from collections.abc import Iterable, Iterator

from flabel import config
from flabel.errors import ConfigError
from flabel.models import (
    COMBINING_CATEGORIES,
    EMOJI_JOINERS,
    AdmissionPolicy,
    SourceAdmission,
    SourceSpec,
)

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

#: A rule's `msg:` value. The marker a feed writes to classify its own rule lives at the front
#: of it (`marker_of`), and #117 is what happens when nothing reads it.
MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')


#: Rule options that carry **no detection logic**: bookkeeping, output, and flow/rate qualifiers.
#: Everything else in Suricata's option vocabulary inspects something.
#:
#: An allowlist, and the inversion is the whole point. The first cut of this was a *blocklist* of
#: payload keywords — `content`, `pcre`, `ja3.hash`, `ja4.hash`, `dataset` — and it was wrong by
#: 588 rules, because Suricata has dozens of matching keywords that touch no payload buffer:
#: `stamus/lateral` detects specific RPC calls with `dcerpc.iface`/`dcerpc.opnum`, and
#: `pawpatrules` reads certificate state with `tls_cert_expired`. A blocklist of everything that
#: inspects is unbounded and cannot be verified; a list of the handful that do not is both.
NON_DETECTING_OPTIONS = frozenset(
    {
        # bookkeeping and output
        "msg",
        "sid",
        "rev",
        "gid",
        "classtype",
        "reference",
        "metadata",
        "priority",
        "rem",
        "target",
        "noalert",
        # flow and rate qualifiers: they restrict *when* a rule may fire, not *what* it matches
        "flow",
        "threshold",
        "detection_filter",
        "tag",
    }
)

#: `flowbits` and `xbits` are deliberately **not** in the set above, because the option *name* does
#: not determine what the option *does* — one keyword covers both a side effect and a condition:
#:
#:     flowbits:set,seen_c2      records a bit. Does not change what this rule matches.
#:     flowbits:isset,seen_c2    fires ONLY IF a prior rule set it. A condition on other traffic.
#:
#: A rule gated on `isset` is not an address indicator: whether it fires depends on traffic
#: elsewhere in the capture, not on the address in front of it. So the operation is read rather
#: than the keyword.
#:
#: Nothing in the nine feeds uses either form on an otherwise-bare rule today. That is not a
#: reason to allow it: "no feed does this yet" is a property of this week's data, not of the
#: definition, and the definition is what will decide `label_basis`.
STATEFUL_BIT_OPTIONS = frozenset({"flowbits", "xbits", "hostbits"})

#: The `flowbits`/`xbits` operations that only *record* state. Everything else — `isset`,
#: `isnotset` — is a condition on traffic this rule is not itself looking at.
BIT_RECORDING_OPERATIONS = frozenset({"set", "unset", "toggle", "noalert"})

#: The name at the head of a rule option, e.g. `content` in `content:"GET"`.
OPTION_NAME = re.compile(r"^\s*([a-z0-9_.]+)\s*(?::|$)", re.IGNORECASE)

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
    by_classtype = by_marker = 0
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
        # Last of the four, so a rule excluded by any earlier test keeps that test's bucket. A
        # `misc-activity` scanner rule marked with an observational emoji is both, and counting
        # it here would make "excluded by classtype" understate what #113's policy is doing.
        if verdict is None and policy.excludes_marker(marker_of(rule)):
            verdict = "marker"

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
        elif verdict == "marker":
            by_marker += 1
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
        rules_excluded_marker=by_marker,
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


def marker_of(rule: str) -> str | None:
    """The marker leading a rule's `msg:`, or `None` when it carries none (#117).

    `pawpatrules` writes one emoji per rule to say what kind of rule it is, and it is the only
    field that says so: measured on the 2026-08-12 mirror, 9,669 rules are marked as detections
    and 605 as observations, and **0 of the 605 carry `misc-activity`** — so #113's classtype
    policy cannot reach any of them. They span `bad-unknown` and `attempted-recon`, where real
    detections also live, which is why the classtype could not be the discriminator.

    **Positional, never a substring search, and that is a measurement rather than a preference.**
    The same emoji appear *inside* rule text — "Google Chrome <globe> for Windows 7 unsupported
    and vulnerable" is a detection carrying an observational marker mid-sentence. Matching
    anywhere in the `msg:` hits **8,125** rules where this parse hits **605**; of the 7,520
    difference, 3,997 are siren-marked detections and 3,315 are skull-marked ones. An unanchored
    match would have cut a third of the feed's real signatures while reading, in a registry, as
    a five-marker policy.

    **The brand prefix is skipped.** All 21,467 rules begin with the feed's paw-print logo and
    a ` - ` separator, so the first pictograph discriminates nothing. A leading run terminated by
    that separator is treated as a brand prefix and stepped over. A feed writing its marker
    first, with no prefix, still works — the partition finds nothing to skip.

    **The first of several adjacent markers wins.** 34 rules are marked with fire-then-eye and
    they are FireEye BEACON backdoor signatures — detections. Taking any marker in the run would
    exclude all 34 under an eye policy; taking the first keeps them, and the corpus outcome is
    identical either way (17 entries).
    """
    match = MSG.search(rule)
    if match is None:
        return None
    text = match.group(1)
    first = _first_marker(text)
    if first is None:
        return None
    marker, rest = first
    # A marker followed by a dash is the feed's brand, not the rule's class: every pawpatrules
    # rule reads `<paw> - <marker> <text>`. Measured on the mirror, the spacing is not uniform —
    # 21,455 rules write `<paw> - ` and 12 phishing rules write `<paw> -<marker>` with no space
    # after the dash — so the dash is found by scanning rather than by matching a fixed string.
    # The first version of this looked for the literal " - " and reported the paw print itself as
    # the marker on those 12; the convention gate caught it on its first run against the feed.
    stripped = rest.lstrip()
    if stripped[:1] in _BRAND_DASHES:
        second = _first_marker(stripped[1:])
        # `<paw> - APT.Backdoor.MSIL.SUNBURST` has no second marker, and 33 rules are written that
        # way: the answer there is None, never the brand.
        return second[0] if second is not None else None
    return marker


def _first_marker(text: str) -> tuple[str, str] | None:
    """The first pictograph in `text`'s leading run, and what follows it.

    `None` once the run reaches prose. The run ends at the first ASCII character that is not
    spacing: past it the `msg:` is a sentence, and a pictograph found there is part of the
    sentence rather than the rule's marker — which is the 7,520-rule difference this docstring's
    caller measures.
    """
    for index, char in enumerate(text):
        if char.isascii():
            if char.isspace():
                continue
            return None
        if unicodedata.category(char) in COMBINING_CATEGORIES or char in EMOJI_JOINERS:
            # The pirate flag is one glyph and four codepoints (flag, ZWJ, skull, VS16) and 6,910
            # rules lead with it. The marker is its first character, so joiners and variation
            # selectors are stepped over rather than read as markers of their own.
            continue
        return char, text[index + 1 :]
    return None


#: What separates a brand prefix from the rule's own marker. A list because the feed is not
#: consistent about which dash or how much space surrounds it.
_BRAND_DASHES = frozenset({"-", "\N{EN DASH}", "\N{EM DASH}"})


def rule_options(rule: str) -> list[str]:
    """The option clauses of a rule, split on `;` outside quoted values."""
    return _parse_options(rule)[0]


def _parse_options(rule: str) -> tuple[list[str], bool]:
    """The option clauses, and whether the rule parsed cleanly.

    A naive `split(";")` is wrong: `content:"a;b"` and `pcre:"/x;y/"` carry semicolons inside
    quotes, and `content:"say \\"hi\\""` carries an escaped quote. Splitting badly would invent
    option names out of the fragments.

    The second element is what makes the failure safe. A rule with **unbalanced quotes** collapses
    everything after the stray quote into one clause, and if that clause happens to begin with an
    allowlisted name the rule reads as inspecting nothing:

        alert ip any any -> 1.2.3.4 any (msg:"unterminated; content:"evil"; sid:1;)

    parses as a single clause named `msg`, hiding the `content:` entirely. The parser knows this
    happened — `quoted` is still set at the end — so it says so rather than discarding it.
    """
    body = rule.split("(", 1)[1].rsplit(")", 1)[0] if "(" in rule else ""
    clauses: list[str] = []
    buffer: list[str] = []
    quoted = escaped = False
    for character in body:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            clauses.append("".join(buffer))
            buffer = []
            continue
        buffer.append(character)
    clauses.append("".join(buffer))
    return [clause.strip() for clause in clauses if clause.strip()], not quoted


def is_address_indicator(rule: str) -> bool:
    """Whether a rule fires on the **header tuple alone**, inspecting no payload.

    The header tuple is protocol, addresses and ports — so this is slightly wider than the name
    says, and issue #93 is the record of measuring how much wider. **Of 16,075 such rules in the
    live nine-feed snapshot, 16,074 name a literal address and exactly one does not**: sid 3500023
    constrains only a destination port range (`alert udp $HOME_NET any -> any 14433:14444`, THL's
    Hysteria v2 operator ports). The name was kept because renaming the field costs a
    `sid_index.json` schema bump that would invalidate every existing snapshot for one rule in
    sixteen thousand — but what the function *means* is written here rather than implied by its
    name (Craig, 2026-08-14).

    That rule is classified correctly for the same reason the address ones are: it establishes
    that a flow reached a known-bad **port**, not that the flow *is* the malicious activity. Same
    distinction, a different field of the tuple. Narrowing the definition to require an address
    would send it to `direct` instead, asserting that traffic to a port range *is* the
    cryptojacker — the overclaim issue #75 exists to remove.

    Measured 2026-08-13 across the nine feeds: **16,079 of 85,431 rules (18.8%)**, and **99.9% of
    them name a literal IP address as their destination**. They look like this:

        alert ip  any any -> 49.234.45.27 any    Connection to IP flagged at Cobalt Strike C2
        alert tcp $HOME_NET any -> [162.243.103.246] 8080   Feodo Tracker: Emotet CnC

    **The name matters and an earlier one was wrong.** This was called `is_ioc_shaped`, which
    invited the reading that it identifies indicator-based rules in general. It does not, and the
    error is instructive: `abuse.ch/urlhaus` is the canonical `ioc-name` source and scores **0%**
    here, because a domain-name indicator is matched in payload content. What this finds is the
    narrower thing — an address list — and "address indicator" is what it should be called.

    The two classifications therefore **compose rather than compete**: `source_class` covers name
    and URL indicators at the feed level, and this covers address indicators buried inside a
    `signature`-class feed. `pawpatrules` holds 16,064 of them while declaring itself a signature
    source, which is why the feed-level answer alone is not enough.

    Why the distinction earns its keep: an address-list rule cannot be wrong about the traffic. It
    can only be wrong about whether the address is still bad — a different failure mode with a
    different half-life, and the one behind the stale `127.0.0.1` rule in #75.
    """
    options, well_formed = _parse_options(rule)
    # A rule that did not parse, or that carries no options at all, is *not* classified. `all([])`
    # is `True`, so without this the most consequential answer would be the one a parse failure
    # falls into — and `is_address_indicator` is public, so a later caller need not have come
    # through the snapshot writer's own validation.
    if not well_formed or not options:
        return False
    return all(not _option_detects(option) for option in options)


def _option_detects(option: str) -> bool:
    """Whether one rule option constrains what traffic matches.

    An unrecognised option counts as detecting. That is the safe direction: Suricata has hundreds
    of matching keywords and a handful of bookkeeping ones, so an option this module has never
    heard of is far more likely to be the former — and treating it as detecting leaves a rule
    merely unclassified rather than claiming something false about it.
    """
    match = OPTION_NAME.match(option)
    if match is None:
        return True
    name = match.group(1).lower()

    if name in STATEFUL_BIT_OPTIONS:
        _, _, arguments = option.partition(":")
        operation = arguments.split(",")[0].strip().lower()
        return operation not in BIT_RECORDING_OPERATIONS

    return name not in NON_DETECTING_OPTIONS


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
        + admission.rules_excluded_marker
    )
    if accounted != admission.rules_fetched:
        raise ValueError(
            f"admission for {admission.name!r} does not balance: {admission.rules_fetched} "
            f"fetched but {accounted} accounted for. Every excluded rule must increment "
            f"exactly one counter (docs/spec.md §6)."
        )
