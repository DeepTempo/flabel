"""Per-rule admission policy and IOC shape (issue #75, spec §6).

`SourceSpec.source_class` classifies a whole **feed**. These classify individual **rules**, which
is the whole of #75: `pawpatrules` is one source carrying both direct detections and policy
observations, so no per-source setting can separate them.

Every number quoted here was measured on 2026-08-13 against snapshot `8c9e8d58af0a8d64` — 85,431
rules from all nine live feeds, rebuilt offline from the mirror. They are recorded in the tests
that depend on them so a future reader can tell a measurement from an assumption.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flabel.config import load_admission_policies, load_admission_policy
from flabel.errors import ConfigError
from flabel.models import AdmissionPolicy, SourceSpec
from flabel.rules.admit import (
    admit,
    classtype_of,
    is_address_indicator,
    marker_of,
    rule_options,
)

REGISTRY = Path(__file__).resolve().parents[1] / "src" / "flabel" / "data" / "sources.toml"

SPEC = SourceSpec(
    name="t/test",
    url="https://example.invalid/t.rules",
    licence="MIT",
    source_class="signature",
    admission_basis="wholesale",
)
FETCHED_AT = "2026-08-13T00:00:00.000000Z"


def rule(sid: int, *, classtype: str | None = None, payload: str | None = 'content:"GET"; ') -> str:
    body = f'msg:"FLABEL TEST {sid}"; {payload or ""}'
    if classtype:
        body += f"classtype:{classtype}; "
    return f"alert tcp any any -> any any ({body}sid:{sid}; rev:1;)"


def registry_without_admission() -> str:
    """The shipped registry text with its own `[admission]` table removed.

    The registry ships one now, and TOML forbids declaring the same table twice — so a fixture
    that appends its own has to take the shipped one out first. The assertion is deliberate: if
    `[admission]` ever disappears from `sources.toml` again, this fails rather than quietly
    reverting every test below to testing a permissive registry.
    """
    text = REGISTRY.read_text(encoding="utf-8")
    head, marker, _ = text.partition("\n[admission]\n")
    assert marker, "the shipped registry has no [admission] table — see issue #75"
    return head + "\n"


@pytest.fixture
def registry_with(tmp_path: Path):
    """The real registry, its own `[admission]` table swapped for this one.

    Built on the shipped registry rather than a minimal stub: `load_admission_policy` reads the
    same file the sources come from, and a stub would not prove the two coexist.
    """

    def build(admission: str) -> Path:
        path = tmp_path / "sources.toml"
        path.write_text(registry_without_admission() + admission, encoding="utf-8")
        return path

    return build


def registry_without_pawpatrules_override() -> str:
    """The shipped registry text with pawpatrules' own `exclude_classtypes` removed.

    The sibling of `registry_without_admission`, and it exists for the same reason: the registry
    ships one now (#113), TOML forbids declaring the same key twice, and a fixture that injects
    its own has to take the shipped one out first. The assertion is deliberate — if that line
    ever disappears from `sources.toml`, this fails rather than quietly reverting every test
    below to exercising a registry with no per-source policy at all.
    """
    text = registry_without_admission()
    shipped = '\nexclude_classtypes = ["misc-activity"]\n'
    assert shipped in text, "pawpatrules no longer excludes misc-activity — see issue #113"
    return text.replace(shipped, "\n", 1)


def _registry_without_pawpatrules_markers() -> str:
    """The shipped registry with pawpatrules' own `exclude_msg_markers` line removed (#117).

    Third of its kind, and for the third time the same reason: the registry ships the setting,
    TOML forbids declaring a key twice, and a fixture injecting its own has to take the shipped
    one out. The assertion means a deleted policy fails here rather than quietly turning every
    test below into a test of a permissive registry.
    """
    text = registry_without_admission()
    head, sep, tail = text.partition("\nexclude_msg_markers = [")
    assert sep, "pawpatrules no longer excludes any marker — see issue #117"
    return head + tail.partition("]\n")[2]


def _registry_with_source_override(
    tmp_path: Path, *, global_: list[str] | None, pawpatrules: list[str]
) -> Path:
    """The shipped registry with a per-source `exclude_classtypes` on `pawpatrules`.

    Built on the real registry for the same reason `registry_with` is: the loader reads the same
    file the sources come from, and a stub would not prove the two coexist.
    """
    text = registry_without_pawpatrules_override().replace(
        '\nname             = "pawpatrules"\n',
        f'\nname             = "pawpatrules"\nexclude_classtypes = {pawpatrules!r}\n',
        1,
    )
    if global_ is not None:
        text += f"\n[admission]\nexclude_classtypes = {global_!r}\n"
    path = tmp_path / "sources.toml"
    path.write_text(text, encoding="utf-8")
    return path


# --- reading a rule's classtype ----------------------------------------------------------------


def test_the_classtype_comes_from_the_rule_text():
    """Spec §8: not from `classification.config`, which is a per-machine description lookup."""
    assert classtype_of(rule(1, classtype="trojan-activity")) == "trojan-activity"


def test_a_rule_with_no_classtype_reads_as_none_rather_than_empty():
    """`None` is ordinary here: 10,949 of 85,431 admitted rules declare no classtype.

    Empty string would be the tempting alternative and it is wrong — it makes "declared nothing"
    compare equal to a classtype named `""`, and it would let an exclusion policy match it.
    """
    assert classtype_of(rule(1)) is None


# --- the address-indicator shape ------------------------------------------------------------
#
# This is the definition that will separate "this flow IS the malicious activity" from "this flow
# reached a known-bad address" (step 3 of #75). It decides `label_basis` on 18.8% of the ruleset,
# so each case is spelled out rather than left to one example.
#
# **It is an allowlist of non-detecting options, and the first cut was a blocklist that was wrong
# by 588 rules.** Suricata has dozens of matching keywords that touch no payload buffer, and a
# sample immediately turned up two: `stamus/lateral` detects RPC calls with `dcerpc.iface`, and
# `pawpatrules` reads certificate state with `tls_cert_expired`. Neither uses `content`, so both
# were counted as indicators. A blocklist of everything that inspects cannot be enumerated; the
# handful of options that do not inspect can be.


@pytest.mark.parametrize(
    "options, indicator",
    [
        ("", True),
        ("flow:to_server; ", True),
        ("threshold: type limit, track by_dst,count 1, seconds 60; ", True),
        ("flowbits:set,x; ", True),
        ('content:"GET"; ', False),
        ('pcre:"/^a+$/"; ', False),
        ("ja3.hash; ", False),
        ("ja4.hash; ", False),
        ("dataset:isset,tor,type string,load tor.lst; ", False),
        ("dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003; ", False),
        ("dcerpc.opnum:12; ", False),
        ("tls_cert_expired; ", False),
        ("tls.version:1.0; ", False),
        ("itype:8; ", False),
    ],
    ids=[
        "bare-tuple",
        "flow-only",
        "threshold-only",
        "flowbits-only",
        "content",
        "pcre",
        "ja3",
        "ja4",
        "dataset",
        "dcerpc-iface",
        "dcerpc-opnum",
        "tls-cert-expired",
        "tls-version",
        "itype",
    ],
)
def test_an_address_indicator_inspects_nothing_but_the_tuple(options: str, indicator: bool):
    """`flow`, `threshold` and `flowbits` restrict *when* a rule may fire, not *what* it matches.

    The four `False` cases at the end are the ones the blocklist missed, and each is a real rule
    shape from the live feeds rather than an invention.
    """
    rule = f'alert ip any any -> 1.2.3.4 any (msg:"x"; {options}sid:1; rev:1;)'

    assert is_address_indicator(rule) is indicator


def test_options_are_split_outside_quotes_only():
    """`content:"a;b"` carries a semicolon inside a quoted value, and `\\"` escapes a quote.

    Splitting naively on `;` would invent option names out of the fragments and misclassify the
    rule — in the direction that matters, since a fragment is unlikely to be an allowlisted name.
    """
    rule = 'alert ip any any -> 1.2.3.4 any (msg:"a;b"; content:"say \\"hi\\"; now"; sid:1;)'

    names = [option.split(":")[0] for option in rule_options(rule)]

    assert names == ["msg", "content", "sid"]
    assert is_address_indicator(rule) is False


def test_a_name_indicator_is_not_an_address_indicator():
    """The measurement that forced the rename, and the reason the two mechanisms compose.

    `abuse.ch/urlhaus` is the canonical `ioc-name` source and scores **0%** here: a domain-name
    indicator is matched in payload content. So this test does not identify indicator-based rules
    in general — only address lists. `source_class` covers the rest at the feed level, which is
    why a rule is `indicator-reference` if *either* answer says so.
    """
    urlhaus_shaped = 'alert dns any any -> any any (msg:"bad name"; content:"evil.invalid"; sid:1;)'

    assert is_address_indicator(urlhaus_shaped) is False


def test_the_declared_classtype_cannot_identify_an_address_indicator():
    """Measured: of the address-list rules in the nine feeds, the overwhelming majority declare
    `trojan-activity` — the same classtype the strongest direct detections use. So the shape has
    to be read off the rule; asking the rule what kind it is gets the wrong answer."""
    indicator = 'alert ip any any -> 1.2.3.4 any (msg:"c2"; classtype:trojan-activity; sid:1;)'
    signature = (
        'alert ip any any -> any any (msg:"c2"; content:"x"; classtype:trojan-activity; sid:2;)'
    )

    assert classtype_of(indicator) == classtype_of(signature) == "trojan-activity"
    assert is_address_indicator(indicator) is True
    assert is_address_indicator(signature) is False


# --- the policy --------------------------------------------------------------------------------


def test_the_default_policy_admits_everything():
    """An absent `[admission]` table must not change what an existing registry admits."""
    policy = AdmissionPolicy()

    assert policy.excludes("policy-violation") is False
    assert policy.excludes("trojan-activity") is False


def test_a_rule_with_no_classtype_is_never_excluded_by_a_classtype_policy():
    """12.8% of admitted rules declare no classtype, and a policy never named them.

    Treating absence as a match would silently drop 10,949 rules on a setting that says
    `policy-violation`, which is the "silently ignored setting" failure spec §5 refuses.
    """
    policy = AdmissionPolicy(frozenset({"policy-violation"}))

    assert policy.excludes(None) is False


def test_excluded_rules_are_counted_into_their_own_bucket():
    """Spec §6's identity has to keep describing the feed: every exclusion gets one counter.

    `admit` asserts the identity internally, so a missing counter fails here rather than
    producing an admission record that quietly does not add up.
    """
    rules = [
        rule(1, classtype="trojan-activity"),
        rule(2, classtype="policy-violation"),
        rule(3, classtype="policy-violation"),
    ]

    kept, admission = admit(
        SPEC, rules, FETCHED_AT, AdmissionPolicy(frozenset({"policy-violation"}))
    )

    assert len(kept) == 1
    assert admission.rules_admitted == 1
    assert admission.rules_excluded_classtype == 2
    assert admission.rules_fetched == 3


def test_admitting_without_a_policy_is_unchanged():
    """The whole change has to be inert until a registry asks for it."""
    rules = [rule(1, classtype="policy-violation"), rule(2, classtype="trojan-activity")]

    kept, admission = admit(SPEC, rules, FETCHED_AT)

    assert len(kept) == 2
    assert admission.rules_excluded_classtype == 0


def test_a_metadata_excluded_rule_stays_in_its_metadata_bucket():
    """Ordering, and it matters for reading the counters (issue #11).

    A rule the metadata filter already dropped must not be re-counted as a classtype exclusion,
    or "excluded by classtype" stops meaning "would have been admitted, but for its kind".
    """
    et = SourceSpec(
        name="et/open",
        url="https://example.invalid/et.rules",
        licence="MIT",
        source_class="signature",
        admission_basis="metadata-filter",
    )
    rules = [
        # Admitted: passes the filter, and its classtype is not excluded.
        'alert tcp any any -> any any (msg:"a"; content:"x"; classtype:trojan-activity; '
        "metadata:confidence High, signature_severity Major; sid:1; rev:1;)",
        # Excluded by the metadata filter *first*, even though its classtype is also excluded.
        'alert tcp any any -> any any (msg:"b"; content:"x"; classtype:policy-violation; '
        "metadata:confidence Low, signature_severity Major; sid:2; rev:1;)",
    ]

    _, admission = admit(et, rules, FETCHED_AT, AdmissionPolicy(frozenset({"policy-violation"})))

    assert admission.rules_excluded_low_confidence == 1
    assert admission.rules_excluded_classtype == 0, "counted twice, or in the wrong bucket"


# --- loading the policy from the registry --------------------------------------------------------


def test_a_registry_with_no_admission_table_is_permissive(registry_with):
    """A registry that names no policy excludes nothing — the absent-table default.

    This asserted the same thing against the *shipped* registry until 2026-08-13, and that is
    the whole of why the defect below survived: the name reads like a unit test of the default,
    but what it actually pinned was `sources.toml` having no `[admission]` table at all.
    """
    assert load_admission_policy(registry_with("")) == AdmissionPolicy()


def test_the_shipped_registry_really_excludes_policy_violation():
    """Building the mechanism is not the fix — the policy being *in force* is (issue #75).

    `[admission] exclude_classtypes` landed in #78 with its loader, its counter and its tests,
    and the PR described the registry change as made. It was not: `sources.toml` had not been
    touched since step 2, so every real run still admitted the 436 `policy-violation` rules that
    #75 measured as **84.8% of the false-positive source entries** (138 -> 21). An operator
    labelling ordinary traffic got `verdict: malicious` with `label_basis: direct` on TLS 1.0
    and cleartext FTP, in a file whose purpose is training data.

    So this asserts the shipped artifact, not the loader. A test of the loader alone passed
    throughout.
    """
    policy = load_admission_policy(REGISTRY)

    assert policy.excludes("policy-violation"), (
        "the shipped registry admits classtype:policy-violation again — issue #75"
    )
    assert policy != AdmissionPolicy(), "the shipped registry carries no admission policy at all"


def test_the_admission_table_is_read_from_the_registry(registry_with):
    """In the registry rather than on the CLI: spec §12's contract is closed, and `--sources`
    already exists as the override — so one file selects both the feeds and the terms."""
    path = registry_with('\n[admission]\nexclude_classtypes = ["policy-violation"]\n')

    assert load_admission_policy(path).exclude_classtypes == frozenset({"policy-violation"})


@pytest.mark.parametrize(
    "table, reason",
    [
        ('\n[admission]\nexclude_classtype = ["x"]\n', "misspelled key"),
        ('\n[admission]\nexclude_classtypes = "policy-violation"\n', "string, not a list"),
        ("\n[admission]\nexclude_classtypes = [1]\n", "not strings"),
        ('\n[admission]\nexclude_classtypes = [""]\n', "empty classtype"),
        ('\n[admission]\nexclude_classtypes = ["Policy Violation"]\n', "impossible name"),
    ],
    ids=["misspelled", "not-a-list", "not-strings", "empty", "impossible-name"],
)
def test_an_unusable_admission_table_refuses_to_load(table: str, reason: str, registry_with):
    """Spec §5's standing rule, applied to this table: a registry that loads with a setting
    silently ignored is worse than one that refuses to load, because it reads as working.

    The sharpest case is `impossible-name`: a classtype no rule can declare would exclude
    nothing while appearing to be in force, which is the same defect as a misspelled key.
    """
    with pytest.raises(ConfigError):
        load_admission_policy(registry_with(table))


# --- what a snapshot records, and which schemas are trusted --------------------------------------


def test_a_schema_2_index_is_readable_but_its_classification_is_not_trusted(tmp_path: Path):
    """Schema 2 recorded `ioc_shaped`, computed by a definition since measured wrong.

    The snapshot stays *readable* — its sid→source attribution was never in question, and refusing
    it would strand every label already traced to it. What is refused is its **classification**:
    reading it would put a known-bad answer behind a label's `label_basis`, and inventing
    provenance is the one thing this project must not do.

    The remedy is a re-run of `flabel rules update`, not a fallback.
    """
    from flabel.rules.snapshot import SID_INDEX_NAME, load_address_indicators, load_sid_index

    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / SID_INDEX_NAME).write_text(
        json.dumps({"schema": 2, "sources": {"a/one": [1, 2]}, "ioc_shaped": [1, 2]}),
        encoding="utf-8",
    )

    assert load_sid_index(directory) == {1: "a/one", 2: "a/one"}, "attribution still readable"
    assert load_address_indicators(directory) is None, (
        "a schema-2 index must report `None` (not recorded), never an empty set — an empty set "
        "says 'no rule is an indicator', which would label ~16,000 address-list rules `direct`"
    )


def test_a_schema_1_index_records_no_classification(tmp_path: Path):
    """It predates the idea entirely, so there is nothing to distrust — only nothing to report."""
    from flabel.rules.snapshot import SID_INDEX_NAME, load_address_indicators

    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / SID_INDEX_NAME).write_text(
        json.dumps({"schema": 1, "sources": {"a/one": [1]}}), encoding="utf-8"
    )

    assert load_address_indicators(directory) is None


# --- flowbits: where the option name does not determine what the option does --------------------
#
# The allowlist is keyed on the option *name*, and `flowbits` is the case that breaks: one keyword
# covers both a side effect and a condition. `flowbits:set,x` records a bit and does not change
# what the rule matches; `flowbits:isset,x` fires only if a prior rule set it, which makes the
# rule depend on traffic it is not itself looking at.
#
# Nothing in the nine feeds uses either form on an otherwise-bare rule today. That is not why
# these tests exist: "no feed does this yet" describes this week's data, not the definition, and
# the definition is what will decide `label_basis`.


@pytest.mark.parametrize(
    "option, indicator",
    [
        ("flowbits:set,seen_c2", True),
        ("flowbits:unset,seen_c2", True),
        ("flowbits:toggle,seen_c2", True),
        ("flowbits:noalert", True),
        ("flowbits:isset,seen_c2", False),
        ("flowbits:isnotset,seen_c2", False),
        ("xbits:set,bad,track ip_dst", True),
        ("xbits:isset,bad,track ip_dst", False),
        ("hostbits:isset,bad", False),
    ],
    ids=[
        "flowbits-set",
        "flowbits-unset",
        "flowbits-toggle",
        "flowbits-noalert",
        "flowbits-isset",
        "flowbits-isnotset",
        "xbits-set",
        "xbits-isset",
        "hostbits-isset",
    ],
)
def test_the_bit_operation_is_read_not_the_keyword(option: str, indicator: bool):
    """Recording a bit is bookkeeping; testing one is a condition on other traffic."""
    rule = f'alert ip any any -> 1.2.3.4 any (msg:"x"; {option}; sid:1; rev:1;)'

    assert is_address_indicator(rule) is indicator


def test_an_unrecognised_option_counts_as_detecting():
    """The safe direction, and the lesson of the blocklist that preceded this.

    Suricata has hundreds of matching keywords and a handful of bookkeeping ones, so an option
    this module has never heard of is far more likely to be the former. Treating it as detecting
    leaves a rule merely *unclassified*; treating it as bookkeeping would claim something false
    about the rule — and that claim would become a label's `label_basis`.
    """
    rule = 'alert ip any any -> 1.2.3.4 any (msg:"x"; keyword_added_in_suricata_9:1; sid:1;)'

    assert is_address_indicator(rule) is False


def test_the_allowlist_holds_no_option_that_can_express_a_condition():
    """A standing guard on the set itself, not on any one rule.

    `flowbits`/`xbits`/`hostbits` must never be added to `NON_DETECTING_OPTIONS`, because their
    name cannot distinguish `set` from `isset` — that is what `_option_detects` handles instead.
    Adding one would silently reclassify every conditional rule using it as a pure address list.
    """
    from flabel.rules.admit import NON_DETECTING_OPTIONS, STATEFUL_BIT_OPTIONS

    assert not (NON_DETECTING_OPTIONS & STATEFUL_BIT_OPTIONS)


# --- guards on the allowlist itself ---------------------------------------------------------
#
# The cases above check individual rules. These check the *set*, because the set is the entire
# semantics: adding one wrong name to `NON_DETECTING_OPTIONS` silently reclassifies every rule
# using it, and none of the per-rule tests above would notice unless the new name happened to be
# one of the ten they name.


def test_no_committed_fixture_rule_that_inspects_content_is_an_address_indicator():
    """A corpus-level guard, over real rule text rather than invented examples.

    This is the one that would catch a wrong allowlist addition. `sameip`, `dsize`, `urilen`,
    `byte_test`, `ttl`, `http.uri` — add any of them to the set and the per-rule tests still pass,
    but a fixture rule combining it with `content:` would start reading as an address indicator
    and fail here.
    """
    fixtures = sorted((Path(__file__).resolve().parent / "fixtures" / "rules").glob("*.rules"))
    assert fixtures, "the rule fixtures are missing, so this guard would prove nothing"

    checked = 0
    for path in fixtures:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("alert"):
                continue
            if not any(k in line for k in ("content:", "pcre:", "dataset:")):
                continue
            checked += 1
            assert not is_address_indicator(line), (
                f"{path.name} contains a rule that inspects content but reads as an address "
                f"indicator, so the allowlist has gained an option that detects: {line[:120]}"
            )
    assert checked >= 10, f"only {checked} content-matching fixture rules — guard too weak"


def test_the_allowlist_is_exactly_this():
    """A change-detector, and deliberately so.

    Every name here is a claim that Suricata's option of that name cannot constrain what traffic
    matches. Growing the set is a real decision about what a label means, so it should require
    editing a test that says so rather than appending one line to a frozenset.
    """
    from flabel.rules.admit import NON_DETECTING_OPTIONS

    assert (
        frozenset(
            {
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
                "flow",
                "threshold",
                "detection_filter",
                "tag",
            }
        )
        == NON_DETECTING_OPTIONS
    )


def test_none_and_empty_are_different_answers(tmp_path: Path):
    """The distinction finding 4 is about, asserted directly.

    A schema-3 snapshot whose rules genuinely contain no address indicator reports `frozenset()`
    — a measurement. A snapshot that recorded no classification reports `None` — an absence. A
    caller that conflates them emits `label_basis: direct` for every rule and says nothing.
    """
    from flabel.rules.snapshot import SID_INDEX_NAME, load_address_indicators

    measured = tmp_path / "measured"
    measured.mkdir()
    (measured / SID_INDEX_NAME).write_text(
        json.dumps({"schema": 3, "sources": {"a/one": [1]}, "address_indicator": []}),
        encoding="utf-8",
    )
    unrecorded = tmp_path / "unrecorded"
    unrecorded.mkdir()
    (unrecorded / SID_INDEX_NAME).write_text(
        json.dumps({"schema": 1, "sources": {"a/one": [1]}}), encoding="utf-8"
    )

    assert load_address_indicators(measured) == frozenset()
    assert load_address_indicators(unrecorded) is None


def test_a_schema_3_index_missing_the_key_is_a_hard_failure(tmp_path: Path):
    """Schema 3 always writes `address_indicator`, so its absence means the file is damaged.

    Reading that as "no rule is an indicator" would turn a truncated file into a confident
    measurement — the shape spec §2.5 exists to forbid.
    """
    from flabel.errors import SnapshotError
    from flabel.rules.snapshot import SID_INDEX_NAME, load_address_indicators

    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / SID_INDEX_NAME).write_text(
        json.dumps({"schema": 3, "sources": {"a/one": [1]}}), encoding="utf-8"
    )

    with pytest.raises(SnapshotError, match="address_indicator"):
        load_address_indicators(directory)


def test_a_port_only_rule_is_classified_and_the_definition_says_why():
    """Issue #93: the classifier reads the whole header tuple, not only the addresses.

    The field is named `address_indicator` and 16,074 of the 16,075 rules in the live snapshot do
    name a literal address — but one constrains only a destination port range. Measured, not
    assumed; it is sid 3500023, THL's Hysteria v2 operator-port rule.

    Craig's call (2026-08-14) was to keep the behaviour and fix the documentation, because
    narrowing the definition to require an address would send that rule to `label_basis: direct`
    — asserting that traffic to a port range *is* the cryptojacker, which is the overclaim #75
    exists to remove. This pins the behaviour so the name cannot later be read as the spec.
    """
    port_only = (
        "alert udp $HOME_NET any -> any 14433:14444 "
        '(msg:"THL GHOST operator ports"; '
        "threshold:type threshold,track by_src,count 5,seconds 60; "
        "classtype:trojan-activity; sid:3500023; rev:1;)"
    )

    assert is_address_indicator(port_only), (
        "a rule deciding from the header tuple alone is an indicator whichever field it uses"
    )


def test_a_rule_that_inspects_payload_is_not_an_indicator_however_narrow_its_header():
    """The other half of the same boundary: a literal address does not make a rule an indicator.

    Guarded because #93's fix was documentation rather than code, and a reader who takes the field
    name literally might later "correct" the classifier toward the addresses.
    """
    content_rule = (
        'alert tcp any any -> 1.2.3.4 443 (msg:"named address but inspects payload"; '
        'content:"evil"; classtype:trojan-activity; sid:9100001; rev:1;)'
    )

    assert not is_address_indicator(content_rule)


# --- per-source exclusion, unioned with the global policy (#113) --------------------------------
#
# `load_admission_policy`'s docstring said a per-source override would be "a pure addition if a
# feed ever needs one". One does. Measured 2026-08-16 against snapshot 40cac3960114e1b4 on a real
# internet-facing capture — 263,895 packets, 24h, one public IP: 555 labels, of which 587 of the
# 600 source entries came from two pawpatrules rules that identify the Censys and Palo Alto
# Expanse internet scanners. Both are `classtype: misc-activity`, both are marked `ℹ` by the feed
# author. Excluding misc-activity GLOBALLY is the wrong fix: 146 of the 274 misc-activity rules in
# that snapshot are in other feeds and include 45 `ET PHISHING` and 18 `ET MALWARE` rules.
#
# UNION, NOT REPLACE (Craig, 2026-08-16). A per-source list can only ever make a feed *more*
# restricted. Replace semantics would let a per-source list silently re-admit `policy-violation`
# for one feed — issue #75 returning through the mechanism built to prevent it — and would mean
# reading two places to know what a feed admits.


def test_a_source_with_no_override_gets_the_global_policy(registry_with):
    policies = load_admission_policies(
        registry_with('\n[admission]\nexclude_classtypes = ["policy-violation"]\n')
    )

    assert policies["et/open"].exclude_classtypes == frozenset({"policy-violation"})


def test_a_per_source_list_is_added_to_the_global_one_not_substituted_for_it(tmp_path):
    """The whole of the union decision, and the reason for it.

    Under replace semantics `pawpatrules` would silently start admitting `policy-violation`
    again — #75 recurring through the mechanism built to prevent it — because the per-source
    list says nothing about it.
    """
    path = _registry_with_source_override(
        tmp_path, global_=["policy-violation"], pawpatrules=["misc-activity"]
    )

    policies = load_admission_policies(path)

    assert policies["pawpatrules"].exclude_classtypes == frozenset(
        {"policy-violation", "misc-activity"}
    )
    assert policies["et/open"].exclude_classtypes == frozenset({"policy-violation"})


def test_a_source_cannot_use_its_override_to_re_admit_a_globally_excluded_classtype(tmp_path):
    """Stated as its own test because it is the property, not a side effect of the last one.

    A feed listing a *different* classtype must not weaken the global policy for itself. This is
    what "fail-closed" means here, and it is the assertion that fails first if someone changes
    the union to a replace.
    """
    path = _registry_with_source_override(
        tmp_path, global_=["policy-violation"], pawpatrules=["misc-activity"]
    )

    assert load_admission_policies(path)["pawpatrules"].excludes("policy-violation")


def test_an_override_repeating_the_global_value_changes_nothing(tmp_path):
    """Idempotent, so a registry can restate a global exclusion locally without side effects."""
    path = _registry_with_source_override(
        tmp_path, global_=["policy-violation"], pawpatrules=["policy-violation"]
    )

    assert load_admission_policies(path)["pawpatrules"].exclude_classtypes == frozenset(
        {"policy-violation"}
    )


def test_an_override_with_no_global_table_still_applies(tmp_path):
    """The global table is optional; a per-source one must not depend on it existing."""
    path = _registry_with_source_override(tmp_path, global_=None, pawpatrules=["misc-activity"])

    assert load_admission_policies(path)["pawpatrules"].exclude_classtypes == frozenset(
        {"misc-activity"}
    )
    assert load_admission_policies(path)["et/open"] == AdmissionPolicy()


def test_every_enabled_source_has_an_entry(registry_with):
    """`admit` is called per source, so a missing key would be a KeyError mid-fetch — after the
    network work and before anything is written."""
    from flabel.config import enabled_sources

    path = registry_with('\n[admission]\nexclude_classtypes = ["policy-violation"]\n')
    policies = load_admission_policies(path)

    assert {spec.name for spec in enabled_sources(path)} <= set(policies)


def test_a_per_source_override_is_casefolded_like_the_global_one(tmp_path):
    """`config.CLASSTYPE_NAME` forbids uppercase, so this can only arrive via a future relaxation
    — but the global list casefolds and two lists that fold differently would be a trap."""
    path = _registry_with_source_override(tmp_path, global_=None, pawpatrules=["misc-activity"])

    assert load_admission_policies(path)["pawpatrules"].excludes("MISC-ACTIVITY")


@pytest.mark.parametrize(
    "value, reason",
    [
        ('"misc-activity"', "string, not a list"),
        ("[1]", "not strings"),
        ('[""]', "empty classtype"),
        ('["Misc Activity"]', "impossible name"),
    ],
    ids=["not-a-list", "not-strings", "empty", "impossible-name"],
)
def test_an_unusable_per_source_override_refuses_to_load(value, reason, tmp_path):
    """The same validation as the global table, because the same mistakes are available.

    Sharing the validator rather than restating it is the point: two copies would drift, and the
    per-source one is the copy nobody would think to update.
    """
    path = tmp_path / "sources.toml"
    text = registry_without_pawpatrules_override().replace(
        '\nname             = "pawpatrules"\n',
        f'\nname             = "pawpatrules"\nexclude_classtypes = {value}\n',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_admission_policies(path)


def test_the_shipped_registry_excludes_misc_activity_for_pawpatrules_and_only_for_it():
    """The shipped artifact, not the loader — the #75 lesson applied to this change (#113).

    `[admission] exclude_classtypes` shipped in #78 with its loader, its counter and its tests,
    and was inert for a day because `sources.toml` never received the table. A test of the
    mechanism passed throughout. So this asserts the file.

    `and only for it` is half the assertion: excluding misc-activity globally would drop the 45
    `ET PHISHING` and 18 `ET MALWARE` rules that also carry it.
    """
    policies = load_admission_policies(REGISTRY)

    assert policies["pawpatrules"].excludes("misc-activity"), (
        "pawpatrules admits classtype:misc-activity again — that is issue #113, and it is "
        "587 of 600 source entries on an internet-facing capture"
    )
    for name, policy in policies.items():
        if name != "pawpatrules":
            assert not policy.excludes("misc-activity"), (
                f"{name} now excludes misc-activity too. 146 of the 274 misc-activity rules are "
                f"outside pawpatrules and include 45 ET PHISHING and 18 ET MALWARE rules."
            )


def test_the_global_policy_is_unchanged_by_all_this():
    """`load_admission_policy` keeps its old meaning and its old callers."""
    assert load_admission_policy(REGISTRY).exclude_classtypes == frozenset({"policy-violation"})


# --- the marker a feed writes into its `msg:` (issue #117) --------------------------------------
#
# `pawpatrules` marks every rule with an emoji: `🚨` for a detection, `👁`/`🔒`/`🌐`/`🤨` for an
# observation. It is the only field distinguishing the two, and #113's `exclude_classtypes` cannot
# reach the observational ones — measured, they span `bad-unknown` and `attempted-recon`, and 0 of
# the 445 surviving the classtype filter carry `misc-activity`.
#
# Every number below was measured on 2026-08-17 against the 2026-08-12 feed mirror (21,467
# pawpatrules rules) and the 22-capture corpus (338 source entries).

#: The marker on a rule that only observes. `ℹ` is already excluded by classtype (#113); it is
#: named here too so a future `ℹ` rule carrying a different classtype is still caught.
OBSERVATIONAL = ("ℹ", "\U0001f441", "\U0001f512", "\U0001f310", "\U0001f928")

PAW = "\U0001f43e"
SIREN = "\U0001f6a8"
EYE = "\U0001f441"
GLOBE = "\U0001f310"
FIRE = "\U0001f525"
PIRATE = "\U0001f3f4"


def paw_rule(sid: int, msg: str, *, classtype: str = "bad-unknown") -> str:
    """A rule spelled the way the feed spells them: `msg:"🐾 - <marker> <text>"`."""
    return (
        f'alert tcp any any -> any any (msg:"{msg}"; content:"GET"; '
        f"classtype:{classtype}; sid:{sid}; rev:1;)"
    )


def test_a_marker_in_prose_after_the_brand_is_not_the_rules_marker():
    """The prose stop, exercised directly — it had no test, and deleting it stayed green.

    Every other parse test puts the marker in the LEADING position, so what protected them was
    first-marker-wins, not this. The shape that needs the stop is ASCII prose after the brand
    with an emoji later in the sentence, and no fixture had it. Found in review.

    What it costs to lose: a detection rule reading `<paw> - Cobalt Strike <globe> beacon` would
    report the globe and be EXCLUDED, and `rules_excluded_marker` would climb from 445 toward
    8,125 — a silent loss of real signatures, which is the worst outcome this policy has.
    """
    assert marker_of(paw_rule(1, f"{PAW} - Cobalt Strike {GLOBE} beacon over HTTPS"), PAW) is None


def test_a_marker_that_is_not_the_brand_is_never_treated_as_one():
    """The re-admission path found in review, and the reason the brand is now named.

    The first parser treated ANY leading marker followed by a dash as branding. So an
    observational rule written `<eye> - DNS request to .dev` — no brand at all — reported no
    marker and was ADMITTED: issue #117 reopening through a formatting change upstream could
    make without notice, which is precisely the risk this whole design concedes is real.
    """
    assert marker_of(paw_rule(1, f"{EYE} - DNS request to .dev extension"), PAW) == EYE
    assert marker_of(paw_rule(2, f"{SIREN} \N{EN DASH} Cobalt Strike"), PAW) == SIREN


def test_a_letter_or_a_space_is_never_a_marker():
    """The feed is French, and `\xa0` is a plausible typo. Both were returned as markers.

    `É` produces a false gate alarm — noise, but it takes the benign canary and corpus down with
    it. The non-breaking space is worse and silent: a rule reading `<paw> -\xa0<eye> DNS request`
    reported `\xa0`, which no policy names, so the observational rule was ADMITTED.
    """
    assert marker_of(paw_rule(1, f"{PAW} - Élévation de privilèges"), PAW) is None
    assert marker_of(paw_rule(2, f"{PAW} -\N{NO-BREAK SPACE}{EYE} DNS request"), PAW) is None


def test_the_information_marker_is_a_letter_and_is_still_a_marker():
    """`\N{INFORMATION SOURCE}` is Unicode category `Ll`, not `So` — it derives from italic *i*.

    Measured after a review recommended a bare `So` test, which would have rejected the one
    marker #113 and #117 both depend on. Widening to letters would have re-admitted `É`, so the
    character is named explicitly in `models.LETTERLIKE_MARKERS` instead.
    """
    import unicodedata

    assert unicodedata.category("ℹ") == "Ll", "the premise of the exception has changed"
    assert marker_of(paw_rule(1, f"{PAW} - ℹ Censys - Scanner"), PAW) == "ℹ"


def test_the_marker_is_the_one_after_the_feeds_brand_prefix():
    """`🐾` is on all 21,467 rules, so the classifying marker is the next one.

    Named in the registry as `msg_brand_marker` rather than inferred from shape — see
    `test_a_marker_that_is_not_the_brand_is_never_treated_as_one` for what inferring it cost.
    """
    assert marker_of(paw_rule(1, f"{PAW} - {EYE} DNS request to .dev extension"), PAW) == EYE
    assert marker_of(paw_rule(2, f"{PAW} - {SIREN} Connection to a C2"), PAW) == SIREN


def test_a_marker_inside_the_text_is_not_the_rules_marker():
    """The measurement that decides how this is parsed, and it is not a close call.

    `🌐` appears *inside* thousands of msgs — "Google Chrome 🌐 for Windows 7 unsupported and
    vulnerable". Measured on the mirror: a substring match for the five observational markers
    hits **8,125** rules where the anchored parse hits **571**. The 7,554 difference is almost
    entirely detections — 3,997 `🚨` and 3,315 `☠` — so an unanchored match would have silently
    cut a third of the feed's real signatures while reading as a five-marker policy.
    """
    rule = paw_rule(3, f"{PAW} - {SIREN} Google Chrome {GLOBE} for Windows 7 vulnerable")

    assert marker_of(rule, PAW) == SIREN, "the marker is positional, never a substring search"


def test_the_brand_prefix_is_found_however_the_feed_spaces_it():
    """Twelve rules write `<paw> -<marker>` with no space after the dash, and they are real.

    The first version of this parser looked for the literal `" - "`, so on those twelve it
    reported the *paw print* as the rule's marker. That is not a cosmetic miss: the paw print is
    on all 21,467 rules, so a policy naming it would exclude the entire feed, and a census
    keyed on it reports a category that does not exist.

    Found by `tests/integration/marker_gate.py` on its first run against the live feed, which is
    the argument for having built the gate at all — no synthetic fixture had this shape.
    """
    warning = "\N{WARNING SIGN}"
    tight = paw_rule(1, f"{PAW} -{warning} DNS request to suspicious domain - Listed by OpenPhish")
    spaced = paw_rule(2, f"{PAW} - {warning} DNS request to suspicious domain")

    assert marker_of(tight, PAW) == warning
    assert marker_of(spaced, PAW) == warning


def test_the_first_of_two_adjacent_markers_wins():
    """34 rules are marked `🔥👁` — FireEye BEACON backdoor signatures, i.e. real detections.

    Taking *any* marker in the run would exclude all 34 under an `👁` policy. Taking the first
    keeps them, and costs nothing measurable: the corpus outcome is 17 entries either way.
    """
    rule = paw_rule(4, f"{PAW} - {FIRE}{EYE} FireEye - Backdoor.HTTP.BEACON")

    assert marker_of(rule, PAW) == FIRE


def test_a_zwj_emoji_sequence_reduces_to_its_first_character():
    """`🏴‍☠️` is `🏴` + ZWJ + `☠` + VS16, and 6,910 rules lead with it."""
    assert marker_of(paw_rule(5, f"{PAW} - \U0001f3f4‍☠️ Connection to Cobalt Strike"), PAW) == PIRATE


@pytest.mark.parametrize(
    "msg",
    [
        f"{PAW} - APT.Backdoor.MSIL.SUNBURST",
        "ET MALWARE Example C2 Checkin",
        "",
    ],
    ids=["brand-then-text", "no-marker-at-all", "empty"],
)
def test_a_rule_with_no_marker_has_none(msg):
    """33 pawpatrules rules carry no marker, and eight other feeds carry no convention at all.

    `None` rather than `""`, so a policy naming a marker can never match a rule that has none —
    the same rule `AdmissionPolicy.excludes` follows for an absent `classtype:`.
    """
    assert marker_of(paw_rule(6, msg), PAW) is None


def test_a_rule_with_no_msg_at_all_has_no_marker():
    assert marker_of("alert tcp any any -> any any (sid:7; rev:1;)", PAW) is None


# --- excluding on the marker, at admission ------------------------------------------------------


def test_a_rule_whose_marker_is_excluded_is_never_admitted():
    """Issue #117: `🐾 - 👁 DNS request 🌐 to .dev extension` labelled `go.dev` twelve times."""
    policy = AdmissionPolicy(exclude_msg_markers=frozenset({EYE}), msg_brand_marker=PAW)
    rules = [
        paw_rule(3301000, f"{PAW} - {EYE} DNS request {GLOBE} to .dev extension"),
        paw_rule(3300003, f"{PAW} - {SIREN} Connection to a C2"),
    ]

    admitted, admission = admit(SPEC, rules, FETCHED_AT, policy)

    assert len(admitted) == 1, "the observational rule was admitted"
    assert "3300003" in admitted[0], "the detection rule was excluded instead"
    assert admission.rules_excluded_marker == 1


def test_the_marker_exclusion_balances_the_admission_identity():
    """Spec §6: `fetched == admitted + sum(excluded)`. A new counter or the identity breaks."""
    policy = AdmissionPolicy(exclude_msg_markers=frozenset({EYE}), msg_brand_marker=PAW)
    rules = [
        paw_rule(1, f"{PAW} - {EYE} DNS request to .ru extension"),
        paw_rule(2, f"{PAW} - {EYE} DNS request to .biz extension"),
        paw_rule(3, f"{PAW} - {SIREN} Connection to a C2"),
    ]

    _, admission = admit(SPEC, rules, FETCHED_AT, policy)

    assert admission.rules_fetched == 3
    assert (admission.rules_admitted, admission.rules_excluded_marker) == (1, 2)


def test_a_rule_carrying_the_marker_only_in_its_text_is_still_admitted():
    """The regression test for the 7,554 rules an unanchored match would have taken."""
    policy = AdmissionPolicy(exclude_msg_markers=frozenset({GLOBE}), msg_brand_marker=PAW)
    rules = [paw_rule(1, f"{PAW} - {SIREN} Microsoft Edge {GLOBE} outdated and vulnerable")]

    admitted, admission = admit(SPEC, rules, FETCHED_AT, policy)

    assert len(admitted) == 1
    assert admission.rules_excluded_marker == 0


def test_a_rule_excluded_by_classtype_is_not_counted_twice():
    """One rule increments exactly one counter, or the §6 identity is meaningless.

    Classtype is tested first, so a rule that is both keeps reading as "its kind is not one we
    label from" — the same ordering argument `admit` already makes for the metadata buckets.
    """
    policy = AdmissionPolicy(
        exclude_classtypes=frozenset({"misc-activity"}),
        exclude_msg_markers=frozenset({EYE}),
        msg_brand_marker=PAW,
    )
    rules = [
        paw_rule(1, f"{PAW} - {EYE} Censys - Scanner", classtype="misc-activity"),
        # A second rule that IS admitted, because a feed admitting nothing at all is a hard
        # failure of its own (spec §5) and would mask what this test is measuring.
        paw_rule(2, f"{PAW} - {SIREN} Connection to a C2"),
    ]

    _, admission = admit(SPEC, rules, FETCHED_AT, policy)

    assert (admission.rules_excluded_classtype, admission.rules_excluded_marker) == (1, 0)


def test_a_policy_naming_no_markers_admits_every_marker():
    """The absent-list default: an existing registry keeps its behaviour."""
    rules = [paw_rule(1, f"{PAW} - {EYE} DNS request to .dev extension")]

    admitted, admission = admit(SPEC, rules, FETCHED_AT, AdmissionPolicy())

    assert len(admitted) == 1
    assert admission.rules_excluded_marker == 0


# --- loading the marker policy from the registry ------------------------------------------------


def test_the_shipped_registry_really_excludes_the_observational_markers():
    """The #113 lesson applied to its own successor: the mechanism is not the fix.

    `exclude_classtypes` shipped as a loader, a counter and a full test suite in #78 — and
    `sources.toml` never received the table, so every real run still admitted the 436 rules it
    was built to exclude. A test of the loader passed throughout. So this asserts the shipped
    artifact.
    """
    policy = load_admission_policies(REGISTRY)["pawpatrules"]

    for marker in OBSERVATIONAL:
        assert policy.excludes_marker(marker), (
            f"the shipped registry admits pawpatrules rules marked {marker!r} again — that is "
            f"issue #117, and it is `go.dev` labelled malicious twelve times"
        )
    assert not policy.excludes_marker(SIREN), (
        "the shipped registry now excludes the feed's detection marker, which would drop 9,669 "
        "content signatures"
    )


def test_only_pawpatrules_carries_a_marker_policy():
    """The convention is one feed's. Applying it globally would exclude on a coincidence."""
    for name, policy in load_admission_policies(REGISTRY).items():
        if name != "pawpatrules":
            assert policy.exclude_msg_markers == frozenset(), (
                f"{name} now has a marker policy, but the emoji convention is pawpatrules' own"
            )


def test_a_per_source_marker_list_is_unioned_with_the_global_one(tmp_path):
    """Same rule as `exclude_classtypes`: a feed can only ever be made more restricted."""
    text = _registry_without_pawpatrules_markers().replace(
        '\nname             = "pawpatrules"\n',
        f'\nname             = "pawpatrules"\nexclude_msg_markers = [{EYE!r}]\n',
        1,
    )
    text += f"\n[admission]\nexclude_msg_markers = [{GLOBE!r}]\n"
    path = tmp_path / "sources.toml"
    path.write_text(text, encoding="utf-8")

    policies = load_admission_policies(path)

    assert policies["pawpatrules"].exclude_msg_markers == frozenset({EYE, GLOBE})
    assert policies["et/open"].exclude_msg_markers == frozenset({GLOBE})


@pytest.mark.parametrize(
    "table, reason",
    [
        ('\n[admission]\nexclude_msg_marker = ["x"]\n', "misspelled key"),
        (f'\n[admission]\nexclude_msg_markers = "{EYE}"\n', "string, not a list"),
        ("\n[admission]\nexclude_msg_markers = [1]\n", "not strings"),
        ('\n[admission]\nexclude_msg_markers = [""]\n', "empty"),
        # ONE ascii character, not "OBS": a multi-character entry is caught by the length
        # check below it, so a longer string would have exercised the wrong guard and passed
        # with the ascii check deleted. Verified by deleting it — the suite stayed green.
        ('\n[admission]\nexclude_msg_markers = ["X"]\n', "ascii, can never match"),
        ('\n[admission]\nexclude_msg_markers = ["OBS"]\n', "ascii and too long"),
        (f'\n[admission]\nexclude_msg_markers = ["{EYE}{GLOBE}"]\n', "two markers in one entry"),
    ],
    ids=["misspelled", "not-a-list", "not-strings", "empty", "ascii", "ascii-long", "two-markers"],
)
def test_an_unusable_marker_list_is_refused(registry_with, table, reason):
    """A policy that cannot match reads as one that is in force, which is the #75 failure.

    An ASCII "marker" is the sharp one: the parse stops at the first ASCII character, so
    `exclude_msg_markers = ["OBS"]` would exclude exactly nothing while sitting in the registry
    looking like a rule about observations.
    """
    with pytest.raises(ConfigError):
        load_admission_policies(registry_with(table))


def test_an_unusable_brand_is_refused(registry_with):
    """A brand that matches nothing is worse than no brand at all.

    `marker_of` only steps over the prefix when the first marker EQUALS the brand. So a brand
    that no rule carries means every rule keeps its own brand as its marker — and a policy
    naming a real marker then excludes nothing, silently, while sitting in the registry.
    """
    for value in ('"paw"', '"\U0001f43e\U0001f441"', "42"):
        with pytest.raises(ConfigError, match="msg_brand_marker"):
            load_admission_policies(registry_with(f"\n[admission]\nmsg_brand_marker = {value}\n"))


def test_the_shipped_registry_names_the_brand(registry_with):
    """The #113 lesson a third time: the mechanism is not the fix, the shipped artifact is."""
    assert load_admission_policies(REGISTRY)["pawpatrules"].msg_brand_marker == PAW
