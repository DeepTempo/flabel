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

from flabel.config import load_admission_policy
from flabel.errors import ConfigError
from flabel.models import AdmissionPolicy, SourceSpec
from flabel.rules.admit import admit, classtype_of, is_address_indicator, rule_options

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
