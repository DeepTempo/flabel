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


@pytest.fixture
def registry_with(tmp_path: Path):
    """The real registry plus an `[admission]` table, so the nine sources stay valid.

    Built on the shipped registry rather than a minimal stub: `load_admission_policy` reads the
    same file the sources come from, and a stub would not prove the two coexist.
    """

    def build(admission: str) -> Path:
        path = tmp_path / "sources.toml"
        path.write_text(REGISTRY.read_text(encoding="utf-8") + admission, encoding="utf-8")
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
# by 585 rules.** Suricata has dozens of matching keywords that touch no payload buffer, and a
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


def test_a_registry_with_no_admission_table_is_permissive():
    assert load_admission_policy(REGISTRY) == AdmissionPolicy()


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
    assert load_address_indicators(directory) == frozenset(), "its classification is not trusted"


def test_a_schema_1_index_records_no_classification(tmp_path: Path):
    """It predates the idea entirely, so there is nothing to distrust — only nothing to report."""
    from flabel.rules.snapshot import SID_INDEX_NAME, load_address_indicators

    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / SID_INDEX_NAME).write_text(
        json.dumps({"schema": 1, "sources": {"a/one": [1]}}), encoding="utf-8"
    )

    assert load_address_indicators(directory) == frozenset()
