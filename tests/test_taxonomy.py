"""Per-rule admission policy and IOC shape (issue #75, spec §6).

`SourceSpec.source_class` classifies a whole **feed**. These classify individual **rules**, which
is the whole of #75: `pawpatrules` is one source carrying both direct detections and policy
observations, so no per-source setting can separate them.

Every number quoted here was measured on 2026-08-13 against snapshot `8c9e8d58af0a8d64` — 85,431
rules from all nine live feeds, rebuilt offline from the mirror. They are recorded in the tests
that depend on them so a future reader can tell a measurement from an assumption.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flabel.config import load_admission_policy
from flabel.errors import ConfigError
from flabel.models import AdmissionPolicy, SourceSpec
from flabel.rules.admit import admit, classtype_of, is_ioc_shaped

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


# --- the IOC shape -----------------------------------------------------------------------------
#
# This is the definition that will separate "this flow IS the malicious activity" from "this flow
# touched a known-bad indicator" (step 3 of #75). It moves the meaning of a label on 19.5% of the
# ruleset, so each case below is spelled out rather than left to a single example.


@pytest.mark.parametrize(
    "payload, shaped",
    [
        (None, True),
        ('content:"GET"; ', False),
        ('pcre:"/^a+$/"; ', False),
        ("ja3.hash; ", False),
        ("ja4.hash; ", False),
        ("dataset:isset,tor,type string,load tor.lst; ", False),
        ("flow:to_server; ", True),
        ("threshold: type limit, track by_dst,count 1, seconds 60; ", True),
    ],
    ids=[
        "bare-tuple",
        "content",
        "pcre",
        "ja3",
        "ja4",
        "dataset",
        "flow-state-only",
        "threshold-only",
    ],
)
def test_ioc_shape_is_the_absence_of_payload_inspection(payload: str | None, shaped: bool):
    """A rule matching on addresses, ports, protocol and flow state alone is an indicator.

    `flow:` and `threshold:` do not make a rule a signature — neither looks at bytes. Getting
    that wrong would misclassify the abuse.ch feeds, which are indicators with flow state.
    """
    assert is_ioc_shaped(rule(1, payload=payload)) is shaped


def test_the_declared_classtype_cannot_identify_an_ioc_rule():
    """The measurement that forces this to be structural rather than declared.

    Of the 16,667 IOC-shaped rules in the nine feeds, **16,067 declare `trojan-activity`** — the
    same classtype the strongest direct detections use. So the shape has to be read off the rule;
    asking the rule what kind it is gets the wrong answer for 96% of them.
    """
    ioc = rule(1, classtype="trojan-activity", payload=None)
    signature = rule(2, classtype="trojan-activity")

    assert classtype_of(ioc) == classtype_of(signature) == "trojan-activity"
    assert is_ioc_shaped(ioc) is True
    assert is_ioc_shaped(signature) is False


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
