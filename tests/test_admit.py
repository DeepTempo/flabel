"""Admission policy (docs/spec.md §6).

Everything here runs against committed fixtures, never the live feeds. The live ET Open set
is the *measurement* target (issue #11) but it is not a test input: it changes weekly, and a
suite that reran the measurement would fail the week ET published rules rather than the week
flabel broke.

`tests/fixtures/rules/et_open_metadata.rules` carries one rule per branch of the policy, with
fixed sids, so a miscount points at a specific rule instead of a total being off by one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flabel import config
from flabel.errors import ConfigError
from flabel.models import SourceAdmission, SourceSpec
from flabel.rules.admit import admit

FIXTURES = Path(__file__).parent / "fixtures" / "rules"

#: A fixed timestamp everywhere, so a `SourceAdmission` can be compared field by field.
FETCHED_AT = "2026-08-12T00:00:00.000000Z"


def rule_lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def et_open() -> SourceSpec:
    """The registry's only metadata-filtered source, built directly rather than loaded.

    Constructing it here keeps this suite independent of `data/sources.toml`: the policy is
    what is under test, not which URL ET publishes at.
    """
    return SourceSpec(
        name="et/open",
        url="https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
        licence="MIT",
        source_class="signature",
        admission_basis="metadata-filter",
    )


def wholesale(name: str = "abuse.ch/feodotracker") -> SourceSpec:
    return SourceSpec(
        name=name,
        url="https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz",
        licence="CC0-1.0",
        source_class="ioc-dest",
        admission_basis="wholesale",
    )


def sids(rules: list[str]) -> set[int]:
    """The sids of `rules`, so assertions name rules rather than counting them."""
    found = set()
    for rule in rules:
        _, _, tail = rule.partition("sid:")
        found.add(int(tail.split(";")[0]))
    return found


# --- the metadata filter -------------------------------------------------------------------


def test_metadata_filter_admits_only_high_confidence_and_major_or_critical():
    admitted, counts = admit(et_open(), rule_lines("et_open_metadata.rules"), FETCHED_AT)

    assert sids(admitted) == {
        2000001,  # High / Major
        2000002,  # High / Critical
        2000010,  # High / Major, ja3.hash
        2000011,  # High / Critical, ja4.hash
        2000012,  # lowercase `high` / `critical`
        2000013,  # confidence and severity split across two metadata: options
    }
    assert counts.rules_admitted == 6


def test_every_exclusion_reason_lands_in_its_own_counter():
    """The four counters are a partition, not overlapping tallies."""
    _, counts = admit(et_open(), rule_lines("et_open_metadata.rules"), FETCHED_AT)

    assert counts.rules_fetched == 13
    assert counts.rules_excluded_no_confidence == 2  # sids 2000007 (no metadata), 2000008
    assert counts.rules_excluded_low_confidence == 3  # Low, Medium, and the excluded ja3 rule
    assert counts.rules_excluded_low_severity == 2  # Minor, and severity key absent


def test_a_missing_confidence_key_is_counted_apart_from_a_low_one():
    """Issue #10 asks how many rules are untagged as opposed to tagged Low/Medium.

    Collapsing the two counters would make that question unanswerable from a run's output,
    which is the whole reason the field exists.
    """
    spec = et_open()
    # Each pair keeps one admitted rule (sid 2000001) alongside the rule under test, because a
    # feed with *no* `confidence` key anywhere is the separate hard failure asserted below.
    untagged = _rules_with_sids(2000001, 2000008)
    tagged_low = _rules_with_sids(2000001, 2000005)

    _, no_key = admit(spec, untagged, FETCHED_AT)
    _, low = admit(spec, tagged_low, FETCHED_AT)

    assert (no_key.rules_excluded_no_confidence, no_key.rules_excluded_low_confidence) == (1, 0)
    assert (low.rules_excluded_no_confidence, low.rules_excluded_low_confidence) == (0, 1)


def _rules_with_sids(*wanted: int) -> list[str]:
    lines = [
        line
        for line in rule_lines("et_open_metadata.rules")
        if any(f"sid:{sid};" in line for sid in wanted)
    ]
    assert len(lines) == len(wanted), f"fixture no longer carries all of {wanted}"
    return lines


@pytest.mark.parametrize(
    ("spec", "fixture"),
    [
        (et_open(), "et_open_metadata.rules"),
        (wholesale(), "et_open_metadata.rules"),
        (wholesale(), "ioc_wholesale.rules"),
    ],
    ids=["filtered-et", "wholesale-et", "wholesale-ioc"],
)
def test_fetched_equals_admitted_plus_every_exclusion(spec: SourceSpec, fixture: str):
    """Spec §6's identity. If it ever fails, rules went missing unaccounted for."""
    _, counts = admit(spec, rule_lines(fixture), FETCHED_AT)

    assert counts.rules_fetched == (
        counts.rules_admitted
        + counts.rules_excluded_no_confidence
        + counts.rules_excluded_low_confidence
        + counts.rules_excluded_low_severity
    )


# --- disabled rules ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "spec", "disabled_sid", "active"),
    [
        ("et_open_metadata.rules", et_open(), 2000009, 13),
        ("ioc_wholesale.rules", wholesale(), 7100005, 4),
    ],
    ids=["metadata-filter", "wholesale"],
)
def test_commented_rules_are_counted_but_never_admitted(
    fixture: str, spec: SourceSpec, disabled_sid: int, active: int
):
    """`#alert` is a rule the feed shipped switched off. Neither basis may turn it on.

    They are counted in their own field rather than in `rules_fetched`: ET Open ships 19,479
    of them against 51,778 active rules, so folding them into the fetched total would make
    the admitted percentage describe a population nobody runs.
    """
    admitted, counts = admit(spec, rule_lines(fixture), FETCHED_AT)

    assert disabled_sid not in sids(admitted)
    assert not any(rule.lstrip().startswith("#") for rule in admitted)
    assert counts.rules_excluded_commented == 1
    assert counts.rules_fetched == active


def test_comments_and_blank_lines_are_not_rules():
    """Only `alert` lines count — a header comment is neither fetched nor excluded."""
    admitted, counts = admit(
        wholesale(),
        ["# a header", "", "   ", "# alert-looking prose about alerts", "\t"],
        FETCHED_AT,
    )

    assert admitted == []
    assert (counts.rules_fetched, counts.rules_excluded_commented) == (0, 0)


# --- wholesale -----------------------------------------------------------------------------


def test_wholesale_admits_every_active_alert_line():
    admitted, counts = admit(wholesale(), rule_lines("ioc_wholesale.rules"), FETCHED_AT)

    assert sids(admitted) == {7100001, 7100002, 7100003, 7100004}
    assert counts.rules_admitted == counts.rules_fetched == 4
    assert (
        counts.rules_excluded_no_confidence
        + counts.rules_excluded_low_confidence
        + counts.rules_excluded_low_severity
    ) == 0


def test_wholesale_ignores_metadata_entirely():
    """A wholesale source's rules are admitted whatever they say about confidence.

    This is the asymmetry issue #11 records: the IOC feeds carry no ET taxonomy, so a global
    filter would exclude 100% of them.
    """
    admitted, counts = admit(wholesale(), rule_lines("et_open_metadata.rules"), FETCHED_AT)

    assert counts.rules_admitted == 13
    assert 2000005 in sids(admitted)  # confidence Low, admitted anyway


# --- fingerprint rules ---------------------------------------------------------------------


def test_fingerprint_rules_are_counted_only_when_admitted():
    """The fields are `ja4_rules_admitted`/`ja3_rules_admitted` — admitted, not present.

    A run reports these so that zero JA4 labels reads as "no JA4 content published upstream"
    rather than "the JA4 path is broken" (issue #13). Counting rules the filter dropped would
    break exactly that reading.
    """
    _, filtered = admit(et_open(), rule_lines("et_open_metadata.rules"), FETCHED_AT)
    assert (filtered.ja3_rules_admitted, filtered.ja4_rules_admitted) == (1, 1)

    # sid 2000014 is a ja3.hash rule with confidence Low; under wholesale it is admitted too.
    _, whole = admit(wholesale(), rule_lines("et_open_metadata.rules"), FETCHED_AT)
    assert (whole.ja3_rules_admitted, whole.ja4_rules_admitted) == (2, 1)


def test_a_disabled_fingerprint_rule_is_not_counted_as_admitted():
    _, counts = admit(
        wholesale(),
        ['#alert tls any any -> any any (msg:"off"; ja4.hash; content:"x"; sid:1; rev:1;)'],
        FETCHED_AT,
    )
    assert (counts.ja4_rules_admitted, counts.rules_excluded_commented) == (0, 1)


# --- the hard failure a name check cannot catch --------------------------------------------


def test_a_metadata_filtered_feed_with_no_confidence_keys_is_a_hard_failure():
    """PLAN.md step 4: ET dropping the key must stop the run, not quietly admit nothing.

    `config.load_sources` checks the source *name* against `ET_METADATA_SOURCES` at load
    time, which cannot see the fetched content. If upstream stopped emitting `confidence`,
    the filter would admit zero rules and the run would look like a feed that matched
    nothing — with ~21,000 rules silently absent from the snapshot.
    """
    with pytest.raises(ConfigError) as excinfo:
        admit(et_open(), rule_lines("et_open_no_confidence.rules"), FETCHED_AT)

    message = str(excinfo.value)
    assert "confidence" in message
    assert "et/open" in message


def test_an_empty_metadata_filtered_feed_is_the_same_hard_failure():
    """Zero rules is the degenerate case of zero `confidence` keys, and just as invisible."""
    with pytest.raises(ConfigError):
        admit(et_open(), [], FETCHED_AT)


def test_a_wholesale_feed_without_confidence_keys_is_perfectly_normal():
    """The check is scoped to the filter that depends on the key, not to every source."""
    admitted, counts = admit(wholesale(), rule_lines("et_open_no_confidence.rules"), FETCHED_AT)

    assert counts.rules_admitted == len(admitted) == 3


def test_an_empty_wholesale_feed_admits_nothing_without_raising():
    admitted, counts = admit(wholesale(), [], FETCHED_AT)
    assert (admitted, counts.rules_fetched) == ([], 0)


def test_metadata_filter_on_a_source_that_cannot_carry_metadata_is_rejected():
    """Defence in depth for a `SourceSpec` built without going through `config`.

    `config.load_sources` already rejects this combination; admit re-checks against the same
    constant rather than trusting its caller, because the failure mode — a filter that admits
    nothing — is silent.
    """
    spec = SourceSpec(
        name="pawpatrules",
        url="https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz",
        licence="CC-BY-SA-4.0",
        source_class="signature",
        admission_basis="metadata-filter",
    )
    with pytest.raises(ConfigError, match="metadata"):
        admit(spec, rule_lines("et_open_metadata.rules"), FETCHED_AT)


def test_the_et_metadata_source_list_is_not_re_encoded_here(monkeypatch: pytest.MonkeyPatch):
    """admit reads `config.ET_METADATA_SOURCES`; it does not keep its own copy.

    Proven by extending the constant: if admit held a private list, the newly-listed source
    would still be rejected.
    """
    monkeypatch.setattr(config, "ET_METADATA_SOURCES", frozenset({"et/open", "someone-else/open"}))
    spec = SourceSpec(
        name="someone-else/open",
        url="https://example.invalid/rules.tar.gz",
        licence="MIT",
        source_class="signature",
        admission_basis="metadata-filter",
    )

    _, counts = admit(spec, rule_lines("et_open_metadata.rules"), FETCHED_AT)
    assert counts.rules_admitted == 6


# --- provenance carried onto the admission -------------------------------------------------


def test_the_admission_carries_the_registry_facts_a_label_will_need():
    """`SourceAdmission` is what a label's provenance resolves through (spec §10)."""
    spec = et_open()
    _, counts = admit(spec, rule_lines("et_open_metadata.rules"), FETCHED_AT)

    assert isinstance(counts, SourceAdmission)
    assert (counts.name, counts.url, counts.licence) == (spec.name, spec.url, spec.licence)
    assert (counts.source_class, counts.admission_basis) == (
        spec.source_class,
        spec.admission_basis,
    )
    assert counts.fetched_at == FETCHED_AT


def test_fetched_at_defaults_to_now_in_the_one_output_timestamp_format():
    """Spec §10: ISO-8601 UTC, microsecond precision, `Z` suffix. One format everywhere."""
    _, counts = admit(wholesale(), rule_lines("ioc_wholesale.rules"))

    assert counts.fetched_at.endswith("Z")
    assert len(counts.fetched_at) == len("2026-08-12T00:00:00.000000Z")
    assert "+00:00" not in counts.fetched_at


# --- purity ---------------------------------------------------------------------------------


def test_admit_is_deterministic_and_does_not_mutate_its_input():
    lines = rule_lines("et_open_metadata.rules")
    before = list(lines)

    first = admit(et_open(), lines, FETCHED_AT)
    second = admit(et_open(), lines, FETCHED_AT)

    assert first == second
    assert lines == before


def test_admitted_rules_are_returned_verbatim_apart_from_line_endings():
    """The admitted text is what Suricata will load, so it must not be rewritten.

    Trailing whitespace and CR are stripped: a feed switching to CRLF would otherwise change
    every rule byte and therefore the snapshot id, for no change in content.
    """
    rule = 'alert tcp any any -> any any (msg:"crlf"; sid:5; rev:1;)'
    admitted, _ = admit(wholesale(), [f"  {rule}  \r"], FETCHED_AT)

    assert admitted == [rule]


def test_admit_accepts_any_iterable_of_lines():
    """Spec §6 types the argument as `Iterable[str]`; a generator must not be consumed twice."""
    lines = (line for line in rule_lines("ioc_wholesale.rules"))

    _, counts = admit(wholesale(), lines, FETCHED_AT)
    assert counts.rules_admitted == 4
