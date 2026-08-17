"""The convention watch's own failure paths (issue #117).

`marker_gate` exists because #117 keys an admission policy on an emoji in third-party rule text.
The gate is what makes that defensible, so a gate that cannot fail would leave the policy resting
on nothing at all — and this repo has shipped four gates whose failure paths were unreachable
(#74, #98, #101, and the first draft of `corpus_gate` itself). Every test here drives `verify` to
a **non-zero** exit.

`main` is not tested here, deliberately, and `test_corpus_gate.py` makes the same choice: `main` is
argv parsing and the verdict is `verify`. The integration-marker guard also reads any `.main(...)`
call as driving the real pipeline, so a test of it would have to claim a toolchain it never uses.

Snapshots are written by the real `write_snapshot`, never hand-assembled, for the reason
`test_suricata.py` gives at its own copy of that helper: a hand-built layout agrees with the
reader by construction and could not catch a disagreement with the real writer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from marker_gate import (  # noqa: E402
    CEILING_SHARE,
    EXPECTED_EXCLUDED,
    FLOOR_FACTOR,
    KNOWN_ADMITTED_MARKERS,
    markers_of_admitted,
    verify,
)

from flabel.models import AdmissionPolicy, SourceSpec  # noqa: E402
from flabel.rules.admit import admit  # noqa: E402
from flabel.rules.snapshot import write_snapshot  # noqa: E402

PAW = "\N{PAW PRINTS}"
SIREN = "\N{POLICE CARS REVOLVING LIGHT}"
EYE = "\N{EYE}"
UNICORN = "\N{UNICORN FACE}"

SPEC = SourceSpec(
    name="pawpatrules",
    url="https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz",
    licence="CC-BY-SA-4.0",
    source_class="signature",
    admission_basis="wholesale",
)
FETCHED_AT = "2026-08-17T00:00:00.000000Z"
POLICY = AdmissionPolicy(exclude_msg_markers=frozenset({EYE}), msg_brand_marker=PAW)


def paw_rule(sid: int, marker: str, text: str) -> str:
    return (
        f'alert tcp any any -> any any (msg:"{PAW} - {marker} {text}"; content:"GET"; '
        f"classtype:bad-unknown; sid:{sid}; rev:1;)"
    )


def build(root: Path, rules: list[str], policy: AdmissionPolicy = POLICY) -> Path:
    """A real snapshot of `rules` as pawpatrules, admitted under `policy`."""
    admitted, admission = admit(SPEC, rules, FETCHED_AT, policy)
    write_snapshot(root, {SPEC.name: admitted}, [admission])
    return root


@pytest.fixture
def healthy(tmp_path: Path) -> Path:
    return build(
        tmp_path / "rules",
        [
            paw_rule(1, EYE, "DNS request to .dev extension"),
            paw_rule(2, SIREN, "Connection to a C2"),
        ],
    )


def test_a_feed_still_writing_its_convention_passes(healthy: Path, capsys):
    assert verify(healthy, expected_excluded=1, ceiling_share=1.0) == 0
    assert "excluded by marker" in capsys.readouterr().out


def test_a_convention_the_feed_stopped_writing_fails(tmp_path: Path, capsys):
    """The failure the whole gate exists for, and the quietest one available.

    If pawpatrules stops marking its observational rules, the policy in `sources.toml` keeps
    reading as though it excludes them and excludes nothing — issue #75's defect reappearing
    through the mechanism built to prevent #75. Every other gate stays green: the corpus is
    protocol traffic that never resolves `.dev`, and the benign canary carries no DNS at all.
    """
    snapshot = build(
        tmp_path / "rules",
        [
            paw_rule(1, SIREN, "DNS request to .dev extension"),
            paw_rule(2, SIREN, "Connection to a C2"),
        ],
    )

    assert verify(snapshot) == 1
    assert "excluded NOTHING" in capsys.readouterr().out


def test_a_marker_nobody_has_classified_fails(tmp_path: Path, capsys):
    """A NEW marker is the event worth waking someone for.

    It means the feed grew a category. Nobody has decided whether it detects or observes, and
    until someone does, its rules are asserting `verdict: malicious` on an unreviewed basis.
    """
    snapshot = build(
        tmp_path / "rules",
        [
            paw_rule(1, EYE, "DNS request to .dev extension"),
            paw_rule(2, SIREN, "Connection to a C2"),
            paw_rule(3, UNICORN, "Something the feed has never done before"),
        ],
    )

    assert verify(snapshot, expected_excluded=1, ceiling_share=1.0) == 1
    out = capsys.readouterr().out
    assert "unreviewed marker" in out
    assert UNICORN in out


def test_a_policy_that_still_bites_a_little_fails(tmp_path: Path, capsys):
    """Non-zero is not the same as working, and the first draft only checked non-zero.

    The realistic shape: upstream consolidates its observational markers under one this policy
    does not name — the recon bell, say, which #118 argues should stay admitted. A handful of
    stragglers keep the count off zero, the unreviewed-marker check finds nothing new because
    the bell is a known marker, and the gate passes while #117 is substantially restored.
    """
    rules = [paw_rule(1, EYE, "the one straggler")]
    rules += [paw_rule(sid, SIREN, f"detection {sid}") for sid in range(2, 40)]
    snapshot = build(tmp_path / "rules", rules)

    assert verify(snapshot, expected_excluded=100, ceiling_share=1.0) == 1
    assert "under the floor" in capsys.readouterr().out


def test_a_rule_that_dropped_the_brand_is_still_censused(tmp_path: Path, capsys):
    """Why the census reads the sid index rather than looking for the feed's logo.

    A feed that stops writing its brand is exactly the convention change this gate exists to
    catch. Identifying its rules by that brand makes the check circular: the rules drop out of
    their own census, so the marker nobody has classified is never reported, and they are
    admitted meanwhile. Sabotaging `_rules_of_source` back to a substring test makes this pass.
    """
    unbranded = (
        f'alert tcp any any -> any any (msg:"{UNICORN} A shape the feed has never used"; '
        f'content:"GET"; classtype:bad-unknown; sid:42; rev:1;)'
    )
    snapshot = build(
        tmp_path / "rules",
        [paw_rule(1, EYE, "DNS request to .dev"), paw_rule(2, SIREN, "C2"), unbranded],
    )

    assert verify(snapshot, expected_excluded=1, ceiling_share=1.0) == 1
    assert "unreviewed marker" in capsys.readouterr().out


def test_a_convention_change_that_swallows_the_feed_fails(tmp_path: Path, capsys):
    """The other direction, and the one an exact-count assertion would have caught by accident.

    A feed that re-marked most of its rules observational would have them all excluded — the
    policy would be working exactly as written and gutting the ruleset. `rules_excluded_marker`
    going up is as much a convention change as it going to zero.
    """
    rules = [paw_rule(sid, EYE, f"observation {sid}") for sid in range(1, 30)]
    rules.append(paw_rule(99, SIREN, "Connection to a C2"))
    snapshot = build(tmp_path / "rules", rules)

    assert verify(snapshot, expected_excluded=1) == 1
    assert "over the ceiling" in capsys.readouterr().out


def test_a_snapshot_without_the_feed_fails_rather_than_passing_vacuously(tmp_path: Path, capsys):
    """No pawpatrules means nothing was reviewed, which must not read as nothing was wrong.

    The `identify`-class shape of the same mistake: a gate that returns 0 because its subject is
    absent is the "0 == 0" assertion this repo has now found in three separate tests (#87).
    """
    spec = SourceSpec(
        name="et/open",
        url="https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
        licence="MIT",
        source_class="signature",
        admission_basis="wholesale",
    )
    rules = ['alert tcp any any -> any any (msg:"ET TEST"; content:"GET"; sid:2000001; rev:1;)']
    admitted, admission = admit(spec, rules, FETCHED_AT, AdmissionPolicy())
    root = tmp_path / "rules"
    write_snapshot(root, {spec.name: admitted}, [admission])

    assert verify(root) == 1
    assert "not in the snapshot" in capsys.readouterr().out


def test_the_shipped_band_brackets_what_was_measured():
    """The constants the workflow actually runs with, checked against the feed's real size.

    Every other test here injects its bounds so a small fixture can reach both branches, which
    leaves the SHIPPED numbers untested — the gap a reviewer found in the first draft. 21,467 is
    the pawpatrules rule count on the 2026-08-12 mirror and 445 is what the shipped policy
    excluded from it.
    """
    fetched, measured = 21467, EXPECTED_EXCLUDED

    floor = EXPECTED_EXCLUDED // FLOOR_FACTOR
    ceiling = int(fetched * CEILING_SHARE)

    assert floor < measured < ceiling, (
        f"the shipped band [{floor}, {ceiling}] does not bracket the {measured} rules the policy "
        f"was measured to exclude — the gate would fail on a healthy feed"
    )
    assert ceiling < fetched * 0.1, (
        f"a ceiling of {ceiling} tolerates deleting {ceiling / fetched:.0%} of the feed's rules; "
        f"this policy is meant to cost about 2%"
    )


def test_the_reviewed_marker_set_is_not_empty():
    """Guards the guard: an empty set would make every marker unreviewed and the gate useless."""
    assert len(KNOWN_ADMITTED_MARKERS) >= 9


def test_the_census_reads_the_marker_not_the_text():
    """The 7,554-rule hazard, asserted where the gate would meet it.

    A rule whose *text* contains a marker must not be counted under it, or a feed writing
    "Chrome <globe> outdated" would look like it had grown a globe category.
    """
    rules = [paw_rule(1, SIREN, "Google Chrome \N{GLOBE WITH MERIDIANS} outdated")]

    assert markers_of_admitted(rules, PAW) == {SIREN: 1}
