"""Tier attestation — spec-label-store §2.4, and why `tiers_unavailable` could not carry it.

Revision 1 said "only a *delivered* tier supersedes", with delivered meaning
`tier ∈ tiers_attempted and tier ∉ tiers_unavailable`. **That invariant could never fire.** A failed
run is never ingested (§2.5), and `docs/spec.md` §10 says `tiers_unavailable` is empty on every
successful run — so every row in `runs` would have had `delivered == attempted`, and the concept was
inert in production and testable only against a hand-forged row.

Worse, the hazard it was written for walks straight past it. #142 — `fl-replay`'s Suricata 7.0.3
refusing an 8.0 ruleset and loading only part of it — exits 0, writes `labels.json`, publishes, and
reports `tiers_unavailable: []`. Under revision 1 it *delivered* tier 2 and superseded good
knowledge with a result that was two rules short and looked complete.

So delivery is attested from **positive evidence**, and these tests are the fixture-driven proof.
`OFFLINE_RUN` is copied from a real `fl-replay --offline` run (2026-08-21), which the plan asks for
by name.
"""

from __future__ import annotations

import copy

import pytest

from flabeldb import attest

#: A real `--offline` run block, trimmed to the keys attestation reads. Verbatim values.
#:
#: **It does NOT attest**, and that is not a contrived fixture — it is what the box produces.
#: Suricata 7.0.3 skipped 2 of 84,960 admitted rules (0 failed), so `rules_loaded` is 84,958. Those
#: two never examined the capture, which is exactly the condition §2.4 refuses on, and flabel's own
#: runtime warning says the same thing in the same words.
OFFLINE_RUN = {
    "mode": "offline",
    "tiers_attempted": [2],
    "counts": {"rules_loaded": 84958, "rules_failed": 0, "rules_skipped": 2},
    "ruleset": {"snapshot_id": "b8b1e00ed2285240", "total_admitted": 84960},
    "tool_failures": [],
}

#: The same run with the two skipped rules loaded — the state a pinned Suricata 8.0.6 should reach.
CLEAN_OFFLINE_RUN = copy.deepcopy(OFFLINE_RUN)
CLEAN_OFFLINE_RUN["counts"]["rules_loaded"] = 84960
CLEAN_OFFLINE_RUN["counts"]["rules_skipped"] = 0

#: A real tier-1 run: `replay` mode, no ruleset at all.
REPLAY_RUN = {
    "mode": "replay",
    "tiers_attempted": [1],
    "counts": {"rules_loaded": None, "rules_failed": None, "rules_skipped": None},
    "ruleset": {"snapshot_id": None, "total_admitted": None},
    "tool_failures": [],
}


def run(base: dict, **changes) -> dict:
    found = copy.deepcopy(base)
    found.update(copy.deepcopy(changes))
    return found


# --- tier 2 ----------------------------------------------------------------------------------


def test_the_real_offline_run_from_the_box_does_not_attest_tier_2():
    """The plan asks for this fixture by name, and the answer it gives is the interesting one.

    84,958 of 84,960 rules loaded. Two never examined the capture, so any label they would have
    produced is absent from a run that otherwise looks complete — flabel says exactly that at
    runtime. §2.4 refuses, and the note has to say why in terms an operator can act on.
    """
    attested, notes = attest.tiers(OFFLINE_RUN)

    assert 2 not in attested
    assert any("84958" in note and "84960" in note for note in notes), notes


def test_a_run_that_loaded_every_admitted_rule_attests_tier_2():
    """The complement, so attestation cannot be satisfied by refusing everything."""
    attested, notes = attest.tiers(CLEAN_OFFLINE_RUN)

    assert 2 in attested
    assert notes == ()


def test_142_the_hazard_attestation_EXISTS_for():
    """Suricata loads NONE of the snapshot, exits 0, publishes, `tiers_unavailable: []`.

    Not #142's shape — that one loaded 84,958 of 84,960 and was caught by the equality
    clause. This is the `0 == 0` case the non-zero clause exists for, and it is the only
    case that clause uniquely catches.

    Under revision 1's rule this delivered tier 2 and superseded good knowledge with an empty
    result. It is the whole reason the mechanism was rewritten, so it gets its own test.
    """
    attested, notes = attest.tiers(run(OFFLINE_RUN, counts={"rules_loaded": 0}))

    assert 2 not in attested
    assert notes


@pytest.mark.parametrize(
    "counts, ruleset, why",
    [
        ({"rules_loaded": None}, {"total_admitted": 84960}, "rules_loaded is null"),
        ({"rules_loaded": 84960}, {"total_admitted": None}, "total_admitted is null"),
        ({"rules_loaded": 0}, {"total_admitted": 0}, "both zero — equal, and still nothing ran"),
    ],
)
def test_null_and_zero_are_refused_even_when_they_agree(counts, ruleset, why):
    """§2.4: "both are non-null and non-zero". `0 == 0` is the trap — a snapshot that admitted
    nothing and a Suricata that loaded nothing agree perfectly and prove nothing at all."""
    attested, notes = attest.tiers(run(OFFLINE_RUN, counts=counts, ruleset=ruleset))

    assert 2 not in attested, why
    assert notes


def test_a_null_count_is_reported_as_NOT_MEASURED_and_not_as_zero():
    """**Found by sabotage.** Deleting the null branch entirely left all 16 tests green, because
    `None` is falsy and the non-zero check catches it anyway — so the two states were refused with
    one message and nothing noticed.

    They are not one state. `docs/spec.md` §10 is emphatic throughout this project that `null` is
    "not measured" and `0` is "measured as none", and an operator reading `attestation_notes` acts
    differently on each: a null means the run block is malformed or the stage never ran, a zero
    means Suricata ran and loaded nothing.

    Not #142: that run loaded 84,958 of 84,960 and was refused by the equality clause. The zero
    case is its own hazard — `0 == 0` satisfies equality and proves nothing.
    """
    _, null_notes = attest.tiers(run(OFFLINE_RUN, counts={"rules_loaded": None}))
    _, zero_notes = attest.tiers(run(OFFLINE_RUN, counts={"rules_loaded": 0}))

    # The discriminating assertion, and the THIRD attempt at it. The first checked only that the
    # notes DIFFERED and that "None" appeared somewhere — both of which stay true when the null
    # branch is deleted, because the zero branch interpolates the value and renders it as `None`.
    # The second discriminated on the string "142", which tied the test to an issue NUMBER in the
    # message rather than to its meaning — and when that citation turned out to be a false
    # attribution and was removed, this test failed for a reason that had nothing to do with the
    # behaviour it guards.
    #
    # What actually separates them is what each one CLAIMS: the zero message states that nothing
    # examined the capture, which is a measurement. On a null there is no measurement to state.
    assert any("examined the capture" in note for note in zero_notes), zero_notes
    assert not any("142" in note for note in null_notes), (
        f"a null was reported as #142's zero-rules-loaded case, which asserts a measurement that "
        f"was never made: {null_notes}"
    )
    assert not any("zero rules" in note.lower() for note in null_notes), null_notes
    assert any("not measured" in note.lower() for note in null_notes), null_notes


def test_a_replay_run_is_not_refused_tier_2_it_simply_never_attempted_it():
    """ "We have no record" and "we have a record we will not treat as current" are different
    states (§2.4), and §9's non-behaviours keep both readable. A tier that was never attempted
    earns no note — a note would read as a complaint about something nobody asked for."""
    attested, notes = attest.tiers(REPLAY_RUN)

    assert 2 not in attested
    assert not any("tier 2" in note.lower() for note in notes), notes


# --- tier 1 ----------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["replay", "both"])
def test_tier_1_attests_in_the_modes_that_replay(mode):
    attempted = [1] if mode == "replay" else [1, 2]
    attested, _ = attest.tiers(run(REPLAY_RUN, mode=mode, tiers_attempted=attempted))
    assert 1 in attested


def test_tier_1_does_not_attest_in_offline_mode():
    """No device, no replay, no tier-1 detections to retrieve."""
    attested, _ = attest.tiers(OFFLINE_RUN)
    assert 1 not in attested


def test_mode_overrules_a_run_block_that_claims_it_attempted_tier_1_offline():
    """**Found by sabotage.** Adding `offline` to `REPLAY_MODES` left all 16 green, because every
    fixture's `tiers_attempted` already agrees with its `mode` — so the mode check was never
    reached with anything to decide, and a guard nothing exercises is a guard nobody knows works.

    The two fields can disagree: `tiers_attempted` is copied from the document and a hand-edited,
    truncated or backfilled-from-an-old-schema run block can claim a tier the mode makes
    physically impossible. `mode` is the authority on what the run could have done — there was no
    replay, so there is no threat log, whatever the array says.
    """
    lying = run(OFFLINE_RUN, tiers_attempted=[1, 2])
    attested, _ = attest.tiers(lying)

    assert 1 not in attested, "tier 1 attested on a run that never replayed anything"


def test_a_panw_tool_failure_refuses_tier_1():
    """§2.4: attested only when tier-1 detections were retrieved WITHOUT a `panw` tool failure.
    A failed threat-log query returns no detections, which is indistinguishable from a clean
    capture unless the failure is read."""
    failed = run(
        REPLAY_RUN,
        tool_failures=[{"tool": "panw", "argv": [], "exit_code": 1, "message": "query failed"}],
    )
    attested, notes = attest.tiers(failed)

    assert 1 not in attested
    assert any("panw" in note for note in notes), notes


def test_a_tool_failure_in_something_else_does_not_refuse_tier_1():
    """Narrow on purpose. A Zeek failure is a different loss and must not be laundered into a
    tier-1 refusal, which would misattribute it."""
    other = run(
        REPLAY_RUN,
        tool_failures=[{"tool": "zeek", "argv": [], "exit_code": 1, "message": "boom"}],
    )
    attested, _ = attest.tiers(other)
    assert 1 in attested


# --- both, and the shape of the answer --------------------------------------------------------


def test_both_mode_can_attest_one_tier_and_refuse_the_other():
    """The case the whole design is for: a `--both` run whose replay worked and whose Suricata
    loaded a short ruleset supplies tier 1 and must not supersede tier 2."""
    mixed = run(
        OFFLINE_RUN,
        mode="both",
        tiers_attempted=[1, 2],
        counts={"rules_loaded": 84958},
    )
    attested, notes = attest.tiers(mixed)

    assert attested == (1,)
    assert notes


def test_attested_tiers_are_sorted_and_a_tuple_so_two_runs_serialise_alike():
    attested, _ = attest.tiers(run(CLEAN_OFFLINE_RUN, mode="both", tiers_attempted=[2, 1]))
    assert attested == (1, 2)


def test_notes_are_a_tuple_of_sentences_not_a_blob():
    """They are written to `runs.attestation_notes`, a REPEATED STRING (§4.1). One reason per
    element or the column may as well be a single string."""
    _, notes = attest.tiers(OFFLINE_RUN)
    assert isinstance(notes, tuple)
    assert all(isinstance(note, str) and note for note in notes)


def test_attestation_never_invents_a_tier_that_was_not_attempted():
    """The one invariant that makes the column safe to read: attested ⊆ attempted, always."""
    for base in (OFFLINE_RUN, CLEAN_OFFLINE_RUN, REPLAY_RUN):
        attested, _ = attest.tiers(base)
        assert set(attested) <= set(base["tiers_attempted"]), base["mode"]
