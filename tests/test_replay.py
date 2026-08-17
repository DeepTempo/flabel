"""The replay timestamp inverse (Phase 2 / Tier 1).

Every fixture here is the **measured** replay from 2026-08-17, recorded in
`docs/phase-2-reachability-spike.md`, rather than round invented numbers. That matters for one
specific reason: the gap between the replay we asked for and the replay we got is the entire
subject of these tests, and a fixture with a nominal multiplier that happens to be exact would
assert the bug rather than the fix.
"""

from __future__ import annotations

import pytest

from flabel.replay import ReplayWindow

#: The 2026-08-17 replay of lax/capture_2026-07-08_pub-216.152.152.123.pcap.
#: 52,599 packets, 14,494.431940 s of capture, replayed at --multiplier 1000 in 14.859840 s.
PCAP_FIRST = 1783540704.306313
PCAP_SPAN = 14494.431940
REPLAY_START = 1786999773.823805
REPLAY_WALL_SPAN = 14.859840


def window(**overrides: object) -> ReplayWindow:
    kwargs: dict[str, object] = {
        "pcap_first_ts": PCAP_FIRST,
        "pcap_last_ts": PCAP_FIRST + PCAP_SPAN,
        "replay_start_wall": REPLAY_START,
        "replay_end_wall": REPLAY_START + REPLAY_WALL_SPAN,
        "multiplier": 1000.0,
    }
    kwargs.update(overrides)
    return ReplayWindow(**kwargs)  # type: ignore[arg-type]


def test_the_start_of_the_replay_maps_to_the_first_packet_of_the_capture():
    assert window().to_pcap_time(REPLAY_START) == pytest.approx(PCAP_FIRST)


def test_the_end_of_the_replay_maps_to_the_last_packet_of_the_capture():
    """The property that makes the *measured* scale the right one to invert with.

    A nominal-multiplier inverse cannot satisfy this and the measured one does, which is the
    whole argument in one assertion.
    """
    replay = window()
    assert replay.to_pcap_time(replay.replay_end_wall) == pytest.approx(replay.pcap_last_ts)


def test_the_scale_is_measured_and_is_not_the_multiplier_that_was_asked_for():
    replay = window()
    assert replay.effective_scale == pytest.approx(PCAP_SPAN / REPLAY_WALL_SPAN)
    assert replay.effective_scale != pytest.approx(replay.multiplier)


def test_inverting_with_the_nominal_multiplier_would_misplace_the_tail_by_minutes():
    """The measurement this design exists for.

    tcpreplay's own overhead made a 14.494 s nominal replay take 14.860 s. Inverted with the
    nominal 1000, the far end of the replay lands about six minutes away from where it belongs
    — wide enough to attribute a detection to the wrong one of two flows sharing a 5-tuple,
    which is the only thing the clock is consulted for (`correlate._place`).
    """
    replay = window()
    naive = replay.pcap_first_ts + replay.wall_span * replay.multiplier
    error = abs(naive - replay.pcap_last_ts)
    assert error > 300, "the nominal inverse should be wrong by minutes, not seconds"
    assert error < 400


def test_the_error_bar_is_large_enough_to_cover_that_mistake():
    """An error bar that did not cover the known error would be decoration."""
    replay = window()
    naive = replay.pcap_first_ts + REPLAY_WALL_SPAN * replay.multiplier
    assert replay.uncertainty_seconds >= abs(naive - replay.pcap_last_ts) * 0.9


def test_two_flows_further_apart_than_the_error_bar_can_be_told_apart():
    replay = window()
    apart = replay.uncertainty_seconds * 2
    assert replay.separates(PCAP_FIRST, PCAP_FIRST + apart)


def test_two_flows_closer_than_the_error_bar_cannot_be_told_apart():
    """Spec §13: report rather than guess.

    `separates()` returning False is what makes a caller emit `ambiguous_flow_match` instead of
    choosing, so this is the assertion standing between a replay's timing noise and a label on
    the wrong connection.
    """
    replay = window()
    assert not replay.separates(PCAP_FIRST, PCAP_FIRST + replay.uncertainty_seconds / 2)


def test_topspeed_admits_that_a_timestamp_carries_no_information():
    """--topspeed abandons relative timing, so the honest error bar is the whole capture.

    Which makes `separates()` false for every pair inside the capture — exactly the degradation
    promised when --topspeed was kept as an opt-in rather than made the default.
    """
    replay = window(topspeed=True)
    assert replay.uncertainty_seconds == pytest.approx(PCAP_SPAN)
    assert not replay.separates(PCAP_FIRST, PCAP_FIRST + PCAP_SPAN / 2)


def test_a_replay_with_no_measurable_duration_falls_back_without_pretending_to_know():
    """A zero wall span cannot yield a measured scale, and must not silently read as precise.

    The nominal multiplier is the best estimate left, but the uncertainty widens to the whole
    capture so that nothing downstream mistakes the fallback for a measurement.
    """
    replay = window(replay_end_wall=REPLAY_START)
    assert replay.effective_scale == replay.multiplier
    assert replay.uncertainty_seconds == pytest.approx(PCAP_SPAN)
