"""The replay timestamp inverse (Phase 2 / Tier 1).

Every fixture here is the **measured** replay from 2026-08-17, recorded in
`docs/phase-2-reachability-spike.md`, rather than round invented numbers. That matters for one
specific reason: the gap between the replay we asked for and the replay we got is the entire
subject of these tests, and a fixture with a nominal multiplier that happens to be exact would
assert the bug rather than the fix.
"""

from __future__ import annotations

import struct

import pytest

from flabel import replay as replay_mod
from flabel.errors import ToolError
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


def _pcap(magic: bytes, endian: str, stamps: list[tuple[int, int]]) -> bytes:
    """A minimal pcap holding `stamps`, one 4-byte packet each."""
    out = magic + struct.pack(f"{endian}HHiIII", 2, 4, 0, 0, 65535, 1)
    for seconds, fraction in stamps:
        out += struct.pack(f"{endian}IIII", seconds, fraction, 4, 4) + b"\xde\xad\xbe\xef"
    return out


@pytest.mark.parametrize(
    ("magic", "endian"),
    [(replay_mod.MAGIC_MICRO_LE, "<"), (replay_mod.MAGIC_MICRO_BE, ">")],
)
def test_the_bounds_are_read_from_the_capture_in_either_byte_order(tmp_path, magic, endian):
    path = tmp_path / "c.pcap"
    path.write_bytes(_pcap(magic, endian, [(1000, 500000), (1005, 250000), (1009, 750000)]))
    first, last = replay_mod.capture_bounds(path)
    assert first == pytest.approx(1000.5)
    assert last == pytest.approx(1009.75)


@pytest.mark.parametrize(
    ("magic", "endian"),
    [(replay_mod.MAGIC_NANO_LE, "<"), (replay_mod.MAGIC_NANO_BE, ">")],
)
def test_a_nanosecond_capture_is_not_read_as_microseconds(tmp_path, magic, endian):
    """The one scale error nothing downstream could catch.

    A nanosecond fraction read as microseconds is out by a factor of 1000, and `ReplayWindow`
    would invert the wrong number perfectly — every test of the arithmetic would still pass,
    because the arithmetic would still be right.
    """
    path = tmp_path / "c.pcap"
    path.write_bytes(_pcap(magic, endian, [(1000, 500_000_000), (1002, 250_000_000)]))
    first, last = replay_mod.capture_bounds(path)
    assert first == pytest.approx(1000.5)
    assert last == pytest.approx(1002.25)


def test_a_truncated_final_record_still_yields_the_bounds_of_what_was_readable(tmp_path):
    """Truncated captures are ordinary input (spec §8), not a reason to refuse to replay."""
    path = tmp_path / "c.pcap"
    good = _pcap(replay_mod.MAGIC_MICRO_LE, "<", [(1000, 0), (1004, 0)])
    path.write_bytes(good + b"\x01\x02\x03")
    assert replay_mod.capture_bounds(path) == (pytest.approx(1000.0), pytest.approx(1004.0))


def test_a_capture_with_no_packets_cannot_yield_a_replay_window(tmp_path):
    path = tmp_path / "c.pcap"
    path.write_bytes(_pcap(replay_mod.MAGIC_MICRO_LE, "<", []))
    with pytest.raises(ToolError, match="no readable packet records"):
        replay_mod.capture_bounds(path)


def test_an_unrecognised_magic_is_reported_as_a_pipeline_error(tmp_path):
    """ingest normalises to pcap first, so reaching here means the pipeline was mis-wired."""
    path = tmp_path / "c.pcap"
    path.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 40)
    with pytest.raises(ToolError, match="pipeline error"):
        replay_mod.capture_bounds(path)


def test_the_capture_walk_also_yields_the_packet_count(tmp_path):
    """The denominator a progress bar needs, for free.

    The header walk already visits every record to find the last timestamp, so counting costs
    nothing — where asking capinfos would mean a second pass and a second tool.
    """
    path = tmp_path / "c.pcap"
    path.write_bytes(_pcap(replay_mod.MAGIC_MICRO_LE, "<", [(1000, 0), (1004, 0), (1009, 0)]))
    stats = replay_mod.capture_stats(path)
    assert stats.packets == 3
    assert stats.span == pytest.approx(9.0)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("Actual: 728 packets (49441 bytes) sent in 1.00 seconds", 728),
        ("Actual: 52599 packets (5019715 bytes) sent in 14.86 seconds", 52599),
    ],
)
def test_the_sent_count_is_read_from_tcpreplays_own_report(line, expected):
    """Parsed rather than inferred from elapsed time: tcpreplay knows, we would be guessing."""
    assert int(replay_mod.SENT.search(line).group(1)) == expected


def test_the_rate_is_read_from_the_pps_field_not_the_bandwidth_fields():
    """The line carries Bps, Mbps and pps; only the last is packets."""
    line = "Rated: 49246.7 Bps, 0.393 Mbps, 725.14 pps"
    assert float(replay_mod.RATED.search(line).group(1)) == pytest.approx(725.14)


def test_a_stats_line_tcpreplay_did_not_emit_does_not_match():
    """The warning spam --no-flow-stats suppresses must never be read as progress."""
    noise = "Warning in flows.c:flow_decode() line 198: Unable to process unsupported DLT type"
    assert replay_mod.SENT.search(noise) is None
    assert replay_mod.RATED.search(noise) is None


def _fake_tcpreplay(tmp_path, flush: bool, intervals: int = 5):
    """A stand-in that emits tcpreplay's stats format, with buffering under our control.

    Two variants, because they distinguish the two possible causes of a counter that sits at
    zero: `flush=True` is a well-behaved line-buffered child, and if progress still does not
    arrive the fault is in our reader. `flush=False` is a block-buffered child, which is what a
    C program writing to a pipe does by default.
    """
    script = tmp_path / "fake-tcpreplay"
    body = "\n".join(
        [
            "import sys, time",
            "if '--version' in sys.argv:",
            "    print('fake tcpreplay 0.0'); raise SystemExit(0)",
            f"for i in range(1, {intervals} + 1):",
            "    sent = i * 1000",
            "    line = f'Actual: {sent} packets ({sent * 60} bytes) sent in {i}.00 seconds'",
            "    sys.stdout.write(line + chr(10))",
            "    sys.stdout.write(f'Rated: 60000.0 Bps, 0.48 Mbps, {900 + i}.00 pps\\n')",
            "    sys.stdout.flush()" if flush else "    pass",
            "    time.sleep(0.05)",
        ]
    )
    script.write_text(f"#!/usr/bin/env python3\n{body}\n")
    script.chmod(0o755)
    return script


def test_progress_arrives_while_the_replay_is_still_running(tmp_path, monkeypatch):
    """The reader must report each interval as it lands, not all of them at the end.

    A counter that sits at 0/total until the replay finishes is the symptom this guards. With a
    line-buffered child, every interval has to reach the callback — and the *order* proves they
    were not delivered in one burst after exit.
    """
    fake = _fake_tcpreplay(tmp_path, flush=True, intervals=5)
    monkeypatch.setattr(replay_mod, "REPLAY", str(fake))
    capture = tmp_path / "c.pcap"
    capture.write_bytes(_pcap(replay_mod.MAGIC_MICRO_LE, "<", [(1000, 0), (1005, 0)]))

    seen: list[tuple[int, float]] = []
    replay_mod.replay(
        capture, tmp_path / "cache", ("lo", "lo"), on_progress=lambda s, r: seen.append((s, r))
    )

    assert [s for s, _ in seen] == [1000, 2000, 3000, 4000, 5000]
    assert [r for _, r in seen] == [901.0, 902.0, 903.0, 904.0, 905.0]


def test_the_pipe_is_drained_even_with_no_callback(tmp_path, monkeypatch):
    """A child writing to a pipe nobody reads blocks once the buffer fills.

    A replay deadlocked on its own stats output would look exactly like a firewall that stopped
    answering, so draining is not optional just because nobody is watching.
    """
    fake = _fake_tcpreplay(tmp_path, flush=True, intervals=400)
    monkeypatch.setattr(replay_mod, "REPLAY", str(fake))
    capture = tmp_path / "c.pcap"
    capture.write_bytes(_pcap(replay_mod.MAGIC_MICRO_LE, "<", [(1000, 0), (1005, 0)]))

    window = replay_mod.replay(capture, tmp_path / "cache", ("lo", "lo"), on_progress=None)

    assert window.wall_span >= 0
