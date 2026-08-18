"""The progress display (spec §12: stderr carries progress, stdout is reserved).

Everything here drives a `StringIO`, which is the point of the stream being injected: the
display is exercised without a terminal, and without the tests depending on what a terminal
would do with the escape codes.
"""

from __future__ import annotations

import io

import pytest

from flabel import progress


def test_a_bar_is_clamped_so_a_bad_fraction_cannot_overflow_its_width():
    """A fraction over 1.0 is a caller bug; a bar wider than its field is a corrupted display."""
    assert len(progress.bar(1.5, width=10)) == 10
    assert len(progress.bar(-0.5, width=10)) == 10
    assert progress.bar(1.5, width=10) == progress.BAR_FILL * 10
    assert progress.bar(-0.5, width=10) == progress.BAR_EMPTY * 10


def test_a_bar_fills_in_proportion():
    assert progress.bar(0.5, width=10) == progress.BAR_FILL * 5 + progress.BAR_EMPTY * 5


def test_a_sparkline_scales_to_its_own_window_not_to_an_absolute_maximum():
    """The interesting thing about replay throughput is its shape.

    Against a fixed scale a capture running at a small fraction of line rate draws as a flat
    line at the bottom, which is exactly the case being watched.
    """
    line = progress.sparkline([10, 20, 30])
    assert line[0] == progress.BLOCKS[0]
    assert line[-1] == progress.BLOCKS[-1]


def test_a_flat_series_draws_at_mid_height_rather_than_empty():
    """Steady throughput is a real observation; drawing it at the floor would read as stalled."""
    line = progress.sparkline([500.0] * 6)
    assert set(line) == {progress.BLOCKS[len(progress.BLOCKS) // 2]}


def test_a_sparkline_shows_only_the_most_recent_window():
    assert len(progress.sparkline(list(range(500)), width=12)) == 12


def test_an_empty_series_draws_nothing_rather_than_raising():
    assert progress.sparkline([]) == ""


@pytest.mark.parametrize(
    ("pps", "expected"),
    [(950.0, "950 pps"), (3421.0, "3.4 Kpps"), (2_400_000.0, "2.40 Mpps")],
)
def test_rates_are_shown_in_a_unit_that_stays_short(pps, expected):
    assert progress.rate(pps) == expected


@pytest.mark.parametrize(
    ("seconds", "expected"), [(14.86, "14.9s"), (95.0, "1m35s"), (3722.0, "1h02m")]
)
def test_durations_use_the_largest_readable_unit(seconds, expected):
    assert progress.duration(seconds) == expected


def test_a_non_terminal_gets_the_plain_reporter():
    """A redirect, a nohup or CI must not receive escape codes."""
    assert isinstance(progress.reporter([("a", "a")], io.StringIO()), progress.PlainReporter)


def test_no_color_is_honoured_even_on_a_terminal(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setenv("NO_COLOR", "1")
    assert isinstance(progress.reporter([("a", "a")], Tty()), progress.PlainReporter)


def test_a_terminal_gets_the_live_reporter(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FLABEL_PLAIN_PROGRESS", raising=False)
    assert isinstance(progress.reporter([("a", "a")], Tty()), progress.LiveReporter)


def test_the_plain_reporter_emits_no_escape_codes_at_all():
    """The assertion that makes a redirected run's log readable."""
    stream = io.StringIO()
    plain = progress.PlainReporter([("replay", "replay")], stream)
    plain.header("capture.pcap")
    plain.start("replay")
    for fraction in (0.1, 0.3, 0.55, 0.8, 1.0):
        plain.update("replay", detail="x", fraction=fraction)
    plain.finish("replay", "done")
    plain.note("a warning")
    assert "\033" not in stream.getvalue()


def test_the_plain_reporter_reports_milestones_rather_than_every_frame():
    """A 90-second replay must leave a few lines in a log, not hundreds."""
    stream = io.StringIO()
    plain = progress.PlainReporter([("replay", "replay")], stream)
    plain.start("replay")
    for i in range(500):
        plain.update("replay", fraction=i / 499)
    percent_lines = [ln for ln in stream.getvalue().splitlines() if "%" in ln]
    assert len(percent_lines) == len(progress.PlainReporter.MILESTONES)


def test_the_live_reporter_draws_a_warning_above_the_block_so_it_survives_the_repaint():
    """A note scrolled away by the next frame is a warning the operator never saw."""
    stream = io.StringIO()
    live = progress.LiveReporter([("replay", "replay")], stream)
    live.start("replay")
    live.note("the firewall wrote more logs than were retrieved")
    live.update("replay", fraction=0.5)
    assert "the firewall wrote more logs than were retrieved" in stream.getvalue()


def test_an_unknown_step_key_is_ignored_rather_than_raising():
    """Progress is a view of the work and must never be able to fail the run."""
    stream = io.StringIO()
    for rep in (
        progress.PlainReporter([("a", "a")], stream),
        progress.LiveReporter([("a", "a")], stream),
    ):
        rep.start("nope")
        rep.update("nope", fraction=0.5)
        rep.finish("nope")
        rep.fail("nope")
        rep.skip("nope")
