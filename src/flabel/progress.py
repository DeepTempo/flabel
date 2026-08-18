"""What the operator watches while a run happens (spec §12: stderr carries progress).

A tier-1 run is minutes of silence — a replay, a 60-second settle, a Suricata rule load — and
silence is indistinguishable from a wedge. This module is the difference between the two.

**Three rules it does not break.**

*stdout is reserved* (spec §12), so everything here goes to stderr, and to a stream the caller
injects rather than to `sys.stderr` directly. That is what makes it testable with a `StringIO`
and what keeps it inside the purity guard: it imports nothing a pure module may not.

*Animation is for terminals only.* `LiveReporter` repaints with ANSI; `PlainReporter` writes one
line per step and no escape codes at all. The choice is made from `stream.isatty()`, so a
redirect, a `nohup`, or CI gets a clean log. This repo has already published output into the
wrong stream once — `input()` writing to stdout put a prompt into a redirected log and left the
operator staring at a silent wedged process — and the lesson generalises: output that looks fine
on a terminal is not thereby fine.

*Zero runtime dependencies.* `pyproject.toml` says `dependencies = []` and that is deliberate, so
there is no `rich` and no `tqdm` here. Every bar, sparkline and cursor move below is hand-rolled,
which is the whole reason this file is longer than importing one would have been.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import IO, Protocol

#: Eight levels of block, low to high. The sparkline's whole vocabulary.
BLOCKS = "▁▂▃▄▅▆▇█"

#: Bar glyphs. Filled and unfilled differ in weight rather than character width, so the bar does
#: not jitter as it fills.
BAR_FILL = "█"
BAR_EMPTY = "░"

#: A step that has not started yet, drawn so the operator can see what is still to come.
PENDING_GLYPH = "·"

DONE = "✔"
FAILED = "✘"
RUNNING = "▸"
SKIPPED = "–"

#: How many throughput samples the sparkline remembers. Wide enough to show a trend, narrow
#: enough to fit beside the bar on an 80-column terminal.
SPARK_WIDTH = 24

#: Repaint interval. Fast enough to look live, slow enough that a 90-second replay does not
#: spend measurable time drawing.
FRAME_SECONDS = 0.2


def bar(fraction: float, width: int = 20) -> str:
    """A progress bar, clamped so a bad fraction cannot draw outside its width."""
    fraction = min(1.0, max(0.0, fraction))
    filled = int(round(fraction * width))
    return BAR_FILL * filled + BAR_EMPTY * (width - filled)


def sparkline(values: list[float], width: int = SPARK_WIDTH) -> str:
    """Recent values as a block graph, scaled to their own range.

    Scaled to the window rather than to an absolute maximum, because the interesting thing about
    replay throughput is its *shape* — whether it is steady, ramping or stalling — and a fixed
    scale flattens that into a straight line at whatever fraction of line rate the capture
    happens to be.

    A flat series draws as a mid-height line rather than as empty or full: zero variation is a
    real observation, and drawing it at the bottom would read as zero throughput.
    """
    if not values:
        return ""
    window = values[-width:]
    low, high = min(window), max(window)
    if high - low < 1e-9:
        return BLOCKS[len(BLOCKS) // 2] * len(window)
    span = high - low
    return "".join(
        BLOCKS[min(len(BLOCKS) - 1, int((v - low) / span * len(BLOCKS)))] for v in window
    )


def count(value: float) -> str:
    """A packet count, thousands-separated below 100k and abbreviated above it."""
    if value < 100_000:
        return f"{int(value):,}"
    if value < 1_000_000:
        return f"{value / 1_000:.1f}k"
    return f"{value / 1_000_000:.2f}M"


def rate(pps: float) -> str:
    """Packets per second, in whatever unit keeps it to three or four characters."""
    if pps < 1_000:
        return f"{pps:.0f} pps"
    if pps < 1_000_000:
        return f"{pps / 1_000:.1f} Kpps"
    return f"{pps / 1_000_000:.2f} Mpps"


def duration(seconds: float) -> str:
    """An elapsed or remaining time, in the largest unit that stays readable."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def span(seconds: float) -> str:
    """A capture's own duration, for the header line."""
    return duration(seconds)


@dataclass
class Step:
    """One stage of a run, and what it has to say for itself."""

    key: str
    label: str
    state: str = "pending"
    detail: str = ""
    started: float | None = None
    ended: float | None = None
    #: Set while a step reports fractional progress; None for steps that simply take time.
    fraction: float | None = None
    #: Throughput samples, for the sparkline. Only the replay step fills this.
    samples: list[float] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        if self.started is None:
            return 0.0
        return (self.ended if self.ended is not None else time.monotonic()) - self.started


class Reporter(Protocol):
    """What the pipeline calls. Two implementations; the pipeline cannot tell them apart."""

    def header(self, text: str) -> None: ...
    def start(self, key: str, detail: str = "") -> None: ...
    def update(
        self, key: str, detail: str = "", fraction: float | None = None, sample: float | None = None
    ) -> None: ...
    def finish(self, key: str, detail: str = "") -> None: ...
    def skip(self, key: str, detail: str = "") -> None: ...
    def fail(self, key: str, detail: str = "") -> None: ...
    def note(self, text: str) -> None: ...
    def close(self) -> None: ...


class _Base:
    def __init__(self, steps: list[tuple[str, str]], stream: IO[str]) -> None:
        self.stream = stream
        self.steps = [Step(key=key, label=label) for key, label in steps]
        self._by_key = {s.key: s for s in self.steps}
        self._title = ""

    def _step(self, key: str) -> Step | None:
        return self._by_key.get(key)


class PlainReporter(_Base):
    """One line per state change, no escape codes, safe to redirect into a log.

    Deliberately not a degraded animation: a log wants a record of what happened and when, and a
    progress bar rendered into a file is neither. Fractions are reported at coarse intervals so a
    long replay leaves a few lines rather than hundreds.
    """

    #: Report a fractional step at each of these, so a redirected run still shows movement.
    MILESTONES = (0.25, 0.5, 0.75)

    def __init__(self, steps: list[tuple[str, str]], stream: IO[str]) -> None:
        super().__init__(steps, stream)
        self._reported: dict[str, set[float]] = {}

    def _write(self, text: str) -> None:
        self.stream.write(text + "\n")
        self.stream.flush()

    def header(self, text: str) -> None:
        self._title = text
        self._write(f"flabel: {text}")

    def start(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.started = "running", time.monotonic()
        self._write(f"flabel: {step.label}: started{f' — {detail}' if detail else ''}")

    def update(
        self, key: str, detail: str = "", fraction: float | None = None, sample: float | None = None
    ) -> None:
        step = self._step(key)
        if step is None or fraction is None:
            return
        step.fraction = fraction
        seen = self._reported.setdefault(key, set())
        for milestone in self.MILESTONES:
            if fraction >= milestone and milestone not in seen:
                seen.add(milestone)
                self._write(
                    f"flabel: {step.label}: {int(milestone * 100)}%"
                    f"{f' — {detail}' if detail else ''}"
                )

    def finish(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.ended = "done", time.monotonic()
        step.detail = detail
        self._write(
            f"flabel: {step.label}: done in {duration(step.elapsed)}"
            f"{f' — {detail}' if detail else ''}"
        )

    def skip(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state = "skipped"
        self._write(f"flabel: {step.label}: skipped{f' — {detail}' if detail else ''}")

    def fail(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.ended = "failed", time.monotonic()
        self._write(f"flabel: {step.label}: FAILED{f' — {detail}' if detail else ''}")

    def note(self, text: str) -> None:
        self._write(f"flabel: {text}")

    def close(self) -> None:
        pass


class LiveReporter(_Base):
    """The repainting display, for a terminal.

    Repaints the whole block each frame by moving the cursor up over what it drew last time.
    That is simpler than tracking which lines changed, and at a fifth of a second it is
    imperceptible either way.

    `note()` is the one thing that must survive the repaint: a warning is part of the run's
    record, so it is printed *above* the block and the block is redrawn beneath it. A warning
    scrolled away by the next frame would be a warning the operator never saw.
    """

    def __init__(self, steps: list[tuple[str, str]], stream: IO[str]) -> None:
        super().__init__(steps, stream)
        self._drawn = 0
        self._last_frame = 0.0

    def _clear(self) -> None:
        if self._drawn:
            self.stream.write(f"\033[{self._drawn}A\033[J")
            self._drawn = 0

    def _render(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_frame < FRAME_SECONDS:
            return
        self._last_frame = now
        self._clear()
        lines: list[str] = []
        if self._title:
            lines.append(f"\033[1mflabel\033[0m │ {self._title}")
            lines.append("")
        for step in self.steps:
            lines.extend(self._lines_for(step))
        for line in lines:
            self.stream.write(line + "\n")
        self._drawn = len(lines)
        self.stream.flush()

    def _lines_for(self, step: Step) -> list[str]:
        if step.state == "pending":
            return [f"  \033[2m{PENDING_GLYPH} {step.label:<11}\033[0m"]
        if step.state == "done":
            tail = f"  \033[2m{duration(step.elapsed)}\033[0m"
            return [f"  \033[32m{DONE}\033[0m {step.label:<11} {step.detail}{tail}"]
        if step.state == "failed":
            return [f"  \033[31m{FAILED}\033[0m {step.label:<11} {step.detail}"]
        if step.state == "skipped":
            return [f"  \033[2m{SKIPPED} {step.label:<11} {step.detail}\033[0m"]

        # Running.
        out = []
        if step.fraction is not None:
            pct = f"{step.fraction * 100:4.0f}%"
            out.append(
                f"  \033[36m{RUNNING}\033[0m {step.label:<11} "
                f"{bar(step.fraction)} {pct}  {step.detail}"
            )
        else:
            out.append(
                f"  \033[36m{RUNNING}\033[0m {step.label:<11} {step.detail}"
                f"  \033[2m{duration(step.elapsed)}\033[0m"
            )
        if step.samples:
            out.append(
                f"                 \033[2m{rate(step.samples[-1])}\033[0m  "
                f"\033[36m{sparkline(step.samples)}\033[0m"
            )
        return out

    def header(self, text: str) -> None:
        self._title = text
        self._render(force=True)

    def start(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.started, step.detail = "running", time.monotonic(), detail
        self._render(force=True)

    def update(
        self, key: str, detail: str = "", fraction: float | None = None, sample: float | None = None
    ) -> None:
        step = self._step(key)
        if step is None:
            return
        if detail:
            step.detail = detail
        if fraction is not None:
            step.fraction = fraction
        if sample is not None:
            step.samples.append(sample)
        self._render()

    def finish(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.ended, step.fraction = "done", time.monotonic(), None
        step.detail = detail or step.detail
        self._render(force=True)

    def skip(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.detail = "skipped", detail
        self._render(force=True)

    def fail(self, key: str, detail: str = "") -> None:
        step = self._step(key)
        if step is None:
            return
        step.state, step.ended, step.detail = "failed", time.monotonic(), detail
        self._render(force=True)

    def note(self, text: str) -> None:
        self._clear()
        self.stream.write(f"  \033[33m!\033[0m {text}\n")
        self._render(force=True)

    def close(self) -> None:
        self._render(force=True)


def supports_ansi(stream: IO[str]) -> bool:
    """Whether this stream is a terminal that should be animated.

    `NO_COLOR` is honoured because it is the convention, and a run whose output is being read by
    a person who asked for no escape codes is exactly the case `PlainReporter` exists for.
    """
    import os  # noqa: PLC0415 - local, so the module's import list stays about drawing

    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FLABEL_PLAIN_PROGRESS"):
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def reporter(steps: list[tuple[str, str]], stream: IO[str] | None = None) -> Reporter:
    """The right reporter for where this run's output is going."""
    target = sys.stderr if stream is None else stream
    if supports_ansi(target):
        return LiveReporter(steps, target)
    return PlainReporter(steps, target)
