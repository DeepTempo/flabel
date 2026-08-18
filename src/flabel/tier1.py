"""The tier-1 stage: replay the capture past the device, then ask it what it saw (Phase 2).

`replay.py` owns the wire and `panw.py` owns the device; this is the sequence that puts them in
the right order and returns something `correlate()` can use. It exists as its own module so that
`cli.py` gains one call rather than forty lines, and so the ordering — which is load-bearing —
has somewhere to be explained.

**The order is today.md's workflow and every step earns its place.**

1. Read the device's clock and refuse a skew the padded window cannot absorb. First, because
   every later step is wasted if the query window will miss the replay — and it would miss it
   *silently*, returning zero rows that read exactly like a clean capture.
2. Refuse a device with no threat content. The base VM-Series image ships Applications-only,
   where no signature can fire; a run against it would look clean and be blind.
3. Read the log counters, then clear sessions, so the run starts from a known state.
4. Replay, recording the wall-clock window.
5. Wait. Content-ID finishes a session after its last packet, and a threat detected on the tail
   of a flow is logged after the replay has already returned.
6. Clear sessions *again*. This is the step that makes the settle sufficient rather than
   hopeful: a replayed capture frequently lacks clean FIN/RST, so sessions would otherwise sit
   until PAN-OS's TCP timeout — 3600s by default — and their logs would not exist yet. Clearing
   forces them out. It is also why session-start logging is unnecessary (measured 2026-08-17).
7. Read the counters again and query the window. The counter delta is what turns "we retrieved
   what we retrieved" into a checkable claim: if the device wrote more than we read, labels are
   missing and the run says so.

Not pure — it drives both of the impure modules — but it makes no decisions about what a label
says. Those live in `panw.py`, which is testable without a device.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from flabel import panw, progress, replay
from flabel.errors import ToolError
from flabel.models import Detection
from flabel.progress import Reporter

#: Seconds between the end of the replay and the first session clear (today.md step 3).
DEFAULT_SETTLE_SECONDS = 60

#: Seconds after the clear before the counters are read, so the flushed logs have landed.
FLUSH_SECONDS = 10


@dataclass(frozen=True)
class Tier1Result:
    """Everything the tier-1 stage produced, including every way it could have under-reported."""

    detections: tuple[Detection, ...]
    #: Detection key -> the device content/config version that produced it, for provenance.
    rulesets: dict[panw.DetectionKey, str]
    window: replay.ReplayWindow
    device: panw.DeviceInfo
    #: Retrieved, admitted and collapsed counts, for the run block.
    entries_retrieved: int
    logs_written: int
    declined: tuple[str, ...]
    collapsed: int
    warnings: tuple[str, ...]


def run(
    capture: Path,
    workdir: Path,
    *,
    host: str,
    api_key: str,
    interfaces: tuple[str, str],
    multiplier: float = replay.DEFAULT_MULTIPLIER,
    topspeed: bool = False,
    settle_seconds: int = DEFAULT_SETTLE_SECONDS,
    report: Reporter | None = None,
) -> Tier1Result:
    """Replay `capture` past the device at `host` and return its verdicts.

    `report` is optional and every call to it is guarded, so the pipeline runs identically
    without one. Progress is a view of the work, never a participant in it.
    """
    say = report if report is not None else _Silent()

    say.start("device")
    device = panw.PanwDevice(host, api_key)
    info = device.system_info()
    if not info.has_threat_content:
        raise ToolError(
            f"the firewall at {host} reports threat-version {info.threat_version!r}, so it has no "
            f"threat signatures installed and no tier-1 label could ever be produced. Install "
            f"Applications-and-Threats content before labelling."
        )
    say.finish("device", f"{info.hostname} {info.sw_version} │ threat {info.threat_version}")

    say.start("clock")
    device_clock = device.clock()
    agreed, complaint = panw.verify_clock(device_clock, time.time())
    if not agreed:
        say.fail("clock", complaint or "clocks disagree")
        raise ToolError(complaint or "the firewall's clock disagrees with this host's")
    say.finish("clock", f"device {device_clock - time.time():+.0f}s │ within window")

    before = device.logs_written()
    device.clear_sessions()

    say.start("prep", "splitting by direction")
    cache = workdir / "replay.cache"
    staged = workdir / "replay-ready.pcap"
    replay.prepare_cache(capture, cache)
    macs = _interface_macs(interfaces)
    replay.rewrite_source_macs(capture, cache, staged, macs)
    stats = replay.capture_stats(staged)
    say.finish("prep", f"{progress.count(stats.packets)} pkts │ {progress.span(stats.span)} span")

    say.start("replay", f"0/{progress.count(stats.packets)}")

    def on_packet(sent: int, pps: float) -> None:
        fraction = min(1.0, sent / stats.packets) if stats.packets else None
        say.update(
            "replay",
            detail=f"{progress.count(sent)}/{progress.count(stats.packets)}",
            fraction=fraction,
            sample=pps,
        )

    window = replay.replay(
        staged,
        cache,
        interfaces,
        multiplier=multiplier,
        topspeed=topspeed,
        on_progress=on_packet,
    )
    say.finish(
        "replay",
        f"{progress.count(stats.packets)} pkts in {progress.duration(window.wall_span)} "
        f"│ x{window.effective_scale:.0f}",
    )

    # Counted down rather than slept through. It is the longest stretch of a run in which
    # nothing visibly happens, and an operator watching a still screen for a minute has no way
    # to tell a settle from a hang.
    say.start("settle", "")
    settle_end = time.monotonic() + settle_seconds
    while True:
        left = settle_end - time.monotonic()
        if left <= 0:
            break
        say.update(
            "settle",
            detail=f"{progress.duration(left)} left │ letting Content-ID finish",
            fraction=1.0 - (left / settle_seconds) if settle_seconds else None,
        )
        time.sleep(min(0.25, left))
    say.finish("settle", f"{settle_seconds}s elapsed")

    say.start("flush", "clearing sessions to force session-end logs")
    device.clear_sessions()
    time.sleep(FLUSH_SECONDS)
    say.finish("flush")

    after = device.logs_written()
    written = panw.counter_delta(before, after)

    say.start("query", "threat logs for the replay window")
    query = panw.ThreatQuery(start_wall=window.replay_start_wall, end_wall=window.replay_end_wall)
    entries = device.threat_entries(query)
    found, declined, rulesets = panw.detections(entries)
    kept, collapsed = panw.deduplicate(found)
    say.finish(
        "query",
        f"{len(entries)} entries │ {len(kept)} detections │ {written} written",
    )

    warnings: list[str] = []
    lost, complaint = panw.loss(retrieved=len(entries), written=written)
    if lost and complaint:
        warnings.append(complaint)
    note = panw.declined_note(declined)
    if note:
        warnings.append(note)
    if collapsed:
        warnings.append(
            f"{collapsed} tier-1 detection(s) were repeat firings of a signature already asserted "
            f"on the same 5-tuple, and were collapsed into the existing assertion"
        )
    if window.topspeed:
        warnings.append(
            "the replay used --topspeed, which abandons relative packet timing: a detection whose "
            "5-tuple occurs more than once in this capture cannot be placed and is reported "
            "unmatched rather than guessed"
        )

    # After every warning is collected, not as each is appended: a note printed mid-collection
    # would have missed the topspeed one, which is the warning most worth seeing.
    for warning in warnings:
        say.note(warning)

    return Tier1Result(
        detections=kept,
        rulesets=rulesets,
        window=window,
        device=info,
        entries_retrieved=len(entries),
        logs_written=written,
        declined=declined,
        collapsed=collapsed,
        warnings=tuple(warnings),
    )


class _Silent:
    """A reporter that says nothing, so `run()` needs no `if report is not None` at each call.

    Cheaper than threading an Optional through eleven call sites, and it keeps the reporting
    calls readable as a description of the sequence.
    """

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


def _interface_macs(interfaces: tuple[str, str]) -> tuple[str, str]:
    """Each replay NIC's own hardware address.

    Read from sysfs rather than configured, because a wrong value here is silent: the frames go
    out, GCE drops them for a source MAC that is not the sending vNIC's, and the run reports a
    capture in which the firewall saw nothing.
    """
    macs = []
    for name in interfaces:
        path = Path(f"/sys/class/net/{name}/address")
        try:
            macs.append(path.read_text().strip())
        except OSError as exc:
            raise ToolError(
                f"replay interface {name} has no readable hardware address at {path}: {exc}"
            ) from exc
    return (macs[0], macs[1])
