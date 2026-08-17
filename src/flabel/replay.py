"""Replay the normalized capture past the PANW device (Phase 2 / Tier 1).

This is the stage Phase 1 had no equivalent of. Suricata and Zeek *read* the capture; the
firewall has to be *shown* it, as traffic, on a wire. Everything awkward about tier 1 follows
from that one difference.

`docs/phase-2-reachability-spike.md` records the measurement that made this module possible at
all (PRD §13 Q16): a cloud VM-Series does see replayed traffic, in a two-zone Layer 3
deployment, **with the original 5-tuple intact**. That last clause is what keeps this module
small. Because the addresses survive, `correlate.py` needs no change and no address map has to
be threaded through the pipeline — a tier-1 detection names the same endpoints Zeek read out of
the capture file.

**The capture is replayed in two directions, not one.** A single interface would show the
firewall both halves of every conversation arriving from the same zone, which is not a
conversation: PAN-OS would fail to pair the reply with its request, and the server-response
half of every flow — where a great many threats actually appear — would go uninspected. So
`tcpprep` decides which side of each flow is the client, and the two sides leave by different
interfaces.

**The time inverse is measured, never assumed, and this is the subtle part.** A capture spanning
hours must be replayed in seconds or the tool is unusable, so `tcpreplay --multiplier N`
compresses it. To read a firewall log timestamp back as a capture timestamp we need the inverse
of that compression — and the *nominal* multiplier is the wrong number to invert with. Measured
2026-08-17: a 14,494.4-second capture at `--multiplier 1000` took **14.86 s** of wall clock,
not the nominal 14.494 s. Inverting with N=1000 would therefore mis-map the tail of the replay
by (14.860 - 14.494) x 1000 ~= **365 capture-seconds**, about six minutes.

That error does not matter for the join — `correlate._place` matches on the 5-tuple and reads
the clock only to separate a tuple that occurs more than once in one capture — but it matters
exactly there, and a six-minute error is wide enough to pick the wrong one of two flows. So
`ReplayWindow` derives its scale from the observed start and end of the replay, and publishes
the residual as `uncertainty_seconds`. A caller that cannot separate two candidates by more
than that must report the detection as unplaced rather than choose, which is spec §13's rule and
the whole reason this class carries an error bar instead of just a scale factor.

Not pure: this module runs subprocesses. The timestamp arithmetic is pure and lives on
`ReplayWindow`, so it is testable without a NIC.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from flabel.errors import ToolError
from flabel.models import ToolFailure

#: Resolved through `PATH` rather than pinned, for the reason `suricata.BINARY` is: a container
#: and a laptop both work, and a test can inject "the binary is absent" by emptying `PATH`.
PREP = "tcpprep"
REPLAY = "tcpreplay"
REWRITE = "tcprewrite"

#: Default time compression. 1000 replays a 24-hour capture in about 90 seconds and a 4-hour
#: one in about 15, which is what makes labelling a real corpus affordable. Tunable because the
#: right value is a property of the capture's density, not of this tool.
DEFAULT_MULTIPLIER = 1000

#: Generous rather than tuned, matching `suricata.RUN_TIMEOUT_SECONDS`: killing a healthy
#: replay would be worse than waiting, and a wedged one must still become a `ToolFailure`
#: rather than a hung pipeline (spec §11).
REPLAY_TIMEOUT_SECONDS = 7200
PREP_TIMEOUT_SECONDS = 1800
VERSION_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class ReplayWindow:
    """Where a replay sat on the wall clock, and how to read that back as capture time.

    Frozen and arithmetic-only so the mapping can be tested without a NIC, a firewall, or a
    capture — the three things that make the rest of this module an integration test.
    """

    #: Timestamp of the capture's first packet, in the capture's own clock.
    pcap_first_ts: float
    #: Timestamp of the capture's last packet. With `pcap_first_ts` this gives the span the
    #: replay compressed, which is what makes the scale measurable rather than assumed.
    pcap_last_ts: float
    #: Wall clock either side of the `tcpreplay` invocation, from the replaying host.
    replay_start_wall: float
    replay_end_wall: float
    #: The `--multiplier` asked for. Recorded because it is an *input* to the run and a
    #: consumer cannot otherwise tell a 1000x replay from a 10x one — the same argument spec
    #: §10 makes for recording the unmatched threshold. Deliberately **not** what
    #: `to_pcap_time` inverts with.
    multiplier: float
    #: True when the caller asked for `--topspeed`, which abandons relative timing altogether.
    topspeed: bool = False

    @property
    def pcap_span(self) -> float:
        return self.pcap_last_ts - self.pcap_first_ts

    @property
    def wall_span(self) -> float:
        return self.replay_end_wall - self.replay_start_wall

    @property
    def effective_scale(self) -> float:
        """Capture-seconds per wall-second, as actually observed.

        The measured ratio, not `multiplier`. tcpreplay's own startup and scheduling overhead
        makes the two differ by a couple of percent, and that difference is multiplied by the
        scale when it is inverted — see this module's header for the 370-second measurement.

        A degenerate wall span falls back to the nominal multiplier: it is the best estimate
        available, and `uncertainty_seconds` reports the whole span as unknown in that case, so
        no caller can mistake the fallback for a measurement.
        """
        if self.wall_span <= 0:
            return self.multiplier
        return self.pcap_span / self.wall_span

    @property
    def uncertainty_seconds(self) -> float:
        """Error bar, in capture-seconds, on any timestamp `to_pcap_time` returns.

        Derived from the disagreement between the replay we asked for and the replay we got:
        `|wall_span - pcap_span / multiplier|` is the unmodelled overhead in wall-seconds, and
        scaling it up gives what that overhead is worth in capture time.

        Under `--topspeed` there is no relative timing to model, so the honest error bar is the
        entire capture span — which is the same as saying a timestamp carries no information,
        and is precisely what should stop a caller using it to choose between two flows.
        """
        if self.topspeed:
            return abs(self.pcap_span)
        if self.wall_span <= 0:
            return abs(self.pcap_span)
        nominal_wall = self.pcap_span / self.multiplier if self.multiplier else self.wall_span
        return abs(self.wall_span - nominal_wall) * self.effective_scale

    def to_pcap_time(self, wall_ts: float) -> float:
        """A firewall log's wall-clock timestamp, read as a capture timestamp.

        The value is only as good as `uncertainty_seconds` says it is. It exists to separate two
        occurrences of one 5-tuple, never to establish that a detection belongs to a flow — the
        tuple does that (`correlate._place`).
        """
        return self.pcap_first_ts + (wall_ts - self.replay_start_wall) * self.effective_scale

    def separates(self, first: float, second: float) -> bool:
        """Whether two capture timestamps are far enough apart to be told apart at all.

        The guard a caller needs before using a mapped timestamp to choose between candidate
        flows. Two flows closer together than the error bar are not distinguishable by this
        replay, and spec §13 says report rather than guess.
        """
        return abs(first - second) > self.uncertainty_seconds


def _run(argv: list[str], timeout: int, what: str) -> subprocess.CompletedProcess[bytes]:
    """One subprocess, with every failure mode turned into a `ToolError` carrying its argv.

    The argv travels with the failure because spec §11's `tool_failures[]` is what an operator
    reads after the fact; a message without the command line cannot be re-run by hand.
    """
    binary = argv[0]
    if shutil.which(binary) is None:
        raise ToolError(
            f"{binary} is not on PATH, so the capture cannot be {what}",
            failures=(ToolFailure(tool=binary, argv=tuple(argv), exit_code=None,
                                  message=f"{binary} not found on PATH"),),
        )
    try:
        return subprocess.run(argv, capture_output=True, timeout=timeout, check=True)
    except subprocess.TimeoutExpired as exc:
        raise ToolError(
            f"{binary} did not finish within {timeout}s while {what}",
            failures=(ToolFailure(tool=binary, argv=tuple(argv), exit_code=None,
                                  message=f"timed out after {timeout}s"),),
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", "replace").strip()
        raise ToolError(
            f"{binary} failed while {what}: {stderr or 'no stderr'}",
            failures=(ToolFailure(tool=binary, argv=tuple(argv), exit_code=exc.returncode,
                                  message=stderr or "no stderr"),),
        ) from exc


def version(binary: str = REPLAY) -> str:
    """The replay toolchain version, for the run block's `tools` section."""
    result = _run([binary, "--version"], VERSION_TIMEOUT_SECONDS, "establishing its version")
    text = (result.stdout or result.stderr or b"").decode("utf-8", "replace")
    return text.strip().splitlines()[0] if text.strip() else "unknown"


def prepare_cache(capture: Path, cache: Path) -> None:
    """Decide, per packet, which side of its flow it belongs to.

    `--auto=client` reads the TCP handshake to identify the initiator, which generalises to an
    arbitrary capture. The alternative considered and rejected was `--cidr` on the capture's own
    public address: deterministic, and the corpus filenames even encode that address
    (`..._pub-216.152.152.123.pcap`), but it makes flow direction depend on a filename
    convention, and a mislabelled file would silently invert every zone in the output.
    """
    _run([PREP, "--auto=client", f"--pcap={capture}", f"--cachefile={cache}"],
         PREP_TIMEOUT_SECONDS, "split by direction")


def rewrite_source_macs(capture: Path, cache: Path, out: Path, macs: tuple[str, str]) -> None:
    """Re-address the frames to the replaying host's own NICs.

    GCE enforces the source MAC of a virtual NIC, so frames still carrying the capture's
    original source MACs are the obvious candidate for being dropped before they ever reach the
    firewall. Destination MACs are deliberately left alone: GCP forwards by destination IP via
    the VPC custom routes, and the spike confirmed the original tuple arrives intact without
    touching them.

    **Whether the source rewrite is strictly required has not been measured.** The spike ran
    with it on and worked; `keep` was never tried. It is cheap and harmless, so it stays on
    until someone runs the A/B — recorded here rather than left as folklore, because an
    unnecessary rewrite step is the kind of thing that survives for years on the strength of one
    successful run.
    """
    _run([REWRITE, f"--enet-smac={macs[0]},{macs[1]}", f"--cachefile={cache}",
          f"--infile={capture}", f"--outfile={out}"],
         PREP_TIMEOUT_SECONDS, "re-addressed for replay")
