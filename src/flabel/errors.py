"""Typed exceptions and the exit codes they map to (spec §12).

Each exception type maps to exactly one exit code, so `cli.py` translates failures by type
rather than by inspecting messages.

Note what is deliberately *not* here: a distinct code for partial input. A truncated capture
still produces labels and still exits 0, with `run.input.input_status` reporting the
truncation. Anything else would make every ordinary `set -e` script treat a successful run
over a slightly-short capture as a failure.
"""

from __future__ import annotations

#: Labels were written. Covers complete and partial input alike.
EXIT_SUCCESS = 0
#: Failure. No labels written — either a complete run directory exists or none does.
EXIT_FAILURE = 1
#: Usage error. argparse exits with this itself; `UsageError` covers the cases it can't express.
EXIT_USAGE = 2
#: Not implemented. The Phase 1 default (non-`--offline`) path only.
EXIT_NOT_IMPLEMENTED = 3


class FlabelError(Exception):
    """Base for every failure flabel raises deliberately.

    `cli.py` catches this one class, so every deliberate failure must inherit from it or it
    will escape as a traceback and exit with the wrong code.
    """

    exit_code: int = EXIT_FAILURE


class ConfigError(FlabelError):
    """The source registry is missing, unparseable, or internally invalid.

    Hard failure rather than a warning: an invalid registry means we do not know which
    sources may label, and guessing that would put untraceable verdicts in the output.
    """


class CaptureError(FlabelError):
    """The capture cannot be read, or cannot be normalized safely.

    Raised for an unreadable header and for a truncated pcapng, where a partial block cannot
    be converted safely. Truncated *pcap* is not an error — it proceeds as partial input.
    """


class SnapshotError(FlabelError):
    """The requested ruleset snapshot is missing or unreadable.

    Never falls back to another snapshot: labels are only reproducible against a known
    ruleset, so silently substituting one would break the guarantee the snapshot exists for.
    """


class ToolError(FlabelError):
    """Zeek, Suricata or editcap failed, exited non-zero, or was killed.

    The failure is recorded in `tool_failures[]` as well as raised, so the run reports what
    was lost rather than merely dying.
    """


class UsageError(FlabelError):
    """Invalid invocation that argparse cannot express structurally."""

    exit_code = EXIT_USAGE


class NotImplementedInPhase1(FlabelError):
    """A Phase 2 capability was requested — the Tier 1 default path.

    Distinct from failure: nothing went wrong, the feature is not built yet, and a caller
    scripting against flabel needs to tell those apart.
    """

    exit_code = EXIT_NOT_IMPLEMENTED


def exit_code_for(exception: BaseException) -> int:
    """The exit code for `exception`.

    Anything that is not a `FlabelError` is an unforeseen crash, which maps to failure —
    never to success, and never to a usage error that would imply the caller's mistake.
    """
    if isinstance(exception, FlabelError):
        return exception.exit_code
    return EXIT_FAILURE
