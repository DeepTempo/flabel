"""Invoke Zeek and parse its logs into flows (spec §8).

One analysis pass per run:

    zeek -C -D -r <normalized.pcap> [ja4] <package-data>/json-logs.zeek

`-D` is not an option. Verified on Zeek 8.0.4: without it, connection `uid` values differ on
every run over identical input, so labels from two runs cannot be joined and Goal 2
(reproducibility) is unreachable. Spec §13 lists invoking Zeek without `-D` among the hard
never-dos, so the flag is built from a constant, recorded in `ZeekRunInfo.flags`, and guarded
by a test that compares uids across two real invocations.

`-C` ignores checksum errors, because a capture taken from a NIC doing checksum offload has
wrong checksums on transmitted packets and Zeek would otherwise discard exactly the traffic
the operator wants labelled.

The retained artifact is Zeek's TSV output. The JSON logs written by `json-logs.zeek` are
parse input only and are removed once read, so the run directory holds one representation of
each log rather than two that a reader would have to reconcile.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from dataclasses import replace
from importlib import resources
from pathlib import Path

from flabel.errors import ToolError
from flabel.models import Flow, ToolFailure, ZeekRunInfo

#: Name recorded on every `ToolFailure` from this module.
TOOL = "zeek"

#: Environment override for the executable. Config comes from the environment rather than a
#: constant so that spec §11's fault injection — "point at a non-existent binary" — is
#: reachable without patching the module under test.
ZEEK_ENV = "FLABEL_ZEEK"

#: The Zeek script that adds the JSON filters, shipped as package data.
SCRIPT_NAME = "json-logs.zeek"

#: The JA4 package, loaded by name (`zkg` puts it on ZEEKPATH). Loaded explicitly rather than
#: relying on `site/local.zeek`, which this invocation deliberately does not read: an ambient
#: local.zeek would make the analysis depend on machine-local configuration.
JA4_SCRIPT = "ja4"

#: Mandatory flags, in order. A constant so `-D` cannot be lost in an edit to the argv
#: builder without a test noticing (see `test_zeek.py`).
MANDATORY_FLAGS = ("-C", "-D")

#: Logs written by `json-logs.zeek`. Parsed, then stripped from the retained output.
CONN_JSON = "conn_json.log"
SSL_JSON = "ssl_json.log"
JSON_LOGS = (CONN_JSON, SSL_JSON)

#: Logs that are never byte-identical across two runs of the same capture, and so must be
#: excluded from any reproducibility comparison. `packet_filter.log` records Zeek's wall-clock
#: start time; it carries no analytic content, and it is retained rather than deleted because
#: deleting a log Zeek wrote would misrepresent the run.
NON_REPRODUCIBLE_LOGS = frozenset({"packet_filter.log"})

#: Version string used when the version probe itself is what failed.
UNKNOWN_VERSION = "unknown"

#: Probes are bounded because they run before any work is done and a hung probe would look
#: like a hung pipeline. The analysis pass is deliberately unbounded: how long Zeek needs is a
#: function of the capture, and killing it at an invented deadline would drop flows silently.
PROBE_TIMEOUT_SECONDS = 60

_SEMVER = re.compile(r"\d+\.\d+(\.\d+)*")

#: conn.log keys every record must carry for a flow to be built from it. `duration` is not
#: among them: an unfinished connection legitimately has none.
_CONN_REQUIRED = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")

#: ssl.log keys joined onto a flow on `uid`. Absent keys leave the field None: a flow with no
#: handshake has no JA4, which is a different thing from a JA4 that failed to compute.
_SSL_FIELDS = ("ja4", "ja4s", "server_name")


class _Aborted(Exception):
    """Internal: the Zeek pass cannot produce flows, and why.

    Raised by the helpers and converted by `run_zeek` into a `ToolFailure` plus a `ToolError`,
    so that no `OSError`, `CalledProcessError` or `JSONDecodeError` reaches a caller. Every
    failure of this stage leaves the pipeline through one typed exception carrying one record.
    """

    def __init__(self, message: str, exit_code: int | None, argv: tuple[str, ...]) -> None:
        super().__init__(message)
        self.failure = ToolFailure(tool=TOOL, argv=argv, exit_code=exit_code, message=message)


def script_path() -> Path:
    """The packaged `json-logs.zeek`.

    Under `src/flabel/data/` rather than at the repo root, so it resolves identically from a
    checkout, an editable install (what `uv sync` produces) and a built wheel. Root-level
    package data reaches a wheel only through a hatch `force-include`, which an editable
    install does not have — it would work in CI's wheel and fail in the tests.
    """
    return Path(str(resources.files("flabel") / "data" / SCRIPT_NAME))


def executable() -> str:
    """The Zeek binary to invoke."""
    return os.environ.get(ZEEK_ENV) or TOOL


def zeek_argv(capture: Path, *, load_ja4: bool, binary: str | None = None) -> tuple[str, ...]:
    """The full argument vector for the analysis pass.

    Built here rather than inline so the flag set is testable without a toolchain: the `-D`
    regression test can assert the argv directly, and does not have to infer the flag from
    behaviour alone.
    """
    scripts = (JA4_SCRIPT,) if load_ja4 else ()
    return (
        binary or executable(),
        *MANDATORY_FLAGS,
        "-r",
        str(capture),
        *scripts,
        str(script_path()),
    )


def run_zeek(capture: Path, outdir: Path) -> tuple[dict[str, Flow], ZeekRunInfo]:
    """Run Zeek over `capture`, writing its logs into `outdir`, and parse the flows.

    Returns the flow table keyed by `uid` — the join key for the rest of the pipeline — and
    what the pass did, for the run block.

    On a non-zero exit, a killed process (an OOM kill arrives as SIGKILL) or unusable output,
    the failure is recorded in `ZeekRunInfo.tool_failures` **and** raised as `ToolError`, per
    that exception's contract in `errors.py`: the run fails, and it reports what was lost
    rather than merely dying. The `ZeekRunInfo` carrying the record is attached to the
    exception as `run_info`, because a caller that catches the failure still has to report it.
    Nothing else escapes — no `OSError`, no `CalledProcessError`, no `JSONDecodeError`.
    """
    capture = Path(capture).resolve()
    outdir = Path(outdir)
    binary = executable()
    version = UNKNOWN_VERSION
    argv: tuple[str, ...] = ()

    try:
        version = _version(binary)
        argv = zeek_argv(capture, load_ja4=_ja4_loadable(binary), binary=binary)
        outdir.mkdir(parents=True, exist_ok=True)
        _invoke(argv, outdir)
        flows = _parse_flows(outdir, argv)
    except _Aborted as aborted:
        # The JSON logs are deliberately *not* stripped here. The run has failed and writes no
        # labels, so there is no artifact for them to clutter — and if the failure was a
        # malformed log, deleting it would destroy the only evidence of why. `retained_logs`
        # therefore reports what is genuinely on disk, JSON logs included.
        info = ZeekRunInfo(
            version=version,
            flags=tuple(argv[1:]),
            log_dir=outdir,
            retained_logs=_retained_logs(outdir),
            tool_failures=(aborted.failure,),
        )
        raise _tool_error(aborted, info) from aborted

    _strip_json_logs(outdir)
    # `ja4_package_version` is left unset on purpose. `zkg list` is the only local source of
    # that string, and shelling out to zkg from a labelling run would risk the one thing spec
    # §2.2 forbids — step 9 asserts a run makes no network call — and I have not verified zkg
    # is offline. Whether ja4 was loaded at all is visible in `flags`; recording the version is
    # left to `provenance.py`, which can read /etc/flabel-toolchain.json. Raised in the PR.
    info = ZeekRunInfo(
        version=version,
        flags=tuple(argv[1:]),
        log_dir=outdir,
        retained_logs=_retained_logs(outdir),
    )
    return flows, info


def reproducible_logs(info: ZeekRunInfo) -> tuple[str, ...]:
    """The retained logs that two runs over one capture must produce identically.

    `packet_filter.log` is excluded: it stamps Zeek's wall-clock start time, so comparing it
    would fail every time and say nothing about whether the analysis was reproducible.
    """
    return tuple(name for name in info.retained_logs if name not in NON_REPRODUCIBLE_LOGS)


# --- invocation ---------------------------------------------------------------------------


def _version(binary: str) -> str:
    """The version Zeek reports, e.g. `8.0.4` from `zeek version 8.0.4`."""
    result = _completed((binary, "--version"), timeout=PROBE_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise _Aborted(
            f"{binary} --version exited {result.returncode}: {_tail(result)}",
            result.returncode,
            (binary, "--version"),
        )
    text = (result.stdout or result.stderr).strip()
    match = _SEMVER.search(text)
    if match:
        return match.group(0)
    # The whole line rather than nothing, if the format ever changes: an unparseable version is
    # worth recording verbatim, whereas an empty one would read as "no version recorded".
    return text.splitlines()[0] if text else UNKNOWN_VERSION


def _ja4_loadable(binary: str) -> bool:
    """Whether `zeek/foxio/ja4` is installed, asked the way `docs/dev-setup.md` asks it.

    A `--parse-only` probe, not an analysis pass: it reads no packets and writes no logs. It
    exists because `@load ja4` is fatal when the package is absent, and Zeek has no
    load-if-present form — so without the probe, a machine without the package (Homebrew's
    `zkg` ships without its Python dependencies) could not run the pipeline at all.

    Asking Zeek to load it, rather than looking for its directory, tests the capability that
    is actually needed and stays correct wherever `zkg` chose to install it.
    """
    probe = (binary, "--parse-only", "-e", f"@load {JA4_SCRIPT}")
    result = _completed(probe, timeout=PROBE_TIMEOUT_SECONDS)
    return result.returncode == 0


def _invoke(argv: tuple[str, ...], outdir: Path) -> None:
    """Run the analysis pass with `outdir` as the working directory.

    Zeek writes its logs to the current directory and has no output-directory flag, so the cwd
    is the mechanism. The capture path is absolute for the same reason.
    """
    result = _completed(argv, cwd=outdir)
    if result.returncode == 0:
        return
    if result.returncode < 0:
        signal_number = -result.returncode
        raise _Aborted(
            f"zeek was killed by signal {signal_number}"
            + (" (SIGKILL — typically the OOM killer)" if signal_number == 9 else "")
            + f": {_tail(result)}",
            result.returncode,
            argv,
        )
    raise _Aborted(f"zeek exited {result.returncode}: {_tail(result)}", result.returncode, argv)


def _completed(
    argv: tuple[str, ...], *, cwd: Path | None = None, timeout: float | None = None
) -> subprocess.CompletedProcess[str]:
    """`subprocess.run` with every failure mode turned into `_Aborted`.

    `check=False`: a non-zero exit is a recorded loss condition here, not an exception to
    translate later. `exit_code=None` distinguishes "could not be run at all" — a missing or
    non-executable binary — from a process that ran and failed.
    """
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _Aborted(f"could not run {argv[0]}: {exc}", None, argv) from exc


def _tail(result: subprocess.CompletedProcess[str], limit: int = 400) -> str:
    """The end of a failed process's output, flattened onto one line.

    Zeek reports the actual problem on stderr, so a failure message without it sends the
    reader to the logs for something we already had.
    """
    text = " ".join((result.stderr or result.stdout or "").split())
    return text[-limit:] if text else "(no output)"


def _tool_error(aborted: _Aborted, info: ZeekRunInfo) -> ToolError:
    error = ToolError(f"Zeek failed: {aborted}")
    # Set dynamically rather than by extending `errors.py`, which three parallel steps share.
    # The caller needs the run info to report the failure it is about to fail on.
    error.run_info = info  # type: ignore[attr-defined]
    return error


# --- logs ---------------------------------------------------------------------------------


def _parse_flows(outdir: Path, argv: tuple[str, ...]) -> dict[str, Flow]:
    """`conn_json.log` into flows, enriched from `ssl_json.log` on `uid`."""
    flows = _parse_conn(outdir / CONN_JSON, argv)
    for uid, tls in _parse_ssl(outdir / SSL_JSON, argv).items():
        flow = flows.get(uid)
        # An ssl record whose uid has no conn record cannot happen — Zeek logs the connection
        # for anything it analyses — so there is nothing to report and nothing to invent.
        if flow is not None:
            flows[uid] = replace(flow, **tls)
    return flows


def _parse_conn(path: Path, argv: tuple[str, ...]) -> dict[str, Flow]:
    """Every connection Zeek logged, keyed by `uid`.

    A missing `conn_json.log` is a failure rather than an empty result: it means the JSON
    filter never ran, and reporting zero flows would be indistinguishable from a capture with
    no traffic (spec §2.5, absence is never a signal). A capture Zeek found nothing in still
    produces the file, empty.
    """
    flows: dict[str, Flow] = {}
    for line_number, record in _records(path, argv):
        missing = [key for key in _CONN_REQUIRED if key not in record]
        if missing:
            raise _Aborted(
                f"{path.name} line {line_number} has no {', '.join(missing)}; "
                f"this is not a Zeek conn log",
                0,
                argv,
            )
        try:
            timestamp = float(record["ts"])
            flow = Flow(
                uid=str(record["uid"]),
                src_ip=str(record["id.orig_h"]),
                src_port=int(record["id.orig_p"]),
                dst_ip=str(record["id.resp_h"]),
                dst_port=int(record["id.resp_p"]),
                proto=str(record["proto"]),
                ts_first=timestamp,
                # An unfinished connection has no duration, so first and last are the same
                # instant. Correlation's window then spans zero, which is correct: nothing was
                # observed after the first packet.
                ts_last=timestamp + float(record.get("duration") or 0.0),
            )
        except (TypeError, ValueError) as exc:
            raise _Aborted(
                f"{path.name} line {line_number} has an unusable field value: {exc}", 0, argv
            ) from exc
        flows[flow.uid] = flow
    return flows


def _parse_ssl(path: Path, argv: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """TLS fields per `uid`, for the join onto flows.

    A missing `ssl_json.log` is normal — Zeek writes no ssl log for a capture with no TLS — so
    it yields nothing rather than failing.

    On repeated records for one uid (renegotiation, or several handshakes on one connection)
    the first value of each field wins and later ones do not overwrite it, so which handshake
    a label's JA4 came from does not depend on log ordering.
    """
    if not path.exists():
        return {}
    joined: dict[str, dict[str, str]] = {}
    for line_number, record in _records(path, argv):
        uid = record.get("uid")
        if uid is None:
            raise _Aborted(f"{path.name} line {line_number} has no uid", 0, argv)
        fields = joined.setdefault(str(uid), {})
        for key in _SSL_FIELDS:
            value = record.get(key)
            if value is not None and fields.get(key) is None:
                fields[key] = str(value)
    return joined


def _records(path: Path, argv: tuple[str, ...]) -> Iterator[tuple[int, dict]]:
    """The JSON objects in a Zeek JSON log, one per line, with line numbers for messages."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise _Aborted(
            f"zeek exited 0 but wrote no {path.name}; the JSON log filter did not run",
            0,
            argv,
        ) from exc
    except OSError as exc:
        raise _Aborted(f"could not read {path}: {exc}", 0, argv) from exc

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise _Aborted(f"{path.name} line {line_number} is not JSON: {exc}", 0, argv) from exc
        if not isinstance(record, dict):
            raise _Aborted(
                f"{path.name} line {line_number} is {type(record).__name__}, not an object",
                0,
                argv,
            )
        yield line_number, record


def _strip_json_logs(outdir: Path) -> None:
    """Remove the JSON logs once parsed.

    They exist to be read, and keeping them would leave the run directory with two copies of
    `conn` — an invitation to a consumer to read the one flabel did not label from.
    """
    for name in JSON_LOGS:
        (outdir / name).unlink(missing_ok=True)


def _retained_logs(outdir: Path) -> tuple[str, ...]:
    """The log files kept in `outdir`, sorted.

    Read from disk rather than assumed, because which logs Zeek writes depends on what
    protocols the capture contained — and the run block should say what is actually there.
    """
    if not outdir.is_dir():
        return ()
    return tuple(sorted(path.name for path in outdir.glob("*.log") if path.is_file()))
