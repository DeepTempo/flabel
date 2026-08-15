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
import sys
from collections.abc import Iterator
from dataclasses import replace
from importlib import resources
from pathlib import Path

from flabel.errors import ToolError
from flabel.models import Flow, Ja4Status, ToolFailure, ZeekRunInfo

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

#: Zeek's own TSV conn log — the retained artifact, and the discriminator that tells a capture
#: with no connections from a JSON filter that failed to run. Zeek's ASCII writer creates a log
#: on the *first record written to that filter*, so neither file exists when there is nothing to
#: write: an ARP/STP-only capture, or a pcap truncated before its first complete record (which
#: spec §8 supports as partial input), legitimately produces no conn log at all.
CONN_TSV = "conn.log"


#: Version string used when the version probe itself is what failed.
UNKNOWN_VERSION = "unknown"

#: `ZeekRunInfo.ja4_status` values — whether JA4 was computable at all, and if not, why not.
#:
#: JA4 absence has to be reportable: with no signal, a consumer cannot tell "this capture had
#: no TLS" from "the fingerprinting package was not installed", and spec §2.5 says absence is
#: never a signal.
#:
#: These used to be spelled `present:version-unknown` / `absent:not-installed` and stored in
#: `ja4_package_version`, because `ZeekRunInfo` had nowhere else to put them while three steps
#: were being built against a shared `models.py`. A status is not a version, and any consumer
#: printing that field would have printed nonsense — flagged on PR #30, fixed here. The field
#: is now `ja4_status`, typed by `models.Ja4Status`, and `ja4_package_version` holds a version
#: string or nothing.
JA4_PRESENT: Ja4Status = "present"
JA4_NOT_INSTALLED: Ja4Status = "not-installed"
JA4_PROBE_FAILED: Ja4Status = "probe-failed"

#: Probes are bounded because they run before any work is done and a hung probe would look
#: like a hung pipeline. The analysis pass is deliberately unbounded: how long Zeek needs is a
#: function of the capture, and killing it at an invented deadline would drop flows silently.
PROBE_TIMEOUT_SECONDS = 60

_SEMVER = re.compile(r"\d+\.\d+(\.\d+)*")


def _missing_script_pattern(script: str) -> re.Pattern[str]:
    """How Zeek says `script` is not on ZEEKPATH: `can't find <script>`.

    A function of the script name rather than one baked-in constant, so a test can build the
    same pattern for a name that is *guaranteed* absent and check it against the real Zeek's
    real wording (#92). Before this, every test reaching the branch used a shell stub echoing
    `can't find ja4` — the classifier was only ever checked against a string the fixture wrote
    for it — and CI runs `--strict-toolchain`, which requires the package present, so CI never
    took the branch at all.

    What that hid: if a Zeek upgrade rewords the message, every laptop and every non-ja4
    container flips from `not-installed` to `probe-failed` — the state the spec calls a defect —
    with CI green throughout.
    """
    return re.compile(rf"can't find {re.escape(script)}\b")


#: Matched so that "the package is not installed" — the ordinary laptop case — is distinguishable
#: from a probe that failed for some other reason, such as a broken ZEEKPATH or a half-finished
#: `zkg` install. Both degrade to no JA4, but only the first is expected, and reporting them as
#: one hides the other.
_JA4_MISSING = _missing_script_pattern(JA4_SCRIPT)

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
    return (
        binary or executable(),
        *MANDATORY_FLAGS,
        "-r",
        str(capture),
        *zeek_flags_tail(load_ja4=load_ja4),
        str(script_path()),
    )


def zeek_flags_tail(*, load_ja4: bool) -> tuple[str, ...]:
    """The scripts loaded by name, which `ZeekRunInfo.flags` also records."""
    return (JA4_SCRIPT,) if load_ja4 else ()


def recorded_flags(*, load_ja4: bool) -> tuple[str, ...]:
    """What `ZeekRunInfo.flags` carries: the flags and script names, and no paths.

    Deliberately **not** the full argv. The argv contains the normalized capture's path, which
    lives in a per-run directory and therefore differs on every run by construction — so
    serialising it into `labels.json` would make two otherwise identical runs differ, breaking
    Goal 2, and would leak host filesystem paths into a shipped artifact. Spec §10 specifies
    `zeek_flags: ["-C", "-D"]`. The full argv is recorded on `ToolFailure.argv`, where it is
    diagnostic rather than part of the reproducibility contract.
    """
    return MANDATORY_FLAGS + zeek_flags_tail(load_ja4=load_ja4)


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
    ja4_status: Ja4Status = JA4_PROBE_FAILED
    warnings: tuple[str, ...] = ()
    # Never `()`: the flags this module *would* use are known before anything runs, and an empty
    # tuple on a failure path would read as "-D was lost", which is the one thing `flags` exists
    # to make visible.
    flags = MANDATORY_FLAGS

    try:
        version = _version(binary)
        ja4_status, ja4_warning = _ja4_status(binary)
        warnings = (ja4_warning,) if ja4_warning else ()
        load_ja4 = ja4_status == JA4_PRESENT
        flags = recorded_flags(load_ja4=load_ja4)
        argv = zeek_argv(capture, load_ja4=load_ja4, binary=binary)
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
            flags=flags,
            log_dir=outdir,
            retained_logs=_retained_logs(outdir),
            ja4_status=ja4_status,
            warnings=warnings,
            tool_failures=(aborted.failure,),
        )
        raise _tool_error(aborted, info) from aborted

    _strip_json_logs(outdir)
    # `ja4_package_version` is left None deliberately, even when JA4 is present: `zkg list` is the
    # only local source of the version string, and shelling out to zkg from a labelling run would
    # risk the one thing spec §2.2 forbids — step 9 asserts a run makes no network call — and I
    # have not verified zkg is offline. `provenance.py` substitutes the real version from
    # /etc/flabel-toolchain.json. Whether JA4 worked at all is `ja4_status`, which is a status
    # and is typed as one.
    info = ZeekRunInfo(
        version=version,
        flags=flags,
        log_dir=outdir,
        retained_logs=_retained_logs(outdir),
        ja4_status=ja4_status,
        warnings=warnings,
    )
    return flows, info


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


def _ja4_status(binary: str) -> tuple[Ja4Status, str | None]:
    """Whether `zeek/foxio/ja4` can be loaded, and the warning text if it cannot.

    Asked the way `docs/dev-setup.md` asks it.

    A `--parse-only` probe, not an analysis pass: it reads no packets and writes no logs. It
    exists because `@load ja4` is fatal when the package is absent, and Zeek has no
    load-if-present form — so without the probe, a machine without the package (Homebrew's
    `zkg` ships without its Python dependencies) could not run the pipeline at all.

    Asking Zeek to load it, rather than looking for its directory, tests the capability that
    is actually needed and stays correct wherever `zkg` chose to install it.

    Three outcomes, not two. "Not installed" is the expected laptop case; a probe that failed
    for any *other* reason — a broken ZEEKPATH, a half-finished `zkg` install, a syntax error in
    the installed package — degrades to the same missing JA4 but is a defect, and collapsing the
    two would hide it. Either way the run continues without JA4 rather than failing: a capture
    is still worth labelling from rule matches, and this is reported rather than silent.

    The warning text is *returned* as well as printed. stderr is where spec §12 puts a warning
    for the operator watching the run; `ZeekRunInfo.warnings` is where spec §10 puts it for
    whoever reads `labels.json` afterwards, and those are different readers. Returning it means
    one sentence serves both instead of the run block paraphrasing what stderr already said.
    """
    probe = (binary, "--parse-only", "-e", f"@load {JA4_SCRIPT}")
    result = _completed(probe, timeout=PROBE_TIMEOUT_SECONDS)
    if result.returncode == 0:
        return JA4_PRESENT, None

    output = f"{result.stderr}\n{result.stdout}"
    if _JA4_MISSING.search(output):
        return JA4_NOT_INSTALLED, _warn(
            f"{JA4_SCRIPT} package not installed: no flow will carry a JA4 fingerprint. "
            f"Labels are unaffected — a fingerprint is never a verdict (spec §2.6) — but a "
            f"missing ja4 in this run's output means 'not computed', not 'no TLS'. "
            f"See docs/dev-setup.md."
        )

    return JA4_PROBE_FAILED, _warn(
        f"the {JA4_SCRIPT} probe failed for an unexpected reason, so no flow will carry a JA4 "
        f"fingerprint. This is not the ordinary 'package not installed' case — check ZEEKPATH "
        f"and the zkg install. zeek --parse-only exited {result.returncode}: {_tail(result)}"
    )


def _warn(message: str) -> str:
    """Print a non-fatal loss on stderr (spec §12) and return it for the run block (spec §10)."""
    print(f"flabel: warning: {message}", file=sys.stderr)
    return message


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
    """The one exception this stage raises, carrying everything the caller has to report.

    `failures` and `run_info` are constructor arguments, not attributes bolted on afterwards:
    the assignment `error.run_info = info` this used to do was invisible to a type checker and
    to anyone reading `errors.py`, which is where a caller looks to find out what a `ToolError`
    carries.
    """
    return ToolError(f"Zeek failed: {aborted}", failures=(aborted.failure,), run_info=info)


# --- logs ---------------------------------------------------------------------------------


def _parse_flows(outdir: Path, argv: tuple[str, ...]) -> dict[str, Flow]:
    """`conn_json.log` into flows, enriched from `ssl_json.log` on `uid`."""
    flows = _parse_conn(outdir, argv)
    for uid, tls in _parse_ssl(outdir / SSL_JSON, argv).items():
        flow = flows.get(uid)
        # An ssl record whose uid has no conn record cannot happen — Zeek logs the connection
        # for anything it analyses — so there is nothing to report and nothing to invent.
        if flow is not None:
            flows[uid] = replace(flow, **tls)
    return flows


def _parse_conn(outdir: Path, argv: tuple[str, ...]) -> dict[str, Flow]:
    """Every connection Zeek logged, keyed by `uid`.

    A missing `conn_json.log` means one of two very different things, and the retained TSV log
    tells them apart. Zeek's ASCII writer creates a log on the first record written to that
    filter, so a capture with no connections at all — ARP/STP/LLDP only, or a pcap truncated
    before its first complete record, which spec §8 supports as partial input — writes *neither*
    `conn.log` nor `conn_json.log`. That is a real, empty result, and failing the run over it
    would reject captures the pipeline is specified to accept.

    `conn.log` present with `conn_json.log` absent is the other case: Zeek logged connections and
    our filter did not fire. Reporting zero flows there would be a silent loss of every flow in
    the capture, so it fails (spec §2.5).
    """
    json_log = outdir / CONN_JSON
    if not json_log.exists():
        if (outdir / CONN_TSV).exists():
            raise _Aborted(
                f"zeek wrote {CONN_TSV} but no {CONN_JSON}, so every flow would be lost; "
                f"the JSON log filter in {SCRIPT_NAME} did not run",
                0,
                argv,
            )
        return {}

    flows: dict[str, Flow] = {}
    for line_number, record in _records(json_log, argv):
        missing = [key for key in _CONN_REQUIRED if key not in record]
        if missing:
            raise _Aborted(
                f"{CONN_JSON} line {line_number} has no {', '.join(missing)}; "
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
                # Lowercased deliberately: Zeek writes `tcp`, Suricata's eve.json writes `TCP`,
                # and step 7 correlates on a tuple that includes proto — so one of the two has to
                # normalize or every detection would be unmatchable. Both sides lowercase.
                proto=str(record["proto"]).lower(),
                ts_first=timestamp,
                # An unfinished connection has no duration, so first and last are the same
                # instant. Correlation's window then spans zero, which is correct: nothing was
                # observed after the first packet.
                ts_last=timestamp + float(record.get("duration") or 0.0),
            )
        except (TypeError, ValueError) as exc:
            raise _Aborted(
                f"{CONN_JSON} line {line_number} has an unusable field value: {exc}", 0, argv
            ) from exc
        if flow.uid in flows:
            # The uid is the join key for every label. Two records sharing one would make
            # "the flow this label is about" ambiguous, and last-one-wins would silently pick.
            raise _Aborted(
                f"{CONN_JSON} line {line_number} repeats uid {flow.uid}, which is the join key "
                f"for every label and must be unique",
                0,
                argv,
            )
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
    """The JSON objects in a Zeek JSON log, one per line, with line numbers for messages.

    Streams the file a line at a time. A `conn_json.log` from a large capture is comfortably
    bigger than memory, and reading it whole would have this module OOM-kill itself one function
    after carefully reporting Zeek being OOM-killed.

    `errors="replace"` because the decode is not allowed to fail: `ssl_json.log` carries
    certificate subject and issuer DNs, which routinely contain non-ASCII, and Zeek does not
    guarantee valid UTF-8 in a field lifted from the wire. A `UnicodeDecodeError` is a
    `ValueError`, so it would have escaped every `OSError` handler here and reached the caller as
    exactly the untyped exception this module promises never to raise. A replacement character in
    a certificate DN costs nothing — flabel does not parse DNs — whereas a failed run costs the
    labels.
    """
    try:
        handle = path.open(encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise _Aborted(
            f"zeek exited 0 but wrote no {path.name}; the JSON log filter did not run",
            0,
            argv,
        ) from exc
    except OSError as exc:
        raise _Aborted(f"could not read {path}: {exc}", 0, argv) from exc

    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise _Aborted(
                    f"{path.name} line {line_number} is not JSON: {exc}", 0, argv
                ) from exc
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
