"""Invoke Suricata over the normalized capture and parse `eve.json` (spec §8).

Three things in here carry the weight:

**The invocation is exact.** ``-S`` *replaces* the ruleset with the snapshot's, so no
ambient system ruleset can contribute a SID that appears in no snapshot; ``--runmode single``
makes the alert set deterministic, which Goal 2 rests on. Both are asserted by a test on
`build_argv`, not left to a comment.

**Every alert is attributed to a source before it can become a label.** `eve.json` records a
SID and nothing about where the rule came from, so attribution is rebuilt from the snapshot.
An alert that cannot be attributed is never emitted with a guess: spec §13 forbids a label
whose origin cannot be traced, and the source is also what decides whether the alert may
label at all.

**Detections from `identify`-class sources are dropped here**, at the earliest point they
exist, and counted in `identify_alerts_suppressed` (spec §2.8). Dropping them further
downstream would mean a window in which a label that must never exist does.

Failure handling splits along a deliberate line:

* **The snapshot cannot support provenance** → `SnapshotError` before any subprocess runs.
  This covers the quiet ones: Suricata treats a missing or empty ``-S`` file as a *warning*
  and exits 0 with an empty alert set (verified on 8.0.6), which is indistinguishable from a
  capture that contained nothing.
* **Suricata failed to run, or ran and failed** → a `ToolFailure` in the returned
  `SuricataRunInfo`, with no exception escaping. The caller fails the run (spec §8) but the
  run block still reports what was lost rather than merely dying (spec §2.5).
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import Any

from flabel.errors import SnapshotError, ToolError
from flabel.models import (
    Detection,
    SnapshotManifest,
    SourceAdmission,
    SourceSpec,
    SuricataRunInfo,
    ToolFailure,
)

#: Suricata is Tier 2 for every label it produces. Phase 2's PANW device is Tier 1; a lower
#: tier is a higher-trust observation (`Label.best_tier` is the minimum).
TIER = 2

#: Resolved through ``PATH`` rather than pinned to a path, so the container and a laptop both
#: work and a test can inject "the binary is not there" by emptying ``PATH``.
BINARY = "suricata"

RULES_FILE = "rules.rules"
MANIFEST_FILE = "manifest.json"
RAW_DIR = "raw"
EVE_FILE = "eve.json"
LOG_FILE = "suricata.log"

#: `sid:` in a rule line. Suricata itself accepts whitespace around the colon, so this does
#: too — a rule we failed to see the SID of would be a rule we could not attribute.
SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")

#: Suricata's own load report in ``suricata.log``, used when the eve stats event is absent.
RULES_LOADED = re.compile(r"(\d+) rules successfully loaded")

VERSION = re.compile(r"\d+\.\d+\.\d+")


def build_argv(capture: Path, snapshot: Path, outdir: Path) -> list[str]:
    """The exact invocation of spec §8.

    Separated from `run_suricata` so the flags are testable without running anything. `-S`
    (replace the ruleset) rather than `-s` (add to it) is the whole reason a label's SID can
    be traced to a snapshot.
    """
    return [
        BINARY,
        "-r",
        str(capture),
        "-S",
        str(snapshot / RULES_FILE),
        "-l",
        str(outdir),
        "--set",
        "app-layer.protocols.tls.ja3-fingerprints=yes",
        "--set",
        "app-layer.protocols.tls.ja4-fingerprints=yes",
        "--runmode",
        "single",
    ]


def run_suricata(
    capture: Path, snapshot: Path, outdir: Path
) -> tuple[list[Detection], SuricataRunInfo]:
    """Run Suricata over `capture` with `snapshot`'s rules, returning parsed detections.

    Detections are returned in eve.json order, which is capture order. Ordering of the final
    output is `labels.py`'s job (spec §10), so nothing is re-sorted here.
    """
    manifest = load_manifest(snapshot)
    sources = {admission.name: admission for admission in manifest.sources}
    index = sid_source_index(snapshot, manifest)
    _prepare_outdir(outdir)

    argv = build_argv(capture, snapshot, outdir)
    version, failure = _version()
    if failure is not None:
        return [], _failed(manifest, failure)

    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as exc:
        return [], _failed(
            manifest,
            _failure(argv, None, f"suricata could not be executed: {exc}"),
            version=version,
        )

    if completed.returncode != 0:
        # A negative code is a signal — an OOM kill shows up here as -9, which is why the
        # message says which of the two happened rather than printing a bare number.
        killed = completed.returncode < 0
        detail = f"killed by signal {-completed.returncode}" if killed else "exited non-zero"
        return [], _failed(
            manifest,
            _failure(
                argv,
                completed.returncode,
                f"suricata {detail}: {_tail(completed.stderr or completed.stdout)}",
            ),
            version=version,
        )

    eve = outdir / EVE_FILE
    if not eve.exists():
        return [], _failed(
            manifest,
            _failure(
                argv,
                completed.returncode,
                f"suricata exited 0 but wrote no {EVE_FILE} in {outdir}",
            ),
            version=version,
        )

    detections, alerts_total, suppressed, loaded = _read_eve(eve, index, sources)
    if loaded is None:
        loaded = _rules_loaded_from_log(outdir / LOG_FILE)

    if not loaded:
        # The snapshot was checked to hold rules before we started, so zero loaded means the
        # engine rejected every one of them — an empty alert set that means nothing.
        return [], _failed(
            manifest,
            _failure(
                argv,
                completed.returncode,
                "suricata loaded no rules from the snapshot, so an empty alert set proves "
                "nothing about the capture",
            ),
            version=version,
        )

    return detections, SuricataRunInfo(
        version=version,
        snapshot_id=manifest.snapshot_id,
        rules_loaded=loaded,
        alerts_total=alerts_total,
        identify_alerts_suppressed=suppressed,
    )


# --- the snapshot -------------------------------------------------------------------------


def load_manifest(snapshot: Path) -> SnapshotManifest:
    """Read and validate `snapshot`'s manifest.

    Strict about missing and unknown keys: the manifest is where `source_class` comes from,
    and `source_class` is what decides whether a source may label at all. A manifest we can
    only partly read is not a basis for that decision, and never falls back to another
    snapshot (spec §7).
    """
    path = snapshot / MANIFEST_FILE
    if not snapshot.is_dir():
        raise SnapshotError(f"ruleset snapshot directory not found: {snapshot}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotError(f"snapshot {snapshot} has no {MANIFEST_FILE}") from exc
    except OSError as exc:
        raise SnapshotError(f"{path} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise SnapshotError(f"{path} must contain a JSON object, got {type(document).__name__}")

    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise SnapshotError(f"{path} lists no sources, so no alert could be attributed")

    admissions = tuple(_build(SourceAdmission, entry, path) for entry in raw_sources)
    return _build(SnapshotManifest, {**document, "sources": admissions}, path)


def sid_source_index(snapshot: Path, manifest: SnapshotManifest) -> dict[int, str]:
    """Map every SID that can fire to the source it came from.

    `eve.json` carries no source, so this is rebuilt from the snapshot: the SIDs in
    ``rules.rules`` are the ones that can fire, and ``raw/<source>.rules`` says which source
    each came from (spec §7). Intersecting the two is deliberate — ``raw/`` is the text *as
    fetched*, so it also holds rules admission rejected, and those can never alert.

    Every failure here is hard, because each one would otherwise surface as a label carrying
    the wrong source or no source at all:

    * no ``raw/`` files → nothing to attribute *from*;
    * a ``raw/`` source the manifest does not list → the two disagree about the snapshot;
    * one SID claimed by two sources → ambiguous, and never resolved by picking one;
    * an admitted SID no source claims → a rule that can fire and cannot be traced.
    """
    rules = snapshot / RULES_FILE
    try:
        admitted = _sids(rules.read_text(encoding="utf-8").splitlines(), strict=True, origin=rules)
    except FileNotFoundError as exc:
        raise SnapshotError(f"snapshot {snapshot} has no {RULES_FILE}") from exc
    except OSError as exc:
        raise SnapshotError(f"{rules} could not be read: {exc}") from exc

    if not admitted:
        raise SnapshotError(
            f"{rules} contains no rules. Suricata treats that as a warning and exits 0 with "
            f"an empty alert set, which is indistinguishable from a capture that contained "
            f"nothing — so it fails here instead."
        )

    known = {admission.name for admission in manifest.sources}
    index: dict[int, str] = {}
    ambiguous: dict[int, set[str]] = {}

    raw_root = snapshot / RAW_DIR
    raw_files = sorted(raw_root.rglob("*.rules")) if raw_root.is_dir() else []
    if not raw_files:
        raise SnapshotError(
            f"snapshot {snapshot} has no {RAW_DIR}/<source>.rules files, so no alert could be "
            f"attributed to a source. eve.json does not carry the source, and a label whose "
            f"origin cannot be traced must never be emitted (spec §13)."
        )

    for path in raw_files:
        name = path.relative_to(raw_root).with_suffix("").as_posix()
        if name not in known:
            raise SnapshotError(
                f"{path} holds rules for source {name!r}, which {MANIFEST_FILE} does not "
                f"list. The manifest is the authority on which sources a snapshot contains "
                f"and on whether each may label."
            )
        for sid in _sids(path.read_text(encoding="utf-8").splitlines()) & admitted:
            owner = index.get(sid)
            if owner is not None and owner != name:
                ambiguous.setdefault(sid, {owner}).add(name)
            index[sid] = name

    if ambiguous:
        detail = ", ".join(
            f"{sid} ({', '.join(sorted(names))})" for sid, names in sorted(ambiguous.items())
        )
        raise SnapshotError(
            f"snapshot {snapshot} claims the same SID from more than one source: {detail}. "
            f"A detection is never attributed by guess, so the snapshot must be rebuilt "
            f"without the collision."
        )

    unattributed = sorted(admitted - set(index))
    if unattributed:
        raise SnapshotError(
            f"snapshot {snapshot} admits SIDs no source claims: {unattributed}. Each could "
            f"fire and could not be traced to a source, which also means we cannot tell "
            f"whether it may label (spec §2.8)."
        )
    return index


def _sids(lines: Iterable[str], *, strict: bool = False, origin: Path | None = None) -> set[int]:
    """The SIDs of the active rules in `lines`.

    Blank lines and comments are skipped — ``raw/`` text is as fetched, and real feeds ship
    both, as well as disabled ``#alert`` rules that were never admitted. `strict` is for
    ``rules.rules``, where an active rule without a SID is a broken snapshot rather than
    noise to skip.
    """
    found: set[int] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = SID.search(stripped)
        if match is None:
            if strict:
                raise SnapshotError(
                    f"{origin} has an active rule with no sid, which cannot be attributed to "
                    f"a source: {stripped[:120]}"
                )
            continue
        found.add(int(match.group(1)))
    return found


def _build(kind: type, values: Mapping[str, Any], path: Path) -> Any:
    """Construct a frozen dataclass from `values`, rejecting missing and unknown keys.

    Unknown keys are rejected rather than ignored: a manifest key we do not understand means
    the writer and the reader disagree about the format, and continuing would mean reading a
    document whose meaning we have guessed at.
    """
    expected = {field.name for field in fields(kind)}
    missing = sorted(expected - set(values))
    unknown = sorted(set(values) - expected)
    if missing or unknown:
        problems = []
        if missing:
            problems.append(f"missing {', '.join(missing)}")
        if unknown:
            problems.append(f"unknown field(s) {unknown}")
        raise SnapshotError(f"{path}: {kind.__name__} has {'; '.join(problems)}")
    try:
        return kind(**values)
    except (TypeError, ValueError) as exc:
        # ValueError covers the models' own Literal checks — an unknown `source_class` lands
        # here, and getting that wrong changes whether a source may label.
        raise SnapshotError(f"{path}: invalid {kind.__name__}: {exc}") from exc


# --- eve.json ------------------------------------------------------------------------------


def _read_eve(
    path: Path, index: Mapping[int, str], sources: Mapping[str, SourceAdmission]
) -> tuple[list[Detection], int, int, int | None]:
    """Parse `path` in one pass.

    Returns the detections that may label, the total alert count, how many were suppressed,
    and the engine's rule-load count if the stats event reported one. One pass because
    eve.json also holds every flow, http and tls record of the run and can be large.
    """
    detections: list[Detection] = []
    alerts_total = 0
    suppressed = 0
    loaded: int | None = None

    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                # Suricata exited 0, so a record it cannot have finished writing means
                # something we do not understand happened. Raised rather than skipped: a
                # dropped alert is a missing label, and silence must not stand for it.
                raise ToolError(f"{path} line {number} is not valid JSON: {exc}") from exc

            event = record.get("event_type")
            if event == "stats":
                # Not `or`: a reported zero is an answer — every rule failed to parse — and
                # must not be mistaken for "the stats record said nothing".
                reported = _rules_loaded_from_stats(record)
                loaded = reported if reported is not None else loaded
                continue
            if event != "alert":
                continue

            alerts_total += 1
            detection = _detection(record, index, sources, path, number)
            if detection is None:
                suppressed += 1
            else:
                detections.append(detection)

    return detections, alerts_total, suppressed, loaded


def _detection(
    record: Mapping[str, Any],
    index: Mapping[int, str],
    sources: Mapping[str, SourceAdmission],
    path: Path,
    number: int,
) -> Detection | None:
    """One alert record as a `Detection`, or None if its source may not label.

    None rather than a flag on the object: a suppressed alert must not exist as something a
    later stage could accidentally read past (spec §2.8).
    """
    alert = record.get("alert")
    if not isinstance(alert, dict) or "signature_id" not in alert:
        raise ToolError(f"{path} line {number} is an alert with no alert.signature_id")

    sid = int(alert["signature_id"])
    source = index.get(sid)
    if source is None:
        # Cannot happen with `-S`: only snapshot rules are loaded and every admitted SID was
        # attributed up front. Checked anyway, because the alternative to failing here is
        # emitting a label with an invented origin.
        raise SnapshotError(
            f"{path} line {number}: alert on sid {sid}, which belongs to no source in the "
            f"snapshot. Only the snapshot's rules were loaded, so this should be impossible."
        )

    admission = sources[source]
    spec = SourceSpec(
        name=admission.name,
        url=admission.url,
        licence=admission.licence,
        source_class=admission.source_class,
        admission_basis=admission.admission_basis,
    )
    if not spec.may_label:
        return None

    category = alert.get("category") or None
    return Detection(
        source=source,
        tier=TIER,
        sid=sid,
        rev=int(alert.get("rev", 0)),
        classtype=category,
        app_proto=record.get("app_proto"),
        threat=str(alert.get("signature", "")),
        ts=_epoch(record.get("timestamp"), path, number),
        src_ip=str(record.get("src_ip", "")),
        src_port=int(record.get("src_port", 0)),
        dst_ip=str(record.get("dest_ip", "")),
        dst_port=int(record.get("dest_port", 0)),
        # Lowercased: Suricata writes `TCP`, Zeek's conn.log writes `tcp`, and correlation
        # matches the two 5-tuples field by field (spec §9). Zeek's spelling wins because
        # `Flow` is built from conn.log.
        proto=str(record.get("proto", "")).lower(),
        metadata=_metadata(alert.get("metadata")),
    )


def _epoch(timestamp: Any, path: Path, number: int) -> float:
    """An eve timestamp as seconds since the epoch.

    Suricata writes local time with an offset (``2023-11-14T14:13:20.050000-0800``); Zeek
    writes epoch seconds. Converting here means correlation compares two numbers on one
    timeline instead of reconciling two formats (spec §9).
    """
    if not isinstance(timestamp, str):
        raise ToolError(f"{path} line {number}: alert has no timestamp")
    try:
        return datetime.fromisoformat(timestamp).timestamp()
    except ValueError as exc:
        raise ToolError(
            f"{path} line {number}: unparseable timestamp {timestamp!r}: {exc}"
        ) from exc


def _metadata(raw: Any) -> tuple[str, ...]:
    """`alert.metadata` flattened to sorted ``"key value"`` strings.

    Suricata reports metadata as an object of key → list of values; the rule wrote them as
    ``metadata:confidence High, signature_severity Major``. Flattened back to that spelling
    so issue #10 (should untagged ET rules be admitted?) can be answered from what the rule
    actually said, and sorted so the value is reproducible.
    """
    if not isinstance(raw, dict):
        return ()
    flattened = []
    for key, values in raw.items():
        if isinstance(values, list):
            flattened.extend(f"{key} {value}" for value in values)
        else:
            flattened.append(f"{key} {values}")
    return tuple(sorted(flattened))


# --- engine reporting ----------------------------------------------------------------------


def _rules_loaded_from_stats(record: Mapping[str, Any]) -> int | None:
    """`detect.engines[].rules_loaded` from an eve stats record."""
    stats = record.get("stats")
    detect = stats.get("detect") if isinstance(stats, dict) else None
    engines = detect.get("engines") if isinstance(detect, dict) else None
    if not isinstance(engines, list) or not engines:
        return None
    counts = [engine.get("rules_loaded") for engine in engines if isinstance(engine, dict)]
    numbers = [count for count in counts if isinstance(count, int)]
    return max(numbers) if numbers else None


def _rules_loaded_from_log(path: Path) -> int | None:
    """The load count Suricata prints to ``suricata.log``.

    Fallback for a configuration with eve stats switched off. The engine's own count is used
    rather than the snapshot's rule count because a rule that failed to parse never fires,
    and reporting it as loaded would overstate what the run actually looked for.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    matches = RULES_LOADED.findall(text)
    return int(matches[-1]) if matches else None


def _version() -> tuple[str, ToolFailure | None]:
    """Suricata's version, or the failure that stopped us getting it.

    ``suricata --version`` does not exist — it exits 1 with "unrecognized option". ``-V`` is
    the flag (verified on 8.0.6), which is also why this is not a one-liner.
    """
    argv = [BINARY, "-V"]
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as exc:
        return "unknown", _failure(argv, None, f"suricata is not runnable: {exc}")
    if completed.returncode != 0:
        return "unknown", _failure(
            argv,
            completed.returncode,
            f"suricata -V failed: {_tail(completed.stderr or completed.stdout)}",
        )
    # Version output lands on stdout here, but both streams are read: the flag that reports it
    # is already a version-specific quirk, so which stream carries it is not worth assuming.
    match = VERSION.search(completed.stdout + completed.stderr)
    if match is None:
        return "unknown", _failure(
            argv,
            completed.returncode,
            f"suricata reported no parseable version: {completed.stdout.strip()!r}",
        )
    return match.group(0), None


# --- plumbing ------------------------------------------------------------------------------


def _prepare_outdir(outdir: Path) -> None:
    """Create `outdir`, refusing to reuse one that already holds a Suricata run.

    Suricata *appends* to ``eve.json``. Reusing a directory would silently fold a previous
    run's alerts into this one's labels, which is both a wrong answer and a modification of a
    previous run directory (spec §13).
    """
    if (outdir / EVE_FILE).exists():
        raise ToolError(
            f"{outdir / EVE_FILE} already exists. Suricata appends to it, so a previous "
            f"run's alerts would be read as this run's. Use a fresh output directory."
        )
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ToolError(f"suricata output directory {outdir} could not be created: {exc}") from exc


def _failure(argv: Sequence[str], exit_code: int | None, message: str) -> ToolFailure:
    """A `ToolFailure` for this tool, with the argv that produced it.

    The argv is recorded rather than just the message so a failure can be reproduced by
    pasting one line into a shell (spec §11).
    """
    return ToolFailure(tool=BINARY, argv=tuple(argv), exit_code=exit_code, message=message)


def _failed(
    manifest: SnapshotManifest, failure: ToolFailure, version: str = "unknown"
) -> SuricataRunInfo:
    """A run info carrying nothing but the failure — and the snapshot id.

    The snapshot id survives because the run block must still say which ruleset was
    attempted; a failed run that cannot say what it tried is a worse artifact than one that
    reports both.
    """
    return SuricataRunInfo(
        version=version,
        snapshot_id=manifest.snapshot_id,
        rules_loaded=0,
        alerts_total=0,
        identify_alerts_suppressed=0,
        tool_failures=(failure,),
    )


def _tail(output: str, limit: int = 400) -> str:
    """The last of a tool's output, for a failure message that fits on a screen."""
    text = " ".join(output.split())
    return text[-limit:] if len(text) > limit else text
