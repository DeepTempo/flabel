"""Canonical comparison of run directories — Goal 2's primitive (docs/spec.md §10).

Reproducibility is defined over **records after canonicalisation**, not over bytes. Spec §10
originally claimed byte-identity excluding three timestamps and one log; that claim is
unachievable and was corrected in step 5. Every Zeek TSV log carries `#open` and `#close`
wall-clock headers, so *no* Zeek log is byte-identical across two runs and a byte comparison
would fail on all of them rather than on the one named.

A filename exclusion list is also the wrong shape for the problem: it forces a whole log to be
dropped over a single wall-clock line inside it. So this module canonicalises, and excludes only
where a file has no analytic content at all.

**This is a shared primitive, not test-local.** `zeek.reproducible_logs` was the knowingly
incomplete stopgap it replaces — it names files, which cannot express "this file is reproducible
except for one column".

Pure: no `subprocess`, no `urllib`, no `socket`. It reads files, which is I/O in the ordinary
sense but not the sense the architecture guard polices — the guard exists to keep network and
process launching out of the modules that decide what a label means.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from flabel.models import is_partial

#: Excluded outright, because neither file has any analytic content to compare.
#:
#: `zeek/packet_filter.log` is nothing but a wall-clock start time. `suricata/suricata.log`
#: carries a wall-clock timestamp *and* a pid on every line. Both are retained on disk rather
#: than deleted — deleting a log the tool wrote would misrepresent the run — and simply never
#: compared. Kept small and justified per name: an exclusion list that can be appended to without
#: argument is how a failing gate gets made to pass.
EXCLUDED_FILES = frozenset({"zeek/packet_filter.log", "suricata/suricata.log"})

#: Canonicalised by its own rule rather than excluded — see `canonical_reporter_records`.
REPORTER_LOG = "zeek/reporter.log"

#: Only the `stats` records inside it are excluded — see `canonical_eve_records`.
EVE_LOG = "suricata/eve.json"

#: Suricata's internal per-run key joining an alert to its flow record. Measured on 8.0.6: the
#: same alert on the same packet carried 1464040180 in one run and 1271398021 in the next.
#: flabel never reads it — correlation is by 5-tuple and time (spec §9) — so it is dropped rather
#: than allowed to fail Goal 2 over a value that says nothing about the capture.
EVE_RUN_LOCAL_KEY = "flow_id"

#: Why Suricata stopped tracking a flow, dropped from `flow` records for the same reason and on
#: the same evidence. Measured over 14 consecutive runs of the benign canary: 13 reported
#: `("shutdown", "shutdown")` and one reported `("shutdown", "timeout")`. It records whether the
#: engine's flow manager timed a flow out before end-of-pcap or flushed it at shutdown — a race
#: against wall-clock, not a fact about the capture.
#:
#: A ~7% flake rate is worse for a gate than a field that always differs: it passes often enough
#: to look sound, then fails for no reason anyone can reproduce, and a gate that cries wolf gets
#: switched off. Everything else on a `flow` record — the packet and byte counts, the TCP state —
#: still compares, so a run where Suricata genuinely saw different traffic still fails.
EVE_FLOW_LOCAL_FIELDS = ("reason",)

#: The JSON documents whose run block carries wall-clock fields.
DOCUMENTS = frozenset({"labels.json", "run.json"})

#: Wall-clock by definition (spec §10).
EXCLUDED_RUN_KEYS = ("started_at", "finished_at", "duration_seconds")

#: The operator's own path, which differs by where they ran flabel rather than by anything about
#: the run. Excluding it is what lets the same capture labelled from two directories compare
#: equal; `input.sha256` still identifies the file, so a *different* capture is still a
#: difference.
EXCLUDED_INPUT_KEYS = ("path",)

COMMENT = "#"


def canonical_records(text: str) -> tuple[str, ...]:
    """The analytic records of a Zeek TSV log: every line that is not a `#` header.

    `#open` and `#close` are where Zeek puts wall-clock time, so this is the whole of what makes
    two runs' logs comparable at all.
    """
    return tuple(line for line in text.splitlines() if line and not line.startswith(COMMENT))


def canonical_reporter_records(text: str) -> tuple[str, ...]:
    """`reporter.log` records without their `ts` column (spec §10, corrected in step 10).

    **Measured on Zeek 8.0.4, 2026-08-13**, two consecutive runs over one capture 1.4s apart:

        run a   1786644711.886324   Reporter::WARNING   startup message
        run b   1786644713.298930   Reporter::WARNING   startup message
        both    1700000000.000000   Reporter::WARNING   packet-time message

    A message raised in `zeek_init` carries **wall-clock** time in `ts` even under `-D`; a message
    raised while reading packets carries **network** time and is identical run to run. Spec §10
    named both halves correctly and then defined canonicalisation as "drop `#`-prefixed header
    lines", which is not enough for this file: the differing value is in a record, not a header.

    The two classes are interleaved in one file and cannot be told apart from content — a
    wall-clock reading and a packet time are both floats, and a capture recorded today would have
    packet times indistinguishable from now. So the `ts` column goes and everything else stays.

    Dropping the column rather than the file is the point. `reporter.log` is where Zeek records
    protocol violations, which is exactly what Goal 3 wants reported; excluding it wholesale
    would hide them. Level, message and location are that content. *When* a reporter message was
    emitted is not something a reproducibility gate needs to police, and for startup messages it
    provably cannot.
    """
    return tuple(
        record.split("\t", 1)[1] if "\t" in record else record for record in canonical_records(text)
    )


def canonical_eve_records(text: str) -> tuple[str, ...]:
    """Suricata's `eve.json`, reduced to what two runs must genuinely agree on (spec §10).

    Three rules, and **two of them are corrections to spec §10 measured in step 10**. §10 said
    the `stats` records are excluded because "`alert` and `flow` records are byte-stable". The
    exclusion is right and the reason given for keeping the rest was wrong: measured on Suricata
    8.0.6 over the benign canary, two consecutive runs differ in more than `stats`.

    **`stats` records are dropped.** Wall-clock counters — uptime, packets per second. Only the
    `stats` records: the alerts are precisely what a reproducibility gate over a labelling tool
    should compare, so excluding the file wholesale would exclude the evidence.

    **`flow_id` is dropped from every record.** Measured: the same alert on the same packet in
    two runs carried `flow_id` 1464040180 and 1271398021. It is Suricata's internal per-run key
    joining an alert to its flow record, and flabel never reads it — correlation is by 5-tuple
    and time (spec §9). Keeping it would fail Goal 2 on every run for a value that says nothing
    about the capture.

    **`flow.reason` is dropped.** Measured over 14 consecutive runs of the benign canary: 13
    reported `("shutdown", "shutdown")` and one reported `("shutdown", "timeout")`. It says
    whether the flow manager timed a flow out before end-of-pcap or flushed it at shutdown,
    which is a race against wall-clock rather than anything about the capture. A ~7% flake rate
    is worse than a field that always differs — it passes often enough to look sound, then fails
    unreproducibly, and a gate that cries wolf gets switched off.

    **The records are sorted.** Measured: the two `flow` records for the canary's two connections
    appear in one order in one run and the reverse in the next, so a positional comparison
    reports four fields differing when nothing differs at all. This is the same reasoning spec
    §10 already applies to `labels` and `unmatched_detections` — "two runs can legitimately
    produce flows in different orders, and the canonical form must erase that difference rather
    than record it". Sorting cannot hide a lost or duplicated record: the multiset is compared,
    so a count that changes still shows.

    Each record is re-encoded with sorted keys, so two runs cannot differ over key order either.

    A line that will not parse raises rather than being skipped: dropping it would let a
    truncated or corrupted `eve.json` compare equal to a healthy one, which is the failure this
    module exists to prevent.
    """
    records = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{EVE_LOG} line {number} is not valid JSON ({exc}). A record that cannot be "
                f"read is a difference between two runs, not a line to skip."
            ) from exc
        if record.get("event_type") == "stats":
            continue
        record.pop(EVE_RUN_LOCAL_KEY, None)
        flow = record.get("flow")
        if isinstance(flow, dict):
            for field in EVE_FLOW_LOCAL_FIELDS:
                flow.pop(field, None)
        records.append(json.dumps(record, sort_keys=True))
    return tuple(sorted(records))


def canonical_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """A `labels.json` or `run.json` with spec §10's excluded fields removed.

    Copies rather than edits: the caller's document is theirs, and a gate that mutates what it
    inspects is a trap for the next reader.
    """
    reduced = dict(document)
    run = reduced.get("run")
    if isinstance(run, Mapping):
        run = {key: value for key, value in run.items() if key not in EXCLUDED_RUN_KEYS}
        section = run.get("input")
        if isinstance(section, Mapping):
            # `input` is `null` on a run that died before ingest, which is not an error here.
            run["input"] = {
                key: value for key, value in section.items() if key not in EXCLUDED_INPUT_KEYS
            }
        reduced["run"] = run
    return reduced


def canonicalise(rundir: Path) -> dict[str, Any]:
    """Everything in `rundir` that two runs over one capture must produce identically.

    Keyed by POSIX-style relative path, so the comparison is stable across platforms and a file
    that exists in only one of two runs is visible as a missing key rather than as nothing.
    """
    rundir = Path(rundir)
    canonicalised: dict[str, Any] = {}

    for path in sorted(rundir.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(rundir).as_posix()
        if name in EXCLUDED_FILES:
            continue
        # An in-progress write left behind by a killed process (issue #70). Not an artifact
        # the run claims, so comparing it would report a difference for a file neither run
        # meant to publish — a crash surfacing as a reproducibility failure.
        if is_partial(name):
            continue
        canonicalised[name] = _canonical_file(name, path)

    return canonicalised


def differences(first: Path, second: Path) -> list[str]:
    """Human-readable differences between two run directories, or an empty list.

    A list of sentences rather than a bare boolean because a failing reproducibility gate that
    says only "these differ" is a gate nobody can act on: the first question is always *which
    file*, and the second is *which record*.
    """
    left, right = canonicalise(first), canonicalise(second)
    reported: list[str] = []

    for name in sorted(set(left) | set(right)):
        if name not in left:
            reported.append(f"{name}: present in {second} but not in {first}")
        elif name not in right:
            reported.append(f"{name}: present in {first} but not in {second}")
        elif left[name] != right[name]:
            reported.append(
                f"{name}: differs after canonicalisation{_detail(left[name], right[name])}"
            )

    return reported


def _canonical_file(name: str, path: Path) -> Any:
    """One file's comparable content, by the rule that applies to it."""
    text = path.read_text(encoding="utf-8")
    if name == REPORTER_LOG:
        return canonical_reporter_records(text)
    if name == EVE_LOG:
        return canonical_eve_records(text)
    if name in DOCUMENTS:
        return canonical_document(json.loads(text))
    if name.endswith(".log"):
        return canonical_records(text)
    # NOTICE and anything else: compared verbatim. NOTICE is generated deterministically from the
    # snapshot and the labels, so it has no wall-clock content to canonicalise away.
    return text


def _detail(left: Any, right: Any) -> str:
    """The first differing record, when both sides are sequences of them."""
    if not (isinstance(left, tuple) and isinstance(right, tuple)):
        return ""
    for index, (one, other) in enumerate(zip(left, right, strict=False)):
        if one != other:
            return f" — first at record {index}: {one!r} != {other!r}"
    return f" — {len(left)} vs {len(right)} records"
