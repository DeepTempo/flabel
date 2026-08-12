"""Canonical serialisation of `labels.json` (spec §4, §10).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.
It does not write files either — step 9 owns the run directory, and this module owns only what
the bytes look like.

**Goal 2 lives here.** "Two runs over the same capture and the same snapshot are identical" is
a claim about this module and almost nothing else: every other stage is deterministic already,
and the one place determinism can be lost is a serialiser that lets input order, dict insertion
order, host timezone or locale through into the output. So each rule below is a contract:

* every array is explicitly ordered — `labels` by `(ts_first, uid)`, a label's `sources` by
  `(tier, source, sid, rev)`, `unmatched_detections` by `(ts, source, sid)`;
* object keys are sorted by the encoder rather than by construction order;
* every moment in time is one format — ISO-8601 UTC, microsecond precision, `Z` suffix — so an
  epoch float never reaches a slot a reader will parse as a string;
* `ensure_ascii=False`, because rule `msg:` text is not guaranteed ASCII and escaping it would
  make two equivalent files differ in bytes.

Serialisation goes through `dataclasses.asdict` rather than field-by-field literals. A
hand-written `{"uid": ..., "src_ip": ...}` is correct exactly until a model gains a field, and
then it silently stops carrying it — a value computed, carried through the whole pipeline, and
never written down. The timestamp fields are the only ones named explicitly, because they are
the only ones whose representation differs from the model's.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from flabel.models import Label, UnmatchedDetection

#: Spec §4. Does **not** change when Phase 2 adds tier-1 entries to `sources[]` (Goal 6).
#: `provenance.py` reads it from here so the document root and the run block cannot disagree.
SCHEMA_VERSION = "1.0"

#: Spec §10's one timestamp format. `rules.utc_now` writes the same shape for `fetched_at` and
#: `created_at`; the two `strftime` calls cannot be merged without editing a module this step
#: does not own, so `test_labels.py` asserts they agree instead.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

INDENT = 2

#: Model fields holding an epoch float that serialises as an ISO-8601 string. Named per model
#: because they are the only fields whose JSON representation differs from the dataclass's.
_EPOCH_FIELDS: dict[str, tuple[str, ...]] = {
    "Flow": ("ts_first", "ts_last"),
    "Detection": ("ts",),
}


def iso_from_epoch(ts: float) -> str:
    """An epoch seconds value in flabel's one timestamp format.

    `UTC` is passed explicitly: `datetime.fromtimestamp(ts)` without a tzinfo returns *local*
    time, which is invisible on a UTC CI runner and silently wrong by whole hours everywhere
    else. Spec §10 forbids locale-dependent formatting for the same reason.

    Sub-microsecond precision is lost, which is what "microsecond precision" in spec §10 means.
    The conversion is deterministic for a given float, so Goal 2 is unaffected.
    """
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise ValueError(f"timestamp {ts!r} is not a number of seconds since the epoch")
    try:
        return datetime.fromtimestamp(ts, UTC).strftime(TIMESTAMP_FORMAT) + "Z"
    except (OverflowError, OSError, ValueError) as exc:
        # A bare OverflowError from deep inside the encoder tells an operator nothing about
        # which record carried the impossible value.
        raise ValueError(f"timestamp {ts!r} cannot be expressed as a UTC datetime: {exc}") from exc


def build_document(
    *,
    run: Mapping[str, Any],
    labels: Sequence[Label],
    unmatched: Sequence[UnmatchedDetection],
) -> dict[str, Any]:
    """The whole `labels.json` document, ordered but not yet encoded (spec §4).

    `run` arrives already assembled — `provenance.build_run_block` builds it — so this module
    never has to know what a run block contains, and a run block can be written on its own to
    `run.json` when there is no `labels.json` to put it in (issue #23).

    An empty `labels` is a real result and produces a real document. Nothing here requires a
    verdict to exist.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "run": dict(run),
        "labels": [_label(label) for label in sorted(labels, key=_label_key)],
        "unmatched_detections": [
            _unmatched(entry) for entry in sorted(unmatched, key=_unmatched_key)
        ],
    }


def serialise(document: Mapping[str, Any]) -> str:
    """`document` as canonical JSON text, trailing newline included (spec §10).

    Takes any already-built mapping, so the same canonical form covers `labels.json` and the
    `run.json` that a failed run writes in its place.

    Two encoder settings are load-bearing beyond spec §10's list:

    * no `default=` hook — an unconverted dataclass must raise rather than serialise as its
      `repr`, which would be a string that looks like data and parses as nothing;
    * `allow_nan=False` — the default emits bare `NaN`/`Infinity`, which Python reads back and
      no strict JSON parser accepts, so a non-finite ratio would ship a file that only looks
      valid from inside this project.
    """
    return (
        json.dumps(
            document,
            sort_keys=True,
            indent=INDENT,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


# --- ordering (spec §10) --------------------------------------------------------------------
#
# `uid` and `sid` are tiebreaks rather than decoration: two flows can share a `ts_first` to the
# microsecond, and two detections a `ts`. Without the tiebreak their order falls back to input
# order, which differs between runs and breaks Goal 2 in a way no fixture reliably reproduces.


def _label_key(label: Label) -> tuple[float, str]:
    return (label.flow.ts_first, label.flow.uid)


def _entry_key(entry: Any) -> tuple[int, str, int, int]:
    return (entry.tier, entry.source, entry.sid, entry.rev)


def _unmatched_key(entry: UnmatchedDetection) -> tuple[float, str, int]:
    return (entry.detection.ts, entry.detection.source, entry.detection.sid)


# --- record serialisation --------------------------------------------------------------------


def _record(instance: Any) -> dict[str, Any]:
    """One dataclass as a JSON object, with its epoch fields converted.

    `asdict` rather than a literal, so a field added to a model reaches the file without
    anyone remembering to add it here.
    """
    fields = dataclasses.asdict(instance)
    for name in _EPOCH_FIELDS.get(type(instance).__name__, ()):
        fields[name] = iso_from_epoch(fields[name])
    return fields


def _label(label: Label) -> dict[str, Any]:
    record = _record(label)
    # `asdict` already recursed into the flow and the sources; both are replaced so the nested
    # timestamps are converted and the sources come out in canonical order.
    record["flow"] = _record(label.flow)
    record["sources"] = [_record(entry) for entry in sorted(label.sources, key=_entry_key)]
    return record


def _unmatched(entry: UnmatchedDetection) -> dict[str, Any]:
    record = _record(entry)
    record["detection"] = _record(entry.detection)
    return record
