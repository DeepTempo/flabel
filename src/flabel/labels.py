"""Canonical serialisation of `labels.json` (spec §4, §10).

Pure: no `subprocess`, no `urllib`, no `socket`. Enforced by `tests/test_architecture.py`.
It does not write files either — step 9 owns the run directory, and this module owns only what
the bytes look like.

**Goal 2 lives here.** "Two runs over the same capture and the same snapshot are identical" is
a claim about this module and almost nothing else: every other stage is deterministic already,
and the one place determinism can be lost is a serialiser that lets input order, dict insertion
order, host timezone or locale through into the output. So each rule below is a contract:

* every array is explicitly ordered — `labels` by `(ts_first, uid)`, a label's own assertions by
  `name`, a label's `sources` by `(tier, source, sid, rev, direction)`, `unmatched_detections` by
  `(ts, source, sid)`. The assertions were missing from this list when #138 added them, which is
  the failure mode this docstring exists to prevent: the order was enforced in `models.py` and the
  document claiming to enumerate what must be ordered did not mention it (#140);
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

from flabel.models import Detection, Flow, Label, UnmatchedDetection

#: Spec §4. `provenance.py` reads it from here so the document root and the run block cannot
#: disagree.
#:
#: **2.0 as of 2026-08-19 (#138), and the first genuine break.** `labels[]` replaced the top-level
#: `verdict` field, so a 1.0 consumer reading a 2.0 document finds no `verdict` key at all — it does
#: not degrade, it fails. Every previous change was argued as additive and kept 1.0: a Phase 1 field
#: (#115), Phase 2's tier-1 entries in `sources[]` (Goal 6), and #132's widened `run.mode`, which
#: held because no document a consumer could already have changed shape. None of those arguments is
#: available here.
#:
#: The major digit moved rather than the minor, because the version exists to tell a reader whether
#: they can parse the document, and the answer changed from yes to no.
SCHEMA_VERSION = "2.0"

#: Spec §10's one timestamp format. `rules.utc_now` writes the same shape for `fetched_at` and
#: `created_at`; the two `strftime` calls cannot be merged without editing a module this step
#: does not own, so `test_labels.py` asserts they agree instead.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

INDENT = 2

#: Model fields holding an epoch float that serialises as an ISO-8601 string. Named per model
#: because they are the only fields whose JSON representation differs from the dataclass's.
#:
#: Keyed by the class rather than by its name: a string key silently stops matching the day a
#: model is renamed, and the failure is a timestamp that quietly serialises as a float instead
#: of an error anyone would see.
_EPOCH_FIELDS: dict[type, tuple[str, ...]] = {
    Flow: ("ts_first", "ts_last"),
    Detection: ("ts",),
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
    label to exist — a capture where nothing fired is the ordinary case, not a failure.
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

    **This returns text. Write it with `serialise_bytes`, not `Path.write_text`** — see there.
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


def serialise_bytes(document: Mapping[str, Any]) -> bytes:
    """`document` as canonical UTF-8 bytes — what a caller writes to disk.

    The encoding is not the caller's choice to make. `ensure_ascii=False` (spec §10) means the
    output carries whatever non-ASCII characters a third-party rule's `msg:` text contains, and
    `Path.write_text` encodes with the **locale** encoding, not UTF-8. Under `LANG=C` or
    `LC_ALL=POSIX` — the default in many container images, cron environments and CI runners —
    that is ASCII, so writing a label whose threat text contains one accented character raises
    `UnicodeEncodeError` *after the entire pipeline has succeeded*. Under a cp1252 locale it
    does not raise at all; it writes mojibake into the ground-truth file.

    Neither failure can be caught by a test that inspects the returned string, which is why the
    encoding is bound here rather than documented and hoped for. `labels.json` and `run.json`
    are UTF-8 by definition — JSON has no other interchange encoding.
    """
    return serialise(document).encode("utf-8")


# --- ordering (spec §10) --------------------------------------------------------------------
#
# `uid` and `sid` are tiebreaks rather than decoration: two flows can share a `ts_first` to the
# microsecond, and two detections a `ts`. Without the tiebreak their order falls back to input
# order, which differs between runs and breaks Goal 2 in a way no fixture reliably reproduces.


def _label_key(label: Label) -> tuple[float, str]:
    return (label.flow.ts_first, label.flow.uid)


def _entry_key(entry: Any) -> tuple[int, str, int, int, str]:
    # `direction` is in the key because entries that differ only by it are now possible — one
    # rule matching both halves of a flow (#115) — and eve.json's record order is not guaranteed
    # stable between runs. Must stay identical to `correlate._source_order`, which sorts the same
    # tuple first; `test_the_two_sort_keys_are_the_same_key` asserts they have not drifted.
    return (entry.tier, entry.source, entry.sid, entry.rev, entry.direction)


def _unmatched_key(entry: UnmatchedDetection) -> tuple[float, str, int]:
    return (entry.detection.ts, entry.detection.source, entry.detection.sid)


# --- record serialisation --------------------------------------------------------------------


def _record(instance: Any) -> dict[str, Any]:
    """One dataclass as a JSON object, with its epoch fields converted.

    `asdict` rather than a literal, so a field added to a model reaches the file without
    anyone remembering to add it here.
    """
    fields = dataclasses.asdict(instance)
    for name in _EPOCH_FIELDS.get(type(instance), ()):
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
