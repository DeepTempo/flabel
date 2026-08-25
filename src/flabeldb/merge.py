"""The merge rule (spec-label-store §5.1, §5.2) — implemented **once**, here, in Python.

**The newest non-excluded run that attested tier T supplies tier T for that capture. Tiers
compose; they do not overwrite each other.** `authoritative_runs` answers which run that is; this
module does everything after, and revision 1's SQL copy of the rule is gone (§5.2, §9).

Pure, and that is the point: §2's testing line records that the `requires_bigquery` tests run
nowhere but `fl-replay`, so a merge behind a client would be the rule the store exists to express
with nothing on every push able to check it. `query.py` fetches rows, this module composes them,
and the seam between them is a list of plain dicts.

**Composition goes through `models.Label`, `models.SourceEntry` and `models.verdict_entry`** — the
same constructors, with the same `__post_init__` invariants, that produced the rows in the first
place. Three consequences are load-bearing:

* The verdict is **rebuilt from the surviving sources** rather than merged from the stored verdict
  entries, and it has to be. A `--both` run's stored verdict entry cites every source's sid; when
  that run is authoritative for tier 1 only, §5.2 rule 2 drops its tier-2 sources and the stored
  entry is left naming sids nothing on the flow carries. `verdict_entry(surviving)` cannot express
  that, which is why §5.2 names the function rather than only the dataclass.
* A row this module cannot construct is a **counted refusal, not a crash** — §9's "LS-7 must
  decide deliberately", answered on §3.2's `ip_proto` precedent: refuse the row, count it, name
  it. A historical row whose (kind, tier) pair falls outside today's `LABEL_KINDS` is data an
  older writer produced legally, and raising on it is how a backfill becomes unrunnable.
* `MergeConflict` is deliberately **not** a `ValueError`, so that refusal path cannot swallow the
  one failure §9 says must never be silent.

`sources` are concatenated and sorted, never de-duplicated: §9 accepts #58's unbounded duplicate
`SourceEntry` values, and collapsing them here would say a rule fired once where two entries
recorded two firings.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from flabel.models import LABEL_KINDS, Flow, Label, LabelEntry, SourceEntry, verdict_entry

#: The `sources` columns, taken from `models.SourceEntry` itself rather than written out again.
#: §4.3's struct and this dataclass are the same eleven fields by construction, so a column the
#: table gains without a model field cannot ride along into a constructor call.
SOURCE_FIELDS = tuple(field.name for field in dataclasses.fields(SourceEntry))

#: `models.Flow`'s fields, and the one rename the store makes: `uid` became `zeek_uid` in §4.3
#: because under `-D` a uid is positional — "connection #N" in every capture — so a column called
#: `uid` invites exactly the cross-run join §3.2 forbids.
FLOW_FIELDS = tuple(field.name for field in dataclasses.fields(Flow))
ZEEK_UID = "zeek_uid"


class MergeConflict(Exception):
    """Two tiers disagree on a single-arity label's value (§5.2, §9).

    **Not a `ValueError`, and that is the guard rather than a note about one.** `compose` refuses
    a row it cannot construct by catching `ValueError` from the model constructors and counting
    it; were this a `ValueError`, the single failure §9 names as one that must never be silent
    would be counted and dropped by that same handler.
    """


class StoreInconsistent(Exception):
    """The store contradicts itself in a way this tool will not resolve on its behalf.

    **Not a `ValueError`, for `MergeConflict`'s reason applied one level up.** `blfile.main` maps
    this to its data-refusal exit code, and a bare `ValueError` there would put a corrupt
    `run_block`'s `json.JSONDecodeError` — and any ordinary coding bug that raises `ValueError` —
    under the same code, reporting a defect in the tool as a disagreement in the dataset.
    """


@dataclasses.dataclass(frozen=True)
class Authority:
    """`authoritative_runs` in our own shape — which run supplies which tier, per capture.

    Both directions are kept because both are asked: `by_capture` answers §6.4's `run_ids` map and
    §6.5's lowest-surviving-tier origin rule, while `by_run` is what the tier filter of §5.2 rule 2
    needs for each row it reads.
    """

    #: `capture_sha256` -> {tier: run_id}
    by_capture: Mapping[str, Mapping[int, str]]
    #: `run_id` -> the tiers that run is authoritative **for**, ascending
    by_run: Mapping[str, tuple[int, ...]]


@dataclasses.dataclass(frozen=True)
class MergedFlow:
    """One flow after composition: everything the authoritative runs jointly assert about it."""

    capture_sha256: str
    flow_key: str
    #: §4.3's `flow` struct verbatim, as the store holds it. Carried rather than rebuilt from
    #: `label.flow` because the struct is a superset — `ip_proto` and the canonical pair are the
    #: content-derived halves of the flow key, and `models.Flow` has nowhere to put them.
    flow: Mapping[str, Any]
    label: Label
    #: `{tier: run_id}`, keys as strings, naming only the tiers that actually contributed a source
    #: to **this** flow. §6.4: `docs/spec.md` §13 requires every assertion to name what produced it.
    run_ids: Mapping[str, str]


@dataclasses.dataclass(frozen=True)
class Merged:
    """The composed flows, and what could not be composed — counted and named, never dropped."""

    flows: tuple[MergedFlow, ...]
    refused: int
    refusal_notes: tuple[str, ...]


def authority(rows: Iterable[Mapping[str, Any]]) -> Authority:
    """`authoritative_runs` rows as an `Authority`.

    A repeated `(capture, tier)` is a **defect in the view**, not data to pick a winner from: the
    window function's `recency = 1` makes it one row, and if two arrive then the very thing §4.6's
    `run_id` tie-break exists to prevent has happened. Raised rather than resolved, and raised as a
    `StoreInconsistent` — which is deliberately not a `ValueError`, so `compose`'s refusal
    handler could not count it even if it were reached from inside one.
    """
    by_capture: dict[str, dict[int, str]] = {}
    by_run: dict[str, set[int]] = {}
    for row in rows:
        capture, tier, run_id = row["capture_sha256"], int(row["tier"]), row["run_id"]
        seen = by_capture.setdefault(capture, {})
        if tier in seen and seen[tier] != run_id:
            raise StoreInconsistent(
                f"authoritative_runs names two runs for capture {capture} tier {tier}: "
                f"{seen[tier]} and {run_id}. The view returns one row per (capture, tier), so "
                f"picking between them here would invent an answer the store does not hold"
            )
        seen[tier] = run_id
        by_run.setdefault(run_id, set()).add(tier)
    return Authority(
        by_capture={
            capture: dict(sorted(tiers.items())) for capture, tiers in sorted(by_capture.items())
        },
        by_run={run_id: tuple(sorted(tiers)) for run_id, tiers in sorted(by_run.items())},
    )


def compose(rows: Iterable[Mapping[str, Any]], auth: Authority) -> Merged:
    """Every `flow_labels` row, composed per §5.2 into one record per flow.

    Rows from a run that is authoritative for nothing are **skipped, not refused**: §2.4 says an
    unattested tier is loaded but does not supersede, so those rows existing is the store working
    as specified rather than anything to report.
    """
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        if row["run_id"] not in auth.by_run:
            continue
        grouped.setdefault((row["capture_sha256"], row["flow_key"]), []).append(row)

    flows: list[MergedFlow] = []
    notes: list[str] = []
    for (capture, flow_key), group in sorted(grouped.items()):
        try:
            merged = _one_flow(capture, flow_key, group, auth)
        except ValueError as error:
            # §9's deliberate decision, on §3.2's precedent. `MergeConflict` is not a `ValueError`
            # and so is not reachable from here — it propagates and fails the build.
            notes.append(f"flow {flow_key} of capture {capture}: {error}")
            continue
        if merged is not None:
            flows.append(merged)
    return Merged(flows=tuple(flows), refused=len(notes), refusal_notes=tuple(notes))


def source_key(entry: SourceEntry) -> tuple[int, str, int, int, str]:
    """`docs/spec.md` §10's ordering for `sources[]`, which §5.2 rule 3 reuses by name.

    **Must stay identical to `labels._entry_key`**, and a test asserts it has not drifted. It is
    written out rather than imported because `tests/test_architecture.py` shares only
    `flabel.models` with this package — `labels.py` is a pipeline module, written for one run at a
    time, and the store is not a second consumer of it.
    """
    return (entry.tier, entry.source, entry.sid, entry.rev, entry.direction)


# --- one flow -----------------------------------------------------------------------------------


def _one_flow(
    capture: str,
    flow_key: str,
    group: Sequence[Mapping[str, Any]],
    auth: Authority,
) -> MergedFlow | None:
    sources: list[SourceEntry] = []
    entries_by_name: dict[str, list[Mapping[str, Any]]] = {}
    run_ids: dict[str, str] = {}
    stored_verdicts: list[tuple[str, Mapping[str, Any]]] = []
    flow_row: Mapping[str, Any] | None = None

    # Lowest authoritative tier first, so the row that supplies the flow struct is the same run
    # §6.5 makes supply the origin. `run_id` is the tie-break for the reason §4.6 gives.
    for row in sorted(group, key=lambda item: (min(auth.by_run[item["run_id"]]), item["run_id"])):
        tiers = auth.by_run[row["run_id"]]
        # §5.2 rule 2: keep only the entries whose tier this run is authoritative FOR. A `--both`
        # run authoritative for tier 1 contributes its tier-1 entries and not its tier-2 ones.
        kept = [item for item in row.get("sources") or () if item.get("tier") in tiers]
        if not kept:
            continue
        if flow_row is None:
            flow_row = row.get("flow") or {}
        for item in kept:
            sources.append(_source(item))
            run_ids[str(item["tier"])] = row["run_id"]
        for entry in row.get("labels") or ():
            if entry.get("name") == "verdict":
                # **The verdict is NOT tier-filtered, and that is not an oversight.** Every source
                # on a flow asserts the verdict, so `LabelEntry.tier` here is a derived
                # `min(sources.tier)` rather than a claim of tier membership — a `--both` run
                # stores its verdict at tier 1 even when the tier it still supplies is 2. Filtering
                # it away left the run shape rule 2 exists for with NO cross-tier value comparison
                # at all (measured 2026-08-25). These are kept only to be checked below; the entry
                # itself is rebuilt from the sources that survived.
                stored_verdicts.append((row["run_id"], entry))
            elif entry.get("tier") in tiers:
                # §5.2's second latent loss: a label whose `LabelEntry.tier` names one tier lives
                # in that tier's slice only, so superseding that tier removes it.
                entries_by_name.setdefault(entry.get("name"), []).append(entry)

    if not sources:
        # Every tier this flow was labelled at has been superseded, or this run supplies no tier
        # the flow carries. Not a refusal: the flow is simply not asserted any more.
        return None

    # §5.2 rule 3: the union, ordered by `docs/spec.md` §10's existing key. Not de-duplicated (#58).
    ordered = tuple(sorted(sources, key=source_key))
    verdict = verdict_entry(ordered)
    _refuse_verdict_conflict(verdict, stored_verdicts)
    labels = [
        verdict,
        *(_merge_entry(name, entries) for name, entries in sorted(entries_by_name.items())),
    ]

    return MergedFlow(
        capture_sha256=capture,
        flow_key=flow_key,
        flow=dict(flow_row or {}),
        label=Label(
            flow=_flow(flow_row or {}),
            # §5.2 rule 5: recomputed, which is what `Label.__post_init__` already asserts.
            best_tier=min(entry.tier for entry in ordered),
            labels=tuple(sorted(labels, key=lambda entry: entry.name)),
            sources=ordered,
        ),
        run_ids=dict(sorted(run_ids.items())),
    )


def _refuse_verdict_conflict(
    rebuilt: LabelEntry, stored: Sequence[tuple[str, Mapping[str, Any]]]
) -> None:
    """The verdict the surviving sources produce must be the verdict the runs actually asserted.

    **`models.verdict_entry` hardcodes `value="malicious"`** (`models.py`), so rebuilding is a
    write, not a read: without this check a stored verdict of any other value is silently rewritten
    to `"malicious"` and published as ground truth — a verdict no run asserted, which is precisely
    what `docs/spec.md` §13 and Goal 1 forbid. Measured 2026-08-25: a single-tier row storing
    `"suspicious"` came out `"malicious"` with nothing raised.

    Checked against **every** contributing run's stored entry rather than only across tiers, which
    is the other half of the same defect. The cross-tier form of this — §5.2's first latent loss and
    §9's "must never silently pick a winner" — is a special case of the comparison below.

    A stored entry with no value is **not** a disagreement. `parse._label` writes `[None]` for an
    archived label whose `value` key was absent, and losing a flow whose sources are intact over a
    field that is then discarded would be a refusal for nothing.
    """
    disagreeing: dict[str, tuple[Any, str]] = {}
    for run_id, entry in stored:
        try:
            value = _single("verdict", entry.get("value"))
        except ValueError:
            continue
        if value != rebuilt.value:
            disagreeing[run_id] = (entry.get("tier"), value)
    if disagreeing:
        raise MergeConflict(
            f"the surviving sources make this flow's verdict {rebuilt.value!r} at tier "
            f"{rebuilt.tier}, but "
            + ", ".join(
                f"run {run_id} asserted {value!r} at tier {tier}"
                for run_id, (tier, value) in sorted(disagreeing.items())
            )
            + ". Publishing the rebuilt value would emit a verdict no run asserted (§5.2, §9, "
            "docs/spec.md §13)"
        )


def _merge_entry(name: str, entries: Sequence[Mapping[str, Any]]) -> LabelEntry:
    """§5.2 rule 4: per name, the entry from the lowest surviving tier, with `sids` unioned."""
    kind = LABEL_KINDS.get(name)
    if kind is None:
        # A kind an older writer produced legally and this build no longer knows. Counted, not
        # fatal — §9's decision. `LabelEntry` would raise the same way one line later; raising here
        # names the kind rather than leaving a reader to infer it from a constructor's message.
        raise ValueError(
            f"label kind {name!r} has no entry in LABEL_KINDS, so its arity and permitted tiers "
            f"are unknown; permitted: {sorted(LABEL_KINDS)}"
        )
    lowest = min(int(entry["tier"]) for entry in entries)
    at_lowest = [entry for entry in entries if int(entry["tier"]) == lowest]
    if len(at_lowest) > 1:
        raise ValueError(
            f"label {name!r} appears {len(at_lowest)} times at tier {lowest} on one flow: one run "
            f"supplies each tier (§4.6), and `Label` forbids a repeated name within a run"
        )

    if kind.arity == "single":
        by_tier = {int(entry["tier"]): _single(name, entry.get("value")) for entry in entries}
        if len(set(by_tier.values())) > 1:
            # §5.2's first latent loss, and §9's "must never silently pick a winner". Rule 4 would
            # discard the higher tier's value; today `verdict` is always "malicious" so nothing is
            # lost, but the rule as stated would hide a genuine disagreement.
            raise MergeConflict(
                f"tiers disagree on single-arity label {name!r}: "
                + ", ".join(
                    f"tier {tier} says {value!r}" for tier, value in sorted(by_tier.items())
                )
                + ". Rule 4 would keep the lowest tier's value and discard the other, which would "
                "hide a disagreement rather than report it (§5.2)"
            )
        value: str | tuple[str, ...] = by_tier[lowest]
    else:
        value = tuple(at_lowest[0].get("value") or ())

    return LabelEntry(
        name=name,
        value=value,
        tier=lowest,
        sids=tuple(sorted({int(sid) for entry in entries for sid in entry.get("sids") or ()})),
    )


def _single(name: str, value: Any) -> str:
    """§4.3's `value` column is REPEATED even for a single-arity kind — one shape serves both.

    A bare `str` is accepted because a hand-built fixture is a producer too, and reading the one
    element out of a list is not the kind of thing a test should have to remember.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, Sequence) and len(value) == 1 and isinstance(value[0], str):
        return value[0]
    raise ValueError(
        f"label {name!r} has arity 'single' but its stored value is {value!r}: §4.3's column is "
        f"REPEATED for both arities, so a single-arity value is exactly one element"
    )


def _source(row: Mapping[str, Any]) -> SourceEntry:
    return SourceEntry(**{name: row.get(name) for name in SOURCE_FIELDS})


def _flow(row: Mapping[str, Any]) -> Flow:
    values: dict[str, Any] = {
        name: row.get(name) for name in FLOW_FIELDS if name not in ("uid", "ts_first", "ts_last")
    }
    values["uid"] = row.get(ZEEK_UID)
    values["ts_first"] = _epoch(row.get("ts_first"))
    values["ts_last"] = _epoch(row.get("ts_last"))
    return Flow(**values)


def _epoch(value: Any) -> float:
    """A stored timestamp as epoch seconds, whichever way it arrived.

    `flow_labels.flow.ts_first` is a BigQuery `TIMESTAMP`, so the client hands back an aware
    `datetime` — while the rows `parse.py` builds on the way *in* carry the ISO strings
    `labels.json` holds. Both reach here, from `blfile` and from a fixture respectively, and a
    module that accepted only one would be tested against a shape production never produces.
    """
    if isinstance(value, datetime):
        # A naive datetime is read as UTC rather than local: `datetime.timestamp()` on a naive
        # value applies the *local* zone, which is invisible on a UTC CI runner and silently wrong
        # by whole hours everywhere else. `docs/spec.md` §10 forbids locale-dependent handling.
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).timestamp()
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as error:
            raise ValueError(f"timestamp {value!r} is not ISO-8601: {error}") from error
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"timestamp {value!r} is not a datetime, an ISO-8601 string, or a number")
    return float(value)
