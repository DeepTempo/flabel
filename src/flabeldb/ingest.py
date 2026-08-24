"""`flabel-ingest` — a published run into the store, survivably.

**Impure**: BigQuery load jobs and a `gs://` read. But the decisions live in pure functions taken
over a `probe` callable, because §2.4's testing line records that the `requires_bigquery` tests run
nowhere but by hand on `fl-replay` — and §5.3 is exactly where LS-4's measured surprises are, so it
is the last logic that should be reachable only from a live dataset.

**Ordering is the design.** `flow_labels`, `unmatched` and `captures` load first and the `runs` row
lands LAST; every read joins through `runs`, so a crash mid-ingest leaves rows nothing can reach
rather than a run that looks present and is missing its flows.

**Revision 1 said "re-running the same ingest completes it", and that was false.** Measured
(§10 M1): a BigQuery load job that *fails* still consumes its job id permanently, so an id derived
only from `(run_id, table)` is burnt by the first transient failure and the run can never be
ingested again. Combined with the ordering, a half-loaded run was unrecoverable except by full
rebuild. Hence attempt-numbered ids and the walk in `next_attempt`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence

#: Load order. **`runs` is last and that is load-bearing** (§5.3) — it is the commit marker.
#:
#: `run_exclusions` is absent deliberately: §4.5 makes retraction an operator's record, and an
#: ingest that could write one could un-retract a run by re-ingesting it.
LOAD_ORDER: tuple[str, ...] = ("flow_labels", "unmatched", "captures", "runs")

#: What a probe reports about one job id.
MISSING = "missing"
SUCCEEDED = "succeeded"
FAILED = "failed"

#: How far `next_attempt` will walk before giving up.
#:
#: A bound rather than a `while True`: the probe is a billed API call, and a table that fails
#: permanently — a bad row, a schema that no longer matches — would otherwise spin against it
#: forever. Ten is far past any transient-failure count and still cheap to exhaust.
MAX_ATTEMPTS = 10

#: `gs://<bucket>/<object>`, with a non-empty object. A bucket alone is not a tarball.
GS_URI = re.compile(r"^gs://(?P<bucket>[A-Za-z0-9][A-Za-z0-9._-]*)/(?P<name>.+)$")


def split_gs_uri(uri: str) -> tuple[str, str]:
    """`gs://bucket/object` as its two parts, or a `ValueError` naming what was wrong.

    Validated before any network call, the same treatment §6.1 gave `--source-uri`: a malformed
    URI should cost nothing and say so, not surface as a 404 from a client three frames down.
    """
    found = GS_URI.match(uri or "")
    if not found:
        raise ValueError(
            f"{uri!r} is not a gs:// object URI. `flabel-ingest` reads the PUBLISHED tarball "
            f"rather than a local run directory (§7.2), so that every ingested run is provably "
            f"rebuildable and the live and backfill paths share one source."
        )
    return found["bucket"], found["name"]


def job_id(run_id: str, table: str, attempt: int) -> str:
    """`ingest-<run_id>-<table>-<attempt>` (§5.3).

    The attempt number is the entire point. Without it the id is a function of the run and the
    table alone, and §10 M1 measured what that costs: a load job that fails consumes its id
    permanently, so one transient failure locks the run out for good.
    """
    return f"ingest-{run_id}-{table}-{attempt}"


def next_attempt(
    probe: Callable[[str], str],
    run_id: str,
    table: str,
    *,
    max_attempts: int = MAX_ATTEMPTS,
) -> int | None:
    """The attempt number to load `table` under, or `None` if it is already loaded.

    §5.3's walk, upward from 1:

    * `MISSING` — the id is unused, so this is the attempt to take.
    * `SUCCEEDED` — this table is done. Returning `None` is what stops a re-run doubling the rows
      of a table that finished before the crash.
    * `FAILED` — the id is burnt (§10 M1). Increment and look again.

    Taken over a callable rather than a client so the whole walk is exercisable in CI. The probe is
    called for each attempt IN ORDER and no further: every call is a billed request.
    """
    for attempt in range(1, max_attempts + 1):
        state = probe(job_id(run_id, table, attempt))
        if state == SUCCEEDED:
            return None
        if state == MISSING:
            return attempt
    raise RuntimeError(
        f"{run_id}/{table}: {max_attempts} consecutive load attempts have failed, so this is not "
        f"a transient failure. Read the errors on `{job_id(run_id, table, max_attempts)}` — a "
        f"permanently bad row or a schema that no longer matches will not fix itself on a retry."
    )


def apply_skip_tiers(
    attested: Sequence[int],
    notes: Sequence[str],
    *,
    skip: Iterable[int],
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    """`--skip-tier n`: load the rows, never attest the tier (§6.3, #142).

    The rows still land. That is the whole distinction §2.4 draws — "we have no record" against
    "we have a record we will not treat as current" — and it is why the flag suppresses attestation
    rather than suppressing the load.

    A tier that was not attested anyway gets no note: it was already refused, with a reason, and a
    second sentence about it would be a second explanation for one fact.
    """
    skipping = sorted(set(skip))
    kept = tuple(tier for tier in sorted(attested) if tier not in skipping)
    added = tuple(
        f"tier {tier} not attested: --skip-tier {tier} was given, so its rows are loaded and "
        f"will not supersede"
        for tier in skipping
        if tier in set(attested)
    )
    return kept, (*notes, *added)


__all__ = [
    "FAILED",
    "GS_URI",
    "LOAD_ORDER",
    "MAX_ATTEMPTS",
    "MISSING",
    "SUCCEEDED",
    "apply_skip_tiers",
    "job_id",
    "next_attempt",
    "split_gs_uri",
]
