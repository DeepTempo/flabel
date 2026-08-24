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


def classify_job(job: object | None) -> str:
    """What a load job's state means for the walk — `MISSING`, `SUCCEEDED` or `FAILED`.

    **Reading `state` alone is the trap, and §10 M1 measured it.** A load that fails on a bad row
    finishes with `state: DONE`, `errorResult: invalid` and `outputRows: None` — so "DONE means it
    worked" calls a failed load a success, skips the retry, and lands a `runs` row for a table that
    has no rows in it. The commit marker would then be pointing at nothing.

    A job still in flight is neither, and is refused rather than guessed at: calling it `FAILED`
    walks past a load that is about to land and duplicates its rows, calling it `SUCCEEDED` skips a
    table that has none yet. §3.3 assumes one runner, so a running job under our own id means a
    previous invocation has not finished.
    """
    if job is None:
        return MISSING
    state = getattr(job, "state", None)
    if state not in (None, "DONE"):
        raise RuntimeError(
            f"a load job for this run is still running (state {state!r}). Ingest assumes one "
            f"runner (§3.3); wait for it to finish rather than starting a second."
        )
    return FAILED if getattr(job, "error_result", None) else SUCCEEDED


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


# --- where the decisions above meet BigQuery ----------------------------------------------------
#
# Everything from here down needs a client, and so is reachable only from `test_flabeldb_live.py`
# and a hand-run against `flabel_scratch`. That boundary is exactly where LS-3 shipped two broken
# commands with CI green, so each function below is kept as thin as it can be: the deciding is done
# above, and these only ask BigQuery and report what it said.


def probe_job(bq, job_reference: str, *, location: str | None = None) -> str:
    """Ask BigQuery about one job id, in the vocabulary `next_attempt` walks over."""
    from google.api_core.exceptions import NotFound

    from flabeldb import client as client_module

    try:
        job = bq.get_job(job_reference, location=location or client_module.LOCATION)
    except NotFound:
        return MISSING
    return classify_job(job)


def already_committed(bq, dataset: str, run_id: str) -> bool:
    """§7.4's PRIMARY guard: `SELECT 1 FROM runs WHERE run_id = @id`.

    A query, not a job id. It is immune to job-id retention (§10 M1) and to the burnt-id problem,
    and it tests the fact that actually matters — that the commit marker is there — rather than a
    fact about our own bookkeeping.
    """
    bigquery = _client_module()._bigquery()
    sql = f"SELECT 1 FROM `{bq.project}.{dataset}.runs` WHERE run_id = @run_id LIMIT 1"
    config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("run_id", "STRING", run_id)]
    )
    return bool(list(bq.query(sql, job_config=config).result()))


def clear_orphans(bq, dataset: str, run_id: str) -> dict[str, int]:
    """§5.3 step 2: delete this run's rows from every table ingest writes.

    A run that is new and a run that is half-loaded are **indistinguishable** — the commit marker
    is absent either way — and they need the same treatment, so this runs unconditionally once
    `already_committed` says no. Bounded, targeted, and by definition invisible rows: §2.2's stated
    exception to append-only.
    """
    bigquery = _client_module()._bigquery()
    removed: dict[str, int] = {}
    for table in LOAD_ORDER:
        sql = f"DELETE FROM `{bq.project}.{dataset}.{table}` WHERE run_id = @run_id"
        config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("run_id", "STRING", run_id)]
        )
        job = bq.query(sql, job_config=config)
        job.result()
        removed[table] = job.num_dml_affected_rows or 0
    return removed


def load_rows(bq, dataset: str, table: str, rows: Sequence[dict], job_reference: str) -> None:
    """One batch load job under an exact job id.

    **Batch loads, never the streaming API** (§7.4): atomic per job, free, and no streaming buffer
    to block a later correction. `WRITE_APPEND` with the declared schema, so a row that does not
    match fails the job rather than inventing a column.
    """
    client_module = _client_module()
    bigquery = client_module._bigquery()
    from flabeldb import schema

    config = bigquery.LoadJobConfig(
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        schema=client_module.to_bigquery(schema.TABLES[table].fields),
    )
    job = bq.load_table_from_json(
        list(rows),
        f"{bq.project}.{dataset}.{table}",
        job_config=config,
        job_id=job_reference,
        location=client_module.LOCATION,
    )
    job.result()


def _client_module():
    """Imported through a function so this module still imports without the `db` extra.

    The same lesson as `cli._not_found_types`: a top-level client import made three tests exit
    EXIT_INTERNAL on a checkout without the extra, and the `bare-runner` job caught it.
    """
    from flabeldb import client

    return client


__all__ = [
    "FAILED",
    "GS_URI",
    "LOAD_ORDER",
    "MAX_ATTEMPTS",
    "MISSING",
    "SUCCEEDED",
    "already_committed",
    "apply_skip_tiers",
    "classify_job",
    "clear_orphans",
    "job_id",
    "load_rows",
    "next_attempt",
    "probe_job",
    "split_gs_uri",
]
