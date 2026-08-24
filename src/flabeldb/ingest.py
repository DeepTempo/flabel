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

import argparse
import pathlib
import re
import traceback
from collections.abc import Callable, Iterable, Sequence

#: Load order. **`runs` is last and that is load-bearing** (§5.3) — it is the commit marker.
#:
#: `run_exclusions` is absent deliberately: §4.5 makes retraction an operator's record, and an
#: ingest that could write one could un-retract a run by re-ingesting it.
LOAD_ORDER: tuple[str, ...] = ("flow_labels", "unmatched", "captures", "runs")

#: The column that names the run, PER TABLE. `captures` is the one that differs.
#:
#: A capture row is a SIGHTING (§4.2) — append-only, because a URI is a location and the digest is
#: the identity — so its reference to the run that saw it is `observed_by_run_id`, not `run_id`.
#: Filtering it on `run_id` is invalid SQL, and BigQuery says so at runtime and not before:
#: `400 Unrecognized name: run_id`. Measured 2026-08-24 on the first real ingest, which exited 3
#: having loaded nothing. `test_flabeldb_ingest.py` now joins this map to the declaration, because
#: neither `schema.py` nor this module reads the other and nothing else would notice a drift.
RUN_COLUMN: dict[str, str] = {
    "flow_labels": "run_id",
    "unmatched": "run_id",
    "captures": "observed_by_run_id",
    "runs": "run_id",
}

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


def first_unused_attempt(
    probe: Callable[[str], str],
    run_id: str,
    table: str,
    *,
    max_attempts: int = MAX_ATTEMPTS,
) -> int:
    """The first attempt number whose job id is UNUSED — succeeded ones included.

    **This is what `load_run` uses, and §5.3's step 3 as written is incompatible with its step 2.**
    Measured 2026-08-24 against `flabel_scratch`, and the failure is worth stating exactly:

    Step 2 deletes this run's rows from every table, unconditionally, because a new run and a
    half-loaded run are indistinguishable. Step 3 then says a job that "exists and *succeeded*
    means this table is done". After step 2 it does not: its rows have just been deleted. Driving
    the recovery path against the real service produced a run whose `flow_labels` table ended up
    with **zero** rows — cleared by step 2, then skipped by step 3, and the `runs` commit marker
    landed on top of the emptiness.

    A job id is permanent (§10 M1), so "this id succeeded once" says nothing about whether the rows
    are there NOW. Once the rows have been cleared, the only question the walk can answer is which
    id is free.

    `next_attempt` keeps §5.3's literal semantics and is still the right function for a path that
    does not clear first. Nothing calls it that way today; it is kept because the distinction is
    the finding, and collapsing the two would hide it.
    """
    for attempt in range(1, max_attempts + 1):
        if probe(job_id(run_id, table, attempt)) == MISSING:
            return attempt
    raise RuntimeError(
        f"{run_id}/{table}: all {max_attempts} attempt ids are used. A job id is permanent, "
        f"so this run has been loaded {max_attempts} times; that is not a retry loop, it is a run "
        f"being re-ingested repeatedly. Check why the `runs` commit marker is not sticking."
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
        sql = f"DELETE FROM `{bq.project}.{dataset}.{table}` WHERE {RUN_COLUMN[table]} = @run_id"
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


def extract(archive: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    """Unpack a published tarball and return the single run directory inside it.

    `tools/flabel-run` builds the archive as `tar -czf - -C <dir> <name>`, so it unpacks to exactly
    one top-level directory. Anything else is not one of ours, and picking a directory out of an
    archive with several would be a guess about provenance.

    **Every member is checked before anything is written**, and "we wrote the archive" is exactly
    the assumption that makes an unreviewed extract the classic mistake — the results bucket is
    writable by two project Owners and nothing detects a replacement, which is #164. Absolute
    paths, `..` traversal and links are refused outright rather than filtered, because nothing
    `flabel-run` produces contains one, so their presence is itself the finding.
    """
    import tarfile

    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    resolved_root = destination.resolve()

    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            if member.issym() or member.islnk():
                raise ValueError(
                    f"{archive}: member {member.name!r} is a link, and nothing flabel-run "
                    f"produces contains one. Refusing rather than filtering (#164)."
                )
            target = (destination / member.name).resolve()
            if target != resolved_root and resolved_root not in target.parents:
                raise ValueError(
                    f"{archive}: member {member.name!r} resolves outside {destination} — an "
                    f"absolute path or `..` traversal. Refusing to extract it."
                )
        tops = {pathlib.PurePosixPath(m.name).parts[0] for m in members if m.name not in (".", "")}
        # One top-level name is not enough: a flat archive of a single FILE also has one. What
        # `flabel-run` produces has members *underneath* that name, which is what distinguishes a
        # run directory from a loose `labels.json` somebody tarred by hand.
        nested = len(tops) == 1 and any("/" in m.name.rstrip("/") for m in members)
        if not nested:
            raise ValueError(
                f"{archive}: expected exactly one directory at the top, with the run inside it, "
                f"and found {sorted(tops)}. `flabel-run` builds `-C <dir> <name>`, so a published "
                f"run always unpacks to one."
            )
        # `filter="data"` is the stdlib's own refusal of absolute paths, `..`, links and special
        # files — the same set checked above, enforced again by the library.
        #
        # **Deliberately redundant, and the sabotage round confirms it rather than faults it:**
        # removing this line leaves every test green, because the loop above already refuses
        # everything it would. That is what redundancy means, and a test that pinned the argument
        # would be testing the implementation rather than the behaviour. The loop stays because its
        # errors name the archive and the member; this stays because it is the library's own
        # judgement of what is unsafe, and it will keep pace with attacks the loop was not written
        # for. It also removes a DeprecationWarning: Python 3.14 makes filtering the default.
        tar.extractall(destination, filter="data")  # noqa: S202 - filtered, and checked above

    found = destination / tops.pop()
    if not found.is_dir():
        raise ValueError(f"{archive}: expected one directory at the top; {found.name} is a file")
    return found


def fetch(uri: str, destination: pathlib.Path, *, local_adc: bool = False) -> pathlib.Path:
    """Download `gs://bucket/object` to `destination` and return the local path.

    The client library rather than `gcloud`: LS-6 measured that gcloud needs `sudo` on `fl-replay`
    because its credential store is per-user, while a client library reaches the metadata server
    unprivileged (§7.1). And the identity comes from `client.credentials()` like everything else,
    which is spec invariant 7 — the identity is named, never discovered.
    """
    from google.cloud import storage

    bucket_name, object_name = split_gs_uri(uri)
    client_module = _client_module()
    gcs = storage.Client(credentials=client_module.credentials(local_adc=local_adc))
    destination = pathlib.Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    gcs.bucket(bucket_name).blob(object_name).download_to_filename(str(destination))
    return destination


def rows_for(parsed, table: str) -> list[dict]:
    """The rows one parsed run contributes to `table`."""
    return {
        "flow_labels": parsed.flow_labels,
        "unmatched": parsed.unmatched,
        "captures": [parsed.capture],
        "runs": [parsed.run],
    }[table]


def ingest_one(
    bq,
    dataset: str,
    *,
    uri: str,
    ingested_at: str,
    skip_tier: Iterable[int] = (),
    local_adc: bool = False,
    workdir: pathlib.Path | None = None,
) -> dict:
    """One published run into the store, in the order that makes a crash survivable.

    §5.3, in the order it is written there:

    1. **Is this run already committed?** `SELECT 1 FROM runs` — the primary guard (§7.4), a query
       rather than a job id, so it is immune to job-id retention and tests the fact that matters.
       If yes, stop: that is what makes re-running an ingest free.
    2. Otherwise the run is new *or* half-loaded, and those are **indistinguishable** — the marker
       is absent either way — so both get the same treatment: clear any orphaned rows.
    3. Load each table under an attempt-numbered id, walking past ids previous attempts burnt, with
       `runs` LAST so a crash leaves rows nothing can reach.
    """
    import tempfile

    with tempfile.TemporaryDirectory(dir=workdir) as scratch:
        root = pathlib.Path(scratch)
        archive = fetch(uri, root / "run.tar.gz", local_adc=local_adc)
        directory = extract(archive, root / "unpacked")

        from flabeldb import parse

        parsed = parse.of_directory(directory, ingested_at=ingested_at, archive_uri=uri)

    return load_run(bq, dataset, parsed, skip_tier=skip_tier)


def load_run(
    bq, dataset: str, parsed, *, skip_tier: Iterable[int] = (), stop_after: str | None = None
) -> dict:
    """§5.3's three steps, over an already-parsed run.

    Split from `ingest_one` so the recovery path can be driven without a network fetch — the
    tarball is `ingest_one`'s concern and the ORDERING is this function's, and it is the ordering
    that the `requires_bigquery` tests need to interrupt.

    `stop_after` exists for exactly that: it stops the loop after the named table, which is how a
    test produces the half-loaded state a crash would. It is not reachable from the CLI.
    """
    run_id = parsed.run["run_id"]
    attested, notes = apply_skip_tiers(
        parsed.run["tiers_attested"], parsed.run["attestation_notes"], skip=skip_tier
    )
    parsed.run["tiers_attested"] = list(attested)
    parsed.run["attestation_notes"] = list(notes)

    # STEP 1 — the primary guard (§7.4). A query, not a job id.
    if already_committed(bq, dataset, run_id):
        return {"run_id": run_id, "status": "already-present", "refused": parsed.refused}

    # STEP 2 — new and half-loaded are indistinguishable, so both get the same treatment.
    cleared = clear_orphans(bq, dataset, run_id)

    # STEP 3 — attempt-numbered loads, `runs` last.
    loaded: dict[str, int] = {}
    for table in LOAD_ORDER:
        rows = rows_for(parsed, table)
        # `first_unused_attempt`, NOT `next_attempt`: step 2 above just deleted this run's rows,
        # so a job that succeeded on a previous invocation does not mean the table is loaded.
        attempt = first_unused_attempt(lambda job: probe_job(bq, job), run_id, table)
        if rows:
            load_rows(bq, dataset, table, rows, job_id(run_id, table, attempt))
        loaded[table] = len(rows)
        if stop_after is not None and table == stop_after:
            return {"run_id": run_id, "status": "interrupted", "loaded": loaded, "cleared": cleared}

    return {
        "run_id": run_id,
        "status": "ingested",
        "loaded": loaded,
        "cleared": cleared,
        "refused": parsed.refused,
        "refusal_notes": parsed.refusal_notes,
        "tiers_attested": list(attested),
    }


# --- the command --------------------------------------------------------------------------------

EXIT_OK = 0
#: The run was not ingested. A real, reported outcome — a load that failed, an archive that is not
#: one of ours, a dataset that is not there.
EXIT_FAILED = 1
#: The operator's environment: no `db` extra, no project, a bad URI, an unusable credential.
EXIT_USAGE = 2
#: A defect in `flabel-ingest` itself, or any failure it does not recognise.
#: **Exists so exit 1 can only ever mean "not ingested"** — the discipline #157 arrived at, where a
#: bare re-raise reached the interpreter as exit 1 and told the caller the dataset had drifted.
EXIT_INTERNAL = 3


def build_parser() -> argparse.ArgumentParser:
    """§6.3's contract, and nothing beyond it."""
    from flabel.models import KNOWN_TIERS

    parser = argparse.ArgumentParser(
        prog="flabel-ingest",
        description="Load a published run into the label store.",
    )
    parser.add_argument("uri", metavar="gs://…tar.gz", help="the published tarball to ingest")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="ingest everything under the prefix that is not already present",
    )
    parser.add_argument(
        "--skip-tier",
        type=int,
        action="append",
        default=[],
        choices=KNOWN_TIERS,
        metavar="N",
        help=(
            "load tier N's rows but never attest it, so they do not supersede. See §9 and #142. "
            "Repeatable."
        ),
    )
    parser.add_argument("--project", default=None, metavar="ID")
    parser.add_argument("--dataset", default=None, metavar="NAME")
    parser.add_argument(
        "--local-adc",
        action="store_true",
        help="authenticate with application-default credentials instead of the instance identity",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Ingest one published run. See `ingest_one` for the ordering that makes it survivable."""
    import sys

    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        split_gs_uri(args.uri)
    except ValueError as error:
        print(f"flabel-ingest: {error}", file=sys.stderr)
        return EXIT_USAGE
    client_module = _client_module()
    try:
        bq = client_module.client(project=args.project, local_adc=args.local_adc)
    except RuntimeError as error:
        # A missing extra or an unset project. The operator's environment, not a defect.
        print(f"flabel-ingest: {error}", file=sys.stderr)
        return EXIT_USAGE

    dataset = args.dataset or client_module.DEFAULT_DATASET
    if args.backfill:
        print(
            "flabel-ingest: --backfill is not implemented yet (LS-4 is mid-step); ingest one "
            "tarball at a time for now.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        result = ingest_one(
            bq,
            dataset,
            uri=args.uri,
            ingested_at=_now_iso(),
            skip_tier=args.skip_tier,
            local_adc=args.local_adc,
        )
    except ValueError as error:
        # A malformed archive: not one of ours, or a member that resolves outside the tree.
        print(f"flabel-ingest: {error}", file=sys.stderr)
        return EXIT_FAILED
    except Exception as error:  # noqa: BLE001 - classified, never re-raised bare
        if client_module and _is_credential_failure(error):
            print(
                f"flabel-ingest: {type(error).__name__}: {error}\n\nThis is NOT a report about "
                f"the run: nothing was loaded, because the identity could not be used.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        traceback.print_exc()
        print(
            "\nThis is a DEFECT in flabel-ingest, not a report about the run. Exit 3 is not 1: "
            "nothing above says the run failed to ingest.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL

    if result["status"] == "already-present":
        print(f"flabel-ingest: {result['run_id']} is already in {dataset}; nothing to do")
        return EXIT_OK

    counts = ", ".join(f"{table}={count}" for table, count in result["loaded"].items())
    print(f"flabel-ingest: {result['run_id']} ingested into {dataset} — {counts}")
    if result["refused"]:
        print(
            f"flabel-ingest: {result['refused']} flow(s) were NOT written, because their proto "
            f"carries no derivable ip_proto (#96):",
            file=sys.stderr,
        )
        for note in result["refusal_notes"]:
            print(f"  {note}", file=sys.stderr)
    if not result["tiers_attested"]:
        print(
            "flabel-ingest: NO tier was attested, so these rows load and will not supersede "
            "anything. See runs.attestation_notes for why (§2.4).",
            file=sys.stderr,
        )
    return EXIT_OK


def _now_iso() -> str:
    """`ingested_at`. The one clock reading in the whole step, and it is here rather than in
    `parse` because §5.5 lists `ingested_at` among the things a rebuild does not reproduce."""
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _is_credential_failure(error: BaseException) -> bool:
    """Whether `error` means the identity failed rather than the run being bad. Mirrors
    `cli._credential_failure_types`: lazily imported and matched by TYPE, because the name-matching
    version missed 15 of 18 `google.auth` classes (#157)."""
    try:
        from google.api_core.exceptions import Forbidden, RetryError, Unauthorized
        from google.auth.exceptions import GoogleAuthError
    except ImportError:  # pragma: no cover - no extra means no google exception could be raised
        return False
    return isinstance(error, (GoogleAuthError, Forbidden, Unauthorized, RetryError))


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
    "first_unused_attempt",
    "clear_orphans",
    "job_id",
    "load_rows",
    "load_run",
    "next_attempt",
    "probe_job",
    "split_gs_uri",
]
