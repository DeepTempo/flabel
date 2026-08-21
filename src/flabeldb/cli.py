"""`flabel-db` — bring the dataset to the declaration, and notice when it drifts.

    flabel-db apply     create or patch every table and view to match schema.py
    flabel-db verify    compare live against declared; exit 1 on ANY difference
    flabel-db show      what the store holds, for one run or capture

**`verify` is the reason this exists.** `apply` makes the tables right today; `verify` is what
notices the day a column is patched in the console — modelled on a failure already on this
project's books, where `ci.yml`'s toolchain digest is updated by hand and can silently lag
`Dockerfile.toolchain` with every test still passing, because the pins and the stale image agree.

It runs as a **pre-deploy gate in `tools/flabel-deploy`**, not in CI (Craig, 2026-08-20): CI has no
GCP credential, the metadata server is absent from GitHub Actions, and this is a public repo so no
key may be committed. Workload Identity Federation would solve it and was declined as out of scope,
so the definition of done says pre-deploy rather than claiming a gate that cannot exist.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import traceback
from collections.abc import Sequence

from flabeldb import client as client_module
from flabeldb import schema

VIEWS = pathlib.Path(__file__).parent / "views"

EXIT_OK = 0
#: The dataset does not match the declaration. `tools/flabel-deploy` stops on this.
EXIT_DRIFT = 1
#: The operator's environment: no `db` extra, no project, or a credential that cannot be used.
#: **Distinct from EXIT_DRIFT on purpose.** Sharing a code would make "I could not ask the dataset"
#: indistinguishable from "the dataset is wrong", which is the confusion `live_schema`'s
#: NotFound-only rule exists to prevent one layer down.
EXIT_USAGE = 2
#: A defect in `flabel-db` itself, or any failure it does not recognise.
#: **Exists so that exit 1 can only ever mean drift.** The previous default was a bare `raise`,
#: which reaches the interpreter and exits 1 — so an unrecognised failure, including a bug in this
#: code, told `tools/flabel-deploy` that the dataset had drifted and sent the operator to look at a
#: schema that was never read. Measured 2026-08-21: the name-matching detector below missed 15 of
#: the 18 exception classes in `google.auth.exceptions`, so that default was the common case, not
#: the edge one.
EXIT_INTERNAL = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flabel-db", description="Keep the label store's schema matching its declaration."
    )
    parser.add_argument("--project", default=None, metavar="ID")
    parser.add_argument("--dataset", default=client_module.DEFAULT_DATASET, metavar="NAME")
    parser.add_argument(
        "--local-adc",
        action="store_true",
        help=(
            "authenticate with application-default credentials instead of the instance identity. "
            "For a laptop and the tests, where there is no metadata server."
        ),
    )
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("apply", help="create or patch tables and views to match the declaration")
    actions.add_parser("verify", help="compare live against declared; exit 1 on any difference")
    show = actions.add_parser("show", help="what the store holds")
    show.add_argument("--run-id", default=None)
    show.add_argument("--capture", default=None, metavar="SHA256")
    return parser


def view_sql(dataset: str) -> list[tuple[str, str]]:
    """Every committed view, with `{dataset}` resolved. Sorted, so `apply` is deterministic."""
    return [
        (path.stem, path.read_text(encoding="utf-8").replace("{dataset}", dataset))
        for path in sorted(VIEWS.glob("*.sql"))
    ]


def _apply(bq, dataset: str) -> int:
    """Create every declared table that is absent, and patch every one that can be patched.

    **`create_table(exists_ok=True)` does not patch.** On a conflict the client returns `get_table`
    and `update_table` appears nowhere in the method — verified in the library source, then measured
    on `flabel_scratch` 2026-08-21: a table created with one column and re-applied with two kept one
    column and its original description, while `apply` printed a success line for it. So after
    LS-6 provisions the dataset, the old `apply` would have changed nothing while `verify` kept
    reporting drift, and the subcommand help said `create or patch`.

    BigQuery permits **additive changes and relaxations only**, so some drift cannot be patched at
    all. Craig decided 2026-08-20 that apply patches what it can and says plainly what it cannot,
    rather than failing obscurely: a narrowed type, a dropped column, a tightened mode, a
    reordering or any partitioning change needs the table rebuilt, and this names it and exits
    `EXIT_DRIFT` — because the dataset does not match the declaration when it returns, and
    `tools/flabel-deploy` must stop.

    Which changes fall on which side is decided by `schema.patch_plan`, which is pure so CI can
    check it; this function executes that plan and nothing more.
    """
    from google.api_core.exceptions import NotFound

    bigquery = client_module._bigquery()
    reference = f"{bq.project}.{dataset}"
    rebuild: list[str] = []
    for name, table in schema.TABLES.items():
        try:
            existing = bq.get_table(f"{reference}.{name}")
        except NotFound:
            target = bigquery.Table(
                f"{reference}.{name}", schema=client_module.to_bigquery(table.fields)
            )
            target.description = table.description
            if table.partition_field:
                target.time_partitioning = bigquery.TimePartitioning(field=table.partition_field)
            if table.clustering:
                target.clustering_fields = list(table.clustering)
            # `exists_ok` guards only the race between the get above and this call. It is NOT the
            # patch mechanism — believing that it was is the defect this function was rewritten for.
            bq.create_table(target, exists_ok=True)
            print(f"flabel-db: table {name} created")
            continue

        plan = schema.patch_plan(name, table, client_module.live_table(existing))
        if plan.is_noop:
            print(f"flabel-db: table {name} matches the declaration")
            continue
        if plan.mask:
            if "schema" in plan.mask:
                existing.schema = client_module.to_bigquery(plan.fields)
            if "clustering_fields" in plan.mask:
                # `None`, not `[]`, is how clustering is removed (measured).
                existing.clustering_fields = list(table.clustering) or None
            if "description" in plan.mask:
                existing.description = table.description
            bq.update_table(existing, list(plan.mask))
            for message in plan.changes:
                print(f"flabel-db: patched {message}")
        for message in plan.rebuild:
            rebuild.append(message)

    for name, sql in view_sql(dataset):
        bq.query(sql).result()
        print(f"flabel-db: view {name}")

    if rebuild:
        # stdout is block-buffered when piped, so without this the summary below lands BEFORE the
        # per-table lines it summarises and reads as though nothing was patched. Measured on
        # fl-replay 2026-08-21.
        sys.stdout.flush()
        print(
            f"\nflabel-db: {len(rebuild)} change(s) in {dataset} CANNOT be patched and need the "
            f"table REBUILT:",
            file=sys.stderr,
        )
        for message in rebuild:
            print(f"  {message}", file=sys.stderr)
        print(
            "\nBigQuery permits additive changes and relaxations only. Rebuilding means creating "
            "the table anew from the declaration and reloading it — `--rebuild` is Phase 3b, so "
            "today it is a deliberate manual step. Everything else above was patched.",
            file=sys.stderr,
        )
        return EXIT_DRIFT
    return EXIT_OK


def _verify(bq, dataset: str) -> int:
    """Compare the live dataset against the declaration, and exit 1 on ANY difference.

    Compares more than the field list. Measured against this declaration: `flow_labels` clustered
    on `zeek_uid` — the store's single named never-do, because a Zeek uid under `-D` is positional —
    verified CLEAN, and reversing all 13 columns of `runs` yielded zero differences.

    The dataset's LOCATION is checked here rather than in `schema.py`, which is pure and must not
    import the client: `LOCATION` lives with the client because it is part of the store's identity.
    It is checked at all because it cannot be fixed later — a dataset's location is immutable, the
    results bucket is US-CENTRAL1 *regional* so a load job needs a compatible dataset, and BigQuery
    job ids are namespaced `project:location.jobid`, so the location is part of the idempotency
    namespace too (spec §10 M2, M4).
    """
    from google.api_core.exceptions import NotFound

    found: list[str] = []
    try:
        location = bq.get_dataset(f"{bq.project}.{dataset}").location
    except NotFound:
        # `NotFound` on a TABLE means the table is absent, which is drift. On the DATASET it means
        # the container is not there, and reporting five missing tables plus "run apply" would be
        # advice that cannot work — apply cannot create a dataset either (that is LS-6).
        print(
            f"flabel-db: dataset {bq.project}.{dataset} does not exist (or this identity cannot "
            f"see it).\n"
            f"\nThis is NOT a report about its tables: nothing in it was read. Check --dataset and "
            f"--project for a typo; the dataset itself is created by LS-6, not by `apply`.",
            file=sys.stderr,
        )
        return EXIT_DRIFT
    if (location or "").lower() != client_module.LOCATION:
        found.append(
            f"{dataset}: dataset location is {location!r}, declared "
            f"{client_module.LOCATION!r} — a location is IMMUTABLE, so this needs the dataset "
            f"recreated, not patched"
        )
    found += list(schema.differences(client_module.live_schema(bq, dataset)))
    found = tuple(found)
    if not found:
        print(f"flabel-db: {dataset} matches the declaration ({len(schema.TABLES)} tables)")
        return EXIT_OK
    print(f"flabel-db: {dataset} DIFFERS from the declaration:", file=sys.stderr)
    for message in found:
        print(f"  {message}", file=sys.stderr)
    print(
        "\nRun `flabel-db apply` if the declaration is right, or fix the declaration if the "
        "dataset is. Do not leave them disagreeing: every load job passes the declared schema.",
        file=sys.stderr,
    )
    return EXIT_DRIFT


def _show(bq, dataset: str, run_id: str | None, capture: str | None) -> int:
    if run_id:
        where, parameter = "run_id = @value", run_id
    elif capture:
        where, parameter = "capture_sha256 = @value", capture
    else:
        where, parameter = None, None
    bigquery = client_module._bigquery()
    sql = (
        "SELECT run_id, capture_sha256, mode, tiers_attested, finished_at "
        f"FROM `{bq.project}.{dataset}.runs`"
    )
    config = None
    if where:
        sql += f" WHERE {where}"
        config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("value", "STRING", parameter)]
        )
    sql += " ORDER BY finished_at DESC LIMIT 50"
    rows = list(bq.query(sql, job_config=config).result())
    if not rows:
        print("flabel-db: the store holds no matching run")
        return EXIT_OK
    for row in rows:
        print(
            f"  {row['run_id']}  {row['mode']:<8}  tiers_attested={list(row['tiers_attested'])}  "
            f"{row['capture_sha256'][:16]}…  {row['finished_at']}"
        )
    return EXIT_OK


def _credential_failure_types() -> tuple[type[BaseException], ...]:
    """The exception types that mean "we never reached the dataset", for `isinstance`.

    **Imported lazily, not matched by name.** The name-matching frozenset this replaces existed so
    the module would import without the `db` extra, and it bought that at the cost of being wrong:
    `type(error).__name__ in {...}` matches an exact class, so every subclass escaped. Measured
    against the installed library 2026-08-21 — `google.auth.exceptions` holds 18 exception classes,
    the frozenset named 3, and **15 escaped**, `ReauthFailError` among them. That one is a
    `RefreshError` subclass and is the exact failure spec-label-store §7.1 quotes from the box.

    A lazy import keeps the no-extra import working and lets `isinstance` do the subclassing, so
    all 18 are covered by `GoogleAuthError` alone.

    The api_core three are named individually rather than by a shared base, because measurement
    says a base would be wrong in both directions: `RetryError` is **not** a `GoogleAPICallError`
    (it derives straight from `GoogleAPIError`), while `NotFound` shares `ClientError` with
    `Forbidden` — and `NotFound` is the one API error that IS a fact about the dataset.
    `PermissionDenied` and `Unauthenticated` need no entry: they are subclasses of `Forbidden` and
    `Unauthorized`, which is the whole point of matching by type.
    """
    try:
        from google.api_core.exceptions import Forbidden, RetryError, Unauthorized
        from google.auth.exceptions import GoogleAuthError
    except ImportError:  # pragma: no cover - no extra means no google exception could be raised
        return ()
    return (GoogleAuthError, Forbidden, Unauthorized, RetryError)


def _is_credential_failure(error: BaseException) -> bool:
    """Whether `error` means the identity failed rather than the dataset being wrong."""
    types = _credential_failure_types()
    return bool(types) and isinstance(error, types)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        bq = client_module.client(project=args.project, local_adc=args.local_adc)
    except RuntimeError as error:
        # A missing extra or an unset project. Both are the operator's environment rather than a
        # defect, so they read as a sentence and not a traceback.
        print(f"flabel-db: {error}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.action == "apply":
            return _apply(bq, args.dataset)
        if args.action == "verify":
            return _verify(bq, args.dataset)
        return _show(bq, args.dataset, args.run_id, args.capture)
    except Exception as error:  # noqa: BLE001
        # A credential that cannot be refreshed, or a role the identity does not hold. Reported as
        # a sentence with EXIT_USAGE rather than a traceback with EXIT_DRIFT, because the two
        # answers are different facts: one says the dataset is wrong, the other says we never saw
        # it. Measured while building this — an expired laptop credential produced a
        # `RefreshError` traceback that exited 1, the code the deploy gate reads as drift.
        if _is_credential_failure(error):
            print(
                f"flabel-db: cannot reach BigQuery as this identity — {type(error).__name__}: "
                f"{error}\n"
                f"\nOn fl-replay the instance identity is used and needs nothing. On a laptop "
                f"pass --local-adc and run `gcloud auth application-default login` first. This is "
                f"NOT a report about the dataset: nothing was read.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        # NOT `raise`. A bare re-raise exits 1, which is EXIT_DRIFT, so any failure we do not
        # recognise would report drift in a dataset nothing finished reading. The traceback is kept
        # because a defect is a bug report; only the exit code changes.
        traceback.print_exc()
        print(
            f"\nflabel-db: internal error — {type(error).__name__}: {error}\n"
            f"\nThis is a DEFECT in flabel-db, not a report about {args.dataset}. Exit "
            f"{EXIT_INTERNAL} is not {EXIT_DRIFT}: nothing above says the dataset drifted.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
