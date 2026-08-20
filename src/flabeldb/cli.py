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
    bigquery = client_module._bigquery()
    reference = f"{bq.project}.{dataset}"
    for name, table in schema.TABLES.items():
        target = bigquery.Table(
            f"{reference}.{name}", schema=client_module.to_bigquery(table.fields)
        )
        target.description = table.description
        if table.partition_field:
            target.time_partitioning = bigquery.TimePartitioning(field=table.partition_field)
        if table.clustering:
            target.clustering_fields = list(table.clustering)
        bq.create_table(target, exists_ok=True)
        print(f"flabel-db: table {name}")
    for name, sql in view_sql(dataset):
        bq.query(sql).result()
        print(f"flabel-db: view {name}")
    return EXIT_OK


def _verify(bq, dataset: str) -> int:
    found = schema.differences(client_module.live_schema(bq, dataset))
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


#: Failure types that mean "we never reached the dataset". Matched by NAME rather than by importing
#: google.auth here, so this module still imports without the `db` extra.
CREDENTIAL_FAILURES = frozenset(
    {
        "RefreshError",
        "DefaultCredentialsError",
        "TransportError",
        "Forbidden",
        "Unauthorized",
        "PermissionDenied",
        "Unauthenticated",
    }
)


def _is_credential_failure(error: BaseException) -> bool:
    """Whether `error` means the identity failed rather than the dataset being wrong."""
    return type(error).__name__ in CREDENTIAL_FAILURES


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
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
