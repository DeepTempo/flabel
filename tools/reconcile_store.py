#!/usr/bin/env python3
"""Reconcile the label store against the archive — spec-label-store LS-8 (#152).

    uv run --extra db python tools/reconcile_store.py [--archive gs://…/results]

**The archive is the system of record and the store is a derived index over it** (§1). This asks
whether the index still agrees with what it was derived from, and it is the check that makes
"derived" a fact rather than a claim: §1 is careful that a rebuild rescues you from a *code* bug
and not from a bad run, so somebody has to compare the two.

**It does not ingest.** Run `flabel-ingest --backfill` first; this only reads. A tool that loaded
the rows and then verified them would be checking its own work in the same process, off the same
parse — which is the shape `tools/flabel-deploy` already had to fix once, and the reason
`CLAUDE.md` says a gate placed after the merge is not a gate.

Read-only means it cannot damage the store, **not that its answer is timeless.** The archive is
listed and parsed before the dataset is queried, so a run published and indexed inside that window
has rows in the store and was not in the listing, and comes back as an orphan. Re-run before
believing one.

## The two legs, and why one alone would prove little

Each run is checked twice, against two independently produced numbers:

1. **The store against the archive.** Row counts in BigQuery versus the rows a fresh parse of that
   tarball produces. Catches a half-loaded run, a load that silently dropped rows, a `runs` marker
   over an empty table (§5.3's measured failure), and a run in the store whose tarball is gone.
2. **The parse against the run block's own self-report.** `run.counts.labels` was written by
   `src/flabel/provenance.py` from `models.CorrelationResult`; the row count is what
   `flabeldb.parse` produces from `labels[]` now.

**Be precise about what leg 2 proves, because the obvious claim for it is wrong.** It is *not* two
independent measurements of the capture: `cli.py` builds `counts.labels` and `labels[]` from the
same `correlation.labels` list, in one process, so at labelling time they cannot disagree. Leg 2 is
a check on the archived document and on the code that reads it, and it catches two things leg 1
structurally cannot:

* the document changed after it was published — corrupted, truncated, or tampered with. This is the
  plan's named test for this step;
* `flabeldb.parse` silently dropping a label while reading. Leg 1 compares the store against that
  same parse, so a reader that loses rows satisfies leg 1 perfectly; `counts.labels` is the only
  number in the file that still says what the run actually found.

That second one is the reason both legs exist. Neither is redundant, and neither is a
cross-validation of the labelling itself — nothing here can tell you the labels are *right*.

## What it detects about a replaced tarball, and what it does not (#164)

**`run_id` is not derived from the whole run block**, and an earlier version of this docstring said
it was. `identity.run_id` hashes exactly four fields — `capture_sha256`, `mode`, `started_at` and
`flabel_version`, the last of which is `"0.0.0"` and contributes nothing. So a replacement can
rewrite `counts`, `ruleset`, `tools`, `warnings`, `loss_conditions`, `tiers_attempted` and
`input.uri` and keep the same id.

That splits the detection into two cases, and the useful one is the case that went unmentioned:

* **The replacement changes the capture digest, the mode, or `started_at`.** The id changes, so the
  old run is orphaned and the new tarball has never been ingested — a pair, and the orphan's own
  message says to look for the other.
* **The replacement keeps all three.** The id is the same, so leg 1 becomes a genuine content
  check: the store side holds the *old* run's rows and the archive side is a fresh parse of the
  *new* tarball, so any change in row cardinality fires. Leg 2 fires on a changed label count.

What survives in neither case is a replacement that keeps every count identical while changing a
label's *content*. Both legs are cardinality-only, and nothing in the store records a digest of the
object its rows came from — so #164 is narrowed here, not closed.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import sys
import traceback
from collections.abc import Iterable, Mapping, Sequence

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flabeldb import client as client_module  # noqa: E402
from flabeldb import ingest, parse, schema  # noqa: E402

EXIT_OK = 0
#: The store and the archive disagree. **The reconciliation failing is the whole point**, so this
#: is a real answer rather than an error, and it is kept apart from 2 and 3 for the reason
#: `flabel-db` keeps drift apart from usage: "they disagree" and "I could not ask" are different.
EXIT_DISAGREES = 1
#: The operator's environment or arguments: no `db` extra, no project, no archive URI.
EXIT_USAGE = 2
#: A defect in this tool. Exists so exit 1 can only ever mean the two sides disagree.
EXIT_INTERNAL = 3

#: The tables a run contributes rows to, and the column each one names the run in.
#:
#: **`ingest.RUN_COLUMN`, not a copy of it.** `captures` calls it `observed_by_run_id`, not
#: `run_id`, because a row there is one *sighting* of a capture by a run (§4.2) rather than a fact
#: about the run — and that map's own comment records this exact drift being MEASURED on
#: 2026-08-24, where a run exited 3 having loaded nothing. Writing the four pairs out again here
#: would be the second declaration of a fact that has already cost one run, in a file whose own
#: §8 argues against exactly that. `run_id_columns` still joins it to the declaration, because
#: neither `schema.py` nor `ingest.py` reads the other.
RUN_ID_COLUMN: Mapping[str, str] = ingest.RUN_COLUMN

#: Leg 2: which `run.counts` field the row count for a table must agree with.
#:
#: `flow_labels` is compared to `counts.labels` **plus the refusals**, because `parse.rows` refuses
#: a flow whose transport carries no derivable `ip_proto` (§3.2, #96) and the store therefore holds
#: fewer rows than the run labelled. Nothing in BigQuery records that number — it exists only in
#: the archive — which is a second reason this tool re-parses rather than reasoning from the store.
COUNTS_FIELD: Mapping[str, str] = {"flow_labels": "labels", "unmatched": "unmatched"}


@dataclasses.dataclass(frozen=True)
class RunExpectation:
    """What one tarball says the store should hold for it."""

    run_id: str
    archive_uri: str
    #: Per table, the number of rows a fresh parse of this tarball produces.
    rows: Mapping[str, int]
    #: `run.counts`, verbatim. Values may be `None` — §10 is emphatic that a null count means "not
    #: measured", and a comparison against one would invent a number.
    counts: Mapping[str, int | None]
    refused: int
    refusal_notes: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Disagreement:
    """One way the store and the archive fail to agree. Never a bare boolean."""

    kind: str
    run_id: str
    archive_uri: str
    detail: str
    table: str | None = None
    expected: int | None = None
    actual: int | None = None


@dataclasses.dataclass(frozen=True)
class Reconciliation:
    runs_checked: int
    disagreements: tuple[Disagreement, ...]

    @property
    def agrees(self) -> bool:
        return not self.disagreements


# --- the pure part: everything that decides anything --------------------------------------------


def run_id_columns() -> Mapping[str, str]:
    """`RUN_ID_COLUMN`, checked against the declaration rather than trusted.

    A column renamed in `schema.py` would otherwise make every count zero and report the whole
    archive as broken — a reconciliation that fails loudly for a reason that has nothing to do with
    the archive is worse than one that does not run.
    """
    for table, column in RUN_ID_COLUMN.items():
        declared = schema.TABLES.get(table)
        if declared is None:
            raise ValueError(
                f"{table!r} is not a declared table; schema.TABLES has {sorted(schema.TABLES)}"
            )
        if column not in {field.name for field in declared.fields}:
            raise ValueError(
                f"{table}.{column} is not a column of that table. RUN_ID_COLUMN is how this tool "
                f"counts a run's rows, so a rename here reports the archive as broken"
            )
    return RUN_ID_COLUMN


def expectation_of(parsed, archive_uri: str) -> RunExpectation:
    """One parsed tarball as the numbers the store is held to.

    `run.counts` is read back out of `parsed.run["run_block"]` rather than off the document a
    second time. §4.1 stores that block as STRING so §6.4 can embed it verbatim, so this is the
    same text the store holds — and a second traversal of the document would be a second opinion
    about what the run said.
    """
    import json

    block = json.loads(parsed.run["run_block"])
    return RunExpectation(
        run_id=parsed.run["run_id"],
        archive_uri=archive_uri,
        rows={table: len(ingest.rows_for(parsed, table)) for table in RUN_ID_COLUMN},
        counts=dict(block.get("counts") or {}),
        refused=parsed.refused,
        refusal_notes=tuple(parsed.refusal_notes),
    )


def compare_run(expectation: RunExpectation, actual: Mapping[str, int]) -> list[Disagreement]:
    """Both legs, for one run.

    **A missing `runs` marker short-circuits leg 1 ONLY, and that distinction was a defect.** The
    first version returned from here, which put leg 2 behind "the store has this run" — and every
    tarball in the archive was un-ingested when this tool was first run, so leg 2 executed zero
    times out of twenty-five and the report's `0 [self-report]` meant "never checked" while reading
    as "all consistent". Leg 2 needs no store at all; gating it on one was #171's shape exactly,
    the one value never exercised being the one that mattered.

    Leg 1 still short-circuits, because §5.3 makes the marker the commit: with it absent, every
    other table reports "0 rows" too and three more lines bury the one that explains them.
    """
    found: list[Disagreement] = []
    marker = actual.get("runs", 0)
    if marker == 0:
        found.append(
            Disagreement(
                kind="not-ingested",
                run_id=expectation.run_id,
                archive_uri=expectation.archive_uri,
                table="runs",
                expected=1,
                actual=0,
                detail=(
                    "this tarball has no `runs` row, so the store cannot see it at all. Either it "
                    "was never ingested, or an ingest crashed before the commit marker landed "
                    "(§5.3) — re-running `flabel-ingest` on this URI is the fix for both"
                ),
            )
        )
        return found + _self_report(expectation)
    if marker > 1:
        found.append(
            Disagreement(
                kind="duplicate-run",
                run_id=expectation.run_id,
                archive_uri=expectation.archive_uri,
                table="runs",
                expected=1,
                actual=marker,
                detail=(
                    "more than one `runs` row for one run id. §7.4's guard 4 exists for this and "
                    "`flabel-db verify` reports it; every read joins through this table, so the "
                    "duplicate multiplies rather than merely repeating"
                ),
            )
        )

    # LEG 1 — the store against a fresh parse of the archive.
    for table in RUN_ID_COLUMN:
        expected = expectation.rows[table]
        got = actual.get(table, 0)
        if expected != got:
            found.append(
                Disagreement(
                    kind="row-count",
                    run_id=expectation.run_id,
                    archive_uri=expectation.archive_uri,
                    table=table,
                    expected=expected,
                    actual=got,
                    detail=(
                        f"the archive parses to {expected} row(s) and the store holds {got}. A "
                        f"visible run pointing at rows that are not there is precisely what §5.3's "
                        f"load ordering exists to prevent, reached from the other direction"
                    ),
                )
            )

    return found + _self_report(expectation)


def _self_report(expectation: RunExpectation) -> list[Disagreement]:
    """LEG 2 — the parse against the run block's own self-report.

    Its own function so it can be reached from both exits of `compare_run`: this needs no store at
    all, and the first version had it behind the "is this run ingested" short circuit.
    """
    found: list[Disagreement] = []
    for table, field in COUNTS_FIELD.items():
        declared = expectation.counts.get(field)
        if declared is None:
            # §10: a null count means NOT MEASURED. Comparing against it would invent a number.
            continue
        # `refused` only applies to flows; an unmatched detection is never refused for transport.
        adjustment = expectation.refused if table == "flow_labels" else 0
        parsed = expectation.rows[table] + adjustment
        if parsed != declared:
            found.append(
                Disagreement(
                    kind="self-report",
                    run_id=expectation.run_id,
                    archive_uri=expectation.archive_uri,
                    table=table,
                    expected=declared,
                    actual=parsed,
                    detail=(
                        f"the tarball is inconsistent with ITSELF, before the store is considered: "
                        f"run.counts.{field} says {declared} and the document parses to "
                        f"{expectation.rows[table]} row(s) plus {adjustment} refused. `cli.py` "
                        f"writes those two from one list in one process, so they CANNOT "
                        f"disagree at labelling time — either the published document changed "
                        f"since, or the code reading it here is losing rows"
                    ),
                )
            )
    return found


def orphans(
    store_run_ids: Iterable[str], expectations: Iterable[RunExpectation]
) -> list[Disagreement]:
    """Runs the store holds that no tarball in the archive accounts for.

    §1: the store is a **derived** index over the archive, so a run with no tarball behind it
    cannot be re-derived and is not reproducible by anything. Two ways to get here, and the message
    names both because the remedies differ: the object was deleted, or it was replaced by one whose
    **capture digest, mode or `started_at`** differs — the three fields `identity.run_id` actually
    depends on — which changes the id and so shows up as this finding beside an un-ingested
    tarball. A replacement that keeps those three is caught by leg 1 instead, not here (#164).
    """
    accounted = {expectation.run_id for expectation in expectations}
    return [
        Disagreement(
            kind="orphan",
            run_id=run_id,
            archive_uri="",
            detail=(
                "the store holds this run and the archive has no tarball for it. The store is a "
                "derived index (§1), so nothing can re-derive this run: the object was deleted, or "
                "replaced by one whose capture digest, mode or started_at differs — the three "
                "fields run_id depends on — and which therefore carries a different id (#164). "
                "Check for an un-ingested tarball naming the same capture"
            ),
        )
        for run_id in sorted(set(store_run_ids) - accounted)
    ]


def reconcile(
    expectations: Sequence[RunExpectation],
    actual_by_run: Mapping[str, Mapping[str, int]],
    store_run_ids: Iterable[str],
    *,
    unreadable: Sequence[Disagreement] = (),
) -> Reconciliation:
    """Every run in the archive, the runs in the store the archive does not explain, and the
    objects in the archive that could not be read at all."""
    disagreements: list[Disagreement] = list(unreadable)
    for expectation in expectations:
        disagreements.extend(compare_run(expectation, actual_by_run.get(expectation.run_id, {})))
    disagreements.extend(orphans(store_run_ids, expectations))
    return Reconciliation(runs_checked=len(expectations), disagreements=tuple(disagreements))


def format_report(result: Reconciliation, *, dataset: str, archive: str) -> str:
    """The report, grouped by run.

    Never a bare pass/fail: a count with no detail is not a check anyone can act on.
    """
    lines = [
        f"reconcile_store: {result.runs_checked} run(s) in {archive}, checked against {dataset}"
    ]
    if result.agrees:
        lines.append("reconcile_store: the store agrees with the archive on every run")
        return "\n".join(lines) + "\n"

    by_run: dict[str, list[Disagreement]] = {}
    for item in result.disagreements:
        by_run.setdefault(item.run_id, []).append(item)

    lines.append(
        f"reconcile_store: {len(result.disagreements)} disagreement(s) across {len(by_run)} run(s)"
    )
    for run_id, items in sorted(by_run.items()):
        uri = next((item.archive_uri for item in items if item.archive_uri), "not in the archive")
        lines.append(f"\n  run {run_id}  ({uri})")
        for item in items:
            where = f" {item.table}" if item.table else ""
            if item.expected is None:
                numbers = ""
            elif item.kind == "self-report":
                # **Not "store has"**: leg 2's `actual` is the PARSE count, and the store is not
                # party to it. One report carrying both kinds otherwise printed two different
                # claims about what the store holds, for one table.
                numbers = f" run block says {item.expected}, the document parses to {item.actual}"
            else:
                numbers = f" expected {item.expected}, store has {item.actual}"
            lines.append(f"    [{item.kind}]{where}{numbers}")
            lines.append(f"      {item.detail}")
    return "\n".join(lines) + "\n"


# --- the impure part: asking BigQuery and reading the archive ------------------------------------


def row_counts(bq, dataset: str, columns: Mapping[str, str]) -> dict[str, dict[str, int]]:
    """Every run's row count in every table, in one query.

    One statement rather than four, because four would be four points in time: a backfill running
    beside this would be counted mid-flight in one table and after it in another, and the
    disagreement would be an artifact of the tool.
    """
    from flabeldb.query import table as qualified

    selects = [
        f"SELECT '{name}' AS table_name, {column} AS run_id, COUNT(*) AS rows_held "
        f"FROM {qualified(bq, dataset, name)} GROUP BY {column}"
        for name, column in columns.items()
    ]
    sql = "\nUNION ALL\n".join(selects)
    found: dict[str, dict[str, int]] = {}
    for row in bq.query(sql).result():
        found.setdefault(row["run_id"], {})[row["table_name"]] = int(row["rows_held"])
    return found


def archive_expectations(
    *, archive: str, local_adc: bool
) -> tuple[list[RunExpectation], list[Disagreement]]:
    """Parse every tarball under `archive`, and **keep going when one cannot be read**.

    That second half is `ingest.backfill_over`'s argument, and this function got it wrong first:
    one unreadable object propagated out of the loop, was classified by `main` as a defect in this
    tool, and discarded the answers for every other run. `select_tarballs` matches anything ending
    `.tar.gz`, so a note or a hand-tarred file in the prefix was enough to produce no report at all
    — and #164 says a replaced tarball is possible rather than hypothetical.

    A tarball that cannot be parsed **is a finding about the archive**, which is this tool's
    subject, so it comes back as a `Disagreement` rather than as an exception.

    No `only` filter here: `--run-id` is applied by the caller, over the returned list, because a
    filter inside an I/O function is unreachable from a test that stubs the I/O.
    """
    import tempfile

    uris = ingest.list_tarballs(archive, local_adc=local_adc)
    found: list[RunExpectation] = []
    unreadable: list[Disagreement] = []
    for index, uri in enumerate(uris, start=1):
        print(f"reconcile_store: [{index}/{len(uris)}] {uri}", file=sys.stderr)
        try:
            with tempfile.TemporaryDirectory() as scratch:
                root = pathlib.Path(scratch)
                directory = ingest.extract(
                    ingest.fetch(uri, root / "run.tar.gz", local_adc=local_adc), root / "unpacked"
                )
                parsed = parse.of_directory(directory, ingested_at="1970-01-01T00:00:00.000000Z")
            found.append(expectation_of(parsed, uri))
        except Exception as error:  # noqa: BLE001 - recorded per URI, never ends the reconciliation
            if ingest.is_credential_failure(error):
                # Not a fact about this object — the identity failed, and every remaining fetch
                # will fail the same way. Propagated so `main` reports it as the environment.
                raise
            unreadable.append(
                Disagreement(
                    kind="parse-failed",
                    run_id="",
                    archive_uri=uri,
                    detail=(
                        f"this object is under the results prefix and could not be read as a "
                        f"published run — {type(error).__name__}: {error}. The archive is the "
                        f"system of record (§1), so an object in it that nothing can parse is a "
                        f"finding about the archive rather than about this tool"
                    ),
                )
            )
    return found, unreadable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconcile_store.py",
        description="check the label store against the archive it is derived from",
    )
    parser.add_argument("--project", default=None, metavar="ID")
    parser.add_argument("--dataset", default=client_module.DEFAULT_DATASET, metavar="NAME")
    parser.add_argument(
        "--archive",
        default=None,
        metavar="GS_URI",
        help="the results prefix. Defaults to $FLABEL_RESULTS_URI; never hardcoded (#162)",
    )
    parser.add_argument(
        "--run-id",
        action="append",
        default=None,
        metavar="ID",
        help="check only these runs. Repeatable — for investigating one disagreement",
    )
    parser.add_argument("--local-adc", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))

    archive = args.archive or os.environ.get("FLABEL_RESULTS_URI")
    if not archive:
        # **Not defaulted to the real bucket.** `tools/flabel-run:281` hardcodes it and that is one
        # of #162's named sites; adding a second one would make the CLAUDE.md guardrail less true
        # rather than more.
        print(
            "reconcile_store: no archive prefix. Pass --archive gs://…/results or set "
            "FLABEL_RESULTS_URI (the repo is public, so the bucket is not committed — see "
            ".env.example and #162).",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not archive.startswith("gs://"):
        print(f"reconcile_store: --archive {archive!r} is not a gs:// URI", file=sys.stderr)
        return EXIT_USAGE

    try:
        columns = run_id_columns()
    except ValueError as error:
        print(f"reconcile_store: {error}", file=sys.stderr)
        return EXIT_INTERNAL

    # **`except Exception`, not `except RuntimeError`.** `credentials(local_adc=True)` calls
    # `google.auth.default()`, whose `DefaultCredentialsError` derives from `GoogleAuthError` and
    # not from `RuntimeError` — so on a laptop with no ADC the narrower form let it escape `main`
    # and reach the interpreter as exit 1, the code this tool publishes as "they disagree".
    try:
        bq = client_module.client(project=args.project, local_adc=args.local_adc)
    except Exception as error:  # noqa: BLE001
        print(f"reconcile_store: cannot build a client — {error}", file=sys.stderr)
        return EXIT_USAGE

    # **Everything below is inside a handler, including the pure half and the write.** `reconcile`,
    # `format_report` and `stdout.write` sat outside the first version, so any failure in them —
    # and a plain `blfile | head`-style broken pipe — reached the interpreter as exit 1. The whole
    # point of EXIT_DISAGREES being 1 is that nothing else may produce it.
    try:
        expectations, unreadable = archive_expectations(
            archive=archive.rstrip("/"), local_adc=args.local_adc
        )
        actual = row_counts(bq, args.dataset, columns)

        wanted = set(args.run_id or ())
        if wanted:
            expectations = [item for item in expectations if item.run_id in wanted]
            unreadable = []
        # `runs` rows exist for every ingested run, so that table's keys are the store's run set.
        store_run_ids = [run_id for run_id, tables in actual.items() if tables.get("runs")]
        if wanted:
            store_run_ids = [run_id for run_id in store_run_ids if run_id in wanted]
            if not expectations and not store_run_ids:
                # **Not exit 0.** A typo in the one argument an operator uses to chase a single
                # disagreement otherwise reported "the store agrees with the archive on every run",
                # having downloaded the whole archive to compare nothing.
                print(
                    f"reconcile_store: --run-id {sorted(wanted)} matched nothing — neither the "
                    f"archive nor {args.dataset} holds any of those runs. Nothing was compared.",
                    file=sys.stderr,
                )
                return EXIT_USAGE

        result = reconcile(expectations, actual, store_run_ids, unreadable=unreadable)
        report = format_report(result, dataset=args.dataset, archive=archive)
        sys.stdout.write(report)
        sys.stdout.flush()
    except BrokenPipeError:
        # `reconcile_store.py | head`. The reader went away, which is not a disagreement.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return EXIT_OK
    except Exception as error:  # noqa: BLE001 - classified, never re-raised bare
        if ingest.is_credential_failure(error):
            print(
                f"reconcile_store: cannot reach GCP as this identity — "
                f"{type(error).__name__}: {error}\n\nNOTHING was compared, so this is not a "
                f"statement about {args.dataset}.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        traceback.print_exc()
        print(
            f"\nreconcile_store: internal error — {type(error).__name__}: {error}\n"
            f"\nThis is a DEFECT in reconcile_store, not a report about {args.dataset}. Exit "
            f"{EXIT_INTERNAL} is not {EXIT_DISAGREES}: nothing above says the two disagree.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL

    return EXIT_OK if result.agrees else EXIT_DISAGREES


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
