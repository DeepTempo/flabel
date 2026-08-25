"""`blfile` — build a `labels-collection` from the store (spec-label-store §6.3, §6.4).

    blfile [--label NAME]...   default: --label verdict. Repeatable, and ANDed
      --capture <sha|name>     restrict to one capture. Repeatable
      --limit <n>
      --output <file>
      --allow-missing-origin

**This is how anyone will actually read the store** (§5.2). Merged labels cannot be queried from
the BigQuery console — the merge is Python, not a view — and that was the accepted trade for having
one implementation of the rule instead of two.

The command is a thin shell over three modules that decide everything: `query` fetches, `merge`
composes, `collection` builds the document. All the judgement is in the two pure ones.

**Exit codes mirror `flabel-db`'s**, and 1 is narrow on purpose. 1 is a refusal about the *data* —
a cross-tier value conflict (§9) or a view returning two runs for one (capture, tier) — 2 is the
operator's environment or arguments, and 3 is a defect in `blfile`. A bare `raise` reaches the
interpreter as 1, which would report a data conflict for a bug in this file, so nothing here
re-raises.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import sys
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime

from flabel.models import LABEL_KINDS
from flabeldb import __version__, collection, merge, query
from flabeldb import client as client_module
from flabeldb.cli import IDENTIFIER

EXIT_OK = 0
#: The store said something this tool refuses to resolve on its behalf: two tiers disagreeing on a
#: single-arity label's value (§5.2, §9), or `authoritative_runs` naming two runs for one tier.
EXIT_REFUSED = 1
#: The operator's environment or arguments: no `db` extra, no project, an unknown `--label` (§6.3).
EXIT_USAGE = 2
#: A defect in `blfile` itself. Exists so that exit 1 can only ever mean the refusal above.
EXIT_INTERNAL = 3

#: §6.3: bare `blfile` selects `verdict`. Not `tuple(LABEL_KINDS)` — the default is *one* kind, and
#: ANDing every kind that exists would emit only flows carrying all of them.
DEFAULT_LABEL = "verdict"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blfile", description="build a labels-collection from the label store"
    )
    parser.add_argument("--project", default=None, metavar="ID")
    parser.add_argument("--dataset", default=client_module.DEFAULT_DATASET, metavar="NAME")
    parser.add_argument(
        "--local-adc",
        action="store_true",
        help="use ADC instead of the instance identity (§7.1) — a laptop, or the tests",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=None,
        metavar="NAME",
        help=f"a label kind to require; repeatable and ANDed. Default: {DEFAULT_LABEL}",
    )
    parser.add_argument("--capture", action="append", default=None, metavar="SHA256|NAME")
    parser.add_argument("--limit", type=int, default=None, metavar="N")
    parser.add_argument("--output", default=None, metavar="FILE")
    parser.add_argument(
        "--allow-missing-origin",
        action="store_true",
        help="emit flows whose capture has no recorded origin (§6.4). They are counted either way",
    )
    return parser


def unknown_labels(wanted: Sequence[str]) -> list[str]:
    """Requested kinds `LABEL_KINDS` does not carry.

    **Reads the table rather than holding a second copy of the names** (§6.2). A literal list here
    would be the 2026-08-19 failure again: a placeholder that every test agreed with, because the
    tests were written against the placeholder.
    """
    return [name for name in wanted if name not in LABEL_KINDS]


def collect(
    bq,
    dataset: str,
    selection: collection.Selection,
    *,
    built_at: str,
    version: str = __version__,
) -> collection.Built:
    """§5.2's four steps: which runs are authoritative, their raw rows, compose, build.

    Separate from `main` so the whole read-and-compose path is drivable from a fake client, which
    is what lets the ordering and the selection be checked in CI rather than only on `fl-replay`.

    **`--capture` is resolved to digests here, once, and `collection.build` never sees the name the
    operator typed.** §3.1 makes the digest the identity while a name is only an entry point, and
    §4.2's `captures` table is append-only — one row per *sighting* — so one capture legitimately
    carries several names. Filtering by name a second time, downstream, against the authoritative
    run's sighting alone, dropped every flow of a capture the SQL had already resolved correctly:
    `blfile --capture old-name.pcap` returned an empty collection at exit 0, which is exactly the
    absence-as-a-signal failure `docs/spec.md` §2.5 exists to prevent. Measured 2026-08-25.
    """
    captures = query.capture_shas(bq, dataset, selection.captures) if selection.captures else []
    if len(captures) > len(selection.captures):
        # §3.1: the digest is the identity, and a *name* need not be unique. Two captures both
        # called `capture.pcap` — ordinary on a box ingesting daily files — make one `--capture`
        # value select both, and silently widening a restriction is the opposite of what the
        # operator asked for. Said out loud rather than resolved: which one they meant is not
        # something this tool can know.
        print(
            f"blfile: {len(selection.captures)} --capture value(s) resolved to {len(captures)} "
            f"capture(s) — a filename is a location, not an identity (§3.1, §4.2). Pass the "
            f"sha256 to narrow it: {', '.join(captures)}",
            file=sys.stderr,
        )
    if selection.captures and not captures:
        # Every requested capture is unknown to the store. Distinguished from "known and unlabelled"
        # by the caller, because an unrestricted query here would silently build the whole corpus.
        rows: list = []
    else:
        rows = query.authoritative(bq, dataset, captures)
    auth = merge.authority(rows)
    run_ids = query.run_ids_of(rows)
    merged = merge.compose(query.flow_labels(bq, dataset, run_ids), auth)
    return collection.build(
        merged=merged,
        auth=auth,
        sightings=query.sightings(bq, dataset, run_ids),
        run_rows=query.runs(bq, dataset, run_ids),
        selection=dataclasses.replace(selection, captures=tuple(captures)),
        built_at=built_at,
        version=version,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))

    for flag, value in (("--project", args.project), ("--dataset", args.dataset)):
        # Checked BEFORE the client is built, so a malformed name never reaches a credential or a
        # statement. `cli.IDENTIFIER` is imported rather than copied: two patterns guarding one
        # interpolation is the duplicate-authority defect this repo keeps catching.
        if value is not None and not IDENTIFIER.match(value):
            print(
                f"blfile: {flag} {value!r} is not a BigQuery identifier (letters, digits, "
                f"underscores and hyphens). It is interpolated into SQL — a dataset name is part "
                f"of a table path, not a value, so it cannot be a query parameter.",
                file=sys.stderr,
            )
            return EXIT_USAGE

    wanted = tuple(args.label or (DEFAULT_LABEL,))
    unknown = unknown_labels(wanted)
    if unknown:
        # §6.3: an unknown name exits 2 naming the permitted set.
        print(
            f"blfile: unknown --label {unknown!r}. Permitted kinds come from models.LABEL_KINDS: "
            f"{sorted(LABEL_KINDS)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.limit is not None and args.limit < 1:
        print(f"blfile: --limit {args.limit} selects nothing; pass 1 or more", file=sys.stderr)
        return EXIT_USAGE

    selection = collection.Selection(
        labels=wanted,
        captures=tuple(args.capture or ()),
        limit=args.limit,
        allow_missing_origin=args.allow_missing_origin,
    )

    try:
        bq = client_module.client(project=args.project, local_adc=args.local_adc)
    except RuntimeError as error:
        print(f"blfile: {error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        built = collect(bq, args.dataset, selection, built_at=now_iso())
    except merge.MergeConflict as error:
        # §9: never silently pick a winner when two tiers disagree on a single-arity label's value.
        print(
            f"blfile: the store holds a disagreement this tool will not resolve for you — {error}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    except merge.StoreInconsistent as error:
        # A view returning two runs for one (capture, tier), or a `run_block` that will not parse.
        # A statement about the data, so it shares 1 with the conflict above and not 3 with a
        # defect in this file.
        #
        # **A named class, not `except ValueError`.** That is what this caught first, and it was far
        # broader than the code it published: `json.JSONDecodeError` IS a `ValueError`, and so is
        # every ordinary coding slip — `min()` on an empty sequence, `int()` on garbage — so a bug
        # in `collection.build` reported itself as a disagreement in the dataset. Exactly what the
        # `MergeConflict`-is-not-a-`ValueError` rule exists to prevent, one level up.
        print(f"blfile: the store is inconsistent — {error}", file=sys.stderr)
        return EXIT_REFUSED
    except Exception as error:  # noqa: BLE001
        if _is_credential_failure(error):
            print(
                f"blfile: cannot reach BigQuery as this identity — {type(error).__name__}: "
                f"{error}\n"
                f"\nOn fl-replay the instance identity is used and needs nothing. On a laptop pass "
                f"--local-adc and run `gcloud auth application-default login` first. NOTHING was "
                f"read, so this is not a statement about {args.dataset}.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        traceback.print_exc()
        print(
            f"\nblfile: internal error — {type(error).__name__}: {error}\n"
            f"\nThis is a DEFECT in blfile, not a report about {args.dataset}. Exit "
            f"{EXIT_INTERNAL} is not {EXIT_REFUSED}: nothing above says the store disagrees.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL

    _report(built, selection, args.dataset)
    try:
        text = collection.serialise(built.document)
        if args.output:
            write_document(pathlib.Path(args.output), text)
        else:
            sys.stdout.write(text)
    except BrokenPipeError:
        # `blfile | head`. The reader went away, which is not a failure of anything here — and
        # letting it escape prints "Exception ignored" past the interpreter and exits 1.
        _silence_broken_pipe()
        return EXIT_OK
    except OSError as error:
        # A `--output` path that does not exist, is not writable, or fills the disk. **The most
        # ordinary operator mistake there is**, and until this handler existed it escaped `main`
        # entirely and reached the interpreter as exit 1 — the code this tool publishes as "the
        # store holds a disagreement". An automation wrapper branching on 1 would have reported a
        # corrupt dataset for a typo'd path.
        print(f"blfile: cannot write {args.output!r} — {error}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def write_document(target: pathlib.Path, text: str) -> None:
    """Write the collection, whole or not at all.

    **UTF-8 is bound here, not left to the locale.** `Path.write_text` encodes with the *locale*
    encoding, which under `LANG=C` — the default in many container images, cron environments and CI
    runners — is ASCII, so one accented character in a rule's `msg` raises after the entire
    collection has been built. `labels.serialise_bytes` binds it for the same reason.

    **And it lands through a temporary**, following `models.partial_name` and issue #70: a
    collection is a larger, slower write than `labels.json` and is the artifact a training pipeline
    consumes, so a killed process must not leave a half-written file that looks finished. The name
    is hidden and suffixed for that convention's reason — a leftover temporary is not an artifact
    anything claims.
    """
    partial = target.with_name(f".{target.name}.partial")
    partial.write_bytes(text.encode("utf-8"))
    os.replace(partial, target)


def _silence_broken_pipe() -> None:
    """Keep the interpreter from re-raising on the flush at exit (CPython's documented recipe)."""
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, sys.stdout.fileno())


def now_iso() -> str:
    """`built_at`. The one clock reading here, and §6.5 excludes it from reproduction."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _report(built: collection.Built, selection: collection.Selection, dataset: str) -> None:
    """What the document cannot say for itself, on stderr so `--output -`-style piping is clean.

    A shortfall is **said out loud**. `docs/spec.md` §2.5 refuses to let absence be a signal, and a
    collection that came back empty because every flow was refused looks exactly like a corpus with
    nothing malicious in it.
    """
    selected = built.document["selection"]
    print(
        f"blfile: {dataset} — {selected['flows']} flow(s) across {selected['captures']} "
        f"capture(s), labels={selected['labels']} match=all",
        file=sys.stderr,
    )
    if built.refused:
        print(
            f"blfile: {built.refused} flow(s) could not be composed from the rows the store holds "
            f"and are NOT in this document. Each is named below; §4.5's run_exclusions is where a "
            f"run that should not supply them is retracted.",
            file=sys.stderr,
        )
        for note in built.refusal_notes:
            print(f"  {note}", file=sys.stderr)
    if built.flows_without_origin:
        # "in the selection", not "in this document": `flows_without_origin` counts the whole
        # selection while `flows` counts what was emitted, and `--limit` separates the two. Saying
        # 400 were "REFUSED" under `--limit 5` would blame the origin rule for a truncation the
        # operator asked for.
        emitted = "emitted anyway" if selection.allow_missing_origin else "REFUSED"
        print(
            f"blfile: {built.flows_without_origin} flow(s) in the selection have no recorded "
            f"origin and were {emitted}. Every run predating --source-uri carries uri_status "
            f"'not-recorded', so this is the headline requirement being unmet rather than a fault "
            f"(§6.4). Pass --allow-missing-origin to include them.",
            file=sys.stderr,
        )


def _is_credential_failure(error: BaseException) -> bool:
    """Whether the identity failed rather than the store being bad.

    Matched by TYPE and imported lazily, mirroring `cli._credential_failure_types`: the
    name-matching version of this missed 15 of the 18 classes in `google.auth.exceptions` (#157),
    and the lazy import is what lets `blfile` run its own error paths with no `db` extra installed.
    """
    try:
        from google.api_core.exceptions import Forbidden, RetryError, Unauthorized
        from google.auth.exceptions import GoogleAuthError
    except ImportError:  # pragma: no cover - the no-db-extra job
        return False
    return isinstance(error, (GoogleAuthError, Forbidden, Unauthorized, RetryError))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
