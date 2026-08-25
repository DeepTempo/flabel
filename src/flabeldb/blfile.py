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
import json
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
    parser.add_argument(
        "--as-of",
        default=None,
        metavar="TIMESTAMP",
        help="only runs ingested at or before this instant (§6.5). Filters ingested_at, never "
        "finished_at",
    )
    parser.add_argument(
        "--rebuild",
        default=None,
        metavar="COLLECTION",
        help="reproduce a prior collection from its own selection and pinned run set (§6.5)",
    )
    return parser


#: Flags `--rebuild` refuses, and why refusing is not pedantry. §6.5 names `--label` and `--as-of`
#: on §12's precedent for `--sources`: "a flag that looks like it changed the selection and did not
#: is worse than one that errors." The other three are refused on the identical reasoning — a
#: rebuild takes its selection from the document, so every one of these would be silently ignored.
REBUILD_REFUSES = ("label", "as_of", "capture", "limit", "allow_missing_origin")


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
        rows = query.authoritative(bq, dataset, captures, as_of=selection.as_of)
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


class PinnedRunMissing(Exception):
    """A run the prior document pinned is not in the store (§6.5's hard failure)."""


class PinnedRunExcluded(Exception):
    """A run the prior document pinned has since been **retracted** (§4.5).

    Reproduction is an audit capability; retraction is a correction. When they collide, retraction
    wins, because a retraction that can be reproduced past is not a retraction — and §4.5 is
    explicit that this table "covers the cases nobody wants to think about: a capture that must come
    out for legal or customer-data reasons, and a run later found to be mislabelled." Rebuilding
    such a document would re-publish exactly what somebody removed.

    The remedy is a fresh `blfile` without `--rebuild`, which reads `authoritative_runs` and so
    honours the exclusion — giving the corrected collection rather than the retracted one.
    """


def collect_rebuild(
    bq,
    dataset: str,
    prior: collection.Prior,
    *,
    built_at: str,
    version: str = __version__,
) -> collection.Built:
    """§6.5's `--rebuild`: the prior document's own selection, over its own pinned run set.

    **Authority is not re-decided, and it is not re-derived either.** `prior.authority` is read
    straight out of the document's `runs[]` entries, because the document already answered §5.1's
    "which run supplies this tier". Re-asking the store would make `--rebuild` a function of today's
    rows rather than of that document plus them, which is the one thing the flag promises it is not.

    The first version asked the store and got it wrong in a way worth remembering: it recovered each
    pinned run's tiers from `runs.tiers_attested`, which is what a run CLAIMED rather than what it
    supplies. §5.2 rule 2 turns on that difference, so a `--both` run attesting [1, 2] while
    supplying only tier 1 made the rebuild see two runs for one (capture, tier) and fail — naming a
    view it had never queried, about a consistent store. Every capture re-run at one tier was
    un-rebuildable.

    A pinned run the store does not hold is a **hard failure naming it** (§6.5), not a smaller
    collection. The store is a derived index (§1); a run it has lost cannot be re-derived, so a
    rebuild that quietly omitted it would answer a different question and look like a reproduction.
    """
    retracted = query.exclusions(bq, dataset, prior.pinned_runs)
    if retracted:
        # **Checked before anything is composed**, so nothing retracted is ever read into a record.
        raise PinnedRunExcluded(
            f"the document pins {len(retracted)} run(s) that have since been retracted (§4.5): "
            + "; ".join(_retraction(row) for row in retracted)
            + ". A retraction that can be reproduced past is not a retraction, and §4.5 covers "
            "legal and customer-data removals as well as mislabelled runs. Run `blfile` WITHOUT "
            "--rebuild to get the corrected collection: it reads authoritative_runs, which "
            "anti-joins this table"
        )
    run_ids = list(prior.pinned_runs)
    run_rows = query.runs(bq, dataset, run_ids)
    found = {row["run_id"] for row in run_rows}
    missing = [run_id for run_id in run_ids if run_id not in found]
    if missing:
        raise PinnedRunMissing(
            f"the document pins {len(run_ids)} run(s) and {len(missing)} are not in "
            f"{dataset}: {', '.join(missing)}. §1 makes the store a derived index over the "
            f"archive, so a run it no longer holds cannot be re-derived — re-ingest the tarball "
            f"(`flabel-ingest`) or reconcile the store first (tools/reconcile_store.py)"
        )
    # **The authority comes from the document, not from a query.** That is what makes a rebuild a
    # function of "that document plus the store" (§6.5) rather than of today's `tiers_attested`.
    merged = merge.compose(query.flow_labels(bq, dataset, run_ids), prior.authority)
    return collection.build(
        merged=merged,
        auth=prior.authority,
        sightings=query.sightings(bq, dataset, run_ids),
        run_rows=run_rows,
        selection=prior.selection,
        built_at=built_at,
        version=version,
    )


def _is_instant(value: str) -> bool:
    """Whether `value` parses as an ISO-8601 instant, `Z` included.

    `datetime.fromisoformat` accepts `Z` from 3.11 and this project requires 3.12, so no separate
    handling is needed. A date with no time is accepted — BigQuery reads it as midnight — because
    `--as-of 2026-08-25` is a reasonable thing to type.
    """
    try:
        datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    return True


def _retraction(row: object) -> str:
    """One `run_exclusions` row as a sentence. §4.5 stores the reason so it stays auditable."""
    reason = row.get("reason")
    who = row.get("excluded_by")
    when = row.get("excluded_at")
    parts = [f"{row.get('run_id')}", f"reason {reason!r}"]
    if who:
        parts.append(f"by {who}")
    if when:
        parts.append(f"at {when}")
    return " ".join(parts)


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

    prior: collection.Prior | None = None
    if args.rebuild is not None:
        # §6.5, on §12's precedent for `--sources`: a flag that looks like it changed the selection
        # and did not is worse than one that errors. Checked BEFORE `--label` is validated, so
        # `--rebuild x --label nonsense` reports the conflict rather than the unknown kind.
        # `is not None` and an explicit falsity check per kind. `not in (None, False, ())` was the
        # first form and `0 == False` in Python, so `--rebuild x --limit 0` slipped the refusal and
        # got the generic "selects nothing" message instead — right code, wrong explanation.
        supplied = [
            name
            for name in REBUILD_REFUSES
            if (getattr(args, name) is not None and getattr(args, name) is not False)
        ]
        if supplied:
            flags = ", ".join(f"--{name.replace('_', '-')}" for name in supplied)
            print(
                f"blfile: --rebuild takes its selection from the document, so {flags} would be "
                f"silently ignored. §6.5 refuses them rather than appear to honour them.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            document = json.loads(pathlib.Path(args.rebuild).read_text(encoding="utf-8"))
            prior = collection.read_prior(document)
        except OSError as error:
            print(f"blfile: cannot read {args.rebuild!r} — {error}", file=sys.stderr)
            return EXIT_USAGE
        except json.JSONDecodeError as error:
            print(f"blfile: {args.rebuild!r} is not JSON — {error}", file=sys.stderr)
            return EXIT_USAGE
        except collection.NotACollection as error:
            print(f"blfile: {args.rebuild!r} cannot be rebuilt — {error}", file=sys.stderr)
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
    if args.as_of is not None and not _is_instant(args.as_of):
        # Checked here rather than left to BigQuery. `--as-of yesterday` bound a `TIMESTAMP`
        # parameter the service rejected, and the failure surfaced as a traceback plus "This is a
        # DEFECT in blfile" at exit 3 — for a typo. The value is also written verbatim into the
        # published `selection.as_of`, so a malformed cutoff would become part of the provenance.
        print(
            f"blfile: --as-of {args.as_of!r} is not an ISO-8601 instant. Pass something like "
            f"2026-08-25T00:00:00Z; §6.5 compares it against `ingested_at`.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    selection = (
        prior.selection
        if prior is not None
        else collection.Selection(
            labels=wanted,
            captures=tuple(args.capture or ()),
            limit=args.limit,
            allow_missing_origin=args.allow_missing_origin,
            as_of=args.as_of,
        )
    )

    try:
        bq = client_module.client(project=args.project, local_adc=args.local_adc)
    except RuntimeError as error:
        print(f"blfile: {error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        if prior is not None:
            built = collect_rebuild(bq, args.dataset, prior, built_at=now_iso())
        else:
            built = collect(bq, args.dataset, selection, built_at=now_iso())
    except (PinnedRunMissing, PinnedRunExcluded) as error:
        # §6.5's hard failure. A statement about the store, so it shares 1 with the conflicts below.
        print(f"blfile: cannot reproduce {args.rebuild!r} — {error}", file=sys.stderr)
        return EXIT_REFUSED
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

    try:
        _report(built, selection, args.dataset)
        reproduced = True
        if prior is not None:
            # **Inside the handler.** `comparable` runs `serialise`, which raises on a non-finite
            # number, and `differences` indexes into records — so a valid-JSON-but-wrong-shaped
            # `--rebuild` file reached the interpreter as exit 1, the code reserved for a refusal
            # about the store. `read_prior` now type-checks the document; this covers the rest.
            reproduced = _report_reproduction(prior, built, args.rebuild)
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
    except Exception as error:  # noqa: BLE001 - anything left is a defect, and must not be exit 1
        traceback.print_exc()
        print(
            f"\nblfile: internal error while reporting — {type(error).__name__}: {error}\n"
            f"\nThis is a DEFECT in blfile. Exit {EXIT_INTERNAL} is not {EXIT_REFUSED}: nothing "
            f"above says the store disagrees.",
            file=sys.stderr,
        )
        return EXIT_INTERNAL
    # A rebuild that did not reproduce is a statement about the DATA — the store no longer yields
    # what that document recorded — so it shares 1 with the conflicts above rather than being a
    # defect or a usage error. Exit 0 would make `--rebuild` a command that cannot fail.
    return EXIT_OK if reproduced else EXIT_REFUSED


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


def _report_reproduction(prior: collection.Prior, built: collection.Built, path: str) -> bool:
    """§6.5's verdict: did this rebuild reproduce that document?

    **Over records, with `built_at` excluded** — not byte-for-byte, which is unachievable and is the
    same error `docs/spec.md` §10 already corrected for a run's output.

    `builder` is compared separately and **never fails the reproduction**, because §6.5 asks only
    that a mismatch be "reported naming both". It is a fact about the two builds rather than a
    difference in the records — but it is printed first, because a changed `LABEL_KINDS` changes
    what `--label verdict` *means*, and a reader needs that before they read anything below it.
    """
    moved = collection.builder_differences(prior.builder, built.document["builder"])
    if moved:
        print(
            f"blfile: this build is not the build that wrote {path!r} — {len(moved)} builder "
            f"field(s) differ. The records may still match; a changed label_kinds or store_schema "
            f"means they would be answering a slightly different question.",
            file=sys.stderr,
        )
        for line in moved:
            print(f"  {line}", file=sys.stderr)

    found = collection.differences(
        collection.comparable(prior.document), collection.comparable(built.document)
    )
    if not found:
        print(
            f"blfile: REPRODUCED {path!r} — {built.document['selection']['flows']} flow(s), "
            f"identical over records with built_at excluded (§6.5)",
            file=sys.stderr,
        )
        return True
    print(
        f"blfile: DID NOT reproduce {path!r} — {len(found)} difference(s). The document pins its "
        f"run set, so this means the rows those runs hold have changed, not that a different "
        f"selection was made.",
        file=sys.stderr,
    )
    for line in found:
        print(f"  {line}", file=sys.stderr)
    return False


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
