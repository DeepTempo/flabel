"""One published run directory, as the rows of spec-label-store §4.

**Pure: filesystem reads only, no network and no clock.** `docs/spec.md` §3 classes a filesystem
read as pure, and that classification is what lets this run in CI — spec-label-store §2.4's testing
line records that the `requires_bigquery` tests run nowhere else, so anything put behind a client is
logic nothing verifies. The `gs://` fetch-and-untar is network I/O and lives in `ingest.py`; this
module is handed a directory that is already on disk.

`ingested_at` is a **parameter, not a call to the clock**, for the same reason: §5.5 lists it among
the things a rebuild does not reproduce, which is only a meaningful statement if the parser cannot
invent one.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from flabeldb import attest, identity

#: What `flabel-ingest` writes into `captures.uri_status` for a run block with no `uri` key.
#:
#: §6.1: flabel itself writes `gs` or `local`; only ingest writes this. Guessing `local` for an old
#: block would assert something that was never measured — the distinction `uri_status` exists for.
NOT_RECORDED = "not-recorded"

#: The document flabel writes. Read rather than assumed, so a schema bump is a loud failure.
LABELS_JSON = "labels.json"


@dataclass(frozen=True)
class ParsedRun:
    """Every row one run contributes, plus what it refused to write and why."""

    run: dict[str, Any]
    capture: dict[str, Any]
    flow_labels: list[dict[str, Any]] = field(default_factory=list)
    unmatched: list[dict[str, Any]] = field(default_factory=list)
    #: Flows not written because their proto is not writable (§3.2, #96).
    refused: int = 0
    refusal_notes: tuple[str, ...] = ()


def read(directory: pathlib.Path) -> dict[str, Any]:
    """The `labels.json` document from a run directory.

    A run that failed writes `run.json` and NO `labels.json`, and **the absence is the signal**
    (spec §12) — such a run is never ingested (§2.5), so this refuses rather than reaching for the
    other file.
    """
    path = pathlib.Path(directory) / LABELS_JSON
    if not path.is_file():
        raise FileNotFoundError(
            f"{directory} has no {LABELS_JSON}. A run that failed writes run.json and no labels — "
            f"the absence is the signal (spec §12), and a failed run is never ingested (§2.5)."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json(value: Mapping[str, Any]) -> str:
    """`value` in flabel's own canonical JSON form.

    Matches `flabel.labels.serialise`'s encoder settings exactly, and is duplicated rather than
    imported because the architecture guard allows `flabeldb` to reach only `flabel.models` and
    `flabel.errors` — the store must not import the pipeline. `test_flabeldb_parse.py` pins that
    two orderings of one run block produce one string, which is what the duplication risks.

    `sort_keys` is what makes it canonical: `runs.run_block` is a STRING column, so two ingests
    that serialised differently would be two values for one fact.
    """
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)


def _capture(run: Mapping[str, Any], run_id: str) -> dict[str, Any]:
    """One SIGHTING of a capture (§4.2).

    Append-only: a URI is a location, the digest is the identity.
    """
    given = run.get("input") or {}
    path = given.get("path")
    return {
        "capture_sha256": given.get("sha256"),
        "uri": given.get("uri"),
        "uri_status": given.get("uri_status") or NOT_RECORDED,
        "filename": pathlib.PurePath(path).name if path else None,
        "bytes": given.get("bytes"),
        "format": given.get("format"),
        "link_type": given.get("link_type"),
        "snaplens": list(given.get("snaplens") or ()),
        "observed_by_run_id": run_id,
        "observed_at": run.get("started_at"),
    }


def _flow(given: Mapping[str, Any], ip_proto: int) -> dict[str, Any]:
    """The flow as the store holds it: the canonical pair, and the orientation Zeek reported.

    `uid` becomes `zeek_uid`. The rename is deliberate — under `-D` a uid is positional, so it is
    "connection #N" in every capture, and a column called `uid` invites exactly the join §3.2
    forbids.
    """
    lo, hi = identity.canonical_pair(
        given["src_ip"], given["src_port"], given["dst_ip"], given["dst_port"]
    )
    ip_lo, _, port_lo = lo.rpartition(":")
    ip_hi, _, port_hi = hi.rpartition(":")
    return {
        "proto": given["proto"],
        "ip_proto": ip_proto,
        "ip_lo": ip_lo,
        "port_lo": int(port_lo),
        "ip_hi": ip_hi,
        "port_hi": int(port_hi),
        "src_ip": given["src_ip"],
        "src_port": given["src_port"],
        "dst_ip": given["dst_ip"],
        "dst_port": given["dst_port"],
        "ts_first": given["ts_first"],
        "ts_last": given["ts_last"],
        "zeek_uid": given.get("uid"),
        "ja4": given.get("ja4"),
        "ja4s": given.get("ja4s"),
        "server_name": given.get("server_name"),
    }


def _label(given: Mapping[str, Any]) -> dict[str, Any]:
    """One assertion about a flow. `value` is wrapped because §4.3's column is REPEATED while every
    kind in `models.LABEL_KINDS` is arity=single today — the column is the general shape."""
    value = given.get("value")
    return {
        "name": given.get("name"),
        "value": list(value) if isinstance(value, list) else [value],
        "tier": given.get("tier"),
        "sids": list(given.get("sids") or ()),
    }


#: `sources` columns, so a field the table does not declare cannot ride along into a load job.
_SOURCE_KEYS = (
    "tier",
    "source",
    "sid",
    "rev",
    "ruleset",
    "admission_basis",
    "licence",
    "classtype",
    "label_basis",
    "threat",
    "direction",
)

#: `unmatched` columns taken from the nested `detection`. `reason` sits beside it, not inside.
_UNMATCHED_KEYS = (
    "tier",
    "source",
    "sid",
    "rev",
    "threat",
    "ts",
    "proto",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "direction",
)


def rows(
    document: Mapping[str, Any],
    *,
    ingested_at: str,
    archive_uri: str | None = None,
) -> ParsedRun:
    """Every row this run contributes, in no particular order — `ingest.py` decides the ordering.

    Ordering is §5.3's concern rather than this module's: `flow_labels`, `unmatched` and `captures`
    load first and the `runs` row lands LAST, so a crash mid-ingest leaves rows nothing can reach.
    """
    run = document["run"]
    given = run.get("input") or {}
    capture_sha256 = given.get("sha256")
    run_id = identity.run_id(
        capture_sha256=capture_sha256,
        mode=run.get("mode"),
        started_at_iso=run.get("started_at"),
        flabel_version=run.get("flabel_version"),
    )
    attested, notes = attest.tiers(run)

    flow_labels: list[dict[str, Any]] = []
    refusals: list[str] = []
    for entry in document.get("labels") or ():
        flow = entry["flow"]
        proto = flow["proto"]
        if not identity.is_writable(proto):
            # Counted and named, never dropped quietly. Refusing loses no labels: such detections
            # are already `unsupported_transport` unmatched detections (§3.2).
            refusals.append(
                f"flow {flow.get('uid')!r} is {proto}, which carries no derivable ip_proto (#96), "
                f"so two such conversations between one host pair are indistinguishable"
            )
            continue
        ip_proto = identity.ip_proto_of(proto)
        flow_labels.append(
            {
                "run_id": run_id,
                "capture_sha256": capture_sha256,
                "flow_key": identity.flow_key(
                    capture_sha256,
                    proto=proto,
                    ip_proto=ip_proto,
                    src_ip=flow["src_ip"],
                    src_port=flow["src_port"],
                    dst_ip=flow["dst_ip"],
                    dst_port=flow["dst_port"],
                    ts_first_iso=flow["ts_first"],
                ),
                "flow": _flow(flow, ip_proto),
                "best_tier": entry.get("best_tier"),
                "labels": [_label(item) for item in entry.get("labels") or ()],
                "sources": [
                    {key: source.get(key) for key in _SOURCE_KEYS}
                    for source in entry.get("sources") or ()
                ],
            }
        )

    unmatched = [
        {
            "run_id": run_id,
            "capture_sha256": capture_sha256,
            **{key: (entry.get("detection") or {}).get(key) for key in _UNMATCHED_KEYS},
            "reason": entry.get("reason"),
        }
        for entry in document.get("unmatched_detections") or ()
    ]

    return ParsedRun(
        run={
            "run_id": run_id,
            "capture_sha256": capture_sha256,
            "mode": run.get("mode"),
            "tiers_attempted": list(run.get("tiers_attempted") or ()),
            "tiers_attested": list(attested),
            "attestation_notes": list(notes),
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "flabel_version": run.get("flabel_version"),
            "snapshot_id": (run.get("ruleset") or {}).get("snapshot_id"),
            "archive_uri": archive_uri,
            "run_block": canonical_json(run),
            "ingested_at": ingested_at,
        },
        capture=_capture(run, run_id),
        flow_labels=flow_labels,
        unmatched=unmatched,
        refused=len(refusals),
        refusal_notes=tuple(refusals),
    )


def of_directory(
    directory: pathlib.Path, *, ingested_at: str, archive_uri: str | None = None
) -> ParsedRun:
    """`read` then `rows`, which is the whole of what a local run directory needs."""
    return rows(read(directory), ingested_at=ingested_at, archive_uri=archive_uri)


__all__ = ["ParsedRun", "canonical_json", "of_directory", "read", "rows"]
