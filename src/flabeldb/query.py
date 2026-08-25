"""Reading the store — the four queries `blfile` composes a collection from.

Impure by definition, and deliberately thin: everything that *decides* anything lives in
`merge.py` and `collection.py`, which are pure and run in CI. §2's testing line records that the
`requires_bigquery` tests run on `fl-replay` and nowhere else, so a rule that reached this module
would be a rule the merge gate cannot check.

**Nothing here limits or paginates the flow rows.** `--limit` is applied after composition, in
`collection.build`: a flow's rows come from up to one run per tier (§4.6), and a `LIMIT` in SQL
would cut a flow's tier-2 row off from its tier-1 one and merge half of it. §5.2 accepts the scale
this implies — a few hundred labels per capture is not a scale problem, and pulling rows and
composing them in Python is the whole reason the merge is not in SQL.

**Identifiers are interpolated; row filters are parameters.** A dataset name is part of a table
path rather than a value, so no `ScalarQueryParameter` can carry it — the same split `cli._show`
makes, guarded by the same `IDENTIFIER` pattern, imported rather than written out a second time.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from flabeldb import client as client_module
from flabeldb import schema
from flabeldb.cli import IDENTIFIER

#: Every read joins through `runs` (§5.3), and `authoritative_runs` already anti-joins
#: `run_exclusions` (§4.6), so nothing here repeats either rule.
VIEW = "authoritative_runs"


def table(bq, dataset: str, name: str) -> str:
    """A fully-qualified table path, with the guards on the parts that cannot be query parameters.

    **Both identifiers are checked, not just the dataset.** `blfile` validates `--project`, but
    `client.client` falls back to `$GCP_PROJECT` when the flag is absent and nothing validated
    that — so on `fl-replay`, where the project id comes from `flabel.env` rather than a flag, the
    unchecked half was the one actually in use. Two identifiers reach a table path; one guard
    covered one of them.

    `fullmatch`, not `match`: `IDENTIFIER` is anchored with `$`, which also matches *before* a
    trailing newline, and `models` records the same correction in its own note about the two.
    """
    for label, value in (("dataset", dataset), ("project", bq.project)):
        if not value or not IDENTIFIER.fullmatch(str(value)):
            raise ValueError(
                f"{label} {value!r} is not a BigQuery identifier. It is interpolated into SQL — a "
                f"{label} name is part of a table path, not a value — so it is checked, not bound"
            )
    return f"`{bq.project}.{dataset}.{name}`"


def _rows(bq, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
    bigquery = client_module._bigquery()
    config = bigquery.QueryJobConfig(query_parameters=list(parameters)) if parameters else None
    return [dict(row) for row in bq.query(sql, job_config=config).result()]


def _strings(name: str, values: Iterable[str]):
    bigquery = client_module._bigquery()
    return bigquery.ArrayQueryParameter(name, "STRING", list(values))


def capture_shas(bq, dataset: str, wanted: Sequence[str]) -> list[str]:
    """`--capture <sha|name>` resolved to digests (§6.3).

    Matched against `capture_sha256` **or** `filename`, because §3.1 makes the digest the identity
    while an operator holds a file name. A value matching neither simply contributes nothing; the
    caller reports the shortfall, since "no such capture" and "that capture has no labels" are
    different facts and this function can only see one of them.
    """
    if not wanted:
        return []
    sql = (
        f"SELECT DISTINCT capture_sha256 FROM {table(bq, dataset, 'captures')} "
        "WHERE capture_sha256 IN UNNEST(@wanted) OR filename IN UNNEST(@wanted)"
    )
    return sorted(row["capture_sha256"] for row in _rows(bq, sql, [_strings("wanted", wanted)]))


def authoritative(
    bq, dataset: str, captures: Sequence[str] = (), *, as_of: str | None = None
) -> list[dict[str, Any]]:
    """For each (capture, tier), the run that currently supplies it — or that supplied it at
    `as_of`.

    Without `as_of` this reads §4.6's view, which is what the BigQuery console sees and what LS-7
    has always used. With it, the view cannot help: a view takes no parameters, and §6.5's cutoff
    filters on `ingested_at`. So the **same statement** is re-rendered from the **same file** as a
    bare parameterised SELECT (`schema.render_view`), which is how `--as-of` gets the supersession
    rule without §9's forbidden second copy of it.

    `as_of` is bound as a `TIMESTAMP` parameter, never interpolated — it is a value, unlike the
    dataset.
    """
    bigquery = client_module._bigquery()
    parameters: list[Any] = []
    if as_of is None:
        sql = f"SELECT capture_sha256, tier, run_id FROM {table(bq, dataset, VIEW)}"
    else:
        # The rendered body already projects (capture_sha256, tier, run_id) and ends at
        # `WHERE recency = 1`, so it is a complete SELECT and needs no wrapping.
        if not IDENTIFIER.fullmatch(dataset):
            raise ValueError(f"dataset {dataset!r} is not a BigQuery identifier")
        sql = schema.render_view(VIEW, dataset, as_of=True, ddl=False).rstrip().rstrip(";")
        sql = f"SELECT capture_sha256, tier, run_id FROM ({sql})"
        parameters.append(bigquery.ScalarQueryParameter("as_of", "TIMESTAMP", as_of))
    if captures:
        # Always `WHERE`, never `AND`: both branches leave an outer SELECT with no predicate on it.
        # A first version chose between them by looking for " WHERE " in `sql`, which the rendered
        # body contains internally — so the as-of path produced `SELECT ... FROM (...) AND ...`.
        sql += " WHERE capture_sha256 IN UNNEST(@captures)"
        parameters.append(_strings("captures", captures))
    return _rows(bq, sql + " ORDER BY capture_sha256, tier", parameters)


def exclusions(bq, dataset: str, run_ids: Sequence[str]) -> list[dict[str, Any]]:
    """§4.5's retractions for the given runs, with their reasons.

    `authoritative_runs` anti-joins this table, so the ordinary read path never sees an excluded
    run and never has to ask. `--rebuild` does: it pins a run set recorded before the exclusion
    existed, so it is the one path that can resurrect a retracted run, and it has to look.
    """
    if not run_ids:
        return []
    sql = (
        f"SELECT run_id, reason, excluded_at, excluded_by "
        f"FROM {table(bq, dataset, 'run_exclusions')} WHERE run_id IN UNNEST(@runs) "
        f"ORDER BY run_id"
    )
    return _rows(bq, sql, [_strings("runs", run_ids)])


def flow_labels(bq, dataset: str, run_ids: Sequence[str]) -> list[dict[str, Any]]:
    """Every raw per-run row for the authoritative runs — §5.2's step 1.

    Raw, and not merged in SQL: revision 1 did that, and it created two implementations of the one
    rule the store exists to express, whose divergence would surface only on `--rebuild` — the
    command whose whole promise is that it does not diverge (§5.2).
    """
    if not run_ids:
        return []
    sql = (
        f"SELECT run_id, capture_sha256, flow_key, flow, best_tier, labels, sources "
        f"FROM {table(bq, dataset, 'flow_labels')} WHERE run_id IN UNNEST(@runs)"
    )
    return _rows(bq, sql, [_strings("runs", run_ids)])


def runs(bq, dataset: str, run_ids: Sequence[str]) -> list[dict[str, Any]]:
    """The run blocks §6.4 embeds verbatim, plus nothing else — `run_block` is the whole payload."""
    if not run_ids:
        return []
    sql = (
        f"SELECT run_id, run_block FROM {table(bq, dataset, 'runs')} WHERE run_id IN UNNEST(@runs)"
    )
    return _rows(bq, sql, [_strings("runs", run_ids)])


def sightings(bq, dataset: str, run_ids: Sequence[str]) -> list[dict[str, Any]]:
    """`captures` rows for the authoritative runs — §4.2's append-only sightings.

    Restricted by `observed_by_run_id` rather than by capture: `collection._origins` resolves the
    origin from the authoritative runs' own sightings, so a sighting by some superseded run is not
    a candidate and fetching it would only invite one.
    """
    if not run_ids:
        return []
    sql = (
        f"SELECT capture_sha256, uri, uri_status, filename, link_type, snaplens, "
        f"observed_by_run_id FROM {table(bq, dataset, 'captures')} "
        f"WHERE observed_by_run_id IN UNNEST(@runs)"
    )
    return _rows(bq, sql, [_strings("runs", run_ids)])


def run_ids_of(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """The distinct runs named by `authoritative_runs` rows, sorted."""
    return sorted({row["run_id"] for row in rows})
