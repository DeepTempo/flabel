"""The BigQuery client, and the one place the store's identity is decided.

Impure by definition. Kept separate from `schema.py` so that the schema and its comparison stay
CI-checkable: spec §2's testing line records that the `requires_bigquery` tests run nowhere, so
anything behind a client is unverified by the gate that guards merges.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from flabeldb import schema

#: Where the store lives. `us-central1` is a REQUIREMENT, not a default: the results bucket is a
#: `US-CENTRAL1` *regional* bucket, a load job needs a compatible dataset location, and BigQuery
#: job ids are namespaced `project:location.jobid` — so the location is part of the idempotency
#: namespace too (spec §10 M2, M4).
LOCATION = "us-central1"
DEFAULT_DATASET = "flabel"

_MISSING_EXTRA = (
    "the BigQuery client is not installed. This is the `db` extra, kept out of the base install "
    "so that `flabel` itself has no dependencies:\n"
    "\n"
    "    uv sync --extra db\n"
)


def _bigquery():
    """The `google.cloud.bigquery` module, or a readable failure.

    Imported lazily so `flabel-db --help` works without the extra, and so an operator who has not
    run `uv sync --extra db` reads a sentence naming the fix rather than an `ImportError`
    traceback from inside a library.
    """
    try:
        from google.cloud import bigquery
    except ImportError as error:  # pragma: no cover - exercised by the message test
        raise RuntimeError(_MISSING_EXTRA) from error
    return bigquery


def credentials(*, local_adc: bool = False):
    """The identity the store writes as — **named, never discovered**.

    ADC resolves `$GOOGLE_APPLICATION_CREDENTIALS`, then the user's
    `application_default_credentials.json`, then the GCE metadata server. Measured on `fl-replay`
    2026-08-20: that second file does not exist for the invoking user, so `google.auth.default()`
    would reach the instance service account **today** — and the day anyone runs
    `gcloud auth application-default login` there, ingestion silently changes identity and writes
    rows attributable to a person rather than the instance. Naming the credential makes that
    unreachable.

    `local_adc` is the documented escape for a laptop and the tests, where there is no metadata
    server. A flag rather than a fallback: a fallback would restore the ambiguity this avoids.

    Also measured, and the reason no `sudo` is needed anywhere here: as the unprivileged user on
    that box the metadata server returned the instance service account and minted a token that read
    the results bucket with HTTP 200, while plain `gcloud storage ls` failed — `gcloud` needs root
    because its credential store is per-user; a client library does not.
    """
    if local_adc:
        import google.auth

        found, _project = google.auth.default()
        return found
    from google.auth.compute_engine import Credentials

    return Credentials()


def client(*, project: str | None = None, local_adc: bool = False):
    """A BigQuery client for `project`, defaulting to `$GCP_PROJECT`."""
    bigquery = _bigquery()
    resolved = project or os.environ.get("GCP_PROJECT")
    if not resolved:
        raise RuntimeError(
            "no project: pass --project or set GCP_PROJECT (the repo is public, so the id is "
            "never committed — see .env.example)"
        )
    return bigquery.Client(
        project=resolved, credentials=credentials(local_adc=local_adc), location=LOCATION
    )


def to_bigquery(columns: Sequence[schema.Column]) -> list:
    """Our declaration, as the client's own `SchemaField` objects."""
    bigquery = _bigquery()
    return [
        bigquery.SchemaField(
            item.name,
            item.field_type,
            mode=item.mode,
            fields=to_bigquery(item.fields) if item.fields else (),
        )
        for item in columns
    ]


def from_bigquery(fields: Sequence) -> tuple[schema.Column, ...]:
    """The client's `SchemaField` objects, as our declaration.

    The inverse of `to_bigquery`, so `verify` compares like with like — `schema.differences` is
    pure and knows nothing about the client's types.
    """
    return tuple(
        schema.Column(
            name=field.name,
            field_type=field.field_type,
            mode=field.mode,
            fields=from_bigquery(field.fields) if field.fields else (),
        )
        for field in fields
    )


def live_schema(bq, dataset: str) -> Mapping[str, tuple[schema.Column, ...]]:
    """Every declared table that exists in `dataset`, in our own shape.

    A table absent from the dataset is simply absent from the result; `schema.differences` reports
    it. Asking per declared table rather than listing the dataset is deliberate — it means an
    unrelated table sharing the dataset is not reported as drift.
    """
    from google.api_core.exceptions import NotFound

    found: dict[str, tuple[schema.Column, ...]] = {}
    for name in schema.TABLES:
        try:
            table = bq.get_table(f"{bq.project}.{dataset}.{name}")
        except NotFound:
            # **Only NotFound.** A bare `except Exception` here was the first version, and it
            # converted "I could not ask" into "it is not there" — measured: with an expired
            # credential, `verify` reported every table as missing from the dataset and said
            # nothing about authentication. That is spec §2.5's failure exactly, in the one command
            # whose job is to report the truth about the dataset. Anything else propagates.
            continue
        found[name] = from_bigquery(table.schema)
    return found
