"""Load and validate the source registry (spec §5).

Validation is strict and every failure is hard. The registry decides which feeds may assert a
label and on what basis, so a typo'd key or an unknown class must stop the run rather than be
skipped: a source silently loaded with the wrong `source_class` changes what its labels mean,
and one silently ignored produces a run that looks complete while missing a whole feed.
"""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any, get_args

from flabel.errors import ConfigError
from flabel.models import AdmissionBasis, SourceClass, SourceSpec

SOURCE_CLASSES = frozenset(get_args(SourceClass))
ADMISSION_BASES = frozenset(get_args(AdmissionBasis))

REQUIRED_FIELDS = ("name", "url", "licence", "source_class", "admission_basis")
OPTIONAL_FIELDS = ("enabled",)

#: Sources whose rules carry ET-style `metadata:` keys (`confidence`, `signature_severity`).
#: `admission_basis = "metadata-filter"` is only meaningful for these — filtering on metadata
#: a source doesn't publish would admit nothing at all, which is indistinguishable from a
#: source that legitimately matched nothing. Spec §5 makes this a load-time failure.
ET_METADATA_SOURCES = frozenset({"et/open"})

PACKAGED_REGISTRY = "sources.toml"

#: A source name becomes a path component in a snapshot (`raw/<source>.rules`, spec §7) and is
#: recorded on every label as provenance. Names legitimately contain one `/` (`abuse.ch/urlhaus`),
#: so path construction from this string is unavoidable — which makes the charset the guard.
#: Without it, `--sources` with `name = "../../../.ssh/authorized_keys"` writes fetched rule
#: text outside the snapshot directory, and step 4 has no reason to expect that to be its job.
SOURCE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$")


def default_registry_path() -> Path:
    """The registry shipped inside the package.

    Lives under `src/flabel/data/` rather than at the repo root so that it resolves
    identically from a checkout, an editable install and a built wheel.
    """
    return Path(str(resources.files("flabel") / "data" / PACKAGED_REGISTRY))


def load_sources(path: Path | None = None) -> tuple[SourceSpec, ...]:
    """Read the registry at `path`, or the packaged one, validated.

    Returns sources sorted by name, so anything derived from the registry — a snapshot, a
    NOTICE file — is reproducible regardless of file order.
    """
    path = default_registry_path() if path is None else Path(path)

    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigError(f"source registry not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"source registry could not be read: {path}: {exc}") from exc

    try:
        # utf-8-sig, so a registry saved by a Windows editor doesn't fail with a cryptic
        # "Expected '=' after a key" caused by an invisible byte-order mark.
        document = tomllib.loads(raw.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"could not parse source registry {path}: {exc}") from exc

    entries = document.get("source")
    if not entries:
        raise ConfigError(f"source registry {path} declares no sources")
    if not isinstance(entries, list):
        # `[source]` instead of `[[source]]` is the likely human error, and iterating a dict
        # would otherwise produce a baffling complaint about strings.
        raise ConfigError(
            f"{path}: `source` must be a list of tables — write [[source]], not [source]"
        )

    specs = tuple(_build_spec(entry, path) for entry in entries)
    _reject_duplicates(specs, path)
    return tuple(sorted(specs, key=lambda spec: spec.name))


def _build_spec(entry: Any, path: Path) -> SourceSpec:
    if not isinstance(entry, dict):
        raise ConfigError(f"{path}: each [[source]] must be a table, got {type(entry).__name__}")

    name = entry.get("name", "<unnamed>")

    # Both reported together: a misspelled key produces *both* a missing field and an unknown
    # one, and reporting only the first sends the reader looking for the wrong mistake.
    problems = []
    missing = [field for field in REQUIRED_FIELDS if field not in entry]
    if missing:
        problems.append(f"missing {', '.join(missing)}")
    unknown = set(entry) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS)
    if unknown:
        # A typo'd key would otherwise read as a setting that took effect.
        problems.append(f"unknown field(s) {sorted(unknown)}")
    if problems:
        raise ConfigError(f"{path}: source {name!r} has {'; '.join(problems)}")

    for field in ("name", "url", "licence"):
        value = entry[field]
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(
                f"{path}: source {name!r} has a non-string or empty {field}: {value!r}"
            )

    if not SOURCE_NAME.match(name):
        raise ConfigError(
            f"{path}: source name {name!r} is not of the form `vendor/feed` in lowercase "
            f"[a-z0-9._-]. The name becomes a path component in a snapshot and is recorded "
            f"on every label, so it cannot contain path separators beyond one '/', '..', "
            f"whitespace or uppercase."
        )

    url = entry["url"]
    if not url.startswith("https://"):
        # Rules become labels. Fetching them over http:// or file:// would make the trust
        # root of every verdict either forgeable in transit or an arbitrary local file.
        raise ConfigError(
            f"{path}: source {name!r} has a non-HTTPS url: {url!r}. Rule feeds must be "
            f"fetched over HTTPS."
        )

    source_class = entry["source_class"]
    if source_class not in SOURCE_CLASSES:
        raise ConfigError(
            f"{path}: source {name!r} has unknown source_class {source_class!r}; "
            f"expected one of {sorted(SOURCE_CLASSES)}"
        )

    admission_basis = entry["admission_basis"]
    if admission_basis not in ADMISSION_BASES:
        raise ConfigError(
            f"{path}: source {name!r} has unknown admission_basis {admission_basis!r}; "
            f"expected one of {sorted(ADMISSION_BASES)}"
        )

    if admission_basis == "metadata-filter" and name not in ET_METADATA_SOURCES:
        raise ConfigError(
            f"{path}: source {name!r} uses admission_basis 'metadata-filter' but does not "
            f"publish ET-style metadata, so the filter would admit nothing. Sources known to "
            f"carry it: {sorted(ET_METADATA_SOURCES)}"
        )

    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"{path}: source {name!r} has non-boolean enabled: {enabled!r}")

    return SourceSpec(
        name=name,
        url=url,
        licence=entry["licence"],
        source_class=source_class,
        admission_basis=admission_basis,
        enabled=enabled,
    )


def _reject_duplicates(specs: tuple[SourceSpec, ...], path: Path) -> None:
    """Reject repeated names, compared case-insensitively.

    Case-folded because step 4 writes `raw/<source>.rules`: on a case-insensitive filesystem
    two names differing only in case would silently clobber each other's fetched rules.
    """
    seen: set[str] = set()
    for spec in specs:
        key = spec.name.casefold()
        if key in seen:
            raise ConfigError(f"{path}: duplicate source name {spec.name!r}")
        seen.add(key)


def enabled_sources(path: Path | None = None) -> tuple[SourceSpec, ...]:
    """Only the sources that should contribute rules.

    Exists so no caller has to remember to filter on `enabled` — forgetting would let a
    source the operator switched off keep producing labels. The complement is deliberately
    still available via `load_sources`, because a run must be able to report which sources
    were skipped: absence is never a signal (spec §2.5).
    """
    return tuple(spec for spec in load_sources(path) if spec.enabled)
