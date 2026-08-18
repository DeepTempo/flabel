"""Load and validate the source registry (spec §5).

Validation is strict and every failure is hard. The registry decides which feeds may assert a
label and on what basis, so a typo'd key or an unknown class must stop the run rather than be
skipped: a source silently loaded with the wrong `source_class` changes what its labels mean,
and one silently ignored produces a run that looks complete while missing a whole feed.
"""

from __future__ import annotations

import re
import tomllib
import unicodedata
from importlib import resources
from pathlib import Path
from typing import Any, get_args

from flabel.errors import ConfigError
from flabel.models import (
    COMBINING_CATEGORIES,
    EMOJI_JOINERS,
    AdmissionBasis,
    AdmissionPolicy,
    SourceClass,
    SourceSpec,
    is_marker,
)

SOURCE_CLASSES = frozenset(get_args(SourceClass))
ADMISSION_BASES = frozenset(get_args(AdmissionBasis))

REQUIRED_FIELDS = ("name", "url", "licence", "source_class", "admission_basis")
OPTIONAL_FIELDS = ("enabled", "exclude_classtypes", "exclude_msg_markers", "msg_brand_marker")

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
CLASSTYPE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

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
    document = _read_registry(path)

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


def _read_registry(path: Path) -> dict[str, Any]:
    """The parsed registry document, with the decoding rules stated once."""
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
    return document


#: Keys permitted in the registry's `[admission]` table. Unknown keys are refused for the same
#: reason a misspelled `[[source]]` field is (spec §5): a registry that loads with a setting
#: silently ignored is worse than one that refuses to load, because it reads as working — and
#: here the ignored setting would be the one deciding which rules may assert a verdict.
ADMISSION_FIELDS = ("exclude_classtypes", "exclude_msg_markers", "msg_brand_marker")


def load_admission_policy(path: Path | None = None) -> AdmissionPolicy:
    """Read the `[admission]` table from the registry, or return the permissive default (#75).

    **In the registry rather than on the CLI**, and the reason outlived its original premise.
    This said "spec §12's contract is closed — Phase 2 adds no flags"; #132 reopened it for
    `--both`, so that half no longer argues anything. What does, and always did the real work: the
    policy belongs inside admission, therefore inside `snapshot_id`, so the rules a label cites are
    exactly the rules the policy admitted and the two cannot drift apart. A CLI flag would sit
    outside the snapshot and break that. `--sources` already exists as the override.

    **In one table rather than per source**, because the policy is about kinds of rule, not about
    feeds. `pawpatrules` is one source containing both direct detections and policy observations
    (#75), which is why no per-source setting could express this; stating it nine times would
    just be one decision with nine chances to disagree with itself. A per-source override is a
    pure addition if a feed ever needs one.

    An absent table admits everything, so an existing registry keeps its current behaviour.
    """
    path = default_registry_path() if path is None else Path(path)
    document = _read_registry(path)

    table = document.get("admission")
    if table is None:
        return AdmissionPolicy()
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: `admission` must be a table — write [admission]")

    unknown = sorted(set(table) - set(ADMISSION_FIELDS))
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s) in [admission]: {', '.join(unknown)}. "
            f"Known keys: {', '.join(ADMISSION_FIELDS)}."
        )

    return AdmissionPolicy(
        exclude_classtypes=_classtypes(table.get("exclude_classtypes", []), path, "[admission]"),
        exclude_msg_markers=_markers(table.get("exclude_msg_markers", []), path, "[admission]"),
        msg_brand_marker=_brand(table.get("msg_brand_marker"), path, "[admission]"),
    )


def _classtypes(value: Any, path: Path, where: str) -> frozenset[str]:
    """Validate and casefold one `exclude_classtypes` list, wherever it was written.

    Shared by `[admission]` and by each `[[source]]` (#113) rather than restated, because the
    same four mistakes are available in both places and two copies would drift — the per-source
    copy being the one nobody would think to update. `where` names the table, so a message about
    a per-source list does not read as a message about the global one.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{path}: {where} `exclude_classtypes` must be a list of strings")
    for item in value:
        if not item.strip():
            raise ConfigError(f"{path}: {where} `exclude_classtypes` contains an empty classtype")
        if not CLASSTYPE_NAME.fullmatch(item):
            # A classtype that cannot appear in a rule would silently exclude nothing, which is
            # the same failure as a misspelled key: it reads as a policy that is in force.
            raise ConfigError(
                f"{path}: {where} {item!r} is not a valid classtype name. A classtype that no "
                f"rule can declare would exclude nothing while appearing to be in force."
            )
    return frozenset(item.casefold() for item in value)


def _markers(value: Any, path: Path, where: str) -> frozenset[str]:
    """Validate one `exclude_msg_markers` list (#117).

    Sibling of `_classtypes`, and separate rather than generalised because the four ways to get
    it wrong are different ones. What both share is the failure they exist to prevent: a policy
    that cannot match anything reads, in a registry, exactly like a policy that is in force —
    which is issue #75 in the mechanism built to prevent issue #75.

    The sharp case is an **ASCII** entry. `admit.marker_of` stops at the first ASCII character,
    because past it the `msg:` is prose, so `exclude_msg_markers = ["OBS"]` could never match a
    rule however many there were. Rejected at load rather than admitted as a no-op.

    A **multi-character** entry is refused for the same reason one character further on: the
    marker is a single pictograph, and a two-emoji entry describes a rule shape that exists
    (34 rules are marked fire-then-eye) but that `marker_of` reports as its first character.
    Accepting it would silently exclude nothing. Joiners and variation selectors are stripped
    first, so a pirate flag written as its four-codepoint ZWJ sequence is accepted and stored
    as the flag itself — which is what `marker_of` returns for those 6,910 rules.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{path}: {where} `exclude_msg_markers` must be a list of strings")
    markers = set()
    for item in value:
        reduced = "".join(
            c
            for c in item
            if c not in EMOJI_JOINERS and unicodedata.category(c) not in COMBINING_CATEGORIES
        )
        if not reduced:
            raise ConfigError(f"{path}: {where} `exclude_msg_markers` contains an empty marker")
        if len(reduced) > 1:
            raise ConfigError(
                f"{path}: {where} {item!r} is more than one marker. `marker_of` reports the "
                f"first pictograph of a rule's marker run, so a multi-marker entry could never "
                f"equal what it is compared against."
            )
        if not is_marker(reduced):
            raise ConfigError(
                f"{path}: {where} {item!r} is not a marker. A marker is the symbol leading a "
                f"rule's `msg:` (`models.is_marker`), and "
                f"`marker_of` returns nothing else — so a letter, a quotation mark, an ASCII "
                f"word or a non-breaking space would exclude nothing while sitting in the "
                f"registry looking like a policy that is in force."
            )
        markers.add(reduced)
    return frozenset(markers)


def _brand(value: Any, path: Path, where: str) -> str | None:
    """Validate a `msg_brand_marker` — the marker a feed puts on every rule (#117).

    Same bar as `_markers`, one value instead of a list. Absent is the ordinary case: eight of
    the nine feeds write no marker at all, and `marker_of` without a brand simply returns the
    first pictograph it finds.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{path}: {where} `msg_brand_marker` must be a string")
    reduced = "".join(
        c
        for c in value
        if c not in EMOJI_JOINERS and unicodedata.category(c) not in COMBINING_CATEGORIES
    )
    if len(reduced) != 1 or not is_marker(reduced):
        raise ConfigError(
            f"{path}: {where} `msg_brand_marker` {value!r} is not a single pictograph. A brand "
            f"that matches nothing is worse than none: every rule then keeps its brand as its "
            f"marker, and a policy naming a real marker excludes nothing."
        )
    return reduced


def load_admission_policies(path: Path | None = None) -> dict[str, AdmissionPolicy]:
    """Each source's *effective* admission policy, keyed by source name (#113).

    A `[[source]]` may carry its own `exclude_classtypes`, and it is **unioned** with the global
    `[admission]` list rather than replacing it: a feed can only ever be made more restricted.
    Replace semantics would let a per-source list silently re-admit `policy-violation` for one
    feed — issue #75 returning through the mechanism built to prevent it — and would mean reading
    two places to know what a feed admits.

    Why a per-source list exists at all, when `load_admission_policy` argues the policy is about
    kinds of rule rather than feeds: because one feed's *taxonomy* differs. Measured 2026-08-16
    on a real internet-facing capture (263,895 packets, 24h, one public IP), `pawpatrules`
    contributed 599 of 600 source entries, and 587 of those came from two `misc-activity` rules
    identifying the Censys and Palo Alto Expanse internet scanners. Excluding `misc-activity`
    globally is not available: 146 of that snapshot's 274 misc-activity rules are in other feeds
    and include 45 `ET PHISHING` and 18 `ET MALWARE` rules. So the exclusion has to be narrowed
    to the feed whose taxonomy is the problem. That is a statement about pawpatrules, and it
    belongs beside pawpatrules.

    Read in one pass, so every source in a `rules update` is admitted under the same registry —
    a second read could see a file edited mid-run and give two feeds different terms inside one
    snapshot id.

    Every enabled source has an entry, so a caller may index it without a fallback: `admit` is
    called per source, and a missing key would be a `KeyError` after the network work and before
    anything is written.
    """
    path = default_registry_path() if path is None else Path(path)
    default = load_admission_policy(path)

    policies: dict[str, AdmissionPolicy] = {}
    for entry in _read_registry(path).get("source", []):
        if not isinstance(entry, dict):
            continue  # `enabled_sources` raises on this; here it is not ours to diagnose.
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        own = _classtypes(entry.get("exclude_classtypes", []), path, f"source {name!r}")
        markers = _markers(entry.get("exclude_msg_markers", []), path, f"source {name!r}")
        brand = _brand(entry.get("msg_brand_marker"), path, f"source {name!r}")
        policies[name] = AdmissionPolicy(
            exclude_classtypes=default.exclude_classtypes | own,
            exclude_msg_markers=default.exclude_msg_markers | markers,
            # Per-source wins over the global one: a brand is one feed's, and unlike the two
            # exclusion lists there is nothing to union — two brands is not a stricter policy.
            msg_brand_marker=brand or default.msg_brand_marker,
        )
    return policies


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
