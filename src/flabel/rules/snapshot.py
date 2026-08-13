"""Content-addressed ruleset snapshots (docs/spec.md §7).

```
<root>/<snapshot_id>/
  manifest.json        the SnapshotManifest, plus manifest_version
  rules.rules          admitted rules, sorted by (source, sid)
  sid_index.json       which source each sid came from
  data/<source>/<file> companion data files the rules read (`dataset:`)
  raw/<source>.rules   as fetched, for audit
```

A snapshot is the unit of reproducibility, and `snapshot_id` is not a label attached to a
directory — it is a hash over the directory's content that anyone can recompute, and this module
recomputes it on every load. Four things follow.

* **The id covers everything the engine reads**: `rules.rules`, `sid_index.json`, and every
  companion data file. `pawpatrules` ships 18 `.lst` files that 26 of its rules read with
  `dataset:`, and a rule whose data file changed underneath it matches differently while its
  rule text stays byte-identical. `raw/` is deliberately *not* covered: it is the as-fetched
  audit copy, so hashing it would change the id whenever upstream edited a comment header.
* **`sid_index.json` exists because the manifest cannot answer "which source is sid 2011465?"**
  Spec §8 says the originating source is resolved from the snapshot, and per-source *counts*
  cannot do that. Deriving it from `raw/` filenames instead would resolve labels through a
  directory listing that nothing hashes and anyone can edit. The index is a file rather than a
  field on `SourceAdmission` because step 8 copies that struct into every `labels.json`, and
  21,221 integers per source do not belong in every output file.
* **Sorting is load-bearing.** Feeds arrive over the network in whatever order they respond, so
  if arrival order reached `rules.rules` two runs over identical rules would produce different
  ids and Goal 2 would be unreachable.
* **A snapshot is immutable.** Re-writing identical content returns the stored manifest
  untouched, and a directory whose content no longer hashes to its own name is a hard failure
  rather than something to repair — labels already emitted point at that id.

This module is classified impure in `test_architecture.py`: it writes files.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import fields
from pathlib import Path

import flabel
from flabel import models
from flabel.errors import SnapshotError
from flabel.models import SnapshotManifest, SourceAdmission
from flabel.rules import utc_now
from flabel.rules.admit import is_address_indicator

MANIFEST_NAME = "manifest.json"
RULES_NAME = "rules.rules"
SID_INDEX_NAME = "sid_index.json"
DATA_DIR = "data"
RAW_DIR = "raw"

#: Version of the on-disk snapshot format, written into `manifest.json`.
#:
#: It exists so that a field can ever be added. `_read_manifest` hard-fails on a key it does not
#: recognise — the right default when a manifest is the provenance of a label — which without a
#: version means the format could never change without every existing snapshot becoming
#: unreadable garbage rather than "written by an older flabel".
MANIFEST_VERSION = 1

#: Schema of `sid_index.json`, versioned separately: step 6 reads that file and nothing else.
#: 3 since the address-indicator correction. The history is worth keeping visible:
#:
#: * **1** — sources only.
#: * **2** — added `ioc_shaped`, computed by a *blocklist* of payload keywords. Measured wrong by
#:   588 rules: it counted `stamus/lateral`'s `dcerpc.iface` detections and `pawpatrules`'
#:   `tls_cert_expired` as indicators, because neither uses `content`.
#: * **3** — `address_indicator`, computed by an allowlist of non-detecting options.
#:
#: **Schemas 1 and 2 both read as "no classification recorded".** For 1 that is literally true.
#: For 2 it is a judgement: the data is there but was computed by a definition since measured to
#: be wrong, and trusting it would put a known-bad classification behind a label's `label_basis`.
#: Re-run `flabel rules update` to get a schema-3 index. This graceful path is the entire reason
#: the file carries a version separate from the manifest's (spec §7).
SID_INDEX_SCHEMA = 3
READABLE_SID_INDEX_SCHEMAS = (1, 2, 3)
#: Schemas whose classification is trusted. See above for why 2 is not among them.
CLASSIFIED_SID_INDEX_SCHEMAS = (3,)

#: Both re-exported from `models`, which owns the shape of a snapshot id so that this module
#: (which resolves an id to a directory) and `provenance.py` (which refuses to write an
#: unresolvable one onto a label) cannot disagree about it. `provenance.py` is a pure module, so
#: it must not reach into this one for the pattern. A directory in the rules root is a snapshot
#: if it is named like one; anything else — a scratch directory, an operator's notes — is
#: ignored by `list_snapshots`.
SNAPSHOT_ID_LENGTH = models.SNAPSHOT_ID_LENGTH
SNAPSHOT_ID = models.SNAPSHOT_ID

#: A rule's `sid`, which with the source name is the sort key spec §7 mandates.
SID = re.compile(r"\bsid\s*:\s*(\d+)")

#: A companion data file name. Names come from a third-party archive and become path components
#: under `data/<source>/`, so the charset is the guard — the same argument config.py makes for
#: source names. No separators and no leading dot, so `../` and dotfiles cannot appear.
DATA_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Prefix for the directory a snapshot is assembled in before it is renamed into place, so a
#: half-written snapshot never exists under a name something might load.
STAGING_PREFIX = ".staging-"


def snapshot_id_for(components: Mapping[str, bytes]) -> str:
    """The id of a snapshot whose hashed content is exactly `components`.

    `components` maps a snapshot-relative POSIX path to its bytes. The digest is

        for path in sorted(components):
            sha256 <- path (utf-8) || 0x00 || len(content) as 8 bytes big-endian || content

    and the id is the first 16 hex characters of it. Paths and lengths are inside the hash, not
    only the content: without them, renaming `data/pawpatrules/tor.lst` to `nrd.lst` — which
    changes which rules read what — would leave the id untouched, and so would moving bytes
    across a file boundary.
    """
    digest = hashlib.sha256()
    for path in sorted(components):
        content = components[path]
        digest.update(path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()[:SNAPSHOT_ID_LENGTH]


def render_rules(admitted: Mapping[str, Sequence[str]]) -> bytes:
    """The exact bytes of `rules.rules`, sorted by (source, sid).

    Separate from writing so the input to the hash is inspectable rather than a side effect.

    The rule text is the third sort key. Sid is not unique across all possible feeds, so without
    a total order two runs over the same rules could order them differently and produce
    different ids.
    """
    lines: list[str] = []
    for source in sorted(admitted):
        rules = sorted(admitted[source], key=lambda rule: (_sid_or_none(rule) or -1, rule))
        lines.extend(rule.strip() for rule in rules)
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_sid_index(admitted: Mapping[str, Sequence[str]]) -> bytes:
    """The exact bytes of `sid_index.json`:
    `{"schema": 3, "sources": {name: [sid, ...]}, "address_indicator": [sid, ...]}`.

    This is how step 6 resolves an alert's sid back to the source that admitted it, since
    `eve.json` does not carry the source. Three conditions are hard failures, because each makes
    that resolution wrong rather than merely incomplete:

    * **a rule with no `sid`** — unattributable, and Suricata would refuse to load it anyway;
    * **one sid twice within a source** — Suricata keeps one and drops the rest silently, so
      `rules_admitted` would overstate the ruleset actually loaded;
    * **one sid claimed by two sources** — a label would then name the source that did not fire.

    Measured 2026-08-12 across all nine live feeds: 116,208 distinct sids, zero duplicates
    within a source and zero collisions across sources. None of this costs anything today.
    """
    owners: dict[int, str] = {}
    index: dict[str, list[int]] = {}
    collisions: list[str] = []

    for source in sorted(admitted):
        sids: set[int] = set()
        for rule in admitted[source]:
            sid = _sid_or_none(rule)
            if sid is None:
                raise SnapshotError(
                    f"source {source!r} admitted a rule with no `sid`, which cannot be "
                    f"attributed to a source in a label and which Suricata would refuse to "
                    f"load: {rule[:120]!r}"
                )
            if sid in sids:
                raise SnapshotError(
                    f"source {source!r} admitted sid {sid} more than once. Suricata keeps one of "
                    f"them and drops the rest without saying so, so `rules_admitted` would "
                    f"overstate the ruleset actually loaded."
                )
            owner = owners.get(sid)
            if owner is not None and owner != source:
                collisions.append(f"{sid} ({owner} and {source})")
            owners[sid] = source
            sids.add(sid)
        index[source] = sorted(sids)

    if collisions:
        raise SnapshotError(
            f"{len(collisions)} sid(s) are claimed by more than one source: "
            f"{', '.join(collisions[:5])}. Suricata would load one rule and drop the other "
            f"without saying so, and a label would then name the source that did not fire."
        )

    # Inside `snapshot_id`, and that placement is load-bearing rather than convenient. The
    # classification changes what a label *means* — `direct` versus `indicator-reference` — while
    # leaving `rules.rules` untouched. Recorded in `manifest.json` it would sit outside the hash
    # (issue #48), and two snapshots sharing an id could then produce labels with different
    # bases, which is precisely the guarantee the id exists to give.
    address_indicator = sorted(
        sid
        for source in sorted(admitted)
        for rule in admitted[source]
        if (sid := _sid_or_none(rule)) is not None and is_address_indicator(rule)
    )
    document = {
        "schema": SID_INDEX_SCHEMA,
        "sources": index,
        "address_indicator": address_indicator,
    }
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def snapshot_components(
    admitted: Mapping[str, Sequence[str]],
    data: Mapping[str, Mapping[str, bytes]] | None = None,
) -> dict[str, bytes]:
    """Every file the snapshot id is taken over, keyed by its snapshot-relative path."""
    components = {
        RULES_NAME: render_rules(admitted),
        SID_INDEX_NAME: render_sid_index(admitted),
    }
    for source, files in sorted((data or {}).items()):
        if source not in admitted:
            raise SnapshotError(
                f"companion data supplied for {source!r}, which contributes no rules to this "
                f"snapshot. A data file with no rules reading it is not part of the ruleset."
            )
        for name, content in sorted(files.items()):
            if not DATA_FILE_NAME.match(name):
                raise SnapshotError(
                    f"companion data file {name!r} from {source!r} is not a plain file name. "
                    f"Names come from a third-party archive and become path components under "
                    f"{DATA_DIR}/, so anything with a separator, a leading dot or '..' is "
                    f"refused rather than written."
                )
            components[f"{DATA_DIR}/{source}/{name}"] = content
    return components


def write_snapshot(
    root: Path,
    admitted: Mapping[str, Sequence[str]],
    admissions: Sequence[SourceAdmission],
    raw: Mapping[str, str] | None = None,
    data: Mapping[str, Mapping[str, bytes]] | None = None,
    created_at: str | None = None,
) -> SnapshotManifest:
    """Write a snapshot under `root` and return its manifest.

    `raw`, `data` and `created_at` extend spec §7's three-argument signature. `raw` is how the
    `raw/<source>.rules` files the same section requires get their content. `data` carries the
    companion files the rules read, keyed source → file name → bytes; unlike `raw` it is part of
    the hash, because rules and the data they consult are one ruleset. `created_at` is injectable
    so the ordering `load_snapshot(root, None)` depends on is testable without sleeping.

    Idempotent: writing identical content twice yields one directory and the manifest of the
    first write. Its `created_at` still records when this ruleset first existed, which is what a
    label pointing at the id needs it to mean.
    """
    _verify_sources_agree(admitted, admissions)

    components = snapshot_components(admitted, data)
    if not components[RULES_NAME]:
        raise SnapshotError(
            "refusing to write a snapshot with no rules: Suricata would load it cleanly and "
            "label nothing, which is the silent under-reporting docs/spec.md §2.5 forbids."
        )

    snapshot_id = snapshot_id_for(components)
    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        created_at=utc_now() if created_at is None else created_at,
        flabel_version=flabel.__version__,
        sources=tuple(sorted(admissions, key=lambda admission: admission.name)),
        total_admitted=sum(admission.rules_admitted for admission in admissions),
        total_ja4_admitted=sum(admission.ja4_rules_admitted for admission in admissions),
    )

    destination = Path(root) / snapshot_id
    if destination.exists():
        return _existing(destination, snapshot_id)

    staging = Path(root) / f"{STAGING_PREFIX}{snapshot_id}"
    _build(staging, components, manifest, raw)
    try:
        staging.rename(destination)
    except OSError:
        # Another process finished the same snapshot first. Its content is identical by
        # construction — the id is the hash — so verify and adopt rather than compete.
        _remove_tree(staging)
        return _existing(destination, snapshot_id)
    return manifest


def load_snapshot(root: Path, snapshot_id: str | None) -> tuple[Path, SnapshotManifest]:
    """The directory and manifest of one snapshot; `None` means the newest.

    Never falls back to another snapshot when the requested one is missing: labels are only
    reproducible against a known ruleset, so silently substituting a different one would break
    the guarantee the id exists for (spec §7).
    """
    if snapshot_id is None:
        available = list_snapshots(root)
        if not available:
            raise SnapshotError(
                f"no usable ruleset snapshot found under {root}. Run `flabel rules update` "
                f"first, or point --rules-dir at the directory holding one."
            )
        snapshot_id = available[-1].snapshot_id

    if not SNAPSHOT_ID.match(snapshot_id):
        # The id becomes a path component under the rules directory and arrives from the command
        # line (`--ruleset-snapshot <id>`), so it is checked rather than joined blindly. It also
        # turns a typo into a message that names the mistake.
        raise SnapshotError(
            f"{snapshot_id!r} is not a ruleset snapshot id: expected {SNAPSHOT_ID_LENGTH} "
            f"lowercase hex characters, as printed by `flabel rules list`."
        )

    directory = Path(root) / snapshot_id
    if not directory.is_dir():
        raise SnapshotError(f"ruleset snapshot {snapshot_id!r} not found under {root}")

    manifest = _read_manifest(directory)
    if manifest.snapshot_id != snapshot_id:
        raise SnapshotError(
            f"snapshot {snapshot_id!r} contains a manifest claiming to be "
            f"{manifest.snapshot_id!r}; the directory is not what it says it is."
        )
    components = _verify_content(directory, snapshot_id)

    # `rules.rules` holds exactly one rule per line, so the manifest's own total is checkable
    # against the file it describes. The hash proves the content was not edited; this proves the
    # counts a run copies into `labels.json` describe that content.
    admitted = components[RULES_NAME].count(b"\n")
    if manifest.total_admitted != admitted:
        raise SnapshotError(
            f"snapshot {snapshot_id} says total_admitted={manifest.total_admitted} but "
            f"{RULES_NAME} holds {admitted} rules; its manifest does not describe it."
        )
    return directory, manifest


def load_sid_index(directory: Path) -> dict[int, str]:
    """Map each sid in a snapshot to the source that admitted it.

    This is the lookup spec §8 needs when parsing `eve.json`, which carries a signature id but
    not the ruleset it came from. Reading it from the hashed `sid_index.json` — rather than
    globbing `raw/*.rules` and taking the source from a file name — is what makes a label's
    stated source verifiable against the snapshot id.
    """
    path = Path(directory) / SID_INDEX_NAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotError(
            f"snapshot {Path(directory).name} has no {SID_INDEX_NAME}, so no alert from it could "
            f"be attributed to the source that raised it."
        ) from exc
    except OSError as exc:
        raise SnapshotError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc

    schema = document.get("schema") if isinstance(document, dict) else None
    if schema not in READABLE_SID_INDEX_SCHEMAS:
        raise SnapshotError(
            f"{path} is not a readable sid index: expected schema one of "
            f"{list(READABLE_SID_INDEX_SCHEMAS)}, found {schema!r}"
        )
    sources = document.get("sources")
    if not isinstance(sources, dict):
        raise SnapshotError(f"{path} has no `sources` object")

    index: dict[int, str] = {}
    for source, sids in sorted(sources.items()):
        if not isinstance(sids, list):
            raise SnapshotError(f"{path}: the sids for {source!r} are not a list")
        for sid in sids:
            # `bool` is an `int` in Python, and `true` in JSON must not become sid 1.
            if not isinstance(sid, int) or isinstance(sid, bool):
                raise SnapshotError(f"{path}: {sid!r} under {source!r} is not an integer sid")
            if index.get(sid, source) != source:
                raise SnapshotError(
                    f"{path}: sid {sid} is claimed by both {index[sid]!r} and {source!r}"
                )
            index[sid] = source
    return index


def load_address_indicators(directory: Path) -> frozenset[int] | None:
    """The sids in a snapshot whose rules fire on the address tuple alone (#75).

    An address-list rule establishes that a flow *reached a known-bad address*, not that the flow
    *is* the malicious activity — the difference `label_basis` already names as
    `indicator-reference` versus `direct`. Today that is decided per **source**, so the 16,064
    address-list rules measured inside `pawpatrules` — a `signature`-class feed — all label
    `direct`. This is what lets it be decided per rule as well.

    **`None` means the snapshot recorded no classification; an empty set means it recorded that
    no rule is an address indicator.** Those are different facts and must not share an answer: a
    caller handed `frozenset()` for a schema-2 snapshot would label ~16,000 address-list rules
    `direct` — the exact defect #75 exists to fix — with nothing anywhere saying so. `None` forces
    the decision to be taken rather than defaulted (spec §2.5: absence is never a signal).

    Schema 1 recorded no classification at all; schema 2 recorded one computed by a definition
    since measured wrong, and reading it would put a known-bad answer behind a label's basis. Both
    stay readable for sid->source attribution, so no label already traced to such a snapshot is
    stranded. The remedy is a re-run of `flabel rules update`, not a fallback.
    """
    path = Path(directory) / SID_INDEX_NAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotError(f"snapshot {Path(directory).name} has no {SID_INDEX_NAME}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"could not read {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise SnapshotError(f"{path} is not a JSON object")
    if document.get("schema") not in CLASSIFIED_SID_INDEX_SCHEMAS:
        return None

    # Schema 3 always writes this key, so its absence means the file was truncated or hand-edited
    # — which must not read as "no rule is an indicator".
    if "address_indicator" not in document:
        raise SnapshotError(
            f"{path} declares schema {document.get('schema')} but has no `address_indicator` "
            f"key. A schema-3 index always writes it, so this file is incomplete."
        )
    sids = document["address_indicator"]
    if not isinstance(sids, list):
        raise SnapshotError(f"{path}: `address_indicator` is not a list")
    for sid in sids:
        # `bool` is an `int` in Python, and `true` in JSON must not become sid 1.
        if not isinstance(sid, int) or isinstance(sid, bool):
            raise SnapshotError(f"{path}: {sid!r} in `address_indicator` is not an integer sid")
    return frozenset(sids)


def list_snapshots(root: Path) -> list[SnapshotManifest]:
    """Every *usable* snapshot under `root`, oldest first.

    An absent root is empty rather than an error: `flabel rules list` before the first
    `rules update` is a reasonable thing to run.

    A directory whose manifest is missing or unreadable is skipped rather than raised on. One
    damaged snapshot must not make `rules list` — or `load_snapshot(root, None)`, which takes the
    newest from this list — impossible for every other snapshot on the machine. Skipping is safe
    *because* nothing is silently substituted: asking for that snapshot by id still fails hard,
    so a broken snapshot is never used, only omitted from a listing.

    Manifests are read but content is not re-hashed — that is `load_snapshot`'s job, and listing
    should not read every rule of every snapshot to print a table.
    """
    root = Path(root)
    if not root.is_dir():
        return []

    manifests = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or not SNAPSHOT_ID.match(entry.name):
            continue
        try:
            manifests.append(_read_manifest(entry))
        except SnapshotError:
            continue
    return sorted(manifests, key=lambda manifest: (manifest.created_at, manifest.snapshot_id))


# --- writing --------------------------------------------------------------------------------


def _build(
    staging: Path,
    components: Mapping[str, bytes],
    manifest: SnapshotManifest,
    raw: Mapping[str, str] | None,
) -> None:
    """Assemble a snapshot in `staging`, which no reader looks at."""
    _remove_tree(staging)
    try:
        staging.mkdir(parents=True)
        for relative, content in sorted(components.items()):
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        for source, text in sorted((raw or {}).items()):
            # A source name legitimately contains one `/` (`abuse.ch/urlhaus`), which becomes a
            # directory here. config.py's charset check on names is what keeps that from being a
            # path-traversal write.
            target = staging / RAW_DIR / f"{source}.rules"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        (staging / MANIFEST_NAME).write_text(_render_manifest(manifest), encoding="utf-8")
    except OSError as exc:
        _remove_tree(staging)
        raise SnapshotError(
            f"could not write ruleset snapshot under {staging.parent}: {exc}"
        ) from exc


def _existing(directory: Path, snapshot_id: str) -> SnapshotManifest:
    """Adopt a snapshot already on disk, having checked its content still hashes to its name.

    No comparison against the rules just admitted is needed on top of that: the id *is* the hash
    of those components, so agreement on the id is agreement on the content.
    """
    _verify_content(directory, snapshot_id)
    return _read_manifest(directory)


def _render_manifest(manifest: SnapshotManifest) -> str:
    """Canonical JSON, per spec §10 — the same rules `labels.json` follows."""
    document = {
        "manifest_version": MANIFEST_VERSION,
        "snapshot_id": manifest.snapshot_id,
        "created_at": manifest.created_at,
        "flabel_version": manifest.flabel_version,
        "total_admitted": manifest.total_admitted,
        "total_ja4_admitted": manifest.total_ja4_admitted,
        "sources": [
            {field.name: getattr(admission, field.name) for field in fields(admission)}
            for admission in manifest.sources
        ],
    }
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _remove_tree(path: Path) -> None:
    """Delete `path` and everything under it.

    `shutil.rmtree` rather than a hand-rolled walk: `Path.is_dir()` follows symlinks, so a walk
    that recursed into one would delete the *target's* contents. A stale
    `.staging-<id>/x -> /Users/craig` in a shared `--rules-dir` would empty a home directory.
    `rmtree` refuses to follow symlinked directories for exactly this reason.
    """
    shutil.rmtree(path, ignore_errors=True)


# --- reading --------------------------------------------------------------------------------


def _read_manifest(directory: Path) -> SnapshotManifest:
    path = directory / MANIFEST_NAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SnapshotError(f"ruleset snapshot {directory.name} has no {MANIFEST_NAME}") from exc
    except OSError as exc:
        raise SnapshotError(f"could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise SnapshotError(f"{path} does not contain a JSON object")

    version = document.pop("manifest_version", None)
    if version != MANIFEST_VERSION:
        raise SnapshotError(
            f"{path} declares manifest_version {version!r}; this flabel reads and writes version "
            f"{MANIFEST_VERSION}. A snapshot in another format version is not guessed at, because "
            f"its id may cover a different set of files."
        )

    sources = document.pop("sources", None)
    if not isinstance(sources, list):
        raise SnapshotError(f"{path} has no `sources` list")
    try:
        return SnapshotManifest(
            sources=tuple(_source_admission(entry, path) for entry in sources),
            **document,
        )
    except (TypeError, ValueError) as exc:
        # A missing field, an unexpected one, or a value outside its Literal. All the same
        # failure: this manifest was not written by a flabel that agrees with this one about what
        # a snapshot is, and guessing would put untraceable verdicts in the output.
        raise SnapshotError(f"{path} is not a usable snapshot manifest: {exc}") from exc


def _source_admission(entry: object, path: Path) -> SourceAdmission:
    if not isinstance(entry, dict):
        raise SnapshotError(f"{path}: each entry of `sources` must be an object")
    try:
        return SourceAdmission(**entry)
    except (TypeError, ValueError) as exc:
        raise SnapshotError(f"{path}: unusable source entry: {exc}") from exc


def _verify_content(directory: Path, snapshot_id: str) -> dict[str, bytes]:
    """Check the snapshot's content still hashes to its own name, and return that content.

    Spec §7 calls the id self-verifying, which is only true if something verifies it. Cheap (one
    sha256 over a few tens of megabytes) and it is the difference between "these labels came from
    ruleset abc123" being a fact and being a filename.
    """
    components = _components_on_disk(directory)
    actual = snapshot_id_for(components)
    if actual != snapshot_id:
        raise SnapshotError(
            f"{directory} hashes to {actual}, not {snapshot_id}: the snapshot has been modified "
            f"since it was written. It is not repaired or replaced, because labels already "
            f"emitted name this id as the ruleset that produced them."
        )
    return components


def _components_on_disk(directory: Path) -> dict[str, bytes]:
    """The hashed files of a snapshot, read back exactly as `snapshot_components` wrote them."""
    components = {
        name: _read_bytes(directory / name, directory) for name in (RULES_NAME, SID_INDEX_NAME)
    }
    data_root = directory / DATA_DIR
    if data_root.is_dir():
        for path in sorted(data_root.rglob("*")):
            # `is_symlink` first: a symlink dropped into `data/` would otherwise contribute the
            # bytes of whatever it points at to the hash of a snapshot that does not contain them.
            if path.is_symlink() or not path.is_file():
                continue
            components[path.relative_to(directory).as_posix()] = _read_bytes(path, directory)
    return components


def _read_bytes(path: Path, directory: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise SnapshotError(
            f"ruleset snapshot {directory.name} has no {path.name}; it is incomplete."
        ) from exc
    except OSError as exc:
        raise SnapshotError(f"could not read {path}: {exc}") from exc


# --- consistency between the rules and the counts that describe them ------------------------


def _verify_sources_agree(
    admitted: Mapping[str, Sequence[str]], admissions: Sequence[SourceAdmission]
) -> None:
    """The manifest must describe exactly the rules in the file, source by source.

    A source counted in the manifest but absent from `rules.rules` would overstate the snapshot —
    `total_admitted` promising coverage the file does not contain — and a source in the file but
    absent from the manifest would put rules into Suricata whose origin no label could report
    (spec §13: never emit a label whose origin can't be traced).
    """
    counted: dict[str, SourceAdmission] = {}
    for admission in admissions:
        if admission.name in counted:
            raise SnapshotError(f"duplicate admission for source {admission.name!r}")
        counted[admission.name] = admission

    mismatched = sorted(set(admitted) ^ set(counted))
    if mismatched:
        name = mismatched[0]
        side = "has admitted rules but no admission" if name in admitted else "has no rules"
        raise SnapshotError(
            f"source {name!r} {side} (all mismatched: {mismatched}). Every source in a snapshot "
            f"must appear in both, or the manifest does not describe the ruleset."
        )

    for name, admission in sorted(counted.items()):
        if admission.rules_admitted != len(admitted[name]):
            raise SnapshotError(
                f"source {name!r} reports rules_admitted={admission.rules_admitted} but "
                f"supplied {len(admitted[name])} rules."
            )


def _sid_or_none(rule: str) -> int | None:
    match = SID.search(rule)
    return int(match.group(1)) if match else None
