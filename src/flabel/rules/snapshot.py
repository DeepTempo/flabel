"""Content-addressed ruleset snapshots (docs/spec.md §7).

```
<root>/<snapshot_id>/
  manifest.json        the SnapshotManifest
  rules.rules          admitted rules, sorted by (source, sid)
  raw/<source>.rules   as fetched, for audit
```

A snapshot is the unit of reproducibility. `snapshot_id = sha256(rules.rules)[:16]`, so the id
is not a label attached to a directory — it is a claim about the directory's content that
anyone can re-check, and this module re-checks it on every load. Two consequences worth
stating plainly:

* **Sorting is load-bearing.** Feeds arrive over the network in whatever order they respond,
  so if arrival order reached `rules.rules`, two runs over identical rules would produce
  different ids and Goal 2 (identical output for identical input) would be unreachable.
* **A snapshot is immutable.** Re-writing identical content returns the stored manifest
  untouched, and a directory whose `rules.rules` no longer hashes to its own name is a hard
  failure rather than something to repair — labels already emitted point at that id.

This module is classified impure in `test_architecture.py`: it writes files.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import fields
from pathlib import Path

import flabel
from flabel.errors import SnapshotError
from flabel.models import SnapshotManifest, SourceAdmission
from flabel.rules import utc_now

MANIFEST_NAME = "manifest.json"
RULES_NAME = "rules.rules"
RAW_DIR = "raw"

SNAPSHOT_ID_LENGTH = 16

#: A directory in the rules root is a snapshot if it is named like one. Anything else — a
#: scratch directory, an operator's notes — is ignored by `list_snapshots` rather than
#: reported as a broken snapshot.
SNAPSHOT_ID = re.compile(rf"^[0-9a-f]{{{SNAPSHOT_ID_LENGTH}}}$")

#: A rule's `sid`, which with the source name is the sort key spec §7 mandates.
SID = re.compile(r"\bsid\s*:\s*(\d+)")

#: Prefix for the directory a snapshot is assembled in before it is renamed into place, so a
#: half-written snapshot never exists under a name something might load.
STAGING_PREFIX = ".staging-"


def snapshot_id_for(rules: bytes) -> str:
    """The id of a snapshot whose `rules.rules` is exactly `rules`."""
    return hashlib.sha256(rules).hexdigest()[:SNAPSHOT_ID_LENGTH]


def render_rules(admitted: Mapping[str, Sequence[str]]) -> bytes:
    """The exact bytes of `rules.rules`, sorted by (source, sid).

    Separate from writing so the input to the hash is inspectable rather than a side effect.

    The rule text is the third sort key. Sid is not unique across feeds and a third-party
    feed may ship a rule with no parseable sid at all; without a total order, two runs over
    the same rules could still order them differently and produce different ids.
    """
    lines: list[str] = []
    for source in sorted(admitted):
        rules = sorted(admitted[source], key=lambda rule: (_sid(rule), rule))
        lines.extend(rule.strip() for rule in rules)
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_snapshot(
    root: Path,
    admitted: Mapping[str, Sequence[str]],
    admissions: Sequence[SourceAdmission],
    raw: Mapping[str, str] | None = None,
    created_at: str | None = None,
) -> SnapshotManifest:
    """Write a snapshot under `root` and return its manifest.

    `raw` and `created_at` extend spec §7's three-argument signature. `raw` is how the
    `raw/<source>.rules` files the same section requires get their content — the filtered file
    alone cannot show what was dropped, and a label's provenance is only checkable against the
    feed as fetched. `created_at` is injectable so the ordering `load_snapshot(root, None)`
    depends on can be tested without sleeping.

    Idempotent: writing identical content twice yields one directory and the manifest of the
    first write. Its `created_at` still records when this ruleset first existed, which is what
    a label pointing at the id needs it to mean.
    """
    _verify_sources_agree(admitted, admissions)

    rules = render_rules(admitted)
    if not rules:
        raise SnapshotError(
            "refusing to write a snapshot with no rules: Suricata would load it cleanly and "
            "label nothing, which is the silent under-reporting docs/spec.md §2.5 forbids."
        )

    snapshot_id = snapshot_id_for(rules)
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
    _build(staging, rules, manifest, raw)
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
                f"no ruleset snapshot found under {root}. Run `flabel rules update` first, or "
                f"point --rules-dir at the directory holding one."
            )
        snapshot_id = available[-1].snapshot_id

    if not SNAPSHOT_ID.match(snapshot_id):
        # The id becomes a path component under the rules directory and arrives from the
        # command line (`--ruleset-snapshot <id>`), so it is checked rather than joined
        # blindly. It also turns a typo into a message that names the mistake.
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
    rules = _verify_content(directory, snapshot_id)

    # `rules.rules` holds exactly one rule per line, so the manifest's own total is checkable
    # against the file it describes. The hash proves the rules were not edited; this proves the
    # counts that a run copies into `labels.json` were not either.
    admitted = rules.count(b"\n")
    if manifest.total_admitted != admitted:
        raise SnapshotError(
            f"snapshot {snapshot_id} says total_admitted={manifest.total_admitted} but "
            f"{RULES_NAME} holds {admitted} rules; its manifest does not describe it."
        )
    return directory, manifest


def list_snapshots(root: Path) -> list[SnapshotManifest]:
    """Every snapshot under `root`, oldest first.

    An absent root is empty rather than an error: `flabel rules list` before the first
    `rules update` is a reasonable thing to run.

    Manifests are read but content is *not* re-hashed — that is `load_snapshot`'s job, and
    listing should not read every rule of every snapshot to print a table.
    """
    root = Path(root)
    if not root.is_dir():
        return []

    manifests = [
        _read_manifest(entry)
        for entry in sorted(root.iterdir())
        if entry.is_dir() and SNAPSHOT_ID.match(entry.name)
    ]
    return sorted(manifests, key=lambda manifest: (manifest.created_at, manifest.snapshot_id))


# --- writing --------------------------------------------------------------------------------


def _build(
    staging: Path,
    rules: bytes,
    manifest: SnapshotManifest,
    raw: Mapping[str, str] | None,
) -> None:
    """Assemble a snapshot in `staging`, which no reader looks at."""
    _remove_tree(staging)
    try:
        staging.mkdir(parents=True)
        (staging / RULES_NAME).write_bytes(rules)
        for source, text in (raw or {}).items():
            # A source name legitimately contains one `/` (`abuse.ch/urlhaus`), which becomes
            # a directory here. config.py's charset check on names is what keeps that from
            # being a path-traversal write.
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
    """Adopt a snapshot already on disk, having checked its bytes still hash to its name.

    No comparison against the rules just admitted is needed on top of that: the id *is* the
    hash of those bytes, so agreement on the id is agreement on the content.
    """
    _verify_content(directory, snapshot_id)
    return _read_manifest(directory)


def _render_manifest(manifest: SnapshotManifest) -> str:
    """Canonical JSON, per spec §10 — the same rules `labels.json` follows."""
    document = {
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
    """Delete `path` and anything under it, without importing shutil for four lines."""
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir():
            _remove_tree(child)
        else:
            child.unlink()
    path.rmdir()


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
        # failure: this manifest was not written by a flabel that agrees with this one about
        # what a snapshot is, and guessing would put untraceable verdicts in the output.
        raise SnapshotError(f"{path} is not a usable snapshot manifest: {exc}") from exc


def _source_admission(entry: object, path: Path) -> SourceAdmission:
    if not isinstance(entry, dict):
        raise SnapshotError(f"{path}: each entry of `sources` must be an object")
    try:
        return SourceAdmission(**entry)
    except (TypeError, ValueError) as exc:
        raise SnapshotError(f"{path}: unusable source entry: {exc}") from exc


def _verify_content(directory: Path, snapshot_id: str) -> bytes:
    """Check that `rules.rules` still hashes to the directory's own name, and return its bytes.

    Spec §7 calls the id self-verifying, which is only true if something verifies it. Cheap
    (one sha256 over a few megabytes) and it is the difference between "these labels came from
    ruleset abc123" being a fact and being a filename.
    """
    path = directory / RULES_NAME
    try:
        rules = path.read_bytes()
    except FileNotFoundError as exc:
        raise SnapshotError(f"ruleset snapshot {snapshot_id} has no {RULES_NAME}") from exc
    except OSError as exc:
        raise SnapshotError(f"could not read {path}: {exc}") from exc

    actual = snapshot_id_for(rules)
    if actual != snapshot_id:
        raise SnapshotError(
            f"{path} hashes to {actual}, not {snapshot_id}: the snapshot has been modified "
            f"since it was written. It is not repaired or replaced, because labels already "
            f"emitted name this id as the ruleset that produced them."
        )
    return rules


# --- consistency between the rules and the counts that describe them ------------------------


def _verify_sources_agree(
    admitted: Mapping[str, Sequence[str]], admissions: Sequence[SourceAdmission]
) -> None:
    """The manifest must describe exactly the rules in the file, source by source.

    A source counted in the manifest but absent from `rules.rules` would overstate the
    snapshot — `total_admitted` promising coverage the file does not contain — and a source in
    the file but absent from the manifest would put rules into Suricata whose origin no label
    could report (spec §13: never emit a label whose origin can't be traced).
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
            f"source {name!r} {side} (all mismatched: {mismatched}). Every source in a "
            f"snapshot must appear in both, or the manifest does not describe the ruleset."
        )

    for name, admission in sorted(counted.items()):
        if admission.rules_admitted != len(admitted[name]):
            raise SnapshotError(
                f"source {name!r} reports rules_admitted={admission.rules_admitted} but "
                f"supplied {len(admitted[name])} rules."
            )


def _sid(rule: str) -> int:
    """A rule's sid, or -1 when it has none — sorted first, deterministically."""
    match = SID.search(rule)
    return int(match.group(1)) if match else -1
