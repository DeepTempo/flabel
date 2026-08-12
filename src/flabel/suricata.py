"""Invoke Suricata over the normalized capture and parse `eve.json` (spec §8).

Five things in here carry the weight:

**The invocation is exact, and self-contained.** ``-S`` *replaces* the ruleset with the
snapshot's, so no ambient system ruleset can contribute a SID that appears in no snapshot;
``--runmode single`` makes the alert set deterministic, which Goal 2 rests on; and ``-c``
points at flabel's own `data/suricata.yaml`, so the operator's ``/etc/suricata/suricata.yaml``
cannot decide what gets labelled, what provenance text a label carries, or whether capture
payloads are written to disk. All asserted by a test on `build_argv`, not left to a comment.

**Every path handed to the tool is absolute.** Measured on 8.0.6: a relative ``-S`` resolves
against the process's working directory. Spec §12's default ``--rules-dir`` is relative, so
this is the ordinary case — and a recorded argv that only works from one directory is not a
reproducible failure report.

**Every alert is attributed to a source before it can become a label.** `eve.json` records a
SID and nothing about where the rule came from, so attribution comes from the snapshot's
`sid_index.json`. An alert that cannot be attributed is never emitted with a guess: spec §13
forbids a label whose origin cannot be traced, and the source is also what decides whether
the alert may label at all.

**The tuple is translated into Zeek's spelling, not Suricata's.** Correlation joins the two
tools' 5-tuples field by field (spec §9), and they disagree on three things: protocol case and
naming, IPv6 address formatting, and what to put in the port columns for ICMP. Each is
normalised here, against measured Zeek output rather than assumption — see `_proto`, `_address`
and `_ports`.

**Detections from `identify`-class sources are dropped here**, at the earliest point they
exist, and counted in `identify_alerts_suppressed` (spec §2.8). Dropping them further
downstream would mean a window in which a label that must never exist does.

Failure handling splits along a deliberate line:

* **The snapshot cannot support provenance** → `SnapshotError` before any subprocess runs.
  This covers the quiet ones: Suricata treats a missing or empty ``-S`` file as a *warning*
  and exits 0 with an empty alert set (verified on 8.0.6), which is indistinguishable from a
  capture that contained nothing.
* **Suricata failed to run, or ran and failed** → a `ToolFailure` in the returned
  `SuricataRunInfo`. The caller fails the run (spec §8) but the run block still reports what
  was lost rather than merely dying (spec §2.5).
* **`eve.json` says something we cannot read** → `ToolError`, raised. Stated plainly because
  it is the one case that raises *after* the tool has written its output directory: a
  corrupt, undecodable or structurally impossible record is not a loss we can quantify, and
  attaching a count to it would be inventing one. The caller must therefore treat a raised
  failure as "the output directory may exist and must not be published" (spec §13).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import fields
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any, get_type_hints

from flabel.errors import SnapshotError, ToolError
from flabel.models import (
    Detection,
    SnapshotManifest,
    SourceAdmission,
    SourceSpec,
    SuricataRunInfo,
    ToolFailure,
)

#: Suricata is Tier 2 for every label it produces. Phase 2's PANW device is Tier 1; a lower
#: tier is a higher-trust observation (`Label.best_tier` is the minimum).
TIER = 2

#: Resolved through ``PATH`` rather than pinned to a path, so the container and a laptop both
#: work and a test can inject "the binary is not there" by emptying ``PATH``.
BINARY = "suricata"

RULES_FILE = "rules.rules"
MANIFEST_FILE = "manifest.json"
#: Step 4 writes this: ``{"schema": 1, "sources": {"<name>": [<sid>, ...]}}``. It is the only
#: place a SID's originating source is recorded — eve.json carries none — and it is hashed into
#: `snapshot_id`, which is what makes the attribution as tamper-evident as the rules themselves.
SID_INDEX_FILE = "sid_index.json"
#: The one `sid_index.json` shape this code understands. A different schema is a hard failure,
#: never a best-effort read: attribution decides whether a source may label at all.
SID_INDEX_SCHEMA = 1
EVE_FILE = "eve.json"
LOG_FILE = "suricata.log"

#: flabel's own Suricata config, shipped as package data. See the file's own header for the six
#: label-affecting things the operator's `/etc/suricata/suricata.yaml` would otherwise decide.
CONFIG_FILE = "suricata.yaml"
CLASSIFICATION_FILE = "classification.config"
REFERENCE_FILE = "reference.config"

#: Timeouts, so a wedged Suricata becomes the `ToolFailure` spec §11 promises instead of a
#: hung pipeline and a hung CI job. Generous rather than tuned: a real capture against a full
#: ET Open snapshot is minutes of work, and killing a healthy run would be worse than waiting.
#: Step 9 should make the run timeout an option rather than leaving it a constant here.
RUN_TIMEOUT_SECONDS = 3600
VERSION_TIMEOUT_SECONDS = 60

#: `sid:` in a rule line. Suricata itself accepts whitespace around the colon, so this does
#: too — a rule we failed to see the SID of would be a rule we could not attribute.
SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")

#: A double-quoted rule argument. Stripped before the SID is read, because a rule whose
#: `content:` or `pcre:` happens to contain the text ``sid:1;`` would otherwise be attributed
#: to SID 1 — and every label from it would name the wrong rule.
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')

#: Length of `snapshot_id`: spec §7 defines it as sha256(rules.rules bytes) truncated here.
SNAPSHOT_ID_LENGTH = 16

#: Suricata's own load report in ``suricata.log``, used when the eve stats event is absent.
#: All three counts come off one line: "N rules successfully loaded, M rules failed, K rules
#: skipped". Reading only the first would leave the interesting number on the floor.
RULES_LOADED = re.compile(
    r"(\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped"
)

VERSION = re.compile(r"\d+\.\d+\.\d+")

#: Protocol names Suricata spells differently from Zeek's `conn.log`. Measured, not assumed:
#: Zeek writes `icmp` for ICMPv6 too — its `transport_proto` has only tcp/udp/icmp/
#: unknown_transport — while Suricata writes `IPv6-ICMP`. Lowercasing alone would leave
#: `ipv6-icmp` against Zeek's `icmp` and every ICMPv6 detection would be uncorrelatable, which
#: is the failure this table exists to prevent. The IP version is still distinguishable from
#: the addresses, so nothing is lost by agreeing with Zeek here.
#:
#: Not covered, and reported rather than guessed: Zeek writes `unknown_transport` for GRE, ESP
#: and anything else that is not TCP/UDP/ICMP, where Suricata writes the protocol name. Those
#: are left as Suricata reports them (lowercased) until Zeek's side is measured on a fixture
#: that has them.
PROTO_ALIASES = {"ipv6-icmp": "icmp"}


def data_dir() -> Path:
    """Where flabel's own Suricata config lives.

    Under `src/flabel/data/` for the same reason the source registry is (spec §3): it resolves
    identically from a checkout, an editable install and a built wheel.
    """
    return Path(str(resources.files("flabel") / "data"))


def config_files() -> tuple[Path, ...]:
    """Every config file the invocation depends on, in a fixed order.

    Fixed because `config_sha256` hashes them in this order: the digest identifies the whole
    configuration, not one file of it. `classification.config` is in here because it supplies
    the `classtype` text recorded on every label.
    """
    directory = data_dir()
    return tuple(directory / name for name in (CONFIG_FILE, CLASSIFICATION_FILE, REFERENCE_FILE))


def config_sha256() -> str:
    """One digest over flabel's Suricata configuration, for the run block.

    A run is only reproducible against a *known* configuration: `HOME_NET`, the classtype
    descriptions and the eve output selection all change what a label says. Recording the
    digest is what lets two runs be compared without trusting that the config was the same.

    Returned rather than stored on `SuricataRunInfo`, which has no field for it — `provenance`
    can call this. A `config_sha256` field on `SuricataRunInfo` would be the better home; that
    is a `models.py` change and is flagged rather than made here.
    """
    digest = hashlib.sha256()
    for path in config_files():
        try:
            digest.update(path.read_bytes())
        except OSError as exc:
            raise ToolError(f"flabel's Suricata config {path} could not be read: {exc}") from exc
    return digest.hexdigest()


def build_argv(capture: Path, snapshot: Path, outdir: Path) -> list[str]:
    """The exact invocation of spec §8, with flabel's own config.

    Separated from `run_suricata` so the flags are testable without running anything. Three
    things here are load-bearing beyond the flags spec §8 lists:

    * ``-c`` — flabel's config rather than the machine's. Without it, whether an abuse.ch
      ``$HOME_NET -> $EXTERNAL_NET`` C2 rule fires at all depends on the operator's
      `suricata.yaml` (proved by a test: on the stock config that rule matches *nothing* in the
      benign canary; with flabel's, it matches).
    * ``--set default-rule-path`` — where a rule's own relative paths (``dataset:``,
      ``filemagic:``) resolve. Pointed at the snapshot so rule-referenced files can only come
      from inside it. It does *not* affect ``-S``: measured on 8.0.6, a relative ``-S`` resolves
      against the working directory and ignores this setting.
    * absolute paths throughout — `Path.resolve()` on all three, so the argv means the same
      thing from any working directory. Spec §12's default ``--rules-dir`` is relative.
    """
    capture, snapshot, outdir = capture.resolve(), snapshot.resolve(), outdir.resolve()
    directory = data_dir()
    return [
        BINARY,
        "-r",
        str(capture),
        "-c",
        str(directory / CONFIG_FILE),
        "-S",
        str(snapshot / RULES_FILE),
        "-l",
        str(outdir),
        # The two config files `suricata.yaml` names relatively. Set absolutely here rather
        # than written as absolute paths in the YAML, because the package's location is not
        # knowable when the YAML is written.
        "--set",
        f"classification-file={directory / CLASSIFICATION_FILE}",
        "--set",
        f"reference-config-file={directory / REFERENCE_FILE}",
        "--set",
        f"default-rule-path={snapshot}",
        "--set",
        "app-layer.protocols.tls.ja3-fingerprints=yes",
        "--set",
        "app-layer.protocols.tls.ja4-fingerprints=yes",
        "--runmode",
        "single",
    ]


def run_suricata(
    capture: Path, snapshot: Path, outdir: Path
) -> tuple[list[Detection], SuricataRunInfo]:
    """Run Suricata over `capture` with `snapshot`'s rules, returning parsed detections.

    Detections are returned in eve.json order, which is capture order. Ordering of the final
    output is `labels.py`'s job (spec §10), so nothing is re-sorted here.
    """
    manifest = load_manifest(snapshot)
    verify_snapshot_id(snapshot, manifest)
    sources = {admission.name: admission for admission in manifest.sources}
    index = sid_source_index(snapshot, manifest)
    _prepare_outdir(outdir)

    argv = build_argv(capture, snapshot, outdir)
    version, failure = _version()
    if failure is not None:
        return [], _failed(manifest, failure)

    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=RUN_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        # A wedged tool is a loss condition like any other (spec §11). Without this the run
        # hangs, and a hung CI job reports nothing at all.
        return [], _failed(
            manifest,
            _failure(
                argv,
                None,
                f"suricata did not finish within {RUN_TIMEOUT_SECONDS}s and was killed",
            ),
            version=version,
        )
    except OSError as exc:
        return [], _failed(
            manifest,
            _failure(argv, None, f"suricata could not be executed: {exc}"),
            version=version,
        )

    if completed.returncode != 0:
        # A negative code is a signal — an OOM kill shows up here as -9, which is why the
        # message says which of the two happened rather than printing a bare number.
        killed = completed.returncode < 0
        detail = f"killed by signal {-completed.returncode}" if killed else "exited non-zero"
        return [], _failed(
            manifest,
            _failure(
                argv,
                completed.returncode,
                f"suricata {detail}: {_tail(completed.stderr or completed.stdout)}",
            ),
            version=version,
        )

    eve = outdir / EVE_FILE
    if not eve.exists():
        return [], _failed(
            manifest,
            _failure(
                argv,
                completed.returncode,
                f"suricata exited 0 but wrote no {EVE_FILE} in {outdir}",
            ),
            version=version,
        )

    detections, alerts_total, suppressed, counts = _read_eve(eve, index, sources)
    if counts is None:
        counts = _rules_loaded_from_log(outdir / LOG_FILE)

    failure = _check_ruleset_loaded(counts, expected=len(index), argv=argv, exit_code=0)
    if failure is not None:
        return [], _failed(manifest, failure, version=version)

    return detections, SuricataRunInfo(
        version=version,
        snapshot_id=manifest.snapshot_id,
        # `counts` is not None here: `_check_ruleset_loaded` returns a failure when it is.
        rules_loaded=counts[0] if counts else 0,
        alerts_total=alerts_total,
        identify_alerts_suppressed=suppressed,
    )


def _check_ruleset_loaded(
    counts: tuple[int, int, int] | None, *, expected: int, argv: Sequence[str], exit_code: int
) -> ToolFailure | None:
    """Decide whether the engine loaded the ruleset flabel thought it handed over.

    Three distinct outcomes, deliberately not collapsed into one truthiness test:

    * **Unknown** — neither the eve stats record nor `suricata.log` reported a count. Both are
      config-owned, so "we could not tell" is a real state and it is not the same as zero. It
      fails the run: an alert set we cannot attest the ruleset for is not evidence.
    * **Zero loaded** — the engine rejected every rule. The snapshot was checked to hold rules
      before the tool started, and Suricata exits 0 in this case, so nothing else would say so.
    * **Fewer loaded than admitted** — the case that actually happens with real feeds: some
      rules use a keyword this build lacks, or name a classtype the config does not define. The
      run reported success and the labels those rules would have produced are simply absent.

    The third is a hard failure by decision (Craig, 2026-08-12): "record it, warn above zero,
    fail above a threshold". Recording needs a `rules_failed` field on `SuricataRunInfo` that
    does not exist yet, and a *threshold* is only meaningful once the count is recorded — so
    until then any shortfall fails, which is the conservative half of that decision. **Note the
    consequence:** with today's feeds this will fail real runs (26 pawpatrules rules were
    measured as failing to load), which is the intended alarm, not a surprise — the fix belongs
    in step 4's admission, which should not admit a rule this engine cannot load.
    """
    if counts is None:
        return _failure(
            argv,
            exit_code,
            "suricata reported no rule-load count in either eve stats or suricata.log, so the "
            "alert set cannot be attested against the snapshot",
        )

    loaded, failed, skipped = counts
    if loaded == 0:
        return _failure(
            argv,
            exit_code,
            f"suricata loaded none of the snapshot's {expected} rules ({failed} failed, "
            f"{skipped} skipped), so an empty alert set proves nothing about the capture",
        )
    if loaded != expected:
        return _failure(
            argv,
            exit_code,
            f"suricata loaded {loaded} of the snapshot's {expected} rules ({failed} failed, "
            f"{skipped} skipped). The missing rules never examined the capture, so any label "
            f"they would have produced is absent from a run that otherwise looks complete",
        )
    return None


# --- the snapshot -------------------------------------------------------------------------


def load_manifest(snapshot: Path) -> SnapshotManifest:
    """Read and validate `snapshot`'s manifest.

    Strict about missing and unknown keys: the manifest is where `source_class` comes from,
    and `source_class` is what decides whether a source may label at all. A manifest we can
    only partly read is not a basis for that decision, and never falls back to another
    snapshot (spec §7).
    """
    path = snapshot / MANIFEST_FILE
    if not snapshot.is_dir():
        raise SnapshotError(f"ruleset snapshot directory not found: {snapshot}")
    document = _load_json(path, snapshot)

    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise SnapshotError(f"{path} lists no sources, so no alert could be attributed")

    admissions = tuple(_build(SourceAdmission, entry, path) for entry in raw_sources)

    # Duplicates rejected the way `config.py` rejects them in the registry: with two entries
    # of the same name, which `source_class` applies — and therefore whether that source may
    # label at all — would depend on manifest order. `may_label` is the one thing spec §13
    # calls absolute, so it may not rest on a dict update winning.
    seen: set[str] = set()
    for admission in admissions:
        key = admission.name.casefold()
        if key in seen:
            raise SnapshotError(
                f"{path}: source {admission.name!r} appears more than once. Which "
                f"source_class applies would depend on the order of the file."
            )
        seen.add(key)

    return _build(SnapshotManifest, {**document, "sources": admissions}, path)


def verify_snapshot_id(snapshot: Path, manifest: SnapshotManifest) -> None:
    """Check that `snapshot_id` really is the hash of the rules and the attribution.

    Spec §7 calls the id self-verifying — "rewriting the file changes the id" — but nothing
    verified it, and the parts come from different files: `snapshot_id` is read from
    `manifest.json`, the rules that alert from `rules.rules`, and the source each SID belongs
    to from `sid_index.json`. Edit either and every label would still claim the original id: a
    label whose origin cannot be traced (spec §13) while looking perfectly traceable.

    Two compositions are accepted, and this is temporary: `rules.rules` alone, which is what
    spec §7 says today, and `rules.rules` followed by `sid_index.json`, which is what step 4
    now writes. Both are exact content hashes, so tampering still fails either way — the only
    slack is that an id computed the old way leaves `sid_index.json` unprotected. **Spec §7
    should pin one**, and this check should move into `rules/snapshot.load_snapshot`, which
    will own the definition.
    """
    if len(manifest.snapshot_id) < SNAPSHOT_ID_LENGTH:
        raise SnapshotError(
            f"snapshot id {manifest.snapshot_id!r} is shorter than {SNAPSHOT_ID_LENGTH} "
            f"characters, which is too little of a sha256 to identify a ruleset"
        )

    rules = _read_bytes(snapshot / RULES_FILE, snapshot)
    index = _read_bytes(snapshot / SID_INDEX_FILE, snapshot)
    candidates = {
        f"sha256({RULES_FILE} + {SID_INDEX_FILE})": hashlib.sha256(rules + index).hexdigest(),
        f"sha256({RULES_FILE})": hashlib.sha256(rules).hexdigest(),
    }

    if not any(digest.startswith(manifest.snapshot_id) for digest in candidates.values()):
        detail = ", ".join(
            f"{name} begins {digest[: len(manifest.snapshot_id)]!r}"
            for name, digest in candidates.items()
        )
        raise SnapshotError(
            f"snapshot {snapshot} is not internally consistent: {MANIFEST_FILE} says "
            f"snapshot_id {manifest.snapshot_id!r}, but {detail}. The rules that would run are "
            f"not the rules this id names, so every label from this run would misstate its "
            f"origin."
        )


def _read_bytes(path: Path, snapshot: Path) -> bytes:
    """Read a required snapshot file, or fail the run saying which one is missing."""
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise SnapshotError(f"snapshot {snapshot} has no {path.name}") from exc
    except OSError as exc:
        raise SnapshotError(f"{path} could not be read: {exc}") from exc


def sid_source_index(snapshot: Path, manifest: SnapshotManifest) -> dict[int, str]:
    """Map every SID that can fire to the source it came from, from `sid_index.json`.

    `eve.json` carries no source, so attribution has to come from the snapshot. Step 4 writes
    it explicitly::

        {"schema": 1, "sources": {"et/open": [2000001, ...], "pawpatrules": [3300303]}}

    Read rather than re-derived. The previous version of this function reconstructed the map by
    globbing ``raw/<source>.rules`` and deriving the source name from the file path — which
    invented an unwritten contract about the layout of multi-file feeds (ET Open is a tarball of
    many `.rules` files), re-read tens of megabytes of rule text on every run, and rested on
    `raw/`, which is not covered by `snapshot_id` and so could be edited without detection.

    The file is still cross-checked against the two things that must agree with it, because a
    label carrying the wrong source is worse than a run that refuses to start:

    * every source it names must be in the manifest — the manifest is where `source_class`,
      hence `may_label`, comes from;
    * every SID in `rules.rules` must appear in it exactly once. A SID claimed twice is
      ambiguous and is never resolved by picking one; a SID claimed by nobody is a rule that
      can fire and cannot be traced.
    """
    path = snapshot / SID_INDEX_FILE
    document = _load_json(path, snapshot)

    schema = document.get("schema")
    if schema != SID_INDEX_SCHEMA:
        raise SnapshotError(
            f"{path} declares schema {schema!r}, but this flabel understands only "
            f"{SID_INDEX_SCHEMA}. Attribution decides whether a source may label at all, so it "
            f"is never read on a best-effort basis."
        )

    sources = document.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise SnapshotError(f"{path} maps no sources to SIDs, so no alert could be attributed")

    known = {admission.name for admission in manifest.sources}
    index: dict[int, str] = {}
    ambiguous: dict[int, set[str]] = {}

    for name in sorted(sources):
        if name not in known:
            raise SnapshotError(
                f"{path} attributes SIDs to source {name!r}, which {MANIFEST_FILE} does not "
                f"list. The manifest is the authority on which sources a snapshot contains and "
                f"on whether each may label."
            )
        sids = sources[name]
        if not isinstance(sids, list):
            raise SnapshotError(
                f"{path}: source {name!r} maps to {type(sids).__name__}, expected a list of SIDs"
            )
        for sid in sids:
            if not isinstance(sid, int) or isinstance(sid, bool):
                raise SnapshotError(f"{path}: source {name!r} lists a non-integer SID {sid!r}")
            owner = index.get(sid)
            if owner is not None and owner != name:
                ambiguous.setdefault(sid, {owner}).add(name)
            index[sid] = name

    if ambiguous:
        detail = ", ".join(
            f"{sid} ({', '.join(sorted(names))})" for sid, names in sorted(ambiguous.items())
        )
        raise SnapshotError(
            f"{path} claims the same SID from more than one source: {detail}. A detection is "
            f"never attributed by guess, so the snapshot must be rebuilt without the collision. "
            f"Step 4 owns detecting this at write time, where dropping one of the two is an "
            f"option the operator actually has."
        )

    _cross_check_rules(snapshot, index)
    return index


def _cross_check_rules(snapshot: Path, index: Mapping[int, str]) -> None:
    """Assert `sid_index.json` describes the rules that will actually run.

    `rules.rules` is the file Suricata reads, so it — not the index — decides what can fire.
    The scan costs one pass over bytes already read for the snapshot-id check, and it catches
    the two ways the two files can disagree: a rule with no attribution, and an attribution
    for a rule that is not there.
    """
    rules = snapshot / RULES_FILE
    text = _read_bytes(rules, snapshot).decode("utf-8", errors="replace")
    admitted = _sids(text.splitlines(), strict=True, origin=rules)

    if not admitted:
        raise SnapshotError(
            f"{rules} contains no rules. Suricata treats that as a warning and exits 0 with "
            f"an empty alert set, which is indistinguishable from a capture that contained "
            f"nothing — so it fails here instead."
        )

    unattributed = sorted(admitted - set(index))
    if unattributed:
        raise SnapshotError(
            f"{rules} admits SIDs that {SID_INDEX_FILE} does not attribute: {unattributed[:20]} "
            f"({len(unattributed)} total). Each could fire and could not be traced to a source, "
            f"which also means we cannot tell whether it may label (spec §2.8)."
        )

    phantom = sorted(set(index) - admitted)
    if phantom:
        raise SnapshotError(
            f"{SID_INDEX_FILE} attributes SIDs that are not in {RULES_FILE}: {phantom[:20]} "
            f"({len(phantom)} total). The two files describe different rulesets, so neither can "
            f"be trusted to say what ran."
        )


def _load_json(path: Path, snapshot: Path) -> Mapping[str, Any]:
    """Read a required snapshot JSON object, with every failure a `SnapshotError`."""
    try:
        document = json.loads(_read_bytes(path, snapshot).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"{path} is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SnapshotError(f"{path} must contain a JSON object, got {type(document).__name__}")
    return document


def _sids(lines: Iterable[str], *, strict: bool = False, origin: Path | None = None) -> set[int]:
    """The SIDs of the active rules in `lines`.

    Blank lines and comments are skipped: a snapshot may carry a header comment, and a disabled
    ``#alert`` rule can never fire (ET Open ships 19,479 of them). `strict` is for
    ``rules.rules``, where an active rule without a SID is a broken snapshot rather than noise
    to skip — it is a rule that can alert and cannot be attributed.
    """
    found: set[int] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Quoted arguments are blanked first, so a `content:"sid:1;"` cannot be mistaken for
        # the rule's own SID, and the *last* remaining match wins: `sid` is conventionally the
        # final option, and anything that survived the blanking is more likely to precede it.
        matches = SID.findall(QUOTED.sub('""', stripped))
        if not matches:
            if strict:
                raise SnapshotError(
                    f"{origin} has an active rule with no sid, which cannot be attributed to "
                    f"a source: {stripped[:120]}"
                )
            continue
        found.add(int(matches[-1]))
    return found


def _build(kind: type, values: Mapping[str, Any], path: Path) -> Any:
    """Construct a frozen dataclass from `values`, requiring every field it declares.

    A *missing* key is fatal: the manifest is where `source_class` comes from, and a field we
    cannot read is a decision we would be guessing at. An *unknown* key is ignored, which is
    the opposite of `config.py`'s rule about the registry, for a reason — a human writes the
    registry, where a typo'd key that reads as a setting is the hazard, while this file is
    written by flabel itself. Rejecting unknown keys would mean a later version that adds a
    field makes every snapshot already on disk unreadable, and spec §2.7 requires Phase 2 to
    be additive. A renamed field still fails loudly, as a missing one.
    """
    if not isinstance(values, Mapping):
        raise SnapshotError(
            f"{path}: expected a JSON object for {kind.__name__}, got {type(values).__name__}"
        )

    expected = {field.name for field in fields(kind)}
    missing = sorted(expected - set(values))
    if missing:
        raise SnapshotError(f"{path}: {kind.__name__} is missing {', '.join(missing)}")

    # Types are checked, not just presence. JSON has no schema, so `"snapshot_id": 12345` or
    # `"name": 5` would otherwise construct a dataclass whose `str` field holds an int, and the
    # failure would surface pages later as a bare `TypeError` or `AttributeError` — not a
    # `FlabelError`, so `cli.py` could only report it as a traceback. Only the scalar fields are
    # checked; `sources` is validated by this same function one level down.
    hints = get_type_hints(kind)
    for name in sorted(expected):
        wanted = hints.get(name)
        if wanted in (str, int) and not _is_instance(values[name], wanted):
            raise SnapshotError(
                f"{path}: {kind.__name__}.{name} must be {wanted.__name__}, got "
                f"{type(values[name]).__name__} ({values[name]!r})"
            )

    try:
        return kind(**{name: values[name] for name in expected})
    except (TypeError, ValueError) as exc:
        # ValueError covers the models' own Literal checks — an unknown `source_class` lands
        # here, and getting that wrong changes whether a source may label.
        raise SnapshotError(f"{path}: invalid {kind.__name__}: {exc}") from exc


def _is_instance(value: object, wanted: type) -> bool:
    """`isinstance`, except that a bool is not an acceptable int.

    `True` would otherwise pass as `rules_admitted`, and arithmetic on it would quietly work.
    """
    if isinstance(value, bool) and wanted is int:
        return False
    return isinstance(value, wanted)


# --- eve.json ------------------------------------------------------------------------------


def _read_eve(
    path: Path, index: Mapping[int, str], sources: Mapping[str, SourceAdmission]
) -> tuple[list[Detection], int, int, tuple[int, int, int] | None]:
    """Parse `path` in one pass.

    Returns the detections that may label, the total alert count, how many were suppressed, and
    the engine's ``(loaded, failed, skipped)`` rule counts if the stats record carried them.
    One pass because eve.json also holds every flow record of the run and can be large.
    """
    detections: list[Detection] = []
    alerts_total = 0
    suppressed = 0
    loaded: tuple[int, int, int] | None = None

    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(_lines(handle, path), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                # Suricata exited 0, so a record it cannot have finished writing means
                # something we do not understand happened. Raised rather than skipped: a
                # dropped alert is a missing label, and silence must not stand for it.
                raise ToolError(f"{path} line {number} is not valid JSON: {exc}") from exc

            event = record.get("event_type")
            if event == "stats":
                # Not `or`: a reported zero is an answer — every rule failed to parse — and
                # must not be mistaken for "the stats record said nothing".
                reported = _rules_loaded_from_stats(record)
                loaded = reported if reported is not None else loaded
                continue
            if event != "alert":
                continue

            alerts_total += 1
            detection = _detection(record, index, sources, path, number)
            if detection is None:
                suppressed += 1
            else:
                detections.append(detection)

    return detections, alerts_total, suppressed, loaded


def _lines(handle: Iterable[str], path: Path) -> Iterable[str]:
    """Yield `handle`'s lines, turning undecodable bytes into a `FlabelError`.

    eve.json carries attacker-influenced strings — SNI, HTTP hosts, filenames — so a byte that
    is not valid UTF-8 is a thing a capture can genuinely contain. Without this, one such byte
    anywhere in the file, including in a record no alert refers to, ends the run with a bare
    `UnicodeDecodeError`: not a `FlabelError`, so `cli.py` cannot map it to an exit code and
    the operator gets a traceback instead of a reason. Decoded strictly rather than with
    ``errors="replace"`` because a silently mangled `threat` or hostname would travel into
    `labels.json` as provenance.
    """
    try:
        yield from handle
    except UnicodeDecodeError as exc:
        raise ToolError(
            f"{path} is not valid UTF-8 ({exc}). Suricata writes capture-derived strings into "
            f"eve.json, so this may be the capture's content rather than a broken tool."
        ) from exc


def _detection(
    record: Mapping[str, Any],
    index: Mapping[int, str],
    sources: Mapping[str, SourceAdmission],
    path: Path,
    number: int,
) -> Detection | None:
    """One alert record as a `Detection`, or None if its source may not label.

    None rather than a flag on the object: a suppressed alert must not exist as something a
    later stage could accidentally read past (spec §2.8).
    """
    alert = record.get("alert")
    if not isinstance(alert, dict):
        raise ToolError(f"{path} line {number} is an alert record with no alert object")
    # `signature` is required alongside `signature_id` because it becomes `SourceEntry.threat`,
    # one of the fields spec §4 demands on every label with no "where applicable" escape. A
    # default of "" would be a label that names no threat while looking complete.
    for key in ("signature_id", "signature"):
        if key not in alert:
            raise ToolError(f"{path} line {number} is an alert with no alert.{key}")

    # Checked rather than coerced: `int(None)` and `int("x")` raise TypeError/ValueError, which
    # are not `FlabelError`s, so `cli.py` could only report them as a traceback.
    raw_sid = alert["signature_id"]
    if not isinstance(raw_sid, int) or isinstance(raw_sid, bool):
        raise ToolError(
            f"{path} line {number}: alert.signature_id is {raw_sid!r}, not an integer, so the "
            f"alert cannot be attributed to a rule"
        )

    sid = raw_sid
    source = index.get(sid)
    if source is None:
        # Cannot happen with `-S`: only snapshot rules are loaded and every admitted SID was
        # attributed up front. Checked anyway, because the alternative to failing here is
        # emitting a label with an invented origin.
        raise SnapshotError(
            f"{path} line {number}: alert on sid {sid}, which belongs to no source in the "
            f"snapshot. Only the snapshot's rules were loaded, so this should be impossible."
        )

    admission = sources[source]
    spec = SourceSpec(
        name=admission.name,
        url=admission.url,
        licence=admission.licence,
        source_class=admission.source_class,
        admission_basis=admission.admission_basis,
    )
    if not spec.may_label:
        return None

    category = alert.get("category") or None
    src_port, dst_port = _ports(record)
    return Detection(
        source=source,
        tier=TIER,
        sid=sid,
        # `rev` defaults to 0 only because that is what Suricata itself reports for a rule
        # written without one — the default matches the tool's own semantics rather than
        # inventing a version.
        rev=int(alert.get("rev", 0)),
        classtype=category,
        app_proto=record.get("app_proto"),
        threat=str(alert["signature"]),
        ts=_epoch(record.get("timestamp"), path, number),
        src_ip=_address(record.get("src_ip")),
        src_port=src_port,
        dst_ip=_address(record.get("dest_ip")),
        dst_port=dst_port,
        proto=_proto(record.get("proto")),
        metadata=_metadata(alert.get("metadata")),
    )


def _proto(raw: Any) -> str:
    """The transport protocol in Zeek's spelling.

    Correlation matches the two tools' 5-tuples field by field (spec §9), and `Flow` is built
    from `conn.log`, so Zeek's spelling wins: lowercase, and `IPv6-ICMP` becomes `icmp` because
    that is what Zeek's `transport_proto` writes for ICMPv6 (measured — see `PROTO_ALIASES`).
    """
    lowered = str(raw or "").lower()
    return PROTO_ALIASES.get(lowered, lowered)


def _address(raw: Any) -> str:
    """An IP address in Zeek's canonical text form.

    Suricata writes IPv6 addresses expanded (``fd00:0000:0000:0000:0000:0000:0000:00a1``); Zeek
    writes them compressed (``fd00::a1``). Both name the same address, but correlation compares
    the *strings*, so without this every IPv6 detection would be uncorrelatable — and spec §9's
    unmatched gate fails the whole run past 1%. IPv4 is unaffected, and anything unparseable is
    passed through rather than dropped, since a malformed address is still evidence.
    """
    text = str(raw or "")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text


def _ports(record: Mapping[str, Any]) -> tuple[int, int]:
    """The port columns, mirroring what Zeek puts there for port-less protocols.

    ICMP has no ports, and Suricata's alert record carries `icmp_type`/`icmp_code` instead. Zeek
    does not leave `conn.log`'s port columns empty either — it writes the ICMP type in
    `id.orig_p` and, for an echo exchange, the counterpart type in `id.resp_p`. Recording
    `(0, 0)` here would make **every** ICMP detection unmatchable, and ET Open ships plenty of
    ICMP rules: three such alerts in 150 detections is enough to trip spec §9's 1% unmatched
    gate and fail an otherwise good run, with the run block blaming correlation.

    So type and code are mirrored into the port columns. Measured limitation, reported rather
    than hidden: for ICMPv4 echo this agrees with Zeek exactly (`8, 0`), but for ICMPv6 echo
    Zeek writes `128, 129` — the *reply* type, not the code — where this yields `128, 0`. A
    single alert record does not carry the counterpart type, so closing that gap needs
    correlation to treat ICMP specially (step 7), not a different value here.
    """
    for key in ("src_port", "dest_port"):
        if key in record:
            return int(record.get("src_port", 0)), int(record.get("dest_port", 0))
    return int(record.get("icmp_type", 0)), int(record.get("icmp_code", 0))


def _epoch(timestamp: Any, path: Path, number: int) -> float:
    """An eve timestamp as seconds since the epoch.

    Suricata writes local time with an offset (``2023-11-14T14:13:20.050000-0800``); Zeek
    writes epoch seconds. Converting here means correlation compares two numbers on one
    timeline instead of reconciling two formats (spec §9).

    A timestamp with **no** offset is rejected rather than assumed. `datetime.timestamp()`
    reads a naive value as *local* time, so an offset-less record would silently shift by the
    machine's UTC offset — no error, an epoch value hours out, and a correlation that quietly
    matches the wrong flow or none at all. Different machines would disagree, which is a
    reproducibility break of exactly the kind Goal 2 rules out.
    """
    if not isinstance(timestamp, str):
        raise ToolError(f"{path} line {number}: alert has no timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ToolError(
            f"{path} line {number}: unparseable timestamp {timestamp!r}: {exc}"
        ) from exc
    if parsed.tzinfo is None:
        raise ToolError(
            f"{path} line {number}: timestamp {timestamp!r} carries no UTC offset, so it "
            f"cannot be placed on the capture timeline without guessing a timezone"
        )
    return parsed.timestamp()


def _metadata(raw: Any) -> tuple[str, ...]:
    """`alert.metadata` flattened to sorted ``"key value"`` strings.

    Suricata reports metadata as an object of key → list of values; the rule wrote them as
    ``metadata:confidence High, signature_severity Major``. Flattened back to that spelling
    so issue #10 (should untagged ET rules be admitted?) can be answered from what the rule
    actually said, and sorted so the value is reproducible.
    """
    if not isinstance(raw, dict):
        return ()
    flattened = []
    for key, values in raw.items():
        if isinstance(values, list):
            flattened.extend(f"{key} {value}" for value in values)
        else:
            flattened.append(f"{key} {values}")
    return tuple(sorted(flattened))


# --- engine reporting ----------------------------------------------------------------------


def _rules_loaded_from_stats(record: Mapping[str, Any]) -> tuple[int, int, int] | None:
    """``(loaded, failed, skipped)`` from an eve stats record's `detect.engines[]`.

    All three, not just the loaded count: `rules_failed` is how a partial load — the failure
    that actually happens with real feeds — becomes visible, and `rules_skipped` distinguishes
    "the engine could not parse this rule" from "two rules share a SID and it kept one".
    """
    stats = record.get("stats")
    detect = stats.get("detect") if isinstance(stats, dict) else None
    engines = detect.get("engines") if isinstance(detect, dict) else None
    if not isinstance(engines, list):
        return None
    reported = [
        (engine.get("rules_loaded"), engine.get("rules_failed", 0), engine.get("rules_skipped", 0))
        for engine in engines
        if isinstance(engine, dict)
    ]
    usable = [
        (loaded, failed, skipped)
        for loaded, failed, skipped in reported
        if isinstance(loaded, int) and isinstance(failed, int) and isinstance(skipped, int)
    ]
    # Multi-tenant configs report one engine each; flabel runs a single ruleset, so the highest
    # loaded count is the one that describes it rather than a sum over engines that would
    # double-count the same rules.
    return max(usable) if usable else None


def _rules_loaded_from_log(path: Path) -> tuple[int, int, int] | None:
    """``(loaded, failed, skipped)`` as Suricata prints them to ``suricata.log``.

    Fallback for a configuration with eve stats switched off. All three counts come off one
    line, so reading it is no more work than reading the loaded count alone. The engine's own
    numbers are used rather than the snapshot's rule count because a rule that failed to parse
    never fires, and reporting it as loaded would overstate what the run looked for.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    matches = RULES_LOADED.findall(text)
    if not matches:
        return None
    loaded, failed, skipped = matches[-1]
    return int(loaded), int(failed), int(skipped)


def _version() -> tuple[str, ToolFailure | None]:
    """Suricata's version, or the failure that stopped us getting it.

    ``suricata --version`` does not exist — it exits 1 with "unrecognized option". ``-V`` is
    the flag (verified on 8.0.6), which is also why this is not a one-liner.
    """
    argv = [BINARY, "-V"]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=VERSION_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        return "unknown", _failure(
            argv, None, f"suricata -V did not return within {VERSION_TIMEOUT_SECONDS}s"
        )
    except OSError as exc:
        return "unknown", _failure(argv, None, f"suricata is not runnable: {exc}")
    if completed.returncode != 0:
        return "unknown", _failure(
            argv,
            completed.returncode,
            f"suricata -V failed: {_tail(completed.stderr or completed.stdout)}",
        )
    # Version output lands on stdout here, but both streams are read: the flag that reports it
    # is already a version-specific quirk, so which stream carries it is not worth assuming.
    match = VERSION.search(completed.stdout + completed.stderr)
    if match is None:
        return "unknown", _failure(
            argv,
            completed.returncode,
            f"suricata reported no parseable version: {completed.stdout.strip()!r}",
        )
    return match.group(0), None


# --- plumbing ------------------------------------------------------------------------------


def _prepare_outdir(outdir: Path) -> None:
    """Create `outdir`, refusing to reuse one that already holds a Suricata run.

    Suricata *appends* to ``eve.json``. Reusing a directory would silently fold a previous
    run's alerts into this one's labels, which is both a wrong answer and a modification of a
    previous run directory (spec §13).
    """
    if (outdir / EVE_FILE).exists():
        raise ToolError(
            f"{outdir / EVE_FILE} already exists. Suricata appends to it, so a previous "
            f"run's alerts would be read as this run's. Use a fresh output directory."
        )
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ToolError(f"suricata output directory {outdir} could not be created: {exc}") from exc


def _failure(argv: Sequence[str], exit_code: int | None, message: str) -> ToolFailure:
    """A `ToolFailure` for this tool, with the argv that produced it.

    The argv is recorded rather than just the message so a failure can be reproduced by
    pasting one line into a shell (spec §11).
    """
    return ToolFailure(tool=BINARY, argv=tuple(argv), exit_code=exit_code, message=message)


def _failed(
    manifest: SnapshotManifest, failure: ToolFailure, version: str = "unknown"
) -> SuricataRunInfo:
    """A run info carrying nothing but the failure — and the snapshot id.

    The snapshot id survives because the run block must still say which ruleset was
    attempted; a failed run that cannot say what it tried is a worse artifact than one that
    reports both.
    """
    return SuricataRunInfo(
        version=version,
        snapshot_id=manifest.snapshot_id,
        rules_loaded=0,
        alerts_total=0,
        identify_alerts_suppressed=0,
        tool_failures=(failure,),
    )


def _tail(output: str, limit: int = 400) -> str:
    """The last of a tool's output, for a failure message that fits on a screen."""
    text = " ".join(output.split())
    return text[-limit:] if len(text) > limit else text
