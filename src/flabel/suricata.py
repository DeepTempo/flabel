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
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any, get_args

from flabel.errors import SnapshotError, ToolError
from flabel.models import (
    Detection,
    Direction,
    SnapshotManifest,
    SourceAdmission,
    SuricataRunInfo,
    ToolFailure,
    may_label,
)
from flabel.rules.snapshot import DATA_DIR, RULES_NAME, load_sid_index, load_snapshot

#: Suricata is Tier 2 for every label it produces. Phase 2's PANW device is Tier 1; a lower
#: tier is a higher-trust observation (`Label.best_tier` is the minimum).
TIER = 2

#: Resolved through ``PATH`` rather than pinned to a path, so the container and a laptop both
#: work and a test can inject "the binary is not there" by emptying ``PATH``.
BINARY = "suricata"

EVE_FILE = "eve.json"
LOG_FILE = "suricata.log"

#: flabel's own Suricata config, shipped as package data. See the file's own header for the
#: label-affecting things the operator's `/etc/suricata/suricata.yaml` would otherwise decide.
CONFIG_FILE = "suricata.yaml"
CLASSIFICATION_FILE = "classification.config"

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

#: The rule's own `classtype:`. Read from the rule text rather than taken from `eve.json`'s
#: `alert.category` — see `rule_classtypes` for why that matters to a label.
CLASSTYPE = re.compile(r"\bclasstype\s*:\s*([A-Za-z0-9._-]+)\s*;")

#: A `dataset:` companion file a rule loads, e.g. `dataset:isset,tor,type string,load
#: pawpatrules_tor.lst`. Suricata resolves that name against the rule path, which is why
#: `default-rule-path` has to point at the directory the file is actually in (`rule_path`).
DATASET_LOAD = re.compile(r"\bdataset\s*:[^;]*?\bload\s+([^\s,;]+)")

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
    configuration, not one file of it.

    Two files, not three. `reference.config` was dropped after measuring: it only maps a
    `reference:` keyword's prefix to a URL, nothing reads those URLs, and against a real
    85,545-rule snapshot its absence changes the load by **0 rules** (the engine warns once per
    unknown prefix). `classification.config` stays because without it Suricata warns once per
    unknown classtype and its `alert.severity` defaults — neither fatal, but noise in a log an
    operator reads.
    """
    directory = data_dir()
    return tuple(directory / name for name in (CONFIG_FILE, CLASSIFICATION_FILE))


def config_sha256() -> str:
    """One digest over flabel's Suricata configuration, for the run block.

    A run is only reproducible against a *known* configuration: `HOME_NET` decides whether a
    whole class of rule can fire at all, and the eve output selection decides what is recorded.
    Recording the digest is what lets two runs be compared without trusting they used the same
    config.

    Computed once per run and carried on `SuricataRunInfo.config_sha256`, which is where the
    run block's `tools` section reads it from. Computed *before* the tool starts, so a run that
    fails still reports the configuration it attempted — and so an unreadable config file is a
    failure before a subprocess exists rather than a mystery afterwards.
    """
    digest = hashlib.sha256()
    for path in config_files():
        try:
            digest.update(path.read_bytes())
        except OSError as exc:
            raise ToolError(f"flabel's Suricata config {path} could not be read: {exc}") from exc
    return digest.hexdigest()


def rule_path(snapshot: Path, rules: str) -> Path:
    """The directory Suricata must resolve a rule's ``dataset:`` file against.

    Measured, and not what one would guess. Suricata resolves ``dataset: ... load
    pawpatrules_tor.lst`` against the *rule path*, so with ``default-rule-path=<snapshot>`` the
    18 pawpatrules dataset rules fail to load — 26 failures against the live feeds. Pointing it
    at ``<snapshot>/data/pawpatrules`` loads all 85,545 with 0 failures.

    Which directory that is comes from the rules themselves: every ``load`` target is looked up
    under ``data/``, so the answer is derived per snapshot rather than hardcoded to the one feed
    that ships datasets today.

    **``default-rule-path`` takes a single path, and that is a real ceiling.** If a second
    dataset-bearing feed is ever admitted, its files will sit in a different per-source directory
    and one of the two sets cannot resolve — so this raises rather than picking a winner and
    letting the other feed's rules quietly fail. The per-source layout itself is not negotiable:
    `et/open` and `stamus/lateral` both ship a file called `LICENSE`, so a flat directory would
    have them overwrite each other. When that day comes the fix is upstream of here — a symlink
    farm or a single merged data directory built at snapshot time, which is step 4's to own.
    """
    targets = sorted(set(DATASET_LOAD.findall(rules)))
    if not targets:
        return snapshot

    data_root = snapshot / DATA_DIR
    homes: dict[str, set[Path]] = {}
    for target in targets:
        name = Path(target).name
        if name != target:
            # A path rather than a bare name resolves relative to the rule path itself, so the
            # directory this function has to return is no longer inferable from where the file is.
            raise SnapshotError(
                f"{snapshot / RULES_NAME} loads dataset {target!r}, which contains a path "
                f"separator. flabel can only resolve bare file names against a snapshot's "
                f"data directory."
            )
        found = sorted(path.parent for path in data_root.rglob(name) if path.is_file())
        if not found:
            raise SnapshotError(
                f"{snapshot / RULES_NAME} loads dataset {target!r}, which is not in "
                f"{data_root}. The rules that need it could not match, so the snapshot is "
                f"incomplete rather than merely unusual."
            )
        homes.setdefault(target, set()).update(found)

    directories = sorted({directory for found in homes.values() for directory in found})
    if len(directories) > 1:
        raise SnapshotError(
            f"snapshot {snapshot.name} needs dataset files from more than one directory "
            f"({[str(directory) for directory in directories]}), and Suricata's "
            f"`default-rule-path` accepts exactly one. Every rule pointing at the directories "
            f"not chosen would fail to load, so this fails here instead of silently losing "
            f"coverage. Merging the data directories is step 4's to do."
        )
    return directories[0]


def build_argv(
    capture: Path, snapshot: Path, outdir: Path, rules_path: Path | None = None
) -> list[str]:
    """The exact invocation of spec §8, with flabel's own config.

    Separated from `run_suricata` so the flags are testable without running anything. Three
    things here are load-bearing beyond the flags spec §8 lists:

    * ``-c`` — flabel's config rather than the machine's. Without it, whether an abuse.ch
      ``$HOME_NET -> $EXTERNAL_NET`` C2 rule fires at all depends on the operator's
      `suricata.yaml` (proved by a test: on the stock config that rule matches *nothing* in the
      benign canary; with flabel's, it matches).
    * ``--set default-rule-path`` — where a rule's own ``dataset:`` files resolve. See
      `rule_path`: it is the per-source data directory, not the snapshot root, and the difference
      is 26 rules that fail to load against the live feeds. It does *not* affect ``-S``: measured
      on 8.0.6, a relative ``-S`` resolves against the working directory and ignores this.
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
        str(snapshot / RULES_NAME),
        "-l",
        str(outdir),
        # `classification.config` is named relatively in the YAML and set absolutely here,
        # because the package's location is not knowable when the YAML is written.
        "--set",
        f"classification-file={directory / CLASSIFICATION_FILE}",
        "--set",
        f"default-rule-path={(rules_path or snapshot).resolve()}",
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

    The snapshot is loaded through `rules/snapshot.py` rather than read here: `load_snapshot`
    re-hashes the content against the id, checks the manifest describes it, and `load_sid_index`
    parses the attribution — all of which this module used to duplicate. `snapshot` is a
    directory because spec §8 says so, and a snapshot directory is always named by its id, so
    the loader is called with the pair it wants.
    """
    # No warnings to collect: an explicit id was given, so nothing was skipped to reach it.
    # `cli.py` is where the `None` resolution happens and where its warnings are recorded (#91).
    directory, manifest, _ = load_snapshot(snapshot.parent, snapshot.name)
    # From the manifest rather than built here: correlation needs the same lookup, and two
    # copies of it carry two copies of the duplicate-name hazard the manifest now rejects.
    sources = manifest.sources_by_name
    index = load_sid_index(directory)
    rules_text = _rules_text(directory)
    classtypes = rule_classtypes(rules_text, index, directory)
    _prepare_outdir(outdir)

    argv = build_argv(capture, directory, outdir, rule_path(directory, rules_text))
    # Before the tool runs, so every return below — including the failure paths — can say which
    # configuration was in force. A config we cannot hash is a run we cannot attest.
    config_digest = config_sha256()
    version, failure = _version()
    if failure is not None:
        return [], _failed(manifest, failure, config_sha256=config_digest)

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
            config_sha256=config_digest,
        )
    except OSError as exc:
        return [], _failed(
            manifest,
            _failure(argv, None, f"suricata could not be executed: {exc}"),
            version=version,
            config_sha256=config_digest,
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
            config_sha256=config_digest,
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
            config_sha256=config_digest,
        )

    detections, alerts_total, suppressed, counts = _read_eve(eve, index, classtypes, sources)
    if counts is None:
        counts = _rules_loaded_from_log(outdir / LOG_FILE)

    failure = _check_ruleset_loaded(counts, expected=len(index), argv=argv, exit_code=0)
    if failure is not None:
        # The eve pass above already established these, so they are handed on rather than
        # discarded (issue #86). A run that suppressed alerts and then failed to account for its
        # ruleset still knows how many it suppressed, and `run.json` is all a reader gets.
        return [], _failed(
            manifest,
            failure,
            version=version,
            config_sha256=config_digest,
            alerts_total=alerts_total,
            identify_alerts_suppressed=suppressed,
        )

    # `counts` is not None here: `_check_ruleset_loaded` returns a failure when it is.
    loaded, failed, skipped = counts if counts else (0, 0, 0)
    return detections, SuricataRunInfo(
        version=version,
        snapshot_id=manifest.snapshot_id,
        rules_loaded=loaded,
        alerts_total=alerts_total,
        rules_failed=failed,
        rules_skipped=skipped,
        identify_alerts_suppressed=suppressed,
        config_sha256=config_digest,
        warnings=_load_warnings(loaded, failed, skipped, len(index)),
    )


def _load_warnings(loaded: int, failed: int, skipped: int, expected: int) -> tuple[str, ...]:
    """What to say about rules the engine did not load (spec §11, issue #46).

    Two different statements, because two different things go wrong.

    A **shortfall** — fewer rules loaded than the snapshot admitted — is the case that used to
    fail the run outright. It no longer does (Craig, 2026-08-12): a threshold is a number of
    labels one is willing to lose in silence, and the measurement gives no evidence for any
    particular value. At full scale the shortfall is not small, it is *zero* — 85,431 loaded, 0
    failed, 0 skipped — because the three rules this engine cannot compile are excluded at
    admission rather than left to fail at load. Zero being the only value ever observed means
    any threshold would be invented, so the run reports the loss and `cli.py` asks the operator.

    **The percentage is here rather than at the call site** because it is what makes the count
    answerable: 26 rules lost is a curiosity against 85,431 and a broken snapshot against 40.
    Composing it once means the sentence an operator reads at the prompt is the same sentence
    the run block records, rather than two roundings of one fact.

    The second case is a **contradiction**: the engine reported rejected rules *and* a loaded
    count matching the snapshot exactly. Both cannot describe the whole ruleset, so the coverage
    of that run is unverified even though nothing is provably missing.
    """
    warnings: list[str] = []
    missing = expected - loaded
    if missing > 0:
        share = (missing / expected * 100) if expected else 0.0
        warnings.append(
            f"{missing} of {expected} rules ({share:.2f}%) did not load: {failed} failed, "
            f"{skipped} skipped. The missing rules never examined the capture, so any label "
            f"they would have produced is absent from a run that otherwise looks complete."
        )
    elif failed or skipped:
        warnings.append(
            f"suricata reported {failed} rules failed and {skipped} rules skipped, yet its "
            f"loaded count matched the snapshot exactly. The two numbers cannot both describe "
            f"the whole ruleset, so treat the rule coverage of this run as unverified."
        )
    return tuple(warnings)


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

    **The third is no longer a failure** (Craig, 2026-08-12 — issue #46). It used to be, on the
    conservative reading of "record it, warn above zero, fail above a threshold". Measured at
    full scale the shortfall is zero — 85,431 admitted, 85,431 loaded — because the rules this
    engine is known in advance to reject are excluded at admission (§5), so these counters
    describe *surprises*. Zero being the only value ever observed means no threshold could be
    derived rather than invented, and an unconditional failure is a threshold of zero chosen by
    default. It is now reported through `_load_warnings` and `cli.py` puts the decision to the
    operator, with the count and the share of the ruleset in front of them.

    The first two stay fatal, and the difference is not a matter of degree. A ruleset that is
    *attestably incomplete* is evidence an operator can weigh; one that **cannot be attested at
    all**, or that produced an empty alert set because nothing loaded, is not evidence at all —
    and zero labels from zero rules is indistinguishable from a clean capture.
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
    # A shortfall returns None: it is reported by `_load_warnings` and decided by the operator
    # (#46), not failed here. Loading *more* than admitted is not a shortfall and not possible
    # from a snapshot, so it is left to the same warning path rather than given a branch.
    return None


# --- the snapshot -------------------------------------------------------------------------
#
# Reading and verifying a snapshot is `rules/snapshot.py`'s job, not this module's: it re-hashes
# the content against the id and checks the manifest describes it. What is left here is the one
# thing only the Suricata pass needs — the classtype each sid declares — plus the cross-check
# that the attribution covers exactly the rules that can fire.


def _rules_text(directory: Path) -> str:
    """`rules.rules` as text, decoded leniently.

    Lenient because the bytes are third-party rule text and the snapshot id already proves they
    are the bytes that were admitted: a stray non-UTF-8 byte in one rule's `msg` must not stop a
    run, and the sid and classtype this module reads are ASCII either way.
    """
    try:
        return (directory / RULES_NAME).read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        raise SnapshotError(f"could not read {directory / RULES_NAME}: {exc}") from exc


def rule_classtypes(rules: str, index: Mapping[int, str], directory: Path) -> dict[int, str]:
    """Each sid's `classtype:`, read from the rule text, and the sid cross-check.

    **Why not `eve.json`'s `alert.category`, which spec §8 names.** `category` is not the
    classtype: it is the *description* Suricata looks up in `classification.config`, so the text
    a label carried depended on a file outside the rule — different wording on two machines for
    one rule (a Goal 2 break), an empty string for any classtype the file omits, and, once that
    file became flabel's own, wording flabel would be inventing on the feed's behalf. The rule
    itself says `classtype:trojan-activity`, that text is inside the hashed snapshot, and it is
    what the feed actually asserted. So a label now records `trojan-activity` rather than
    "A Network Trojan was detected".

    A rule with no `classtype:` maps to nothing and its detections carry `classtype=None`. That
    is common, not exceptional: 10,949 of the 85,545 admitted rules in the measured snapshot have
    none.

    The cross-check rides along because the scan is already happening. `rules.rules` is what
    Suricata reads, so it decides what can fire; `sid_index.json` decides what a firing rule can
    be attributed to. A sid in one and not the other means a label with no traceable origin, or
    an attribution for a rule that is not there — either way the two files describe different
    rulesets and neither can be trusted (spec §13).
    """
    classtypes: dict[int, str] = {}
    admitted: set[int] = set()

    for line in rules.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Quoted arguments are blanked first, so a `content:"sid:1;"` cannot be read as the
        # rule's own sid, and the last remaining match wins: `sid` is conventionally the final
        # option, so anything that survived the blanking is more likely to precede it.
        bare = QUOTED.sub('""', stripped)
        found = SID.findall(bare)
        if not found:
            raise SnapshotError(
                f"{directory / RULES_NAME} has an active rule with no sid, which cannot be "
                f"attributed to a source: {stripped[:120]}"
            )
        sid = int(found[-1])
        admitted.add(sid)
        classtype = CLASSTYPE.search(bare)
        if classtype is not None:
            classtypes[sid] = classtype.group(1)

    if not admitted:
        raise SnapshotError(
            f"{directory / RULES_NAME} contains no rules. Suricata treats that as a warning and "
            f"exits 0 with an empty alert set, which is indistinguishable from a capture that "
            f"contained nothing — so it fails here instead."
        )

    unattributed = sorted(admitted - set(index))
    if unattributed:
        raise SnapshotError(
            f"{directory / RULES_NAME} admits sids that sid_index.json does not attribute: "
            f"{unattributed[:20]} ({len(unattributed)} total). Each could fire and could not be "
            f"traced to a source, which also means we cannot tell whether it may label "
            f"(spec §2.8)."
        )

    phantom = sorted(set(index) - admitted)
    if phantom:
        raise SnapshotError(
            f"sid_index.json attributes sids that are not in {RULES_NAME}: {phantom[:20]} "
            f"({len(phantom)} total). The two files describe different rulesets, so neither can "
            f"be trusted to say what ran."
        )
    return classtypes


# --- eve.json ------------------------------------------------------------------------------


def _read_eve(
    path: Path,
    index: Mapping[int, str],
    classtypes: Mapping[int, str],
    sources: Mapping[str, SourceAdmission],
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
            detection = _detection(record, index, classtypes, sources, path, number)
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
    classtypes: Mapping[int, str],
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

    # Read straight off the admission record. This used to build a throwaway `SourceSpec` to
    # reach `may_label`, because the rule lived only as a property; `models.may_label` is now
    # the one derivation and both this module and `provenance.py` call it (#47).
    if not may_label(sources[source].source_class):
        return None

    # From the rule text in the hashed snapshot, not from `alert.category`: see
    # `rule_classtypes`. A rule with no `classtype:` yields None, which is ordinary — 10,949 of
    # the 85,545 rules in the measured snapshot declare none.
    classtype = classtypes.get(sid)
    src_port, dst_port = _ports(record)
    return Detection(
        source=source,
        tier=TIER,
        sid=sid,
        # `rev` defaults to 0 only because that is what Suricata itself reports for a rule
        # written without one — the default matches the tool's own semantics rather than
        # inventing a version.
        rev=int(alert.get("rev", 0)),
        classtype=classtype,
        app_proto=record.get("app_proto"),
        threat=str(alert["signature"]),
        ts=_epoch(record.get("timestamp"), path, number),
        src_ip=_address(record.get("src_ip")),
        src_port=src_port,
        dst_ip=_address(record.get("dest_ip")),
        dst_port=dst_port,
        proto=_proto(record.get("proto")),
        # Top level of the eve record, beside `src_ip` — **not** inside the `alert` object with
        # `signature_id` and `rev`. Measured on 8.0.6, and asserted against a real run, because
        # reading the right key at the wrong nesting level yields `unknown` on every alert and
        # looks exactly like a tool that stopped reporting it.
        direction=_direction(record.get("direction")),
        metadata=_metadata(alert.get("metadata")),
    )


def _direction(raw: Any) -> Direction:
    """Which side of the flow the matching packet was on (issue #115).

    Anything this build does not recognise — an absent key, a value a later Suricata adds —
    becomes `unknown`, which says the direction was not established. The alternative would be
    to pick one of the two real values, and inventing a direction is the defect #115 exists
    to report: a rule whose `msg` says "Outgoing connection" fired on an inbound flow, and a
    guess would make the label agree with itself while still being wrong.

    Not an error, because an alert Suricata cannot direct is ordinary traffic — an unsolicited
    ICMP destination-unreachable is the measured case — and failing the run over it would lose
    every label in the capture for a field no verdict depends on.
    """
    return raw if raw in get_args(Direction) else "unknown"


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
    manifest: SnapshotManifest,
    failure: ToolFailure,
    version: str = "unknown",
    config_sha256: str | None = None,
    *,
    alerts_total: int | None = None,
    identify_alerts_suppressed: int | None = None,
) -> SuricataRunInfo:
    """A run info carrying nothing but the failure — the snapshot id, and the config digest.

    The snapshot id survives because the run block must still say which ruleset was
    attempted; a failed run that cannot say what it tried is a worse artifact than one that
    reports both. The config digest survives for the same reason: `HOME_NET` and the eve
    selection decide what could have fired, so a failure is only diagnosable against them.

    **Everything else is `None`, not `0`** (issue #86). Spec §10: every field whose stage did not
    run is `null`. Zeros here published measurements that never happened — `rules_loaded: 0` for a
    run where the engine may have loaded all of them, and `loss_conditions` reporting
    `rules_failed_or_skipped: false` off the back of it, a zero load reading as a clean load.

    `alerts_total` and `identify_alerts_suppressed` are accepted rather than assumed, because
    `_read_eve` runs *before* `_check_ruleset_loaded` and does establish them. A run that
    suppressed 40 `identify` alerts and then failed used to throw that number away and report
    `0` — discarding a fact it held, on the one path where the record is all there is.
    """
    return SuricataRunInfo(
        version=version,
        snapshot_id=manifest.snapshot_id,
        rules_loaded=None,
        alerts_total=alerts_total,
        rules_failed=None,
        rules_skipped=None,
        identify_alerts_suppressed=identify_alerts_suppressed,
        config_sha256=config_sha256,
        tool_failures=(failure,),
    )


def _tail(output: str, limit: int = 400) -> str:
    """The last of a tool's output, for a failure message that fits on a screen."""
    text = " ".join(output.split())
    return text[-limit:] if len(text) > limit else text
