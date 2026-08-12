# Specification — flabel Phase 1

**Stage 4, Part A.** Derived from `docs/prd.md` v0.4 and `docs/eng-review.md`. Scope: **Phase 1 (Tier 2 / open-source screening) only.** Phase 2 is specified after its reachability spike.

The bar for this document: hand it to a stranger and they build the same thing.

---

## 1. Vocabulary

Terms are used exactly as defined here, in code and in output.

| Term | Meaning |
| :-- | :-- |
| **capture** | The input file as supplied by the operator: `pcap`, `pcapng`, optionally gzipped. |
| **normalized capture** | The single `pcap` file derived from the capture that every consumer reads. Never the original artifact. |
| **run** | One invocation of flabel against one capture. Produces exactly one run directory. |
| **run directory** | `{capture-name}_{datetime}/` — the complete, self-contained output of a run. |
| **flow** | A Zeek connection, identified by its `uid`. The authoritative unit of identity in the system. |
| **detection** | One alert from one source. Not yet tied to a flow. |
| **label** | A verdict about one flow, carrying every detection that asserted it. |
| **source** | A named ruleset or feed (e.g. `et/open`, `abuse.ch/urlhaus`). |
| **source class** | `signature`, `ioc-dest`, `ioc-name`, or `identify`. Determines `label_basis` and whether the source may label at all. |
| **admission basis** | `metadata-filter` or `wholesale`. How a source's rules were gated. Orthogonal to source class. |
| **label basis** | `direct` (this flow is the malicious activity) or `indicator-reference` (this flow referenced a malicious indicator). |
| **ruleset snapshot** | An immutable, content-addressed directory of filtered rules plus a manifest. The unit of reproducibility. |
| **canary** | A fixture capture with a known-correct expected outcome. Benign → zero labels; malicious → at least one. |
| **loss condition** | An enumerated way a run can under-report. Each has a named field in the run block and one fault-injection test. |

---

## 2. Constraints and invariants

These hold everywhere. A violation is a bug, not a trade-off.

1. **Zero runtime dependencies.** Standard library only. `tomllib` (3.11+) for config; `argparse` for the CLI. Dev dependencies (pytest, ruff) are unrestricted.
2. **Only `flabel rules update` performs network I/O.** A labelling run that attempts a network connection is a defect. This is what makes Goal 2 achievable.
3. **Zeek is always invoked with `-D`.** Verified: without it, `uid` differs on every run and reproducibility is impossible.
4. **All consumers read the same normalized capture.** They cannot disagree about input.
5. **Absence is never a signal.** Every enumerated loss condition is reported in the run block. Silence means nothing happened, never "something happened and we didn't say."
6. **A computed fingerprint is never a verdict.** Labels come only from rule matches.
7. **Phase 2 must be additive.** No schema version change, no consumer change. Any Phase 1 design that would force one is wrong.
8. **`identify`-class sources can never produce a label.** Enforced in code and asserted in a test.

### Testing line: tools real, network stubbed

`CLAUDE.md` says never call external APIs in tests. That rule targets **external services and devices**, and it stands: the PANW device (Phase 2) and rule-feed endpoints are never contacted from a test.

Local CLI tools are a different category — Zeek, Suricata, and `editcap` are hermetic, deterministic, and versioned. **They are hard test dependencies and are invoked for real.** There are no mocks and no golden-file substitutes for them, because a mock would encode our assumptions about tool behaviour, which is exactly what needs verifying.

| Boundary | In tests |
| :-- | :-- |
| Zeek, Suricata, `editcap`, `capinfos` | **Invoked for real.** Suite cannot run without them. |
| Rule-feed HTTP endpoints | **Stubbed** — `fetch` reads local fixture files. |
| PANW device (Phase 2) | **Never contacted.** `[LAB]` criteria only. |

Consequence: CI must provide the toolchain before any other step is testable. That is step 1 of the plan.

---

## 3. Module layout and responsibilities

```
src/flabel/
  __init__.py       __version__
  models.py         all dataclasses; imported by everything, imports nothing
  errors.py         typed exceptions -> exit codes
  config.py         load + validate the source registry
  ingest.py         format sniff, decompress, convert, validate
  zeek.py           invoke Zeek; parse conn.log + ssl.log
  suricata.py       invoke Suricata; parse eve.json
  rules/
    __init__.py
    fetch.py        the ONLY network I/O in the package
    admit.py        per-source admission policy (pure)
    snapshot.py     hash, write, load snapshots
  correlate.py      detections -> flows (pure)
  labels.py         build labels, canonical serialisation (pure)
  provenance.py     assemble the run block (pure)
  notice.py         emit NOTICE attribution (pure)
  cli.py            argument parsing, orchestration, exit codes
  data/
    sources.toml          the source registry (shipped with the package)
    json-logs.zeek        Zeek script adding JSON filters
    suricata.yaml         flabel's own Suricata config (§8) — added in step 6
    classification.config the classtypes that config names — added in step 6
```

**Package data lives inside the package**, not at the repo root. Root-level `data/` can only
reach a wheel via a hatch `force-include`, which is absent from an editable install — the mode
`uv sync` uses — so `importlib.resources` would resolve in a built wheel and fail in the tests.
Under `src/flabel/data/` it resolves identically from a checkout, an editable install and a
wheel. Corrected in step 2; the original diagram placed `data/` alongside `src/`.

**`models.py` is a refinement of the approved layout.** Every module codes against shared dataclasses rather than each owning its own, which is what allows steps 4–7 to be built in parallel without importing one another.

**Pure modules** (`models`, `errors`, `config`, `admit`, `correlate`, `labels`, `provenance`, `notice`) must not import `subprocess`, `urllib`, or `socket`. Enforced by a test that greps the module sources — a cheap architectural guard that survives refactoring.

---

## 4. Data models

All are frozen dataclasses in `models.py`.

```python
# --- configuration -------------------------------------------------------
SourceClass = Literal["signature", "ioc-dest", "ioc-name", "identify"]
AdmissionBasis = Literal["metadata-filter", "wholesale"]
LabelBasis = Literal["direct", "indicator-reference"]

@dataclass(frozen=True)
class SourceSpec:
    name: str                    # "et/open"
    url: str
    licence: str                 # SPDX id, or "unstated"
    source_class: SourceClass
    admission_basis: AdmissionBasis
    enabled: bool = True

    @property
    def may_label(self) -> bool:        # False iff source_class == "identify"
    @property
    def label_basis(self) -> LabelBasis | None:  # None iff not may_label

# --- ruleset snapshot ----------------------------------------------------
@dataclass(frozen=True)
class SourceAdmission:
    name: str
    licence: str
    source_class: SourceClass
    admission_basis: AdmissionBasis
    rules_fetched: int
    rules_admitted: int
    rules_excluded_no_confidence: int
    rules_excluded_low_confidence: int
    rules_excluded_low_severity: int
    ja4_rules_admitted: int
    ja3_rules_admitted: int
    fetched_at: str              # ISO-8601 UTC

@dataclass(frozen=True)
class SnapshotManifest:
    snapshot_id: str             # content hash over the whole snapshot — see §7
    created_at: str
    flabel_version: str
    sources: tuple[SourceAdmission, ...]
    total_admitted: int
    total_ja4_admitted: int

# --- pipeline ------------------------------------------------------------
@dataclass(frozen=True)
class Flow:
    uid: str
    src_ip: str; src_port: int
    dst_ip: str; dst_port: int
    proto: str
    ts_first: float; ts_last: float
    ja4: str | None = None
    ja4s: str | None = None
    server_name: str | None = None

@dataclass(frozen=True)
class Detection:
    source: str                  # SourceSpec.name
    tier: int                    # always 2 in Phase 1
    sid: int
    rev: int
    classtype: str | None
    app_proto: str | None
    threat: str                  # the rule's msg
    ts: float                    # alert timestamp, capture timeline
    src_ip: str; src_port: int
    dst_ip: str; dst_port: int
    proto: str

@dataclass(frozen=True)
class SourceEntry:               # one asserting detection on a label
    tier: int
    source: str
    sid: int
    rev: int
    ruleset: str                 # snapshot_id
    admission_basis: AdmissionBasis
    licence: str
    classtype: str | None
    label_basis: LabelBasis
    threat: str

@dataclass(frozen=True)
class Label:
    flow: Flow
    verdict: Literal["malicious"]
    best_tier: int               # min(tier); lower is higher trust
    sources: tuple[SourceEntry, ...]

@dataclass(frozen=True)
class UnmatchedDetection:
    detection: Detection
    reason: Literal["no_flow_match", "ambiguous_flow_match"]
```

**Added in step 2**, because §8 and §9 name them as return types but this section did not define
them: `NormalizedCapture`, `ZeekRunInfo`, `SuricataRunInfo`, `CorrelationResult`, and
`ToolFailure` (carried by the two RunInfo types). Fields are derived from the run block in §10.
They live here rather than in steps 3/5/6/7 so those steps only *read* `models.py`; a step that
has to create a shared type collides with its siblings in the file meant to prevent that.

**Three fields added in step 2**, each with its reason in the code:

| Field | Why |
| :-- | :-- |
| `Detection.metadata` | §8 says to parse `alert.metadata`; there was nowhere to put it. Issue #10 is answered from it. |
| `SourceAdmission.url` | Otherwise a label's origin traces only to a source *name* in a TOML file that can change between runs. |
| `SourceAdmission.rules_excluded_commented` | ET Open 8.0 ships 19,479 `#alert` lines against 51,778 active rules. Without this counter §6's `fetched == admitted + sum(excluded)` identity cannot describe the feed. `rules_fetched` therefore counts active `alert` lines only. |

**The `Literal` types are enforced at runtime**, not merely annotated: `Label(verdict="benign")`
would otherwise construct happily, and §13's first never-do is asserting a flow is benign. A
`Label` also rejects empty `sources` (a label with no assertion has no provenance) and a
`best_tier` disagreeing with `min(sources.tier)`.

**Fields added after steps 3–6 measured the tools.** Each exists because a real loss turned out
to have nowhere to be reported, and §2.5 says absence is never a signal. They are field
corrections, not design changes: nothing here alters what a label means.

| Field | Added by | Why |
| :-- | :-- | :-- |
| `warnings: tuple[str, ...]` on `NormalizedCapture`, `ZeekRunInfo`, `SuricataRunInfo` | steps 3, 5, 6 | Every stage found non-fatal losses worth reporting — a trimmed tail record, a missing JA4 package, rules the engine refused. Warnings were going to stderr only, so a consumer reading `labels.json` alone could not see them. §10's run block already has a `warnings` array; these are what fills it, per stage, so the stage that observed a loss is the stage that reports it. |
| `rules_failed`, `rules_skipped` on `SuricataRunInfo` | step 6 | Suricata reports `N loaded, M failed, K skipped` and exits 0 either way. Without the last two, a snapshot of 85,545 rules loading as 85,519 is a run that looks complete and silently never examined the capture with 26 rules. `failed` and `skipped` are separate because they are different faults: `failed` is a rule this build cannot parse, `skipped` is a rule dropped for duplicating another's SID. |
| `ja4_status: Literal["present", "not-installed", "probe-failed"] \| None` on `ZeekRunInfo` | step 5 | A null `ja4` on a flow has two causes — no TLS in the capture, or no fingerprinting package installed — and they are not the same fact. Step 5 initially overloaded `ja4_package_version` with status strings; that field is now reserved for an actual version (§8 says where it comes from), and the status has its own field. `probe-failed` is separate from `not-installed` because an absent package is the ordinary laptop case and a broken `ZEEKPATH` is a defect. |
| `rules_excluded_unloadable` on `SourceAdmission` | step 6 | Three pawpatrules rules cannot compile under this configuration (§8). They have to be excluded at admission, and §6's `fetched == admitted + sum(excluded)` identity means every exclusion needs its own counter, or the rules go missing unaccounted for. |

**`ToolError` carries the evidence, not just a message.** Recorded in step 5 and relied on by
step 6: the exception exposes `failures` (the `ToolFailure` records it was raised over) and
`run_info` (the stage's run info, carrying those same records). §8 says a tool failure is
recorded *as well as* raised — an exception carrying only a string would force the caller to
choose between reporting the loss and failing on it.

### `labels.json` document

```json
{
  "schema_version": "1.0",
  "run": { "...": "see §9" },
  "labels": [ "...Label..." ],
  "unmatched_detections": [ "...UnmatchedDetection..." ]
}
```

`schema_version` is `"1.0"` and **does not change when Phase 2 adds tier-1 entries to `sources[]`** (Goal 6).

---

## 5. Source registry

`data/sources.toml`, shipped with the package, overridable with `--sources`.

```toml
[[source]]
name             = "et/open"
url              = "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz"
licence          = "MIT"
source_class     = "signature"
admission_basis  = "metadata-filter"

[[source]]
name             = "abuse.ch/feodotracker"
url              = "https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz"
licence          = "CC0-1.0"
source_class     = "ioc-dest"        # matches a C2 destination -> the flow IS malicious
admission_basis  = "wholesale"

[[source]]
name             = "abuse.ch/urlhaus"
licence          = "CC0-1.0"
source_class     = "ioc-name"        # matches a looked-up name -> reference
admission_basis  = "wholesale"

[[source]]
name             = "oisf/trafficid"
licence          = "MIT"
source_class     = "identify"        # may_label == False
admission_basis  = "wholesale"
```

**Authoritative class assignments:**

| Source | Licence | Class | Basis | Labels? |
| :-- | :-- | :-- | :-- | :-: |
| `et/open` | MIT | `signature` | metadata-filter | direct |
| `stamus/lateral` | GPL-3.0-only | `signature` | wholesale | direct |
| `malsilo/win-malware` | MIT | `signature` | wholesale | direct (unmaintained — risk accepted) |
| `the-hunters-ledger/open` | CC-BY-4.0 | `signature` | wholesale | direct |
| `pawpatrules` | CC-BY-SA-4.0 | `signature` | wholesale | direct |
| `abuse.ch/feodotracker` | CC0-1.0 | `ioc-dest` | wholesale | direct |
| `abuse.ch/sslbl-blacklist` | CC0-1.0 | `ioc-dest` | wholesale | direct |
| `abuse.ch/urlhaus` | CC0-1.0 | `ioc-name` | wholesale | **indicator-reference** |
| `oisf/trafficid` | MIT | `identify` | wholesale | **never** |

Excluded entirely and absent from the registry: `tgreen/hunting`, `etnetera/aggressive`, `ptresearch/attackdetection`, `ptrules/open`, `sslbl/ja3-fingerprints`, and all commercial sources.

**`sslbl/ssl-fp-blacklist` was renamed to `abuse.ch/sslbl-blacklist` in step 2.** The OISF index marks the old name `deprecated: Renamed to abuse.ch/sslbl-blacklist` (same URL). Since the source name is recorded on every label as provenance, the canonical name was adopted before any label could carry the stale alias. The exclusion list above likewise cites `sslbl/ja3-fingerprints` by its old name; upstream now calls it `abuse.ch/sslbl-ja3`, and both are excluded.

**`malsilo/win-malware` is upstream-unmaintained, and that risk is accepted** (Craig, 2026-08-12). The OISF index flags it `obsolete: unmaintained`; the live artifact is 1,089 bytes with 14 alert rules across three files, last modified 2022-12-01. Kept on the same terms as `pawpatrules`: no per-rule gate, with the benign canary as its standing review. This knowingly accepts an inconsistency — `docs/research.md` §B1 excluded `sslbl/ja3-fingerprints` partly for being abandoned. Revisit if it ever produces a false positive.

**`abuse.ch/sslbl-c2` was removed in step 2** after verification against the live feed, leaving nine sources. The OISF index marks it `deprecated: Deprecated by source on 2025-01-03`, and the artifact is 335 bytes: a header plus "ATTENTION: This list has been deprecated". It ships zero rules. Shipping it would imply coverage that cannot exist, and its zero count would be indistinguishable from a feed that matched nothing that run.

Validation on load, as originally specified: unknown `source_class` or `admission_basis` is a hard failure; `metadata-filter` is permitted only where ET-style metadata exists.

**The following were added in step 2 as a design decision, not carried over from an earlier draft** — recorded here so the code and this document agree, but they are the implementer's judgment rather than a pre-existing requirement. Reasoning: a registry that loads with a setting silently ignored is worse than one that refuses to load, because it reads as working.

- An unknown or misspelled field, a missing required field, a duplicate name (compared case-insensitively, since step 4 writes `raw/<source>.rules`), an empty registry, a non-boolean `enabled`, and a non-string or empty `name`/`url`/`licence`.
- **A non-HTTPS `url`.** Rules are the trust root of every label: over `http://` they are forgeable in transit, and `file://` would make an arbitrary local file into label evidence.
- **A `name` outside `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$`.** The name becomes a path component in a snapshot (§7), so `--sources` with `name = "../../.ssh/authorized_keys"` would otherwise write fetched rule text outside the snapshot directory.

A `licence` of `"unstated"` remains legal per §4, but no shipped source uses it and a test asserts so.

**Three `pawpatrules` rules are excluded at admission and can never label — measured in step 6.**
Sids 3300158, 3300159 and 3321393 ("P2P direct calling via STUN") are each written
`-> ![..., $HOME_NET]`, and negating flabel's `HOME_NET: any` leaves the empty set, so Suricata
refuses to compile them: *"Complete IP space negated. Rule address range is NIL."* They are
counted in `rules_excluded_unloadable` (§4) rather than left to fail at load, because a rule the
engine rejects is coverage flabel does not have, and a snapshot whose `total_admitted` counts
rules that cannot run overstates what examined the capture. The configuration trade-off that
produces this is in §8; 3 lost rules against up to 1,397 is why it is decided that way.

The ET Open URL pins `suricata-8.0` to match the pinned engine (8.0.6). ET compiles per engine version, so the 7.0 set omits rules using 8.0-era keywords; this originally read `suricata-7.0`, corrected in step 2.

---

## 6. Admission policy — `rules/admit.py`

```python
def admit(spec: SourceSpec, rule_lines: Iterable[str]) -> tuple[list[str], SourceAdmission]
```

Pure. Given a source and its fetched rule text, return the admitted rules plus counts.

- `admission_basis == "wholesale"` → admit every `alert` line. Count JA3/JA4 rules by presence of `ja3.hash` / `ja4.hash`.
- `admission_basis == "metadata-filter"` → admit only where **both** hold:
  - `metadata: ... confidence High ...`
  - `metadata: ... signature_severity Major|Critical ...`

  Rules with no `confidence` key are excluded and counted separately from rules with `confidence Low`/`Medium` — the distinction feeds issue #10.
- Commented-out rules (`#alert`) are never admitted.
- Every exclusion increments exactly one counter; `fetched == admitted + sum(excluded)` is asserted.

---

## 7. Ruleset snapshots — `rules/snapshot.py`

```
.flabel/rules/<snapshot_id>/
  manifest.json        SnapshotManifest, plus manifest_version
  rules.rules          concatenated admitted rules, sorted by (source, sid)
  sid_index.json       which source each sid came from
  data/<source>/<file> companion data files the rules read (`dataset:`)
  raw/<source>.rules   as fetched, for audit
```

```python
def write_snapshot(root: Path, admitted: Mapping[str, list[str]],
                   admissions: Sequence[SourceAdmission]) -> SnapshotManifest
def load_snapshot(root: Path, snapshot_id: str | None) -> tuple[Path, SnapshotManifest]
def list_snapshots(root: Path) -> list[SnapshotManifest]
```

- `rules.rules` is written **sorted by (source, sid)** so the id depends on content, not fetch order.
- `load_snapshot(root, None)` returns the most recently created snapshot.
- A missing or unreadable snapshot is a hard failure (`SnapshotError` → exit 1).
- `.flabel/` is gitignored.

**The layout and the id are wider than this section originally said — corrected in steps 4 and 6.**
The original was one hashed file, `rules.rules`, with `snapshot_id = sha256(rules.rules)[:16]`.
Two things measured against the live feeds made that insufficient.

**`sid_index.json` — `{"schema": 1, "sources": {"<source>": [sid, ...]}}`.** §8 resolves the
originating source of each alert from the snapshot, because `eve.json` carries a signature id and
nothing about where the rule came from. Per-source *counts* in the manifest cannot answer "which
source is sid 2011465?", so the mapping has to be stored. It is a file rather than a field on
`SourceAdmission` because step 8 copies that struct into every `labels.json`, and 21,221 integers
per source do not belong in every output file. It is versioned separately from the manifest
because step 6 reads this file and nothing else in the snapshot.

**Companion data files are part of the ruleset, so they are inside the id.** Measured in step 6:
`pawpatrules` ships 18 `.lst` files that 26 of its rules read with `dataset:`. Loaded away from
them, those 26 rules fail; loaded alongside them, 0 fail. Two of those lists — `openphish` and
`nrd_phishing_14day` — refresh daily upstream. A rules-only hash would therefore let two runs
share a `snapshot_id`, match different traffic and produce different labels, which is precisely
the guarantee the id exists to give.

**`snapshot_id` is a sha256 over `rules.rules`, `sid_index.json`, and every file under `data/`, in
sorted path order, with each contribution framed by its path and length:**

```
for path in sorted(components):
    sha256 <- path (utf-8) || 0x00 || len(content) as 8 bytes big-endian || content
snapshot_id = first 16 hex characters
```

The framing is not decoration. Under plain concatenation, renaming `data/pawpatrules/tor.lst` to
`nrd.lst` would leave the id untouched — and a rename changes which rules read which list, so it
changes which rules match. Length framing likewise stops bytes moving across a file boundary
unnoticed. Still self-verifying, now over the whole directory: `load_snapshot` recomputes the id
and refuses a snapshot that no longer hashes to its own name, rather than repairing it, because
labels already emitted name that id as the ruleset that produced them.

**`raw/` is deliberately outside the hash.** It is the as-fetched audit copy, not what the engine
reads: hashing it would change the id — and orphan every label pointing at the old one — whenever
upstream edited a comment header, while changing nothing about which rules match.

**`manifest.json` carries a `manifest_version`.** Reading a manifest hard-fails on any key it does
not recognise, which is the right default when a manifest is the provenance of a label. Without a
version, that means the format could never gain a field without every snapshot already on disk
becoming unreadable garbage rather than "written by an older flabel".

---

## 8. Tool invocation

### Zeek — `zeek.py`

One invocation per run:

```
zeek -C -D -r <normalized.pcap> [ja4] <package-data>/json-logs.zeek
```

- `-C` ignore checksum errors; `-D` deterministic seeds (**mandatory**).
- `json-logs.zeek` adds a JSON `Log::add_filter` for `conn` and `ssl` writing `conn_json.log` / `ssl_json.log`. **One pass produces both formats, so TSV and JSON cannot disagree.**
- TSV logs are the retained artifact in `zeek/`. The `_json` files are parse input and are removed from the retained output.
- Parsed: `conn_json.log` → `Flow`; `ssl_json.log` → `ja4`, `ja4s`, `server_name` joined on `uid`. All other logs retained unparsed.
- Non-zero exit or an OOM kill (which arrives as SIGKILL) → `tool_failures[]` entry; the run fails.

```python
def run_zeek(capture: Path, outdir: Path) -> tuple[dict[str, Flow], ZeekRunInfo]
```

**Five corrections from step 5**, all measured against Zeek 8.0.4.

**A tool failure is recorded *and* raised.** `run_zeek` puts the `ToolFailure` in
`ZeekRunInfo.tool_failures` and raises `ToolError` with that same `ZeekRunInfo` attached as
`run_info`. Recording without raising would let a run continue with no flows; raising without
recording would lose the only description of what failed. Nothing untyped escapes — no `OSError`,
`CalledProcessError` or `JSONDecodeError` reaches a caller. §9's consumer therefore catches
`ToolError` and reads `.failures` and `.run_info` (see PLAN step 9).

**`ja4` is loaded by name, explicitly, and probed first.** This invocation deliberately does not
read `site/local.zeek` — an ambient local config would make the analysis depend on machine-local
state — so nothing else would load the package, and JA4 would be silently absent on every flow.
The probe (`zeek --parse-only -e '@load ja4'`, reading no packets and writing no logs) exists
because `@load ja4` is **fatal** when the package is missing and Zeek has no load-if-present form:
without it, a machine without the package could not run the pipeline at all. The outcome is
recorded in `ja4_status` (§4) with three values, not two: "not installed" is the ordinary laptop
case, while a broken `ZEEKPATH` or a half-finished `zkg` install is a defect, and reporting them
as one hides the second. Either way the run continues — a capture is still worth labelling from
rule matches, and §2.6 says a fingerprint is never a verdict.

**A capture with zero connections writes no `conn.log` at all**, and that is a real result rather
than a failure. Zeek's ASCII writer creates a log on the *first record written to that filter*, so
an ARP/STP-only capture — or a pcap truncated before its first complete record, which this section
accepts as partial input — produces neither `conn.log` nor `conn_json.log`. The retained TSV log is
therefore the discriminator: **both absent means zero connections; `conn.log` present without
`conn_json.log` means the JSON filter genuinely failed** and every flow in the capture would be
lost, which fails the run per §2.5.

**`ZeekRunInfo.flags` records flags and script names only, never the full argv.** The argv contains
the normalized capture's path, which lives in a per-run directory and so differs on every run by
construction: serialising it into `labels.json` would make two otherwise identical runs differ and
break Goal 2, and it would leak host filesystem paths into a shipped artifact. The full argv is
recorded on `ToolFailure.argv`, where it is diagnostic rather than part of the reproducibility
contract.

**`ja4_package_version` is the installed package's version, and it comes from the toolchain
manifest.** `zkg list` is the only local source of that string, and shelling out to `zkg` from a
labelling run risks the network call §2.2 forbids. Step 8 reads the version from
`/etc/flabel-toolchain.json` instead; the Zeek stage reports only `ja4_status`.

### Suricata — `suricata.py`

```
suricata -r <normalized.pcap> -c <package-data>/suricata.yaml \
         -S <snapshot>/rules.rules -l <outdir> \
         --set classification-file=<package-data>/classification.config \
         --set default-rule-path=<snapshot>/data/<source> \
         --set app-layer.protocols.tls.ja3-fingerprints=yes \
         --set app-layer.protocols.tls.ja4-fingerprints=yes \
         --runmode single
```

- `-S` loads **only** the snapshot rules, replacing any system ruleset — no ambient state.
- `--runmode single` for determinism of the alert set.
- Parsed from `eve.json`: records with `event_type == "alert"` → `Detection`, taking `alert.signature_id`, `alert.rev`, `alert.signature`, `alert.metadata`, `app_proto`, `timestamp`, and the 5-tuple.
- The originating source for each SID is resolved from the snapshot's `sid_index.json` (§7), since `eve.json` does not carry it.
- Detections whose source has `may_label == False` are **dropped before correlation** and counted in `identify_alerts_suppressed`.
- Every path handed to the tool is absolute. Measured on 8.0.6: a relative `-S` resolves against the process's working directory, and §12's default `--rules-dir` is relative — so the ordinary case would otherwise depend on where flabel was launched from.

**The invocation gained three things in step 6**, each measured rather than assumed.

**flabel ships its own `suricata.yaml` and passes `-c`.** Without it Suricata reads the operator's
`/etc/suricata/suricata.yaml`, and that file decides `HOME_NET` — hence whether an abuse.ch
`$HOME_NET -> $EXTERNAL_NET` C2 rule can fire at all — the `classtype` description text that lands
in provenance, whether alerts and stats are written to `eve.json` in the first place, and whether
payloads, HTTP bodies and carved files are written into the run directory. flabel processes other
people's captures; none of that may depend on an unreviewed setting on one machine. The config's
sha256 is recorded in the run block, because a run is only reproducible against a *known*
configuration.

**`HOME_NET: any` and `EXTERNAL_NET: any`** (Craig, 2026-08-12). Measured against a real
85,545-rule snapshot: only **3** rules negate `$HOME_NET`, while **1,397** are `$HOME_NET`-anchored.
An RFC 1918 `HOME_NET` would therefore silently kill up to 1,397 rules on any capture whose own
endpoints are publicly addressed — the common case for a capture flabel is handed. `EXTERNAL_NET`
is forced to `any` by that choice: the stock `!$HOME_NET` against a `HOME_NET` of everything
evaluates to the empty set, so every `$HOME_NET -> $EXTERNAL_NET` rule would match nothing, which
is the opposite of the point. The cost is the 3 negating rules (§5), which cannot compile at all.
The trade-off stated plainly: `any -> any` maximises the traffic each rule is tested against, and
removes directionality as a false-positive filter. The benign canary is the standing check on that.

**`--set default-rule-path=<snapshot>/data/<source>` is required for `dataset:` resolution.**
Suricata resolves a rule's `dataset: ... load <file>` against the *rule path*, not against the
config or the `-S` file. Measured: `default-rule-path=<snapshot>` gives 26 rule-load failures;
the per-source data directory gives 0. Two consequences are recorded rather than discovered later:
the setting takes **a single path**, so a second dataset-bearing feed cannot be satisfied at the
same time and admitting one must fail loudly instead of letting half the rules quietly not load;
and the `data/<source>/` layout is **not** flattenable, because `et/open` and `stamus/lateral` both
ship a file called `LICENSE` and a flat directory would have them overwrite each other.

**`Detection.classtype` is read from `classtype:` in the rule text, not from `alert.category`.**
This section originally named `alert.category`, which is not the classtype: it is the *description*
Suricata looks up by name in `classification.config`. So the text a label carried would depend on a
file outside the rule — different wording on two machines for one rule, an empty string for any
classtype that file omits, and, once the file became flabel's own, wording flabel would be
inventing on the feed's behalf. The rule itself says `classtype:trojan-activity`, that text is
inside the hashed snapshot, and it is what the feed actually asserted. A rule with no `classtype:`
yields `None`, which is ordinary: 10,949 of 85,545 admitted rules declare none.

**Tuple normalisation — Suricata's 5-tuple is translated into Zeek's spelling.** §9 correlates by
comparing the two tools' tuples field by field, and they disagree on three things. Every rule here
was measured against real Zeek output, not inferred:

| Disagreement | Normalisation | Why |
| :-- | :-- | :-- |
| Protocol case | lowercase both sides | Zeek writes `tcp`, Suricata writes `TCP`. One side has to normalise or **no** detection would ever match. |
| ICMP ports | mirror `icmp_type`/`icmp_code` into the port columns | Suricata omits ports for ICMP; Zeek writes the ICMP type in `id.orig_p` and a counterpart type in `id.resp_p`. Recording `(0, 0)` would make every ICMP detection unmatchable, and ET Open ships plenty of ICMP rules — 3 such alerts in 150 detections is enough to trip §9's 1% gate and fail a good run, with the run block blaming correlation. |
| `IPv6-ICMP` | maps to `icmp` | Zeek's `transport_proto` holds only tcp/udp/icmp/unknown_transport, so it writes `icmp` for ICMPv6 too. Lowercasing alone would leave `ipv6-icmp` against `icmp`. The IP version is still readable from the addresses, so nothing is lost. |
| IPv6 address form | canonicalise (compressed) | Suricata expands (`fd00:0000:...:00a1`), Zeek compresses (`fd00::a1`). Correlation compares strings, so without this every IPv6 detection is uncorrelatable. |

**Residual, owned by step 7:** for an ICMPv6 echo, Zeek writes the counterpart *type* in
`id.resp_p` (`128, 129`) where mirroring yields `128, 0`. A single alert record does not carry the
counterpart type, so mirroring is exact for ICMPv4 and one field out for ICMPv6 echo. Closing it
needs correlation to treat ICMP specially, not a different value here.

**A partial rule load is a reported loss, not a silent one.** Suricata exits 0 whether it loaded
every rule or none, so `rules_loaded`, `rules_failed` and `rules_skipped` are read from the eve
`stats` record (falling back to `suricata.log`), and a run that cannot obtain those counts at all
fails: an alert set whose ruleset cannot be attested is not evidence. See §11 for the gate.

```python
def run_suricata(capture: Path, snapshot: Path, outdir: Path) -> tuple[list[Detection], SuricataRunInfo]
```

### Ingest — `ingest.py`

```python
def normalize(capture: Path, workdir: Path) -> NormalizedCapture
```

Order of operations:
1. **Sniff by magic bytes**, never by extension: gzip `1f 8b`; pcap `a1b2c3d4`/`d4c3b2a1` (and nanosecond variants); pcapng `0a0d0d0a`.
2. Decompress gzip to a temporary file.
3. **Validate by walking record headers** — flabel's own walk, because no tool in the dependency set reports a truncation offset. Yields `packets_read` and, if the final record is short, `truncated_at_offset`.
4. **Unreadable header** → `CaptureError`, hard failure, no output directory.
5. **Truncated pcap** → proceed; `input_status = "partial"`.
6. **Truncated pcapng** → hard failure telling the operator to repair with `editcap`; a partial pcapng block cannot be converted safely.
7. **pcapng** → `editcap -F pcap`. If it reports multiple link types, determine the dominant type by packet count, split with `editcap`, keep only the dominant, and record `discarded_link_types` and `discarded_packets` with `input_status = "partial"`.
8. Record every transformation in provenance.

---

## 9. Correlation — `correlate.py`

```python
def correlate(detections: Sequence[Detection], flows: Mapping[str, Flow],
              threshold: float = 0.01) -> CorrelationResult
```

Pure. For each detection:

1. Candidate flows are those matching the 5-tuple in either direction.
2. **Zero candidates** → `UnmatchedDetection(reason="no_flow_match")`.
3. **One candidate** → matched.
4. **Multiple candidates** (port reuse within one capture) → select the flow whose `[ts_first, ts_last]` window contains the detection `ts`. If exactly one qualifies, matched; otherwise `UnmatchedDetection(reason="ambiguous_flow_match")`. **A detection is never assigned to a flow by guess.**

Then consolidate: one `Label` per flow, `sources` sorted, `best_tier = min(tier)`.

**Gate:** zero unmatched is silent; any unmatched warns; unmatched / total detections above `threshold` (default `0.01`) fails the run. Phase 2 configures its own, looser threshold rather than relaxing this default.

---

## 10. Canonical output — `labels.py`

Reproducibility depends entirely on this being exact.

- `labels` sorted by `(flow.ts_first, flow.uid)`.
- `sources` within a label sorted by `(tier, source, sid, rev)`.
- `unmatched_detections` sorted by `(ts, source, sid)`.
- `json.dump(..., sort_keys=True, indent=2, ensure_ascii=False)`, trailing newline.
- Timestamps: ISO-8601 UTC with microsecond precision and a `Z` suffix. One format everywhere.
- Floats never emitted where a string is expected; no locale-dependent formatting.

### Reproducibility is over records, after canonicalisation — not bytes

**This section originally claimed byte-identity, excluding `run.started_at`,
`run.finished_at`, `run.duration_seconds` and `zeek/packet_filter.log` "and nothing else". That
claim is wrong and unachievable**, found in step 5 and confirmed in step 6. Every Zeek TSV log
carries `#open` and `#close` wall-clock header lines, so **no** Zeek log is byte-identical across
two runs and a byte comparison would fail on all of them, not just the one named. A filename
exclusion list is also the wrong shape for the problem: it forces a whole log to be dropped over a
single wall-clock line inside it.

So Goal 2 compares **records after canonicalisation**. Canonicalisation drops `#`-prefixed header
lines, which is where Zeek puts every wall-clock value; what remains is the analytic content.

**Excluded from the comparison entirely:**

| Excluded | Why |
| :-- | :-- |
| `run.started_at`, `run.finished_at`, `run.duration_seconds` | Wall-clock by definition. |
| `run.input.path` | The operator's own file path (see below). |
| `zeek/packet_filter.log` | Nothing but a wall-clock start time, and no analytic content to compare. Retained rather than deleted — deleting a log Zeek wrote would misrepresent the run. |
| `suricata/suricata.log` | Wall-clock timestamp *and* pid on every line. Nothing in it is analytic output. |
| `stats` records within `suricata/eve.json` | Wall-clock counters. **Only** the `stats` records: `alert` and `flow` records are byte-stable, and they are exactly what a reproducibility gate should be comparing. Excluding the file wholesale would exclude the alerts. |

**Canonicalised, not excluded: `zeek/reporter.log`.** It is *conditionally* non-reproducible, which
is why the filename list could not express it. A message raised in `zeek_init` carries wall-clock
time even under `-D` (verified); a message raised while reading packets carries **network** time and
is reproducible run to run. Dropping the file wholesale would hide exactly the protocol violations
Goal 3 wants reported, so it is canonicalised like any other log.

### Field definitions, as built

These four were ambiguous enough that step 3 had to decide them; the decisions are recorded here so
a consumer reads the numbers the way they are meant.

- **`packets_read` counts *complete* records in the decompressed input.** An incomplete tail record
  is not counted, and it is **not** in `discarded_packets` either — `truncated_at_offset` is the
  only field that reports it. So `discarded_packets: 0` on a truncated capture is correct, not a
  bug: that counter is for link-type discards.
- **The normalized file holds `packets_read - discarded_packets` packets.** Stated because it is the
  only relation between the three counters, and a reader would otherwise have to guess whether the
  truncated tail is inside `packets_read`.
- **`truncated_at_offset` indexes the *uncompressed* stream.** For a `.pcap.gz` it therefore does
  **not** index the file on disk — the offset is where the record walk stopped, and the walk runs
  after decompression. An operator repairing the capture must decompress first.
- **`sha256` and `bytes` describe the input as it was handed over**, so a `.gz` hashes and measures
  compressed. They identify the operator's artifact, which is what provenance needs; the normalized
  capture is derived and reproducible from it.

**`run.input.path` is the operator's original path** (`NormalizedCapture.original_path`), never the
normalized copy, because the normalized copy lives in a per-run temporary directory that means
nothing to a reader. That makes it **the one input field a reproducibility comparison must exclude
or normalise**: the same capture labelled from two directories would otherwise differ and fail Goal
2, which would be a false alarm about the pipeline.

### Run block

```python
{
  "flabel_version": str, "schema_version": "1.0",
  "started_at": str, "finished_at": str, "duration_seconds": float,
  "mode": "offline",                      # Phase 1 is always this
  "tiers_attempted": [2], "tiers_unavailable": [1],
  "input": {"path": str, "sha256": str, "format": "pcap|pcapng|pcap.gz|pcapng.gz",
            "bytes": int, "input_status": "complete|partial",
            "packets_read": int,
            "truncated_at_offset": int | None,
            "discarded_link_types": [str], "discarded_packets": int,
            "normalization": [str]},
  "ruleset": {"snapshot_id": str, "sources": [...SourceAdmission...],
              "total_admitted": int, "total_ja4_admitted": int},
  "tools": {"zeek": str, "zeek_flags": ["-C", "-D"], "suricata": str,
            "editcap": str, "ja4_zeek_package": str | None,
            "ja4_status": "present|not-installed|probe-failed" | None,
            "suricata_config_sha256": str},
  "counts": {"flows": int, "detections": int, "labels": int,
             "unmatched": int, "unmatched_ratio": float,
             "identify_alerts_suppressed": int,
             "rules_loaded": int, "rules_failed": int, "rules_skipped": int},
  "loss_conditions": {...},               # §11
  "tool_failures": [ ... ],
  "warnings": [str]
}
```

**Five keys were added to the run block in steps 5 and 6**, each because the model field behind it
had nowhere to surface: `tools.ja4_status` and `tools.suricata_config_sha256`, and
`counts.rules_loaded` / `rules_failed` / `rules_skipped`. `tools.ja4_zeek_package` is now nullable —
it holds a real package version read from the toolchain manifest, or nothing, and never a status
string standing in for one (§8).

### `NOTICE` — `notice.py`

Lists every source that asserted at least one label in this run, with its licence and required attribution. Sources present in the snapshot but which asserted nothing are not listed.

---

## 11. Loss conditions

Each has a field and exactly one fault-injection test. This closed list is what Goal 3 is checked against.

| Condition | Field | Fault injection |
| :-- | :-- | :-- |
| Input truncated | `input.input_status`, `packets_read`, `truncated_at_offset` | truncate a fixture mid-record |
| Multi-datalink discard | `input.discarded_link_types`, `discarded_packets` | fixture with two link types |
| Detection uncorrelatable | `counts.unmatched`, `unmatched_detections[]` | detection with a tuple absent from `conn.log` |
| Ambiguous flow match | `unmatched_detections[].reason` | two flows, same tuple, detection outside both windows |
| Tool non-zero exit / OOM | `tool_failures[]` | point at a non-existent binary |
| Snapshot missing | hard failure, exit 1 | `--ruleset-snapshot nonexistent` |
| `identify` alert suppressed | `counts.identify_alerts_suppressed` | rule from an `identify` source that fires |
| Rules failed or skipped at load | `counts.rules_failed`, `counts.rules_skipped` | snapshot containing a rule this engine cannot compile |
| JA4 unavailable | `tools.ja4_status` | run with the `ja4` package absent from `ZEEKPATH` |

**Two rows added in steps 5 and 6.** Both are losses the tools report and then exit 0 over, which
is the shape §2.5 exists to catch.

**Rules failed or skipped at load: record always, warn above zero, fail above a threshold** (Craig,
2026-08-12). Suricata loads what it can and exits 0, so a snapshot of 85,545 rules loading as
85,519 is a run that looks complete and never examined the capture with 26 of its rules. Any
shortfall is worth saying out loud, and a large one means the snapshot and the engine disagree about
what a rule is — but a hard failure on *any* shortfall would fail real runs over a handful of rules
using a keyword this build lacks, which is why the threshold exists. Rules the engine is known in
advance to reject are excluded at admission instead (§5), so the counters describe surprises rather
than known incompatibilities.

**JA4 unavailable: `tools.ja4_status`, so a null `ja4` cannot be mistaken for "no TLS in this
capture".** Those are different facts about a flow, and with no field to hold the difference a
consumer training on the output would read a missing package as an observation.

---

## 12. CLI contract — `cli.py`

```
flabel <capture>                      Phase 1: stub. Prints "Coming Soon (TM)",
                                      names --offline, writes nothing, exit 3.
flabel --offline <capture>            Runs the Tier 2 pipeline.
    --ruleset-snapshot <id>           default: newest available
    --output-dir <dir>                default: cwd
    --rules-dir <dir>                 default: ./.flabel/rules
    --sources <file>                  default: packaged data/sources.toml
    --unmatched-threshold <float>     default: 0.01
flabel rules update [--sources <f>] [--rules-dir <d>]
flabel rules list  [--rules-dir <d>]
```

**Exit codes**

| Code | Meaning |
| :-: | :-- |
| 0 | Success. Labels written. Covers both complete and partial input — `run.input.input_status` distinguishes them. |
| 1 | Failure. No labels written. |
| 2 | Usage error (argparse). |
| 3 | Not implemented — the Phase 1 default path only. |

Partial input is deliberately **not** a distinct code: truncated captures are common, and a non-zero exit would make every ordinary `set -e` script treat a successful run as a failure.

stderr carries progress and warnings; stdout is reserved and currently unused by the pipeline. `errors.py` maps each exception type to exactly one exit code.

---

## 13. Explicit non-behaviours

flabel **must never**:

- assert that a flow is benign, or emit any verdict other than `malicious`;
- emit a label from a fingerprint value alone, without a rule match;
- emit a label attributable to an `identify`-class source;
- assign a detection to a flow by guess when the match is ambiguous;
- perform network I/O outside `flabel rules update`;
- invoke Zeek without `-D`;
- overwrite or modify a previous run directory;
- write a partial `labels.json` on a hard failure — either a complete run directory exists or none does;
- report full coverage when any loss condition fired;
- contact the PANW device (Phase 1 has no Tier 1 code path beyond the stub);
- commit, transmit, or copy capture data anywhere outside the run directory.

---

## 14. Open items carried into build

Not blocking the plan; each has an owner.

| Item | Where |
| :-- | :-- |
| Malicious canary capture must be sourced (origin + licence recorded) | `tests/fixtures/README.md`, PRD Q8 |
| Exact ET Open admitted-rule counts | issue #11, measured by step 4 |
| Untagged-ET-rule policy | issue #10 |
| JA4 rule content | issue #13 |
| Stakeholders, target release, metric review dates | PRD Q1, Q2, Q10 |
