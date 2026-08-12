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
    sources.toml    the source registry (shipped with the package)
    json-logs.zeek  Zeek script adding JSON filters
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
    snapshot_id: str             # sha256(rules.rules)[:16]
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
| `malsilo/win-malware` | MIT | `signature` | wholesale | direct |
| `the-hunters-ledger/open` | CC-BY-4.0 | `signature` | wholesale | direct |
| `pawpatrules` | CC-BY-SA-4.0 | `signature` | wholesale | direct |
| `abuse.ch/feodotracker` | CC0-1.0 | `ioc-dest` | wholesale | direct |
| `sslbl/ssl-fp-blacklist` | CC0-1.0 | `ioc-dest` | wholesale | direct |
| `abuse.ch/urlhaus` | CC0-1.0 | `ioc-name` | wholesale | **indicator-reference** |
| `oisf/trafficid` | MIT | `identify` | wholesale | **never** |

Excluded entirely and absent from the registry: `tgreen/hunting`, `etnetera/aggressive`, `ptresearch/attackdetection`, `ptrules/open`, `sslbl/ja3-fingerprints`, and all commercial sources.

**`abuse.ch/sslbl-c2` was removed in step 2** after verification against the live feed, leaving nine sources. The OISF index marks it `deprecated: Deprecated by source on 2025-01-03`, and the artifact is 335 bytes: a header plus "ATTENTION: This list has been deprecated". It ships zero rules. Shipping it would imply coverage that cannot exist, and its zero count would be indistinguishable from a feed that matched nothing that run.

Validation on load, as originally specified: unknown `source_class` or `admission_basis` is a hard failure; `metadata-filter` is permitted only where ET-style metadata exists.

**The following were added in step 2 as a design decision, not carried over from an earlier draft** — recorded here so the code and this document agree, but they are the implementer's judgment rather than a pre-existing requirement. Reasoning: a registry that loads with a setting silently ignored is worse than one that refuses to load, because it reads as working.

- An unknown or misspelled field, a missing required field, a duplicate name (compared case-insensitively, since step 4 writes `raw/<source>.rules`), an empty registry, a non-boolean `enabled`, and a non-string or empty `name`/`url`/`licence`.
- **A non-HTTPS `url`.** Rules are the trust root of every label: over `http://` they are forgeable in transit, and `file://` would make an arbitrary local file into label evidence.
- **A `name` outside `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$`.** The name becomes a path component in a snapshot (§7), so `--sources` with `name = "../../.ssh/authorized_keys"` would otherwise write fetched rule text outside the snapshot directory.

A `licence` of `"unstated"` remains legal per §4, but no shipped source uses it and a test asserts so.

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
  manifest.json     SnapshotManifest
  rules.rules       concatenated admitted rules, sorted by (source, sid)
  raw/<source>.rules  as fetched, for audit
```

```python
def write_snapshot(root: Path, admitted: Mapping[str, list[str]],
                   admissions: Sequence[SourceAdmission]) -> SnapshotManifest
def load_snapshot(root: Path, snapshot_id: str | None) -> tuple[Path, SnapshotManifest]
def list_snapshots(root: Path) -> list[SnapshotManifest]
```

- `snapshot_id = sha256(rules.rules bytes)[:16]`. Self-verifying: rewriting the file changes the id.
- `rules.rules` is written **sorted by (source, sid)** so the id depends on content, not fetch order.
- `load_snapshot(root, None)` returns the most recently created snapshot.
- A missing or unreadable snapshot is a hard failure (`SnapshotError` → exit 1).
- `.flabel/` is gitignored.

---

## 8. Tool invocation

### Zeek — `zeek.py`

One invocation per run:

```
zeek -C -D -r <normalized.pcap> <package-data>/json-logs.zeek
```

- `-C` ignore checksum errors; `-D` deterministic seeds (**mandatory**).
- `json-logs.zeek` adds a JSON `Log::add_filter` for `conn` and `ssl` writing `conn_json.log` / `ssl_json.log`. **One pass produces both formats, so TSV and JSON cannot disagree.**
- TSV logs are the retained artifact in `zeek/`. The `_json` files are parse input and are removed from the retained output.
- Parsed: `conn_json.log` → `Flow`; `ssl_json.log` → `ja4`, `ja4s`, `server_name` joined on `uid`. All other logs retained unparsed.
- `packet_filter.log` carries a wall-clock stamp, is never reproducible, and is excluded from any reproducibility comparison.
- Non-zero exit or an OOM kill → `tool_failures[]` entry; the run fails.

```python
def run_zeek(capture: Path, outdir: Path) -> tuple[dict[str, Flow], ZeekRunInfo]
```

### Suricata — `suricata.py`

```
suricata -r <normalized.pcap> -S <snapshot>/rules.rules -l <outdir> \
         --set app-layer.protocols.tls.ja3-fingerprints=yes \
         --set app-layer.protocols.tls.ja4-fingerprints=yes \
         --runmode single
```

- `-S` loads **only** the snapshot rules, replacing any system ruleset — no ambient state.
- `--runmode single` for determinism of the alert set.
- Parsed from `eve.json`: records with `event_type == "alert"` → `Detection`, taking `alert.signature_id`, `alert.rev`, `alert.category`, `alert.signature`, `alert.metadata`, `app_proto`, `timestamp`, and the 5-tuple.
- The originating source for each SID is resolved from the snapshot manifest, since `eve.json` does not carry it.
- Detections whose source has `may_label == False` are **dropped before correlation** and counted in `identify_alerts_suppressed`.

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

**Excluded from a reproducibility comparison** — and nothing else: `run.started_at`, `run.finished_at`, `run.duration_seconds`, and `zeek/packet_filter.log`.

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
            "editcap": str, "ja4_zeek_package": str},
  "counts": {"flows": int, "detections": int, "labels": int,
             "unmatched": int, "unmatched_ratio": float,
             "identify_alerts_suppressed": int},
  "loss_conditions": {...},               # §11
  "tool_failures": [ ... ],
  "warnings": [str]
}
```

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
