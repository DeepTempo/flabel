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
| **run directory** | `LABELED_{capture-name}_{datetime}/` — the complete, self-contained output of a run. The prefix marks the producer and is **not** an assertion that labels were written: the name is fixed before the outcome is known, so a failed run leaves a `LABELED_` directory holding `run.json` and no `labels.json` (#23, #134). |
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
2. **`--offline` performs no network I/O, and `flabel rules update` is the only other network path.** A `--offline` labelling run that attempts a network connection is a defect. This is what makes Goal 2 achievable *for that mode*.

   **Amended 2026-08-17 (Craig), when Phase 2 landed.** This clause was written when every mode read files. Tier 1 cannot honour it — the firewall has to be asked what it saw — so the guarantee moved to the mode that can keep it rather than being quietly weakened for all of them. The default path contacts the device through `panw.py`, which is the second and last permitted network module; `tests/test_architecture.py` enforces the closed list. Reproducibility is correspondingly narrower and says so: an `--offline` run is reproducible from its snapshot, while a tier-1 run depends on a device whose content and configuration versions it therefore records on every label.
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
  provenance.py     build SourceEntry values; assemble the run block (pure)
  notice.py         emit NOTICE attribution (pure)
  canonical.py      canonical comparison of run directories — Goal 2's primitive (pure)
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

**Pure modules** (`models`, `errors`, `config`, `admit`, `correlate`, `labels`, `provenance`, `notice`, `canonical`) must not import `subprocess`, `urllib`, or `socket`. Enforced by a test that greps the module sources — a cheap architectural guard that survives refactoring.

---

## 4. Data models

All are frozen dataclasses in `models.py`.

```python
# --- configuration -------------------------------------------------------
SourceClass = Literal["signature", "ioc-dest", "ioc-name", "identify"]
AdmissionBasis = Literal["metadata-filter", "wholesale"]
LabelBasis = Literal["direct", "indicator-reference"]
Direction = Literal["to_server", "to_client", "unknown"]

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
    rules_excluded_marker: int   # excluded by their `msg:` marker (#117)
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
    direction: Direction         # which side of the flow the matching packet was on

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
    direction: Direction

@dataclass(frozen=True)
class LabelEntry:                # one assertion about a flow (schema 2.0, #138)
    name: Literal["verdict", "threat-name"]
    value: str
    tier: int                    # the tier of the source(s) asserting THIS entry
    sids: tuple[int, ...]        # sorted; what is behind the claim

@dataclass(frozen=True)
class Label:
    flow: Flow
    best_tier: int               # min(tier); lower is higher trust
    labels: tuple[LabelEntry, ...]   # sorted by name; exactly one `verdict`
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

**The `Literal` types are enforced at runtime**, not merely annotated: a forged `LabelEntry(name="verdict", value="benign", …)`
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

**`direction` is published on every `SourceEntry`, and no verdict depends on it** (issue #115,
Craig, 2026-08-17). It is the one field here added because of what real captures did rather than
what a tool measurement demanded, so the reasoning is recorded in full.

Measured on twenty-two internet-facing captures: **16,576 rules — 19.5% of the 84,977-rule
snapshot** — are `alert <proto> any any -> <literal address> any`, destination-anchored with an
unconstrained source, concentrated in the highest-signal families in the ruleset (Cobalt Strike,
Conti, Emotet, Log4Shell, Trickbot, Dridex, Ryuk). Every one of them fires on *our RST back* to an
unsolicited inbound packet from a flagged address. The resulting label carried `threat: "Outgoing
connection to an IP seen in Conti Ransomware Leak"` beside a Zeek flow with `conn_state: REJ`,
`history: Sr`, zero bytes each way — one SYN in, one RST out. Forty-six of the corpus's
fifty-four questionable source entries were this, and Suricata had reported `direction:
to_client` on every one of them.

Three properties of the fix, each a decision that could have gone the other way:

| | |
| :-- | :-- |
| **Additive** | No label is dropped, no `label_basis` changes, no gate consults it. The rejected alternative was suppressing a `to_client` match on a destination-anchored rule, which is an inference: a rule that legitimately matches a C2 *response* would be silently lost, and §2.5 says absence is never a signal. Publishing lets a consumer filter on evidence flabel measured rather than on a guess flabel made. |
| **Never null** | An alert Suricata cannot place on one side of a flow — an unsolicited ICMP destination-unreachable is the measured case on 8.0.6 — carries `"unknown"`, in the manner of `licence: "unstated"`. `classtype` stays the sole nullable field on a `SourceEntry`, which two tests assert against this section. |
| **Read from the record, never derived** | `direction` is a top-level key of the eve record, beside `src_ip`, not a member of the `alert` object. Reading it from the wrong nesting level yields `"unknown"` on every alert and is indistinguishable from a tool that stopped reporting it, so the parse is asserted against a real run rather than a hand-written record. |

**The frame of reference is Suricata's flow, not Zeek's.** `to_server` means the matching packet
travelled towards the endpoint *Suricata* treats as the responder, and the `Label` it is published
on names a **Zeek** flow. §9 matches a detection's tuple in either direction precisely because it
does not require the two engines to agree on who initiated a connection; they normally do, and a
midstream pickup or a UDP flow one engine has expired and the other has not are where they need
not. The field is therefore a faithful report of what the engine that raised the alert said —
**not** a derived claim about `Label.flow`'s orientation, which would be a different field.

**`schema_version` moved to `"2.0"` on 2026-08-19 (#138), and everything below explains why it had
not moved before.** That history is kept rather than replaced: the arguments were sound and the
break is what ended them. `labels[]` replaced the top-level `verdict`, so a 1.0 consumer finds no
`verdict` key — it fails rather than reading a document it partly understands. The major digit moved
because the version exists to tell a reader whether they can parse the document, and the answer
changed from yes to no.

**`schema_version` stayed `"1.0"` for everything before that.** An additive Phase 1 field does not bump it, for the same reason
Phase 2's tier-1 entries do not (§4): the version tracks what a consumer must understand to read
the document, and a reader written against 1.0 reads a post-#115 file correctly and simply does not
look at the new key. The cost is real and accepted: two files both stamped `"1.0"` can differ in
whether `direction` is present, so a corpus spanning the change is told apart by the run block's
`flabel_version`, not by the schema version.

**#132 is the first change that is not additive, and it still does not bump it** (Craig,
2026-08-18, after review). Two things moved: `run.mode` gained the values `replay` and `both`, and
`run.ruleset`'s four fields became nullable. Read literally that breaks a 1.0 consumer —
`run["ruleset"]["snapshot_id"][:8]` raises where a string was guaranteed. The reason it is not a
version bump is that **no document a consumer could already have changes shape**:

* The null `ruleset` block occurs only in `replay` mode, which produced no output before this
  change. There is no historical file to re-read and no consumer that can have been reading one.
* `--offline` output is byte-identical but for `tiers_unavailable`, which narrows from `[1]` to
  `[]` — a field whose old value was a Phase 1 constant that had been wrong since tier 1 shipped.
* `--both` output stamps `mode: "both"` where the same pipeline previously stamped `"offline"`.
  A consumer branching on that string does change behaviour — and it was being misinformed
  before, because Phase 2 stamped `"offline"` on every run that replayed past a firewall.

So the consumer this would protect is one relying on a value the document should never have
published. Bumping to signal that costs every consumer of unchanged `--offline` output a rejected
version string, to warn about a field that was previously lying to them. The version tracks what a
reader must understand; a reader must understand `mode` before branching on it, which was true at
1.0 as well. The cost is accepted and recorded here rather than left implicit: `flabel_version` in
the run block is what tells a corpus spanning 2026-08-18 apart.

What this does **not** resolve is whether an inbound scan that our host refused belongs in
malicious-flow ground truth at all. That is a product question about what the labels are training
— "this host is being attacked" against "this host is compromised" — and no field settles it. The
same corpus answered a neighbouring one by measurement (issue #118): a flow that never established
*should* still be able to carry `verdict: malicious`, because every real exploit attempt in the
corpus was a single fire-and-forget UDP packet with `conn_state: S0`, and excluding on
establishment would have deleted the twenty most valuable labels while keeping the noise.

**`ToolError` carries the evidence, not just a message.** Recorded in step 5 and relied on by
step 6: the exception exposes `failures` (the `ToolFailure` records it was raised over) and
`run_info` (the stage's run info, carrying those same records). §8 says a tool failure is
recorded *as well as* raised — an exception carrying only a string would force the caller to
choose between reporting the loss and failing on it.

**A `SourceEntry` is built in exactly one place: `provenance.build_source_entry(detection,
admission, snapshot_id)`.** Pre-placed before steps 7 and 8 were built (#44), because as
written they both claimed the job. Step 7 cannot avoid it — `CorrelationResult.labels` is
`tuple[Label, ...]` and a `Label` cannot be constructed without its `sources` — while PLAN
step 8 assigned the derivation of `label_basis`, `admission_basis` and `licence` to
`labels.py`. Neither could own it alone, and two parallel worktrees deriving `label_basis`
separately is the shape of defect §13's never-dos exist to prevent: two plausible answers, no
way for a consumer to tell which one a label carries.

The function is where the three inputs to provenance meet, and it is the only place they do:
the **detection** for what the engine observed (`tier`, `sid`, `rev`, `classtype`, `threat`),
the **`SourceAdmission`** for the terms the source was admitted on (`admission_basis`,
`licence`, and `label_basis` derived through `models.label_basis` rather than a second copy of
the rule), and the **`snapshot_id`** for which exact ruleset produced it.

**`may_label` and `label_basis` are module-level functions of `source_class` in `models.py`**,
with `SourceSpec`'s properties delegating to them. They were properties only, which meant that
reading either off a `SourceAdmission` — the snapshot's record, and the authority per the
paragraph below — required building a throwaway `SourceSpec` out of it. Two modules did exactly
that, independently. An adapter written twice to reach two properties means the properties are
on the wrong object, so the derivation moved to where both callers can reach it and no caller
constructs an object it does not need. `SourceSpec`'s API is unchanged.

**The terms come from the snapshot manifest, never from the live registry** — which is why the
parameter is a `SourceAdmission` and not a `SourceSpec`. Corrected in review before either step
was built. `SourceAdmission` is what the manifest recorded when the rules were fetched, frozen
alongside the rules that fired; a `SourceSpec` is whatever `data/sources.toml` says today, and
`--sources` lets an operator substitute a different file entirely. Between `flabel rules update`
and a labelling run a licence can be corrected upstream or a `source_class` reconsidered, and
every label from the older snapshot would then carry today's terms over yesterday's rules — every
field present, plausible, and unverifiable. The consequential case is not the licence: moving
`abuse.ch/urlhaus` from `ioc-name` to `ioc-dest` silently turns `indicator-reference` into
`direct` on labels already emitted, which is the difference between "this flow looked up a bad
name" and "this flow is the attack". §8 already resolves a detection's originating source through
the snapshot for the same reason; this is the same authority, not a second one.

It refuses six things rather than emitting an entry that would look complete and be wrong, in
this order:

| Refused | Why |
| :-- | :-- |
| An `admission` that is not a `SourceAdmission` | The type hint is not the guard. `SourceSpec` carries all five attributes read off an admission, so before this check a registry spec passed through and produced a well-formed entry — reinstating the very defect the parameter was changed to prevent. Nothing in the repo checks annotations: CI runs ruff, and there is no mypy or pyright. |
| `admission.name != detection.source` | Would attribute one feed's licence and admission basis to another feed's alert. Checked before the rest, because diagnosing a mis-built mapping as an identify-class suppression bug sends the reader into the wrong module. |
| `may_label == False` | §2.8, a second enforcement after step 6's suppression. This is the last point at which an identify source could acquire a verdict. |
| A `snapshot_id` failing `fullmatch` on `[0-9a-f]{16}` | Not merely non-empty. `--ruleset-snapshot` defaults to `None` meaning "newest available" (§12), so a caller stringifying that default hands over the literal `"None"` — which a non-empty check accepts and which then names a ruleset nobody can look up. `fullmatch` rather than `match`, because `$` also matches before a trailing newline. A non-`str` is rejected first, since `None` itself would otherwise raise `TypeError` and reach the operator as the traceback this guard replaces. |
| A `tier` outside `{1, 2}`, or a `bool` | `tier` ranks label trust and `Label.best_tier` is `min(tier)`. A stray edit setting tier 1 in `suricata.py` would present open-source screening as NGFW verdicts — well-formed, and wrong in the field a consumer weights by. The set is `{1, 2}` rather than `{2}` so Phase 2 stays additive (§2.7). `bool` is excluded explicitly because `True == 1`, and the tier would serialise as `true`. |
| An empty `threat` or `licence` | §8 checks that the `signature` *key* exists, not that it has a value, so a rule emitting `"signature": ""` yields a label that names no threat while passing every other check. §4 provides `"unstated"` for an unknown licence, and it is not the empty string. |

### `labels.json` document

```json
{
  "schema_version": "2.0",
  "run": { "...": "see §9" },
  "labels": [ "...Label..." ],
  "unmatched_detections": [ "...UnmatchedDetection..." ]
}
```

`schema_version` is **`"2.0"`** as of 2026-08-19 (#138). It did not change when Phase 2 added
tier-1 entries to `sources[]` (Goal 6), and it changed now because `labels[]` replaced the
top-level `verdict` field: a 1.0 consumer finds no `verdict` key in a 2.0 document, so it fails
rather than degrading. See §4's schema-version paragraph.

**A `Label` carries several assertions, and each one names what asserts it.** `verdict` is asserted
by every source on the flow and carries all their sids; `threat-name` is asserted by exactly one
detection and carries only that sid. Without per-entry provenance the document would imply that
`sources[]` accounts for all of them, which it does not once a label is narrower than the whole
list (Goal 1, §13).

**`threat-name` appears only when a tier-1 source is present, and is omitted otherwise** — not
null. §2.5's distinction: the fact is not applicable to a Suricata-only flow, rather than measured
and absent. Extending it to tier 2 is therefore purely additive.

**Which tier-1 detection supplies it is decided by `(unestablished, ts, sid)`** (Craig,
2026-08-19): lowest tier first, then the earliest detection, with `sid` breaking timestamp ties and
a detection whose timestamp could not be established sorted last.

**`sid` is what makes this stable, not `ts`** — an earlier draft of this section claimed the
opposite and was wrong (#140). PAN-OS writes `receive_time` to the **second**
(`%Y/%m/%d %H:%M:%S`, no sub-second field) off the device's wall clock, and a whole capture replays
in seconds, so two threats on one flow routinely share a timestamp: the tie-break is the common
path rather than the edge case. What the comparator guarantees is that it is *total* — given the
same alerts, the same threat name is chosen — not that the timestamps are precise. Nothing in
flabel can make them so; PAN-OS supplies seconds.

The leading key exists because `panw._receive_epoch` yields `0.0` for an unparseable
`receive_time`, and `0.0` is the minimum of every real epoch — so a parse failure would otherwise
outrank every genuine alert and name the flow. Sorted last, it supplies the label only when it is
the only candidate.

**A device entry PAN-OS sent no threat name for supplies no `threat-name` at all.** `panw`
substitutes a placeholder so `SourceEntry.threat` is never empty (§4 forbids that), and promoting it
would assert that the threat is *called* "unnamed". The placeholder stays in `sources[]`, which is
the record of what arrived; the label is omitted, which is this section's own rule for a fact that
is not available.

Note that tier precedence rarely decides anything: `threat-name` is tier-1 only, so on a
replay-only run every source is tier 1 and the rest of the comparator *is* the rule.

When both tiers flag a flow, **tier 2's threat name does not become a label**. It remains in
`sources[].threat` with its full provenance; what it loses is promotion. Recorded as a deliberate
trade for one trainable value per flow rather than a set a consumer must reduce.

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
- **A rule whose `classtype:` the registry's `[admission]` table excludes is never admitted**, counted in `rules_excluded_classtype`.
- **A rule whose leading `msg:` marker the registry excludes is never admitted** (issue #117), counted in `rules_excluded_marker`. Tested *after* the classtype, so a rule that is both keeps the earlier bucket and "excluded by classtype" does not understate what that policy removes.
- Every exclusion increments exactly one counter; `fetched == admitted + sum(excluded)` is asserted.

### Per-rule admission — `[admission]` (issue #75)

`source_class` classifies a **feed**. This classifies individual **rules**, and the two are not
substitutes: `pawpatrules` is one source carrying both direct detections and policy observations,
so no per-source setting can separate them.

```toml
[admission]
exclude_classtypes = ["policy-violation"]
```

**Measured 2026-08-13.** 23 captures of ordinary protocol traffic (Suricata's own
protocol-conformance corpus) against the full nine-feed snapshot produced **100 malicious labels
across 12 captures, 138 source entries, every one from `pawpatrules`**. Excluding the single
classtype `policy-violation` — **436 rules, 0.51% of the ruleset** — removes **84.8%** of them:

| | before | after |
| :-- | --: | --: |
| captures producing labels | 12 | 8 |
| labels | 100 | 12 |
| source entries | 138 | 21 |

Those rules are not wrong about what they observe — TLS 1.0 really is in use, the FTP password
really is in clear text. The defect is promoting an observation to `"verdict": "malicious"` with
`label_basis: direct`, which asserts the flow *is* the attack. The output is training data, so a
model learns that curl and TLS 1.0 are malicious.

**In the registry rather than on the CLI**, because §12's contract is closed and `--sources`
already exists as the override — and because it puts the policy inside admission, so it is inside
`snapshot_id`. The rules a label cites are exactly the rules the policy admitted.

**A rule declaring no `classtype:` is never excluded by this policy.** 10,949 of 85,431 admitted
rules declare none, so treating absence as a match would drop 12.8% of the ruleset on a setting
that never named it.

**What this does not fix**, both confirmed by what survives the filter: one structurally broken
rule (sid 3317444, whose destination is literally `127.0.0.1`), and the directionality loss from
`HOME_NET: any` (issue #77). Different causes, different fixes.

### Measured yield — 2026-08-12 (closes issue #11)

Reproduced offline from a saved mirror of the nine live feeds, so these are repeatable without
network access: `tests/fixtures/rules/measure_feeds.py --mirror <dir>`.

| Source | Basis | Fetched | Admitted | % | no-conf | low-conf | low-sev | unloadable |
| :-- | :-- | --: | --: | --: | --: | --: | --: | --: |
| `abuse.ch/feodotracker` | wholesale | 5 | 5 | 100.0% | | | | |
| `abuse.ch/sslbl-blacklist` | wholesale | 10,369 | 10,369 | 100.0% | | | | |
| `abuse.ch/urlhaus` | wholesale | 31,682 | 31,682 | 100.0% | | | | |
| `et/open` | metadata-filter | 51,778 | 21,221 | **41.0%** | 5,836 | 11,425 | 13,296 | |
| `malsilo/win-malware` | wholesale | 14 | 14 | 100.0% | | | | |
| `oisf/trafficid` | wholesale | 34 | 34 | 100.0% | | | | |
| `pawpatrules` | wholesale | 21,467 | 21,464 | 100.0% | | | | 3 |
| `stamus/lateral` | wholesale | 546 | 546 | 100.0% | | | | |
| `the-hunters-ledger/open` | wholesale | 96 | 96 | 100.0% | | | | |
| **Total** | | **115,991** | **85,431** | **73.7%** | 5,836 | 11,425 | 13,296 | 3 |

The `fetched == admitted + sum(excluded)` identity holds for every source. `rules_fetched` counts
active `alert` lines only; the 19,495 `#alert` lines (19,479 of them ET Open's) are counted in
`rules_excluded_commented`.

**This table predates `exclude_classtypes`, which now ships in the registry.** Re-measured
2026-08-13 from the same mirror with the policy in force: **84,995 admitted of 115,991 (73.3%)**
— 436 fewer, exactly the `policy-violation` count above. The drop falls on `pawpatrules`
(21,464 → 21,052), `et/open` (21,221 → 21,202) and `the-hunters-ledger/open` (96 → 91). The
2026-08-12 figures are kept as the issue #11 closure record; **84,995 is what a snapshot built
today contains.**

**41.0% is not the coverage figure, and reading it as one would be the wrong conclusion.** The
metadata filter applies to exactly one source. ET Open is 24.8% of admitted volume, so Tier 2
coverage is **85,431 rules across nine sources, 73.7% of everything fetched** — the per-source
policy working as designed rather than a filter discarding most of the ruleset.

**What this gives issue #10.** ET Open's exclusions split 5,836 with no `confidence` key, 11,425
`confidence` too low, 13,296 severity too low. So untagged rules are 11.3% of ET Open's active
rules and 19.4% of what the filter drops; admitting them would move ET Open from 41.0% to 52.3%
yield with no per-rule evidence behind any of them. That is the trade #10 has to decide, now with a
denominator.

**Zero `ja4.hash` rules exist across all nine feeds** (199 `ja3.hash`: 193 `pawpatrules`, 5
`et/open`, 1 `the-hunters-ledger/open`), confirming issue #13 — the capability ships, the content
does not exist upstream.

**These counts describe one mirror, not a constant.** `abuse.ch/urlhaus` and two of `pawpatrules`'
companion lists (`openphish`, `nrd_phishing_14day`) refresh upstream daily, which is why companion
data is inside the `snapshot_id` hash (§7). A later fetch is a different measurement.

### Per-rule admission by marker — `exclude_msg_markers` (issue #117)

The sibling of `exclude_classtypes`, and it exists because the classtype could not reach the rules
it needed to. `pawpatrules` writes an emoji at the front of every `msg:` saying what kind of rule it
is — a siren for a detection, an eye or a lock or a globe for an observation — and it is the **only
field that says so**. Measured: 571 rules carry one of the five observational markers, 126 of them
the info-marked rules `exclude_classtypes` already removes, and **0 of the remaining 445 carry
`misc-activity`**. They declare `bad-unknown` and `attempted-recon`, which elsewhere in the ruleset
carry genuine detections, so no classtype policy can separate them.

What that cost, before this: 17 source entries across the 22-capture corpus labelling `go.dev` — the
official Go website, on a Google-operated gTLD — as `verdict: malicious`, `label_basis: direct`. One
of the four rules ends its own `msg:` with the word *"observed"*.

```toml
[[source]]
name = "pawpatrules"
exclude_msg_markers = ["ℹ", "👁", "🔒", "🌐", "🤨"]
```

**The marker is positional and is never a substring search.** The same emoji appear inside rule
prose — *"Google Chrome 🌐 for Windows 7 unsupported and vulnerable"* is a detection. Matching
anywhere in the `msg:` hits **8,125** rules where the anchored parse hits **571**, and of the 7,554
difference 3,997 are siren-marked detections and 3,315 skull-marked ones. An unanchored policy would
have cut a third of the feed's real signatures while reading, in the registry, as a five-marker
rule.

`marker_of` therefore skips the feed's brand prefix — every rule begins with a paw print and a dash,
so the first pictograph discriminates nothing — and returns the first marker after it. The first of
several adjacent markers wins: 34 rules are marked fire-then-eye and are FireEye BEACON backdoor
signatures, which taking any marker in the run would have excluded.

**Cost, measured by running the shipped policy over the 21,467-rule feed:** `rules_excluded_marker`
is **445** — 571 rules carry one of the five markers, and 126 of those are the `ℹ` rules
`exclude_classtypes` already removes, classtype being tested first. Reproduce it offline with
`uv run python tests/fixtures/rules/measure_feeds.py --mirror <mirror>`, whose table now carries a
column for each of the two policies.

**A convention is not an interface, so it is watched rather than trusted.** The feed publishes no
schema for these markers and could change them without notice; the failure that would follow is the
quiet one, where the policy stays in the registry reading as if in force while excluding nothing —
issue #75 returning through the mechanism built to prevent it. `tests/integration/marker_gate.py`
runs in the scheduled feeds workflow and fails the build when the policy stops excluding anything,
when it starts excluding an order of magnitude more, or when a marker nobody has classified appears
on an admitted rule. It found a real parser defect on its first run against the live feed: twelve
phishing rules write the brand prefix without a space after the dash, and the first version of the
parse reported the paw print itself as their marker.

**What this deliberately does not do.** It removes 17 of 338 corpus source entries. It does not
touch the 207 entries from two siren-marked VxWorks scanning rules, or the 46 that #115's `direction`
field now makes filterable — no marker policy reaches those, because the feed classifies them as
detections and, as observations of inbound scanning, they are not wrong. Whether an inbound scan a
host refused belongs in malicious-flow ground truth is a product question about what the labels
train, and no admission policy settles it (§11's note on issue #118).

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

def load_sid_index(directory: Path) -> dict[int, str]
def load_address_indicators(directory: Path) -> frozenset[int] | None
```

The two readers are as much a part of this section's contract as the writers: §8 resolves an
alert's source through the first, and a label's `label_basis` will be refined by the second.
`load_address_indicators` returns **`None` when the snapshot recorded no classification** —
distinct from an empty set, which records that no rule is an address indicator. Conflating them
would label every rule `direct` and say nothing (§2.5).

- `rules.rules` is written **sorted by (source, sid)** so the id depends on content, not fetch order.
- `load_snapshot(root, None)` returns the most recently created snapshot.
- A missing or unreadable snapshot is a hard failure (`SnapshotError` → exit 1).
- `.flabel/` is gitignored.

**The layout and the id are wider than this section originally said — corrected in steps 4 and 6.**
The original was one hashed file, `rules.rules`, with `snapshot_id = sha256(rules.rules)[:16]`.
Two things measured against the live feeds made that insufficient.

**`sid_index.json` — `{"schema": 3, "sources": {"<source>": [sid, ...]}, "address_indicator": [sid, ...]}`.** §8 resolves the
originating source of each alert from the snapshot, because `eve.json` carries a signature id and
nothing about where the rule came from. Per-source *counts* in the manifest cannot answer "which
source is sid 2011465?", so the mapping has to be stored. It is a file rather than a field on
`SourceAdmission` because step 8 copies that struct into every `labels.json`, and 21,221 integers
per source do not belong in every output file. It is versioned separately from the manifest
because step 6 reads this file and nothing else in the snapshot.

**`address_indicator` records which rules fire on the header tuple alone** (issue #75, schema 3) — protocol, addresses and ports, inspecting no payload. **Wider than the field name says, and measured rather than assumed** (issue #93): of 16,075 such rules in the live snapshot, 16,074 name a literal address and exactly one is port-only (sid 3500023, `alert udp $HOME_NET any -> any 14433:14444`). The name was kept because renaming it costs a `sid_index.json` schema bump — invalidating every existing snapshot — for one rule in sixteen thousand. The port-only rule is classified correctly for the same reason the others are: it establishes that a flow reached a known-bad *port*, not that the flow *is* the malicious activity.
Such a rule establishes that a flow *reached a known-bad address*, not that the flow *is* the
malicious activity — the distinction `label_basis` already names. Re-measured 2026-08-13 against
a snapshot built with `exclude_classtypes` in force: **16,075 of 84,995 admitted rules (18.9%)**,
of which **99.9% name a literal IP as their destination**, and they sit almost entirely in
`pawpatrules` (16,061) — a feed that declares itself `signature`, which is why the feed-level
answer alone cannot find them. (Before the policy shipped: 16,079 of 85,431, 16,064 in
`pawpatrules`. Four address indicators declared `policy-violation` and are now excluded.)

**The two classifications compose rather than compete.** `source_class` covers name and URL
indicators at the feed level; this covers address indicators buried inside a signature feed.
`abuse.ch/urlhaus` is the canonical `ioc-name` source and scores **0%** here, because a
domain-name indicator is matched in payload content — so a rule is an indicator if *either*
answer says so.

**Computed by an allowlist of non-detecting options**, not a blocklist of payload keywords. The
first cut was a blocklist — `content`, `pcre`, `ja3.hash`, `ja4.hash`, `dataset` — and it was
wrong by 588 rules: `stamus/lateral` detects RPC calls with `dcerpc.iface`/`dcerpc.opnum` and
`pawpatrules` reads certificate state with `tls_cert_expired`, and neither uses `content`.
Everything that inspects cannot be enumerated; the handful of options that do not inspect can be.

It lives here, **inside the hash**, rather than in `manifest.json`, and that placement is
load-bearing. Exclusion changes `rules.rules`, so `snapshot_id` moves with it. Re-labelling
changes no rules at all — recorded in the manifest it would sit outside the id (issue #48), and
two snapshots sharing an id could then produce labels with different bases, which is exactly the
guarantee the id exists to give.

**Schemas 1 and 2 read as "no classification recorded".** For 1 that is literally true; for 2 it
is a judgement — the data is there but was computed by the blocklist since measured wrong, and
reading it would put a known-bad answer behind a label's basis. Both stay readable for sid→source
attribution, so no label already traced to such a snapshot is stranded. The remedy is a re-run of
`flabel rules update`, not a fallback.

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

**`snapshot_id` is a function of flabel's code as well as of the feeds.** The id is a hash over
the directory's contents, and `sid_index.json` is one of them — so the same nine feeds fetched at
the same instant produce **different ids under different flabel versions** whenever the index
format or the classification changes. It has happened twice already (schema 1 → 2 → 3).

This does not weaken Goal 2, and it is worth being exact about why. Reproducibility is defined
over *a retained snapshot directory*: two runs against the same snapshot produce the same labels,
and that is what a label citing an id needs. It is **re-derivation from the feeds** that is not
promised — and never was, since `abuse.ch/urlhaus` and two pawpatrules companion lists refresh
upstream daily (§6). Stated because "content-addressed" invites the stronger reading.

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
- Parsed from `eve.json`: records with `event_type == "alert"` → `Detection`, taking `alert.signature_id`, `alert.rev`, `alert.signature`, `alert.metadata`, `app_proto`, `timestamp`, `direction`, and the 5-tuple.
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

**Zero readable packets never reaches Suricata** — refused during ingest, §8 step 9 (issue #85). Zeek handles such a capture happily; Suricata cannot read it and burns its 60-second thread-start budget first.

**Tuple normalisation — Suricata's 5-tuple is translated into Zeek's spelling.** §9 correlates by
comparing the two tools' tuples field by field, and they disagree on four things. Every rule here
was measured against real Zeek output, not inferred:

| Disagreement | Normalisation | Why |
| :-- | :-- | :-- |
| Protocol case | lowercase both sides | Zeek writes `tcp`, Suricata writes `TCP`. One side has to normalise or **no** detection would ever match. |
| ICMP ports | mirror `icmp_type`/`icmp_code` into the port columns | Suricata omits ports for ICMP; Zeek writes the ICMP type in `id.orig_p` and, in `id.resp_p`, either a counterpart type or — for most types — the code (see the residual below). Recording `(0, 0)` would make every ICMP detection unmatchable, and ET Open ships plenty of ICMP rules — 3 such alerts in 150 detections is enough to trip §9's 1% gate and fail a good run, with the run block blaming correlation. |
| `IPv6-ICMP` | maps to `icmp` | Zeek's `transport_proto` holds only tcp/udp/icmp/unknown_transport, so it writes `icmp` for ICMPv6 too. Lowercasing alone would leave `ipv6-icmp` against `icmp`. The IP version is still readable from the addresses, so nothing is lost. |
| IPv6 address form | canonicalise (compressed) | Suricata expands (`fd00:0000:...:00a1`), Zeek compresses (`fd00::a1`). Correlation compares strings, so without this every IPv6 detection is uncorrelatable. |
| Anything not TCP/UDP/ICMP | **none — not normalisable** | Zeek writes `unknown_transport` and zeroes both port columns; Suricata reports the real protocol, and for SCTP the real ports. There is no spelling that makes these tuples equal, so §9 step 0 reports the detection as `unsupported_transport` instead of translating it (issue #84). |

**Residual, owned by step 7 — and wider than this section first said.** A single alert record
carries only its own packet's type and code, so mirroring produces `(type, code)`. Zeek writes the
type in `id.orig_p` and, in `id.resp_p`, either the type it *pairs* that type with or, for every
other type, the code. Mirroring is therefore exact only where a type's counterpart happens to equal
its code, and one field out everywhere else. Closing it needs correlation to treat ICMP specially —
matching on the type column and accepting either the code or the counterpart in the responder
column — not a different value in `suricata.py`.

**Measured on Zeek 8.0.4, exhaustively** — every ICMPv4 type 0–45 and every ICMPv6 type 0–160,
one packet each at `code 7` so a code can never be mistaken for a counterpart, reading `id.resp_p`
back from `conn.log`. The sweep is `test_the_icmp_tables_are_what_zeek_actually_writes`, a
`requires_tools` test, so this table is re-measured against the pinned Zeek on every CI run rather
than being a fact recorded once and trusted thereafter:

| Family | Types Zeek pairs | Every other type |
| :-- | :-- | :-- |
| ICMPv4 | `0↔8`, `9↔10`, `13↔14`, `15↔16`, `17↔18` | writes the code |
| ICMPv6 | `128↔129`, `130↔131`, `133↔134`, `135↔136`, `139↔140`, `144↔145` | writes the code |

This section previously said mirroring is *"exact for ICMPv4 and one field out for ICMPv6 echo"*.
Both halves were wrong, and each would have left detections silently uncorrelatable:

- **ICMPv4 is exact for the echo *request* only** — type 8 pairs with 0, which is also its code, so
  the family looked exact because of a coincidence in the one case anybody checks by hand. An alert
  on the echo *reply* yields `(0, 0)` against a flow whose responder column holds `8`. Timestamp,
  information and address-mask exchanges are out by the same field.
- **ICMPv6 is not only echo.** Neighbour discovery (`135↔136`) pairs identically and appears on
  essentially every real IPv6 capture, where echo may not. Handling echo alone would have looked
  like the residual was closed while leaving the ordinary case broken.

The family is selected by the address, not the protocol: Zeek's `transport_proto` writes `icmp` for
both, so the protocol field cannot distinguish them.

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
5. **Truncated pcap** → proceed; `input_status = "partial"` — *provided at least one whole record survives*. See step 9.
6. **Truncated pcapng** → hard failure telling the operator to repair with `editcap`; a partial pcapng block cannot be converted safely.
7. **pcapng** → `editcap -F pcap`. If it reports multiple link types, determine the dominant type by packet count, split with `editcap`, keep only the dominant, and record `discarded_link_types` and `discarded_packets` with `input_status = "partial"`.
8. Record every transformation in provenance.
9. **Zero usable packets** → `CaptureError`, hard failure, no output directory (issue #85). A valid-but-empty pcap, a pcapng carrying only SHB+IDB, and a pcap truncated before its first complete record all reach this state, and none of them is labellable: `input_status: partial` on a file with nothing in it asserts a coverage figure over an empty set. **Amends §12's exit-0 promise**, deliberately — exit 0 covers partial *data*, not zero data.

   The check runs after conversion rather than at the walk, so `editcap` may already have been invoked; it is Zeek and Suricata it precedes, which is where the cost was. Measured before it existed: **63.1 s** to fail, because Suricata cannot read such a file and spends its full 60-second thread-start budget first, then blames a thread that failed to start.

---

## 9. Correlation — `correlate.py`

```python
def correlate(detections: Sequence[Detection], flows: Mapping[str, Flow],
              manifest: SnapshotManifest,
              threshold: float = 0.01,
              address_indicators: frozenset[int] | None = None) -> CorrelationResult
```

**`address_indicators` was added in step 11c** (issue #75): the sids whose rules fire on the header tuple alone, read from the snapshot's `sid_index.json`. A `SourceEntry` is `indicator-reference` if **either** the source's class says so **or** the rule is one of these — the two compose, and neither half is redundant. `abuse.ch/urlhaus` is the canonical `ioc-name` source and scores 0% on the per-rule test because a domain indicator is matched in payload content, while `pawpatrules` declares itself `signature` and holds 16,061 of them.

**`None` means the snapshot recorded no classification**, which is a different fact from `frozenset()` — "it recorded that no rule is an indicator". Absence takes the *weaker* claim: every basis becomes `indicator-reference` and `warnings[]` says so once for the run, naming the snapshot to rebuild. Reading `None` as "not an indicator" would publish `direct` for ~16,000 rules and say nothing, which is §2.5's failure mode in the field the whole file exists to get right.

**`manifest` was added to this signature in #44.** The original three arguments cannot produce
the declared return type: `CorrelationResult.labels` is `tuple[Label, ...]`, a `Label` requires
`SourceEntry` values, and a `SourceEntry` needs four fields a `Detection` does not carry —
`ruleset`, `admission_basis`, `licence`, `label_basis`. Correlation does not derive any of them
itself; it passes each matched detection to `provenance.build_source_entry` (§4) with the
`SourceAdmission` for that detection's source.

**It is the whole manifest rather than a mapping plus an id**, because those two arguments can
disagree and this one cannot: the manifest carries `sources` and `snapshot_id` together, already
validated by `load_snapshot`, so there is no way to pass one snapshot's admissions with another
snapshot's id. It also settles where the terms come from — the loaded snapshot, never
`config.load_sources()` or `config.enabled_sources()`. Those describe the registry *now*;
`enabled` in particular has no bearing on a run against an existing snapshot, since a snapshot is
a record of what *was* admitted, and letting a later `enabled = false` change the reading of an
old snapshot would make labels retroactively unattributable.

**`manifest.sources` is a `tuple`, not a mapping.** Correlation indexes it once, by
`SourceAdmission.name`, and the wording above should not be read as a dict lookup. Stated
because `suricata.py` already writes the same line and a step built in an isolated worktree
would otherwise write a third copy of it.

**A detection whose source is absent from `manifest.sources` is a hard failure** —
`SnapshotError`, matching §8's handling of a SID that belongs to no source in the snapshot. It
should be impossible: `-S` loads only snapshot rules, and §8 already resolves every alert's source
through `sid_index.json` before a `Detection` exists. Failing rather than dropping is the same
reasoning as there — the alternative is emitting a label with an invented origin.

**An `identify`-class detection reaching correlation is a hard failure, not a filter.**
Correlation does not drop it and does not count it: §8 already suppresses those before a
`Detection` exists and counts them in `identify_alerts_suppressed`, so one arriving here means
that suppression was bypassed, and continuing would paper over a mis-wired pipeline.
`build_source_entry` raises, and step 7's test asserts the raise rather than an empty `labels`.
Stated because "never becomes a label" is satisfied equally by raising and by silently
filtering, and those differ in exit code, in whether output exists at all, and in what step 10's
canary observes.

**The manifest handed to `correlate` must be the one Suricata used.** Its `snapshot_id` has to
equal `SuricataRunInfo.snapshot_id`, and §12's orchestration asserts it. `run_suricata` loads a
manifest and returns only the id, so the caller loads the snapshot a second time — and with
`--ruleset-snapshot` defaulting to "newest available", a `rules update` landing between the two
loads would resolve a *different* snapshot. Every label would then cite a ruleset whose rules
never ran, with the same terms-versus-rules mismatch this section exists to prevent, moved one
function to the left. Correlation's own job remains attaching detections to flows.

Pure. For each detection:

0. **The protocol is one Zeek can name** — `tcp`, `udp` or `icmp`, compared case-insensitively — or the detection is `UnmatchedDetection(reason="unsupported_transport")` and no candidate is looked up. Zeek's `transport_proto` has no other values and it zeroes the port columns for anything else, so there is no tuple to compare; ESP and SCTP arrive here in full; for GRE only the alerts Suricata attributes to the tunnel do, since Zeek decapsulates it and the inner TCP conversation correlates normally. **Two such conversations between one host pair are written with identical 5-tuples** (`10.0.0.5 0 10.0.0.200 0 unknown_transport`, measured with different `uid`s), which is why this reports rather than falling through to a lookup that could only guess between them. Zeek *does* record the difference, in `conn.log`'s `ip_proto` column — 50 for ESP, 132 for SCTP — but `Flow` does not carry it, so the limit is flabel's rather than Zeek's and correlating these properly is issue #96. Excluded from the gate's denominator — see §10's note on `unmatched_ratio`. The case-insensitivity is confined to *this* test: an un-normalised `TCP` is a step 6 regression, not an unsupported transport, and must stay inside the gate as `no_flow_match`.
1. Candidate flows are those matching the 5-tuple in either direction.
2. **Zero candidates** → `UnmatchedDetection(reason="no_flow_match")`.
3. **One candidate** → matched.
4. **Multiple candidates** (port reuse within one capture) → select the flow whose `[ts_first, ts_last]` window contains the detection `ts`. If exactly one qualifies, matched; otherwise `UnmatchedDetection(reason="ambiguous_flow_match")`. **A detection is never assigned to a flow by guess.**

Then consolidate: one `Label` per flow, `sources` sorted, `best_tier = min(tier)`.

**Gate:** zero unmatched is silent; any unmatched warns; **correlatable** unmatched over **correlatable** detections above `threshold` (default `0.01`) fails the run. Phase 2 configures its own, looser threshold rather than relaxing this default.

Correlatable excludes the step 0 detections, on both sides of the ratio (issue #84) — they were never going to be placed, so counting them would fail a run on ordinary IPsec traffic, and counting enough of them would drag a genuine tuple-normalisation defect below the threshold. An **empty** protocol is deliberately *not* excluded: that is a parse failure rather than a protocol Zeek cannot name, and nothing licenses tolerating a loss that was never measured. §10 publishes the ratio and the excluded count separately.

`CorrelationResult` carries `warnings` like every sibling stage's run info, and the gate's own message is one of them (issue #57) — stderr is not kept, so a loss that appeared only on a terminal is a loss `run.json` does not record. On the raising path the warning is on the result the exception carries, so the failed run's `run.json` says what stderr said.

**Failing raises `CorrelationError`, carrying the `CorrelationResult`.** The gate fires *because*
detections went unplaced, so the `UnmatchedDetection` records — each with the reason it could not
be matched — are the whole content of the failure, and a bare message would discard them at the
moment they became the point. §11 requires them reported, and §10's `run.json` is where they go on
a failed run. Same convention as `ToolError` carrying `failures` and `run_info` (§4), so a caller
writes one shape of `except` clause across the pipeline rather than one per stage.

---

## 10. Canonical output — `labels.py`

Reproducibility depends entirely on this being exact.

- `labels` sorted by `(flow.ts_first, flow.uid)`.
- `sources` within a label sorted by `(tier, source, sid, rev, direction)`. `direction` joined the key with the field (issue #115): one rule matching both halves of a flow used to yield two identical entries, so the tie was unobservable, and eve.json's record order is not *guaranteed* stable between runs — the instability measured below is in `flow` records rather than `alert` records, so this closes a latent tie rather than an observed failure.
- `labels` within a label — the assertions themselves — sorted by `name` (#138). Alphabetical
  rather than a hand-ordered precedence, for the reason every other collection here is sorted
  mechanically: a curated order is a second thing to keep in step as names are added. It puts
  `threat-name` before `verdict`, which reads oddly and is the price of the rule.
- `unmatched_detections` sorted by `(ts, source, sid)`.
- `json.dump(..., sort_keys=True, indent=2, ensure_ascii=False)`, trailing newline.
- Timestamps: ISO-8601 UTC with microsecond precision and a `Z` suffix. One format everywhere.
- Floats never emitted where a string is expected; no locale-dependent formatting.

**"One format everywhere" governs every timestamp in the document, not only the run block's**
(Craig, 2026-08-12). So `Flow.ts_first` / `ts_last` and `Detection.ts` — which Zeek and Suricata
both produce as epoch floats — serialise as ISO-8601 strings like every other timestamp. Ratified
here because the sentence sat in a section about the run block and could be read as scoped to it,
and the two readings produce different data for every consumer that joins on time.

Zeek writes microsecond precision, so nothing is lost at the resolution the tools actually report.
A consumer wanting epoch converts on read, against a fixed documented format. The rejected
alternative was epoch floats for flow and detection times with ISO for wall-clock fields, which is
two formats in one document — exactly what this line exists to prevent — and the rejected
compromise was emitting both, which is two fields that must agree.

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
| `run.started_at`, `run.finished_at`, `run.duration_seconds` | Wall-clock by definition. `duration_seconds` is `null` when the clock stepped backwards mid-run, with a warning naming both timestamps (issue #62) — an NTP correction or a VM resume must not cost the report. |
| `run.input.path` | The operator's own file path (see below). |
| `zeek/packet_filter.log` | Nothing but a wall-clock start time, and no analytic content to compare. Retained rather than deleted — deleting a log Zeek wrote would misrepresent the run. |
| `suricata/suricata.log` | Wall-clock timestamp *and* pid on every line. Nothing in it is analytic output. |
| `stats` records within `suricata/eve.json` | Wall-clock counters. **Only** the `stats` records — excluding the file wholesale would exclude the alerts, which are exactly what a reproducibility gate should be comparing. |
| `flow_id` on every `suricata/eve.json` record | Suricata's internal per-run key joining an alert to its flow record. flabel never reads it (§9 correlates by 5-tuple and time). |
| `flow.reason` on `suricata/eve.json` flow records | Whether the flow manager timed a flow out before end-of-pcap or flushed it at shutdown — a race against wall-clock. |

**Three corrections measured in step 10, when the gate was first built and run.** This section
claimed `alert` and `flow` records are byte-stable and defined canonicalisation as dropping
`#`-prefixed header lines. Both were too strong, and Goal 2 failed on all three before they were
found. Each is now a rule in `flabel.canonical` with its measurement in the docstring.

| Corrected | Measured | Why it is not analytic content |
| :-- | :-- | :-- |
| `reporter.log`'s `ts` column | two runs 1.4s apart wrote `1786644711.886324` and `1786644713.298930` for the same `zeek_init` message | A message raised in `zeek_init` carries **wall-clock** time even under `-D`; one raised while reading packets carries **network** time and is stable. The two are interleaved and indistinguishable from content, so the column goes and level, message and location stay. |
| `flow_id` | the same alert on the same packet carried `1464040180` and `1271398021` | An engine-internal join key for one run. flabel correlates by 5-tuple and time and never reads it. |
| `flow.reason` | 14 consecutive runs: 13 × `("shutdown", "shutdown")`, 1 × `("shutdown", "timeout")` | A ~7% flake rate, which is worse for a gate than a value that always differs: it passes often enough to look sound, then fails unreproducibly, and a gate that cries wolf gets switched off. |

**`eve.json` records are compared as a multiset, not in file order.** Measured: the two `flow`
records for the benign canary's two connections appear in one order in one run and the reverse in
the next, so a positional comparison reported four fields differing when nothing had changed.
This is the same reasoning this section already applies to `labels` and `unmatched_detections`.
Sorting cannot hide a lost or duplicated record, because the multiset still counts.

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

**`mode`, `tiers_attempted` and `tiers_unavailable` are three different questions** (2026-08-18,
issue #132). `mode` is what the operator asked for and is named after the flag they typed;
`tiers_attempted` is what that mode means, from one table in `models.TIERS_BY_MODE`; and
`tiers_unavailable` is **attempted-and-lost, never not-asked-for**.

That last distinction is the correction. Phase 1 hardcoded all three — `"offline"`, `[2]`, `[1]` —
on the reasoning that tier 1 was unbuilt, and Phase 2 built tier 1 without coming back, so for
four days every run that replayed past the firewall published a run block calling itself offline
with tier 1 unavailable, contradicted in the same document by a `sources[].tier` of `1`. Deriving
all three from the invocation is what makes that class of staleness unreachable.

`tiers_unavailable` is therefore empty on every successful run, in all three modes, and that is not
a dead field: the path that populates it is the failure path. A `--both` run whose device raised
mid-replay writes `[1, 2]` — tier 1 is where it died, and tier 2 was never reached, because the
device stage runs first. One that got past the device and then lost Zeek or Suricata writes `[2]`,
as does an `--offline` run whose Suricata failed. Those are exactly the runs whose reader needs to
know which half they got, and a field that said `[1]` regardless could not tell them.

**A tier counts as delivered only when its stage returned**, never because its record exists in the
block. `run_suricata` reports a tool failure by *returning* a populated `SuricataRunInfo` and
letting the caller raise, so `tools.suricata` is filled in on precisely the runs where tier 2 was
lost. Both completions are therefore told to the run block by the orchestrator rather than inferred
from what is present in it.

**A `replay` run has no `ruleset` block to fill**, and every field in it is `null` rather than
absent or zero. Tier 1 loads no Suricata rules, so there is no snapshot: `null` is §2.5's "not
measured", where `0` would claim the run loaded a ruleset and found it empty. `NOTICE` is still
written — the run's output carries vendor threat names, and the artifact's subject is whose text is
in there — but it names no snapshot and records the absence of an attribution obligation.

**`run.input.path` is the operator's original path** (`NormalizedCapture.original_path`), never the
normalized copy, because the normalized copy lives in a per-run temporary directory that means
nothing to a reader. That makes it **the one input field a reproducibility comparison must exclude
or normalise**: the same capture labelled from two directories would otherwise differ and fail Goal
2, which would be a false alarm about the pipeline.

### Run block

```python
{
  "flabel_version": str, "schema_version": "2.0",
  "started_at": str, "finished_at": str, "duration_seconds": float | None,
  "mode": "replay|offline|both",          # the invocation, one value per flag (§12)
  "unmatched_threshold": float,           # the gate this run was held to — see below
  "tiers_attempted": [1|2], "tiers_unavailable": [1|2],
  "input": {"path": str, "sha256": str, "format": "pcap|pcapng|pcap.gz|pcapng.gz",
            "bytes": int, "input_status": "complete|partial",
            "packets_read": int,
            "truncated_at_offset": int | None,
            "discarded_link_types": [str], "discarded_packets": int,
            "normalization": [str]},
  "ruleset": {"snapshot_id": str, "sources": [...SourceAdmission...],
              "total_admitted": int, "total_ja4_admitted": int},   # every field null on `replay`
  "tools": {"zeek": str, "zeek_flags": ["-C", "-D"], "suricata": str,
            "editcap": str | None, "ja4_zeek_package": str | None,
            "ja4_status": "present|not-installed|probe-failed" | None,
            "suricata_config_sha256": str},
  "counts": {"flows": int, "detections": int, "labels": int,
             "unmatched": int, "unmatched_unsupported_transport": int,
             "unmatched_ratio": float,
             "identify_alerts_suppressed": int | None,
             "rules_loaded": int | None, "rules_failed": int | None,
             "rules_skipped": int | None},
  "loss_conditions": {...},               # §11
  "tool_failures": [ ... ],
  "warnings": [str]
}
```

The four `int | None` counts are Suricata's, and they are `null` whenever that pass failed before establishing the number (issue #86) — including the case where the pass failed *after* establishing some of them, which are then reported as measured. `loss_conditions.rules_failed_or_skipped` and `identify_alert_suppressed` are `null` on the same condition, because `bool(None or None)` is `False` and would assert that nothing failed about a run that never counted.

**The types above describe a completed run.** In the `run.json` of a run that failed part-way,
every field of `input`, `ruleset`, `tools` and `counts` whose stage did not run is `null` — not
zero, not an empty list, and never a dropped key, so a reader can tell "not measured" from
"measured as none". A consumer written from the literal above must expect `null` in place of any
of them, including where a list is declared.

**Five keys were added to the run block in steps 5 and 6**, each because the model field behind it
had nowhere to surface: `tools.ja4_status` and `tools.suricata_config_sha256`, and
`counts.rules_loaded` / `rules_failed` / `rules_skipped`. `tools.ja4_zeek_package` is now nullable —
it holds a real package version read from the toolchain manifest, or nothing, and never a status
string standing in for one (§8).

**`tools.editcap` became nullable in step 8**, for the same reason and from the same source.
Nothing records an editcap version at run time — `ingest.py` invokes the binary without capturing
one, and a labelling run may not shell out to ask (§2.2) — so a non-nullable `str` was a field with
no way to be filled. It is read from the toolchain manifest's `wireshark` entry, or is `null`.
A null here means the manifest was absent, which is the ordinary laptop case; it never means
`editcap` did not run, because a run that needed it and could not use it fails.

**`loss_conditions` is derived, never stored** — an implementer's decision taken in step 8,
recorded here with its reasoning rather than attributed to a product call, because §10 named the
key and never defined it. This section names the key while §11 puts each
condition's authoritative field elsewhere in the block — `input.*`, `counts.*`, `tools.ja4_status`,
`tool_failures[]`. It is computed from those on the way out, so the two cannot disagree; storing it
would create nine pairs of fields that must agree and one place for them to drift. Each flag is
`null` rather than `false` when the stage that would know never ran, because "JA4 was fine" and
"nothing ever probed JA4" are different facts and `false` asserts the first. §13 forbids reporting
full coverage when a loss condition fired, and this is the field that makes that answerable in one
lookup rather than by reconstructing §11's rules from six scattered numbers.

### `run.json` — the run block when there are no labels to carry it

**On a hard tool failure the run directory contains `run.json` and no `labels.json`** (Craig,
2026-08-12 — issue #23). `run.json` holds the same run block defined above, including
`tool_failures[]` with each failure's argv, exit code, and whether the tool was killed rather than
exited.

**`run.json` is the `labels.json` document minus `labels`** (Craig, 2026-08-13, in step 9):

```json
{
  "schema_version": "2.0",
  "run": { "...as above..." },
  "unmatched_detections": [ "...UnmatchedDetection..." ]
}
```

Settled in step 9 because §9 and this section disagreed. §9 says the `UnmatchedDetection`
records "go in `run.json` on a failed run" and `CorrelationError` carries them for exactly that
purpose — but the run block's key set is fixed by the literal above and asserted against it, so
they cannot go *inside* it. They therefore sit beside it, in the same position and the same
order they occupy in `labels.json`, rendered by the same code.

The array is present on every run, not only failed ones, so the document has one shape. On the
run where it matters most — the correlation gate firing — there is no `labels.json` to carry it,
and `counts.unmatched` gives only the scale of the loss: `no_flow_match` is a tuple-normalisation
fault, `ambiguous_flow_match` is port reuse, and `unsupported_transport` is not a bug at all —
they are different causes in different modules.

**`unmatched_threshold` is the bar `unmatched_ratio` was measured against** (2026-08-15, issue #68). It decides *whether `labels.json` exists at all*: above it, `correlate()` raises and the run writes `run.json` with no labels. It is an operator-supplied input with a default of `0.01` (§12), and it was the one input to a run that the run did not record.

Two `labels.json` files reporting `unmatched_ratio: 0.08` were indistinguishable, where one had passed a deliberately loosened gate and the other would never have been written at the default. The artifact could not be checked against the rule that produced it.

It sits beside `mode` rather than inside `counts` because it is an **input**, not a measurement: everything in `counts` is a number read off the run, and a configuration knob among them invites a consumer to treat it as one. Every other input to a run is already recorded here — the snapshot id, the Suricata config sha256, the Zeek flags, the toolchain versions — and this was the gap, which also made Goal 2 unreproducible from the artifact alone. Phase 2 is expected to set its own, looser threshold (§9), at which point an unrecorded one stops being a detail.

Never `null`: argparse supplies the default when the operator does not, so a run always had a threshold, even one that died before correlation. `null` would mean "not measured", and this is not measured — it is given.

**`unmatched_ratio` is the number the gate acted on, and it is not `unmatched / detections`**
(issue #84). Detections on a protocol Zeek cannot express are excluded from *both* sides of it:
they were never going to correlate, so counting them would fail a run on ordinary IPsec traffic,
and counting enough of them would drag a genuine tuple-normalisation defect below the threshold
and silence the gate. `counts.unmatched` still counts every unmatched detection and
`counts.unmatched_unsupported_transport` says how many of them were of this kind, so the
descriptive share stays recoverable — but a consumer recomputing `unmatched / detections` will
not reproduce `unmatched_ratio` whenever that count is non-zero. Zero correlatable detections
yields `0.0`.

**`unmatched_detections` is `null` when correlation never ran, and `[]` when it ran and placed
everything.** The key is always present — that is what "one shape" means — but its *value*
carries the same distinction as every field in the run block: `null` is "not measured", `[]` is
"measured as none". A run that died in Zeek examined no detections at all, and an empty array
there asserts that every detection was placed, which is §2.5's failure mode in the document that
exists to prevent it. `counts.unmatched` is already `null` on that path, and the two are records
of one fact.
The cost is that a successful run serialises the array twice; both come from one
`CorrelationResult` in one call, so they cannot disagree.

`run.json` **is** part of the Goal 2 comparison (step 10). An earlier draft of this section said
it was excluded; it is not, and including it is the safer reading — a run block that drifts
between two runs over one capture is precisely what Goal 2 exists to catch. The wall-clock fields
inside it are excluded by field, exactly as `labels.json`'s are.

**`labels` is absent, never `[]`.** That is the same distinction the file exists to make: an
empty array reads as "nothing malicious was found" when the pipeline died, and a consumer
training on the output cannot tell it from a clean capture.

This resolves a genuine tension between two requirements rather than working around either. §11
requires a tool failure recorded in `tool_failures[]`; §13 forbids writing a partial `labels.json`
on a hard failure. The array therefore belongs to a document that must not exist — so it moves to
one that may.

Two alternatives were rejected, and why matters more than the choice:

| Rejected | Why |
| :-- | :-- |
| stderr only, nothing on disk | A calling script would have to parse prose to learn what was lost. That is exactly the structured-record loss `ToolError.failures` exists to prevent (§4) — the argv, the exit code and the kill status would survive only as text. |
| A complete `labels.json` with empty `labels[]` | It reads as "nothing malicious was found" when the pipeline in fact died. A consumer training on the output cannot distinguish it from a clean capture, which is §2.5's failure mode in its purest form. |

**The absence of `labels.json` is the signal, and it is unambiguous**: no verdict was ever claimed.
A consumer tests for the file, not for a status field inside it — a status field would have to be
read and understood, whereas a missing file cannot be misread as a verdict.

Consequently `run.json` is written by **every** run, successful or not, so that a consumer has one
place to find the run block regardless of outcome and never has to infer which file to open. Two
consequences follow for later steps: it is a name in the output contract (§12), and §10's
reproducibility comparison must skip label-free run directories rather than fail on the missing
`labels.json`.

### `NOTICE` — `notice.py`

Lists every source **whose rule text appears anywhere in this run's output**, with its licence and required attribution. Sources present in the snapshot but absent from the output are not listed: the snapshot describes what was *available*, NOTICE describes what was *used*.

**Widened from "every source that asserted a label" in step 8** (Craig, 2026-08-12). `unmatched_detections[].detection.threat` is verbatim rule `msg:` text, copied into `labels.json` from sources that asserted nothing — and several admitted feeds are CC-BY-4.0, CC-BY-SA-4.0 or GPL-3.0-only, whose terms ask for attribution wherever their text is redistributed. Under the narrow reading a licence obligation would depend on whether a detection happened to *correlate*, which is an accident of the capture rather than anything about the source. Over-attributing costs a longer file; under-attributing is a breach in the one artifact carrying legal weight, in a public repo.

A source reached only through an unmatched detection has no `SourceEntry`, so its licence is resolved through the snapshot manifest — the same authority, one step less direct. A source appearing under two different licences in one run raises rather than picking one.

---

## 11. Loss conditions

Each has a field and exactly one fault-injection test. This closed list is what Goal 3 is checked against.

| Condition | Field | Fault injection |
| :-- | :-- | :-- |
| Input truncated | `input.input_status`, `packets_read`, `truncated_at_offset` | truncate a fixture mid-record |
| Multi-datalink discard | `input.discarded_link_types`, `discarded_packets` | fixture with two link types |
| Detection uncorrelatable | `counts.unmatched`, `unmatched_detections[]` | detection with a tuple absent from `conn.log` |
| Ambiguous flow match | `unmatched_detections[].reason` | two flows, same tuple, detection outside both windows |
| Unsupported transport | `counts.unmatched_unsupported_transport` | capture carrying ESP, SCTP or GRE with an `alert ip` rule loaded |
| Tool non-zero exit / OOM | `tool_failures[]` | point at a non-existent binary |
| Snapshot missing | hard failure, exit 1 | `--ruleset-snapshot nonexistent` |
| `identify` alert suppressed | `counts.identify_alerts_suppressed` | rule from an `identify` source that fires |
| Rules failed or skipped at load | `counts.rules_failed`, `counts.rules_skipped` | snapshot containing a rule this engine cannot compile |
| JA4 unavailable | `tools.ja4_status` | run with the `ja4` package absent from `ZEEKPATH` |

**Two rows added in steps 5 and 6.** Both are losses the tools report and then exit 0 over, which
is the shape §2.5 exists to catch.

**A third added in step 12 (issue #84).** `unsupported_transport` needs its own row precisely
because it is *excluded from the gate*: `detection_uncorrelatable` reports `no_flow_match`, so
without this row a run that discarded every detection in an IPsec capture would report a clean
`loss_conditions` block with every flag false. A loss that is deliberately not failed is still a
loss, and §2.5 does not make an exception for the ones we decided to tolerate.

**Rules failed or skipped at load: record always, warn on any shortfall, and let the operator
decide** (Craig, 2026-08-12 — issue #46). Suricata loads what it can and exits 0, so a snapshot of
85,545 rules loading as 85,519 is a run that looks complete and never examined the capture with 26
of its rules. Any shortfall is worth saying out loud, and a large one means the snapshot and the
engine disagree about what a rule is. Rules the engine is known in advance to reject are excluded
at admission instead (§5), so these counters describe *surprises* rather than known
incompatibilities.

**This replaces the earlier "fail above a threshold".** A threshold is a number of labels you are
willing to lose in silence, and the measurement gives no evidence for any particular value.
Measured 2026-08-12 against a snapshot built from all nine feeds (`8c9e8d58af0a8d64`, 85,431
rules): **85,431 loaded, 0 failed, 0 skipped** — `rules_loaded` equals `total_admitted` exactly.
Zero is the only value ever observed, so any threshold would be invented rather than derived.

So the run reports the shortfall — the count **and** the percentage of the ruleset it represents —
and asks whether to continue (`Y/n`, default yes). The operator decides in the moment, with the
loss quantified in front of them, rather than a constant deciding in advance on their behalf.

**The prompt appears only when stdin is a TTY.** flabel runs in CI, cron and `set -e` scripts,
where a prompt either hangs the pipeline or blocks §10's own reproducibility gates. Without a TTY
the run proceeds — that is what "default yes" means — and the warning is recorded in the run block
either way, so a non-interactive run never loses the fact that rules went missing. No flag controls
this: the CLI contract in §12 is closed, and a flag would be a second way to express something the
default already answers.

A run that cannot obtain the counts at all still fails (§8): an alert set whose ruleset cannot be
attested is not evidence, and that is a different condition from a ruleset that is attestably
incomplete.

**JA4 unavailable: `tools.ja4_status`, so a null `ja4` cannot be mistaken for "no TLS in this
capture".** Those are different facts about a flow, and with no field to hold the difference a
consumer training on the output would read a missing package as an observation.

---

## 12. CLI contract — `cli.py`

```
flabel <capture>                      Tier 1 only: replays the capture past the device and
                                      labels from its threat logs. The device comes from
                                      FLABEL_INLINE_* (see .env.example).
flabel --offline <capture>            Tier 2 only: Suricata + Zeek read the capture file.
flabel --both <capture>               Tier 1 and Tier 2, labelling from both.
    --ruleset-snapshot <id>           default: newest available. REFUSED on a replay-only
                                      run — exit 2. See below.
    --output-dir <dir>                default: cwd
    --rules-dir <dir>                 default: ./.flabel/rules. Tier 2 only — REFUSED on a
                                      replay-only run, with --ruleset-snapshot.
    --sources <file>                  REFUSED here — exit 2. See below.
    --unmatched-threshold <float>     default: 0.01
flabel rules update [--sources <f>] [--rules-dir <d>]
flabel rules list  [--rules-dir <d>]
```

**Zeek runs in all three modes and is not a tier.** It is the flow substrate every label's `flow`
block is built from: a replay-only run still needs `conn.log` to attach a threat log to a flow and
to publish a `uid`. A mode switches off a *detector*, never the thing detections are attached to.

**The bare command was Tier 1 + Tier 2 until 2026-08-18** (Craig, issue #132), and `--both` is that
behaviour renamed rather than removed. Three pipelines existed and only two could be asked for, so
evaluating the device alone meant paying a full 85,000-rule Suricata load on every replay and
reading an output that mixed the tier under test with the open-source baseline. Naming all three is
what lets a run be about one tier deliberately.

**This supersedes "Phase 2 adds no flags"** (PRD v0.4, 2026-08-11), which was true when written and
is recorded here rather than deleted: the contract was closed on the belief that Phase 2 only
needed to *build* the default path, and that held right up until the built default turned out to be
the wrong default. `--offline` is unchanged, and remains permanent.

**`--ruleset-snapshot` and `--rules-dir` are refused on a replay-only run**, on `--sources`'
reasoning (§5, issue #71) one mode along: that pipeline loads no Suricata rules, so neither flag
can change a single label, and an operator who passed one believes they have pinned what this run
labelled against. Accepting and ignoring it would put that belief into `run.ruleset`, which is
all-null on such a run. Both are refused rather than only the snapshot id, because they express the
same intent at two levels of precision — refusing one and ignoring the other would teach that the
distinction is meaningful when it is not. Only an *explicitly passed* `--rules-dir` is refused; its
default is resolved at use, so a bare replay-only run is unaffected.

`--offline --both` is refused by argparse's own mutually-exclusive group, because the two requests
cannot both be honoured and picking a winner would make the losing flag silently ineffective.

**`--sources` is refused on the labelling path, not ignored** (2026-08-15, issue #71). It is still *declared* there, so the refusal can explain itself rather than argparse saying `unrecognized arguments`. Passing it exits 2 before any tool runs and before a run directory exists.

The reason is §4's, and the behaviour it protects does not change: a label's terms — `licence`, `source_class`, `admission_basis`, `url` — come from the snapshot manifest written when the rules were fetched, never from the registry as it stands now. `enabled` describes the registry today, not what was admitted then, and letting a later registry edit change the reading of an old snapshot would make labels retroactively unattributable.

What changed is that the flag used to be parsed and discarded. `flabel --offline capture.pcap --sources my-registry.toml` looked like it had changed which sources may label; it had not, and nothing said so. That is §5's own rule — *a registry that loads with a setting silently ignored is worse than one that refuses to load* — applied to the CLI instead of the TOML. Choosing a registry happens at `flabel rules update --sources <file>`, and the resulting snapshot is then named with `--ruleset-snapshot <id>`.

The refusal applies on every labelling invocation, in all three modes: the invocation is wrong either way, and it exits 2 rather than 3. It predates the stub path being built and is unaffected by #132 adding `--both` — what a snapshot's terms are does not depend on which tiers ran.

**Exit codes**

| Code | Meaning |
| :-: | :-- |
| 0 | Success. Labels written. Covers both complete and partial input — `run.input.input_status` distinguishes them. **Partial means partial *data*, not zero data**: a capture with no readable packets is a `CaptureError` (issue #85), because `input_status: partial` on a file with nothing in it asserts a coverage figure over an empty set. |

**A rejected capture leaves no run directory, and that is deliberate** (Craig, 2026-08-14). Issue #23 argued that a script must not have to parse a log to learn that the artifact beside it is not a result — but that argument is about a run which *started* and then died, where `run.json` records what was lost. A capture flabel cannot read never starts a run: §8 step 4 has made an unreadable header a `CaptureError` with no output since step 3, and step 9's zero-packet case is the same category, not a new one. The exit code and the stderr message are the contract every `CaptureError` has. A batch caller distinguishes "this capture was rejected" from "flabel died mid-run" by whether a run directory exists at all, which is the same signal §13 already relies on.
| 1 | Failure. **No `labels.json`** — but the run directory exists and holds `run.json` with `tool_failures[]` (§10), unless the failure occurred before a run directory could be created (a missing snapshot, an unreadable capture). |
| 2 | Usage error (argparse). |
| 3 | Not implemented. **Unused since Phase 2** — the default path is built, so nothing remains to report. Retained rather than renumbered: a caller scripting against the old contract must not have exit 3 silently start meaning something else. |
| 4 | **`tools/flabel-run` only, never `flabel` itself.** The labelling run succeeded and its result was **not published** to `$FLABEL_RESULTS_URI` — the tarball, the upload, or the identification of which directory to publish failed. `labels.json` is intact on the box. A code of its own because reusing 1 told a batch caller to discard or re-run a capture whose labels exist (review of #134), and the wrapper is the only thing that can emit it: `flabel` has no publishing step. |

Partial input is deliberately **not** a distinct code: truncated captures are common, and a non-zero exit would make every ordinary `set -e` script treat a successful run as a failure.

stderr carries progress and warnings; stdout is reserved and currently unused by the pipeline. `errors.py` maps each exception type to exactly one exit code.

---

## 13. Explicit non-behaviours

flabel **must never**:

- assert that a flow is benign, or emit any verdict other than `malicious`;
- emit a label from a fingerprint value alone, without a rule match;
- emit a label attributable to an `identify`-class source;
- assign a detection to a flow by guess when the match is ambiguous;
- perform network I/O on an `--offline` run, or outside `flabel rules update` and `panw.py`;
- invoke Zeek without `-D`;
- overwrite or modify a previous run directory;
- write a partial `labels.json` on a hard failure — either a complete run directory exists or none does;
- report full coverage when any loss condition fired;
- contact the PANW device (Phase 1 has no Tier 1 code path beyond the stub);
- commit, transmit, or copy capture data anywhere outside the run directory.

**That last rule needs its scope stated now that a run directory is published** (2026-08-19, #134).
`tools/flabel-run` tars a successful run and uploads it to a GCS bucket, which is transmission of
the run directory — so the rule has to be read precisely, and it holds: what it forbids is moving
**capture data**, and no capture data is in there. The normalized pcap lives in a
`TemporaryDirectory` and never enters the run directory at all (§10), and the shipped Suricata
configuration writes no payloads, HTTP bodies or extracted files.

What *is* published is derived metadata, and it is not anonymous: Zeek's retained logs carry the
DNS names queried, the HTTP URIs and hosts requested, and the TLS server names offered by whoever
appears in the capture. That is the same content `labels.json` already publishes for a labelled
flow, now for every flow in the run. Publishing is therefore a deliberate destination decision
rather than a side effect — which is why it lives in the wrapper, is off when
`FLABEL_RESULTS_URI` is empty, and never happens for a run that wrote no labels.

**And a consumer must never read an empty `labels[]` as "nothing malicious was found."** Since
step 12 (issue #84) a run can succeed while structurally withholding a detection that *did*
fire: an all-IPsec capture tripping a C2 rule exits 0 with `labels[]` empty, because the
detection could not be attached to a flow and this project does not guess. The evidence is in
`unmatched_detections[]` and `loss_conditions.unsupported_transport`, and nothing forces a
consumer to look. This is the first case where zero labels is not the same claim as zero
findings, and it is a property of the output rather than a rule flabel can enforce — which is
why it is written here, next to the things that must never happen, rather than left implicit.

---

## 14. Open items carried into build

Not blocking the plan; each has an owner.

| Item | Where |
| :-- | :-- |
| Malicious canary capture must be sourced (origin + licence recorded) | `tests/fixtures/README.md`, PRD Q8 |
| ~~Exact ET Open admitted-rule counts~~ | **Closed 2026-08-12 — §6 records the measured per-source yield (issue #11)** |
| Untagged-ET-rule policy | issue #10 — §6 now supplies the denominator it was waiting on |
| JA4 rule content | issue #13 — confirmed zero `ja4.hash` rules across all nine feeds (§6) |
| Stakeholders, target release, metric review dates | PRD Q1, Q2, Q10 |
| `manifest.json` is not covered by `snapshot_id`, so a label's terms are stored with the rules but not sealed with them | issue #48 |
| `_read_manifest` accepts duplicate source names; the last silently wins | issue #49 |
