# PLAN — flabel Phase 1

**Stage 4, Part B.** Built from `docs/spec.md`. **Phase 1 only** — Phase 2 is planned after its reachability spike.

Test-first throughout (`/tdd`). No code is written in this stage.

## Shape of the work

```
Step 1  toolchain + CI          ── blocks everything
   │
Step 2  models, errors, config  ── blocks everything downstream
   │
   ├─ Step 3  ingest      ─┐
   ├─ Step 4  rules       ─┤   all four touch disjoint files
   ├─ Step 5  zeek        ─┤   → safe to build in parallel
   └─ Step 6  suricata    ─┘
   │
   ├─ Step 7  correlate   ─┐   pure; parallel with each other
   └─ Step 8  labels      ─┘
   │
Step 9  cli (integration)
   │
Step 10 canaries + reproducibility gates
   │
Step 11 per-rule label basis   ── post-Phase 1 (#75)
Step 12 unsupported transports ── post-Phase 1 (#84), independent of 11
Step 13 hardening: six ways the output can lie ── post-Phase 1, blocks sign-off
```

**Parallel groups:** {3, 4, 5, 6} and {7, 8}. Cap at 2–3 worktrees at a time. Every other step is sequential.

| Step | Issue | Parallel-safe |
| :-: | :-: | :-: |
| 1 Toolchain and CI | [#15](https://github.com/DeepTempo/flabel/issues/15) | |
| 2 Foundations | [#16](https://github.com/DeepTempo/flabel/issues/16) | |
| 3 Ingest | [#17](https://github.com/DeepTempo/flabel/issues/17) | ⟂ |
| 4 Rules | [#18](https://github.com/DeepTempo/flabel/issues/18) | ⟂ |
| 5 Zeek | [#19](https://github.com/DeepTempo/flabel/issues/19) | ⟂ |
| 6 Suricata | [#20](https://github.com/DeepTempo/flabel/issues/20) | ⟂ |
| 7 Correlate | [#21](https://github.com/DeepTempo/flabel/issues/21) | ⟂ |
| 8 Labels | [#22](https://github.com/DeepTempo/flabel/issues/22) | ⟂ |
| 9 CLI | [#23](https://github.com/DeepTempo/flabel/issues/23) | |
| 10 Canaries | [#24](https://github.com/DeepTempo/flabel/issues/24) | |
| 11 Per-rule label basis | [#75](https://github.com/DeepTempo/flabel/issues/75) | *post-Phase 1* |
| 12 Unsupported transports | [#84](https://github.com/DeepTempo/flabel/issues/84) | *post-Phase 1* |
| 13 Hardening: the output must not lie | [#85](https://github.com/DeepTempo/flabel/issues/85) +5 | *post-Phase 1* |

**Why step 1 is first:** the testing decision is *tools real, network stubbed* — Zeek, Suricata, and `editcap` are invoked for real in tests. Until CI can run them, **nothing else is testable**, so this is a hard prerequisite rather than scaffolding to do later.

---

## Step 1 — Toolchain and CI

**Files:** `.github/workflows/ci.yml`, `Dockerfile.toolchain` (or a CI install block), `docs/dev-setup.md`, `.gitignore`

**Changes:** Provide pinned Zeek 6+/8.x, Suricata 8.x, and Wireshark (`editcap`, `capinfos`) to CI, plus the `zeek/foxio/ja4` package via `zkg`. Record exact versions — pinning is a precondition for Goal 2, since reproducibility across unpinned tool versions is meaningless. Document local setup (`brew install zeek suricata wireshark`). Add `.flabel/` to `.gitignore`.

**Test that proves it:** CI runs a job asserting `zeek --version`, `suricata --version`, `editcap --version` all succeed and match the pinned versions, then runs `pytest -q`. **CI fails if zero `requires_tools` tests executed** — a skipped integration suite must never look like a passing one.

**Depends on:** nothing. **Blocks:** everything.

---

## Step 2 — Foundations: models, errors, config

**Files:** `src/flabel/models.py`, `src/flabel/errors.py`, `src/flabel/config.py`, `src/flabel/data/sources.toml`, `tests/test_models.py`, `tests/test_config.py`

**Changes:** All frozen dataclasses from spec §4, **plus the four types spec §8/§9 name as return values** (`NormalizedCapture`, `ZeekRunInfo`, `SuricataRunInfo`, `CorrelationResult`) and `ToolFailure`, in one module that imports nothing from the package. Defining them here rather than in steps 3/5/6/7 is what keeps those steps read-only against `models.py` — a step that has to *create* a shared type collides with its siblings in the file meant to prevent that. Typed exceptions mapped to exit codes (spec §12). Source-registry loader with validation. `data/sources.toml` populated with the ten sources and their authoritative class/basis/licence assignments from spec §5.

**Test that proves it:** `SourceSpec.may_label` is `False` exactly for `identify`; `label_basis` is `indicator-reference` exactly for `ioc-name`; unknown `source_class` or `admission_basis` raises; `metadata-filter` on a source without ET metadata raises; every exception type maps to exactly one exit code, and every exit code in spec §12 is reachable. **Plus the architectural guard:** a test asserting no pure module's source contains `subprocess`, `urllib`, or `socket`.

**Depends on:** 1. **Blocks:** 3, 4, 5, 6, 7, 8.

---

## Step 3 — Ingest and normalization ⟂

**Files:** `src/flabel/ingest.py`, `tests/test_ingest.py`, `tests/fixtures/make_awkward.py`

**Changes:** Format sniffing by magic bytes (never extension), gzip decompression, flabel's own record-header walk for packet count and truncation offset, `editcap -F pcap` conversion, multi-datalink dominant-type selection. Emits `NormalizedCapture` with everything provenance needs.

`make_awkward.py` extends the existing canary generator to emit the nasty inputs: truncated pcap, truncated pcapng, multi-datalink pcapng, bad header, gzipped variants.

**Test that proves it:** each awkward fixture produces its specified outcome — truncated pcap gives `input_status: partial` with a correct offset; truncated pcapng and bad header raise `CaptureError` and create **no** output; multi-datalink keeps the dominant type and records the discards; gzip is transparent. Round-trip: a plain pcap normalizes to a byte-identical file.

**Depends on:** 2. **Parallel with:** 4, 5, 6.

---

## Step 4 — Ruleset fetch, admission, snapshots ⟂

**Files:** `src/flabel/rules/{__init__,fetch,admit,snapshot}.py`, `tests/test_admit.py`, `tests/test_snapshot.py`, `tests/fixtures/rules/*.rules`

**Changes:** `fetch.py` is the only network I/O in the package, behind an interface a test can point at local files. `admit.py` implements the per-source policy: wholesale, or ET metadata filter on `confidence High` **and** `signature_severity Major|Critical`, counting each exclusion reason separately. `snapshot.py` writes content-addressed immutable snapshots with a manifest, and loads them.

**Test that proves it:** on committed rule fixtures, `fetched == admitted + sum(excluded)` exactly; a `confidence Low` rule and a rule with no `confidence` key are excluded into *different* counters; `#alert` lines never admit; `ja3.hash` / `ja4.hash` rules are counted separately. Snapshot id is stable across writes of identical content and changes when content changes; `rules.rules` is sorted so fetch order cannot affect the id; `load_snapshot(None)` returns the newest; a missing snapshot raises. **Reports the real ET Open admitted counts, closing issue #11.**

**Also required, from step 2's verification (measured against the live feeds):**
- Import `ET_METADATA_SOURCES` from `config.py`; do not re-encode which feeds carry ET metadata.
- **A `metadata-filter` source whose fetched rules contain zero `confidence` keys is a hard failure.** The load-time name check cannot detect ET dropping the key: the filter would admit zero rules, indistinguishable from a feed that matched nothing.
- Count `#alert` lines into `rules_excluded_commented`. ET Open 8.0 ships **19,479** of them against 51,778 active rules, so `rules_fetched` counts active `alert` lines only.
- Feeds differ in shape: six are `.tar.gz`, two are plain `.rules`, and `malsilo` is a tarball of **three** rules files. `malsilo` is also the only feed publishing a checksum.
- Expected ET Open result, measured 2026-08-12: **21,221 admitted of 51,778** (41.0%); excluded 5,836 no-confidence, 11,425 low-confidence, 13,296 low-severity. The four counters sum exactly. Closing #11 means reproducing these from code.
- ET Open 8.0 contains **zero `ja4.hash` rules** (19 `ja3.hash`), confirming #13: the capability ships, the content does not exist upstream yet.

**Depends on:** 2. **Parallel with:** 3, 5, 6.

---

## Step 5 — Zeek invocation and parsing ⟂

**Files:** `src/flabel/zeek.py`, `src/flabel/data/json-logs.zeek`, `tests/test_zeek.py`

**Changes:** Single invocation `zeek -C -D -r <pcap> json-logs.zeek`. The Zeek script adds JSON log filters for `conn` and `ssl` so one pass yields both TSV (retained) and JSON (parsed) and they cannot disagree. Parse `conn_json.log` into `Flow`, join `ssl_json.log` for `ja4`/`ja4s`/`server_name` on `uid`. Retain all TSV logs; strip the `_json` files from retained output.

**Test that proves it:** on `benign.pcap`, exactly two flows with the expected tuples. **Determinism gate: two runs produce identical `uid`s** — this is the regression test for the verified spike-3 finding, and it fails if `-D` is ever dropped. A TLS fixture yields a populated `ja4`. Non-zero exit produces a `tool_failures[]` entry rather than an exception escaping.

**As built, and corrected here:** `packet_filter.log` is excluded, but it is not the only
non-reproducible log — *no* Zeek TSV log is byte-identical across runs, because they all carry
wall-clock `#open`/`#close` headers. Step 5 compares non-`#` records and ships a filename filter as
a knowingly-incomplete stopgap; step 10 replaces it with the canonicalizer. Step 5 also loads `ja4`
explicitly after probing for it, and raises `ToolError` carrying `.failures` and `.run_info` as
well as recording the failure — see spec §8.

**Depends on:** 2. **Parallel with:** 3, 4, 6.

---

## Step 6 — Suricata invocation and parsing ⟂

**Files:** `src/flabel/suricata.py`, `tests/test_suricata.py`, `tests/fixtures/rules/synthetic.rules`

**Changes:** Invoke with `-S <snapshot>/rules.rules` so only snapshot rules load and no ambient system ruleset leaks in; `--runmode single` for a deterministic alert set; JA3/JA4 fingerprinting enabled by `--set`. Parse `eve.json` alert records into `Detection`, resolving each SID's originating source from the snapshot manifest. **Drop detections from `identify`-class sources before they can become labels**, counting them.

**Test that proves it:** a synthetic rule matching `benign.pcap` produces exactly one parsed `Detection` with correct sid/rev/classtype/tuple/timestamp. A synthetic **`ja4.hash`** rule matching a TLS fixture also produces a detection — proving the JA4 labelling *capability* independent of whether content exists (US-14). An `identify`-source rule that fires yields **zero** detections and increments `identify_alerts_suppressed` (US-16). Two runs produce the same alert set.

**As built, and corrected here:** the invocation also needs `-c` (flabel's own `suricata.yaml`) and
`--set default-rule-path`, and a SID's originating source is resolved from the snapshot's
`sid_index.json` — not from the manifest, whose per-source *counts* cannot answer which source a SID
belongs to. `classtype` is read from the rule text rather than from `alert.category`, and the
5-tuple is translated into Zeek's spelling before it leaves this step. All in spec §7 and §8.

**Depends on:** 2 (and step 4's snapshot writer for a real snapshot; a hand-built snapshot directory suffices to keep them parallel). **Parallel with:** 3, 4, 5.

---

## Step 7 — Correlation ⟂

**Files:** `src/flabel/correlate.py`, `tests/test_correlate.py`

**Changes:** Pure. Tuple match in either direction, time-window disambiguation on multiple candidates, `UnmatchedDetection` with a reason when zero or still-ambiguous. Consolidate to one `Label` per flow with sorted `sources` and `best_tier`. Implement the unmatched gate: silent at zero, warn above zero, fail above the threshold.

**Test that proves it:** synthetic detections and flows only — no tools needed. One flow, one detection → one label. Two detections on one flow → one label with two sources. Port reuse with two candidate flows → resolved by time containment; detection outside both windows → `ambiguous_flow_match`. Tuple absent → `no_flow_match`. Threshold: 1 unmatched in 200 passes, 1 in 50 fails. `best_tier` is the minimum, not the maximum.

**Also required, from step 6's measurements (spec §8, Suricata):**
- **Correlate on the normalised tuple, and do not re-normalise.** Step 6 already translates Suricata's 5-tuple into Zeek's spelling — lowercased proto, `IPv6-ICMP` → `icmp`, compressed IPv6, ICMP type/code mirrored into the port columns. Correlation compares the fields as given; a second normalisation here would be two places that must agree about what a tuple is.
- **Step 7 owns the ICMPv6 counterpart-type residual.** For an ICMPv6 echo, Zeek writes the *reply* type in `id.resp_p` (`128, 129`) where step 6 can only yield `128, 0`, because a single alert record does not carry the counterpart type. Mirroring is exact for ICMPv4 and one field out for ICMPv6 echo, so closing it means correlation treating ICMP specially — matching on type and accepting the counterpart type in the responder column — not a different value in `suricata.py`. **Test:** an ICMPv6 echo detection correlates to the Zeek flow for the same exchange; an ICMPv4 one still matches exactly.

**Pre-placed before this step, and read-only to it (#44):**
- **`provenance.build_source_entry(detection, admission, snapshot_id)` already exists on `main`.**
  Correlation cannot return a `CorrelationResult` without constructing `SourceEntry` values, and
  step 8 was separately told to build them. Step 7 **imports and calls** that function; it does
  not write its own, and it does not derive `label_basis` from `source_class` itself.
- Consequently `correlate()` takes a `SnapshotManifest` (spec §9, corrected). **`manifest.sources`
  is a `tuple[SourceAdmission, ...]`, not a mapping** — index it once, exactly as `suricata.py`
  already does, and pass the record to the builder:

  ```python
  admissions = {admission.name: admission for admission in manifest.sources}
  entry = build_source_entry(detection, admissions[detection.source], manifest.snapshot_id)
  ```

  **Do not** call `config.load_sources()` or `config.enabled_sources()` — a label's terms come
  from the snapshot that produced it, and `enabled` describes the registry now, not what was
  admitted then. `build_source_entry` rejects a `SourceSpec` outright, so this is enforced and
  not merely advised.
- A detection whose source is absent from that mapping raises `SnapshotError`, matching
  `suricata.py`'s handling of a SID belonging to no source. Not a bare `ValueError`: that reaches
  the operator as a traceback rather than a reason. **Duplicate names in `manifest.sources` are a
  known unchecked case** — `_read_manifest` does not reject them, and the comprehension above
  silently keeps the last. Tracked separately; do not paper over it here.
- **An `identify` detection reaching correlation is a hard failure, not a filter.** Do not drop
  it and do not count it — §8 already suppressed and counted those, so one arriving here means
  that was bypassed. Let `build_source_entry` raise and assert the raise; asserting `labels == ()`
  instead would satisfy the words and produce a run that exits 0 having silently lost a detection.
- The `may_label`, tier, `snapshot_id` and type checks inside `build_source_entry` are backstops,
  not this step's excuse to skip the §2.8 test.

**Depends on:** 2. **Parallel with:** 8.

---

## Step 8 — Labels, provenance, NOTICE ⟂

**Files:** `src/flabel/labels.py`, `src/flabel/provenance.py`, `src/flabel/notice.py`, `tests/test_labels.py`, `tests/test_provenance.py`

**Changes:** Canonical serialisation per spec §10. Assemble the run block including every loss-condition field. Emit `NOTICE` for sources that actually asserted a label.

**No longer this step's job (#44):** *"Build `SourceEntry` values, deriving `label_basis` from
source class and carrying `admission_basis` and `licence`"* moved to
`provenance.build_source_entry`, pre-placed on `main` before this step and step 7 started —
step 7 has to construct `SourceEntry` values to return a `Label` at all, so leaving the job here
meant both worktrees writing it.

**`provenance.py` and `tests/test_provenance.py` are append-only to this step**, which is not the
same as read-only and the difference matters:

| File | Step 8 may | Step 8 may not |
| :-- | :-- | :-- |
| `src/flabel/provenance.py` | add the run-block assembly **below** the existing contents | change `build_source_entry`, its signature, its guards, or `KNOWN_TIERS` |
| `tests/test_provenance.py` | add a new section of run-block tests below the existing ones | modify, weaken or delete any existing test |

Do not change the builder's signature: step 7's worktree is written against it in parallel, so a
change here is green in both worktrees and broken on merge — the same defect class the
pre-placement exists to prevent. If it looks wrong, **raise it rather than edit it.**

(An earlier revision of this section called both files "read-only" while also telling step 8 to add
a test section to one of them, which cannot both be true. Recorded because the ambiguity was found
by having to answer it for a build agent, not by reading the plan — the plan read fine.)

The required-fields assertion below **already exists** as
`test_every_mandatory_field_is_populated_with_a_real_value` and
`test_the_mandatory_field_set_is_exactly_this`. Step 8 does not rewrite them; its Goal 1 work is
the equivalent check over the *serialised* `labels.json`, where a field can also be lost to the
JSON encoder rather than to the builder.

**Test that proves it:** canonical output is byte-identical across two serialisations of the same data, and the `labels` array sorts by `(ts_first, uid)` regardless of input order. **Required-fields check: every `SourceEntry` carries every field the spec §4 table demands** — this is the automated form of Goal 1, with no "where applicable" escape. `ioc-name` sources yield `indicator-reference`; all other labelling classes yield `direct`. `NOTICE` lists a GPL/CC-BY source that asserted a label and omits a source that asserted none. Every loss-condition field exists in the run block.

**Also required, from steps 3 and 5 (spec §8, §10):**
- **`run.input.path` is `NormalizedCapture.original_path`** — the operator's own file, not the normalized copy, which lives in a per-run temporary directory and means nothing to a reader. Spec §10 correspondingly makes it an excluded field in the reproducibility comparison.
- **Read the toolchain versions from `/etc/flabel-toolchain.json`, not by shelling out.** `zkg list` is the only local source of the `ja4` package version, and calling it from a labelling run risks the network call spec §2.2 forbids and step 9 asserts against. Step 1 already pins and records the toolchain; step 8 reads that manifest and fills `tools.ja4_zeek_package` from it. `tools.ja4_status` comes from `ZeekRunInfo` and is a separate field — a status must never be written into the version slot.
- **Test:** with a fixture toolchain manifest, `tools.ja4_zeek_package` is the version it names; with the manifest absent the field is null and the run still succeeds; the socket guard from step 9 stays clean throughout.

**Depends on:** 2. **Parallel with:** 7.

---

## Step 9 — CLI and orchestration

**Files:** `src/flabel/cli.py`, `tests/test_cli.py`

**Changes:** argparse surface from spec §12 including the `rules` subcommands. Wire ingest → zeek → suricata → correlate → labels into the run directory (`{capture-name}_{datetime}/`). The default path is the `Coming Soon (TM)` stub. Map exceptions to exit codes.

**Test that proves it:** end-to-end `--offline` on `benign.pcap` writes a run directory with `zeek/`, `labels.json`, and `NOTICE`, and exits 0. **The stub path prints `Coming Soon (TM)`, names `--offline`, creates no directory, and exits 3** (US-22). Re-running creates a sibling directory and leaves the first untouched; sorted names are chronological. A hard failure writes **no** `labels.json` — never a partial one. `--ruleset-snapshot nonexistent` exits 1. A labelling run makes no network call (asserted by a socket guard).

**Also required, from step 5 (spec §4, §8):**
- **Catch `ToolError` and read `.failures` and `.run_info`.** Step 5 records a tool failure *and* raises it, attaching the stage's run info to the exception, precisely so the caller can report the loss it is about to fail on. Catching `ToolError` and printing `str(exc)` would throw away the `ToolFailure` records — the argv, the exit code, and whether the tool was killed rather than exited.
- **`tool_failures[]` goes in a separate `run.json`, in a run directory with no `labels.json`** (Craig, 2026-08-12 — issue #23). §11 requires the failure recorded and §13 forbids a partial `labels.json`, so the array belongs in a file that is not `labels.json`. `run.json` carries the full run block including `tool_failures[]` with the argv, the exit code, and whether the tool was killed. Rejected: stderr-only, which makes a script parse prose to learn what was lost; and a complete `labels.json` with empty `labels[]`, which reads as "nothing malicious found" when the pipeline died. **The test asserts both halves: the failure is readable by a script, and no `labels.json` claims a verdict.** Two consequences: `run.json` is a new name in the output contract (spec §10, §12), and step 10's reproducibility gate must skip label-free run directories rather than fail on the missing file.

**Also required, from step 7 (spec §9):**
- **Assert `manifest.snapshot_id == suricata_run_info.snapshot_id` before correlating.** `run_suricata` loads a manifest and returns only the id, so step 9 loads the snapshot a second time to hand `correlate` its argument. With `--ruleset-snapshot` defaulting to "newest available", a `rules update` landing between those two loads resolves a *different* snapshot — and every label then cites a ruleset whose rules never ran. One assertion closes it; without it the two loads are silently allowed to disagree.

**Depends on:** 3, 4, 5, 6, 7, 8.

---

## Step 10 — Canaries and reproducibility gates

**Files:** `tests/integration/test_canaries.py`, `tests/integration/test_reproducibility.py`, `tests/fixtures/README.md`, `.github/workflows/ci.yml`

**Changes:** Wire Goal 5 and Goal 2 into CI as build-failing gates. Source the malicious canary and record its origin and licence.

**Test that proves it:** **benign canary produces zero labels — any label fails the build** (Goal 5, and the standing FP review for every wholesale-admitted source including `pawpatrules`). Malicious canary produces at least one label. **Reproducibility: two full `--offline` runs against the same capture and pinned snapshot are identical after canonicalisation** (Goal 2). Fault-injection test for every Phase 1 loss condition in spec §11 — including the two rows added after step 6: a snapshot holding a rule this engine cannot compile, and a run with the `ja4` package absent.

**Corrected after step 5, and this step owns the fix.** The reproducibility gate above originally
compared bytes, excluding `started_at`/`finished_at`/`duration_seconds` and `packet_filter.log`.
Byte-identity is unachievable: every Zeek TSV log carries wall-clock `#open`/`#close` headers, so a
byte comparison fails on all of them. Step 10 builds **the canonicalizer** — drop `#`-prefixed
header lines — and uses spec §10's corrected exclusion list: `run.input.path` alongside the three
timestamps, `zeek/packet_filter.log` and `suricata/suricata.log` excluded outright, and within
`suricata/eve.json` the `stats` records only, since `alert` and `flow` records are byte-stable and
are the ones worth comparing. `zeek/reporter.log` is canonicalised rather than excluded — its
startup messages carry wall-clock time even under `-D` while its packet-time messages are
reproducible, and dropping the file would hide the protocol violations Goal 3 wants reported.
The canonicalizer is a shared primitive, not test-local: step 5's `reproducible_logs` filename
filter is the knowingly-incomplete stopgap it replaces.

**Depends on:** 9. **Note:** the malicious canary is the one unresolved input (spec §14); if it slips, the benign canary and reproducibility gates land without it and the sensitivity test follows.

---

## Step 11 — Per-rule label basis (#75)

**Not part of Phase 1.** Phase 1's ten steps are merged and its Definition of Done is met; this is
remediation of a defect that only became visible once the pipeline ran against real traffic, and
it is written here because its last step touches files three earlier steps deliberately fenced off.

**The defect.** Measured 2026-08-13: 23 captures of ordinary protocol traffic against the real
nine-feed snapshot produced **100 malicious labels, 138 source entries, every one from
`pawpatrules`**. `source_class` classifies a *feed*, and `pawpatrules` is one feed carrying both
direct detections and policy observations, so no per-source setting can separate them. Full
decomposition on issue #75.

| Sub-step | Change | State |
| :-: | :-- | :-- |
| 11a | `[admission] exclude_classtypes` in the registry, with its own exclusion counter | **merged** (#78) |
| 11b | Address-indicator classification recorded in `sid_index.json` | **merged** (#78, corrected in #79) |
| 11c | `build_source_entry` consumes it for `label_basis` | **not started** |
| 11d | The benign corpus against the real ruleset, in `feeds.yml` | **not started** |

### 11c — the one that needs care

**Files:** `src/flabel/provenance.py`, `src/flabel/models.py`, `src/flabel/correlate.py`,
`tests/test_provenance.py`

`provenance.build_source_entry` is **the single place a `Detection` becomes provenance**. It was
pre-placed on `main` before steps 7 and 8 started (#44) precisely so two parallel worktrees could
not each invent their own `label_basis`, and both of those steps are written against its current
signature. It is the most load-bearing function in the package and the one this plan is least
willing to see changed casually.

**The rule, and it composes rather than replaces:**

> A `SourceEntry` is `indicator-reference` if **either** the source's `source_class` says so
> (`ioc-name`) **or** the rule is an address indicator.

Both halves are needed and neither is redundant. `abuse.ch/urlhaus` is the canonical `ioc-name`
source and scores **0%** on the per-rule test, because a domain-name indicator is matched in
payload content; `pawpatrules` declares itself `signature` and holds **16,064** address
indicators. Feed-level and rule-level answers each see what the other cannot.

**Test that proves it:** a `signature`-class source whose rule is an address indicator yields
`indicator-reference`; the same source's content-matching rule yields `direct`; an `ioc-name`
source yields `indicator-reference` regardless of shape; and an `identify` source still raises.

**The hard part is not the derivation, it is the absence.** `load_address_indicators` returns
`None` for a snapshot that recorded no classification — schema 1, or the schema 2 written by the
definition #79 corrected. `build_source_entry` must not read that as "no rule is an indicator",
which would emit `direct` for ~16,000 address-list rules and say nothing. Spec §2.5: absence is
never a signal.

**DECIDED (Craig, 2026-08-13) — warn, and downgrade to `indicator-reference`.** A run against an
unclassified snapshot proceeds. It records the fact once in the run block's `warnings[]`, naming
the snapshot, and every `SourceEntry` takes `indicator-reference` rather than `direct`.

Under the composed rule that means: `ioc-name` is unaffected (its feed-level answer already says
`indicator-reference`), `identify` still raises, and `signature` — the only class whose basis
depends on the missing per-rule answer — takes the weaker claim instead of the stronger one. So
when the classification is absent, *every* entry is `indicator-reference`.

Why: it strands no snapshot, and it cannot reproduce #75. The error it risks instead is
understating a genuine `direct` detection, which is wrong in the safer direction — an overclaim
of `direct` on ~16,000 address-list rules is the defect this whole step exists to remove, and it
would land in a file whose purpose is ML training data. Rejected: **refusing to label**, which
strands every snapshot built before #79 (and `load_address_indicators`' own docstring argues for
it — that argument is noted and overruled); and **warning while labelling `direct`**, which
reproduces #75 exactly with only a warning saying so.

Implementation consequence to carry into the build: `build_source_entry` is per-detection and
pure, so it cannot by itself put a once-per-run entry in `warnings[]`. Expect 11c's file list to
grow `src/flabel/cli.py` — confirm the plumbing before writing, rather than emitting the warning
per label.

**Tests this adds** to the four above: a `signature`-class content-matching rule against a `None`
classification yields `indicator-reference`, not `direct`; and the run block carries the warning
exactly once.

**Depends on:** 11b. **Blocks:** 11d.

### 11d — the gate that closes the loop

**Files:** `.github/workflows/feeds.yml`

Run `tests/fixtures/benign-corpus/` against the freshly-fetched nine-feed snapshot and fail on any
label. Deliberately **not** written before 11a-c land: the assertion depends on the policy in
force, and a gate written against an expectation already known to be false is a gate written to
fail. With 11a alone the corpus still produces 21 source entries — the residue #75 attributes to a
structurally broken rule, a loose regex, and #77's directionality loss — so the expectation is
"zero" only once those are settled too.

**Depends on:** 11c, and a decision on the three residual causes in #75.

---

## Step 12 — Unsupported transport protocols (#84)

**Not part of Phase 1**, and found the same way #75 was: by running the pipeline over traffic
nobody had tried. Filed from the final `/project:verify` pass.

**The defect, demonstrated.** Zeek's `transport_proto` holds only `tcp`/`udp`/`icmp`/
`unknown_transport`, and it zeroes the port columns for anything else. Suricata reports the real
protocol, and for SCTP the real ports. So the tuples disagree in the protocol field *always*:

| capture | flows | detections | unmatched | ratio | exit |
| :-- | --: | --: | --: | --: | --: |
| ESP (IP proto 50) | 1 | 1 | 1 | 100% | **1** |
| SCTP (IP proto 132) | 1 | 1 | 1 | 100% | **1** |
| GRE carrying TCP | 1 | 9 | 7 | 77.8% | **1** |

The run **dies** — `CorrelationError`, exit 1, no `labels.json` — on a capture that is otherwise
perfectly labellable, and the message misdirects the operator to check that Zeek and Suricata read
the same capture, which they did. Below the 1% threshold the failure flips to the other bad one:
the detections vanish into `unmatched_detections[]` and a C2-over-GRE alert never becomes a label.

`suricata.py:130` already recorded the gap in a comment. What nobody measured is that "reported"
meant the run dies.

**DECIDED (Craig, 2026-08-13) — report it, never correlate it.** A detection on a protocol Zeek
writes as `unknown_transport` is never attached to a flow. It lands in `unmatched_detections[]`
under a new reason, `unsupported_transport`, is counted separately, and is **excluded from the 1%
gate denominator** so a legitimate IPsec or tunnelled capture no longer fails the run.

**Rejected: matching on the address pair.** Two different such protocols between one host pair
produce two Zeek flows with **identical 5-tuples** — both `10.0.0.5 0 10.0.0.200 0
unknown_transport`. Address-pair matching therefore fails as `ambiguous_flow_match` exactly where
a host is busiest, and before it detects the ambiguity it can attach an ESP detection to an SCTP
flow. That trades the guarantee the output exists to provide for labels that cannot be trusted.

**Corrected during the build, by reading the log rather than the plan.** Zeek 8's `conn.log`
carries an **`ip_proto`** column — 50 for ESP, 132 for SCTP — so the two conversations *are*
distinguishable; `Flow` simply does not parse it. The decision stands, because reporting is right
either way and parsing `ip_proto` means mapping Suricata's protocol names onto IP protocol numbers
and widening `Flow`, which is a larger change than a crash fix should carry. But the reason is now
"flabel cannot tell them apart", not "the data does not exist" — filed as **#96**.

**Files:** `src/flabel/models.py`, `src/flabel/correlate.py`, `src/flabel/provenance.py`,
`docs/spec.md` (§4, §8, §9, §10, §11), `tests/fixtures/make_awkward.py`, `tests/test_correlate.py`,
`tests/test_provenance.py`, `tests/integration/test_canaries.py`.

**The classification is computable from the detection alone**, which is the same property that let
step 7 handle the ICMP counterpart without a second index: if the detection's normalised protocol
is not one of `tcp`/`udp`/`icmp`, the reason is `unsupported_transport` — decided before any
candidate lookup, so a detection on a protocol Zeek cannot express never reaches the tuple compare.
This also means an ESP detection with no Zeek flow at all is reported as `unsupported_transport`
rather than `no_flow_match`, which is right: the protocol is the cause.

**The one sub-decision this step takes, because it changes a published field.** `counts` gains
`unmatched_unsupported_transport`, and **`unmatched_ratio` becomes the ratio the gate actually
used** — correlatable unmatched over correlatable detections — rather than `unmatched / detections`.
Recording a ratio the gate did not use is issue #68's complaint one field over. `counts.unmatched`
keeps counting *every* unmatched detection, so nothing is hidden and the descriptive number stays
recoverable. §10 must say so explicitly, since a consumer recomputing `unmatched / detections` will
now get a different number when the count is non-zero. Zero correlatable detections yields ratio
`0.0`, not a division by zero.

**Test that proves it, test-first:**

1. A detection whose protocol is `esp` yields `UnmatchedDetection(reason="unsupported_transport")`
   even when a Zeek flow exists between the same addresses — the ambiguity measurement above is
   why this is the assertion rather than a match.
2. A capture that is *entirely* ESP completes: **exit 0**, a full run directory, `labels.json`
   present with an empty `labels` array, every detection in `unmatched_detections[]`.
3. The gate is not fired by unsupported transports alone — `unmatched_ratio` is `0.0` when every
   unmatched detection is one, and the run succeeds.
4. The gate still fires on a genuine tuple failure *mixed with* unsupported transports: the
   denominator excludes the latter, so one uncorrelatable TCP detection in a small correlatable
   population still fails. **This is the test that stops the fix from becoming a way to switch the
   gate off**, which is the step-10 lesson.
5. `counts.unmatched` counts all of them while `unmatched_ratio` counts only the correlatable —
   asserted together on one run, since the whole risk is that they silently become the same number.
6. The §11 loss-condition row resolves against real output, and §10's run block key set still
   equals the spec literal. Both are existing spec-parsing tests and will fail until the spec is
   edited, which is the point.

**Fixtures:** the repo has no capture carrying a non-TCP/UDP/ICMP protocol and `unknown_transport`
appears nowhere in `tests/`. `make_awkward.py` gains ESP, SCTP and GRE generators — byte-deterministic
like its siblings, so they can be regenerated and byte-compared.

**Depends on:** nothing outstanding. **Related, deliberately not folded in:** #68 (the run block
does not record the `--unmatched-threshold` the gate used) and #87 (the corpus correlation test is
vacuous, and would have caught this on day one).

---

## Step 13 — Hardening: the output must not lie (#85, #86, #70, #57, #62, #87)

**Not part of Phase 1**, and not a feature. Six issues from the two `/project:verify` passes,
grouped because they are **one defect in six places**: the run loses something, or fails, and the
artifact it leaves reads clean. That is what spec §2.5 and §13 exist to forbid, and it is the one
property the whole project is arguing for — a label nobody can trust the provenance of is worse
than no label.

Craig's call, 2026-08-14, after the whole-project assessment: take these six now, then sign off
Phase 1 with the remaining backlog tracked. The other 24 open issues are enhancements, known
deferrals, or test hardening that does not change what a consumer receives.

| Sub-step | Issue | Change |
| :-: | :-: | :-- |
| 13a | #87 | The benign-corpus correlation assertion is vacuous — 0 detections measured across all 17 captures, so it asserts `0 == 0` |
| 13b | #70 | `labels.json` / `run.json` written non-atomically, so a partial one is still possible — §13 forbids exactly that |
| 13c | #62 | A wall clock stepping backwards raises, and **no `run.json` is written at all** |
| 13d | #57 | `CorrelationResult` has no `warnings` field, so a correlation loss never reaches `run.warnings[]` |
| 13e | #86 | A failed Suricata run writes measured-looking **zeros** where §10 demands `null` — and discards a suppression count it had already measured |
| 13f | #85 | A capture with zero readable packets fails after **63 s**, and for truncated input contradicts §12 |

### 13a — the vacuous assertion (#87)

**Files:** `tests/integration/test_benign_corpus.py`

`test_no_detection_goes_unreported` claims it would surface a fourth tuple disagreement "as
detections that cannot be placed". Its snapshot holds three rules needing UDP/53 with literal
`flabel-test`, ICMPv4 echo, or ICMPv6 echo; the corpus is HTTP/1.x, HTTP/2, FTP, DNS, MQTT,
DCERPC, Kerberos and SMB. **Measured: 0 detections across all 17 captures.** No tuple is ever
compared.

A second module-scoped fixture with a *loud* snapshot fixes it. Measured with `alert tcp …
flow:established` + `alert udp` + `alert icmp`: **693 detections across the 17 captures, 0
unmatched** — including HTTP/2 (123 over 5 flows), SMB (281), Kerberos (33 over 6 flows), FTP
(109). Costs one extra pipeline run per capture; taken deliberately, because this is the test that
would have caught #84 on day one.

**Test that proves it:** the loud run asserts `detections > 0` per capture *and* `unmatched == 0`.
The first half is what stops it silently reverting to `0 == 0`.

### 13b — atomic output (#70)

**Files:** `src/flabel/labels.py` or `src/flabel/cli.py`, `tests/test_cli.py`

Write to a temporary file in the run directory, `os.replace` into place. §13 says either a complete
run directory exists or none does; a process killed mid-write currently leaves a truncated JSON
document that parses as neither.

**Test that proves it:** a write interrupted after the temporary file exists leaves **no**
`labels.json`, and the temporary file is not mistaken for one by the reproducibility gate's
directory scan.

### 13c — a backwards clock must not cost the report (#62)

**Files:** `src/flabel/provenance.py`, `docs/spec.md` §10, `tests/test_provenance.py`

`_duration()` raises when `finished_at < started_at`. The caller is `datetime.now(UTC)` at two
points in real time, so an NTP step, a VM resume or a container clock adjustment makes that
legitimately negative — and `build_run_block` then raises while step 9 is assembling the report,
losing `run.json` entirely. On a long run, which is when a correction is most likely and when
losing the report costs most.

`duration_seconds` becomes `null` with a warning in `warnings[]` — this module's own convention for
a fact it could not establish. **A programming error and an environmental one were being treated
identically**, and the environmental one cost the file.

**Test that proves it:** a backwards pair yields `duration_seconds: null`, a warning naming both
timestamps, and a **written** `run.json`. This is the third defect of this exact shape (after
`UnicodeDecodeError` escaping `read_toolchain` and `snapshot_missing` inference); the assertion is
that the file exists, not merely that no exception escaped.

### 13d — correlation losses must reach the run block (#57)

**Files:** `src/flabel/models.py`, `src/flabel/correlate.py`, `src/flabel/cli.py`,
`docs/spec.md` §9/§10, `tests/test_correlate.py`

Every sibling stage returns warnings; `CorrelationResult` does not, so the gate's own warning
reaches stderr and nothing else. An operator reading `run.json` after the fact — the normal case,
since stderr is not kept — cannot see that anything was warned about.

**Test that proves it:** a run with unmatched detections below the threshold carries the warning in
`run.warnings[]`, not only on stderr. Redirect stderr in the test so passing by accident is
impossible.

### 13e — a failed stage must not publish numbers it never measured (#86)

**Files:** `src/flabel/models.py`, `src/flabel/suricata.py`, `src/flabel/provenance.py`,
`tests/test_suricata.py`

`_failed()` returns `rules_loaded=0, alerts_total=0, identify_alerts_suppressed=0`, so `counts`
publishes zeros and `loss_conditions` reports `rules_failed_or_skipped: false` and
`identify_alert_suppressed: false`. §10: *"every field whose stage did not run is `null` — not
zero, not an empty list."*

Two distinct wrongs, and the second is worse: `_read_eve` runs **before** `_check_ruleset_loaded`
and does compute `suppressed`, so a run that suppressed 40 `identify` alerts throws that measured
number away and reports `0`. The count fields become `int | None`; a measured value survives a
later failure.

**Test that proves it:** a Suricata failure after eve parsing preserves the suppression count it
measured, and reports `null` — not `0` — for what it never established. Asserted through
`run.json`, because the existing test asserts only `loss_conditions.tool_failure is True`.

### 13f — zero readable packets (#85)

**Files:** `src/flabel/ingest.py`, `docs/spec.md` §8/§12, `tests/test_ingest.py`,
`tests/integration/test_canaries.py`

Three inputs reach this state — a valid empty pcap, a pcapng with only SHB+IDB, and a pcap
truncated before its first complete record. Zeek handles all three (§8 blesses "zero connections
writes no conn.log"); Suricata cannot read them and burns its **60-second** thread-start budget
first. Measured: 63.1 s to failure, `run.duration_seconds` 63.04.

**DECIDED (Craig, 2026-08-14): a hard failure, before any tool runs.** `ingest` raises
`CaptureError` on zero usable packets — exit 1, no run directory, a message naming the capture and
the count, in about 0.1 s. Consistent with the unreadable-header case §8 already makes a
`CaptureError`, and with US-05's "writes no labels".

**This amends §12 in writing**, so it is recorded rather than assumed: exit 0 covers partial
*data*, not *zero* data. A capture with no readable packets is not one flabel can label, and
`input_status: partial` on a file with nothing in it asserts a coverage figure over an empty set.
§8 gains the rule that the packet walk decides this before Zeek or Suricata are invoked.

**Test that proves it:** each of the three inputs raises `CaptureError` and creates no run
directory; the failure happens **without invoking Suricata**, asserted on elapsed time being far
below the 60-second budget rather than on a mock, since a mock would encode the assumption under
test.

**Depends on:** nothing. **Blocks:** Phase 1 sign-off.

---

## Definition of done for Phase 1

- All ten steps merged, each behind a green `/project:verify`.
- CI green on `main` with the toolchain container, and **executing** the `requires_tools` tests rather than skipping them.
- Goals 1, 2, 3, 4, and 5 each have a passing automated test.
- `flabel --offline` labels a real public capture end to end.
- The default path prints `Coming Soon (TM)` and exits 3.
- Issue #11 closed with real admitted-rule counts.
