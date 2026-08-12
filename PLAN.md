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

**Why step 1 is first:** the testing decision is *tools real, network stubbed* — Zeek, Suricata, and `editcap` are invoked for real in tests. Until CI can run them, **nothing else is testable**, so this is a hard prerequisite rather than scaffolding to do later.

---

## Step 1 — Toolchain and CI

**Files:** `.github/workflows/ci.yml`, `Dockerfile.toolchain` (or a CI install block), `docs/dev-setup.md`, `.gitignore`

**Changes:** Provide pinned Zeek 6+/8.x, Suricata 8.x, and Wireshark (`editcap`, `capinfos`) to CI, plus the `zeek/foxio/ja4` package via `zkg`. Record exact versions — pinning is a precondition for Goal 2, since reproducibility across unpinned tool versions is meaningless. Document local setup (`brew install zeek suricata wireshark`). Add `.flabel/` to `.gitignore`.

**Test that proves it:** CI runs a job asserting `zeek --version`, `suricata --version`, `editcap --version` all succeed and match the pinned versions, then runs `pytest -q`. **CI fails if zero `requires_tools` tests executed** — a skipped integration suite must never look like a passing one.

**Depends on:** nothing. **Blocks:** everything.

---

## Step 2 — Foundations: models, errors, config

**Files:** `src/flabel/models.py`, `src/flabel/errors.py`, `src/flabel/config.py`, `data/sources.toml`, `tests/test_models.py`, `tests/test_config.py`

**Changes:** All frozen dataclasses from spec §4, in one module that imports nothing from the package. Typed exceptions mapped to exit codes (spec §12). Source-registry loader with validation. `data/sources.toml` populated with the ten sources and their authoritative class/basis/licence assignments from spec §5.

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

**Depends on:** 2. **Parallel with:** 3, 5, 6.

---

## Step 5 — Zeek invocation and parsing ⟂

**Files:** `src/flabel/zeek.py`, `data/json-logs.zeek`, `tests/test_zeek.py`

**Changes:** Single invocation `zeek -C -D -r <pcap> json-logs.zeek`. The Zeek script adds JSON log filters for `conn` and `ssl` so one pass yields both TSV (retained) and JSON (parsed) and they cannot disagree. Parse `conn_json.log` into `Flow`, join `ssl_json.log` for `ja4`/`ja4s`/`server_name` on `uid`. Retain all TSV logs; strip the `_json` files from retained output.

**Test that proves it:** on `benign.pcap`, exactly two flows with the expected tuples. **Determinism gate: two runs produce identical `uid`s** — this is the regression test for the verified spike-3 finding, and it fails if `-D` is ever dropped. `packet_filter.log` is confirmed non-reproducible and excluded. A TLS fixture yields a populated `ja4`. Non-zero exit produces a `tool_failures[]` entry rather than an exception escaping.

**Depends on:** 2. **Parallel with:** 3, 4, 6.

---

## Step 6 — Suricata invocation and parsing ⟂

**Files:** `src/flabel/suricata.py`, `tests/test_suricata.py`, `tests/fixtures/rules/synthetic.rules`

**Changes:** Invoke with `-S <snapshot>/rules.rules` so only snapshot rules load and no ambient system ruleset leaks in; `--runmode single` for a deterministic alert set; JA3/JA4 fingerprinting enabled by `--set`. Parse `eve.json` alert records into `Detection`, resolving each SID's originating source from the snapshot manifest. **Drop detections from `identify`-class sources before they can become labels**, counting them.

**Test that proves it:** a synthetic rule matching `benign.pcap` produces exactly one parsed `Detection` with correct sid/rev/classtype/tuple/timestamp. A synthetic **`ja4.hash`** rule matching a TLS fixture also produces a detection — proving the JA4 labelling *capability* independent of whether content exists (US-14). An `identify`-source rule that fires yields **zero** detections and increments `identify_alerts_suppressed` (US-16). Two runs produce the same alert set.

**Depends on:** 2 (and step 4's snapshot writer for a real snapshot; a hand-built snapshot directory suffices to keep them parallel). **Parallel with:** 3, 4, 5.

---

## Step 7 — Correlation ⟂

**Files:** `src/flabel/correlate.py`, `tests/test_correlate.py`

**Changes:** Pure. Tuple match in either direction, time-window disambiguation on multiple candidates, `UnmatchedDetection` with a reason when zero or still-ambiguous. Consolidate to one `Label` per flow with sorted `sources` and `best_tier`. Implement the unmatched gate: silent at zero, warn above zero, fail above the threshold.

**Test that proves it:** synthetic detections and flows only — no tools needed. One flow, one detection → one label. Two detections on one flow → one label with two sources. Port reuse with two candidate flows → resolved by time containment; detection outside both windows → `ambiguous_flow_match`. Tuple absent → `no_flow_match`. Threshold: 1 unmatched in 200 passes, 1 in 50 fails. `best_tier` is the minimum, not the maximum.

**Depends on:** 2. **Parallel with:** 8.

---

## Step 8 — Labels, provenance, NOTICE ⟂

**Files:** `src/flabel/labels.py`, `src/flabel/provenance.py`, `src/flabel/notice.py`, `tests/test_labels.py`, `tests/test_provenance.py`

**Changes:** Build `SourceEntry` values, deriving `label_basis` from source class and carrying `admission_basis` and `licence`. Canonical serialisation per spec §10. Assemble the run block including every loss-condition field. Emit `NOTICE` for sources that actually asserted a label.

**Test that proves it:** canonical output is byte-identical across two serialisations of the same data, and the `labels` array sorts by `(ts_first, uid)` regardless of input order. **Required-fields check: every `SourceEntry` carries every field the spec §4 table demands** — this is the automated form of Goal 1, with no "where applicable" escape. `ioc-name` sources yield `indicator-reference`; all other labelling classes yield `direct`. `NOTICE` lists a GPL/CC-BY source that asserted a label and omits a source that asserted none. Every loss-condition field exists in the run block.

**Depends on:** 2. **Parallel with:** 7.

---

## Step 9 — CLI and orchestration

**Files:** `src/flabel/cli.py`, `tests/test_cli.py`

**Changes:** argparse surface from spec §12 including the `rules` subcommands. Wire ingest → zeek → suricata → correlate → labels into the run directory (`{capture-name}_{datetime}/`). The default path is the `Coming Soon (TM)` stub. Map exceptions to exit codes.

**Test that proves it:** end-to-end `--offline` on `benign.pcap` writes a run directory with `zeek/`, `labels.json`, and `NOTICE`, and exits 0. **The stub path prints `Coming Soon (TM)`, names `--offline`, creates no directory, and exits 3** (US-22). Re-running creates a sibling directory and leaves the first untouched; sorted names are chronological. A hard failure writes **no** `labels.json` — never a partial one. `--ruleset-snapshot nonexistent` exits 1. A labelling run makes no network call (asserted by a socket guard).

**Depends on:** 3, 4, 5, 6, 7, 8.

---

## Step 10 — Canaries and reproducibility gates

**Files:** `tests/integration/test_canaries.py`, `tests/integration/test_reproducibility.py`, `tests/fixtures/README.md`, `.github/workflows/ci.yml`

**Changes:** Wire Goal 5 and Goal 2 into CI as build-failing gates. Source the malicious canary and record its origin and licence.

**Test that proves it:** **benign canary produces zero labels — any label fails the build** (Goal 5, and the standing FP review for every wholesale-admitted source including `pawpatrules`). Malicious canary produces at least one label. **Reproducibility: two full `--offline` runs against the same capture and pinned snapshot are identical after canonicalisation**, excluding only `started_at`/`finished_at`/`duration_seconds` and `packet_filter.log` (Goal 2). Fault-injection test for every Phase 1 loss condition in spec §11.

**Depends on:** 9. **Note:** the malicious canary is the one unresolved input (spec §14); if it slips, the benign canary and reproducibility gates land without it and the sensitivity test follows.

---

## Definition of done for Phase 1

- All ten steps merged, each behind a green `/project:verify`.
- CI green on `main` with the toolchain container, and **executing** the `requires_tools` tests rather than skipping them.
- Goals 1, 2, 3, 4, and 5 each have a passing automated test.
- `flabel --offline` labels a real public capture end to end.
- The default path prints `Coming Soon (TM)` and exits 3.
- Issue #11 closed with real admitted-rule counts.
