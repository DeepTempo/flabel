# Product Requirements Document

|  |  |
| :-: | :-: |
| **Document Title** | flabel — Malicious Flow Labeling for Packet Captures |
| **Author** | Craig |
| **Last Updated** | 2026-08-11 |
| **Status** | Draft |
| **Stakeholders** | TBD — Craig (author/PM). Legal required as approver for the FoxIO License 1.1 / JA4+ question. Remaining reviewers and approvers to be named. |
| **Target Release** | TBD |

## Revision History

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Date** | **Author** | **Version** | **Change Summary** |
| 2026-08-11 | Craig | 0.1 | Initial draft |
| 2026-08-11 | Craig | 0.2 | Output layout changed to sibling run directories named `{capture-name}_{datetime}`; `latest` pointer removed |
| 2026-08-11 | Craig | 0.3 | JA4 labeling moved into phase one as a first-class Tier 2 capability (US-14, US-15); only JA4 *rule content* remains out of scope |

## 1. Problem Statement

Training a network detection model requires labeled flow data: examples of traffic known to be malicious, tied to the flows that carried them. Packet captures are abundant and cheap to collect; **trustworthy labels for them are neither.**

The options available today are each inadequate for the purpose:

- **Manual analyst labeling** produces high-quality verdicts but does not scale to the volume a model needs.
- **Public labeled datasets** are fixed corpora — they cannot label *our* captures, and their labeling methodology is often undocumented or dated.
- **Running an IDS and taking its alerts at face value** scales, but silently inherits every false positive in whatever ruleset happened to be loaded. For training data this is the expensive failure: a false positive teaches the model that benign traffic is malicious, and the error is invisible downstream.

The people affected are the engineers building DeepTempo's detection models, who currently have no repeatable way to turn an arbitrary capture into labels they can defend. The cost of inaction is models trained on ground truth that is either too small to be useful or too noisy to be trusted — and, critically, **no way to tell which**, because label provenance is not recorded.

`flabel` addresses this by processing a capture through detection sources of *known, documented* trust and emitting labels that each carry their origin — the source, the exact rule, and the ruleset snapshot that produced them.

> **Evidence note:** this statement is grounded in the project brief (`docs/prep-n-research.md`) and the Stage 1 research findings, not in customer interviews or support data. Stakeholders should treat the problem framing as internally asserted rather than externally validated.

## 2. Goals

| | Goal | How it is verified |
| :-: | :-- | :-- |
| **Goal 1** | **Every label is traceable to its origin.** A label records its tier, source, the specific rule or signature that fired, and the ruleset snapshot in use. | 100% of emitted labels carry a complete provenance block. Machine-checkable on the output. |
| **Goal 2** | **Runs are reproducible.** The same capture processed with the same ruleset snapshot in `--offline` mode produces identical labels. | Byte-identical `labels.json` across two runs, ignoring run-metadata timestamps. |
| **Goal 3** | **Nothing is lost silently.** Truncated input, packet-count mismatch during replay, and detections that cannot be correlated to a flow are all surfaced in the output. | Every such condition has a corresponding field in the `run` block; zero silent-drop paths. |
| **Goal 4** | **One label per flow.** Detections from multiple tiers against the same flow consolidate into a single entry retaining all asserting sources. | No duplicate flow identity in `labels`. |
| **Goal 5** | **Usable without the lab.** A Tier 2-only run is available and clearly marked as lacking Tier 1 coverage. | `--offline` completes successfully with no NGFW reachable and stamps reduced coverage in the output. |

**Explicitly not a goal:** a measured false-positive rate. Per the trust-by-construction decision (Stage 1), label quality is argued from source provenance and ruleset curation, not measured against a ground-truth corpus. See Risks.

## 3. Non-Goals

- **Not a real-time IDS or IPS.** flabel processes captures after the fact. It never blocks, resets, or otherwise acts on live traffic.
- **Not a TLS decryption or MITM tool.** Encrypted traffic is handled by fingerprint- and certificate-based detection only; decryption is impossible on an after-the-fact capture.
- **Not an assertion of benign.** flabel labels malicious flows. It does not and cannot certify that any flow is safe.
- **Not a general pcap forensics or analysis platform.** Zeek logs are emitted because they are needed for correlation and enrichment, not as a product surface.
- **Not a false-positive measurement system.** flabel does not estimate its own accuracy.
- **No graphical interface.** Command-line only.
- **Not a ruleset authoring tool.** flabel consumes third-party rulesets; it does not write detection rules.

## 4. Out of Scope

|  |  |  |
| :-: | :-: | :-: |
| **Item** | **Reason** | **Future Phase?** |
| Label validation against a ground-truth corpus | Trust-by-construction decided at Stage 1; trustworthiness argued from provenance | TBD — flagged for eng-review |
| JA4 *rule content* — a source of malicious JA4 fingerprints | No admitted source publishes `ja4.hash` rules today, and no free maintained JA4 verdict feed exists. **The JA4 labeling capability itself is in phase one** (§6.3) — only the content is missing | Content only. The capability ships in v1 and begins producing labels the moment any admitted source publishes JA4 rules, with no code change |
| Snort 3 as the Tier 2 engine | Suricata selected on free high-confidence ruleset volume and native fingerprint keywords | No |
| FortiGate as the NGFW | PANW VM-Series selected as Tier 1 | No |
| Free/OSS L7 equivalent to PANW App-ID | No free equivalent exists; line of inquiry closed | No |
| Paid rulesets (ET Pro ~$900/sensor/yr, Secureworks, Stamus) | Free sources with a 30-day delay are acceptable for v1 | TBD — revisit if free-source coverage proves inadequate |
| Government-published rule feeds | No agency publishes a maintained general-purpose ruleset; advisory signatures are point-in-time IOCs with no cadence | No |
| Positive Technologies rulesets | Non-standard licence and vendor under US sanctions since 2021 | No |
| PANW tap-mode deployment | Virtual-wire pair selected; avoids the unresolved question of whether tap forfeits detections | No |
| Benign / negative-class labels | flabel cannot assert benign; absence of a label is not a verdict | No |
| `abuse.ch` SSLBL JA3 fingerprint feed | Abandoned — newest entry 2021-08-03, self-declared untested FP posture | No |

## 5. Background & Context

**Prior work.** Stage 1 research (`docs/research.md`, driven by `docs/research-brief.md`) evaluated detection sources, rulesets, fingerprinting methods, and replay mechanics. The original design brief is `docs/prep-n-research.md`. Three research findings changed the design as originally conceived:

1. **Only PANW requires replay.** Suricata and Zeek read capture files natively. The original design sent all traffic through the inline device; confining replay to the one source that needs it removes the largest source of label nondeterminism from the Tier 2 path.
2. **The canonical free JA3 feed is abandoned**, but ET Open independently maintains its own JA3 ruleset — actively updated through 2026, carrying per-rule confidence metadata, MIT-licensed. Fingerprint detection therefore belongs in Tier 2 as ordinary Suricata rule content, matched via Suricata's native `ja3.hash` / `ja4.hash` keywords.
3. **pcapng cannot be fed directly to Zeek at all**, and only partially to Suricata. Since pcapng is Wireshark's default output, an input normalization stage is mandatory rather than optional.

**Trust model.** Trust is assigned **per source**, not per rule. Tier 1 is PANW VM-Series; Tier 2 is Suricata with a curated, admission-filtered ruleset set. Because trust is not modeled per rule, **ruleset curation is the entire false-positive defence** — which is why the admission filter and its per-run snapshot are product requirements, not implementation details.

**Environment.** A GCP lab is a v1 requirement: a host running flabel, a PANW VM-Series in virtual-wire configuration, and a Suricata host, with millisecond clock synchronization across all three.

## 6. Feature Description

### 6.1 Capture Ingest & Normalization

**Description:** Accepts a capture file, determines its true format, and normalizes it to a single artifact that every downstream consumer reads identically.

**Key Business Rules / Logic:**

- Accepted inputs: `pcap`, `pcapng`, and gzip-compressed variants of both.
- pcapng is normalized to pcap via `editcap -F pcap`. Multi-datalink captures are split before conversion.
- All three consumers (Zeek, Suricata, replay) receive the **same normalized file**, so they cannot disagree about the input.
- A capture whose header is unreadable is a **hard failure** — no labels are emitted.
- A capture that is **truncated** (readable prefix, incomplete tail) is processed, and the output is stamped `input_status: partial` with the packet count reached and the truncation offset.
- The normalization performed is recorded in run provenance, because a converted capture is not the original artifact.

### 6.2 Zeek Processing & Fingerprint Enrichment

**Description:** Runs Zeek over the normalized capture to produce flow logs and TLS fingerprints. Zeek's `uid` is the authoritative flow identity for the entire system.

**Key Business Rules / Logic:**

- All Zeek logs generated for the capture are retained in the output.
- JA4 (and JA4+, subject to the licence decision) is computed for every TLS connection via the `zeek/foxio/ja4` package.
- **A computed fingerprint is an attribute, not a verdict.** Zeek's JA4 output never produces a label by itself. Labels arise only where a fingerprint **matches an admitted rule**, which happens in the Tier 2 path (§6.3) — the same way every other detection is produced.
- Zeek `uid` is assigned to every flow and becomes the join key between `labels.json` and the Zeek logs.

### 6.3 Tier 2 Detection — Suricata

**Description:** Runs Suricata offline against the normalized capture using a curated, admission-filtered ruleset, producing Tier 2 detections. This path requires no lab and is fully deterministic.

**Key Business Rules / Logic:**

- **Per-source admission policy.** Signature rulesets (ET Open) are filtered on rule metadata: `confidence == High` **and** `signature_severity in (Major, Critical)`. IOC feeds (abuse.ch, malsilo, and similar) carry no such metadata and are admitted wholesale, with the feed snapshot date as their provenance.
- Rules lacking a `confidence` tag are **excluded** (fail-closed).
- Excluded sources: hunting/anomaly rulesets, self-described aggressive blacklists, and Positive Technologies.
- **Encrypted-traffic detection is part of this tier, and both fingerprint families are first-class in phase one.** Suricata's native `ja3.hash` **and** `ja4.hash` matching are both enabled, and JA4 rules pass through the identical per-source admission filter and snapshot provenance as any other rule.
- **JA4 has the capability but not yet the content.** No admitted source currently publishes `ja4.hash` rules, so JA4 label output will be zero on release. This is a *content* gap, not a capability gap: when any admitted source ships JA4 rules, they are picked up and produce labels with **no code change**. The path is therefore built, enabled, and tested in v1 rather than deferred.
- Because an inactive path is indistinguishable from a broken one, **the run records how many JA4 rules were admitted.** A zero count proves the path ran and found no content, rather than leaving silence to be misread as either working or failing.
- **The admitted rule set is snapshotted per run** — source, version, and date — because filter output changes as vendors revise metadata. Without this, two runs of "the same" flabel are not comparable.

### 6.4 Tier 1 Detection — PANW VM-Series

**Description:** Replays the normalized capture past a PANW VM-Series in virtual-wire configuration, then retrieves the resulting threat detections.

**Key Business Rules / Logic:**

- Replay runs at a **controlled rate**. `--topspeed` is prohibited: it trades timing accuracy for speed, and distorted timing can suppress stateful and rate-based detections.
- **Packets sent are reconciled against packets seen by the device.** A mismatch is a fidelity failure and is surfaced, because a dropped packet is a *missing* label — invisible unless reported.
- Threat logs are retrieved via the PAN-OS API, with the query **bounded by the replay window** and results **matched by flow tuple**. Time scopes the query; the tuple performs the match.
- Detections are stamped at replay time, not capture time. Labels reference the **capture's** timeline; replay time is never emitted as a label timestamp.
- Requires millisecond clock synchronization between flabel and the firewall.

### 6.5 Consolidation & Correlation

**Description:** Merges Tier 1 and Tier 2 detections into one label per flow, resolving each to a Zeek flow identity.

**Key Business Rules / Logic:**

- **One entry per flow.** A flow flagged by multiple tiers yields a single entry whose `sources[]` array retains every asserting detection.
- `max_tier` records the highest-trust source that asserted the flow, so consumers can filter by trust without walking the array.
- A detection that **cannot be correlated** to any flow is emitted in a separate `unmatched_detections[]` block with a reason and the raw device fields. It is never silently dropped and never guessed into a flow.
- The count of unmatched detections is surfaced in run metadata as a correlation-health signal.

### 6.6 Output & Provenance

**Description:** Writes Zeek logs and `labels.json` to a per-run directory named after the capture and the run time, with complete provenance for the run.

**Key Business Rules / Logic:**

- Output layout — **each run writes its own top-level directory named `{capture-name}_{datetime}`**, so runs of the same capture are siblings and a re-run never destroys prior labels:

```
my-capture_2026-08-11T213045Z/
├── zeek/            # all Zeek logs
└── labels.json

my-capture_2026-08-12T091500Z/
├── zeek/
└── labels.json
```

- **Directory naming rules:**
  - `{capture-name}` is the input filename with its extension stripped, including a trailing `.gz` (`my-capture.pcap.gz` → `my-capture`). Characters unsafe in a path are replaced.
  - `{datetime}` is the run start in UTC, ISO-8601 with no colons — `2026-08-11T213045Z` — so the name is filesystem-safe on every platform.
  - Because ISO-8601 sorts lexicographically, a plain sort of `{capture-name}_*` is also a chronological ordering, and the newest run is the last entry.
- **No `latest` pointer.** A `{capture-name}_latest` symlink would be matched by the same `{capture-name}_*` glob used to enumerate runs, so it would corrupt iteration. Consumers needing the newest run sort and take the last.
- `labels.json` contains **malicious flows only.** An unlabeled flow is *unlabeled*, not verified benign — this distinction is stated in the output schema itself so it cannot be lost downstream.
- A capture with zero detections is a **successful run** producing an empty `labels` array, not an error.
- Every run records: input file identity and status, normalization applied, ruleset snapshots per source, tool versions, tiers attempted, and coverage actually achieved.
- `labels.json` carries a **schema version**, so consumers can detect shape changes rather than silently mis-parsing.

**Label entry shape:**

```json
{
  "flow": {
    "uid": "CHhAvVGS1DHFjwGM9",
    "src_ip": "10.0.0.5", "src_port": 49152,
    "dst_ip": "203.0.113.10", "dst_port": 443,
    "proto": "tcp",
    "ts_first": "...", "ts_last": "..."
  },
  "verdict": "malicious",
  "max_tier": 1,
  "sources": [
    { "tier": 1, "source": "panw", "threat": "...", "detected_at": "..." },
    { "tier": 2, "source": "suricata", "sid": 2028831, "rev": 1,
      "ruleset": "et-open@2026-08-11", "confidence": "High", "threat": "..." }
  ]
}
```

### 6.7 CLI & Run Modes

**Description:** A single command processes a capture end to end.

**Key Business Rules / Logic:**

- `flabel <capture>` is the primary invocation. Tier 1 (NGFW) is **required by default**; if the lab is unreachable, the run fails rather than silently producing partial coverage.
- `--offline` runs Tier 2 only, completing without any lab, and **stamps the output as lacking Tier 1 coverage.**
- Exit codes distinguish success, partial-input success, and failure, so the tool is usable in a pipeline.
- Progress and warnings go to stderr; machine-readable output goes to files, never stdout-mixed.

## 7. User Stories

Personas: **DME** = DeepTempo detection-model engineer (primary consumer of labels). **OPS** = lab/platform operator (provisions and maintains the environment).

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **ID** | **Priority** | **User Story** | **Notes** |
| US-01 | P0 | As a DME, I want to run one command against a capture and get Zeek logs plus a malicious-flow label file, so that I can turn raw captures into training data without manual analysis. | Core capability |
| US-02 | P0 | As a DME, I want every label to record the source, rule, and ruleset snapshot that produced it, so that I can defend or audit any individual label later. | Goal 1 |
| US-03 | P0 | As a DME, I want each label to join directly to the Zeek flow record, so that I can extract features for the labeled flow. | Zeek `uid` |
| US-04 | P0 | As a DME, I want a flow flagged by several sources to appear once with all sources listed, so that I don't have to deduplicate before training. | One entry per flow |
| US-05 | P0 | As a DME, I want to know when a run's coverage was incomplete — truncated input, dropped packets, uncorrelated detections — so that I don't train on a label set I believe to be complete when it isn't. | Goal 3 |
| US-06 | P0 | As a DME, I want re-running a capture to preserve the previous run's output, so that I can compare label sets across ruleset snapshots. | Sibling run dirs, `{capture}_{datetime}` |
| US-07 | P0 | As an OPS, I want the same capture and ruleset snapshot to yield identical labels, so that I can verify the pipeline is behaving deterministically. | Goal 2; `--offline` |
| US-08 | P1 | As an OPS, I want an `--offline` mode that runs without the NGFW, so that I can process captures and test the pipeline when the lab is unavailable. | Marked reduced coverage |
| US-09 | P1 | As a DME, I want pcapng and gzipped captures accepted directly, so that I can use files as they come off Wireshark or a sensor without pre-processing. | Normalization |
| US-10 | P1 | As a DME, I want JA4 fingerprints recorded on TLS flows, so that I can use them as model features and pivot on them during analysis. | The enrichment half — Zeek-computed attributes, no verdict |
| US-14 | P0 | As a DME, I want a JA4 fingerprint matching an admitted rule to produce a Tier 2 label, so that encrypted-traffic detections are labelled by the same machinery as every other detection and need no rework when JA4 rule content becomes available. | The labeling half. Capability ships in v1; content arrives later |
| US-15 | P1 | As an OPS, I want the run to record how many JA4 rules were admitted, so that I can tell "no JA4 content published yet" apart from "the JA4 path is broken". | Guards against the capability silently rotting |
| US-11 | P1 | As an OPS, I want the ruleset admission filter and its results recorded per run, so that I can see exactly which rules were live and how many were excluded. | Ties to issue #11 |
| US-12 | P2 | As an OPS, I want a documented environment diagram in draw.io and mermaid form, so that the lab can be rebuilt or handed over. | From the brief |
| US-13 | P2 | As a DME, I want `labels.json` to carry a schema version, so that a shape change breaks loudly rather than silently. | Forward compatibility |

## 8. UX Requirements

**Key Workflows:**

- **Label a capture (default).** `flabel capture.pcap` → normalize → Zeek + Suricata + PANW replay → consolidate → write run directory. Fails clearly if the lab is unreachable.
- **Label without the lab.** `flabel --offline capture.pcap` → Tier 2 only → output stamped as reduced coverage.
- **Compare across ruleset snapshots.** Re-run the same capture; each run lands in its own sibling directory named `{capture-name}_{datetime}`; sorting the set gives them in chronological order.
- **Inspect a label.** Read a label's `sources[]`, then join its `flow.uid` to `zeek/conn.log` for the full flow record.

**Design Constraints / Guidelines:**

- Command-line only; no GUI, no daemon, no service.
- One capture per invocation. Batch processing is the caller's job (shell loop, pipeline).
- Human-readable progress and warnings to **stderr**; all machine-consumable output to files. Never interleave the two.
- Failures state what went wrong, which stage it happened in, and what would fix it.
- Silence is never used to signal a problem. Absent coverage is always explicitly reported.

**Accessibility Requirements:**

- No information conveyed by colour alone; any colour is decorative and the text stands without it.
- Output remains fully legible when redirected to a file or read by a screen reader (no cursor-control or spinner-dependent rendering).
- Distinct, documented exit codes: success, success-with-partial-input, failure.
- All output UTF-8.

**Prototype / Mockup Links:**

- N/A — command-line tool, no visual design surface.

## 9. Acceptance Criteria

### US-01: Label a capture end to end

- Given a valid pcap and a reachable lab, when `flabel my-capture.pcap` runs, then a directory named `my-capture_{datetime}` is created containing `zeek/` with the Zeek logs and `labels.json`.
- Given an input named `my-capture.pcap.gz`, when the run completes, then the output directory is named `my-capture_{datetime}` — both extensions stripped — and its `{datetime}` contains no colons.
- Given a capture containing no detectable threats, when the run completes, then `labels.json` exists with an empty `labels` array and the run is reported as successful.
- Given the NGFW is unreachable and `--offline` was not passed, when flabel runs, then it fails with a message naming the unreachable Tier 1 dependency, and no partial label file is written.

### US-02: Label provenance

- Given any emitted label, when its `sources[]` entries are inspected, then each records tier, source, the firing rule identity where applicable, and the ruleset snapshot identifier.
- Given a completed run, when the run metadata is inspected, then it lists every ruleset source with its version and snapshot date, plus the versions of Zeek, Suricata, and flabel.

### US-03: Join to Zeek

- Given a label with `flow.uid`, when that uid is looked up in `zeek/conn.log`, then exactly one matching flow record exists.
- Given a Tier 1 detection correlated to a flow, when its label is written, then the label carries the Zeek `uid` for that flow, not only the tuple.

### US-04: One entry per flow

- Given a flow flagged by both Tier 1 and Tier 2, when labels are written, then exactly one entry exists for that flow, its `sources[]` contains both detections, and `max_tier` is 1.
- Given the full `labels` array, when flow identities are compared, then no flow identity appears more than once.

### US-05: Incomplete coverage is visible

- Given a truncated capture, when the run completes, then `input_status` is `partial` and the packet count reached is recorded.
- Given a replay where packets seen by the device differ from packets sent, when the run completes, then the discrepancy is reported and the run is not presented as full-coverage.
- Given a detection that cannot be correlated to any flow, when labels are written, then it appears in `unmatched_detections[]` with a reason, and the unmatched count appears in run metadata.
- Given a capture whose header is unreadable, when flabel runs, then it fails and writes no labels.

### US-06: Re-runs preserve history

- Given a capture already processed, when flabel runs against it again, then a new sibling directory `{capture-name}_{datetime}` is created and the previous run directory is unmodified.
- Given two or more run directories for the same capture, when their names are sorted lexicographically, then they appear in chronological order and the last is the most recent.

### US-07: Reproducibility

- Given the same capture, the same ruleset snapshot, and `--offline`, when flabel runs twice, then the two `labels.json` files are identical apart from run-metadata timestamps.

### US-08: Offline mode

- Given no reachable lab, when `flabel --offline capture.pcap` runs, then it completes successfully, emits Tier 2 labels, and the output records that Tier 1 was not attempted.
- Given an `--offline` run, when the output is inspected, then no label claims a Tier 1 source.

### US-09: Format handling

- Given a pcapng capture, when flabel runs, then it is normalized to pcap, processed successfully, and the conversion is recorded in provenance.
- Given a gzipped capture, when flabel runs, then it is decompressed and processed.
- Given a pcapng capture containing multiple link-layer types, when flabel runs, then it is split before conversion and processed without error.
- Given any accepted input, when the run completes, then Zeek, Suricata, and the replay all processed the identical normalized file.

### US-10: Fingerprint enrichment

- Given a capture containing TLS connections, when the run completes, then JA4 values are present on those flows in the Zeek output.
- Given a JA4 value that matches no admitted rule, when labels are written, then no label is produced from that fingerprint — a computed fingerprint alone is never a verdict.

### US-14: JA4 labeling capability

- Given an admitted ruleset containing a `ja4.hash` rule, when a capture contains a TLS flow whose JA4 matches it, then a Tier 2 label is produced carrying that rule's identity, ruleset snapshot, and confidence — structurally identical to any other Tier 2 label.
- Given JA4 rules are present in an admitted source, when the run executes, then Suricata JA4 fingerprinting is active rather than silently skipped.
- Given a JA4-matched label, when it is inspected, then it is indistinguishable in shape from a JA3- or content-matched Tier 2 label, requiring no special handling by consumers.

### US-15: JA4 content visibility

- Given no admitted source publishes JA4 rules, when the run completes, then run metadata records the JA4 rule path as active with an admitted JA4 rule count of zero.
- Given an admitted source begins publishing JA4 rules, when the next run executes, then those rules are admitted and counted with no change to flabel's code or configuration.

## 10. Technical Considerations

**Architecture / System Design Notes:**

- **Hybrid ingest (Approach B).** Zeek and Suricata read the capture file directly; only PANW receives a replay. This confines replay-fidelity and clock-correlation risk to the Tier 1 path and makes Tier 2 deterministic — and makes `--offline` a natural consequence of the architecture rather than a special case.
- PANW deployed as a **virtual-wire pair**, per Palo Alto's replay guidance, not tap mode.
- Correlation is **tuple-driven**, with the replay window only scoping the API query. Replay-time stamps are never emitted as label timestamps.
- Fingerprint matching uses Suricata's native `ja3.hash` / `ja4.hash` keywords, so encrypted detection needs no separate engine and inherits Tier 2's filtering and provenance.
- Stack: Python 3.12, uv, pytest, ruff. Test-first development.

**Dependencies (internal and external):**

- **External tools:** Zeek 6+ (with `zeek/foxio/ja4`), Suricata 8+ (with `ja3`/`ja4` fingerprinting enabled), tcpreplay, Wireshark `editcap`.
- **External services:** PAN-OS API on the VM-Series; ruleset and IOC feed endpoints (ET Open, abuse.ch, and the other admitted sources).
- **Infrastructure:** GCP lab — flabel host, PANW VM-Series, Suricata host; NTP with millisecond accuracy across all three. **The lab is a v1 requirement.**
- **Licensing:** plain JA4 is BSD 3-Clause. The **JA4+ suite is FoxIO License 1.1 (non-commercial)** — approved for use pending Legal's assessment, since flabel output feeds product models. This is a blocking external dependency on Legal, not an engineering task.

**Data & Privacy Considerations:**

- **Captures contain real network traffic** and may include personal data, credentials in cleartext protocols, internal addressing, and business-sensitive content. Zeek logs derived from them include URLs, DNS queries, and certificate details.
- The repository is **public**. Captures, Zeek logs, `labels.json` outputs, device credentials, and internal identifiers must never be committed. `.gitignore` already excludes `*.pcap`, `*.pcapng`, `*.log`, `zeek/`, and `.env`.
- Test fixtures must not embed real capture data. A fixture strategy is required (synthetic or explicitly-licensed public captures) — tracked as part of scaffold.
- Device credentials and the GCP project identifier live in a gitignored `.env`; committed files reference them only as `${VAR}`.
- Labels and Zeek logs are derived data and inherit the sensitivity of their source capture. Retention and handling are the operator's responsibility; flabel does not transmit capture data anywhere outside the lab.

**Performance / Scale Requirements:**

- Tier 1 throughput is bounded by the controlled replay rate, deliberately: fidelity is preferred over speed. Wall-clock for a run is therefore at least the replay duration.
- Tier 2 and Zeek run at file-read speed and are the fast path; `--offline` runs are substantially quicker than full runs.
- One capture per invocation; no concurrency requirement within a run.
- **Concurrent runs against one device are unsafe** without coordination, since overlapping replay windows would make Tier 1 log queries ambiguous. Serialization is required — mechanism TBD at spec.
- No target maximum capture size is set for v1; behaviour on very large captures is an open question.

## 11. Success Metrics

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Metric** | **Target** | **How Measured** | **Review Date** |
| Provenance completeness | 100% of labels carry tier, source, rule identity (where applicable), and ruleset snapshot | Automated check over `labels.json` in CI and per run | TBD |
| Reproducibility | 100% — identical `labels.json` across two `--offline` runs with a pinned snapshot | Regression test diffing two runs, ignoring run timestamps | TBD |
| Silent-loss paths | Zero | Code review plus tests asserting every loss condition surfaces in the `run` block | TBD |
| Replay integrity | Packets sent equal packets seen, or the discrepancy is reported | Per-run reconciliation; failure surfaced, never suppressed | TBD |
| Unmatched detection rate | Tracked and reported; no target set for v1 | Per-run `unmatched_count`; trend reviewed as capture volume grows | TBD |
| Supported-format success rate | 100% of pcap, pcapng, and gzipped inputs process or fail with a clear reason | Test matrix across format variants | TBD |
| Tier 2 admitted-rule count | Recorded per source, **including a separate JA4 rule count** | Measured at build time (issue #11); JA4 count surfaced in run metadata every run | TBD |

**Note:** these metrics measure *pipeline integrity*, not *label accuracy*. Under trust-by-construction there is no measurement of false-positive rate — see Risks.

## 12. Risks & Mitigations

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Risk** | **Likelihood** | **Impact** | **Mitigation** |
| Replay infidelity silently drops labels, and a missing label is invisible in the output | Med | High | `--topspeed` prohibited; controlled-rate replay; sent-vs-seen packet reconciliation surfaced per run; repeat-run detection diffing; Tier 2 kept off the replay path entirely |
| Trust-by-construction is unfalsifiable — no false-positive rate can be quoted if a label consumer asks | High | High | Ruleset snapshots recorded per run so labels are reproducible and auditable even if unmeasured; fail-closed admission filter; flagged for eng-review reconsideration |
| Tier 1 detections cannot be correlated to capture flows (port reuse, NAT, tunnelling) | Med | Med | Tuple-driven matching with time only scoping the query; uncorrelated detections emitted in `unmatched_detections[]` rather than dropped or guessed |
| Fingerprint verdicts drift as benign software adopts a fingerprint, silently invalidating a verdict | Med | Med | Fingerprint verdicts sourced through ET rules rather than raw feeds, so vendor revisions carry the aging burden; ruleset snapshot dates recorded |
| The JA4 labeling path ships with no rule content, so it appears functional while producing nothing — and may quietly rot untested | Med | Med | Admitted JA4 rule count surfaced in run metadata every run, so zero content is visible rather than assumed; the path is tested against a synthetic JA4 rule so the capability is proven independent of content availability; sourcing tracked as a live issue rather than a future phase |
| Admission filter proves too strict, leaving Tier 2 coverage too thin to be useful | Med | Med | Admitted-rule counts measured per source (issue #11); untagged-rule policy revisitable (issue #10); paid high-fidelity rulesets remain a costed fallback |
| JA4+ licensing (FoxIO 1.1, non-commercial) conflicts with output feeding product models | Med | High | Legal engaged as an approver; plain JA4 is BSD 3-Clause and available as an unrestricted fallback |
| Capture data or credentials leak into the public repository | Low | High | `.gitignore` coverage for captures, logs, and `.env`; no real capture data in fixtures; pre-commit secret checks |
| Lab environment build slips and blocks all Tier 1 work | Med | Med | `--offline` mode delivers Tier 2 labels with no lab; environment build tracked as explicit plan and build steps |
| Clock drift beyond millisecond breaks Tier 1 log correlation | Low | Med | NTP across all hosts; correlation designed to survive drift by matching on tuple rather than time |

## 13. Open Questions

|  |  |  |  |  |
| :-: | :-: | :-: | :-: | :-: |
| **\#** | **Question** | **Owner** | **Target Date** | **Resolution** |
| 1 | Who are the PRD stakeholders — reviewers and approvers beyond Craig and Legal? | Craig | TBD | Open |
| 2 | What is the target release for v1? | Craig | TBD | Open |
| 3 | Does Legal approve JA4+ under FoxIO License 1.1 given output feeds product models, or do we restrict to plain JA4? | Legal | TBD | Open — blocking 6.2 scope |
| 4 | What is the admitted-rule count per source once the admission filter is applied, and is Tier 2 coverage adequate? | Craig | At build | Open — issue #11 |
| 5 | How are concurrent runs against a single PANW device serialized, given overlapping replay windows make log queries ambiguous? | TBD | At spec | Open |
| 6 | Is there a maximum supported capture size, and what is the behaviour beyond it? | Craig | At spec | Open |
| 7 | Does the PANW threat log need a settling delay before querying, and what is the exact bounded-`receive_time` filter syntax? | TBD | At spec | Open — on-device verification |
| 8 | What fixture strategy provides test captures without committing real traffic? | TBD | At scaffold | Open |
| 9 | Should `pawpatrules` remain admitted without an FP review, being the least-vetted admitted source? | Craig | At spec | Open |
| 10 | What are the review dates for the success metrics? | Craig | TBD | Open |
| 11 | Where does JA4 rule content come from — wait for ET to publish, evaluate a commercial feed, or derive our own from malware captures? The capability ships in v1 regardless; this decides when it starts producing labels. | Craig | Post-v1 | Open — tracked as a live issue |

15. Basic Test Cases

|  |  |  |  |  |
| :-: | :-: | :-: | :-: | :-: |
| **\#** | **Case** | **Expected Behavior** | **Observed Behavior** | **Pass/Fail** |
| 1 | Valid pcap, lab reachable | Directory `{capture-name}_{datetime}` created with `zeek/` and `labels.json` | | |
| 2 | Capture with no detections | Success; `labels` is an empty array | | |
| 3 | pcapng input | Normalized to pcap, processed, conversion recorded in provenance | | |
| 4 | Gzipped pcap input | Decompressed and processed | | |
| 5 | pcapng with multiple link-layer types | Split before conversion; processed without error | | |
| 6 | Capture with unreadable header | Hard failure; no labels written | | |
| 7 | Truncated capture | Processed; `input_status: partial` with packet count reached | | |
| 8 | Flow flagged by both Tier 1 and Tier 2 | Single entry; both entries in `sources[]`; `max_tier` = 1 | | |
| 9 | Detection uncorrelatable to any flow | Appears in `unmatched_detections[]` with reason; counted in run metadata | | |
| 10 | Re-run of an already-processed capture | New sibling directory; prior run untouched; sorted names are chronological | | |
| 11 | Two `--offline` runs, pinned snapshot | `labels.json` identical apart from run timestamps | | |
| 12 | `--offline` with no lab reachable | Succeeds; Tier 2 labels only; output records Tier 1 not attempted | | |
| 13 | Default run with lab unreachable | Fails naming the Tier 1 dependency; no partial label file | | |
| 14 | Replay with packet-count mismatch | Discrepancy reported; run not presented as full coverage | | |
| 15 | TLS capture | JA4 present on TLS flows in Zeek output; no label from fingerprint alone | | |
| 17 | Synthetic `ja4.hash` rule matching a capture's TLS flow | Tier 2 label produced, structurally identical to a JA3 or content match, carrying rule identity and snapshot | | |
| 18 | No admitted source publishes JA4 rules | Run metadata records JA4 path active with admitted JA4 rule count of zero | | |
| 16 | Every emitted label | Complete provenance block; `flow.uid` resolves to exactly one `conn.log` record | | |

## 14. References & Related Documents

- [`docs/research.md`](research.md) — Stage 1 research findings and decisions
- [`docs/research-brief.md`](research-brief.md) — approved research brief (Stage 1 gate)
- [`docs/prep-n-research.md`](prep-n-research.md) — original design brief
- [`docs/status.yaml`](status.yaml) — pipeline state and stage issue mapping
- [OISF suricata-intel-index](https://github.com/OISF/suricata-intel-index/blob/master/index.yaml) — rule source licences and provenance
- [Signature Metadata — Emerging Threats wiki](https://community.emergingthreats.net/t/signature-metadata/96) — `confidence` / `signature_severity` definitions
- [JA3/JA4 Keywords — Suricata docs](https://docs.suricata.io/en/latest/rules/ja-keywords.html)
- [FoxIO License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) — JA4+ commercial-use terms
- [Retrieve Logs — PAN-OS XML API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs)
- GitHub issues [#10](https://github.com/DeepTempo/flabel/issues/10) (untagged ET rules) and [#11](https://github.com/DeepTempo/flabel/issues/11) (admission-filter measurement)
