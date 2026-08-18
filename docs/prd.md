# Product Requirements Document

|  |  |
| :-: | :-: |
| **Document Title** | flabel — Malicious Flow Labeling for Packet Captures |
| **Author** | Craig |
| **Last Updated** | 2026-08-15 |
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
| 2026-08-15 | Craig | 0.5 | **Two divergences recorded at Phase 1 sign-off, rather than left implicit.** §6.6: `classtype` is **nullable**, not required — the code and spec §4 always made it so, and read literally that meant Goal 1 was unmet (#89). §6.2 / §9 / §6.6: US-14's **JA4 cross-check is deferred alongside #13** — it shipped unimplemented, and is a precondition for admitting JA4 rule content rather than a Phase 1 gate (#90). Neither is a change of behaviour; both are the document catching up with what was built and argued for. |
| 2026-08-11 | Craig | 0.4 | **Phased delivery.** Phase 1 is Tier 2 (open-source) screening only; Tier 1 (PANW NGFW) moves to Phase 2 as an immediate follow-on. The CLI contract is fixed now — the NGFW-inclusive default is retained and stubbed with `Coming Soon (TM)`, `--offline` is retained as the Phase 1 working path, and Phase 2 adds no flags. Incorporates `docs/eng-review.md`: ruleset snapshots become first-class artifacts, verdict vs non-verdict source classification, `label_basis`, canonical output form, enumerated loss conditions, specificity canary goal, and per-source licence attribution. `max_tier` renamed `best_tier`. |
| 2026-08-15 | Craig | 0.6 | **Goal 5's real review is a split, and §6.3 described only the stronger half.** The benign canary that runs on every build is three synthetic rules and reviews none of the wholesale-admitted ruleset; the real review is a daily `schedule:` GitHub disables after 60 days of repository inactivity. §6.3 now states the split, and `ci.yml` refuses a push when that review has not succeeded lately (#88). |

## Phasing

This PRD covers both phases in one document because they share a schema, an architecture, and a trust model. Splitting them would duplicate those and let the two drift apart.

| Phase | Contents | Lab required |
| :-: | :-- | :-: |
| **Phase 1** | Ingest normalization, Zeek processing and fingerprint enrichment, **Tier 2 detection (Suricata)**, consolidation, output and provenance, CLI. Run via `--offline`; the NGFW-inclusive default is a `Coming Soon (TM)` stub | **No** |
| **Phase 2** | **Tier 1 detection (PANW VM-Series)** — capture replay, threat-log retrieval, Tier 1 correlation. Fills in the default path; **adds no CLI flags** | Yes |

Every capability in §6 and every user story in §7 is tagged with its phase. **Phase 2 is additive: it introduces new entries into the existing `sources[]` array and requires no schema version change.** That property is a Phase 1 design constraint, not a Phase 2 hope — §6.6 states it explicitly so it cannot be traded away later.

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

All five goals apply to **Phase 1**. Goal 6 is a Phase 1 design constraint verified in Phase 2.

| | Goal | How it is verified |
| :-: | :-- | :-- |
| **Goal 1** | **Every label is traceable to its origin.** A label records its tier, source, the specific rule that fired, the ruleset snapshot in use, the admission basis by which that rule was accepted, and the source's licence. | Automated check: 100% of emitted labels carry every required provenance field for their source class (§6.6 defines the required fields per class — no "where applicable" escape). |
| **Goal 2** | **Runs are reproducible.** The same capture, the same pinned ruleset snapshot, and the same pinned tool versions produce identical labels **after canonicalisation**. | Two runs produce `labels.json` files that are identical once written in canonical form (§6.6), excluding only the explicitly enumerated run-metadata fields. Requires `zeek -D` (§6.2, verified) and a pinned snapshot (§6.3). |
| **Goal 3** | **Nothing is lost silently.** Every *enumerated* loss condition is reported in the run block. | Each condition in the §6.6 loss-condition table has a named field **and one fault-injection test**. Verified by tests, not by code review. |
| **Goal 4** | **One label per flow.** Detections from multiple sources against the same flow consolidate into a single entry retaining all asserting sources. | No duplicate flow identity in `labels`. |
| **Goal 5** | **Specificity canary.** A curated benign capture produces zero labels; a curated known-malicious capture produces labels. | Two regression tests over committed fixtures. Any label on the benign canary is a false positive by construction and fails the build. |
| **Goal 6** | **Phase 2 is additive.** Adding Tier 1 introduces new `sources[]` entries and requires no schema version change and no consumer change. | Verified at Phase 2: the Phase 1 schema version is unchanged, and a Phase 1 consumer parses Phase 2 output without modification. |

**Explicitly not a goal:** a measured false-positive *rate*. Goal 5 is a bounded regression test over two fixtures, not a measurement programme — it detects gross specificity failures, it does not quantify accuracy. Per the trust-by-construction decision (Stage 1), label quality is otherwise argued from source provenance and ruleset curation. See Risks.

## 3. Non-Goals

- **Not a real-time IDS or IPS.** flabel processes captures after the fact. It never blocks, resets, or otherwise acts on live traffic.
- **Not a TLS decryption or MITM tool.** Encrypted traffic is handled by fingerprint- and certificate-based detection only; decryption is impossible on an after-the-fact capture.
- **Not an assertion of benign.** flabel labels malicious flows. It does not and cannot certify that any flow is safe.
- **Not a general pcap forensics or analysis platform.** Zeek logs are emitted because they are needed for correlation and enrichment, not as a product surface.
- **Not a false-positive rate measurement system.** See the note on Goal 5 above.
- **No graphical interface.** Command-line only.
- **Not a ruleset authoring tool.** flabel consumes third-party rulesets; it does not write detection rules.

## 4. Out of Scope

|  |  |  |
| :-: | :-: | :-: |
| **Item** | **Reason** | **Future Phase?** |
| **Tier 1 detection (PANW VM-Series) and the lab that hosts it** | Roughly 60% of total effort, all recurring cost, and the only part untestable in CI (`docs/eng-review.md`). Phase 1 delivers a working labelling pipeline without it | **Yes — Phase 2, immediate follow-on** |
| Label validation against a ground-truth corpus | Trust-by-construction decided at Stage 1. Goal 5's canary provides a bounded substitute | No — superseded by Goal 5 |
| JA4 *rule content* — a source of malicious JA4 fingerprints | No admitted source publishes `ja4.hash` rules today. **The JA4 labeling capability itself is in Phase 1** (§6.3) — only the content is missing | Content only; capability ships in Phase 1 (issue #13) |
| Snort 3 as the Tier 2 engine | Suricata selected on free high-confidence ruleset volume and native fingerprint keywords | No |
| FortiGate as the NGFW | PANW VM-Series selected as Tier 1 | No |
| Free/OSS L7 equivalent to PANW App-ID | No free equivalent exists; line of inquiry closed | No |
| Paid rulesets (ET Pro ~$900/sensor/yr, Secureworks, Stamus) | Free sources with a 30-day delay are acceptable | Re-ask at Phase 2, alongside the PANW subscription cost (§10) |
| Government-published rule feeds | No agency publishes a maintained general-purpose ruleset; advisory signatures are point-in-time IOCs with no cadence | No |
| Positive Technologies rulesets | Non-standard licence and vendor under US sanctions since 2021 | No |
| PANW tap-mode deployment | Virtual-wire pair selected for Phase 2 | No |
| Benign / negative-class labels | flabel cannot assert benign; absence of a label is not a verdict | No |
| `abuse.ch` SSLBL JA3 fingerprint feed | Abandoned — newest entry 2021-08-03, self-declared untested FP posture | No |

## 5. Background & Context

**Prior work.** Stage 1 research (`docs/research.md`, driven by `docs/research-brief.md`) evaluated detection sources, rulesets, fingerprinting methods, and replay mechanics. Stage 3 engineering review (`docs/eng-review.md`) reviewed this PRD cold and drove the v0.4 changes. The original design brief is `docs/prep-n-research.md`.

Findings that shaped the design:

1. **Only PANW requires replay.** Suricata and Zeek read capture files natively. Confining replay to the one component that needs it is what makes the Phase 1 / Phase 2 split a configuration boundary rather than a rewrite.
2. **The canonical free JA3 feed is abandoned**, but ET Open maintains its own JA3 ruleset — actively updated through 2026, carrying per-rule confidence metadata, MIT-licensed. Fingerprint detection therefore belongs in Tier 2 as ordinary Suricata rule content, matched via native `ja3.hash` / `ja4.hash` keywords.
3. **pcapng cannot be fed directly to Zeek at all**, and only partially to Suricata. Since pcapng is Wireshark's default output, input normalization is mandatory rather than optional.
4. **Tier 1 is ~60% of the effort and carries all the infeasibility risk.** Whether a cloud VM-Series can even observe replayed capture traffic is unverified. Phase 1 removes that from the critical path.

**Trust model.** Trust is assigned **per source**, not per rule. Tier 1 (Phase 2) is PANW VM-Series; Tier 2 is Suricata with a curated, admission-filtered ruleset set. Because trust is not modeled per rule, **ruleset curation is the entire false-positive defence** — and in Phase 1, where Tier 2 is the whole product, it is the *only* defence. That is why the admission filter, its per-source policy, and its snapshot are product requirements rather than implementation details.

**Environment.** Phase 1 requires no lab: it runs on one machine against local files.

Phase 2 requires **two hosts** — a PANW VM-Series in a **two-zone Layer 3** configuration, and a host that runs flabel and the replay.

**Amended 2026-08-17: this said virtual-wire, and virtual wire is not achievable in GCP.** A vwire interface carries no IP address, and GCP's virtual switch forwards by destination IP rather than by L2 adjacency, so there is no route target to deliver replayed frames to. The L3 substitution gives each replay leg an IP that a VPC custom route can target. That answers §13 Q16, and the measurement is in `docs/phase-2-reachability-spike.md`: the device received the replayed traffic **with the original 5-tuple intact**, which is what lets correlation match on the tuple with no address map. Suricata does not need a host of its own because it reads the capture file; the original three-host design was reduced accordingly. Clock sync is **NTP to sub-second accuracy with a padded query window**, not millisecond: correlation is tuple-driven and time only scopes the log query, so the design deliberately does not depend on tight clock accuracy — a millisecond gate could fail for a reason that does not affect a single label. Q16 is **answered**: see above and `docs/phase-2-reachability-spike.md`.

## 6. Feature Description

### 6.1 Capture Ingest & Normalization — *Phase 1*

**Description:** Accepts a capture file, determines its true format, and normalizes it to a single artifact that every downstream consumer reads identically.

**Key Business Rules / Logic:**

- Accepted inputs: `pcap`, `pcapng`, and gzip-compressed variants of both.
- pcapng is normalized to pcap via `editcap -F pcap`.
- All consumers receive the **same normalized file**, so they cannot disagree about the input.
- **Validation is performed by flabel itself**, walking capture record headers to derive packet count and byte offsets. The truncation offset is not obtainable from `editcap` or `capinfos`, which error on truncated input rather than reporting where it stopped.
- A capture whose **header** is unreadable is a **hard failure** — no labels are emitted.
- A **truncated pcap** (readable prefix, incomplete tail) is processed, and the output is stamped `input_status: partial` with the packet count reached and the truncation byte offset.
- A **truncated pcapng** is a **hard failure**, with a message directing the operator to repair it with `editcap`. A partial pcapng block cannot be safely converted.
- A **multi-datalink** capture processes only the **dominant link type**; the output is stamped `input_status: partial` recording the discarded packet count and the link types dropped. Processing all splits would create independent Zeek `uid` namespaces and break flow identity.
- The normalization performed is recorded in run provenance, because a converted capture is not the original artifact.

### 6.2 Zeek Processing & Fingerprint Enrichment — *Phase 1*

**Description:** Runs Zeek over the normalized capture to produce flow logs and TLS fingerprints. Zeek's `uid` is the authoritative flow identity for the entire system.

**Key Business Rules / Logic:**

- All Zeek logs generated for the capture are retained in the output.
- **Zeek is invoked with `-D` / `--deterministic`**, which initialises its random seeds to zero and makes `uid` assignment stable for a given input. The mechanism is recorded in run provenance.

  > **Verified empirically, 2026-08-11 (spike 3).** Zeek 8.0.4, 14-packet synthetic capture, two flows. **Default behaviour: UIDs differ on every run** — run A produced `CTCqb34rMyhpo79tSk`, run B produced `Cyh21dwPOqRx2XKui` for the same flow. **With `-D`: byte-identical across three consecutive runs**, and `conn.log`, `files.log`, and `http.log` were fully identical record-for-record. `-G <seed-file>` also works but yields a different stable value set and adds an artifact to manage, so `-D` is preferred. This confirms the review's Critical finding: without this flag Goal 2 would have failed 100% of the time and US-06's cross-run label joins would have been impossible.
  >
  > **`packet_filter.log` remains non-deterministic** — it carries Zeek's wall-clock start time. It contains no analytic content and is excluded from reproducibility comparison.
- JA4 is computed for every TLS connection via the `zeek/foxio/ja4` package. **The JA4 value carried on a label is always the Zeek-computed one**, so there is a single authority — Suricata computes JA4 independently for matching. The cross-check that would prove the two agree is **deferred alongside #13** and is a precondition for admitting JA4 rule content, not a Phase 1 gate (§9, US-14, #90).
- JA4+ (JA4S, JA4H, JA4X, JA4T) is enabled. Licensing: plain JA4 is BSD 3-Clause; the JA4+ suite is FoxIO License 1.1 (non-commercial). JA4+ is **approved for use with Legal's review in progress**; restricting to plain JA4 is the documented contingency if Legal declines (§13 Q3).
- **A computed fingerprint is an attribute, not a verdict.** Zeek's JA4 output never produces a label by itself. Labels arise only where a fingerprint **matches an admitted rule**, which happens in the Tier 2 path (§6.3).
- Zeek `uid` is assigned to every flow and becomes the join key between `labels.json` and the Zeek logs.

### 6.3 Tier 2 Detection — Suricata — *Phase 1*

**Description:** Runs Suricata offline against the normalized capture using a curated, admission-filtered ruleset, producing Tier 2 detections. Requires no lab and is fully deterministic.

**Ruleset snapshots are first-class artifacts:**

- A **separate command** (`flabel rules update`) fetches sources, applies the admission policy, and writes an **immutable snapshot directory**. The snapshot's identifier is a content hash of the emitted filtered rule file.
- A labelling run takes `--ruleset-snapshot <id>`, defaults to the newest available, and **performs no network I/O whatsoever.** This is what makes Goal 2 achievable, makes US-06's cross-snapshot comparison real, and removes network flakiness from every test.
- The snapshot records, per source: name, version, fetch date, licence, admission basis, and admitted rule counts — including a separate JA4 rule count.

**Sources are classified before they are filtered:**

- Every source is classified **`verdict`** or **`non-verdict`**. Non-verdict sources (e.g. `oisf/trafficid`, which performs traffic identification) **can never produce a label** — their alerts are routed to enrichment. Without this, an identification rule firing becomes a malicious label.
- Every source records an **`admission_basis`**: `metadata-filter` or `wholesale`. A downstream consumer can therefore filter out ungated sources.

**Admission policy is per source:**

- **Signature rulesets** (ET Open) are filtered on rule metadata: `confidence == High` **and** `signature_severity in (Major, Critical)`. Rules lacking a `confidence` tag are **excluded** (fail-closed).
- **IOC feeds and community rulesets without ET-style metadata** (abuse.ch, malsilo, `stamus/lateral`, `the-hunters-ledger`, `pawpatrules`) are admitted **wholesale**, with the feed snapshot date as provenance. Wholesale admission means *no per-rule gate exists* for those sources — hence `admission_basis` being machine-visible.
- `pawpatrules` is admitted **with its false-positive risk knowingly accepted.** It is the broadest-scope and least-vetted admitted source, and it is share-alike licensed (CC-BY-SA-4.0). **The Goal 5 benign canary is its standing FP review.**

  **Amendment, 2026-08-15 (#88): that review does *not* run on every build, and this paragraph claimed it did.** The review is split, and only the weaker half is on the PR path:

  | | Runs | What it reviews |
  | :-- | :-- | :-- |
  | `test_the_benign_canary_produces_zero_labels` | every build | **Three synthetic rules** against a 14-packet capture. Its own assertion is `rules_loaded == 3`. It reviews none of the ~85,000 wholesale-admitted rules this risk is about — it proves the labelling path works, not that the ruleset is quiet. |
  | `.github/workflows/feeds.yml` | daily `schedule:` | The real review: nine feeds fetched live, a real snapshot built, the benign canary **and** the 17-capture benign corpus labelled against it. |

  The scheduled half cannot move onto the PR path — the test suite may never contact a rule feed (spec §2.2) and a real snapshot is 124 MB — and that decision stands (Craig, 2026-08-12, on #24). What was missing is that **GitHub disables `schedule:` triggers after 60 days of repository inactivity**, so the real review can stop with nothing to announce it. `ci.yml`'s `feeds-liveness` job now refuses a push when `feeds` has not succeeded within seven days. So the honest claim is not "it runs on every build" but **"no change can merge while it has been dark"**.
- Excluded: hunting/anomaly rulesets, self-described aggressive blacklists, and Positive Technologies.
- The filter is an **inclusion** filter, which `suricata-update`'s subtractive model does not express — flabel parses rule metadata and emits its own filtered rule file.

**Encrypted-traffic detection is part of this tier, in Phase 1:**

- Suricata's native `ja3.hash` **and** `ja4.hash` matching are both enabled, and fingerprint rules pass through the identical admission filter and snapshot provenance as any other rule.
- **JA4 has the capability but not yet the content.** No admitted source currently publishes `ja4.hash` rules, so JA4 label output will be zero on release. This is a *content* gap, not a capability gap: when any admitted source ships JA4 rules, they are picked up with **no code change**.
- Because an inactive path is indistinguishable from a broken one, **the run records how many JA4 rules were admitted.** A zero count proves the path ran and found no content.

### 6.4 Tier 1 Detection — PANW VM-Series — *Phase 2*

**Description:** Replays the normalized capture past a PANW VM-Series in a two-zone Layer 3 configuration, then retrieves the resulting threat detections. **Built 2026-08-17** (`replay.py`, `panw.py`, `tier1.py`).

**Key Business Rules / Logic:**

- Replay runs at a **controlled rate**; `--topspeed` is prohibited. The exact rate is set by the Phase 2 replay-yield spike, not guessed.
- Replay uses a **`tcpprep`-derived client/server split** across the vwire pair, recorded in provenance. A stateful firewall needs each direction presented on the correct interface; replaying both directions from one side produces malformed sessions.
- **Sessions the device rejects as non-SYN are recorded and reported**, along with the device's non-SYN policy. Real captures routinely begin mid-connection, and PAN-OS discards non-SYN TCP sessions by default — an invisible source of missing labels.
- **Packets sent are reconciled against packets seen, with device-side legitimate-discard counters accounted for separately.** Without that separation the alarm fires on every real capture and becomes noise.
- Threat logs are retrieved via the PAN-OS API, **bounded by the replay window** and **matched by flow tuple**. Time scopes the query; the tuple performs the match.
- **Tier 1 provenance:** the run records PAN-OS version, threat content release version, and application content release version, retrieved from the device. Each Tier 1 source entry carries the PANW threat ID as its rule identity. A PANW detection's meaning is determined by the auto-updating content release, so without this the highest-trust tier would be the least auditable.
- Detections are stamped at replay time. Labels reference the **capture's** timeline; the device's own timestamp is carried as `device_observed_at` and must never be interpreted as capture time (§6.6).

### 6.5 Consolidation & Correlation — *Phase 1 (Tier 2), Phase 2 (Tier 1)*

**Description:** Merges detections into one label per flow, resolving each to a Zeek flow identity.

**Key Business Rules / Logic:**

- **One entry per flow.** A flow flagged by multiple sources yields a single entry whose `sources[]` array retains every asserting detection.
- `best_tier` records the highest-trust source that asserted the flow. **Lower tier numbers are higher trust** — stated explicitly because the ordering is counter-intuitive.
- **Tier 2 correlation rule:** a Suricata alert is resolved to a Zeek `uid` by flow tuple plus timestamp containment. Where a tuple maps to more than one `conn.log` record (port reuse within a capture), the record whose time window contains the alert wins; if still ambiguous, the detection is emitted unmatched rather than assigned by guess.
- A detection that **cannot be correlated** to any flow — including a Suricata alert with no corresponding Zeek connection — is emitted in `unmatched_detections[]` with a reason and the raw fields. Never silently dropped, never guessed into a flow.
- **The unmatched count is a gate, not just a signal** (resolves Q9). In Phase 1 both Zeek and Suricata read identical bytes, so any unmatched detection is anomalous:
  - zero unmatched — silent;
  - any unmatched — **warn**, run still succeeds;
  - above a configurable threshold (**default 1%** of *correlatable* detections) — **fail the run**, because a systemic correlation break would otherwise produce a quietly incomplete label set.
  - *Amended 2026-08-13 (issue #84):* detections on a transport Zeek cannot name — ESP, SCTP, GRE — are excluded from both sides of that share, reported in `unmatched_detections[]` and counted in `counts.unmatched_unsupported_transport`. They could never correlate, so including them failed runs on ordinary tunnelled traffic. See spec §9 step 0.
  - Phase 2 will need a looser threshold, since Tier 1 correlation is inherently harder; it is configured separately rather than by relaxing the Phase 1 default.

### 6.6 Output & Provenance — *Phase 1*

**Description:** Writes Zeek logs and `labels.json` to a per-run directory named after the capture and the run time, with complete provenance.

**Output layout** — each run writes its own top-level directory named `{capture-name}_{datetime}`, so runs of the same capture are siblings and a re-run never destroys prior labels:

```
my-capture_2026-08-11T213045Z/
├── zeek/            # all Zeek logs
├── labels.json
└── NOTICE           # licence attribution for sources that asserted a label
```

- **Directory naming:** `{capture-name}` is the input filename with its extension stripped, including a trailing `.gz`; unsafe path characters are replaced. `{datetime}` is the run start in UTC, ISO-8601 with no colons (`2026-08-11T213045Z`), filesystem-safe on every platform. ISO-8601 sorts lexicographically, so a plain sort of `{capture-name}_*` is chronological and the newest run is the last entry.
- **No `latest` pointer.** A `{capture-name}_latest` symlink would be matched by the same `{capture-name}_*` glob used to enumerate runs and would corrupt iteration.

**Canonical form** — required for Goal 2:

- The `labels` array is sorted by `(flow.ts_first, flow.uid)`; `sources[]` within an entry is sorted by `(tier, source, sid, rev, direction)`. `direction` is part of the key because two entries from one rule that fired in both directions share a rule identity and are otherwise identical (#115), so nothing else would break the tie.
- Object keys are emitted in sorted order; timestamps use a single fixed format.
- Only these are excluded from a reproducibility comparison: run start/end time, run duration, and Zeek's `packet_filter.log` (which carries a wall-clock start stamp and no analytic content). Everything else must match.

**Content rules:**

- `labels.json` contains **malicious flows only.** An unlabeled flow is *unlabeled*, not verified benign — stated in the output schema itself so the distinction cannot be lost downstream.
- A capture with zero detections is a **successful run** producing an empty `labels` array.
- `labels.json` carries a **schema version**. **Phase 2 adds Tier 1 entries to `sources[]` without changing it** — the addition is purely additive by design (Goal 6).
- A `NOTICE` file lists every source that asserted a label, with its licence and any required attribution. Admitted sources include GPL-3.0-only, CC-BY-SA-4.0 and CC-BY-4.0 content, and rule `msg` text is reproduced in the `threat` field.

**Required provenance fields per source class** — Goal 1 is checked against this table, so there is no "where applicable" ambiguity:

| Source class | Required fields | Nullable |
| :-- | :-- | :-- |
| Suricata (signature or IOC) | `tier`, `source`, `sid`, `rev`, `ruleset` (snapshot id), `admission_basis`, `licence`, `label_basis`, `threat`, `direction` | `classtype` |
| PANW (Phase 2) | `tier`, `source`, `threat_id`, `threat`, `content_version`, `panos_version`, `device_observed_at`, `label_basis`, `direction` | — |

**Amendment, 2026-08-15 (#89): `classtype` is nullable, not required.** It was listed as required above through PRD v0.4, and the code and `docs/spec.md` §4 have always made it `str | None` — so read literally, Goal 1 was not met. The divergence is resolved in favour of the code. **10,949 of the 84,995 admitted rules declare no `classtype:` at all**, so requiring it would mean either refusing to label on 12.9% of the ruleset or inventing a value, and an invented classtype is exactly the untraceable provenance Goal 1 exists to prevent. Spec §4's `classtype: str | None` is the single declaration both the field list and its nullability are now read from at test time; a `""` is still a defect, because §4 provides no empty-string convention the way it provides `"unstated"` for an unknown licence.

**Amendment, 2026-08-17 (#115): `direction` is required, and never null.** Added after twenty-two real internet-facing captures showed the field a label needs to be honest about itself. 19.5% of the ruleset is destination-anchored with an unconstrained source (`alert ip any any -> <flagged address> any`), so a rule written for outbound traffic to a known-bad address fires on *our RST back* to that address's inbound scan — and the label then reads `threat: "Outgoing connection to ..."` beside an inbound flow. Suricata reports which side of the flow the matching packet was on; flabel now publishes it. **No verdict depends on it**: suppressing the label instead was rejected because a rule that legitimately matches a C2 response would be silently dropped, which is the failure §2.5 forbids. The value is `to_server`, `to_client`, or `unknown` — the last for an alert Suricata could not place on either side, measured on an unsolicited ICMP destination-unreachable. `unknown` is a sentinel in the manner of `licence: "unstated"`, so `classtype` remains the sole nullable field. **For Phase 2**, a PANW threat log records client-to-server / server-to-client explicitly, so a tier-1 entry carries the device's own value and must not default to `unknown` — which would assert that the direction was not established about a device that knows it. Note the frame of reference differs by tier and spec §4 says so: a tier-2 value is relative to *Suricata's* flow, and correlation does not require Suricata and Zeek to agree on who initiated.

**`label_basis`** distinguishes `direct` (this flow is the malicious activity) from `indicator-reference` (this flow merely referenced a malicious indicator). An IOC rule matching a DNS query labels the flow **to your resolver**; an HTTP-URL rule behind a proxy labels the flow **to the proxy**. Both are correct rule matches on benign infrastructure flows, and a model trained on them learns that its own resolver is malicious. The distinction must be machine-visible so a consumer can exclude them.

**Enumerated loss conditions** — Goal 3 is checked against this closed list, each with a named field and a fault-injection test:

| Condition | Field | Phase |
| :-- | :-- | :-: |
| Input truncated | `input_status`, `packets_read`, `truncated_at_offset` | 1 |
| Multi-datalink splits discarded | `discarded_link_types`, `discarded_packets` | 1 |
| Detection uncorrelatable to a flow | `unmatched_count` + `unmatched_detections[]` | 1 |
| Zeek or Suricata non-zero exit, **including an OOM kill on a large capture** | `tool_failures[]` | 1 |
| Ruleset snapshot missing or unreadable | hard failure, `error` | 1 |
| Replay packet count mismatch | `replay_sent`, `replay_seen`, `replay_device_discards` | 2 |
| Device rejected sessions as non-SYN | `non_syn_rejected` | 2 |
| Threat-log query returned fewer records than expected | `tier1_query_status` | 2 |

**Run provenance** additionally records: input identity and status, normalization applied, ruleset snapshot id with per-source detail, Zeek seed, tool versions (flabel, Zeek, Suricata, `editcap`, JA4 package — *not* the Suricata JA4 implementation, deferred with #90), tiers attempted, and coverage achieved.

**Label entry shape:**

```json
{
  "flow": {
    "uid": "CHhAvVGS1DHFjwGM9",
    "src_ip": "10.0.0.5", "src_port": 49152,
    "dst_ip": "203.0.113.10", "dst_port": 443,
    "proto": "tcp",
    "ts_first": "...", "ts_last": "...",
    "ja4": "t13d1516h2_8daaf6152771_02713d6af862"
  },
  "verdict": "malicious",
  "best_tier": 2,
  "sources": [
    { "tier": 2, "source": "suricata", "sid": 2028831, "rev": 1,
      "ruleset": "snap-9f2c1a…", "admission_basis": "metadata-filter",
      "licence": "MIT", "classtype": "command-and-control",
      "label_basis": "direct", "threat": "...", "direction": "to_server" }
  ]
}
```

### 6.7 CLI & Run Modes — *Phase 1*

**Description:** A single command processes a capture end to end. **The CLI contract is fixed in Phase 1 and does not change in Phase 2** — only the default path's implementation is filled in.

**Key Business Rules / Logic:**

- `flabel <capture>` is the primary invocation and **includes Tier 1 by default**, as originally specified. In **Phase 1 the default path is a stub**: it prints `Coming Soon (TM)`, names `--offline` as the working alternative, writes no output, and exits with a **distinct documented "not implemented" code** — not `0`. A zero exit with no labels would be exactly the silent-absence failure this project exists to avoid.
- `flabel --offline <capture>` runs the **Tier 2 pipeline** and is the functional labelling path in Phase 1. The output records that Tier 1 was not attempted.
- **Phase 2 fills in the default path.** No flag is added, renamed, or removed; `--offline` keeps its meaning permanently as "skip Tier 1". Anyone who scripts against `--offline` in Phase 1 keeps working unchanged.
- `flabel rules update` manages ruleset snapshots (§6.3). It is the **only** command that touches the network.
- `--ruleset-snapshot <id>` pins a run to a snapshot; the default is the newest available.
- Exit codes distinguish success, success-with-partial-input, not-implemented, and failure.
- Progress and warnings go to stderr; machine-readable output goes to files, never stdout-mixed.

## 7. User Stories

Personas: **DME** = DeepTempo detection-model engineer (primary consumer of labels). **OPS** = lab/platform operator.

|  |  |  |  |  |
| :-: | :-: | :-: | :-- | :-- |
| **ID** | **Phase** | **Priority** | **User Story** | **Notes** |
| US-01 | 1 | P0 | As a DME, I want to run one command against a capture and get Zeek logs plus a malicious-flow label file, so that I can turn raw captures into training data without manual analysis. | Core capability; `--offline` in Phase 1 |
| US-22 | 1 | P0 | As a DME, I want the default (NGFW-inclusive) invocation to tell me plainly that it isn't built yet and point me at `--offline`, so that I never mistake an unimplemented path for a clean run with no findings. | Stub prints `Coming Soon (TM)`, non-zero exit |
| US-02 | 1 | P0 | As a DME, I want every label to record the source, rule, ruleset snapshot, admission basis, and licence that produced it, so that I can defend or audit any individual label later. | Goal 1 |
| US-03 | 1 | P0 | As a DME, I want each label to join directly to the Zeek flow record, so that I can extract features for the labeled flow. | Zeek `uid` |
| US-04 | 1 | P0 | As a DME, I want a flow flagged by several sources to appear once with all sources listed, so that I don't have to deduplicate before training. | One entry per flow |
| US-05 | 1 | P0 | As a DME, I want to know when a run's coverage was incomplete, so that I don't train on a label set I believe to be complete when it isn't. | Goal 3, enumerated conditions |
| US-06 | 1 | P0 | As a DME, I want re-running a capture to preserve the previous run's output and produce joinable labels, so that I can compare label sets across ruleset snapshots. | Sibling run dirs; requires the fixed Zeek seed |
| US-07 | 1 | P0 | As an OPS, I want the same capture, snapshot, and tool versions to yield identical labels after canonicalisation, so that I can verify the pipeline is deterministic. | Goal 2 |
| US-16 | 1 | P0 | As a DME, I want a rule that only *identifies* traffic to be incapable of producing a malicious label, so that identification rules cannot silently poison the training set. | Verdict vs non-verdict classification |
| US-17 | 1 | P0 | As a DME, I want to distinguish a label on the malicious flow itself from a label on a flow that merely referenced a malicious indicator, so that I don't train a model that thinks my DNS resolver is malicious. | `label_basis` |
| US-18 | 1 | P0 | As an OPS, I want a benign capture to produce zero labels in CI, so that a specificity regression fails the build instead of reaching a model. | Goal 5 canary |
| US-19 | 1 | P0 | As an OPS, I want ruleset snapshots to be immutable, addressable artifacts fetched by a separate command, so that a labelling run never touches the network and is reproducible. | `flabel rules update` |
| US-09 | 1 | P1 | As a DME, I want pcapng and gzipped captures accepted directly, so that I can use files as they come off Wireshark or a sensor. | Normalization |
| US-10 | 1 | P1 | As a DME, I want JA4 fingerprints recorded on TLS flows, so that I can use them as model features and pivot on them during analysis. | Enrichment half — Zeek-computed attribute |
| US-14 | 1 | P0 | As a DME, I want a JA4 fingerprint matching an admitted rule to produce a Tier 2 label, so that encrypted-traffic detections use the same machinery as every other detection. | Labeling half; capability now, content later |
| US-15 | 1 | P1 | As an OPS, I want the run to record how many JA4 rules were admitted, so that I can tell "no JA4 content published" apart from "the JA4 path is broken". | Guards against silent rot |
| US-11 | 1 | P1 | As an OPS, I want the admission filter's results recorded per source per run, so that I can see which rules were live and how many were excluded and why. | Issue #11 |
| US-20 | 1 | P1 | As a DME, I want a NOTICE file listing the licence and attribution of every source that asserted a label, so that the output is distributable without a compliance defect. | GPL/CC-BY sources |
| US-13 | 1 | P2 | As a DME, I want `labels.json` to carry a schema version, so that a shape change breaks loudly rather than silently. | Forward compatibility |
| US-08 | 1 | P0 | As an OPS, I want `--offline` to run the Tier 2 pipeline without any lab, so that captures can be labelled today and the flag keeps the same meaning after Phase 2 lands. | The Phase 1 working path; contract stable across phases |
| US-23 | 2 | P0 | As a DME, I want the default invocation to actually perform NGFW screening, so that Tier 1 labels appear without me changing any command or script. | Fills in the Phase 1 stub; no CLI change |
| US-21 | 2 | P0 | As a DME, I want Tier 1 labels to record the device's content release version, so that the highest-trust tier is as auditable as the others. | Tier 1 provenance |
| US-12 | 2 | P1 | As an OPS, I want a documented environment diagram in draw.io and mermaid form, so that the lab can be rebuilt or handed over. | Promoted from P2; drawn before Phase 2 planning |

## 8. UX Requirements

**Key Workflows:**

- **Update rulesets.** `flabel rules update` → fetch, filter, write an immutable snapshot, report per-source admitted counts.
- **Label a capture (Phase 1).** `flabel --offline capture.pcap` → normalize → Zeek + Suricata → consolidate → write run directory. No network access. The bare `flabel capture.pcap` default is the NGFW-inclusive path and prints `Coming Soon (TM)` until Phase 2 fills it in.
- **Compare across ruleset snapshots.** Re-run with a different `--ruleset-snapshot`; each run lands in its own sibling directory; sorted names are chronological; labels are joinable by `uid` because the Zeek seed is fixed.
- **Inspect a label.** Read `sources[]`, check `label_basis` and `admission_basis`, then join `flow.uid` to `zeek/conn.log`.

**Design Constraints / Guidelines:**

- Command-line only; no GUI, no daemon, no service.
- One capture per invocation. Batch processing is the caller's job.
- Human-readable progress and warnings to **stderr**; machine-consumable output to files. Never interleaved.
- Only `flabel rules update` performs network I/O.
- Failures state what went wrong, which stage, and what would fix it.
- Silence is never used to signal a problem. Absent coverage is always explicitly reported.

**Accessibility Requirements:**

- No information conveyed by colour alone.
- Output legible when redirected to a file or read by a screen reader — no cursor-control or spinner-dependent rendering.
- Distinct, documented exit codes: success, success-with-partial-input, failure.
- All output UTF-8.

**Prototype / Mockup Links:** N/A — command-line tool.

## 9. Acceptance Criteria

Each criterion is marked **[CI]** (testable in continuous integration) or **[LAB]** (requires the Phase 2 lab and must be executed manually against the real device, with results recorded in the repo).

### US-01: Label a capture end to end
- **[CI]** Given a valid pcap, when `flabel --offline my-capture.pcap` runs, then a directory `my-capture_{datetime}` is created containing `zeek/`, `labels.json`, and `NOTICE`.
- **[CI]** Given an input named `my-capture.pcap.gz`, then the output directory is `my-capture_{datetime}` with both extensions stripped and no colons in `{datetime}`.
- **[CI]** Given a capture with no detectable threats, then `labels.json` exists with an empty `labels` array and the run succeeds.

### US-22: The default path is an honest stub in Phase 1
- **[CI]** Given `flabel my-capture.pcap` with no `--offline`, then `Coming Soon (TM)` is printed, the message names `--offline` as the working path, **no output directory is created**, and the exit code is the documented not-implemented code — never `0`.
- **[CI]** Given the stub path, then no `labels.json` is written anywhere, so no consumer can mistake it for a run with zero findings.

### US-02: Label provenance
- **[CI]** Given any emitted label, then every field required for its source class (§6.6 table) is present and non-empty.
- **[CI]** Given a completed run, then provenance lists the ruleset snapshot id, per-source detail including licence and admission basis, the Zeek seed, and all tool versions.

### US-03: Join to Zeek
- **[CI]** Given a label with `flow.uid`, then exactly one matching record exists in `zeek/conn.log`.

### US-04: One entry per flow
- **[CI]** Given a flow flagged by two Suricata rules, then exactly one entry exists with both in `sources[]`.
- **[CI]** Given the full `labels` array, then no flow identity appears more than once.
- **[LAB]** Given a flow flagged by both Tier 1 and Tier 2, then one entry exists with both sources and `best_tier` is 1.

### US-05: Incomplete coverage is visible
- **[CI]** Given a truncated pcap, then `input_status` is `partial` with packet count and truncation offset recorded.
- **[CI]** Given a truncated pcapng, then the run fails with a message directing repair via `editcap`.
- **[CI]** Given a capture with an unreadable header, then the run fails and writes no labels.
- **[CI]** Given a multi-datalink capture, then only the dominant link type is processed and the discarded link types and packet count are recorded.
- **[CI]** Given a detection that cannot be correlated, then it appears in `unmatched_detections[]` with a reason and is counted.
- **[CI]** For **each** condition in the §6.6 loss-condition table marked Phase 1, a fault-injection test asserts its field is populated.
- **[LAB]** Given a replay where packets seen differ from packets sent beyond device discards, then the discrepancy is reported and the run is not presented as full coverage.

### US-06: Re-runs preserve history and remain joinable
- **[CI]** Given a capture already processed, then a new sibling directory is created and the previous run directory is unmodified.
- **[CI]** Given two or more run directories for one capture, then sorting their names lexicographically yields chronological order.
- **[CI]** Given two runs of the same capture, then a flow present in both carries the **same** `flow.uid`, so labels from the two runs can be joined.

### US-07: Reproducibility
- **[CI]** Given the same capture, the same `--ruleset-snapshot`, and the same pinned tool versions, when flabel runs twice, then the canonical `labels.json` files are identical excluding only run start/end/duration.

### US-16: Non-verdict sources cannot label
- **[CI]** Given a capture that triggers a rule from a non-verdict source, then no label references that source, and the alert appears only as enrichment.
- **[CI]** Given the ruleset snapshot, then every source carries an explicit `verdict` / `non-verdict` classification.

### US-17: Indicator-reference labels are distinguishable
- **[CI]** Given a label produced by an IOC rule matching a DNS query, then its `label_basis` is `indicator-reference`, not `direct`.
- **[CI]** Given any label, then `label_basis` is present and one of the defined values.

### US-18: Specificity canary
- **[CI]** Given the curated benign fixture capture, when flabel runs, then `labels` is empty. Any label fails the build.
- **[CI]** Given the curated known-malicious fixture capture, then at least one label is produced.

### US-19: Ruleset snapshots
- **[CI]** Given `flabel rules update`, then an immutable snapshot directory is written whose id is a content hash of the filtered rule file.
- **[CI]** Given a labelling run, then no network connection is attempted.
- **[CI]** Given a non-existent `--ruleset-snapshot`, then the run fails without emitting labels.

### US-09: Format handling
- **[CI]** Given a pcapng capture, then it is normalized to pcap, processed, and the conversion recorded.
- **[CI]** Given a gzipped capture, then it is decompressed and processed.
- **[CI]** Given any accepted input, then Zeek and Suricata processed the identical normalized file.

### US-10 / US-14 / US-15: Fingerprints
- **[CI]** Given a capture with TLS connections, then JA4 values are present on those flows in the Zeek output and on any resulting labels.
- **[DEFERRED — 2026-08-15, #90]** ~~Given a TLS fixture, then Zeek's computed JA4 and Suricata's computed JA4 for the same flow are equal, and both implementation versions are recorded.~~ **Deferred alongside #13, and this criterion does not gate Phase 1.** It shipped unimplemented and unrecorded: no test joins a Zeek-computed JA4 to a Suricata-computed one, and spec §10's `tools` block has no field for the Suricata JA4 implementation. Deferring it is safe *only because* no `ja4.hash` rules exist in any admitted source (#13), so Suricata never computes a JA4 that a label could disagree with. **The cross-check is a precondition for closing #13, not an independent nicety** — §6.2's "the JA4 value carried on a label is always the Zeek-computed one" is what makes a divergence dangerous, since a `ja4.hash` rule would fire on Suricata's value while the label records Zeek's. Whoever admits the first JA4 rule content implements this first.
- **[CI]** Given a synthetic `ja4.hash` rule that matches a fixture flow, then a Tier 2 label is produced, structurally identical to a content-matched label.
- **[CI]** Given a JA4 value matching no admitted rule, then no label is produced from that fingerprint.
- **[CI]** Given no admitted source publishes JA4 rules, then run metadata records the JA4 path active with an admitted JA4 rule count of zero.

### US-20: Licence attribution
- **[CI]** Given a run whose labels came from sources with attribution requirements, then `NOTICE` lists each source, its licence, and its required attribution.

### US-08: Offline mode (Phase 1)
- **[CI]** Given no reachable lab, when `flabel --offline capture.pcap` runs, then it completes successfully, emits Tier 2 labels, and the output records that Tier 1 was not attempted.
- **[CI]** Given an `--offline` run, then no label claims a Tier 1 source.

### US-21 / US-23: Tier 1 (Phase 2)
- **[LAB]** Given the default invocation and a reachable device, then Tier 1 labels are produced and each records threat id, content release version, and PAN-OS version.
- **[LAB]** Given the default invocation and an unreachable device, then the run fails naming the dependency, and no partial label file is written.
- **[CI]** Given Phase 2 output parsed by a Phase 1 consumer, then it parses without modification and the schema version is unchanged (Goal 6).

## 10. Technical Considerations

**Architecture / System Design Notes:**

- **Phase 1 is file-only.** Zeek and Suricata read the normalized capture directly. One machine, no lab, no clocks, no network I/O during a run. Fully deterministic given a fixed Zeek seed, a pinned snapshot, and pinned tool versions.
- **Phase 2 adds replay** past a PANW VM-Series in a two-zone Layer 3 configuration. Confining replay to the one component that needs it is what makes this a configuration boundary rather than a rewrite.
- **Phase 2 must be additive** (Goal 6): new `sources[]` entries, no schema version change, no consumer change.
- Correlation is tuple-plus-time driven; replay-time stamps are never emitted as capture-timeline values.
- Fingerprint matching uses Suricata's native `ja3.hash` / `ja4.hash` keywords, inheriting Tier 2's filtering and provenance.
- Stack: Python 3.12, uv, pytest, ruff. Test-first development.

**Dependencies (internal and external):**

- **External tools (Phase 1):** Zeek 6+ with `zeek/foxio/ja4`, Suricata 8+ with `ja3`/`ja4` fingerprinting enabled, Wireshark `editcap`.
- **CI toolchain container (Phase 1 scaffold requirement):** current CI is `ubuntu-latest` + `uv sync` and cannot run the pipeline at all. A container with **pinned** Zeek, Suricata, and Wireshark versions is required — both to test the pipeline and because reproducibility across unpinned tool versions is meaningless.
- **Rule and IOC feed endpoints**, reached only by `flabel rules update`.
- **Phase 2:** tcpreplay, `tcpprep`, PAN-OS API (`kevinsteves/pan-python`), a PANW VM-Series **with a Threat Prevention subscription** — without the subscription the device produces no threat logs and Tier 1 is empty. Licensing model (BYOL vs Marketplace PAYG) and estimated monthly lab cost are unresolved (§13 Q12). Note the asymmetry to resolve at Phase 2: ET Pro was excluded at ~$900/sensor/yr while the PANW subscription is likely an order of magnitude more.
- **Licensing:** plain JA4 is BSD 3-Clause; JA4+ is FoxIO License 1.1 (non-commercial), approved with Legal review in progress. Rule text is reproduced in output, so per-source licence and attribution are recorded (§6.6).

**Data & Privacy Considerations:**

- **Captures contain real network traffic** and may include personal data, credentials in cleartext protocols, internal addressing, and business-sensitive content. Zeek logs derived from them include URLs, DNS queries, and certificate details.
- The repository is **public**. Captures, Zeek logs, `labels.json`, credentials, and internal identifiers must never be committed. `.gitignore` excludes `*.pcap`, `*.pcapng`, `*.log`, `zeek/`, and `.env`.
- **Those ignore rules currently also block the test fixtures** the acceptance criteria require. Narrow negations scoped to `tests/fixtures/**` are a scaffold requirement; the broad ignores stay.
- **Fixture strategy (resolves Q8):**
  - The **benign canary is synthesized**, not sourced. This matters for correctness, not just licensing: a real-world "benign" capture may legitimately trip an admitted rule, which would make the canary flaky and its failures ambiguous. A synthesized capture makes *zero labels* a known-correct expectation rather than an empirical hope. It contains no real hosts, payloads, or addresses.
  - The **malicious canary is a small publicly-published capture**, because the test needs a rule to genuinely fire and synthesizing that convincingly is harder than sourcing it. Its origin and licence are recorded in the repo alongside it.
  - No other fixture may contain real capture data.
- **Phase 1 processes publicly-published captures only** (resolves Q11), with each capture's origin and licence documented. This defers the contractual question of whether customer- or internal-derived captures may lawfully train a product model — a question that must be answered *before* flabel is pointed at such traffic, and one that is contractual rather than technical. Output retention and location are deferred with it.
- No maximum capture size is enforced. A tested known-good size is established at build; an OOM-killed Zeek surfaces via `tool_failures[]` rather than yielding a silently truncated label set.
- Labels and Zeek logs inherit the sensitivity of their source capture. flabel transmits capture data nowhere.

**Performance / Scale Requirements:**

- Phase 1 runs at file-read speed; Zeek is typically the bound.
- One capture per invocation; no concurrency requirement within a run.
- **Phase 2:** throughput is bounded by the controlled replay rate, deliberately — fidelity over speed. The device is a global mutex, so concurrent runs must be serialized (§13 Q5).
- No maximum capture size set; Zeek memory on multi-GB captures is a known operational cliff and needs a stated known-good figure (§13 Q6).

## 11. Success Metrics

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Metric** | **Target** | **How Measured** | **Review Date** |
| Provenance completeness | 100% of labels carry every field required for their source class | Automated check in CI and per run | TBD |
| Reproducibility | 100% — canonical `labels.json` identical across two runs with pinned snapshot and tool versions | CI regression test | TBD |
| Enumerated loss conditions covered | 100% — every Phase 1 condition has a field and a fault-injection test | CI test count vs the §6.6 table | TBD |
| **Specificity canary** | **Zero labels on the benign fixture** | CI regression test; any label fails the build | TBD |
| Sensitivity canary | ≥1 label on the known-malicious fixture | CI regression test | TBD |
| Non-verdict source leakage | Zero labels attributable to a non-verdict source | CI assertion | TBD |
| Unmatched detection rate | Tracked and reported per run; threshold TBD (§13 Q9) | `unmatched_count` | TBD |
| Supported-format success rate | 100% of pcap, pcapng, gzipped inputs process or fail with a clear reason | CI test matrix | TBD |
| Tier 2 admitted-rule count | Recorded per source, including a separate JA4 count | `flabel rules update` output (issue #11) | TBD |
| Replay integrity *(Phase 2)* | Packets sent equal packets seen after device discards, or reported | Per-run reconciliation | Phase 2 |

**Note:** these metrics measure *pipeline integrity* and *gross specificity*, not label accuracy. There is no false-positive rate measurement — see Risks.

## 12. Risks & Mitigations

|  |  |  |  |
| :-: | :-: | :-: | :-: |
| **Risk** | **Likelihood** | **Impact** | **Mitigation** |
| **Ungated rule sources produce systematically false labels.** In Phase 1 Tier 2 is the entire product, so wholesale-admitted sources are the dominant quality risk — the `confidence` filter covers ET Open only | High | High | `admission_basis` machine-visible so consumers can exclude ungated sources; non-verdict sources cannot label at all; **the Goal 5 benign canary is the standing detector and runs on every build**. `pawpatrules` is admitted with its FP risk knowingly accepted (Craig's decision), with the canary as its review |
| Indicator-reference labels mark benign infrastructure (resolver, proxy) as malicious — a correlated, repeated error, worse than random FPs | High | High | `label_basis` required on every label; canary fixture exercises DNS/URL rules specifically |
| Trust-by-construction gives no false-positive rate if a label consumer asks | High | Med | Goal 5 canary converts an unfalsifiable claim into a falsifiable one; snapshots make labels reproducible and auditable. Accepted limitation, recorded |
| Reproducibility quietly abandoned when the byte-identity test fails | Med | High | Fixed Zeek seed, canonical output form, pinned tool versions in CI container, explicit excluded-field list |
| Ruleset snapshot lifecycle undefined, so runs fetch at start and determinism dies | Med | High | Snapshots are immutable content-hashed artifacts produced by a separate command; labelling runs perform no network I/O |
| Licence/attribution defect baked into every output | Med | Med | Per-source `licence` in provenance; `NOTICE` emitted per run |
| JA4 labeling path ships with no content and rots untested | Med | Med | Admitted JA4 count surfaced every run; path tested against a synthetic JA4 rule |
| JA4+ licensing (FoxIO 1.1, non-commercial) conflicts with output feeding product models | Med | High | Legal review in progress; plain JA4 (BSD) is the documented contingency. **Craig's decision: JA4+ remains the default while review proceeds** |
| Capture data or credentials leak into the public repository | Low | High | `.gitignore` coverage; fixture negations scoped to `tests/fixtures/**`; no real capture data in fixtures; pre-commit secret checks |
| **Phase 2 may be infeasible as designed** — whether a cloud VM-Series can observe replayed capture traffic is unverified, and vwire may be an on-premises-only mode | Med | High | Phase 1 delivers full value without Tier 1. **Craig's decision: the reachability spike runs after Phase 1 rather than in parallel — feasibility and procurement lead time are knowingly on the Phase 2 critical path** |
| Phase 2 replay loses most mid-stream flows (non-SYN) and the fidelity alarm becomes noise | Med | Med | `tcpprep` client/server split; non-SYN rejections recorded separately from drops; yield measured by spike before Phase 2 planning |
| Phase 2 recurring cost unbudgeted | Med | Med | Licensing model and monthly estimate required before Phase 2 planning (§13 Q12) |

## 13. Open Questions

|  |  |  |  |  |
| :-: | :-: | :-: | :-: | :-: |
| **#** | **Question** | **Owner** | **Target Date** | **Resolution** |
| 1 | Who are the PRD stakeholders — reviewers and approvers beyond Craig and Legal? | Craig | TBD | Open |
| 2 | What is the target release for Phase 1? | Craig | TBD | Open |
| 3 | Does Legal approve JA4+ under FoxIO License 1.1? | Legal | TBD | Open — JA4+ is the default meanwhile; plain JA4 is the contingency |
| 4 | What is the admitted-rule count per source once the filter is applied, and is Tier 2 coverage adequate? | Craig | Early Phase 1 | Open — issue #11 |
| 5 | How are concurrent Phase 2 runs against one device serialized? | TBD | Phase 2 spec | Open |
| 6 | Is there a maximum supported capture size, and what happens beyond it? | Craig | — | **Resolved 2026-08-11:** no enforced ceiling. Build establishes a tested known-good size and documents it; an OOM-killed Zeek is an enumerated loss condition (`tool_failures[]`) so a truncated label set is never silent |
| 7 | Exact bounded-`receive_time` filter syntax, and does the threat log need a settling delay? | TBD | Phase 2 spike | Open |
| 8 | What fixture strategy provides test captures without real traffic — including the Goal 5 benign and malicious canaries? | Craig | — | **Resolved 2026-08-11:** benign canary synthesized (so zero labels is known-correct, not empirical); malicious canary is a small publicly-published capture with origin and licence recorded (§10) |
| 9 | Should `unmatched_detections[]` have a failure threshold rather than being reported without a target? | Craig | — | **Resolved 2026-08-11:** warn on any unmatched; fail above a configurable threshold, default 1% of detections (§6.5). Phase 2 gets its own looser threshold. **Amended 2026-08-13 (#84):** the share is over *correlatable* detections |
| 10 | What are the review dates for the success metrics? | Craig | TBD | Open |
| 11 | Where do captures come from (customer / internal / public), and does that constrain using them to train a product model? | Craig | — | **Resolved 2026-08-11:** Phase 1 processes **publicly-published captures only**, with origin and licence documented. This sidesteps the contractual question while the pipeline is built. Pointing flabel at internal or customer traffic requires answering it first — recorded as a gate, not a blocker |
| 12 | PANW licensing model and estimated monthly lab cost; and does that change the ET Pro decision? | Craig | Before Phase 2 planning | Open |
| 13 | Can `zeek/foxio/ja4` emit plain JA4 only, if the JA4+ contingency is invoked? | TBD | Phase 1 spec | Open |
| 14 | What is the Phase 2 replay rate ("controlled rate")? | TBD | Phase 2 spike | Open |
| 15 | Where do JA4 rules come from — wait for ET, evaluate a feed, or self-derive? | Craig | Post-Phase 1 | Open — issue #13 |
| 16 | **Is virtual-wire replay achievable for a VM-Series in GCP at all?** Public-cloud VM-Series interfaces may be Layer 3 only, and a VPC drops arbitrary Ethernet frames and spoofed source IPs — which is what replaying an original capture sends. Unverified; recorded as an assumption, not a fact | Craig | Before Phase 2 planning | **ANSWERED 2026-08-17** — `docs/phase-2-reachability-spike.md`. Virtual wire: **no**, and for the reason half-guessed here — a vwire interface has no IP, and GCP forwards by destination IP, so there is nothing to route to. Two-zone **Layer 3**: **yes**. The other half of the assumption was **wrong in our favour**: with `--can-ip-forward` and a VPC custom route, GCP delivered the replayed traffic carrying the capture's original spoofed source addresses, and the 5-tuple arrived intact — so correlation needs no address map and the `tcprewrite --pnat` fallback was never required |

## 14. Basic Test Cases

|  |  |  |  |  |
| :-: | :-: | :-: | :-: | :-: |
| **#** | **Case** | **Expected Behavior** | **Observed Behavior** | **Pass/Fail** |
| 1 | Valid pcap, `--offline` | Directory `{capture-name}_{datetime}` with `zeek/`, `labels.json`, `NOTICE` | | |
| 1b | Default invocation, no `--offline` (Phase 1) | Prints `Coming Soon (TM)` naming `--offline`; no output directory; non-zero not-implemented exit | | |
| 2 | Capture with no detections | Success; `labels` empty | | |
| 3 | pcapng input | Normalized to pcap, processed, conversion recorded | | |
| 4 | Gzipped pcap input | Decompressed and processed | | |
| 5 | Multi-datalink pcapng | Dominant link type processed; discarded types and packet count recorded; `input_status: partial` | | |
| 6 | Unreadable header | Hard failure; no labels | | |
| 7 | Truncated pcap | Processed; `input_status: partial` with packet count and offset | | |
| 8 | Truncated pcapng | Hard failure directing repair via `editcap` | | |
| 9 | Flow flagged by two rules | Single entry; both in `sources[]` | | |
| 10 | Detection uncorrelatable to a flow | In `unmatched_detections[]` with reason; counted | | |
| 11 | Tuple maps to two `conn.log` records | Resolved by time containment; if ambiguous, emitted unmatched | | |
| 12 | Re-run of a processed capture | New sibling directory; prior untouched; same `uid` for the same flow | | |
| 13 | Two runs, pinned snapshot and versions | Canonical `labels.json` identical excluding run times | | |
| 14 | **Benign canary fixture** | **Zero labels; build fails on any label** | | |
| 15 | **Known-malicious canary fixture** | **At least one label** | | |
| 16 | Non-verdict source rule fires | No label references it; appears as enrichment only | | |
| 17 | IOC rule matching a DNS query | Label carries `label_basis: indicator-reference` | | |
| 18 | TLS capture | JA4 present in Zeek output and on labels. ~~Zeek and Suricata JA4 agree~~ — deferred with #13 (#90) | | |
| 19 | Synthetic `ja4.hash` rule matches | Tier 2 label produced, structurally identical to a content match | | |
| 20 | No JA4 rules in snapshot | JA4 path recorded active with admitted count zero | | |
| 21 | Labelling run | No network connection attempted | | |
| 22 | Non-existent `--ruleset-snapshot` | Run fails; no labels | | |
| 23 | Every emitted label | All fields required for its source class present; `flow.uid` resolves to exactly one `conn.log` record | | |
| 24 | Each Phase 1 loss condition (§6.6) | Fault injection populates the named field | | |

## 15. References & Related Documents

- [`docs/eng-review.md`](eng-review.md) — Stage 3 engineering review; source of the v0.4 changes
- [`docs/research.md`](research.md) — Stage 1 research findings and decisions
- [`docs/research-brief.md`](research-brief.md) — approved research brief (Stage 1 gate)
- [`docs/prep-n-research.md`](prep-n-research.md) — original design brief
- [`docs/status.yaml`](status.yaml) — pipeline state and stage issue mapping
- [OISF suricata-intel-index](https://github.com/OISF/suricata-intel-index/blob/master/index.yaml) — rule source licences and provenance
- [Signature Metadata — Emerging Threats wiki](https://community.emergingthreats.net/t/signature-metadata/96) — `confidence` / `signature_severity` definitions
- [JA3/JA4 Keywords — Suricata docs](https://docs.suricata.io/en/latest/rules/ja-keywords.html)
- [FoxIO License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) — JA4+ commercial-use terms
- [Retrieve Logs — PAN-OS XML API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs)
- GitHub issues [#10](https://github.com/DeepTempo/flabel/issues/10), [#11](https://github.com/DeepTempo/flabel/issues/11), [#13](https://github.com/DeepTempo/flabel/issues/13)

> **Note on section numbering:** the source template numbers Basic Test Cases as "15" and places it before "14. References", and renders the former as body text rather than a heading. Both are corrected here (Test Cases = 14, References = 15, both proper headings). Worth fixing in the template itself.
