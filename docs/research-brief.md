# Research Brief — flabel

**Stage 1 gate.** Approved by Craig on: 2026-08-11 · Issue: #1

## Objective

Determine which detection sources, rulesets, and fingerprint feeds `flabel` can trust enough to produce malicious-flow labels for detection-model training — and confirm that the replay-based architecture required by a Tier 1 NGFW is workable — so that a PRD can specify the `labels.json` schema and pipeline without guessing.

## Decisions already made (not open for research)

These came out of the grill and bound the research:

| Decision | Detail |
| --- | --- |
| NGFW is in | Palo Alto Networks VM-Series is a **Tier 1 trust source** for v1. The replay architecture it requires is accepted, not re-litigated. |
| Trust is **per-source**, not per-rule | A label carries its source's tier. Per-rule confidence metadata is *not* modelled in the output. |
| Consequence | Because trust isn't modelled per rule, **ruleset curation is the entire false-positive defence.** Research must answer *which rules are admitted*, not *how confident each rule is*. |
| Ruleset budget | Free sources preferred. A **30-day delay is acceptable** for high-confidence free rulesets. |
| Source breadth | Look beyond the OSS projects themselves: government agencies, highly regarded third parties, and rulesets curated by long-time security professionals (including top public repos). |
| Licensing | **Licence status must be recorded, not satisfied.** A high-quality source with no explicit licence is acceptable — note it as unlicensed/unstated. Do not exclude a trustworthy source for lacking a licence, and do not silently assume one. |
| Validation | **Trust by construction.** No ground-truth corpus validation in scope — see Out of scope. |

## Key questions to answer

### A. Content-inspection sources and rulesets
1. **Snort or Suricata?** Judge on technical merit *and* — likely decisive — the volume of high-confidence rulesets actually available for each.
2. Which specific free rulesets clear the "high confidence" bar? Candidates include ET Open (metadata-filtered), Talos registered (30-day delay), government-published sets, reputable third-party and professionally-curated repos. Each needs **source, provenance, licence status, update cadence, and why it is trusted** — where "licence status" may legitimately be *unstated/unlicensed*, recorded as such.
3. Given per-source tiering, what **rule-admission criteria** yield a uniformly high-confidence Tier 2 set? (Rule metadata such as `signature_severity`, `confidence`, and `deployment` is machine-readable and may serve as the filter.)
4. What does PANW VM-Series contribute as Tier 1 — what threat metadata does it expose, and how are detections queried programmatically?
5. Stretch: is there a free/OSS L7 application-detection equivalent to PANW/FortiGate?

### B. Encrypted traffic — JA3/JA4
6. Which JA3/JA4 feeds come from **highly trusted sources** (multiple; industry-standard, government, research-grade)? Provenance and update cadence for each.
7. How are multiple feeds **collated and deconflicted** into one list — specifically, what happens when two feeds disagree about the same fingerprint?
8. **Can a threat *name* be derived from a JA3/JA4 match**, or is the verdict only "matches a known-bad fingerprint"? This determines how usable these labels are for training.
9. What is the known **collision / false-positive behaviour** of JA3/JA4 fingerprinting — and does that make it a labelling source in its own right, or enrichment only?
10. Can Zeek compute both JA3 and JA4 natively, and at what version / with which plugins?

### C. Architecture and replay fidelity
11. **Replay fidelity:** does `tcpreplay --topspeed` preserve what the inspection engine needs? Rewriting inter-packet timing can affect reassembly, flow timeouts, and rate-based rules. Are packet drops a risk — a dropped packet is a *missing label*.
12. **Tap vs routed** deployment for PANW: which detections are possible in tap/sniffer mode, and does tap silently disable a class of rules?
13. **Correlation:** how is the PANW log query bounded by the replay window, what clock-sync accuracy does that demand, and how are device detections (stamped at replay time) mapped back to the original capture's flows?
14. Which **pcap formats** can each component ingest (pcap, pcapng, gzipped, size limits)? This defines "all commonly supported formats."
15. What are the 2–3 viable overall architectures, and which is recommended?

### D. Trust tiers
16. What evidence justifies assigning a source to Tier 1/2/3, and which tier does each source land in?

## Constraints

- **Stack:** Python 3.12 + uv + pytest + ruff (already scaffolded). Test-first via `/tdd`.
- **Environment:** GCP project `${GCP_PROJECT}` — Ubuntu host (flabel), PANW VM-Series (inline inspection), Snort/Suricata host. NTP sync required across all hosts.
- **Public repo:** no secrets, credentials, capture data, or internal identifiers may be committed.
- **Output contract:** `{input-pcap-name}/zeek/` (all Zeek logs) + `{input-pcap-name}/labels.json`.
- **Per-label data:** threat name, full flow tuple (src/dst IP, src/dst port, protocol), detection timestamp, detection source.
- **Primary quality bar:** label trustworthiness over label volume. Every verdict must be traceable to its origin.
- **Deliverable:** an environment diagram compatible with both draw.io and mermaid.

## Exit criteria

Research is done when:

1. Snort vs Suricata is recommended, with justification covering both technical merit and high-confidence ruleset volume.
2. Every proposed ruleset and feed is documented with source, provenance, **licence status** (an explicit licence, or an explicit "unstated" — both acceptable, neither may be left blank or assumed), update cadence, and a written justification for trusting it.
3. Rule-admission criteria for a uniformly high-confidence Tier 2 set are defined.
4. Every detection source has a tier assignment with justification.
5. The JA3/JA4 questions are answered: threat-name derivability, collation/deconfliction approach, and a recommendation on labelling source vs enrichment.
6. Replay fidelity, tap-mode limits, and the clock/correlation approach are assessed, with risks ranked.
7. A pcap-format support matrix per component exists.
8. 2–3 viable architectures are compared, with a recommendation.
9. Top 5 risks are ranked, each with a concrete de-risking action.
10. Sources are cited; uncertainty is flagged rather than guessed.
11. 3–5 open questions are raised for Craig.

## Out of scope

- **Label validation against a ground-truth corpus.** Decided: trust by construction, resting on source tiers plus curated high-confidence rulesets. *Documented assumption:* the trustworthiness claim will be argued from provenance, not measured — so `/project:verify` can confirm the pipeline ran correctly but not that its verdicts are right. Revisit at eng-review if the claim needs to be defensible to an external consumer of the labels.
- Exact `labels.json` schema, confidence representation, and versioning — PRD.
- Whether benign flows are labelled at all (negative class) — PRD.
- Actual GCP provisioning and device configuration — **deferred, not dropped.** Designing *and building* the lab environment (Ubuntu host, PANW VM-Series, Snort/Suricata host, tap wiring, NTP) is a required project deliverable, along with the draw.io- and mermaid-compatible diagram. The environment gets designed at `/project:plan` (as spec + numbered steps) and built at `/project:build`. Research only needs to surface the constraints that shape that design — tap-vs-routed, clock accuracy, replay drops — not the build itself.
- FortiGate as the NGFW; PANW VM-Series is chosen.
- Paid rulesets, unless the research finds nothing free clears the trust bar — in which case flag it explicitly rather than lowering the bar.
- TLS decryption / MITM inspection — impossible on after-the-fact captures; fingerprinting is the substitute.
