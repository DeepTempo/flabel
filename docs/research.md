# Research — flabel

**Stage 1, Part B.** Driven by the approved `docs/research-brief.md` · Issue #1 · 2026-08-11

---

## Headline recommendation

**Run Suricata and Zeek directly against the capture file. Replay only for PANW.**

The brief's flow sends everything through the inline device via replay. That isn't necessary: Suricata and Zeek both read a pcap natively (`suricata -r`, `zeek -r`), and only PANW VM-Series has no offline pcap ingestion — Palo Alto's own guidance is to build a virtual-wire pair and replay at it from an external server ([LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/replay-pcap/td-p/36261)).

That split matters because **replay is the single largest threat to label fidelity.** Rewritten packet timing can disturb reassembly and rate-based rules, and a dropped packet is a *missing label*. Keeping the Tier 2 and Tier 3 paths offline makes them deterministic and byte-for-byte reproducible, and confines the nondeterminism to the one source that cannot avoid it. It also means a Tier 2/Tier 3-only run needs **no lab environment at all** — useful for testing and for captures processed before the lab exists.

**Second recommendation: drop JA3 in favour of JA4, and treat fingerprint hits as enrichment rather than labels.** Evidence below — this is the most significant finding in this research and it contradicts the brief's assumption that JA3/JA4 feeds can supply trustworthy labels.

---

## A. Content-inspection sources and rulesets

### A1. Snort 3 or Suricata? → **Suricata**

Your stated tiebreaker was volume of high-confidence rulesets, and Suricata wins it decisively — but on a subtler axis than raw rule count.

| | Suricata | Snort 3 |
| --- | --- | --- |
| Free ruleset ecosystem | ~30 sources indexed centrally (below) | Talos registered + community |
| High-confidence *selection* mechanism | Per-rule `confidence` / `signature_severity` metadata | Policy tiers (connectivity / balanced / security / max-detect) |
| Free-tier delay | ET Open: none | Registered: 30 days behind subscriber, no zero-days |
| Rule compatibility | Reads Snort rules (imperfectly) | Cannot read Suricata-native keywords |
| Native pcap ingest | Yes (`-r`) | Yes (`-r`) |

Two decisive points. First, Suricata has a **central, machine-readable index of free rule sources** — `OISF/suricata-intel-index` — with a declared licence per source, which is exactly the provenance record your brief demands and Snort has no equivalent of. Second, Suricata-native rules can express protocol fields Snort cannot, so equivalent detections are more precise with fewer false positives ([comparison](https://www.decryptiondigest.com/blog/snort-vs-suricata-ids-ips-comparison)). One study measured Suricata running ~4,600 more enabled rules than Snort on the same traffic.

Snort's counter-argument is real and worth recording: Talos LightSPD is maintained by **dedicated paid researchers**, whereas ET Open is largely community-produced ([Snort blog](https://blog.snort.org/2020/12/soft-release-lightspd-new-rules-package.html)). If uniform curation mattered more than breadth, Snort would win. Under per-source tiering — where we curate the input set ourselves — breadth plus filterable metadata is more useful.

**Nothing prevents running both.** They'd both be Tier 2, and deduplication would be needed. Not recommended for v1.

### A2. Free rule sources, with licence status

From `OISF/suricata-intel-index` (authoritative, machine-readable). **Licence status recorded as required — including the non-standard cases.**

**Recommended for Tier 2 admission:**

| Source | Vendor | Licence | Notes |
| --- | --- | --- | --- |
| `et/open` | Proofpoint | **MIT** | Primary set. Filter by metadata — see A3. |
| `oisf/trafficid` | OISF | **MIT** | Traffic identification, not threat detection. Enrichment. |
| `abuse.ch/feodotracker` | abuse.ch | **CC0-1.0** | Botnet C2 IPs, actively maintained. |
| `abuse.ch/urlhaus` | abuse.ch | **CC0-1.0** | Malware-distribution URLs. |
| `abuse.ch/sslbl-c2` | abuse.ch | **CC0-1.0** | C2 servers by blacklisted certificate. |
| `malsilo/win-malware` | malsilo | **MIT** | Windows malware artifacts. Small, focused. |
| `stamus/lateral` | Stamus Networks | **GPL-3.0-only** | Lateral movement. Copyleft — rules only, no linking concern. |
| `the-hunters-ledger/open` | The Hunters Ledger | **CC-BY-4.0** | Attribution required. Derived from malware investigations. |
| `pawpatrules` | pawpatrules | **CC-BY-SA-4.0** | Share-alike. Broad scope; needs FP review. |

**Excluded, with reasons:**

| Source | Licence | Why excluded |
| --- | --- | --- |
| `tgreen/hunting` | GPLv3 | Self-described **hunting / anomaly-detection** ruleset. Your brief explicitly excludes threat-hunting rules in favour of detection. Policy exclusion, not a quality judgement. |
| `etnetera/aggressive` | MIT | Self-described "**aggressive** IP blacklist". Incompatible with a low-FP bar. |
| `ptresearch/attackdetection`, `ptrules/open` | **Custom** (non-standard) | Two concerns. The licence is non-standard — acceptable per your guidance if noted, and it is noted. But the vendor, **Positive Technologies, has been under US sanctions since April 2021**. Against a requirement for "highly trusted sources," a sanctioned entity is a provenance problem independent of rule quality, and plausibly a compliance one for DeepTempo. **Recommend exclude; flagging as your call.** |
| `et/pro`, `scwx/*`, `stamus/nrd-*` | Commercial | Require paid subscription. `scwx/malware` is notable — self-described "**high-fidelity, high-priority**" — and is the closest thing to a purpose-built low-FP set. Worth pricing if free sources underdeliver. |

**Government sources:** no government body publishes a maintained, general-purpose Suricata/Snort ruleset. CISA and allied agencies publish Snort signatures *inside individual advisories*, which are point-in-time IOCs rather than a feed. Harvesting them would mean scraping advisories — real work, low yield, no update cadence. **Recommend: not a v1 source.** This is a gap against your "government sources" ask, and I'd rather say so than pad the list.

### A3. Tier 2 rule-admission criteria → filter on ET metadata

This is where per-source tiering gets its false-positive defence.

ET introduced a `confidence` metadata tag in 2022 specifically to express **false-positive likelihood** — "High" confidence means minimal FP likelihood. Coverage has grown from 30% to **over 70% of the ruleset, with newer rules at 100%** ([Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/emerging-threats-updates-improve-metadata-including-mitre-attck-tags), [ET wiki](https://community.emergingthreats.net/t/signature-metadata/96)). `signature_severity` runs Informational → Critical.

**Proposed admission rule:**

```
admit if   metadata.confidence == High
  and     metadata.signature_severity in (Major, Critical)
  and     source in the recommended table above
```

Two consequences to decide at PRD time:

- **The <30% of ET Open rules lacking a `confidence` tag are excluded** by this rule. Fail-closed is the right default when trustworthiness is paramount, but it discards untagged rules that may be good.
- The admitted rule set must be **snapshotted and recorded per run** (source + version + date), because the filter's output changes as ET revises metadata. Without that, two runs of "the same" flabel produce differently-grounded labels.

### A4. PANW VM-Series as Tier 1

- **Tap mode works for our purpose.** In tap mode the firewall cannot block or reset, so every security profile action is set to `alert` — which is precisely what a labeller wants. It still performs App-ID and threat identification, and writes to the threat log ([PANW docs](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-networking-admin/configure-interfaces/tap-interfaces)).
- **But Palo Alto's own replay guidance is a virtual-wire pair**, not tap. Vwire is inline-but-transparent and is the configuration their community recommends for replaying a pcap at the device. Your brief prefers tap. **Unresolved:** whether tap-plus-mirror and vwire yield identical detection sets. This needs an empirical check on the actual device — see Open Questions.
- **Threat name is available.** PAN-OS threat logs carry the threat/content name, and the XML API retrieves Threat-type logs with filter expressions equivalent to the Monitor tab, including a `receive_time` field ([Retrieve Logs](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs)). `kevinsteves/pan-python` is the mature Python client. **Not yet verified:** the exact filter syntax for a bounded `receive_time` range, and whether log-write latency requires a settling delay before querying. Verify on-device.

### A5. Free L7 equivalent to PANW App-ID → partial, not equivalent

Zeek plus Suricata's app-layer protocol detection covers protocol identification well. Neither reproduces App-ID's application-level catalogue. `oisf/trafficid` adds some identification. **Conclusion: no free equivalent; PANW's Tier 1 contribution is genuinely distinct.** That is an argument *for* keeping the NGFW, consistent with your decision.

---

## B. Encrypted traffic — JA3/JA4

This section changed my view of the brief's design. Reporting it plainly.

### B1. The canonical free JA3 feed is abandoned and self-declares an FP problem

abuse.ch SSLBL's JA3 fingerprint blacklist is the source the brief implicitly assumes. Fetched directly:

- **Most recent listed fingerprint: `2021-08-03`.** Five years stale. The *file* regenerates every 5 minutes, so automated freshness checks that watch file mtime would report it healthy — the *content* is frozen.
- The page carries this warning: **"These fingerprints have not been tested against known good traffic yet and may cause a significant amount of FPs!"**
- Licence is **CC0-1.0** — unrestricted, commercial use fine. Licensing is not the problem; provenance quality is.

A feed that is both abandoned and self-declared as untested against benign traffic cannot be a labelling source for ML training data under a per-source trust model with no per-rule filter.

### B2. JA3 is structurally degraded, independent of feed quality

- Chrome and Firefox **shuffle ClientHello extension order**, which changes the JA3 hash for the same client. Stable JA3 values can no longer be assumed.
- JA3's limited attribute set produces **collisions** — unrelated clients sharing a fingerprint, so benign traffic can match a "malicious" JA3 ([Fingerprint.com](https://fingerprint.com/blog/limitations-ja3-fingerprinting-accurate-device-identification/)).

For training data this failure mode is the expensive one: a collision mislabels *benign* traffic as malicious, teaching the model the wrong thing.

### B3. JA4 is the successor, is maintained, and is partly licence-restricted

- **Maintained:** `zkg install zeek/foxio/ja4`, v0.18.8. Zeek 5+ supported, Zeek 6+ for QUIC. Zeek published a how-to in January 2026 ([zeek.org](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)).
- JA4 sorts extensions, so it is **resistant to the shuffling that breaks JA3**.
- **Licence split matters:**
  - **JA4 (TLS client) — BSD 3-Clause**, with FoxIO explicitly claiming no patent rights.
  - **JA4+ (JA4S, JA4H, JA4X, JA4L, JA4SSH, JA4T, …) — FoxIO License 1.1: non-commercial only.** Internal use securing your own company is permitted; selling it in a product requires an OEM licence from FoxIO.

**flabel produces training data for detection models.** If those models ship in a DeepTempo product, using JA4+ plausibly constitutes monetization. **Recommendation: use only plain JA4 (BSD), avoid the JA4+ extensions.** That keeps the project unambiguously clear of the restriction. This is a legal question, not an engineering one — flagged for your decision, and it is exactly the licence-status issue your correction to the brief anticipated.

### B4. Can a threat *name* come from a fingerprint? → **No, not reliably**

A fingerprint match yields "this client matches a known-bad fingerprint." Malware-family attribution only exists if the feed supplies it, and the one CC0 feed that did is frozen at 2021. `ja4db` (FoxIO) catalogues fingerprint→application mappings for identification, not malicious verdicts. **Answer: a Tier 3 label would carry no trustworthy threat name.**

### B5. Recommendation: Tier 3 is **enrichment, not a label**

Combining B1–B4: no maintained, trustworthy, free malicious-fingerprint feed exists; JA3 is collision-prone and unstable; JA4 is sound as a *fingerprint* but has no reputable free malicious-verdict feed behind it; and no threat name is derivable.

**Recommend:** compute JA4 for every TLS connection and record it in the Zeek output and alongside labels as an *attribute*, but **do not emit a malicious label on fingerprint match alone.** This preserves all the analytic value — a model can learn from JA4 as a feature, and analysts can pivot on it — without asserting a verdict the evidence doesn't support.

This contradicts the brief, which treats JA3/JA4 as a second labelling source. It's your call to overrule; I'd rather flag it now than produce labels I can't defend.

### B6. Feed deconfliction

Largely moot if B5 is accepted — with no feed supplying verdicts, there is nothing to deconflict. Should you keep fingerprint labelling, the required design is: per-feed provenance retained per fingerprint, never silently merged; disagreement resolved by recording *all* asserting feeds rather than voting; and a snapshot date pinned per run.

---

## C. Architecture, replay fidelity, and formats

### C1. Three viable architectures

**Approach A — Offline only (no NGFW).** `zeek -r` + `suricata -r`, merge, emit. One host, no lab, no clocks, fully deterministic and reproducible. **Excluded by your Tier 1 decision**, but it is the correct v0/test configuration and the fallback if the lab is delayed.

**Approach B — Hybrid: offline OSS + replay for PANW only. ⭐ Recommended.** Zeek and Suricata read the file directly; only PANW gets a replay. Confines all replay-fidelity and clock-correlation risk to the Tier 1 path, and Tier 2/3 stay reproducible. Costs one extra concept: two ingest paths for one capture.

**Approach C — Full replay (as briefed).** Everything past the tap. Matches the original design, and is arguably more "realistic". But it makes the Suricata path nondeterministic and drop-prone **for no benefit**, since Suricata reads the file perfectly well. Not recommended.

### C2. Replay fidelity — the top risk

- `--topspeed` explicitly trades timing accuracy for speed; tcpreplay's own docs note that batching packets for throughput costs accuracy ([tcpreplay man](https://tcpreplay.appneta.com/wiki/tcpreplay-man.html)).
- Rewritten timing can affect stateful reassembly, flow timeouts, and any rate-based rule. **A dropped or reordered packet is a missing label, not a wrong one** — and a missing label is invisible in the output.
- **De-risking:** replay at a controlled rate rather than `--topspeed`; verify packet counts sent vs. seen; run the same capture twice and diff the detection sets — instability across identical runs quantifies the problem directly. I could not find published measurements of `--topspeed`-induced missed alerts; this needs empirical measurement in the lab, not a literature answer.

### C3. Clock and correlation

Bounding the PANW log query by the replay window requires that flabel's clock and the firewall's agree. NTP is necessary but I found **no published figure** for the required accuracy — it depends on log-write latency and how tightly the window is drawn. Practical approach: record replay start/end from flabel, pad the query window generously, then filter returned records by flow tuple rather than relying on time alone. Time bounds the query; the tuple does the matching.

**Unsolved and worth PRD attention:** detections are stamped at *replay* time, but labels must reference the *capture's* original timeline. The mapping is not 1:1 under `--topspeed`, because the replay compresses the capture's duration. Correlation should therefore be tuple-driven, with replay-time used only to scope the query.

### C4. pcap format support matrix

| Component | pcap | pcapng | Notes |
| --- | --- | --- | --- |
| Zeek | Yes | **No** | `zeek -r` on pcapng produces parser errors; conversion via `editcap -F pcap` required ([Zeek community](https://community.zeek.org/t/analysing-pcapng-files-from-wireshark-traffic-captured-with-zeek-or-spicy/6959)) |
| Suricata | Yes | **Partial** | Reads pcapng 1.0; breaks on multi-interface files with differing datalinks ([Feature #432](https://redmine.openinfosecfoundation.org/issues/432)) |
| tcpreplay | Yes | Partial | Same multi-datalink caveat |
| PANW | n/a | n/a | No file ingest at all — replay only |

**This kills "all commonly supported formats" as a naive requirement.** Since pcapng is what Wireshark produces by default, flabel needs an **ingest normalization stage**: detect format, convert pcapng → pcap with `editcap`, split multi-datalink captures first (`frame.interface_id` / `frame.dlt`), and record the conversion in provenance. Gzipped input needs decompression too. This is a real work item the brief didn't anticipate.

### C5. Trust tier assignments

| Tier | Source | Justification |
| --- | --- | --- |
| **1** | PANW VM-Series | Commercially curated signatures, named threats, App-ID coverage with no free equivalent. Your decision. |
| **2** | Suricata + metadata-filtered ET Open and the CC0/MIT sources in A2 | Per-rule `confidence: High` is a vendor-declared low-FP assertion; admission filter is machine-checkable and snapshottable. |
| **3** | JA4 fingerprints | **Recommend: enrichment only, not a labelling tier** (see B5). No maintained trustworthy verdict feed; no derivable threat name. |

---

## Existing tools and maintenance status

| Tool | Status | Role |
| --- | --- | --- |
| Zeek | Actively maintained; 8.x current | Logs, flow `uid`, JA4 host |
| `zeek/foxio/ja4` | Active, v0.18.8, Zeek 5+/6+ | JA4 computation |
| Suricata | Active, 8.x stable, 9.0 in dev | Tier 2 engine |
| `suricata-update` | Active, ships the source index | Ruleset fetch + filter |
| `OISF/suricata-intel-index` | Active | Licence/provenance record per source |
| tcpreplay | Maintained (AppNeta) | Replay to PANW |
| Wireshark `editcap` | Active | pcapng → pcap normalization |
| `kevinsteves/pan-python` | Mature; verify recent activity before adopting | PAN-OS XML API client |
| abuse.ch CC0 feeds (feodotracker, urlhaus, sslbl-c2) | Active, 5-min regeneration | Tier 2 IOC rules |
| abuse.ch SSLBL **JA3** list | **Effectively abandoned — newest entry 2021-08-03** | Do not use |

---

## Top 5 risks, ranked

1. **Replay infidelity silently drops labels (Tier 1).** A missing label is invisible — nothing in the output says "we lost a packet". *De-risk:* Approach B confines it to the PANW path; assert sent-vs-seen packet counts; diff repeat runs; avoid `--topspeed` in favour of a controlled rate.
2. **Trust-by-construction is unfalsifiable.** With per-source tiering and no validation corpus (your decision), the trustworthiness claim rests entirely on ruleset curation and cannot be measured. If a consumer of these labels ever asks "what's your false-positive rate?", there is no answer. *De-risk:* snapshot rulesets per run so labels are at least *reproducible* and auditable; revisit at eng-review.
3. **JA3/JA4 labelling would inject false positives into training data.** Abandoned feed plus collision-prone fingerprints. *De-risk:* adopt B5 — enrichment, not labels.
4. **JA4+ licensing exposure.** FoxIO License 1.1 forbids monetization; flabel feeds product models. *De-risk:* restrict to BSD-licensed plain JA4; get a legal read before touching JA4+.
5. **Correlating PANW detections back to capture flows.** Replay-time stamps, `--topspeed` time compression, and possible port reuse within a capture. *De-risk:* tuple-driven matching with time only scoping the query; define the unmatchable-detection behaviour explicitly (drop vs. emit unmatched) at PRD.

---

## What I need from you to make a full recommendation

1. A ruling on **JA4 as enrichment vs. label** (B5) — it changes the schema and the whole Tier 3 story.
2. A ruling on **Positive Technologies** sources given the sanctions status (A2).
3. Whether **JA4+ licensing** needs legal review, or whether restricting to plain JA4 settles it (B3).
4. Whether the **lab environment is a v1 prerequisite** or whether an Approach-A offline mode ships first while the lab is built.

---

## Open questions

1. **Does PANW tap mode produce the same detections as a virtual-wire pair?** Your brief prefers tap; Palo Alto's replay guidance says vwire. Needs an on-device A/B with an identical capture. If they differ, tap may silently forfeit a class of detections.
2. **Should flabel emit labels at all when the lab is unavailable** — i.e. is a Tier 2/3-only run a valid, clearly-marked output, or an error? Affects whether offline mode is a first-class feature.
3. **What is the required clock accuracy** between flabel and the firewall, and does the threat log need a settling delay before querying? Empirical, not documented.
4. **Are untagged ET Open rules (the <30% without `confidence` metadata) excluded or manually reviewed?** Fail-closed loses coverage; reviewing them is ongoing manual work.
5. **Is `scwx/malware` worth pricing?** It is the only ruleset explicitly marketed as high-fidelity/low-FP, and your bar is unusually demanding. You said free-with-30-day-delay is acceptable; this asks whether that's a preference or a hard constraint.

---

## Sources

- [Snort vs Suricata IDS/IPS 2026: Performance, Rule Sets](https://www.decryptiondigest.com/blog/snort-vs-suricata-ids-ips-comparison)
- [A Comparative Analysis of Snort 3 and Suricata (Univ. of Portsmouth)](https://pure.port.ac.uk/ws/portalfiles/portal/79753845/A_Comparative_Analysis_of_Snort_3_and_Suricata.pdf)
- [Emerging Threats Updates Improve Metadata, Including MITRE ATT&CK Tags — Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/emerging-threats-updates-improve-metadata-including-mitre-attck-tags)
- [Signature Metadata — Emerging Threats wiki](https://community.emergingthreats.net/t/signature-metadata/96)
- [OISF suricata-intel-index (rule source licences)](https://github.com/OISF/suricata-intel-index/blob/master/index.yaml)
- [What are the differences in the rule sets? — Snort FAQ](https://www.snort.org/faq/what-are-the-differences-in-the-rule-sets)
- [Soft Release: lightSPD, the new rules package for Snort 3](https://blog.snort.org/2020/12/soft-release-lightspd-new-rules-package.html)
- [SSLBL Blacklist — abuse.ch](https://sslbl.abuse.ch/blacklist/)
- [SSLBL Malicious JA3 Fingerprints — abuse.ch](https://sslbl.abuse.ch/ja3-fingerprints/)
- [The Limits of JA3 Fingerprinting — Fingerprint.com](https://fingerprint.com/blog/limitations-ja3-fingerprinting-accurate-device-identification/)
- [JA3 vs JA4: TLS Fingerprinting for Bot Detection in 2026 — VoidMob](https://voidmob.com/blog/ja3-vs-ja4-tls-fingerprinting-bot-detection-2026)
- [FoxIO-LLC/ja4 — README and licensing](https://github.com/FoxIO-LLC/ja4/blob/main/README.md)
- [FoxIO License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md)
- [How to Use JA4 Network Fingerprints in Zeek (Jan 2026)](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)
- [JA4+ Zeek package](https://packages.zeek.org/packages/view/65d88958-d5f0-11ee-8674-0a598146b5c6)
- [Tap Interfaces — PAN-OS docs](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-networking-admin/configure-interfaces/tap-interfaces)
- [How to Configure a Palo Alto Networks Device for Tap Mode](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClMzCAK)
- [Retrieve Logs — PAN-OS XML API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs)
- [Replay pcap — Palo Alto LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/replay-pcap/td-p/36261)
- [tcpreplay man page](https://tcpreplay.appneta.com/wiki/tcpreplay-man.html)
- [Suricata Feature #432: PCAP-NG support](https://redmine.openinfosecfoundation.org/issues/432)
- [Analysing PCAPNG files with Zeek — Zeek community](https://community.zeek.org/t/analysing-pcapng-files-from-wireshark-traffic-captured-with-zeek-or-spicy/6959)
- [HowTo handle PcapNG files — Netresec](https://www.netresec.com/?page=Blog&month=2012-12&post=HowTo-handle-PcapNG-files)
