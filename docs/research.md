# Research — flabel

**Stage 1, Part B.** Driven by the approved `docs/research-brief.md` · Issue #1 · 2026-08-11
**Status:** findings reviewed by Craig; all decisions resolved and folded in below.

---

## Decisions (resolved 2026-08-11)

| # | Decision |
| --- | --- |
| 1 | **Suricata**, not Snort 3. |
| 2 | **Approach B** — Zeek and Suricata read the capture file directly; replay only for PANW. |
| 3 | PANW deployed as a **virtual-wire pair**, not tap mode. |
| 4 | **No `--topspeed`.** Replay at a controlled rate. |
| 5 | **Positive Technologies sources excluded** (sanctions + non-standard licence). |
| 6 | **JA4+ approved** — use the highest-fidelity option; Legal engaged on FoxIO License 1.1. |
| 7 | **Lab environment is a v1 requirement.** |
| 8 | NGFW **required by default**; a Tier 2-only run is available behind an **`--offline`** flag. |
| 9 | Clock sync accuracy target: **millisecond**. |
| 10 | **pcapng supported** via `editcap -F pcap` normalization, with multi-datalink caveats noted. |
| 11 | Encrypted-traffic detection lives in **Tier 2**, as Suricata rule content — not a separate trust tier. |
| 12 | **ET Open's JA3 rules kept** (confidence-filtered); the abandoned abuse.ch SSLBL JA3 source dropped. |
| 13 | Untagged ET Open rules **excluded for now**; enhancement issue filed to revisit. |
| 14 | Admission-filter impact **measured at build time**, not estimated now. |
| 15 | No free/OSS NGFW-equivalent line of inquiry — closed as not worth pursuing. |

---

## Headline recommendation

**Run Suricata and Zeek directly against the capture file. Replay only for PANW, over a virtual-wire pair, at a controlled rate.**

The brief's flow sent everything through the inline device. That isn't necessary: Suricata and Zeek both read a pcap natively (`suricata -r`, `zeek -r`), and only PANW VM-Series has no offline pcap ingestion — Palo Alto's own guidance is a virtual-wire pair fed by an external replay server ([LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/replay-pcap/td-p/36261)).

That split matters because **replay is the single largest threat to label fidelity.** Rewritten packet timing can disturb reassembly and rate-based rules, and a dropped packet is a *missing label* — invisible in the output. Keeping the Tier 2 path offline makes it deterministic and byte-for-byte reproducible, and confines nondeterminism to the one source that cannot avoid it. It also makes the `--offline` mode a natural consequence of the architecture rather than a bolted-on special case.

---

## A. Content-inspection sources and rulesets

### A1. Suricata, not Snort 3

The stated tiebreaker was volume of high-confidence rulesets, and Suricata wins it — on a subtler axis than raw rule count.

| | Suricata | Snort 3 |
| --- | --- | --- |
| Free ruleset ecosystem | ~30 sources indexed centrally | Talos registered + community |
| High-confidence *selection* mechanism | Per-rule `confidence` / `signature_severity` metadata | Policy tiers (connectivity / balanced / security / max-detect) |
| Free-tier delay | ET Open: none | Registered: 30 days behind subscriber, no zero-days |
| Native pcap ingest | Yes (`-r`) | Yes (`-r`) |
| Native TLS fingerprint matching | **`ja3.hash` and `ja4.hash` rule keywords** | No equivalent |

Three decisive points. Suricata has a **central, machine-readable index of free rule sources** (`OISF/suricata-intel-index`) with a declared licence per source — exactly the provenance record the brief demands, and Snort has no equivalent. Suricata-native rules express protocol fields Snort cannot, so equivalent detections are more precise with fewer false positives ([comparison](https://www.decryptiondigest.com/blog/snort-vs-suricata-ids-ips-comparison)). And critically for this project, Suricata matches TLS fingerprints natively as rule content — see section B.

Snort's counter-argument, recorded for the record: Talos LightSPD is maintained by dedicated paid researchers, whereas ET Open is largely community-produced ([Snort blog](https://blog.snort.org/2020/12/soft-release-lightspd-new-rules-package.html)). If uniform curation mattered more than breadth, Snort would win.

### A2. Rule sources and licence status

From `OISF/suricata-intel-index` (authoritative, machine-readable).

**Admitted:**

| Source | Vendor | Licence | Admission policy |
| --- | --- | --- | --- |
| `et/open` | Proofpoint | **MIT** | Metadata filter (A3). Includes `emerging-ja3.rules` — see B. |
| `oisf/trafficid` | OISF | **MIT** | Wholesale; identification only, contributes no verdicts |
| `abuse.ch/feodotracker` | abuse.ch | **CC0-1.0** | Wholesale (IOC feed) |
| `abuse.ch/urlhaus` | abuse.ch | **CC0-1.0** | Wholesale (IOC feed) |
| `abuse.ch/sslbl-c2` | abuse.ch | **CC0-1.0** | Wholesale (IOC feed) — certificate-based, unaffected by the JA3 issue |
| `sslbl/ssl-fp-blacklist` | abuse.ch | **CC0-1.0** | Wholesale (IOC feed) — certificate-based |
| `malsilo/win-malware` | malsilo | **MIT** | Wholesale; small and focused |
| `stamus/lateral` | Stamus Networks | **GPL-3.0-only** | Wholesale; copyleft applies to rules, no linking concern |
| `the-hunters-ledger/open` | The Hunters Ledger | **CC-BY-4.0** | Wholesale; attribution required |
| `pawpatrules` | pawpatrules | **CC-BY-SA-4.0** | Wholesale, pending FP review; share-alike |

**Excluded:**

| Source | Licence | Why |
| --- | --- | --- |
| `sslbl/ja3-fingerprints` | CC0-1.0 | **Abandoned** — newest entry 2021-08-03; self-declared untested FP posture (B1) |
| `tgreen/hunting` | GPLv3 | Hunting/anomaly ruleset; brief excludes hunting in favour of detection |
| `etnetera/aggressive` | MIT | Self-described "aggressive" blacklist; incompatible with a low-FP bar |
| `ptresearch/attackdetection`, `ptrules/open` | **Custom** (non-standard) | Non-standard licence *and* vendor under US sanctions since April 2021. **Excluded by decision.** |

**Commercial options, priced as requested:**

| Source | Price | Notes |
| --- | --- | --- |
| `et/pro` | **~$900/sensor/year** list; ~$750 via the OPNsense reseller | The only publicly-priced option found. Proofpoint raised prices post-acquisition; older subscriptions grandfathered. |
| `scwx/enhanced`, `scwx/malware`, `scwx/security` | **Not published — quote only** | `scwx/malware` is self-described "high-fidelity, high-priority", the closest thing to a purpose-built low-FP set. Requires contacting Secureworks. |
| `stamus/nrd-*` | **Not published — quote only** | Newly-registered-domain feeds. Requires contacting Stamus. |

**Government sources:** no government body publishes a maintained, general-purpose Suricata/Snort ruleset. CISA and allied agencies publish signatures *inside individual advisories* — point-in-time IOCs with no feed or update cadence. Harvesting them means scraping advisories: real work, low yield. Not a v1 source. This is a stated gap against the "government sources" ask rather than a padded list.

### A3. Tier 2 admission — a **per-source** policy

An earlier draft proposed one global filter: `confidence == High AND signature_severity in (Major, Critical) AND source in <table>`. **That was wrong, and applying it would have silently deleted most of the admitted sources.** The abuse.ch, malsilo, and pawpatrules sources are IOC-match rulesets that don't carry ET's `confidence` taxonomy at all, so the condition evaluates false for every rule in them. The filter would have admitted ET Open alone.

The correct design is a per-source policy, because the two source classes control false positives by different means:

**Class 1 — signature rulesets (ET Open).** FP risk lives in the rule logic, and ET expresses it per rule. Filter:

```
admit if metadata.confidence == High
     and metadata.signature_severity in (Major, Critical)
```

ET introduced `confidence` in 2022 specifically to express FP likelihood; coverage has grown from 30% to over 70% of the ruleset, with newer rules at 100% ([Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/emerging-threats-updates-improve-metadata-including-mitre-attck-tags), [ET wiki](https://community.emergingthreats.net/t/signature-metadata/96)).

**Class 2 — IOC feeds (abuse.ch, malsilo, and similar).** FP risk lives in the *indicator list*, not the rule logic — the rule is an exact match on a C2 IP, URL, or certificate. There is no per-rule confidence to filter on, and the curation happened upstream. Admit wholesale, and record the feed snapshot date as the provenance.

**A clarification on my own earlier framing:** ">70% coverage" is not "we keep 70%". Coverage means the tag *exists*; admission additionally requires it to equal `High` **and** severity to be Major/Critical. The admitted fraction is materially smaller than 70%. **The exact figure is deferred to build-time measurement** (`suricata-update` with the filter applied, counted per source) rather than estimated from a partial sample.

**Required either way:** the admitted rule set must be **snapshotted per run** — source, version, and date — because the filter's output changes as ET revises metadata. Without that, two runs of "the same" flabel produce differently-grounded labels.

### A4. PANW VM-Series as Tier 1

- **Deployment: virtual-wire pair** (decided). Vwire is inline-but-transparent and is what Palo Alto's community recommends for replaying a capture at the device. Tap mode would also have worked functionally — it forces every security-profile action to `alert`, which is what a labeller wants — but vwire avoids the unresolved question of whether tap forfeits a class of detections.
- **Threat name is available.** PAN-OS threat logs carry the threat/content name, and the XML API retrieves Threat-type logs with Monitor-tab-equivalent filter expressions including `receive_time` ([Retrieve Logs](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs)). `kevinsteves/pan-python` is the mature Python client.
- **Still to verify on-device:** exact filter syntax for a bounded `receive_time` range, and whether log-write latency requires a settling delay before querying.

### A5. Free L7 equivalent to App-ID

Closed by decision — not pursued further. For the record: Zeek plus Suricata's app-layer detection covers protocol identification, but nothing free reproduces App-ID's application catalogue. PANW's Tier 1 contribution is genuinely distinct, which argues for keeping the NGFW.

---

## B. Encrypted traffic detection

**Design:** encrypted-traffic detection is **Tier 2 Suricata rule content**, not a separate trust tier. Suricata matches TLS fingerprints natively via the **`ja3.hash` and `ja4.hash` rule keywords** ([Suricata JA3/JA4 keywords](https://docs.suricata.io/en/latest/rules/ja-keywords.html)), enabled by setting `app-layer.protocols.tls.ja{3,4}-fingerprints` (auto-enabled when a loaded rule requires it). This means no separate matching engine and no separate feed pipeline — fingerprint detections inherit the same admission filter, snapshot provenance, and tiering as every other Tier 2 rule.

### B1. The abandoned source: abuse.ch SSLBL JA3 — **dropped**

Verified directly:

- **Newest listed fingerprint: `2021-08-03`.** The *file* regenerates every 5 minutes, so an mtime-based freshness check would report it healthy — the *content* is frozen.
- The page warns: **"These fingerprints have not been tested against known good traffic yet and may cause a significant amount of FPs!"**
- Licence is CC0-1.0. Licensing was never the problem; provenance quality is.

A feed that is both abandoned and self-declared as untested against benign traffic cannot supply labels for training data.

### B2. The maintained source: ET Open `emerging-ja3.rules` — **kept, confidence-filtered**

This corrects an earlier conclusion in this document. Having found SSLBL dead, an earlier draft generalized to "JA3 has no trustworthy free source." That was wrong. Inspecting `emerging-ja3.rules` directly:

- Rules carry `created_at` dates from **2019_09_10 through 2026_03_13** — actively maintained.
- Every rule carries **`confidence` and `signature_severity` metadata**, so it plugs straight into the A3 Class 1 filter. Values range across `confidence Low` (excluded) to `confidence High` (admitted).
- ~100+ active rules, MIT-licensed, targeting malware C2 with `classtype:command-and-control` — Cobalt Strike Malleable C2, Remcos, Trickbot among them.
- Provenance is mixed: some rules credit abuse.ch/SSLBL, others cite malware-traffic-analysis.net or ET's own research.

**This is a trustworthy free source, and it is one we already accept as Tier 2.** It is the only free fingerprint labelling content available today.

### B3. On JA3's known weaknesses — narrower than they first appear

JA3's documented problems are real but apply unevenly:

- **ClientHello extension shuffling** (Chrome, Firefox) changes the JA3 hash for the same client. This degrades JA3 for identifying **browsers**. ET's rules fingerprint **malware TLS stacks**, which are typically fixed — so the effect on these detections is much smaller than a general critique of JA3 implies.
- **Collisions** remain a genuine risk: JA3's limited attribute set means unrelated clients can share a fingerprint ([Fingerprint.com](https://fingerprint.com/blog/limitations-ja3-fingerprinting-accurate-device-identification/)). This is the expensive failure mode for training data, because a collision mislabels *benign* traffic as malicious. Mitigation is the `confidence High` filter — ET assigns confidence with FP likelihood explicitly in mind.

### B4. JA4 — mechanism ready, free content not yet

- **Maintained:** `zkg install zeek/foxio/ja4`, v0.18.8. Zeek 5+ supported, Zeek 6+ for QUIC. Zeek published a how-to in January 2026 ([zeek.org](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)).
- JA4 **sorts extensions**, making it resistant to the shuffling that destabilizes JA3 — technically the better fingerprint.
- **But ET Open ships no JA4 rules yet**, and no free maintained JA4 malicious-verdict feed exists. `ja4db` (FoxIO) catalogues fingerprint→application mappings for identification, not malicious verdicts. Organizations currently build their own JA4 blocklists.

**Therefore:** compute JA4 (and JA4+) via the Zeek plugin on every TLS connection and record it as an **attribute** in the Zeek output and alongside labels — valuable as a model feature and an analyst pivot — but **do not emit a label on a JA4 match**, because there is no verdict source to match against. **Promote JA4 to labelling the moment ET publishes `ja4.hash` rules**, at which point it flows through the existing Tier 2 path with no architectural change.

**Licensing:** plain JA4 (TLS client) is **BSD 3-Clause** with no patent claims. The JA4+ suite (JA4S, JA4H, JA4X, JA4L, JA4SSH, JA4T) is **FoxIO License 1.1 — non-commercial**. JA4+ is approved for use on the highest-fidelity basis, with Legal engaged on the licence question. Recording the exposure precisely: internal use securing your own company is permitted; shipping it in a product requires an OEM licence from FoxIO.

### B5. Does fingerprint aging matter? — **differently than for IP/domain IOCs**

A JA4 or JA3 hash is a deterministic function of the TLS ClientHello, so unlike an IP address it is never reassigned. What changes over time is the **population of software sharing a fingerprint**:

- Malware updating its TLS library **changes its fingerprint** → false negatives, not false positives. The old entry becomes inert rather than harmful.
- A fingerprint tied to a library version gets **adopted by more benign software** as that library spreads → a once-distinctive fingerprint becomes shared, and the verdict silently becomes wrong. This is the failure that matters.
- JA4's extension sorting makes it **more stable than JA3**, so drift is slower.

**Implication:** age the *fingerprint→verdict assertion*, not the fingerprint, and track first-seen/last-seen per feed. Aging is less about expiry than about detecting when a fingerprint has become too common to carry a verdict. In practice ET handles this for us by revising rules and their confidence values — which is another argument for sourcing fingerprint verdicts through ET rather than a raw feed.

### B6. Deconfliction

Simple deconfliction is sufficient. With fingerprint verdicts arriving as ET rules rather than raw feeds, deduplication happens at the detection level like any other Suricata rule: retain per-rule provenance (SID, rev, ruleset snapshot), never silently merge, and record all asserting rules rather than voting. If additional fingerprint feeds are added later, keep per-feed provenance per fingerprint and pin a snapshot date per run.

---

## C. Architecture, replay fidelity, and formats

### C1. Chosen architecture — Approach B (hybrid)

**Approach B — offline OSS + replay for PANW only. ✅ Chosen.** Zeek and Suricata read the file directly; only PANW receives a replay, over a virtual-wire pair. Confines all replay-fidelity and clock-correlation risk to the Tier 1 path; Tier 2 stays deterministic and reproducible. Costs one extra concept: two ingest paths for one capture.

The `--offline` flag runs the Tier 2 path alone, with the output clearly marked as lacking Tier 1 coverage. NGFW is required by default.

*Considered and rejected:* **Approach A** (offline only, no NGFW) — excluded because the lab is a v1 requirement, though it remains the natural test configuration and is effectively what `--offline` provides. **Approach C** (full replay, as briefed) — rejected because it makes the Suricata path nondeterministic and drop-prone for no benefit.

### C2. Replay fidelity — the top risk

**`--topspeed` is dropped by decision.** Its own documentation notes that batching packets for throughput costs timing accuracy ([tcpreplay man](https://tcpreplay.appneta.com/wiki/tcpreplay-man.html)), and rewritten timing can affect stateful reassembly, flow timeouts, and rate-based rules. Replay at a controlled rate instead.

**A dropped or reordered packet is a missing label, not a wrong one** — and nothing in the output announces it. Required controls:

- Assert packets sent vs. packets seen by the device; fail the run on mismatch rather than emitting a silently incomplete label set.
- Replay the same capture twice and diff the detection sets; instability across identical runs quantifies the problem directly.
- No published measurements of replay-induced missed alerts were found; this needs empirical measurement in the lab.

### C3. Clock and correlation

**Target accuracy: millisecond**, via NTP across all hosts. That is tight enough that the query window can be drawn closely around the replay, but the correlation design should not depend on it:

- Record replay start/end from flabel, pad the query window, then **match returned records by flow tuple** rather than by time. Time bounds the query; the tuple does the matching.
- **Detections are stamped at replay time, but labels must reference the capture's original timeline.** Even at a controlled rate the mapping is not 1:1, since replay does not reproduce the capture's wall-clock duration. Tuple-driven correlation is therefore not just more robust — it's necessary.
- Port reuse within a single capture can make a tuple ambiguous. Behaviour for an unmatchable detection (drop vs. emit unmatched) must be defined at PRD.

### C4. pcap format support — normalization required

| Component | pcap | pcapng | Handling |
| --- | --- | --- | --- |
| Zeek | Yes | **No** | Convert with `editcap -F pcap`; `zeek -r` on pcapng produces parser errors ([Zeek community](https://community.zeek.org/t/analysing-pcapng-files-from-wireshark-traffic-captured-with-zeek-or-spicy/6959)) |
| Suricata | Yes | **Partial** | Reads pcapng 1.0; breaks on multi-interface files with differing datalinks ([Feature #432](https://redmine.openinfosecfoundation.org/issues/432)). Feed it the normalized pcap for consistency. |
| tcpreplay | Yes | Partial | Same multi-datalink caveat; feed the normalized pcap |
| PANW | n/a | n/a | No file ingest — replay only. Not an issue. |

**pcapng is supported, via a normalization stage** — not by hoping each component copes. Required behaviour: detect input format; decompress gzipped input; split multi-datalink captures first (`frame.interface_id` / `frame.dlt`); convert to pcap with `editcap -F pcap`; feed all three consumers the same normalized file so they see identical bytes; and **record the conversion in provenance**, since a converted capture is not the original artifact.

### C5. Trust tiers

| Tier | Source | Basis |
| --- | --- | --- |
| **1** | PANW VM-Series (vwire) | Commercially curated signatures, named threats, App-ID coverage with no free equivalent |
| **2** | Suricata — ET Open (metadata-filtered, **including `emerging-ja3.rules`**) plus the CC0/MIT IOC feeds | Per-rule `confidence: High` is a vendor-declared low-FP assertion for signature rules; upstream curation plus snapshot provenance for IOC feeds |
| *Enrichment* | JA4 / JA4+ via Zeek | Recorded as an attribute, not a verdict — no free verdict source yet. Promote into Tier 2 when ET ships `ja4.hash` rules. |

> **Superseded by the PRD (2026-08-11).** This section recommended deferring the JA4 *labeling* path until rule content existed. `docs/prd.md` v0.3 instead moves the **capability** into phase one — `ja4.hash` matching is built, enabled, and tested in v1, with only the rule *content* remaining unavailable. The finding above (no free JA4 verdict source exists) is unchanged and still accurate; what changed is that the capability is no longer deferred behind it.

---

## Tools and maintenance status

| Tool | Status | Role |
| --- | --- | --- |
| Zeek | Actively maintained; 8.x current | Logs, flow `uid`, JA4 computation |
| `zeek/foxio/ja4` | Active, v0.18.8, Zeek 5+/6+ | JA4 / JA4+ enrichment |
| Suricata | Active, 8.x stable, 9.0 in dev | Tier 2 engine; native `ja3.hash` / `ja4.hash` |
| `suricata-update` | Active; ships the source index | Ruleset fetch, filter, snapshot |
| `OISF/suricata-intel-index` | Active | Licence/provenance record per source |
| ET Open `emerging-ja3.rules` | Active — rules created through 2026_03_13 | Tier 2 encrypted-traffic detection |
| tcpreplay | Maintained (AppNeta) | Controlled-rate replay to PANW |
| Wireshark `editcap` | Active | pcapng → pcap normalization |
| `kevinsteves/pan-python` | Mature; verify recent activity before adopting | PAN-OS XML API client |
| abuse.ch CC0 feeds (feodotracker, urlhaus, sslbl-c2, ssl-fp-blacklist) | Active, 5-min regeneration | Tier 2 IOC rules |
| abuse.ch SSLBL **JA3** list | **Abandoned — newest entry 2021-08-03** | Excluded |

---

## Top 5 risks, ranked

1. **Replay infidelity silently drops labels (Tier 1).** A missing label is invisible. *Controls:* Approach B confines it to the PANW path; `--topspeed` dropped; assert sent-vs-seen packet counts and fail on mismatch; diff repeat runs.
2. **Trust-by-construction is unfalsifiable.** With per-source tiering and no validation corpus, the trustworthiness claim rests entirely on curation and cannot be measured — if a consumer asks for a false-positive rate, there is no answer. *Control:* snapshot rulesets per run so labels are at least reproducible and auditable. Flagged for eng-review.
3. **Correlating PANW detections back to capture flows.** Replay-time stamps, time compression, and port reuse within a capture. *Control:* tuple-driven matching with time only scoping the query; define unmatchable-detection behaviour at PRD.
4. **Fingerprint verdicts drift as software populations converge (B5).** A fingerprint can become shared by benign software, turning a valid verdict silently wrong. *Control:* source fingerprint verdicts through ET rules rather than raw feeds, so ET's revisions carry the aging burden; track ruleset snapshot dates.
5. **JA4+ licensing exposure.** FoxIO License 1.1 forbids monetization; flabel feeds product models. *Control:* Legal engaged; plain JA4 is BSD and unrestricted if a fallback is needed.

---

## Open questions

Resolved items removed. Remaining:

1. **What is the exact admitted-rule count per source** once the A3 per-source filter is applied? Deferred to build-time measurement with `suricata-update`; needed to know whether Tier 2 coverage is adequate.
2. **Does PANW's threat log need a settling delay** before the API query returns all records for a completed replay, and what is the exact bounded-`receive_time` filter syntax? On-device verification.
3. **What is the behaviour for a detection that cannot be matched to a capture flow** — drop it, or emit it unmatched with a flag? PRD decision.
4. **Are `scwx/malware` or `stamus/nrd-*` worth pursuing** given they are quote-only? Requires contacting sales; ET Pro at ~$900/sensor/year is the only known figure.
5. **Does `pawpatrules` pass an FP review?** Admitted wholesale on a share-alike licence with broad scope; it is the least-vetted of the admitted sources.

---

## Sources

- [Snort vs Suricata IDS/IPS 2026: Performance, Rule Sets](https://www.decryptiondigest.com/blog/snort-vs-suricata-ids-ips-comparison)
- [A Comparative Analysis of Snort 3 and Suricata (Univ. of Portsmouth)](https://pure.port.ac.uk/ws/portalfiles/portal/79753845/A_Comparative_Analysis_of_Snort_3_and_Suricata.pdf)
- [Emerging Threats Updates Improve Metadata, Including MITRE ATT&CK Tags — Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/emerging-threats-updates-improve-metadata-including-mitre-attck-tags)
- [Signature Metadata — Emerging Threats wiki](https://community.emergingthreats.net/t/signature-metadata/96)
- [ET Open rule index (suricata-7.0)](https://rules.emergingthreats.net/open/suricata-7.0/rules/)
- [ET Open `emerging-ja3.rules`](https://rules.emergingthreats.net/open/suricata-7.0/rules/emerging-ja3.rules)
- [OISF suricata-intel-index (rule source licences)](https://github.com/OISF/suricata-intel-index/blob/master/index.yaml)
- [JA3/JA4 Keywords — Suricata docs](https://docs.suricata.io/en/latest/rules/ja-keywords.html)
- [What are the differences in the rule sets? — Snort FAQ](https://www.snort.org/faq/what-are-the-differences-in-the-rule-sets)
- [Soft Release: lightSPD, the new rules package for Snort 3](https://blog.snort.org/2020/12/soft-release-lightspd-new-rules-package.html)
- [ET Pro Ruleset — Proofpoint](https://www.proofpoint.com/us/resources/data-sheets/et-pro-ruleset)
- [Proofpoint ET Pro Ruleset 1yr subscription — OPNsense shop](https://shop.opnsense.com/product/proofpoint-et-pro-ruleset-1yr-subscription/)
- [SSLBL Blacklist — abuse.ch](https://sslbl.abuse.ch/blacklist/)
- [SSLBL Malicious JA3 Fingerprints — abuse.ch](https://sslbl.abuse.ch/ja3-fingerprints/)
- [The Limits of JA3 Fingerprinting — Fingerprint.com](https://fingerprint.com/blog/limitations-ja3-fingerprinting-accurate-device-identification/)
- [FoxIO-LLC/ja4 — README and licensing](https://github.com/FoxIO-LLC/ja4/blob/main/README.md)
- [FoxIO License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md)
- [How to Use JA4 Network Fingerprints in Zeek (Jan 2026)](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)
- [JA4+ Zeek package](https://packages.zeek.org/packages/view/65d88958-d5f0-11ee-8674-0a598146b5c6)
- [Tap Interfaces — PAN-OS docs](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-networking-admin/configure-interfaces/tap-interfaces)
- [Retrieve Logs — PAN-OS XML API](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs)
- [Replay pcap — Palo Alto LIVEcommunity](https://live.paloaltonetworks.com/t5/general-topics/replay-pcap/td-p/36261)
- [tcpreplay man page](https://tcpreplay.appneta.com/wiki/tcpreplay-man.html)
- [Suricata Feature #432: PCAP-NG support](https://redmine.openinfosecfoundation.org/issues/432)
- [Analysing PCAPNG files with Zeek — Zeek community](https://community.zeek.org/t/analysing-pcapng-files-from-wireshark-traffic-captured-with-zeek-or-spicy/6959)
