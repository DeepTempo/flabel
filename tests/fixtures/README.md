# Test fixtures

Implements the fixture strategy in `docs/prd.md` §10 and the Goal 5 specificity canary.

**No real capture data may ever live here.** Only synthesized captures and
explicitly-licensed public captures. The repository is public, and `.gitignore` carries a
deliberately narrow exception for this directory only — the broad `*.pcap` / `*.log` /
`zeek/` rules still apply everywhere else.

## The two canaries

| Fixture | Origin | Expected result | Status |
| --- | --- | --- | --- |
| `benign.pcap` | **Synthesized** by `make_canary.py` | **Zero labels.** Any label is a false positive by construction and fails the build | ✅ gated on every scheduled feeds run |
| `malicious.pcap` | **Sourced** — small, publicly-published, documented | **At least one label**, from a rule in an admitted source | ⏳ not yet sourced (issue #24) |

### The two benign fixtures

| Fixture | Role |
| --- | --- |
| `benign.pcap` | the **narrow** review — 14 synthetic packets, zero labels known-correct *by construction* |
| `benign-corpus/` | the **broad** review — 17 real protocol captures (MIT, from suricata-verify) |

The corpus exists because the canary, while correct, is narrow: it carries two cleartext HTTP
flows and can only ever exercise the rules that could match them. Measured 2026-08-13 (#75), 23
realistic captures against the real nine-feed snapshot produced 100 labels — all from
`pawpatrules` — while `benign.pcap` produced zero and was right to. See `benign-corpus/README.md`.

### Where each canary is gated

| Gate | Runs | Against |
| --- | --- | --- |
| `tests/integration/test_canaries.py` | every PR | a small real snapshot built from `rules/synthetic.rules` — proves the pipeline invents no labels |
| `.github/workflows/feeds.yml` — narrow | daily, and on demand | `benign.pcap` against the **live nine-feed ruleset**, ~85k rules. Zero tolerance: any label fails |
| `.github/workflows/feeds.yml` — broad | daily, and on demand | the **17-capture corpus** against the same snapshot. Fails on any source entry not in `benign-corpus/tolerated.json` (PLAN 11d) |

**`tolerated.json` is the load-bearing part of the broad review**, and the file to read first when
it fails. It lists every source entry the corpus is known to produce — three, as of 2026-08-14 —
with the argument for tolerating each. The gate fails on anything else, on a tolerated sid that
claims a *stronger* basis than recorded, and on any entry firing more than ten times its measured
count. The list is capped at three entries so a fourth is a deliberate edit rather than an append,
and `tests/integration/corpus_gate.py` holds the decision so `test_corpus_gate.py` can prove it
fails.

The PR suite cannot do either of the scheduled reviews: spec §2.2 forbids the test suite contacting
rule feeds, and a real snapshot is 124 MB. Neither gate is sufficient alone — the scheduled one could pass forever
against a canary someone had quietly emptied, which is why `benign.pcap` is byte-pinned by
`test_the_benign_canary_fixture_is_the_one_the_gate_was_measured_against`.

**`benign.pcap` sha256:** `7aa343087a8743a73ced055b4af2c743de8e96a1a7112e127c1d97499f522ab1`

Measured against snapshot `8c9e8d58af0a8d64` (85,431 rules, all nine feeds, 2026-08-12):
**0 detections.** If the fixture is ever regenerated, that measurement has to be retaken — the
digest in the test is not a formality, it is what stops the gate being made to pass by editing
the thing it measures.

### Why the benign canary is synthesized rather than sourced

So that *zero labels* is a **known-correct** expectation rather than an empirical one. A
real-world capture believed to be benign may legitimately trip an admitted rule — which
would make the canary flaky and, worse, make its failures ambiguous: you could never tell
a genuine specificity regression from a quirk of the capture.

This matters more than it looks. Every wholesale-admitted source — the abuse.ch feeds,
`malsilo`, `stamus/lateral`, `the-hunters-ledger`, `pawpatrules` — passes through **no
per-rule false-positive gate** (`docs/prd.md` §6.3). The benign canary is their standing
review, and it runs on every build.

### Why the malicious canary is sourced rather than synthesized

Because the test needs a rule to genuinely fire. Hand-crafting traffic that trips a
specific rule tests the rule you targeted, not the pipeline against realistic traffic.

### What the malicious canary must satisfy

Still unsourced (issue #24). `tests/integration/test_canaries.py::test_the_malicious_canary_produces_at_least_one_label`
skips while `malicious.pcap` is absent and activates itself the moment it lands, so the gap stays
visible in test output rather than disappearing from it.

The bar it has to clear, in order of how likely each is to be the thing that blocks a candidate:

1. **A licence that permits redistribution in a public repo.** This repo is public and currently
   carries no LICENSE of its own. A capture that may be downloaded but not redistributed cannot
   live here — that is a licence breach, not a technicality.
2. **No real personal or customer data.** Malware captures routinely carry real victim addresses,
   credentials in cleartext, and payloads. "Publicly published" is not the same as "safe to
   redistribute", and this is the criterion most candidates fail.
3. **Small.** Single-digit MB at most; it is fetched on every scheduled run.
4. **It must fire a rule in an *admitted* source** — one of the nine in `docs/spec.md` §5, after
   admission. A capture that only trips a rule ET Open's metadata filter excludes proves nothing
   about this pipeline.
5. **Documented here**: origin URL, licence, publication date, and *which* sid it is expected to
   trigger. A canary whose expected outcome is "something, probably" cannot detect a sensitivity
   regression — it can only detect a total outage.

Point 5 is what makes the pair meaningful. Zero labels on the benign canary proves specificity
and nothing else: a pipeline that had silently stopped labelling **anything** would pass it every
single time. The malicious canary is the only test that would catch that.

Candidate sources worth checking against points 1 and 2: Netresec's published captures, the
Stratosphere IPS datasets, and malware-traffic-analysis.net — each has its own terms, and the
terms are the part to read first.

**Ruled out 2026-08-13 — EICAR.** `benign-corpus/smb-eicar-file-segmentation-random.pcap` clears
points 1, 2 and 3 outright — MIT, a suricata-verify test capture carrying no real party's data,
and 22 KB — and looks like the obvious candidate. It fails
point 4, and not for the reason it appears to. ET Open is the only feed of the nine carrying any
EICAR rule at all — checked by grepping every mirror payload for both the ASCII string and its
hex encoding — and none of the three enabled ones detects EICAR as such:

| sid | What it actually requires |
| --- | --- |
| 2022932, 2022933 | `alert http`, `to_client`, and a Symantec MIME name-overflow shape: `Content-Type: … name="<78+ chars>"` |
| 2039680 | `alert http`, an `x-powered-by: Kaspersky Labs` response header, and `filename="eicar.zip"` |

All three are HTTP; the fixture is SMB. The metadata filter that excludes them is therefore not
the blocker, and admitting them would gain nothing. The one rule that did match the raw EICAR
string, 2012591, is `# ET DELETED` upstream and additionally demands an MZ header. Adopting the
fixture would also have meant moving it out of `benign-corpus/`, which step 11d asserts produces
zero labels.

**Decided 2026-08-13 (Craig):** Phase 1 signs off with this criterion explicitly **not met**.
Issue #24 stays open and the skip above stays, so the gap remains visible in test output.

## Regenerating the benign canary

```sh
python tests/fixtures/make_canary.py benign.pcap
```

Output is byte-deterministic — fixed timestamps, IP IDs, and sequence numbers — so it can
be regenerated and byte-compared. 14 packets, two complete TCP flows (handshake, HTTP
exchange, teardown), **both to port 80**, RFC 1918 addresses, correct IP and TCP checksums.

### Why port 80 matters

Flow 2 used to be the same cleartext HTTP exchange sent to port **443**. pawpatrules sid
3300303 — "Suspicious HTTP traffic on unusual HTTP port" — fires on that, and it is right
to: cleartext HTTP on the TLS port is exactly the anomaly it is looking for.

That single alert made Goal 5's gate unpassable. The canary is synthesized so that *zero
labels is known-correct by construction*; a canary that contains traffic a reasonable rule
would flag has no such property, and its failure would be ambiguous in the worst way —
indistinguishable from the specificity regression the gate exists to catch. **The fixture
was at fault, not the feed.**

So the two flows differ by endpoint and timing, not by port. Anything added here has to
clear the same bar: not merely benign, but *unremarkable* — traffic no admitted rule could
reasonably alert on. Port 443 belongs to a capture carrying a real TLS handshake, and those
are generated at test time (`test_zeek.py::tls_capture`,
`test_suricata.py::write_tls_capture`) rather than committed.

## Note on Zeek determinism

Zeek must be invoked with `-D` / `--deterministic`, or connection `uid` values differ on
every run. Verified on Zeek 8.0.4: by default two runs over identical input produced
entirely different UIDs; with `-D`, `conn.log`, `files.log`, and `http.log` were identical
record-for-record across three consecutive runs. See `docs/prd.md` §6.2.

One caveat when writing golden-file tests: `packet_filter.log` carries Zeek's wall-clock
start time and is **never** reproducible. It holds no analytic content — exclude it from
comparison.

Do not hand-roll that comparison. `flabel.canonical` is the shared primitive (step 10), and it
knows about four things a naive `#`-stripping comparison gets wrong — `reporter.log`'s wall-clock
`ts` column, Suricata's per-run `flow_id`, the `flow.reason` race, and eve record ordering. Each
was measured; see that module's docstrings for the numbers.
