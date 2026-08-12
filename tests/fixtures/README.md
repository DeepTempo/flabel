# Test fixtures

Implements the fixture strategy in `docs/prd.md` §10 and the Goal 5 specificity canary.

**No real capture data may ever live here.** Only synthesized captures and
explicitly-licensed public captures. The repository is public, and `.gitignore` carries a
deliberately narrow exception for this directory only — the broad `*.pcap` / `*.log` /
`zeek/` rules still apply everywhere else.

## The two canaries

| Fixture | Origin | Expected result | Status |
| --- | --- | --- | --- |
| `benign.pcap` | **Synthesized** by `make_canary.py` | **Zero labels.** Any label is a false positive by construction and fails the build | ✅ generator landed |
| malicious capture | **Sourced** — small, publicly-published, documented | **At least one label**, from a rule in an admitted source | ⏳ to be sourced |

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
When it is added, record its origin, licence, and what it is expected to trigger.

## Regenerating the benign canary

```sh
python tests/fixtures/make_canary.py benign.pcap
```

Output is byte-deterministic — fixed timestamps, IP IDs, and sequence numbers — so it can
be regenerated and byte-compared. 14 packets, two complete TCP flows (handshake, HTTP
exchange, teardown), RFC 1918 addresses, correct IP and TCP checksums.

## Note on Zeek determinism

Zeek must be invoked with `-D` / `--deterministic`, or connection `uid` values differ on
every run. Verified on Zeek 8.0.4: by default two runs over identical input produced
entirely different UIDs; with `-D`, `conn.log`, `files.log`, and `http.log` were identical
record-for-record across three consecutive runs. See `docs/prd.md` §6.2.

One caveat when writing golden-file tests: `packet_filter.log` carries Zeek's wall-clock
start time and is **never** reproducible. It holds no analytic content — exclude it from
comparison.
