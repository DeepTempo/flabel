# flabel

Label malicious flows in unlabeled packet captures.

`flabel` takes a packet capture and produces Zeek logs plus a companion `labels.json` naming the
malicious flows inside it. The intended consumer is model training, so the output is meant to
serve as ground truth — which makes **label trustworthiness, and recording how each verdict was
reached, matter more than label volume.**

That priority drives most of the design decisions below. flabel would rather report that it
could not place a detection than guess which flow it belonged to.

## How it works

One capture goes in. Zeek and Suricata both read **the same normalized copy** of it, so the two
tools cannot disagree about their input:

```
capture ──▶ ingest ──▶ zeek ──────▶ flows ──┐
                   └──▶ suricata ─▶ detections ─▶ correlate ─▶ labels.json + NOTICE
                          ▲
                   ruleset snapshot
```

- **ingest** sniffs the format by magic bytes, decompresses, converts to `pcap`, and walks the
  record headers itself to report truncation — no tool in the dependency set reports a
  truncation offset.
- **zeek** produces the flows. A flow, identified by its Zeek `uid`, is the unit of identity in
  the whole system. Zeek is always invoked with `-D`; without it `uid` differs on every run and
  reproducibility is impossible.
- **suricata** produces the detections, loading **only** the rules in a pinned ruleset snapshot
  so no ambient system ruleset can leak in.
- **correlate** attaches each detection to the one flow it fired on — or reports it as unmatched
  with the reason. It never assigns a detection to a flow by guess.
- **labels** writes the canonical output.

### What a label rests on

Rules come from **nine open-source feeds**. Only Emerging Threats Open carries per-rule
confidence metadata, so only it can be filtered on quality; the rest are admitted wholesale,
which is recorded on every label as `admission_basis` so a consumer can exclude ungated sources.
One classtype is excluded across every feed — `policy-violation`, 436 rules — because those
rules observe a policy breach rather than an attack, and promoting "TLS 1.0 is in use" to
`verdict: malicious` teaches a model the wrong thing (issue #75).

Measured 2026-08-13: **84,995 rules admitted from 115,991 fetched**, ET Open contributing
21,202 of 51,778 (40.9%).

A snapshot is **content-addressed** — its id is a hash over the rules, the SID-to-source index,
and every companion data file the rules read. Two runs against the same `snapshot_id` matched
against exactly the same rules.

Every label carries where it came from: the source, the rule's sid and revision, the licence,
how the source was admitted, and the snapshot id. A verdict whose origin cannot be traced is the
worst thing this project can ship.

### What it will not do

- **Never asserts a flow is benign.** flabel labels malicious flows and says nothing about the
  rest. Absence of a label is not a verdict.
- **Never labels from a fingerprint alone.** JA4 is recorded as an attribute of a flow, never as
  evidence. Labels come only from rule matches.
- **Never reports full coverage when something was lost.** Every way a run can under-report — a
  truncated capture, a rule the engine could not load, a detection that could not be placed — has
  a named field in the run block and a fault-injection test behind it.

## Status

**Build stage, 9 of 10 steps complete.** `flabel --offline <capture>` runs the whole Tier 2
pipeline and writes a run directory. What is still missing is the CI gates that would let you
trust it unattended: the canary and reproducibility checks of step 10.

| | |
| :-- | :-- |
| Built | ingest, ruleset fetch/admission/snapshots, Zeek, Suricata, correlation, labels, provenance, NOTICE, and the CLI that wires them together |
| Not yet built | the canary and reproducibility gates (step 10) |

```
flabel rules update                    # fetch the nine sources, write a ruleset snapshot
flabel --offline capture.pcap          # label it
```

**Phase 1 is open-source screening only** (Suricata and Zeek reading the capture file). A second
tier — a PANW next-generation firewall seeing the traffic via replay — is designed but deferred
to Phase 2, behind a feasibility question that has not been answered. The CLI contract is already
final: `--offline` is permanent and Phase 2 adds no flags.

Progress is tracked in [`docs/status.yaml`](docs/status.yaml). The specification is
[`docs/spec.md`](docs/spec.md); the build plan is [`PLAN.md`](PLAN.md); the original design brief
is [`docs/prep-n-research.md`](docs/prep-n-research.md).

## Output layout

One run produces one self-contained directory. Re-running never modifies a previous one.

```
{capture-name}_{datetime}/
├── zeek/          Zeek's logs for this capture, retained as written
├── suricata/      eve.json and the engine's own logs
├── labels.json    malicious-flow verdicts, plus the run block
├── run.json       the run block on its own — written by every run
└── NOTICE         attribution for every source whose rule text appears in the output
```

`labels.json` holds one entry per malicious flow, each carrying every detection that asserted it,
and a `run` block recording the input, the ruleset, the tool versions and every loss condition.

**A failed run writes `run.json` and no `labels.json`.** The absence of the file is the signal,
and it cannot be misread: an empty `labels` array would say "nothing malicious was found" when in
fact the pipeline died.

## Develop

Requires [uv](https://docs.astral.sh/uv/) and the Zeek/Suricata/Wireshark toolchain — the tests
invoke those tools for real rather than mocking them, because a mock would encode our assumptions
about tool behaviour, which is exactly what needs verifying. Full setup, including the Zeek JA4
package, is in [`docs/dev-setup.md`](docs/dev-setup.md).

```sh
brew install zeek suricata wireshark
uv sync                # install (dev deps only — zero runtime dependencies)
uv run pytest -q       # test
uv run ruff check .    # lint
uv run flabel --help   # run
```

Without the toolchain the tool-dependent tests skip with a reason naming what is missing. CI runs
in a digest-pinned container and passes `--require-tool-tests`, which turns that skip into a
failure — a build that skipped the integration layer must never look green.

Rule feeds are **never contacted from a test.** Only `flabel rules update` performs network I/O;
a labelling run that opens a socket is a defect, and that is what makes reproducible output
achievable at all.

## License

**None yet, deliberately.** This repository is public but unlicensed while the JA4+ licensing
question is with legal review. Until a LICENSE file exists, no permissions are granted — treat
the code as all-rights-reserved.

Note that the *rule feeds* flabel admits carry their own licences (MIT, CC0-1.0, CC-BY-4.0,
CC-BY-SA-4.0, GPL-3.0-only). A run's `NOTICE` states the obligations for every source whose text
appears in that run's output.
