# Project: flabel

Labels malicious flows in unlabeled packet captures: pcap in → Zeek logs + a companion `labels.json` of malicious-flow verdicts, suitable as ground truth for training detection models.

## Process
This repo follows the 7-stage pipeline tracked in `docs/status.yaml`. Use `/project:*` commands for stage work and keep the tracker current. Key artifacts: `docs/research.md`, `docs/prd.md`, `docs/eng-review.md`, `docs/spec.md`, `PLAN.md`.

The original design brief is `docs/prep-n-research.md`. It marks open questions as `{RESEARCH}` (must be answered with cited justification) and `{GRILL}` (must be nailed down in PRD / eng review). Do not silently resolve them.

### The order of work on a step
Tests and code, then the sabotage round, then **a fresh `eng-reviewer` pass on the diff**, then act
on its findings, and only then open the PR or hand the work back. The review is a **gate, and a gate
placed after the merge is not a gate** — that is not a style preference, it is what happened: LS-5
was green on CI, sabotage-checked five ways, merged as #169, and reviewed afterwards, at which point
the review found that `tools/flabel-run` invoked `flabel-ingest` by a bare name that is on nobody's
`PATH`, so every successful run on the box would have exited 5 with the label store permanently
empty (#171, #172).

**Never review your own work** — spawn the agent. Give it the diff as a file and the specific
hazards to chase; a generic "review this" is much weaker. **Verify its findings yourself** before
acting on them: the same report that correctly found #171 also claimed files were on `main` when
they were only uncommitted locally, because the agent has no git access.

A green suite around a new seam is evidence about the tests, not about the code. The #171 defect was
invisible because the fixture overrode that one value in **every** test — the one value that was
wrong in production was the one value never exercised.

## Commands
- Install: `uv sync`  · also needs Zeek, Suricata, Wireshark (`brew install zeek suricata wireshark`)
- Test:    `uv run pytest -q`   (tests invoke Zeek/Suricata for real — see Conventions)
- Lint:    `uv run ruff check . && uv run ruff format .`
- Run:     `uv run flabel --offline <pcap>`   (bare `flabel <pcap>` replays past the device)

## Delivery phases
- **Phase 1 (done): Tier 2** — Suricata + Zeek reading the capture file. Signed off 2026-08-14.
- **Phase 2 (done): Tier 1** — PANW NGFW via capture replay, merged 2026-08-18 (#122, #128).
- Three modes, one flag each (spec §12, #132): bare `flabel <capture>` is **tier 1 only**,
  `--offline` is tier 2 only and permanent, `--both` runs both. Zeek runs in all three — it is
  the flow substrate, not a tier.

## Architecture
Entry point `src/flabel/cli.py` (argparse, zero runtime deps). One module per pipeline stage:
`ingest` → `zeek` → `suricata` → `correlate` → `labels`, with `rules/{fetch,admit,snapshot}`
managing content-addressed ruleset snapshots. Full contracts in `docs/spec.md` §3–§4.
- **Pure** (no `subprocess`/`urllib`/`socket`): `models`, `errors`, `config`, `rules/admit`,
  `correlate`, `labels`, `provenance`, `notice`. A test enforces this.
- **I/O**: `ingest`, `zeek`, `suricata`, `rules/fetch`. `rules/fetch` is the *only* network I/O.
- `models.py` holds every dataclass and imports nothing from the package.

## Conventions
- Write a test alongside every new function. Build test-first (`/tdd`).
- Small functions; type hints on public interfaces.
- **Tools real, network stubbed.** Zeek/Suricata/`editcap` are invoked for real in tests — a mock
  would encode our assumptions about tool behaviour, which is what needs verifying. Rule-feed
  endpoints and the PANW device are never contacted.
- **Zeek is always invoked with `-D`.** Verified: without it `uid` differs every run and
  reproducibility is impossible. Step 5 has a regression test that fails if it's dropped.
- Config via environment, never hardcoded. Copy `.env.example` → `.env` (gitignored) for the GCP
  project ID and device endpoints; refer to them as `${GCP_PROJECT}` etc. in committed files.
- **`docs/spec.md` is load-bearing for the tests.** Step 8's tests parse it at run time: the run
  block's key set must equal §10's literal, and every §11 loss-condition field must resolve in the
  output. Editing those sections can fail the build — which is the point, since the spec cannot
  gain a row the code ignores — but it means the spec is not inert prose. Run the tests after
  editing it.

## Guardrails
- **Label trustworthiness is the top quality bar.** Every verdict carries its source and provenance;
  never emit a label whose origin can't be traced. `docs/spec.md` §13 lists the hard never-dos.
- **The benign canary is the standing FP review.** Wholesale-admitted sources have no per-rule gate,
  so a benign fixture producing any label fails the build. Don't weaken it to make a test pass.
- Public repo. Never commit secrets, capture data, device credentials, or internal identifiers.
  `.gitignore` has a deliberately narrow `tests/fixtures/**` exception — keep it narrow.
- `archive/` is local-only (gitignored) — GCP teardown manifests with IAM and network detail.
- Don't edit files outside the current PLAN.md step without asking.
