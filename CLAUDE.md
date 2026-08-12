# Project: flabel

Labels malicious flows in unlabeled packet captures: pcap in → Zeek logs + a companion `labels.json` of malicious-flow verdicts, suitable as ground truth for training detection models.

## Process
This repo follows the 7-stage pipeline tracked in `docs/status.yaml`. Use `/project:*` commands for stage work and keep the tracker current. Key artifacts: `docs/research.md`, `docs/prd.md`, `docs/eng-review.md`, `docs/spec.md`, `PLAN.md`.

The original design brief is `docs/prep-n-research.md`. It marks open questions as `{RESEARCH}` (must be answered with cited justification) and `{GRILL}` (must be nailed down in PRD / eng review). Do not silently resolve them.

## Commands
- Install: `uv sync`  · also needs Zeek, Suricata, Wireshark (`brew install zeek suricata wireshark`)
- Test:    `uv run pytest -q`   (tests invoke Zeek/Suricata for real — see Conventions)
- Lint:    `uv run ruff check . && uv run ruff format .`
- Run:     `uv run flabel --offline <pcap>`   (bare `flabel <pcap>` is a Phase 2 stub)

## Delivery phases
- **Phase 1 (current): Tier 2 only** — Suricata + Zeek reading the capture file. No lab.
- **Phase 2: Tier 1** — PANW NGFW via capture replay. Blocked on an unverified feasibility
  question (can a cloud VM-Series see replayed traffic at all?) — PRD §13 Q16. Plan Phase 2
  only after that reachability spike.
- The CLI contract is already final: `--offline` is permanent, Phase 2 adds no flags.

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
