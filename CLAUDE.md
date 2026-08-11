# Project: flabel

Labels malicious flows in unlabeled packet captures: pcap in → Zeek logs + a companion `labels.json` of malicious-flow verdicts, suitable as ground truth for training detection models.

## Process
This repo follows the 7-stage pipeline tracked in `docs/status.yaml`. Use `/project:*` commands for stage work and keep the tracker current. Key artifacts: `docs/research.md`, `docs/prd.md`, `docs/eng-review.md`, `docs/spec.md`, `PLAN.md`.

The original design brief is `docs/prep-n-research.md`. It marks open questions as `{RESEARCH}` (must be answered with cited justification) and `{GRILL}` (must be nailed down in PRD / eng review). Do not silently resolve them.

## Commands
- Install: `uv sync`
- Test:    `uv run pytest -q`
- Lint:    `uv run ruff check . && uv run ruff format .`
- Run:     `uv run flabel <pcap>`

## Architecture
- FILL_IN after /project:plan (entry point, module boundaries, where logic vs IO lives)

## Conventions
- Write a test alongside every new function. Build test-first (`/tdd`).
- Small functions; type hints on public interfaces.
- Config via environment, never hardcoded. Copy `.env.example` → `.env` (gitignored) for the GCP project ID and device endpoints; refer to them as `${GCP_PROJECT}` etc. in committed files.

## Guardrails
- **Label trustworthiness is the top quality bar.** Every verdict carries its source and provenance; never emit a label whose origin can't be traced.
- Public repo. Never commit secrets, capture data (`*.pcap`), device credentials, or internal host/project identifiers.
- `archive/` is local-only (gitignored) — GCP teardown manifests with IAM and network detail.
- Never call external APIs or real devices in tests (mock them).
- Don't edit files outside the current PLAN.md step without asking.
