# Resuming LS-5 on `fl-replay`

Written 2026-08-24 as a handoff, on `docs/RESUME-ls-3.md`'s precedent. **Authoritative state is
`docs/status.yaml` — its `next_action` leads with this and its `log:` carries the reasoning.** This
file is the operational half: where you are, what is decided, and what to do first.

## The situation in one paragraph

Phase 3a is **4 of 7**. LS-5 is **mostly built and not yet opened as a PR**. Branch
`feat/150-wire-flabel-run`, two commits ahead of `main`, pushed. `tools/flabel-run` now carries the
origin URI and indexes after publishing; **one test from the plan is still owed and it needs
BigQuery.** Everything else in the step is done and sabotage-checked.

## Where things stand

| | |
| :-- | :-- |
| `main` | `c6a592f` — LS-1, LS-3, LS-6, LS-4 all merged |
| branch | `feat/150-wire-flabel-run`, pushed, **no PR yet** |
| suite | 1497 pass (`-m "not requires_tools"`), 53 of them `test_flabel_run.py` |
| live | 20 `requires_bigquery` tests pass against `flabel_scratch` |
| the store | `flabel` provisioned and EMPTY; `flabel_scratch` holds a 25-run backfill |

## What LS-5 has already done

- **`--source-uri` carries the ORIGINAL argument**, captured into `SOURCE_URI` before the `gs://`
  staging block reassigns `TARGET="$LOCAL"`. Only a `gs://` argument becomes a `--source-uri`: flabel
  validates the flag as a `gs://` object, and `provenance` derives `uri_status` as
  `"gs" if source_uri else "local"`, so a local path would both fail validation and assert a false
  origin.
- **`flabel-ingest` runs after a successful publish**, never before — archive-then-index (§7.5).
  `FLABEL_RUN_INGEST` overrides the binary, following the wrapper's existing convention.
- **Exit 5, published-not-indexed**, documented in `docs/spec.md` §12 beside exit 4.
- Five sabotages, all red.

**A defect the tests found while wiring it, worth not re-introducing:** `publish` returns `0` both
when it publishes and when it DECLINES (a run with no `labels.json` is not a result). An
`if publish; then index` cannot tell those apart, so the first version indexed a run whose tarball
was never written. The wrapper sets `PUBLISHED` on the success path only and indexes on that.

## Do this first

1. **The one test still owed.** From the plan: *"A successful run with an empty `labels[]` is
   published, and ingesting it clears a previously authoritative tier."* This is the behaviour
   revision 1's deleted publish-on-exit-0 bullet was reaching for, and it needs BigQuery — write it
   in `tests/test_flabeldb_live.py`, not `test_flabel_run.py`. Shape: ingest a run that attests a
   tier, confirm `authoritative_runs` names it, ingest a LATER run for the same capture whose
   `labels[]` is empty but which attests the same tier, confirm the view now names the later one.
2. **Open the PR.** Everything else in LS-5 is done.

The plan's `SIGTERM` bullet is already satisfied by
`test_a_terminating_signal_is_forwarded_to_the_run` (pre-existing, still green with the added
post-command step) — no new test needed, but say so in the PR rather than letting it read as unwritten.

## Decisions already taken — do not re-litigate

| | |
| :-- | :-- |
| A local capture passes **no** `--source-uri` | `uri_status` is derived from its presence; passing a local path asserts a `gs` origin that is false |
| Index only what was actually published | `publish` returns 0 on decline too; read `PUBLISHED`, not the exit code |
| Exit 5 is its own code | Reusing 1 tells a batch caller to discard a capture that succeeded; reusing 4 claims the tarball is missing when it is not |
| `--backfill` is LS-4's flag; LS-8 is the operation | LS-8 also owns `tools/reconcile_store.py` and depends on LS-5 and LS-7 |
| BigQuery tests do not run in CI | No credential; WIF declined. Run by hand: `uv run pytest -q --bigquery tests/test_flabeldb_live.py` |

## Two things that will bite if you do not know them

**A job id is permanent.** `flabel-ingest`'s recovery walks to the first *unused* attempt id, not
past *failed* ones only — spec §5.3 step 3 was corrected for this in PR #167. A consequence for
tests: anything asserting on attempt NUMBERS cannot reuse a `run_id` between sessions, which is why
`test_flabeldb_live.py` has a per-session UUID salt.

**#142 gates tier 2 in fact.** Measured across all 25 published runs: 24 replay runs attest tier 1
and the one `--offline` run attests nothing, because Suricata 7.0.3 skipped 2 of 84,960 rules. Every
tier-2 row will load and none will become authoritative until the box's Suricata matches the pin.

## Verify like CI does, not approximately

    uv run ruff check . && uv run ruff format --check . && uv run pytest -q -m "not requires_tools"

Chained, so a failure stops. Three separate mistakes this session came from verifying with something
adjacent to the gate: `ruff check` without `format --check` (CI runs both), `bash -c` when the hook
runs under `dash`, and reading `PIPESTATUS[0]` when the interesting status was `[1]`. The
`PostToolUse` formatter hook fires on `Edit|Write|MultiEdit` only, so anything appended with a
`cat >> … <<'EOF'` heredoc is never auto-formatted.

## Also open

- **#146 LS-2** `tools/flabel-deploy` — parallel, unblocked, and now has the provisioned dataset its
  pre-deploy `verify` gate needs (that was #163, closed).
- **#151 LS-7** `blfile` — the last of Phase 3a.
- **#159** `flabel-db show` exits 3 on a dataset whose TABLES are missing. No longer reproduces
  against `flabel`, and NOT fixed; LS-2 will meet it when it provisions a new environment.
- **#161** project Editors are writers via the default dataset ACL. **#162** the real project id and
  SA email are in plaintext on this public repo — a standing `CLAUDE.md` guardrail violation, still
  unowned. **#164** nothing detects a replaced published tarball.
