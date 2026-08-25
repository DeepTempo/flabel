# Resuming at LS-7 on `fl-replay`

Written 2026-08-24, on `docs/RESUME-ls-5.md`'s precedent. **Authoritative state is
`docs/status.yaml` — its `next_action` leads with this and its `log:` carries the reasoning.** This
file is the operational half: where you are, what is decided, and what to do first.

## The situation in one paragraph

Phase 3a is **6 of 7**. Everything except **LS-7 (`blfile`, #151)** is merged, and the
wrapper-to-store seam has been **run for real on this box** rather than only in tests. LS-7 depends
on LS-4, which merged long ago, so it is unblocked and is the whole of the remaining work.

## Where things stand

| | |
| :-- | :-- |
| `main` | `2682a3d` — LS-1, LS-3, LS-6, LS-4, LS-5, LS-2 merged, plus the #171 fix (#172) |
| suite | 1527 pass (`-m "not requires_tools"`), 21 more behind `--bigquery` |
| the box | `/opt/flabel/repo` is current; `/usr/local/bin/flabel-run` is the new wrapper |
| `flabel` | provisioned, matches the declaration, and **still EMPTY** — 0 rows |
| `flabel_scratch` | the 25-run backfill, plus one benign-canary seam test |

## You are on `fl-replay`

Not a dev laptop. `hostname` says so, and it matters: the metadata server gives the instance
service account with no `sudo` and no reauthentication, which is why the `--bigquery` tests and
`flabel-db` work here and nowhere else. Two clones exist and confusing them wastes an hour:

* **`/opt/flabel/repo`** — the deployment clone. `flabel-deploy` maintains it. What the box runs.
* **`~/flabel-dev`** — where you edit. Nothing deploys from here.

## What the seam test proved, and what it did not

Run 2026-08-24, benign canary, `--offline`, published to a throwaway `test-seam-…` bucket prefix
and indexed into `flabel_scratch`:

```
flabel-run → tarball published → flabel-ingest → captures=1, runs=1 → exit 0
re-index the same tarball → "already in flabel_scratch; nothing to do"
```

Validated outside their own tests: the #172 `PATH` fix (the default `uv run --no-sync
flabel-ingest` resolves), the #172 word-splitting override (`FLABEL_RUN_INGEST` carrying
`--dataset flabel_scratch`), LS-2's pre-deploy gate reading `GCP_PROJECT` from `flabel.env`, LS-5's
origin logic (`uri_status: local` for a local path), and the busy guard's process-group rewrite
against the **real** `pgrep` with the production pattern.

**It did not touch the firewall and it wrote nothing to `flabel` or to `results/`.** Tier 1 has not
been exercised since Phase 2, and no production row exists yet.

## Do this first

**LS-7 (`blfile`, #151)** — `docs/PLAN-label-store.md` has the step. It owns the merge rule, moved
out of SQL into Python, which the plan calls the largest single change between spec revisions. Five
modules and two test files. The merge tests are pure and run in CI; they are the ones that matter.

Two bullets deserve care because they are hard failures rather than defaults: a cross-tier conflict
on a single-arity label's value must **fail**, not silently pick; and a flow whose capture has
`uri_status: not-recorded` must be **refused** unless `--allow-missing-origin`.

## Decisions already taken — do not re-litigate

| | |
| :-- | :-- |
| **The eng-review is a gate BEFORE the PR** | Not after the merge. `CLAUDE.md` has the order of work. This cost us #171 |
| Never review your own work, and verify the reviewer | Both riders are in `CLAUDE.md`, and both were earned the same day |
| **#142 is deferred** | Craig, 2026-08-24: after Phase 2 live replay is buttoned down |
| `GCP_PROJECT` lives in `flabel.env` | Read from the metadata server, never committed |
| BigQuery tests do not run in CI | No credential; WIF declined. By hand, and record the measured output |

## Things that will bite if you do not know them

**`uv run` does not prune the `db` extra.** `uv sync` is *exact* — a dry run without the extra
reports "Would uninstall 25 packages" — while `uv run` is *inexact*, `--exact` being opt-in. Two
independent reviews raised the opposite as a CRITICAL and measurement disproved both. `--no-sync`
buys a skipped re-resolve, nothing more.

**`install` does not overwrite in place.** It unlinks and creates a new inode, so a running bash
reads the old one to completion. That claim was the busy guard's stated justification in a spec
section, a script header and three test docstrings before anyone measured it. The guard is still
right; the real hazard is that a deploy pulls source a running run imports lazily and `uv sync`
prunes the venv it is executing out of.

**A sabotage that stays green is a finding, and the escape is usually in the test.** LS-2 ran
thirteen and three were findings; the second round ran nine more and three of those escaped, every
one a missing test rather than working code. Check each fails for the *stated* reason — #136's trap
caught four tests and, once, a sabotage that had drifted onto the wrong code.

**Every tier-2 run attests nothing until #142.** Observed end to end: 84,958 of 84,960 rules
loaded, so no tier attested, `authoritative_runs` returned 0 for the run, nothing superseded. That
is §2.4 working. It means LS-7's cross-tier composition path has **only fixtures** behind it.

**No JA4 on this box.** The `ja4` Zeek package is in the CI container and not on `fl-replay`, so
rows written here carry null `ja4`/`ja4s` — "not computed", not "no TLS".

## Verify like CI does, not approximately

    uv run ruff check . && uv run ruff format --check . && uv run pytest -q -m "not requires_tools"

Chained, so a failure stops. CI runs **both** ruff commands; `ruff format .` fixes and reports
success, only `--check` fails. The `PostToolUse` formatter hook fires on `Edit|Write|MultiEdit`
only, so anything appended with a `cat >> … <<'EOF'` heredoc is never auto-formatted. The Stop hook
runs under `dash`.

## Also open

- **#162** the real project id and SA email are in plaintext on this public repo — a standing
  `CLAUDE.md` guardrail violation, still unowned. **#161** project Editors are writers via the
  default dataset ACL. **#164** nothing detects a replaced published tarball. **#159**
  `flabel-db show` exits 3 on a dataset whose tables are missing.
- **Phase 3b** is LS-8 (backfill and reconcile, #152) and LS-9 (`blfile` reproduction, #153).
- The `test-seam-…` bucket prefix from the seam test is throwaway and can be deleted.
