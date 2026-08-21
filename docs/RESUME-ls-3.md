# Resuming LS-3 on `fl-replay`

Written 2026-08-20 as a handoff. **Authoritative state is `docs/status.yaml` — its `next_action`
leads with this workstream and its `log:` carries the reasoning.** This file is the operational
half: where you are, what is already decided, and what to do first.

## The situation in one paragraph

**PR #157 is green in CI and both of its commands are broken.** `flabel-db verify` cannot succeed
against a table that exists, and `flabel-db apply` cannot patch one. Do not merge it. Fix it on
`feat/147-flabeldb-schema`, which is pushed.

That CI is green is itself the finding: nothing in the PR path executes the code where `flabeldb`
meets BigQuery, so a green build is not evidence about the only two commands the step delivers.

## Why resume on the box rather than the laptop

`fl-replay` reaches the instance service account through the **metadata server**, with no `sudo` and
no reauthentication — measured 2026-08-20 as the unprivileged user: the metadata endpoint returned
`846009159455-compute@developer.gserviceaccount.com`, minted a token, and that token read
`results/` over the JSON API with **HTTP 200**. The laptop's ADC needs
`gcloud auth application-default login`.

So the one test that would have caught Critical 1 — a real `apply` followed by a real `verify`
against `flabel_scratch` — is simply runnable there. That is the whole reason for moving.

`gcloud` on the box still needs `sudo` (its credential store is per-user); a **client library does
not**. Do not add `sudo` to anything Python.

## Before you touch anything

    pgrep -af "tcpreplay|flabel|uv run"

A labelling run holds the replay interfaces and has already spent its replay and a 60-second
settle. Do not disturb one.

Then know which clone you are in. `/opt/flabel/repo` is the **deployment** clone that
`flabel-run` executes from, on `main`, and privileged commands there go through `sudo`. Developing
in it risks changing what runs. Prefer a separate clone in your home directory for this work, and
leave `/opt/flabel/repo` for deployment.

## Decisions already taken — do not re-litigate

| | |
| :-- | :-- |
| **`apply` patches what it can** (Craig, 2026-08-20) | BigQuery permits additive changes and relaxations only, so a narrowed type needs a table rebuild. `apply` must **say that plainly** rather than fail obscurely. |
| The cross-tier merge lives in `blfile`, in Python | Not in SQL. `authoritative_runs` is the only view. |
| BigQuery tests do not run in CI | No credential; WIF declined. `flabel-db verify` is a **pre-deploy** gate. |
| Phase 3 is split 3a / 3b | 3a is LS-1…LS-7; the whole-archive backfill and `--rebuild` are 3b. |
| One lab | flabel runs only on `fl-replay`. |

## The fix list, in order

1. **Critical 1 — type-name normalisation.** `tables.get` returns legacy names: `INTEGER` for
   `INT64`, `RECORD` for `STRUCT`, `FLOAT` for `FLOAT64`, `BOOLEAN` for `BOOL`. Normalise on both
   sides of the comparison, accept `RECORD` in `Column.__post_init__`, and add the round-trip test
   `differences(from_bigquery(to_bigquery(declared))) == ()` with the API's legacy names injected.
   Then **measure it** against `flabel_scratch` rather than trusting the alias table.
2. **Critical 2 — make `apply` patch.** `create_table(exists_ok=True)` returns `get_table` on
   conflict and never calls `update_table`. Patch via `update_table` for what BigQuery allows,
   and name the rebuild case explicitly. `_apply` currently has **no test at all**.
3. **`credentials()` has no test of any kind** — the item to fix even if nothing else gets done.
   Replacing its body with `google.auth.default()` passes all 1364 tests, and that function *is*
   spec invariant 7 and all of §7.1.
4. **The credential detector.** `ReauthFailError` is a `RefreshError` **subclass** and escapes the
   name-matching frozenset; it is the exact failure §7.1 quotes from the box, and it exits 1 =
   `EXIT_DRIFT`. Add `EXIT_INTERNAL = 3` so an unrecognised failure can never read as drift, and
   match `isinstance` against lazily-imported `GoogleAuthError` and api_core `RetryError`.
5. **The suite is red without the `db` extra.** `importlib.util.find_spec` on a dotted name imports
   the parent and **raises** when it is absent. Wrap it, and add a CI job that syncs *without* the
   extra — this branch made `--extra db` unconditional in both jobs, so CI can no longer notice.
6. **`verify` compares field lists only.** Extend it to partitioning, clustering, descriptions,
   column **order**, and the dataset **location**. Today `flow_labels` clustered on `zeek_uid` —
   the store's one named never-do — verifies clean, and reversing all 13 columns of `runs` yields
   zero differences.
7. **The declaration guards have zero coverage.** `schema.py` lines 41/43/45/73/76/81 are all
   unexecuted and there is no `pytest.raises` in the new test file. They reject
   `partition_field="flow.ts_first"` and accept `partition_field="run_id"`, a STRING, with the
   identical consequence. Also validate the type name itself, cap clustering at 4, and reject an
   empty `fields` tuple.
8. **The view tests grep vocabulary, not behaviour.** A view inverting *every* load-bearing
   decision passes all five. Write the plan's own stated test — two runs with an identical
   `finished_at`, one row in `run_exclusions`, assert the returned `run_id`s — as a
   `requires_bigquery` test against `flabel_scratch`. **Register the marker in `pyproject.toml`
   first**; `--strict-markers` is on.
9. **Smaller, all real:** `NotFound`-only is right for a table and wrong for a missing *dataset*
   (a `--dataset` typo reports five missing tables and then advises `apply`, which cannot work);
   validate `--dataset`/`--project` against `^[A-Za-z0-9_-]+$` because the view path runs as
   `dataOwner`; make `--run-id`/`--capture` mutually exclusive rather than silently dropping one;
   apply `FORBIDDEN_IN_PURE` to `flabeldb`'s own pure list, which is currently decorative.
10. **Amend LS-1's precedent:** `docs/PLAN-label-store.md` should record that `.github/workflows/ci.yml`
    and `docs/spec-label-store.md` were touched outside LS-3's stated file list, as LS-1 did.

## The lesson to carry into LS-4

The tests in this step cluster on `schema.differences()` and the exit codes — the pure,
easy-to-reach parts — and **stop exactly where the code meets BigQuery**. That boundary is where all
four measured surprises in spec §10 lived, and it is where both Criticals live. Twenty-six sabotages
across LS-1 and LS-3 all went red, which says the guards that exist are held; it says nothing about
the ones never written.

Check coverage on the boundary before believing a green suite:

    uv run pytest -q --cov=src/flabeldb --cov-report=term-missing

## Also open

- **PR #156** — LS-1 verify tracker, docs only, safe to merge.
- **#142** still gates tier-2 ingestion: `fl-replay` runs Suricata 7.0.3 against an 8.0 ruleset.
  Irrelevant to LS-3, which touches no detector.
- **LS-2 (#146)** can run beside LS-3 but must *land* after it — `flabel-deploy` runs
  `uv sync --extra db`, and the extra does not exist until LS-3 merges.
