# PLAN — the label store and `blfile` (Phase 3)

Spec: `docs/spec-label-store.md`. Design reasoning and measurements:
`inline-labeling/label-store-design.html`.

`PLAN.md` is Phase 1 and is closed. This is a separate plan for a separate phase, in the manner
Phase 2 was kept off main's Phase 1 work — not an extension of it.

## Shape of the work

Nine steps, one GitHub issue each, labelled `plan-step` (#145–#153). One touches `src/flabel/` and
everything depends on it; one is a Craig action with no code; one is a gate rather than a build. Two pairs can run in parallel and are marked `⟂` — they
share no files, which is the only safe basis for splitting.

```
LS-1 additive fields ─┬─→ LS-3 flabeldb + schema ─┬─→ LS-4 flabel-ingest ─┬─→ LS-5 wire wrapper ─┐
                      │                            └─→ LS-6 IAM + dataset ─┴─→ LS-7 blfile ──────┴─→ LS-8 backfill ─→ LS-9 tier 2
LS-2 flabel-deploy ───┘                                                                                                    ↑ #142
```

**Sabotage round on every step.** Break each new guard deliberately, one at a time, and confirm a
test goes red. A sabotage that *passes* is a finding, not a relief: of #138's twelve guards, seven
had no test at all and only breaking them found it. Restore from file copies, never
`git checkout <file>` — that restores from the index and has twice silently reverted real fixes here.

**Definition of done for a step**: tests pass locally, CI green on the branch, a fresh `eng-reviewer`
pass on the diff, and the sabotage round recorded in the PR body.

---

## Step LS-1 — Additive `run.input` fields and `LABEL_KINDS` (#145)

The only step that touches `src/flabel/`. Everything else waits on it, so it goes first and stays
small.

**Files touched**
- `src/flabel/models.py` — `LABEL_KINDS` and `LabelKind`; three fields on the input model
- `src/flabel/ingest.py` — stop discarding `_snaplen`; publish the retained `link_type`
- `src/flabel/cli.py` — `--source-uri`, validated
- `src/flabel/labels.py` — the run block gains three keys
- `docs/spec.md` §10 — the run block's literal key set, and §4's `LabelEntry`
- `tests/test_models.py`, `tests/test_ingest.py`, `tests/test_cli.py`, `tests/test_labels.py`

**What changes**
- `run.input.uri` — `str | null`, from `--source-uri`. Validated as a well-formed `gs://` URI or
  exit 2 before any tool runs. flabel does **not** verify the URI holds the bytes it hashed; that
  would be network I/O on a path forbidden from performing it (`docs/spec.md` §13).
- `run.input.link_type` — the retained dominant type. Already computed to decide what to discard.
- `run.input.snaplen` — currently unpacked as `_snaplen` at `ingest.py:255` and thrown away.
- `models.LABEL_KINDS` replaces the bare `Literal["verdict","threat-name"]`, carrying arity and
  permitted tiers, and becomes the single authority the existing `LabelEntry` guards read.

**Expect the build to go red before it goes green, and that is the mechanism working.** `CLAUDE.md`
records that step 8's tests parse `docs/spec.md` at run time: the run block's key set must equal
§10's literal. Adding a field without editing the spec fails, which is why the spec is in this step's
file list rather than a follow-up.

**The test that proves it**
- A run over `tests/fixtures/benign.pcap` publishes all three keys, with `uri: null` when
  `--source-uri` is absent and the literal value when present.
- `--source-uri notagsuri` and `--source-uri ""` both exit 2, before a run directory exists.
- `snaplen` matches `capinfos` on the same fixture — asserted against the tool, not against our own
  parse of the header.
- `link_type` is the *retained* type on the multi-datalink fixture, not the discarded one. This is
  the assertion most likely to pass for the wrong reason on a single-link fixture, so it uses the
  two-link-type fixture `make_awkward.py` builds.
- Every `LabelEntry` guard resolves its permitted names through `LABEL_KINDS`.

**Sabotage** — remove `LABEL_KINDS` from the `LabelEntry` name check and confirm a forged
`LabelEntry(name="mitre", …)` starts constructing. Point `link_type` at the discarded type and
confirm the two-link-type test goes red. Both must go red; the first is the shape that has shipped
untested twice.

**Depends on** nothing. `⟂ LS-2`.

---

## Step LS-2 — `tools/flabel-deploy` ⟂ (#146)

Deployment becomes three steps once there is an optional dependency to sync, and the **two**-step
version has already left `fl-replay` two merges behind with #137 undeployed, because only the pull
was done. This retires that hazard rather than adding to it.

**Files touched**
- `tools/flabel-deploy` (new)
- `tests/test_flabel_deploy.py` (new)

**What changes**
One script doing `git -C /opt/flabel/repo pull --ff-only`, `uv sync --extra db`, and a **conditional**
`install -m 0755 tools/flabel-run /usr/local/bin/flabel-run` — reinstalling only when `md5sum`
differs, so the report says honestly whether anything changed. It refuses to run at all while
`pgrep -af "tcpreplay|flabel|uv run"` matches, and prints what it did in each of the three positions.

**The test that proves it**
- An `md5`-identical wrapper is **not** reinstalled, and the output says so.
- A differing wrapper **is** reinstalled.
- A `pgrep` match aborts before touching anything — asserted by observing that neither the pull nor
  the install command was issued, not merely that the exit code was non-zero.
- A failed `pull` does not proceed to `uv sync`.
- Overridable paths, following `flabel-run`'s own convention (`FLABEL_RUN_REPO` etc.), so the tests
  drive it without `/opt` or `/var` and without root.

**Sabotage** — make the `pgrep` guard non-fatal and confirm a test goes red. Note the trap #136 hit:
a guard can be held twice, so check the sabotage fails for the *stated* reason and not because a
later check caught it independently.

**Depends on** nothing. `⟂ LS-1`.

---

## Step LS-3 — `flabeldb` package, schema, `apply` / `verify` (#147)

**Files touched**
- `pyproject.toml` — `[project.optional-dependencies] db`, `packages = ["src/flabel", "src/flabeldb"]`,
  console scripts
- `src/flabeldb/{__init__,schema,client,cli}.py`
- `src/flabeldb/views/{authoritative_runs,current_labels}.sql`
- `tests/test_architecture.py` — extended
- `tests/test_flabeldb_schema.py` (new)

**What changes**
The four tables of spec §4 declared as client schema objects in `schema.py` — the form the load jobs
need anyway, so there is no second copy in a `.sql` file. Views as committed SQL. `flabel-db apply`
creates or patches; `flabel-db verify` compares live against declared and exits 1 on any difference,
naming it. Credentials per spec §7.1: `compute_engine.Credentials()` by default, `--local-adc` as the
documented escape.

**The test that proves it**
- `verify` detects a deliberately mismatched column — a type change, a dropped field, and an added
  field are three separate assertions, because "detects a difference" is satisfied by code that only
  notices one of them.
- `test_architecture.py` fails if any module under `src/flabel/` imports `flabeldb`, `google.cloud`
  or `google.auth`. Static, same shape as the existing closed-list check.
- `import flabel` succeeds with the `db` extra absent; the console scripts exit with a message naming
  `flabel[db]` rather than an `ImportError` traceback.
- The view SQL parses — a dry-run query against the scratch dataset, marked `requires_bigquery`.
- `authoritative_runs` picks the newer of two runs finishing in the **same second**, proving the
  `run_id` tie-break rather than the timestamp.

**Sabotage** — drop `run_id` from `authoritative_runs`' `ORDER BY` and confirm the same-second test
goes red. This is #138's own correction in a second place, and without a test the non-total order is
invisible until two runs happen to tie.

**Depends on** LS-1 (`LABEL_KINDS`). `⟂ LS-2`.

---

## Step LS-4 — `flabel-ingest` (#148)

**Files touched**
- `src/flabeldb/{parse,identity,ingest}.py`
- `tests/test_flabeldb_identity.py`, `tests/test_flabeldb_ingest.py` (new)

**What changes**
One parser over a run directory, with a fetch-and-untar adapter for the `gs://` case. `run_id` and
`flow_key` per spec §3. The per-tier split of each `Label`, with `verdict` recomputed per tier. Load
jobs in commit-marker order — `flow_labels`, `unmatched`, `captures`, then `runs` last. `jobId =
ingest-<run_id>-<table>`. `--backfill`. The duplicate-`run_id` assertion query.

**The test that proves it**
- **Pure, no client:** `flow_key` is identical for the same flow read from two runs whose Zeek `uid`s
  differ — driven by the two fixtures that produced the M1 measurement, so the test encodes the
  finding rather than restating it. And `flow_key` is *different* for two flows sharing a 5-tuple and
  differing only in `ts_first`.
- **Pure:** a `--both` run's single `Label` splits into two rows whose `labels` and `sources` carry
  only their own tier, and whose `verdict` sids partition the original's.
- **Against BigQuery** (`requires_bigquery`): the same tarball ingested twice yields one set of rows,
  and the second attempt fails at the API on the job id. Verified against the service, not a mock —
  spec §2's testing line, and the same discipline that measured `objectCreator`'s refusal rather than
  inferring it from the role name.
- **Against BigQuery:** killing ingest after `flow_labels` and before `runs` leaves nothing any view
  can reach, and re-running completes it.
- `--backfill` over an archive containing one already-ingested run loads only the new one.

**Sabotage** — reorder the loads so `runs` lands first, and confirm the commit-marker test goes red.
Make `flow_key` read `flow.uid` and confirm the cross-run test goes red.

**Depends on** LS-3.

---

## Step LS-6 — IAM grant, dataset, and verification ⟂ (#149)

No repo code. Craig's actions, with the verification written down.

**Files touched**
- `docs/label-store-provision.md` (new) — the commands, the grants, and what was verified

**What changes**
- `roles/storage.objectViewer` for the instance service account on
  `gs://pm-proto-496816-flabel-pcaps`. Needed because `objectCreator` grants
  `storage.objects.create` only, so the box cannot currently read back what it uploaded.
- The `flabel` dataset created, and `flabel-db apply` run against it.
- A scratch dataset for the `requires_bigquery` tests.

**The test that proves it** — measured from the box, both directions, the way `objectCreator` was on
2026-08-19 rather than inferred from the role name: a read of a published tarball **succeeds**, and
an overwrite and a delete of the same object are **refused**. Recorded with the command and its
output, because a measurement that cannot be re-run is a claim.

**Depends on** LS-3 (needs `flabel-db apply`). `⟂ LS-4`.

---

## Step LS-5 — Wire `tools/flabel-run` (#150)

The layer where both of #134's late bugs lived and which had no tests at all until #135. Wrapper
tests matter more here than Python ones.

**Files touched**
- `tools/flabel-run`
- `tests/test_flabel_run.py`
- `docs/spec.md` §12 — exit 5

**What changes**
- Publish on exit 0 **whether or not `labels.json` exists**, revising #135's artifact rule. Without
  this a tier that legitimately goes quiet can never clear a stale label.
- Pass `--source-uri` with the *original* argument, captured before `TARGET="$LOCAL"` overwrites it.
- Call `flabel-ingest` after a successful publish.
- Exit 5 — published, not indexed — on exit 4's reasoning: the labels are intact both on the box and
  in the bucket, so reusing 1 would tell a batch caller to discard a capture that succeeded.

**The test that proves it**
- A successful run that wrote **no** `labels.json` is published.
- A failed run is still not published, and still exits 1.
- `--source-uri` carries the `gs://` argument, **not** the staged local path. Asserted on the
  argument alone rather than by substring over the whole command line — #134's review found a
  `'older' not in calls[0]` check that matched the pytest temp path because macOS puts runs under
  `/var/folders/`.
- An ingest failure exits 5 with `labels.json` intact and the tarball published.
- A usage error still exits 2 rather than being flattened, and a `SIGTERM` still reaches the child —
  the extra post-command step must not re-break what #134's trap fixed.

**Sabotage** — make the publish condition read `labels.json` again and confirm the zero-label test
goes red. Change the `--source-uri` value to the staged path and confirm the argument test goes red.

**Depends on** LS-1 (`--source-uri` must exist) and LS-4 (`flabel-ingest` must exist).

---

## Step LS-7 — `blfile` (#151)

**Files touched**
- `src/flabeldb/{query,collection,blfile}.py`
- `tests/test_blfile.py`, `tests/test_collection.py` (new)
- `docs/spec-label-store.md` §6.4 — amended if the built document differs from the specified one

**What changes**
Selection with AND semantics over `current_labels`; `--label` validated against `LABEL_KINDS`; the
`labels-collection` document of spec §6.4 with `collection_id` and canonical ordering; `--rebuild`
and `--as-of` per §6.5.

**The test that proves it**
- Two `--label` values emit only flows carrying **both**; a flow carrying one is absent.
- An unknown `--label` exits 2 naming the permitted set, sourced from `LABEL_KINDS` — and a test
  asserts `blfile` reads that table rather than a second copy of the names. The 2026-08-19 sabotage
  that changed `panw`'s placeholder literal and left every test green is why this is asserted and not
  assumed.
- Bare `blfile` selects `verdict`.
- `--rebuild` of a document reproduces it over records with `built_at` excluded, and the recomputed
  `collection_id` matches.
- `--rebuild` with a pinned `run_id` deleted from the store **fails**, naming it — not a smaller
  document.
- `--rebuild --label verdict` exits 2. `--rebuild --as-of …` exits 2.
- `--as-of` filters on `ingested_at`: a run whose `finished_at` precedes the cutoff but whose
  `ingested_at` follows it is **excluded**. This is the assertion that pins the whole reproduction
  argument, and it is the one a plausible implementation gets backwards.
- `origin` resolves from the pinned set: a later sighting of the same capture at a different URI does
  not change a rebuilt document.

**Sabotage** — switch `--as-of` to `finished_at` and confirm the backfill test goes red. Drop the
pinned-run check and confirm the missing-run test goes red.

**Depends on** LS-4 and LS-6.

---

## Step LS-8 — Backfill and reconcile (#152)

**Files touched**
- `tools/reconcile_store.py` (new)
- `docs/label-store-provision.md` — the measurement

**What changes**
Ingest everything already in `results/`, then reconcile the store against the archive: for each run,
the store's row counts must agree with that tarball's own `run.counts`. A backfill that cannot be
checked against the archive it came from is a claim, which is this repo's standing objection to any
unverified measurement.

**The test that proves it** — the reconciliation is the test. It is proven by a deliberately
corrupted count failing it, so the reconciler is not trivially agreeing with itself. Also: a second
full backfill over an already-ingested archive adds **zero** rows.

**Depends on** LS-5 and LS-7.

---

## Step LS-9 — Tier-2 ingestion (#153)

A gate, not a build. The path is identical; what it needs is that the one remaining runner produces
tier-2 output worth storing.

**What changes** — nothing in this repo. Issue #142 fixed, then one `--both` run whose `run.ruleset`
shows the full snapshot loaded, ingested and read back out through `blfile`.

**The test that proves it** — `run.counts.rules_loaded` equals `total_admitted` on a run from
`fl-replay`, and the resulting store rows carry `tier: 2`. Today that number is zero there, which is
the whole issue.

**Depends on** LS-8 and **#142**.

---

## Definition of done for Phase 3

1. A capture labelled on `fl-replay` lands in the store without anyone typing a second command.
2. Re-running that capture updates it rather than duplicating it, and a `TRUNCATE` plus
   `--backfill` reproduces the same rows.
3. `blfile --label verdict` produces a schema-correct collection in which **every** flow names the
   `gs://` path and digest of the capture it came from.
4. `blfile --rebuild` of that document reproduces it over records.
5. `flabel-db verify` is green in CI, and a hand-patched column turns it red.
6. Tier 2 is either in the store from an 8.0.6 engine, or **#142 is open and the spec says tier 2 is
   not there** — not silently absent.
