# PLAN — the label store and `blfile` (Phase 3)

Spec: `docs/spec-label-store.md`. Design reasoning: `inline-labeling/label-store-design.html`.

`PLAN.md` is Phase 1 and is closed. This is a separate plan for a separate phase.

**Revision 2, 2026-08-20.** Revision 1 was reviewed by a fresh agent and four of its BigQuery claims
were then executed against the live service. The step list is resequenced rather than renumbered —
issues #145–#153 keep their step ids, so nothing has to be re-filed.

## Progress — Phase 3a is COMPLETE

| Step | Issue | State |
| :-- | :-- | :-- |
| LS-1 additive fields | [#145](https://github.com/DeepTempo/flabel/issues/145) | ✅ merged (PR #155) |
| LS-3 `flabeldb` + schema | [#147](https://github.com/DeepTempo/flabel/issues/147) | ✅ merged (PR #157) |
| LS-6 dataset + IAM | [#149](https://github.com/DeepTempo/flabel/issues/149) | ✅ merged (PR #160) |
| LS-4 `flabel-ingest` | [#148](https://github.com/DeepTempo/flabel/issues/148) | ✅ merged (PRs #166, #167, #168) |
| LS-2 `flabel-deploy` ⟂ | [#146](https://github.com/DeepTempo/flabel/issues/146) | ✅ merged (PR #170) |
| LS-5 wire `flabel-run` | [#150](https://github.com/DeepTempo/flabel/issues/150) | ✅ merged (PR #169) |
| LS-7 `blfile` | [#151](https://github.com/DeepTempo/flabel/issues/151) | ✅ merged (PR #174) — the last of Phase 3a |

LS-4 landed two corrections to documents outside its own scope, both found by running it rather
than reading it: spec §5.3 step 3 contradicted its own step 2 (a table cleared by step 2 and then
skipped by step 3 as "already done" ended with zero rows under a live commit marker), and §7.4's
guard 4 — the duplicate-`run_id` assertion — had never been implemented at all.

LS-7 moved the merge rule out of SQL and into `src/flabeldb/merge.py`, and the eng-review gate ran
**before** the PR this time. It returned thirteen findings; the three that mattered were all in the
same place — the verdict. `models.verdict_entry` hardcodes `value="malicious"`, so rebuilding it
from the surviving sources is a *write*: a stored verdict of any other value was silently rewritten
and published as ground truth, and the cross-tier conflict guard could not see it because it only
compared stored entries with each other. Worse, a `--both` run stores its verdict at
`min(sources.tier)`, so tier-filtering that entry dropped it entirely — leaving the exact run shape
rule 2 exists for with no comparison at all. Both were reproduced by hand before being believed.
Two more were found by running the tool rather than reading it: `--capture <name>` resolved
correctly in SQL and was then re-filtered by name downstream, returning an empty collection at exit
0; and a bad `--output` path escaped `main` entirely and reached the interpreter as exit 1 — the
code `blfile` publishes as "the store holds a disagreement".

Forty-eight sabotages, all red for their stated reason. Six of them were green first: four were
escapes in the tests (a `flow_key` tie-break `merge.compose`'s own pre-sort made unobservable, a
`--limit` fixture whose two sort keys ascended together, an ordering test that never used two
captures, and a UTF-8 assertion that round-tripped through `json.loads`), and one was a stale `.pyc`
in the sabotage harness itself, which is worth knowing: a patch and a restore inside one second can
leave the previous bytecode in place and read as a guard that holds.

LS-5 closed the gap between "`--source-uri` exists" (LS-1) and "anything passes it": the wrapper now
carries the original `gs://` argument and calls `flabel-ingest` after a successful publish. Its one
`requires_bigquery` test pins the behaviour revision 1's deleted publish-on-exit-0 bullet was reaching
for — **an empty `labels[]` is a result, not an absence**, so a capture since found clean takes the
tier and stops reading as malicious.

The `flabel` dataset was provisioned 2026-08-24 — five tables and `authoritative_runs`, all empty —
closing [#163](https://github.com/DeepTempo/flabel/issues/163), which no step owned. It is what LS-2's
pre-deploy `verify` gate needs in order to pass, and what LS-4 will write the first rows into.

## Shape of the work

**Phase 3a — LS-1 … LS-7.** Land the store, and the origin URI the requirement actually asks for.
**Phase 3b — LS-8, LS-9.** The whole-archive backfill and reproduction, once real rows have been seen.

Splitting was Craig's call, and the reason is not only scope: LS-8 backfills every run already in the
archive, and revision 1 would have done that *before* anyone looked at a real row. LS-9's
`--rebuild` / `--as-of` machinery is a sub-project for a use case nobody has had yet.

```
3a │ LS-1 additive fields ─→ LS-3 flabeldb + schema ─→ LS-6 dataset + IAM ─→ LS-4 ingest ─┬─→ LS-5 wrapper ─→ LS-7 blfile
   │                                    └────────────→ LS-2 flabel-deploy ⟂
   ├──────────────────────────────────────────────────────────────────────────────────────────────────────────
3b │ LS-8 backfill + reconcile ─→ LS-9 blfile reproduction          tier 2 ← gated on #142
```

**Two parallelism claims from revision 1 were wrong**, and the lesson is that file-disjointness is
necessary but not sufficient:

- **LS-1 ⟂ LS-2** was file-disjoint, but `flabel-deploy` runs `uv sync --extra db` and that extra does
  not exist until LS-3. Landing LS-2 first ships a deploy script that fails on an unknown extra. LS-2
  now follows LS-3.
- **LS-4 ⟂ LS-6** was file-disjoint, but LS-4's three most important tests are `requires_bigquery`.
  LS-6 now precedes LS-4. **The reason given here was wrong and is corrected in LS-6's own section:**
  those tests need `flabel_scratch`, which already existed, and `test_flabeldb_live.py` *refuses* to
  run against `flabel` at all. What LS-6 gives LS-4 is **verified grants** — the confidence that a load
  job from the box will not 403 — not the dataset. The ordering stands; the justification did not.

Only LS-2 is now genuinely parallel, against LS-6 and LS-4.

**Sabotage round on every step.** Break each new guard deliberately, one at a time, and confirm a test
goes red. A sabotage that *passes* is a finding: of #138's twelve guards, seven had no test at all and
only breaking them found it. Restore from file copies, never `git checkout <file>`.

**Definition of done for a step**, and the list is now *ordered*: tests pass locally, CI green on the
branch, the sabotage round run and recorded, **then a fresh `eng-reviewer` pass on the diff and its
findings acted on — before the PR is opened**, not after it merges.

The ordering was implicit and it did not hold. LS-5 met every other item on this list, merged as
#169, and was reviewed afterwards; the review found a CRITICAL that all of it had missed — a bare
`flabel-ingest` on nobody's `PATH`, which would have left the store permanently empty while every
run reported exit 5 (#171, fixed in #172). Reviewing after the merge turns the gate into a
post-mortem.

---

# Phase 3a

## Step LS-1 — Additive `run.input` fields and `LABEL_KINDS` (#145)

The only step touching `src/flabel/`. **Revision 1 called it small; it is not.** Six source files,
three test files, two spec sections — roughly a day. Planned for rather than discovered.

**Files touched**
- `src/flabel/models.py` — `LABEL_KINDS`, `LabelKind`; `NormalizedCapture` carries `link_type` and
  `snaplen`; arity and tier enforcement in `LabelEntry` / `Label.__post_init__`
- `src/flabel/ingest.py` — stop discarding `_snaplen`; return the retained `link_type`
- `src/flabel/cli.py` — `--source-uri`, validated, threaded through to the run block
- **`src/flabel/provenance.py`** — `_input_section` (~line 508) is where the `input` block is built,
  **not `labels.py`**, which revision 1 named. Its `capture is None` branch lists keys explicitly and
  must gain all four as `null`, or a dead run drops a key §10 forbids dropping.
- **`src/flabel/canonical.py`** — add `input.uri` to `EXCLUDED_INPUT_KEYS`. A spec decision (§6.1), not
  a detail: without it the same capture staged from two origins fails Goal 2's gate.
- `docs/spec.md` §10 (the run block's key set) and **§12** (the flag — §11 declares the CLI contract
  closed, so this needs its reasoning recorded as #132's did)
- `tests/test_models.py`, `tests/test_ingest.py`, `tests/test_cli.py`, **`tests/test_provenance.py`**

**Four files outside this list were touched, and the list is amended rather than the fact hidden**:
`src/flabel/correlate.py` and `tests/test_correlate.py` (the first review's HIGH 1 — the tier rule
was enforced in two places), `tests/test_canonical.py` (implied by this step's own two-origins
test), `tests/fixtures/make_awkward.py` (a fixture whose interfaces disagree on snaplen, without
which the second review's HIGH 2 was untestable), and `docs/spec-label-store.md`. `CLAUDE.md` says
not to edit outside the step without asking; each of these came from a review finding rather than
improvisation, and recording them here is what keeps the next reader from comparing against a stale
list.

**After this step lands, `--source-uri` exists and nothing passes it.** The headline requirement
stays unmet in production until LS-5 wires the wrapper. Said out loud so the step is not mistaken
for the deliverable.

**Expect the build red before green.** `test_the_run_block_carries_exactly_the_keys_spec_10_declares`
(`test_provenance.py`, ~line 1518) asserts set **equality** between the built block and §10's literal,
and its `full_run` fixture must change too. That is the mechanism working.

**What changes** — the four fields of spec §6.1 (`uri`, `uri_status`, `link_type`, `snaplen`) and
`LABEL_KINDS`.

**`LABEL_KINDS` joins the `Literal`, it does not replace it.** `LabelEntry.name: LabelName` uses
`Literal` as a type annotation and `_check` reads `get_args(LabelName)`; static typing cannot come from
a `Mapping`. Both exist, plus a test asserting `get_args(LabelName) == tuple(LABEL_KINDS)` — without
which this creates the two-copies hazard it is meant to prevent.

**The test that proves it**
- All four keys present, `uri: null` + `uri_status: "local"` with no flag, populated with one.
- The failed-run path (`capture is None`) reports all four as `null` rather than omitting them.
- `--source-uri notagsuri` and `--source-uri ""` exit 2 before a run directory exists.
- `snaplen` matches `capinfos` on the fixture — asserted against the tool, not our own header parse.
- `link_type` is the *retained* type on the two-link-type fixture `make_awkward.py` builds. On a
  single-link fixture this passes for the wrong reason.
- Two runs of one capture from different origins compare equal through `canonical`.
- `get_args(LabelName) == tuple(LABEL_KINDS)`; arity and permitted tiers are **enforced**, not declared.

**Sabotage** — the wording here was originally *"remove `LABEL_KINDS` from the name check and
confirm a forged `LabelEntry(name="mitre")` starts constructing"*, and that is **not executable**:
`_check(self.name, get_args(LabelName), …)` runs first, so the table is never consulted for an
unknown name. What was run instead, sixteen sabotages across the two parts, all sixteen red after
two rounds of fixing:

*Part A* — drop the kind-tier check · drop the single-arity check · drop the multi-arity check ·
add a kind to `LABEL_KINDS` absent from `LabelName` · drop `LabelKind`'s empty-tiers guard · drop
its arity `_check` · make `correlate` hardcode the tier again · drop `MappingProxyType`.
*Part B* — report the **discarded** link type · discard `snaplen` again · drop `uri` from the run
block · pin `uri_status` to `local` · drop the null keys on a dead run · stop excluding `uri` from
`canonical` · accept any `--source-uri` · accept a bucket with no object.

**Three passed on the first attempt and each was a finding**: `LabelKind`'s empty-tiers and arity
guards had no test at all (nothing in the codebase builds a bad kind), and the multi-arity
empty-item test used `("T1190", "")` — which the *sorted* guard catches first, so it passed without
the empty-item check existing. See `passing-tests-near-new-guards-are-suspect` for the general rule.

**Depends on** nothing.

---

## Step LS-3 — `flabeldb` package, schema, `apply` / `verify` (#147)

**Files touched**
- `pyproject.toml` **and `uv.lock`** — `[project.optional-dependencies] db`,
  `packages = ["src/flabel", "src/flabeldb"]`, console scripts. `ci.yml` runs `uv sync --locked`, so a
  stale lock turns CI red on the first push; revision 1 listed neither file.
- `src/flabeldb/{__init__,schema,client,cli}.py`
- `src/flabeldb/views/authoritative_runs.sql` — **the only view.** `current_labels` is gone (spec §5.2).
- `tests/test_architecture.py`, `tests/test_flabeldb_schema.py`

**Files outside this list were touched, and the list is amended rather than the fact hidden** — the
same precedent LS-1 set above. `.github/workflows/ci.yml` gains a `no-db-extra` job: this step made
`--extra db` unconditional in both existing jobs, so nothing could notice that the suite was red
without the extra, which is what `uv sync` gives by default. `tests/conftest.py` and `pyproject.toml`
gain the `requires_bigquery` and `requires_db_extra` markers and the `--bigquery` opt-in, because
`--strict-markers` is on and the live tests must not run by default — they delete and recreate
tables, and fl-replay's metadata server would otherwise let a bare `pytest` rewrite a dataset. New
test files `tests/test_flabeldb_{apply,credentials,live,db_extra}.py` and `tests/db_extra.py`.
`docs/spec-label-store.md` §4.2 said `snaplen` where LS-1 had made the field plural — the drift was
LS-1's, found while declaring the column, and corrected here rather than left for a reader to trip
over. `docs/status.yaml` carries the tracker as always, and `docs/RESUME-ls-3.md` is a new handoff
document written when the work moved to `fl-replay`.

CLAUDE.md says not to edit outside the step without asking; each of these came from a review finding
rather than improvisation.

**A measurement worth carrying forward, from the sabotage round on 2026-08-21.** The plan's stated
sabotages for the view were run against `flabel_scratch`, and the grep tests and the behavioural
tests turned out to be complementary rather than one replacing the other:

| sabotage | grep tests | behavioural tests |
| :-- | :-: | :-: |
| `ORDER BY` drops `run_id` | **caught** | passed |
| `ORDER BY finished_at ASC` | passed | **caught** |
| `EXISTS` for `NOT EXISTS` | passed | **caught** |
| `UNNEST(tiers_attempted)` | **caught** | **caught** |
| `WHERE recency >= 1` | passed | **caught** |

Three of five were invisible to a suite that only greps, which is why the behavioural tests were
written. But the first row is why the grep tests stay: with the tie-break gone the engine still
returned the expected run, because the sabotaged view is not wrong on every execution — it has
merely stopped being a function of the data. **No behavioural test can reliably catch the absence
of a tie-break.** Reading the statement is the right tool for that one decision.

**What changes**
The five tables of spec §4 — `runs`, `captures`, `flow_labels`, `unmatched`, `run_exclusions` — as
client schema objects. `flabel-db apply | verify | show`. Credentials per §7.1.

**Three things in the schema are revision-2 corrections**: no partition on `flow_labels` (a struct
field cannot be partitioned on — measured), `run_block` as `STRING` not `JSON` (the `JSON` type
normalises numbers, so it cannot be "verbatim"), and `tiers_attested` + `attestation_notes` replacing
`tiers_delivered`.

**The test that proves it**
- `verify` detects a type change, a dropped field, and an added field — three assertions, because
  "detects a difference" is satisfied by code noticing only one.
- `test_architecture.py` fails if a module under `src/flabel/` imports **`google`** or `flabeldb`.
  `imported_modules()` records top-level names only, so a check on `"google.cloud"` would pass forever
  — revision 1's exact wording could never have fired.
- `src/flabeldb` gets its own accounted-for test; `PACKAGE` is hard-coded to `src/flabel` today, so the
  new package would otherwise carry no architectural check at all.
- `import flabel` succeeds with the `db` extra absent; console scripts name `flabel[db]`.
- `authoritative_runs` picks the newer of two runs finishing in the **same second** — the `run_id`
  tie-break, not the timestamp — and excludes a run present in `run_exclusions`.
- The view SQL is templated on the dataset name, so it can be dry-run against `flabel_scratch`.

**Sabotage** — drop `run_id` from the `ORDER BY`. Drop the `run_exclusions` anti-join. Change the
architecture guard to `"google.cloud"` and confirm it stops firing.

**Depends on** LS-1.

---

## Step LS-6 — Dataset, IAM, and verification (#149) ✅ merged 2026-08-24 (PR #160)

**Amended after the fact from `docs/label-store-provision.md` §4**, which recorded three ways this
section had gone stale and correctly declined to edit a file outside its own list. The original
wording is kept struck through where it was *wrong*, not merely superseded, because what it got wrong
is the point: this step turned out to be **verification, not provisioning**.

~~Resequenced to **precede** LS-4, because LS-4's real tests need what this provisions.~~
**False.** `tests/test_flabeldb_live.py` *refuses* to run against `flabel` — it deletes and recreates
tables — and defaults to `flabel_scratch`, which already existed. The resequencing was still right,
but the reason was wrong: what LS-6 gives LS-4 is **grant verification**, not the dataset.

**Files touched** — `docs/label-store-provision.md`

**What changes**
- ~~The `flabel` dataset in **`us-central1`**~~ — **it already existed**, created 2026-08-20 18:33 UTC
  as a side effect of LS-3's live round trip, in `us-central1`, and undocumented until now. That
  undocumented state is what LS-6 actually closed. The location requirement itself stands: the results
  bucket is `US-CENTRAL1` regional and a load job needs a compatible location.
- **BigQuery IAM, which revision 1 omitted entirely** — the same omission as the 2026-08-19 GCS
  blocker, one service over: `bigquery.jobUser` on the project and `bigquery.dataEditor` on the dataset
  for the instance SA. ~~`dataOwner` for whoever runs `apply`.~~ **Measured false** — `apply` run as the
  SA, which holds only `dataEditor`, exited `0` and 16 live tests passed. Spec §7.3's `dataOwner` row is
  over-broad and should be narrowed or justified.
- ~~**No GCS grant is needed.** Revision 1 called `objectViewer` a blocker~~ — true, but **established
  in spec §7.2, not found here.** LS-6 does not get credit for it.

**The test that proves it** — from the box, both directions: a read of a published tarball succeeds
(**already verified** — metadata-server token, HTTP 200), a load job succeeds, and an overwrite and a
delete are still refused. Recorded with the command and its output.

**What it actually established**, beyond the above: the archive **is** protected from the ingestion
identity in both directions (`403` on delete and on overwrite), which retracted #158. The probe that
said otherwise used `--if-generation-match=0`, whose precondition fails on any existing object, so it
returned `412` regardless of permission — the guard that made it safe made it blind. A discriminating
probe needs a *matching* precondition and an operator-side positive control. And the answer had been
in `docs/status.yaml` since 2026-08-19 from a better probe than either revision built.

**Left open** — #159, #161, #162, #163 (closed 2026-08-24, below), #164.

**Depends on** LS-3. `⟂ LS-2`.

---

## Step LS-4 — `flabel-ingest` (#148)

**Files touched** — `src/flabeldb/{parse,identity,attest,ingest}.py`, `tests/test_flabeldb_*.py`

**What changes**
One parser over a run directory, with a fetch-and-untar adapter for `gs://`. `run_id` and `flow_key`
per spec §3. **Tier attestation** per §2.4. Load jobs in commit-marker order with the §5.3 retry path.
`--backfill`, `--skip-tier`, and the duplicate-`run_id` assertion.

**Two things here are revision 2 and are the point of the step.** Attestation, because
`tiers_unavailable` is empty on every successful run and so revision 1's delivery guard could never
fire — while #142's zero-rules-loaded run would have superseded good tier-2 knowledge. And the retry
path, because a **failed BigQuery load job burns its job id permanently** (measured), so revision 1's
"re-running the same ingest completes it" was false and a half-loaded run was unrecoverable.

**The test that proves it**
- *Pure:* `flow_key` is identical for one flow read from two runs whose Zeek `uid`s differ — driven by
  the two fixtures that produced the M1 measurement — and differs for two flows sharing a 5-tuple and
  differing only in `ts_first`. Computed from the **ISO string**, never a re-parsed float.
- *Pure:* a flow whose proto is not tcp/udp/icmp is refused and counted, not written (§3.2, #96).
- *Pure:* attestation refuses tier 2 when `rules_loaded != total_admitted`, and the note says why. A run
  block copied from a real `fl-replay` `--offline` run is the fixture.
- *Against BigQuery:* the same tarball twice yields one set of rows, short-circuiting on the `runs`
  query rather than on a job-id error.
- *Against BigQuery:* **the recovery path.** Kill after `flow_labels`, before `runs`; nothing is
  visible; re-run; the run completes with no duplicated rows. Then force a load failure and confirm the
  attempt walk gets past the burnt id.

**Sabotage** — reorder the loads so `runs` lands first. Make `flow_key` read `flow.uid`. Make
attestation return `tiers_attempted` unconditionally and confirm the #142 fixture test goes red.

**Depends on** LS-6.

---

## Step LS-2 — `tools/flabel-deploy` (#146) ⟂

Resequenced after LS-3: it runs `uv sync --extra db`, and that extra does not exist until then.

**Files touched** — `tools/flabel-deploy`, `tests/test_flabel_deploy.py`

**What changes** — `git pull --ff-only`, `uv sync --extra db`, `flabel-db verify`, and a **conditional**
wrapper reinstall on `md5sum` difference. Refuses while `pgrep -af "tcpreplay|flabel|uv run"` matches.

`verify` runs **here** rather than in CI: `ci.yml` has no GCP credential, the metadata server does not
exist in GitHub Actions, and this is a public repo. Craig declined Workload Identity Federation as out
of scope, so pre-deploy is where the gate lives and Phase 3's DoD says so.

**The test that proves it**
- An `md5`-identical wrapper is not reinstalled, and the output says so; a differing one is.
- A `pgrep` match aborts **before** issuing the pull or the install — asserted on the commands issued,
  not on the exit code.
- A failed `pull` does not proceed to `uv sync`; a failed `verify` does not proceed to the reinstall.
- Overridable paths following `flabel-run`'s convention, so tests need neither `/opt` nor root.

**Sabotage** — make the `pgrep` guard non-fatal. Note #136's trap: check the sabotage fails for the
*stated* reason, not because a later check caught it independently.

**Thirteen were run, and #136's trap caught four of the tests rather than the code.** The plan's own
sabotage — the non-fatal `pgrep` guard — came back as a bare `assert 0 == 1`, because every
"does not proceed to X" test asserted the exit code *before* the commands issued. A script that
pulled, synced and then exited 1 would have satisfied that first assertion completely. The four
tests now assert the command list first, so the sabotage names the escape instead of the symptom.

**Two guards were measured inert, and both were found only by sabotaging them:**

- `install -m 0755` — removing the flag left the test green, because `install`'s own default mode
  is already 0755. The flag is documentation; the test is red for `-m 0644`, which is the mistake
  that can actually be made.
- the `[ -f "$INSTALL_TO" ]` before the `md5sum` comparison — the expected failure was "the first
  deploy on a fresh box breaks", and it does not: `set -e` is suppressed inside an `if` condition,
  so the failing `md5sum` yields an empty string and the install proceeds correctly. What the guard
  actually buys is that a successful first deploy does not print an `md5sum: ... No such file` line
  to stderr on its way to succeeding, and the test now pins that.

Both belong to `passing-tests-near-new-guards-are-suspect`, and neither would have been visible by
reading the diff.

**Depends on** LS-3. `⟂ LS-6`, `⟂ LS-4`.

---

## Step LS-5 — Wire `tools/flabel-run` (#150)

The layer where both of #134's late bugs lived, and which had no tests until #135.

**Files touched** — `tools/flabel-run`, `tests/test_flabel_run.py`, `docs/spec.md` §12 (exit 5)

**What changes**
- Pass `--source-uri` with the **original** argument, captured before `TARGET="$LOCAL"` overwrites it.
- Call `flabel-ingest` after a successful publish.
- Exit 5 — published, not indexed.

**Revision 1's publish-on-exit-0 bullet is deleted.** Its premise was false: `_write_output` writes
`run.json`, `NOTICE` and `labels.json` unconditionally on the success path, and `docs/spec.md` §13 says
an all-IPsec capture "exits 0 with `labels[]` empty" — so a clean capture already publishes and already
clears a stale tier. The change would have reversed a recorded 2026-08-19 decision, deleted a passing
test, and destroyed the only unambiguous signal spec §2.5 has, because **a tarball carries no exit
code**.

**The test that proves it**
- `--source-uri` carries the `gs://` argument, **not** the staged path — asserted on the argument alone,
  not by substring over the command line (#134's review found a check that matched the pytest temp path
  because macOS puts runs under `/var/folders/`).
- A successful run with an **empty `labels[]`** is published, and ingesting it clears a previously
  authoritative tier. This is what revision 1's deleted bullet was reaching for, tested where it is
  actually true.
- An ingest failure exits 5 with `labels.json` intact and the tarball published.
- A failed run is still not published and still exits 1.
- A usage error still exits 2, and a `SIGTERM` still reaches the child — the extra post-command step
  must not re-break what #134's trap fixed.

**Sabotage** — send the staged path as `--source-uri`. Make the ingest failure exit 1.

**Depends on** LS-1 and LS-4.

---

## Step LS-7 — `blfile` (#151)

**This step now owns the merge rule**, which revision 1 had in SQL. That is the largest single change
between revisions: one implementation, in the language whose constructors already assert the invariants.

**Files touched** — `src/flabeldb/{query,merge,collection,blfile}.py`, `tests/test_flabeldb_merge.py`,
`tests/test_blfile.py`

**What changes**
Read the authoritative runs' raw rows; compose per spec §5.2 using `models.Label` and
`models.verdict_entry`; emit the `labels-collection` document of §6.4. Selection with AND semantics,
`--label` validated against `LABEL_KINDS`, plus `--capture` and `--limit`.

**The test that proves it** — the merge tests are pure, run in CI, and are the ones that matter:
- A `--both` run authoritative for tier 1 only contributes its tier-1 sources and **not** its tier-2
  ones.
- Tier 1 from one run and tier 2 from another compose into one record whose `origin.run_ids` is a
  `{tier: run_id}` map naming both. `docs/spec.md` §13 requires every assertion to name what produced it.
- `best_tier` is recomputed and agrees with `min(sources.tier)` — `Label.__post_init__` enforcing itself.
- A cross-tier conflict on a single-arity label's value is a **hard failure**, not a silent pick.
- An unknown `--label` exits 2, and a test asserts `blfile` reads `LABEL_KINDS` rather than a second copy
  of the names. The 2026-08-19 placeholder sabotage is why this is asserted.
- Two `--label` values emit only flows carrying both. Bare `blfile` selects `verdict`.
- A flow whose capture has `uri_status: not-recorded` is **refused** unless `--allow-missing-origin`, and
  `selection.flows_without_origin` is published either way.
- `coverage` per capture is present and matches the run block's `loss_conditions` and `counts`.

**Sabotage** — drop the tier filter in step 2 of the composition and confirm the `--both` test goes red.
Make the value conflict pick silently.

**Depends on** LS-4.

---

# Phase 3b

## Step LS-8 — Backfill and reconcile (#152)

**Files touched** — `tools/reconcile_store.py`, `docs/label-store-provision.md`

**What changes** — ingest the archive, then reconcile the store against it: each run's row counts must
agree with that tarball's own `run.counts`.

**Run with `--skip-tier 2` until #142 is fixed.** Every `--offline` and `--both` run already in the
archive came from the box whose Suricata loads none of the snapshot. Revision 1 said "tier-2 ingestion
is gated on #142" and supplied no mechanism; attestation (§2.4) plus this flag is the mechanism.

**The test that proves it** — the reconciliation is the test, proven by a deliberately corrupted count
failing it. A second full backfill adds **zero** rows. Expect ~375 runs/day maximum: four load jobs per
run against a 1,500-per-table-per-day quota.

**Depends on** LS-5 and LS-7.

---

## Step LS-9 — `blfile` reproduction (#153)

`--as-of`, `--rebuild`, `collection_id`, and the `builder` digests. Design is spec §6.5 and is not
re-derived. Note §4.1's limit: `ingested_at` does not survive a rebuild, so `--as-of` is an audit tool
across that boundary, not a reproduction one.

Issue #153 was originally "tier-2 ingestion"; that is now a gate rather than a step, tracked on **#142**
plus LS-8's `--skip-tier`.

**The test that proves it** — `--rebuild` reproduces over records with `built_at` excluded; a pinned
`run_id` missing from the store is a hard failure naming it; `--rebuild --label` and `--rebuild --as-of`
exit 2; a run whose `finished_at` precedes an `--as-of` cutoff but whose `ingested_at` follows it is
**excluded** — the assertion that pins the whole argument, and the one a plausible implementation gets
backwards.

**Depends on** LS-8.

---

## Definition of done for Phase 3a

1. A capture labelled on `fl-replay` lands in the store without anyone typing a second command.
2. Re-running that capture updates it rather than duplicating it; a killed ingest is completed by
   re-running it; and `TRUNCATE` + `--backfill` reproduces the same rows apart from `ingested_at`.
3. `blfile --label verdict` produces a schema-correct collection in which every flow either names the
   `gs://` path and digest of its capture, or is refused and counted.
4. `flabel-db verify` is green as a **pre-deploy gate**, and a hand-patched column turns it red. Not a
   CI gate — see spec §2's testing line.
5. Tier 2 is in the store only from an engine that attested a full ruleset load; otherwise it is loaded
   and not authoritative, and `attestation_notes` says why.
