# Resuming after LS-9 on `fl-replay`

Written 2026-08-27, on `docs/RESUME-ls-7.md`'s precedent. **Authoritative state is
`docs/status.yaml` — its `next_action` leads with this and its `log:` carries the reasoning.** This
file is the operational half: where you are, what is decided, and what to do first.

## The situation in one paragraph

**Phase 3 is one merge from complete.** LS-7 and LS-8 are on `main`; LS-9 is PR #177, green on every
check and `MERGEABLE`, waiting only on review approval. The production `flabel` dataset holds
**1,955 rows** and reconciles clean against the archive. Nothing is blocked: the one open question
outside Phase 3 — whether to bring Zeek down to the pinned 8.0.9 — was **decided on 2026-08-27 in
favour of staying on 8.2.1**, and the last section records what that leaves behind.

## Where things stand

| | |
| :-- | :-- |
| `main` | `f2d5639` — Phase 3a, LS-8 (#175), and the production-backfill record (#176) |
| open | **#177** (LS-9), 4 commits, green, `MERGEABLE`, `REVIEW_REQUIRED` |
| suite | 1,807 pass (`-m "not requires_tools"`), 30 more behind `--bigquery` |
| `flabel` | 25 runs · 25 captures · 1,870 `flow_labels` · 35 `unmatched` = **1,955 rows** |
| `blfile` | 408 flows across 15 captures selectable; round-trips at exit 0 |
| `#153` | stays **open** on `collection_id` alone — deferred, see §6.4 |

## What the review process cost, and what changed because of it

Read this before the next step, because it is the most transferable thing here.

**One review per step was not the gate `CLAUDE.md` describes.** The pattern each time was review →
substantial fixes → PR, with the fixes unreviewed. LS-9 got three rounds, and each round found
defects **in the previous round's fixes**:

1. Round 1 found the pinned-tier defect (`--rebuild` recovered a run's tiers from `tiers_attested`,
   which is what a run *claimed*, not what it supplies — every capture re-run at one tier was
   un-rebuildable).
2. Round 2, on the fixes, found two blocking defects — one of them a re-run of round 1's own
   finding, in the same function: validation that covered two of three pin fields and missed
   `run_id`.
3. Round 3, on *those* fixes, found the same shape a third time: `run_id` and `limit` validated,
   `selection.labels` missed.

So the fourth fix was **structural rather than another field**: `collection.DOCUMENT_SHAPE` declares
every field a rebuild path reads, one walk checks it, and a test asserts the declaration covers every
key `build` emits. A new field without a spec is now a failing test rather than a latent crash. Note
the meta-test beside it — the first version of that coverage test could not fail, because it filtered
the document's paths by the declaration before comparing.

**The standing change:** re-cut the diff and re-review after acting on findings. Do not treat the
first pass as the gate.

## Things that will bite if you do not know them

**Every merge in this phase has been a squash, and every stacked branch has needed a rebase.** Four
times: #173, #174, #175, #176. The recipe, and it is worth following exactly:

```sh
git diff --quiet <old-base> origin/main   # PROVE the squash preserved the content first
git rebase --onto origin/main <old-base> <branch>
```

Git drops the duplicated commit itself ("patch contents already upstream"). Two traps: GitHub reports
`CONFLICTING` for a while after a force-push plus retarget even when the merge is clean — check with
`git merge-tree --write-tree` locally before chasing it; and rebasing onto the *wrong* base silently
drops commits, so check `git rev-list --left-right --count origin/main...HEAD` afterwards.

**BigQuery's metadata is eventually consistent behind DDL.** Making a live fixture function-scoped
turned one table rebuild into five and produced five fixture errors in one run of
`test_flabeldb_live.py`. Fixtures that only want an *empty* table use `empty()` (`TRUNCATE`), not
`rebuild()` (delete-and-recreate). `rebuild` stays for tests whose subject is the table's shape.

**A sabotage harness can under-report.** CPython keys a `.pyc` on `(mtime, size)`, so patching and
restoring a file inside one second can leave stale bytecode — a genuinely broken guard read as
holding. The harnesses in the scratchpad clear `__pycache__` and set `PYTHONDONTWRITEBYTECODE=1`.

**Doc claims are load-bearing and have been wrong twice.** LS-8's provisioning doc asserted
"0 `[self-report]` — every one of the 25 tarballs is internally consistent" when that leg had
executed *zero* times; #176 asserted "8 of the 24 replay runs are superseded" when it is 7 (8 is
`25 − 17`, which counts the unattested `--offline` run that was never a candidate). Both were caught
by review, not by tests. **A measured number in a doc deserves the same scepticism as a guard.**

## What only real rows could establish

- Only **408 of 1,870** `flow_labels` rows are selectable; 1,462 are superseded or unattested. That
  is §5.1 working, and `blfile` emitting exactly 408 matches a SQL count over the same view — a
  cardinality check, **not** two implementations agreeing (§5.2 forbids a second one existing).
- The archive is 24 `replay` runs and one `--offline` run, and that one attests **nothing**:
  `84958 of 84960 admitted rules loaded`. So **no tier-2 knowledge is selectable**, and LS-7's
  cross-tier composition path still has only fixtures behind it (#144). Note the branch that fired
  is §2.4's strict equality, *not* #142's "loads none of it" — pinning Suricata may not clear it.
- **The headline requirement is unmet for every row now in the store.** Bare `blfile` emits 0 flows
  and refuses 408 for want of a recorded origin: all 25 `captures` rows predate `--source-uri`. A
  capture labelled after LS-5 carries its `gs://` origin and needs no flag.

## Do this first

1. **Merge #177.** Phase 3 is complete with it.
2. Then **Phase 4, or the unowned backlog** — see below. There is no LS-10.

## Zeek: decided — the box stays on 8.2.1

**Decided 2026-08-27 (Craig): stay on the installed version. There is no downgrade to do.** Asked
that day to bring local Zeek to **8.0.9**, which is `Dockerfile.toolchain`'s `ZEEK_PACKAGE_VERSION`.
Measured first, and it could not have been done anyway:

| | |
| :-- | :-- |
| this box | **8.2.1-0**, from the `security:zeek` OBS repo, into `/opt/zeek` |
| the apt repo now serves | `zeek-8.0` at **8.0.1-0**; unversioned `zeek` at **8.2.2-0** |
| `security:zeek:8.0` per-branch repo | **404** — does not exist |
| the pinned GHCR image | **private**; `gh`'s token has no `read:packages`, and there is no docker or podman on the box |
| source | `v8.0.9` exists (`6e96ac1`); `cmake`, `bison`, `flex` missing; 4 cores |

**This is the shelf-life gap `status.yaml` already recorded** — *"the apt repos serve only
newest-patch, so `Dockerfile.toolchain` will eventually stop being rebuildable and the pinned
toolchain survives only as the GHCR image pinned by digest"* — arriving. Staying on 8.2.1 settles
which Zeek this box runs; it does not settle the gap, and the choice that entry names ("mirror the
.debs/image or accept the bound in writing") is still open — see the last paragraph of this section.

**And 8.0.9 was the wrong target, which is why the decision went the other way.** All 25 archived
runs record `tools.zeek: 8.2.1` — so the corpus, and the 1,955 rows derived from it, were produced by
8.2.1. The box agrees with the data; only the *pin* says 8.0.9. Downgrading would have moved the box
away from every row in the store to match a pin that can no longer be rebuilt, and it would have made
the next run's `tools.zeek` differ from all 25 existing ones for no gain.

**What the decision does not close, and nobody owns:** `Dockerfile.toolchain` still pins
`ZEEK_PACKAGE_VERSION=8.0.9-0`, now matching neither the box nor a single row in the store, and
unobtainable from apt. **CI is green only because the image is pinned by digest** — so the digest is
the real pin and that Dockerfile line documents a build no one can reproduce. Bumping it to 8.2.x is
the rebuildable fix; it changes what CI tests against, so make it deliberately rather than in
passing. Left unfiled on purpose — raise it with the rest of the backlog below.

## Still open and unowned

- **#162** — the real project id and SA email in plaintext on this public repo. A standing
  `CLAUDE.md` guardrail violation, and the issue is explicit that the fix is a *decision* (history
  rewrite versus accepted exposure) rather than a patch.
- **#142** — now with a measured production consequence, and a corrected diagnosis (see above).
- **#161** project Editors are writers via the default dataset ACL. **#164** nothing detects a
  replaced published tarball — narrowed by LS-8's reconciliation, not closed. **#159** `flabel-db
  show` exits 3 on a provisioned-but-empty dataset.
- **#153** on `collection_id` only. §6.4 records the three jobs it could serve; if it is built, build
  both digests rather than either alone.
