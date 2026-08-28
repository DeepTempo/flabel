# PLAN — Phase 4: make the store answer the question it was built for

**Built from what the production rows say, not from a spec.** Phase 3 delivered a label store that is
correct and a corpus that is not yet fit for it. This phase closes that gap.

**There was no Phase 4 before this document.** The delivery phases were 1 (tier 2), 2 (tier 1) and 3
(the label store); `PLAN.md` is Phase 1 and closed, `docs/PLAN-label-store.md` is Phase 3, and Phase 2
was built on a branch with no plan document (Craig, 2026-08-17). Scope chosen by Craig 2026-08-27
from four candidates, on the evidence in the next section.

## Why this phase, and not one of the others

Three facts, all measured against the 1,955 production rows on 2026-08-27. **They have three
different causes, not one** — an earlier draft of this plan claimed one, and the review was right
that the claim shaped the plan badly. They can each fail independently, so they are accepted
independently (see P4-5):

| | |
| :-- | :-- |
| **Bare `blfile` emits ZERO flows** | It refuses all 408 selectable ones for want of a recorded origin. Every capture row is `uri_status: not-recorded` — 25 sightings over 17 distinct captures, all labelled before `--source-uri` existed. **This is the headline requirement, unmet for every row in the store.** |
| **No tier-2 knowledge is selectable** | 24 of 25 runs are tier-1 `replay` runs that never invoked Suricata at all (`tools.suricata` is null in every one). The single `--offline` run attested nothing — 84,958 of 84,960 rules loaded, and §2.4 demands strict equality (#142). |
| **Cross-tier composition has only fixtures behind it** | It follows from the two above. The merge rule LS-7 exists to implement has never once run on real two-tier data (#144). |

The store is not broken. It has never been given data that exercises it.

**Revision 2, 2026-08-27**, after a fresh `eng-reviewer` pass. The destination is unchanged; the
route is not. The review found that the original route — `--both` on all 24 captures — was the
riskiest one available and would not even have exercised the merge rule it was chosen for. Revision 1
is preserved in git history. Findings verified before acting, and one of the two BLOCKING ones was
wrong: see "What the review changed" at the end.

## What makes this phase cheap, and it is worth stating up front

Every prerequisite was verified present before this plan was written, rather than assumed:

- **The captures are already in GCS with `gs://` URIs**, readable by the instance service account —
  so origins cost nothing. No upload, no curation, no capture data moved anywhere new.
- **All 17 captures the store knows are in that bucket**, and **7 more have never been labelled** —
  so the corpus grows from 17 to 24 in the same pass, at no extra step.
- **Suricata's pin is obtainable**, unlike Zeek's: the OISF stable PPA carries
  `1:8.0.6-0ubuntu0`, character-for-character the string `Dockerfile.toolchain` pins.
- **The tier-1 device answers on 443** — which the chosen route no longer depends on, and that
  is the point: it is available for P4-6 rather than load-bearing for the corpus.

## Shape of the work

```
P4-0  pre-flight: digests, snapshot, baseline   ── cheap, and it is what makes P4-4 reversible
   │
P4-1  Suricata 8.0.6 (#142)                     ── blocks every tier-2 result
   │
P4-2  ja4 on the box              ✅ DONE 2026-08-27
   │
P4-3  one --offline gs:// run on a capture the store already knows
   │      └─ the highest-information experiment available: it proves the whole route
   │
P4-4  --offline from gs:// on the 17 known captures, then the 7 new ones
   │
P4-5  reconcile and verify, per symptom
   ·
P4-6  one --both run, OFF the critical path   ── still unproven on this box, still worth proving
```

**The route is `--offline`, not `--both`, and that is the review's most valuable finding.** Spec
§6.4 already anticipated this situation: *"`origin` resolves to the lowest authoritative tier that
actually recorded one … This is not hypothetical: every run in the archive predates `--source-uri`,
so a strict lowest-tier rule would refuse a flow whose origin the store demonstrably holds from a
newer run at the other tier."* So a tier-2-only run from a `gs://` URI:

- **records the origin** — a new `captures` sighting carrying the `gs://` URI, which is all bare
  `blfile` needs;
- **attests tier 2**, making tier-2 knowledge selectable for the first time;
- **leaves the existing tier-1 runs authoritative** — nothing is superseded, so there is nothing to
  roll back and no dependency on the device;
- and gives the cross-tier merge rule its **real** first test: tier 1 from an August replay run and
  tier 2 from a new offline run — *two different runs*, which is what `merge.py`'s rule 2 actually
  implements.

`--both` would have done none of that last part. `src/flabel/cli.py:835` correlates both tiers
*together in one run*, producing one `Label` with a multi-tier `sources[]` — so it arrives as a
single `flow_labels` row, one iteration in `merge.py`, and rule 2 is never taken. A `--both` corpus
would have proven cross-tier *correlation* while leaving cross-tier *merge* exactly as untested as it
is today, at the cost of superseding every tier-1 verdict in the store.

---

## P4-0 — Pre-flight, before anything is run

Cheap, and it is what makes the rest reversible.

**The digest triangle.** `tools/flabel-run:290` short-circuits on `if [ -f "$LOCAL" ]` — a capture
already staged locally is reused **with no digest check**, while `--source-uri` is set from the
`gs://` argument regardless. So a stale local copy would publish an origin the bytes did not come
from, which is the one thing CLAUDE.md's top guardrail forbids. **Measured 2026-08-27 and currently
green:** all 17 captures are byte-identical across bucket, local staging directory, and the
`capture_sha256` the store recorded. Re-check it immediately before P4-4 rather than trusting this
line, and file the missing check against `flabel-run` — it is latent, not benign.

**Pin the ruleset snapshot.** The plan said nothing about this and it decides what the whole new
corpus says. `--ruleset-snapshot` defaults to *newest available*, so a `flabel rules update` between
capture 12 and 13 would split the corpus across two rulesets with nothing recording that it happened.
Decide whether to update first, then **pass the same explicit snapshot id on all runs** and record it
here.

**Build the baseline.** P4-5 rebuilds "a document built before the re-run", and no step created one.
Build it now: `blfile --allow-missing-origin` over the current store, kept with a per-capture label
count. That flag is required — bare `blfile` emits zero flows today, which is the whole problem —
and it cannot be combined with `--rebuild` later, because `--rebuild` reads the value back out of
the document's own `selection`.

**Know the rollback.** It exists and the plan did not name it: `run_exclusions` (§4.5) retracts a run,
and `authoritative_runs` anti-joins it, so a bad run can be withdrawn without deleting anything.
§5.5 warns that exclusions are **not** reproduced by a rebuild and must be backed up separately.

## P4-1 — Suricata 8.0.6 on `fl-replay` (#142)

**The blocker for tier 2.** Until it is fixed, §2.4's strict equality refuses to attest tier 2.

The review argued this step's premise was wrong — that the 2 missing rules were duplicate SIDs, which
no upgrade would fix. **Checked, and it is not so.** Suricata's own log for the 2026-08-24 run says:

```
Info:   detect: 1 rule files processed. 84958 rules successfully loaded, 0 rules failed, 2 …
Notice: requires: 2 rules were skipped because the running Suricata version 7.0.3 is less than 8.0.0
```

`0 rules failed`, and the skip is explicitly a version predicate. The upgrade is the fix.

Route: the **OISF stable PPA**, confirmed 2026-08-27 to serve `1:8.0.6-0ubuntu0` for noble — the exact
string `Dockerfile.toolchain` pins, so this aligns the box with CI rather than merely moving it
forward. **Pin the version in the install**, or a later `apt upgrade` moves the engine underneath the
corpus.

Per #142's scope, put the route in `docs/phase-2-replay-box-provision.sh`, whose line 12 still
installs `suricata` from plain apt — that line *is* the bug.

**Also correct the spec.** `docs/spec-label-store.md` §2.4 describes #142 as "Suricata 7.0.3 refuses
an 8.0 ruleset and loads **none** of it". The measurement says 84,958 of 84,960. The spec sentence is
the justification for §2.4's design, so it should say what actually happens.

**Done when:** the ruleset loads N of N; a tier-2 run attests tier 2 *in the store*; and the
reproducibility tests are **stably** green across three consecutive runs — #142 records them failing
1, 2 or 3 at random under 7.0.3, so one green run proves nothing.

## P4-2 — `ja4` on the box ✅ done 2026-08-27

Installed at the pinned tag `v0.18.8`, which still resolves to the pinned commit
`3ecddb5f…c7b8` — checked, because a moved tag would silently change JA4 values on published labels.
Verified four ways: the commit matches; `zeek --parse-only -e '@load ja4'` exits 0; `zkg list` reports
the pinned version; and `flabel`'s own probe returns `present`. Then verified where it actually
counts — a real production capture produced a real fingerprint in `ssl_json.log`, which is the file
`zeek.py` parses.

The route is recorded in `docs/phase-2-replay-box-provision.sh`, idempotent and re-applying the
shebang fix, rather than left in a shell history.

**Two things to carry forward.** `zeek.py:245` leaves `ja4_package_version` `None` on purpose and
lets `provenance.py` substitute it from `/etc/flabel-toolchain.json` — a file that exists only in the
CI container. So runs from this box will record `ja4_status: present` with **no package version**.
And `zkg list` still fails for the unprivileged run user (it wants write access to its state dir),
which leaves `test_installed_ja4_version_matches_the_pin` skipping locally. Neither affects labelling
— the run path never calls `zkg` — but the second means the pin is unverified on the box.

## P4-3 — One `--offline` run from `gs://`, on a capture the store already knows

The single highest-information experiment available: it proves the entire route end to end.

**Done when,** after ingest: the run attests tier 2; bare `blfile` emits that capture's flows, having
resolved the origin from the new tier-2 sighting; and the composed flow carries **tier-1 entries from
the old August run and tier-2 entries from this one**. That last is the first real exercise of
`merge.py` rule 2 and the thing that closes #144 properly.

**Check attestation in the store, not the run block.** `tiers_attested` is a `runs` *column* computed
by `flabel-ingest` (§4.1); the run block carries only `tiers_attempted` and `tiers_unavailable`. An
earlier draft of this plan told the implementer to grep the run block for a field that is not there.

Record the run's wall-clock, tarball size, and `eve.json` size — they are the only real input to the
cost estimate for the rest.

## P4-4 — The corpus

The 17 known captures first, then the 7 new ones, `--offline` from `gs://` with the pinned snapshot.

**The 7 are not free, which the plan previously assumed.** The count that produced them looked only
at run directories *containing a `labels.json`*, so it structurally could not see failed attempts —
and there are two: `capture_2026-07-21` was attempted twice on 2026-08-20 and failed both times with
`tcpprep` fatal, *"packet capture length 43 too small to process"*. Two things follow. That capture
is known-bad for the **replay** path, and `tcpprep` is tier-1 only — so `--offline` may well succeed
where `replay` failed, which is worth knowing rather than assuming in either direction. Run the 7
**after** the 17 are done and verified, so a surprise among them cannot be confused with a problem in
the part that matters.

**Drive the batch explicitly.** A capture that fails writes no `labels.json`, is never published, and
therefore leaves **no record in the store that it was attempted** — the failure exists only in a local
`run.json`. `flabel-run` exits 5 for published-but-not-indexed, which under `set -e` stops the batch
and without it goes unnoticed. So: capture the exit code per capture, keep going, and print a summary
table. Run it under `nohup` or `systemd-run` — with no TTY, a rule-load shortfall defaults to
continue instead of prompting `[Y/n]` per capture.

**Ingest is not a later step.** `tools/flabel-run` already calls `flabel-ingest` after each successful
publish, ordering archive-then-index. Only runs that exited 5 need re-indexing.

## P4-5 — Reconcile and verify, per symptom

`tools/reconcile_store.py` against the archive, then check the three opening facts **independently**,
because they have independent causes and a partial result is the likely one:

| Symptom | Check | Minimum to call it done |
| :-- | :-- | :-- |
| No origin | bare `blfile` emits flows | every capture that ran successfully |
| Tier 2 unselectable | `authoritative_runs` resolves tier 2 | every capture that ran successfully |
| #144 | a flow whose `sources[]` spans two runs, one per tier | **one** is enough — it is a yes/no |

Then compare against the P4-0 baseline **per capture** and require a written explanation for any
decrease in label count. Finally re-run `blfile --rebuild` over the baseline document to confirm
reproduction survives a corpus change, and re-measure `docs/label-store-provision.md` rather than
editing its numbers.

**Reconcile gets slower.** It downloads and parses *every* tarball in the archive on every run, and a
tier-2 tarball carries an `eve.json` with a flow record per flow, not just alerts. Use P4-3's measured
size to predict it before being surprised by it.

## P4-6 — One `--both` run, off the critical path

Still never run on this box, still worth proving, no longer blocking anything. Do it on the **smallest**
capture, after the corpus is fixed.

## Definition of done for Phase 4

Ordered, because the eng-review is a gate and a gate placed after the merge is not a gate:

1. P4-0's digest triangle re-checked green, the snapshot pinned and recorded, the baseline document
   built, and the `flabel-run` staging-digest gap filed as an issue.
2. #142 closed, the route in the provisioning script with the version pinned, and §2.4's "loads none
   of it" sentence corrected.
3. `--offline` from `gs://` proven end to end on one known capture before the batch.
4. The 17 known captures done and verified; then the 7 new ones, reported separately.
5. All three symptoms checked independently, with the per-capture baseline comparison written down.
6. #144 closed by a flow composed from two runs — not by a single `--both` row.
7. Tests and code, then the sabotage round, then a **fresh `eng-reviewer` pass on the diff**, then act
   on its findings, **then re-cut the diff and review again** — LS-9 needed three rounds and rounds 2
   and 3 each found defects in the previous round's fixes.
8. `docs/status.yaml` current, and the provisioning doc's measurements re-measured rather than edited.

## What this phase deliberately does not do

- **It does not touch #162** — the real project id and service-account email committed in plaintext
  on this public repo. That is a standing guardrail violation and a decision (history rewrite versus
  accepted exposure), and it is not made better by being folded into a data phase.
- **It does not bump `Dockerfile.toolchain`'s Zeek pin.** Decided 2026-08-27: the box stays on 8.2.1.
  The pin still reads `8.0.9-0`, matching neither the box nor any row in the store, so the GHCR digest
  is the real pin — see `docs/RESUME-ls-9.md`.
- **It does not measure a false-positive rate.** Still a PRD non-goal.

## One thing this phase makes real that nobody has decided

`docs/spec-label-store.md` §9 lists, under *"Open, and deliberately not decided here"*: **who may read
the dataset.** Phase 3 added two destinations for non-anonymous network metadata — Zeek's DNS names,
HTTP URIs and TLS server names — and `docs/spec.md` §13's standard is that a new destination is a
decision someone writes down. Nobody has.

This phase takes the store from **one** tier-2 run to **24**, and a tier-2 run's `eve.json` carries a
record per flow rather than only alerts. So it is the moment that open question stops being
theoretical. It does not have to be settled here, but it should be settled or explicitly deferred
**in writing** before P4-4, rather than answered by default.

## What the review changed, and what it got wrong

A fresh `eng-reviewer` pass on revision 1 raised 2 BLOCKING, 6 HIGH, 5 MEDIUM and 5 LOW. Every
finding acted on below was **verified first**, because the reviewer has no shell and no git — the same
discipline that caught a reviewer claiming files were on `main` when they were only local (#171's
review).

**Changed the plan:**

- **The route.** `--offline` from `gs://` instead of `--both` on 24 — reaches all three outcomes,
  destroys nothing, drops the device dependency, and is the *only* one of the two that exercises the
  cross-tier merge rule. Verified against `cli.py:835` and spec §6.4.
- **`tiers_attested` is not in the run block.** Verified: the block carries `tiers_attempted` and
  `tiers_unavailable`. The old acceptance criterion named a field that does not exist.
- **The 7 "free" captures are not free.** Verified: `capture_2026-07-21` failed twice on `tcpprep`.
  The count that missed it only looked at directories containing a `labels.json`.
- **Ingest already happens** inside `flabel-run`, so P4-5 was describing work that P4-4 does.
- **Three causes, not one**, so the symptoms are now accepted independently.
- Added: the ruleset-snapshot pin, the baseline document, the rollback path, the batch driver, the
  data-exposure note, and the digest triangle.

**Wrong, and worth recording so it is not re-raised:**

- **BLOCKING 1 — "the 2 skipped rules are duplicate SIDs, so no Suricata version will fix them."**
  Carefully argued from `suricata.py`, `snapshot.py` and `attest.py`, and refuted by one grep of the
  engine's own log: *"2 rules were skipped because the running Suricata version 7.0.3 is less than
  8.0.0"*, with `0 rules failed`. It is a version predicate. Had this been taken on trust, the phase
  would have grown a code change it does not need.
- **HIGH 4 — "the provisioning script already installs ja4, so the box is out of compliance."** The
  reviewer was reading the ja4 block **added to that file thirty minutes earlier**, in the same
  session, uncommitted. A reviewer reads the working tree, not the state you think it reviewed.
- **BLOCKING 2 — the digest triangle** was a real hazard in the *code* and not a live one in the
  *data*: bucket, local staging and the store's `capture_sha256` are identical for all 17. Kept as a
  pre-flight and an issue rather than a blocker.
