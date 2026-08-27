# PLAN — Phase 4: make the store answer the question it was built for

**Built from what the production rows say, not from a spec.** Phase 3 delivered a label store that is
correct and a corpus that is not yet fit for it. This phase closes that gap.

**There was no Phase 4 before this document.** The delivery phases were 1 (tier 2), 2 (tier 1) and 3
(the label store); `PLAN.md` is Phase 1 and closed, `docs/PLAN-label-store.md` is Phase 3, and Phase 2
was built on a branch with no plan document (Craig, 2026-08-17). Scope chosen by Craig 2026-08-27
from four candidates, on the evidence in the next section.

## Why this phase, and not one of the others

Three facts, all measured against the 1,955 production rows on 2026-08-27, all with one cause:

| | |
| :-- | :-- |
| **Bare `blfile` emits ZERO flows** | It refuses all 408 selectable ones for want of a recorded origin. Every capture row is `uri_status: not-recorded` — 25 sightings over 17 distinct captures, all labelled before `--source-uri` existed. **This is the headline requirement, unmet for every row in the store.** |
| **No tier-2 knowledge is selectable** | 24 of 25 runs are tier-1 `replay` runs that never invoked Suricata at all (`tools.suricata` is null in every one). The single `--offline` run attested nothing — 84,958 of 84,960 rules loaded, and §2.4 demands strict equality (#142). |
| **Cross-tier composition has only fixtures behind it** | It follows from the two above. The merge rule LS-7 exists to implement has never once run on real two-tier data (#144). |

The store is not broken. It has never been given data that exercises it.

## What makes this phase cheap, and it is worth stating up front

Every prerequisite was verified present before this plan was written, rather than assumed:

- **The captures are already in GCS with `gs://` URIs**, readable by the instance service account —
  so origins cost nothing. No upload, no curation, no capture data moved anywhere new.
- **All 17 captures the store knows are in that bucket**, and **7 more have never been labelled** —
  so the corpus grows from 17 to 24 in the same pass, at no extra step.
- **Suricata's pin is obtainable**, unlike Zeek's: the OISF stable PPA carries
  `1:8.0.6-0ubuntu0`, character-for-character the string `Dockerfile.toolchain` pins.
- **The tier-1 device answers on 443**, so `--both` is viable.

## Shape of the work

```
P4-1  Suricata 8.0.6 (#142)   ── blocks every tier-2 result
   │
P4-2  ja4 on the box          ── decide BEFORE the re-run, not after
   │
P4-3  prove --both ONCE       ── it has never run on this box
   │
P4-4  re-label the corpus     ── 24 captures from gs://, --both
   │
P4-5  ingest, reconcile, verify
```

Sequential throughout. P4-2 is a decision that must be taken before P4-4 and could be declined; every
other step blocks the next.

---

## P4-1 — Suricata 8.0.6 on `fl-replay` (#142)

**The blocker.** Until it is fixed, every tier-2 run contributes rows that can never become current,
and §2.4 is what stops them: the engine refuses rules written for 8.0, so the attested set is empty.

Measured 2026-08-27: installed `1:7.0.3-1build3` from `noble/universe`, which is the newest apt can
reach. The route apt *can* reach is the **OISF stable PPA**, confirmed to serve
`1:8.0.6-0ubuntu0` for noble — the exact pinned version, so this aligns the box with CI rather than
merely moving it forward.

Per #142's own scope, **record the route in the provisioning script rather than doing it by hand on
the box.** That is the whole difference between fixing this instance and fixing the gap.

**Done when:** the admitted ruleset loads in full (N of N, not N−2); a tier-2 run attests tier 2; and
Goal 2's reproducibility tests stop being non-deterministic — #142 records them failing 1, 2 or 3 at
random under 7.0.3, so *stably green over three consecutive runs* is the check, not one green run.

## P4-2 — Decide `ja4` before re-labelling, not after

`tools.ja4_status` reads `not-installed` on this box, so every stored `ja4` is **unmeasured, not
absent** — a distinction the run block is careful to record and a consumer cannot recover later.

The re-run replaces the authoritative rows for every capture. Doing it with `ja4` still missing bakes
that gap into the new corpus and makes it the permanent state of the store. `Dockerfile.toolchain`
pins the package by tag *and* commit, so installing it on the box is a bounded change with an exact
target.

**This is a decision, and it belongs to Craig.** Install it and the corpus carries fingerprints;
decline it and the corpus carries a documented hole. Either is defensible; discovering it afterwards
is not.

## P4-3 — Prove `--both` once, on one capture

**`--both` has never run on this box.** Of 48 local run directories: 46 `replay`, 2 `offline`, zero
`--both`. The mode this whole phase depends on is unexercised in production, and Phase 3's clearest
lesson is that a path production never took is where the defect lives (#171).

So: one capture, end to end, examined by hand before committing to 24. Both tiers attested, both
present in `sources[]`, the run block's `tiers_attested` equal to `[1, 2]`, and — the one that
matters — at least one flow carrying entries from *both* tiers, which is the first real input the
merge rule has ever had.

## P4-4 — Re-label the corpus from `gs://`

24 captures through `flabel-run gs://<bucket>/<object>.pcap --both`. The `gs://` argument is what
makes `--source-uri` fire, and `--source-uri` is what records the origin — LS-5 sets it only for a
`gs://` argument, deliberately, because a local path would assert an origin that is false.

**Three things to settle before starting, not during:**

1. **Supersession is the point, and it is still worth stating.** Each re-run replaces prior knowledge
   of the tiers it attests, per capture (§5.1). The 24 existing tier-1 runs stop being current. That
   is the design working, not data loss — the superseded rows survive as a record — but it means
   this is a one-way operation on what the store currently serves.
2. **Goal 2:** the new runs carry a different `tools.suricata` from anything in the store, and a
   `tools.ja4_status` that depends on P4-2. Zeek does **not** change — the box and all 25 existing
   runs are already 8.2.1, which is why 8.0.9 was not pursued (2026-08-27). #142 notes the store keys
   flows on content rather than Zeek's `uid`, so no stored flow fragments.
3. **Cost:** replay runs at `FLABEL_REPLAY_MULTIPLIER=1000` with a 60s settle, over captures up to
   175 MB. Measure one (P4-3) and multiply before scheduling 24, rather than discovering it at
   capture 19.

## P4-5 — Ingest, reconcile, verify

`flabel-ingest` each published tarball, then `tools/reconcile_store.py` against the archive — the
LS-8 machinery, used for the job it was built for.

**Done when all three opening facts have flipped, checked as measurements and not as assertions:**

- **bare `blfile` emits flows** rather than refusing them for want of an origin — the headline
  requirement, met for real rows for the first time;
- **tier 2 is selectable** — `authoritative_runs` resolves tier 2 for the re-labelled captures;
- **cross-tier composition runs on real data** (#144), with a flow whose `sources[]` carries both
  tiers, which is the first non-fixture exercise of the merge rule.

Then update `docs/label-store-provision.md` with the new measurements, and re-run `blfile --rebuild`
over a document built before the re-run to confirm reproduction still holds across a corpus change.

## Definition of done for Phase 4

Ordered, because the eng-review is a gate and a gate placed after the merge is not a gate:

1. #142 closed, with the install route in the provisioning script rather than in a shell history.
2. The ja4 decision taken and written down, whichever way it went.
3. `--both` proven on one capture before 24 were attempted.
4. 24 captures labelled from `gs://`, ingested, and reconciling clean.
5. Bare `blfile` emitting flows; tier 2 selectable; #144 closed by real rows.
6. Tests and code, then the sabotage round, then a **fresh `eng-reviewer` pass on the diff**, then act
   on its findings, **then re-cut the diff and review again** — LS-9 needed three rounds and rounds 2
   and 3 each found defects in the previous round's fixes.
7. `docs/status.yaml` current, and the provisioning doc's measurements re-measured rather than edited.

## What this phase deliberately does not do

- **It does not touch #162** — the real project id and service-account email committed in plaintext
  on this public repo. That is a standing guardrail violation and a decision (history rewrite versus
  accepted exposure), and it is not made better by being folded into a data phase.
- **It does not bump `Dockerfile.toolchain`'s Zeek pin.** Decided 2026-08-27: the box stays on 8.2.1.
  The pin still reads `8.0.9-0`, matching neither the box nor any row in the store, so the GHCR digest
  is the real pin — see `docs/RESUME-ls-9.md`.
- **It does not measure a false-positive rate.** Still a PRD non-goal.
