# Resuming after Phase 4 on `fl-replay`

Written 2026-09-01, on `docs/RESUME-ls-9.md`'s precedent. **Authoritative state is
`docs/status.yaml` — its `next_action` leads with this and its `log:` carries the reasoning.** This
file is the operational half.

## The situation in one paragraph

**Phase 4 is one step from complete and the store now does what it was built for.** Bare `blfile`
emits **880 flows across 24 captures**, every one with a recorded `gs://` origin — it emitted **zero**
on 2026-08-27. Tier 2 is selectable for all 24 captures, and the cross-tier merge rule runs on real
rows. Only **P4-6** remains, and it is deliberately off the critical path.

## Where things stand

| | |
| :-- | :-- |
| `main` | `5d24c3d` — #184 merged |
| Phase 4 | P4-0…P4-5 **done**; **P4-6** outstanding (one `--both` run on the smallest capture) |
| store | 50 runs · 50 sightings over **24 distinct captures** · 2,362 flow_labels · 35 unmatched |
| `blfile` | 880 flows, 24 captures, all `uri_status: gs`; rebuilds at exit 0 |
| box suite | **1 failure** — the decided Zeek 8.2.1-vs-8.0.9 divergence. It was 9 on 2026-08-27 |
| toolchain | Suricata **8.0.6**, Wireshark **4.6.6**, ja4 **v0.18.8** — all pinned *and* `apt-mark hold`ed |
| corpus | described in `docs/corpus-2026-08-28.md` — **read that before using it as ground truth** |

## Read this before touching the corpus

`docs/corpus-2026-08-28.md` exists because three reviews said the numbers alone would let a consumer
over-trust it. The four things that matter most:

1. **Split by capture, never by flow.** One capture is **41%** of the corpus; the top three are 58%.
   A random flow-level split measures memorisation.
2. **52% of the flows are port 22.** Top four ports: 69%. No flow carries TLS enrichment. This is not
   a general malicious-traffic corpus.
3. **177 of 880 flows (20%) carry only `indicator-reference` sources** — the flow to your own
   resolver or proxy, not the malicious activity.
4. **Licence obligations ride on the labels**: 462 entries CC-BY-SA-4.0 (share-alike), 408
   `proprietary:vendor-signature (not redistributed)`. `blfile` writes **no `NOTICE`**.

## What the review process cost, and it is the most transferable thing here

`CLAUDE.md` already says re-cut and re-review after acting on findings. Phase 4 is the evidence for
why, and it went further than LS-9's three rounds: **Craig asked "has this had a fresh-eyes review?"
three times, and all three times the honest answer was no.** Each time the gap had the same shape —
a review ran, produced substantial new content, and *that content* shipped unreviewed.

The sharper lesson is what rounds 2 and 3 found. **They repeatedly found the code sound and my
justifications false.** In one change: a fabricated measurement pasted into a block captioned "one
real X"; "`build` already refuses elsewhere" (it does not); "`coverage` gains fields as loss
conditions are added" (it does not); "a digest so the next added field cannot repeat this" (it
covered a strict subset). Each was a confident sentence that one command contradicted.

**So: when you write a justifying sentence, run the thing that would falsify it.** That is cheaper
than a review round and it is what the reviews kept doing on my behalf.

Two more, both cheap to internalise:

- **A sabotage that does not do what you think is worse than none.** Two of mine went wrong mid-round
  — one edited `SourceSpec` instead of `SourceEntry`, one produced a pytest *collection error* rather
  than a failure. Both returned green, and green meant nothing.
- **Verify the reviewer.** One invented four loss-condition field names that do not exist; another's
  SQL measured a different set from the one it claimed. Both were still worth their round.

## Things that will bite if you do not know them

- **`--offline` from `gs://` is the route, and `--both` is not.** A tier-2-only run records the
  origin, attests tier 2, and **supersedes nothing** — the arithmetic held on production: 400 tier-1
  only + 8 both = 408, exactly the pre-phase baseline. `--both` would have replaced all 408 with
  re-observed device results *and* still not exercised cross-run merge, because one `--both` run
  correlates both tiers into a single row.
- **`tcpprep` is tier-1 only.** `capture_2026-07-21` failed the replay path twice and labelled
  cleanly offline. A capture that is bad for replay is not a bad capture.
- **`flabel-run` refuses to start without `/var/lib/flabel/.provisioned`** (exit 2). The provisioning
  script writes it last, after every tool-pin assertion.
- **`flabel-deploy`'s busy guard fires on any process whose command line mentions flabel** (#181),
  including your own shell. It will refuse on an idle box.
- **Documents written before #184 cannot be rebuilt** — `schema_version` moved to `1.1`. They are
  still readable; only reproduction is refused, and the message says so.

## Do this first

1. **P4-6** — one `--both` run on the smallest capture, off the critical path. Then Phase 4 is done.
2. **#183** — the scheduled false-positive review failed on 2026-08-30 and **nobody has looked**.
   That job is Goal 5's real FP control, and `ci.yml` refuses a push if it goes dark seven days.
3. **PRD Q11, unrecorded**: are these 24 captures publicly-published, or internal/customer traffic?
   The PRD restricts flabel to the former and calls the latter a gate. The licence findings make this
   sharper, and nobody has written the answer down.

## Still open and unowned

- **#162** — real project id and SA email in plaintext on this public repo. A standing `CLAUDE.md`
  guardrail violation, and a decision (history rewrite vs accepted exposure) rather than a patch.
- **#185** an authoritative run with a NULL `run_block` is dropped from the pin (latent: 0 of 50).
  **#179** `flabel-run` reuses a staged capture without checking its digest while still asserting the
  `gs://` origin (latent: triangle green). **#181** the busy guard. **#161**, **#164**, **#159**.
- **#103** — Goal 5's sensitivity half is still unmet; the malicious canary is unsourced.
- **#153** stays open on `collection_id` alone, deferred.
- **The Zeek pin.** `Dockerfile.toolchain` still says `8.0.9-0`, which matches neither the box nor any
  row in the store and cannot be rebuilt from apt. The GHCR digest is the real pin. Bumping to 8.2.x
  is the rebuildable fix — Craig's call, recorded 2026-08-27.
