# Specification — the label store and `blfile`

Phase 3. A sibling of `docs/spec.md`, not a section of it: what this specifies lives in a **separate
package** (`src/flabeldb/`), because flabel itself has `dependencies = []` and
`tests/test_architecture.py` keeps a closed list of network-capable modules. A BigQuery client is
both a dependency and network I/O.

`docs/spec.md` remains the authority for everything flabel emits. This document is the authority for
what happens to it afterwards. Where the two must agree, this document says so and names the section.

Decisions are Craig's and are recorded in `docs/status.yaml`. The narrative design and its
measurements are `inline-labeling/label-store-design.html`.

**Revision 2, 2026-08-20.** Revision 1 was reviewed by a fresh agent and four of its claims about
BigQuery were then executed against the live service. Three were wrong. §10 records what was
measured, and the corrections are load-bearing rather than cosmetic: the cross-tier merge has moved
out of SQL, the idempotency guard has been redesigned, and one invariant turned out to be incapable
of ever firing. Revision 1's reasoning is preserved where it still holds and named where it does not.

---

## 1. Vocabulary

Extends `docs/spec.md` §1 rather than restating it. `flow`, `detection`, `label`, `source entry`,
`tier`, `snapshot` and `run` keep their meanings from there.

| Term | Meaning |
| :-- | :-- |
| **capture** | A pcap identified by `run.input.sha256`. Its filename and `gs://` URI are *attributes*, not identity — one capture may be seen at several paths, and two files sharing a name may hold different bytes. |
| **sighting** | One observation of a capture at a path, by one run. Append-only; a capture accumulates sightings. |
| **flow key** | The content-derived identity of a flow within a capture (§3.2). Not Zeek's `uid`. |
| **run id** | The content-derived identity of a run (§3.3). |
| **attested tier** | A tier this run can be *shown* to have actually performed, by evidence in the run block rather than by absence of a failure flag (§2.4). Only an attested tier supersedes. |
| **tier slice** | Everything one run asserted about one flow at one tier. The unit of supersession — computed in `blfile`, not stored (§5). |
| **authoritative run** | For a given (capture, tier), the newest non-excluded run that attested that tier. |
| **collection** | A `labels-collection` document — labels for many flows, from many captures and many runs. Distinct from a `labels.json`, which is one run over one capture. |
| **the archive** | `gs://pm-proto-496816-flabel-pcaps/results/`. The system of record. |
| **the store** | The BigQuery dataset `flabel` in `us-central1`. A **derived index** over the archive. |

**"the store is derived" is load-bearing, but narrower than revision 1 claimed.** A rebuild rescues
you from a *code* bug — a wrong projection, a wrong merge — because every identity in §3 is
content-derived. It does **not** rescue you from a bad run in the archive, because a deterministic
rebuild over the same archive reproduces the same bad state. That is what §4.5 exists for.

---

## 2. Constraints and invariants

1. **Nothing in `src/flabel/` may import `flabeldb`, and nothing in `src/flabel/` may import a
   Google client library.** Enforced statically by `tests/test_architecture.py`, extended for this
   phase — see §6.6 for why the obvious form of that check cannot fire.
2. **The store is append-only in normal operation.** Two exceptions, both explicit and both on the
   failure path: clearing the orphan rows of an incomplete ingest before retrying it (§5.3), and
   `TRUNCATE` before a full rebuild (§5.5). Nothing else updates or deletes.
3. **A run is visible only when its `runs` row exists.** A multi-table load is not atomic, so the
   `runs` row is the commit marker and every read joins through it.
4. **Only an *attested* tier supersedes** (§2.4 below).
5. **A failed run is never ingested** (Craig). `run.json` on the box is where a failure is diagnosed.
   §9 names the consequence.
6. **Identity is derived from content, never from a name or a tool's internal counter.** §3.
7. **The identity `flabeldb` authenticates as is named, never discovered.** §7.1.
8. **The merge rule has exactly one implementation, in Python** (§5).

### 2.4 Attested delivery, and why `tiers_unavailable` cannot carry it

Revision 1 said "only a *delivered* tier supersedes", where delivered meant
`tier ∈ tiers_attempted and tier ∉ tiers_unavailable`. **That invariant could never fire, and the
hazard it was written to prevent walks straight past it.**

The chain, every link from `docs/spec.md`:

1. A failed run is never ingested (§2.5).
2. `docs/spec.md` §10: *"`tiers_unavailable` is therefore empty on every successful run, in all three
   modes... the path that populates it is the failure path."*
3. Therefore every row in `runs` would have `tiers_delivered == tiers_attempted`. The concept is
   inert in production and testable only against a hand-forged row.

And the disclosed hazard — #142, where `fl-replay`'s Suricata 7.0.3 could not load the whole of an
8.0 ruleset — exits 0, writes `labels.json`, publishes, and reports `tiers_unavailable: []`.
(**Corrected 2026-08-27**: this said the engine "loads **none** of it". It was worse than that as an
argument and milder as a fact — measured, 7.0.3 loaded 84,958 of 84,960 and skipped 2 marked
`requires: version >= 8.0.0`. A shortfall of two rules out of eighty-five thousand is a *better*
justification for attesting on strict equality than a total refusal would be, because it is the case
a threshold would have waved through. Fixed by the 8.0.6 upgrade, which loads 84,960 of 84,960.) Under
revision 1 it *delivered* tier 2 and superseded good knowledge with a result that was two rules
short and looked complete — which is the more dangerous shape, not the milder one. "Tier-2
ingestion is gated on #142" was a sentence, not a gate.

So delivery must be **attested from positive evidence**:

| Tier | Attested when |
| :-: | :-- |
| 2 | `counts.rules_loaded == ruleset.total_admitted`, and both are non-null and non-zero. |
| 1 | `mode ∈ {replay, both}` and the run block records tier-1 detections were retrieved without a `panw` tool failure. |

An unattested tier is **loaded but does not supersede**: its rows exist, and `blfile` will not select
them as authoritative. That is the difference between "we have no record" and "we have a record we
will not treat as current", and §9's non-behaviours keep both readable.

`flabel-ingest` computes attestation and writes it to `runs.tiers_attested`. It is derived at ingest
rather than at read time so that the *reason* a tier was refused can be recorded beside it.

### Testing line

Same shape as `docs/spec.md` §2's, one layer out, but with an honest limit revision 1 did not state.

**BigQuery is real in the tests that touch BigQuery**, marked `requires_bigquery`, run against the
`flabel_scratch` dataset. A mocked client would encode our assumptions about the service, and §10
records four such assumptions that were wrong.

**Those tests do not run in CI, and that is a decision, not an oversight** (Craig, 2026-08-20).
`.github/workflows/ci.yml` has no GCP credential; the metadata server does not exist in GitHub
Actions; and this is a public repo, so no key may be committed. Workload Identity Federation would
solve it and was declined as out of scope for now. Consequently:

- `flabel-db verify` runs as a **pre-deploy gate in `tools/flabel-deploy`**, against the live
  dataset, not in CI. §7.4.
- Phase 3's definition of done says so rather than claiming a CI gate that cannot exist.
- **The majority of the suite is pure and does run in CI**: `flow_key`, `run_id`, attestation, the
  merge (§5 — now Python, so it is ordinary unit-testable code), canonical ordering and document
  assembly.

That last point is the main practical dividend of moving the merge out of SQL: the logic that decides
what a label *is* became testable in the place tests actually run.

---

## 3. Identity

### 3.1 Capture

`capture_sha256` = `run.input.sha256`, unchanged from `docs/spec.md` §10.

Known and accepted: that digest covers the input **as handed over**, so `foo.pcap` and `foo.pcap.gz`
of the same packets are two captures and will not merge.

### 3.2 Flow

**Zeek's `uid` must not appear in any key.** Measured 2026-08-20 on Zeek 8.0.4: under `-D` — which
`docs/spec.md` §2.3 makes mandatory — uids are a fixed sequence assigned in connection-creation
order, so the Nth connection of *any* capture gets the Nth value. The 24-hour internet capture in
`inline-labeling/sample-run/`, a synthetic two-flow lab pcap and one benign-corpus fixture alone all
report `CJKFoj4bpHEhTeaRoj` as flow #1. And the same flow `10.92.95.2:49161 → 10.92.67.138:80`
carried `CRdT6w4PA64qWKmBk3` when second in a file and `CJKFoj4bpHEhTeaRoj` when first, with
`ts_first` `1693125635.672335` both times.

So `uid` collides across captures *and* is unstable for a given flow. It is a per-run observation.

```python
def flow_key(capture_sha256: str, flow: FlowRecord) -> str:
    """Identity of a flow within a capture. Derived from content; never reads flow.uid.

    `ts_first` is the ISO-8601 string as it appears in labels.json, NOT a float. A
    float -> ISO -> float -> ISO round trip is where a one-microsecond drift would
    silently produce two keys for one flow, and ingest reads the serialised archive.
    """
    lo, hi = sorted(
        (
            (ip_address(flow.src_ip).packed, flow.src_port),
            (ip_address(flow.dst_ip).packed, flow.dst_port),
        )
    )
    material = "|".join(
        (
            capture_sha256,
            flow.proto.lower(),
            str(flow.ip_proto),  # see "the ESP/SCTP collision" below
            _endpoint(lo),
            _endpoint(hi),
            flow.ts_first_iso,  # a str, straight from the document
        )
    )
    return sha256(material.encode()).hexdigest()[:16]
```

**The endpoint pair is canonically ordered, and the orientation Zeek reported is stored beside it.**
Ordering the pair means an orientation disagreement cannot split one flow into two rows.
`docs/spec.md` §9 already declines to require Zeek and Suricata to agree on who initiated a
connection; this declines to require two *Zeek versions* to.

**The ESP/SCTP collision, and why `ip_proto` is in the key.** `docs/spec.md` §9 step 0 measured it:
two ESP or SCTP conversations between one host pair are written with **identical 5-tuples**
(`10.0.0.5 0 10.0.0.200 0 unknown_transport`, different `uid`s), and Zeek records the difference only
in `conn.log`'s `ip_proto` column — 50 for ESP, 132 for SCTP — which `Flow` does not carry. Without
`ip_proto` the key degenerates to `(capture, "unknown_transport", ip:0, ip:0, ts_first)` and two real
flows can produce one key, whose labels and sources would then be unioned into a flow that never
existed. Carrying `ip_proto` in `Flow` is issue **#96**; until it lands, **`flabel-ingest` refuses to
write a `flow_labels` row for a flow whose proto is not `tcp`, `udp` or `icmp`**, counts the refusals,
and records them on the run. Refusing is not a loss of labels: such detections are already
`unsupported_transport` unmatched detections and never became labels in the first place.

**ICMP has no ports.** Zeek puts ICMP type in `id.orig_p` and code in `id.resp_p`, so the canonical
sort orders on type/code. Deterministic, so identity holds — but `port_lo`/`port_hi` are *not* ports
for ICMP rows and no consumer should read them as such.

**Sixteen hex characters**, matching the `snapshot_id` convention, so the existing
`fullmatch(r"[0-9a-f]{16}")` guard applies. Collisions matter only within one capture, which bounds
the birthday exposure at a few thousand flows against a 64-bit space; stated rather than left implicit.

**`ts_last` is stored but is not part of the key.** Issue #60: it is computed from a rounded duration
and can exclude a detection on the last packet. Keying on it would inherit that; storing it does not,
but a consumer filtering on the window does.

### 3.3 Run

```python
run_id = sha256(f"{capture_sha256}|{mode}|{started_at_iso}|{flabel_version}".encode()).hexdigest()[
    :16
]
```

Derived from the run block alone, so re-reading the same tarball computes the same id.

Two honest limits. **`flabel_version` contributes nothing today** — it is `"0.0.0"` and nobody bumps
it — so uniqueness rests on `(capture, mode, started_at)` with a microsecond timestamp. And that
holds only because there is **one runner** (Craig): a second concurrent runner would need the host in
the material. Both are dependencies, recorded rather than assumed.

---

## 4. Schema

Dataset `flabel`, **location `us-central1`** — pinned, and not incidental. The results bucket is a
`US-CENTRAL1` *regional* bucket, a load job needs a compatible dataset location, and BigQuery job ids
are namespaced `project:location.jobid` (§10 M2), so location is part of the idempotency namespace
too. Revision 1 never stated it.

Tables are declared in `src/flabeldb/schema.py` as client schema objects — the form the load jobs need
anyway, so there is no second copy in a `.sql` file.

### 4.1 `runs`

| Column | Type | Notes |
| :-- | :-- | :-- |
| `run_id` | STRING | §3.3 |
| `capture_sha256` | STRING | |
| `mode` | STRING | `replay` \| `offline` \| `both` |
| `tiers_attempted` | ARRAY&lt;INT64&gt; | |
| `tiers_attested` | ARRAY&lt;INT64&gt; | §2.4. May be **narrower** than attempted. |
| `attestation_notes` | ARRAY&lt;STRING&gt; | why a tier was refused, one string per refusal |
| `started_at`, `finished_at` | TIMESTAMP | |
| `flabel_version` | STRING | |
| `snapshot_id` | STRING | null on a `replay` run, per `docs/spec.md` §10 |
| `archive_uri` | STRING | the tarball this was read from |
| `run_block` | **STRING** | the run block's canonical JSON bytes, verbatim |
| `ingested_at` | TIMESTAMP | the **client's** clock, set by `flabel-ingest` |

`PARTITION BY DATE(finished_at)`, `CLUSTER BY capture_sha256, mode`.

**`run_block` is `STRING`, not `JSON`** — revision 1 had `JSON` and called it "verbatim", which those
two cannot both be. BigQuery's `JSON` type normalises on ingest: it sorts keys, drops duplicates and
normalises numeric literals, so `duration_seconds: 12.30` returns as `12.3`. §6.4 embeds the run block
verbatim into a collection, so a normalising column would make a rebuilt document differ from the
archive. Stored as the canonical bytes; parsed on read by whoever needs fields.

**`ingested_at` is a wall clock and is not reproduced by a rebuild.** After `TRUNCATE` + backfill
every value is new. It is therefore excluded from any reproducibility claim, and it is why Phase 3b's
`--as-of` is scoped as an audit tool rather than a reproduction one.

### 4.2 `captures`

One row per sighting: `capture_sha256`, `uri`, `uri_status`, `filename`, `bytes`, `format`,
`link_type`, `snaplens`, `observed_by_run_id`, `observed_at`. `CLUSTER BY capture_sha256`.

**`snaplens` is plural**, following LS-1: a `mergecap` pcapng's interfaces need not agree on
snapshot length, so a scalar would invent a winner and erase the disagreement — which is the fact
the field exists to expose. This column list said `snaplen` until LS-3; the drift was introduced by
LS-1 changing the field and not this table.

**`uri_status` exists because a null `uri` would otherwise mean two different things** — the failure
`docs/spec.md` §10 is emphatic about (`null` is "not measured", `[]` is "measured as none"). Revision
1 justified the null by citing §2.5 and misread it. Three values:

| `uri_status` | Means |
| :-- | :-- |
| `gs` | staged from GCS; `uri` is populated |
| `local` | the operator passed a local path; there is no origin URI to record |
| `not-recorded` | this run predates `--source-uri` — **every run currently in the archive** — *or* the run died before ingest returned, so `uri_status` is `null` in the block |

**A dead run publishes `uri_status: null`, and that maps to `not-recorded`.** flabel writes `gs` or
`local`; a run that died before ingest returned publishes the whole `input` section as nulls,
following `path`. Revision 2 of this document typed the field `"gs" | "local"` and enumerated three
values, which left that fourth state — produced by code this plan itself mandated — with no mapping,
so `flabel-ingest` would have had to guess. Folded into `not-recorded` rather than given a value of
its own: from the store's point of view "no origin was recorded" is the same fact however it came
about, and the run block is still there to say which.

### 4.3 `flow_labels`

**One row per (run, flow), holding the `Label` exactly as `labels.json` emits it.** Revision 1 split
this per tier so that supersession could be a row filter in SQL; §5 no longer merges in SQL, so the
split has no purpose and cost three separate defects (§10). No decomposition, no re-merge, nothing to
prove lossless.

```
run_id, capture_sha256, flow_key,

flow      STRUCT<proto, ip_proto, ip_lo, port_lo, ip_hi, port_hi,
                 src_ip, src_port, dst_ip, dst_port,
                 ts_first, ts_last, zeek_uid, ja4, ja4s, server_name>

best_tier INT64
labels    ARRAY<STRUCT<name STRING, value ARRAY<STRING>, tier INT64, sids ARRAY<INT64>>>
sources   ARRAY<STRUCT<tier, source, sid, rev, ruleset, admission_basis,
                       licence, classtype, label_basis, threat, direction>>
```

`CLUSTER BY capture_sha256, flow_key`. **No partition** — revision 1 had
`PARTITION BY DATE(flow.ts_first)`, which BigQuery rejects at `CREATE TABLE`: *"The field specified
for partitioning can only be a top-level field"* (§10 M3). It is not merely re-expressible: nothing
queries on flow time, so the partition bought nothing while requiring the schema to be contorted
around it. Clustering is what serves the access pattern.

**`zeek_uid` is stored and must never be joined on.** It is how an operator finds the flow in that
run's `conn.log`, which is a real use. §3.2 is why it is nothing more.

### 4.4 `unmatched`

One row per (run, detection): `run_id`, `capture_sha256`, `tier`, `source`, `sid`, `rev`, `threat`,
`ts`, `proto`, endpoints, `direction`, `reason`. `PARTITION BY DATE(ts)`,
`CLUSTER BY capture_sha256, reason`.

Stored because `docs/spec.md` §13 ends on exactly this: *a consumer must never read an empty
`labels[]` as "nothing malicious was found"*, and `unmatched_detections[]` is the evidence.

### 4.5 `run_exclusions`

`run_id`, `reason`, `excluded_at`, `excluded_by`. Append-only.

**Retraction has to exist, and it cannot be a delete.** Revision 1 had no way to un-do anything, which
matters because supersession is decided by **wall clock, not ruleset recency**: `docs/spec.md` §12
lets an operator pin `--ruleset-snapshot` to an old snapshot, and that run finishes *later* and would
become authoritative — inverting the very argument (§5.1) that justified supersession. A rebuild does
not help, because the archive still contains the run.

So a run can be excluded by adding a row here, which `blfile` and `authoritative_runs` anti-join. The
exclusion is a **record** rather than a deletion, which keeps §2.2 intact and keeps the reason
auditable. It also covers the cases nobody wants to think about: a capture that must come out for
legal or customer-data reasons, and a run later found to be mislabelled.

Whether tier-2 supersession *should* order on snapshot recency rather than `finished_at` is left open
in §9 rather than silently decided.

### 4.6 `authoritative_runs` — the only view

```sql
CREATE OR REPLACE VIEW flabel.authoritative_runs AS
SELECT capture_sha256, tier, run_id FROM (
  SELECT r.capture_sha256, tier, r.run_id,
         ROW_NUMBER() OVER (PARTITION BY r.capture_sha256, tier
                            ORDER BY r.finished_at DESC, r.run_id DESC) AS recency
  FROM flabel.runs r, UNNEST(r.tiers_attested) AS tier
  WHERE NOT EXISTS (SELECT 1 FROM flabel.run_exclusions x WHERE x.run_id = r.run_id)
) WHERE recency = 1;
```

**`run_id` in the sort key is required, not cosmetic.** `finished_at` alone is not a total order, and
on a box that replays a whole capture in seconds two runs finishing in the same second is the
*ordinary* case. This is #138's correction applied to a second comparator.

**There is no `current_labels` view.** Revision 1 had one, specified in a single prose sentence, and it
was the hardest artifact in the phase — see §5 and §10 for why it is gone.

---

## 5. Merge semantics

### 5.1 The rule

**The newest non-excluded run that attested tier T supplies tier T for that capture. Tiers compose;
they do not overwrite each other.**

Chosen over pure accumulation because upstream feeds retract: 1,469 ET sids were removed in two days.
Accumulation keeps a label no current run asserts, inside a dataset whose purpose is ground truth.
Chosen over whole-capture latest-wins because bare `flabel` is tier 1 only and `--offline` is tier 2
only (`docs/spec.md` §12), so latest-wins would make a replay run delete every Suricata label.

### 5.2 It is implemented once, in Python

`blfile` reads the raw per-run rows for the authoritative runs and composes them using
**`models.Label` and `models.verdict_entry`** — the same constructors, with the same
`__post_init__` invariants, that produced the rows in the first place.

Revision 1 did this in SQL, and the review's central architectural finding was that this creates two
implementations of the one rule the store exists to express — the duplicate-authority defect this repo
keeps catching (`build_source_entry`, `manifest.sources`, `LABEL_KINDS`). It was worse than the usual
case: a divergence would surface only on `--rebuild`, the command whose whole promise is that it does
not diverge. And it doubled logic that has **never met real data** — both measured captures put
exactly one source on every labelled flow, 432/432 and 367/367 (#144).

Composition, per flow:

1. Take each authoritative run's row for that `flow_key`.
2. Keep only the `sources` entries whose `tier` that run is authoritative *for*. A `--both` run
   authoritative for tier 1 only contributes its tier-1 entries.
3. `sources` = the union, ordered by `docs/spec.md` §10's existing key.
4. `labels` = per name, the entry from the lowest surviving tier, with `sids` unioned.
5. `best_tier = min(tier)` — recomputed, which is what `Label.__post_init__` already asserts.

**What is deliberately given up:** merged labels cannot be queried from the BigQuery console, only
raw per-run rows. Accepted (Craig) — at a few hundred labels per capture, pulling rows and composing
in Python is not a scale problem, and `blfile` is how anyone will actually read this.

**Three latent losses, recorded now because they are cheap to design for and expensive to retrofit.**
Rule 4 discards the higher tier's value when two tiers disagree on a single-arity label — today
`verdict` is always `"malicious"` so nothing is lost, but the rule as stated would hide a genuine
disagreement. `blfile` therefore treats a cross-tier value conflict as a **hard failure**, not a
silent pick. And a label whose `LabelEntry.tier` names one tier lives in that tier's slice only, so
superseding that tier removes the label even if another tier's sources would support it.

**The third is in the `multi` arity, and lands with the kind this section says is next.** Rule 4
takes the *value* from the lowest surviving tier's entry while unioning `sids` across all of them,
so a merged MITRE-technique entry would cite a tier-2 sid beside a value list that tier-2 source
never asserted — untraceable in exactly the way `LabelEntry`'s own docstring forbids. The
single-arity conflict guard cannot see it, because differing `multi` values are not a conflict
under rule 4 as written. Nothing is at risk today: every kind in `LABEL_KINDS` is `single`. Whoever
adds the first `multi` kind must decide whether its `sids` narrow to the tier the value came from,
or the value becomes the union — and rule 4 must then say which.

**A cross-run disagreement about `verdict` is the same failure and is guarded the same way, but it
is not a cross-*tier* check.** `models.verdict_entry` hardcodes `value="malicious"`, so `blfile`
rebuilding the verdict from the surviving sources is a write rather than a read: a stored verdict
carrying any other value would be silently rewritten and published as ground truth. `blfile`
therefore compares the rebuilt verdict against **every contributing run's** stored entry and fails
on any mismatch. The verdict is deliberately **not** tier-filtered on the way in, because
`LabelEntry.tier` on a verdict is a derived `min(sources.tier)` rather than a claim of tier
membership — a `--both` run stores its verdict at tier 1 even when the tier it still supplies is 2,
and filtering on that number left the run shape rule 2 exists for with no comparison at all.

### 5.3 Commit ordering, and the recovery that actually works

`flow_labels`, `unmatched` and `captures` load first; the `runs` row lands **last**, and every read
joins through it. A crash mid-ingest leaves rows nothing can reach.

**Revision 1 then said "re-running the same ingest completes it", and that was false.** Measured
(§10 M1): a BigQuery load job that *fails* still consumes its job id permanently, so a job id derived
only from `(run_id, table)` is burnt by the first transient failure and the run can never be ingested
again. Combined with the ordering, a half-loaded run was unrecoverable except by full rebuild.

The retry path, verified working:

1. **Is this run already committed?** `SELECT 1 FROM runs WHERE run_id = @id`. If yes, stop — this is
   the primary idempotency guard (§7.3).
2. Otherwise the run is new *or* half-loaded, and those are indistinguishable and need the same
   treatment: `DELETE FROM <each table> WHERE run_id = @id`, clearing any orphans. Bounded, targeted,
   and by definition invisible rows — §2.2's stated exception.
3. Load **every** table with `jobId = ingest-<run_id>-<table>-<attempt>`, where `attempt` is the
   first id that is **unused** — walking upward from 1 until `Not found`. A job that already
   exists is used, whether it succeeded or failed.

**Revision 3 corrects step 3, and step 2 is why** (measured 2026-08-24 against `flabel_scratch`).
Revision 2 read: *"a job that exists and succeeded means this table is done; one that exists and
failed means increment and retry."* The first half is incompatible with step 2. Step 2 has just
deleted that table's rows — unconditionally, because a new run and a half-loaded run are
indistinguishable — so after it runs, "done" is false.

Driven against the live service, that combination produced a run whose `flow_labels` table ended
with **zero rows**: cleared by step 2, skipped by step 3 as already done, and then the `runs` commit
marker landed on top of the emptiness. Which is precisely the failure the ordering exists to
prevent, reached from the other direction — a visible run pointing at rows that are not there.

The root cause is §10 M1 generalised. **A job id is permanent, so "this id succeeded once" says
nothing about whether its rows are there now.** Once step 2 has cleared them, the only question the
walk can answer is which id is free — which is what step 3 now asks.

A consequence worth stating for anyone writing tests here: because job ids never expire, a test that
asserts on attempt *numbers* cannot reuse a `run_id` between sessions. The second run finds the
first run's attempts already used and the walk correctly answers something different.

### 5.5 Rebuild

`TRUNCATE` the dataset and `flabel-ingest --backfill`. Deterministic for every content-derived
identity in §3. What it does **not** reproduce: `ingested_at`, `observed_at`, and `run_exclusions` —
which is precisely why exclusions are data rather than deletions, and why they must be backed up
separately from the archive.

---

## 6. Interfaces

### 6.1 Additive fields in `run.input`

None bumps `schema_version`: additive, and a 2.0 reader that ignores them reads the document
correctly — the precedent #115 set for `direction`.

| Field | Type | Why |
| :-- | :-- | :-- |
| `uri` | `str \| null` | The origin the capture was staged from. **Without it the requirement cannot be met at all**: `tools/flabel-run:211-220` stages a `gs://` object and then assigns `TARGET="$LOCAL"`, so `run.input.path` records the staged local path and the bucket URI is discarded with the shell variable. |
| `uri_status` | `"gs" \| "local" \| null` | So a null `uri` is not two facts in one field (§4.2). flabel writes `gs` or `local`; only `flabel-ingest` writes `not-recorded`, for a run whose block has no such key. |
| `link_type` | `int \| null` | The link type **retained**. Already determined internally to decide what to discard, but only `discarded_link_types` is published. §8 needs the kept one. |
| `snaplens` | `[int] \| null` | Every **distinct** snapshot length of the retained interfaces, ascending. Plural, and that is the correction: a first version published `snaplen: int` as the largest where interfaces disagreed, which asserted a coverage the file did not have and erased the disagreement — the one fact the field exists to expose, since Zeek refuses a merge across differing snapshot lengths. A `mergecap` pcapng carries one interface description block per input file and nothing makes them agree (measured: 96 and 65535). `link_type` stays singular because after normalisation a pcap can hold only one. |

`--source-uri` is **validated, not merely recorded**: a value that is not a well-formed `gs://` URI
exits 2 before any tool runs. flabel does **not** verify the URI holds the bytes it hashed — that
would be network I/O on a path forbidden from it — so the field records what the operator asserted,
and `sha256` remains the identity.

**`input.uri` must be added to `canonical.EXCLUDED_INPUT_KEYS`, beside `path`.** That list exists
because the same capture labelled from two directories must not fail Goal 2's reproducibility gate;
a URI is the same category of field — the same capture staged from two origins is the same capture.
This is a spec decision, not an implementation detail, which is why it is here.

`docs/spec.md` §12 must document `--source-uri`, and §11 declares the CLI contract closed — so adding
a flag needs its reasoning recorded there, as #132's did.

### 6.2 `models.LABEL_KINDS`

Carries arity and permitted tiers:

```python
LABEL_KINDS: Mapping[str, LabelKind] = {
    "verdict": LabelKind(arity="single", tiers=(1, 2)),
    "threat-name": LabelKind(arity="single", tiers=(1,)),
}
```

**It does not replace the `Literal`; it joins it.** `LabelEntry.name: LabelName` uses `Literal` as a
*type annotation* and `_check` reads `get_args(LabelName)` — static typing cannot come from a
`Mapping`. Revision 1 said "replaces", which would have been a rewrite of the type system. Both exist,
and a test asserts `get_args(LabelName) == tuple(LABEL_KINDS)`; without it, this section's own
justification creates the two-copies hazard it invokes.

`arity` and `tiers` must be **enforced**, not merely declared — a declared-but-unchecked field is the
drift this section exists to prevent. **Both checks live in `LabelEntry.__post_init__`.** This
sentence previously put the tier check in `Label.__post_init__`; the code is right and the sentence
was wrong. A kind's permitted tiers are a property of the entry alone — name and tier, no flow
context — so construction is the earliest point it can be refused, where `Label` would let an
impossible entry exist first. Amended to match what was built rather than the code bent to match
prose, and the choice is not free: enforcing at construction made four existing tests unable to
build a tier-2 `threat-name`, one of which had been passing on the wrong guard.

**A `multi` value must be a sorted, unique `tuple` of non-empty strings.** A first implementation
checked only "not a `str`, and every item is a `str`", which admitted a list (mutable provenance,
against `models`' own rule), a set and a generator (both fail inside `labels.py` *after* the
pipeline has succeeded), an empty item, and unsorted or duplicated values. `sids` is required sorted
for the same reason — the tuple reaches the file directly, and canonical output means the same data
serialises the same way however it was assembled (spec §10). A kind whose order is *meaningful*
would need that declared on `LabelKind`; none is, so the field is not invented yet.

**`correlate` reads the table rather than repeating it.** `_label_entries` filtered
`entry.tier == 1`, putting the tier-1-only rule in two places whose disagreement was asymmetric:
widening the table alone did nothing, while widening `correlate` alone made `LabelEntry` raise and
took the run to exit 1 on a capture that had produced labels the day before. It now reads
`LABEL_KINDS["threat-name"].tiers`, so spec §4's claim that extending to tier 2 is "purely additive"
is true rather than aspirational.

**`KNOWN_TIERS` lives in `models`**, for the reason `DEFAULT_THRESHOLD` does: that module imports
nothing from the package, so it is the one place every other module can share a definition through.
Which tiers exist was previously written in four unlinked places.

### 6.3 CLI contracts

```
flabel-db apply                       create or patch the dataset to match schema.py
flabel-db verify                      compare live against declared; exit 1 on any difference
flabel-db show <run-id|capture-sha>   what the store holds — the diagnostic read path
flabel-ingest <gs://…tar.gz>          ingest one published run
flabel-ingest --backfill <gs://…>     ingest everything not already present
    --skip-tier <n>                   load but never attest tier n. See §9 / #142
    --local-adc                       use ADC instead of the instance identity (§7.1)
blfile [--label NAME]...              build a collection. Default: --label verdict
    --capture <sha|name>              restrict to one capture. Repeatable
    --limit <n>
    --output <file>
    --allow-missing-origin            emit flows with no recorded origin (§6.4)
    --as-of <timestamp>               only runs ingested at or before this instant (§6.5)
    --rebuild <collection.json>       reproduce a prior collection (§6.5). Refuses the five flags
                                      that would shape a selection it takes from the document
    --local-adc                       use ADC instead of the instance identity (§7.1)
```

`blfile`'s exit codes mirror `flabel-db`'s, and **1 is narrow on purpose**: 1 is a refusal about the
*data* — a cross-tier value conflict, or `authoritative_runs` returning two runs for one
(capture, tier) — 2 is the operator's environment or arguments, and 3 is a defect in `blfile`
itself. A bare `raise` reaches the interpreter as 1, which would report a store disagreement for a
bug in the tool, so nothing in `main` re-raises. `--limit` is applied **after** composition, never
in SQL: a flow's rows come from up to one run per tier, so a `LIMIT` on `flow_labels` would cut a
flow's tier-2 row off from its tier-1 one and merge half of it.

`--label` values are validated against `LABEL_KINDS`; an unknown name exits 2 naming the permitted
set. Multiple values are **ANDed**: a flow is emitted only if it carries every requested kind, because
ragged rows are useless as training data and `docs/spec.md` §2.5 refuses to let absence be a signal.

`flabel-db show` exists because revision 1 had no way to ask what the store contains — a tool that
can fail naming a missing run, and no command to find out what is present.

**Phase 3b adds `--as-of`, `--rebuild` and `collection_id`.** Deferred deliberately (Craig): they are a
sub-project for a use case nobody has had yet, and deferring them means the archive backfill happens
after someone has looked at real rows. §6.5 keeps their design so it is not re-derived.

### 6.4 The `labels-collection` document

```json
{
  "document_type": "labels-collection",
  "schema_version": "1.1",
  "built_at": "2026-08-20T14:02:11.402931Z",
  "builder": { "tool": "blfile", "version": "0.1.0",
               "store_schema": "9f3c1a20d4e78b61", "label_kinds": "c41d0e77a9b28305" },
  "selection": { "labels": ["verdict"], "match": "all",
                 "captures": 12, "flows": 431,
                 "flows_without_origin": 0 },
  "runs": [ { "run_id": "…", "…": "the run block, verbatim" } ],
  "labels": [
    { "origin": { "capture_sha256": "76f4e17e…",
                  "uri": "gs://tempo-datasets-002-north-south/lax_capture_2026-07-08.pcap",
                  "uri_status": "gs",
                  "filename": "lax_capture_2026-07-08.pcap",
                  "link_type": 1, "snaplens": [262144],
                  "run_ids": { "1": "a1b2c3d4e5f60718", "2": "9f8e7d6c5b4a3928" },
                  "coverage": { "input_status": "complete", "unmatched": 0,
                                "unmatched_ratio": 0.0, "loss_conditions_fired": [],
                                "tiers_supplying": [1, 2] } },
      "flow": { "flow_key": "3c9a…", "…": "as labels.json" },
      "best_tier": 1, "labels": [ … ], "sources": [ … ] }
  ]
}
```

**A new document type, not a labels.json variant**, because a collection spans many runs, captures and
snapshots and `labels.json`'s single `run` block has no honest value to hold. A `labels.json` consumer
fails on this document, which is correct.

Five things revision 1 got wrong here, plus one found in Phase 4:

- **`run_ids` is a `{tier: run_id}` map, not a flat list.** A merged record's `sources` can hold a
  tier-1 entry from an August replay run and a tier-2 entry from a December offline run — a `Label` no
  single run ever asserted. `docs/spec.md` §13 requires every assertion to *name* what produced it,
  and "recoverable with effort by cross-referencing three fields" is weaker than that.
- **`schema_version` moved to `1.1`** when `coverage.tiers_supplying` was added, and the contrast
  with §6.1 is the reason. There, additive `run.input` fields deliberately do **not** bump the
  version, because a reader that ignores them reads the document correctly. Here the consumer that
  matters is not a reader but `--rebuild`, which compares records key by key: an added field makes
  every pre-existing document report one difference per record and exit 1 saying *"the rows those
  runs hold have changed"*. Measured against the P4-5 baseline before the bump: 409 difference
  lines, on nothing but the new key. So the rule is **a change to what a record carries is a
  version move**; a change to a declaration's types or nullability alone is not.

  The cost is stated rather than hidden: a `1.0` document can no longer be reproduced by this
  build. It is still readable — only reproduction is refused, and the refusal says so and names the
  remedy. A test pins a digest of the declared field paths beside the version so the next added
  field cannot repeat #184.

- **`coverage.tiers_supplying`** (#184) — the tiers that have an authoritative run for this
  **capture**, ascending. It is here because `origin.run_ids` is per *flow*: it names only the tiers
  that contributed a source to that flow, so a tier-2-only flow reads `{"2": …}` whether the capture
  had a tier-1 run that did not flag it or was never replayed at all. §2.5 exists to keep those two
  apart, and Phase 4 put both populations in one corpus — 17 captures with both tiers and 7 with
  tier 2 only — where a consumer training on the result would otherwise learn which captures happened
  to be replayed. The bullet below argues that a count no consumer can reach is not published; the
  same argument applies to a distinction no consumer can make.

  **It reports authority, not attempt.** A run that attempted a tier without attesting it (§2.4), or
  one since excluded (§4.5), supplies nothing and does not appear. `tiers_examined` was the name in
  #184 and would have invited the opposite reading; what makes the absence of a label meaningful is
  whether *currently valid* evidence exists, not whether something once ran. Measured 2026-08-28
  before the name was chosen: no capture in production has an attempted tier without an
  authoritative run, so the two readings agree on today's data and diverge only on a future
  exclusion or attestation failure — exactly when the wrong reading would matter.

  **It is scoped to the selection, like everything else in the document.** On the fresh path the
  tiers come from `authoritative_runs` as filtered by `--as-of`; on `--rebuild` they come from the
  document's own pinned `runs[]`. So two collections of one capture built with different cutoffs can
  carry different `tiers_supplying`, and that is the field reporting its selection rather than
  disagreeing with itself.

- **`coverage` per capture**, because §4.4 stores `unmatched` precisely so a consumer is not misled by
  a short label list — and then revision 1's document dropped it, re-creating the misreading at corpus
  level. `docs/spec.md` §10 requires this answerable "in one lookup", not by reading twenty run blocks.
- **`origin.uri_status` and `selection.flows_without_origin`.** Every run currently in the archive
  predates `--source-uri`, so the headline requirement is unmet for all of them. `blfile` **refuses**
  to emit a flow with no origin unless `--allow-missing-origin` is passed, and the count is published
  either way.
- **`builder` pins the store schema and `LABEL_KINDS` digests**, not just its own version. The merge
  now lives in `blfile`, so `builder.version` covers it — but a changed `LABEL_KINDS` changes what
  `--label verdict` means, and a changed schema changes what was read.

**Canonical ordering** follows `docs/spec.md` §10 rather than inventing new rules. Flows sorted by
`(origin.capture_sha256, flow.ts_first, flow_key)` — `flow_key` replacing `uid` as the tie-break,
since §3.2 disqualifies `uid` from carrying ordering meaning. `runs` by `run_id`, labels by `name`.
`json.dump(sort_keys=True, indent=2, ensure_ascii=False)`, trailing newline.

**Three rules this section left to the implementer, settled in LS-7** (Craig, 2026-08-25). Recorded
here rather than in `collection.py` alone, because each is a property of the document a consumer
reads and would otherwise be re-derived differently by `--rebuild`:

- **`snaplens` is plural.** The example literal above said `snaplen` until LS-7; §4.2, §6.1 and the
  `captures` column are plural, and §4.2 already records this same drift being corrected once at
  LS-3. A singular value would have to invent a winner where a `mergecap` pcapng's interfaces
  disagree — measured 96 and 65535 — which is the one fact the field exists to expose.
- **`origin` resolves to the lowest authoritative tier that actually *recorded* one**, falling back
  to the lowest tier's sighting when none did, so `filename`, `link_type` and `snaplens` are still
  published for a flow that is then counted origin-less. §6.5's "lowest surviving tier's run when
  two tiers **disagree**" governs two *recorded* origins; a `not-recorded` sighting is not a
  disagreeing value — §4.2 added `uri_status` precisely so a null `uri` is one fact rather than
  two. This is not hypothetical: every run in the archive predates `--source-uri`, so a strict
  lowest-tier rule would refuse a flow whose origin the store demonstrably holds from a newer run
  at the other tier.
- **`coverage` aggregates over the capture's authoritative runs**, rather than quoting one of them.
  `unmatched` is the sum, `loss_conditions_fired` the union of the flags that are `true` — never
  the ones that are `null`, since §10 makes "JA4 was fine" and "nothing ever probed JA4" different
  facts — `input_status` is `partial` if any contributing run read the capture short, and
  `unmatched_ratio` is recomputed by `models.CorrelationResult`'s own formula over the summed
  counts. **Not `unmatched / detections`**: `docs/spec.md` §10 says outright that the published
  ratio excludes unsupported-transport detections (#84), so the obvious division publishes a
  different number from the one each run was gated on. Quoting a single tier's block would report
  `unmatched: 0` over a capture whose other tier left detections unplaced — the misreading this
  bullet's own justification says `coverage` exists to prevent, one level up. A count no
  contributing run established is `null`, not `0` — and so is one only *some* contributing runs
  established, since summing the rest would publish one run's number as though it described the
  capture. `unmatched_ratio` is `null` whenever any of its three inputs is, including
  `unmatched_unsupported_transport`: treating a missing exclusion count as zero silently reduces
  the ratio to the `unmatched / detections` this bullet forbids.

**A row `blfile` cannot construct is a counted refusal, not a crash** — §9 asks LS-7 to decide this
deliberately and it is decided on §3.2's `ip_proto` precedent: refuse the flow, count it, name it
on stderr. A historical row whose (kind, tier) pair falls outside today's `LABEL_KINDS` is data an
older writer produced legally, and raising on it is how a backfill becomes unrunnable. The two
failures §9 says must never be quiet keep their own exit code: `merge.MergeConflict` is
deliberately **not** a `ValueError`, so the refusal handler cannot swallow it, and neither is
`merge.StoreInconsistent` — a bare `except ValueError` at the CLI would put a corrupt `run_block`'s
`json.JSONDecodeError`, and every ordinary coding slip, under the exit code reserved for the
dataset contradicting itself.

**`selection.flows_without_origin` counts the selection; `selection.flows` counts what was
emitted.** `--limit` separates the two, and they are different facts rather than a discrepancy: the
shortfall in origins is a property of the corpus, not of how much of it was asked for.

### 6.5 Reproducing a collection — Phase 3b

Kept here so the reasoning is not re-derived when it is picked up.

`--rebuild <collection.json>` takes the selection **and the pinned `run_id` set** from a prior
document, making the output a function of that document plus the store. `--as-of <ts>` is the weaker
audit form.

**Reproduction is over records, excluding `built_at` — not byte-for-byte.** An earlier statement of
this requirement claimed byte identity; that is unachievable, and it is the same error `docs/spec.md`
§10 already corrected for a run's output.

**`--as-of` filters on `ingested_at`, never `finished_at`.** A backfill ingests old tarballs late, so a
run finishing 2026-08-17 can carry an `ingested_at` of 2026-09-01, and a `finished_at` filter would let
a document rebuilt "as of the 25th" silently gain a run that was not in the store that day. Both
clocks are needed: **`ingested_at` selects the candidate set, `finished_at` decides which candidate
wins.** Note §4.1's limit — `ingested_at` does not survive a rebuild, so `--as-of` is an audit tool
across a rebuild boundary, not a reproduction one.

Required behaviours: a pinned `run_id` absent from the store is a **hard failure** naming it; `origin`
resolves from the pinned set only, taking the **lowest surviving tier's** run when two tiers disagree;
a `builder`-digest mismatch is reported naming both; and `--rebuild` refuses `--label` and `--as-of`
(exit 2), on §12's precedent for `--sources` — a flag that looks like it changed the selection and did
not is worse than one that errors.

**Built in LS-9, with four corrections §6.5 needed before it could work.** Recorded here because
each was found by running the thing, and the first was a defect rather than a shortfall.

**"The pinned `run_id` set" was under-specified, and ids alone are not enough.** A rebuild needs to
know which run supplied which *(capture, tier)*, and the only thing available to recover that from —
`runs.tiers_attested` — is the wrong answer: that is what a run **claimed**, not what it supplies.
§5.2 rule 2 turns on exactly that difference, so a `--both` run attesting `[1, 2]` while supplying
only tier 1 (its tier 2 having been superseded) made the rebuild see two runs for one (capture,
tier) and fail — naming `authoritative_runs`, a view that code path never queries, about a perfectly
consistent store. **Every capture re-run at one tier was un-rebuildable.** So each `runs[]` entry
carries `run_id`, `capture_sha256` and `supplies` (the tiers it supplies *in this collection*)
beside the verbatim block, and the authority is read from the document. That is what makes a rebuild
a function of "that document plus the store" rather than of today's attestations.

**The selection records its inputs.** `limit`, `allow_missing_origin` and `as_of` join `labels` in
§6.4's block. All three are derivable from the records — the limit from the count, the flag from
whether any emitted origin is `not-recorded` — and an inference that happens to work is a worse
contract than a field.

**A pinned run that has since been retracted is a hard failure.** `authoritative_runs` anti-joins
§4.5, so the ordinary read path never sees an excluded run; `--rebuild` pins a set recorded *before*
the exclusion existed, so it is the one path that can resurrect one. §4.5 is explicit that the table
covers "a capture that must come out for legal or customer-data reasons, and a run later found to be
mislabelled" — so reproducing past it would re-publish exactly what somebody removed. Reproduction
is an audit capability and retraction is a correction; when they collide, **retraction wins**, and
the remedy is a fresh `blfile` without `--rebuild`, which reads the view and so honours it.

**Reproduction compares records, run blocks and order — not the outcome counts.** `built_at` and
`builder` are excluded (the latter reported separately, per below), and so are `selection.captures`,
`flows` and `flows_without_origin`: a `--limit`ed document pins only the runs whose flows survived
truncation, while its `flows_without_origin` counted the whole pre-limit selection — measured at 408
against 20 — so the count differs while every record matches. Dropping them costs no detection,
because a changed flow count *is* an added or removed record. The comparison is over the **JSON
value**: `dataclasses.asdict` leaves `sids` a tuple and `json.loads` yields a list, and without
canonicalising, every record of every document differed on `(40151,) != [40151]`.

**`collection_id` is deliberately not invented** (Craig, 2026-08-25). §6.3 promised it and nothing —
here, in §6.4, or in LS-9's named tests — ever defined it, so building it would mean guessing which
of three jobs it serves: a one-field reproduction check (a digest of the records), an unambiguous
"same question, different answer" signal (a digest of the inputs), or a per-build handle. The three
are not interchangeable, and an inputs-only id has a genuinely dangerous property for ground truth —
a stable name whose content silently changed. §6.2's precedent applies in almost these words: "a
kind whose order is *meaningful* would need that declared on `LabelKind`; none is, so the field is
not invented yet." Decide it when §8's consolidator exists and there is a consumer with a
requirement; if it is built then, build **both** digests rather than either alone.

---

### 6.6 The architecture guard, and why the obvious form cannot fire

Revision 1's plan said the guard fails if a module under `src/flabel/` imports "`flabeldb`,
`google.cloud` or `google.auth`". **`imported_modules()` in `tests/test_architecture.py` records
top-level names only** (`alias.name.split(".")[0]`), so it yields `"google"` and never those two
strings — a check on them passes forever. Exactly the failure class `status.yaml` records for
2026-08-19, where changing a placeholder literal left every test green.

So: check for `"google"` and `"flabeldb"`. And two gaps revision 1 left:

- `PACKAGE` is hard-coded to `src/flabel`, so `test_pure_modules_are_all_accounted_for` never sees
  `src/flabeldb` — the new package would grow modules with no architectural check at all. It gets its
  own accounted-for test.
- The guard is import-based, so `importlib.import_module("flabeldb")` from an impure module slips
  through. `cli.py` is impure and `importlib` is only forbidden in pure modules. Named as a known
  limit rather than papered over.

---

## 7. Operation

### 7.1 Identity

**The credential is named, never discovered.**

```python
from google.auth.compute_engine import Credentials

client = bigquery.Client(credentials=Credentials(), project=GCP_PROJECT)
```

ADC resolves `$GOOGLE_APPLICATION_CREDENTIALS` → the user's `application_default_credentials.json` →
the GCE metadata server. Measured on `fl-replay` 2026-08-20: that second file **does not exist** for
the invoking user, so `google.auth.default()` would reach the instance service account *today* — and
the day anyone runs `gcloud auth application-default login` there, ingestion silently changes identity
and writes rows attributable to a person. Naming the credential makes that unreachable.

`--local-adc` is the documented escape for a laptop and the tests. A flag rather than a fallback,
because a fallback restores the ambiguity this avoids.

**No `sudo`, and the asymmetry with #200 is measured, not assumed.** On the box, as the unprivileged
user: the metadata server returned `846009159455-compute@developer.gserviceaccount.com` and minted a
token, and that token read `results/` over the JSON API with **HTTP 200** — while plain
`gcloud storage ls` failed (*"Reauthentication failed. cannot prompt during non-interactive
execution"*) and `sudo gcloud` succeeded. `gcloud` needs root because its credential store is
per-user; a client library does not, because the metadata server is not user-scoped. Ingest only
*reads* the run directory, which is root-owned but `0755`.

### 7.2 Ingest reads the archive

`flabel-ingest` fetches the published tarball from `gs://` rather than reading the local run directory,
so every ingested run is provably rebuildable, and the live and backfill paths share one source.

**The GCS grant this needs already exists.** Revision 1 called it a blocker on the reasoning that
`objectCreator` grants `storage.objects.create` only. That reasoning is right and the conclusion was
wrong: measured 2026-08-20, the service account holds **both** `objectCreator` *and* `objectViewer` on
`gs://pm-proto-496816-flabel-pcaps`, unconditionally, with no project-level storage role. The read was
verified end to end (§7.1). Recorded as a correction because it was asserted from a partial memory of
a grant rather than from the grant.

One parser, over a run directory, with a fetch-and-untar adapter for the `gs://` case.

### 7.3 The BigQuery grants nobody had specified

Revision 1 specified GCS IAM carefully and **no BigQuery IAM at all** — the same omission as the
2026-08-19 blocker, one service over. Required:

| Principal | Role | Scope |
| :-- | :-- | :-- |
| instance SA | `roles/bigquery.jobUser` | project — to run load jobs |
| instance SA | `roles/bigquery.dataEditor` | dataset `flabel` — to load, and to clear orphans (§5.3) |
| whoever runs `flabel-db apply` | `roles/bigquery.dataOwner` | dataset — to create and patch tables and views |
| readers | `roles/bigquery.dataViewer` | dataset — **to be decided; see §9** |

To be verified from the box in both directions rather than inferred from role names.

### 7.4 Guards, because BigQuery enforces nothing

1. **The primary guard is a query, not a job id**: `SELECT 1 FROM runs WHERE run_id = @id` before any
   load. Immune to job-id retention (§10 M1) and to the burnt-id problem, and it tests the fact that
   actually matters.
2. **Batch load jobs only, never the streaming API.** Atomic per job, free, and no streaming buffer to
   block a later correction.
3. **Attempt-numbered job ids** (§5.3) so a failed attempt does not poison the run.
4. **A duplicate-`run_id` assertion query** — guards 1–3 are the mechanism; this proves the mechanism
   is still connected. It runs in `flabel-db verify`, so it has a home, a caller and a schedule rather
   than being an unowned intention.
5. **`flabel-db verify` runs as a pre-deploy gate in `tools/flabel-deploy`**, not in CI (§2's testing
   line). `apply` makes the tables right today; `verify` notices the day a column is patched in the
   console — modelled on `ci.yml`'s hand-updated toolchain digest, which can silently lag with every
   test still passing.

### 7.5 Trigger, deployment, packaging

`tools/flabel-run` calls `flabel-ingest` after a successful publish; ordering is always
archive-then-index.

**It is invoked as `uv run --no-sync flabel-ingest`, never as a bare command name** (#171). The
console scripts of the `db` extra live in the repo's uv-managed virtualenv, which is on nobody's
`PATH` — the same reason the labelling call is `uv run flabel` and `tools/flabel-deploy` runs
`uv run flabel-db verify`. `--no-sync` follows `docs/label-store-provision.md`, which reaches every
console script that way, and buys a skipped re-resolve on each indexed run.

**It does not rescue the environment, and the first version of this paragraph said it did.** That
claim — that a plain `uv run` would uninstall `google-cloud-bigquery`, `db` being optional — was
asserted in a review, repeated here, and is false. Measured 2026-08-24: `uv sync` is EXACT, and
`uv sync --dry-run` without the extra reports *"Would uninstall 25 packages"* including
`google-cloud-bigquery`; `uv run` is INEXACT, with `--exact` opt-in, so it adds what is missing and
prunes nothing. Both `uv run flabel` and `uv run flabel-db` left the extra intact. Recorded because
two independent reviews raised it as a CRITICAL and only measurement settled it.

The wrapper also requires `GCP_PROJECT` — checked before the call, so a missing one names the
variable rather than surfacing as an opaque exit 5 — and echoes `flabel-ingest`'s own exit code,
because the recovery differs by code and "re-run the ingest" is wrong advice for 2 and 3. A status
above 128 is reported as the signal it is, since `wait` returns 128+N and `flabel-ingest` returns
only 0–3.

**`GCP_PROJECT` lives in `/var/lib/flabel/flabel.env`**, added there 2026-08-24 from the metadata
server's project id — never committed, the repo being public. Both wrappers read it from the config
and let the environment win over it. It had no owner until then, which is the same shape as #163:
`flabel-deploy` and `flabel-ingest` both named the variable when it was missing, and nothing made
it exist. The first deploy on `fl-replay` is what surfaced it. **Exit 5: published, not indexed** — on exit 4's reasoning from `docs/spec.md`
§12, that the labels are intact both on the box and in the bucket, so reusing 1 would tell a batch
caller to discard a capture that succeeded.

**The publish condition does not change.** Revision 1 had `flabel-run` publish on exit 0 rather than on
`labels.json` existing, to let a quiet tier clear a stale label. The premise was false: `_write_output`
writes `run.json`, `NOTICE` and `labels.json` unconditionally on the success path, and `docs/spec.md`
§13 says an all-IPsec capture "exits 0 with `labels[]` empty" — so a clean capture already publishes an
empty `labels[]` and already clears a stale tier. The change would have achieved nothing for its stated
purpose while reversing a recorded decision (2026-08-19, on the *artifact* rather than the exit code),
deleting a passing test, and destroying the one unambiguous signal §2.5 needs, since **a tarball
carries no exit code**.

Deployment is three steps — `git pull`, `uv sync --extra db`, reinstall the wrapper — and the two-step
version already left the box two merges behind with #137 undeployed. `tools/flabel-deploy` does all
three, `md5sum`-checks the wrapper so it reinstalls only on a real change, runs `flabel-db verify`, and
refuses while `pgrep -af "tcpreplay|flabel|uv run"` matches, because a deploy `git pull`s source a
running labelling run imports lazily and `uv sync --extra db` **prunes the very virtualenv that run
is executing out of** — a sync without the extra reports "Would uninstall 25 packages".

The reason first given here was that "`install` overwrites in place and bash reads a script as it
executes". **Measured 2026-08-24: that is false.** GNU `install` unlinks the destination and creates
a new inode — the inode number changes and a hardlink to the old one keeps the old contents — which
is exactly why it can replace a running binary where `cp` gets `ETXTBSY`. A running bash holds its
descriptor on the old, unlinked inode and reads it to completion. The guard is right; the reason was
folklore, and it had been repeated into a script header and three test docstrings before anyone
measured it.

One distribution. `[project.optional-dependencies] db`, and `packages = ["src/flabel", "src/flabeldb"]`
— a sibling directory is not packaged until that list changes. `flabel`'s `dependencies = []` stays
literally true, and the console scripts fail naming `flabel[db]` rather than with an `ImportError`.
`uv.lock` changes with `pyproject.toml`, and `ci.yml` runs `uv sync --locked`, so both move together or
CI goes red.

---

## 8. Planning for the consolidator

Out of scope. Three constraints honoured now because they are expensive to retrofit.

**Merging captures is not a one-liner — Zeek refuses the result.** `mergecap`'s default pcapng output
writes one interface description block per input file, and Zeek rejects a file whose interfaces
disagree. Measured against this repo's own fixtures:

```
fatal error: … an interface has a snapshot length 262144 different from the
             snapshot length of the first interface
fatal error: … an interface has a type 1 different from the type of the first interface
mergecap: The capture file being read can't be written as a "pcap" file.
```

1. **Group by capture, one pass each.** A capture is a multi-gigabyte object in another project's
   bucket; extraction must fetch it once and pull every selected flow in a single pass. This is why
   §6.4 sorts by `capture_sha256` — the document is already in extraction order.
2. **Preserve original timestamps; never rebase.** The labels' `ts_first`/`ts_last` are the join key
   back to the record. State the consequence in the output rather than let it be discovered: the
   merged file interleaves unrelated captures and is not a coherent timeline.
3. **Normalise before merging, and report what could not be included.** flabel's `ingest` already does
   this normalisation and reports `discarded_link_types` with `input_status: partial`; reuse that
   vocabulary rather than invent a second one for the same loss.

---

## 9. Explicit non-behaviours

The store and `blfile` **must never**:

- key any row on Zeek's `uid`, or join across runs on it (§3.2);
- write a `flow_labels` row for a flow whose transport cannot be distinguished (§3.2, #96);
- treat a tier as authoritative on the *absence* of a failure flag rather than on positive evidence
  (§2.4);
- let an excluded run supply an authoritative tier slice (§4.5);
- update or delete a row outside §2.2's two named exceptions;
- ingest a failed run (§2.5);
- implement the merge rule twice (§5.2);
- emit a `labels-collection` claiming a single `run` block, or stamped with `labels.json`'s
  `schema_version` (§6.4);
- emit a flow missing any requested label kind, or one with no recorded origin unless
  `--allow-missing-origin` was passed (§6.3, §6.4);
- silently pick a winner when two tiers disagree on a single-arity label's value (§5.2);
- discover its credential rather than naming it (§7.1);
- write to the archive.

### Accepted consequences, named rather than mitigated

- **A capture absent from the store is indistinguishable from one never run.** Failed runs are not
  ingested and a gate-failing run is not published, so its `run.json` lives only on `fl-replay`'s local
  disk. Issue #143 means that path is reached regularly.
- **The BigQuery tests do not run in CI.** §2's testing line. `flabel-db verify` moved to pre-deploy,
  and Phase 3's DoD says so rather than claiming a gate that cannot exist.
- **The headline requirement is unmet for every run already in the archive**, which all predate
  `--source-uri`. `uri_status: not-recorded` and `selection.flows_without_origin` make it visible
  instead of silent (§4.2, §6.4).
- **A construction-time rule makes an old row unreadable rather than reportable.** `LABEL_KINDS` is
  enforced when a `LabelEntry` is built, and LS-7 and LS-8 build them from archived rows. A
  historical row whose (kind, tier) pair falls outside the table would raise on data an older
  writer legally produced — which is how a backfill becomes unrunnable. Nothing in the archive is at
  risk today: `correlate` has filtered `threat-name` to tier 1 since #138, and `verdict` has only
  ever carried 1 or 2. **LS-7 must decide deliberately** whether a row it cannot construct is a hard
  failure or a counted exclusion; §3.2's `ip_proto` case — refuse the row, count it, record it on
  the run — is the precedent, and §4.5's `run_exclusions` is where it belongs.
- **Two inherited defects.** `flow.ts_last` can exclude a last-packet detection (#60); duplicate
  `SourceEntry` values are unbounded (#58), so a composed `sources` list can carry repeats.
- **The cross-tier merge path has never met real data** (#144) — 432/432 and 367/367 single-source. It
  is now implemented once, in the language whose constructors already assert its invariants, which is
  the best available mitigation short of a real capture.
- **BigQuery job-id retention is a documented ~6 months and was not measured.** It no longer matters,
  because §7.4's primary guard is a query rather than a job id — but if that ordering is ever reversed,
  this becomes a silent doubling after six months.

### Open, and deliberately not decided here

- **Should tier-2 supersession order on snapshot recency rather than `finished_at`?** A run pinned to
  an old `--ruleset-snapshot` finishes later and currently wins, which inverts §5.1's own argument.
  §4.5's exclusions make it recoverable; they do not make it right.
- **Who may read the dataset** (§7.3). Phase 3 adds two destinations for non-anonymous network
  metadata — Zeek's DNS names, HTTP URIs and TLS server names — and `docs/spec.md` §13's standard is
  that a new destination is a decision someone writes down. Nobody has.
- **Retention.** Nothing deletes anything, and at this scale nothing needs to for years.
- **Load-job quota on a large backfill.** Four load jobs per run against a 1,500-per-table-per-day
  limit bounds a single day's backfill at ~375 runs.

---

## 10. What was measured against BigQuery

Revision 1 made four claims about BigQuery, none executed. All four were tested on 2026-08-20 in the
`flabel_scratch` dataset. Recorded here so nobody re-derives them, in the manner `docs/spec.md` §10
records the tool measurements that corrected it.

| | Claim in revision 1 | Measured |
| :-: | :-- | :-- |
| **M1** | A repeated `jobId` is rejected, so double-ingest fails loudly. | **True, and insufficient.** The repeat is refused (`Already Exists`) with the row count unchanged. But a load job that **fails** also consumes its id permanently: a bad-row load left `state: DONE`, `errorResult: invalid`, `outputRows: None`, and the retry under the same id was refused. So one transient failure permanently burnt the run's id. Verified fix: `DELETE WHERE run_id = …` then reload under an attempt-numbered id — both succeeded. |
| **M2** | (unstated) | Job ids are namespaced **`project:location.jobid`**, so the dataset location is part of the idempotency namespace. An unused id returns `Not found`, which is how "no attempt yet" is detected. |
| **M3** | `flow_labels PARTITION BY DATE(flow.ts_first)`. | **Fails at `CREATE TABLE`**: *"The field specified for partitioning can only be a top-level field."* A control table partitioned on a top-level timestamp created fine, so it is the nesting and not the syntax. §4.3 now has no partition. |
| **M4** | The results bucket's location. | `US-CENTRAL1`, **regional** — so the dataset is pinned to `us-central1` (§4). Revision 1 never stated a location. |

Reproduce with `bq --location=us-central1` against `pm-proto-496816:flabel_scratch`. Note `proto` is a
reserved word in BigQuery DDL — a first attempt at M3 failed on that instead, and only the control
failing identically showed the test was invalid.
