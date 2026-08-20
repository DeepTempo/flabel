# Specification — the label store and `blfile`

Phase 3. A sibling of `docs/spec.md`, not a section of it: what this specifies lives in a **separate
package** (`src/flabeldb/`), because flabel itself has `dependencies = []` and
`tests/test_architecture.py` keeps a closed list of network-capable modules. A BigQuery client is
both a dependency and network I/O.

`docs/spec.md` remains the authority for everything flabel emits. This document is the authority for
what happens to it afterwards. Where the two must agree, this document says so and names the section.

Decisions were taken by Craig on 2026-08-20 and are recorded in `docs/status.yaml`. The design
reasoning, including the measurements that produced it, is `inline-labeling/label-store-design.html`.

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
| **delivered tier** | A tier that a run attempted *and* did not lose: `tier ∈ tiers_attempted and tier ∉ tiers_unavailable`. Only a delivered tier supersedes. |
| **tier slice** | Everything one run asserted about one flow at one tier. The unit of supersession. |
| **authoritative run** | For a given (capture, tier), the run that currently supplies that tier slice: the newest run to have delivered that tier. |
| **collection** | A `labels-collection` document — labels for many flows, from many captures and many runs. Distinct from a `labels.json`, which is one run over one capture. |
| **collection id** | `sha256(selection ‖ sorted run ids)[:16]`. Names a set without reference to a clock. |
| **the archive** | `gs://pm-proto-496816-flabel-pcaps/results/`. The system of record. |
| **the store** | The BigQuery dataset. A **derived index** over the archive, rebuildable from it. |

**"the store is derived" is load-bearing, not a figure of speech.** Every safety argument in this
document reduces to it: a merge rule that turns out wrong is a `TRUNCATE` and a backfill, not a data
loss. §5.4 is what keeps the claim true, and §7.2 is what verifies it per run rather than assuming it.

---

## 2. Constraints and invariants

1. **Nothing in `src/flabel/` may import `flabeldb`, and nothing in `src/flabel/` may import a
   BigQuery or Google client library.** Enforced statically by `tests/test_architecture.py`, extended
   for this phase. A guard that exists only as a convention stops meaning anything the moment a
   sibling package exists.
2. **The store is append-only.** No row is ever updated or deleted in normal operation. "Current" is
   a view (§4.5). This is what makes BigQuery's lack of enforced uniqueness survivable, and it is why
   the merge rule chosen in §5 is the only one this schema supports cheaply.
3. **A run is visible only when its `runs` row exists.** A multi-table load is not atomic, so the
   `runs` row is the commit marker and every view joins through it (§5.3).
4. **Only a delivered tier supersedes.** A run that lost a tier must not replace what was known about
   it. `docs/spec.md` §10 already guarantees the field this rests on: `tiers_unavailable` is
   *attempted-and-lost, never not-asked-for*, and a tier counts as delivered only when its stage
   returned.
5. **A failed run is never ingested** (Craig, 2026-08-20). `run.json` on the box is where a failure is
   diagnosed. See §9 for the consequence, which is accepted rather than mitigated.
6. **Identity is derived from content, never from a name or a tool's internal counter.** §3.
7. **The identity `flabeldb` authenticates as is named, never discovered.** §7.1.

### Testing line

Same shape as `docs/spec.md` §2's, one layer out: **BigQuery is real in the tests that matter.**
Idempotency, the commit-marker ordering and `flabel-db verify` are properties of the service, not of
our code, and a mocked client would encode our assumptions about BigQuery — which is what needs
verifying. Those tests run against a scratch dataset and are marked `requires_bigquery`, in the
manner of the existing `requires_tools` marker, so a laptop without credentials skips rather than
fails. Pure logic — `flow_key`, `run_id`, the per-tier split, canonical ordering, document assembly —
is tested without a client at all and is the majority of the suite.

---

## 3. Identity

### 3.1 Capture

`capture_sha256` = `run.input.sha256`, unchanged from `docs/spec.md` §10.

Known and accepted: that digest covers the input **as handed over**, so `foo.pcap` and `foo.pcap.gz`
of the same packets are two captures and will not merge. Correct for provenance; surprising in the
field, so it is written down here.

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
def flow_key(capture_sha256: str, flow: Flow) -> str:
    """Content-derived identity of a flow within a capture. Never reads flow.uid."""
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
            _endpoint(lo),
            _endpoint(hi),
            iso_micros(flow.ts_first),  # the format from docs/spec.md §10
        )
    )
    return sha256(material.encode()).hexdigest()[:16]
```

**The endpoint pair is canonically ordered, and the orientation Zeek reported is stored beside it.**
Ordering the pair means an orientation disagreement cannot split one flow into two rows.
`docs/spec.md` §9 already declines to require Zeek and Suricata to agree on who initiated a
connection; this declines to require two *Zeek versions* to.

**Sixteen hex characters**, matching the `snapshot_id` convention, so the existing
`fullmatch(r"[0-9a-f]{16}")` guard applies unchanged.

`ts_first` comes from the pcap timeline, so it is unaffected by the replay wall-clock imprecision
that makes tier-1 detection timestamps coarse, and it is identical across runs. Port reuse within one
capture is disambiguated by it — the same property `docs/spec.md` §9 step 4 already relies on.

**`ts_last` is stored but is not part of the key.** Issue #60 records that it is computed from a
rounded duration and can exclude a detection on the last packet. Keying on it would inherit that
defect; storing it does not, but a consumer filtering on the window does. Noted in §9.

### 3.3 Run

```python
run_id = sha256(
    f"{capture_sha256}|{mode}|{iso_micros(started_at)}|{flabel_version}".encode()
).hexdigest()[:16]
```

Derived from the run block alone, so **re-reading the same tarball computes the same id**. That is
what makes ingestion idempotent in a store that will not enforce it (§5.2).

Uniqueness rests on two runs never starting in the same microsecond. That holds because there is one
runner (Craig, 2026-08-20) and a run holds the replay interfaces for its duration. Stated as a
dependency rather than left implicit: **a second concurrent runner breaks this**, and the fix would
be to add the host to the material, not to hope.

---

## 4. Schema

Dataset `flabel` in `${GCP_PROJECT}`. Four tables, two views. Tables are declared in
`src/flabeldb/schema.py` as client schema objects — the form the load jobs already need — and views
as committed SQL under `src/flabeldb/views/`. There is no second copy in a `.sql` file or a shell
script; §7.3 is what stops the live tables drifting from the declaration.

### 4.1 `runs`

| Column | Type | Notes |
| :-- | :-- | :-- |
| `run_id` | STRING | §3.3 |
| `capture_sha256` | STRING | |
| `mode` | STRING | `replay` \| `offline` \| `both` |
| `tiers_attempted` | ARRAY&lt;INT64&gt; | |
| `tiers_delivered` | ARRAY&lt;INT64&gt; | attempted **minus** `tiers_unavailable` |
| `started_at`, `finished_at` | TIMESTAMP | |
| `flabel_version` | STRING | |
| `snapshot_id` | STRING | null on a `replay` run, per `docs/spec.md` §10 |
| `archive_uri` | STRING | the tarball this was read from |
| `run_block` | JSON | verbatim — the record, not a summary |
| `ingested_at` | TIMESTAMP | the store's own clock. §6.3 |

`PARTITION BY DATE(finished_at)`, `CLUSTER BY capture_sha256, mode`.

`run_block` is stored whole and unparsed as well as projected into columns. The columns are what the
views join on; the JSON is what makes the store answer a question nobody anticipated without a
re-ingest.

### 4.2 `captures`

One row per sighting: `capture_sha256`, `uri` (nullable), `filename`, `bytes`, `format`, `link_type`,
`snaplen`, `observed_by_run_id`, `observed_at`. `CLUSTER BY capture_sha256`.

`uri` is **null when the capture was not staged from `gs://`** — `docs/spec.md` §2.5's rule, that
absence means not-applicable rather than unknown. `link_type` and `snaplen` are the fields §8 needs
and §6.1 adds.

### 4.3 `flow_labels`

**One row per (run, flow, tier).** This is the design's least obvious decision and it falls straight
out of the merge rule: a `--both` run puts tier-1 and tier-2 sources on a *single* `Label`, so
storing that shape would make superseding tier 1 an array edit. Splitting at ingest makes
supersession a row filter.

```
run_id, capture_sha256, flow_key, tier

flow    STRUCT<proto, ip_lo, port_lo, ip_hi, port_hi,
               src_ip, src_port, dst_ip, dst_port,
               ts_first, ts_last, zeek_uid, ja4, ja4s, server_name>

labels  ARRAY<STRUCT<name STRING, value ARRAY<STRING>, tier INT64, sids ARRAY<INT64>>>

sources ARRAY<STRUCT<tier, source, sid, rev, ruleset, admission_basis,
                     licence, classtype, label_basis, threat, direction>>
```

`PARTITION BY DATE(flow.ts_first)`, `CLUSTER BY capture_sha256, flow_key, tier`.

**The `verdict` entry is recomputed per tier** — same value, that tier's sids — and §4.5 re-unions
them on the way out. Lossless, and strictly more traceable than one entry covering both tiers.
`threat-name` is tier-1 only and lands in the tier-1 row untouched.

**`value` is `ARRAY<STRING>` for every label kind**, single-valued ones carrying one element. In the
*document* a single-valued kind serialises as a bare string; the arity is declared by
`models.LABEL_KINDS` (§6.2), so the JSON type follows from the name and is never a per-record
surprise.

**`zeek_uid` is stored and must never be joined on.** It is kept because it is how an operator finds
the flow in that run's `conn.log`, which is a real use. §3.2 is why it is nothing more.

### 4.4 `unmatched`

One row per (run, detection) from `unmatched_detections[]`: `run_id`, `capture_sha256`, `tier`,
`source`, `sid`, `rev`, `threat`, `ts`, `proto`, endpoints, `direction`, `reason`.

Stored because `docs/spec.md` §13 ends on exactly this: *a consumer must never read an empty
`labels[]` as "nothing malicious was found"*, and `unmatched_detections[]` is the evidence. A store
that dropped them would reintroduce, at the corpus level, the misreading the spec spends a paragraph
forbidding at the document level.

It supersedes per tier like `flow_labels`, and for the same reason.

### 4.5 Views

`authoritative_runs` — for each (capture, tier), the run that currently supplies it:

```sql
SELECT capture_sha256, tier, run_id FROM (
  SELECT r.capture_sha256, tier, r.run_id,
         ROW_NUMBER() OVER (PARTITION BY r.capture_sha256, tier
                            ORDER BY r.finished_at DESC, r.run_id DESC) AS recency
  FROM flabel.runs r, UNNEST(r.tiers_delivered) AS tier
) WHERE recency = 1;
```

**`run_id` in the sort key is required, not cosmetic.** `finished_at` alone is not a total order, and
on a box that replays a whole capture in seconds two runs finishing in the same second is the
ordinary case rather than the edge one. This is #138's correction applied to a second comparator: a
rule that is not total does not produce a property of the data.

`current_labels` — the merged per-flow view `blfile` reads. Labels are merged by name across
surviving tiers: **value from the lowest tier, `tier` = `MIN`, `sids` = union**; `best_tier` is
recomputed as `MIN(tier)` rather than stored, reproducing the invariant `Label.__post_init__` already
enforces instead of carrying a second copy that can drift. It returns `run_ids` **plural** — one
flow's labels can legitimately come from two runs, which is the concrete reason a collection cannot
carry a single `run` block (§6.4).

---

## 5. Merge semantics

### 5.1 The rule

**The newest run that delivered tier T replaces everything previously known about tier T for that
capture. Tiers compose; they do not overwrite each other.**

Chosen over pure accumulation because upstream feeds retract: 1,469 ET sids were removed in two days
(measured 2026-08-17). Accumulation keeps a label no current run asserts, inside a dataset whose
purpose is ground truth. Chosen over whole-capture latest-wins because bare `flabel` is tier 1 only
and `--offline` is tier 2 only (`docs/spec.md` §12), so latest-wins would make a replay run delete
every Suricata label and vice versa — multi-source labelling would survive only if every run were
`--both`.

Craig's two stated cases both follow: a re-run showing a new label adds it, because the tier's slice
is replaced by the newer and richer one; a re-run showing a new threat name updates it, because
tier 1's slice is replaced wholesale.

### 5.2 What the rule removes from the design

**No cross-run comparator for `threat-name`.** A tier slice arrives whole from one run, so the
`threat-name` on it is that run's own `(unestablished, ts, sid)` pick from `docs/spec.md` §4. A
merged value that matched no single run's output is unreachable. This was an open problem under
accumulation and the merge rule dissolves it.

**No upsert.** Nothing is updated in place, which is what makes BigQuery viable here (§2.2).

### 5.3 Commit ordering

`flow_labels`, `unmatched` and `captures` load first; the `runs` row lands **last**. A crash
mid-ingest therefore leaves rows no view can reach, and re-running the same ingest completes it.

### 5.4 Rebuild

`TRUNCATE` the dataset and `flabel-ingest --backfill` the archive. Deterministic: every id in §3 is
content-derived, so a rebuild reproduces the same rows. This is the escape hatch that licenses
shipping a merge rule at all.

---

## 6. Interfaces

### 6.1 Additive fields in `run.input`

Three, in `docs/spec.md` §10's run block. None bumps `schema_version`: they are additive, and a 2.0
reader that ignores them reads the document correctly — the precedent #115 set for `direction`.

| Field | Type | Why |
| :-- | :-- | :-- |
| `uri` | `str \| null` | The origin the capture was staged from. **Without it the requirement cannot be met at all**: `tools/flabel-run` lines 211–220 stage a `gs://` object and then assign `TARGET="$LOCAL"`, so today `run.input.path` records the staged local path and the bucket URI is discarded with the shell variable. It belongs in `run.input` because that is where the provenance of the input lives; a sidecar file would be a second record that can disagree. |
| `link_type` | `int` | The link type **retained**. Already determined internally to decide what to discard, but only `discarded_link_types` is published. §8 needs the kept one. |
| `snaplen` | `int` | Unpacked and discarded at `ingest.py:255` (`_snaplen`). Zeek refuses a merge across differing snaplens (§8), so this is not cosmetic. |

`--source-uri` is **validated, not merely recorded**: a value that is not a well-formed `gs://` URI
exits 2 before any tool runs. flabel does not verify that the URI *holds* the bytes it hashed — that
would be network I/O on a path that must not perform it — so the field is a faithful record of what
the operator asserted, and `run.input.sha256` remains the identity. Stated because the two could be
mistaken for one guarantee.

### 6.2 `models.LABEL_KINDS`

Replaces the bare `Literal["verdict", "threat-name"]` with one authority carrying arity and permitted
tiers:

```python
LABEL_KINDS: Mapping[str, LabelKind] = {
    "verdict": LabelKind(arity="single", tiers=(1, 2)),
    "threat-name": LabelKind(arity="single", tiers=(1,)),
}
```

`blfile`'s `--label` validation, the store's array column and flabel's own `LabelEntry` guards all
read it. **A test must assert that each of them does** — status.yaml's 2026-08-19 sabotage finding is
exactly this shape: changing `panw`'s placeholder literal left every test green while re-opening a
bug just closed, because a shared constant stops two copies but does not stop one of them being
ignored.

Today both kinds are `single`, so flabel's output is byte-unchanged. The first `multi` kind
introduces a list-typed `value` into `labels.json`, which is something a consumer must understand —
**that** is what bumps `schema_version` to 3.0, when MITRE ships and not before.

### 6.3 CLI contracts

```
flabel-db apply                       create or patch the dataset to match schema.py
flabel-db verify                      compare live against declared; exit 1 on any difference
flabel-ingest <gs://…tar.gz>          ingest one published run
flabel-ingest --backfill <gs://…/**>  ingest everything not already present
    --local-adc                       use ADC instead of the instance identity (§7.1)
blfile [--label NAME]...              build a collection. Default: --label verdict
    --as-of <ts>                      only runs ingested at or before <ts>
    --rebuild <collection.json>       reproduce a prior collection; refuses --label and --as-of
    --output <file>
```

**`--rebuild` refuses `--label` and `--as-of`** — exit 2, on `docs/spec.md` §12's own precedent for
`--sources`: a flag that looks like it changed the selection and did not is worse than one that
errors. The selection and the run set both come from the document, which is what makes the output a
function of it.

**`--label` values are validated against `LABEL_KINDS`**; an unknown name exits 2 naming the
permitted set. Multiple `--label` values are **ANDed**: a flow is emitted only if it carries every
requested kind. Ragged rows are useless as training data, and `docs/spec.md` §2.5 already refuses to
let absence be a signal.

### 6.4 The `labels-collection` document

```json
{
  "document_type": "labels-collection",
  "schema_version": "1.0",
  "collection_id": "5b1e0c7742a9d380",
  "built_at": "2026-08-20T14:02:11.402931Z",
  "builder": { "tool": "blfile", "version": "0.1.0" },
  "selection": { "labels": ["verdict"], "match": "all", "as_of": null,
                 "captures": 12, "flows": 431 },
  "runs":   [ { "run_id": "…", "…": "the run block, verbatim" } ],
  "labels": [ { "origin": { "capture_sha256": "…", "uri": "gs://…", "filename": "…",
                            "link_type": 1, "snaplen": 262144, "run_ids": ["…", "…"] },
                "flow": { "flow_key": "…", "…": "as labels.json" },
                "best_tier": 1, "labels": [ … ], "sources": [ … ] } ]
}
```

**It is a new document type rather than a labels.json variant** because a collection spans many runs,
captures and snapshots, and `labels.json`'s single `run` block has no honest value to hold —
`run.ruleset.snapshot_id`, `run.input.sha256` and `run.counts` all describe one run over one capture.
A `labels.json` consumer fails on this document, which is correct: it is not one run's output and
must not claim to be.

`origin` carries the digest **beside** the URI because the URI is a location and the digest is the
identity: a consolidator that fetches by URI can verify it received the bytes the labels describe.

**Canonical ordering** follows `docs/spec.md` §10's rules rather than inventing new ones. Flows sorted
by `(origin.capture_sha256, flow.ts_first, flow_key)` — `flow_key` replacing `uid` as the tie-break,
since §3.2 disqualifies `uid` from carrying ordering meaning. `runs` sorted by `run_id`. Labels within
a flow sorted by `name`. `json.dump(sort_keys=True, indent=2, ensure_ascii=False)`, trailing newline.

### 6.5 Reproducing a collection

**`--rebuild` reproduces over records, excluding `built_at` — not byte-for-byte.** An earlier
statement of this requirement claimed byte identity; that is unachievable because `built_at` is a
wall clock, and it is the same error `docs/spec.md` §10 already corrected for a run's output, where
byte-identity was found "wrong and unachievable" and replaced with record comparison over named
exclusions. `collection_id` is the short handle for "the same set" precisely because it is derived
from the selection and the sorted run ids and not from any clock.

Four required behaviours, each because the silent version is worse:

- **A pinned `run_id` absent from the store is a hard failure**, naming which. The alternative is a
  quietly smaller document that still presents as the original set.
- **`origin` resolves from the pinned run set only.** `captures` is append-only per sighting, so if a
  later run observes the same capture at a different URI, an unpinned rebuild would change
  `origin.uri` while every label stayed identical. Origin comes from the authoritative run's own
  sighting *within* the pinned set.
- **A `builder.version` mismatch is reported**, naming both versions. If blfile's ordering changed
  between versions the output legitimately differs, and saying so beats emitting a different document
  under the old set's name.
- **`--as-of` filters on `ingested_at`, never `finished_at`.** These are not interchangeable and the
  intuitive choice breaks reproduction: a backfill ingests old tarballs late, so a run finishing
  2026-08-17 can carry an `ingested_at` of 2026-09-01, and a `finished_at` filter would let a
  document rebuilt "as of the 25th" silently gain a run that was not in the store that day. Both
  clocks are needed and they do different jobs — **`ingested_at` selects the candidate set,
  `finished_at` decides which candidate wins supersession** (§4.5).

---

## 7. Operation

### 7.1 Identity

**The credential is named, never discovered.**

```python
from google.auth.compute_engine import Credentials

client = bigquery.Client(credentials=Credentials(), project=GCP_PROJECT)
```

ADC resolves `$GOOGLE_APPLICATION_CREDENTIALS` → the user's
`application_default_credentials.json` → the GCE metadata server. `google.auth.default()` would land
on the metadata server *today* only because the second does not exist for that user — and the day
anyone runs `gcloud auth application-default login` on the box, ingestion silently changes identity
and writes rows attributable to a person rather than the instance. Naming the credential makes that
unreachable.

`--local-adc` is the documented escape for a laptop and for the tests, where there is no metadata
server. It is a flag rather than a fallback: a fallback would restore the ambiguity this avoids.

**No `sudo`.** This is deliberately unlike every other cloud call in `tools/flabel-run`, and the
asymmetry has a reason: `gcloud` reads a **per-user** credential store, which is why #200 had to
elevate it, while the Python client reaches the metadata server regardless of user. Ingest only
*reads* the run directory, which is root-owned but `0755`. Elevating would be privilege the job does
not need, and `uv run` under `sudo` resolves a different `HOME`, `PATH` and cache — a new failure
surface on the layer where both of #134's late bugs lived.

### 7.2 Ingest reads the archive

`flabel-ingest` fetches the published tarball from `gs://` rather than reading the local run
directory, so **every ingested run is provably rebuildable** — rebuilding from the archive is
literally what ingest just did. It also collapses the live and backfill paths onto one source, so the
path relied on in a recovery is the path that runs every day.

**This requires a new IAM grant**: `roles/storage.objectViewer` for the instance service account on
`gs://pm-proto-496816-flabel-pcaps`. `objectCreator` grants `storage.objects.create` only, so the box
currently cannot read back what it uploaded. Read-only; overwrite and delete stay refused. To be
verified from the box in both directions, the way `objectCreator` was on 2026-08-19, rather than
inferred from the role name.

One parser, over a run directory, with a thin fetch-and-untar adapter for the `gs://` case. Two
parsers for one document shape is the defect this repo keeps finding.

### 7.3 Guards, because BigQuery enforces nothing

1. **Batch load jobs only, never the streaming API.** Atomic per job, free, and no streaming buffer
   to block a later correction.
2. **`jobId = ingest-<run_id>-<table>`.** Because `run_id` is content-derived, re-reading the same
   tarball produces the same job id and the API rejects it as already existing. Accidental
   double-ingest fails loudly instead of silently doubling every row.
3. **A duplicate-`run_id` assertion query, wired as a standing gate.** Guards 1 and 2 are the
   mechanism; this is what proves the mechanism is still connected.
4. **`flabel-db verify` as a preflight and as a CI gate.** `apply` makes the tables right today;
   `verify` is what notices the day a column is patched in the console. Modelled on a failure already
   on the books: `ci.yml`'s toolchain digest is updated by hand and can silently lag
   `Dockerfile.toolchain`, with every test still passing because the pins and the stale image agree.

### 7.4 Trigger and deployment

`tools/flabel-run` calls `flabel-ingest` after a successful publish, so ordering is always
archive-then-index and the store can never hold a run the archive lacks. `--backfill` is the
reconciler. **Exit 5: published, not indexed** — on exit 4's own reasoning from `docs/spec.md` §12,
that the labels are intact both on the box and in the bucket, so reusing 1 would tell a batch caller
to discard a capture that succeeded.

Deployment becomes three steps — `git pull`, `uv sync --extra db`, reinstall the wrapper — and the
two-step version has already left that box two merges behind with #137 undeployed because only the
pull was done. `tools/flabel-deploy` does all three, `md5sum`-checks the wrapper so it reinstalls only
on a real change, and refuses to run while `pgrep -af "tcpreplay|flabel|uv run"` matches: `install`
overwrites in place and bash reads a script as it executes, so replacing the wrapper mid-run can
corrupt a run that has already spent its replay and 60-second settle.

### 7.5 Packaging

One distribution. `[project.optional-dependencies] db`, and `[tool.hatch.build.targets.wheel]
packages = ["src/flabel", "src/flabeldb"]` — a sibling directory is not packaged until that list
changes. `flabel`'s own `dependencies = []` stays literally true, and the console scripts fail with a
message naming `flabel[db]` when the extra is absent rather than with an `ImportError` traceback.

---

## 8. Planning for the consolidator

Out of scope. Three of its constraints are honoured now because they are expensive to retrofit.

**Merging captures is not a one-liner — Zeek refuses the result.** `mergecap`'s default pcapng output
writes one interface description block per input file, and Zeek rejects a file whose interfaces
disagree. Both measured 2026-08-20 against this repo's benign-corpus fixtures:

```
fatal error: … an interface has a snapshot length 262144 different from the
             snapshot length of the first interface
fatal error: … an interface has a type 1 different from the type of the first interface
mergecap: The capture file being read can't be written as a "pcap" file.
```

1. **Group by capture, one pass each.** A capture is a multi-gigabyte object in another project's
   bucket; extraction must fetch it once and pull every selected flow in a single pass, not once per
   flow. This is why `current_labels` is keyed by `capture_sha256` and why §6.4 sorts by it — the
   document is already in extraction order.
2. **Preserve original timestamps; never rebase.** The labels' `ts_first`/`ts_last` are the join key
   back to the record. The consequence must be stated in the output rather than discovered: the merged
   file interleaves unrelated captures and is not a coherent timeline. Fine per-flow, wrong for
   anything reading it as a session.
3. **Normalise before merging, and report what could not be included.** flabel's `ingest` already
   performs this normalisation and already reports `discarded_link_types` with
   `input_status: partial`. The consolidator reuses that vocabulary rather than inventing a second
   one for the same loss.

---

## 9. Explicit non-behaviours

The store and `blfile` **must never**:

- key any row on Zeek's `uid`, or join across runs on it (§3.2);
- update or delete a row in normal operation — corrections are new rows, and a rebuild is a truncate
  plus a backfill (§5.4);
- let a run that did not deliver a tier supersede that tier (§2.4);
- ingest a failed run (§2.5);
- emit a `labels-collection` claiming a single `run` block, or stamp one with `labels.json`'s
  `schema_version` (§6.4);
- emit a flow missing any requested label kind (§6.3);
- reproduce a collection while silently dropping a pinned run, changing an origin URI, or ignoring a
  builder-version mismatch (§6.5);
- discover its credential rather than naming it (§7.1);
- write to the archive. The store is derived; the archive is the record. The service account's
  `objectCreator` grant already makes overwrite and delete impossible, and §7.2's addition is
  read-only.

### Accepted consequences, named rather than mitigated

- **A capture absent from the store is indistinguishable from one never run.** Failed runs are not
  ingested and a gate-failing run is not published either, so its `run.json` lives only on
  `fl-replay`'s local disk. Issue #143 means this path is reached regularly, not rarely.
- **Two defects are inherited.** `flow.ts_last` can exclude a last-packet detection (#60) — the flow
  *key* is unaffected, a consumer filtering on the stored window is not. Duplicate `SourceEntry`
  values are unbounded (#58), so the merged view's concatenated `sources` can carry repeats across
  tiers. Both belong upstream, not papered over in SQL.
- **The cross-tier merge path has never met real data.** Both measured captures put exactly one source
  on every labelled flow (432/432 and 367/367), so `best_tier` consolidation and tier precedence are
  fixture-exercised only — now in SQL as well as in Python. Issue #144.
- **Tier-2 ingestion is gated on #142.** `fl-replay` runs Suricata 7.0.3 against an 8.0 ruleset and is
  now the only runner, so ingesting tier 2 from it would fill the store with labels from an engine
  that loaded none of the snapshot — and under §5.1 those results would *replace* good tier-2
  knowledge rather than sit beside it.
