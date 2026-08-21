# Provisioning the label store — dataset, IAM, and what was verified

Step **LS-6** (#149) of `docs/PLAN-label-store.md`. Spec: `docs/spec-label-store.md` §1, §4, §7.1–§7.5, §9.

Measured on `fl-replay` on **2026-08-21**, against the live service. **Revision 2** — revision 1 of
this document reported that the archive was overwritable. It is not; the probe that said so could not
tell the difference. §3.4 records how, because that error is the most useful thing in this document.

Every claim below has a command behind it in §6. Where a claim rests on something other than a
command's output, it says so.

This repo is public, so identifiers are `${GCP_PROJECT}`, `${INSTANCE_SA}` (the GCE default service
account) and `${BUCKET}` (`${GCP_PROJECT}-flabel-pcaps`). Published object names carry the monitored
host's address, so they appear as `LABELED_capture_<date>_pub-<addr>_<ts>.tar.gz`; object generations
are `<generation>`, because a generation is a microsecond timestamp and would pin a real run's publish
time. **Those placeholders are local to this file.** The real project id, project number and service
account are already committed in plaintext elsewhere in this repo — see §5.

---

## 1. The dataset already existed

**It was not created by this step.** It was made on **2026-08-20 18:33:21 UTC** during LS-3's live
round trip, and nobody wrote it down — which is the gap this document closes. LS-6's remaining work
was therefore verification.

| Fact | Value |
| :-- | :-- |
| Dataset | `${GCP_PROJECT}.flabel` |
| Location | **`us-central1`** — as spec §4 requires, and immutable once set |
| Created / last modified | 2026-08-20 18:33:21 UTC / 18:33:52 UTC |
| Description | `flabel label store — derived index over gs://${BUCKET}/results. Phase 3, docs/spec-label-store.md` |
| Tables | **none** |

`flabel` holding no tables is the correct state at the end of LS-6. `flabel-db apply` is LS-3's tool;
§3.5 records what `verify` says in the meantime, and §5 records that **no step currently owns running
`apply` against `flabel`**. `flabel_scratch`, the dataset LS-3 was developed against, is also
`us-central1` and holds all five tables plus the `authoritative_runs` view.

---

## 2. The grants

Spec §7.3's table, against what is actually held:

| Principal | Required role | Present as | How it was verified |
| :-- | :-- | :-- | :-- |
| `${INSTANCE_SA}` | `bigquery.dataEditor` on the dataset | `WRITER  userByEmail=${INSTANCE_SA}` | **behaviourally** — a load job landed rows (§3.2) |
| `${INSTANCE_SA}` | `bigquery.jobUser` on the project | `roles/bigquery.jobUser`, held explicitly | project IAM policy, and §3.2 |
| `craig@deeptempo.ai` | `bigquery.dataOwner` on the dataset | `OWNER  userByEmail=craig@deeptempo.ai` | **ACL read only — not exercised.** See §5 |
| readers | `bigquery.dataViewer` | **deliberately absent** | — |

The `dataOwner` row is the weak one, and calling it verified would be the very thing §7.3 exists to
prevent. Nothing in this step ran `flabel-db apply` against `flabel`, so "`apply` needs `dataOwner`"
is still an inference from a role name. It may be wrong in the permissive direction: `dataEditor`
grants `tables.create` and `tables.update`, so the SA's `WRITER` entry is plausibly sufficient — which
matters, because the human credential on that box expires non-interactively (§7.1's failure mode, met
twice while writing this).

`dataViewer` is missing on purpose. Spec §9 lists "who may read the dataset" as open: Phase 3 puts
non-anonymous network metadata — Zeek's DNS names, HTTP URIs, TLS server names — into BigQuery, and
`docs/spec.md` §13's standard is that a new destination for it is a decision somebody writes down.
Nobody has. Granting a reader role here would have made that decision by momentum.

**In BigQuery the instance SA holds `roles/bigquery.jobUser` and nothing else at project level**, so
§7.3's least-privilege table is satisfied as written rather than bypassed by a broad role.

An earlier draft suspected the opposite, reasoning that the account can also *list* datasets, which
`jobUser` and `dataEditor` do not grant between them. **That reasoning was wrong**, and it is kept
because the conclusion it nearly reached — that the store's access control was being bypassed — was
far more serious than the truth. `datasets.list` returns the datasets the caller already has an ACL
on, and the SA has an explicit `WRITER` entry on both `flabel` and `flabel_scratch`. It enumerates
nothing project-wide; it returned exactly those two.

So the explicit `userByEmail` binding is **not** redundant. With no project BigQuery role beyond
`jobUser`, it is the only thing granting the SA write access to the store.

Outside BigQuery the same account holds `compute.instanceAdmin.v1`, `compute.viewer` and
`iam.serviceAccountUser`. Out of scope here, and recorded because "the instance service account is
narrowly scoped" would be the wrong thing to carry away from the BigQuery half alone.

**The dataset ACL also carries the three default project groups** — `WRITER specialGroup=projectWriters`,
`OWNER specialGroup=projectOwners`, `READER specialGroup=projectReaders`. These are BigQuery's
defaults, and they are not nothing: **anyone holding project Editor is a writer on the label store**
without appearing in the ACL by name. Least privilege at the dataset is bounded by project roles, not
by this ACL. Filed as #161.

---

## 3. Verification, in both directions

Run as `${INSTANCE_SA}` — the identity ingestion actually uses — except where §6 marks otherwise.
Spec §7.1 names that credential rather than discovering it, and §7.2's measurement (no `sudo` needed,
because the metadata server is not user-scoped) is what makes these runnable as the unprivileged user.

### 3.1 The archive is readable

`results/` lists **25 objects**, and a published tarball's metadata reads back.

Bucket *listing* is refused — `403, storage.buckets.list denied`. Correct and expected: §7.2 measured
the grant as `objectCreator` + `objectViewer` at the **bucket** level with no project-level storage
role, and object access does not imply bucket enumeration.

The bucket reads as `location: US-CENTRAL1`, `location_type: region` — the measurement spec §10 M4
rests on, and therefore why the dataset's location in §1 is not a free choice.

### 3.2 A load job succeeds

A load job as `${INSTANCE_SA}` into a throwaway `${GCP_PROJECT}.flabel._provision_probe`:
`state=DONE`, `errors=None`, `output_rows=2`, `location=us-central1`, and the two rows read back. The
probe table was dropped immediately and `flabel` is empty again.

A throwaway table rather than `runs`, deliberately: proving the grant does not require a synthetic row
in the store, and spec §2.2 permits deletes in two named cases of which "cleaning up after a smoke
test" is not one. **`flabel_scratch` would have been the better venue** — an undeclared table left
behind in `flabel` would be invisible to `verify` forever, because `client.live_schema` asks per
*declared* table. The cleanup is asserted by §1's "Tables: none", which is a command in §6.

That the job ran at all is the `jobUser` evidence — `dataEditor` does not grant `bigquery.jobs.create`.
A bare `SELECT 1` also succeeded, in `us-central1`.

### 3.3 Deleting a published tarball is refused

```
HTTPError 403: ${INSTANCE_SA} does not have storage.objects.delete access
to the Google Cloud Storage object.
```

### 3.4 Overwriting is refused too — and revision 1 of this document said otherwise

**The archive is protected against replacement, exactly as the plan claimed and as
`docs/status.yaml` records it was designed to be.** That entry (2026-08-19) says `objectCreator` was
granted with Craig's approval because it is "create but not overwrite or delete, which matches spec
§13's never-modify-a-previous-run rule and means a repeated run cannot silently replace a published
result." Revision 1 contradicted an approved design decision and did not cite it.

The error is worth more than the result. Revision 1 probed with
`cp --if-generation-match=0` against an existing object, got `412`, and concluded the overwrite was
*permitted and merely blocked by the precondition*. **`412` could not have meant anything else.**
`ifGenerationMatch=0` means "only if no live object exists"; against an existing object that
precondition fails and is evaluated **before** the overwrite permission is consulted. The probe
returns `412` in both worlds. It was not an instrument.

The discriminating probe is a precondition that **matches**, so nothing masks the permission check.
Run against a disposable object the SA created itself, the truth table is:

| Principal | Precondition | Result |
| :-- | :-- | :-- |
| `${INSTANCE_SA}` | mismatched | `412` |
| **`${INSTANCE_SA}`** | **matching** | **`403` — `storage.objects.delete` denied** |
| human (holds delete) | mismatched | `412` |
| human (holds delete) | matching | **succeeds** — content replaced, new generation |

The bottom two rows are the positive control: they prove `412` and `403` are distinguishable answers
from this instrument, and that the instrument can register a permitted overwrite when there is one.
Without them the `403` above would be one more uncorroborated code.

So `roles/storage.objectCreator` **is** a create-but-do-not-replace grant. Revision 1's claim that
"GCS has no create-but-do-not-replace permission" was false: replacing an object requires
`storage.objects.delete`, which §3.3 shows the SA does not hold anywhere.

**What generalises.** Revision 1's probe was designed to be *safe*, and the precondition that made it
safe is the same thing that made it blind — a guard that prevents the operation also prevents the
measurement. A refusal-shaped result from a probe that cannot succeed proves nothing, and needs a
positive control before it can be believed.

Issue **#158** was filed on revision 1's reading and is **closed as invalid**.

**Soft delete is a seven-day backstop, and it is a GCS default rather than a control anyone chose.**
The bucket carries `softDeletePolicy.retentionDurationSeconds = 604800`; object versioning is not
enabled and there is no retention policy. It now matters only for a principal that *does* hold delete
— a project editor, or the human — not for the ingestion identity.

### 3.5 The location requirement, checked by the tool that will keep checking it

`flabel-db --dataset flabel verify` exits **1** and reports the five declared tables as missing —
correct, and expected until `apply` runs. What matters here is the line it does **not** print:
`_verify` compares the live dataset's location against `client.LOCATION` and said nothing, so the real
dataset is `us-central1` as read by the code that gates deploys.

That silence is evidence only because the branch demonstrably fires:
`tests/test_flabeldb_schema.py::test_a_dataset_in_the_wrong_location_is_drift` pins it against
`us-east1`.

The check cannot be deferred. A dataset's location is immutable, the results bucket is `US-CENTRAL1`
*regional* so a load job needs a compatible dataset, and BigQuery job ids are namespaced
`project:location.jobid` — so the location is part of the idempotency namespace (spec §10 M2, M4).

---

## 4. The sabotage round

The plan's DoD asks for one per step, and revision 1 claimed a docs-only step has no guard to invert.
That was a gap, not an argument: the instrument *is* the guard here, and it can be inverted.

| Inversion | Expectation | Result |
| :-- | :-- | :-- |
| Run the overwrite probe as a principal that **holds** `storage.objects.delete` | a different answer than the SA gets, or the probe is not measuring permission | **caught the defect** — the human overwrite succeeds where the SA gets `403`, and revision 1 had no such control |
| Give the overwrite probe a **matching** generation instead of `0` | if `412` was about permission it should stay `412` | `403`. This is what invalidated #158 |
| `flabel-db --dataset <absent> verify` | must read differently from "tables missing" | distinct branch, distinct message — `_verify` handles `NotFound` on the dataset separately from a missing table |

The first two are the round that mattered, and they went red. Recorded rather than smoothed over,
because a sabotage that changes the conclusion is the mechanism working.

---

## 5. Open, and not decided here

- **Project Editors are writers on the store** (#161, §2). Verified and uncontested. Either accept it
  in spec §9 or narrow the dataset ACL.
- **The real identifiers are committed in plaintext on this public repo** (#162).
  `docs/spec-label-store.md`, `docs/status.yaml`, `tools/flabel-run`, `tests/test_flabeldb_schema.py`,
  `docs/phase-2-reachability-spike.md` and `docs/RESUME-ls-3.md` carry the project id and the full
  default-compute service-account email, against `CLAUDE.md`'s guardrail and `.env.example`'s own
  instruction. This file's placeholders do not change that, which is why the preamble says so.
- **No step owns running `flabel-db apply` against `flabel`** (§1, §2). It is not in LS-4's file list,
  and LS-2 ships `flabel-db verify` as a pre-deploy gate — which exits 1 against `flabel` today. So
  merging LS-2 before somebody applies gives a deploy script that refuses to deploy. Needs an owner.
- **`flabel-db show` misreports an empty provisioned dataset** (#159). Against `flabel` it exits **3**
  (`EXIT_INTERNAL`) on `NotFound: Table ... flabel.runs`, printing "This is a DEFECT in flabel-db."
  That state is ordinary between LS-6 and LS-4. `_verify` handles the same case correctly. LS-3's
  file, so not fixed here.
- **LS-6 is not what unblocks LS-4's live tests.** The plan resequenced this step before LS-4 because
  "LS-4's three most important tests… need the dataset and grants LS-6 provisions." But
  `tests/test_flabeldb_live.py` *refuses* to run against `flabel` — it deletes and recreates tables —
  and defaults to `flabel_scratch`, which already existed. What LS-6 actually delivers to LS-4 is the
  grant verification, not the dataset. A third stale premise, found in review rather than by me.
- **Who may read the dataset** (§2, spec §9). Still nobody's decision.

---

## 6. Reproducing this

`.env` does not exist on the box, so `GCP_PROJECT` is not in the environment. Global flags precede the
subcommand.

**Never probe a real published object.** Revision 1 did, and the reasoning that made it safe was also
what made it blind (§3.4). It was unsafe in a second way: `--if-generation-match=0` blocks the write
only if the named object *exists*, so a mistyped or stale object name makes the precondition
**succeed** and writes junk into the published `results/` prefix — a write to the archive, which spec
§9 forbids and which LS-4 and LS-8 would then fetch and untar. `results/` already holds a soft-deleted
`LABELED_iamcheck_<ts>.tar.gz` from an earlier IAM probe, so this has happened before. Probe a
disposable object under a non-`results/` prefix, and delete it afterwards.

```bash
export GCP_PROJECT=...            # never committed; see .env.example
SA=...                            # ${INSTANCE_SA}
B="gs://${GCP_PROJECT}-flabel-pcaps"

# §3.1  read, and the expected refusal of bucket listing
gcloud storage ls "$B/results/" --account=$SA
gcloud storage ls --account=$SA                       # 403, storage.buckets.list

# §3.3 / §3.4  the discriminating probe, on a disposable object.
# The SA can create; a MATCHING precondition is what exposes the overwrite permission.
echo v1 > /tmp/v1; echo v2 > /tmp/v2
gcloud storage cp /tmp/v1 "$B/_provision-probe/t.txt" --account=$SA
GEN=$(gcloud storage objects describe "$B/_provision-probe/t.txt" \
        --account=$SA --format="value(generation)")
gcloud storage cp /tmp/v2 "$B/_provision-probe/t.txt" \
        --if-generation-match="$GEN" --account=$SA     # 403 -> cannot replace
gcloud storage rm "$B/_provision-probe/t.txt"          # as the HUMAN; the SA cannot delete

# §4  the positive control, WITHOUT which the 403 above proves nothing.
# As the human, who holds storage.objects.delete: mismatched -> 412, matching -> succeeds.

# §3.5  location and table state, through the tool the deploy gate uses
uv run --no-sync flabel-db --dataset flabel verify

# §1, §2, §3.2  dataset facts, ACL, and the load job — through the named-credential path
#               production uses, not through `bq`, whose per-user credential store is what
#               §7.1 measured as needing sudo.
uv run --no-sync python - <<'PY'
from google.cloud import bigquery
from flabeldb import client as c
bq = c.client()
d = bq.get_dataset(f"{bq.project}.flabel")
print(d.location, d.created, d.modified, d.description)
for e in d.access_entries:
    print(e.role, e.entity_type, e.entity_id)
print("tables:", [t.table_id for t in bq.list_tables(d)])
print("query:", [dict(r) for r in bq.query("SELECT 1 AS ok").result()])

tid = f"{bq.project}.flabel._provision_probe"      # prefer flabel_scratch; see §3.2
cfg = bigquery.LoadJobConfig(
    source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
    schema=[bigquery.SchemaField("probe", "STRING"), bigquery.SchemaField("n", "INT64")],
    write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
)
with open("/tmp/probe.ndjson", "rb") as fh:        # {"probe":"ls-6","n":1} x2
    job = bq.load_table_from_file(fh, tid, job_config=cfg, location=c.LOCATION)
job.result()
print(job.state, job.errors, job.output_rows, job.location)
bq.delete_table(tid)
PY

# §2, §3.4  these need the HUMAN credential — the SA can read neither.
# `gcloud auth login` first; a stale token fails non-interactively, which is §7.1's own
# failure mode and the reason these were the last things measured.
gcloud projects get-iam-policy "$GCP_PROJECT" \
  --flatten="bindings[].members" --filter="bindings.members:$SA" \
  --format="value(bindings.role)"
gcloud storage buckets describe "$B" \
  --format="yaml(location,location_type,versioning,retention_policy,soft_delete_policy)"
gcloud storage ls --soft-deleted "$B/results/**"
```
