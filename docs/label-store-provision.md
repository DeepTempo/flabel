# Provisioning the label store — dataset, IAM, and what was verified

Step **LS-6** (#149) of `docs/PLAN-label-store.md`. Spec: `docs/spec-label-store.md` §4, §7.1–§7.3, §9.

Measured on `fl-replay` on **2026-08-21**, against the live service. Every claim below is the output of
a command in §6, not a reading of a role name — which is the whole point of the step, because
revision 1 of the plan specified GCS IAM carefully and *inferred* the BigQuery half, and §7.3 was
written to stop that happening twice.

This repo is public, so identifiers are `${GCP_PROJECT}`, `${INSTANCE_SA}` (the GCE default service
account, `${PROJECT_NUMBER}-compute@developer.gserviceaccount.com`) and `${BUCKET}`
(`${GCP_PROJECT}-flabel-pcaps`). Published object names carry the monitored host's address, so they
appear here as `LABELED_capture_<date>_pub-<addr>_<ts>.tar.gz`.

---

## 1. Two of the plan's premises were already stale

**The dataset was not created by this step. It already existed**, made on **2026-08-20 18:33:21 UTC**
during LS-3's live round trip, and nobody wrote it down — which is the gap this document closes.
LS-6's remaining work was therefore verification, and verification is what found the two corrections
in §4.

| Fact | Value |
| :-- | :-- |
| Dataset | `${GCP_PROJECT}.flabel` |
| Location | **`us-central1`** — as spec §4 requires, and immutable once set |
| Created / last modified | 2026-08-20 18:33:21 UTC / 18:33:52 UTC |
| Description | `flabel label store — derived index over gs://${BUCKET}/results. Phase 3, docs/spec-label-store.md` |
| Tables | **none** |

`flabel` holding no tables is correct at the end of LS-6 and is not drift-to-be-fixed here.
`flabel-db apply` is LS-3's tool and the tables are LS-4's business; §3.5 records what `verify` says
in the meantime. `flabel_scratch`, the scratch dataset LS-3 was developed against, is also
`us-central1` and holds all five tables plus the `authoritative_runs` view.

---

## 2. The grants

Spec §7.3's table, against what the dataset's ACL actually carries:

| Principal | Required role | Present as | Verified by |
| :-- | :-- | :-- | :-- |
| `${INSTANCE_SA}` | `bigquery.dataEditor` on the dataset | `WRITER  userByEmail=${INSTANCE_SA}` | §3.2 — a load job landed rows |
| `craig@deeptempo.ai` | `bigquery.dataOwner` on the dataset | `OWNER  userByEmail=craig@deeptempo.ai` | ACL read |
| `${INSTANCE_SA}` | `bigquery.jobUser` on the project | `roles/bigquery.jobUser`, **held explicitly** | project IAM policy, and §3.2 — a query job and a load job both ran |
| readers | `bigquery.dataViewer` | **deliberately absent** | — |

`dataViewer` is missing on purpose. Spec §9 lists "who may read the dataset" as open and undecided:
Phase 3 puts non-anonymous network metadata — Zeek's DNS names, HTTP URIs, TLS server names — in
BigQuery, and `docs/spec.md` §13's standard is that a new destination for it is a decision somebody
writes down. Nobody has. Granting a reader role here would have quietly made that decision.

**The ACL also carries the three default project groups** — `WRITER specialGroup=projectWriters`,
`OWNER specialGroup=projectOwners`, `READER specialGroup=projectReaders`. These are BigQuery's
defaults on any new dataset, and they are not nothing: anyone holding project **Editor** has `WRITER`
on the store without appearing in it by name. Least privilege at the dataset is therefore bounded by
project-level roles, not by this ACL.

**In BigQuery the instance SA holds `roles/bigquery.jobUser` at the project level and nothing
else** — read from the project IAM policy, so §7.3's table is satisfied as written rather than
bypassed by a broad role.

An earlier draft of this document suspected the opposite, on the reasoning that the account can also
*list* datasets, which `jobUser` and `dataEditor` do not grant between them. **That reasoning was
wrong**, and it is recorded because the conclusion it nearly reached — that the store's access control
was being bypassed — was much more serious than the truth. `datasets.list` returns the datasets the
caller already has access to, and the SA holds an explicit `WRITER` entry on both `flabel` and
`flabel_scratch`; the call enumerates nothing project-wide. It returned exactly those two.

So the explicit `userByEmail` binding is **not** redundant. With no project-level BigQuery role beyond
`jobUser`, it is the only thing granting the SA write access to the store, and removing it would stop
ingestion.

Outside BigQuery the same account holds `compute.instanceAdmin.v1`, `compute.viewer` and
`iam.serviceAccountUser` at the project level. Out of scope for this step, and recorded because "the
instance service account is narrowly scoped" would be the wrong conclusion to carry away from the
BigQuery half on its own.

---

## 3. Verification, in both directions

Run as `${INSTANCE_SA}` — the identity ingestion actually uses. Spec §7.1 names that credential
rather than discovering it, and §7.2's measurement (no `sudo` needed, because the metadata server is
not user-scoped) is what makes these runnable as the unprivileged user.

### 3.1 The archive is readable — the direction ingest depends on

`results/` lists, and a published tarball's metadata reads back: **25 objects**, and the object used
throughout §3 is **3,136,681 bytes, generation `1787169551649296`**.

Bucket *listing* is refused — `403, storage.buckets.list denied`. Correct and expected: §7.2 measured
the grant as `objectCreator` + `objectViewer` at the **bucket** level with no project-level storage
role, and object access does not imply bucket enumeration.

The bucket reads as `location: US-CENTRAL1`, `location_type: region` — which is the measurement spec
§10 M4 rests on, and therefore the reason the dataset's location in §1 is not a free choice.

### 3.2 A load job succeeds — the direction ingest depends on

A load job as `${INSTANCE_SA}` into a throwaway `${GCP_PROJECT}.flabel._provision_probe`:
`state=DONE`, `errors=None`, `output_rows=2`, `location=us-central1`, and the two rows read back.
**The probe table was dropped immediately afterwards and `flabel` is empty again.**

A throwaway table rather than `runs`, deliberately: proving the grant does not require putting a
synthetic row in the store, and spec §2.2 permits update and delete only in two named cases, neither
of which is "cleaning up after a smoke test".

That the job ran at all is the `jobUser` evidence — `dataEditor` does not grant `bigquery.jobs.create`.
A bare `SELECT 1` also succeeded, in `us-central1`.

### 3.3 Deleting a published tarball is refused — as it must be

```
HTTPError 403: ${INSTANCE_SA} does not have storage.objects.delete access
to the Google Cloud Storage object.
```

**The probe cannot destroy anything, by construction.** `--if-generation-match=1` cannot match a real
generation, so an IAM-permitted delete would return `412` and a refused one returns `403` — the object
is untouched either way, and the distinction between the two answers is the whole measurement. Its
size and generation were re-read afterwards and are unchanged.

### 3.4 Overwriting a published tarball is **permitted** — and the plan said it was refused

```
HTTPError 412: At least one of the pre-conditions you specified did not hold.
```

`412`, not `403`. **The service account is allowed to overwrite any published tarball.** The only thing
that stopped the write was the `--if-generation-match=0` precondition chosen for the probe; without
it, that object would now be a 34-byte text file instead of a 3 MB archive.

This is not an IAM oversight that a narrower role would fix, because **no such role exists**. GCS has
no create-but-do-not-replace permission: `roles/storage.objectCreator` grants
`storage.objects.create`, and a create against an existing name *replaces* it. `objectCreator` is
required for `flabel-run` to publish at all. So the delete refusal in §3.3 buys less than it appears
to — the archive is protected against erasure and **not** against replacement.

Why it matters beyond this step: spec §9 says the store must never "write to the archive"; §2.5 treats
the published tarball as the durable record of a run, the one that carries no exit code; and LS-4 and
LS-8 both *re-read* tarballs, with reproducibility resting on `capture_sha256` recomputed from them.
An overwritable archive means a published run's bytes are not immutable. `tools/flabel-run` publishes
under a timestamped name with a plain copy, so a name collision replaces silently rather than failing.

**Soft delete bounds the damage to seven days, and it is the only thing that does.** The bucket
carries `softDeletePolicy.retentionDurationSeconds = 604800`, effective 2026-08-17. Object
**versioning is not enabled, and there is no retention policy.** Soft delete retains the generation an
overwrite or a delete displaced, so a replaced tarball is restorable — for seven days, and only if
somebody notices inside them. Verified live rather than read off the policy: `results/` currently holds
one soft-deleted generation, `LABELED_iamcheck_<ts>.tar.gz#<generation>`, left by an IAM probe on
2026-08-19.

That changes the shape of the exposure without removing it. It is not permanent loss; it is **silent**
loss with a seven-day window and nothing watching. Since nothing compares a re-read tarball against
what was published, the seven days would elapse unnoticed.

Not fixed here. Nothing in LS-6's file list can fix it, and the candidate fixes belong elsewhere:
object versioning or a retention policy on `${BUCKET}` (infrastructure), or publishing with
`--if-generation-match=0` so a collision is an error (`tools/flabel-run`, which is LS-5's file).
Recorded as a finding (**#158**) rather than repaired out of scope — see §5.

### 3.5 The location requirement, checked by the tool that will keep checking it

`flabel-db --dataset flabel verify` exits **1** and reports the five declared tables as missing —
correct, and expected until LS-4. What matters here is the line it **does not** print: `_verify`
compares the live dataset's location against `client.LOCATION` and said nothing, so the real dataset
is `us-central1` as read by the code that gates deploys, not merely as read by this document.

That check cannot be deferred. A dataset's location is immutable, the results bucket is
`US-CENTRAL1` *regional* so a load job needs a compatible dataset, and BigQuery job ids are namespaced
`project:location.jobid` — so the location is part of the idempotency namespace (spec §10 M2, M4).

---

## 4. Corrections to the plan and the spec

1. **"An overwrite and a delete are still refused" is half wrong** (plan, LS-6). The delete is
   refused; the overwrite is permitted. §3.4.
2. **The dataset and both dataset-scoped grants already existed** before this step, from 2026-08-20.
   LS-6 as written reads as though it creates them. §1.

Neither is edited into the plan by this step — the plan is amended in its own revision, and this
document is the measurement it would be amended from.

---

## 5. Open, and not decided here

- **The archive's mutability** (#158, §3.4). Soft delete gives seven days; versioning, a retention
  policy and a publisher-side precondition are the durable options — the first two are infrastructure
  and the third is LS-5's file. Not LS-6's decision to make.
- **`flabel-db show` misreports an empty provisioned dataset.** Against `flabel` it exits **3**
  (`EXIT_INTERNAL`) on `NotFound: Table ... flabel.runs`, printing "This is a DEFECT in flabel-db,
  not a report about flabel." A provisioned dataset whose tables do not exist yet is an ordinary
  operator state between LS-6 and LS-4, not a defect. `_verify` handles exactly this case correctly
  and says the tables are missing; `_show` should too. LS-3's file, so not fixed here — **#159**.
- **Who may read the dataset** (§2, spec §9). Still nobody's decision.

---

## 6. Reproducing this

`.env` does not exist on the box, so `GCP_PROJECT` is not in the environment and every `flabel-db`
invocation must carry it. Global flags precede the subcommand.

```bash
export GCP_PROJECT=...            # never committed; see .env.example
SA=...                            # ${INSTANCE_SA}
OBJ=gs://${GCP_PROJECT}-flabel-pcaps/results/LABELED_capture_<date>_pub-<addr>_<ts>.tar.gz

# §3.1  read, and the expected refusal of bucket listing
gcloud storage ls "gs://${GCP_PROJECT}-flabel-pcaps/results/" --account=$SA
gcloud storage objects describe "$OBJ" --account=$SA \
  --format="value(size,generation)"
gcloud storage ls --account=$SA                     # 403, storage.buckets.list

# §3.3  delete: 403 = refused by IAM, 412 = permitted but precondition blocked
gcloud storage rm "$OBJ" --if-generation-match=1 --account=$SA

# §3.4  overwrite: same reading of the two codes
gcloud storage cp ./any-small-file "$OBJ" --if-generation-match=0 --account=$SA

# §3.5  location and table state, through the tool the deploy gate uses
uv run --no-sync flabel-db --dataset flabel verify

# §2 and §3.4 need the HUMAN credential, not the SA — the SA cannot read either.
# `gcloud auth login` first; a stale token fails non-interactively, which is §7.1's own
# failure mode and the reason these two were the last things measured.
gcloud projects get-iam-policy "$GCP_PROJECT" \
  --flatten="bindings[].members" --filter="bindings.members:$SA" \
  --format="value(bindings.role)"
gcloud storage buckets describe "gs://${GCP_PROJECT}-flabel-pcaps" \
  --format="yaml(location,location_type,versioning,retention_policy,soft_delete_policy)"
gcloud storage ls --soft-deleted "gs://${GCP_PROJECT}-flabel-pcaps/results/**"
```

The dataset ACL, the query job and the load-job probe of §3.2 were driven through
`flabeldb.client.client()` — the same named-credential path production uses — rather than through
`bq`, whose per-user credential store is what §7.1 measured as needing `sudo`.

**Do not drop `--if-generation-match` from the two probes.** It is not a detail of how they were run;
it is the reason running them against a real published tarball is safe.
