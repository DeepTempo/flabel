# Provisioning the label store — dataset, IAM, and what was verified

Step **LS-6** (#149) of `docs/PLAN-label-store.md`. Spec: `docs/spec-label-store.md` §1, §4, §7.1–§7.5, §9.

Measured on the replay box on **2026-08-21/22**, against the live service.

**Revision 3.** Revision 1 reported the archive was overwritable; it is not, and §3.4 records why the
probe that said so could not have known. Revision 2 corrected that but shipped a §7 nobody could
execute. Both errors came from the same habit — asserting a measurement instead of making one — and
they are kept in the branch history rather than squashed, because that habit is what this document is
now partly about.

**What §7 is.** A reconstruction, not a transcript: the commands as they should be run, verified to be
runnable, with the identity each one needs. Where a claim below has no command, it says so inline
rather than being covered by a blanket promise. Revision 2 opened with "every claim has a command
behind it in §7" and that was false for six of them.

This repo is public. `${GCP_PROJECT}`, `${INSTANCE_SA}` (the GCE default service account),
`${OPERATOR}` (the human who runs `apply`) and `${BUCKET}` (`${GCP_PROJECT}-flabel-pcaps`) are
placeholders **local to this file**; the real values are committed in plaintext elsewhere in this repo
(#162). Object generations appear as `<generation>` because a generation is a microsecond timestamp
that would pin a real run's publish time. The box's hostname is *not* redacted — it is used repo-wide,
so hiding it here would be theatre; #162 covers it.

---

## 1. The dataset already existed

**It was not created by this step.** It was made on **2026-08-20 18:33:21 UTC** during LS-3's live
round trip, and nobody wrote it down — which is the gap this document closes. LS-6's remaining work
was therefore verification. §4 lists what this makes stale in the plan.

| Fact | Value |
| :-- | :-- |
| Dataset | `${GCP_PROJECT}.flabel` |
| Location | **`us-central1`** — as spec §4 requires, and immutable once set |
| Created / last modified | 2026-08-20 18:33:21 UTC / 18:33:52 UTC |
| Description | `flabel label store — derived index over gs://${BUCKET}/results. Phase 3, docs/spec-label-store.md` |
| Tables | **none** |

`flabel` holding no tables is the correct state at the end of LS-6, and §6 records that **no step owns
changing that** (#163). `flabel_scratch`, the dataset LS-3 was developed against, is also
`us-central1` and holds all five tables plus the `authoritative_runs` view.

---

## 2. The grants

Spec §7.3's table, against what is actually held:

| Principal | §7.3 requires | Actually held | How verified |
| :-- | :-- | :-- | :-- |
| `${INSTANCE_SA}` | `bigquery.dataEditor` on the dataset | `WRITER  userByEmail=${INSTANCE_SA}` | **behaviourally** — a load job landed rows (§3.2) |
| `${INSTANCE_SA}` | `bigquery.jobUser` on the project | `roles/bigquery.jobUser`, held explicitly | project IAM policy, and §3.2 |
| whoever runs `apply` | `bigquery.dataOwner` on the dataset | `OWNER userByEmail=${OPERATOR}` exists — **but is not required** | **behaviourally** — see below |
| readers | `bigquery.dataViewer` | **deliberately absent** | — |

**§7.3 over-specifies the third row, and that is a useful result rather than a nitpick.** `apply` was
run as `${INSTANCE_SA}` — which holds `WRITER`, not `OWNER` — against `flabel_scratch`, and exited
`0`, patching five tables and replacing the view. The full creation and deletion path was then
exercised by the 16 `requires_bigquery` tests, which `delete_table` and `create_table` directly and
call `cli._apply`: **16 passed** as the service account.

So `dataEditor` is sufficient for `apply`, and the deploy path does **not** need a human credential on
the box. That matters because `docs/status.yaml` (2026-08-19) records that putting a human credential
on a shared VM was **rejected** — "a refresh token on a lab box outlives the session and is not
attributable to a person acting" — and because that credential expires non-interactively (spec §7.1's
own failure mode, hit twice while writing this). A deploy gate that needed it would be a gate that
stalls on a browser login. Spec §7.3 should be narrowed to `dataEditor`, or say why `dataOwner` is
wanted anyway.

`dataViewer` is missing on purpose. Spec §9 lists "who may read the dataset" as open: Phase 3 puts
non-anonymous network metadata — Zeek's DNS names, HTTP URIs, TLS server names — into BigQuery, and
`docs/spec.md` §13's standard is that a new destination for it is a decision somebody writes down.
Nobody has. Granting a reader role here would have made that decision by momentum.

**In BigQuery the instance SA holds `roles/bigquery.jobUser` and nothing else at project level**, so
§7.3's least-privilege intent is met rather than bypassed by a broad role.

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

### 2.1 The default ACL groups, and how big that actually is

The dataset ACL also carries BigQuery's three defaults — `WRITER specialGroup=projectWriters`,
`OWNER specialGroup=projectOwners`, `READER specialGroup=projectReaders`. So project-level roles can
confer store access without appearing in the ACL by name (#161).

**Measured rather than left as a scare:** nobody holds `roles/editor` on this project, so
`projectWriters` is currently **empty**. The only broad grants are two `roles/owner` — the two people
who run the project. #161 is therefore *structural* — the default admits a future Editor silently —
and not a live exposure. Revision 2 called it "verified and uncontested" on an ACL read alone,
without checking the population, which is the same standard it refused to accept for the `dataOwner`
row three rows above.

---

## 3. Verification, in both directions

Run as `${INSTANCE_SA}` — the identity ingestion actually uses — except where noted.

**On how the SA identity was assumed, because the repo records the opposite.** Spec §7.1 measured that
plain `gcloud storage ls` fails on this box ("Reauthentication failed. cannot prompt during
non-interactive execution") while `sudo gcloud` works, and concluded "`gcloud` needs root because its
credential store is per-user." That is true of the *active* account. It is not the only route:
`gcloud --account=${INSTANCE_SA}` selects the metadata-backed service-account credential and works
**unprivileged, without `sudo`** — measured throughout this step. `tools/flabel-run` uses `sudo`
instead, so nothing else in the repo exercises `--account`. Recorded because §7.1 as written would
predict every command in §7 fails.

### 3.1 The archive is readable

`results/` lists **25 objects** (2026-08-21; this count expires the moment another run publishes), and
a published tarball's metadata reads back — size and `<generation>`.

Bucket *listing* is refused: `403, storage.buckets.list denied`. Correct and expected — §7.2 measured
the grant as `objectCreator` + `objectViewer` at the **bucket** level with no project-level storage
role, and object access does not imply bucket enumeration.

The bucket reads as `location: US-CENTRAL1`, `location_type: region` — the measurement spec §10 M4
rests on, and therefore why the dataset's location in §1 is not a free choice.

### 3.2 A load job succeeds

A load job as `${INSTANCE_SA}`: `state=DONE`, `errors=None`, `output_rows=2`,
`location=us-central1`, and the two rows read back.

It ran into a throwaway table **in `flabel`**, which was the wrong venue and is corrected in §7 to
`flabel_scratch`. An undeclared table left behind in `flabel` would be invisible to `verify` forever,
because `client.live_schema` asks per *declared* table. It was dropped, and `flabel` lists no tables.

That the job ran at all is the `jobUser` evidence — `dataEditor` does not grant `bigquery.jobs.create`.
A bare `SELECT 1` also succeeded, in `us-central1`.

### 3.3 Deleting a published tarball is refused

```
HTTPError 403: ${INSTANCE_SA} does not have storage.objects.delete access
to the Google Cloud Storage object.
```

**That output came from a real published tarball**, probed with a generation guard before §7's
never-probe-a-published-object rule existed. §7 reproduces it against a disposable object instead,
which gives the same `403` from the same missing permission and cannot touch the archive.

### 3.4 Overwriting is refused too — and revision 1 said otherwise

**The archive is protected against replacement**, and this was **already a measured fact in the
repo before LS-6 started.** `docs/status.yaml` (2026-08-19):

> "objectCreator verified against the live bucket rather than assumed: `sudo gcloud storage cp`
> SUCCEEDED and the immediate re-upload of the same name was REFUSED for lack of
> `storage.objects.delete`. So the never-overwrite-a-published-result property is a measured fact,
> not an inference from the role name."

**That is the finding of this section, and it is not a happy one.** The question had been answered
three days earlier by a simpler and safer probe — no precondition, so it needed no positive control
and could not accidentally write — and revision 1 neither found it nor cited the approval entry
recording that `objectCreator` was granted *because* it is "create but not overwrite or delete." The
root cause was not a bad instrument. It was not reading the decision log.

The instrument was also bad. Revision 1 probed with `cp --if-generation-match=0` against an existing
object, got `412`, and read it as "permitted, and only the precondition stopped it." **`412` could
not have meant anything else.** `ifGenerationMatch=0` means "only if no live object exists"; against
an existing object the precondition fails, so the request never reaches the point where a replacement
would be authorised. The probe returns `412` whether or not the caller may replace.

The discriminating probe uses a precondition that **matches**. On a disposable object:

| Principal | Precondition | Result |
| :-- | :-- | :-- |
| `${INSTANCE_SA}` | mismatched | `412` |
| **`${INSTANCE_SA}`** | **matching** | **`403` — `storage.objects.delete` denied** |
| `${OPERATOR}` (holds delete) | mismatched | `412` |
| `${OPERATOR}` (holds delete) | matching | **succeeds** — content replaced, new generation |

The bottom two rows are the positive control: they show the instrument can register a permitted
overwrite, so the `403` is a refusal and not an artefact.

So `roles/storage.objectCreator` **is** a create-but-do-not-replace grant — documented as granting
`storage.objects.create` only, with replacement of a live object additionally requiring
`storage.objects.delete`. Revision 1's "GCS has no create-but-do-not-replace permission" was false.

**A narrower statement of the ordering, because the general form is wrong.** Revision 2 wrote that the
precondition is evaluated "before the overwrite permission is consulted", as a rule. §3.3 contradicts
that rule: a *delete* with a mismatched precondition returned `403`, not `412`. The consistent reading
is that the permission for the method actually requested is checked first — hence `403` on a delete
the SA may not perform — while the *implied* delete permission that an overwrite needs is only reached
if the precondition passes. Applying revision 2's general form would mispredict §3.3.

**What generalises.** A guard that prevents the operation also prevents the measurement. A
refusal-shaped result from a probe that cannot succeed proves nothing without a positive control — and
before building any instrument, read the decision log, because the answer may already be in it.

Issue **#158** was filed on revision 1's reading and is **closed as invalid**. What survives it is in
§6 and #164: the archive is writable by the two project Owners, and nothing detects a replacement.

**Soft delete is a seven-day backstop, and it is a GCS default rather than a control anyone chose.**
`softDeletePolicy.retentionDurationSeconds = 604800`; versioning is not enabled and there is no
retention policy. It is irrelevant to the ingestion identity and relevant to the two Owners.

### 3.5 The location requirement, checked by the tool that will keep checking it

`flabel-db --dataset flabel verify` exits **1** and reports the five declared tables as missing —
correct, and expected until `apply` runs. What matters is the line it does **not** print: `_verify`
compares the live dataset's location against `client.LOCATION` and said nothing.

That silence is evidence only because the branch demonstrably fires:
`tests/test_flabeldb_schema.py::test_a_dataset_in_the_wrong_location_is_drift` pins it against
`us-east1`.

`verify` compares `schema.TABLES` only, so a green `verify` says nothing about the
`authoritative_runs` view; §1's view claim rests on `list_tables`, not on `verify`.

The check cannot be deferred. A dataset's location is immutable, the results bucket is `US-CENTRAL1`
*regional* so a load job needs a compatible dataset, and BigQuery job ids are namespaced
`project:location.jobid` — so the location is part of the idempotency namespace (spec §10 M2, M4).

---

## 4. What this step makes stale in the plan

Recorded here because `docs/PLAN-label-store.md` is what the next implementer reads, and it still says
all three. **This document does not amend it** — that file is outside LS-6's file list, and LS-1 set
the precedent of amending the plan in place, so somebody should.

1. **"What changes — The `flabel` dataset in `us-central1`."** It already existed (§1). LS-6 as written
   reads as though it creates it.
2. **"Resequenced to precede LS-4, because LS-4's real tests need what this provisions."** False:
   `tests/test_flabeldb_live.py` *refuses* to run against `flabel` — it deletes and recreates tables —
   and defaults to `flabel_scratch`, which already existed. What LS-6 gives LS-4 is grant
   verification, not the dataset.
3. **"No GCS grant is needed."** True, but it was already established in spec §7.2 rather than found
   here.

---

## 5. The sabotage round

Revision 1 argued a docs-only step has no guard to invert. That was a gap, not an argument: the
instrument is the guard.

| Inversion | Expectation | Result |
| :-- | :-- | :-- |
| Run the overwrite probe as a principal that **holds** `storage.objects.delete` | a different answer than the SA gets, or the probe is not measuring permission | **caught the defect** — the operator's overwrite succeeds where the SA gets `403`; revision 1 had no such control |
| Give the overwrite probe a **matching** generation instead of `0` | if `412` was about permission it should stay `412` | `403`. This is what invalidated #158 |
| Run `apply` as the SA, which lacks `dataOwner` | should fail if §7.3's third row is a real requirement | exit `0`, and 16 live tests passed. §7.3 is over-broad (§2) |

The first two are the round that mattered, and they went red.

Not a sabotage, and listed separately so it is not miscounted as one: `flabel-db --dataset <absent>
verify` reads differently from "tables missing" (`nothing in it was read` versus `table is missing`),
both exiting `1` deliberately — `_verify`'s own comment says reporting missing tables for an absent
container would be "advice that cannot work". Revision 2 put this in the sabotage table; it is an
adjacent-behaviour check.

---

## 6. Open, and not decided here

- **The archive is writable by the two project Owners, and nothing detects a replacement** (#164).
  This is what survives #158's retraction. IAM protects the archive from the *ingestion identity*
  only; spec §2's append-only intent and LS-4/LS-8's re-read of published tarballs rest on bytes not
  changing, and no check compares a re-read tarball to what was published.
- **No step owns running `flabel-db apply` against `flabel`** (#163). Not in LS-4's file list, and
  LS-2 ships `verify` as a pre-deploy gate that exits 1 against `flabel` today — so merging LS-2
  first gives a deploy script that refuses to deploy. §2 removes the hard part: the SA can do it.
- **Project Editors would be writers on the store** (#161, §2.1). Structural, not live —
  `projectWriters` is empty today.
- **The real identifiers are committed in plaintext on this public repo** (#162), including the box's
  hostname, against `CLAUDE.md`'s guardrail and `.env.example`'s own instruction.
- **Spec §7.3's `dataOwner` row should be narrowed to `dataEditor`** (§2), or justified.
- **`flabel-db show` misreports an empty provisioned dataset** (#159) — exits `3` (`EXIT_INTERNAL`),
  printing "This is a DEFECT in flabel-db", for a state that is ordinary between LS-6 and LS-4.
  LS-3's file.
- **Who may read the dataset** (§2, spec §9). Still nobody's decision.

---

## 7. Reproducing this

A reconstruction, not a transcript — see the preamble. `gcloud` needs `--project` because
exporting a shell variable does not set gcloud's config. Global `flabel-db` flags precede the
subcommand.

**Superseded 2026-08-24**: this section used to open "`.env` does not exist on the box, so
`GCP_PROJECT` is not in the environment", and that was true when written. It is no longer — the
first `flabel-deploy` run found that its own pre-deploy gate could not resolve a project, and
`export GCP_PROJECT=` was added to `/var/lib/flabel/flabel.env` (the box config, not `.env`, which
still does not exist there). `flabel-db verify` now passes on the box without a `--project` flag.
The interactive commands below still pass one, because a shell here does not source that file.

**Never probe a real published object.** Beyond destruction, `--if-generation-match=0` blocks a write
only if the named object *exists* — so a mistyped or stale name makes the precondition **succeed** and
writes junk into the published `results/` prefix, which spec §9 forbids and LS-4 would later fetch and
untar. `results/` already holds a soft-deleted `LABELED_iamcheck_<ts>.tar.gz` from an earlier probe,
so this has happened. Probe a disposable object outside `results/`.

**The two `gcloud` reads at the end need the human credential.** `docs/status.yaml` (2026-08-19)
records that a human credential on this shared box was *rejected* — a refresh token outlives the
session and is not attributable — so revoke it afterwards, or run those two from a laptop.

```bash
set -euo pipefail
P=...                             # ${GCP_PROJECT}; never committed, see .env.example
SA=...                            # ${INSTANCE_SA}
B="gs://${P}-flabel-pcaps"
export GCP_PROJECT="$P"

# --- as the SERVICE ACCOUNT. --account selects the metadata-backed credential, so no sudo
#     is needed despite spec §7.1's note about gcloud's per-user credential store (§3).

# §3.1  read, metadata read, and the expected refusal of bucket listing
gcloud storage ls "$B/results/" --account=$SA
gcloud storage ls "$B/results/" --account=$SA | head -1 | xargs -I{} \
  gcloud storage objects describe {} --account=$SA --format="value(size,generation)"
gcloud storage ls --project="$P" --account=$SA          # 403, storage.buckets.list

# §3.3 / §3.4  the discriminating probe, on a DISPOSABLE object outside results/.
echo v1 > /tmp/v1; echo v2 > /tmp/v2
gcloud storage cp /tmp/v1 "$B/_provision-probe/t.txt" --account=$SA
GEN=$(gcloud storage objects describe "$B/_provision-probe/t.txt" \
        --account=$SA --format="value(generation)")
test -n "$GEN"
gcloud storage rm "$B/_provision-probe/t.txt" --if-generation-match="$GEN" --account=$SA || true
        # 403 storage.objects.delete  -> §3.3's refusal, safely
gcloud storage cp /tmp/v2 "$B/_provision-probe/t.txt" \
        --if-generation-match="$GEN" --account=$SA || true
        # 403 storage.objects.delete  -> §3.4: cannot replace

# §5  THE POSITIVE CONTROL, without which the two 403s above prove nothing.
#     As the OPERATOR, who holds storage.objects.delete. Run BEFORE the cleanup below.
gcloud storage cp /tmp/v2 "$B/_provision-probe/t.txt" --if-generation-match=1 || true  # 412
gcloud storage cp /tmp/v2 "$B/_provision-probe/t.txt" --if-generation-match="$GEN"     # succeeds
gcloud storage objects describe "$B/_provision-probe/t.txt" --format="value(generation)"
gcloud storage rm "$B/_provision-probe/t.txt"          # cleanup; the SA cannot do this

# §3.5, §5  verify against the real dataset, and against an absent one
uv run --no-sync flabel-db --dataset flabel verify              || true   # exit 1, tables missing
uv run --no-sync flabel-db --dataset flabel_absent_probe verify || true   # exit 1, "nothing read"
uv run --no-sync flabel-db --dataset flabel show                || true   # exit 3, #159

# §2  apply needs only dataEditor: run it AS THE SA, and then the full create/delete path
uv run --no-sync flabel-db --dataset flabel_scratch apply
uv run --no-sync pytest -q tests/test_flabeldb_live.py --bigquery

# §1, §2, §3.2  dataset facts, ACL, the load job — through the named-credential path
#               production uses. The probe table goes in flabel_scratch, NOT flabel (§3.2).
printf '%s\n' '{"probe":"ls-6","n":1}' '{"probe":"ls-6","n":2}' > /tmp/probe.ndjson
uv run --no-sync python - <<'PY'
from google.cloud import bigquery
from flabeldb import client as c
bq = c.client()
print("datasets visible:", [d.dataset_id for d in bq.list_datasets()])
for name in ("flabel", "flabel_scratch"):
    d = bq.get_dataset(f"{bq.project}.{name}")
    print(name, d.location, d.created, d.modified, d.description)
    for e in d.access_entries:
        print("  ", e.role, e.entity_type, e.entity_id)
    print("  tables:", [t.table_id for t in bq.list_tables(d)])
print("query:", [dict(r) for r in bq.query("SELECT 1 AS ok").result()])

tid = f"{bq.project}.flabel_scratch._provision_probe"
cfg = bigquery.LoadJobConfig(
    source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
    schema=[bigquery.SchemaField("probe", "STRING"), bigquery.SchemaField("n", "INT64")],
)
try:
    with open("/tmp/probe.ndjson", "rb") as fh:
        job = bq.load_table_from_file(fh, tid, job_config=cfg, location=c.LOCATION)
    job.result()
    print("load:", job.state, job.errors, job.output_rows, job.location)
finally:
    bq.delete_table(tid, not_found_ok=True)
# AFTER the drop, so this actually evidences cleanup (revision 2 printed it before the create)
print("scratch tables after cleanup:", [t.table_id for t in bq.list_tables(f"{bq.project}.flabel_scratch")])
PY

# --- as the OPERATOR. `gcloud auth login` first; a stale token fails non-interactively,
#     which is spec §7.1's own failure mode. Then revoke — see the note above.
gcloud projects get-iam-policy "$P" --flatten="bindings[].members" \
  --filter="bindings.members:$SA" --format="value(bindings.role)"
gcloud projects get-iam-policy "$P" --flatten="bindings[].members" \
  --filter="bindings.role:roles/editor OR bindings.role:roles/owner" \
  --format="value(bindings.role,bindings.members)"          # §2.1: how many principals
gcloud storage buckets describe "$B" \
  --format="yaml(location,location_type,versioning,retention_policy,soft_delete_policy)"
gcloud storage ls --soft-deleted "$B/results/**"
gcloud auth revoke                                          # status.yaml 2026-08-19
```
