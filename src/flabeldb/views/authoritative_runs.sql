-- For each (capture, tier), the run that currently supplies it: the newest non-excluded run to
-- have ATTESTED that tier.
--
-- `{dataset}` is templated rather than literal so this can be dry-run against `flabel_scratch`.
-- A gate that can only be exercised against production is a gate nobody runs.
--
-- The header and as-of placeholders below are what let LS-9's --as-of reuse this statement rather
-- than copy it. `flabel-db apply` renders the header as the CREATE and the predicate as nothing,
-- which is byte-identical to what LS-3 shipped; `blfile --as-of T` renders the header as nothing
-- and the predicate as one more AND, giving an ad-hoc SELECT over the same body. §9 forbids
-- implementing the supersession rule twice, and one file rendered two ways cannot diverge — a
-- second view could, which is also why §4.6 says there is exactly one.
--
-- (Written without the brace spelling on purpose: `render_view` substitutes by plain text replace,
-- so naming a placeholder in a comment injects the substitution into the comment. It did.)
--
-- Two things here are load-bearing and neither is cosmetic:
--
--   `tiers_attested`, not `tiers_attempted`. A failed run is never ingested and spec §10 says
--   `tiers_unavailable` is empty on every successful run, so a rule built on attempted-minus-
--   unavailable would be inert -- and #142's run, whose Suricata loaded 84,958 of the snapshot's
--   84,960 rules, exits 0 and would have superseded good tier-2 knowledge with a result that was
--   two rules short and looked complete. (Corrected 2026-08-27: this said "loads NONE". The real
--   number is the better argument -- a near-miss is what a threshold would have waved through.)
--
--   `run_id` in the ORDER BY. `finished_at` alone is not a total order, and on a box that replays a
--   whole capture in seconds two runs finishing in the same second is the ORDINARY case, so without
--   the tie-break the winner follows whatever order the engine returned -- which is not a property
--   of the data. This is #138's correction applied to a second comparator.
{header}
SELECT capture_sha256, tier, run_id
FROM (
  SELECT
    r.capture_sha256,
    tier,
    r.run_id,
    ROW_NUMBER() OVER (
      PARTITION BY r.capture_sha256, tier
      ORDER BY r.finished_at DESC, r.run_id DESC
    ) AS recency
  FROM `{dataset}.runs` AS r, UNNEST(r.tiers_attested) AS tier
  WHERE NOT EXISTS (
    -- Retraction is a record, not a delete (§4.5), so it has to be joined away on every read.
    SELECT 1 FROM `{dataset}.run_exclusions` AS x WHERE x.run_id = r.run_id
  ){as_of}
)
WHERE recency = 1;
