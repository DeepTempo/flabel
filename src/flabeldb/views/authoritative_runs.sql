-- For each (capture, tier), the run that currently supplies it: the newest non-excluded run to
-- have ATTESTED that tier.
--
-- `{dataset}` is templated rather than literal so this can be dry-run against `flabel_scratch`.
-- A gate that can only be exercised against production is a gate nobody runs.
--
-- Two things here are load-bearing and neither is cosmetic:
--
--   `tiers_attested`, not `tiers_attempted`. A failed run is never ingested and spec §10 says
--   `tiers_unavailable` is empty on every successful run, so a rule built on attempted-minus-
--   unavailable would be inert -- and #142's run, whose Suricata loads NONE of the snapshot, exits
--   0 and would have superseded good tier-2 knowledge with an empty result.
--
--   `run_id` in the ORDER BY. `finished_at` alone is not a total order, and on a box that replays a
--   whole capture in seconds two runs finishing in the same second is the ORDINARY case, so without
--   the tie-break the winner follows whatever order the engine returned -- which is not a property
--   of the data. This is #138's correction applied to a second comparator.
CREATE OR REPLACE VIEW `{dataset}.authoritative_runs` AS
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
  )
)
WHERE recency = 1;
