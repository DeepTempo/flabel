#!/bin/bash
# Phase 4 P4-4: label a list of gs:// captures, one per line on stdin, and SUMMARISE.
#
# Not a loop in someone's shell history, for three reasons the plan records:
#
#   1. A failed run writes no labels.json, is never published, and therefore leaves NO RECORD IN
#      THE STORE that it was attempted. The failure exists only in a local run.json. So the summary
#      this prints is the only account of what happened to the batch.
#   2. `flabel-run` exits 5 for published-but-not-indexed. Under `set -e` that stops the batch at
#      capture 4 of 24; without it, it scrolls past unnoticed. Neither is what you want: keep going,
#      and say so loudly at the end.
#   3. With no TTY a rule-load shortfall defaults to continue rather than prompting per capture,
#      which is why this is meant to be run under nohup/systemd-run rather than interactively.
#
# usage:  printf '%s\n' gs://b/a.pcap gs://b/b.pcap | tools/phase4_batch.sh --ruleset-snapshot ID
set -uo pipefail

LOG="${PHASE4_LOG:-/var/lib/flabel/phase4/batch-$(date -u +%Y%m%dT%H%M%SZ).log}"
mkdir -p "$(dirname "$LOG")"
RUNNER="${PHASE4_RUNNER:-/usr/local/bin/flabel-run}"

declare -a URIS=() CODES=()
while IFS= read -r uri; do
  [ -n "$uri" ] || continue
  URIS+=("$uri")
done

echo "phase4: ${#URIS[@]} capture(s), extra args: $*" | tee -a "$LOG"
started="$(date -u +%s)"

for i in "${!URIS[@]}"; do
  uri="${URIS[$i]}"
  n=$((i + 1))
  echo "" | tee -a "$LOG"
  echo "=== [$n/${#URIS[@]}] $(date -u +%H:%M:%SZ) $uri ===" | tee -a "$LOG"
  # Deliberately NOT `|| true` and NOT under set -e: capture the code, keep going.
  "$RUNNER" "$uri" "$@" 2>&1 | tee -a "$LOG"
  # ${PIPESTATUS[0]}, not $? — $? is tee's. The same mistake is recorded in status.yaml as one of
  # three "verified with something adjacent to the gate" errors.
  code="${PIPESTATUS[0]}"
  CODES+=("$code")
  echo "=== [$n/${#URIS[@]}] exit $code ===" | tee -a "$LOG"
done

elapsed=$(( $(date -u +%s) - started ))
echo "" | tee -a "$LOG"
echo "=== SUMMARY  (${elapsed}s total) ===" | tee -a "$LOG"
ok=0; refused=0; unindexed=0; other=0
for i in "${!URIS[@]}"; do
  code="${CODES[$i]}"
  case "$code" in
    0) label="ok";                      ok=$((ok+1)) ;;
    1) label="REFUSED (about the data)"; refused=$((refused+1)) ;;
    5) label="PUBLISHED BUT NOT INDEXED — re-ingest this tarball"; unindexed=$((unindexed+1)) ;;
    *) label="FAILED";                  other=$((other+1)) ;;
  esac
  printf '  %-3s %-4s %s  %s\n' "$((i+1))" "$code" "$label" "${URIS[$i]}" | tee -a "$LOG"
done
echo "" | tee -a "$LOG"
echo "  ok=$ok refused=$refused published-not-indexed=$unindexed failed=$other" | tee -a "$LOG"
echo "  log: $LOG" | tee -a "$LOG"

# Exit non-zero if ANY capture did not fully succeed, so a caller cannot read silence as success.
[ "$((refused + unindexed + other))" -eq 0 ]
