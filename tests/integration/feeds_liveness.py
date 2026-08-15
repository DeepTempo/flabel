"""Goal 5's real review must not have gone dark (issue #88).

WHAT THIS IS FOR, AND WHAT IT IS NOT FOR

`.github/workflows/feeds.yml` is the only false-positive review the ~85,000 wholesale-admitted
rules ever get — `pawpatrules` alone contributes 21,464 through no per-rule gate. PRD §6.3 said
that review "runs on every build". It does not. What runs on every build is
`test_the_benign_canary_produces_zero_labels`, whose own assertion is `rules_loaded == 3`: three
synthetic rules against a 14-packet capture, reviewing none of the ruleset the risk is about.

The real review runs on a `schedule:`, and **GitHub disables `schedule:` triggers after 60 days
of repository inactivity.** `feeds.yml` records that in its own header. What it could not do is
*act* on it, because a workflow that is not running cannot notice that it is not running.

When `feeds` **fails**, it files an issue and that works — proved on 2026-08-15, when the first
scheduled run after step 11d died on `set -euo pipefail` under `sh` and opened #105 within two
minutes. When `feeds` is **disabled**, nothing runs, nothing fails, and nothing is filed. That
hole is what this closes.

WHY IT LIVES IN `ci.yml` AND NOT ON A SCHEDULE OF ITS OWN

A scheduled liveness check for a scheduled workflow inherits the identical 60-day disable, so it
would go dark in the same silence it exists to break. `ci.yml` runs `on: [push, pull_request]`,
which makes this self-defending: the repository inactivity that disables `feeds` is the same
inactivity that means nobody is pushing, and the moment somebody does push, this fails and says
so. The property is therefore **"you cannot merge a change while the standing false-positive
review has been dark"** — not "the review is running right now", which nothing inside GitHub can
assert about itself.

WHY LAST *SUCCESS* RATHER THAN LAST RUN

A `feeds` run that did not succeed did not complete the review. Keying on "it ran" would have
called the pipeline healthy all through the 2026-08-15 breakage, because a run that dies on line
1 of the first gate is still a run. Keying on success also gives this a second, unplanned catch:
sustained failure, which files an issue that can then sit unread.

The decision is `verify()`, which takes its inputs as arguments and returns an exit code, and
`main()` is argv parsing and file reading. That split is deliberate and it is this repo's most
expensive lesson: a gate whose logic lives in a YAML heredoc runs only on the trigger that
invokes it, so nothing can prove it is able to *fail*. That is how the Goal 2 reproducibility
gate came to be hollowed out with CI green (#74), how three of step 13's fixes shipped with tests
that passed against unfixed code (#98), and how `corpus_gate.py`'s first draft put every guard
inside `main` where no test reached it (#101).

Run it directly against a saved API response:

    gh api "repos/DeepTempo/flabel/actions/workflows/feeds.yml/runs?per_page=30" \
      --jq '[.workflow_runs[] | {conclusion, created_at}]' > feeds-runs.json
    uv run python tests/integration/feeds_liveness.py feeds-runs.json
"""

from __future__ import annotations

import json
import math
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: How long Goal 5's real review may go without a success before a push is refused.
#:
#: `feeds` is scheduled daily, so seven consecutive misses is not flakiness — it is a fortnight's
#: worth of signal already lost by the time anyone reads this. The number trades two failure modes
#: against each other and neither is free: too tight and this becomes a nag that blocks unrelated
#: work, which is how gates get deleted; too loose and the 60-day disable this exists to catch
#: hides behind it. Seven is short enough to catch a dead schedule long before GitHub's 60 days,
#: and long enough to absorb the upstream feed outages that are the ordinary cause of a red day —
#: `abuse.ch/urlhaus` and two pawpatrules companion lists are fetched live every run.
MAX_AGE_DAYS = 7

#: Escape hatch for a deliberate, temporary raise — a known upstream outage, say. An env var
#: rather than an edit, so raising it does not look like a permanent policy change in the diff,
#: and so the test can drive the boundary without monkeypatching a constant.
ENV_MAX_AGE = "FLABEL_FEEDS_MAX_AGE_DAYS"


def max_age_days(environ: dict[str, str] | None = None) -> float:
    """The threshold, from the environment or the default.

    Raises on a non-numeric or non-positive override rather than falling back to the default:
    silently ignoring `FLABEL_FEEDS_MAX_AGE_DAYS=verylong` would leave someone believing they had
    suspended this gate when they had not, which is the wrong direction to be wrong in for a
    variable whose whole purpose is to relax a check.
    """
    raw = (environ if environ is not None else os.environ).get(ENV_MAX_AGE)
    if raw is None or raw == "":
        return float(MAX_AGE_DAYS)
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{ENV_MAX_AGE}={raw!r} is not a number") from None
    # `nan` and `inf` both parse and both survive a `<= 0` check, and `age > nan` is False for
    # every age — so either one would switch this gate off permanently while reading, in a diff,
    # as a number. Found by writing the test for it, not by inspection.
    if not math.isfinite(value):
        raise ValueError(f"{ENV_MAX_AGE}={raw!r} is not finite: it would disable this gate")
    if value <= 0:
        raise ValueError(f"{ENV_MAX_AGE}={raw!r} must be positive")
    return value


def parse_timestamp(raw: object) -> datetime | None:
    """A GitHub `created_at` as an aware UTC datetime, or `None` if it is unusable.

    `None` rather than an exception, so one malformed record in a page of thirty cannot decide
    the verdict — but see `verify`, where *every* record being unusable is a failure rather than
    "no successful run found". Those two diagnose completely differently and the caller must not
    confuse them.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def verify(
    runs: list[dict[str, Any]] | None,
    now: datetime,
    threshold_days: float = MAX_AGE_DAYS,
) -> int:
    """The whole verdict, as an exit code. Every guard lives here so every guard is testable.

    `runs` is `None` when the API could not be reached or its response could not be parsed. That
    is a failure, not a pass: a liveness check that goes green when it cannot determine liveness
    is spec §2.5's "absence is never a signal" in the one place it would be most tempting to bend.
    """
    if runs is None:
        print(
            "could not determine when the feeds review last succeeded. That is not a pass — read "
            "the step above for why the API call failed, and check the Actions tab by hand before "
            "trusting anything about Goal 5.",
            file=sys.stderr,
        )
        return 1

    if not runs:
        print(
            "GitHub reports no runs of feeds.yml at all. Either the workflow has never run or the "
            "query named the wrong workflow file — both mean Goal 5's real review is not running. "
            "Trigger it with `gh workflow run feeds.yml`.",
            file=sys.stderr,
        )
        return 1

    dated = [(parse_timestamp(run.get("created_at")), run) for run in runs]
    if not any(stamp for stamp, _ in dated):
        print(
            f"none of the {len(runs)} runs returned carried a readable `created_at`, so their age "
            f"is unknown. This is a broken query or a changed API shape, not a quiet schedule — "
            f"do not read it as 'no successful run'.",
            file=sys.stderr,
        )
        return 1

    # Newest first, so the messages below name the run a reader would look at.
    dated = sorted(
        ((stamp, run) for stamp, run in dated if stamp is not None),
        key=lambda pair: pair[0],
        reverse=True,
    )
    latest_stamp, latest = dated[0]
    print(
        f"most recent feeds run : {latest_stamp.isoformat()} "
        f"({(now - latest_stamp).total_seconds() / 86400:.1f} days ago), "
        f"conclusion {latest.get('conclusion')!r}"
    )

    successes = [(stamp, run) for stamp, run in dated if run.get("conclusion") == "success"]
    if not successes:
        print(
            f"none of the last {len(runs)} feeds runs succeeded. Goal 5's real review has not "
            f"completed once in that window, so the ~85,000 wholesale-admitted rules currently "
            f"have no standing false-positive review at all. There should be an open issue "
            f"labelled `goal-5` explaining why; if there is not, that is a second defect.",
            file=sys.stderr,
        )
        return 1

    stamp, _ = successes[0]
    age = (now - stamp).total_seconds() / 86400
    print(f"last SUCCESSFUL run   : {stamp.isoformat()} ({age:.1f} days ago)")

    if age > threshold_days:
        print(
            f"\nGoal 5's real review last succeeded {age:.1f} days ago, over the "
            f"{threshold_days:g}-day limit. The benign canary that runs on every build is three "
            f"synthetic rules and reviews none of the wholesale-admitted ruleset (PRD §6.3), so "
            f"this window is a window with no false-positive review in it.\n"
            f"\nMost likely cause: GitHub disables `schedule:` triggers after 60 days of "
            f"repository inactivity, and nothing announces it. Re-enable `feeds` from the Actions "
            f"tab, or run it now:\n"
            f"\n    gh workflow run feeds.yml\n"
            f"\nIf it is failing rather than disabled, fix that first — a red review is not a "
            f"review. To suspend this deliberately for a known upstream outage, set "
            f"{ENV_MAX_AGE} and say why in the PR.",
            file=sys.stderr,
        )
        return 1

    print(f"Goal 5's real review is live (within {threshold_days:g} days)")
    return 0


def main(argv: list[str]) -> int:
    """argv parsing and file reading. The decision is `verify`."""
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <feeds-runs.json>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    runs: list[dict[str, Any]] | None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        runs = None
    else:
        # Accept either the `--jq` projection this is invoked with or a raw API response, so
        # running it by hand against `gh api ... > file` with no jq does something sensible.
        if isinstance(payload, dict):
            payload = payload.get("workflow_runs")
        runs = payload if isinstance(payload, list) else None
        if runs is None:
            print(
                f"{path} is neither a list of runs nor an API response carrying `workflow_runs`",
                file=sys.stderr,
            )

    return verify(runs, datetime.now(UTC), max_age_days())


if __name__ == "__main__":  # pragma: no cover - exercised through `verify` and `main`
    sys.exit(main(sys.argv))
