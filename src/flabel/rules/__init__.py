"""Ruleset acquisition, admission and snapshots (docs/spec.md §5–§7).

Three modules, split by what they are allowed to do rather than by subject matter:

* `fetch`    — the **only** network I/O in the package (spec §2.2), behind a transport
               interface so every other test points it at local files.
* `admit`    — pure: which of a feed's rules may become labels, and why the rest may not.
* `snapshot` — writes and loads the content-addressed, immutable rule directories that make
               a label reproducible.

This module deliberately re-exports nothing. `admit` and `snapshot` both import `utc_now`
from here, so a re-export would make the package import cycle back through its own members.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> str:
    """The current time in flabel's one timestamp format: ISO-8601 UTC, microseconds, `Z`.

    Shared by `admit` (`fetched_at`) and `snapshot` (`created_at`) rather than written twice,
    because spec §10 requires one format everywhere and two independent `strftime` strings is
    how that requirement quietly stops being true.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
