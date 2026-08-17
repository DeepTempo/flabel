"""Fixtures for the end-to-end gates (PLAN.md step 10).

The helpers themselves live in `gates.py` rather than here: `conftest` exists twice in this
suite, so a test module importing `conftest` by name could resolve to either one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from gates import ANY_IP_PROTOCOL, MATCHES_CANARY, MISSES_CANARY, build_snapshot


@pytest.fixture
def quiet_snapshot(tmp_path: Path) -> Path:
    """A real, fully-loading ruleset that asserts nothing about the benign canary."""
    root = tmp_path / "rules-quiet"
    build_snapshot(root, {"et/open": list(MISSES_CANARY)})
    return root


@pytest.fixture
def labelling_snapshot(tmp_path: Path) -> Path:
    """A real ruleset with rules that match the canary, so labels exist to compare.

    Two rules, not one, since #115. `ANY_IP_PROTOCOL` matches every packet of both canary flows,
    so each label carries a `to_server` entry *and* a `to_client` entry from the same rule —
    entries identical in every other field, which is the one shape whose serialised order rests
    on a tiebreak. Before #115 no gate had ever run a capture producing it.

    **Stated precisely, because it would be easy to oversell:** this makes the gate *exercise*
    the shape end to end; it does **not** make the gate fail when `direction` is dropped from
    the sort key. Measured — dropping it from both keys and re-running these seven tests: all
    seven still pass. Suricata's alert records come out in packet order under `--runmode
    single`, so the tie is broken identically in both runs and the hazard stays latent. What
    holds the sort key is the pair of unit tests in `test_labels.py` and `test_correlate.py`,
    which feed the two entries in both orders; those do fail. This fixture's value is that a
    real run now produces the shape at all, so a future ordering instability has something to
    show up in.
    """
    root = tmp_path / "rules-labelling"
    build_snapshot(root, {"et/open": [MATCHES_CANARY, ANY_IP_PROTOCOL]})
    return root
