"""Fixtures for the end-to-end gates (PLAN.md step 10).

The helpers themselves live in `gates.py` rather than here: `conftest` exists twice in this
suite, so a test module importing `conftest` by name could resolve to either one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from gates import MATCHES_CANARY, MISSES_CANARY, build_snapshot


@pytest.fixture
def quiet_snapshot(tmp_path: Path) -> Path:
    """A real, fully-loading ruleset that asserts nothing about the benign canary."""
    root = tmp_path / "rules-quiet"
    build_snapshot(root, {"et/open": list(MISSES_CANARY)})
    return root


@pytest.fixture
def labelling_snapshot(tmp_path: Path) -> Path:
    """A real ruleset with one rule that does match the canary, so labels exist to compare."""
    root = tmp_path / "rules-labelling"
    build_snapshot(root, {"et/open": [MATCHES_CANARY]})
    return root
