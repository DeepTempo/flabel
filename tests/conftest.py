"""Shared test configuration — the toolchain gates.

The testing line is *tools real, network stubbed* (`docs/spec.md` §2): Zeek, Suricata and
`editcap` are invoked for real, never mocked. That makes the toolchain a hard test
dependency, which creates a specific hazard: a suite that skipped every tool test looks
exactly like a suite that passed. Two options guard it.

``--require-tool-tests``
    Fail the run unless at least one ``requires_tools`` test actually executed. CI passes
    this, so a green build can never mean "the integration layer was skipped".

``--strict-toolchain``
    Assert the *exact* pinned tool versions rather than just major.minor, and treat a
    missing Zeek JA4 package as a failure rather than a skip. CI passes this too, because
    CI runs the digest-pinned container where the exact versions are the contract. Local
    runs omit it, so brew patch-version drift doesn't turn the suite red.

Without either option, ``requires_tools`` tests skip cleanly when a tool is absent — the
laptop case, where the pure tests should still be runnable.
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Every executable the suite shells out to. Absence of any one of them skips the whole
#: ``requires_tools`` layer, because a partial toolchain gives partial, misleading results.
REQUIRED_TOOLS = ("zeek", "suricata", "editcap", "capinfos")

_TOOL_TESTS_RUN = "_flabel_tool_tests_run"


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("flabel")
    group.addoption(
        "--require-tool-tests",
        action="store_true",
        help="Fail the run if no requires_tools test executed (a skipped suite is not a pass).",
    )
    group.addoption(
        "--strict-toolchain",
        action="store_true",
        help="Assert exact pinned tool versions and require the Zeek JA4 package.",
    )


def missing_tools() -> list[str]:
    """Names of the required executables that are not on PATH."""
    return [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]


@pytest.fixture(scope="session")
def toolchain_pins() -> dict[str, str]:
    """The ``[tool.flabel.toolchain]`` table — the single source of truth for versions."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["flabel"]["toolchain"]


@pytest.fixture(scope="session")
def strict_toolchain(pytestconfig: pytest.Config) -> bool:
    return bool(pytestconfig.getoption("--strict-toolchain"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    missing = missing_tools()
    if not missing:
        return

    if config.getoption("--require-tool-tests"):
        # Fail loudly and immediately rather than emitting a wall of skips that a reader
        # (or a CI badge) could mistake for success.
        raise pytest.UsageError(
            f"--require-tool-tests was given but these tools are not on PATH: "
            f"{', '.join(missing)}. See docs/dev-setup.md."
        )

    skip = pytest.mark.skip(
        reason=f"toolchain not installed: {', '.join(missing)} — see docs/dev-setup.md"
    )
    for item in items:
        if "requires_tools" in item.keywords:
            item.add_marker(skip)


def pytest_runtest_call(item: pytest.Item) -> None:
    """Count tool tests that reach their body. Skipped tests never get here."""
    if "requires_tools" in item.keywords:
        count = getattr(item.config, _TOOL_TESTS_RUN, 0)
        setattr(item.config, _TOOL_TESTS_RUN, count + 1)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    config = session.config
    if not config.getoption("--require-tool-tests"):
        return
    if getattr(config, _TOOL_TESTS_RUN, 0) > 0:
        return

    # Reached when the tools are present but no tool test ran at all — deselected by a
    # filter, skipped for another reason, or none collected. Still not a pass.
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(
            "ERROR: --require-tool-tests was given but zero requires_tools tests executed.",
            red=True,
        )
    session.exitstatus = 1
