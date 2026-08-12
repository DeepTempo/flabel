"""Shared test configuration — the toolchain gates.

The testing line is *tools real, network stubbed* (`docs/spec.md` §2): Zeek, Suricata and
`editcap` are invoked for real, never mocked. That makes the toolchain a hard test
dependency, which creates a specific hazard: a suite that skipped every tool test looks
exactly like a suite that passed. Two options guard it.

``--require-tool-tests``
    Fail the run unless a ``requires_tools`` test actually ran *and passed*, and fail if any
    was deselected. CI passes this, so a green build can never mean "the integration layer
    was skipped" — nor "someone parked the broken tool test as xfail".

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


class _ToolGate:
    """Per-session gate state, registered as a plugin.

    An object rather than module globals: `test_tool_gate.py` runs this same conftest inside
    a nested pytest session, and relying on module identity to keep the two sets of counters
    apart would depend on a pytest implementation detail rather than on anything guaranteed.

    Note for a future pytest-xdist: counters would live on the workers, so the controller
    would see zero and the gate would fail closed — safe, but it would look like a bug.
    """

    def __init__(self) -> None:
        self.passed = 0
        self.deselected: list[str] = []

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """Count tool tests that ran their body **and passed**.

        Deliberately not ``pytest_runtest_call``, which fires before the body: an ``xfail``ed
        tool test, or one calling ``pytest.skip`` partway through, would enter its body and
        satisfy the gate while proving nothing about the toolchain. Marking a broken tool
        test ``xfail`` must not turn CI green. An ``xpass`` does count — it ran and passed.
        """
        if report.when == "call" and report.passed and "requires_tools" in report.keywords:
            self.passed += 1

    def pytest_deselected(self, items: list[pytest.Item]) -> None:
        """Remember tool tests filtered out, so narrowing can't silently shrink coverage.

        If the suite is ever split for speed (`-m requires_tools` in one job, the rest in
        another), only the tool-running job may pass --require-tool-tests.
        """
        self.deselected.extend(item.nodeid for item in items if "requires_tools" in item.keywords)

    def failure(self) -> str | None:
        """Why the gate should fail this run, or None if it shouldn't."""
        if self.deselected:
            return (
                f"{len(self.deselected)} requires_tools test(s) were deselected: "
                f"{', '.join(self.deselected[:5])}. Under --require-tool-tests the whole tool "
                f"suite must run — a filtered run proves less than it appears to. Note that "
                f"--lf/--ff and -k all deselect."
            )
        if self.passed == 0:
            return (
                "zero requires_tools tests executed and passed. A run that skipped the "
                "integration layer must not look like a passing one (docs/spec.md §2)."
            )
        return None


_GATE = "flabel-tool-gate"


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


def pytest_configure(config: pytest.Config) -> None:
    config.pluginmanager.register(_ToolGate(), _GATE)
    config.addinivalue_line(
        "markers",
        "requires_tools: invokes the real Zeek/Suricata/Wireshark toolchain (docs/spec.md §2)",
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


def pytest_terminal_summary(terminalreporter, exitstatus: int, config: pytest.Config) -> None:
    """Explain the gate failure in the summary block, where a reader actually looks."""
    if not config.getoption("--require-tool-tests"):
        return
    reason = config.pluginmanager.get_plugin(_GATE).failure()
    if reason is not None:
        terminalreporter.section("toolchain gate", red=True, bold=True)
        terminalreporter.write_line(f"FAILED: {reason}")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not session.config.getoption("--require-tool-tests"):
        return
    if session.config.pluginmanager.get_plugin(_GATE).failure() is not None:
        session.exitstatus = 1
