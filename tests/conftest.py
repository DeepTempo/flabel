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

#: `requires_tools` tests allowed to skip under `--require-tool-tests`, by node id, each with the
#: reason it is expected. Anything else that skips fails the run (#95).
#:
#: The gate used to have a floor of *one*: it failed only when zero tool tests passed, and a skip
#: is not a deselection. So if a shared fixture broke — the `tls_capture` generator, say — half
#: the integration layer could start skipping and CI would stay green on the strength of one
#: surviving test. "The suite ran" was proven to a floor of 1 out of ~139.
#:
#: An allowlist rather than a blanket ban because one skip is legitimate and permanent-for-now:
#: the malicious canary has no fixture (#103), and its skip is the deliberate visible marker of
#: that gap. Naming it here means that when the fixture lands, the entry is removed in the same
#: diff — and until then, no *other* test can hide behind the same tolerance.
EXPECTED_TOOL_SKIPS = {
    "tests/integration/test_canaries.py::test_the_malicious_canary_produces_at_least_one_label": (
        "the malicious canary is unsourced — issue #103, spec §14. Remove this entry when "
        "tests/fixtures/malicious.pcap lands."
    ),
}

#: A floor on how many `requires_tools` tests must pass under `--require-tool-tests`.
#:
#: The skip allowlist above catches tests that *stop running*; this catches tests that stop
#: *existing*, which no skip is ever reported for. Measured 2026-08-15: 136 pass locally and
#: three more pass in CI, where `zkg` and the JA4 package are present — so ~139. The floor is set
#: well below that rather than at it, because a number that has to be edited every time a test is
#: added is a number people learn to edit without reading. It is high enough to catch the
#: scenario #95 describes — half the layer going missing — and no tighter.
MINIMUM_TOOL_TESTS = 100


class _ToolGate:
    """Per-session gate state, registered as a plugin.

    An object rather than module globals: `test_tool_gate.py` runs this same conftest inside
    a nested pytest session, and relying on module identity to keep the two sets of counters
    apart would depend on a pytest implementation detail rather than on anything guaranteed.

    Note for a future pytest-xdist: counters would live on the workers, so the controller
    would see zero and the gate would fail closed — safe, but it would look like a bug.
    """

    def __init__(self, minimum: int = MINIMUM_TOOL_TESTS) -> None:
        self.passed = 0
        self.deselected: list[str] = []
        self.skipped: list[str] = []
        #: Injected rather than read from the constant, so `test_tool_gate.py`'s nested sessions
        #: — which have one or two tool tests, not a hundred — can drive the floor from both
        #: sides instead of being exempted from it.
        self.minimum = minimum

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """Count tool tests that ran their body **and passed**.

        Deliberately not ``pytest_runtest_call``, which fires before the body: an ``xfail``ed
        tool test, or one calling ``pytest.skip`` partway through, would enter its body and
        satisfy the gate while proving nothing about the toolchain. Marking a broken tool
        test ``xfail`` must not turn CI green. An ``xpass`` does count — it ran and passed.
        """
        if "requires_tools" not in report.keywords:
            return
        if report.when == "call" and report.passed:
            self.passed += 1
        # A skip is decided at setup, so `when` is "setup" and there is no "call" report at all —
        # which is exactly why counting only passes could never see one.
        elif report.skipped:
            self.skipped.append(report.nodeid)

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

        unexpected = sorted(set(self.skipped) - set(EXPECTED_TOOL_SKIPS))
        if unexpected:
            return (
                f"{len(unexpected)} requires_tools test(s) skipped that are not in "
                f"EXPECTED_TOOL_SKIPS: {', '.join(unexpected[:5])}. Under --require-tool-tests a "
                f"tool test that does not run is a gap in the toolchain, not a pass — a broken "
                f"shared fixture can silence half the integration layer while one surviving test "
                f"keeps the build green. If the skip is legitimate and permanent, add it to that "
                f"allowlist with its reason."
            )

        if self.passed < self.minimum:
            return (
                f"only {self.passed} requires_tools tests passed, under the floor of "
                f"{self.minimum}. Nothing reports a test that stopped existing, so this is "
                f"the only thing that would notice the integration layer being deleted rather "
                f"than skipped. If the suite legitimately shrank, lower the floor in the same diff."
            )
        return None


_GATE = "flabel-tool-gate"


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("flabel")
    group.addoption(
        "--require-tool-tests",
        action="store_true",
        help=(
            "Fail the run unless the whole requires_tools layer ran: none deselected, none "
            "skipped outside EXPECTED_TOOL_SKIPS, and at least --min-tool-tests passing. A "
            "skipped suite is not a pass. Intended with --strict-toolchain inside the toolchain "
            "container — on a laptop without the JA4 package this correctly fails, because such "
            "a run does not prove what CI's does."
        ),
    )
    group.addoption(
        "--bigquery",
        action="store_true",
        help=(
            "Run the requires_bigquery tests against a real dataset. OFF by default, and an "
            "explicit flag rather than an auto-detect, because those tests DELETE AND RECREATE "
            "tables: on fl-replay the metadata server would make an auto-detect succeed, so a "
            "bare `pytest` would quietly rewrite a dataset. Needs GCP_PROJECT (or an instance "
            "metadata server) and FLABELDB_TEST_DATASET, which defaults to flabel_scratch."
        ),
    )
    group.addoption(
        "--strict-toolchain",
        action="store_true",
        help="Assert exact pinned tool versions and require the Zeek JA4 package.",
    )
    group.addoption(
        "--min-tool-tests",
        type=int,
        default=MINIMUM_TOOL_TESTS,
        metavar="N",
        help=(
            f"Under --require-tool-tests, fail if fewer than N requires_tools tests passed "
            f"(default: {MINIMUM_TOOL_TESTS}). An option rather than a constant so the value CI "
            f"runs with is visible in argv, and so the gate's own tests can drive it."
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    config.pluginmanager.register(_ToolGate(config.getoption("--min-tool-tests")), _GATE)
    config.addinivalue_line(
        "markers",
        "requires_tools: invokes the real Zeek/Suricata/Wireshark toolchain (docs/spec.md §2)",
    )
    config.addinivalue_line(
        "markers",
        "requires_bigquery: talks to a real BigQuery dataset; opt in with --bigquery",
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
    if not config.getoption("--bigquery"):
        # Skipped rather than deselected, so the count stays visible: these are the only tests that
        # execute the code where flabeldb meets BigQuery, and LS-3 shipped green without them.
        skip_bq = pytest.mark.skip(reason="live BigQuery tests are opt-in — pass --bigquery")
        for item in items:
            if "requires_bigquery" in item.keywords:
                item.add_marker(skip_bq)

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
    gate = config.pluginmanager.get_plugin(_GATE)
    reason = gate.failure()
    if reason is not None:
        terminalreporter.section("toolchain gate", red=True, bold=True)
        terminalreporter.write_line(f"FAILED: {reason}")

    # An allowlist entry that no longer skips is not a failure — the test started running, which
    # is the outcome we wanted. It is worth saying out loud, because an entry nobody removes is
    # how a tolerance outlives the reason for it. Same argument as corpus_gate's `stale` note.
    for node, why in sorted(EXPECTED_TOOL_SKIPS.items()):
        if node not in gate.skipped:
            terminalreporter.write_line(
                f"NOTE: {node} no longer skips — remove it from EXPECTED_TOOL_SKIPS ({why})"
            )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not session.config.getoption("--require-tool-tests"):
        return
    if session.config.pluginmanager.get_plugin(_GATE).failure() is not None:
        session.exitstatus = 1
