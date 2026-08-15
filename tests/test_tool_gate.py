"""The toolchain gate itself fails when it should.

`conftest.py` carries the guarantee that a run which skipped every real-tool test cannot
look like a passing run. Every step from 2 onward leans on that, so it gets its own tests
rather than trusting a one-off manual check.

Each case runs a throwaway suite through pytest-in-pytest with `shutil.which` stubbed, so
the results do not depend on what happens to be installed on the machine running them.
"""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT_CONFTEST = Path(__file__).parent / "conftest.py"
CONFTEST_SOURCE = ROOT_CONFTEST.read_text()


def root_conftest():
    """`tests/conftest.py`, loaded by path rather than by name.

    A bare `import conftest` resolves to `tests/integration/conftest.py` once the whole suite
    runs: pytest puts both directories on `sys.path` and the last one collected wins. These
    tests passed in isolation and failed in the full run, which is issue #63's "two test modules
    coupled through sys.path" complaint arriving for real. Loading by path cannot be shadowed.
    """
    spec = importlib.util.spec_from_file_location("flabel_root_conftest", ROOT_CONFTEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL_TEST = """
import pytest

@pytest.mark.requires_tools
def test_uses_the_toolchain():
    pass
"""

PURE_TEST = """
def test_needs_no_tools():
    pass
"""

# A tool test marked xfail still enters its body. If the gate counts bodies entered rather
# than tests passed, marking a broken tool test xfail turns CI green with the toolchain
# unexercised — the exact outcome the gate exists to prevent.
XFAIL_TOOL_TEST = """
import pytest

@pytest.mark.requires_tools
@pytest.mark.xfail(reason="pretend someone parked a broken tool test")
def test_uses_the_toolchain():
    raise AssertionError("the tool check is broken")
"""

# Same hazard from the other direction: a test that decides mid-body it cannot run.
INBODY_SKIP_TOOL_TEST = """
import pytest

@pytest.mark.requires_tools
def test_uses_the_toolchain():
    pytest.skip("decided at runtime that a fixture was missing")
"""


@pytest.fixture
def gate(pytester):
    """A throwaway suite wired to the real conftest."""
    pytester.makeconftest(CONFTEST_SOURCE)
    return pytester


def _stub_which(monkeypatch, *, found: bool):
    monkeypatch.setattr(shutil, "which", lambda name: f"/stub/bin/{name}" if found else None)


def test_tool_tests_skip_when_a_tool_is_absent(gate, monkeypatch):
    """The laptop case: no toolchain, the pure tests still run, tool tests skip cleanly."""
    _stub_which(monkeypatch, found=False)
    gate.makepyfile(test_tools=TOOL_TEST, test_pure=PURE_TEST)

    result = gate.runpytest()

    result.assert_outcomes(passed=1, skipped=1)
    assert result.ret == 0


def test_require_tool_tests_errors_when_a_tool_is_absent(gate, monkeypatch):
    """CI's case: the skip that would have hidden an untested pipeline is now fatal."""
    _stub_which(monkeypatch, found=False)
    gate.makepyfile(test_tools=TOOL_TEST)

    result = gate.runpytest("--require-tool-tests")

    assert result.ret != 0
    result.stderr.fnmatch_lines(["*not on PATH*"])


def test_require_tool_tests_fails_when_no_tool_test_is_collected(gate, monkeypatch):
    """Tools present, but nothing exercised them — deselected, or none written yet."""
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_pure=PURE_TEST)

    result = gate.runpytest("--require-tool-tests")

    assert result.ret != 0
    result.stdout.fnmatch_lines(["*zero requires_tools tests executed*"])


def test_xfailed_tool_test_does_not_satisfy_the_gate(gate, monkeypatch):
    """A parked-as-xfail tool test must not count. It proves nothing about the toolchain."""
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_tools=XFAIL_TOOL_TEST)

    result = gate.runpytest("--require-tool-tests")

    assert result.ret != 0
    result.stdout.fnmatch_lines(["*zero requires_tools tests executed*"])


def test_inbody_skip_does_not_satisfy_the_gate(gate, monkeypatch):
    """A test that skips itself mid-body never exercised a tool, so it cannot count."""
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_tools=INBODY_SKIP_TOOL_TEST)

    result = gate.runpytest("--require-tool-tests")

    assert result.ret != 0
    result.stdout.fnmatch_lines(["*zero requires_tools tests executed*"])


def test_deselecting_a_tool_test_fails_the_gate(gate, monkeypatch):
    """`-k` narrowing must not quietly shrink the toolchain coverage CI thinks it has.

    By step 10 there will be dozens of these; "at least one ran" is too weak a floor if
    the rest can be filtered away unnoticed.
    """
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(
        test_tools="""
import pytest

@pytest.mark.requires_tools
def test_alpha():
    pass

@pytest.mark.requires_tools
def test_beta():
    pass
"""
    )

    result = gate.runpytest("--require-tool-tests", "-k", "alpha")

    assert result.ret != 0
    result.stdout.fnmatch_lines(["*deselected*"])


def test_require_tool_tests_passes_when_a_tool_test_ran(gate, monkeypatch):
    """The green path. `--min-tool-tests=1` because this suite has one tool test, not ~139."""
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_tools=TOOL_TEST, test_pure=PURE_TEST)

    result = gate.runpytest("--require-tool-tests", "--min-tool-tests=1")

    result.assert_outcomes(passed=2)
    assert result.ret == 0


# --- a skipped tool test is not a passing one (#95) ---------------------------------------------
#
# The gate's floor used to be *one*: it failed only when zero tool tests passed, and a skip is
# not a deselection. So a broken shared fixture — the `tls_capture` generator, say — could put
# half the integration layer into `skipped` and CI would stay green on the strength of one
# survivor. "The suite ran" was proven to a floor of 1 out of ~139.

SETUP_SKIP_TOOL_TEST = """
import pytest

@pytest.fixture
def broken_fixture():
    pytest.skip("a shared fixture stopped working")

@pytest.mark.requires_tools
def test_alpha(broken_fixture):
    pass

@pytest.mark.requires_tools
def test_beta():
    pass
"""


def test_a_tool_test_skipped_by_a_broken_fixture_fails_the_gate(gate, monkeypatch):
    """The #95 scenario exactly: one survivor kept the build green while coverage collapsed."""
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_tools=SETUP_SKIP_TOOL_TEST)

    result = gate.runpytest("--require-tool-tests", "--min-tool-tests=1")

    assert result.ret != 0, "a tool test skipped at setup left the gate green"
    result.stdout.fnmatch_lines(["*not in EXPECTED_TOOL_SKIPS*"])


def test_an_allowlisted_skip_is_tolerated(pytester, monkeypatch):
    """One skip is legitimate and permanent-for-now — the unsourced malicious canary (#103).

    The allowlist is keyed by node id and pytester's files land at their own paths, so the real
    entry can never match here. This stubs an entry naming *this* suite's node id, which tests
    the mechanism; `test_the_real_allowlist_names_only_the_unsourced_malicious_canary` asserts
    the committed contents separately.
    """
    _stub_which(monkeypatch, found=True)
    pytester.makeconftest(
        CONFTEST_SOURCE.replace(
            "EXPECTED_TOOL_SKIPS = {",
            'EXPECTED_TOOL_SKIPS = {\n    "test_tools.py::test_unsourced": "stands in",',
            1,
        )
    )
    pytester.makepyfile(
        test_tools="""
import pytest

@pytest.mark.requires_tools
@pytest.mark.skip(reason="no fixture yet")
def test_unsourced():
    pass

@pytest.mark.requires_tools
def test_that_really_runs():
    pass
"""
    )

    result = pytester.runpytest("--require-tool-tests", "--min-tool-tests=1")

    assert result.ret == 0, "an allowlisted skip must not fail the gate"
    assert "not in EXPECTED_TOOL_SKIPS" not in result.stdout.str()


def test_an_allowlist_entry_that_stopped_skipping_is_reported(pytester, monkeypatch):
    """Not a failure — the test started running, which is what we wanted. But say so.

    An entry nobody removes is how a tolerance outlives its reason. Same argument as
    `corpus_gate`'s `stale` note, and the same choice: stderr, not silence.
    """
    _stub_which(monkeypatch, found=True)
    pytester.makeconftest(
        CONFTEST_SOURCE.replace(
            "EXPECTED_TOOL_SKIPS = {",
            'EXPECTED_TOOL_SKIPS = {\n    "test_tools.py::test_unsourced": "stands in",',
            1,
        )
    )
    pytester.makepyfile(
        test_tools="""
import pytest

@pytest.mark.requires_tools
def test_unsourced():
    pass
"""
    )

    result = pytester.runpytest("--require-tool-tests", "--min-tool-tests=1")

    assert result.ret == 0
    result.stdout.fnmatch_lines(["*no longer skips*"])


def test_the_real_allowlist_names_only_the_unsourced_malicious_canary():
    """The allowlist must not grow quietly — it is the one hole in "no tool test may skip".

    An entry here is a standing exemption from the gate, so a second one has to be argued for in
    a reviewed diff rather than appended. Same reasoning as `corpus_gate.MAX_TOLERATED`.
    """
    expected = root_conftest().EXPECTED_TOOL_SKIPS

    assert set(expected) == {
        "tests/integration/test_canaries.py::test_the_malicious_canary_produces_at_least_one_label"
    }
    for node, reason in expected.items():
        assert reason.strip(), f"{node} is exempted with no reason given"


def test_a_shrunken_tool_suite_fails_the_floor(gate, monkeypatch):
    """The complement of the skip guard: nothing reports a test that stopped *existing*.

    A skip is visible; a deletion is not. Without a floor, deleting the integration layer down
    to one test leaves the gate green and reads, in the summary line, as a smaller suite.
    """
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_tools=TOOL_TEST)

    result = gate.runpytest("--require-tool-tests", "--min-tool-tests=5")

    assert result.ret != 0
    result.stdout.fnmatch_lines(["*under the floor of 5*"])


def test_the_floor_that_ci_actually_runs_with_is_below_todays_count():
    """A floor above the real count would fail every CI run; one at it would need editing daily.

    Measured 2026-08-15: 136 requires_tools tests pass locally, ~139 in CI where `zkg` and the
    JA4 package are present. This asserts the floor is a floor and not a tripwire.
    """
    minimum = root_conftest().MINIMUM_TOOL_TESTS

    assert 0 < minimum < 136, (
        f"MINIMUM_TOOL_TESTS is {minimum}, which is not below the 136 that pass "
        f"locally — CI would fail on the floor rather than on anything real."
    )
