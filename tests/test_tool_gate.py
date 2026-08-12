"""The toolchain gate itself fails when it should.

`conftest.py` carries the guarantee that a run which skipped every real-tool test cannot
look like a passing run. Every step from 2 onward leans on that, so it gets its own tests
rather than trusting a one-off manual check.

Each case runs a throwaway suite through pytest-in-pytest with `shutil.which` stubbed, so
the results do not depend on what happens to be installed on the machine running them.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

CONFTEST_SOURCE = (Path(__file__).parent / "conftest.py").read_text()

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


def test_require_tool_tests_passes_when_a_tool_test_ran(gate, monkeypatch):
    """The green path: one real tool test executed is enough to satisfy the gate."""
    _stub_which(monkeypatch, found=True)
    gate.makepyfile(test_tools=TOOL_TEST, test_pure=PURE_TEST)

    result = gate.runpytest("--require-tool-tests")

    result.assert_outcomes(passed=2)
    assert result.ret == 0
