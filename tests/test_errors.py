"""Exit codes, and the record a tool failure carries (spec §11, §12).

`errors.py` maps each exception type to exactly one exit code. The contract is small but
load-bearing: exit 0 must mean "labels were written", including for partial input, because a
non-zero exit on a truncated capture would make every ordinary `set -e` script treat a
successful run as a failure.

The second half of this file pins the *shape* of `ToolError`. Spec §11 wants a tool failure in
the run block's `tool_failures[]` as well as a non-zero exit, so the structured record has to
travel with the exception — and `cli.py` populates one run block from every stage, so there can
only be one way of carrying it.
"""

from __future__ import annotations

import inspect

import pytest

from flabel import errors
from flabel.models import SuricataRunInfo, ToolFailure

#: Every code spec §12 documents. The table is the contract; this list mirrors it.
DOCUMENTED_CODES = {
    errors.EXIT_SUCCESS: 0,
    errors.EXIT_FAILURE: 1,
    errors.EXIT_USAGE: 2,
    errors.EXIT_NOT_IMPLEMENTED: 3,
}


def flabel_exceptions() -> list[type[errors.FlabelError]]:
    return [
        obj
        for _, obj in inspect.getmembers(errors, inspect.isclass)
        if issubclass(obj, errors.FlabelError) and obj is not errors.FlabelError
    ]


def test_the_documented_codes_have_the_documented_values():
    for constant, expected in DOCUMENTED_CODES.items():
        assert constant == expected


def test_every_exception_maps_to_exactly_one_documented_code():
    for exc in flabel_exceptions():
        code = exc.exit_code
        assert isinstance(code, int), f"{exc.__name__}.exit_code is not an int"
        assert code in DOCUMENTED_CODES, f"{exc.__name__} maps to undocumented exit {code}"


def test_every_documented_exit_code_is_reachable():
    """A code nobody can produce is a documentation bug, so each is claimed by something.

    0 is reachable by returning normally, so it is excluded from the exception sweep and
    asserted separately as the success constant.
    """
    reachable = {exc.exit_code for exc in flabel_exceptions()}
    assert reachable == {errors.EXIT_FAILURE, errors.EXIT_USAGE, errors.EXIT_NOT_IMPLEMENTED}
    assert errors.EXIT_SUCCESS == 0


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (errors.ConfigError, errors.EXIT_FAILURE),
        (errors.CaptureError, errors.EXIT_FAILURE),
        (errors.SnapshotError, errors.EXIT_FAILURE),
        (errors.ToolError, errors.EXIT_FAILURE),
        (errors.UsageError, errors.EXIT_USAGE),
        (errors.NotImplementedInPhase1, errors.EXIT_NOT_IMPLEMENTED),
    ],
)
def test_named_exceptions_keep_their_codes(exception, expected):
    """Pinned by name: silently repointing one of these changes the CLI's contract."""
    assert exception.exit_code == expected


def test_exit_code_for_an_unexpected_exception_is_failure():
    """An unforeseen crash must not be mistaken for success, or for a usage error."""
    assert errors.exit_code_for(RuntimeError("something unforeseen")) == errors.EXIT_FAILURE


def test_exit_code_for_a_flabel_error_uses_its_own_code():
    assert errors.exit_code_for(errors.NotImplementedInPhase1("stub")) == (
        errors.EXIT_NOT_IMPLEMENTED
    )


def test_every_exception_is_catchable_as_flabel_error():
    """cli.py catches one base class, so nothing may escape it."""
    for exc in flabel_exceptions():
        with pytest.raises(errors.FlabelError):
            raise exc("boom")


def test_every_exception_takes_a_bare_message():
    """One constructor shape across the family, so a raise site never has to look it up.

    `ToolError` grew two optional arguments; if any exception ever *required* extra arguments,
    the sweeps above would stop being able to construct it and the guard they provide would
    quietly become vacuous.
    """
    for exc in flabel_exceptions():
        assert str(exc("boom")) == "boom"


# --- ToolError carries the failure, for every stage -----------------------------------------
#
# Steps 3, 5 and 6 each invented a way to carry a tool failure out of a stage — a local
# `ConversionError` subclass with a singular `.failure`, an `error.run_info = info` assignment
# after construction, and a plain message with nothing attached — because `errors.py` was
# read-only while they were built in parallel. `cli.py` has to populate one run block from all
# three, and it cannot do that against three shapes. These tests pin the one shape.


def test_tool_error_carries_failures_and_a_run_info():
    failure = ToolFailure(tool="zeek", argv=("zeek", "-r", "x.pcap"), exit_code=1, message="boom")
    info = SuricataRunInfo(version="8.0.6", snapshot_id="abc", rules_loaded=1, alerts_total=0)

    error = errors.ToolError("Zeek failed: boom", failures=(failure,), run_info=info)

    assert error.failures == (failure,)
    assert error.run_info is info
    assert str(error) == "Zeek failed: boom"
    assert error.exit_code == errors.EXIT_FAILURE


def test_tool_error_without_a_record_still_has_the_attributes():
    """A caller reads `.failures` unconditionally, so the empty case must not be `AttributeError`.

    Some failures genuinely have no `ToolFailure` behind them — an unreadable config file, an
    output directory that already holds an `eve.json`. Those must still be a `ToolError` a
    caller can inspect without a `getattr` dance.
    """
    error = errors.ToolError("no tool was even reached")

    assert error.failures == ()
    assert error.run_info is None


def test_tool_error_accepts_its_record_positionally_or_by_keyword():
    """Both spellings, so no raise site has to remember which one `errors.py` chose."""
    failure = ToolFailure(tool="editcap", argv=("editcap",), exit_code=None, message="missing")

    assert errors.ToolError("m", (failure,)).failures == (failure,)
    assert errors.ToolError("m", failures=(failure,)).failures == (failure,)
