"""Exit codes (spec §12).

`errors.py` maps each exception type to exactly one exit code. The contract is small but
load-bearing: exit 0 must mean "labels were written", including for partial input, because a
non-zero exit on a truncated capture would make every ordinary `set -e` script treat a
successful run as a failure.
"""

from __future__ import annotations

import inspect

import pytest

from flabel import errors

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
