"""Smoke tests: the package imports and the CLI is wired up."""

import pytest

import flabel
from flabel.cli import build_parser, main


def test_version_is_set():
    assert flabel.__version__


def test_parser_reports_prog_name():
    assert build_parser().prog == "flabel"


def test_no_arguments_is_a_usage_error(capsys):
    """`flabel` with no capture is exit 2 (spec §12), not the exit 0 the placeholder returned.

    Rewritten in step 9. Until then `main([])` printed a "not implemented yet" line and returned
    0, which is now three separate wrongs: a capture is required, argparse owns exit 2, and the
    Phase 1 default path exits 3 rather than 0 (`test_cli.py` covers that one).
    """
    with pytest.raises(SystemExit) as raised:
        main([])

    assert raised.value.code == 2
    assert "usage" in capsys.readouterr().err.lower()
