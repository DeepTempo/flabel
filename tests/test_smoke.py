"""Smoke tests: the package imports and the CLI is wired up."""

import flabel
from flabel.cli import build_parser, main


def test_version_is_set():
    assert flabel.__version__


def test_parser_reports_prog_name():
    assert build_parser().prog == "flabel"


def test_main_exits_zero(capsys):
    assert main([]) == 0
    assert "flabel" in capsys.readouterr().out
