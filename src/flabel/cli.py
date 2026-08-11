"""Command-line entry point.

Placeholder only — the real pipeline is designed in docs/spec.md and built per PLAN.md.
"""

import argparse

from flabel import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flabel",
        description="Label malicious flows in a packet capture.",
    )
    parser.add_argument("--version", action="version", version=f"flabel {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    print("flabel: not implemented yet — see docs/status.yaml for pipeline stage")
    return 0
