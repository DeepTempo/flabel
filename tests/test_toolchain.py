"""The toolchain is present, real, and at the pinned versions.

Every later step's tests invoke Zeek, Suricata or ``editcap`` for real, so these are the
tests that prove the environment can support them at all. They are also the Goal 2
precondition: reproducibility only means something across *pinned* tool versions.

Version comparison is major.minor by default and exact under ``--strict-toolchain``; see
``conftest.py`` for why.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

# Suricata has no --version: it exits 1 with "unrecognized option". -V is the flag that
# works, and PLAN.md step 1 / issue #15 say --version only as shorthand for "reports its
# version". Verified on Suricata 8.0.6.
VERSION_FLAG = {
    "zeek": "--version",
    "suricata": "-V",
    "editcap": "--version",
    "capinfos": "--version",
}

#: Which pin in ``[tool.flabel.toolchain]`` governs each tool. editcap and capinfos ship
#: from one Wireshark build and cannot diverge, so they share a single pin.
PIN_KEY = {
    "zeek": "zeek",
    "suricata": "suricata",
    "editcap": "wireshark",
    "capinfos": "wireshark",
}

SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def tool_version(tool: str) -> str:
    """Run ``tool`` with its version flag and return the first x.y.z it reports.

    Version output lands on stdout for some tools and stderr for others, so both are read.
    """
    result = subprocess.run(
        [tool, VERSION_FLAG[tool]],
        capture_output=True,
        text=True,
        check=True,
    )
    match = SEMVER.search(result.stdout + result.stderr)
    assert match is not None, f"{tool} reported no parseable version: {result.stdout!r}"
    return match.group(0)


def test_pins_are_exact_versions(toolchain_pins):
    """No wildcard pins. A pin that isn't a concrete x.y.z cannot anchor reproducibility."""
    for key in ("zeek", "suricata", "wireshark"):
        pin = toolchain_pins[key]
        assert SEMVER.fullmatch(pin), f"{key} pin {pin!r} is not an exact x.y.z version"


def test_dockerfile_args_match_the_pins(toolchain_pins):
    """The image recipe and the pins cannot drift apart unnoticed.

    ``Dockerfile.toolchain`` decides what CI actually installs; ``[tool.flabel.toolchain]``
    is what the tests assert. If they disagree, CI either fails mysteriously or — worse —
    passes while asserting the wrong thing. Needs no tools, so it runs everywhere.
    """
    dockerfile = (pathlib.Path(__file__).resolve().parents[1] / "Dockerfile.toolchain").read_text()
    args = dict(re.findall(r"^ARG (\w+)=(\S+)$", dockerfile, re.MULTILINE))

    zeek_line = ".".join(toolchain_pins["zeek"].split(".")[:2])
    assert args["ZEEK_VERSION"] == zeek_line, (
        f"Dockerfile installs zeek-{args['ZEEK_VERSION']} but the pin is "
        f"{toolchain_pins['zeek']} (the {zeek_line} line)"
    )
    assert args["JA4_PACKAGE_VERSION"] == toolchain_pins["ja4_zeek_package"], (
        f"Dockerfile installs ja4 {args['JA4_PACKAGE_VERSION']} but the pin is "
        f"{toolchain_pins['ja4_zeek_package']}"
    )


@pytest.mark.requires_tools
@pytest.mark.parametrize("tool", sorted(VERSION_FLAG))
def test_tool_version_matches_pin(tool, toolchain_pins, strict_toolchain):
    installed = tool_version(tool)
    pinned = toolchain_pins[PIN_KEY[tool]]

    if strict_toolchain:
        assert installed == pinned, (
            f"{tool} is {installed}, pinned at {pinned}. Under --strict-toolchain the "
            f"container and the pin must agree exactly — rebuild the image or bump the pin."
        )
    else:
        major_minor = ".".join(installed.split(".")[:2])
        expected = ".".join(pinned.split(".")[:2])
        assert major_minor == expected, (
            f"{tool} is {installed}, pinned at {pinned} — a major.minor mismatch. "
            f"See docs/dev-setup.md."
        )


@pytest.mark.requires_tools
def test_zeek_loads_ja4_package(strict_toolchain):
    """The ``zeek/foxio/ja4`` package parses, so step 5 can compute JA4 on TLS flows.

    Skipped when the package is absent (a laptop with a broken ``zkg``); fatal under
    ``--strict-toolchain``, so the CI container can never silently ship without it.

    Asks Zeek to load the package rather than looking for its directory: that tests the
    capability step 5 actually needs and stays correct wherever ``zkg`` chose to install it.
    """
    parse = subprocess.run(
        ["zeek", "--parse-only", "-e", "@load ja4"],
        capture_output=True,
        text=True,
    )

    if parse.returncode != 0 and not strict_toolchain:
        pytest.skip("zeek/foxio/ja4 is not installed — see docs/dev-setup.md")

    assert parse.returncode == 0, (
        "Zeek cannot load the ja4 package. JA4 is computed by Zeek and is the single "
        f"authority for the value carried on a label (docs/prd.md §9), so the container "
        f"must ship it. Zeek said:\n{parse.stderr}"
    )
