"""The toolchain is present, real, and at the pinned versions.

Every later step's tests invoke Zeek, Suricata or ``editcap`` for real, so these are the
tests that prove the environment can support them at all. They are also the Goal 2
precondition: reproducibility only means something across *pinned* tool versions.

Version comparison is major.minor by default and exact under ``--strict-toolchain``; see
``conftest.py`` for why.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

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
    dockerfile = (REPO_ROOT / "Dockerfile.toolchain").read_text()
    args = dict(re.findall(r"^ARG (\w+)=(\S+)$", dockerfile, re.MULTILINE))

    required = (
        "ZEEK_VERSION",
        "ZEEK_PACKAGE_VERSION",
        "SURICATA_PACKAGE_VERSION",
        "WIRESHARK_PACKAGE_VERSION",
        "JA4_PACKAGE_VERSION",
        "JA4_PACKAGE_COMMIT",
    )
    for name in required:
        assert name in args, f"Dockerfile.toolchain has no `ARG {name}=<value>` with a default"

    # The apt ARGs are what actually get installed, so they must carry the pinned version.
    # Substring rather than equality: apt versions add epochs and suffixes like
    # `1:8.0.6-0ubuntu0` and `4.6.6-1~ubuntu24.04.0~ppa1`. Without this, bumping a pin and
    # forgetting its ARG only surfaces after a ~15-minute image build.
    for pin, arg in (
        ("zeek", "ZEEK_PACKAGE_VERSION"),
        ("suricata", "SURICATA_PACKAGE_VERSION"),
        ("wireshark", "WIRESHARK_PACKAGE_VERSION"),
    ):
        assert toolchain_pins[pin] in args[arg], (
            f"{arg}={args[arg]} does not contain the pinned {pin} version "
            f"{toolchain_pins[pin]} — the image would install something else"
        )

    zeek_line = ".".join(toolchain_pins["zeek"].split(".")[:2])
    assert args["ZEEK_VERSION"] == zeek_line, (
        f"Dockerfile installs zeek-{args['ZEEK_VERSION']} but the pin is "
        f"{toolchain_pins['zeek']} (the {zeek_line} line)"
    )
    assert args["JA4_PACKAGE_VERSION"] == toolchain_pins["ja4_zeek_package"], (
        f"Dockerfile installs ja4 {args['JA4_PACKAGE_VERSION']} but the pin is "
        f"{toolchain_pins['ja4_zeek_package']}"
    )
    assert args["JA4_PACKAGE_COMMIT"] == toolchain_pins["ja4_zeek_commit"], (
        f"Dockerfile expects ja4 commit {args['JA4_PACKAGE_COMMIT']} but the pin is "
        f"{toolchain_pins['ja4_zeek_commit']}"
    )


def test_ci_still_passes_the_toolchain_flags(toolchain_pins):
    """CI's own invocation is a gate, not a convention.

    Everything here rests on one line of YAML. Drop ``--require-tool-tests``, or swap the
    digest for a moving tag, and every test in this repo still passes while the guarantees
    quietly evaporate. So the workflow is asserted like any other contract.
    """
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text()

    assert "--require-tool-tests" in ci, "ci.yml no longer fails on a skipped tool suite"
    assert "--strict-toolchain" in ci, "ci.yml no longer asserts exact tool versions"
    assert re.search(r"image:\s*\S+@sha256:[0-9a-f]{64}", ci), (
        "ci.yml's container must be pinned by digest, not by tag — a tag can move "
        "underneath a green build, which is what Goal 2 rules out"
    )
    assert "uv sync --locked" in ci, (
        "ci.yml must use `uv sync --locked`; plain `uv sync` silently re-resolves "
        "dependencies when uv.lock is stale"
    )


# Deliberately not marked requires_tools: it reads a file rather than invoking anything, so
# counting it toward "a tool test ran" would weaken the gate it sits next to.
def test_recorded_manifest_matches_the_pins(toolchain_pins, strict_toolchain):
    """``/etc/flabel-toolchain.json`` is what the image says it installed.

    It exists only inside the container, and `provenance.py` is earmarked to read it, at
    which point these strings end up on shipped labels. So it is checked against the pins
    rather than trusted.

    Under ``--strict-toolchain`` a missing manifest is a failure, not a skip: this is the
    only runtime assertion on ``ja4_zeek_commit``, so if the recorded-versions layer were
    ever dropped from the Dockerfile, skipping here would leave that pin unguarded in CI.
    """
    manifest = pathlib.Path("/etc/flabel-toolchain.json")
    if not manifest.exists():
        if strict_toolchain:
            pytest.fail(
                "the toolchain image must ship /etc/flabel-toolchain.json — it is the only "
                "runtime check on the ja4 commit pin, and provenance.py will read it"
            )
        pytest.skip("not running inside the toolchain container")

    recorded = json.loads(manifest.read_text())
    for key in ("zeek", "suricata", "wireshark", "ja4_zeek_package", "ja4_zeek_commit"):
        assert recorded.get(key) == toolchain_pins[key], (
            f"image recorded {key}={recorded.get(key)!r}, pin says "
            f"{toolchain_pins[key]!r} — rebuild the image or fix the pin"
        )


@pytest.mark.requires_tools
def test_installed_ja4_version_matches_the_pin(toolchain_pins, strict_toolchain):
    """The ja4 version Zeek will actually use, as reported by zkg.

    Checked separately from the Dockerfile text because that text only describes the build
    that *should* have happened: a ``--build-arg`` override, or a rebuild after upstream
    moved the tag, both yield an image whose ja4 differs from the pin while every other
    assertion here still passes. This one changes label content, so it gets a real check.
    """
    listing = subprocess.run(["zkg", "list"], capture_output=True, text=True)
    if listing.returncode != 0:
        if strict_toolchain:
            pytest.fail(f"zkg is not usable, so the ja4 pin cannot be verified: {listing.stderr}")
        pytest.skip("zkg is not usable here — see docs/dev-setup.md")

    match = re.search(r"zeek/foxio/ja4 \(installed: (\S+)\)", listing.stdout)
    if match is None and not strict_toolchain:
        pytest.skip("zeek/foxio/ja4 is not installed — see docs/dev-setup.md")

    assert match is not None, f"zkg does not report ja4 as installed:\n{listing.stdout}"
    assert match.group(1) == toolchain_pins["ja4_zeek_package"], (
        f"ja4 {match.group(1)} is installed but the pin is "
        f"{toolchain_pins['ja4_zeek_package']}. A different ja4 version can change the JA4 "
        f"value carried on labels (docs/prd.md §9), so this is a reproducibility break."
    )

    # zkg reports the *tag*, which is the mutable thing the commit pin defends against, so
    # check the commit actually checked out — the code Zeek will load, not a claim about it.
    clone = _ja4_clone_dir()
    if clone is None or not (clone / ".git").exists():
        if strict_toolchain:
            pytest.fail(f"ja4 clone not found at {clone}, so the commit pin cannot be verified")
        pytest.skip("ja4 clone directory not found — cannot verify the commit pin")

    head = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert head.stdout.strip() == toolchain_pins["ja4_zeek_commit"], (
        f"ja4 is at commit {head.stdout.strip()} but the pin is "
        f"{toolchain_pins['ja4_zeek_commit']} — the tag moved, or the pin is stale"
    )


def _ja4_clone_dir() -> pathlib.Path | None:
    """Where zkg keeps its ja4 clone, derived the same way Dockerfile.toolchain derives it."""
    config = subprocess.run(["zkg", "config"], capture_output=True, text=True)
    if config.returncode != 0:
        return None
    for line in config.stdout.splitlines():
        if line.startswith("state_dir = "):
            return pathlib.Path(line.removeprefix("state_dir = ").strip()) / "clones/package/ja4"
    return None


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
