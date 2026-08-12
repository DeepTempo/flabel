"""Architectural guards (spec §2, §3).

Two invariants that no unit test would catch, both cheap to check and both surviving
refactoring because they read the source rather than the behaviour:

* **Pure modules perform no I/O.** This is what makes "a labelling run performs no network
  I/O" (spec §2.2) checkable rather than aspirational, and it keeps the modules that decide
  what a label *means* testable without tools.
* **`models.py` imports nothing from the package.** That acyclic base is what lets steps 3-8
  be built in parallel without importing one another.

Imports are read from the AST rather than grepped, so a module may still *mention*
`subprocess` in a comment explaining why it doesn't use one.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "src" / "flabel"

#: Spec §3. These must not import subprocess, urllib or socket. Listed by name rather than
#: discovered, so a new module is a deliberate decision about which side of the line it is on.
PURE_MODULES = (
    "models.py",
    "errors.py",
    "config.py",
    "correlate.py",
    "labels.py",
    "provenance.py",
    "notice.py",
    "rules/admit.py",
)

#: Spec §2.2: only `flabel rules update` touches the network, and only through this module.
NETWORK_MODULE = "rules/fetch.py"

FORBIDDEN_IN_PURE = frozenset({"subprocess", "urllib", "socket", "http", "requests", "ftplib"})


def imported_modules(path: pathlib.Path) -> set[str]:
    """Top-level names of everything `path` imports."""
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def existing(*relative: str) -> list[pathlib.Path]:
    """Only the modules that exist yet — the guard grows as steps land."""
    return [PACKAGE / name for name in relative if (PACKAGE / name).exists()]


@pytest.mark.parametrize("module", PURE_MODULES)
def test_pure_modules_perform_no_io(module):
    path = PACKAGE / module
    if not path.exists():
        pytest.skip(f"{module} lands in a later step")

    offenders = imported_modules(path) & FORBIDDEN_IN_PURE
    assert not offenders, (
        f"{module} is a pure module (spec §3) but imports {sorted(offenders)}. "
        f"Move the I/O to an impure module rather than relaxing this guard."
    )


def test_models_imports_nothing_from_the_package():
    """The base of the dependency graph. If it imports upward, the parallel steps deadlock."""
    imports = imported_modules(PACKAGE / "models.py")
    assert "flabel" not in imports, f"models.py must not import from flabel: {sorted(imports)}"


def test_pure_modules_are_all_accounted_for():
    """Every module is explicitly pure or explicitly impure — no unclassified third state.

    Without this, adding a module quietly opts it out of the I/O guard.
    """
    impure = {"ingest.py", "zeek.py", "suricata.py", "cli.py", NETWORK_MODULE}
    classified = set(PURE_MODULES) | impure | {"__init__.py", "rules/__init__.py"}

    present = {
        str(path.relative_to(PACKAGE))
        for path in PACKAGE.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    unclassified = present - classified
    assert not unclassified, (
        f"unclassified modules: {sorted(unclassified)}. Add each to PURE_MODULES or to the "
        f"impure list in this test, so the I/O guard cannot be sidestepped by accident."
    )


def test_only_the_fetch_module_may_touch_the_network():
    """The inverse of the purity guard: network I/O is confined to one file, by name."""
    network_names = frozenset({"urllib", "socket", "http", "requests", "ftplib"})
    for path in PACKAGE.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        relative = str(path.relative_to(PACKAGE))
        if relative == NETWORK_MODULE:
            continue
        offenders = imported_modules(path) & network_names
        assert not offenders, (
            f"{relative} imports {sorted(offenders)}. Only {NETWORK_MODULE} may perform "
            f"network I/O (spec §2.2), which is what makes a labelling run offline by "
            f"construction rather than by convention."
        )
