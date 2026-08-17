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

Scope, stated honestly: this catches direct imports, including the `os.system`/`os.popen` and
`importlib.import_module` spellings of the same thing. It does **not** prove a run makes no
network call — a runtime socket guard on the real pipeline is step 9's job (PLAN step 9). What
it does buy is that the decision is explicit: no module can quietly become impure.
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
    "canonical.py",
    "rules/admit.py",
)

#: Spec §2.2: only `flabel rules update` touches the network, and only through this module.
NETWORK_MODULE = "rules/fetch.py"

#: Every module permitted to perform network I/O, with the reason each one is here.
#:
#: `panw.py` was added for Phase 2 (Craig, 2026-08-17). Spec §2.2's "a labelling run performs no
#: network I/O" was written when every mode read files, and tier 1 cannot honour it: the firewall
#: has to be asked what it saw. The guarantee therefore moved to the mode that can keep it —
#: **`--offline` performs no network I/O; the default path contacts the device** — which is what
#: `--offline` meant when it was named, a phase before this module existed.
#:
#: The list stays closed and by name. Two modules with a stated reason is a boundary; "any module
#: that needs it" is not, and the whole value of this guard is that becoming network-facing is a
#: decision someone had to write down.
NETWORK_MODULES = frozenset({NETWORK_MODULE, "panw.py"})

#: `os` is here for `os.system`/`os.popen`, which are subprocess execution by another name and
#: would otherwise sail past a guard that only looks at imports of `subprocess`. `importlib`
#: because `importlib.import_module("subprocess")` is the same bypass spelled differently.
FORBIDDEN_IN_PURE = frozenset(
    {"subprocess", "urllib", "socket", "http", "requests", "ftplib", "asyncio", "ssl", "importlib"}
)

#: Modules a pure module may legitimately import despite the rule above, with the reason.
PURE_EXEMPTIONS = {
    # config.py reads the registry from disk; spec §3 classes filesystem reads as pure. It
    # needs importlib.resources to find package data, which cannot execute anything.
    ("config.py", "importlib"),
}


def imported_modules(path: pathlib.Path) -> set[str]:
    """Top-level names of everything `path` imports."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("module", PURE_MODULES)
def test_pure_modules_perform_no_io(module):
    path = PACKAGE / module
    # Was a skip while modules were landing one step at a time. All ten steps are merged, so a
    # listed module that is absent now means it was renamed or deleted — and a skip would drop
    # its I/O guard without a word (#95). `test_pure_modules_are_all_accounted_for` catches a
    # *new* unclassified module; only this catches a listed one going missing.
    assert path.exists(), (
        f"{module} is listed in PURE_MODULES but does not exist. If it was renamed, rename it "
        f"here too; if it was deleted, remove it here — do not let its purity guard vanish."
    )

    offenders = {
        name
        for name in imported_modules(path) & FORBIDDEN_IN_PURE
        if (module, name) not in PURE_EXEMPTIONS
    }
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
    # rules/snapshot.py is impure because it *writes* files. config.py reads the registry and
    # is classified pure (spec §3 counts a filesystem read as pure), so the line between them
    # is writing, not touching the disk at all.
    impure = {
        "ingest.py",
        "zeek.py",
        "suricata.py",
        "cli.py",
        "rules/snapshot.py",
        # Impure because it drives tcpprep/tcprewrite/tcpreplay as subprocesses. The timestamp
        # arithmetic — the part a wrong answer would put on a label — is pure and lives on
        # `ReplayWindow`, so `tests/test_replay.py` exercises it without a NIC or a firewall.
        "replay.py",
        # Impure because it drives replay.py and panw.py in sequence. It makes no decision
        # about what a label says — those live in panw.py, which is testable without a device.
        "tier1.py",
        *NETWORK_MODULES,
    }
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


def test_only_named_modules_may_touch_the_network():
    """The inverse of the purity guard: network I/O is confined to named files.

    Two now rather than one, and the difference between them is worth stating: `rules/fetch.py`
    reaches feed endpoints and is never on a labelling path at all, while `panw.py` is on the
    default labelling path by design. That is why the no-network guarantee now belongs to
    `--offline` rather than to every run (see `NETWORK_MODULES`).
    """
    network_names = frozenset({"urllib", "socket", "http", "requests", "ftplib", "ssl"})
    for path in PACKAGE.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        relative = str(path.relative_to(PACKAGE))
        if relative in NETWORK_MODULES:
            continue
        offenders = imported_modules(path) & network_names
        assert not offenders, (
            f"{relative} imports {sorted(offenders)}. Only {sorted(NETWORK_MODULES)} may "
            f"perform network I/O, which is what keeps `--offline` offline by construction "
            f"rather than by convention."
        )
