"""Whether the optional `db` extra is installed — one implementation, in one place.

A module of its own rather than a helper in `conftest.py`, for a measured reason: there are TWO
conftest files in this suite (`tests/` and `tests/integration/`), both importable under the module
name `conftest`, so `from conftest import ...` resolves to whichever pytest loaded first. Measured
2026-08-21: it resolved to `tests/integration/conftest.py` and the import failed. A uniquely named
module cannot be ambiguous.
"""

from __future__ import annotations

import importlib.util


def module_is_available(name: str) -> bool:
    """Whether `name` can be imported, without importing it and without raising.

    **`importlib.util.find_spec` on a dotted name raises when the parent is absent.** It has to
    import the parent package to find its `__path__`, so `ModuleNotFoundError` comes out instead of
    the `None` the caller is testing for. Measured 2026-08-21:

        find_spec("definitely_not_a_package.sub")  -> raises ModuleNotFoundError
        find_spec("definitely_not_a_package")      -> returns None

    The bare-name case returning `None` is exactly what makes the dotted case look correct.
    Unwrapped, the `db` extra guard turned "the extra is not installed" into a collection ERROR, so
    the suite was red on a checkout without it — and `uv sync` installs no extras, so that is the
    default checkout. `ValueError` is caught too: `find_spec` raises it for an imported module whose
    `__spec__` is None.
    """
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False
