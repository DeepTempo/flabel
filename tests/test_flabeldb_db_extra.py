"""The `db` extra gate — the check that decides whether the store's tests can run at all.

**The suite was RED on a checkout without the extra**, which is the default checkout: `uv sync`
installs no extras, and `flabel` itself declares `dependencies = []` precisely so it has none.

The cause is a trap in the standard library. `importlib.util.find_spec` on a **dotted** name has to
import the parent package to find its `__path__`, so when the parent is absent it **raises
ModuleNotFoundError instead of returning None**. Measured 2026-08-21:

    find_spec("definitely_not_a_package.sub")  -> raises ModuleNotFoundError
    find_spec("definitely_not_a_package")      -> returns None

So `find_spec("google.cloud.bigquery") is None` — written to mean "skip if the extra is missing" —
raised during collection instead, turning a clean skip into a collection ERROR for the whole file.

And CI could not notice, because this branch made `--extra db` unconditional in **both** jobs. A
gate never exercised in the state it guards against is not a gate. `.github/workflows/ci.yml` now
has a job that syncs WITHOUT the extra, and `docs/PLAN-label-store.md` records that ci.yml was
touched outside LS-3's stated file list.
"""

from __future__ import annotations

import importlib.util

import pytest

from db_extra import module_is_available

ABSENT = "definitely_not_a_package_and_never_will_be"


def test_the_stdlib_trap_this_guard_exists_for_is_still_real():
    """If CPython ever makes this return None, the wrapper is harmless — but say so out loud.

    Asserting the trap rather than assuming it: the whole defect was a reasonable-looking belief
    about what `find_spec` returns.
    """
    with pytest.raises(ModuleNotFoundError):
        importlib.util.find_spec(f"{ABSENT}.sub")

    assert importlib.util.find_spec(ABSENT) is None, (
        "a BARE name returns None — which is why the dotted case looked correct"
    )


def test_a_missing_dotted_module_reads_as_absent_and_does_not_raise():
    """The fix, tested on the mechanism rather than on `google.cloud.bigquery`.

    Testing it against the real module name would prove nothing on a machine that HAS the extra —
    which is every machine CI runs on, and the reason this went unnoticed.
    """
    assert module_is_available(f"{ABSENT}.sub") is False


def test_a_missing_bare_module_also_reads_as_absent():
    assert module_is_available(ABSENT) is False


def test_a_module_that_is_present_reads_as_present():
    assert module_is_available("importlib.util") is True
    assert module_is_available("pytest") is True


def test_the_guard_returns_a_bool_and_not_a_spec():
    """`find_spec` returns a truthy object; a caller writing `if guard(...)` must not get one."""
    assert module_is_available("pytest") is True
    assert module_is_available(ABSENT) is False


def test_the_db_extra_marker_is_registered(pytestconfig):
    """`--strict-markers` is on, so a typo would make a test that is neither run nor skipped."""
    markers = pytestconfig.getini("markers")
    assert any(line.startswith("requires_db_extra:") for line in markers), (
        f"requires_db_extra is not registered in pyproject.toml: {markers}"
    )


@pytest.mark.requires_db_extra
def test_a_marked_test_runs_when_the_extra_is_installed():
    """Self-check: on a machine WITH the extra this must execute, not skip.

    A gate that skips everything is indistinguishable from a gate that works, which is the failure
    mode `--require-tool-tests` exists for one layer up.
    """
    import google.cloud.bigquery  # noqa: F401


# --- the CI job, asserted here rather than trusted to exist ------------------------------------
#
# `ci.yml` itself says it, about three separate incidents (#74, #98, #101): a gate whose logic
# lives only inside a workflow is one nothing can prove is able to fail. `test_toolchain.py` reads
# ci.yml the same way, for the same reason.

import pathlib  # noqa: E402

CI = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


def ci_job(name: str) -> str:
    """The YAML block for one job, COMMENTS STRIPPED. No yaml dependency, as test_toolchain.py does.

    Comments are stripped because they cannot change what CI does, and the comment on the
    `no-db-extra` job necessarily quotes the very flag the job must not pass — which tripped the
    first version of this test.
    """
    text = CI.read_text(encoding="utf-8")
    start = text.index(f"\n  {name}:\n")
    rest = text[start + 1 :]
    lines = rest.splitlines(keepends=True)
    block = [lines[0]]
    for line in lines[1:]:
        # the next job starts at two-space indentation with a bare key
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            break
        block.append(line)
    return "".join(line for line in block if not line.lstrip().startswith("#"))


def test_ci_has_a_job_that_runs_on_a_bare_machine():
    """Without this job, nothing exercises the state the guard exists for.

    This branch made `--extra db` unconditional in both pre-existing jobs, so the default checkout
    — `uv sync`, no extras — was the one state CI could no longer see.

    Renamed from `no-db-extra` on 2026-08-21, because the job turned out to guard **two**
    invariants and the old name claimed only one. It is the only job outside the toolchain
    container, so it is also the only place an unmarked `requires_tools` test can fail: on its
    first run it caught eleven of them in `test_cli.py` and `test_suricata.py`, which every other
    job had been passing for weeks because the tools are always present there.
    """
    job = ci_job("bare-runner")

    assert "uv sync" in job, "the job does not sync at all"
    assert "--extra db" not in job, (
        "the bare-runner job passes --extra db, which defeats half its purpose"
    )
    assert "pytest" in job, "the job syncs but never runs the suite, so it proves nothing"
    assert "--locked" in job, "plain `uv sync` silently re-resolves; CI must use --locked"
    # The second invariant, which the rename is about. Installing the toolchain here would make
    # the job green again while deleting the only check on the `requires_tools` marker.
    assert "container" not in job, (
        "the bare-runner job runs in a container; it must run on a BARE machine, because that is "
        "what makes an unmarked requires_tools test fail somewhere"
    )
    for tool in ("zeek", "suricata", "wireshark"):
        assert tool not in job.lower(), (
            f"the bare-runner job installs {tool}. An unmarked requires_tools test would then "
            f"pass here as it does everywhere else, and nothing would ever catch it."
        )


def test_the_other_ci_jobs_still_install_the_extra():
    """The complement: the pure store tests must not silently stop running in CI.

    46 tests are gated on the extra. A branch that dropped `--extra db` everywhere would make this
    file's guard look perfect while quietly skipping all of them.
    """
    for name in ("lint", "test"):
        assert "--extra db" in ci_job(name), (
            f"the `{name}` job no longer installs the db extra, so the store's pure tests skip "
            f"in CI — which is how LS-3 shipped two broken commands green"
        )
