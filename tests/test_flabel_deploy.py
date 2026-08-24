"""The `flabel-deploy` wrapper (tools/flabel-deploy).

Same reason `tools/flabel-run` has tests, and the same evidence behind it: this layer is where the
bugs live, because it is the one layer the architecture guard, the NOTICE check and CI never see.

The specific failure this script exists to prevent is recorded in spec-label-store §7.5 — the
two-step deploy left the box **two merges behind with #137 undeployed**, because reinstalling the
wrapper was a step someone had to remember.

Nothing here needs `/opt`, `/usr/local/bin` or root. Every external command is overridable, so
`git`, `uv` and the privilege wrapper are pointed at stubs that record instead of executing. Two
tests deliberately use the **real** `pgrep`, because the busy-guard's hazard is a property of what
`pgrep` actually matches and a stub would encode our assumption about it — which is the thing that
needs verifying (CLAUDE.md, "Tools real, network stubbed").
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "tools" / "flabel-deploy"


@pytest.fixture
def box(tmp_path: Path) -> dict[str, str]:
    """A fake deployment box: a checkout, an install destination, and recorders for git and uv."""
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    source = repo / "tools" / "flabel-run"
    source.write_text("#!/bin/bash\necho the checked-out wrapper\n")
    source.chmod(0o755)

    installed = tmp_path / "bin" / "flabel-run"
    installed.parent.mkdir()

    log = tmp_path / "commands"

    def stub(name: str, body: str) -> Path:
        path = tmp_path / f"fake-{name}"
        # `$*` and not `$@`: this log is read as ordered lines of "what was issued", and one line
        # per command is what makes "aborted before the pull" a single readable assertion.
        path.write_text(f'#!/bin/bash\nprintf "{name} %s\\n" "$*" >> {log}\n{body}\n')
        path.chmod(0o755)
        return path

    git = stub("git", 'exit "${FAKE_GIT_EXIT:-0}"')
    # One stub for both `uv sync` and `uv run flabel-db verify`, dispatching on the subcommand, so
    # a test can fail the sync and the verify independently — which is what "a failed verify does
    # not proceed to the reinstall" needs in order to mean anything.
    uv = stub(
        "uv",
        'case "$1" in\n'
        '  sync) exit "${FAKE_SYNC_EXIT:-0}" ;;\n'
        '  run)  exit "${FAKE_VERIFY_EXIT:-0}" ;;\n'
        "esac\n"
        "exit 0",
    )
    # `pgrep -af` prints "<pid> <command line>". The stub reproduces that shape, and exits 1 with
    # no output when nothing matches, exactly as pgrep does.
    pgrep = stub(
        "pgrep",
        'if [ -n "${FAKE_PGREP_MATCH:-}" ]; then printf "%s\\n" "$FAKE_PGREP_MATCH"; exit 0; fi\n'
        "exit 1",
    )

    return {
        "FLABEL_DEPLOY_REPO": str(repo),
        "FLABEL_DEPLOY_INSTALL_TO": str(installed),
        "FLABEL_DEPLOY_GIT": str(git),
        "FLABEL_DEPLOY_UV": str(uv),
        "FLABEL_DEPLOY_PGREP": str(pgrep),
        # Empty, so `install` runs directly and actually copies the file. In production this
        # defaults to `sudo`, because /usr/local/bin is not writable by the operator —
        # `test_the_install_is_privileged_by_default` is what holds that default in place.
        "FLABEL_DEPLOY_SUDO": "",
        "_log": str(log),
        "_source": str(source),
        "_installed": str(installed),
        "_tmp": str(tmp_path),
    }


def invoke(
    box: dict[str, str], *args: str, extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **{k: v for k, v in box.items() if not k.startswith("_")}}
    env.update(extra or {})
    # The same sentinel `test_flabel_run.py` uses, for the same reason: the fixture sets
    # `FLABEL_DEPLOY_SUDO` to the EMPTY string on purpose, so a test that wants the script's own
    # default has to remove the name from the environment entirely, which "" cannot express.
    for name, value in list(env.items()):
        if value == "__unset__":
            del env[name]
    return subprocess.run(
        [str(WRAPPER), *args], capture_output=True, text=True, env=env, cwd=box["_tmp"], check=False
    )


def issued(box: dict[str, str]) -> list[str]:
    """Every command the script issued, in order, or `[]` if it issued none."""
    log = Path(box["_log"])
    return log.read_text().splitlines() if log.exists() else []


def commands(box: dict[str, str]) -> list[str]:
    """Just the command names, which is the ordering assertion without the argument noise."""
    return [line.split(" ", 1)[0] for line in issued(box)]


# --- the happy path -----------------------------------------------------------------------------


def test_the_deploy_issues_pull_sync_verify_and_install_in_that_order(box):
    """All three steps of spec-label-store §7.5 plus the gate, and **the order is the contract**.

    `uv sync` before `flabel-db verify` because verify is a console script of the `db` extra that
    the sync installs; verify before the reinstall because a dataset that has drifted must stop the
    deploy while the box still runs the wrapper it was running before.
    """
    result = invoke(box)

    assert result.returncode == 0, result.stderr
    assert commands(box) == ["pgrep", "git", "uv", "uv", "git"], issued(box)
    assert issued(box)[1] == "git pull --ff-only"
    assert issued(box)[2] == "uv sync --extra db"
    assert issued(box)[3] == "uv run flabel-db verify"
    # The trailing `git` is the deployed-commit line. It runs AFTER the install, so it cannot be
    # mistaken for a step, and it is what turns "the deploy ran" into "the box is on this commit"
    # — the fact whose absence let the box sit two merges behind.
    assert issued(box)[4].startswith("git rev-parse")
    assert Path(box["_installed"]).read_text() == Path(box["_source"]).read_text()


def test_the_pull_is_ff_only_so_a_diverged_checkout_stops_rather_than_merging(box):
    """A merge commit created on the deployment box is a state no branch in the repo has, and the
    box would then be running code nobody reviewed. `--ff-only` turns that into a refusal."""
    invoke(box)
    pulls = [line for line in issued(box) if line.startswith("git pull")]
    assert pulls == ["git pull --ff-only"], pulls


# --- the conditional reinstall ------------------------------------------------------------------


def test_a_wrapper_that_is_already_installed_is_not_reinstalled_and_the_output_says_so(box):
    """`install` overwrites IN PLACE, and bash reads a script as it executes (§7.5). Reinstalling
    a byte-identical file is therefore not a harmless no-op — it is a needless chance to corrupt a
    running wrapper — and "nothing to do" has to be visible or the operator cannot tell a skipped
    deploy from a silent one."""
    installed = Path(box["_installed"])
    installed.write_text(Path(box["_source"]).read_text())
    installed.chmod(0o755)
    before = installed.stat().st_mtime_ns

    result = invoke(box)

    assert result.returncode == 0, result.stderr
    assert installed.stat().st_mtime_ns == before, "an identical wrapper was rewritten"
    assert "not reinstalling" in result.stdout, result.stdout


def test_a_wrapper_that_differs_is_reinstalled(box):
    """The other half, and the one #137 needed: a checkout that moved must reach the box."""
    installed = Path(box["_installed"])
    installed.write_text("#!/bin/bash\necho the STALE wrapper\n")
    installed.chmod(0o755)

    result = invoke(box)

    assert result.returncode == 0, result.stderr
    assert installed.read_text() == Path(box["_source"]).read_text()
    assert "installed" in result.stdout, result.stdout


def test_a_first_deploy_installs_a_wrapper_that_is_not_there_yet(box):
    """The comparison must treat "absent" as "differs", and **the assertion that matters here is
    the clean stderr**, which the sabotage round is what established.

    The obvious claim would be that a naive `[ "$FRESH" = "$(hash_of "$INSTALL_TO")" ]` breaks the
    first deploy. It does not: `set -e` is suppressed inside an `if` condition (measured
    2026-08-24), so the failing `md5sum` yields an empty string, the comparison is false, and the
    install happens correctly. Dropping the `-f` guard left this test green when it only asserted
    the exit code and the contents.

    What the guard actually buys is that the first deploy on a fresh box does not print
    `md5sum: /usr/local/bin/flabel-run: No such file or directory` on its way to succeeding — an
    error line under a successful deploy, which is how an operator learns to ignore error lines.
    """
    installed = Path(box["_installed"])
    assert not installed.exists()

    result = invoke(box)

    assert result.returncode == 0, result.stderr
    assert installed.read_text() == Path(box["_source"]).read_text()
    assert result.stderr == "", f"a clean first deploy wrote to stderr: {result.stderr!r}"


def test_the_reinstalled_wrapper_is_executable(box):
    """A wrapper copied without the executable bit is on the box and unrunnable, which reads to the
    operator as a deploy that worked.

    **`-m 0755` is documentation, not a guard, and the sabotage round is what established that.**
    Removing the flag left this test green — because `install`'s own default mode is already 0755
    (measured 2026-08-24: `install src dst` with no `-m` produces mode 755). The flag is kept for
    saying the mode out loud rather than inheriting it, and this test is red for `-m 0644`, which
    is the mistake that can actually be made. See `passing-tests-near-new-guards-are-suspect`.
    """
    invoke(box)
    assert os.access(box["_installed"], os.X_OK), "the installed wrapper is not executable"


def test_a_checkout_with_no_wrapper_is_an_error_rather_than_a_silent_skip(box):
    """`docs/phase-2-replay-box-provision.sh` guards its install with `if [ -x ... ]` and skips
    silently, which is right for a first boot where the clone may not exist yet. It is wrong here:
    this script's entire purpose is that the box ends up running the checked-out wrapper, so a
    checkout that cannot supply one is a failure, not a step to pass over."""
    Path(box["_source"]).unlink()

    result = invoke(box)

    assert result.returncode == 1
    assert "flabel-run" in result.stderr
    assert not Path(box["_installed"]).exists()


# --- the busy guard -----------------------------------------------------------------------------


def test_a_busy_box_aborts_before_the_pull_and_before_the_install(box):
    """§7.5: `install` overwrites in place and bash reads a script as it executes, so deploying
    under a live run can change a script mid-flight.

    **Asserted on the commands issued, not on the exit code.** A script that ran the pull, ran the
    sync and then exited 1 would satisfy an exit-code assertion completely while having done the
    exact thing the guard forbids.
    """
    result = invoke(box, extra={"FAKE_PGREP_MATCH": "4242 tcpreplay -i ens5 --topspeed x.pcap"})

    # FIRST, because it is the claim. Asserting the exit code first means a script that pulled,
    # synced and then exited 1 reports as `assert 0 == 1` — technically red, and silent about the
    # thing that actually went wrong. Found by sabotaging the guard and reading what came back.
    assert commands(box) == ["pgrep"], f"the guard did not abort before the pull: {issued(box)}"
    assert result.returncode == 1
    assert not Path(box["_installed"]).exists()
    assert "4242 tcpreplay" in result.stderr, "the refusal did not name what was still running"


def test_the_busy_guard_runs_before_anything_else_at_all(box):
    """Ordering, stated as its own assertion so it cannot be satisfied by accident: `pgrep` is the
    FIRST command issued on the happy path too, not merely the only one on the refusing path."""
    invoke(box)
    assert commands(box)[0] == "pgrep", issued(box)


def test_the_real_pgrep_does_not_match_the_deploy_script_itself(box):
    """**The trap this guard walks straight into, and the real `pgrep` is the only way to see it.**

    The production pattern is `tcpreplay|flabel|uv run`, and this script is called `flabel-deploy`.
    `pgrep -af` matches against the full command line, so the bash process running this very script
    matches `flabel` — and under `sudo flabel-deploy`, so does its parent. Without dropping our own
    pid and our parent's, the guard fires on every single invocation and the deploy can never run
    at all: a refusal that looks exactly like a busy box.

    Driven by narrowing the pattern to `flabel-deploy` rather than by widening the environment, so
    the test does not depend on what else happens to be running on the machine.
    """
    if shutil.which("pgrep") is None:
        pytest.skip("no pgrep here — the guard's own refusal is covered by its own test")

    result = invoke(
        box,
        extra={"FLABEL_DEPLOY_PGREP": "__unset__", "FLABEL_DEPLOY_BUSY_PATTERN": "flabel-deploy"},
    )

    assert result.returncode == 0, f"the deploy refused because of its own process: {result.stderr}"
    assert Path(box["_installed"]).exists()


def test_the_real_pgrep_still_sees_a_process_that_is_genuinely_running(box, tmp_path):
    """The other half, and it is not redundant: an over-broad self-exclusion — dropping every match
    rather than our own two pids — would pass the test above and leave the guard inert.

    A `sleep` renamed into the pattern, so the match is a real process found by the real tool.
    The marker is deliberately NOT named `flabel-deploy-...`: the self-exclusion drops any line
    naming this script, so such a marker would be filtered as our own process and this test would
    go green for precisely the wrong reason.
    """
    if shutil.which("pgrep") is None:
        pytest.skip("no pgrep here — the guard's own refusal is covered by its own test")

    marker = tmp_path / "flabel-busy-marker"
    marker.symlink_to(shutil.which("sleep") or "/bin/sleep")
    child = subprocess.Popen([str(marker), "30"])
    try:
        # **Wait until pgrep can actually see it.** `Popen` returns as soon as the fork succeeds,
        # before the child has exec'd, so the deploy could run its guard against a process that
        # does not yet have its command line — the test then measures the race rather than the
        # guard. This box was fast enough and CI was not: it went green here and red there, which
        # is the only reason the race was visible at all.
        for _ in range(200):
            if (
                subprocess.run(
                    ["pgrep", "-f", "flabel-busy-marker"], capture_output=True
                ).returncode
                == 0
            ):
                break
            time.sleep(0.05)
        else:
            pytest.fail("the marker process never became visible to pgrep")

        result = invoke(
            box,
            extra={
                "FLABEL_DEPLOY_PGREP": "__unset__",
                "FLABEL_DEPLOY_BUSY_PATTERN": "flabel-busy-marker",
            },
        )
    finally:
        child.terminate()
        child.wait(timeout=10)

    assert result.returncode == 1, "the real pgrep did not see a process that was genuinely running"
    assert commands(box) == [], issued(box)


# --- a failing step stops the one after it ------------------------------------------------------


def test_a_failed_pull_does_not_proceed_to_uv_sync(box):
    """Deploying a checkout that did not move is not a smaller deploy; it is a deploy of the wrong
    commit, reported as a success."""
    result = invoke(box, extra={"FAKE_GIT_EXIT": "1"})

    # The commands first: that is the claim, and the exit code is the weaker check (see the busy
    # guard's test for what reading the sabotage output taught).
    assert commands(box) == ["pgrep", "git"], issued(box)
    assert result.returncode == 1
    assert not Path(box["_installed"]).exists()


def test_a_failed_sync_does_not_proceed_to_verify(box):
    """`flabel-db verify` is a console script the sync installs. Running it after a failed sync
    reports on whatever version was already there, which is the reading it must never give."""
    result = invoke(box, extra={"FAKE_SYNC_EXIT": "1"})

    # The commands first: that is the claim, and the exit code is the weaker check (see the busy
    # guard's test for what reading the sabotage output taught).
    assert commands(box) == ["pgrep", "git", "uv"], issued(box)
    assert result.returncode == 1
    assert not Path(box["_installed"]).exists()


def test_a_failed_verify_does_not_proceed_to_the_reinstall(box):
    """**The pre-deploy gate, and the reason it exists here rather than in CI** (spec-label-store
    §2 testing line, decided 2026-08-20): CI has no GCP credential and this repo is public, so this
    is the only place the live dataset is ever checked against the declaration.

    A gate that reports drift and then deploys anyway is not a gate. The box keeps running the
    wrapper it was already running.
    """
    result = invoke(box, extra={"FAKE_VERIFY_EXIT": "1"})

    # The commands first: that is the claim, and the exit code is the weaker check (see the busy
    # guard's test for what reading the sabotage output taught).
    assert commands(box) == ["pgrep", "git", "uv", "uv"], issued(box)
    assert result.returncode == 1
    assert not Path(box["_installed"]).exists()
    assert "verify" in result.stderr, result.stderr


def test_a_failed_verify_leaves_an_already_installed_wrapper_untouched(box):
    """The stronger form of the above: "did not install" and "did not overwrite" are different
    claims, and the second is the one that matters on a box that is already deployed."""
    installed = Path(box["_installed"])
    installed.write_text("#!/bin/bash\necho the STALE wrapper\n")

    result = invoke(box, extra={"FAKE_VERIFY_EXIT": "1"})

    assert result.returncode == 1
    assert installed.read_text() == "#!/bin/bash\necho the STALE wrapper\n"


# --- the contract at the edges ------------------------------------------------------------------


def test_help_goes_to_stdout_and_exits_0(box):
    """`flabel-run`'s convention: an explicit --help is the operator asking, and a script that
    answers it on stderr with a failing status cannot be piped into a pager."""
    result = invoke(box, "--help")

    assert result.returncode == 0
    assert "flabel-deploy" in result.stdout
    assert result.stderr == ""
    assert issued(box) == [], "--help issued a command"


def test_an_unknown_argument_exits_2_without_deploying_anything(box):
    """A usage error is the operator being TOLD, so it goes to stderr with exit 2 — and it must not
    have half-deployed on the way to finding out."""
    result = invoke(box, "--force")

    assert result.returncode == 2
    assert result.stdout == ""
    assert issued(box) == [], issued(box)


def test_the_install_is_privileged_by_default(box):
    """`/usr/local/bin` is not writable by the operator, so the default must be `sudo` — and the
    fixture sets it EMPTY, which is exactly the kind of test-only convenience that silently becomes
    the production default. Read out of the script rather than executed.

    **The no-colon form is the assertion.** `${VAR:-sudo}` treats an empty value as unset and would
    elevate anyway, so it cannot express "run unwrapped" at all — `flabel-run` draws the same
    distinction on `PUBLISH_SUDO` for the same reason.
    """
    text = WRAPPER.read_text()
    assert 'SUDO="${FLABEL_DEPLOY_SUDO-sudo}"' in text


def test_the_production_defaults_are_the_boxes_real_paths(box):
    """The overrides exist so the tests need neither `/opt` nor root (the plan's fourth bullet).
    That is only safe if the defaults are still the real ones — an override whose default drifted
    to a tmp path would make every test above pass while deploying nothing."""
    text = WRAPPER.read_text()
    assert 'REPO="${FLABEL_DEPLOY_REPO:-/opt/flabel/repo}"' in text
    assert 'INSTALL_TO="${FLABEL_DEPLOY_INSTALL_TO:-/usr/local/bin/flabel-run}"' in text
    assert 'BUSY_PATTERN="${FLABEL_DEPLOY_BUSY_PATTERN:-tcpreplay|flabel|uv run}"' in text


def test_a_pgrep_that_is_not_there_stops_the_deploy_rather_than_reading_as_idle(box):
    """**A guard that cannot run must stop the deploy.**

    `busy()` ends in `|| true` so that pgrep's no-match exit 1 is not fatal — and that same
    `|| true`, with the `2>/dev/null` beside it, swallows "command not found" just as quietly. The
    result is a guard that reports an idle box on a busy one, and an `install` that overwrites a
    wrapper mid-run.

    Not hypothetical: `procps` is absent from plenty of minimal images, and this repo's own CI
    container is built with `--no-install-recommends`. This test is also why the two real-`pgrep`
    tests may skip without leaving the behaviour uncovered.
    """
    result = invoke(box, extra={"FLABEL_DEPLOY_PGREP": "/nonexistent/pgrep"})

    assert commands(box) == [], issued(box)
    assert result.returncode == 1
    assert not Path(box["_installed"]).exists()
    assert "UNKNOWABLE" in result.stderr, result.stderr
