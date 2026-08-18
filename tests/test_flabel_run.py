"""The `flabel-run` wrapper (tools/flabel-run).

**Why a shell script has tests at all.** Three bugs reached "it is running" on 2026-08-17 and
every one of them was in this wrapper, not in the Python: Zeek invisible because `/etc/profile.d`
is not read by `sudo`; a relative capture path resolved against the repo after the script `cd`s
there; and the config file overwriting environment variables the caller had set. The Python
caught its own problems through the architecture guard, the NOTICE check and CI. This layer had
no gate at all, so it became where the bugs lived.

Nothing here runs a replay, contacts a device, or needs root. `FLABEL_RUN_SUDO` is pointed at a
stub that records the command instead of executing it, which is what makes the interesting
assertion — *what would have been run* — available without running it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "tools" / "flabel-run"


@pytest.fixture
def lab(tmp_path: Path) -> dict[str, str]:
    """A fake replay box: a config file, a repo, and a `sudo` that only records."""
    conf = tmp_path / "flabel.env"
    conf.write_text(
        "export FLABEL_INLINE_HOST=10.10.0.2\n"
        "export FLABEL_INLINE_API_KEY_FILE=/dev/null\n"
        "export FLABEL_REPLAY_IF1=ens5\n"
        "export FLABEL_REPLAY_IF2=ens6\n"
        "export FLABEL_REPLAY_MULTIPLIER=1000\n"
        "export FLABEL_SETTLE_SECONDS=60\n"
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    recorded = tmp_path / "recorded"
    stub = tmp_path / "fake-sudo"
    stub.write_text(
        f'#!/bin/bash\nprintf "%s\\n" "$@" > {recorded}\nprintf "CWD=%s\\n" "$PWD" >> {recorded}\n'
    )
    stub.chmod(0o755)
    return {
        "FLABEL_RUN_CONF": str(conf),
        "FLABEL_RUN_CAPTURES": str(tmp_path / "captures"),
        "FLABEL_RUN_RUNS": str(tmp_path / "runs"),
        "FLABEL_RUN_REPO": str(repo),
        "FLABEL_RUN_SUDO": str(stub),
        "_recorded": str(recorded),
        "_tmp": str(tmp_path),
    }


def invoke(
    lab: dict[str, str], *args: str, extra: dict[str, str] | None = None, cwd: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **{k: v for k, v in lab.items() if not k.startswith("_")}}
    env.update(extra or {})
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd or lab["_tmp"],
        check=False,
    )


def recorded(lab: dict[str, str]) -> str:
    return Path(lab["_recorded"]).read_text()


def test_a_relative_capture_path_is_resolved_before_the_script_changes_directory(lab, tmp_path):
    """The bug that could have labelled the wrong file.

    The existence check runs in the caller's directory and the command runs in the repo. Passing
    the relative string through meant it resolved against the repo — an error if nothing was
    there, and silently the WRONG CAPTURE if something was.
    """
    here = tmp_path / "work"
    here.mkdir()
    (here / "some.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    result = invoke(lab, "./some.pcap", cwd=str(here))

    assert result.returncode == 0, result.stderr
    assert str(here / "some.pcap") in recorded(lab)
    assert "./some.pcap" not in recorded(lab).replace(str(here / "some.pcap"), "")


def test_the_wrong_capture_cannot_be_picked_up_from_the_repo(lab, tmp_path):
    """A same-named file in the repo must not win. This is the dangerous half of the bug."""
    here = tmp_path / "work"
    here.mkdir()
    (here / "trap.pcap").write_bytes(b"REAL")
    decoy = Path(lab["FLABEL_RUN_REPO"]) / "trap.pcap"
    decoy.write_bytes(b"DECOY")

    invoke(lab, "./trap.pcap", cwd=str(here))

    assert str(here / "trap.pcap") in recorded(lab)
    assert str(decoy) not in recorded(lab)


def test_an_environment_variable_beats_the_config_file(lab, tmp_path):
    """`FLABEL_SETTLE_SECONDS=15 flabel-run x.pcap` settled for 60 and said nothing.

    `set -a; . "$CONF"` overwrites, so the file won. That is backwards for an environment
    variable, and the silence is what made it a bug rather than a preference.
    """
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture), extra={"FLABEL_SETTLE_SECONDS": "15"})

    assert "FLABEL_SETTLE_SECONDS=15" in recorded(lab)
    assert "FLABEL_SETTLE_SECONDS=60" not in recorded(lab)


def test_the_config_file_still_supplies_everything_the_caller_did_not_set(lab, tmp_path):
    """Precedence, not replacement: overriding one value must not blank the rest."""
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture), extra={"FLABEL_SETTLE_SECONDS": "15"})

    text = recorded(lab)
    assert "FLABEL_INLINE_HOST=10.10.0.2" in text
    assert "FLABEL_REPLAY_IF1=ens5" in text


def test_the_run_happens_in_the_repo_so_the_venv_and_snapshot_resolve(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture))

    assert f"CWD={lab['FLABEL_RUN_REPO']}" in recorded(lab)


def test_zeeks_directory_is_on_the_path_handed_to_the_run(lab, tmp_path):
    """Zeek is symlinked into /usr/local/bin because sudo does not read /etc/profile.d.

    The first full tier-1 run died at the Zeek stage after spending a replay and a 60s settle.
    """
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture))

    path_line = [line for line in recorded(lab).splitlines() if line.startswith("PATH=")]
    assert path_line and "/usr/local/bin" in path_line[0]


def test_extra_arguments_are_forwarded_to_flabel(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture), "--offline")

    assert "--offline" in recorded(lab).splitlines()


def test_output_goes_to_the_runs_directory_not_beside_the_capture(lab, tmp_path):
    """Labelling a capture in a home directory must not scatter run directories there."""
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture))

    assert lab["FLABEL_RUN_RUNS"] in recorded(lab)


def test_a_missing_capture_fails_before_anything_is_run(lab):
    result = invoke(lab, "/nowhere/absent.pcap")

    assert result.returncode == 1
    assert "no such capture" in result.stderr
    assert not Path(lab["_recorded"]).exists()


def test_no_argument_prints_usage_and_exits_two(lab):
    result = invoke(lab)

    assert result.returncode == 2
    assert "usage: flabel-run" in result.stderr


def test_a_missing_config_file_says_where_it_should_be(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    result = invoke(lab, str(capture), extra={"FLABEL_RUN_CONF": str(tmp_path / "absent.env")})

    assert result.returncode == 1
    assert "device settings live there" in result.stderr
