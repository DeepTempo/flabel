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

    # The `sudo` stub records the command and, when asked, fabricates the run directory that a
    # real labelling run would have left behind. Fabricating it is what makes the publish step
    # (#134) reachable without a replay: the interesting assertions are about which directory is
    # published and whether `labels.json` is in it, and neither needs flabel to have run.
    #
    # FAKE_EXIT lets a test drive a *failed* run, because "the exit code still survives the added
    # publish step" is only testable against a non-zero one.
    stub = tmp_path / "fake-sudo"
    stub.write_text(
        f"""#!/bin/bash
printf "%s\\n" "$@" > {recorded}
printf "CWD=%s\\n" "$PWD" >> {recorded}
if [ -n "${{FAKE_MAKE_RUN:-}}" ]; then
  d="$FLABEL_RUN_RUNS/$FAKE_MAKE_RUN"
  mkdir -p "$d/zeek"
  printf '%s' '{{"run":{{"mode":"replay"}}}}' > "$d/run.json"
  printf '%s' 'zeek log' > "$d/zeek/conn.log"
  if [ -n "${{FAKE_WRITE_LABELS:-}}" ]; then
    printf '%s' '{{"labels":[]}}' > "$d/labels.json"
  fi
fi
if [ -n "${{FAKE_MAKE_SECOND_RUN:-}}" ]; then
  mkdir -p "$FLABEL_RUN_RUNS/$FAKE_MAKE_SECOND_RUN"
  printf '%s' '{{"labels":[]}}' > "$FLABEL_RUN_RUNS/$FAKE_MAKE_SECOND_RUN/labels.json"
fi
exit "${{FAKE_EXIT:-0}}"
"""
    )
    stub.chmod(0o755)

    # A `gcloud` that records instead of uploading, and a destination that is not a real bucket.
    # Both are set for EVERY test, not only the publishing ones: `FLABEL_RESULTS_URI` defaults to
    # the production bucket, so leaving it unset would make the suite's behaviour depend on whether
    # a test happened to create a run directory. Nothing here may contact GCS by accident.
    gcloud_log = tmp_path / "gcloud-calls"
    gcloud = tmp_path / "fake-gcloud"
    gcloud.write_text(
        f'#!/bin/bash\nprintf "%s\\n" "$*" >> {gcloud_log}\nexit "${{FAKE_GCLOUD_EXIT:-0}}"\n'
    )
    gcloud.chmod(0o755)

    return {
        "FLABEL_RUN_CONF": str(conf),
        "FLABEL_RUN_CAPTURES": str(tmp_path / "captures"),
        "FLABEL_RUN_RUNS": str(tmp_path / "runs"),
        "FLABEL_RUN_REPO": str(repo),
        "FLABEL_RUN_SUDO": str(stub),
        "FLABEL_RUN_GCLOUD": str(gcloud),
        "FLABEL_RESULTS_URI": "gs://test-bucket/results",
        "_recorded": str(recorded),
        "_gcloud_log": str(gcloud_log),
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


def uploads(lab: dict[str, str]) -> list[str]:
    """Every `gcloud` invocation the wrapper made, one per line, or `[]` if it made none."""
    log = Path(lab["_gcloud_log"])
    return log.read_text().splitlines() if log.exists() else []


def capture(tmp_path: Path, name: str = "some.pcap") -> Path:
    """A file that passes the wrapper's existence check. Never read — the run is stubbed."""
    path = tmp_path / name
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return path


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


def test_no_argument_prints_usage_to_stderr_and_exits_two(lab):
    result = invoke(lab)

    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("flag", ["-h", "--help", "help"])
def test_help_goes_to_stdout_and_succeeds(lab, flag):
    """Asking is not the same event as being told.

    `--help` on stderr with a failing status cannot be piped into a pager, which is the one
    thing an operator does with it.
    """
    result = invoke(lab, flag)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "usage:" in result.stdout


def test_help_documents_the_knobs_that_change_what_a_label_means(lab):
    """--topspeed and the settle are not cosmetic, so help has to say what they cost."""
    text = invoke(lab, "--help").stdout
    for knob in (
        "FLABEL_REPLAY_MULTIPLIER",
        "FLABEL_REPLAY_TOPSPEED",
        "FLABEL_SETTLE_SECONDS",
        "FLABEL_PLAIN_PROGRESS",
        "--offline",
    ):
        assert knob in text, f"help does not mention {knob}"
    assert "unmatched rather than" in text, "help must say what --topspeed costs"


def test_help_works_without_a_config_file(lab, tmp_path):
    """An operator whose config is missing still needs to be able to read the help."""
    result = invoke(lab, "--help", extra={"FLABEL_RUN_CONF": str(tmp_path / "absent.env")})

    assert result.returncode == 0
    assert "usage:" in result.stdout


def test_a_missing_config_file_says_where_it_should_be(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    result = invoke(lab, str(capture), extra={"FLABEL_RUN_CONF": str(tmp_path / "absent.env")})

    assert result.returncode == 1
    assert "device settings live there" in result.stderr


# --- publishing a finished run (#134) --------------------------------------------------------
#
# The destination is a stub `gcloud` and a `gs://test-bucket` that does not exist. What is asserted
# is *what would have been uploaded*, which is the same trick `FLABEL_RUN_SUDO` plays on the replay
# itself — and for the same reason: the interesting behaviour is the decision, not the transfer.

RUN_NAME = "LABELED_some_20260819T120000.000000Z"


def test_a_successful_run_is_published_under_the_run_directory_name(lab, tmp_path):
    """The whole feature: labels on the box become a tarball in the bucket, named to match."""
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"expected exactly one upload, got {calls}"
    assert calls[0].startswith("storage cp "), calls[0]
    assert calls[0].endswith(f"gs://test-bucket/results/{RUN_NAME}.tar.gz"), calls[0]


def test_the_published_tarball_unpacks_to_one_directory_of_that_name(lab, tmp_path):
    """`tar -C $RUNS <name>` rather than an absolute path, so it cannot unpack to `var/lib/...`.

    Asserted by unpacking the real archive: the stub `gcloud` is handed a genuine tarball, so the
    bytes are checkable even though nothing is transferred. A test on the *command* alone would
    pass with an archive rooted at an absolute path.
    """
    import tarfile

    capture(tmp_path)
    staged = tmp_path / "staged.tar.gz"
    # A `gcloud` that keeps the file it was asked to upload, instead of only recording the call.
    keeper = tmp_path / "keeping-gcloud"
    keeper.write_text(f'#!/bin/bash\nshift 2\ncp "$1" {staged}\n')
    keeper.chmod(0o755)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_GCLOUD": str(keeper),
        },
    )

    assert result.returncode == 0, result.stderr
    assert staged.exists(), "the wrapper never handed gcloud a file"
    with tarfile.open(staged) as archive:
        names = archive.getnames()
    tops = {name.split("/")[0] for name in names}
    assert tops == {RUN_NAME}, f"archive has more than one root: {tops}"
    assert f"{RUN_NAME}/labels.json" in names
    assert f"{RUN_NAME}/run.json" in names
    assert f"{RUN_NAME}/zeek/conn.log" in names


def test_a_run_with_no_labels_is_not_published(lab, tmp_path):
    """Craig, 2026-08-19: `results/` is trustworthy by construction or it is not worth having.

    Decided on the ARTIFACT, not the exit code. Issue #23 makes the presence of `labels.json` the
    definition of a completed run, so the directory's contents and a consumer's conclusion cannot
    disagree — where an exit code is a second record of the same fact.
    """
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME})

    assert uploads(lab) == [], "a run that wrote no labels must publish nothing"
    assert "wrote no labels.json" in result.stderr
    assert (Path(lab["FLABEL_RUN_RUNS"]) / RUN_NAME / "run.json").exists(), (
        "the local run must be left alone — it is the diagnosis"
    )


def test_a_failed_run_still_exits_with_flabels_code(lab, tmp_path):
    """`exec` had to go so publishing could happen after the run; the exit code must survive it.

    This is the regression the refactor most plausibly introduces: dropping `exec` makes the exit
    status something the script now has to carry by hand, and `set -e` would otherwise kill it
    before it could report.
    """
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_EXIT": "1"})

    assert result.returncode == 1, result.stderr
    assert uploads(lab) == []


def test_a_usage_exit_code_of_two_is_not_flattened_to_one(lab, tmp_path):
    """Exit 2 means "the invocation was wrong" (spec §12) and must not become a generic failure."""
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_EXIT": "2"})

    assert result.returncode == 2, result.stderr


def test_a_failed_upload_does_not_report_success(lab, tmp_path):
    """The worst available outcome is a silent one: labels on the box, operator believes otherwise.

    The local run must survive untouched — the upload failing is not a reason to lose the result.
    """
    capture(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FAKE_GCLOUD_EXIT": "1",
        },
    )

    assert result.returncode != 0, "a failed publish must not exit 0"
    assert "FAILED to publish" in result.stderr
    assert "labels are intact" in result.stderr
    assert (Path(lab["FLABEL_RUN_RUNS"]) / RUN_NAME / "labels.json").exists()


def test_publishing_can_be_switched_off_with_an_empty_destination(lab, tmp_path):
    """So this wrapper stays the one way to run flabel even where there is no bucket.

    An empty value rather than a second flag or a second script: a "run but do not publish" code
    path is a second thing to keep correct, and the one that gets exercised less is the one that
    rots.
    """
    capture(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "",
        },
    )

    assert result.returncode == 0, result.stderr
    assert uploads(lab) == []


def test_two_new_directories_are_refused_rather_than_guessed_between(lab, tmp_path):
    """Publishing the wrong directory puts one capture's labels in the bucket under another's name.

    Reachable in the field: a concurrent run, or a stale directory appearing under `$RUNS` between
    the before and after listings. Nothing is published and the operator is told how to do it by
    hand, because a wrong publish is worse than no publish.
    """
    capture(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FAKE_MAKE_SECOND_RUN": "LABELED_other_20260819T120001.000000Z",
        },
    )

    assert uploads(lab) == [], "with two candidates, nothing may be published"
    assert "cannot tell which is this run's" in result.stderr
    assert result.returncode != 0


def test_a_run_that_created_no_directory_publishes_nothing_and_says_so(lab, tmp_path):
    """A rejected capture leaves no run directory at all (spec §12) — normal, and worth one line."""
    capture(tmp_path)

    result = invoke(lab, "some.pcap")

    assert uploads(lab) == []
    assert "nothing to publish" in result.stderr


def test_a_pre_existing_run_directory_is_not_republished(lab, tmp_path):
    """Only what THIS invocation created. Spec §13 forbids modifying a previous run; republishing
    one is the same mistake pointed at the bucket — and with `objectCreator` the overwrite would
    be refused anyway, so the operator would get a 403 about a run they did not just make.
    """
    capture(tmp_path)
    stale = Path(lab["FLABEL_RUN_RUNS"]) / "LABELED_older_20260818T120000.000000Z"
    stale.mkdir(parents=True)
    (stale / "labels.json").write_text("{}")

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, calls
    # The DESTINATION only. Asserting `"older" not in calls[0]` matched the pytest temp path,
    # which on macOS contains ".../var/folders/..." — and "folders" contains "older". A substring
    # check over a whole command line is a check over whatever the environment put in it.
    destination = calls[0].split()[-1]
    assert destination == f"gs://test-bucket/results/{RUN_NAME}.tar.gz", destination


def test_the_tarball_is_not_left_inside_the_runs_directory(lab, tmp_path):
    """A `.tar.gz` beside the run directories is picked up as one by anything that lists them —
    including this wrapper's own before/after comparison on the very next run."""
    capture(tmp_path)

    invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"})

    leftovers = list(Path(lab["FLABEL_RUN_RUNS"]).glob("*.tar.gz"))
    assert leftovers == [], f"tarball left in the runs directory: {leftovers}"
