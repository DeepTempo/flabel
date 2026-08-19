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
  # The run directory is created under the --output-dir this stub was ACTUALLY PASSED, taking the
  # last occurrence exactly as argparse does. Reading $FLABEL_RUN_RUNS instead made the stub
  # disagree with real flabel in the two cases that matter: a relative runs directory (the wrapper
  # passes it resolved, the env var is not) and an operator-supplied --output-dir (which wins).
  base=""
  prev=""
  for a in "$@"; do
    if [ "$prev" = "--output-dir" ]; then base="$a"; fi
    case "$a" in --output-dir=*) base="${{a#--output-dir=}}" ;; esac
    prev="$a"
  done
  : "${{base:=$FLABEL_RUN_RUNS}}"
  d="$base/$FAKE_MAKE_RUN"
  mkdir -p "$d/zeek"
  printf '%s' '{{"run":{{"mode":"replay"}}}}' > "$d/run.json"
  printf '%s' 'zeek log' > "$d/zeek/conn.log"
  if [ -n "${{FAKE_WRITE_LABELS:-}}" ]; then
    printf '%s' '{{"labels":[]}}' > "$d/labels.json"
  fi
fi
if [ -n "${{FAKE_STRAY_FILE:-}}" ] && [ -n "${{base:-}}" ]; then
  printf '%s' 'not a run' > "$base/$FAKE_STRAY_FILE"
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
        f"""#!/bin/bash
printf "%s\\n" "$*" >> {gcloud_log}
# A staging fetch has to leave a file behind or the wrapper's existence check stops the run before
# anything interesting happens. Only for a LOCAL destination: an upload's destination is a gs:// URI
# and must not be created on disk.
dest="${{@: -1}}"
case "$dest" in
  gs://*) : ;;
  *) [ -n "$dest" ] && printf '%s' 'staged' > "$dest" ;;
esac
exit "${{FAKE_GCLOUD_EXIT:-0}}"
"""
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
        # Empty, so the stub gcloud runs directly. In production this defaults to $SUDO, because
        # only root's gcloud carries the instance service-account credential — see the wrapper.
        # `test_gcloud_runs_privileged_by_default` is what holds that default in place.
        "FLABEL_RUN_PUBLISH_SUDO": "",
        "_recorded": str(recorded),
        "_gcloud_log": str(gcloud_log),
        "_tmp": str(tmp_path),
    }


def invoke(
    lab: dict[str, str], *args: str, extra: dict[str, str] | None = None, cwd: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **{k: v for k, v in lab.items() if not k.startswith("_")}}
    env.update(extra or {})
    # The sentinel exists because the fixture sets some variables to the EMPTY string on purpose —
    # `FLABEL_RESULTS_URI=""` means "do not publish" and `FLABEL_RUN_PUBLISH_SUDO=""` means "do not
    # elevate" — so a test that wants the wrapper's own default has to remove the name from the
    # environment entirely, which passing "" cannot express.
    for name, value in list(env.items()):
        if value == "__unset__":
            del env[name]
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


def recording_sudo(tmp_path: Path) -> tuple[Path, Path]:
    """A `sudo` replacement that logs every privileged command AND fabricates the run directory.

    Both halves are needed: logging is the assertion, and the run directory is what makes the
    publish step reachable at all. The first version of this only logged, so the wrapper found no
    new directory, published nothing, and the test failed for a reason that had nothing to do with
    what it was checking.

    Returns `(stub, log)`.
    """
    log = tmp_path / "privileged-calls"
    stub = tmp_path / "recording-sudo"
    stub.write_text(
        f"""#!/bin/bash
printf "%s\\n" "$*" >> {log}
if [ -n "${{FAKE_MAKE_RUN:-}}" ] && [ -n "${{FLABEL_RUN_RUNS:-}}" ]; then
  d="$FLABEL_RUN_RUNS/$FAKE_MAKE_RUN"
  mkdir -p "$d"
  printf '%s' '{{"labels":[]}}' > "$d/labels.json"
fi
"""
    )
    stub.chmod(0o755)
    return stub, log


def passthrough_sudo(tmp_path: Path) -> tuple[Path, Path]:
    """A privilege stub that logs the command and then actually runs it. Returns `(stub, log)`.

    Safe here in a way it would not be for `$SUDO`: `$PUBLISH_SUDO` only ever wraps `gcloud`, never
    the labelling command, so executing its arguments runs the stub gcloud rather than a real
    replay. That is what lets a test assert the fetch was privileged *and* let the fetch succeed.
    """
    log = tmp_path / "privileged-calls"
    stub = tmp_path / "passthrough-sudo"
    stub.write_text(f'#!/bin/bash\nprintf "%s\\n" "$*" >> {log}\nexec "$@"\n')
    stub.chmod(0o755)
    return stub, log


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

#: `flabel succeeded and the result was not published`. Distinct from spec §12's exit 1 ("no
#: labels.json"), because reusing 1 told a batch caller to discard a capture whose labels are
#: intact on the box (review of #134).
EXIT_NOT_PUBLISHED = 4


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

    assert result.returncode == EXIT_NOT_PUBLISHED, (
        "a failed publish must not exit 0, and must not claim the run failed either"
    )
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
    assert "cannot tell which is this" in result.stderr
    assert result.returncode == EXIT_NOT_PUBLISHED, (
        "the run itself succeeded, so this is not spec §12's exit 1"
    )


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


def test_gcloud_runs_privileged_by_default(lab, tmp_path):
    """Only root's gcloud has the instance service-account credential (measured 2026-08-19).

    The bug this pins: the publish step first ran gcloud as the invoking user, whose active
    account on `fl-replay` was a human one with no valid token — so every upload failed with
    "select an already authenticated account", while `sudo gcloud` worked as the service account
    IAM had actually been granted to.

    Every other test in this file sets `FLABEL_RUN_PUBLISH_SUDO=""` so the stub gcloud runs
    directly, which means none of them exercise the default. This one unsets it and asserts the
    privilege wrapper is invoked with the gcloud command — the production wiring, checked without
    needing root.
    """
    capture(tmp_path)
    recorder, privileged = recording_sudo(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            # Unset, so the wrapper's own default applies.
            "FLABEL_RUN_PUBLISH_SUDO": "__unset__",
            "FLABEL_RUN_SUDO": str(recorder),
        },
    )

    assert result.returncode == 0, result.stderr
    calls = privileged.read_text().splitlines() if privileged.exists() else []
    uploaded = [call for call in calls if "storage cp" in call]
    assert uploaded, f"gcloud was not run through the privilege wrapper; calls were {calls}"
    assert uploaded[0].endswith(f"gs://test-bucket/results/{RUN_NAME}.tar.gz"), uploaded[0]


def test_tar_is_deliberately_not_privileged(lab, tmp_path):
    """Run directories are root-owned but 0755, so `tar` reads them unprivileged (measured).

    Stated as a test because "run gcloud as root" invites "run everything as root", and the two
    have different reasons: gcloud needs root for its *identity*, tar would only need it for file
    access it does not lack. Building the archive as root would also leave it root-owned in a
    temporary directory this script then has to clean up.
    """
    capture(tmp_path)
    recorder, privileged = recording_sudo(tmp_path)

    invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_PUBLISH_SUDO": "__unset__",
            "FLABEL_RUN_SUDO": str(recorder),
        },
    )

    calls = privileged.read_text().splitlines() if privileged.exists() else []
    assert not [call for call in calls if call.startswith("tar ") or " tar " in call], (
        f"tar was run privileged, which it does not need: {calls}"
    )


# --- staging a gs:// capture (pre-existing path, privilege fixed in #134) ----------------------


def test_a_gs_capture_is_staged_through_the_privilege_wrapper(lab, tmp_path):
    """The same credential bug as the publish, in code that predates it.

    `gcloud storage cp` to stage a `gs://` capture ran as the invoking user, whose gcloud on
    `fl-replay` had no usable credential — so staging would have failed exactly as the first
    version of the upload did. Nothing covered this path at all, which is why the sabotage that
    reverted it passed while every other one went red.
    """
    stub, privileged = passthrough_sudo(tmp_path)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_PUBLISH_SUDO": str(stub),
        },
    )

    assert result.returncode == 0, result.stderr
    calls = privileged.read_text().splitlines() if privileged.exists() else []
    fetches = [call for call in calls if "gs://some-bucket/remote.pcap" in call]
    assert fetches, f"the staging fetch was not privileged; calls were {calls}"
    staged = Path(lab["FLABEL_RUN_CAPTURES"]) / "remote.pcap"
    assert staged.exists(), "the capture was not staged locally"
    assert str(staged) in recorded(lab), "flabel was not pointed at the staged copy"


def test_an_already_staged_capture_is_not_fetched_again(lab, tmp_path):
    """The wrapper's documented reuse, and the complement of the test above.

    Worth holding: re-downloading inside the timed part of a run widens the gap between the replay
    and the device's log query, which is the window the threat logs are selected by.
    """
    stub, privileged = passthrough_sudo(tmp_path)
    staged_dir = Path(lab["FLABEL_RUN_CAPTURES"])
    staged_dir.mkdir(parents=True, exist_ok=True)
    (staged_dir / "remote.pcap").write_bytes(b"already here")

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_PUBLISH_SUDO": str(stub),
        },
    )

    assert result.returncode == 0, result.stderr
    assert "already staged" in result.stdout + result.stderr
    calls = privileged.read_text().splitlines() if privileged.exists() else []
    assert not [call for call in calls if "gs://some-bucket/remote.pcap" in call], (
        f"a staged capture was fetched again: {calls}"
    )
    assert (staged_dir / "remote.pcap").read_bytes() == b"already here", (
        "the staged copy was replaced"
    )


# --- what the review of #134 found ------------------------------------------------------------


def test_the_config_file_can_set_the_publishing_destination(lab, tmp_path):
    """It could not, and the comment claimed it was the whole point of the override.

    `RESULTS_URI` was resolved at the top of the script and `$CONF` is sourced ~100 lines later, so
    a `FLABEL_RESULTS_URI` written into /var/lib/flabel/flabel.env was read and thrown away — and a
    second lab publishing to its own bucket silently published to the first lab's, or 403'd against
    it. The config file is exactly where a per-lab override belongs.
    """
    capture(tmp_path)
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export FLABEL_RESULTS_URI=gs://second-lab/results\n")

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            # Unset, so the config file's value is what decides.
            "FLABEL_RESULTS_URI": "__unset__",
        },
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, calls
    assert calls[0].endswith(f"gs://second-lab/results/{RUN_NAME}.tar.gz"), calls[0]


def test_the_caller_environment_still_beats_the_config_file_for_the_destination(lab, tmp_path):
    """Moving the resolution must not invert the precedence the rest of the script guarantees."""
    capture(tmp_path)
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export FLABEL_RESULTS_URI=gs://from-config/results\n")

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "gs://from-caller/results",
        },
    )

    assert result.returncode == 0, result.stderr
    assert uploads(lab)[0].endswith(f"gs://from-caller/results/{RUN_NAME}.tar.gz")


def test_publishing_can_be_switched_off_from_the_config_file(lab, tmp_path):
    """The other half of the ordering bug: an empty value in the config did not switch it off."""
    capture(tmp_path)
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export FLABEL_RESULTS_URI=\n")

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "__unset__",
        },
    )

    assert result.returncode == 0, result.stderr
    assert uploads(lab) == []


def test_a_trailing_slash_does_not_produce_a_double_slash_in_the_object_name(lab, tmp_path):
    """`gs://bucket/results/` is the natural way to write a prefix, and GCS accepts `results//x`.

    It creates an object no `results/` listing or download script matches, so it is lost rather
    than wrong.
    """
    capture(tmp_path)

    invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "gs://test-bucket/results/",
        },
    )

    assert uploads(lab)[0].endswith(f"gs://test-bucket/results/{RUN_NAME}.tar.gz")
    assert "//LABELED" not in uploads(lab)[0]


def test_a_relative_runs_directory_survives_the_change_into_the_repo(lab, tmp_path):
    """The same bug this script already fixed for the capture path, one variable over.

    `$RUNS` was listed in the caller's directory and then written to under `$REPO`, so a run looked
    like it had created several directories, published none of them, and failed.
    """
    work = tmp_path / "work"
    work.mkdir()
    capture(work)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FLABEL_RUN_RUNS": "relruns",
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
        },
        cwd=str(work),
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"a relative runs directory broke publishing: {result.stderr}"
    assert calls[0].endswith(f"{RUN_NAME}.tar.gz")


def test_an_operator_supplied_output_dir_is_still_published_from(lab, tmp_path):
    """The help lists `--output-dir` as supported AND promises a publish; both must be true.

    argparse takes the last `--output-dir`, and the wrapper passes its own first — so the
    operator's wins, the run lands elsewhere, and watching `$RUNS` saw nothing.
    """
    capture(tmp_path)
    elsewhere = tmp_path / "elsewhere"

    result = invoke(
        lab,
        "some.pcap",
        "--output-dir",
        str(elsewhere),
        extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"},
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"an overridden output dir was not published from: {result.stderr}"
    assert calls[0].endswith(f"{RUN_NAME}.tar.gz")


def test_a_stray_file_in_the_output_directory_is_not_mistaken_for_a_run(lab, tmp_path):
    """It used to satisfy the count, fail the `-d` test, and print "1 new directories"."""
    capture(tmp_path)
    runs = Path(lab["FLABEL_RUN_RUNS"])
    runs.mkdir(parents=True, exist_ok=True)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FAKE_STRAY_FILE": "notes.txt",
        },
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"a stray file confused run selection: {result.stderr}"
    assert calls[0].endswith(f"{RUN_NAME}.tar.gz")


def test_a_terminating_signal_is_forwarded_to_the_run(lab, tmp_path):
    """`exec` forwarded signals for free; dropping it orphaned a root-privileged replay.

    Without this, a SIGTERM — from `timeout`, systemd, or an operator — killed only the wrapper
    while `tcpreplay` kept injecting into the firewall as root, after the operator believed the run
    had stopped. Asserted by making the stubbed run sleep, terminating the wrapper, and checking
    the child recorded a TERM rather than running to completion.
    """
    import signal
    import time

    capture(tmp_path)
    marker = tmp_path / "child-state"
    sleeper = tmp_path / "sleeping-sudo"
    sleeper.write_text(
        f"#!/bin/bash\ntrap 'printf terminated > {marker}; exit 143' TERM\n"
        f"printf started > {marker}\nfor _ in $(seq 1 100); do sleep 0.1; done\n"
        f"printf finished > {marker}\n"
    )
    sleeper.chmod(0o755)

    env = {**os.environ, **{k: v for k, v in lab.items() if not k.startswith("_")}}
    env["FLABEL_RUN_SUDO"] = str(sleeper)
    process = subprocess.Popen(
        [str(WRAPPER), "some.pcap"],
        env=env,
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(100):
        if marker.exists():
            break
        time.sleep(0.05)
    assert marker.read_text() == "started", "the stubbed run never started"

    process.send_signal(signal.SIGTERM)
    process.wait(timeout=20)

    for _ in range(100):
        if marker.read_text() != "started":
            break
        time.sleep(0.05)
    assert marker.read_text() == "terminated", (
        "the run was orphaned: the wrapper died and left it running"
    )


# --- staging with either identity (#136) -------------------------------------------------------


def two_identity_gcloud(tmp_path: Path, *, root_ok: bool, caller_ok: bool) -> tuple[Path, Path]:
    """A `gcloud` that succeeds or fails depending on whether it was invoked through sudo.

    The privilege stub exports `VIA_SUDO=1` before exec'ing, which is how this tells the two apart
    without needing root. Returns `(gcloud, log)`.
    """
    log = tmp_path / "identity-calls"
    gcloud = tmp_path / "two-identity-gcloud"
    # The identity rule applies to DOWNLOADS only. Uploads always succeed, because the publish is
    # service-account-only by design and a stub that failed it too would make every fallback test
    # exit 4 for a reason that has nothing to do with staging — which is exactly what the first
    # version of this did.
    gcloud.write_text(
        f"""#!/bin/bash
who=caller
[ -n "${{VIA_SUDO:-}}" ] && who=root
printf '%s %s\\n' "$who" "$*" >> {log}
dest="${{@: -1}}"
case "$dest" in
  gs://*)
    exit 0
    ;;
esac
ok=0
if [ "$who" = root ]; then ok={1 if root_ok else 0}; else ok={1 if caller_ok else 0}; fi
if [ "$ok" = "1" ]; then
  [ -n "$dest" ] && printf '%s' 'staged' > "$dest"
  exit 0
fi
echo "HTTPError 403: $who cannot read it" >&2
exit 1
"""
    )
    gcloud.chmod(0o755)
    return gcloud, log


def sudo_marking_gcloud(tmp_path: Path) -> Path:
    """A privilege stub that marks the environment and runs the command, so `gcloud` can tell."""
    stub = tmp_path / "marking-sudo"
    stub.write_text('#!/bin/bash\nexport VIA_SUDO=1\nexec "$@"\n')
    stub.chmod(0o755)
    return stub


def test_the_service_account_is_tried_first_and_the_caller_is_not_needed(lab, tmp_path):
    """The ordinary path is ONE attempt, so a scheduled run behaves like an interactive one."""
    gcloud, log = two_identity_gcloud(tmp_path, root_ok=True, caller_ok=False)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode == 0, result.stderr
    fetches = [c for c in log.read_text().splitlines() if "remote.pcap" in c]
    assert len(fetches) == 1, f"the fetch should have taken one attempt: {fetches}"
    assert fetches[0].startswith("root "), fetches[0]


def test_the_caller_is_the_fallback_when_the_service_account_cannot_read_it(lab, tmp_path):
    """An object the operator can reach and the box has not been granted still works (#136).

    Safe because this is a read: `run.input.sha256` records the capture, not who fetched it.
    """
    gcloud, log = two_identity_gcloud(tmp_path, root_ok=False, caller_ok=True)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode == 0, result.stderr
    fetches = [c for c in log.read_text().splitlines() if "remote.pcap" in c]
    assert [c.split()[0] for c in fetches] == ["root", "caller"], fetches
    assert "the service account could not read it" in result.stderr
    assert (Path(lab["FLABEL_RUN_CAPTURES"]) / "remote.pcap").exists()


def test_when_neither_identity_can_read_it_both_failures_are_reported(lab, tmp_path):
    """The bug report that started #136 showed one 403 and named one principal.

    Both identities had failed, for different reasons, and the message made a two-part access
    problem look like a one-part one. The remedies are printed because a 403 tells an operator what
    was refused and never what to do about it.
    """
    gcloud, log = two_identity_gcloud(tmp_path, root_ok=False, caller_ok=False)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode != 0
    assert "NEITHER identity" in result.stderr
    assert "root cannot read it" in result.stderr, "the service account's own error must appear"
    assert "caller cannot read it" in result.stderr, "the caller's own error must appear"
    assert "objectViewer" in result.stderr, "the remedy must be named, not just the refusal"
    assert uploads(lab) == [], "a run that never started publishes nothing"
    fetches = [c for c in log.read_text().splitlines() if "remote.pcap" in c]
    assert [c.split()[0] for c in fetches] == ["root", "caller"], fetches


def test_a_failed_stage_stops_immediately_and_says_only_the_real_reason(lab, tmp_path):
    """The capture is fetched before the run for exactly this reason — fail before the 60s settle.

    Two properties, and only the second is unique to `stage_capture`. That no replay starts is also
    held by the `[ -f "$TARGET" ]` check further down, so a sabotage removing this function's
    failure propagation still leaves the run un-started — belt and braces, and worth knowing.

    What *is* unique here: the failure has to be fatal AT THE FETCH, so the operator reads the
    both-identities diagnosis and nothing else. Letting it fall through produces a second,
    misleading "no such capture: /var/lib/flabel/captures/remote.pcap" underneath the real
    explanation, which reads like a missing file rather than a denied one.
    """
    gcloud, _ = two_identity_gcloud(tmp_path, root_ok=False, caller_ok=False)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode != 0
    assert not Path(lab["_recorded"]).exists(), "flabel was invoked despite having no capture"
    assert "NEITHER identity" in result.stderr
    assert "no such capture" not in result.stderr, (
        "a denied fetch must not also report a missing file — that is the wrong diagnosis"
    )
